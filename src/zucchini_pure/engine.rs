//! Format-independent apply engine: equivalences, extra data, raw deltas,
//! reference correction, `OffsetMapper`, and `TargetPool`.

use std::collections::BTreeMap;

use super::bytes::{range_is_bounded, range_covers};
use super::dex;
use super::patch::{
    Equivalence, PatchElement, EXE_TYPE_DEX, EXE_TYPE_ELF_AARCH32, EXE_TYPE_ELF_AARCH64,
    EXE_TYPE_ELF_X64, EXE_TYPE_ELF_X86, EXE_TYPE_NOOP,
};
use super::{
    is_android_executable, make_disassembler, Disassembler, Error, GroupTraits, Result, Status,
    K_INVALID_OFFSET, OFFSET_BOUND,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reference {
    pub location: u32,
    pub target: u32,
}

pub(crate) struct NoOpDisassembler {
    pub size: u32,
}

impl Disassembler for NoOpDisassembler {
    fn size(&self) -> u32 {
        self.size
    }

    fn groups(&self) -> &[GroupTraits] {
        &[]
    }

    fn read(&self, _group: usize, _image: &[u8], _lo: u32, _hi: u32) -> Vec<Reference> {
        Vec::new()
    }

    fn write(&self, _group: usize, _image: &mut [u8], _reference: Reference) {}
}

fn apply_error(message: impl Into<String>) -> Error {
    Error::new(Status::ApplyError, message)
}

pub(crate) fn apply_element(
    old: &[u8],
    element: &PatchElement,
    output: &mut [u8],
) -> Result<()> {
    let matching = &element.element_match;
    let old_end = (matching.old_offset as usize)
        .checked_add(matching.old_size as usize)
        .ok_or_else(|| apply_error("old element range overflow"))?;
    let new_end = (matching.new_offset as usize)
        .checked_add(matching.new_size as usize)
        .ok_or_else(|| apply_error("new element range overflow"))?;
    let old_element = old
        .get(matching.old_offset as usize..old_end)
        .ok_or_else(|| apply_error("old element out of bounds"))?;
    let new_element = output
        .get_mut(matching.new_offset as usize..new_end)
        .ok_or_else(|| apply_error("new element out of bounds"))?;

    apply_equivalence_and_extra_data(old_element, element, new_element)?;
    apply_raw_delta(element, new_element)?;
    apply_references_correction(matching.exe_type, old_element, element, new_element)?;
    Ok(())
}

/// Mirrors the native FFI's `PreflightAndroidElements` for one element: apply
/// equivalence/extra/raw data to a scratch output, then run the Android
/// boundary and DEX-target validations that upstream Zucchini does not.
pub(crate) fn preflight_element(
    old: &[u8],
    element: &PatchElement,
    output: &mut [u8],
) -> Result<()> {
    let exe_type = element.element_match.exe_type;
    if exe_type == EXE_TYPE_NOOP || !is_android_executable(exe_type) {
        return Ok(());
    }

    let matching = &element.element_match;
    let old_end = (matching.old_offset as usize)
        .checked_add(matching.old_size as usize)
        .ok_or_else(|| apply_error("old element range overflow"))?;
    let new_end = (matching.new_offset as usize)
        .checked_add(matching.new_size as usize)
        .ok_or_else(|| apply_error("new element range overflow"))?;
    let old_element = old
        .get(matching.old_offset as usize..old_end)
        .ok_or_else(|| apply_error("old element out of bounds"))?;
    let new_element = output
        .get_mut(matching.new_offset as usize..new_end)
        .ok_or_else(|| apply_error("new element out of bounds"))?;

    apply_equivalence_and_extra_data(old_element, element, new_element)?;
    apply_raw_delta(element, new_element)?;

    let old_disasm = make_disassembler(exe_type, old_element)
        .ok_or_else(|| apply_error("failed to create old disassembler"))?;
    let new_disasm = make_disassembler(exe_type, new_element)
        .ok_or_else(|| apply_error("failed to create new disassembler"))?;
    if old_disasm.size() != old_element.len() as u32
        || new_disasm.size() != new_element.len() as u32
    {
        return Err(apply_error("disassembler and element size mismatch"));
    }
    let new_size = new_element.len() as u32;
    if !validate_reference_boundaries(&*old_disasm, exe_type, element, old_element, new_size) {
        return Err(apply_error("reference boundary violation"));
    }
    if exe_type == EXE_TYPE_DEX {
        if !dex::narrow_writer_widths_ok(new_element) {
            return Err(apply_error("dex writer width violation"));
        }
        if !validate_dex_reference_targets(
            &*old_disasm,
            &*new_disasm,
            element,
            old_element,
            new_element,
        ) {
            return Err(apply_error("dex reference target violation"));
        }
    }
    Ok(())
}

/// Mirrors the FFI's `ValidateReferenceBoundaries`.
fn validate_reference_boundaries(
    old_disasm: &dyn Disassembler,
    exe_type: u32,
    element: &PatchElement,
    old_image: &[u8],
    new_size: u32,
) -> bool {
    let mut boundaries: Vec<u32> = Vec::new();
    for equivalence in &element.equivalences {
        boundaries.push(equivalence.src_offset);
        boundaries.push(equivalence.src_end());
    }
    boundaries.sort_unstable();

    let old_size = old_image.len() as u32;
    for (group_index, group) in old_disasm.groups().iter().enumerate() {
        let mut writer_width = group.width;
        if group.type_tag == 0 {
            match exe_type {
                EXE_TYPE_ELF_X86 | EXE_TYPE_ELF_AARCH32 => writer_width = 8,
                EXE_TYPE_ELF_X64 | EXE_TYPE_ELF_AARCH64 => writer_width = 16,
                _ => {}
            }
        }

        for reference in old_disasm.read(group_index, old_image, 0, old_size) {
            let boundary = boundaries.partition_point(|value| *value <= reference.location);
            if boundary < boundaries.len()
                && boundaries[boundary] < reference.location.wrapping_add(group.width)
            {
                return false;
            }
        }

        for equivalence in &element.equivalences {
            for reference in old_disasm.read(
                group_index,
                old_image,
                equivalence.src_offset,
                equivalence.src_end(),
            ) {
                if reference.location < equivalence.src_offset
                    || reference.location > equivalence.src_end()
                    || group.width > equivalence.src_end() - reference.location
                {
                    return false;
                }
                let projected = equivalence.dst_offset.wrapping_add(
                    reference.location.wrapping_sub(equivalence.src_offset),
                );
                if projected > new_size || writer_width > new_size - projected {
                    return false;
                }
            }
        }
    }
    true
}

/// Mirrors the FFI's `ValidateDexReferenceTargets`.
fn validate_dex_reference_targets(
    old_disasm: &dyn Disassembler,
    new_disasm: &dyn Disassembler,
    element: &PatchElement,
    old_image: &[u8],
    new_image: &[u8],
) -> bool {
    let Some(string_ids) = dex::string_ids(new_image) else { return false };

    let mut pools: BTreeMap<u8, Vec<usize>> = BTreeMap::new();
    for (index, group) in old_disasm.groups().iter().enumerate() {
        pools.entry(group.pool_tag).or_default().push(index);
    }

    let mut deltas = element.reference_deltas.iter();
    let old_size = old_image.len() as u32;
    let mapper = OffsetMapper::new(
        &element.equivalences,
        old_size,
        new_image.len() as u32,
    );

    for (pool_tag, sub_groups) in &pools {
        let mut targets = TargetPool::default();
        for &group_index in sub_groups {
            targets.insert_references(&old_disasm.read(group_index, old_image, 0, old_size));
        }
        targets.filter_and_project(&mapper);
        if let Some(extra) = element.extra_targets.get(pool_tag) {
            targets.insert_targets(&extra.targets);
            if !extra.done {
                return false;
            }
        }

        for &group_index in sub_groups {
            let type_tag = old_disasm.groups()[group_index].type_tag;
            if usize::from(type_tag) >= new_disasm.groups().len() {
                return false;
            }
            for equivalence in &element.equivalences {
                for reference in old_disasm.read(
                    group_index,
                    old_image,
                    equivalence.src_offset,
                    equivalence.src_end(),
                ) {
                    let projected = mapper.extended_forward_project(reference.target);
                    let expected = targets.key_for_nearest_offset(projected);
                    let Some(delta) = deltas.next() else { return false };
                    let key = i64::from(expected) + i64::from(*delta);
                    if !(0..=i64::from(u32::MAX)).contains(&key) {
                        return false;
                    }
                    let key = key as u32;
                    if !targets.key_is_valid(key) {
                        return false;
                    }
                    if type_tag == 5 {
                        let target = targets.offset_for_key(key);
                        if target < string_ids.offset
                            || (target - string_ids.offset) % 4 != 0
                            || (target - string_ids.offset) / 4 > u32::from(u16::MAX)
                        {
                            return false;
                        }
                    }
                }
            }
        }
    }

    deltas.next().is_none() && element.reference_deltas_done
}

/// Mirrors `ApplyEquivalenceAndExtraData`.
fn apply_equivalence_and_extra_data(
    old_image: &[u8],
    element: &PatchElement,
    new_image: &mut [u8],
) -> Result<()> {
    let mut extra_cursor = 0usize;
    let mut dst_it = 0usize;

    for equivalence in &element.equivalences {
        let next_dst_it = equivalence.dst_offset as usize;
        if next_dst_it < dst_it {
            return Err(apply_error("overlapping equivalences"));
        }
        let gap = next_dst_it - dst_it;
        let extra = take_extra(&element.extra_data, &mut extra_cursor, gap)?;
        new_image
            .get_mut(dst_it..next_dst_it)
            .ok_or_else(|| apply_error("extra data out of bounds"))?
            .copy_from_slice(extra);

        let src_begin = equivalence.src_offset as usize;
        let src_end = src_begin
            .checked_add(equivalence.length as usize)
            .ok_or_else(|| apply_error("equivalence source overflow"))?;
        let dst_end = next_dst_it
            .checked_add(equivalence.length as usize)
            .ok_or_else(|| apply_error("equivalence destination overflow"))?;
        let source = old_image
            .get(src_begin..src_end)
            .ok_or_else(|| apply_error("equivalence source out of bounds"))?;
        new_image
            .get_mut(next_dst_it..dst_end)
            .ok_or_else(|| apply_error("equivalence destination out of bounds"))?
            .copy_from_slice(source);
        dst_it = dst_end;
    }

    let gap = new_image
        .len()
        .checked_sub(dst_it)
        .ok_or_else(|| apply_error("extra data length mismatch"))?;
    let extra = take_extra(&element.extra_data, &mut extra_cursor, gap)?;
    new_image
        .get_mut(dst_it..)
        .ok_or_else(|| apply_error("extra data out of bounds"))?
        .copy_from_slice(extra);

    if !element.equivalences_done || extra_cursor != element.extra_data.len() {
        return Err(apply_error("trailing equivalence or extra data"));
    }
    Ok(())
}

fn take_extra<'a>(extra: &'a [u8], cursor: &mut usize, size: usize) -> Result<&'a [u8]> {
    let end = cursor
        .checked_add(size)
        .ok_or_else(|| apply_error("extra data length overflow"))?;
    let slice = extra.get(*cursor..end).ok_or_else(|| apply_error("extra data exhausted"))?;
    *cursor = end;
    Ok(slice)
}

/// Mirrors `ApplyRawDelta`.
fn apply_raw_delta(element: &PatchElement, new_image: &mut [u8]) -> Result<()> {
    let mut base_copy_offset: u32 = 0;
    let mut equivalence_index = 0usize;

    for delta in &element.raw_deltas {
        while equivalence_index < element.equivalences.len() {
            let equivalence = element.equivalences[equivalence_index];
            let end = base_copy_offset
                .checked_add(equivalence.length)
                .ok_or_else(|| apply_error("equivalence length overflow"))?;
            if end <= delta.copy_offset {
                base_copy_offset = end;
                equivalence_index += 1;
            } else {
                break;
            }
        }
        let equivalence = element
            .equivalences
            .get(equivalence_index)
            .ok_or_else(|| apply_error("error reading equivalences"))?;
        if delta.copy_offset < base_copy_offset
            || delta.copy_offset
                >= base_copy_offset
                    .checked_add(equivalence.length)
                    .ok_or_else(|| apply_error("equivalence length overflow"))?
        {
            return Err(apply_error("raw delta out of equivalence range"));
        }
        let index = equivalence
            .dst_offset
            .checked_sub(base_copy_offset)
            .and_then(|value| value.checked_add(delta.copy_offset))
            .ok_or_else(|| apply_error("raw delta destination overflow"))?;
        let slot = new_image
            .get_mut(index as usize)
            .ok_or_else(|| apply_error("raw delta out of bounds"))?;
        *slot = slot.wrapping_add(delta.diff as u8);
    }

    if !element.raw_deltas_done {
        return Err(apply_error("found trailing raw delta"));
    }
    Ok(())
}

/// Mirrors `ApplyReferencesCorrection`.
fn apply_references_correction(
    exe_type: u32,
    old_image: &[u8],
    element: &PatchElement,
    new_image: &mut [u8],
) -> Result<()> {
    let old_disasm = make_disassembler(exe_type, old_image)
        .ok_or_else(|| apply_error("failed to create old disassembler"))?;
    let new_disasm = make_disassembler(exe_type, new_image)
        .ok_or_else(|| apply_error("failed to create new disassembler"))?;
    if old_disasm.size() != old_image.len() as u32 || new_disasm.size() != new_image.len() as u32 {
        return Err(apply_error("disassembler and element size mismatch"));
    }

    let old_groups = old_disasm.groups();
    let new_groups = new_disasm.groups();
    let mapper = OffsetMapper::new(
        &element.equivalences,
        old_image.len() as u32,
        new_image.len() as u32,
    );

    let mut pools: BTreeMap<u8, Vec<usize>> = BTreeMap::new();
    for (index, group) in old_groups.iter().enumerate() {
        pools.entry(group.pool_tag).or_default().push(index);
    }

    let mut deltas = element.reference_deltas.iter();
    for (pool_tag, sub_groups) in &pools {
        let mut targets = TargetPool::default();
        for &group_index in sub_groups {
            let references = old_disasm.read(group_index, old_image, 0, old_image.len() as u32);
            targets.insert_references(&references);
        }
        targets.filter_and_project(&mapper);

        if let Some(extra) = element.extra_targets.get(pool_tag) {
            targets.insert_targets(&extra.targets);
            if !extra.done {
                return Err(apply_error("found trailing extra targets"));
            }
        }

        for &group_index in sub_groups {
            let type_tag = old_groups[group_index].type_tag as usize;
            if type_tag >= new_groups.len() {
                return Err(apply_error("new reference group is missing"));
            }
            for equivalence in &element.equivalences {
                let references = old_disasm.read(
                    group_index,
                    old_image,
                    equivalence.src_offset,
                    equivalence.src_end(),
                );
                for mut reference in references {
                    let projected = mapper.extended_forward_project(reference.target);
                    let expected_key = targets.key_for_nearest_offset(projected);
                    let delta = deltas
                        .next()
                        .ok_or_else(|| apply_error("error reading reference delta"))?;
                    let key = expected_key.wrapping_add(*delta as u32);
                    if !targets.key_is_valid(key) {
                        return Err(apply_error("invalid reference delta"));
                    }
                    reference.target = targets.offset_for_key(key);
                    reference.location = reference
                        .location
                        .wrapping_sub(equivalence.src_offset)
                        .wrapping_add(equivalence.dst_offset);
                    new_disasm.write(type_tag, new_image, reference);
                }
            }
        }
    }

    // Match `ReferenceDeltaSource::Done()`: unconsumed malformed trailing bytes
    // are a trailing-reference-delta error even if every needed delta decoded.
    if deltas.next().is_some() || !element.reference_deltas_done {
        return Err(apply_error("found trailing reference delta"));
    }
    Ok(())
}

/// Mirrors `OffsetMapper` in `equivalence_map.cc`.
struct OffsetMapper {
    equivalences: Vec<Equivalence>,
    old_image_size: u32,
    new_image_size: u32,
}

impl OffsetMapper {
    fn new(source: &[Equivalence], old_image_size: u32, new_image_size: u32) -> Self {
        let mut equivalences = source.to_vec();
        PruneEquivalencesAndSortBySource::prune(&mut equivalences);
        Self { equivalences, old_image_size, new_image_size }
    }

    fn naive_extended_forward_project(&self, unit: &Equivalence, offset: u32) -> u32 {
        let value = offset as i64 - unit.src_offset as i64 + unit.dst_offset as i64;
        let clamped = value.clamp(0, self.new_image_size as i64 - 1);
        clamped as u32
    }

    fn extended_forward_project(&self, offset: u32) -> u32 {
        if offset < self.old_image_size {
            // First equivalence with `src_offset > offset`.
            let pos = self
                .equivalences
                .partition_point(|equivalence| equivalence.src_offset <= offset);
            let mut chosen = pos;
            if pos != 0 {
                let back = self.equivalences[pos - 1];
                let take_back = pos == self.equivalences.len()
                    || offset < back.src_end()
                    || (offset - back.src_end()) < (self.equivalences[pos].src_offset - offset);
                if take_back {
                    chosen = pos - 1;
                }
            }
            return self.naive_extended_forward_project(&self.equivalences[chosen], offset);
        }
        let delta = offset - self.old_image_size;
        if delta < OFFSET_BOUND as u32 - self.new_image_size {
            self.new_image_size + delta
        } else {
            (OFFSET_BOUND - 1) as u32
        }
    }

    fn forward_project_all(&self, offsets: &mut Vec<u32>) {
        let mut current = 0usize;
        for source in offsets.iter_mut() {
            while current < self.equivalences.len()
                && self.equivalences[current].src_end() <= *source
            {
                current += 1;
            }
            if current < self.equivalences.len()
                && self.equivalences[current].src_offset <= *source
            {
                *source = *source - self.equivalences[current].src_offset
                    + self.equivalences[current].dst_offset;
            } else {
                *source = K_INVALID_OFFSET;
            }
        }
        offsets.retain(|value| *value != K_INVALID_OFFSET);
    }
}

/// Mirrors `OffsetMapper::PruneEquivalencesAndSortBySource`.
struct PruneEquivalencesAndSortBySource;

impl PruneEquivalencesAndSortBySource {
    fn prune(equivalences: &mut Vec<Equivalence>) {
        equivalences.sort_by_key(|equivalence| equivalence.src_offset);

        let mut current = 0usize;
        while current < equivalences.len() {
            let mut next_is_reaper = false;
            let mut next = current + 1;
            while next < equivalences.len() {
                if equivalences[next].src_offset >= equivalences[current].src_end() {
                    break;
                }
                if equivalences[current].length < equivalences[next].length {
                    let delta =
                        equivalences[current].src_end() - equivalences[next].src_offset;
                    equivalences[current].length -= delta;
                    next_is_reaper = true;
                    break;
                }
                next += 1;
            }

            if next_is_reaper {
                for reduced in (current + 1)..next {
                    equivalences[reduced].length = 0;
                }
                current = next;
            } else {
                for reduced in (current + 1)..next {
                    let delta =
                        equivalences[current].src_end() - equivalences[reduced].src_offset;
                    let shrink = equivalences[reduced].length.min(delta);
                    equivalences[reduced].length -= shrink;
                    equivalences[reduced].src_offset += delta;
                    equivalences[reduced].dst_offset += delta;
                }
                current += 1;
            }
        }

        equivalences.retain(|equivalence| equivalence.length != 0);
    }
}

/// Mirrors `TargetPool`.
#[derive(Default)]
struct TargetPool {
    targets: Vec<u32>,
}

impl TargetPool {
    fn sort_and_uniquify(&mut self) {
        self.targets.sort_unstable();
        self.targets.dedup();
    }

    fn insert_references(&mut self, references: &[Reference]) {
        self.targets.extend(references.iter().map(|reference| reference.target));
        self.sort_and_uniquify();
    }

    fn insert_targets(&mut self, targets: &[u32]) {
        self.targets.extend_from_slice(targets);
        self.sort_and_uniquify();
    }

    fn filter_and_project(&mut self, mapper: &OffsetMapper) {
        mapper.forward_project_all(&mut self.targets);
        self.targets.sort_unstable();
    }

    /// Mirrors `KeyForNearestOffset`, including its lower-key tie-breaking.
    fn key_for_nearest_offset(&self, offset: u32) -> u32 {
        let mut pos = self.targets.partition_point(|target| *target < offset);
        if pos != 0 {
            if pos == self.targets.len()
                || self.targets[pos] - offset >= offset - self.targets[pos - 1]
            {
                pos -= 1;
            }
        }
        pos as u32
    }

    fn offset_for_key(&self, key: u32) -> u32 {
        self.targets[key as usize]
    }

    fn key_is_valid(&self, key: u32) -> bool {
        (key as usize) < self.targets.len()
    }
}

/// Keeps the range helpers referenced for later DEX validation code.
#[allow(dead_code)]
fn _range_helpers() {
    let _ = range_covers;
    let _ = range_is_bounded;
}
