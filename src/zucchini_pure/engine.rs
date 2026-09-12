//! Format-independent apply engine: equivalences, extra data, raw deltas,
//! reference correction, `OffsetMapper`, and `TargetPool`.

use std::collections::BTreeMap;

use super::bytes::{range_covers, range_is_bounded};
use super::dex;
use super::patch::{
    EXE_TYPE_DEX, EXE_TYPE_ELF_AARCH32, EXE_TYPE_ELF_AARCH64, EXE_TYPE_ELF_X64, EXE_TYPE_ELF_X86,
    EXE_TYPE_NOOP, Equivalence, PatchElement,
};
use super::{
    Disassembler, Error, GroupTraits, K_INVALID_OFFSET, OFFSET_BOUND, Result, Status,
    is_android_executable, make_disassembler,
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

    fn read(&self, _group: usize, _image: &[u8], _lo: u32, _hi: u32) -> Result<Vec<Reference>> {
        Ok(Vec::new())
    }

    fn write(&self, _group: usize, _image: &mut [u8], _reference: Reference) {}
}

fn apply_error(message: impl Into<String>) -> Error {
    Error::new(Status::ApplyError, message)
}

fn check_not_cancelled(cancelled: &dyn Fn() -> bool) -> Result<()> {
    if cancelled() {
        Err(Error::new(Status::Cancelled, "Zucchini apply cancelled"))
    } else {
        Ok(())
    }
}

/// Old-image analysis shared by preflight and apply for one element.
pub(crate) struct ElementAnalysis {
    disasm: Box<dyn Disassembler>,
    refs: GroupRefCache,
}

/// Per-group references for one parsed image, computed once. Ranged queries
/// binary-search the location-sorted list instead of re-scanning the
/// disassembler for every equivalence.
struct GroupRefCache {
    refs: Vec<Vec<Reference>>,
}

impl GroupRefCache {
    fn build(disasm: &dyn Disassembler, image: &[u8]) -> Result<Self> {
        let groups = disasm.groups();
        let size = disasm.size();
        let mut refs = Vec::new();
        refs.try_reserve_exact(groups.len())
            .map_err(|_| super::allocation_error("Zucchini reference groups"))?;
        for group in 0..groups.len() {
            refs.push(disasm.read(group, image, 0, size)?);
        }
        Ok(Self { refs })
    }

    fn full(&self, group: usize) -> &[Reference] {
        &self.refs[group]
    }

    fn range(&self, group: usize, lo: u32, hi: u32) -> &[Reference] {
        let refs = &self.refs[group];
        let start = refs.partition_point(|reference| reference.location < lo);
        let end = refs.partition_point(|reference| reference.location < hi);
        &refs[start..end]
    }
}

/// Parses the old element and caches its per-group references once.
pub(crate) fn analyze_element(exe_type: u32, old_element: &[u8]) -> Result<ElementAnalysis> {
    let disasm = make_disassembler(exe_type, old_element)
        .ok_or_else(|| apply_error("failed to create old disassembler"))?;
    let refs = GroupRefCache::build(&*disasm, old_element)?;
    Ok(ElementAnalysis { disasm, refs })
}

/// Splits the element's old and new regions out of the images.
pub(crate) fn element_regions<'a>(
    old: &'a [u8],
    element: &PatchElement,
    output: &'a mut [u8],
) -> Result<(&'a [u8], &'a mut [u8])> {
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
    Ok((old_element, new_element))
}

pub(crate) fn apply_element(
    element: &PatchElement,
    old_element: &[u8],
    new_element: &mut [u8],
    analysis: &ElementAnalysis,
    cancelled: &dyn Fn() -> bool,
) -> Result<()> {
    check_not_cancelled(cancelled)?;
    apply_equivalence_and_extra_data(old_element, element, new_element, cancelled)?;
    apply_raw_delta(element, new_element, cancelled)?;
    apply_references_correction(
        element.element_match.exe_type,
        old_element,
        element,
        new_element,
        &*analysis.disasm,
        &analysis.refs,
        cancelled,
    )?;
    Ok(())
}

/// Mirrors the native FFI's `PreflightAndroidElements` for one element: apply
/// equivalence/extra/raw data to a scratch output, then run the Android
/// boundary and DEX-target validations that upstream Zucchini does not.
pub(crate) fn preflight_element(
    element: &PatchElement,
    old_element: &[u8],
    new_element: &mut [u8],
    analysis: &ElementAnalysis,
    cancelled: &dyn Fn() -> bool,
) -> Result<()> {
    let exe_type = element.element_match.exe_type;
    if exe_type == EXE_TYPE_NOOP || !is_android_executable(exe_type) {
        return Ok(());
    }
    check_not_cancelled(cancelled)?;

    apply_equivalence_and_extra_data(old_element, element, new_element, cancelled)?;
    apply_raw_delta(element, new_element, cancelled)?;

    let old_disasm = &*analysis.disasm;
    let new_disasm = make_disassembler(exe_type, new_element)
        .ok_or_else(|| apply_error("failed to create new disassembler"))?;
    if old_disasm.size() != old_element.len() as u32
        || new_disasm.size() != new_element.len() as u32
    {
        return Err(apply_error("disassembler and element size mismatch"));
    }
    let new_size = new_element.len() as u32;
    if !validate_reference_boundaries(
        old_disasm,
        &analysis.refs,
        exe_type,
        element,
        new_size,
        cancelled,
    )? {
        return Err(apply_error("reference boundary violation"));
    }
    if exe_type == EXE_TYPE_DEX {
        if !dex::narrow_writer_widths_ok(new_element) {
            return Err(apply_error("dex writer width violation"));
        }
        if !validate_dex_reference_targets(
            old_disasm,
            &*new_disasm,
            &analysis.refs,
            element,
            new_element,
            cancelled,
        )? {
            return Err(apply_error("dex reference target violation"));
        }
    }
    Ok(())
}

/// Mirrors the FFI's `ValidateReferenceBoundaries`. Returns `Ok(true)` when the
/// element is safe, `Ok(false)` on a boundary violation, and `Err(Cancelled)`
/// if the caller cancels.
fn validate_reference_boundaries(
    old_disasm: &dyn Disassembler,
    cache: &GroupRefCache,
    exe_type: u32,
    element: &PatchElement,
    new_size: u32,
    cancelled: &dyn Fn() -> bool,
) -> Result<bool> {
    let mut boundaries: Vec<u32> = Vec::new();
    boundaries
        .try_reserve(element.equivalences.len().saturating_mul(2))
        .map_err(|_| super::allocation_error("Zucchini equivalence boundaries"))?;
    for equivalence in &element.equivalences {
        boundaries.push(equivalence.src_offset);
        boundaries.push(equivalence.src_end());
    }
    boundaries.sort_unstable();

    for (group_index, group) in old_disasm.groups().iter().enumerate() {
        check_not_cancelled(cancelled)?;
        let mut writer_width = group.width;
        if group.type_tag == 0 {
            match exe_type {
                EXE_TYPE_ELF_X86 | EXE_TYPE_ELF_AARCH32 => writer_width = 8,
                EXE_TYPE_ELF_X64 | EXE_TYPE_ELF_AARCH64 => writer_width = 16,
                _ => {}
            }
        }

        for reference in cache.full(group_index) {
            let boundary = boundaries.partition_point(|value| *value <= reference.location);
            if boundary < boundaries.len()
                && boundaries[boundary] < reference.location.wrapping_add(group.width)
            {
                return Ok(false);
            }
        }

        for equivalence in &element.equivalences {
            check_not_cancelled(cancelled)?;
            for reference in cache.range(group_index, equivalence.src_offset, equivalence.src_end())
            {
                if reference.location < equivalence.src_offset
                    || reference.location > equivalence.src_end()
                    || group.width > equivalence.src_end() - reference.location
                {
                    return Ok(false);
                }
                let projected = equivalence
                    .dst_offset
                    .wrapping_add(reference.location.wrapping_sub(equivalence.src_offset));
                if projected > new_size || writer_width > new_size - projected {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

/// Mirrors the FFI's `ValidateDexReferenceTargets`. Returns `Ok(true)` when the
/// targets are safe, `Ok(false)` on violation, and `Err(Cancelled)` otherwise.
fn validate_dex_reference_targets(
    old_disasm: &dyn Disassembler,
    new_disasm: &dyn Disassembler,
    cache: &GroupRefCache,
    element: &PatchElement,
    new_image: &[u8],
    cancelled: &dyn Fn() -> bool,
) -> Result<bool> {
    let Some(string_ids) = dex::string_ids(new_image) else { return Ok(false) };

    let mut pools: BTreeMap<u8, Vec<usize>> = BTreeMap::new();
    for (index, group) in old_disasm.groups().iter().enumerate() {
        pools.entry(group.pool_tag).or_default().push(index);
    }

    let mut deltas = element.reference_deltas.iter();
    let mapper =
        OffsetMapper::new(&element.equivalences, old_disasm.size(), new_image.len() as u32)?;

    for (pool_tag, sub_groups) in &pools {
        check_not_cancelled(cancelled)?;
        let mut targets = TargetPool::default();
        for &group_index in sub_groups {
            targets.insert_references(cache.full(group_index))?;
        }
        targets.filter_and_project(&mapper)?;
        if let Some(extra) = element.extra_targets.get(pool_tag) {
            targets.insert_targets(&extra.targets)?;
            if !extra.done {
                return Ok(false);
            }
        }

        for &group_index in sub_groups {
            let type_tag = old_disasm.groups()[group_index].type_tag;
            if usize::from(type_tag) >= new_disasm.groups().len() {
                return Ok(false);
            }
            for equivalence in &element.equivalences {
                check_not_cancelled(cancelled)?;
                for reference in
                    cache.range(group_index, equivalence.src_offset, equivalence.src_end())
                {
                    let projected = mapper.extended_forward_project(reference.target);
                    let expected = targets.key_for_nearest_offset(projected);
                    let Some(delta) = deltas.next() else { return Ok(false) };
                    let key = i64::from(expected) + i64::from(*delta);
                    if !(0..=i64::from(u32::MAX)).contains(&key) {
                        return Ok(false);
                    }
                    let key = key as u32;
                    if !targets.key_is_valid(key) {
                        return Ok(false);
                    }
                    if type_tag == 5 {
                        let target = targets.offset_for_key(key);
                        if target < string_ids.offset
                            || (target - string_ids.offset) % 4 != 0
                            || (target - string_ids.offset) / 4 > u32::from(u16::MAX)
                        {
                            return Ok(false);
                        }
                    }
                }
            }
        }
    }

    Ok(deltas.next().is_none() && element.reference_deltas_done)
}

/// Mirrors `ApplyEquivalenceAndExtraData`.
fn apply_equivalence_and_extra_data(
    old_image: &[u8],
    element: &PatchElement,
    new_image: &mut [u8],
    cancelled: &dyn Fn() -> bool,
) -> Result<()> {
    let mut extra_cursor = 0usize;
    let mut dst_it = 0usize;

    for equivalence in &element.equivalences {
        check_not_cancelled(cancelled)?;
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
    let end = cursor.checked_add(size).ok_or_else(|| apply_error("extra data length overflow"))?;
    let slice = extra.get(*cursor..end).ok_or_else(|| apply_error("extra data exhausted"))?;
    *cursor = end;
    Ok(slice)
}

/// Mirrors `ApplyRawDelta`.
fn apply_raw_delta(
    element: &PatchElement,
    new_image: &mut [u8],
    cancelled: &dyn Fn() -> bool,
) -> Result<()> {
    let mut base_copy_offset: u32 = 0;
    let mut equivalence_index = 0usize;

    for delta in &element.raw_deltas {
        check_not_cancelled(cancelled)?;
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
    old_disasm: &dyn Disassembler,
    cache: &GroupRefCache,
    cancelled: &dyn Fn() -> bool,
) -> Result<()> {
    check_not_cancelled(cancelled)?;
    let new_disasm = make_disassembler(exe_type, new_image)
        .ok_or_else(|| apply_error("failed to create new disassembler"))?;
    if old_disasm.size() != old_image.len() as u32 || new_disasm.size() != new_image.len() as u32 {
        return Err(apply_error("disassembler and element size mismatch"));
    }

    let old_groups = old_disasm.groups();
    let new_groups = new_disasm.groups();
    let mapper =
        OffsetMapper::new(&element.equivalences, old_image.len() as u32, new_image.len() as u32)?;

    let mut pools: BTreeMap<u8, Vec<usize>> = BTreeMap::new();
    for (index, group) in old_groups.iter().enumerate() {
        pools.entry(group.pool_tag).or_default().push(index);
    }

    let mut deltas = element.reference_deltas.iter();
    for (pool_tag, sub_groups) in &pools {
        check_not_cancelled(cancelled)?;
        let mut targets = TargetPool::default();
        for &group_index in sub_groups {
            targets.insert_references(cache.full(group_index))?;
        }
        targets.filter_and_project(&mapper)?;

        if let Some(extra) = element.extra_targets.get(pool_tag) {
            targets.insert_targets(&extra.targets)?;
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
                check_not_cancelled(cancelled)?;
                for &reference in
                    cache.range(group_index, equivalence.src_offset, equivalence.src_end())
                {
                    check_not_cancelled(cancelled)?;
                    let mut reference = reference;
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
    fn new(source: &[Equivalence], old_image_size: u32, new_image_size: u32) -> Result<Self> {
        let mut equivalences = Vec::new();
        equivalences
            .try_reserve_exact(source.len())
            .map_err(|_| super::allocation_error("Zucchini equivalences"))?;
        equivalences.extend_from_slice(source);
        PruneEquivalencesAndSortBySource::prune(&mut equivalences);
        Ok(Self { equivalences, old_image_size, new_image_size })
    }

    fn naive_extended_forward_project(&self, unit: &Equivalence, offset: u32) -> u32 {
        let value = offset as i64 - unit.src_offset as i64 + unit.dst_offset as i64;
        let clamped = value.clamp(0, self.new_image_size as i64 - 1);
        clamped as u32
    }

    fn extended_forward_project(&self, offset: u32) -> u32 {
        if offset < self.old_image_size {
            // First equivalence with `src_offset > offset`.
            let pos =
                self.equivalences.partition_point(|equivalence| equivalence.src_offset <= offset);
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
            if current < self.equivalences.len() && self.equivalences[current].src_offset <= *source
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

/// Reproduces the permutation produced by libstdc++'s `std::sort` when the
/// comparator only orders by `src_offset`.
///
/// Zucchini's reference-delta stream is generated with the native OffsetMapper,
/// whose `PruneEquivalencesAndSortBySource` calls `std::sort`. `std::sort` is
/// not stable, and the pruning is order-sensitive for equivalences that share a
/// `src_offset` (their post-prune order determines which one a projection
/// picks). A stable Rust sort produces a different projection and diverges from
/// native output, so the exact native permutation must be reproduced. This is
/// a direct port of libstdc++ `__introsort_loop` / `__final_insertion_sort`
/// with the `__partial_sort` heap fallback.
#[allow(clippy::many_single_char_names)]
mod stdcpp {
    use super::Equivalence;

    const THRESHOLD: usize = 16;

    #[inline]
    fn comp(a: &Equivalence, b: &Equivalence) -> bool {
        a.src_offset < b.src_offset
    }

    fn lg(n: usize) -> u32 {
        (usize::BITS - 1) - n.leading_zeros()
    }

    fn move_median_to_first(v: &mut [Equivalence], result: usize, a: usize, b: usize, c: usize) {
        if comp(&v[a], &v[b]) {
            if comp(&v[b], &v[c]) {
                v.swap(result, b);
            } else if comp(&v[a], &v[c]) {
                v.swap(result, c);
            } else {
                v.swap(result, a);
            }
        } else if comp(&v[a], &v[c]) {
            v.swap(result, a);
        } else if comp(&v[b], &v[c]) {
            v.swap(result, c);
        } else {
            v.swap(result, b);
        }
    }

    fn unguarded_partition(
        v: &mut [Equivalence],
        mut first: usize,
        mut last: usize,
        pivot: usize,
    ) -> usize {
        loop {
            while comp(&v[first], &v[pivot]) {
                first += 1;
            }
            last -= 1;
            while comp(&v[pivot], &v[last]) {
                last -= 1;
            }
            if first >= last {
                return first;
            }
            v.swap(first, last);
            first += 1;
        }
    }

    fn unguarded_partition_pivot(v: &mut [Equivalence], first: usize, last: usize) -> usize {
        let mid = first + (last - first) / 2;
        move_median_to_first(v, first, first + 1, mid, last - 1);
        unguarded_partition(v, first + 1, last, first)
    }

    fn unguarded_linear_insert(v: &mut [Equivalence], mut last: usize) {
        let value = v[last];
        let mut next = last - 1;
        while comp(&value, &v[next]) {
            v[last] = v[next];
            last = next;
            next -= 1;
        }
        v[last] = value;
    }

    fn insertion_sort(v: &mut [Equivalence], first: usize, last: usize) {
        if first == last {
            return;
        }
        for i in (first + 1)..last {
            if comp(&v[i], &v[first]) {
                let value = v[i];
                let mut j = i;
                while j > first {
                    v[j] = v[j - 1];
                    j -= 1;
                }
                v[first] = value;
            } else {
                unguarded_linear_insert(v, i);
            }
        }
    }

    fn unguarded_insertion_sort(v: &mut [Equivalence], first: usize, last: usize) {
        for i in first..last {
            unguarded_linear_insert(v, i);
        }
    }

    fn final_insertion_sort(v: &mut [Equivalence], first: usize, last: usize) {
        if last - first > THRESHOLD {
            insertion_sort(v, first, first + THRESHOLD);
            unguarded_insertion_sort(v, first + THRESHOLD, last);
        } else {
            insertion_sort(v, first, last);
        }
    }

    fn push_heap(v: &mut [Equivalence], mut hole: usize, top: usize, value: Equivalence) {
        let mut parent = (hole - 1) / 2;
        while hole > top && comp(&v[parent], &value) {
            v[hole] = v[parent];
            hole = parent;
            parent = (hole - 1) / 2;
        }
        v[hole] = value;
    }

    fn adjust_heap(v: &mut [Equivalence], mut hole: usize, len: usize, value: Equivalence) {
        let top = hole;
        let mut second = hole;
        while second < (len - 1) / 2 {
            second = 2 * (second + 1);
            if comp(&v[second], &v[second - 1]) {
                second -= 1;
            }
            v[hole] = v[second];
            hole = second;
        }
        if len & 1 == 0 && second == (len - 2) / 2 {
            second = 2 * (second + 1);
            v[hole] = v[second - 1];
            hole = second - 1;
        }
        push_heap(v, hole, top, value);
    }

    fn pop_heap(v: &mut [Equivalence], last: usize) {
        // [0, last) is the heap; `last` is the element being removed.
        let value = v[last];
        v[last] = v[0];
        adjust_heap(&mut v[..last], 0, last, value);
    }

    fn heapsort(v: &mut [Equivalence]) {
        if v.len() < 2 {
            return;
        }
        let len = v.len();
        let mut parent = (len - 2) / 2;
        loop {
            let value = v[parent];
            adjust_heap(v, parent, len, value);
            if parent == 0 {
                break;
            }
            parent -= 1;
        }
        let mut last = len;
        while last > 1 {
            last -= 1;
            pop_heap(v, last);
        }
    }

    fn introsort_loop(v: &mut [Equivalence], first: usize, mut last: usize, mut depth: u32) {
        while last - first > THRESHOLD {
            if depth == 0 {
                heapsort(&mut v[first..last]);
                return;
            }
            depth -= 1;
            let cut = unguarded_partition_pivot(v, first, last);
            introsort_loop(v, cut, last, depth);
            last = cut;
        }
    }

    pub(super) fn sort_by_src(v: &mut [Equivalence]) {
        let n = v.len();
        if n > 1 {
            introsort_loop(v, 0, n, lg(n) * 2);
            final_insertion_sort(v, 0, n);
        }
    }
}

/// Mirrors `OffsetMapper::PruneEquivalencesAndSortBySource`.
struct PruneEquivalencesAndSortBySource;

impl PruneEquivalencesAndSortBySource {
    fn prune(equivalences: &mut Vec<Equivalence>) {
        stdcpp::sort_by_src(equivalences);

        let mut current = 0usize;
        while current < equivalences.len() {
            let mut next_is_reaper = false;
            let mut next = current + 1;
            while next < equivalences.len() {
                if equivalences[next].src_offset >= equivalences[current].src_end() {
                    break;
                }
                if equivalences[current].length < equivalences[next].length {
                    let delta = equivalences[current].src_end() - equivalences[next].src_offset;
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
                    let delta = equivalences[current].src_end() - equivalences[reduced].src_offset;
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

    fn insert_references(&mut self, references: &[Reference]) -> Result<()> {
        self.targets
            .try_reserve(references.len())
            .map_err(|_| super::allocation_error("Zucchini target pool"))?;
        self.targets.extend(references.iter().map(|reference| reference.target));
        self.sort_and_uniquify();
        Ok(())
    }

    fn insert_targets(&mut self, targets: &[u32]) -> Result<()> {
        self.targets
            .try_reserve(targets.len())
            .map_err(|_| super::allocation_error("Zucchini target pool"))?;
        self.targets.extend_from_slice(targets);
        self.sort_and_uniquify();
        Ok(())
    }

    fn filter_and_project(&mut self, mapper: &OffsetMapper) -> Result<()> {
        mapper.forward_project_all(&mut self.targets);
        self.targets.sort_unstable();
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// The cached per-group references must equal what a fresh ranged read
    /// returns for every group and range.
    #[test]
    fn group_ref_cache_matches_ranged_reads() {
        let fixtures = "tests/fixtures/zucchini";
        for (name, exe_type) in [
            ("elf-old", EXE_TYPE_ELF_X64),
            ("elf-arm32-old", EXE_TYPE_ELF_AARCH32),
            ("elf-arm64-old", EXE_TYPE_ELF_AARCH64),
            ("dex-old.dex", EXE_TYPE_DEX),
            ("dex-large-old.dex", EXE_TYPE_DEX),
        ] {
            let Ok(image) = fs::read(format!("{fixtures}/{name}")) else { continue };
            let disasm = make_disassembler(exe_type, &image).unwrap();
            let cache = GroupRefCache::build(&*disasm, &image).unwrap();
            let size = disasm.size();
            let ranges = [(0, size), (0, size / 3), (size / 3, size * 2 / 3), (size * 2 / 3, size)];
            for group in 0..disasm.groups().len() {
                for &(lo, hi) in &ranges {
                    if lo > hi || hi > size {
                        continue;
                    }
                    let expected = disasm.read(group, &image, lo, hi).unwrap();
                    assert_eq!(
                        cache.range(group, lo, hi),
                        expected.as_slice(),
                        "{name} group {group} range {lo}..{hi}"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod native_sort_tests {
    use super::*;

    /// Guards the libstdc++ `std::sort` port: the native permutation of
    /// equal-`src_offset` equivalences is what the reference-delta stream
    /// depends on, so the expected order below was produced by compiling
    /// `PruneEquivalencesAndSortBySource`'s `std::sort` comparator with
    /// libstdc++ on this 48-element tie-heavy input.
    #[test]
    fn sort_reproduces_native_tie_order() {
        let input: [(u32, u32, u32); 48] = [
            (0, 1000, 1),
            (5, 1001, 2),
            (10, 1002, 3),
            (15, 1003, 4),
            (6, 1004, 5),
            (11, 1005, 1),
            (16, 1006, 2),
            (4, 1007, 3),
            (12, 1008, 4),
            (0, 1009, 5),
            (5, 1010, 1),
            (10, 1011, 2),
            (1, 1012, 3),
            (6, 1013, 4),
            (11, 1014, 5),
            (16, 1015, 1),
            (7, 1016, 2),
            (12, 1017, 3),
            (0, 1018, 4),
            (5, 1019, 5),
            (13, 1020, 1),
            (1, 1021, 2),
            (6, 1022, 3),
            (11, 1023, 4),
            (2, 1024, 5),
            (7, 1025, 1),
            (12, 1026, 2),
            (0, 1027, 3),
            (8, 1028, 4),
            (13, 1029, 5),
            (1, 1030, 1),
            (6, 1031, 2),
            (14, 1032, 3),
            (2, 1033, 4),
            (7, 1034, 5),
            (12, 1035, 1),
            (3, 1036, 2),
            (8, 1037, 3),
            (13, 1038, 4),
            (1, 1039, 5),
            (9, 1040, 1),
            (14, 1041, 2),
            (2, 1042, 3),
            (7, 1043, 4),
            (15, 1044, 5),
            (3, 1045, 1),
            (8, 1046, 2),
            (13, 1047, 3),
        ];
        let expected: [(u32, u32, u32); 48] = [
            (0, 1000, 1),
            (0, 1009, 5),
            (0, 1027, 3),
            (0, 1018, 4),
            (1, 1039, 5),
            (1, 1030, 1),
            (1, 1012, 3),
            (1, 1021, 2),
            (2, 1042, 3),
            (2, 1033, 4),
            (2, 1024, 5),
            (3, 1045, 1),
            (3, 1036, 2),
            (4, 1007, 3),
            (5, 1001, 2),
            (5, 1019, 5),
            (5, 1010, 1),
            (6, 1004, 5),
            (6, 1031, 2),
            (6, 1022, 3),
            (6, 1013, 4),
            (7, 1025, 1),
            (7, 1016, 2),
            (7, 1043, 4),
            (7, 1034, 5),
            (8, 1037, 3),
            (8, 1028, 4),
            (8, 1046, 2),
            (9, 1040, 1),
            (10, 1011, 2),
            (10, 1002, 3),
            (11, 1014, 5),
            (11, 1023, 4),
            (11, 1005, 1),
            (12, 1008, 4),
            (12, 1035, 1),
            (12, 1017, 3),
            (12, 1026, 2),
            (13, 1047, 3),
            (13, 1038, 4),
            (13, 1029, 5),
            (13, 1020, 1),
            (14, 1041, 2),
            (14, 1032, 3),
            (15, 1003, 4),
            (15, 1044, 5),
            (16, 1006, 2),
            (16, 1015, 1),
        ];
        let mut values: Vec<Equivalence> = input
            .iter()
            .map(|&(src_offset, dst_offset, length)| Equivalence { src_offset, dst_offset, length })
            .collect();
        stdcpp::sort_by_src(&mut values);
        let got: Vec<(u32, u32, u32)> =
            values.iter().map(|e| (e.src_offset, e.dst_offset, e.length)).collect();
        assert_eq!(got, expected);
    }
}
