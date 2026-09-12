//! Pure-Rust port of `disassembler_elf.cc` + `reloc_elf.cc` + `abs32_utils.cc`
//! + `rel32_utils.cc` + `rel32_finder.cc` + `address_translator.cc` for apply.

use super::arm;
use super::bytes::{
    align_ceil, increment_for_align_ceil2, increment_for_align_ceil4, range_covers,
    range_is_bounded, read_i32, read_u16, read_u32, read_u64, write_u16, write_u32, write_u64,
};
use super::{
    Disassembler, GroupTraits, K_INVALID_OFFSET, K_INVALID_RVA, OFFSET_BOUND, Reference, Result,
};

const K_RVA_BOUND: u32 = 0x7FFF_FFFF;
const K_SIZE_BOUND: u64 = 0x7FFF_0000;

/// Fallible push: only grows the vector through `try_reserve`.
fn push_checked<T>(vec: &mut Vec<T>, value: T) -> Option<()> {
    if vec.len() == vec.capacity() {
        vec.try_reserve(1).ok()?;
    }
    vec.push(value);
    Some(())
}

const SHT_PROGBITS: u32 = 1;
const SHT_RELA: u32 = 4;
const SHT_NOBITS: u32 = 8;
const SHT_REL: u32 = 9;
const SHF_EXECINSTR: u64 = 1 << 2;
const SHF_TLS: u64 = 1 << 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfKind {
    X86,
    X64,
    AArch32,
    AArch64,
}

impl ElfKind {
    fn bitness(self) -> u32 {
        match self {
            ElfKind::X86 | ElfKind::AArch32 => 4,
            ElfKind::X64 | ElfKind::AArch64 => 8,
        }
    }

    fn class(self) -> u8 {
        match self {
            ElfKind::X86 | ElfKind::AArch32 => 1,
            ElfKind::X64 | ElfKind::AArch64 => 2,
        }
    }

    fn machine(self) -> u16 {
        match self {
            ElfKind::X86 => 3,
            ElfKind::X64 => 62,
            ElfKind::AArch32 => 40,
            ElfKind::AArch64 => 183,
        }
    }

    fn shdr_size(self) -> u16 {
        match self {
            ElfKind::X86 | ElfKind::AArch32 => 40,
            ElfKind::X64 | ElfKind::AArch64 => 64,
        }
    }

    fn phdr_size(self) -> u16 {
        match self {
            ElfKind::X86 | ElfKind::AArch32 => 32,
            ElfKind::X64 | ElfKind::AArch64 => 56,
        }
    }

    fn rel_type(self) -> u32 {
        match self {
            ElfKind::X86 | ElfKind::X64 => 8,
            ElfKind::AArch32 => 23,
            ElfKind::AArch64 => 0x403,
        }
    }

    fn va_width(self) -> u32 {
        self.bitness()
    }

    fn is_arm(self) -> bool {
        matches!(self, ElfKind::AArch32 | ElfKind::AArch64)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct SectionHeader {
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_entsize: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct RelocSection {
    offset: u32,
    size: u32,
    entry_size: u32,
}

#[derive(Clone, Copy, Debug, Default)]
struct ExecHeader {
    offset: u32,
    size: u32,
    addr: u32,
}

#[derive(Clone, Copy, Debug, Default)]
struct Unit {
    offset_begin: u32,
    offset_size: u32,
    rva_begin: u32,
    rva_size: u32,
}

impl Unit {
    fn offset_end(&self) -> u32 {
        self.offset_begin.wrapping_add(self.offset_size)
    }

    fn rva_end(&self) -> u32 {
        self.rva_begin.wrapping_add(self.rva_size)
    }

    fn covers_offset(&self, offset: u32) -> bool {
        range_covers(u64::from(self.offset_begin), u64::from(self.offset_size), u64::from(offset))
    }

    fn covers_rva(&self, rva: u32) -> bool {
        range_covers(u64::from(self.rva_begin), u64::from(self.rva_size), u64::from(rva))
    }

    fn has_dangling_rva(&self) -> bool {
        self.rva_size > self.offset_size
    }

    fn covers_dangling_rva(&self, rva: u32) -> bool {
        self.covers_rva(rva) && rva - self.rva_begin >= self.offset_size
    }

    fn offset_to_rva_unsafe(&self, offset: u32) -> u32 {
        offset.wrapping_sub(self.offset_begin).wrapping_add(self.rva_begin)
    }

    fn rva_to_offset_unsafe(&self, rva: u32, fake_offset_begin: u32) -> u32 {
        let delta = rva.wrapping_sub(self.rva_begin);
        if delta < self.offset_size {
            delta.wrapping_add(self.offset_begin)
        } else {
            fake_offset_begin.wrapping_add(rva)
        }
    }
}

#[derive(Clone, Debug, Default)]
struct AddressTranslator {
    by_offset: Vec<Unit>,
    by_rva: Vec<Unit>,
    fake_offset_begin: u32,
}

impl AddressTranslator {
    fn initialize(&mut self, mut units: Vec<Unit>) -> bool {
        for unit in &mut units {
            if !range_is_bounded(
                u64::from(unit.offset_begin),
                u64::from(unit.offset_size),
                u64::from(K_RVA_BOUND),
            ) || !range_is_bounded(
                u64::from(unit.rva_begin),
                u64::from(unit.rva_size),
                u64::from(K_RVA_BOUND),
            ) {
                return false;
            }
            unit.offset_size = unit.offset_size.min(unit.rva_size);
        }
        units.retain(|unit| unit.rva_size != 0);

        units.sort_by_key(|unit| (unit.rva_begin, unit.rva_size));
        units.dedup_by(|a, b| a.rva_begin == b.rva_begin && a.rva_size == b.rva_size);

        if units.len() > 1 {
            let mut slow = 0usize;
            for fast in 1..units.len() {
                if units[slow].rva_end() < units[fast].rva_begin {
                    slow += 1;
                    units[slow] = units[fast];
                    continue;
                }
                let merge_optional = units[slow].rva_end() == units[fast].rva_begin;
                if units[fast].offset_begin < units[slow].offset_begin
                    || units[fast].offset_begin.wrapping_sub(units[slow].offset_begin)
                        != units[fast].rva_begin.wrapping_sub(units[slow].rva_begin)
                {
                    if merge_optional {
                        slow += 1;
                        units[slow] = units[fast];
                        continue;
                    }
                    return false;
                }
                let dangling_mismatch = (units[fast].has_dangling_rva()
                    && units[fast].offset_end() < units[slow].offset_end())
                    || (units[slow].has_dangling_rva()
                        && units[slow].offset_end() < units[fast].offset_end());
                if dangling_mismatch {
                    if merge_optional {
                        slow += 1;
                        units[slow] = units[fast];
                        continue;
                    }
                    return false;
                }
                units[slow].rva_size = units[slow]
                    .rva_size
                    .max(units[fast].rva_end().wrapping_sub(units[slow].rva_begin));
                units[slow].offset_size = units[slow]
                    .offset_size
                    .max(units[fast].offset_end().wrapping_sub(units[slow].offset_begin));
            }
            slow += 1;
            units.truncate(slow);
        }

        units.sort_by_key(|unit| unit.offset_begin);
        for pair in units.windows(2) {
            if pair[0].offset_end() > pair[1].offset_begin {
                return false;
            }
        }

        let mut offset_bound = 0u32;
        let mut rva_bound = 0u32;
        for unit in &units {
            offset_bound = offset_bound.max(unit.offset_end());
            rva_bound = rva_bound.max(unit.rva_end());
        }
        if !range_is_bounded(u64::from(offset_bound), u64::from(rva_bound), u64::from(K_RVA_BOUND))
        {
            return false;
        }

        self.by_offset = Vec::new();
        if self.by_offset.try_reserve_exact(units.len()).is_err() {
            return false;
        }
        self.by_offset.extend_from_slice(&units);
        units.sort_by_key(|unit| unit.rva_begin);
        self.by_rva = units;
        self.fake_offset_begin = offset_bound;
        true
    }

    fn offset_to_unit(&self, offset: u32) -> Option<&Unit> {
        let index = self.by_offset.partition_point(|unit| unit.offset_begin <= offset);
        if index == 0 {
            return None;
        }
        let unit = &self.by_offset[index - 1];
        unit.covers_offset(offset).then_some(unit)
    }

    fn rva_to_unit(&self, rva: u32) -> Option<&Unit> {
        let index = self.by_rva.partition_point(|unit| unit.rva_begin <= rva);
        if index == 0 {
            return None;
        }
        let unit = &self.by_rva[index - 1];
        unit.covers_rva(rva).then_some(unit)
    }

    fn offset_to_rva(&self, offset: u32) -> Option<u32> {
        if offset >= self.fake_offset_begin {
            let rva = offset.wrapping_sub(self.fake_offset_begin);
            return match self.rva_to_unit(rva) {
                Some(unit) if unit.has_dangling_rva() && unit.covers_dangling_rva(rva) => Some(rva),
                _ => None,
            };
        }
        self.offset_to_unit(offset).map(|unit| unit.offset_to_rva_unsafe(offset))
    }

    fn rva_to_offset(&self, rva: u32) -> Option<u32> {
        self.rva_to_unit(rva).map(|unit| unit.rva_to_offset_unsafe(rva, self.fake_offset_begin))
    }
}

pub struct ElfDisassembler {
    kind: ElfKind,
    size: u32,
    groups: Vec<GroupTraits>,
    translator: AddressTranslator,
    reloc_sections: Vec<RelocSection>,
    exec_headers: Vec<ExecHeader>,
    abs32_locations: Vec<u32>,
    /// Rel32 locations per address type. Intel uses index 0 only.
    rel32_locations: Vec<Vec<u32>>,
}

impl ElfDisassembler {
    pub fn parse(kind: ElfKind, image: &[u8]) -> Option<Self> {
        let (sections, offset_bound) = parse_elf_header(kind, image)?;

        let mut units = Vec::new();
        units.try_reserve_exact(sections.len()).ok()?;
        let mut judgements = Vec::new();
        judgements.try_reserve_exact(sections.len()).ok()?;
        judgements.resize(sections.len(), 0i32);
        let mut offset_bound = offset_bound;

        for (index, section) in sections.iter().enumerate() {
            let judgement = judge_section(kind, image.len() as u64, section);
            judgements[index] = judgement;
            if judgement & 1 == 0 {
                return None;
            }
            let sh_size = section.sh_size as u32;
            let sh_offset = section.sh_offset as u32;
            let sh_addr = section.sh_addr as u32;
            if judgement & (1 << 1) != 0 {
                units.push(Unit {
                    offset_begin: sh_offset,
                    offset_size: sh_size,
                    rva_begin: sh_addr,
                    rva_size: sh_size,
                });
            }
            if judgement & (1 << 2) != 0 {
                let end = sh_offset.checked_add(sh_size)?;
                offset_bound = offset_bound.max(end);
            }
        }

        let mut translator = AddressTranslator::default();
        if !translator.initialize(units) {
            return None;
        }

        let mut disassembler = ElfDisassembler {
            kind,
            size: offset_bound,
            groups: build_groups(kind),
            translator,
            reloc_sections: Vec::new(),
            exec_headers: Vec::new(),
            abs32_locations: Vec::new(),
            rel32_locations: vec![Vec::new(); rel32_type_count(kind)],
        };

        disassembler.extract_interesting_section_headers(&sections, &judgements)?;
        disassembler.get_abs32_from_reloc_sections(image)?;
        disassembler.get_rel32_from_code_sections(image)?;
        Some(disassembler)
    }

    fn extract_interesting_section_headers(
        &mut self,
        sections: &[SectionHeader],
        judgements: &[i32],
    ) -> Option<()> {
        self.reloc_sections.try_reserve(sections.len()).ok()?;
        self.exec_headers.try_reserve(sections.len()).ok()?;
        for (index, section) in sections.iter().enumerate() {
            if judgements[index] & (1 << 3) == 0 {
                continue;
            }
            if is_reloc_section(self.kind, section) {
                self.reloc_sections.push(RelocSection {
                    offset: section.sh_offset as u32,
                    size: section.sh_size as u32,
                    entry_size: section.sh_entsize as u32,
                });
            } else if is_exec_section(section) {
                self.exec_headers.push(ExecHeader {
                    offset: section.sh_offset as u32,
                    size: section.sh_size as u32,
                    addr: section.sh_addr as u32,
                });
            }
        }
        self.reloc_sections.sort_by_key(|section| section.offset);
        self.exec_headers.sort_by_key(|header| header.offset);
        Some(())
    }

    fn get_abs32_from_reloc_sections(&mut self, image: &[u8]) -> Option<()> {
        let relocs = self.read_relocs(image, 0, self.size).ok()?;
        let mut locations: Vec<u32> = Vec::new();
        locations.try_reserve_exact(relocs.len()).ok()?;
        locations.extend(relocs.iter().map(|reference| reference.target));
        locations.sort_unstable();

        // RemoveUntranslatableAbs32.
        let mut kept = Vec::new();
        kept.try_reserve_exact(locations.len()).ok()?;
        for location in locations {
            let value = self.read_absolute(location, image);
            let Some(value) = value else { continue };
            if value >= u64::from(K_RVA_BOUND) {
                continue;
            }
            let target_rva = value as u32;
            if self.translator.rva_to_offset(target_rva).is_some() {
                kept.push(location);
            }
        }
        locations = kept;

        // RemoveOverlappingAbs32Locations.
        remove_overlapping(self.kind.va_width(), &mut locations);
        self.abs32_locations = locations;
        Some(())
    }

    fn read_absolute(&self, offset: u32, image: &[u8]) -> Option<u64> {
        if self.kind.bitness() == 4 {
            read_u32(image, offset as usize).map(u64::from)
        } else {
            read_u64(image, offset as usize)
        }
    }

    fn get_rel32_from_code_sections(&mut self, image: &[u8]) -> Option<()> {
        let count = self.exec_headers.len();
        for index in 0..count {
            let section = self.exec_headers[index];
            if !self.kind.is_arm() {
                self.parse_exec_section_intel(&section, image)?;
            } else {
                self.parse_exec_section_arm(&section, image)?;
            }
        }
        for locations in self.rel32_locations.iter_mut() {
            locations.sort_unstable();
        }
        Some(())
    }

    fn parse_exec_section_intel(&mut self, section: &ExecHeader, image: &[u8]) -> Option<()> {
        let start_rva = section.addr;
        let end_rva = start_rva.wrapping_add(section.size);
        let Some(region) = image.get(section.offset as usize..) else { return Some(()) };
        let region = &region[..section.size.min(region.len() as u32) as usize];
        for (gap_start, gap_end) in
            self.abs32_gaps(section.offset, section.offset.wrapping_add(section.size))?
        {
            let mut cursor = gap_start as usize;
            let gap_end = gap_end as usize;
            while cursor < gap_end {
                let candidate = intel_candidate(self.kind, image, cursor, gap_end);
                if let Some((location, can_point_outside)) = candidate {
                    if let Some(location_rva) = self.translator.offset_to_rva(location as u32) {
                        let disp = read_u32(image, location).unwrap_or(0);
                        let target_rva = location_rva.wrapping_add(4).wrapping_add(disp);
                        if self.translator.rva_to_offset(target_rva).is_some()
                            && (can_point_outside
                                || (start_rva <= target_rva && target_rva < end_rva))
                        {
                            push_checked(&mut self.rel32_locations[0], location as u32)?;
                            cursor = location + 4;
                            continue;
                        }
                    }
                }
                cursor += 1;
            }
        }
        let _ = region;
        Some(())
    }

    fn parse_exec_section_arm(&mut self, section: &ExecHeader, image: &[u8]) -> Option<()> {
        let is_thumb2 = if self.kind == ElfKind::AArch32 {
            is_exec_section_thumb2(image, section)
        } else {
            false
        };
        let gaps = self.abs32_gaps(section.offset, section.offset.wrapping_add(section.size))?;
        for (gap_start, gap_end) in gaps {
            match self.kind {
                ElfKind::AArch32 => {
                    let mut cursor = align_gap_start_a32(gap_start, gap_end, is_thumb2);
                    let step = if is_thumb2 { 2 } else { 4 };
                    while cursor + step <= gap_end {
                        let location = cursor as u32;
                        let Some(instr_rva) = self.translator.offset_to_rva(location) else {
                            cursor += step;
                            continue;
                        };
                        let advancement = if is_thumb2 {
                            let (found, size) =
                                scan_thumb2(image, instr_rva, location, gap_end - cursor);
                            if let Some((addr_type, target_rva)) = found {
                                self.record_arm_rel32(addr_type, target_rva, location)?;
                            }
                            size
                        } else {
                            if let Some((addr_type, target_rva, _)) =
                                scan_arm32(image, instr_rva, location)
                            {
                                self.record_arm_rel32(addr_type, target_rva, location)?;
                            }
                            4
                        };
                        // Native always advances by the decoded instruction size,
                        // including when no reference type matches.
                        cursor += advancement as usize;
                    }
                }
                ElfKind::AArch64 => {
                    let mut cursor =
                        gap_start + increment_for_align_ceil4(gap_start as u64) as usize;
                    while cursor + 4 <= gap_end {
                        let location = cursor as u32;
                        if let Some(instr_rva) = self.translator.offset_to_rva(location) {
                            if let Some((addr_type, target_rva)) =
                                scan_aarch64(image, instr_rva, location)
                            {
                                if let Some(target_offset) =
                                    self.translator.rva_to_offset(target_rva)
                                {
                                    if self.is_target_in_exec_section(target_offset) {
                                        push_checked(
                                            &mut self.rel32_locations[addr_type as usize],
                                            location,
                                        )?;
                                    }
                                }
                            }
                        }
                        cursor += 4;
                    }
                }
                _ => unreachable!(),
            }
        }
        Some(())
    }

    fn record_arm_rel32(&mut self, addr_type: u8, target_rva: u32, location: u32) -> Option<()> {
        if let Some(target_offset) = self.translator.rva_to_offset(target_rva) {
            if self.is_target_in_exec_section(target_offset) {
                push_checked(&mut self.rel32_locations[addr_type as usize], location)?;
            }
        }
        Some(())
    }

    fn is_target_in_exec_section(&self, offset: u32) -> bool {
        let index = self.exec_headers.partition_point(|header| header.offset <= offset);
        if index == 0 {
            return false;
        }
        let header = self.exec_headers[index - 1];
        offset >= header.offset && offset - header.offset < header.size
    }

    /// Mirrors `Abs32GapFinder`: non-empty gaps in `[region_start, region_end)`
    /// that do not overlap an abs32 body.
    fn abs32_gaps(&self, region_start: u32, region_end: u32) -> Option<Vec<(usize, usize)>> {
        let width = self.kind.va_width();
        let mut gaps = Vec::new();
        gaps.try_reserve(self.abs32_locations.len().saturating_add(1)).ok()?;
        let mut current = self.abs32_locations.partition_point(|location| *location < region_start);
        let mut cur_lo = region_start;
        if current > 0 {
            let previous = self.abs32_locations[current - 1];
            cur_lo = cur_lo.max(previous.saturating_add(width));
        }
        while current < self.abs32_locations.len() && self.abs32_locations[current] < region_end {
            let hi = self.abs32_locations[current];
            if hi > cur_lo {
                gaps.push((cur_lo as usize, hi as usize));
            }
            cur_lo = hi.saturating_add(width);
            current += 1;
        }
        if cur_lo < region_end {
            gaps.push((cur_lo as usize, region_end as usize));
        }
        Some(gaps)
    }

    fn read_relocs(&self, image: &[u8], lo: u32, hi: u32) -> Result<Vec<Reference>> {
        if self.reloc_sections.is_empty() {
            return Ok(Vec::new());
        }
        let mut result = Vec::new();
        // Upper bound: one reference per relocation entry in the range.
        let upper = ((hi.saturating_sub(lo)) as usize) / 4 + 1;
        result
            .try_reserve(upper)
            .map_err(|_| super::allocation_error("ELF relocation references"))?;
        let bitness = self.kind.bitness();
        let rel_type = self.kind.rel_type();

        let mut current = self.reloc_sections.partition_point(|section| section.offset <= lo);
        if current > 0 {
            current -= 1;
        }
        let mut cursor = self.reloc_sections[current].offset;
        if cursor < lo {
            cursor += align_ceil(
                u64::from(lo - cursor),
                u64::from(self.reloc_sections[current].entry_size),
            ) as u32;
        }

        let mut hi = hi;
        let end_index = self.reloc_sections.partition_point(|section| section.offset <= hi);
        if end_index > 0 {
            let section = self.reloc_sections[end_index - 1];
            if hi - section.offset < section.size {
                hi = section.offset
                    + align_ceil(u64::from(hi - section.offset), u64::from(section.entry_size))
                        as u32;
            }
        }

        loop {
            while current < self.reloc_sections.len()
                && cursor >= self.reloc_sections[current].offset + self.reloc_sections[current].size
            {
                current += 1;
                if current == self.reloc_sections.len() {
                    return Ok(result);
                }
                cursor = self.reloc_sections[current].offset;
                if cursor + self.reloc_sections[current].entry_size > hi {
                    return Ok(result);
                }
            }
            if current >= self.reloc_sections.len() {
                return Ok(result);
            }
            let entry_size = self.reloc_sections[current].entry_size;
            if cursor + entry_size > hi {
                return Ok(result);
            }

            let (r_offset, r_info) = if bitness == 4 {
                (
                    read_u32(image, cursor as usize).unwrap_or(0),
                    read_u32(image, cursor as usize + 4).unwrap_or(0) as u64,
                )
            } else {
                (
                    read_u64(image, cursor as usize).unwrap_or(0) as u32,
                    read_u64(image, cursor as usize + 8).unwrap_or(0),
                )
            };
            let rel_type_value =
                if bitness == 4 { (r_info & 0xFF) as u32 } else { (r_info & 0xFFFF_FFFF) as u32 };
            if rel_type_value == rel_type {
                let valid_r_offset =
                    bitness == 4 || (r_offset as u64 & 0xFFFF_FFFF) == r_offset as u64;
                if valid_r_offset {
                    if let Some(target) = self.translator.rva_to_offset(r_offset) {
                        if range_covers(0, image.len() as u64, u64::from(target))
                            && target as usize + (bitness as usize) <= image.len()
                        {
                            result.push(Reference { location: cursor, target });
                        }
                    }
                }
            }
            cursor += entry_size;
        }
    }

    fn read_abs32(&self, image: &[u8], lo: u32, hi: u32) -> Result<Vec<Reference>> {
        let mut result = Vec::new();
        let start = self.abs32_locations.partition_point(|location| *location < lo);
        let end = self.abs32_locations.partition_point(|location| *location < hi);
        result
            .try_reserve(end.saturating_sub(start))
            .map_err(|_| super::allocation_error("ELF abs32 references"))?;
        for &location in &self.abs32_locations[start..end] {
            let Some(value) = self.read_absolute(location, image) else { continue };
            if value >= u64::from(K_RVA_BOUND) {
                continue;
            }
            if let Some(target) = self.translator.rva_to_offset(value as u32) {
                result.push(Reference { location, target });
            }
        }
        Ok(result)
    }

    fn read_rel32_intel(&self, image: &[u8], lo: u32, hi: u32) -> Result<Vec<Reference>> {
        let mut result = Vec::new();
        let locations = &self.rel32_locations[0];
        let start = locations.partition_point(|location| *location < lo);
        let end = locations.partition_point(|location| *location < hi);
        result
            .try_reserve(end.saturating_sub(start))
            .map_err(|_| super::allocation_error("ELF rel32 references"))?;
        for &location in &locations[start..end] {
            let Some(location_rva) = self.translator.offset_to_rva(location) else { continue };
            let disp = read_i32(image, location as usize).unwrap_or(0);
            let target_rva = location_rva.wrapping_add(4).wrapping_add(disp as u32);
            if let Some(target) = self.translator.rva_to_offset(target_rva) {
                result.push(Reference { location, target });
            }
        }
        Ok(result)
    }

    fn read_rel32_arm(
        &self,
        image: &[u8],
        addr_type: usize,
        lo: u32,
        hi: u32,
    ) -> Result<Vec<Reference>> {
        let mut result = Vec::new();
        let locations = &self.rel32_locations[addr_type];
        let start = locations.partition_point(|location| *location < lo);
        let end = locations.partition_point(|location| *location < hi);
        result
            .try_reserve(end.saturating_sub(start))
            .map_err(|_| super::allocation_error("ELF ARM rel32 references"))?;
        for &location in &locations[start..end] {
            let Some(instr_rva) = self.translator.offset_to_rva(location) else { continue };
            let target_rva = if self.kind == ElfKind::AArch32 {
                fetch_and_read_a32(image, addr_type, location, instr_rva)
            } else {
                fetch_and_read_a64(image, addr_type, location, instr_rva)
            };
            if let Some(target_rva) = target_rva {
                if let Some(target) = self.translator.rva_to_offset(target_rva) {
                    result.push(Reference { location, target });
                }
            }
        }
        Ok(result)
    }

    fn write_reloc(&self, image: &mut [u8], reference: Reference) {
        let target_rva = self.translator.offset_to_rva(reference.target).unwrap_or(K_INVALID_RVA);
        if self.kind.bitness() == 4 {
            let _ = write_u32(image, reference.location as usize, target_rva);
        } else {
            let _ = write_u64(image, reference.location as usize, u64::from(target_rva));
        }
    }

    fn write_abs32(&self, image: &mut [u8], reference: Reference) {
        let Some(target_rva) = self.translator.offset_to_rva(reference.target) else { return };
        if self.kind.bitness() == 4 {
            let _ = write_u32(image, reference.location as usize, target_rva);
        } else {
            let _ = write_u64(image, reference.location as usize, u64::from(target_rva));
        }
    }

    fn write_rel32_intel(&self, image: &mut [u8], reference: Reference) {
        let target_rva = self.translator.offset_to_rva(reference.target).unwrap_or(K_INVALID_RVA);
        let location_rva =
            self.translator.offset_to_rva(reference.location).unwrap_or(K_INVALID_RVA);
        let code = target_rva.wrapping_sub(location_rva.wrapping_add(4));
        let _ = write_u32(image, reference.location as usize, code);
    }

    fn write_rel32_arm(&self, image: &mut [u8], addr_type: usize, reference: Reference) {
        let instr_rva = self.translator.offset_to_rva(reference.location).unwrap_or(K_INVALID_RVA);
        let target_rva = self.translator.offset_to_rva(reference.target).unwrap_or(K_INVALID_RVA);
        if self.kind == ElfKind::AArch32 {
            write_arm32(image, addr_type, reference.location, instr_rva, target_rva);
        } else {
            write_aarch64(image, addr_type, reference.location, instr_rva, target_rva);
        }
    }
}

impl Disassembler for ElfDisassembler {
    fn size(&self) -> u32 {
        self.size
    }

    fn groups(&self) -> &[GroupTraits] {
        &self.groups
    }

    fn read(&self, group: usize, image: &[u8], lo: u32, hi: u32) -> Result<Vec<Reference>> {
        if group == 0 {
            return self.read_relocs(image, lo, hi);
        }
        if group == 1 {
            return self.read_abs32(image, lo, hi);
        }
        match self.kind {
            ElfKind::X86 | ElfKind::X64 => self.read_rel32_intel(image, lo, hi),
            ElfKind::AArch32 | ElfKind::AArch64 => {
                // Group index == address type index + 2 for ARM.
                let addr_type = group - 2;
                if addr_type < self.rel32_locations.len() {
                    self.read_rel32_arm(image, addr_type, lo, hi)
                } else {
                    Ok(Vec::new())
                }
            }
        }
    }

    fn write(&self, group: usize, image: &mut [u8], reference: Reference) {
        if group == 0 {
            self.write_reloc(image, reference);
        } else if group == 1 {
            self.write_abs32(image, reference);
        } else {
            match self.kind {
                ElfKind::X86 | ElfKind::X64 => self.write_rel32_intel(image, reference),
                ElfKind::AArch32 | ElfKind::AArch64 => {
                    self.write_rel32_arm(image, group - 2, reference);
                }
            }
        }
    }
}

fn rel32_type_count(kind: ElfKind) -> usize {
    match kind {
        ElfKind::X86 | ElfKind::X64 => 1,
        ElfKind::AArch32 => 5,
        ElfKind::AArch64 => 3,
    }
}

fn build_groups(kind: ElfKind) -> Vec<GroupTraits> {
    let mut groups = Vec::new();
    let reloc_width = kind.bitness();
    groups.push(GroupTraits { width: reloc_width, type_tag: 0, pool_tag: 0 });
    groups.push(GroupTraits { width: kind.va_width(), type_tag: 1, pool_tag: 1 });
    match kind {
        ElfKind::X86 | ElfKind::X64 => {
            groups.push(GroupTraits { width: 4, type_tag: 2, pool_tag: 2 });
        }
        ElfKind::AArch32 => {
            groups.push(GroupTraits { width: 4, type_tag: 2, pool_tag: 2 }); // A24
            groups.push(GroupTraits { width: 2, type_tag: 3, pool_tag: 2 }); // T8
            groups.push(GroupTraits { width: 2, type_tag: 4, pool_tag: 2 }); // T11
            groups.push(GroupTraits { width: 4, type_tag: 5, pool_tag: 2 }); // T20
            groups.push(GroupTraits { width: 4, type_tag: 6, pool_tag: 2 }); // T24
        }
        ElfKind::AArch64 => {
            groups.push(GroupTraits { width: 4, type_tag: 2, pool_tag: 2 }); // Immd14
            groups.push(GroupTraits { width: 4, type_tag: 3, pool_tag: 2 }); // Immd19
            groups.push(GroupTraits { width: 4, type_tag: 4, pool_tag: 2 }); // Immd26
        }
    }
    groups
}

fn judge_section(_kind: ElfKind, image_size: u64, section: &SectionHeader) -> i32 {
    // Bit flags mirror `SectionJudgement`.
    const SAFE: i32 = 1 << 0;
    const USEFUL_ADDRESS: i32 = 1 << 1;
    const USEFUL_BOUND: i32 = 1 << 2;
    const MAYBE_POINTERS: i32 = 1 << 3;
    const USELESS: i32 = SAFE;

    if !region_fits(section.sh_addr, section.sh_size, K_SIZE_BOUND) {
        return 0;
    }
    let offset_bound = if section.sh_type == SHT_NOBITS { K_SIZE_BOUND } else { image_size };
    if !region_fits(section.sh_offset, section.sh_size, offset_bound) {
        return 0;
    }
    if section.sh_size == 0 {
        return USELESS;
    }
    if section.sh_addr == 0 {
        return USELESS;
    }
    if section.sh_type == SHT_NOBITS {
        if section.sh_flags & SHF_TLS != 0 {
            return USELESS;
        }
        return SAFE | USEFUL_ADDRESS;
    }
    SAFE | USEFUL_ADDRESS | USEFUL_BOUND | MAYBE_POINTERS
}

fn region_fits(offset: u64, size: u64, container: u64) -> bool {
    offset <= container && container - offset >= size
}

fn is_reloc_section(kind: ElfKind, section: &SectionHeader) -> bool {
    if section.sh_type == SHT_REL {
        return section.sh_entsize == kind.bitness() as u64 * 2;
    }
    if section.sh_type == SHT_RELA {
        return section.sh_entsize == kind.bitness() as u64 * 2 + kind.bitness() as u64;
    }
    false
}

fn is_exec_section(section: &SectionHeader) -> bool {
    section.sh_type == SHT_PROGBITS && section.sh_flags & SHF_EXECINSTR != 0
}

fn remove_overlapping(width: u32, locations: &mut Vec<u32>) {
    if locations.len() <= 1 {
        return;
    }
    let mut slow = 0usize;
    let mut fast = 1usize;
    loop {
        while fast < locations.len() && locations[fast] - locations[slow] < width {
            fast += 1;
        }
        slow += 1;
        if fast == locations.len() {
            break;
        }
        if slow != fast {
            locations[slow] = locations[fast];
        }
        fast += 1;
    }
    locations.truncate(slow);
}

/// Parses the ELF header, section table, program table, and derives the
/// `offset_bound` estimate. Mirrors `DisassemblerElf::ParseHeader`.
fn parse_elf_header(kind: ElfKind, image: &[u8]) -> Option<(Vec<SectionHeader>, u32)> {
    if u64::from(kind.class()) != 0 {
        // QuickDetect checks.
        if image.len() < 16 || &image[..4] != b"\x7FELF" {
            return None;
        }
        if image[4] != kind.class() || image[5] != 1 {
            return None;
        }
        let e_type = read_u16(image, 16)?;
        if e_type != 2 && e_type != 3 {
            return None;
        }
        let e_machine = read_u16(image, 18)?;
        let e_version = read_u32(image, 20)?;
        if e_version != 1 || image[6] != 1 || e_machine != kind.machine() {
            return None;
        }
        let e_shentsize = read_u16(image, if kind.class() == 2 { 58 } else { 46 })?;
        if e_shentsize != kind.shdr_size() {
            return None;
        }
    }

    let (e_shoff, e_phoff, e_shnum, e_phnum, e_shstrndx, e_phentsize) = if kind.class() == 2 {
        (
            read_u64(image, 40)?,
            read_u64(image, 32)?,
            read_u16(image, 60)?,
            read_u16(image, 56)?,
            read_u16(image, 62)?,
            read_u16(image, 54)?,
        )
    } else {
        (
            u64::from(read_u32(image, 32)?),
            u64::from(read_u32(image, 28)?),
            read_u16(image, 48)?,
            read_u16(image, 44)?,
            read_u16(image, 50)?,
            read_u16(image, 42)?,
        )
    };
    if e_phentsize != kind.phdr_size() {
        // Not part of QuickDetect, but the array read would fail anyway.
    }

    let sections_count = e_shnum as usize;
    let shdr_size = kind.shdr_size() as usize;
    let sections_start = usize::try_from(e_shoff).ok()?;
    let sections_end = sections_start.checked_add(sections_count.checked_mul(shdr_size)?)?;
    if sections_end > image.len() {
        return None;
    }
    let mut sections = Vec::new();
    sections.try_reserve(sections_count).ok()?;
    for index in 0..sections_count {
        let base = sections_start + index * shdr_size;
        sections.push(parse_shdr(kind, image, base)?);
    }
    let section_table_end = sections_end as u32;

    let segments_count = e_phnum as usize;
    let phdr_size = kind.phdr_size() as usize;
    let segments_start = usize::try_from(e_phoff).ok()?;
    let segments_end = segments_start.checked_add(segments_count.checked_mul(phdr_size)?)?;
    if segments_end > image.len() {
        return None;
    }
    let segment_table_end = segments_end as u32;

    // String section check.
    let string_section_id = e_shstrndx as usize;
    if string_section_id >= sections_count {
        return None;
    }
    let section_names_size = sections[string_section_id].sh_size;
    if section_names_size > 0 {
        let offset = usize::try_from(sections[string_section_id].sh_offset).ok()?;
        let end = offset.checked_add(usize::try_from(section_names_size).ok()?)?;
        let names = image.get(offset..end)?;
        if *names.last()? != 0 {
            return None;
        }
    }

    let mut offset_bound = section_table_end.max(segment_table_end);
    for index in 0..segments_count {
        let base = segments_start + index * phdr_size;
        let (p_offset, p_filesz) = parse_phdr(kind, image, base)?;
        // Validate the original 64-bit values before narrowing to offset_t.
        let segment_end = p_offset.checked_add(p_filesz)?;
        if segment_end > u64::from(u32::MAX) {
            return None;
        }
        if !region_fits(p_offset, p_filesz, image.len() as u64) {
            return None;
        }
        offset_bound = offset_bound.max(segment_end as u32);
    }

    Some((sections, offset_bound))
}

fn parse_shdr(kind: ElfKind, image: &[u8], base: usize) -> Option<SectionHeader> {
    if kind.class() == 2 {
        Some(SectionHeader {
            sh_type: read_u32(image, base + 4)?,
            sh_flags: read_u64(image, base + 8)?,
            sh_addr: read_u64(image, base + 16)?,
            sh_offset: read_u64(image, base + 24)?,
            sh_size: read_u64(image, base + 32)?,
            sh_entsize: read_u64(image, base + 56)?,
        })
    } else {
        Some(SectionHeader {
            sh_type: read_u32(image, base + 4)?,
            sh_flags: u64::from(read_u32(image, base + 8)?),
            sh_addr: u64::from(read_u32(image, base + 12)?),
            sh_offset: u64::from(read_u32(image, base + 16)?),
            sh_size: u64::from(read_u32(image, base + 20)?),
            sh_entsize: u64::from(read_u32(image, base + 36)?),
        })
    }
}

fn parse_phdr(kind: ElfKind, image: &[u8], base: usize) -> Option<(u64, u64)> {
    if kind.class() == 2 {
        Some((read_u64(image, base + 8)?, read_u64(image, base + 32)?))
    } else {
        Some((u64::from(read_u32(image, base + 4)?), u64::from(read_u32(image, base + 16)?)))
    }
}

fn is_exec_section_thumb2(image: &[u8], section: &ExecHeader) -> bool {
    if section.addr % 4 != 0 || section.size % 4 != 0 {
        return true;
    }
    let start = section.offset as usize;
    let end = start + section.size as usize;
    let Some(data) = image.get(start..end) else { return true };
    let mut num = 0usize;
    let mut den = 0usize;
    let mut cursor = 0usize;
    while cursor + 4 <= data.len() {
        if data[cursor + 3] & 0xF0 == 0xE0 {
            num += 1;
        }
        den += 1;
        cursor += 4;
    }
    num < (den as f64 * 0.4) as usize
}

fn intel_candidate(
    kind: ElfKind,
    image: &[u8],
    cursor: usize,
    region_end: usize,
) -> Option<(usize, bool)> {
    if cursor + 5 <= region_end {
        let first = *image.get(cursor)?;
        if first == 0xE8 || first == 0xE9 {
            return Some((cursor + 1, false));
        }
    }
    if cursor + 6 <= region_end {
        let c0 = *image.get(cursor)?;
        let c1 = *image.get(cursor + 1)?;
        if c0 == 0x0F && (c1 & 0xF0) == 0x80 {
            return Some((cursor + 2, false));
        }
        if kind == ElfKind::X64
            && ((c0 == 0xFF && (c1 == 0x15 || c1 == 0x25))
                || ((c0 == 0x89 || c0 == 0x8B || c0 == 0x8D) && (c1 & 0xC7) == 0x05))
        {
            return Some((cursor + 2, true));
        }
    }
    None
}

fn align_gap_start_a32(gap_start: usize, gap_end: usize, is_thumb2: bool) -> usize {
    if is_thumb2 {
        if gap_end.saturating_sub(gap_start) < 2 {
            return gap_end;
        }
        gap_start + increment_for_align_ceil2(gap_start as u64) as usize
    } else {
        if gap_end.saturating_sub(gap_start) < 4 {
            return gap_end;
        }
        gap_start + increment_for_align_ceil4(gap_start as u64) as usize
    }
}

/// Returns `(addr_type, target_rva, instruction_size)` for ARM mode.
fn scan_arm32(image: &[u8], instr_rva: u32, location: u32) -> Option<(u8, u32, u32)> {
    let code32 = arm::fetch_arm_code32(image, location);
    arm::read_a24(instr_rva, code32).map(|target| (0u8, target, 4u32))
}

/// Returns `(addr_type, target_rva, instruction_size)` for THUMB2 mode.
/// Returns `(reference, instruction_size)` for THUMB2. Native always advances
/// by the decoded instruction size, even when no reference type matches.
fn scan_thumb2(
    image: &[u8],
    instr_rva: u32,
    location: u32,
    available: usize,
) -> (Option<(u8, u32)>, u32) {
    let code16 = arm::fetch_thumb2_code16(image, location);
    let instr_size = arm::get_thumb2_instruction_size(code16);
    if instr_size == 2 {
        if let Some(target) = arm::read_t8(instr_rva, code16) {
            return (Some((1, target)), 2);
        }
        if let Some(target) = arm::read_t11(instr_rva, code16) {
            return (Some((2, target)), 2);
        }
        return (None, 2);
    }
    if available < 4 {
        // Native does not fetch the second half if it lies outside the region.
        return (None, 4);
    }
    let code32 = arm::fetch_thumb2_code32(image, location);
    if let Some(target) = arm::read_t20(instr_rva, code32) {
        return (Some((3, target)), 4);
    }
    if let Some(target) = arm::read_t24(instr_rva, code32) {
        return (Some((4, target)), 4);
    }
    (None, 4)
}

fn scan_aarch64(image: &[u8], instr_rva: u32, location: u32) -> Option<(u8, u32)> {
    let code32 = arm::fetch_arm_code32(image, location);
    if let Some(target) = arm::read_immd14(instr_rva, code32) {
        return Some((0, target));
    }
    if let Some(target) = arm::read_immd19(instr_rva, code32) {
        return Some((1, target));
    }
    if let Some(target) = arm::read_immd26(instr_rva, code32) {
        return Some((2, target));
    }
    None
}

fn fetch_and_read_a32(
    image: &[u8],
    addr_type: usize,
    location: u32,
    instr_rva: u32,
) -> Option<u32> {
    match addr_type {
        0 => arm::read_a24(instr_rva, arm::fetch_arm_code32(image, location)),
        1 => arm::read_t8(instr_rva, arm::fetch_thumb2_code16(image, location)),
        2 => arm::read_t11(instr_rva, arm::fetch_thumb2_code16(image, location)),
        3 => arm::read_t20(instr_rva, arm::fetch_thumb2_code32(image, location)),
        4 => arm::read_t24(instr_rva, arm::fetch_thumb2_code32(image, location)),
        _ => None,
    }
}

fn fetch_and_read_a64(
    image: &[u8],
    addr_type: usize,
    location: u32,
    instr_rva: u32,
) -> Option<u32> {
    let code32 = arm::fetch_arm_code32(image, location);
    match addr_type {
        0 => arm::read_immd14(instr_rva, code32),
        1 => arm::read_immd19(instr_rva, code32),
        2 => arm::read_immd26(instr_rva, code32),
        _ => None,
    }
}

fn write_arm32(image: &mut [u8], addr_type: usize, location: u32, instr_rva: u32, target_rva: u32) {
    match addr_type {
        0 => {
            let mut code = arm::fetch_arm_code32(image, location);
            if arm::write_a24(instr_rva, target_rva, &mut code) {
                arm::store_arm_code32(image, location, code);
            }
        }
        1 => {
            let mut code = arm::fetch_thumb2_code16(image, location);
            if arm::write_t8(instr_rva, target_rva, &mut code) {
                arm::store_thumb2_code16(image, location, code);
            }
        }
        2 => {
            let mut code = arm::fetch_thumb2_code16(image, location);
            if arm::write_t11(instr_rva, target_rva, &mut code) {
                arm::store_thumb2_code16(image, location, code);
            }
        }
        3 => {
            let mut code = arm::fetch_thumb2_code32(image, location);
            if arm::write_t20(instr_rva, target_rva, &mut code) {
                arm::store_thumb2_code32(image, location, code);
            }
        }
        4 => {
            let mut code = arm::fetch_thumb2_code32(image, location);
            if arm::write_t24(instr_rva, target_rva, &mut code) {
                arm::store_thumb2_code32(image, location, code);
            }
        }
        _ => {}
    }
}

fn write_aarch64(
    image: &mut [u8],
    addr_type: usize,
    location: u32,
    instr_rva: u32,
    target_rva: u32,
) {
    let mut code = arm::fetch_arm_code32(image, location);
    let ok = match addr_type {
        0 => arm::write_immd14(instr_rva, target_rva, &mut code),
        1 => arm::write_immd19(instr_rva, target_rva, &mut code),
        2 => arm::write_immd26(instr_rva, target_rva, &mut code),
        _ => false,
    };
    if ok {
        arm::store_arm_code32(image, location, code);
    }
}

#[allow(dead_code)]
fn _keep_helpers() {
    let _ = write_u16;
    let _ = range_is_bounded;
    let _ = K_INVALID_OFFSET;
    let _ = OFFSET_BOUND;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thumb2_unknown_32bit_reports_size_four() {
        // code16 = 0xF800 selects a 32-bit THUMB2 instruction; the resulting
        // code32 matches neither T20 nor T24, so it is advanced past in full.
        let image = [0x00u8, 0xF8, 0x00, 0x00];
        let (found, size) = scan_thumb2(&image, 0, 0, 4);
        assert!(found.is_none());
        assert_eq!(size, 4);
    }

    #[test]
    fn thumb2_truncated_32bit_does_not_fetch() {
        let image = [0x00u8, 0xF8, 0x00];
        let (found, size) = scan_thumb2(&image, 0, 0, 2);
        assert!(found.is_none());
        assert_eq!(size, 4);
    }

    fn minimal_elf64(p_offset: u64, p_filesz: u64) -> Vec<u8> {
        let mut image = vec![0u8; 64 + 56 + 64];
        image[..4].copy_from_slice(b"\x7FELF");
        image[4] = 2; // ELFCLASS64
        image[5] = 1; // ELFDATA2LSB
        image[6] = 1; // EV_CURRENT
        image[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        image[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        image[20..24].copy_from_slice(&1u32.to_le_bytes());
        image[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        image[40..48].copy_from_slice(&120u64.to_le_bytes()); // e_shoff
        image[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        image[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        image[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        image[60..62].copy_from_slice(&1u16.to_le_bytes()); // e_shnum
        // Section 0 stays a zeroed SHT_NULL entry.
        image[72..80].copy_from_slice(&p_offset.to_le_bytes());
        image[96..104].copy_from_slice(&p_filesz.to_le_bytes());
        image
    }

    #[test]
    fn elf64_program_header_bounds_are_validated_as_u64() {
        assert!(parse_elf_header(ElfKind::X64, &minimal_elf64(0x80, 0x10)).is_some());
        // 2^32 offsets must not truncate to a small valid-looking value.
        assert!(parse_elf_header(ElfKind::X64, &minimal_elf64(0x1_0000_0000, 0x10)).is_none());
        // A segment extending past the image must fail too.
        assert!(parse_elf_header(ElfKind::X64, &minimal_elf64(0x80, 0x1000)).is_none());
    }
}
