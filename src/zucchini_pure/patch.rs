//! Parsing for the Zucchini ensemble patch format.
//!
//! This mirrors `components/zucchini/patch_reader.{h,cc}` and
//! `components/zucchini/patch_utils.h`, including the stream-termination
//! semantics that the native apply path relies on.

use std::collections::BTreeMap;

use super::bytes::read_u16;
use super::bytes::read_u32;
use super::{Error, Result, Status};

/// Magic signature `'Z' | ('u' << 8) | ('c' << 16) | ('c' << 24)`.
pub const PATCH_MAGIC: u32 = u32::from_le_bytes(*b"Zucc");
pub const MAJOR_VERSION: u16 = 1;
pub const K_INVALID_VERSION: u16 = 0xFFFF;

pub const EXE_TYPE_NOOP: u32 = u32::from_le_bytes(*b"NoOp");
pub const EXE_TYPE_ELF_X86: u32 = u32::from_le_bytes(*b"Ex86");
pub const EXE_TYPE_ELF_X64: u32 = u32::from_le_bytes(*b"Ex64");
pub const EXE_TYPE_ELF_AARCH32: u32 = u32::from_le_bytes(*b"EA32");
pub const EXE_TYPE_ELF_AARCH64: u32 = u32::from_le_bytes(*b"EA64");
pub const EXE_TYPE_DEX: u32 = u32::from_le_bytes(*b"DEX ");

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PatchHeader {
    pub magic: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub old_size: u32,
    pub old_crc: u32,
    pub new_size: u32,
    pub new_crc: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ElementMatch {
    pub old_offset: u32,
    pub old_size: u32,
    pub new_offset: u32,
    pub new_size: u32,
    pub exe_type: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Equivalence {
    pub src_offset: u32,
    pub dst_offset: u32,
    pub length: u32,
}

impl Equivalence {
    pub fn src_end(&self) -> u32 {
        self.src_offset.wrapping_add(self.length)
    }

    pub fn dst_end(&self) -> u32 {
        self.dst_offset.wrapping_add(self.length)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawDeltaUnit {
    pub copy_offset: u32,
    pub diff: i8,
}

#[derive(Clone, Debug)]
pub struct PatchElement {
    pub element_match: ElementMatch,
    pub equivalences: Vec<Equivalence>,
    /// Whether every equivalence stream was fully consumed (native `Done()`).
    pub equivalences_done: bool,
    pub extra_data: Vec<u8>,
    pub raw_deltas: Vec<RawDeltaUnit>,
    pub raw_deltas_done: bool,
    pub reference_deltas: Vec<i32>,
    pub reference_deltas_done: bool,
    pub extra_targets: BTreeMap<u8, ExtraTargets>,
}

#[derive(Clone, Debug, Default)]
pub struct ExtraTargets {
    pub targets: Vec<u32>,
    pub done: bool,
}

#[derive(Clone, Debug)]
pub struct Patch {
    pub header: PatchHeader,
    pub elements: Vec<PatchElement>,
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn empty(&self) -> bool {
        self.remaining() == 0
    }

    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(count)?;
        let slice = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        let value = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(value)
    }

    fn u16(&mut self) -> Option<u16> {
        let value = read_u16(self.data, self.pos)?;
        self.pos += 2;
        Some(value)
    }

    fn u32(&mut self) -> Option<u32> {
        let value = read_u32(self.data, self.pos)?;
        self.pos += 4;
        Some(value)
    }

    /// Decodes a `uint32_t` base-128 varint, mirroring `DecodeVarUInt`. On
    /// failure the cursor is left unchanged, matching `ParseVarUInt`, which only
    /// consumes bytes when decoding succeeds.
    fn var_u32(&mut self) -> Option<u32> {
        let start = self.pos;
        let mut value = 0u32;
        for shift in (0..32).step_by(7) {
            let Some(&byte) = self.data.get(self.pos) else {
                self.pos = start;
                return None;
            };
            self.pos += 1;
            value |= u32::from(byte & 0x7F) << shift;
            if byte < 0x80 {
                return Some(value);
            }
        }
        self.pos = start;
        None
    }

    /// Decodes an `int32_t` zig-zag varint, mirroring `DecodeVarInt`.
    fn var_i32(&mut self) -> Option<i32> {
        let tmp = self.var_u32()?;
        if tmp & 1 != 0 {
            Some(!((tmp >> 1) as i32))
        } else {
            Some((tmp >> 1) as i32)
        }
    }

    /// Mirrors `patch::ParseBuffer`: a `uint32_t` size followed by that many bytes.
    fn buffer(&mut self) -> Option<&'a [u8]> {
        let size = self.u32()? as usize;
        self.take(size)
    }
}

fn invalid_patch(message: &str) -> Error {
    Error { status: Status::InvalidPatch, message: message.into() }
}

fn executable_version(exe_type: u32) -> Option<u16> {
    match exe_type {
        EXE_TYPE_NOOP
        | EXE_TYPE_ELF_X86
        | EXE_TYPE_ELF_X64
        | EXE_TYPE_ELF_AARCH32
        | EXE_TYPE_ELF_AARCH64
        | EXE_TYPE_DEX => Some(1),
        _ => None,
    }
}

fn parse_element_match(cursor: &mut Cursor<'_>) -> Option<ElementMatch> {
    let old_offset = cursor.u32()?;
    let old_size = cursor.u32()?;
    let new_offset = cursor.u32()?;
    let new_size = cursor.u32()?;
    let exe_type = cursor.u32()?;
    let version = cursor.u16()?;
    let expected = executable_version(exe_type)?;
    if expected != version {
        return None;
    }
    if old_size == 0 || new_size == 0 {
        return None;
    }
    Some(ElementMatch { old_offset, old_size, new_offset, new_size, exe_type })
}

/// Decodes all equivalences and reports whether the three streams were fully
/// consumed, matching `EquivalenceSource::Done()`.
fn parse_equivalences(
    src_skip: &[u8],
    dst_skip: &[u8],
    copy_count: &[u8],
) -> (Vec<Equivalence>, bool) {
    let mut src = Cursor::new(src_skip);
    let mut dst = Cursor::new(dst_skip);
    let mut count = Cursor::new(copy_count);
    let mut result = Vec::new();
    let mut previous_src: u32 = 0;
    let mut previous_dst: u32 = 0;
    while !src.empty() && !dst.empty() && !count.empty() {
        let length = match count.var_u32() {
            Some(value) => value,
            None => break,
        };
        let src_diff = match src.var_i32() {
            Some(value) => value,
            None => break,
        };
        let src_offset = match (previous_src as i64).checked_add(src_diff as i64) {
            Some(value) if (0..=u32::MAX as i64).contains(&value) => value as u32,
            _ => break,
        };
        previous_src = match src_offset.checked_add(length) {
            Some(value) => value,
            None => break,
        };
        let dst_diff = match dst.var_u32() {
            Some(value) => value,
            None => break,
        };
        let dst_offset = match previous_dst.checked_add(dst_diff) {
            Some(value) => value,
            None => break,
        };
        previous_dst = match dst_offset.checked_add(length) {
            Some(value) => value,
            None => break,
        };
        result.push(Equivalence { src_offset, dst_offset, length });
    }
    let done = src.empty() && dst.empty() && count.empty();
    (result, done)
}

fn parse_raw_deltas(skip: &[u8], diffs: &[u8]) -> (Vec<RawDeltaUnit>, bool) {
    let mut skip = Cursor::new(skip);
    let mut diffs = Cursor::new(diffs);
    let mut result = Vec::new();
    let mut compensation: u32 = 0;
    while !skip.empty() && !diffs.empty() {
        let diff = match skip.var_u32() {
            Some(value) => value,
            None => break,
        };
        let copy_offset = match diff.checked_add(compensation) {
            Some(value) => value,
            None => break,
        };
        let byte = match diffs.u8() {
            Some(value) => value,
            None => break,
        };
        let byte_diff = byte as i8;
        if byte_diff == 0 {
            break;
        }
        compensation = match copy_offset.checked_add(1) {
            Some(value) => value,
            None => break,
        };
        result.push(RawDeltaUnit { copy_offset, diff: byte_diff });
    }
    let done = skip.empty() && diffs.empty();
    (result, done)
}

fn parse_reference_deltas(source: &[u8]) -> (Vec<i32>, bool) {
    let mut cursor = Cursor::new(source);
    let mut result = Vec::new();
    while !cursor.empty() {
        match cursor.var_i32() {
            Some(value) => result.push(value),
            None => break,
        }
    }
    (result, cursor.empty())
}

fn parse_extra_targets(source: &[u8]) -> ExtraTargets {
    let mut cursor = Cursor::new(source);
    let mut targets = Vec::new();
    let mut compensation: u32 = 0;
    while !cursor.empty() {
        let diff = match cursor.var_u32() {
            Some(value) => value,
            None => break,
        };
        let target = match diff.checked_add(compensation) {
            Some(value) => value,
            None => break,
        };
        compensation = match target.checked_add(1) {
            Some(value) => value,
            None => break,
        };
        targets.push(target);
    }
    ExtraTargets { targets, done: cursor.empty() }
}

impl PatchElement {
    fn parse(cursor: &mut Cursor<'_>) -> Result<Self> {
        let element_match =
            parse_element_match(cursor).ok_or_else(|| invalid_patch("invalid patch element"))?;

        let src_skip = cursor
            .buffer()
            .ok_or_else(|| invalid_patch("invalid equivalence source"))?;
        let dst_skip = cursor
            .buffer()
            .ok_or_else(|| invalid_patch("invalid equivalence source"))?;
        let copy_count = cursor
            .buffer()
            .ok_or_else(|| invalid_patch("invalid equivalence source"))?;
        let (equivalences, equivalences_done) =
            parse_equivalences(src_skip, dst_skip, copy_count);
        let extra_data = cursor
            .buffer()
            .ok_or_else(|| invalid_patch("invalid extra data"))?
            .to_vec();

        // Mirrors ValidateEquivalencesAndExtraData().
        let old_region_size = u64::from(element_match.old_size);
        let new_region_size = u64::from(element_match.new_size);
        let mut total_length: u64 = 0;
        let mut previous_dst_end: u64 = 0;
        for equivalence in &equivalences {
            if !super::bytes::range_is_bounded(
                u64::from(equivalence.src_offset),
                u64::from(equivalence.length),
                old_region_size,
            ) || !super::bytes::range_is_bounded(
                u64::from(equivalence.dst_offset),
                u64::from(equivalence.length),
                new_region_size,
            ) {
                return Err(invalid_patch("out of bounds equivalence"));
            }
            if previous_dst_end > u64::from(equivalence.dst_end()) {
                return Err(invalid_patch("out of order equivalence"));
            }
            previous_dst_end = u64::from(equivalence.dst_end());
            total_length += u64::from(equivalence.length);
        }
        if total_length > new_region_size
            || extra_data.len() as u64 != new_region_size - total_length
        {
            return Err(invalid_patch("incorrect amount of extra data"));
        }

        let raw_skip = cursor
            .buffer()
            .ok_or_else(|| invalid_patch("invalid raw delta source"))?;
        let raw_diff = cursor
            .buffer()
            .ok_or_else(|| invalid_patch("invalid raw delta source"))?;
        let (raw_deltas, raw_deltas_done) = parse_raw_deltas(raw_skip, raw_diff);

        let reference_source = cursor
            .buffer()
            .ok_or_else(|| invalid_patch("invalid reference delta source"))?;
        let (reference_deltas, reference_deltas_done) =
            parse_reference_deltas(reference_source);

        let pool_count = cursor
            .u32()
            .ok_or_else(|| invalid_patch("invalid extra target list"))?;
        let mut extra_targets = BTreeMap::new();
        for _ in 0..pool_count {
            let pool_tag = cursor
                .u8()
                .ok_or_else(|| invalid_patch("invalid extra target list"))?;
            if pool_tag == 0xFF {
                return Err(invalid_patch("invalid pool tag"));
            }
            let source = cursor
                .buffer()
                .ok_or_else(|| invalid_patch("invalid extra target list"))?;
            if extra_targets.insert(pool_tag, parse_extra_targets(source)).is_some() {
                return Err(invalid_patch("duplicate pool tag"));
            }
        }

        Ok(PatchElement {
            element_match,
            equivalences,
            equivalences_done,
            extra_data,
            raw_deltas,
            raw_deltas_done,
            reference_deltas,
            reference_deltas_done,
            extra_targets,
        })
    }
}

impl Patch {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);
        let header = PatchHeader {
            magic: cursor.u32().ok_or_else(|| invalid_patch("invalid ensemble patch"))?,
            major_version: cursor.u16().ok_or_else(|| invalid_patch("invalid ensemble patch"))?,
            minor_version: cursor.u16().ok_or_else(|| invalid_patch("invalid ensemble patch"))?,
            old_size: cursor.u32().ok_or_else(|| invalid_patch("invalid ensemble patch"))?,
            old_crc: cursor.u32().ok_or_else(|| invalid_patch("invalid ensemble patch"))?,
            new_size: cursor.u32().ok_or_else(|| invalid_patch("invalid ensemble patch"))?,
            new_crc: cursor.u32().ok_or_else(|| invalid_patch("invalid ensemble patch"))?,
        };
        if header.magic != PATCH_MAGIC || header.major_version != MAJOR_VERSION {
            return Err(invalid_patch("invalid ensemble patch"));
        }
        let element_count = cursor
            .u32()
            .ok_or_else(|| invalid_patch("invalid ensemble patch"))?;
        let mut elements = Vec::new();
        let mut current_dst_offset: u32 = 0;
        for _ in 0..element_count {
            let element = PatchElement::parse(&mut cursor)?;
            if !region_fits(element.element_match.old_offset, element.element_match.old_size, header.old_size)
                || !region_fits(
                    element.element_match.new_offset,
                    element.element_match.new_size,
                    header.new_size,
                )
            {
                return Err(invalid_patch("invalid patch element"));
            }
            if element.element_match.new_offset != current_dst_offset {
                return Err(invalid_patch("invalid patch element"));
            }
            current_dst_offset = element
                .element_match
                .new_offset
                .checked_add(element.element_match.new_size)
                .ok_or_else(|| invalid_patch("invalid patch element"))?;
            elements.push(element);
        }
        if current_dst_offset != header.new_size {
            return Err(invalid_patch("patch elements do not fully cover new image"));
        }
        if !cursor.empty() {
            return Err(invalid_patch("patch was not fully consumed"));
        }
        Ok(Patch { header, elements })
    }
}

fn region_fits(offset: u32, size: u32, container: u32) -> bool {
    offset <= container && container - offset >= size
}

pub fn check_old_file(header: &PatchHeader, old_image: &[u8]) -> bool {
    old_image.len() == header.old_size as usize
        && super::crc32::calculate_crc32(old_image) == header.old_crc
}

pub fn check_new_file(header: &PatchHeader, new_image: &[u8]) -> bool {
    new_image.len() == header.new_size as usize
        && super::crc32::calculate_crc32(new_image) == header.new_crc
}

/// Cancellable variant of [`check_old_file`].
pub(crate) fn check_old_file_cancel(
    header: &PatchHeader,
    old_image: &[u8],
    cancelled: &dyn Fn() -> bool,
) -> Result<bool> {
    if old_image.len() != header.old_size as usize {
        return Ok(false);
    }
    Ok(super::crc32::calculate_crc32_cancel(old_image, cancelled)? == header.old_crc)
}

/// Cancellable variant of [`check_new_file`].
pub(crate) fn check_new_file_cancel(
    header: &PatchHeader,
    new_image: &[u8],
    cancelled: &dyn Fn() -> bool,
) -> Result<bool> {
    if new_image.len() != header.new_size as usize {
        return Ok(false);
    }
    Ok(super::crc32::calculate_crc32_cancel(new_image, cancelled)? == header.new_crc)
}
