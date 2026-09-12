//! Little-endian byte access helpers shared by the pure-Rust Zucchini port.

pub fn read_u8(data: &[u8], offset: usize) -> Option<u8> {
    data.get(offset).copied()
}

pub fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes(bytes.try_into().ok()?))
}

pub fn read_i16(data: &[u8], offset: usize) -> Option<i16> {
    Some(read_u16(data, offset)? as i16)
}

pub fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

pub fn read_i32(data: &[u8], offset: usize) -> Option<i32> {
    Some(read_u32(data, offset)? as i32)
}

pub fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

pub fn write_u16(data: &mut [u8], offset: usize, value: u16) -> Option<()> {
    let end = offset.checked_add(2)?;
    data.get_mut(offset..end)?.copy_from_slice(&value.to_le_bytes());
    Some(())
}

pub fn write_u32(data: &mut [u8], offset: usize, value: u32) -> Option<()> {
    let end = offset.checked_add(4)?;
    data.get_mut(offset..end)?.copy_from_slice(&value.to_le_bytes());
    Some(())
}

pub fn write_u64(data: &mut [u8], offset: usize, value: u64) -> Option<()> {
    let end = offset.checked_add(8)?;
    data.get_mut(offset..end)?.copy_from_slice(&value.to_le_bytes());
    Some(())
}

/// Mirrors `zucchini::RangeIsBounded`: `begin < bound && size <= bound - begin`.
pub fn range_is_bounded(begin: u64, size: u64, bound: u64) -> bool {
    begin < bound && size <= bound - begin
}

/// Mirrors `zucchini::RangeCovers`: `begin <= value && value - begin < size`.
pub fn range_covers(begin: u64, size: u64, value: u64) -> bool {
    begin <= value && value - begin < size
}

/// Mirrors `zucchini::IncrementForAlignCeil2`.
pub fn increment_for_align_ceil2(pos: u64) -> u64 {
    pos & 1
}

/// Mirrors `zucchini::IncrementForAlignCeil4`.
pub fn increment_for_align_ceil4(pos: u64) -> u64 {
    (-(pos as i64) & 3) as u64
}

/// Mirrors `zucchini::AlignCeil`.
pub fn align_ceil(x: u64, m: u64) -> u64 {
    x.div_ceil(m) * m
}

/// Zero-extends bits `[lo, hi]` (inclusive) of a 32-bit value.
pub fn get_unsigned_bits_u32(value: u32, lo: u32, hi: u32) -> u32 {
    let num_bits = 32u32;
    (value << (num_bits - 1 - hi)) >> (num_bits - 1 - hi + lo)
}

/// Sign-extends bits `[lo, hi]` (inclusive) of a 32-bit value.
pub fn get_signed_bits_u32(value: u32, lo: u32, hi: u32) -> i32 {
    let num_bits = 32i32;
    let shift = num_bits - 1 - hi as i32;
    ((value << shift) as i32) >> (shift + lo as i32)
}

/// Sign-extends the low `pos + 1` bits of `value`.
pub fn sign_extend_u32(value: u32, pos: u32) -> i32 {
    let shift = 31 - pos;
    ((value << shift) as i32) >> shift
}

/// Mirrors `zucchini::SignedFit<digs>` for a 32-bit signed value.
pub fn signed_fit(value: i32, digs: u32) -> bool {
    let shift = 32 - digs;
    (value << shift) >> shift == value
}
