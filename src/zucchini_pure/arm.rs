//! Ports of `arm_utils.cc`: AArch32 (ARM/THUMB2) and AArch64 rel32 codecs.

use super::bytes::sign_extend_u32;
use super::bytes::{get_signed_bits_u32, get_unsigned_bits_u32, signed_fit};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArmAlign {
    Fail = 0,
    Align2 = 2,
    Align4 = 4,
}

#[inline]
fn bit(value: u32, pos: u32) -> u32 {
    (value >> pos) & 1
}

#[inline]
fn unsigned_bits(value: u32, lo: u32, hi: u32) -> u32 {
    get_unsigned_bits_u32(value, lo, hi)
}

#[inline]
fn signed_bits(value: u32, lo: u32, hi: u32) -> i32 {
    get_signed_bits_u32(value, lo, hi)
}

#[inline]
fn signed_bits_u16(value: u16, lo: u32, hi: u32) -> i32 {
    // `GetSignedBits` on a 16-bit value.
    let num_bits = 16i32;
    let shift = num_bits - 1 - hi as i32;
    (i32::from(value) << shift) >> (shift + lo as i32)
}

#[inline]
fn is_misaligned(rva: u32, align: ArmAlign) -> bool {
    (rva & (align as u32 - 1)) != 0
}

pub fn fetch_arm_code32(image: &[u8], offset: u32) -> u32 {
    super::bytes::read_u32(image, offset as usize).unwrap_or(0)
}

pub fn fetch_thumb2_code16(image: &[u8], offset: u32) -> u16 {
    super::bytes::read_u16(image, offset as usize).unwrap_or(0)
}

pub fn fetch_thumb2_code32(image: &[u8], offset: u32) -> u32 {
    let hi = super::bytes::read_u16(image, offset as usize).unwrap_or(0) as u32;
    let lo = super::bytes::read_u16(image, offset as usize + 2).unwrap_or(0) as u32;
    (hi << 16) | lo
}

pub fn store_arm_code32(image: &mut [u8], offset: u32, code: u32) {
    let _ = super::bytes::write_u32(image, offset as usize, code);
}

pub fn store_thumb2_code16(image: &mut [u8], offset: u32, code: u16) {
    let _ = super::bytes::write_u16(image, offset as usize, code);
}

pub fn store_thumb2_code32(image: &mut [u8], offset: u32, code: u32) {
    let _ = super::bytes::write_u16(image, offset as usize, (code >> 16) as u16);
    let _ = super::bytes::write_u16(image, offset as usize + 2, (code & 0xFFFF) as u16);
}

pub fn get_thumb2_instruction_size(code16: u16) -> u32 {
    if (code16 & 0xF000) == 0xF000 || (code16 & 0xF800) == 0xE800 {
        4
    } else {
        2
    }
}

/// Mirrors `AArch32Rel32Translator::DecodeA24`.
pub fn decode_a24(code32: u32) -> (ArmAlign, i32) {
    let bits = unsigned_bits(code32, 24, 27);
    if bits == 0xA || bits == 0xB {
        let mut disp = signed_bits(code32, 0, 23) << 2;
        let cond = unsigned_bits(code32, 28, 31);
        if cond == 0xF {
            let h = bit(code32, 24);
            disp |= (h << 1) as i32;
            return (ArmAlign::Align2, disp);
        }
        return (ArmAlign::Align4, disp);
    }
    (ArmAlign::Fail, 0)
}

/// Mirrors `AArch32Rel32Translator::EncodeA24`.
pub fn encode_a24(disp: i32, code32: &mut u32) -> bool {
    let mut t = *code32;
    let bits = unsigned_bits(t, 24, 27);
    if bits == 0xA || bits == 0xB {
        if !signed_fit(disp, 26) {
            return false;
        }
        let cond = unsigned_bits(t, 28, 31);
        if cond == 0xF {
            if disp % 2 != 0 {
                return false;
            }
            let h = bit(disp as u32, 1);
            t = (t & 0xFEFF_FFFF) | (h << 24);
        } else if disp % 4 != 0 {
            return false;
        }
        t = (t & 0xFF00_0000) | (((disp >> 2) as u32) & 0x00FF_FFFF);
        *code32 = t;
        return true;
    }
    false
}

fn get_arm_target_rva_from_disp(instr_rva: u32, disp: i32, align: ArmAlign) -> u32 {
    let ret = instr_rva.wrapping_add(8).wrapping_add(disp as u32);
    ret - (ret & (align as u32 - 1))
}

fn get_thumb2_target_rva_from_disp(instr_rva: u32, disp: i32, align: ArmAlign) -> u32 {
    let ret = instr_rva.wrapping_add(4).wrapping_add(disp as u32);
    ret - (ret & (align as u32 - 1))
}

fn get_arm_disp_from_target_rva(instr_rva: u32, target_rva: u32, align: ArmAlign) -> i32 {
    let ret = target_rva as i32 - instr_rva.wrapping_add(8) as i32;
    ret + ((-ret) & (align as i32 - 1))
}

fn get_thumb2_disp_from_target_rva(instr_rva: u32, target_rva: u32, align: ArmAlign) -> i32 {
    let ret = target_rva as i32 - instr_rva.wrapping_add(4) as i32;
    ret + ((-ret) & (align as i32 - 1))
}

pub fn read_a24(instr_rva: u32, code32: u32) -> Option<u32> {
    if is_misaligned(instr_rva, ArmAlign::Align4) {
        return None;
    }
    let (align, disp) = decode_a24(code32);
    if align == ArmAlign::Fail {
        return None;
    }
    Some(get_arm_target_rva_from_disp(instr_rva, disp, align))
}

pub fn write_a24(instr_rva: u32, target_rva: u32, code32: &mut u32) -> bool {
    if is_misaligned(instr_rva, ArmAlign::Align4) {
        return false;
    }
    let (align, _) = decode_a24(*code32);
    if align == ArmAlign::Fail || is_misaligned(target_rva, align) {
        return false;
    }
    let disp = get_arm_disp_from_target_rva(instr_rva, target_rva, align);
    encode_a24(disp, code32)
}

pub fn decode_t8(code16: u16) -> (ArmAlign, i32) {
    if (code16 & 0xF000) == 0xD000 && (code16 & 0x0F00) != 0x0F00 {
        return (ArmAlign::Align2, signed_bits_u16(code16, 0, 7) << 1);
    }
    (ArmAlign::Fail, 0)
}

pub fn encode_t8(disp: i32, code16: &mut u16) -> bool {
    let mut t = *code16;
    if (t & 0xF000) == 0xD000 && (t & 0x0F00) != 0x0F00 {
        if disp % 2 != 0 || !signed_fit(disp, 9) {
            return false;
        }
        t = (t & 0xFF00) | (((disp >> 1) as u16) & 0x00FF);
        *code16 = t;
        return true;
    }
    false
}

pub fn read_t8(instr_rva: u32, code16: u16) -> Option<u32> {
    if is_misaligned(instr_rva, ArmAlign::Align2) {
        return None;
    }
    let (align, disp) = decode_t8(code16);
    if align == ArmAlign::Fail {
        return None;
    }
    Some(get_thumb2_target_rva_from_disp(instr_rva, disp, align))
}

pub fn write_t8(instr_rva: u32, target_rva: u32, code16: &mut u16) -> bool {
    if is_misaligned(instr_rva, ArmAlign::Align2) || is_misaligned(target_rva, ArmAlign::Align2) {
        return false;
    }
    let disp = get_thumb2_disp_from_target_rva(instr_rva, target_rva, ArmAlign::Align2);
    encode_t8(disp, code16)
}

pub fn decode_t11(code16: u16) -> (ArmAlign, i32) {
    if (code16 & 0xF800) == 0xE000 {
        return (ArmAlign::Align2, signed_bits_u16(code16, 0, 10) << 1);
    }
    (ArmAlign::Fail, 0)
}

pub fn encode_t11(disp: i32, code16: &mut u16) -> bool {
    let mut t = *code16;
    if (t & 0xF800) == 0xE000 {
        if disp % 2 != 0 || !signed_fit(disp, 12) {
            return false;
        }
        t = (t & 0xF800) | (((disp >> 1) as u16) & 0x07FF);
        *code16 = t;
        return true;
    }
    false
}

pub fn read_t11(instr_rva: u32, code16: u16) -> Option<u32> {
    if is_misaligned(instr_rva, ArmAlign::Align2) {
        return None;
    }
    let (align, disp) = decode_t11(code16);
    if align == ArmAlign::Fail {
        return None;
    }
    Some(get_thumb2_target_rva_from_disp(instr_rva, disp, align))
}

pub fn write_t11(instr_rva: u32, target_rva: u32, code16: &mut u16) -> bool {
    if is_misaligned(instr_rva, ArmAlign::Align2) || is_misaligned(target_rva, ArmAlign::Align2) {
        return false;
    }
    let disp = get_thumb2_disp_from_target_rva(instr_rva, target_rva, ArmAlign::Align2);
    encode_t11(disp, code16)
}

pub fn decode_t20(code32: u32) -> (ArmAlign, i32) {
    if (code32 & 0xF800_D000) == 0xF000_8000 && (code32 & 0x03C0_0000) != 0x03C0_0000 {
        let imm11 = unsigned_bits(code32, 0, 10);
        let j2 = bit(code32, 11);
        let j1 = bit(code32, 13);
        let imm6 = unsigned_bits(code32, 16, 21);
        let s = bit(code32, 26);
        let mut t = (imm6 << 12) | (imm11 << 1);
        t |= (s << 20) | (j2 << 19) | (j1 << 18);
        return (ArmAlign::Align2, sign_extend_u32(t, 20));
    }
    (ArmAlign::Fail, 0)
}

pub fn encode_t20(disp: i32, code32: &mut u32) -> bool {
    let mut t = *code32;
    if (t & 0xF800_D000) == 0xF000_8000 && (t & 0x03C0_0000) != 0x03C0_0000 {
        if disp % 2 != 0 || !signed_fit(disp, 21) {
            return false;
        }
        let s = bit(disp as u32, 20);
        let j2 = bit(disp as u32, 19);
        let j1 = bit(disp as u32, 18);
        let imm6 = unsigned_bits(disp as u32, 12, 17);
        let imm11 = unsigned_bits(disp as u32, 1, 11);
        t &= 0xFBC0_D000;
        t |= (s << 26) | (imm6 << 16) | (j1 << 13) | (j2 << 11) | imm11;
        *code32 = t;
        return true;
    }
    false
}

pub fn read_t20(instr_rva: u32, code32: u32) -> Option<u32> {
    if is_misaligned(instr_rva, ArmAlign::Align2) {
        return None;
    }
    let (align, disp) = decode_t20(code32);
    if align == ArmAlign::Fail {
        return None;
    }
    Some(get_thumb2_target_rva_from_disp(instr_rva, disp, align))
}

pub fn write_t20(instr_rva: u32, target_rva: u32, code32: &mut u32) -> bool {
    if is_misaligned(instr_rva, ArmAlign::Align2) || is_misaligned(target_rva, ArmAlign::Align2) {
        return false;
    }
    let disp = get_thumb2_disp_from_target_rva(instr_rva, target_rva, ArmAlign::Align2);
    encode_t20(disp, code32)
}

pub fn decode_t24(code32: u32) -> (ArmAlign, i32) {
    let bits = code32 & 0xF800_D000;
    if bits == 0xF000_9000 || bits == 0xF000_D000 || bits == 0xF000_C000 {
        let imm11 = unsigned_bits(code32, 0, 10);
        let j2 = bit(code32, 11);
        let j1 = bit(code32, 13);
        let imm10 = unsigned_bits(code32, 16, 25);
        let s = bit(code32, 26);
        let mut t = (imm10 << 12) | (imm11 << 1);
        t |= (s << 24) | ((j1 ^ s ^ 1) << 23) | ((j2 ^ s ^ 1) << 22);
        let disp = sign_extend_u32(t, 24);
        let mut align = ArmAlign::Align2;
        if bits == 0xF000_C000 {
            if bit(code32, 0) != 0 {
                return (ArmAlign::Fail, 0);
            }
            align = ArmAlign::Align4;
        }
        return (align, disp);
    }
    (ArmAlign::Fail, 0)
}

pub fn encode_t24(disp: i32, code32: &mut u32) -> bool {
    let mut t = *code32;
    let bits = t & 0xF800_D000;
    if bits == 0xF000_9000 || bits == 0xF000_D000 || bits == 0xF000_C000 {
        if disp % 2 != 0 {
            return false;
        }
        if bits == 0xF000_C000 && bit(disp as u32, 1) != 0 {
            return false;
        }
        if !signed_fit(disp, 25) {
            return false;
        }
        let imm11 = unsigned_bits(disp as u32, 1, 11);
        let imm10 = unsigned_bits(disp as u32, 12, 21);
        let i2 = bit(disp as u32, 22);
        let i1 = bit(disp as u32, 23);
        let s = bit(disp as u32, 24);
        t &= 0xF800_D000;
        t |= (s << 26)
            | (imm10 << 16)
            | ((i1 ^ s ^ 1) << 13)
            | ((i2 ^ s ^ 1) << 11)
            | imm11;
        *code32 = t;
        return true;
    }
    false
}

pub fn read_t24(instr_rva: u32, code32: u32) -> Option<u32> {
    if is_misaligned(instr_rva, ArmAlign::Align2) {
        return None;
    }
    let (align, disp) = decode_t24(code32);
    if align == ArmAlign::Fail {
        return None;
    }
    Some(get_thumb2_target_rva_from_disp(instr_rva, disp, align))
}

pub fn write_t24(instr_rva: u32, target_rva: u32, code32: &mut u32) -> bool {
    if is_misaligned(instr_rva, ArmAlign::Align2) {
        return false;
    }
    let (align, _) = decode_t24(*code32);
    if align == ArmAlign::Fail || is_misaligned(target_rva, align) {
        return false;
    }
    let disp = get_thumb2_disp_from_target_rva(instr_rva, target_rva, align);
    encode_t24(disp, code32)
}

// `AArch64Rel32Translator`.

fn get_target_rva_from_disp(instr_rva: u32, disp: i32) -> u32 {
    instr_rva.wrapping_add(disp as u32)
}

fn get_disp_from_target_rva(instr_rva: u32, target_rva: u32) -> i32 {
    target_rva.wrapping_sub(instr_rva) as i32
}

pub fn decode_immd14(code32: u32) -> (ArmAlign, i32) {
    let bits = code32 & 0x7F00_0000;
    if bits == 0x3600_0000 || bits == 0x3700_0000 {
        return (ArmAlign::Align4, signed_bits(code32, 5, 18) << 2);
    }
    (ArmAlign::Fail, 0)
}

pub fn encode_immd14(disp: i32, code32: &mut u32) -> bool {
    let mut t = *code32;
    let bits = t & 0x7F00_0000;
    if bits == 0x3600_0000 || bits == 0x3700_0000 {
        if disp % 4 != 0 || !signed_fit(disp, 16) {
            return false;
        }
        let imm14 = unsigned_bits(disp as u32, 2, 15);
        t &= 0xFFF8_001F;
        t |= imm14 << 5;
        *code32 = t;
        return true;
    }
    false
}

pub fn read_immd14(instr_rva: u32, code32: u32) -> Option<u32> {
    if is_misaligned(instr_rva, ArmAlign::Align4) {
        return None;
    }
    let (align, disp) = decode_immd14(code32);
    if align == ArmAlign::Fail {
        return None;
    }
    Some(get_target_rva_from_disp(instr_rva, disp))
}

pub fn write_immd14(instr_rva: u32, target_rva: u32, code32: &mut u32) -> bool {
    if is_misaligned(instr_rva, ArmAlign::Align4) || is_misaligned(target_rva, ArmAlign::Align4) {
        return false;
    }
    let disp = get_disp_from_target_rva(instr_rva, target_rva);
    encode_immd14(disp, code32)
}

pub fn decode_immd19(code32: u32) -> (ArmAlign, i32) {
    let bits1 = code32 & 0xFF00_0010;
    let bits2 = code32 & 0x7F00_0000;
    if bits1 == 0x5400_0000 || bits2 == 0x3400_0000 || bits2 == 0x3500_0000 {
        return (ArmAlign::Align4, signed_bits(code32, 5, 23) << 2);
    }
    (ArmAlign::Fail, 0)
}

pub fn encode_immd19(disp: i32, code32: &mut u32) -> bool {
    let mut t = *code32;
    let bits1 = t & 0xFF00_0010;
    let bits2 = t & 0x7F00_0000;
    if bits1 == 0x5400_0000 || bits2 == 0x3400_0000 || bits2 == 0x3500_0000 {
        if disp % 4 != 0 || !signed_fit(disp, 21) {
            return false;
        }
        let imm19 = unsigned_bits(disp as u32, 2, 20);
        t &= 0xFF00_001F;
        t |= imm19 << 5;
        *code32 = t;
        return true;
    }
    false
}

pub fn read_immd19(instr_rva: u32, code32: u32) -> Option<u32> {
    if is_misaligned(instr_rva, ArmAlign::Align4) {
        return None;
    }
    let (align, disp) = decode_immd19(code32);
    if align == ArmAlign::Fail {
        return None;
    }
    Some(get_target_rva_from_disp(instr_rva, disp))
}

pub fn write_immd19(instr_rva: u32, target_rva: u32, code32: &mut u32) -> bool {
    if is_misaligned(instr_rva, ArmAlign::Align4) || is_misaligned(target_rva, ArmAlign::Align4) {
        return false;
    }
    let disp = get_disp_from_target_rva(instr_rva, target_rva);
    encode_immd19(disp, code32)
}

pub fn decode_immd26(code32: u32) -> (ArmAlign, i32) {
    let bits = code32 & 0xFC00_0000;
    if bits == 0x1400_0000 || bits == 0x9400_0000 {
        return (ArmAlign::Align4, signed_bits(code32, 0, 25) << 2);
    }
    (ArmAlign::Fail, 0)
}

pub fn encode_immd26(disp: i32, code32: &mut u32) -> bool {
    let mut t = *code32;
    let bits = t & 0xFC00_0000;
    if bits == 0x1400_0000 || bits == 0x9400_0000 {
        if disp % 4 != 0 || !signed_fit(disp, 28) {
            return false;
        }
        let imm26 = unsigned_bits(disp as u32, 2, 27);
        t &= 0xFC00_0000;
        t |= imm26;
        *code32 = t;
        return true;
    }
    false
}

pub fn read_immd26(instr_rva: u32, code32: u32) -> Option<u32> {
    if is_misaligned(instr_rva, ArmAlign::Align4) {
        return None;
    }
    let (align, disp) = decode_immd26(code32);
    if align == ArmAlign::Fail {
        return None;
    }
    Some(get_target_rva_from_disp(instr_rva, disp))
}

pub fn write_immd26(instr_rva: u32, target_rva: u32, code32: &mut u32) -> bool {
    if is_misaligned(instr_rva, ArmAlign::Align4) || is_misaligned(target_rva, ArmAlign::Align4) {
        return false;
    }
    let disp = get_disp_from_target_rva(instr_rva, target_rva);
    encode_immd26(disp, code32)
}
