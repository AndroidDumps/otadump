//! CRC-32 implementation matching `components/zucchini/crc32.cc`.

fn make_crc32_table() -> [u32; 256] {
    const POLY: u32 = 0xEDB8_8320;
    let mut table = [0u32; 256];
    for (i, entry) in table.iter_mut().enumerate() {
        let mut r = i as u32;
        for _ in 0..8 {
            r = (r >> 1) ^ (POLY & (!((r & 1).wrapping_sub(1))));
        }
        *entry = r;
    }
    table
}

pub fn calculate_crc32(data: &[u8]) -> u32 {
    let table = make_crc32_table();
    let mut ret = 0xFFFF_FFFFu32;
    for &byte in data {
        ret = table[((ret ^ byte as u32) & 0xFF) as usize] ^ (ret >> 8);
    }
    ret ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        assert_eq!(calculate_crc32(b""), 0x0000_0000);
        assert_eq!(calculate_crc32(b"123456789"), 0xCBF4_3926);
    }
}
