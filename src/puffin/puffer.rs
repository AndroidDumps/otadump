// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Adapted from puffdiff 0.1.0, a pure-Rust port of ChromiumOS Puffin.

//! Deflate -> puff transform, ported from puffin `puffer.cc`.

use crate::CancellationToken;
use crate::puffin::bit_io::BitReader;
use crate::puffin::huffman::{
    BlockType, DISTANCE_BASES, DISTANCE_EXTRA_BITS, HuffmanTable, LENGTH_BASES, LENGTH_EXTRA_BITS,
};
use crate::puffin::puff_io::{BLOCK_METADATA_MAX, PuffData, PuffWriter};
use crate::puffin::{Error, Result, check_cancelled};

/// Puff every deflate block in `br` into `pw`, until the input is exhausted.
pub fn puff_deflate(
    br: &mut BitReader,
    pw: &mut PuffWriter,
    cancellation_token: &CancellationToken,
) -> Result<()> {
    puff_deflate_impl(br, pw, cancellation_token)
}

fn puff_deflate_impl(
    br: &mut BitReader,
    pw: &mut PuffWriter,
    cancellation_token: &CancellationToken,
) -> Result<()> {
    let mut fixed_ht = HuffmanTable::new()?;
    let mut dyn_ht = HuffmanTable::new()?;
    let mut fixed_built = false;
    // Minimum deflate block is 8 bits (3-bit header + a 5-bit fixed symbol).
    while br.cache_bits(8) {
        check_cancelled(cancellation_token)?;
        if !br.cache_bits(3) {
            return Err(Error::Corrupt("eof reading block header".into()));
        }
        let final_bit = br.read_bits(1) as u8;
        br.drop_bits(1);
        let btype = br.read_bits(2) as u8;
        br.drop_bits(2);

        let block_header = (final_bit << 7) | (btype << 5);

        let use_dynamic = match BlockType::from_bits(btype)? {
            BlockType::Uncompressed => {
                let skipped_bits = br.read_boundary_bits();
                br.skip_boundary_bits();
                if !br.cache_bits(32) {
                    return Err(Error::Corrupt("eof reading uncompressed lengths".into()));
                }
                let len = br.read_bits(16);
                br.drop_bits(16);
                let nlen = br.read_bits(16);
                br.drop_bits(16);
                if (len ^ nlen) != 0xFFFF {
                    return Err(Error::Corrupt("bad uncompressed LEN/NLEN".into()));
                }

                let header = block_header | skipped_bits;
                pw.insert(&PuffData::BlockMetadata(&[header]))?;

                let raw = br.get_bytes(len as usize)?;
                pw.insert(&PuffData::Literals(raw))?;
                pw.insert(&PuffData::EndOfBlock)?;
                continue;
            }
            BlockType::Fixed => {
                if !fixed_built {
                    fixed_ht.build_fixed()?;
                    fixed_built = true;
                }
                pw.insert(&PuffData::BlockMetadata(&[block_header]))?;
                false
            }
            BlockType::Dynamic => {
                let mut meta = [0u8; BLOCK_METADATA_MAX];
                meta[0] = block_header;
                let written = dyn_ht.build_dynamic_from_deflate(br, &mut meta[1..])?;
                pw.insert(&PuffData::BlockMetadata(&meta[..written + 1]))?;
                true
            }
        };

        loop {
            check_cancelled(cancellation_token)?;
            let cur_ht: &HuffmanTable = if use_dynamic { &dyn_ht } else { &fixed_ht };
            let mut max_bits = cur_ht.lit_len_max_bits();
            if !br.cache_bits(max_bits) {
                max_bits = cur_ht.end_of_block_bit_length()?;
            }
            if !br.cache_bits(max_bits) {
                return Err(Error::Corrupt("eof reading lit/len".into()));
            }
            let bits = br.read_bits(max_bits);
            let (lit_len_alphabet, nbits) = cur_ht.lit_len_alphabet(bits)?;
            if nbits > br.cached_bits() {
                return Err(Error::Corrupt("truncated lit/len Huffman code".into()));
            }
            br.drop_bits(nbits);

            if lit_len_alphabet < 256 {
                pw.insert(&PuffData::Literal(lit_len_alphabet as u8))?;
            } else if lit_len_alphabet == 256 {
                pw.insert(&PuffData::EndOfBlock)?;
                break;
            } else {
                if lit_len_alphabet > 285 {
                    return Err(Error::Corrupt("lit/len alphabet > 285".into()));
                }
                let len_code_start = (lit_len_alphabet - 257) as usize;
                let extra_len = LENGTH_EXTRA_BITS[len_code_start] as usize;
                let mut extra_val = 0u32;
                if extra_len != 0 {
                    if !br.cache_bits(extra_len) {
                        return Err(Error::Corrupt("eof reading length extra".into()));
                    }
                    extra_val = br.read_bits(extra_len);
                    br.drop_bits(extra_len);
                }
                let length = LENGTH_BASES[len_code_start] as usize + extra_val as usize;

                let mut bits_to_cache = cur_ht.distance_max_bits();
                if !br.cache_bits(bits_to_cache) {
                    // Rare legacy corner case (crbug.com/915559): not enough
                    // bits for a full-width distance code near the stream end.
                    bits_to_cache = br.bits_remaining() as usize;
                    if !br.cache_bits(bits_to_cache) {
                        return Err(Error::Corrupt("eof reading distance".into()));
                    }
                }
                let dbits = br.read_bits(bits_to_cache);
                let (distance_alphabet, nbits) = cur_ht.distance_alphabet(dbits)?;
                if nbits > br.cached_bits() {
                    return Err(Error::Corrupt("truncated distance Huffman code".into()));
                }
                br.drop_bits(nbits);

                let extra_len = DISTANCE_EXTRA_BITS[distance_alphabet as usize] as usize;
                let mut extra_val = 0u32;
                if extra_len != 0 {
                    if !br.cache_bits(extra_len) {
                        return Err(Error::Corrupt("eof reading distance extra".into()));
                    }
                    extra_val = br.read_bits(extra_len);
                    br.drop_bits(extra_len);
                }
                let distance =
                    DISTANCE_BASES[distance_alphabet as usize] as usize + extra_val as usize;
                pw.insert(&PuffData::LenDist { length, distance })?;
            }
        }
    }
    pw.flush()?;
    check_cancelled(cancellation_token)?;
    Ok(())
}
