// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Adapted from puffdiff 0.1.0, a pure-Rust port of ChromiumOS Puffin.

//! Puff -> deflate transform, ported from puffin `huffer.cc`.

use crate::CancellationToken;
use crate::puffin::bit_io::BitWriter;
use crate::puffin::huffman::{
    BlockType, DISTANCE_BASES, DISTANCE_EXTRA_BITS, HuffmanTable, LENGTH_BASES, LENGTH_EXTRA_BITS,
};
use crate::puffin::puff_io::{PuffData, PuffReader};
use crate::puffin::{Error, Result, check_cancelled};

/// Re-encode puff tokens from `pr` back into a bit-exact deflate stream in `bw`.
pub fn huff_deflate(
    pr: &mut PuffReader,
    bw: &mut BitWriter,
    cancellation_token: &CancellationToken,
) -> Result<()> {
    let mut fixed_ht = HuffmanTable::new()?;
    let mut dyn_ht = HuffmanTable::new()?;
    let mut fixed_built = false;

    while pr.bytes_left() != 0 {
        check_cancelled(cancellation_token)?;
        let pd = pr.get_next()?;
        let meta = match pd {
            PuffData::BlockMetadata(m) => m,
            _ => return Err(Error::Corrupt("expected block metadata".into())),
        };
        let header = meta[0];
        let final_bit = (header & 0x80) >> 7;
        let btype = (header & 0x60) >> 5;
        let skipped_bits = header & 0x1F;

        bw.write_bits(1, final_bit as u32)?;
        bw.write_bits(2, btype as u32)?;

        let use_dynamic = match BlockType::from_bits(btype)? {
            BlockType::Uncompressed => {
                bw.write_boundary_bits(skipped_bits)?;
                let next = pr.get_next()?;
                match next {
                    PuffData::Literals(raw) => {
                        bw.write_bits(16, raw.len() as u32)?;
                        bw.write_bits(16, !(raw.len() as u32) & 0xFFFF)?;
                        bw.write_bytes(raw)?;
                        match pr.get_next()? {
                            PuffData::EndOfBlock => {}
                            _ => return Err(Error::Corrupt("uncompressed block not ended".into())),
                        }
                    }
                    PuffData::EndOfBlock => {
                        bw.write_bits(16, 0)?;
                        bw.write_bits(16, 0xFFFF)?;
                    }
                    PuffData::Literal(_) => {
                        return Err(Error::Corrupt("unexpected single literal".into()));
                    }
                    _ => return Err(Error::Corrupt("uncompressed block malformed".into())),
                }
                continue;
            }
            BlockType::Fixed => {
                if !fixed_built {
                    fixed_ht.build_fixed()?;
                    fixed_built = true;
                }
                false
            }
            BlockType::Dynamic => {
                dyn_ht.build_dynamic_from_puff(&meta[1..], bw)?;
                true
            }
        };

        let mut block_ended = false;
        while !block_ended {
            check_cancelled(cancellation_token)?;
            let pd = pr.get_next()?;
            let cur_ht: &HuffmanTable = if use_dynamic { &dyn_ht } else { &fixed_ht };
            match pd {
                PuffData::Literal(b) => {
                    let (code, nbits) = cur_ht.lit_len_huffman(b as u16)?;
                    bw.write_bits(nbits, code as u32)?;
                }
                PuffData::Literals(bytes) => {
                    for &b in bytes {
                        check_cancelled(cancellation_token)?;
                        let (code, nbits) = cur_ht.lit_len_huffman(b as u16)?;
                        bw.write_bits(nbits, code as u32)?;
                    }
                }
                PuffData::LenDist { length, distance } => {
                    if !(3..=258).contains(&length) {
                        return Err(Error::Corrupt("length out of range".into()));
                    }
                    // Linear search for the length base (guard stops us short).
                    let mut index = 0usize;
                    while length > LENGTH_BASES[index] as usize {
                        index += 1;
                    }
                    if length < LENGTH_BASES[index] as usize {
                        index -= 1;
                    }
                    let extra_len = LENGTH_EXTRA_BITS[index] as usize;
                    let (code, nbits) = cur_ht.lit_len_huffman((index + 257) as u16)?;
                    bw.write_bits(nbits, code as u32)?;
                    if extra_len > 0 {
                        bw.write_bits(extra_len, (length - LENGTH_BASES[index] as usize) as u32)?;
                    }

                    let mut index = 0usize;
                    while distance > DISTANCE_BASES[index] as usize {
                        index += 1;
                    }
                    if distance < DISTANCE_BASES[index] as usize {
                        index -= 1;
                    }
                    let extra_len = DISTANCE_EXTRA_BITS[index] as usize;
                    let (code, nbits) = cur_ht.distance_huffman(index as u16)?;
                    bw.write_bits(nbits, code as u32)?;
                    if extra_len > 0 {
                        bw.write_bits(
                            extra_len,
                            (distance - DISTANCE_BASES[index] as usize) as u32,
                        )?;
                    }
                }
                PuffData::EndOfBlock => {
                    let (code, nbits) = cur_ht.lit_len_huffman(256)?;
                    bw.write_bits(nbits, code as u32)?;
                    block_ended = true;
                }
                PuffData::BlockMetadata(_) => {
                    return Err(Error::Corrupt("unexpected block metadata".into()));
                }
            }
        }
    }
    check_cancelled(cancellation_token)?;
    Ok(())
}
