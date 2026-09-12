//! Local BSDF2/BSDIFF40 patch header and stream reader.
//!
//! Replaces the external `bsdiff-android` crate, of which only
//! `parse_bsdf2_header` was ever linked. The apply loop itself lives in
//! `lib.rs`; this module reproduces the header semantics bit-exactly:
//!
//! - `BSDIFF40`: all three streams are bzip2-compressed.
//! - `BSDF2`: magic bytes 5..8 select a per-stream algorithm
//!   (`0` = stored, `1` = bzip2, `2` = brotli).
//! - Lengths use the bspatch sign-magnitude 64-bit encoding (`offtin`).
//! - The extra stream spans the remainder of the patch.

use std::io::Read;

use anyhow::{Result, bail, ensure};

enum Algorithm {
    None,
    Bz2,
    Brotli,
}

type ParsedPatch = (i64, Vec<u8>, Vec<u8>, Vec<u8>);

fn algorithm_from_byte(value: u8) -> Result<Algorithm> {
    match value {
        0 => Ok(Algorithm::None),
        1 => Ok(Algorithm::Bz2),
        2 => Ok(Algorithm::Brotli),
        _ => bail!("Unknown BSDF2 compression algorithm: {value}"),
    }
}

/// Reads a sign-magnitude 64-bit integer as used by bspatch. This is not plain
/// little-endian: the top bit encodes the sign of the magnitude.
#[inline]
fn offtin(buf: [u8; 8]) -> i64 {
    let value = i64::from_le_bytes(buf);
    if value & (1 << 63) == 0 { value } else { -(value & !(1 << 63)) }
}

fn decompress_bz2(data: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut decoder = bzip2::read::BzDecoder::new(data);
    decoder.read_to_end(&mut output)?;
    Ok(output)
}

fn decompress_brotli(data: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut decoder = brotli::Decompressor::new(data, 4096);
    decoder.read_to_end(&mut output)?;
    Ok(output)
}

fn decompress(algorithm: Algorithm, data: &[u8]) -> Result<Vec<u8>> {
    match algorithm {
        Algorithm::None => Ok(data.to_vec()),
        Algorithm::Bz2 => decompress_bz2(data),
        Algorithm::Brotli => decompress_brotli(data),
    }
}

/// Parses a BSDIFF40/BSDF2 patch header and returns the decompressed
/// `(new_size, control, diff, extra)` streams.
pub fn parse_header(patch: &[u8]) -> Result<ParsedPatch> {
    ensure!(patch.len() >= 32, "Patch data too short");

    let magic = &patch[0..8];
    let (control_algorithm, diff_algorithm, extra_algorithm) = if magic == b"BSDIFF40" {
        (Algorithm::Bz2, Algorithm::Bz2, Algorithm::Bz2)
    } else if &magic[0..5] == b"BSDF2" {
        (
            algorithm_from_byte(magic[5])?,
            algorithm_from_byte(magic[6])?,
            algorithm_from_byte(magic[7])?,
        )
    } else {
        bail!("Invalid BSDIFF/BSDF2 magic header");
    };

    let control_length = offtin(patch[8..16].try_into()?);
    let diff_length = offtin(patch[16..24].try_into()?);
    let new_size = offtin(patch[24..32].try_into()?);
    ensure!(
        control_length >= 0 && diff_length >= 0 && new_size >= 0,
        "Negative length in patch header"
    );
    let (control_length, diff_length) = (control_length as usize, diff_length as usize);

    let control_end = 32usize
        .checked_add(control_length)
        .ok_or_else(|| anyhow::anyhow!("Control stream length overflows patch bounds"))?;
    ensure!(control_end <= patch.len(), "Control stream exceeds patch bounds");
    let diff_end = control_end
        .checked_add(diff_length)
        .ok_or_else(|| anyhow::anyhow!("Diff stream length overflows patch bounds"))?;
    ensure!(diff_end <= patch.len(), "Diff stream exceeds patch bounds");

    let control = decompress(control_algorithm, &patch[32..control_end])?;
    ensure!(control.len() % 24 == 0, "Invalid control data length (not multiple of 24)");
    let diff = decompress(diff_algorithm, &patch[control_end..diff_end])?;
    let extra = decompress(extra_algorithm, &patch[diff_end..])?;
    Ok((new_size, control, diff, extra))
}
