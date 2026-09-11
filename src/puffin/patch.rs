// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Adapted from puffdiff 0.1.0 and ChromiumOS Puffin's puffpatch.cc.

use std::io::Read;

use brotli::Decompressor as BrotliDecoder;
use bzip2::read::BzDecoder;

use crate::puffin::{BitExtent, ByteExtent, Error, Result, check_cancelled, stream};
use crate::{CancellationToken, validate_bsdiff_output_len, zucchini};

const MAGIC: &[u8; 4] = b"PUF1";
const PATCH_TYPE_BSDIFF: i32 = 0;
const DECODE_CHUNK_SIZE: usize = 32 * 1024;

#[derive(Clone, Copy)]
enum Compression {
    None,
    Bzip2,
    Brotli,
}

struct StreamInfo {
    deflates: Vec<BitExtent>,
    puffs: Vec<ByteExtent>,
    puff_length: usize,
}

impl StreamInfo {
    fn empty() -> Self {
        Self { deflates: Vec::new(), puffs: Vec::new(), puff_length: 0 }
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn at_end(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for index in 0..10 {
            let byte = *self
                .bytes
                .get(self.position)
                .ok_or_else(|| Error::BadProto("truncated protobuf varint".into()))?;
            self.position += 1;
            if index == 9 && byte > 1 {
                return Err(Error::BadProto("protobuf varint overflows u64".into()));
            }
            value |= u64::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(Error::BadProto("protobuf varint is too long".into()))
    }

    fn length_delimited(&mut self) -> Result<&'a [u8]> {
        let length = usize::try_from(self.varint()?)
            .map_err(|_| Error::BadProto("protobuf field length is too large".into()))?;
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| Error::BadProto("protobuf field range overflows".into()))?;
        let field = self.bytes.get(self.position..end).ok_or_else(|| {
            Error::BadProto("length-delimited protobuf field overruns header".into())
        })?;
        self.position = end;
        Ok(field)
    }

    fn skip(&mut self, wire_type: u8) -> Result<()> {
        match wire_type {
            0 => {
                self.varint()?;
            }
            1 => self.advance(8)?,
            2 => {
                self.length_delimited()?;
            }
            5 => self.advance(4)?,
            _ => {
                return Err(Error::BadProto(format!("unsupported protobuf wire type {wire_type}")));
            }
        }
        Ok(())
    }

    fn advance(&mut self, count: usize) -> Result<()> {
        let end = self
            .position
            .checked_add(count)
            .ok_or_else(|| Error::BadProto("protobuf field range overflows".into()))?;
        if end > self.bytes.len() {
            return Err(Error::BadProto("protobuf field overruns header".into()));
        }
        self.position = end;
        Ok(())
    }

    fn key(&mut self) -> Result<(u64, u8)> {
        let key = self.varint()?;
        let field = key >> 3;
        if field == 0 {
            return Err(Error::BadProto("protobuf field number is zero".into()));
        }
        Ok((field, (key & 7) as u8))
    }
}

fn parse_bit_extent(bytes: &[u8]) -> Result<(u64, u64)> {
    let mut cursor = Cursor::new(bytes);
    let mut offset = 0u64;
    let mut length = 0u64;
    while !cursor.at_end() {
        let (field, wire_type) = cursor.key()?;
        match (field, wire_type) {
            (1, 0) => offset = cursor.varint()?,
            (2, 0) => length = cursor.varint()?,
            _ => cursor.skip(wire_type)?,
        }
    }
    Ok((offset, length))
}

fn push_extent<T>(extents: &mut Vec<T>, extent: T) -> Result<()> {
    extents
        .try_reserve(1)
        .map_err(|error| Error::Allocation(format!("PUFFDIFF extent metadata: {error}")))?;
    extents.push(extent);
    Ok(())
}

fn parse_stream_info(bytes: &[u8]) -> Result<StreamInfo> {
    let mut info = StreamInfo::empty();
    let mut cursor = Cursor::new(bytes);
    while !cursor.at_end() {
        let (field, wire_type) = cursor.key()?;
        match (field, wire_type) {
            (1, 2) => {
                let (offset, length) = parse_bit_extent(cursor.length_delimited()?)?;
                push_extent(
                    &mut info.deflates,
                    BitExtent {
                        offset: usize::try_from(offset).map_err(|_| {
                            Error::InvalidMetadata("deflate offset is too large".into())
                        })?,
                        length: usize::try_from(length).map_err(|_| {
                            Error::InvalidMetadata("deflate length is too large".into())
                        })?,
                    },
                )?;
            }
            (2, 2) => {
                let (offset, length) = parse_bit_extent(cursor.length_delimited()?)?;
                if offset % 8 != 0 || length % 8 != 0 {
                    return Err(Error::InvalidMetadata("puff extent is not byte-aligned".into()));
                }
                push_extent(
                    &mut info.puffs,
                    ByteExtent {
                        offset: usize::try_from(offset / 8).map_err(|_| {
                            Error::InvalidMetadata("puff offset is too large".into())
                        })?,
                        length: usize::try_from(length / 8).map_err(|_| {
                            Error::InvalidMetadata("puff length is too large".into())
                        })?,
                    },
                )?;
            }
            (3, 0) => {
                info.puff_length = usize::try_from(cursor.varint()?).map_err(|_| {
                    Error::InvalidMetadata("puff stream length is too large".into())
                })?;
            }
            _ => cursor.skip(wire_type)?,
        }
    }
    Ok(info)
}

struct PatchHeader {
    source: StreamInfo,
    destination: StreamInfo,
    patch_type: i32,
}

fn parse_header(bytes: &[u8]) -> Result<PatchHeader> {
    let mut source = StreamInfo::empty();
    let mut destination = StreamInfo::empty();
    let mut patch_type = PATCH_TYPE_BSDIFF;
    let mut cursor = Cursor::new(bytes);
    while !cursor.at_end() {
        let (field, wire_type) = cursor.key()?;
        match (field, wire_type) {
            (1, 0) => {
                cursor.varint()?;
            }
            (2, 2) => source = parse_stream_info(cursor.length_delimited()?)?,
            (3, 2) => destination = parse_stream_info(cursor.length_delimited()?)?,
            (4, 0) => patch_type = cursor.varint()? as u32 as i32,
            _ => cursor.skip(wire_type)?,
        }
    }
    Ok(PatchHeader { source, destination, patch_type })
}

fn validate_extents<T>(
    extents: &[T],
    label: &str,
    limit: usize,
    parts: impl Fn(&T) -> (usize, usize),
) -> Result<()> {
    let mut previous_end = 0usize;
    for (index, extent) in extents.iter().enumerate() {
        let (offset, length) = parts(extent);
        if length == 0 {
            return Err(Error::InvalidMetadata(format!("{label} extent {index} is empty")));
        }
        let end = offset
            .checked_add(length)
            .ok_or_else(|| Error::InvalidMetadata(format!("{label} extent {index} overflows")))?;
        if index != 0 && offset < previous_end {
            return Err(Error::InvalidMetadata(format!("{label} extents overlap or are unsorted")));
        }
        if end > limit {
            return Err(Error::InvalidMetadata(format!(
                "{label} extent {index} exceeds its stream"
            )));
        }
        previous_end = end;
    }
    Ok(())
}

fn validate_stream(info: &StreamInfo, raw_size: usize, label: &str) -> Result<()> {
    if info.puff_length >= zucchini::OFFSET_BOUND {
        return Err(Error::InvalidMetadata(format!(
            "{label} puff length exceeds the maximum of {} bytes",
            zucchini::OFFSET_BOUND - 1
        )));
    }
    if info.deflates.len() != info.puffs.len() {
        return Err(Error::InvalidMetadata(format!(
            "{label} deflate and puff extent counts differ"
        )));
    }
    validate_extents(&info.deflates, "deflate", usize::MAX, |extent| {
        (extent.offset, extent.length)
    })?;
    validate_extents(&info.puffs, "puff", info.puff_length, |extent| {
        (extent.offset, extent.length)
    })?;

    let computed_raw_size =
        match (info.deflates.last(), info.puffs.last()) {
            (Some(deflate), Some(puff)) => {
                let deflate_end = deflate
                    .offset
                    .checked_add(deflate.length)
                    .ok_or_else(|| Error::InvalidMetadata("deflate end overflows".into()))?;
                let puff_end = puff
                    .offset
                    .checked_add(puff.length)
                    .ok_or_else(|| Error::InvalidMetadata("puff end overflows".into()))?;
                (deflate_end / 8)
                    .checked_add(info.puff_length.checked_sub(puff_end).ok_or_else(|| {
                        Error::InvalidMetadata("puff extent exceeds stream".into())
                    })?)
                    .ok_or_else(|| Error::InvalidMetadata(format!("{label} raw size overflows")))?
            }
            (None, None) => info.puff_length,
            _ => {
                return Err(Error::InvalidMetadata(format!(
                    "{label} deflate and puff extent counts differ"
                )));
            }
        };
    if computed_raw_size != raw_size {
        return Err(Error::InvalidMetadata(format!(
            "{label} raw size mismatch: metadata describes {computed_raw_size} bytes, operation provides {raw_size}"
        )));
    }
    let raw_bits = raw_size
        .checked_mul(8)
        .ok_or_else(|| Error::InvalidMetadata(format!("{label} raw bit length overflows")))?;
    for (index, extent) in info.deflates.iter().enumerate() {
        let end = extent
            .offset
            .checked_add(extent.length)
            .ok_or_else(|| Error::InvalidMetadata("deflate extent end overflows".into()))?;
        if end > raw_bits {
            return Err(Error::InvalidMetadata(format!(
                "deflate extent {index} exceeds its stream"
            )));
        }
    }
    Ok(())
}

fn sign_magnitude_usize(bytes: &[u8], label: &str) -> Result<usize> {
    let encoded = u64::from_le_bytes(
        bytes
            .get(..8)
            .ok_or_else(|| Error::Bsdiff(format!("truncated {label}")))?
            .try_into()
            .map_err(|_| Error::Bsdiff(format!("invalid {label}")))?,
    );
    if encoded & (1 << 63) != 0 {
        return Err(Error::Bsdiff(format!("negative {label}")));
    }
    usize::try_from(encoded).map_err(|_| Error::Bsdiff(format!("{label} is too large")))
}

fn compression(value: u8, label: &str) -> Result<Compression> {
    match value {
        0 => Ok(Compression::None),
        1 => Ok(Compression::Bzip2),
        2 => Ok(Compression::Brotli),
        _ => Err(Error::Bsdiff(format!("unsupported {label} compression algorithm {value}"))),
    }
}

fn check_decoded_bound(
    mut reader: impl Read,
    maximum: usize,
    label: &str,
    cancellation_token: &CancellationToken,
) -> Result<()> {
    let mut decoded = 0usize;
    let mut buffer = [0u8; DECODE_CHUNK_SIZE];
    loop {
        check_cancelled(cancellation_token)?;
        let remaining = maximum
            .checked_sub(decoded)
            .ok_or_else(|| Error::Bsdiff(format!("decoded {label} stream exceeds its bound")))?;
        let read_size = buffer.len().min(remaining.saturating_add(1));
        let count = reader
            .read(&mut buffer[..read_size])
            .map_err(|error| Error::Bsdiff(format!("unable to decode {label} stream: {error}")))?;
        if count == 0 {
            return Ok(());
        }
        if count > remaining {
            return Err(Error::Bsdiff(format!(
                "decoded {label} stream exceeds its bound of {maximum} bytes"
            )));
        }
        decoded = decoded
            .checked_add(count)
            .ok_or_else(|| Error::Bsdiff(format!("decoded {label} length overflows")))?;
    }
}

fn validate_compressed_stream(
    algorithm: Compression,
    bytes: &[u8],
    maximum: usize,
    label: &str,
    cancellation_token: &CancellationToken,
) -> Result<()> {
    match algorithm {
        Compression::None => {
            if bytes.len() > maximum {
                return Err(Error::Bsdiff(format!(
                    "uncompressed {label} stream exceeds its bound of {maximum} bytes"
                )));
            }
            Ok(())
        }
        Compression::Bzip2 => {
            check_decoded_bound(BzDecoder::new(bytes), maximum, label, cancellation_token)
        }
        Compression::Brotli => check_decoded_bound(
            BrotliDecoder::new(bytes, DECODE_CHUNK_SIZE),
            maximum,
            label,
            cancellation_token,
        ),
    }
}

fn validate_inner_bsdiff_resources(
    patch: &[u8],
    output_size: usize,
    cancellation_token: &CancellationToken,
) -> Result<()> {
    let header = patch
        .get(..32)
        .ok_or_else(|| Error::Bsdiff("patch data is shorter than 32 bytes".into()))?;
    let algorithms = if &header[..8] == b"BSDIFF40" {
        [Compression::Bzip2; 3]
    } else if &header[..5] == b"BSDF2" {
        [
            compression(header[5], "control")?,
            compression(header[6], "diff")?,
            compression(header[7], "extra")?,
        ]
    } else {
        return Err(Error::Bsdiff("invalid BSDIFF/BSDF2 magic header".into()));
    };
    let control_length = sign_magnitude_usize(&header[8..16], "control stream length")?;
    let diff_length = sign_magnitude_usize(&header[16..24], "diff stream length")?;
    let control_end = 32usize
        .checked_add(control_length)
        .ok_or_else(|| Error::Bsdiff("control stream range overflows".into()))?;
    let diff_end = control_end
        .checked_add(diff_length)
        .ok_or_else(|| Error::Bsdiff("diff stream range overflows".into()))?;
    let control = patch
        .get(32..control_end)
        .ok_or_else(|| Error::Bsdiff("control stream exceeds patch".into()))?;
    let diff = patch
        .get(control_end..diff_end)
        .ok_or_else(|| Error::Bsdiff("diff stream exceeds patch".into()))?;
    let extra = patch
        .get(diff_end..)
        .ok_or_else(|| Error::Bsdiff("extra stream offset exceeds patch".into()))?;
    let control_bound =
        output_size.saturating_mul(48).saturating_add(4096).min(zucchini::OFFSET_BOUND - 1);
    validate_compressed_stream(
        algorithms[0],
        control,
        control_bound,
        "control",
        cancellation_token,
    )?;
    validate_compressed_stream(algorithms[1], diff, output_size, "diff", cancellation_token)?;
    validate_compressed_stream(algorithms[2], extra, output_size, "extra", cancellation_token)?;
    Ok(())
}

pub(crate) fn validate_bsdiff_resources(
    patch: &[u8],
    output_size: usize,
    cancellation_token: &CancellationToken,
) -> Result<()> {
    validate_inner_bsdiff_resources(patch, output_size, cancellation_token)
}

pub fn apply(
    source: &[u8],
    patch: &[u8],
    destination_size: usize,
    cancellation_token: &CancellationToken,
) -> Result<Vec<u8>> {
    check_cancelled(cancellation_token)?;
    let prefix = patch
        .get(..8)
        .ok_or_else(|| Error::BadPatchHeader("patch is shorter than eight bytes".into()))?;
    if &prefix[..4] != MAGIC {
        return Err(Error::BadPatchHeader("missing PUF1 magic".into()));
    }
    let header_size =
        usize::try_from(u32::from_be_bytes([prefix[4], prefix[5], prefix[6], prefix[7]]))
            .map_err(|_| Error::BadPatchHeader("protobuf header is too large".into()))?;
    let header_end = 8usize
        .checked_add(header_size)
        .ok_or_else(|| Error::BadPatchHeader("protobuf header range overflows".into()))?;
    let header_bytes = patch
        .get(8..header_end)
        .ok_or_else(|| Error::BadPatchHeader("protobuf header overruns patch".into()))?;
    let header = parse_header(header_bytes)?;
    if header.patch_type != PATCH_TYPE_BSDIFF {
        return Err(Error::UnsupportedPatchType(header.patch_type));
    }
    validate_stream(&header.source, source.len(), "source")?;
    validate_stream(&header.destination, destination_size, "destination")?;
    let raw_patch = patch
        .get(header_end..)
        .ok_or_else(|| Error::BadPatchHeader("inner patch offset is invalid".into()))?;

    check_cancelled(cancellation_token)?;
    let puffed_source = stream::puff(
        source,
        &header.source.deflates,
        &header.source.puffs,
        header.source.puff_length,
        cancellation_token,
    )?;

    check_cancelled(cancellation_token)?;
    validate_bsdiff_output_len(raw_patch, header.destination.puff_length)
        .map_err(|error| Error::Bsdiff(error.to_string()))?;
    validate_inner_bsdiff_resources(raw_patch, header.destination.puff_length, cancellation_token)?;
    let mut puffed_destination = Vec::new();
    puffed_destination
        .try_reserve_exact(header.destination.puff_length)
        .map_err(|error| Error::Allocation(format!("puffed destination: {error}")))?;
    bsdiff_android::patch_bsdf2(&puffed_source, raw_patch, &mut puffed_destination)
        .map_err(|error| Error::Bsdiff(error.to_string()))?;
    if puffed_destination.len() != header.destination.puff_length {
        return Err(Error::SizeMismatch {
            expected: header.destination.puff_length,
            actual: puffed_destination.len(),
        });
    }

    check_cancelled(cancellation_token)?;
    let destination = stream::huff(
        &puffed_destination,
        &header.destination.deflates,
        &header.destination.puffs,
        header.destination.puff_length,
        destination_size,
        cancellation_token,
    )?;
    check_cancelled(cancellation_token)?;
    Ok(destination)
}
