// Copyright 2026 otadump contributors
// SPDX-License-Identifier: MIT

use anyhow::{Context as _, Result, bail, ensure};
use bsdiff_android::patch_bsdf2;
use prost::Message as _;
use ring::digest;

use crate::{CancellationToken, lz4, puffin, validate_bsdiff_output_len, zucchini};

const MAGIC: &[u8; 7] = b"LZ4DIFF";
const FRAMING_SIZE: usize = 16;
const VERSION: u32 = 1;
const EROFS_BLOCK_SIZE: usize = 4096;
const PROTOBUF_RECURSION_LIMIT: usize = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InnerPatch {
    Bsdiff,
    Puffdiff,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Algorithm {
    Uncompressed,
    Lz4,
    Lz4hc,
}

struct Block<'a> {
    uncompressed_offset: usize,
    uncompressed_length: usize,
    compressed_length: usize,
    sha256_hash: &'a [u8],
    postfix_bspatch: &'a [u8],
}

struct CompressionInfo<'a> {
    algorithm: Algorithm,
    level: i32,
    blocks: Vec<Block<'a>>,
    zero_padding_enabled: bool,
    uncompressed_size: usize,
    physical_size: usize,
}

pub(crate) struct Patch<'a> {
    source: CompressionInfo<'a>,
    destination: CompressionInfo<'a>,
    inner_patch: &'a [u8],
    inner_type: InnerPatch,
}

#[derive(Clone, Copy, PartialEq, Eq, prost::Message)]
struct CompressionAlgorithmProto {
    #[prost(enumeration = "AlgorithmProto", tag = "1")]
    r#type: i32,
    #[prost(int32, tag = "2")]
    level: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum AlgorithmProto {
    Uncompressed = 0,
    Lz4 = 1,
    Lz4hc = 2,
}

#[derive(Clone, PartialEq, Eq, prost::Message)]
struct BlockProto {
    #[prost(uint64, tag = "1")]
    uncompressed_offset: u64,
    #[prost(uint64, tag = "2")]
    uncompressed_length: u64,
    #[prost(uint64, tag = "3")]
    compressed_length: u64,
}

#[derive(Clone, PartialEq, prost::Message)]
struct CompressionInfoProto {
    #[prost(message, optional, tag = "1")]
    algo: Option<CompressionAlgorithmProto>,
    #[prost(message, repeated, tag = "2")]
    block_info: Vec<BlockProto>,
    #[prost(bool, tag = "3")]
    zero_padding_enabled: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
struct HeaderProto {
    #[prost(message, optional, tag = "1")]
    src_info: Option<CompressionInfoProto>,
    #[prost(message, optional, tag = "2")]
    dst_info: Option<CompressionInfoProto>,
    #[prost(enumeration = "InnerPatchProto", tag = "3")]
    inner_type: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum InnerPatchProto {
    Bsdiff = 0,
    Puffdiff = 1,
}

struct HeaderLayout<'a> {
    source_seen: bool,
    destination_seen: bool,
    source_blocks: Vec<&'a [u8]>,
    destination_blocks: Vec<&'a [u8]>,
}

struct ProtoCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> ProtoCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn at_end(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for index in 0..10 {
            let byte =
                *self.bytes.get(self.position).context("truncated LZ4DIFF protobuf varint")?;
            self.position += 1;
            if index == 9 && byte > 1 {
                bail!("LZ4DIFF protobuf varint overflows u64");
            }
            value |= u64::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        bail!("LZ4DIFF protobuf varint is too long")
    }

    fn key(&mut self) -> Result<(u64, u8)> {
        let key = self.varint()?;
        ensure!(key >> 3 != 0, "LZ4DIFF protobuf field number is zero");
        Ok((key >> 3, (key & 7) as u8))
    }

    fn bytes(&mut self) -> Result<&'a [u8]> {
        let length = usize::try_from(self.varint()?)
            .context("LZ4DIFF protobuf field length is too large")?;
        let end =
            self.position.checked_add(length).context("LZ4DIFF protobuf field range overflow")?;
        let bytes =
            self.bytes.get(self.position..end).context("LZ4DIFF protobuf field overruns header")?;
        self.position = end;
        Ok(bytes)
    }

    fn advance(&mut self, length: usize) -> Result<()> {
        let end =
            self.position.checked_add(length).context("LZ4DIFF protobuf field range overflow")?;
        ensure!(end <= self.bytes.len(), "LZ4DIFF protobuf field overruns header");
        self.position = end;
        Ok(())
    }

    fn skip(&mut self, field: u64, wire_type: u8) -> Result<()> {
        self.skip_with_depth(field, wire_type, 0)
    }

    fn skip_with_depth(&mut self, field: u64, wire_type: u8, depth: usize) -> Result<()> {
        match wire_type {
            0 => {
                self.varint()?;
            }
            1 => self.advance(8)?,
            2 => {
                self.bytes()?;
            }
            3 => {
                ensure!(
                    depth < PROTOBUF_RECURSION_LIMIT,
                    "LZ4DIFF protobuf recursion limit exceeded"
                );
                loop {
                    let (nested_field, nested_wire_type) = self.key()?;
                    if nested_wire_type == 4 {
                        ensure!(nested_field == field, "mismatched LZ4DIFF protobuf end group");
                        break;
                    }
                    self.skip_with_depth(nested_field, nested_wire_type, depth + 1)?;
                }
            }
            4 => bail!("unexpected LZ4DIFF protobuf end group"),
            5 => self.advance(4)?,
            _ => bail!("unsupported LZ4DIFF protobuf wire type {wire_type}"),
        }
        Ok(())
    }
}

fn scan_header(bytes: &[u8]) -> Result<HeaderLayout<'_>> {
    let mut layout = HeaderLayout {
        source_seen: false,
        destination_seen: false,
        source_blocks: Vec::new(),
        destination_blocks: Vec::new(),
    };
    let mut cursor = ProtoCursor::new(bytes);
    while !cursor.at_end() {
        let (field, wire_type) = cursor.key()?;
        match (field, wire_type) {
            (1, 2) => {
                layout.source_seen = true;
                scan_compression_info(cursor.bytes()?, &mut layout.source_blocks)?;
            }
            (2, 2) => {
                layout.destination_seen = true;
                scan_compression_info(cursor.bytes()?, &mut layout.destination_blocks)?;
            }
            _ => cursor.skip(field, wire_type)?,
        }
    }
    Ok(layout)
}

fn scan_compression_info<'a>(bytes: &'a [u8], blocks: &mut Vec<&'a [u8]>) -> Result<()> {
    let mut cursor = ProtoCursor::new(bytes);
    while !cursor.at_end() {
        let (field, wire_type) = cursor.key()?;
        if (field, wire_type) == (2, 2) {
            let block = cursor.bytes()?;
            blocks.try_reserve(1).context("unable to allocate LZ4DIFF block preflight")?;
            blocks.push(block);
        } else {
            cursor.skip(field, wire_type)?;
        }
    }
    Ok(())
}

fn scan_block_blobs(bytes: &[u8]) -> Result<(&[u8], &[u8])> {
    let mut sha256_hash = &[][..];
    let mut postfix_bspatch = &[][..];
    let mut cursor = ProtoCursor::new(bytes);
    while !cursor.at_end() {
        let (field, wire_type) = cursor.key()?;
        match (field, wire_type) {
            (4, 2) => sha256_hash = cursor.bytes()?,
            (5, 2) => postfix_bspatch = cursor.bytes()?,
            _ => cursor.skip(field, wire_type)?,
        }
    }
    Ok((sha256_hash, postfix_bspatch))
}

fn preallocated_info(block_count: usize) -> Result<CompressionInfoProto> {
    let mut block_info = Vec::new();
    block_info
        .try_reserve_exact(block_count)
        .context("unable to allocate LZ4DIFF protobuf block metadata")?;
    Ok(CompressionInfoProto { algo: None, block_info, zero_padding_enabled: false })
}

pub(crate) fn apply(
    source: &[u8],
    patch: Patch<'_>,
    cancellation_token: &CancellationToken,
) -> Result<Vec<u8>> {
    cancellation_token.check()?;
    ensure!(
        source.len() == patch.source.physical_size,
        "LZ4DIFF source size changed after validation"
    );
    let uncompressed_source = decompress_source(source, &patch.source, cancellation_token)?;
    cancellation_token.check()?;
    let uncompressed_destination = match patch.inner_type {
        InnerPatch::Bsdiff => apply_bsdiff(
            &uncompressed_source,
            patch.inner_patch,
            patch.destination.uncompressed_size,
            "inner BSDIFF",
            cancellation_token,
        )?,
        InnerPatch::Puffdiff => puffin::apply(
            &uncompressed_source,
            patch.inner_patch,
            patch.destination.uncompressed_size,
            cancellation_token,
        )
        .map_err(|error| preserve_puffin_error(error, "inner PUFFDIFF patch is invalid"))?,
    };
    ensure!(
        uncompressed_destination.len() == patch.destination.uncompressed_size,
        "LZ4DIFF inner output size mismatch: expected {}, got {}",
        patch.destination.uncompressed_size,
        uncompressed_destination.len()
    );
    cancellation_token.check()?;
    compress_destination(&uncompressed_destination, &patch.destination, cancellation_token)
}

pub(crate) fn parse<'a>(
    patch_data: &'a [u8],
    source_size: usize,
    destination_size: usize,
    expected_inner: InnerPatch,
    cancellation_token: &CancellationToken,
) -> Result<Patch<'a>> {
    ensure_below_bound(patch_data.len(), "patch")?;
    let framing = patch_data.get(..FRAMING_SIZE).context("LZ4DIFF framing is truncated")?;
    ensure!(&framing[..MAGIC.len()] == MAGIC, "invalid LZ4DIFF magic");
    let version =
        u32::from_be_bytes(framing[7..11].try_into().context("invalid LZ4DIFF version field")?);
    ensure!(version == VERSION, "unsupported LZ4DIFF version {version}");
    let header_size = usize::try_from(u32::from_be_bytes(
        framing[11..15].try_into().context("invalid LZ4DIFF header size field")?,
    ))
    .context("LZ4DIFF protobuf header is too large")?;
    ensure!(framing[15] == 0, "LZ4DIFF framing padding byte is not zero");
    ensure_below_bound(header_size, "protobuf header")?;
    let header_end =
        FRAMING_SIZE.checked_add(header_size).context("LZ4DIFF protobuf header range overflow")?;
    let header_bytes = patch_data
        .get(FRAMING_SIZE..header_end)
        .context("LZ4DIFF protobuf header overruns patch")?;
    let layout = scan_header(header_bytes)?;
    ensure!(layout.source_seen, "LZ4DIFF source compression info is missing");
    ensure!(layout.destination_seen, "LZ4DIFF destination compression info is missing");
    let mut header = HeaderProto {
        src_info: Some(preallocated_info(layout.source_blocks.len())?),
        dst_info: Some(preallocated_info(layout.destination_blocks.len())?),
        inner_type: 0,
    };
    header.merge(header_bytes).context("invalid LZ4DIFF protobuf header")?;
    let inner = InnerPatchProto::try_from(header.inner_type)
        .map_err(|_| anyhow::anyhow!("unknown LZ4DIFF inner patch type {}", header.inner_type))?;
    let actual_inner = match inner {
        InnerPatchProto::Bsdiff => InnerPatch::Bsdiff,
        InnerPatchProto::Puffdiff => InnerPatch::Puffdiff,
    };
    ensure!(
        actual_inner == expected_inner,
        "LZ4DIFF operation type does not match inner patch type"
    );
    let source = validate_info(
        header.src_info.context("LZ4DIFF source compression info is missing")?,
        &layout.source_blocks,
        "source",
        true,
        cancellation_token,
    )?;
    let destination = validate_info(
        header.dst_info.context("LZ4DIFF destination compression info is missing")?,
        &layout.destination_blocks,
        "destination",
        false,
        cancellation_token,
    )?;
    ensure!(
        source.physical_size == source_size,
        "LZ4DIFF source physical size mismatch: metadata describes {}, operation provides {source_size}",
        source.physical_size
    );
    ensure!(
        destination.physical_size == destination_size,
        "LZ4DIFF destination physical size mismatch: metadata describes {}, operation provides {destination_size}",
        destination.physical_size
    );
    let inner_patch = patch_data.get(header_end..).context("invalid LZ4DIFF inner patch offset")?;
    ensure!(!inner_patch.is_empty(), "LZ4DIFF inner patch is empty");
    ensure_below_bound(inner_patch.len(), "inner patch")?;
    Ok(Patch { source, destination, inner_patch, inner_type: actual_inner })
}

fn validate_info<'a>(
    info: CompressionInfoProto,
    block_messages: &[&'a [u8]],
    label: &str,
    is_source: bool,
    cancellation_token: &CancellationToken,
) -> Result<CompressionInfo<'a>> {
    cancellation_token.check()?;
    let algorithm = info.algo.context(format!("LZ4DIFF {label} algorithm is missing"))?;
    let algorithm_type = AlgorithmProto::try_from(algorithm.r#type).map_err(|_| {
        anyhow::anyhow!("unknown LZ4DIFF {label} compression algorithm {}", algorithm.r#type)
    })?;
    let algorithm_type = match algorithm_type {
        AlgorithmProto::Uncompressed => {
            ensure!(algorithm.level == 0, "LZ4DIFF {label} uncompressed level must be zero");
            Algorithm::Uncompressed
        }
        AlgorithmProto::Lz4 => {
            ensure!(algorithm.level == 0, "LZ4DIFF {label} LZ4 level must be zero");
            Algorithm::Lz4
        }
        AlgorithmProto::Lz4hc => {
            ensure!(
                (lz4::HC_LEVEL_MIN..=lz4::HC_LEVEL_MAX).contains(&algorithm.level),
                "LZ4DIFF {label} LZ4HC level must be in {}..={}",
                lz4::HC_LEVEL_MIN,
                lz4::HC_LEVEL_MAX
            );
            Algorithm::Lz4hc
        }
    };
    ensure!(!info.block_info.is_empty(), "LZ4DIFF {label} block list is empty");
    if info.zero_padding_enabled {
        ensure!(
            algorithm_type != Algorithm::Uncompressed,
            "LZ4DIFF {label} zero padding requires LZ4 compression"
        );
    }

    let mut blocks = Vec::new();
    blocks
        .try_reserve_exact(info.block_info.len())
        .context("unable to allocate LZ4DIFF block metadata")?;
    let mut uncompressed_size = 0usize;
    let mut physical_size = 0usize;
    let mut has_compressed_block = false;
    ensure!(
        info.block_info.len() == block_messages.len(),
        "LZ4DIFF {label} block preflight count mismatch"
    );
    for (index, (block, block_message)) in
        info.block_info.into_iter().zip(block_messages).enumerate()
    {
        cancellation_token.check()?;
        let (sha256_hash, postfix_bspatch) = scan_block_blobs(block_message)?;
        let uncompressed_offset = to_size(block.uncompressed_offset, label, index, "offset")?;
        let uncompressed_length = to_size(block.uncompressed_length, label, index, "length")?;
        let compressed_length = to_size(block.compressed_length, label, index, "physical length")?;
        ensure!(
            uncompressed_offset == uncompressed_size,
            "LZ4DIFF {label} blocks are not contiguous at block {index}"
        );
        ensure!(
            uncompressed_length > 0 && compressed_length > 0,
            "LZ4DIFF {label} block {index} has an empty length"
        );
        ensure!(
            compressed_length <= uncompressed_length,
            "LZ4DIFF {label} block {index} physical length exceeds its raw length"
        );
        has_compressed_block |= compressed_length < uncompressed_length;
        uncompressed_size = uncompressed_size
            .checked_add(uncompressed_length)
            .context(format!("LZ4DIFF {label} uncompressed size overflow"))?;
        physical_size = physical_size
            .checked_add(compressed_length)
            .context(format!("LZ4DIFF {label} physical size overflow"))?;
        ensure_below_bound(uncompressed_size, &format!("{label} uncompressed stream"))?;
        ensure_below_bound(physical_size, &format!("{label} physical stream"))?;

        if is_source {
            ensure!(
                sha256_hash.is_empty() && postfix_bspatch.is_empty(),
                "LZ4DIFF source block {index} contains destination-only metadata"
            );
        } else {
            ensure!(
                sha256_hash.is_empty() || sha256_hash.len() == digest::SHA256_OUTPUT_LEN,
                "LZ4DIFF destination block {index} SHA-256 hash must be empty or 32 bytes"
            );
            if !postfix_bspatch.is_empty() {
                ensure!(
                    compressed_length < uncompressed_length,
                    "LZ4DIFF destination raw block {index} cannot have a postfix patch"
                );
                ensure!(
                    sha256_hash.len() == digest::SHA256_OUTPUT_LEN,
                    "LZ4DIFF destination block {index} postfix patch requires a SHA-256 hash"
                );
                ensure_below_bound(postfix_bspatch.len(), "postfix patch")?;
                validate_bsdiff_output_len(postfix_bspatch, compressed_length)
                    .with_context(|| format!("LZ4DIFF destination block {index} postfix patch"))?;
                puffin::validate_bsdiff_resources(
                    postfix_bspatch,
                    compressed_length,
                    cancellation_token,
                )
                .map_err(|error| {
                    preserve_puffin_error(
                        error,
                        &format!("LZ4DIFF destination block {index} postfix patch is invalid"),
                    )
                })?;
            }
        }
        blocks.push(Block {
            uncompressed_offset,
            uncompressed_length,
            compressed_length,
            sha256_hash,
            postfix_bspatch,
        });
    }
    ensure!(
        algorithm_type != Algorithm::Uncompressed || !has_compressed_block,
        "LZ4DIFF {label} uses compressed blocks with the uncompressed algorithm"
    );
    Ok(CompressionInfo {
        algorithm: algorithm_type,
        level: algorithm.level,
        blocks,
        zero_padding_enabled: info.zero_padding_enabled,
        uncompressed_size,
        physical_size,
    })
}

fn to_size(value: u64, label: &str, index: usize, field: &str) -> Result<usize> {
    usize::try_from(value)
        .with_context(|| format!("LZ4DIFF {label} block {index} {field} is too large"))
}

fn ensure_below_bound(size: usize, label: &str) -> Result<()> {
    ensure!(
        size < zucchini::OFFSET_BOUND,
        "LZ4DIFF {label} exceeds the maximum size of {} bytes",
        zucchini::OFFSET_BOUND - 1
    );
    Ok(())
}

fn decompress_source(
    source: &[u8],
    info: &CompressionInfo,
    cancellation_token: &CancellationToken,
) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(info.uncompressed_size)
        .context("unable to allocate LZ4DIFF uncompressed source")?;
    let mut physical_offset = 0usize;
    for (index, block) in info.blocks.iter().enumerate() {
        cancellation_token.check()?;
        let end = physical_offset
            .checked_add(block.compressed_length)
            .context("LZ4DIFF source block range overflow")?;
        let physical = source
            .get(physical_offset..end)
            .with_context(|| format!("LZ4DIFF source block {index} exceeds source data"))?;
        if block.compressed_length == block.uncompressed_length {
            output.extend_from_slice(physical);
        } else {
            let margin = if info.zero_padding_enabled {
                physical
                    .iter()
                    .take(EROFS_BLOCK_SIZE.min(physical.len()))
                    .take_while(|byte| **byte == 0)
                    .count()
            } else {
                0
            };
            let compressed = physical
                .get(margin..)
                .with_context(|| format!("invalid LZ4DIFF source block {index} input margin"))?;
            let decompressed = lz4::decompress_safe_partial(compressed, block.uncompressed_length)
                .with_context(|| format!("unable to decompress LZ4DIFF source block {index}"))?;
            output.extend_from_slice(&decompressed);
        }
        physical_offset = end;
    }
    ensure!(
        physical_offset == source.len() && output.len() == info.uncompressed_size,
        "LZ4DIFF source block layout size mismatch"
    );
    Ok(output)
}

fn apply_bsdiff(
    source: &[u8],
    patch: &[u8],
    output_size: usize,
    label: &str,
    cancellation_token: &CancellationToken,
) -> Result<Vec<u8>> {
    validate_bsdiff_output_len(patch, output_size)
        .with_context(|| format!("LZ4DIFF {label} patch is invalid"))?;
    cancellation_token.check()?;
    puffin::validate_bsdiff_resources(patch, output_size, cancellation_token).map_err(|error| {
        preserve_puffin_error(error, &format!("LZ4DIFF {label} patch is invalid"))
    })?;
    cancellation_token.check()?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(output_size)
        .with_context(|| format!("unable to allocate LZ4DIFF {label} output"))?;
    patch_bsdf2(source, patch, &mut output)
        .with_context(|| format!("LZ4DIFF {label} patch is invalid"))?;
    cancellation_token.check()?;
    ensure!(
        output.len() == output_size,
        "LZ4DIFF {label} output size mismatch: expected {output_size}, got {}",
        output.len()
    );
    Ok(output)
}

fn preserve_puffin_error(error: puffin::Error, context: &str) -> anyhow::Error {
    let message = error.to_string();
    anyhow::Error::new(error).context(format!("{context}: {message}"))
}

fn compress_destination(
    uncompressed: &[u8],
    info: &CompressionInfo,
    cancellation_token: &CancellationToken,
) -> Result<Vec<u8>> {
    ensure!(
        uncompressed.len() == info.uncompressed_size,
        "LZ4DIFF destination uncompressed size mismatch"
    );
    let mut output = Vec::new();
    output
        .try_reserve_exact(info.physical_size)
        .context("unable to allocate LZ4DIFF destination")?;
    for (index, block) in info.blocks.iter().enumerate() {
        cancellation_token.check()?;
        let raw_end = block
            .uncompressed_offset
            .checked_add(block.uncompressed_length)
            .context("LZ4DIFF destination block range overflow")?;
        let raw = uncompressed
            .get(block.uncompressed_offset..raw_end)
            .with_context(|| format!("LZ4DIFF destination block {index} exceeds inner output"))?;
        if block.compressed_length == block.uncompressed_length {
            output.extend_from_slice(raw);
            continue;
        }
        let mut physical = {
            let remaining = uncompressed
                .get(block.uncompressed_offset..)
                .with_context(|| format!("invalid LZ4DIFF destination block {index} offset"))?;
            let level = match info.algorithm {
                Algorithm::Lz4 => None,
                Algorithm::Lz4hc => Some(info.level),
                Algorithm::Uncompressed => {
                    bail!("LZ4DIFF destination compressed block uses uncompressed algorithm")
                }
            };
            lz4::compress_dest_size_partial(
                remaining,
                block.uncompressed_length,
                block.compressed_length,
                level,
                info.zero_padding_enabled,
            )
            .with_context(|| format!("unable to compress LZ4DIFF destination block {index}"))?
        };
        ensure!(
            physical.len() == block.compressed_length,
            "LZ4DIFF destination block {index} physical size mismatch"
        );
        if !block.postfix_bspatch.is_empty() {
            cancellation_token.check()?;
            let actual = digest::digest(&digest::SHA256, &physical);
            ensure!(
                actual.as_ref() == block.sha256_hash,
                "LZ4DIFF destination block {index} reference recompression hash mismatch"
            );
            physical = apply_bsdiff(
                &physical,
                block.postfix_bspatch,
                block.compressed_length,
                "postfix BSDIFF",
                cancellation_token,
            )?;
        }
        output.extend_from_slice(&physical);
    }
    ensure!(
        output.len() == info.physical_size,
        "LZ4DIFF destination physical size mismatch after compression"
    );
    cancellation_token.check()?;
    Ok(output)
}
