use std::ops::Range;

use anyhow::{Context as _, Result, ensure};
use ring::digest;

use crate::CancellationToken;
use crate::chromeos_update_engine::{Extent, PartitionUpdate};

const SHA256_SIZE: usize = 32;
const FEC_BLOCK_SIZE: usize = 4096;
const FEC_SYMBOLS: usize = 255;

pub(crate) struct VerityConfig {
    hash_tree: Option<HashTreeConfig>,
    fec: Option<FecConfig>,
}

struct HashTreeConfig {
    data: Range<usize>,
    tree: Range<usize>,
    salt: Vec<u8>,
}

struct FecConfig {
    data: Range<usize>,
    storage: Range<usize>,
    roots: usize,
    rounds: usize,
}

pub(crate) fn validate(
    update: &PartitionUpdate,
    block_size: usize,
    partition_len: usize,
    operation_destinations: &[(Range<usize>, usize)],
) -> Result<Option<VerityConfig>> {
    let hash_tree = validate_hash_tree(update, block_size, partition_len, operation_destinations)?;
    let fec = validate_fec(
        update,
        block_size,
        partition_len,
        operation_destinations,
        hash_tree.as_ref(),
    )?;
    if hash_tree.is_none() && fec.is_none() {
        return Ok(None);
    }
    Ok(Some(VerityConfig { hash_tree, fec }))
}

fn validate_hash_tree(
    update: &PartitionUpdate,
    block_size: usize,
    partition_len: usize,
    operation_destinations: &[(Range<usize>, usize)],
) -> Result<Option<HashTreeConfig>> {
    let data_blocks =
        extent_num_blocks(update.hash_tree_data_extent.as_ref(), "Hash tree data")?.unwrap_or(0);
    let tree_blocks =
        extent_num_blocks(update.hash_tree_extent.as_ref(), "Hash tree")?.unwrap_or(0);
    ensure!(
        (data_blocks == 0) == (tree_blocks == 0),
        "Hash tree data and storage extents must both be nonempty"
    );
    if tree_blocks == 0 {
        return Ok(None);
    }

    let algorithm = update.hash_tree_algorithm.as_deref().unwrap_or_default();
    let is_sha256 =
        algorithm.eq_ignore_ascii_case("sha256") || algorithm.eq_ignore_ascii_case("sha-256");
    ensure!(is_sha256, "Unsupported verity hash algorithm: {algorithm:?}");
    ensure!(
        block_size > SHA256_SIZE * 2 && block_size % SHA256_SIZE == 0,
        "Block size {block_size} is not supported for SHA-256 verity trees"
    );

    let data_extent =
        update.hash_tree_data_extent.as_ref().context("Hash tree data extent is missing")?;
    let tree_extent =
        update.hash_tree_extent.as_ref().context("Hash tree storage extent is missing")?;
    let data = extent_range(data_extent, block_size, partition_len, "Hash tree data")?;
    let tree = extent_range(tree_extent, block_size, partition_len, "Hash tree")?;
    ensure!(!ranges_overlap(&data, &tree), "Hash tree data and storage extents overlap");
    ensure!(
        operation_destinations.iter().all(|(destination, _)| !ranges_overlap(&tree, destination)),
        "Hash tree extent overlaps destination extents"
    );

    let hashes_per_block = block_size / SHA256_SIZE;
    let mut level_blocks = div_ceil(data_blocks, hashes_per_block)?;
    let mut required_blocks = 0usize;
    loop {
        required_blocks =
            required_blocks.checked_add(level_blocks).context("Hash tree size overflow")?;
        if level_blocks == 1 {
            break;
        }
        level_blocks = div_ceil(level_blocks, hashes_per_block)?;
    }
    let required_size =
        required_blocks.checked_mul(block_size).context("Hash tree size overflow")?;
    ensure!(
        tree.len() == required_size,
        "Hash tree size mismatch: expected {required_size} bytes, got {}",
        tree.len()
    );

    Ok(Some(HashTreeConfig { data, tree, salt: update.hash_tree_salt.clone().unwrap_or_default() }))
}

pub(crate) fn generate(
    partition: &mut [u8],
    config: &VerityConfig,
    block_size: usize,
    cancellation_token: &CancellationToken,
) -> Result<()> {
    if let Some(hash_tree) = config.hash_tree.as_ref() {
        generate_hash_tree(partition, hash_tree, block_size, cancellation_token)?;
    }
    if let Some(fec) = config.fec.as_ref() {
        generate_fec(partition, fec, block_size, cancellation_token)?;
    }
    Ok(())
}

fn generate_hash_tree(
    partition: &mut [u8],
    config: &HashTreeConfig,
    block_size: usize,
    cancellation_token: &CancellationToken,
) -> Result<()> {
    cancellation_token.check()?;
    let hashes_per_block = block_size / SHA256_SIZE;
    let data_blocks = config.data.len() / block_size;
    let base_blocks = div_ceil(data_blocks, hashes_per_block)?;
    let mut level = zeroed_level(base_blocks, block_size)?;
    for (block, hash_slot) in partition[config.data.clone()]
        .chunks_exact(block_size)
        .zip(level.chunks_exact_mut(SHA256_SIZE))
    {
        cancellation_token.check()?;
        hash_slot.copy_from_slice(salted_hash(&config.salt, block).as_ref());
    }

    let mut levels = vec![level];
    while levels.last().expect("base level exists").len() > block_size {
        let current = levels.last().expect("base level exists");
        let next_blocks = div_ceil(current.len() / block_size, hashes_per_block)?;
        let mut next = zeroed_level(next_blocks, block_size)?;
        for (block, hash_slot) in
            current.chunks_exact(block_size).zip(next.chunks_exact_mut(SHA256_SIZE))
        {
            cancellation_token.check()?;
            hash_slot.copy_from_slice(salted_hash(&config.salt, block).as_ref());
        }
        levels.push(next);
    }

    let tree = &mut partition[config.tree.clone()];
    let mut offset = 0usize;
    for level in levels.iter().rev() {
        for block in level.chunks_exact(block_size) {
            cancellation_token.check()?;
            let end = offset.checked_add(block_size).context("Hash tree write overflow")?;
            tree[offset..end].copy_from_slice(block);
            offset = end;
        }
    }
    ensure!(offset == tree.len(), "Generated hash tree size mismatch");
    cancellation_token.check()
}

fn validate_fec(
    update: &PartitionUpdate,
    block_size: usize,
    partition_len: usize,
    operation_destinations: &[(Range<usize>, usize)],
    hash_tree: Option<&HashTreeConfig>,
) -> Result<Option<FecConfig>> {
    let data_blocks = extent_num_blocks(update.fec_data_extent.as_ref(), "FEC data")?.unwrap_or(0);
    let storage_blocks = extent_num_blocks(update.fec_extent.as_ref(), "FEC")?.unwrap_or(0);
    ensure!(
        (data_blocks == 0) == (storage_blocks == 0),
        "FEC data and storage extents must both be nonempty"
    );
    if storage_blocks == 0 {
        return Ok(None);
    }

    ensure!(block_size == FEC_BLOCK_SIZE, "FEC requires 4096-byte blocks");
    let roots =
        usize::try_from(update.fec_roots.unwrap_or(2)).context("FEC roots are too large")?;
    ensure!((1..FEC_SYMBOLS).contains(&roots), "FEC roots must be between 1 and 254");
    let data = extent_range(
        update.fec_data_extent.as_ref().context("FEC data extent is missing")?,
        block_size,
        partition_len,
        "FEC data",
    )?;
    let storage = extent_range(
        update.fec_extent.as_ref().context("FEC storage extent is missing")?,
        block_size,
        partition_len,
        "FEC storage",
    )?;
    ensure!(storage.start >= data.end, "FEC storage extent must follow the protected data extent");
    ensure!(
        operation_destinations
            .iter()
            .all(|(destination, _)| !ranges_overlap(&storage, destination)),
        "FEC storage extent overlaps destination extents"
    );
    if let Some(hash_tree) = hash_tree {
        ensure!(
            !ranges_overlap(&storage, &hash_tree.tree),
            "FEC storage extent overlaps hash tree extent"
        );
        ensure!(
            !ranges_overlap(&storage, &hash_tree.data),
            "FEC storage extent overlaps hash tree data extent"
        );
    }

    let rs_n = FEC_SYMBOLS - roots;
    let rounds = div_ceil(data_blocks, rs_n)?;
    let required_blocks = rounds.checked_mul(roots).context("FEC size overflow")?;
    let required_size = required_blocks.checked_mul(block_size).context("FEC size overflow")?;
    ensure!(
        storage.len() == required_size,
        "FEC size mismatch: expected {required_size} bytes, got {}",
        storage.len()
    );

    Ok(Some(FecConfig { data, storage, roots, rounds }))
}

fn generate_fec(
    partition: &mut [u8],
    config: &FecConfig,
    block_size: usize,
    cancellation_token: &CancellationToken,
) -> Result<()> {
    cancellation_token.check()?;
    let rs = ReedSolomon::new(config.roots)?;
    let rs_n = FEC_SYMBOLS - config.roots;
    let matrix_len = block_size.checked_mul(rs_n).context("FEC matrix size overflow")?;
    let parity_len = block_size.checked_mul(config.roots).context("FEC parity size overflow")?;
    let mut matrix = zeroed_buffer(matrix_len, "FEC matrix")?;
    let mut parity = zeroed_buffer(parity_len, "FEC parity")?;
    let data_blocks = config.data.len() / block_size;

    for round in 0..config.rounds {
        cancellation_token.check()?;
        matrix.fill(0);
        for symbol in 0..rs_n {
            if symbol % 32 == 0 {
                cancellation_token.check()?;
            }
            let block_index = symbol
                .checked_mul(config.rounds)
                .and_then(|value| value.checked_add(round))
                .context("FEC interleave offset overflow")?;
            if block_index >= data_blocks {
                continue;
            }
            let source_start = config
                .data
                .start
                .checked_add(
                    block_index.checked_mul(block_size).context("FEC data offset overflow")?,
                )
                .context("FEC data offset overflow")?;
            let source_end =
                source_start.checked_add(block_size).context("FEC data end overflow")?;
            let source = &partition[source_start..source_end];
            for (byte_index, byte) in source.iter().copied().enumerate() {
                matrix[byte_index * rs_n + symbol] = byte;
            }
        }

        parity.fill(0);
        for byte_index in 0..block_size {
            if byte_index % 256 == 0 {
                cancellation_token.check()?;
            }
            let data_start = byte_index * rs_n;
            let parity_start = byte_index * config.roots;
            rs.encode(
                &matrix[data_start..data_start + rs_n],
                &mut parity[parity_start..parity_start + config.roots],
            );
        }

        cancellation_token.check()?;
        let destination_start = config
            .storage
            .start
            .checked_add(round.checked_mul(parity_len).context("FEC write offset overflow")?)
            .context("FEC write offset overflow")?;
        let destination_end =
            destination_start.checked_add(parity_len).context("FEC write end overflow")?;
        partition[destination_start..destination_end].copy_from_slice(&parity);
    }
    cancellation_token.check()
}

struct ReedSolomon {
    alpha_to: [u8; FEC_SYMBOLS + 1],
    index_of: [u8; FEC_SYMBOLS + 1],
    generator: Vec<u8>,
    roots: usize,
}

impl ReedSolomon {
    fn new(roots: usize) -> Result<Self> {
        let mut alpha_to = [0u8; FEC_SYMBOLS + 1];
        let mut index_of = [0u8; FEC_SYMBOLS + 1];
        index_of[0] = FEC_SYMBOLS as u8;
        let mut symbol = 1u16;
        for (exponent, alpha) in alpha_to.iter_mut().take(FEC_SYMBOLS).enumerate() {
            index_of[usize::from(symbol)] = exponent as u8;
            *alpha = symbol as u8;
            symbol <<= 1;
            if symbol & 0x100 != 0 {
                symbol ^= 0x11d;
            }
            symbol &= 0xff;
        }
        ensure!(symbol == 1, "FEC field polynomial is not primitive");

        let mut generator = zeroed_buffer(roots + 1, "FEC generator polynomial")?;
        generator[0] = 1;
        for root in 0..roots {
            generator[root + 1] = 1;
            for coefficient in (1..=root).rev() {
                generator[coefficient] = if generator[coefficient] == 0 {
                    generator[coefficient - 1]
                } else {
                    let exponent = usize::from(index_of[usize::from(generator[coefficient])]);
                    generator[coefficient - 1] ^ alpha_to[(exponent + root) % FEC_SYMBOLS]
                };
            }
            let exponent = usize::from(index_of[usize::from(generator[0])]);
            generator[0] = alpha_to[(exponent + root) % FEC_SYMBOLS];
        }
        for coefficient in &mut generator {
            *coefficient = index_of[usize::from(*coefficient)];
        }
        Ok(Self { alpha_to, index_of, generator, roots })
    }

    fn encode(&self, data: &[u8], parity: &mut [u8]) {
        parity.fill(0);
        for byte in data {
            let feedback = usize::from(self.index_of[usize::from(*byte ^ parity[0])]);
            if feedback != FEC_SYMBOLS {
                for (index, parity_byte) in parity.iter_mut().enumerate().take(self.roots).skip(1) {
                    let generator = usize::from(self.generator[self.roots - index]);
                    *parity_byte ^= self.alpha_to[(feedback + generator) % FEC_SYMBOLS];
                }
            }
            parity.copy_within(1..self.roots, 0);
            parity[self.roots - 1] = if feedback == FEC_SYMBOLS {
                0
            } else {
                let generator = usize::from(self.generator[0]);
                self.alpha_to[(feedback + generator) % FEC_SYMBOLS]
            };
        }
    }
}

fn extent_num_blocks(extent: Option<&Extent>, label: &str) -> Result<Option<usize>> {
    extent
        .map(|extent| {
            usize::try_from(
                extent
                    .num_blocks
                    .with_context(|| format!("{label} extent block count is missing"))?,
            )
            .with_context(|| format!("{label} extent block count is too large"))
        })
        .transpose()
}

fn extent_range(
    extent: &Extent,
    block_size: usize,
    partition_len: usize,
    label: &str,
) -> Result<Range<usize>> {
    let start_block = usize::try_from(
        extent.start_block.with_context(|| format!("{label} extent start block is missing"))?,
    )
    .with_context(|| format!("{label} extent start block is too large"))?;
    let num_blocks = usize::try_from(
        extent.num_blocks.with_context(|| format!("{label} extent block count is missing"))?,
    )
    .with_context(|| format!("{label} extent block count is too large"))?;
    let start = start_block.checked_mul(block_size).context("Verity extent offset overflow")?;
    let len = num_blocks.checked_mul(block_size).context("Verity extent length overflow")?;
    let end = start.checked_add(len).context("Verity extent end overflow")?;
    ensure!(end <= partition_len, "{label} extent exceeds partition size");
    Ok(start..end)
}

fn div_ceil(value: usize, divisor: usize) -> Result<usize> {
    value
        .checked_add(divisor - 1)
        .context("Hash tree block count overflow")
        .map(|rounded| rounded / divisor)
}

fn zeroed_level(blocks: usize, block_size: usize) -> Result<Vec<u8>> {
    let len = blocks.checked_mul(block_size).context("Hash tree level size overflow")?;
    zeroed_buffer(len, "hash tree")
}

fn zeroed_buffer(len: usize, label: &str) -> Result<Vec<u8>> {
    let mut level = Vec::new();
    level.try_reserve_exact(len).with_context(|| format!("Unable to allocate {label}"))?;
    level.resize(len, 0);
    Ok(level)
}

fn salted_hash(salt: &[u8], block: &[u8]) -> digest::Digest {
    let mut context = digest::Context::new(&digest::SHA256);
    context.update(salt);
    context.update(block);
    context.finish()
}

fn ranges_overlap(left: &Range<usize>, right: &Range<usize>) -> bool {
    left.start < right.end && right.start < left.end
}
