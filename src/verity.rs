use std::ops::Range;

use anyhow::{Context as _, Result, bail, ensure};
use ring::digest;

use crate::CancellationToken;
use crate::chromeos_update_engine::{Extent, PartitionUpdate};

const SHA256_SIZE: usize = 32;

pub(crate) struct VerityConfig {
    data: Range<usize>,
    tree: Range<usize>,
    salt: Vec<u8>,
}

pub(crate) fn validate(
    update: &PartitionUpdate,
    block_size: usize,
    partition_len: usize,
    operation_destinations: &[(Range<usize>, usize)],
) -> Result<Option<VerityConfig>> {
    if extent_num_blocks(update.fec_extent.as_ref(), "FEC")?.unwrap_or(0) > 0 {
        bail!("FEC generation is not supported for partition {:?}", update.partition_name);
    }

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

    Ok(Some(VerityConfig { data, tree, salt: update.hash_tree_salt.clone().unwrap_or_default() }))
}

pub(crate) fn generate(
    partition: &mut [u8],
    config: &VerityConfig,
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
    let mut level = Vec::new();
    level.try_reserve_exact(len).context("Unable to allocate hash tree")?;
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
