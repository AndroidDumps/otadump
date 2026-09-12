#[allow(clippy::all)]
#[allow(dead_code)]
mod chromeos_update_engine {
    include!(concat!(env!("OUT_DIR"), "/chromeos_update_engine.rs"));
}
mod bsdiff;
pub mod lz4;
mod lz4diff;
mod payload;
mod puffin;
#[cfg(feature = "python")]
mod python;
mod verity;
pub mod zucchini;
pub mod zucchini_pure;

use std::cmp::Reverse;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::num::NonZero;
use std::ops::Range;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::{error, result, slice, thread};

use anyhow::{Context as _, Error, Result, bail, ensure};
use brotli::Decompressor as BrotliDecoder;
use bzip2::read::BzDecoder;
use chromeos_update_engine::install_operation::Type;
use chromeos_update_engine::{DeltaArchiveManifest, InstallOperation, PartitionUpdate};
use liblzma::read::XzDecoder;
use memmap2::{Mmap, MmapMut, MmapOptions};
use prost::Message as _;
use rayon::ThreadPoolBuilder;
use ring::digest;
use sync_unsafe_cell::SyncUnsafeCell;
use tempfile::TempPath;
use zip::ZipArchive;
use zip::result::ZipError;
use zstd::Decoder as ZstdDecoder;

pub use crate::payload::Payload;

// The chunk size is the number of bytes we verify before we count one "tick" in
// the progress tracker.
const VERIFY_CHUNK_SIZE: usize = 2 * 1024 * 1024; // 2 MiB
const BROTLI_DECODE_CHUNK_SIZE: usize = 32 * 1024;

#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    fn check(&self) -> Result<()> {
        if self.is_cancelled() {
            return Err(ExtractionCancelled.into());
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct ExtractionCancelled;

impl std::fmt::Display for ExtractionCancelled {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Extraction cancelled")
    }
}

impl error::Error for ExtractionCancelled {}

pub fn is_cancellation(error: &(dyn error::Error + 'static)) -> bool {
    let mut error = Some(error);
    while let Some(current) = error {
        if current.downcast_ref::<ExtractionCancelled>().is_some() {
            return true;
        }
        error = current.source();
    }
    false
}

pub struct ExtractOptions<'a> {
    num_threads: Option<usize>,
    overwrite: bool,
    partitions: Option<HashSet<String>>,
    progress_reporter: &'a dyn ProgressReporter,
    verify: bool,
    source_dir: Option<PathBuf>,
    cancellation_token: CancellationToken,
}

impl<'a> ExtractOptions<'a> {
    /// Creates a blank new set of options ready for configuration.
    pub fn new() -> Self {
        Self {
            num_threads: None,
            overwrite: false,
            partitions: None,
            progress_reporter: &NoOpProgressReporter,
            verify: true,
            source_dir: None,
            cancellation_token: CancellationToken::new(),
        }
    }

    /// Extracts the payload file to the output directory.
    pub fn extract<P, Q>(
        &self,
        payload_file: P,
        output_dir: Q,
    ) -> result::Result<(), Box<dyn error::Error>>
    where
        P: AsRef<Path>,
        Q: AsRef<Path>,
    {
        let payload_file = payload_file.as_ref();
        let output_dir = output_dir.as_ref();
        match self.extract_impl(payload_file, output_dir) {
            Ok(()) => Ok(()),
            Err(error) if is_cancellation(error.as_ref()) => Err(Box::new(ExtractionCancelled)),
            Err(error) => Err(error.into()),
        }
    }

    fn extract_impl(&self, payload_file: &Path, output_dir: &Path) -> Result<()> {
        self.cancellation_token.check()?;
        self.progress_reporter.report_progress(0.);

        let payload_file = self.open_payload_file(payload_file)?;
        let payload = Payload::parse(&payload_file)?;

        let mut manifest =
            DeltaArchiveManifest::decode(payload.manifest).context("Unable to parse manifest")?;

        // Skip partitions that are not in the list of partitions to be extracted.
        if let Some(partitions) = &self.partitions {
            manifest.partitions.retain(|update| partitions.contains(&update.partition_name));
        }

        // Verification is slow for large partitions, and cannot be parallelized.
        // Extracting the largest partition first allows us to start verifying
        // it as early as possible.
        manifest.partitions.sort_unstable_by_key(|partition| {
            Reverse(partition.new_partition_info.as_ref().and_then(|info| info.size).unwrap_or(0))
        });

        let extract_ops =
            manifest.partitions.iter().map(|update| update.operations.len()).sum::<usize>();
        let verify_ops: usize = manifest
            .partitions
            .iter()
            .map(|update| {
                let partition_size =
                    update.new_partition_info.as_ref().and_then(|info| info.size).unwrap_or(0)
                        as usize;
                partition_size.div_ceil(VERIFY_CHUNK_SIZE)
            })
            .sum();
        let total_ops = extract_ops + verify_ops;
        let total_ops_completed = AtomicUsize::new(0);

        let block_size = manifest.block_size.context("block_size not defined")? as usize;
        ensure!(block_size > 0, "block_size must be greater than zero");

        // Ensure that all partitions to be extracted are present in the manifest.
        for partition_name in self.partitions.iter().flatten() {
            self.cancellation_token.check()?;
            ensure!(
                manifest.partitions.iter().any(|update| &update.partition_name == partition_name),
                "Partition not found: {partition_name}",
            );
        }

        fs::create_dir_all(output_dir)
            .with_context(|| format!("Could not create output directory: {output_dir:?}"))?;

        let validated = manifest
            .partitions
            .iter()
            .map(|update| self.validate_partition(update, &payload, block_size))
            .collect::<Result<Vec<_>>>()?;
        let (sources, verity_configs): (Vec<_>, Vec<_>) = validated.into_iter().unzip();

        let mut partition_names = HashSet::with_capacity(manifest.partitions.len());
        let mut destinations = Vec::with_capacity(manifest.partitions.len());
        for update in &manifest.partitions {
            self.cancellation_token.check()?;
            ensure!(
                partition_names.insert(&update.partition_name),
                "Duplicate partition mapping: {:?}",
                update.partition_name
            );
            destinations.push(output_dir.join(format!("{}.img", update.partition_name)));
        }
        for (update, destination) in manifest.partitions.iter().zip(&destinations) {
            self.cancellation_token.check()?;
            for source in sources.iter().flatten() {
                ensure!(
                    !paths_alias(&source.path, destination)?,
                    "Source partition image {:?} and destination partition image {destination:?} refer to the same file",
                    source.path,
                );
            }
            if !self.overwrite {
                ensure!(
                    !path_entry_exists(destination)?,
                    "Destination partition image already exists for {:?}: {destination:?}",
                    update.partition_name
                );
            }
        }

        let staging_dir = tempfile::Builder::new()
            .prefix(".otadump-")
            .tempdir_in(output_dir)
            .context("Unable to create staging directory")?;
        let mut staging_paths = Vec::with_capacity(manifest.partitions.len());
        let mut partitions = Vec::with_capacity(manifest.partitions.len());
        for update in &manifest.partitions {
            self.cancellation_token.check()?;
            let (path, partition) = self.create_staged_partition(update, staging_dir.path())?;
            staging_paths.push(path);
            partitions.push(partition);
        }

        let num_threads = self
            .num_threads
            .unwrap_or_else(|| thread::available_parallelism().map(NonZero::get).unwrap_or(1))
            .max(1);
        let threadpool = ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .context("Unable to start threadpool")?;
        let mut error = OnceLock::new();

        threadpool.in_place_scope_fifo(|scope| {
            for ((update, source), partition) in
                manifest.partitions.iter().zip(sources).zip(partitions)
            {
                // Exit early if an error has occurred.
                if error.get().is_some() {
                    break;
                }
                if let Err(cancelled) = self.cancellation_token.check() {
                    _ = error.set(cancelled);
                    break;
                }

                // Create and broadcast a task to the threadpool.
                let task = Task {
                    payload: &payload,
                    block_size,
                    verify: self.verify,
                    update,
                    source,
                    op_idx: AtomicUsize::new(0),
                    partition: SyncUnsafeCell::new(partition),
                    total_ops,
                    total_ops_completed: &total_ops_completed,
                    progress_reporter: self.progress_reporter,
                    cancellation_token: &self.cancellation_token,
                    error: &error,
                };
                scope.spawn_broadcast(move |_, _| {
                    if let Err(e) = task.run() {
                        _ = task.error.set(e);
                    }
                });
            }
        });

        self.cancellation_token.check()?;
        if let Some(e) = error.take() {
            return Err(e);
        }

        for ((update, verity_config), staging_path) in
            manifest.partitions.iter().zip(verity_configs).zip(&staging_paths)
        {
            self.cancellation_token.check()?;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(staging_path)
                .context("Unable to reopen staged partition image")?;
            let mut partition = unsafe { MmapMut::map_mut(&file) }
                .context("Failed to mmap staged partition image")?;
            if let Some(config) = verity_config.as_ref() {
                verity::generate(&mut partition, config, block_size, &self.cancellation_token)
                    .map_err(|error| {
                        if is_cancellation(error.as_ref()) {
                            error
                        } else {
                            error.context(format!(
                                "Failed to generate verity data for {:?}",
                                update.partition_name
                            ))
                        }
                    })?;
            }
            verify_partition(
                update,
                &partition,
                total_ops,
                &total_ops_completed,
                self.progress_reporter,
                &self.cancellation_token,
            )?;
            self.cancellation_token.check()?;
            partition.flush().context("Error while flushing file to disk")?;
        }

        for (staging_path, destination) in staging_paths.into_iter().zip(destinations) {
            self.cancellation_token.check()?;
            let result = if self.overwrite {
                staging_path.persist(&destination)
            } else {
                staging_path.persist_noclobber(&destination)
            };
            result.map_err(|error| error.error)?;
        }

        self.progress_reporter.report_progress(1.);
        self.cancellation_token.check()?;
        Ok(())
    }

    fn open_payload_file(&self, path: &Path) -> Result<Mmap> {
        let in_file = File::open(path)
            .with_context(|| format!("Failed to open file for reading: {path:?}"))?;

        // Assume the file is a zip archive. If it's not, we get an InvalidArchive
        // error, and we can treat it as a payload.bin file.
        match ZipArchive::new(&in_file) {
            Ok(mut archive) => {
                let mut zip_file = archive
                    .by_name("payload.bin")
                    .context("Could not find payload.bin file in archive")?;

                match zip_file.compression() {
                    // Most OTA zip files use the STORED (no compression) method for the payload.bin
                    // file, which means we can use it directly.
                    zip::CompressionMethod::Stored => unsafe {
                        MmapOptions::new()
                            .offset(zip_file.data_start())
                            .len(zip_file.compressed_size() as usize)
                            .map(&in_file)
                            .with_context(|| format!("Failed to mmap file: {path:?}"))
                    },
                    _ => {
                        let out_file =
                            tempfile::tempfile().context("Failed to create temporary file")?;
                        out_file
                            .set_len(zip_file.size())
                            .context("Failed to set size of temporary file")?;
                        let mut out_file = unsafe { MmapMut::map_mut(&out_file) }
                            .context("Failed to mmap temporary file")?;

                        for chunk in out_file.chunks_mut(VERIFY_CHUNK_SIZE) {
                            self.cancellation_token.check()?;
                            zip_file
                                .read_exact(chunk)
                                .context("Failed to write to temporary file")?;
                        }
                        out_file.make_read_only().context("Failed to make temporary file read-only")
                    }
                }
            }
            Err(ZipError::InvalidArchive(_)) => unsafe { Mmap::map(&in_file) }
                .with_context(|| format!("Failed to mmap file: {path:?}")),
            Err(e) => Err(e).with_context(|| format!("Failed to open payload file: {path:?}")),
        }
    }

    fn validate_partition(
        &self,
        update: &PartitionUpdate,
        payload: &Payload<'_>,
        block_size: usize,
    ) -> Result<(Option<SourcePartition>, Option<verity::VerityConfig>)> {
        validate_partition_name(&update.partition_name)?;
        self.cancellation_token.check()?;

        let partition_len = update
            .new_partition_info
            .as_ref()
            .and_then(|info| info.size)
            .context("Unable to determine output file size")?;
        let partition_len =
            usize::try_from(partition_len).context("Output partition is too large")?;
        ensure!(
            update.new_partition_info.as_ref().and_then(|info| info.hash.as_ref()).is_some(),
            "Unable to determine output partition hash"
        );

        let needs_source = update.operations.iter().try_fold(false, |needed, op| {
            self.cancellation_token.check()?;
            let op_type = Type::try_from(op.r#type).context("Invalid operation")?;
            validate_operation_type(op_type)?;
            Ok::<_, Error>(needed || operation_needs_source(op_type))
        })?;
        let source = if needs_source { Some(self.open_source_partition(update)?) } else { None };

        let mut destination_ranges = Vec::new();
        for (op_index, op) in update.operations.iter().enumerate() {
            self.cancellation_token.check()?;
            let op_type = Type::try_from(op.r#type).context("Invalid operation")?;
            let dst_ranges = extent_ranges(&op.dst_extents, block_size, partition_len)
                .with_context(|| format!("Invalid destination extents for operation {op_index}"))?;
            ensure!(!dst_ranges.is_empty(), "Operation {op_index} has no destination extents");
            let dst_len = ranges_len(&dst_ranges)?;
            if let Some(declared_len) = op.dst_length {
                ensure!(
                    usize::try_from(declared_len).ok() == Some(dst_len),
                    "Destination length mismatch for operation {op_index}"
                );
            }
            destination_ranges.extend(
                dst_ranges
                    .iter()
                    .filter(|range| !range.is_empty())
                    .map(|range| (range.clone(), op_index)),
            );

            if operation_needs_source(op_type) {
                let source = source.as_ref().context("Source partition was not opened")?;
                let src_ranges = extent_ranges(&op.src_extents, block_size, source.len)
                    .with_context(|| format!("Invalid source extents for operation {op_index}"))?;
                ensure!(!src_ranges.is_empty(), "Operation {op_index} has no source extents");
                let src_len = ranges_len(&src_ranges)?;
                if let Some(declared_len) = op.src_length {
                    ensure!(
                        usize::try_from(declared_len).ok() == Some(src_len),
                        "Source length mismatch for operation {op_index}"
                    );
                }
                if self.verify {
                    verify_hash_over_ranges(
                        source.bytes(),
                        &src_ranges,
                        op.src_sha256_hash.as_deref(),
                        "Source extent",
                        &self.cancellation_token,
                    )
                    .with_context(|| {
                        format!("Source verification failed for operation {op_index}")
                    })?;
                }
            }

            if operation_has_data(op_type) {
                let data = extract_operation_data(payload, op)
                    .with_context(|| format!("Invalid data for operation {op_index}"))?;
                if self.verify {
                    verify_hash(
                        data,
                        op.data_sha256_hash.as_deref(),
                        "Input",
                        &self.cancellation_token,
                    )
                    .with_context(|| {
                        format!("Data verification failed for operation {op_index}")
                    })?;
                }
            }
        }

        destination_ranges.sort_unstable_by_key(|(range, _)| (range.start, range.end));
        for pair in destination_ranges.windows(2) {
            let (left, left_op) = &pair[0];
            let (right, right_op) = &pair[1];
            ensure!(
                left.end <= right.start,
                "Destination extents overlap between operations {left_op} and {right_op}"
            );
        }

        let verity = verity::validate(update, block_size, partition_len, &destination_ranges)
            .map_err(|error| {
                anyhow::anyhow!("Invalid verity metadata for {:?}: {error}", update.partition_name)
            })?;

        Ok((source, verity))
    }

    fn open_source_partition(&self, update: &PartitionUpdate) -> Result<SourcePartition> {
        let source_dir = self.source_dir.as_ref().with_context(|| {
            format!(
                "Delta operations for partition {:?} require a source directory",
                update.partition_name
            )
        })?;
        let path = source_dir.join(format!("{}.img", update.partition_name));
        let file = File::open(&path)
            .with_context(|| format!("Unable to open source partition image: {path:?}"))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("Unable to inspect source partition image: {path:?}"))?;
        ensure!(metadata.is_file(), "Source partition image is not a file: {path:?}");
        let backing_len =
            usize::try_from(metadata.len()).context("Source partition is too large")?;
        let info =
            update.old_partition_info.as_ref().context("Source partition info is missing")?;
        let expected_size = info.size.context("Source partition size is missing")?;
        let len = usize::try_from(expected_size).context("Source partition is too large")?;
        ensure!(
            backing_len >= len,
            "Source partition size mismatch for {:?}: expected at least {expected_size}, got {backing_len}",
            update.partition_name,
        );
        let mmap = if backing_len == 0 {
            None
        } else {
            Some(
                unsafe { MmapOptions::new().map(&file) }
                    .with_context(|| format!("Failed to mmap source partition image: {path:?}"))?,
            )
        };
        let source = SourcePartition { path, len, mmap };

        let expected_hash = info.hash.as_deref().context("Source partition hash is missing")?;
        verify_hash(
            source.bytes(),
            Some(expected_hash),
            "Source partition",
            &self.cancellation_token,
        )?;
        Ok(source)
    }

    fn create_staged_partition(
        &self,
        update: &PartitionUpdate,
        staging_dir: &Path,
    ) -> Result<(TempPath, MmapMut)> {
        let partition_len = update
            .new_partition_info
            .as_ref()
            .and_then(|info| info.size)
            .context("Unable to determine output file size")?;
        ensure!(partition_len > 0, "Output partition size must be greater than zero");

        let file = tempfile::Builder::new()
            .prefix("partition-")
            .tempfile_in(staging_dir)
            .context("Unable to create staged partition image")?;
        file.as_file().set_len(partition_len)?;

        let partition = unsafe { MmapMut::map_mut(file.as_file()) }
            .context("Failed to mmap staged partition image")?;
        Ok((file.into_temp_path(), partition))
    }

    /// Number of threads to use for extraction. By default, this is set to the
    /// number of logical CPUs on the system.
    pub fn num_threads(&mut self, num_threads: usize) -> &mut Self {
        self.num_threads = Some(num_threads);
        self
    }

    /// Whether to overwrite existing files when extracting. By default,
    /// existing files are not overwritten.
    pub fn overwrite(&mut self, overwrite: bool) -> &mut Self {
        self.overwrite = overwrite;
        self
    }

    /// Extract only the specified partitions from the payload. By default, all
    /// partitions are extracted.
    pub fn partitions<I, S>(&mut self, partitions: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.partitions =
            Some(partitions.into_iter().map(|partition| partition.as_ref().to_string()).collect());
        self
    }

    /// Set a progress reporter to report extraction progress.
    pub fn progress_reporter(&mut self, progress_reporter: &'a dyn ProgressReporter) -> &mut Self {
        self.progress_reporter = progress_reporter;
        self
    }

    /// Verify operation data and source extent hashes. This is enabled by default.
    /// Whole source images and staged output images are always verified.
    pub fn verify(&mut self, verify: bool) -> &mut Self {
        self.verify = verify;
        self
    }

    /// Set the directory containing base partition images for delta OTA extraction.
    pub fn source_dir<P: AsRef<Path>>(&mut self, source_dir: P) -> &mut Self {
        self.source_dir = Some(source_dir.as_ref().to_path_buf());
        self
    }

    /// Stop extraction cooperatively when the caller cancels the token.
    pub fn cancellation_token(&mut self, cancellation_token: &CancellationToken) -> &mut Self {
        self.cancellation_token = cancellation_token.clone();
        self
    }
}

struct SourcePartition {
    path: PathBuf,
    len: usize,
    mmap: Option<Mmap>,
}

impl SourcePartition {
    fn bytes(&self) -> &[u8] {
        &self.mmap.as_deref().unwrap_or_default()[..self.len]
    }
}

fn validate_partition_name(name: &str) -> Result<()> {
    let mut components = Path::new(name).components();
    let valid = matches!(components.next(), Some(Component::Normal(component)) if component == name)
        && components.next().is_none()
        && !name.contains('/')
        && !name.contains('\\');
    ensure!(valid, "Unsafe partition name: {name:?}");
    Ok(())
}

#[allow(deprecated)]
fn validate_operation_type(op_type: Type) -> Result<()> {
    match op_type {
        Type::Move | Type::Bsdiff => bail!("Deprecated operation is not supported: {op_type:?}"),
        Type::Replace
        | Type::ReplaceBz
        | Type::SourceCopy
        | Type::SourceBsdiff
        | Type::Zero
        | Type::Discard
        | Type::ReplaceXz
        | Type::Puffdiff
        | Type::BrotliBsdiff
        | Type::Zucchini
        | Type::Lz4diffBsdiff
        | Type::Lz4diffPuffdiff
        | Type::ReplaceZstd => Ok(()),
    }
}

fn operation_needs_source(op_type: Type) -> bool {
    matches!(
        op_type,
        Type::SourceCopy
            | Type::SourceBsdiff
            | Type::Puffdiff
            | Type::BrotliBsdiff
            | Type::Zucchini
            | Type::Lz4diffBsdiff
            | Type::Lz4diffPuffdiff
    )
}

fn operation_has_data(op_type: Type) -> bool {
    matches!(
        op_type,
        Type::Replace
            | Type::ReplaceBz
            | Type::SourceBsdiff
            | Type::ReplaceXz
            | Type::Puffdiff
            | Type::BrotliBsdiff
            | Type::Zucchini
            | Type::Lz4diffBsdiff
            | Type::Lz4diffPuffdiff
            | Type::ReplaceZstd
    )
}

fn extent_ranges(
    extents: &[chromeos_update_engine::Extent],
    block_size: usize,
    partition_len: usize,
) -> Result<Vec<Range<usize>>> {
    extents
        .iter()
        .map(|extent| {
            let start_block =
                usize::try_from(extent.start_block.context("start_block not defined in extent")?)
                    .context("Extent start block is too large")?;
            let num_blocks =
                usize::try_from(extent.num_blocks.context("num_blocks not defined in extent")?)
                    .context("Extent block count is too large")?;
            let start = start_block.checked_mul(block_size).context("Extent offset overflow")?;
            let len = num_blocks.checked_mul(block_size).context("Extent length overflow")?;
            let end = start.checked_add(len).context("Extent end overflow")?;
            ensure!(end <= partition_len, "Extent exceeds partition size");
            Ok(start..end)
        })
        .collect()
}

fn ranges_len(ranges: &[Range<usize>]) -> Result<usize> {
    ranges.iter().try_fold(0usize, |len, range| {
        len.checked_add(range.len()).context("Combined extent length overflow")
    })
}

fn extract_operation_data<'a>(payload: &'a Payload<'a>, op: &InstallOperation) -> Result<&'a [u8]> {
    let offset = usize::try_from(op.data_offset.context("data_offset not defined")?)
        .context("Data offset is too large")?;
    let len = usize::try_from(op.data_length.context("data_length not defined")?)
        .context("Data length is too large")?;
    let end = offset.checked_add(len).context("Data range overflow")?;
    payload.data.get(offset..end).context("Data range exceeds payload size")
}

fn verify_hash(
    data: &[u8],
    expected: Option<&[u8]>,
    label: &str,
    cancellation_token: &CancellationToken,
) -> Result<()> {
    cancellation_token.check()?;
    let Some(expected) = expected else {
        return Ok(());
    };
    let mut context = digest::Context::new(&digest::SHA256);
    for chunk in data.chunks(VERIFY_CHUNK_SIZE) {
        cancellation_token.check()?;
        context.update(chunk);
    }
    let actual = context.finish();
    ensure!(
        actual.as_ref() == expected,
        "{label} hash mismatch: expected {}, got {}",
        hex::encode(expected),
        hex::encode(actual.as_ref())
    );
    Ok(())
}

fn verify_hash_over_ranges(
    data: &[u8],
    ranges: &[Range<usize>],
    expected: Option<&[u8]>,
    label: &str,
    cancellation_token: &CancellationToken,
) -> Result<()> {
    cancellation_token.check()?;
    let Some(expected) = expected else {
        return Ok(());
    };
    let mut context = digest::Context::new(&digest::SHA256);
    for range in ranges {
        for chunk in data[range.clone()].chunks(VERIFY_CHUNK_SIZE) {
            cancellation_token.check()?;
            context.update(chunk);
        }
    }
    let actual = context.finish();
    ensure!(
        actual.as_ref() == expected,
        "{label} hash mismatch: expected {}, got {}",
        hex::encode(expected),
        hex::encode(actual.as_ref())
    );
    Ok(())
}

fn paths_alias(source: &Path, destination: &Path) -> Result<bool> {
    let destination_metadata = match fs::metadata(destination) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("Unable to inspect destination partition image: {destination:?}")
            });
        }
    };
    let source_metadata = fs::metadata(source)
        .with_context(|| format!("Unable to inspect source partition image: {source:?}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        Ok(source_metadata.dev() == destination_metadata.dev()
            && source_metadata.ino() == destination_metadata.ino())
    }
    #[cfg(not(unix))]
    {
        Ok(fs::canonicalize(source)? == fs::canonicalize(destination)?)
    }
}

fn path_entry_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("Unable to inspect destination partition image: {path:?}")),
    }
}

impl Default for ExtractOptions<'_> {
    fn default() -> Self {
        Self::new()
    }
}

struct Task<'a> {
    payload: &'a Payload<'a>,
    block_size: usize,
    verify: bool,

    update: &'a PartitionUpdate,
    source: Option<SourcePartition>,
    op_idx: AtomicUsize,
    partition: SyncUnsafeCell<MmapMut>,

    total_ops: usize,
    total_ops_completed: &'a AtomicUsize,
    progress_reporter: &'a dyn ProgressReporter,
    cancellation_token: &'a CancellationToken,

    error: &'a OnceLock<Error>,
}

impl Task<'_> {
    fn run(&self) -> Result<()> {
        // If an error has already occurred, stop processing the partition.
        while self.error.get().is_none() {
            self.cancellation_token.check()?;
            let op_idx = self.op_idx.fetch_add(1, Ordering::AcqRel);
            match self.update.operations.get(op_idx) {
                Some(op) => {
                    self.run_op(op)?;
                    self.cancellation_token.check()?;
                    self.increment_progress();
                }
                None => {
                    break;
                }
            }
        }
        Ok(())
    }

    #[allow(deprecated)]
    fn run_op(&self, op: &InstallOperation) -> Result<()> {
        self.cancellation_token.check()?;
        let mut dst_extents =
            self.extract_dst_extents(op).context("Error extracting dst_extents")?;
        match Type::try_from(op.r#type).context("Invalid operation")? {
            Type::Replace => {
                let data = self.extract_data(op).context("Error extracting data")?;
                self.run_op_replace(&mut &*data, &mut dst_extents)
                    .context("Error in REPLACE operation")
            }
            Type::ReplaceBz => {
                let data = self.extract_data(op).context("Error extracting data")?;
                let mut decoder = BzDecoder::new(data);
                self.run_op_replace(&mut decoder, &mut dst_extents)
                    .context("Error in REPLACE_BZ operation")
            }
            Type::ReplaceXz => {
                let data = self.extract_data(op).context("Error extracting data")?;
                let mut decoder = XzDecoder::new(data);
                self.run_op_replace(&mut decoder, &mut dst_extents)
                    .context("Error in REPLACE_XZ operation")
            }
            Type::ReplaceZstd => {
                let data = self.extract_data(op).context("Error extracting data")?;
                let mut decoder =
                    ZstdDecoder::with_buffer(data).context("Unable to initialize zstd decoder")?;
                self.run_op_replace(&mut decoder, &mut dst_extents)
                    .context("Error in REPLACE_ZSTD operation")
            }
            Type::SourceCopy => {
                let source = self.extract_source_data(op)?;
                self.write_exact(&source, &mut dst_extents)
                    .context("Error in SOURCE_COPY operation")
            }
            Type::SourceBsdiff => {
                let patch = self.extract_data(op).context("Error extracting SOURCE_BSDIFF data")?;
                self.run_op_bsdiff(op, patch, "SOURCE_BSDIFF", &mut dst_extents)
            }
            Type::BrotliBsdiff => {
                let patch = self.extract_data(op).context("Error extracting BROTLI_BSDIFF data")?;
                self.run_op_bsdiff(op, patch, "BROTLI_BSDIFF", &mut dst_extents)
            }
            Type::Zucchini => {
                let patch = self.extract_data(op).context("Error extracting ZUCCHINI data")?;
                self.run_op_zucchini(op, patch, &mut dst_extents)
            }
            Type::Puffdiff => {
                let patch = self.extract_data(op).context("Error extracting PUFFDIFF data")?;
                self.run_op_puffdiff(op, patch, &mut dst_extents)
            }
            Type::Lz4diffBsdiff | Type::Lz4diffPuffdiff => {
                let patch = self.extract_data(op).context("Error extracting LZ4DIFF data")?;
                self.run_op_lz4diff(op, patch, &mut dst_extents)
            }
            Type::Zero | Type::Discard => {
                for extent in dst_extents {
                    for chunk in extent.chunks_mut(VERIFY_CHUNK_SIZE) {
                        self.cancellation_token.check()?;
                        chunk.fill(0);
                    }
                }
                Ok(())
            }
            Type::Move | Type::Bsdiff => {
                bail!("Deprecated operation is not supported: {:?}", Type::try_from(op.r#type)?)
            }
        }?;
        self.cancellation_token.check()
    }

    fn extract_source_data(&self, op: &InstallOperation) -> Result<Vec<u8>> {
        let source = self.source.as_ref().context("Source partition was not opened")?;
        let ranges = extent_ranges(&op.src_extents, self.block_size, source.len)?;
        let capacity = ranges_len(&ranges)?;
        let mut data = Vec::new();
        data.try_reserve_exact(capacity).context("Unable to allocate source extent buffer")?;
        for range in ranges {
            for chunk in source.bytes()[range].chunks(VERIFY_CHUNK_SIZE) {
                self.cancellation_token.check()?;
                data.extend_from_slice(chunk);
            }
        }
        Ok(data)
    }

    fn run_op_bsdiff(
        &self,
        op: &InstallOperation,
        patch: &[u8],
        operation: &str,
        dst_extents: &mut [&mut [u8]],
    ) -> Result<()> {
        let source = self.extract_source_data(op)?;
        let expected_output_len = dst_extents.iter().try_fold(0usize, |len, extent| {
            len.checked_add(extent.len()).context("Combined destination length overflow")
        })?;
        let output = apply_bsdiff(&source, patch, expected_output_len, self.cancellation_token)
            .map_err(|error| {
                if is_cancellation(error.as_ref()) {
                    error
                } else {
                    anyhow::anyhow!("{operation} patch is invalid: {error}")
                }
            })?;
        self.cancellation_token.check()?;
        self.write_exact(&output, dst_extents)
    }

    fn run_op_zucchini(
        &self,
        op: &InstallOperation,
        compressed_patch: &[u8],
        dst_extents: &mut [&mut [u8]],
    ) -> Result<()> {
        let source_partition = self.source.as_ref().context("Source partition was not opened")?;
        let source_ranges = extent_ranges(&op.src_extents, self.block_size, source_partition.len)?;
        let source_len = ranges_len(&source_ranges)?;
        ensure!(
            source_len < zucchini::OFFSET_BOUND,
            "ZUCCHINI source exceeds the maximum size of {} bytes",
            zucchini::OFFSET_BOUND - 1
        );
        let source = self.extract_source_data(op)?;
        let expected_output_len = dst_extents.iter().try_fold(0usize, |len, extent| {
            len.checked_add(extent.len()).context("Combined destination length overflow")
        })?;
        self.cancellation_token.check()?;
        let patch = decode_zucchini_patch(compressed_patch, self.cancellation_token)?;
        self.cancellation_token.check()?;
        let output = zucchini::apply_with_cancel(&source, &patch, expected_output_len, || {
            self.cancellation_token.is_cancelled()
        })
        .map_err(|error| {
            // Preserve cooperative cancellation as a typed error so the
            // extraction layer can unwind cleanly; anything else is a patch
            // failure.
            if error.status() == zucchini::Status::Cancelled {
                anyhow::Error::new(ExtractionCancelled)
            } else {
                anyhow::anyhow!("ZUCCHINI apply failed: {error}")
            }
        })?;
        self.cancellation_token.check()?;
        self.write_exact(&output, dst_extents)
    }

    fn run_op_puffdiff(
        &self,
        op: &InstallOperation,
        patch: &[u8],
        dst_extents: &mut [&mut [u8]],
    ) -> Result<()> {
        let source_partition = self.source.as_ref().context("Source partition was not opened")?;
        let source_ranges = extent_ranges(&op.src_extents, self.block_size, source_partition.len)?;
        let source_size = ranges_len(&source_ranges)?;
        let destination_size = dst_extents.iter().try_fold(0usize, |size, extent| {
            size.checked_add(extent.len()).context("Combined PUFFDIFF destination length overflow")
        })?;
        ensure!(
            source_size < zucchini::OFFSET_BOUND && destination_size < zucchini::OFFSET_BOUND,
            "PUFFDIFF raw stream exceeds the maximum size of {} bytes",
            zucchini::OFFSET_BOUND - 1
        );
        let source = self.extract_source_data(op)?;
        self.cancellation_token.check()?;
        let output = puffin::apply(&source, patch, destination_size, self.cancellation_token)
            .map_err(|error| {
                let message = error.to_string();
                anyhow::Error::new(error).context(format!("PUFFDIFF apply failed: {message}"))
            })?;
        self.cancellation_token.check()?;
        self.write_exact(&output, dst_extents)
    }

    fn run_op_lz4diff(
        &self,
        op: &InstallOperation,
        patch: &[u8],
        dst_extents: &mut [&mut [u8]],
    ) -> Result<()> {
        let source_partition = self.source.as_ref().context("Source partition was not opened")?;
        let source_ranges = extent_ranges(&op.src_extents, self.block_size, source_partition.len)?;
        let source_size = ranges_len(&source_ranges)?;
        let destination_size = dst_extents.iter().try_fold(0usize, |size, extent| {
            size.checked_add(extent.len()).context("Combined LZ4DIFF destination length overflow")
        })?;
        let inner = match Type::try_from(op.r#type).context("Invalid operation")? {
            Type::Lz4diffBsdiff => lz4diff::InnerPatch::Bsdiff,
            Type::Lz4diffPuffdiff => lz4diff::InnerPatch::Puffdiff,
            _ => bail!("Invalid LZ4DIFF operation type"),
        };
        let parsed =
            lz4diff::parse(patch, source_size, destination_size, inner, self.cancellation_token)
                .map_err(lz4diff_error)?;
        let source = self.extract_source_data(op)?;
        let output =
            lz4diff::apply(&source, parsed, self.cancellation_token).map_err(lz4diff_error)?;
        self.cancellation_token.check()?;
        self.write_exact(&output, dst_extents)
    }

    fn write_exact(&self, data: &[u8], dst_extents: &mut [&mut [u8]]) -> Result<()> {
        let dst_len = dst_extents.iter().try_fold(0usize, |len, extent| {
            len.checked_add(extent.len()).context("Combined destination length overflow")
        })?;
        ensure!(
            data.len() == dst_len,
            "Patched output size mismatch: expected {dst_len}, got {}",
            data.len()
        );
        let mut offset = 0usize;
        for extent in dst_extents {
            for chunk in extent.chunks_mut(VERIFY_CHUNK_SIZE) {
                self.cancellation_token.check()?;
                let end = offset.checked_add(chunk.len()).context("Destination offset overflow")?;
                chunk.copy_from_slice(&data[offset..end]);
                offset = end;
            }
        }
        Ok(())
    }

    fn run_op_replace(&self, reader: &mut impl Read, dst_extents: &mut [&mut [u8]]) -> Result<()> {
        let dst_len = dst_extents.iter().map(|extent| extent.len()).sum::<usize>();
        let mut bytes_written = 0usize;

        for extent in dst_extents {
            let mut extent = &mut **extent;
            loop {
                self.cancellation_token.check()?;
                let chunk_len = extent.len().min(VERIFY_CHUNK_SIZE);
                match reader.read(&mut extent[..chunk_len]).context("Failed to write to buffer")? {
                    0 => break,
                    n => {
                        bytes_written += n;
                        extent = &mut extent[n..];
                    }
                }
            }
        }
        self.cancellation_token.check()?;
        ensure!(reader.read(&mut [0])? == 0, "Decoded data exceeds destination extents");

        // Align number of bytes written to block size. The formula for alignment is:
        //   ((operand + alignment - 1) / alignment) * alignment.
        let bytes_written_aligned = bytes_written
            .checked_add(self.block_size - 1)
            .context("Decoded data length overflow")?
            / self.block_size
            * self.block_size;
        ensure!(bytes_written_aligned == dst_len, "More dst blocks than data, even with padding");

        Ok(())
    }

    #[allow(clippy::mut_from_ref)]
    fn extract_dst_extents(&self, op: &InstallOperation) -> Result<Vec<&mut [u8]>> {
        let partition = unsafe { (*self.partition.get()).as_mut_ptr() };
        let partition_len = unsafe { (&(*self.partition.get())).len() };
        let ranges = extent_ranges(&op.dst_extents, self.block_size, partition_len)?;

        // validate_partition rejects overlapping destination ranges before any task starts.
        // This guarantees that parallel workers never create aliases into the mutable map.
        Ok(ranges
            .into_iter()
            .map(|range| unsafe {
                slice::from_raw_parts_mut(partition.add(range.start), range.len())
            })
            .collect())
    }

    fn extract_data<'a>(&'a self, op: &InstallOperation) -> Result<&'a [u8]> {
        let data = extract_operation_data(self.payload, op)?;
        self.verify_op(op, data)?;
        Ok(data)
    }

    fn verify_op(&self, op: &InstallOperation, data: &[u8]) -> Result<()> {
        if !self.verify {
            return Ok(());
        }
        verify_hash(data, op.data_sha256_hash.as_deref(), "Input", self.cancellation_token)
    }

    fn increment_progress(&self) {
        increment_progress(self.total_ops, self.total_ops_completed, self.progress_reporter);
    }
}

fn lz4diff_error(error: Error) -> Error {
    if is_cancellation(error.as_ref()) {
        error
    } else {
        let message = error.to_string();
        error.context(format!("Error in LZ4DIFF operation: {message}"))
    }
}

pub(crate) fn decode_zucchini_patch(
    compressed_patch: &[u8],
    cancellation_token: &CancellationToken,
) -> Result<Vec<u8>> {
    cancellation_token.check()?;
    let mut decoder = BrotliDecoder::new(compressed_patch, BROTLI_DECODE_CHUNK_SIZE);
    let mut patch = Vec::new();
    let mut chunk = [0u8; BROTLI_DECODE_CHUNK_SIZE];
    let maximum_size = zucchini::OFFSET_BOUND - 1;

    loop {
        cancellation_token.check()?;
        let remaining = maximum_size
            .checked_sub(patch.len())
            .context("Decoded ZUCCHINI patch length exceeded its bound")?;
        let read_len = chunk.len().min(remaining.saturating_add(1));
        let count = decoder
            .read(&mut chunk[..read_len])
            .context("Unable to decode ZUCCHINI Brotli patch")?;
        if count == 0 {
            cancellation_token.check()?;
            // The decoder reports buffered trailing input only on a read after
            // EOF. The source check also catches trailing bytes it did not read.
            let mut trailing = [0u8; 1];
            let trailing_count =
                decoder.read(&mut trailing).context("Unable to decode ZUCCHINI Brotli patch")?;
            ensure!(
                trailing_count == 0 && decoder.get_ref().is_empty(),
                "ZUCCHINI Brotli patch contains trailing data"
            );
            break;
        }
        ensure!(
            count <= remaining,
            "Decoded ZUCCHINI patch exceeds the maximum size of {maximum_size} bytes"
        );
        let new_len =
            patch.len().checked_add(count).context("Decoded ZUCCHINI patch length overflow")?;
        patch.try_reserve(count).context("Unable to allocate decoded ZUCCHINI patch buffer")?;
        patch.extend_from_slice(&chunk[..count]);
        debug_assert_eq!(patch.len(), new_len);
    }

    Ok(patch)
}

fn verify_partition(
    update: &PartitionUpdate,
    partition: &[u8],
    total_ops: usize,
    total_ops_completed: &AtomicUsize,
    progress_reporter: &dyn ProgressReporter,
    cancellation_token: &CancellationToken,
) -> Result<()> {
    let exp_hash = update
        .new_partition_info
        .as_ref()
        .and_then(|info| info.hash.as_ref())
        .context("Unable to determine output partition hash")?;

    let mut context = digest::Context::new(&digest::SHA256);
    for chunk in partition.chunks(VERIFY_CHUNK_SIZE) {
        cancellation_token.check()?;
        context.update(chunk);
        increment_progress(total_ops, total_ops_completed, progress_reporter);
    }

    cancellation_token.check()?;
    let got_hash = context.finish();
    ensure!(
        got_hash.as_ref() == exp_hash,
        "Output verification failed: hash mismatch: expected {}, got {}",
        hex::encode(exp_hash),
        hex::encode(got_hash.as_ref())
    );
    Ok(())
}

fn increment_progress(
    total_ops: usize,
    total_ops_completed: &AtomicUsize,
    progress_reporter: &dyn ProgressReporter,
) {
    let total_ops_completed = total_ops_completed.fetch_add(1, Ordering::Relaxed) + 1;
    if total_ops_completed % 16 == 0 {
        let progress = total_ops_completed as f64 / total_ops as f64;
        progress_reporter.report_progress(progress);
    }
}

fn validate_bsdiff_output_len(patch: &[u8], expected: usize) -> Result<()> {
    ensure!(patch.len() >= 32, "Patch data too short");
    ensure!(
        &patch[..8] == b"BSDIFF40" || &patch[..5] == b"BSDF2",
        "Invalid BSDIFF/BSDF2 magic header"
    );
    let encoded =
        u64::from_le_bytes(patch[24..32].try_into().context("Invalid BSDIFF output length field")?);
    ensure!(encoded & (1 << 63) == 0, "Negative output length in patch header");
    let actual = usize::try_from(encoded).context("Patch output length is too large")?;
    ensure!(actual == expected, "Patch output length mismatch: expected {expected}, got {actual}");
    Ok(())
}

#[inline]
fn offtin(buf: [u8; 8]) -> i64 {
    let y = i64::from_le_bytes(buf);
    if 0 == y & (1 << 63) { y } else { -(y & !(1 << 63)) }
}

pub(crate) fn apply_bsdiff(
    source: &[u8],
    patch: &[u8],
    expected_output_len: usize,
    cancellation_token: &CancellationToken,
) -> Result<Vec<u8>> {
    validate_bsdiff_output_len(patch, expected_output_len)?;
    cancellation_token.check()?;
    puffin::validate_bsdiff_resources(patch, expected_output_len, cancellation_token)?;
    cancellation_token.check()?;

    let (new_size, control_data, diff_data, extra_data) = bsdiff::parse_header(patch)?;
    let new_size = usize::try_from(new_size).context("Patch new_size is negative or overflows")?;
    ensure!(
        new_size == expected_output_len,
        "Patch output length mismatch: expected {expected_output_len}, got {new_size}"
    );

    let mut output = Vec::new();
    output
        .try_reserve_exact(expected_output_len)
        .context("Unable to allocate patched output buffer")?;

    ensure!(control_data.len() % 24 == 0, "Invalid control data length (not a multiple of 24)");
    let mut oldpos: i64 = 0;
    let mut diff_pos: usize = 0;
    let mut extra_pos: usize = 0;

    for chunk in control_data.chunks_exact(24) {
        cancellation_token.check()?;
        let add_len = offtin(chunk[0..8].try_into().unwrap());
        let copy_len = offtin(chunk[8..16].try_into().unwrap());
        let seek_amount = offtin(chunk[16..24].try_into().unwrap());

        ensure!(
            add_len >= 0 && copy_len >= 0,
            "Negative length in control tuple: add={add_len}, copy={copy_len}"
        );
        let add_len = usize::try_from(add_len).context("Control tuple add_len overflow")?;
        let copy_len = usize::try_from(copy_len).context("Control tuple copy_len overflow")?;

        let pending_len = add_len.checked_add(copy_len).context("Control tuple length overflow")?;
        let target_len =
            output.len().checked_add(pending_len).context("Patched output length overflow")?;
        ensure!(
            target_len <= expected_output_len,
            "Control tuple would exceed expected output size"
        );

        if add_len > 0 {
            let diff_end = diff_pos.checked_add(add_len).context("Diff stream offset overflow")?;
            let diff_chunk = diff_data.get(diff_pos..diff_end).context("Diff stream exhausted")?;
            for (i, &diff_byte) in diff_chunk.iter().enumerate() {
                let offset = i64::try_from(i).context("Diff offset overflow")?;
                let src_pos = oldpos.checked_add(offset).context("Source position overflow")?;
                let old_byte = match usize::try_from(src_pos) {
                    Ok(pos) if pos < source.len() => source[pos],
                    _ => 0u8,
                };
                output.push(old_byte.wrapping_add(diff_byte));
            }
            let add_i64 = i64::try_from(add_len).context("Source position overflow")?;
            oldpos = oldpos.checked_add(add_i64).context("Source position overflow")?;
            diff_pos = diff_end;
        }

        if copy_len > 0 {
            let extra_end =
                extra_pos.checked_add(copy_len).context("Extra stream offset overflow")?;
            let extra_chunk =
                extra_data.get(extra_pos..extra_end).context("Extra stream exhausted")?;
            output.extend_from_slice(extra_chunk);
            extra_pos = extra_end;
        }

        oldpos = oldpos.checked_add(seek_amount).context("Source position overflow")?;
    }

    cancellation_token.check()?;
    ensure!(
        output.len() == expected_output_len,
        "Patched output size mismatch: expected {expected_output_len}, got {}",
        output.len()
    );
    ensure!(
        diff_pos == diff_data.len(),
        "Diff stream not fully consumed: used {diff_pos}/{}",
        diff_data.len()
    );
    ensure!(
        extra_pos == extra_data.len(),
        "Extra stream not fully consumed: used {extra_pos}/{}",
        extra_data.len()
    );

    Ok(output)
}

pub trait ProgressReporter: Sync {
    /// Reports the progress of the extraction process. The progress is provided
    /// as a value between 0 and 1.
    fn report_progress(&self, progress: f64);
}

pub struct NoOpProgressReporter;

impl ProgressReporter for NoOpProgressReporter {
    fn report_progress(&self, _progress: f64) {}
}
