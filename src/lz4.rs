//! LZ4 block operations for Android `lz4diff`, backed by the pinned `lz4-sys`
//! crate. The crate bundles liblz4 1.10.0 C sources that are byte-identical
//! (SHA-256 verified) to AOSP `platform/external/lz4` commit
//! `734e07032602e9a72fcc9701028b0aee45147fcd`, so compressed output matches
//! the AOSP reference byte for byte. See `licenses/README.md`.

// Force the pinned `lz4-sys` crate into the crate graph: its rlib carries the
// `cargo:rustc-link-lib=static=lz4` metadata that links the bundled liblz4
// archive, which the direct extern declarations below resolve against.
use lz4_sys as _;

use std::error;
use std::ffi::{c_char, c_int, c_void};
use std::fmt;

const MAX_INPUT_SIZE: usize = 0x7e00_0000;
pub const HC_LEVEL_MIN: i32 = 2;
pub const HC_LEVEL_MAX: i32 = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    InvalidArgument,
    CompressionFailed,
    DecompressionFailed,
    AllocationFailure,
    CompressionDivergence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    status: Status,
    message: String,
}

impl Error {
    pub fn status(&self) -> Status {
        self.status
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Decompresses one LZ4 block into a newly allocated, exact-size buffer.
pub fn decompress_safe_partial(input: &[u8], output_size: usize) -> Result<Vec<u8>> {
    validate_sizes(input.len(), output_size)?;
    if input.len() >= output_size {
        return Err(invalid_argument("stored LZ4 block must be smaller than its raw block"));
    }
    let mut output = allocate_output(output_size, "decompression")?;
    let result = decompress_native(input, &mut output)?;
    if result.output_size != output_size {
        return Err(Error {
            status: Status::DecompressionFailed,
            message: format!(
                "LZ4 decompressed {} bytes, expected {output_size}",
                result.output_size
            ),
        });
    }
    Ok(output)
}

/// Compresses one complete block with LZ4 acceleration 1.
///
/// The returned buffer always has `output_size` bytes. Short compressed output
/// receives leading zeros when `zero_padding` is true and trailing zeros otherwise.
pub fn compress_dest_size(input: &[u8], output_size: usize, zero_padding: bool) -> Result<Vec<u8>> {
    compress(input, Some(input.len()), output_size, zero_padding, None)
}

/// Compresses one complete block with the metadata-selected LZ4HC level.
pub fn compress_hc_dest_size(
    input: &[u8],
    output_size: usize,
    compression_level: i32,
    zero_padding: bool,
) -> Result<Vec<u8>> {
    if !(HC_LEVEL_MIN..=HC_LEVEL_MAX).contains(&compression_level) {
        return Err(invalid_argument(format!(
            "LZ4HC compression level must be in {HC_LEVEL_MIN}..={HC_LEVEL_MAX}"
        )));
    }
    compress(input, Some(input.len()), output_size, zero_padding, Some(compression_level))
}

pub(crate) fn compress_dest_size_partial(
    input: &[u8],
    raw_block_size: usize,
    output_size: usize,
    compression_level: Option<i32>,
    zero_padding: bool,
) -> Result<Vec<u8>> {
    if let Some(level) = compression_level
        && !(HC_LEVEL_MIN..=HC_LEVEL_MAX).contains(&level)
    {
        return Err(invalid_argument(format!(
            "LZ4HC compression level must be in {HC_LEVEL_MIN}..={HC_LEVEL_MAX}"
        )));
    }
    if raw_block_size == 0 || raw_block_size > input.len() {
        return Err(invalid_argument("LZ4 source consumption size is invalid"));
    }
    if output_size >= raw_block_size {
        return Err(invalid_argument("stored LZ4 block must be smaller than its raw block"));
    }
    compress(input, None, output_size, zero_padding, compression_level)
}

fn compress(
    input: &[u8],
    expected_source_size: Option<usize>,
    output_size: usize,
    zero_padding: bool,
    compression_level: Option<i32>,
) -> Result<Vec<u8>> {
    validate_sizes(input.len(), output_size)?;
    if let Some(expected) = expected_source_size {
        if expected == 0 || expected > input.len() {
            return Err(invalid_argument("LZ4 source consumption size is invalid"));
        }
        if output_size >= expected {
            return Err(invalid_argument("stored LZ4 block must be smaller than its raw block"));
        }
    } else if output_size >= input.len() {
        return Err(invalid_argument("stored LZ4 block must be smaller than its raw block"));
    }
    let mut output = allocate_output(output_size, "compression")?;
    let result = compress_native(input, &mut output, compression_level)?;
    if result.source_size == 0 || result.source_size > input.len() {
        return Err(Error {
            status: Status::CompressionFailed,
            message: "LZ4 compression consumed invalid source bytes".into(),
        });
    }
    if let Some(expected) = expected_source_size {
        if result.source_size != expected {
            return Err(Error {
                status: Status::CompressionDivergence,
                message: format!(
                    "LZ4 compression consumed {} of {} source bytes",
                    result.source_size, expected
                ),
            });
        }
    }
    if result.output_size == 0 || result.output_size > output_size {
        return Err(Error {
            status: Status::CompressionDivergence,
            message: format!(
                "LZ4 compression produced {} bytes for capacity {output_size}",
                result.output_size
            ),
        });
    }

    let padding = output_size - result.output_size;
    if padding > 0 {
        if zero_padding {
            output.copy_within(0..result.output_size, padding);
            output[..padding].fill(0);
        } else {
            output[result.output_size..].fill(0);
        }
    }
    Ok(output)
}

fn validate_sizes(input_size: usize, output_size: usize) -> Result<()> {
    if input_size == 0 || output_size == 0 {
        return Err(invalid_argument("LZ4 block sizes must be greater than zero"));
    }
    if input_size > MAX_INPUT_SIZE || output_size > MAX_INPUT_SIZE {
        return Err(invalid_argument("LZ4 block exceeds LZ4_MAX_INPUT_SIZE"));
    }
    i32::try_from(input_size).map_err(|_| invalid_argument("LZ4 input size exceeds int"))?;
    i32::try_from(output_size).map_err(|_| invalid_argument("LZ4 output size exceeds int"))?;
    Ok(())
}

fn allocate_output(size: usize, operation: &str) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    output.try_reserve_exact(size).map_err(|error| Error {
        status: Status::AllocationFailure,
        message: format!("unable to allocate LZ4 {operation} output: {error}"),
    })?;
    output.resize(size, 0);
    Ok(output)
}

fn invalid_argument(message: impl Into<String>) -> Error {
    Error { status: Status::InvalidArgument, message: message.into() }
}

#[derive(Clone, Copy)]
struct NativeResult {
    source_size: usize,
    output_size: usize,
}

fn decompress_native(input: &[u8], output: &mut [u8]) -> Result<NativeResult> {
    // SAFETY: The immutable input and mutable output slices cannot alias. They
    // remain alive for the call, and their checked lengths match the pointers.
    let written = unsafe {
        LZ4_decompress_safe_partial(
            input.as_ptr().cast::<c_char>(),
            output.as_mut_ptr().cast::<c_char>(),
            to_c_int(input.len())?,
            to_c_int(output.len())?,
            to_c_int(output.len())?,
        )
    };
    if written < 0 {
        return Err(Error {
            status: Status::DecompressionFailed,
            message: "LZ4 decompression failed".into(),
        });
    }
    Ok(NativeResult { source_size: input.len(), output_size: written as usize })
}

fn compress_native(
    input: &[u8],
    output: &mut [u8],
    compression_level: Option<i32>,
) -> Result<NativeResult> {
    let mut consumed = to_c_int(input.len())?;
    let capacity = to_c_int(output.len())?;
    // SAFETY: The immutable input and mutable output slices cannot alias. They
    // remain alive for the call, and their checked lengths match the pointers.
    // `consumed` is a valid in-out parameter initialized to the input length.
    let written = unsafe {
        if let Some(level) = compression_level {
            let stream = LZ4_createStreamHC();
            if stream.is_null() {
                return Err(Error {
                    status: Status::AllocationFailure,
                    message: "unable to allocate the LZ4HC stream state".into(),
                });
            }
            let written = LZ4_compress_HC_destSize(
                stream,
                input.as_ptr().cast::<c_char>(),
                output.as_mut_ptr().cast::<c_char>(),
                &mut consumed,
                capacity,
                level,
            );
            LZ4_freeStreamHC(stream);
            written
        } else {
            LZ4_compress_destSize(
                input.as_ptr().cast::<c_char>(),
                output.as_mut_ptr().cast::<c_char>(),
                &mut consumed,
                capacity,
            )
        }
    };
    if written <= 0 {
        return Err(Error {
            status: Status::CompressionFailed,
            message: "LZ4 compression failed".into(),
        });
    }
    Ok(NativeResult { source_size: consumed as usize, output_size: written as usize })
}

fn to_c_int(size: usize) -> Result<c_int> {
    c_int::try_from(size).map_err(|_| invalid_argument("LZ4 size exceeds int"))
}

// Direct declarations for the liblz4 block API: the pinned `lz4-sys` crate
// statically links the bundled liblz4 archive but its bindings omit these
// symbols. Signatures match `lz4.h`/`lz4hc.h` 1.10.0.
unsafe extern "C" {
    fn LZ4_decompress_safe_partial(
        source: *const c_char,
        dest: *mut c_char,
        compressed_size: c_int,
        target_output_size: c_int,
        max_decompressed_size: c_int,
    ) -> c_int;
    fn LZ4_compress_destSize(
        source: *const c_char,
        dest: *mut c_char,
        source_size: *mut c_int,
        target_dest_size: c_int,
    ) -> c_int;
    fn LZ4_createStreamHC() -> *mut c_void;
    fn LZ4_freeStreamHC(stream: *mut c_void) -> c_int;
    fn LZ4_compress_HC_destSize(
        stream: *mut c_void,
        source: *const c_char,
        dest: *mut c_char,
        source_size: *mut c_int,
        target_dest_size: c_int,
        compression_level: c_int,
    ) -> c_int;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs::File;
    use std::sync::OnceLock;

    use zip::ZipArchive;

    static FIXTURES: OnceLock<HashMap<String, Vec<u8>>> = OnceLock::new();

    fn fixture(path: &str) -> Vec<u8> {
        FIXTURES
            .get_or_init(|| {
                let file = File::open("tests/fixtures/corpus/opaque-fixtures.zip").unwrap();
                let mut archive = ZipArchive::new(file).unwrap();
                let mut fixtures = HashMap::with_capacity(archive.len());
                for index in 0..archive.len() {
                    let mut member = archive.by_index(index).unwrap();
                    let mut bytes = Vec::new();
                    std::io::copy(&mut member, &mut bytes).unwrap();
                    fixtures.insert(member.name().to_string(), bytes);
                }
                fixtures
            })
            .get(path)
            .unwrap_or_else(|| panic!("missing fixture in corpus zip: {path}"))
            .clone()
    }

    #[test]
    fn matches_frozen_lz4_reference() {
        let raw = fixture("lz4/lz4-no-postfix.raw");
        let expected = fixture("lz4/lz4-no-postfix.lz4");

        let compressed = compress_dest_size(&raw, expected.len(), false).unwrap();
        assert_eq!(compressed, expected);
        assert_eq!(decompress_safe_partial(&expected, raw.len()).unwrap(), raw);
    }

    #[test]
    fn matches_frozen_lz4hc9_reference() {
        let raw = fixture("lz4/lz4hc9-no-postfix.raw");
        let expected = fixture("lz4/lz4hc9-no-postfix.lz4");

        let compressed = compress_hc_dest_size(&raw, expected.len(), 9, false).unwrap();
        assert_eq!(compressed, expected);
        assert_eq!(decompress_safe_partial(&expected, raw.len()).unwrap(), raw);
    }

    #[test]
    fn matches_frozen_zero_padding_layout() {
        let raw = fixture("lz4/zero-padding-layout.raw");
        let expected = fixture("lz4/zero-padding-layout.lz4");
        let (raw_block, compressed_raw) = raw.split_at(32);
        let (expected_raw, expected_compressed) = expected.split_at(32);

        assert_eq!(raw_block, expected_raw);
        let compressed =
            compress_dest_size(compressed_raw, expected_compressed.len(), true).unwrap();
        assert_eq!(compressed, expected_compressed);

        let first_byte = compressed.iter().position(|byte| *byte != 0).unwrap();
        assert_eq!(
            decompress_safe_partial(&compressed[first_byte..], compressed_raw.len()).unwrap(),
            compressed_raw
        );
    }

    #[test]
    fn round_trip_synthetic_data() {
        let mut raw = Vec::with_capacity(2048);
        for i in 0..2048 {
            raw.push((i % 37) as u8);
        }
        let output_size = 512;
        let compressed = compress_dest_size(&raw, output_size, false).unwrap();
        assert_eq!(compressed.len(), output_size);
        let decompressed = decompress_safe_partial(&compressed, raw.len()).unwrap();
        assert_eq!(decompressed, raw);
    }

    #[test]
    fn round_trip_hc_levels() {
        let mut raw = Vec::with_capacity(2048);
        for i in 0..2048 {
            raw.push((i % 37) as u8);
        }
        let output_size = 512;
        for level in [HC_LEVEL_MIN, 6, 9, HC_LEVEL_MAX] {
            let compressed = compress_hc_dest_size(&raw, output_size, level, false).unwrap();
            assert_eq!(compressed.len(), output_size);
            let decompressed = decompress_safe_partial(&compressed, raw.len()).unwrap();
            assert_eq!(decompressed, raw);
        }
    }

    #[test]
    fn rejects_invalid_compression_levels() {
        let raw = fixture("lz4/lz4-no-postfix.raw");
        assert_eq!(
            compress_hc_dest_size(&raw, 512, HC_LEVEL_MIN - 1, false).unwrap_err().status(),
            Status::InvalidArgument
        );
        assert_eq!(
            compress_hc_dest_size(&raw, 512, HC_LEVEL_MAX + 1, false).unwrap_err().status(),
            Status::InvalidArgument
        );
    }

    #[test]
    fn rejects_zero_or_oversized_inputs() {
        let raw = fixture("lz4/lz4-no-postfix.raw");
        let expected = fixture("lz4/lz4-no-postfix.lz4");

        assert_eq!(
            compress_dest_size(&[], 512, false).unwrap_err().status(),
            Status::InvalidArgument
        );
        assert_eq!(
            compress_dest_size(&raw, 0, false).unwrap_err().status(),
            Status::InvalidArgument
        );
        assert_eq!(
            compress_dest_size(&raw, MAX_INPUT_SIZE + 1, false).unwrap_err().status(),
            Status::InvalidArgument
        );
        assert_eq!(
            decompress_safe_partial(&[], 512).unwrap_err().status(),
            Status::InvalidArgument
        );
        assert_eq!(
            decompress_safe_partial(&expected, 0).unwrap_err().status(),
            Status::InvalidArgument
        );
        assert_eq!(
            decompress_safe_partial(&expected, MAX_INPUT_SIZE + 1).unwrap_err().status(),
            Status::InvalidArgument
        );
    }

    #[test]
    fn rejects_stored_not_smaller_than_raw() {
        let raw = fixture("lz4/lz4-no-postfix.raw");
        assert_eq!(
            compress_dest_size(&raw, raw.len(), false).unwrap_err().status(),
            Status::InvalidArgument
        );
        assert_eq!(
            compress_dest_size(&raw, raw.len() + 10, false).unwrap_err().status(),
            Status::InvalidArgument
        );
        assert_eq!(
            decompress_safe_partial(&raw, raw.len() / 2).unwrap_err().status(),
            Status::InvalidArgument
        );
    }

    #[test]
    fn fails_on_corrupted_decompression_input() {
        let raw = fixture("lz4/lz4-no-postfix.raw");
        let expected = fixture("lz4/lz4-no-postfix.lz4");
        let mut corrupted = expected.clone();
        corrupted[0] = 0xff;
        corrupted[1] = 0xff;
        assert_eq!(
            decompress_safe_partial(&corrupted, raw.len()).unwrap_err().status(),
            Status::DecompressionFailed
        );
    }

    #[test]
    fn fails_on_decompression_size_mismatch() {
        let raw = fixture("lz4/lz4-no-postfix.raw");
        let expected = fixture("lz4/lz4-no-postfix.lz4");
        let compressed_end = expected.iter().rposition(|byte| *byte != 0).map_or(0, |i| i + 1);
        assert_eq!(
            decompress_safe_partial(&expected[..compressed_end], raw.len() + 256)
                .unwrap_err()
                .status(),
            Status::DecompressionFailed
        );
    }

    #[test]
    fn fails_when_output_budget_too_small() {
        let raw = fixture("lz4/lz4-no-postfix.raw");
        let error = compress_dest_size(&raw, 16, false).unwrap_err();
        assert!(
            error.status() == Status::CompressionDivergence
                || error.status() == Status::CompressionFailed
        );
    }
}
