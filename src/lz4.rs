use std::error;
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
    UnsupportedTarget,
    Unknown(i32),
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
    ensure_supported()?;
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
    ensure_supported()?;
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

#[cfg(otadump_lz4)]
fn decompress_native(input: &[u8], output: &mut [u8]) -> Result<NativeResult> {
    native_call(input, output, None, true)
}

#[cfg(not(otadump_lz4))]
fn decompress_native(_input: &[u8], _output: &mut [u8]) -> Result<NativeResult> {
    Err(unsupported_target())
}

#[cfg(otadump_lz4)]
fn compress_native(
    input: &[u8],
    output: &mut [u8],
    compression_level: Option<i32>,
) -> Result<NativeResult> {
    native_call(input, output, compression_level, false)
}

#[cfg(not(otadump_lz4))]
fn compress_native(
    _input: &[u8],
    _output: &mut [u8],
    _compression_level: Option<i32>,
) -> Result<NativeResult> {
    Err(unsupported_target())
}

#[cfg(not(otadump_lz4))]
fn ensure_supported() -> Result<()> {
    Err(unsupported_target())
}

#[cfg(otadump_lz4)]
fn ensure_supported() -> Result<()> {
    Ok(())
}

#[allow(dead_code)]
fn unsupported_target() -> Error {
    Error {
        status: Status::UnsupportedTarget,
        message: "LZ4 block operations are supported only on Linux x86_64 GNU hosts".into(),
    }
}

#[cfg(otadump_lz4)]
fn native_call(
    input: &[u8],
    output: &mut [u8],
    compression_level: Option<i32>,
    decompress: bool,
) -> Result<NativeResult> {
    use std::ffi::c_int;

    #[repr(C)]
    struct FfiResult {
        status: c_int,
        source_size: c_int,
        output_size: c_int,
    }

    unsafe extern "C" {
        fn otadump_lz4_decompress_safe_partial(
            source: *const u8,
            source_size: c_int,
            output: *mut u8,
            output_capacity: c_int,
            target_output_size: c_int,
        ) -> FfiResult;
        fn otadump_lz4_compress_dest_size(
            source: *const u8,
            source_size: c_int,
            output: *mut u8,
            output_capacity: c_int,
        ) -> FfiResult;
        fn otadump_lz4_compress_hc_dest_size(
            source: *const u8,
            source_size: c_int,
            output: *mut u8,
            output_capacity: c_int,
            compression_level: c_int,
        ) -> FfiResult;
    }

    let source_size =
        i32::try_from(input.len()).map_err(|_| invalid_argument("LZ4 input size exceeds int"))?;
    let output_size =
        i32::try_from(output.len()).map_err(|_| invalid_argument("LZ4 output size exceeds int"))?;
    // SAFETY: The immutable input and mutable output slices cannot alias. They
    // remain alive for the call, and their checked lengths match the pointers.
    let result = unsafe {
        if decompress {
            otadump_lz4_decompress_safe_partial(
                input.as_ptr(),
                source_size,
                output.as_mut_ptr(),
                output_size,
                output_size,
            )
        } else if let Some(level) = compression_level {
            otadump_lz4_compress_hc_dest_size(
                input.as_ptr(),
                source_size,
                output.as_mut_ptr(),
                output_size,
                level,
            )
        } else {
            otadump_lz4_compress_dest_size(
                input.as_ptr(),
                source_size,
                output.as_mut_ptr(),
                output_size,
            )
        }
    };
    if result.status != 0 {
        return Err(Error {
            status: native_status(result.status),
            message: native_message(result.status).into(),
        });
    }
    Ok(NativeResult {
        source_size: usize::try_from(result.source_size)
            .map_err(|_| invalid_argument("native LZ4 returned a negative source size"))?,
        output_size: usize::try_from(result.output_size)
            .map_err(|_| invalid_argument("native LZ4 returned a negative output size"))?,
    })
}

#[cfg(otadump_lz4)]
fn native_status(status: i32) -> Status {
    match status {
        1 => Status::InvalidArgument,
        2 => Status::CompressionFailed,
        3 => Status::DecompressionFailed,
        4 => Status::AllocationFailure,
        status => Status::Unknown(status),
    }
}

#[cfg(otadump_lz4)]
fn native_message(status: i32) -> &'static str {
    match status {
        1 => "native LZ4 rejected an argument",
        2 => "native LZ4 compression failed",
        3 => "native LZ4 decompression failed",
        4 => "native LZ4 allocation failed",
        _ => "native LZ4 failed with an unknown status",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_frozen_lz4_reference() {
        let raw = include_bytes!("../tests/fixtures/lz4/lz4-no-postfix.raw");
        let expected = include_bytes!("../tests/fixtures/lz4/lz4-no-postfix.lz4");

        let compressed = compress_dest_size(raw, expected.len(), false).unwrap();
        assert_eq!(compressed, expected);
        assert_eq!(decompress_safe_partial(expected, raw.len()).unwrap(), raw);
    }

    #[test]
    fn matches_frozen_lz4hc9_reference() {
        let raw = include_bytes!("../tests/fixtures/lz4/lz4hc9-no-postfix.raw");
        let expected = include_bytes!("../tests/fixtures/lz4/lz4hc9-no-postfix.lz4");

        let compressed = compress_hc_dest_size(raw, expected.len(), 9, false).unwrap();
        assert_eq!(compressed, expected);
        assert_eq!(decompress_safe_partial(expected, raw.len()).unwrap(), raw);
    }

    #[test]
    fn matches_frozen_zero_padding_layout() {
        let raw = include_bytes!("../tests/fixtures/lz4/zero-padding-layout.raw");
        let expected = include_bytes!("../tests/fixtures/lz4/zero-padding-layout.lz4");
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
        let raw = include_bytes!("../tests/fixtures/lz4/lz4-no-postfix.raw");
        assert_eq!(
            compress_hc_dest_size(raw, 512, HC_LEVEL_MIN - 1, false).unwrap_err().status(),
            Status::InvalidArgument
        );
        assert_eq!(
            compress_hc_dest_size(raw, 512, HC_LEVEL_MAX + 1, false).unwrap_err().status(),
            Status::InvalidArgument
        );
    }

    #[test]
    fn rejects_zero_or_oversized_inputs() {
        let raw = include_bytes!("../tests/fixtures/lz4/lz4-no-postfix.raw");
        let expected = include_bytes!("../tests/fixtures/lz4/lz4-no-postfix.lz4");

        assert_eq!(
            compress_dest_size(&[], 512, false).unwrap_err().status(),
            Status::InvalidArgument
        );
        assert_eq!(
            compress_dest_size(raw, 0, false).unwrap_err().status(),
            Status::InvalidArgument
        );
        assert_eq!(
            compress_dest_size(raw, MAX_INPUT_SIZE + 1, false).unwrap_err().status(),
            Status::InvalidArgument
        );
        assert_eq!(
            decompress_safe_partial(&[], 512).unwrap_err().status(),
            Status::InvalidArgument
        );
        assert_eq!(
            decompress_safe_partial(expected, 0).unwrap_err().status(),
            Status::InvalidArgument
        );
        assert_eq!(
            decompress_safe_partial(expected, MAX_INPUT_SIZE + 1).unwrap_err().status(),
            Status::InvalidArgument
        );
    }

    #[test]
    fn rejects_stored_not_smaller_than_raw() {
        let raw = include_bytes!("../tests/fixtures/lz4/lz4-no-postfix.raw");
        assert_eq!(
            compress_dest_size(raw, raw.len(), false).unwrap_err().status(),
            Status::InvalidArgument
        );
        assert_eq!(
            compress_dest_size(raw, raw.len() + 10, false).unwrap_err().status(),
            Status::InvalidArgument
        );
        assert_eq!(
            decompress_safe_partial(raw, raw.len() / 2).unwrap_err().status(),
            Status::InvalidArgument
        );
    }

    #[test]
    fn fails_on_corrupted_decompression_input() {
        let raw = include_bytes!("../tests/fixtures/lz4/lz4-no-postfix.raw");
        let expected = include_bytes!("../tests/fixtures/lz4/lz4-no-postfix.lz4");
        let mut corrupted = expected.to_vec();
        corrupted[0] = 0xff;
        corrupted[1] = 0xff;
        assert_eq!(
            decompress_safe_partial(&corrupted, raw.len()).unwrap_err().status(),
            Status::DecompressionFailed
        );
    }

    #[test]
    fn fails_on_decompression_size_mismatch() {
        let raw = include_bytes!("../tests/fixtures/lz4/lz4-no-postfix.raw");
        let expected = include_bytes!("../tests/fixtures/lz4/lz4-no-postfix.lz4");
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
        let raw = include_bytes!("../tests/fixtures/lz4/lz4-no-postfix.raw");
        let error = compress_dest_size(raw, 16, false).unwrap_err();
        assert!(
            error.status() == Status::CompressionDivergence
                || error.status() == Status::CompressionFailed
        );
    }
}
