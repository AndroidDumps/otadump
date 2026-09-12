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

    #[test]
    fn compress_and_decompress_round_trip() {
        let raw = (0..2048).map(|i| (i % 37) as u8).collect::<Vec<_>>();
        let compressed = compress_dest_size(&raw, 512, false).unwrap();
        let decompressed = decompress_safe_partial(&compressed, raw.len()).unwrap();
        assert_eq!(decompressed, raw);
    }

    #[test]
    fn zero_padding_round_trip() {
        let raw = vec![0x5a; 1024];
        let compressed = compress_dest_size(&raw, 64, true).unwrap();
        let start = compressed.iter().position(|byte| *byte != 0).unwrap();
        let decompressed = decompress_safe_partial(&compressed[start..], raw.len()).unwrap();
        assert_eq!(decompressed, raw);
    }

    #[test]
    fn invalid_sizes_return_invalid_argument() {
        assert_eq!(
            compress_dest_size(&[], 32, false).unwrap_err().status(),
            Status::InvalidArgument
        );
        assert_eq!(
            decompress_safe_partial(&[1, 2, 3], 0).unwrap_err().status(),
            Status::InvalidArgument
        );
    }
}
