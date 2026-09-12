use std::error;
use std::fmt;

use crate::zucchini_pure;

/// Exclusive upper bound for buffers represented by Zucchini offsets.
pub const OFFSET_BOUND: usize = zucchini_pure::OFFSET_BOUND;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    InvalidArgument,
    InvalidPatch,
    UnsupportedElement,
    WrongOutputSize,
    ApplyError,
    AllocationFailure,
    UnsupportedTarget,
    Cancelled,
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

fn map_status(status: zucchini_pure::Status) -> Status {
    match status {
        zucchini_pure::Status::InvalidArgument => Status::InvalidArgument,
        zucchini_pure::Status::InvalidPatch => Status::InvalidPatch,
        zucchini_pure::Status::UnsupportedElement => Status::UnsupportedElement,
        zucchini_pure::Status::WrongOutputSize => Status::WrongOutputSize,
        zucchini_pure::Status::ApplyError => Status::ApplyError,
        zucchini_pure::Status::AllocationFailure => Status::AllocationFailure,
        zucchini_pure::Status::UnsupportedTarget => Status::UnsupportedTarget,
        zucchini_pure::Status::Cancelled => Status::Cancelled,
        zucchini_pure::Status::Unknown(code) => Status::Unknown(code),
    }
}

fn map_error(error: zucchini_pure::Error) -> Error {
    Error { status: map_status(error.status()), message: error.to_string() }
}

/// Applies a Zucchini patch into a newly allocated, exact-size output buffer.
///
/// This is now backed entirely by the pure-Rust implementation in
/// `zucchini_pure`; the vendored C++ Zucchini is no longer required.
pub fn apply(old: &[u8], patch: &[u8], output_size: usize) -> Result<Vec<u8>> {
    zucchini_pure::apply(old, patch, output_size).map_err(map_error)
}

/// Same as [`apply`], but cooperatively stops when `cancelled` returns true.
pub fn apply_with_cancel<F: Fn() -> bool>(
    old: &[u8],
    patch: &[u8],
    output_size: usize,
    cancelled: F,
) -> Result<Vec<u8>> {
    zucchini_pure::apply_with_cancel(old, patch, output_size, cancelled).map_err(map_error)
}

/// The vendored C++ implementation, retained only for differential testing when
/// `OTADUMP_NATIVE_ZUCCHINI=1` selects it at build time.
#[cfg(otadump_native_zucchini)]
pub fn apply_native(old: &[u8], patch: &[u8], output_size: usize) -> Result<Vec<u8>> {
    use std::ffi::{CStr, c_char};

    #[repr(C)]
    struct NativeResult {
        status: i32,
        error: *const c_char,
    }

    unsafe extern "C" {
        fn otadump_zucchini_apply(
            old_data: *const u8,
            old_size: usize,
            patch_data: *const u8,
            patch_size: usize,
            new_data: *mut u8,
            new_size: usize,
        ) -> NativeResult;
    }

    if old.len() >= OFFSET_BOUND || output_size >= OFFSET_BOUND {
        return Err(Error {
            status: Status::InvalidArgument,
            message: "image exceeds Zucchini offset bound".into(),
        });
    }
    if patch.len() >= OFFSET_BOUND {
        return Err(Error {
            status: Status::InvalidArgument,
            message: "patch exceeds Zucchini offset bound".into(),
        });
    }

    let mut output = Vec::new();
    output.try_reserve_exact(output_size).map_err(|error| Error {
        status: Status::AllocationFailure,
        message: format!("unable to allocate Zucchini output: {error}"),
    })?;
    output.resize(output_size, 0);

    // SAFETY: The slices remain alive for the call. `output` is a separate
    // owned allocation and cannot overlap either borrowed input.
    let result = unsafe {
        otadump_zucchini_apply(
            old.as_ptr(),
            old.len(),
            patch.as_ptr(),
            patch.len(),
            output.as_mut_ptr(),
            output.len(),
        )
    };
    if result.status == 0 {
        return Ok(output);
    }

    let message = if result.error.is_null() {
        format!("Zucchini failed with status {}", result.status)
    } else {
        // SAFETY: Native errors point to static NUL-terminated strings.
        unsafe { CStr::from_ptr(result.error) }.to_string_lossy().into_owned()
    };
    Err(Error { status: native_status(result.status), message })
}

#[cfg(otadump_native_zucchini)]
fn native_status(status: i32) -> Status {
    match status {
        1 => Status::InvalidArgument,
        2 => Status::InvalidPatch,
        3 => Status::UnsupportedElement,
        4 => Status::WrongOutputSize,
        5 => Status::ApplyError,
        status => Status::Unknown(status),
    }
}
