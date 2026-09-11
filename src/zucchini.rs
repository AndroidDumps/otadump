use std::error;
use std::fmt;

#[cfg(otadump_zucchini)]
const OFFSET_BOUND: usize = (u32::MAX / 2) as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    InvalidArgument,
    InvalidPatch,
    UnsupportedElement,
    WrongOutputSize,
    ApplyError,
    AllocationFailure,
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

/// Applies a Zucchini patch into a newly allocated, exact-size output buffer.
///
/// The native boundary borrows `old` and `patch` only for this call. The output
/// allocation is distinct from both inputs, as required by Zucchini.
pub fn apply(old: &[u8], patch: &[u8], output_size: usize) -> Result<Vec<u8>> {
    apply_impl(old, patch, output_size)
}

#[cfg(otadump_zucchini)]
fn apply_impl(old: &[u8], patch: &[u8], output_size: usize) -> Result<Vec<u8>> {
    if old.len() >= OFFSET_BOUND || output_size >= OFFSET_BOUND {
        return Err(Error {
            status: Status::InvalidArgument,
            message: "image exceeds Zucchini offset bound".into(),
        });
    }

    let mut output = Vec::new();
    output.try_reserve_exact(output_size).map_err(|error| Error {
        status: Status::AllocationFailure,
        message: format!("unable to allocate Zucchini output: {error}"),
    })?;
    output.resize(output_size, 0);

    apply_native(old, patch, &mut output)?;
    Ok(output)
}

#[cfg(not(otadump_zucchini))]
fn apply_impl(_old: &[u8], _patch: &[u8], _output_size: usize) -> Result<Vec<u8>> {
    Err(Error {
        status: Status::UnsupportedTarget,
        message: "Zucchini is supported only on Linux x86_64 GNU hosts".into(),
    })
}

#[cfg(otadump_zucchini)]
fn apply_native(old: &[u8], patch: &[u8], output: &mut [u8]) -> Result<()> {
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

    // SAFETY: The slices remain alive for the call. `output` is a separate
    // owned allocation and cannot overlap either borrowed input. The native
    // function validates every length before it performs pointer arithmetic.
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
        return Ok(());
    }

    let message = if result.error.is_null() {
        format!("Zucchini failed with status {}", result.status)
    } else {
        // SAFETY: Native errors point to static NUL-terminated strings. Copy
        // the message before returning so Rust does not retain the pointer.
        unsafe { CStr::from_ptr(result.error) }.to_string_lossy().into_owned()
    };
    Err(Error { status: native_status(result.status), message })
}

#[cfg(otadump_zucchini)]
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
