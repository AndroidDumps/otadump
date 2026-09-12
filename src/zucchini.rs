use std::error;
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    InvalidArgument,
    InvalidPatch,
    UnsupportedElement,
    WrongOutputSize,
    ApplyError,
    Cancelled,
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

/// Exclusive upper bound for buffers represented by Zucchini offsets.
pub const OFFSET_BOUND: usize = (u32::MAX / 2) as usize;

/// Applies a Zucchini patch into a newly allocated, exact-size output buffer.
///
pub fn apply(old: &[u8], patch: &[u8], output_size: usize) -> Result<Vec<u8>> {
    if old.len() >= OFFSET_BOUND || patch.len() >= OFFSET_BOUND || output_size >= OFFSET_BOUND {
        return Err(Error {
            status: Status::InvalidArgument,
            message: "image exceeds Zucchini offset bound".into(),
        });
    }
    let mut output = Vec::new();
    output.try_reserve_exact(output_size).map_err(|e| Error {
        status: Status::AllocationFailure,
        message: format!("unable to allocate Zucchini output: {e}"),
    })?;
    output.resize(output_size, 0);
    #[cfg(otadump_zucchini)]
    {
        use std::ffi::{CStr, c_char};
        #[repr(C)]
        struct NativeResult {
            status: i32,
            error: *const c_char,
        }
        unsafe extern "C" {
            fn otadump_zucchini_apply(
                old: *const u8,
                old_len: usize,
                patch: *const u8,
                patch_len: usize,
                new: *mut u8,
                new_len: usize,
            ) -> NativeResult;
        }
        // SAFETY: all slices remain alive and output is a distinct allocation for the call.
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
            unsafe { CStr::from_ptr(result.error) }.to_string_lossy().into_owned()
        };
        Err(Error {
            status: match result.status {
                1 => Status::InvalidArgument,
                2 => Status::InvalidPatch,
                3 => Status::UnsupportedElement,
                4 => Status::WrongOutputSize,
                5 => Status::ApplyError,
                n => Status::Unknown(n),
            },
            message,
        })
    }
    #[cfg(not(otadump_zucchini))]
    {
        let _ = (old, patch, output);
        Err(Error {
            status: Status::UnsupportedTarget,
            message: "Zucchini is supported only on Linux x86_64 GNU hosts".into(),
        })
    }
}

/// Same as [`apply`], but cooperatively stops when `cancelled` returns true.
/// Native Zucchini is one non-interruptible operation; cancellation is checked
/// immediately before and after that call.
pub fn apply_with_cancel<F: Fn() -> bool>(
    old: &[u8],
    patch: &[u8],
    output_size: usize,
    cancelled: F,
) -> Result<Vec<u8>> {
    if cancelled() {
        return Err(Error {
            status: Status::Cancelled,
            message: "Zucchini operation cancelled".into(),
        });
    }
    // ponytail: the upstream apply loop has no safe cancellation seam; the
    // operation boundary is the deliberate cancellation ceiling.
    let result = apply(old, patch, output_size);
    if cancelled() {
        return Err(Error {
            status: Status::Cancelled,
            message: "Zucchini operation cancelled".into(),
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_with_cancel_reports_cancelled() {
        let error = apply_with_cancel(b"abcd", b"not a patch", 5, || true).unwrap_err();
        assert_eq!(error.status(), Status::Cancelled);
    }

    #[test]
    fn apply_reports_invalid_patch_when_not_cancelled() {
        let error = apply_with_cancel(b"abcd", b"not a patch", 5, || false).unwrap_err();
        assert_eq!(error.status(), Status::InvalidPatch);
    }
}
