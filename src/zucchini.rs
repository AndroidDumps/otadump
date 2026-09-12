use crate::zucchini_pure;

pub use crate::zucchini_pure::{Error, Result, Status};

/// Exclusive upper bound for buffers represented by Zucchini offsets.
pub const OFFSET_BOUND: usize = zucchini_pure::OFFSET_BOUND;

/// Applies a Zucchini patch into a newly allocated, exact-size output buffer.
///
/// This is now backed entirely by the pure-Rust implementation in
/// `zucchini_pure`; the vendored C++ Zucchini is no longer required.
pub fn apply(old: &[u8], patch: &[u8], output_size: usize) -> Result<Vec<u8>> {
    zucchini_pure::apply(old, patch, output_size)
}

/// Same as [`apply`], but cooperatively stops when `cancelled` returns true.
pub fn apply_with_cancel<F: Fn() -> bool>(
    old: &[u8],
    patch: &[u8],
    output_size: usize,
    cancelled: F,
) -> Result<Vec<u8>> {
    zucchini_pure::apply_with_cancel(old, patch, output_size, cancelled)
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
