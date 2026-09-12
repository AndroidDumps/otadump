//! Pure-Rust, apply-only reimplementation of the Zucchini executable patcher.
//!
//! The native implementation vendored for this crate links the upstream C++
//! `components/zucchini` sources plus libchrome. This module is an independent
//! Rust port of the apply path (no C++ and no libchrome). It targets exactly
//! the element formats that Android delta OTA payloads use: `NoOp`, ELF
//! x86/x86-64/AArch32/AArch64, and DEX.
//!
//! Scope and status are documented in `docs/zucchini-rust-port.md`.

// This is a line-by-line port of the C++ apply path, so several clippy style
// lints (control-flow shape, argument counts, explicit byte indexing) are
// intentionally allowed rather than restructured away from the original.
#![allow(
    clippy::collapsible_if,
    clippy::implicit_saturating_sub,
    clippy::manual_is_multiple_of,
    clippy::needless_range_loop,
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::unnecessary_cast
)]

use std::error;
use std::fmt;

mod arm;
pub mod bytes;
mod crc32;
mod dex;
mod elf;
mod engine;
pub mod patch;

pub use engine::Reference;
pub use elf::ElfDisassembler;

/// Exclusive upper bound for buffers represented by Zucchini offsets.
pub const OFFSET_BOUND: usize = (u32::MAX / 2) as usize;
/// `0xFFFFFFFE`, distinct from the fake-offset sentinel used by DEX indices.
pub const K_INVALID_OFFSET: u32 = 0xFFFF_FFFE;
pub const K_INVALID_RVA: u32 = 0xFFFF_FFFE;

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

    pub(crate) fn new(status: Status, message: impl Into<String>) -> Self {
        Self { status, message: message.into() }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Builds an `AllocationFailure` for a named attacker-influenced allocation.
pub(crate) fn allocation_error(context: &str) -> Error {
    Error::new(Status::AllocationFailure, format!("unable to allocate {context}"))
}

/// A parsed reference type within an executable element.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupTraits {
    pub width: u32,
    pub type_tag: u8,
    pub pool_tag: u8,
}

/// The reference-correction interface implemented by each element format.
pub trait Disassembler {
    /// Size of the recognized executable, after header parsing shrinks the view.
    fn size(&self) -> u32;

    /// Reference groups, in the native `MakeReferenceGroups()` order.
    fn groups(&self) -> &[GroupTraits];

    /// Emits references of `group` whose bodies lie in `[lo, hi)`.
    ///
    /// Fallible so that reference vectors derived from attacker-controlled
    /// counts can fail with `Status::AllocationFailure` instead of aborting.
    fn read(&self, group: usize, image: &[u8], lo: u32, hi: u32) -> Result<Vec<Reference>>;

    /// Writes a single corrected reference into the new image.
    fn write(&self, group: usize, image: &mut [u8], reference: Reference);
}

/// Applies a Zucchini patch into a newly allocated, exact-size output buffer.
pub fn apply(old: &[u8], patch_bytes: &[u8], output_size: usize) -> Result<Vec<u8>> {
    apply_with_cancel(old, patch_bytes, output_size, || false)
}

/// Same as [`apply`], but polls `cancelled` between elements, pools, and
/// equivalence units and returns [`Status::Cancelled`] if it becomes true.
///
/// This keeps the original [`apply`] signature intact while giving callers a
/// cooperative stop hook (for example, a UI or signal-driven token).
pub fn apply_with_cancel<F: Fn() -> bool>(
    old: &[u8],
    patch_bytes: &[u8],
    output_size: usize,
    cancelled: F,
) -> Result<Vec<u8>> {
    apply_inner(old, patch_bytes, output_size, &cancelled)
}

fn apply_inner(
    old: &[u8],
    patch_bytes: &[u8],
    output_size: usize,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>> {
    let check = || -> Result<()> {
        if cancelled() {
            Err(Error::new(Status::Cancelled, "Zucchini apply cancelled"))
        } else {
            Ok(())
        }
    };

    check()?;
    if old.len() >= OFFSET_BOUND || output_size >= OFFSET_BOUND {
        return Err(Error::new(Status::InvalidArgument, "image exceeds Zucchini offset bound"));
    }
    if patch_bytes.len() >= OFFSET_BOUND {
        return Err(Error::new(Status::InvalidArgument, "patch exceeds Zucchini offset bound"));
    }

    let patch = patch::Patch::parse(patch_bytes)?;
    if patch.header.new_size as usize != output_size {
        return Err(Error::new(Status::WrongOutputSize, "output buffer size does not match patch"));
    }

    // Reject element formats that Android never emits, matching the native FFI
    // allow-list (NoOp plus Android executables).
    for element in &patch.elements {
        if element.element_match.exe_type != patch::EXE_TYPE_NOOP
            && !is_android_executable(element.element_match.exe_type)
        {
            return Err(Error::new(
                Status::UnsupportedElement,
                "element format is not enabled by Android",
            ));
        }
    }

    let mut output = Vec::new();
    output.try_reserve_exact(output_size).map_err(|error| {
        Error::new(Status::AllocationFailure, format!("unable to allocate Zucchini output: {error}"))
    })?;
    output.resize(output_size, 0);

    // Android hardens upstream apply with an additional preflight. Mirror the
    // native FFI so unsafe patches are rejected before publication. The native
    // `PreflightAndroidElements` performs the old-file check here too, hence the
    // preflight-specific message.
    if !patch::check_old_file_cancel(&patch.header, old, cancelled)? {
        return Err(Error::new(Status::ApplyError, "android executable preflight failed"));
    }
    for element in &patch.elements {
        check()?;
        let exe_type = element.element_match.exe_type;
        // Parse and cache the old element's per-group references once, then
        // share them between preflight and apply (the native FFI re-reads them
        // for every equivalence in both phases).
        let (old_element, new_element) = engine::element_regions(old, element, &mut output)?;
        let analysis = engine::analyze_element(exe_type, old_element)?;
        engine::preflight_element(element, old_element, new_element, &analysis, cancelled).map_err(
            |error| match error.status() {
                Status::Cancelled => error,
                _ => Error::new(Status::ApplyError, "android executable preflight failed"),
            },
        )?;
        let (old_element, new_element) = engine::element_regions(old, element, &mut output)?;
        engine::apply_element(element, old_element, new_element, &analysis, cancelled)?;
    }

    if !patch::check_new_file_cancel(&patch.header, &output, cancelled)? {
        return Err(Error::new(Status::ApplyError, "zucchini apply failed"));
    }
    Ok(output)
}

pub(crate) fn is_android_executable(exe_type: u32) -> bool {
    matches!(
        exe_type,
        patch::EXE_TYPE_ELF_X86
            | patch::EXE_TYPE_ELF_X64
            | patch::EXE_TYPE_ELF_AARCH32
            | patch::EXE_TYPE_ELF_AARCH64
            | patch::EXE_TYPE_DEX
    )
}

/// Dispatches to the format disassembler for `exe_type`, parsing `image`.
pub(crate) fn make_disassembler(
    exe_type: u32,
    image: &[u8],
) -> Option<Box<dyn Disassembler>> {
    match exe_type {
        patch::EXE_TYPE_NOOP => Some(Box::new(engine::NoOpDisassembler { size: image.len() as u32 })),
        patch::EXE_TYPE_ELF_X86 => {
            elf::ElfDisassembler::parse(elf::ElfKind::X86, image).map(|d| Box::new(d) as _)
        }
        patch::EXE_TYPE_ELF_X64 => {
            elf::ElfDisassembler::parse(elf::ElfKind::X64, image).map(|d| Box::new(d) as _)
        }
        patch::EXE_TYPE_ELF_AARCH32 => {
            elf::ElfDisassembler::parse(elf::ElfKind::AArch32, image).map(|d| Box::new(d) as _)
        }
        patch::EXE_TYPE_ELF_AARCH64 => {
            elf::ElfDisassembler::parse(elf::ElfKind::AArch64, image).map(|d| Box::new(d) as _)
        }
        patch::EXE_TYPE_DEX => {
            dex::DexDisassembler::parse(image).map(|d| Box::new(d) as _)
        }
        _ => None,
    }
}
