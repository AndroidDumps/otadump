//! Byte-exact fixture tests for the pure-Rust Zucchini apply path.

use std::fs;
use std::path::Path;

use otadump::zucchini_pure::{self, Status};

const FIXTURES: &str = "tests/fixtures/zucchini";

/// Applies `<name>-old<ext>` + `<name>.zuc` and compares with `<name>-new<ext>`.
fn assert_fixture(name: &str, extension: &str) {
    let fixtures = Path::new(FIXTURES);
    let old = fs::read(fixtures.join(format!("{name}-old{extension}"))).unwrap();
    let expected = fs::read(fixtures.join(format!("{name}-new{extension}"))).unwrap();
    let patch = fs::read(fixtures.join(format!("{name}.zuc"))).unwrap();
    let output = zucchini_pure::apply(&old, &patch, expected.len()).unwrap();
    assert_eq!(output, expected, "fixture {name} did not reconstruct byte-exactly");
}

#[test]
fn pure_rust_applies_noop_and_elf_fixtures() {
    assert_fixture("noop", ".bin");
    assert_fixture("elf-x86", "");
    assert_fixture("elf", "");
    assert_fixture("elf-arm32", "");
    assert_fixture("elf-arm64", "");
}

#[test]
fn pure_rust_applies_dex_fixtures() {
    assert_fixture("dex", ".dex");
    assert_fixture("dex-large", ".dex");
}

#[test]
fn pure_rust_rejects_garbage_patch() {
    let error = zucchini_pure::apply(b"abcd", b"not a patch", 5).unwrap_err();
    assert_eq!(error.status(), Status::InvalidPatch);
}

#[test]
fn pure_rust_rejects_wrong_output_size() {
    let fixtures = Path::new(FIXTURES);
    let old = fs::read(fixtures.join("noop-old.bin")).unwrap();
    let patch = fs::read(fixtures.join("noop.zuc")).unwrap();
    let error = zucchini_pure::apply(&old, &patch, 999).unwrap_err();
    assert_eq!(error.status(), Status::WrongOutputSize);
}

/// Mirrors the native test for `dex-large-unsafe16.zuc`: the Android preflight
/// must reject the unsafe 16-bit string reference before publication.
#[test]
fn pure_rust_rejects_unsafe_large_dex_string16_reference() {
    let fixtures = Path::new(FIXTURES);
    let old = fs::read(fixtures.join("dex-large-old.dex")).unwrap();
    let patch = fs::read(fixtures.join("dex-large-unsafe16.zuc")).unwrap();
    let expected_size = fs::metadata(fixtures.join("dex-large-new.dex")).unwrap().len() as usize;
    let error = zucchini_pure::apply(&old, &patch, expected_size).unwrap_err();
    assert_eq!(error.status(), Status::ApplyError);
    assert_eq!(error.to_string(), "android executable preflight failed");
}

#[test]
fn pure_rust_rejects_truncated_patch() {
    let fixtures = Path::new(FIXTURES);
    let old = fs::read(fixtures.join("noop-old.bin")).unwrap();
    let patch = fs::read(fixtures.join("noop.zuc")).unwrap();
    let error = zucchini_pure::apply(&old, &patch[..patch.len() - 1], 5).unwrap_err();
    assert_eq!(error.status(), Status::InvalidPatch);
}

fn var_u32(mut value: u32, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn var_i32(value: i32, out: &mut Vec<u8>) {
    let encoded = if value < 0 { (((!value) as u32) << 1) | 1 } else { (value as u32) << 1 };
    var_u32(encoded, out);
}

fn push_buffer(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
}

fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (index, entry) in table.iter_mut().enumerate() {
        let mut r = index as u32;
        for _ in 0..8 {
            r = (r >> 1) ^ (0xEDB8_8320 & (!((r & 1).wrapping_sub(1))));
        }
        *entry = r;
    }
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc = table[((crc ^ u32::from(byte)) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

/// Builds a single-element NoOp patch whose reference-delta stream is
/// `reference_delta`.
fn build_noop_patch(old: &[u8], new: &[u8], reference_delta: &[u8]) -> Vec<u8> {
    let mut patch = Vec::new();
    patch.extend_from_slice(b"Zucc");
    patch.extend_from_slice(&1u16.to_le_bytes());
    patch.extend_from_slice(&0u16.to_le_bytes());
    patch.extend_from_slice(&(old.len() as u32).to_le_bytes());
    patch.extend_from_slice(&crc32(old).to_le_bytes());
    patch.extend_from_slice(&(new.len() as u32).to_le_bytes());
    patch.extend_from_slice(&crc32(new).to_le_bytes());
    patch.extend_from_slice(&1u32.to_le_bytes());

    patch.extend_from_slice(&0u32.to_le_bytes());
    patch.extend_from_slice(&(old.len() as u32).to_le_bytes());
    patch.extend_from_slice(&0u32.to_le_bytes());
    patch.extend_from_slice(&(new.len() as u32).to_le_bytes());
    patch.extend_from_slice(&u32::from_le_bytes(*b"NoOp").to_le_bytes());
    patch.extend_from_slice(&1u16.to_le_bytes());

    let mut src_skip = Vec::new();
    var_i32(0, &mut src_skip);
    let mut dst_skip = Vec::new();
    var_u32(0, &mut dst_skip);
    let mut copy_count = Vec::new();
    var_u32(old.len() as u32, &mut copy_count);
    push_buffer(&mut patch, &src_skip);
    push_buffer(&mut patch, &dst_skip);
    push_buffer(&mut patch, &copy_count);

    push_buffer(&mut patch, &new[old.len()..]);
    push_buffer(&mut patch, &[]); // raw delta skip
    push_buffer(&mut patch, &[]); // raw delta diff
    push_buffer(&mut patch, reference_delta);
    patch.extend_from_slice(&0u32.to_le_bytes());
    patch
}

#[test]
fn pure_rust_rejects_malformed_trailing_reference_delta() {
    let old = b"ABCD";
    let new = b"ABCDE";

    // A well-formed empty stream applies cleanly for NoOp elements.
    let valid = build_noop_patch(old, new, &[]);
    assert_eq!(zucchini_pure::apply(old, &valid, new.len()).unwrap(), new.to_vec());

    // An unterminated varint must be rejected like the native Done() semantics,
    // even though a NoOp element needs no reference deltas at all.
    let malformed = build_noop_patch(old, new, &[0x80]);
    let error = zucchini_pure::apply(old, &malformed, new.len()).unwrap_err();
    assert_eq!(error.status(), Status::ApplyError);
}

#[test]
fn pure_rust_honors_cancellation() {
    use std::cell::Cell;

    let fixtures = Path::new(FIXTURES);
    let old = fs::read(fixtures.join("noop-old.bin")).unwrap();
    let patch = fs::read(fixtures.join("noop.zuc")).unwrap();
    let new_size = fs::metadata(fixtures.join("noop-new.bin")).unwrap().len() as usize;

    let calls = Cell::new(0);
    let error = zucchini_pure::apply_with_cancel(&old, &patch, new_size, || {
        calls.set(calls.get() + 1);
        calls.get() > 1
    })
    .unwrap_err();
    assert_eq!(error.status(), Status::Cancelled);
}

/// Cancellation occurring while the Android preflight is running must surface
/// as `Status::Cancelled`, not be folded into the preflight `ApplyError`.
#[test]
fn pure_rust_preserves_cancellation_through_preflight() {
    use std::cell::Cell;

    let fixtures = Path::new(FIXTURES);
    for (old_name, patch_name, new_name) in
        [("elf-old", "elf.zuc", "elf-new"), ("dex-old.dex", "dex.zuc", "dex-new.dex")]
    {
        let old = fs::read(fixtures.join(old_name)).unwrap();
        let patch = fs::read(fixtures.join(patch_name)).unwrap();
        let size = fs::metadata(fixtures.join(new_name)).unwrap().len() as usize;

        // Every early poll site (CRC chunks, per-element, per-group, per
        // equivalence, and DEX target validation) must preserve Cancelled.
        for threshold in 1..=20u32 {
            let calls = Cell::new(0u32);
            let error = zucchini_pure::apply_with_cancel(&old, &patch, size, || {
                calls.set(calls.get() + 1);
                calls.get() >= threshold
            })
            .unwrap_err();
            assert_eq!(
                error.status(),
                Status::Cancelled,
                "{patch_name} threshold {threshold} lost cancellation: {error}"
            );
        }
    }
}

/// A declared stream length larger than the patch must be rejected during
/// parsing without attempting the allocation.
#[test]
fn pure_rust_rejects_absurd_declared_stream_length() {
    let old = b"ABCD";
    let new = b"ABCDE";
    let mut patch = Vec::new();
    patch.extend_from_slice(b"Zucc");
    patch.extend_from_slice(&1u16.to_le_bytes());
    patch.extend_from_slice(&0u16.to_le_bytes());
    patch.extend_from_slice(&(old.len() as u32).to_le_bytes());
    patch.extend_from_slice(&crc32(old).to_le_bytes());
    patch.extend_from_slice(&(new.len() as u32).to_le_bytes());
    patch.extend_from_slice(&crc32(new).to_le_bytes());
    patch.extend_from_slice(&1u32.to_le_bytes());

    patch.extend_from_slice(&0u32.to_le_bytes());
    patch.extend_from_slice(&(old.len() as u32).to_le_bytes());
    patch.extend_from_slice(&0u32.to_le_bytes());
    patch.extend_from_slice(&(new.len() as u32).to_le_bytes());
    patch.extend_from_slice(&u32::from_le_bytes(*b"NoOp").to_le_bytes());
    patch.extend_from_slice(&1u16.to_le_bytes());

    patch.extend_from_slice(&1u32.to_le_bytes());
    patch.push(0); // src_skip
    patch.extend_from_slice(&1u32.to_le_bytes());
    patch.push(0); // dst_skip
    // copy_count claims 4 GiB while the patch ends here.
    patch.extend_from_slice(&u32::MAX.to_le_bytes());

    let error = zucchini_pure::apply(old, &patch, new.len()).unwrap_err();
    assert_eq!(error.status(), Status::InvalidPatch);
}

#[test]
fn pure_rust_rejects_absurd_pool_count() {
    let old = b"ABCD";
    let new = b"ABCDE";
    let mut patch = build_noop_patch(old, new, &[]);
    let len = patch.len();
    patch[len - 4..].copy_from_slice(&u32::MAX.to_le_bytes());
    let error = zucchini_pure::apply(old, &patch, new.len()).unwrap_err();
    assert_eq!(error.status(), Status::InvalidPatch);
}

#[test]
fn pure_rust_rejects_absurd_element_count() {
    let old = b"ABCD";
    let new = b"ABCDE";
    let mut patch = build_noop_patch(old, new, &[]);
    patch[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
    let error = zucchini_pure::apply(old, &patch, new.len()).unwrap_err();
    assert_eq!(error.status(), Status::InvalidPatch);
}

/// Real-world differential case (AndroidX annotation-jvm 1.8.1 -> 1.10.0).
/// It requires both the canonical Dalvik opcode-family mapping and the
/// libstdc++ `std::sort` tie ordering in the equivalence-map pruning.
#[test]
fn pure_rust_applies_realistic_dex_differential_fixture() {
    assert_fixture("annotation-jvm", ".dex");
}
