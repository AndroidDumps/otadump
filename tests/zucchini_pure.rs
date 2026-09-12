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
