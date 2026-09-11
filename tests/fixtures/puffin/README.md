# Puffin fixtures

These fixtures come from ChromiumOS Puffin commit `343e23db1b4d81045e91a10244244893f5acd73b`.
The source files are `src/unittest_common.cc` and `src/patching_unittest.cc`.

- `deflates-sample1.bin` is `kDeflatesSample1`.
- `deflates-sample2.bin` is `kDeflatesSample2`.
- `patch-1-to-2.puf` is `kPatch1To2`.
- `patch-1-to-raw.puf` is `kPatch1ToNoDeflate`.
- `raw-11-22-33-44.bin` is the expected output declared by `Patching1ToNoDeflateTest`.

The files retain Puffin's BSD-3-Clause license in `LICENSE`.
Verify them with `sha256sum -c SHA256SUMS` from this directory.
