# Native Zucchini Builder Inputs

This directory contains the compile-once source and lock inputs used to produce
the pinned Linux x86_64 GNU static artifact in `native/artifacts/zucchini/`.

- `SOURCE_LOCK.sha256` pins the exact AOSP source closure and per-file hashes.
- The selected closure is exactly 17 upstream apply translation units plus
  project-owned `src/zucchini_ffi.cc` and `src/zucchini_ffi.h`.
- `shim/` and `include/` are project-owned compatibility headers.
- `ARTIFACT_LOCK.sha256` pins the extracted artifact contents.

Rebuild command:

```bash
OTADUMP_NATIVE_OUT=<output-dir> \
OTADUMP_ZUCCHINI_SOURCE_DIR=<verified-source-root> \
bash scripts/build-zucchini-artifact.sh
```

For reproducible CI builds, use the pinned manylinux image in
`BUILDER_LOCK.json` and keep the repository mounted at `/src/otadump`.
