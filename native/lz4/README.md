# AOSP LZ4 boundary

This directory vendors the LZ4 block operations used by Android `lz4diff`.
The files under `vendor/lib` come from AOSP `platform/external/lz4` commit `734e07032602e9a72fcc9701028b0aee45147fcd`.
They use the BSD-2-Clause license in `LICENSE`.

`src/lz4_ffi.c` and `src/lz4_ffi.h` are project-owned BSD-2-Clause files.
They provide a fixed C ABI for `LZ4_decompress_safe_partial`, `LZ4_compress_destSize`, and `LZ4_compress_HC_destSize`.
The HC wrapper owns and frees its native stream state.
No dictionary API is exposed.

`build.rs` compiles only the three pinned library source units and the local wrapper on Linux x86_64 GNU.
It uses C99, optimization level 3, `NDEBUG`, compiler warnings, and warnings as errors.
The resulting archive links statically into `otadump`.

Run `sha256sum -c SOURCE_INVENTORY.sha256` from this directory to verify the source inventory.
