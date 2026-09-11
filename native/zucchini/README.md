# Zucchini native boundary

This directory contains the audited apply-only closure used by `otadump` on Linux x86_64.
It does not contain either complete upstream repository, patch generators, command-line tools, tests, binaries, or object files.

## Source pins

- AOSP `external/zucchini`: `e256025d9d9c906caba814fd7b99a311ac8b8ec1`
- AOSP `external/libchrome`: `0aba0dccfcd93d8303678a4beb61594f7582c73c`

`SOURCE_INVENTORY.sha256` lists every vendored file and its digest.
The apply closure contains these upstream Zucchini translation units:

```text
abs32_utils.cc
address_translator.cc
arm_utils.cc
buffer_source.cc
crc32.cc
disassembler.cc
disassembler_dex.cc
disassembler_elf.cc
disassembler_no_op.cc
element_detection.cc
equivalence_map.cc
patch_reader.cc
rel32_finder.cc
rel32_utils.cc
reloc_elf.cc
target_pool.cc
zucchini_apply.cc
```

It contains these upstream libchrome translation units:

```text
base/at_exit.cc
base/callback_internal.cc
base/debug/activity_tracker.cc
base/debug/alias.cc
base/debug/debugger_posix.cc
base/debug/stack_trace.cc
base/debug/stack_trace_posix.cc
base/lazy_instance_helpers.cc
base/location.cc
base/logging.cc
base/metrics/persistent_memory_allocator.cc
base/strings/string_piece.cc
base/strings/stringprintf.cc
base/strings/string_util.cc
base/synchronization/lock_impl_posix.cc
base/threading/platform_thread_posix.cc
base/threading/thread_local_storage.cc
base/time/time.cc
base/time/time_now_posix.cc
```

Headers in the inventory are the compiler-reported transitive header closure for these units and the FFI wrapper.

## Build configuration

`build.rs` uses `cc` with the audited release configuration:

```text
-std=c++17 -O2 -DNDEBUG -DOFFICIAL_BUILD -D__ANDROID_HOST__
-DDONT_EMBED_BUILD_METADATA -ffunction-sections -fdata-sections
-fno-exceptions -fno-rtti
```

The generated `include/components/zucchini/buildflags.h` is copied from the pinned Android build.
It enables DEX and ELF and disables Win32 and ZTF.
`include/gtest/gtest_prod.h` is a declaration-only generated-header substitute used by the proof.
The build links the native C++ and GCC support archives statically.
Rust's Linux GNU target still links its baseline `libgcc_s.so.1`, as an empty Rust binary does, and retains dynamic glibc.

## Local boundary code

`src/zucchini_ffi.cc` and `src/zucchini_ffi.h` started as the project-owned Milestone 5a proof boundary.
The local copy changes the exported prefix from `zucchini_proof` to `otadump_zucchini`.
It also extends the audited DEX preflight to allow more than 65,536 strings.
The extension resolves each reference delta without writing and rejects any `const-string` 16-bit writer target above index 65,535 before upstream apply can reach its checked narrowing cast.
The 32-bit and jumbo writers retain the full DEX string range.

## License notices

The Zucchini sources use the BSD-style license in `vendor/zucchini/LICENSE` and retain `vendor/zucchini/MODULE_LICENSE_CHROME`.
The libchrome sources retain `vendor/libchrome/NOTICE` and `vendor/libchrome/MODULE_LICENSE_BSD`.
The copied ICU declarations retain `vendor/libchrome/base/third_party/icu/LICENSE`.
The copied NSPR declarations retain their tri-license notice in `vendor/libchrome/base/third_party/nspr/LICENSE` and the canonical full MPL 1.1 text in `vendor/libchrome/base/third_party/nspr/MPL-1.1.txt`.
