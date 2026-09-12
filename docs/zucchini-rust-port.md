# Pure-Rust Zucchini apply port

Status: prototype, verified byte-exact against every committed Zucchini fixture.
Scope: **apply only**, Android delta OTA element formats (`NoOp`, ELF
x86/x86-64/AArch32/AArch64, DEX).

## Motivation

The current PR vendors AOSP `external/zucchini` plus `external/libchrome` and
compiles them from `build.rs` (`src/zucchini.rs` calls the
`otadump_zucchini_apply` C ABI). That boundary is large: ~5,200 lines of
disassembler/generator C++ and a vendored libchrome slice. otadump only ever
*applies* patches, so almost all of that surface is unnecessary.

This port reimplements the apply path in safe Rust under
`src/zucchini_pure/`, with no C++ and no libchrome.

## What is implemented

| Area | Source ported | File |
| --- | --- | --- |
| Ensemble patch format, varints, stream validation | `patch_reader.{h,cc}`, `patch_utils.h` | `patch.rs` |
| CRC-32 | `crc32.cc` | `crc32.rs` |
| Equivalence/extra-data/raw-delta/reference correction, `OffsetMapper`, `TargetPool` | `zucchini_apply.cc`, `equivalence_map.cc`, `target_pool.cc` | `engine.rs` |
| NoOp element | `disassembler_no_op.cc` | `engine.rs` |
| ELF parse, address translation, reloc/abs32, Intel + ARM rel32 finders | `disassembler_elf.cc`, `address_translator.cc`, `reloc_elf.cc`, `abs32_utils.cc`, `rel32_utils.cc`, `rel32_finder.cc` | `elf.rs` |
| AArch32/AArch64 and THUMB2 instruction codecs | `arm_utils.cc` | `arm.rs` |
| DEX header/map/code-item/item-list parsing and all 42 reference groups | `disassembler_dex.cc`, `type_dex.h` | `dex.rs` |
| Little-endian helpers and bit fields | `buffer_view.h`, `algorithm.h` | `bytes.rs` |

The `Disassembler` trait in `mod.rs` is the only abstraction the engine needs:
size, reference groups, ranged reads, and single-reference writes. Both ELF and
DEX implement it; `make_disassembler` rejects non-Android formats
(`UnsupportedElement`), matching the native FFI allow-list.

## Verification

`tests/zucchini_pure.rs` replays the committed fixtures byte-for-byte:

- `noop.zuc` → `noop-new.bin`
- `elf-x86.zuc`, `elf.zuc`, `elf-arm32.zuc`, `elf-arm64.zuc`
- `dex.zuc`, `dex-large.zuc` (65,537 strings, 16-bit and 32-bit code refs)

Negative cases check that garbage and truncated patches return
`Status::InvalidPatch` and a mismatched output size returns
`Status::WrongOutputSize`.

Run with:

```sh
cargo test --test zucchini_pure
```

The fixtures were already portable; no new goldens were required. This makes an
incremental landing possible: each format/architecture can be merged and
validated independently.

## Fixture coverage caveat

The fixtures exercise only a subset of each format's reference types (for
example `elf-x86`/`elf` only hit rel32, `elf-arm32` only A24, `elf-arm64` only
Immd26). Passing them is necessary but not sufficient. This port implements
every reference type the native disassemblers emit, so it is deliberately
broader than the fixtures.

## Blockers and the smallest C++ boundary

A complete apply rewrite is realistic. The remaining gaps are small and
well-delimited:

1. **Android preflight hardening (the only real semantic gap).**
   `native/zucchini/src/zucchini_ffi.cc` layers three validations on top of
   upstream `ApplyBuffer` that upstream Zucchini does not have:
   - `ValidateReferenceBoundaries` — no reference/writer body may straddle an
     equivalence boundary.
   - `ValidateDexWriterWidths` — `type_id`/`proto_id`/`field_id`/`method_id`/
     `call_site_id`/`method_handle` lists must fit a 16-bit writer.
   - `ValidateDexReferenceTargets` — 16-bit `const-string` references must
     resolve to string ids that fit in 16 bits.
   These reject otherwise byte-valid patches (the `dex-large-unsafe16.zuc`
   fixture). The pure port currently surfaces that case as a new-image CRC
   mismatch (`ApplyError`), not as `"android executable preflight failed"`.
   This is Android policy, not format math, so it must be ported deliberately
   with dedicated tests.

2. **Smallest C++ boundary.** Because the three validators above call the
   vendored C++ disassemblers, *keeping any of them in C++ keeps the entire
   zucchini + libchrome stack*. There is no useful smaller C++ subset. The two
   coherent options are therefore:
   - *Strict native parity now*: keep the existing C++ boundary unchanged.
   - *Pure-Rust target*: port the three validators (≈250–350 lines) on top of
     the existing Rust readers/writers. After that the C++ boundary for
     apply-only builds is **zero** — `build.rs`, `native/`, `libchrome`, and
     the `cc` build dependency can be removed for the apply path.

3. **Non-Android formats (Win32, ZTF).** Not emitted by Android payloads and
   intentionally rejected. Porting them would only matter for non-Android use.

4. **Performance parity.** The C++ readers are lazy state machines; the Rust
   `read` recomputes each group's references per range query, so DEX apply is
   `O(groups × equivalences × items)`. Correct but slower on real partitions.
   Before production cutover, cache each group's full reference list once per
   parsed image (the engine already asks for it once per pool).

5. **Wiring.** `zucchini_pure` is exposed alongside `zucchini::apply` rather
   than replacing it, so the native path and tests remain intact. The final
   step is to route `zucchini::apply` to the pure implementation and drop the
   `otadump_zucchini` cfg/build once items 1 and 4 are addressed.

## Reproducing the measurement

The mini C++ diagnostic used to confirm which reference types each fixture
touches lives outside the repo; the equivalent information is available from
`tests/fixtures/zucchini/README.md` and the group tables in `dex.rs`/`elf.rs`.
