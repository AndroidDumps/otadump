# Pure-Rust Zucchini apply port

Status: implemented and verified byte-exact against every committed Zucchini
fixture. This is now the only apply path; the vendored C++/libchrome build is
opt-in for differential testing.
Scope: **apply only**, Android delta OTA element formats (`NoOp`, ELF
x86/x86-64/AArch32/AArch64, DEX).

## Motivation

The original PR vendored AOSP `external/zucchini` plus `external/libchrome` and
compiled them from `build.rs` (`src/zucchini.rs` called the
`otadump_zucchini_apply` C ABI). otadump only ever *applies* patches, so almost
all of that surface was unnecessary. The apply path is now safe Rust under
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
| Android preflight hardening | `native/zucchini/src/zucchini_ffi.cc` | `engine.rs` |
| Little-endian helpers and bit fields | `buffer_view.h`, `algorithm.h` | `bytes.rs` |

`Disassembler` (in `mod.rs`) is the only abstraction the engine needs: size,
reference groups, ranged reads, and single-reference writes. ELF and DEX
implement it; `make_disassembler` rejects non-Android formats
(`UnsupportedElement`), matching the native FFI allow-list.

## Verification

`tests/zucchini_pure.rs` replays the committed fixtures byte-for-byte:

- `noop.zuc` → `noop-new.bin`
- `elf-x86.zuc`, `elf.zuc`, `elf-arm32.zuc`, `elf-arm64.zuc`
- `dex.zuc`, `dex-large.zuc` (65,537 strings, 16-bit and 32-bit code refs)

Negative/edge cases: garbage and truncated patches (`InvalidPatch`), a
mismatched output size (`WrongOutputSize`), a malformed trailing reference-delta
varint, cancellation, and `dex-large-unsafe16.zuc` (rejected by the ported
Android preflight with `"android executable preflight failed"`).

Unit regressions cover the DEX opcode table boundary, DEX payload bounds, the
THUMB2 instruction-size advance, and ELF64 program-header bounds.

The native `tests/delta_extraction.rs` suite (which exercises extraction through
`zucchini::apply`) now runs against the pure implementation. The full suite
passes with no C++ configured:

```sh
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

## Audit fixes applied

1. **Trailing reference-delta varints.** `Cursor::var_u32` no longer consumes
   bytes on decode failure (mirroring `DecodeVarUInt`/`ParseVarUInt`), and
   `apply_references_correction` now honors `reference_deltas_done` like native
   `ReferenceDeltaSource::Done()`.
2. **DEX opcode 0xFF.** The opcode-table range check widened to `u16`, so
   `0xFF + 1` no longer wraps to 0. `const-method-type` now parses and its proto
   reference is corrected.
3. **THUMB2 advancement.** The scanner returns the decoded instruction size (4
   for an unmatched 32-bit instruction) and the parser advances by it instead of
   always stepping 2; it also avoids fetching past the region.
4. **ELF64 program headers.** `p_offset`/`p_filesz` are summed and bounds-checked
   as `u64` before narrowing to `offset_t`, so 2^32 offsets cannot truncate into
   a small valid-looking segment.
5. **DEX payload offsets.** The payload bound is measured against remaining
   instruction units, not the whole code item.
6. **Preflight sizes.** The preflight checks both the old and new disassembler
   sizes.
7. **Checked DEX map sizing.** Map-array sizes use checked multiplication, and
   attacker-sized parser vectors use `try_reserve` instead of infallible
   `with_capacity`.
8. **DEX index read widths.** Index-based mappers derive their read width from
   the group's declared reference width (differential testing against native
   caught group 0; this also fixes the 32-bit annotations-directory ids in
   groups 19/22/23, which were being read as 16-bit).

## Cancellation and allocation

`apply()` keeps its signature. `apply_with_cancel(old, patch, size, cancelled)`
polls a `Fn() -> bool` between elements, pools, and equivalence units and returns
`Status::Cancelled`. `src/zucchini.rs` exposes the same hook. Parser allocations
derived from attacker-controlled counts use `try_reserve`.

## Intentional behavioural and size deltas

- **Stricter than upstream Zucchini by design.** The ported Android preflight
  (`ValidateReferenceBoundaries`, `ValidateDexWriterWidths`,
  `ValidateDexReferenceTargets`) rejects patches upstream would accept. This
  matches the AndroidDumps native FFI exactly; `dex-large-unsafe16.zuc` is the
  canonical case.
- **Message alignment.** An old-file failure reports
  `"android executable preflight failed"` and a final new-file mismatch reports
  `"zucchini apply failed"`, matching the native FFI's ordering.
- **Size.** The vendored C++ boundary is 2.4 MB of source (37 C/C++ files) and
  produces a 14,559,914-byte debug static archive including the libchrome slice.
  The pure-Rust module compiles to a 244,312-byte object (≈127 KB of text) at
  `-C opt-level=2`. The default `build.rs` now builds only protobuf and the
  small C lz4 library.

## Remaining work

1. **Performance parity.** The C++ readers are lazy state machines; the Rust
   `read` recomputes each group's references per range query, so DEX apply is
   `O(groups × equivalences × items)`. Correct but slower on real partitions.
   Cache each group's full reference list once per parsed image before
   production cutover.
2. **Differential testing.** Building the native path
   (`OTADUMP_NATIVE_ZUCCHINI=1 cargo test`) enables
   `native_and_pure_agree_on_all_fixtures`. That build currently fails to link in
   this environment on pre-existing libchrome symbols
   (`base::Histogram::FactoryGet` from `activity_tracker.cc`), unrelated to the
   Rust port; the default, pure build is unaffected.
3. **Non-Android formats (Win32, ZTF).** Not emitted by Android payloads and
   intentionally rejected.
