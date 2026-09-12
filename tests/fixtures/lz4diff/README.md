# Frozen LZ4DIFF operation fixtures

These static fixtures exercise complete version-1 `LZ4DIFF` operation data.
Each case contains the physical source bytes, the independently frozen physical target bytes, and the complete container patch.

The LZ4, LZ4HC9, and zero-padding source and target bytes come unchanged from the Milestone 6a reference proof.
That proof pins AOSP `platform/external/lz4` commit `734e07032602e9a72fcc9701028b0aee45147fcd` and `platform/system/update_engine` commit `dc84c2552b2d4cf00d2a843cb1c091d99d0499f1`.
The postfix target starts from the frozen LZ4 reference block and changes byte 23 with XOR `0x5a` before patch generation.
The PUFFDIFF source, patch, and expected target come unchanged from ChromiumOS Puffin commit `343e23db1b4d81045e91a10244244893f5acd73b`.

The LZ4DIFF protobuf and framing follow the pinned Android update_engine `lz4diff.proto`, `lz4diff_format.h`, and `lz4diff.cc` sources.
The inner identity patches and the real postfix patch are frozen BSDIFF40 output from the reference BSDIFF algorithm in `bsdiff-android` 0.0.2.
Fixture generation is separate from the extractor implementation.
The extractor does not generate expected target bytes.

| Case | Inner type | Destination layout | Postfix |
| --- | --- | --- | --- |
| `lz4-bsdiff` | BSDIFF | LZ4, 1024 raw bytes in 768 physical bytes | None |
| `lz4hc9-bsdiff` | BSDIFF | LZ4HC level 9, 1536 raw bytes in 1152 physical bytes | None |
| `zero-padding-bsdiff` | BSDIFF | 32-byte raw block and leading-zero-padded LZ4 block | None |
| `postfix-bsdiff` | BSDIFF | LZ4 reference recompression | BSDIFF40 with SHA-256 guard |
| `raw-puffdiff` | PUFFDIFF | Uncompressed blocks | None |

The LZ4-derived bytes retain the BSD-2-Clause license in `LICENSE.lz4`.
The Puffin-derived bytes retain the BSD-3-Clause license in `LICENSE.puffin`.
Run `sha256sum -c SHA256SUMS` from this directory to verify every frozen file.
