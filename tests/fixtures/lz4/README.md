# Frozen Milestone 6a fixtures

These files contain only the raw and expected block bytes needed by the Milestone 6b1 Rust boundary tests.
They were extracted without transformation from the frozen Milestone 6a fixtures produced under the BSD-2-Clause license in `LICENSE`.

The source proof pins AOSP `platform/external/lz4` commit `734e07032602e9a72fcc9701028b0aee45147fcd` and AOSP `platform/system/update_engine` commit `dc84c2552b2d4cf00d2a843cb1c091d99d0499f1`.

| Case | Raw bytes | Stored bytes | Algorithm | Level | Layout |
| --- | ---: | ---: | --- | ---: | --- |
| `lz4-no-postfix` | 1024 | 768 | LZ4 | implicit acceleration 1 | trailing zero padding |
| `lz4hc9-no-postfix` | 1536 | 1152 | LZ4HC | 9 | trailing zero padding |
| `zero-padding-layout` | 800 | 608 | LZ4 | implicit acceleration 1 | 32 raw bytes, then 576 stored bytes with leading zero padding |

Run `sha256sum -c SHA256SUMS` from this directory to verify every fixture file.
