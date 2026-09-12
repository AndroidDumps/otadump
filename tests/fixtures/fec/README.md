# dm-verity FEC fixtures

These parity extents verify Android 17 dm-verity FEC generation.
They use the Apache-2.0 license in `LICENSE`.

`fec-one-block.bin` is the `FECTest` vector from AOSP `system/update_engine` commit `4591637f51644f5429f9e2fe589ab22b92f61842`.
Its input is one 4,096-byte block filled with `0x01`, with two FEC roots.
The output alternates `0x8e, 0x8f` for 8,192 bytes.

`fec-300-block.bin` is a multi-round reference vector generated with AOSP `external/fec` commit `90857deb7973c0ca24c79b9c1809fc9667f32c4f`.
Input byte `i` in block `b` is `(i * 37 + b * 53 + 13) mod 256`, so each block and interleaved round differ.
The reference generator calls `init_rs_char(8, 0x11d, 0, 1, 2, 0)` and `encode_rs_char` with the interleaving from Android 17 `VerityWriterAndroid::EncodeFEC`.
Only the generated parity bytes are included; no LGPL source is distributed.

Run `sha256sum -c SHA256SUMS` from this directory.
