# otadump

`otadump` is a small Python interface to LineageOS's static `ota_extractor`.
It supports full and incremental Android OTA payloads without maintaining a
separate delta implementation.

The package supports Linux x86_64 only. On first use it downloads the pinned
static executable and verifies its exact size and SHA-256 against
`otadump/_artifact_lock.json` before execution. The URL and hash are isolated in
that lock file so the backend artifact can be replaced independently later.

## Installation

```sh
python -m pip install .
```

## Usage

```python
from pathlib import Path

import otadump

otadump.extract(
    Path("payload.bin"),
    Path("output"),
    source_dir=Path("old-images"),  # Required only for incremental OTAs.
    partitions=["boot", "system"],
)
```

`payload_file` may be a raw `payload.bin` or an OTA ZIP whose `payload.bin` is
stored without compression, as required by Android OTA packages. Set
`source_dir` to the old partition images when extracting an incremental OTA.

The pinned extractor does not support payload operations of type `DISCARD`.
Such payloads fail extraction with `OtaDumpError`; otadump does not pre-scan the
protobuf manifest because that would duplicate a payload parser in Python.

Extraction failures raise `otadump.OtaDumpError` with the native tool's error
output. Runtime files are cached under `$XDG_CACHE_HOME/otadump` (or
`~/.cache/otadump`). Set `OTADUMP_CACHE_DIR` to use another cache location.

## Provenance

The executable comes directly from LineageOS's prebuilt extract-tools
repository:

- Repository: `LineageOS/android_prebuilts_extract-tools`
- Signed commit: `f29fef8c620c67e680877126ca19fe0bc1b7038d`
- Commit provenance: statically compiled from AOSP tag `android-14.0.0_r17`
- Path: `linux-x86/bin/ota_extractor`
- SHA-256: `b417304695c671c003cec9747ff671ab0579979b2c374a0229346df4cadfd3d5`
- Size: 36,167,008 bytes

GitHub verifies the commit's PGP signature. The downloaded ELF is statically
linked, so no LineageOS or AOSP shared-library bundle is installed.
