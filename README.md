# otadump

`otadump` is a small Python interface to AOSP's `ota_extractor`. It supports
full and incremental Android OTA payloads without maintaining a separate delta
implementation.

The package supports Linux x86_64. On first use it downloads a pinned runtime
bundle containing unmodified files from the official Android 17
`android17-release` otatools build 14524720. The bundle and every extracted
file are verified against `otadump/_artifact_lock.json` before execution.

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
`single_thread=True` to request AOSP's serial extraction mode.

Extraction failures raise `otadump.OtaDumpError` with the native tool's error
output. Runtime files are cached under `$XDG_CACHE_HOME/otadump` (or
`~/.cache/otadump`). Set `OTADUMP_CACHE_DIR` to use another cache location.

## Provenance

The runtime is derived from AOSP's official artifact:

- Build: `android17-release` build `14524720`
- Source tag: `android-17.0.0_r1`
- `system/update_engine`: `4591637f51644f5429f9e2fe589ab22b92f61842`
- Upstream SHA-256: `4f8da78667e4bbc49fb993d4d6dca52d09e7cf6ed9fc9a62ebad2647d2dc454c`

The reproducible subset builder is `scripts/build-artifact.py`. It only copies
the extractor and its runtime shared-library closure; it does not compile or
modify AOSP code.
