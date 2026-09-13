<!-- markdownlint-configure-file {
  "MD033": false,
  "MD041": false
} -->

<div align="center">

# otadump

[![crates.io][crates.io-badge]][crates.io]

**`otadump` helps you extract partitions from Android OTA files.** <br />
Partitions can be individually flashed to your device using `fastboot`.

Compared to other tools, `otadump` is significantly faster and handles file
verification - no fear of a bad OTA file bricking your device.

![Demo][demo]

</div>

## Features

|                              | [crazystylus/otadump] | [ssut/payload-dumper-go] | [vm03/payload_dumper]                     |
| ---------------------------- | --------------------- | ------------------------ | ----------------------------------------- |
| Input file verification      | ✔                     | ✔                        |                                           |
| Output file verification     | ✔                     |                          |                                           |
| Extract selective partitions | ✔                     | ✔                        | ✔                                         |
| Parallelized extraction      | ✔                     | ✔                        |                                           |
| Runs directly on .zip files  | ✔                     | ✔                        |                                           |
| Incremental OTA support      |                       |                          | [Partial][payload_dumper-incremental-ota] |

## Benchmarks

Comparing the time taken to extract all partitions from a few sample files
(lower is better):

![Benchmarks][benchmarks]

**Note:** `otadump` was run with args `--no-verify -c 12` and `payload-dumper-go` was run with args `-c 12`

System specifications:

- Processor: AMD Ryzen 5 5600X (12) @ 3.700GHz
- RAM: 16 GiB
- OS: Pop!_OS 22.04 / Linux 6.0.6
- SSD: Samsung 970 EVO 250GB

## Installation

### macOS / Linux

Install a pre-built binary:

```sh
curl -sS https://raw.githubusercontent.com/crazystylus/otadump/mainline/install.sh | bash
```

Otherwise, using Cargo:

```sh
# Needs LZMA, Protobuf and pkg-config libraries installed.
# - On macOS: brew install protobuf xz pkg-config
# - On Debian / Ubuntu: apt install liblzma-dev protobuf-compiler pkg-config
cargo install --locked otadump
```

### Windows

Download the pre-built binary from the [Releases] page. Extract it and run the
`otadump.exe` file.

## Usage

Run the following command in your terminal:

```sh
# Run directly on .zip file.
otadump ota.zip

# Run on payload.bin file.
otadump payload.bin
```

### Python

Build and install the native Python module with `pip` or
[maturin](https://www.maturin.rs/), then call `otadump.extract`:

```python
from pathlib import Path

import otadump

otadump.extract(
    Path("payload.bin"),
    Path("output"),
    partitions=["boot", "system"],
    overwrite=True,
)
```

The optional keyword arguments are `num_threads`, `overwrite`, `partitions`,
and `verify`. Extraction releases the Python GIL.

Incremental OTAs are supported on Linux x86_64 by passing `source_dir`, which
contains the old partition images. This additive path uses LineageOS's static,
partition-parallel `ota_extractor`; full OTAs and the CLI continue to use the
original Rust implementation. `timeout` limits the external extractor runtime.
Outputs are reconstructed in a staging directory and published only after the
process succeeds and every requested partition is present.

```python
otadump.extract(
    "incremental-ota.zip",
    "output",
    source_dir="old-images",
    partitions=["boot", "vendor_boot"],
    timeout=300,
)
```

The runtime is downloaded once into `$XDG_CACHE_HOME/otadump` (or
`~/.cache/otadump`) and locked during installation. Set `OTADUMP_CACHE_DIR` to
override that location.

### Incremental backend provenance

- Repository: `LineageOS/android_prebuilts_extract-tools`
- Commit: `a8aabbbe42bdecba4c6d1a9e6e71fbc47de59f96`
- Commit signature: unsigned (GitHub verification status)
- Path: `linux-x86/bin/ota_extractor`
- SHA-256: `7cf65d6c557cc6e761082e88aa225123d445be26dd1a18f618f87c142afaff8c`
- Size: 20,650,520 bytes

The immutable hash is the trust anchor despite the unsigned upstream commit.
This newer partition-parallel build was selected after the Pong incremental OTA
benchmark measured approximately 1.8x lower wall time and 12x lower peak RSS
than the in-process Rust delta implementation. See
`python/otadump/THIRD_PARTY_NOTICES.md` for linked-component notices.

## Contributors

- [Kartik Sharma][crazystylus]
- [Ajeet D'Souza][ajeetdsouza]

[ajeetdsouza]: https://github.com/ajeetdsouza
[benchmarks]: contrib/benchmarks.svg
[crates.io-badge]: https://img.shields.io/crates/v/otadump?logo=rust&logoColor=white&style=flat-square
[crates.io]: https://crates.io/crates/otadump
[crazystylus]: https://github.com/crazystylus
[crazystylus/otadump]: https://github.com/crazystylus/otadump
[demo]: contrib/demo.gif
[payload_dumper-incremental-ota]: https://github.com/vm03/payload_dumper/issues/53
[releases]: https://github.com/crazystylus/otadump/releases
[ssut/payload-dumper-go]: https://github.com/ssut/payload-dumper-go
[vm03/payload_dumper]: https://github.com/vm03/payload_dumper
