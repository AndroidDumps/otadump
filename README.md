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

# Apply a SOURCE_COPY, SOURCE_BSDIFF, BROTLI_BSDIFF, PUFFDIFF (inner BSDIFF or
# ZUCCHINI), standalone ZUCCHINI, or LZ4DIFF (inner BSDIFF or PUFFDIFF) delta
# payload with matching base images.
# ZUCCHINI requires Linux x86-64 GNU.
otadump delta.zip --output-dir output --source-dir source-images
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
    source_dir=Path("source-images"),
)
```

The optional keyword arguments are `num_threads`, `overwrite`, `partitions`, `verify`, and `source_dir`.
Set `source_dir` to a directory containing matching base partition images for supported delta operations.
Extraction generates declared dm-verity hash-tree and FEC extents before verifying each partition.
Extraction releases the Python GIL.

### Local release packages

Build the Linux x86-64 GNU CLI with `cargo build --profile release-cli --bin otadump --locked`
(`release-cli` adds `panic = "abort"` on top of `release`; the plain `release`
profile keeps unwinding so Python wheels can raise panics as exceptions).
Build the ABI3 Python wheel with `uv build --wheel`.
The wheel supports Python 3.9 and later and uses the build host's glibc baseline.
Build release packages on the oldest Linux environment that you support.
Release archives and wheels include the notices for vendored Puffin and LZ4 code.

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
