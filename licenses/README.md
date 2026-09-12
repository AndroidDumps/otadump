# Third-party license notices

`LICENSE.lz4` is the BSD-2-Clause license of upstream liblz4, statically linked
into release binaries and wheels via the pinned
[`lz4-sys`](https://crates.io/crates/lz4-sys) `=1.11.1+lz4-1.10.0` crate.

That crate bundles the liblz4 1.10.0 C sources. The `lz4.c`, `lz4.h`,
`lz4hc.c`, and `lz4hc.h` files it compiles are byte-identical (SHA-256
verified) to the AOSP `platform/external/lz4` sources pinned at commit
`734e07032602e9a72fcc9701028b0aee45147fcd`, which Android `lz4diff` uses.
