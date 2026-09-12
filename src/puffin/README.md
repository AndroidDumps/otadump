# Puffin-derived Rust code

This module adapts the pure-Rust Puffin implementation from `puffdiff` 0.1.0.
That crate ports ChromiumOS Puffin's parser, bit I/O, PuffData I/O, Huffman table, puffer, huffer, and whole-buffer stream code.

The reference Puffin revision is `343e23db1b4d81045e91a10244244893f5acd73b`.
The Rust code is restricted to PUF1 parsing and inner BSDIFF application.
It adds checked arithmetic, fallible allocations, operation size bounds, and cooperative cancellation for otadump.

The code is available under the BSD-3-Clause terms in `LICENSE`.
