# Prebuilt Native Artifact

This directory is the immutable trust root consumed by the runtime branch.

- `zucchini-linux-x86_64-gnu.tar.gz` is a deterministic archive containing the
  static library, public header, license, provenance, and extracted checksums.
- `zucchini-linux-x86_64-gnu.tar.gz.sha256` pins the archive itself.
- `LOCK.json` captures the expected digest and source/build pins.

Archive layout:

- `linux-x86_64-gnu/lib/libotadump_zucchini.a`
- `linux-x86_64-gnu/include/zucchini_ffi.h`
- `linux-x86_64-gnu/licenses/LICENSE.zucchini`
- `linux-x86_64-gnu/provenance.txt`
- `linux-x86_64-gnu/SHA256SUMS`
