# Puffin fixtures

These fixtures come from ChromiumOS Puffin commit `343e23db1b4d81045e91a10244244893f5acd73b`.
The source files are `src/unittest_common.cc` and `src/patching_unittest.cc`.

- `deflates-sample1.bin` is `kDeflatesSample1`.
- `deflates-sample2.bin` is `kDeflatesSample2`.
- `patch-1-to-2.puf` is `kPatch1To2`.
- `patch-1-to-2-zucchini.puf` reconstructs `deflates-sample2.bin` from `deflates-sample1.bin` through three actual deflate streams on each side.
- `patch-1-to-raw.puf` is `kPatch1ToNoDeflate`.
- `raw-11-22-33-44.bin` is the expected output declared by `Patching1ToNoDeflateTest`.

The files retain Puffin's BSD-3-Clause license in `LICENSE` and Zucchini's BSD-3-Clause license in `LICENSE.zucchini`.
Verify them with `sha256sum -c SHA256SUMS` from this directory.

The Zucchini fixture uses Puffin at the commit above and AOSP Zucchini at `e256025d9d9c906caba814fd7b99a311ac8b8ec1`.
Build the pinned AOSP host `puffin` target with the pinned Zucchini source.
Generate and independently apply the PUF1 bytes with the upstream tool:

```sh
PUFFIN=/path/to/aosp/out/host/linux-x86/bin/puffin
"$PUFFIN" \
  --operation=puffdiff \
  --src_file=deflates-sample1.bin \
  --dst_file=deflates-sample2.bin \
  --patch_file=patch-1-to-2-zucchini.puf \
  --src_file_type=raw \
  --dst_file_type=raw \
  --src_deflates_bit=16:50,80:10,96:18 \
  --dst_deflates_bit=0:50,72:80,152:18 \
  --patch_algorithm=1
"$PUFFIN" \
  --operation=puffpatch \
  --src_file=deflates-sample1.bin \
  --dst_file=generated.bin \
  --patch_file=patch-1-to-2-zucchini.puf
cmp deflates-sample2.bin generated.bin
```
