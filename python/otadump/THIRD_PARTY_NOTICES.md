# Third-party notices for the incremental backend

The optional incremental path downloads the static Linux x86-64
`ota_extractor` recorded in `_artifact_lock.json`. It is redistributed by
LineageOS at the immutable, unsigned commit linked below; the SHA-256 in that
file, rather than a commit signature, is the binary trust anchor.

- Binary and provenance: https://github.com/LineageOS/android_prebuilts_extract-tools/tree/a8aabbbe42bdecba4c6d1a9e6e71fbc47de59f96
- Upstream extractor source: https://android.googlesource.com/platform/system/update_engine/+/refs/heads/main/aosp/ota_extractor.cc
- Apache License 2.0 text used by AOSP components: https://www.apache.org/licenses/LICENSE-2.0.txt

The static binary contains the following components. Each source link also
contains the linked license or notice text. These notices apply to the
downloaded executable, not to otadump's MIT-licensed source.

| Component | Source | License text / notice |
| --- | --- | --- |
| LineageOS ota_extractor changes | https://github.com/LineageOS/android_system_update_engine | https://github.com/LineageOS/android_system_update_engine/blob/lineage-23.2/NOTICE |
| AOSP update_engine | https://android.googlesource.com/platform/system/update_engine/ | https://android.googlesource.com/platform/system/update_engine/+/refs/heads/main/NOTICE |
| Android libbase | https://android.googlesource.com/platform/system/libbase/ | https://android.googlesource.com/platform/system/libbase/+/refs/heads/main/NOTICE |
| Android core/cpu features and extras | https://android.googlesource.com/platform/system/core/ | https://android.googlesource.com/platform/system/core/+/refs/heads/main/NOTICE |
| Abseil C++ | https://android.googlesource.com/platform/external/abseil-cpp/ | https://android.googlesource.com/platform/external/abseil-cpp/+/refs/heads/main/LICENSE |
| BoringSSL | https://android.googlesource.com/platform/external/boringssl/ | https://android.googlesource.com/platform/external/boringssl/+/refs/heads/main/LICENSE |
| bsdiff | https://android.googlesource.com/platform/external/bsdiff/ | https://android.googlesource.com/platform/external/bsdiff/+/refs/heads/main/LICENSE |
| Brotli | https://android.googlesource.com/platform/external/brotli/ | https://android.googlesource.com/platform/external/brotli/+/refs/heads/main/LICENSE |
| bzip2 | https://android.googlesource.com/platform/external/bzip2/ | https://android.googlesource.com/platform/external/bzip2/+/refs/heads/main/LICENSE |
| gflags | https://android.googlesource.com/platform/external/gflags/ | https://android.googlesource.com/platform/external/gflags/+/refs/heads/main/COPYING.txt |
| libchrome | https://android.googlesource.com/platform/external/libchrome/ | https://android.googlesource.com/platform/external/libchrome/+/refs/heads/main/LICENSE |
| Protocol Buffers | https://android.googlesource.com/platform/external/protobuf/ | https://android.googlesource.com/platform/external/protobuf/+/refs/heads/main/LICENSE |
| Puffin | https://android.googlesource.com/platform/external/puffin/ | https://android.googlesource.com/platform/external/puffin/+/refs/heads/main/LICENSE |
| XZ Embedded | https://android.googlesource.com/platform/external/xz-embedded/ | https://android.googlesource.com/platform/external/xz-embedded/+/refs/heads/main/COPYING (0BSD) |
| Zucchini | https://android.googlesource.com/platform/external/zucchini/ | https://android.googlesource.com/platform/external/zucchini/+/refs/heads/main/LICENSE |
| glibc | https://sourceware.org/git/glibc.git | https://sourceware.org/git/?p=glibc.git;a=blob;f=COPYING.LIB;hb=HEAD (LGPL-2.1-or-later) |
| Android libfec | https://android.googlesource.com/platform/external/fec/ | https://android.googlesource.com/platform/external/fec/+/refs/heads/main/NOTICE (LGPL-2.1) |
| GCC runtime libraries | https://gcc.gnu.org/git/gcc.git | https://gcc.gnu.org/onlinedocs/libstdc++/manual/license.html (GPL-3.0 with GCC Runtime Library Exception) |
| LLVM libc++ | https://github.com/llvm/llvm-project/tree/main/libcxx | https://github.com/llvm/llvm-project/blob/main/libcxx/LICENSE.TXT (Apache-2.0 WITH LLVM-exception) |

The linked license texts cover Apache-2.0, BSD-3-Clause, MIT, ISC, the GCC and
LLVM runtime exceptions, LGPL-2.1-or-later, 0BSD, and component-specific
BoringSSL and bzip2 terms. otadump does not bundle or redistribute the ELF;
it downloads the SHA-pinned LineageOS copy at runtime. In particular, no claim
is made that static LGPL relinking obligations for glibc or libfec have been
satisfied by the Python package. This notice file is included in both wheels
and source distributions.
