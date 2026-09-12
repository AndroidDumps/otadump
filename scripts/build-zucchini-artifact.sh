#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=${OTADUMP_NATIVE_OUT:-$root/.native-cache/zucchini/x86_64-linux-gnu}
source_dir=${OTADUMP_ZUCCHINI_SOURCE_DIR:-}
commit=e256025d9d9c906caba814fd7b99a311ac8b8ec1
cache=${OTADUMP_ZUCCHINI_CACHE:-$root/.native-cache/src/$commit}
builder_image=${OTADUMP_ZUCCHINI_BUILDER_IMAGE:-quay.io/pypa/manylinux2014_x86_64@sha256:493d2032114d757aaa761a9385ad8497f391503bf71acef9abeeb66682ca5d90}
[[ "$(uname -s):$(uname -m)" == Linux:x86_64 ]] || { echo 'Linux x86_64 only' >&2; exit 2; }
if [[ -z "$source_dir" ]]; then
  source_dir="$cache/native/zucchini"
  if [[ ! -d "$source_dir/vendor/zucchini" ]]; then
    if [[ -n "${OTADUMP_ZUCCHINI_OFFLINE:-}" ]]; then
      echo "offline Zucchini build requested but verified source cache is absent: $source_dir" >&2
      exit 2
    fi
    mkdir -p "$cache"
    curl --fail --location --retry 3 -o "$cache/aosp-zucchini.tar.gz" "https://android.googlesource.com/platform/external/zucchini/+archive/$commit.tar.gz"
    mkdir -p "$cache/native/zucchini/vendor"
    # Gitiles archives contain the selected tree itself, not a top-level
    # directory. Extract directly into the locked vendor root.
    mkdir -p "$source_dir/vendor/zucchini"
    tar -xzf "$cache/aosp-zucchini.tar.gz" -C "$source_dir/vendor/zucchini"
  fi
fi
[[ -d "$source_dir/vendor/zucchini" ]] || { echo "invalid source dir: $source_dir" >&2; exit 2; }
(cd "$source_dir" && sha256sum -c "$root/native/zucchini/SOURCE_LOCK.sha256" --strict)
rm -rf "$out"; mkdir -p "$out/lib" "$out/include" "$out/licenses"
tmp=$(mktemp -d "$out/.build.XXXXXX"); trap 'rm -rf "$tmp"' EXIT
flags=(-std=c++17 -O2 -DNDEBUG -DOFFICIAL_BUILD -D__ANDROID_HOST__ -DDONT_EMBED_BUILD_METADATA -ffunction-sections -fdata-sections -fno-exceptions -fno-rtti -fPIC -fvisibility=hidden -ffile-prefix-map="$root"=/src/otadump -fmacro-prefix-map="$root"=/src/otadump -ffile-prefix-map="$source_dir"=/src/zucchini -fmacro-prefix-map="$source_dir"=/src/zucchini)
includes=(-I"$root/native/zucchini/shim" -I"$root/native/zucchini/include" -I"$source_dir/vendor/zucchini/aosp/include" -I"$source_dir/vendor/zucchini/aosp/include/components" -I"$root/native/zucchini/src")
sources=(abs32_utils.cc address_translator.cc arm_utils.cc buffer_source.cc crc32.cc disassembler.cc disassembler_dex.cc disassembler_elf.cc disassembler_no_op.cc element_detection.cc equivalence_map.cc patch_reader.cc rel32_finder.cc rel32_utils.cc reloc_elf.cc target_pool.cc zucchini_apply.cc)
locked_sources=($(awk '/vendor\/zucchini\/.*\.cc$/{sub("./vendor/zucchini/", ""); print $2}' "$root/native/zucchini/SOURCE_LOCK.sha256" | sort))
selected_sources=($(printf '%s\n' "${sources[@]}" | sort))
[[ "${locked_sources[*]}" == "${selected_sources[*]}" ]] || { echo 'selected Zucchini source manifest does not match SOURCE_LOCK.sha256' >&2; exit 2; }
for name in "${sources[@]}"; do
  source="$source_dir/vendor/zucchini/$name"
  [[ -f "$source" ]] || { echo "missing selected Zucchini source: $source" >&2; exit 2; }
  g++ "${flags[@]}" "${includes[@]}" -c "$source" -o "$tmp/$name.o"
done
for source in "$root/native/zucchini/src/zucchini_ffi.cc"; do
  g++ "${flags[@]}" "${includes[@]}" -c "$source" -o "$tmp/$(basename "$source").o"
done
ar Drcs "$out/lib/libotadump_zucchini.a" "$tmp"/abs32_utils.cc.o "$tmp"/address_translator.cc.o "$tmp"/arm_utils.cc.o "$tmp"/buffer_source.cc.o "$tmp"/crc32.cc.o "$tmp"/disassembler.cc.o "$tmp"/disassembler_dex.cc.o "$tmp"/disassembler_elf.cc.o "$tmp"/disassembler_no_op.cc.o "$tmp"/element_detection.cc.o "$tmp"/equivalence_map.cc.o "$tmp"/patch_reader.cc.o "$tmp"/rel32_finder.cc.o "$tmp"/rel32_utils.cc.o "$tmp"/reloc_elf.cc.o "$tmp"/target_pool.cc.o "$tmp"/zucchini_apply.cc.o "$tmp"/zucchini_ffi.cc.o
cp "$root/native/zucchini/src/zucchini_ffi.h" "$out/include/"
cp "$source_dir/vendor/zucchini/LICENSE" "$out/licenses/LICENSE.zucchini"
printf 'aosp_commit=%s\nsource_lock_sha256=%s\nbuilder_image=%s\ncompiler=%s\narchiver=%s\ntu_count=%s\n' \
  "$commit" \
  "$(sha256sum "$root/native/zucchini/SOURCE_LOCK.sha256" | awk '{print $1}')" \
  "$builder_image" \
  "$(g++ --version | head -1)" \
  "$(ar --version | head -1)" \
  "${#sources[@]}" > "$out/provenance.txt"
(cd "$out" && sha256sum lib/libotadump_zucchini.a include/zucchini_ffi.h licenses/LICENSE.zucchini provenance.txt > SHA256SUMS)
echo "built verified artifact: $out"
