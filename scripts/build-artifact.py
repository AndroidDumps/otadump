#!/usr/bin/env python3
"""Build the locked runtime subset from the official AOSP otatools archive."""

import hashlib
import json
import sys
import urllib.request
import zipfile
from pathlib import Path

UPSTREAM_URL = "https://ci.android.com/builds/submitted/14524720/android17-release/latest/otatools.zip"
UPSTREAM_SHA256 = "4f8da78667e4bbc49fb993d4d6dca52d09e7cf6ed9fc9a62ebad2647d2dc454c"
FILES = (
    "bin/ota_extractor",
    "lib64/libbase.so",
    "lib64/libbrillo.so",
    "lib64/libbrillo-stream.so",
    "lib64/libchrome.so",
    "lib64/libcrypto-host.so",
    "lib64/libcrypto_utils.so",
    "lib64/libc++.so",
    "lib64/libcutils.so",
    "lib64/libevent-host.so",
    "lib64/libext4_utils.so",
    "lib64/libfec.so",
    "lib64/liblog.so",
    "lib64/liblz4.so",
    "lib64/libprotobuf-cpp-lite.so",
    "lib64/libsquashfs_utils.so",
    "lib64/libssl-host.so",
    "lib64/libz-host.so",
    "lib64/libziparchive.so",
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def main() -> None:
    output = Path(sys.argv[1] if len(sys.argv) > 1 else "aosp-ota-extractor-14524720.zip")
    source = Path(sys.argv[2] if len(sys.argv) > 2 else "otatools-14524720.zip")
    if not source.exists():
        urllib.request.urlretrieve(UPSTREAM_URL, source)
    if file_digest(source) != UPSTREAM_SHA256:
        raise SystemExit("upstream otatools checksum mismatch")

    hashes = {}
    with zipfile.ZipFile(source) as upstream, zipfile.ZipFile(
        output, "w", compression=zipfile.ZIP_STORED
    ) as bundle:
        for name in FILES:
            data = upstream.read(name)
            hashes[name] = digest(data)
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (0o755 if name == "bin/ota_extractor" else 0o644) << 16
            bundle.writestr(info, data)

    print(json.dumps(hashes, indent=2, sort_keys=True))
    print(f"bundle_sha256={file_digest(output)}")


if __name__ == "__main__":
    main()
