#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import sys
import tarfile
import tempfile
import urllib.request


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_sha256_lock(path: pathlib.Path) -> dict[str, str]:
    checksums = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        digest, relpath = line.split(maxsplit=1)
        checksums[relpath.strip()] = digest
    return checksums


def verify_tree(root: pathlib.Path, checksums: dict[str, str]) -> None:
    for relpath, expected in checksums.items():
        target = root / relpath
        if not target.is_file():
            raise RuntimeError(f"missing native artifact file: {target}")
        actual = sha256_file(target)
        if actual != expected:
            raise RuntimeError(
                f"native artifact checksum mismatch for {relpath}: expected {expected}, got {actual}"
            )


def safe_extract(archive: pathlib.Path, destination: pathlib.Path) -> None:
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            name = pathlib.PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts:
                raise RuntimeError(f"unsafe entry in native artifact archive: {member.name}")
            if member.issym() or member.islnk():
                raise RuntimeError(f"links are not allowed in native artifact archive: {member.name}")
            if not (member.isfile() or member.isdir()):
                raise RuntimeError(f"unsupported tar entry in native artifact archive: {member.name}")
        tar.extractall(destination)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle-lock", required=True)
    parser.add_argument("--checksum-lock", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--cache", required=True)
    args = parser.parse_args()

    bundle_lock = json.loads(pathlib.Path(args.bundle_lock).read_text(encoding="utf-8"))
    checksums = parse_sha256_lock(pathlib.Path(args.checksum_lock))
    out_dir = pathlib.Path(args.out)

    if out_dir.is_dir():
        verify_tree(out_dir, checksums)
        return 0

    cache_root = pathlib.Path(args.cache)
    cache_root.mkdir(parents=True, exist_ok=True)
    archive_path = cache_root / f"{bundle_lock['sha256']}.tar.gz"

    preseed = os.environ.get("OTADUMP_NATIVE_PRESEED")
    offline = os.environ.get("OTADUMP_NATIVE_OFFLINE")

    if preseed:
        preseed_path = pathlib.Path(preseed)
        if preseed_path.is_dir():
            verify_tree(preseed_path, checksums)
            out_dir.parent.mkdir(parents=True, exist_ok=True)
            if out_dir.exists():
                shutil.rmtree(out_dir)
            shutil.copytree(preseed_path, out_dir)
            return 0
        if not preseed_path.is_file():
            raise RuntimeError(f"OTADUMP_NATIVE_PRESEED path does not exist: {preseed_path}")
        shutil.copy2(preseed_path, archive_path)

    if not archive_path.is_file():
        if offline:
            raise RuntimeError(
                "offline native artifact mode is enabled but cache is empty; "
                "set OTADUMP_NATIVE_PRESEED or unset OTADUMP_NATIVE_OFFLINE"
            )
        with urllib.request.urlopen(bundle_lock["url"]) as response:
            with tempfile.NamedTemporaryFile(delete=False, dir=cache_root) as handle:
                handle.write(response.read())
                temp_name = handle.name
        pathlib.Path(temp_name).replace(archive_path)

    archive_digest = sha256_file(archive_path)
    if archive_digest != bundle_lock["sha256"]:
        raise RuntimeError(
            f"native artifact archive checksum mismatch: expected {bundle_lock['sha256']}, got {archive_digest}"
        )

    with tempfile.TemporaryDirectory(dir=cache_root) as temp:
        temp_root = pathlib.Path(temp)
        safe_extract(archive_path, temp_root)
        extracted = temp_root / bundle_lock["extract_root"]
        if not extracted.is_dir():
            raise RuntimeError(f"missing artifact root after extraction: {bundle_lock['extract_root']}")
        verify_tree(extracted, checksums)

        out_dir.parent.mkdir(parents=True, exist_ok=True)
        staging = out_dir.with_name(out_dir.name + ".tmp")
        if staging.exists():
            shutil.rmtree(staging)
        shutil.copytree(extracted, staging)
        os.replace(staging, out_dir)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"otadump native artifact fetch failed: {error}", file=sys.stderr)
        raise SystemExit(2)
