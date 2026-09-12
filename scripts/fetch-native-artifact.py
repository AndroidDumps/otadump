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
import time
import urllib.request
import uuid
from urllib.parse import urlsplit


DOWNLOAD_TIMEOUT_SECONDS = 30
DOWNLOAD_MAX_BYTES = 256 * 1024 * 1024
LOCK_WAIT_SECONDS = 120
LOCK_POLL_SECONDS = 0.05


class FileLock:
    def __init__(self, path: pathlib.Path, timeout_seconds: float) -> None:
        self.path = path
        self.timeout_seconds = timeout_seconds
        self.fd = -1

    def __enter__(self) -> "FileLock":
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            try:
                self.fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(self.fd, f"{os.getpid()}\n".encode("ascii"))
                return self
            except FileExistsError:
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"timed out waiting for lock: {self.path}")
                time.sleep(LOCK_POLL_SECONDS)

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


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


def validate_bundle_url(url: str, commit: str) -> None:
    if len(commit) != 40 or any(ch not in "0123456789abcdef" for ch in commit):
        raise RuntimeError(f"bundle lock commit must be a lowercase 40-char hex SHA: {commit}")
    parsed = urlsplit(url)
    if parsed.scheme != "https":
        raise RuntimeError(f"native artifact URL must use HTTPS: {url}")
    if parsed.hostname != "raw.githubusercontent.com":
        raise RuntimeError(
            "native artifact URL host must be raw.githubusercontent.com: "
            f"{parsed.hostname or '<missing>'}"
        )
    if parsed.query or parsed.fragment:
        raise RuntimeError("native artifact URL must not include query parameters or fragments")
    expected_path = (
        f"/AndroidDumps/otadump/{commit}/native/artifacts/zucchini/"
        "zucchini-linux-x86_64-gnu.tar.gz"
    )
    if parsed.path != expected_path:
        raise RuntimeError(
            "native artifact URL path must match the immutable commit artifact path: "
            f"expected {expected_path}, got {parsed.path}"
        )


def verify_tree(root: pathlib.Path, checksums: dict[str, str]) -> None:
    expected_files = set(checksums)
    allowed_dirs = {"."}
    for relpath in checksums:
        parent = pathlib.PurePosixPath(relpath).parent
        while True:
            allowed_dirs.add(parent.as_posix())
            if parent == pathlib.PurePosixPath("."):
                break
            parent = parent.parent

    discovered_files = set()
    for candidate in root.rglob("*"):
        relpath = candidate.relative_to(root).as_posix()
        if candidate.is_symlink():
            raise RuntimeError(f"links are not allowed in native artifact tree: {relpath}")
        if candidate.is_dir():
            if relpath not in allowed_dirs:
                raise RuntimeError(f"unexpected native artifact directory: {relpath}")
            continue
        if not candidate.is_file():
            raise RuntimeError(f"unsupported native artifact entry type: {relpath}")
        if relpath not in expected_files:
            raise RuntimeError(f"unexpected native artifact file: {relpath}")
        discovered_files.add(relpath)

    missing = sorted(expected_files - discovered_files)
    if missing:
        raise RuntimeError(f"missing native artifact files: {', '.join(missing)}")

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


def download_archive(url: str, archive_path: pathlib.Path) -> None:
    with urllib.request.urlopen(url, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:
        header_length = response.headers.get("Content-Length")
        if header_length is not None:
            try:
                if int(header_length) > DOWNLOAD_MAX_BYTES:
                    raise RuntimeError(
                        "native artifact archive is too large: "
                        f"{header_length} bytes exceeds {DOWNLOAD_MAX_BYTES}"
                    )
            except ValueError:
                pass
        with tempfile.NamedTemporaryFile(delete=False, dir=archive_path.parent) as handle:
            total = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > DOWNLOAD_MAX_BYTES:
                    raise RuntimeError(
                        "native artifact archive is too large: "
                        f"streamed {total} bytes exceeds {DOWNLOAD_MAX_BYTES}"
                    )
                handle.write(chunk)
            temp_name = handle.name
    pathlib.Path(temp_name).replace(archive_path)


def publish_tree(source: pathlib.Path, out_dir: pathlib.Path, checksums: dict[str, str]) -> int:
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = out_dir.with_name(f"{out_dir.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}")
    if staging.exists():
        shutil.rmtree(staging)
    shutil.copytree(source, staging)
    try:
        os.replace(staging, out_dir)
    except OSError:
        if staging.exists():
            shutil.rmtree(staging)
        if out_dir.is_dir():
            verify_tree(out_dir, checksums)
            return 0
        raise
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle-lock", required=True)
    parser.add_argument("--checksum-lock", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--cache", required=True)
    args = parser.parse_args()

    bundle_lock = json.loads(pathlib.Path(args.bundle_lock).read_text(encoding="utf-8"))
    validate_bundle_url(bundle_lock["url"], bundle_lock["commit"])
    checksums = parse_sha256_lock(pathlib.Path(args.checksum_lock))
    out_dir = pathlib.Path(args.out)

    if out_dir.is_dir():
        verify_tree(out_dir, checksums)
        return 0

    cache_root = pathlib.Path(args.cache)
    cache_root.mkdir(parents=True, exist_ok=True)
    archive_path = cache_root / f"{bundle_lock['sha256']}.tar.gz"
    fetch_lock = cache_root / f".{bundle_lock['sha256']}.fetch.lock"

    preseed = os.environ.get("OTADUMP_NATIVE_PRESEED")
    offline = os.environ.get("OTADUMP_NATIVE_OFFLINE")

    if preseed:
        preseed_path = pathlib.Path(preseed)
        if preseed_path.is_dir():
            verify_tree(preseed_path, checksums)
            return publish_tree(preseed_path, out_dir, checksums)
        if not preseed_path.is_file():
            raise RuntimeError(f"OTADUMP_NATIVE_PRESEED path does not exist: {preseed_path}")

    with FileLock(fetch_lock, LOCK_WAIT_SECONDS):
        if preseed and pathlib.Path(preseed).is_file():
            shutil.copy2(pathlib.Path(preseed), archive_path)
        if not archive_path.is_file():
            if offline:
                raise RuntimeError(
                    "offline native artifact mode is enabled but cache is empty; "
                    "set OTADUMP_NATIVE_PRESEED or unset OTADUMP_NATIVE_OFFLINE"
                )
            download_archive(bundle_lock["url"], archive_path)

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

        return publish_tree(extracted, out_dir, checksums)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"otadump native artifact fetch failed: {error}", file=sys.stderr)
        raise SystemExit(2)
