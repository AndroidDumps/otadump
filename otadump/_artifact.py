from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import tempfile
import urllib.request
import zipfile
from importlib.resources import files
from pathlib import Path


class ArtifactError(RuntimeError):
    pass


def _lock() -> dict:
    return json.loads(files("otadump").joinpath("_artifact_lock.json").read_text())


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _cache_root() -> Path:
    override = os.environ.get("OTADUMP_CACHE_DIR")
    if override:
        return Path(override).expanduser()
    return Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "otadump"


def _runtime_valid(runtime: Path, expected: dict[str, str]) -> bool:
    return all(
        (runtime / name).is_file() and _sha256(runtime / name) == digest
        for name, digest in expected.items()
    )


def executable() -> Path:
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        raise ArtifactError("otadump supports Linux x86_64 only")

    lock = _lock()
    runtime = _cache_root() / lock["bundle_sha256"]
    binary = runtime / "bin" / "ota_extractor"
    if _runtime_valid(runtime, lock["files"]):
        return binary

    runtime.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="otadump-", dir=runtime.parent) as temp_name:
        temp = Path(temp_name)
        bundle = temp / "runtime.zip"
        try:
            urllib.request.urlretrieve(lock["bundle_url"], bundle)
        except OSError as error:
            raise ArtifactError(f"could not download AOSP ota_extractor: {error}") from error
        if _sha256(bundle) != lock["bundle_sha256"]:
            raise ArtifactError("AOSP ota_extractor bundle checksum mismatch")

        unpacked = temp / "runtime"
        unpacked.mkdir()
        with zipfile.ZipFile(bundle) as archive:
            if set(archive.namelist()) != set(lock["files"]):
                raise ArtifactError("AOSP ota_extractor bundle contents do not match lock")
            for name, expected_hash in lock["files"].items():
                target = unpacked / name
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(name) as source, target.open("wb") as destination:
                    shutil.copyfileobj(source, destination)
                if _sha256(target) != expected_hash:
                    raise ArtifactError(f"AOSP runtime checksum mismatch: {name}")

        (unpacked / "bin" / "ota_extractor").chmod(0o755)
        try:
            unpacked.rename(runtime)
        except FileExistsError:
            pass

    if not _runtime_valid(runtime, lock["files"]):
        raise ArtifactError("AOSP ota_extractor cache installation failed")
    return binary
