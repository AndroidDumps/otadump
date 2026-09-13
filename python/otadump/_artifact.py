from __future__ import annotations

import hashlib
import json
import os
import platform
import tempfile
import urllib.request
from importlib.resources import files
from pathlib import Path


class ArtifactError(RuntimeError):
    pass


class ArtifactMetadataError(ArtifactError):
    pass


class ArtifactDownloadError(ArtifactError):
    pass


class ArtifactCacheError(ArtifactError):
    pass


def _lock() -> dict:
    try:
        lock = json.loads(
            files("otadump").joinpath("_artifact_lock.json").read_text()
        )
        if (
            not isinstance(lock, dict)
            or not isinstance(lock.get("url"), str)
            or not lock["url"].startswith("https://")
            or not isinstance(lock.get("sha256"), str)
            or len(lock["sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in lock["sha256"])
            or type(lock.get("size")) is not int
            or lock["size"] <= 0
        ):
            raise ValueError("invalid fields")
        return lock
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ArtifactMetadataError(
            f"could not read incremental backend metadata: {error}"
        ) from error


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


def _valid(binary: Path, lock: dict) -> bool:
    try:
        return (
            binary.is_file()
            and binary.stat().st_size == lock["size"]
            and os.access(binary, os.X_OK)
            and _sha256(binary) == lock["sha256"]
        )
    except OSError:
        return False


def executable() -> Path:
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        raise ArtifactError("the incremental backend supports Linux x86_64 only")

    import fcntl

    lock = _lock()
    root = _cache_root()
    binary = root / lock["sha256"] / "ota_extractor"
    if _valid(binary, lock):
        return binary

    try:
        root.mkdir(parents=True, exist_ok=True)
        with (root / ".install.lock").open("a+b") as install_lock:
            fcntl.flock(install_lock, fcntl.LOCK_EX)
            if _valid(binary, lock):
                return binary

            binary.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix="download-", dir=root) as temp_name:
                download = Path(temp_name) / "ota_extractor"
                try:
                    urllib.request.urlretrieve(lock["url"], download)
                except (OSError, ValueError) as error:
                    raise ArtifactDownloadError(
                        f"could not download LineageOS ota_extractor: {error}"
                    ) from error
                if not _valid_download(download, lock):
                    raise ArtifactDownloadError(
                        "LineageOS ota_extractor checksum mismatch"
                    )
                download.chmod(0o555)
                os.replace(download, binary)
    except ArtifactError:
        raise
    except OSError as error:
        raise ArtifactCacheError(
            f"could not install LineageOS ota_extractor: {error}"
        ) from error

    if not _valid(binary, lock):
        raise ArtifactCacheError(
            "LineageOS ota_extractor cache installation failed"
        )
    return binary


def _valid_download(download: Path, lock: dict) -> bool:
    try:
        return (
            download.stat().st_size == lock["size"]
            and _sha256(download) == lock["sha256"]
        )
    except OSError:
        return False
