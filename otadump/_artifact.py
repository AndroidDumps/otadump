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


def executable() -> Path:
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        raise ArtifactError("otadump supports Linux x86_64 only")

    lock = _lock()
    runtime = _cache_root() / lock["sha256"]
    binary = runtime / "ota_extractor"
    if binary.is_file() and _sha256(binary) == lock["sha256"]:
        binary.chmod(0o755)
        return binary

    runtime.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="download-", dir=runtime) as temp_name:
        download = Path(temp_name) / "ota_extractor"
        try:
            urllib.request.urlretrieve(lock["url"], download)
        except OSError as error:
            raise ArtifactError(f"could not download LineageOS ota_extractor: {error}") from error
        if download.stat().st_size != lock["size"] or _sha256(download) != lock["sha256"]:
            raise ArtifactError("LineageOS ota_extractor checksum mismatch")
        download.chmod(0o755)
        download.replace(binary)

    return binary
