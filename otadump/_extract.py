from __future__ import annotations

import struct
import subprocess
import zipfile
from pathlib import Path
from typing import Iterable, Union

from . import _artifact

PathLike = Union[str, "Path"]


class OtaDumpError(RuntimeError):
    """Raised when the AOSP extractor cannot reconstruct the requested images."""


def _zip_payload_offset(path: Path) -> int:
    try:
        with zipfile.ZipFile(path) as archive:
            info = archive.getinfo("payload.bin")
            if info.compress_type != zipfile.ZIP_STORED:
                raise OtaDumpError("OTA payload.bin must be stored without compression")
            with path.open("rb") as stream:
                stream.seek(info.header_offset)
                header = stream.read(30)
    except (OSError, zipfile.BadZipFile, KeyError) as error:
        raise OtaDumpError(f"could not read OTA ZIP: {error}") from error

    if len(header) != 30 or header[:4] != b"PK\x03\x04":
        raise OtaDumpError("invalid payload.bin local ZIP header")
    fields = struct.unpack("<4s5H3L2H", header)
    return info.header_offset + 30 + fields[-2] + fields[-1]


def extract(
    payload_file: PathLike,
    output_dir: PathLike,
    *,
    source_dir: PathLike | None = None,
    partitions: Iterable[str] | None = None,
    single_thread: bool = False,
) -> None:
    """Extract images from a full or incremental Android OTA payload."""
    payload = Path(payload_file).expanduser().resolve()
    output = Path(output_dir).expanduser().resolve()
    if not payload.is_file():
        raise OtaDumpError(f"payload does not exist: {payload}")
    output.mkdir(parents=True, exist_ok=True)

    try:
        executable = _artifact.executable()
    except _artifact.ArtifactError as error:
        raise OtaDumpError(str(error)) from error

    command = [
        str(executable),
        f"--payload={payload}",
        f"--output_dir={output}",
    ]
    if zipfile.is_zipfile(payload):
        command.append(f"--payload_offset={_zip_payload_offset(payload)}")
    if source_dir is not None:
        source = Path(source_dir).expanduser().resolve()
        if not source.is_dir():
            raise OtaDumpError(f"source directory does not exist: {source}")
        command.append(f"--input_dir={source}")
    if partitions is not None:
        if isinstance(partitions, (str, bytes)):
            raise TypeError("partitions must be an iterable of partition names")
        selected = list(partitions)
        if not selected or any(not name or "," in name for name in selected):
            raise ValueError("partitions must contain non-empty names without commas")
        command.append(f"--partitions={','.join(selected)}")
    if single_thread:
        command.append("--single_thread")
    try:
        result = subprocess.run(command, text=True, capture_output=True, check=False)
    except OSError as error:
        raise OtaDumpError(f"could not start AOSP ota_extractor: {error}") from error
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic output"
        raise OtaDumpError(
            f"AOSP ota_extractor failed with status {result.returncode}: {detail}"
        )
