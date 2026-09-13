from __future__ import annotations

import os
import re
import signal
import struct
import subprocess
import tempfile
import time
import zipfile
from collections.abc import Iterable
from contextlib import ExitStack
from pathlib import Path
from typing import Optional, Union

from . import _artifact
from ._native import OtaDumpError

PathLike = Union[str, "Path"]
_PARTITION_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
_MAX_THREADS = 2**31 - 1
_MAX_PAYLOAD_SIZE = 64 * 1024**3


def _partitions(value: Optional[Iterable[str]]) -> Optional[list[str]]:
    if value is None:
        return None
    if isinstance(value, (str, bytes)):
        raise OtaDumpError(
            "partitions must be an iterable of partition names, not a string"
        )
    selected = list(value)
    if not selected or any(
        not isinstance(name, str)
        or name in {".", ".."}
        or not _PARTITION_NAME.fullmatch(name)
        for name in selected
    ):
        raise OtaDumpError(
            "partitions must contain safe partition names without separators"
        )
    return list(dict.fromkeys(selected))


def _num_threads(value: Optional[int]) -> Optional[int]:
    if value is None:
        return None
    if type(value) is not int:
        raise TypeError("num_threads must be an integer")
    if not 1 <= value <= _MAX_THREADS:
        raise ValueError(f"num_threads must be between 1 and {_MAX_THREADS}")
    return value


def _payload_path(
    payload: Path, stack: ExitStack, deadline: Optional[float]
) -> tuple[Path, Optional[int]]:
    if not zipfile.is_zipfile(payload):
        return payload, None
    try:
        archive = stack.enter_context(zipfile.ZipFile(payload))
        info = archive.getinfo("payload.bin")
        if info.flag_bits & 1:
            raise OtaDumpError("encrypted payload.bin is not supported")
        if info.file_size > _MAX_PAYLOAD_SIZE:
            raise OtaDumpError("payload.bin exceeds the maximum supported size")
        if info.compress_type == zipfile.ZIP_STORED:
            with payload.open("rb") as stream:
                stream.seek(info.header_offset)
                header = stream.read(30)
            if len(header) != 30 or header[:4] != b"PK\x03\x04":
                raise OtaDumpError("invalid payload.bin local ZIP header")
            fields = struct.unpack("<4s5H3L2H", header)
            return payload, info.header_offset + 30 + fields[-2] + fields[-1]
        temporary = (
            Path(stack.enter_context(tempfile.TemporaryDirectory())) / "payload.bin"
        )
        with archive.open(info) as source, temporary.open("wb") as destination:
            copied = 0
            while chunk := source.read(1024 * 1024):
                copied += len(chunk)
                if copied > _MAX_PAYLOAD_SIZE:
                    raise OtaDumpError(
                        "payload.bin exceeds the maximum supported size"
                    )
                if deadline is not None and time.monotonic() >= deadline:
                    raise OtaDumpError(
                        "LineageOS ota_extractor timed out while reading payload.bin"
                    )
                destination.write(chunk)
        return temporary, None
    except (
        OSError,
        KeyError,
        RuntimeError,
        NotImplementedError,
        zipfile.BadZipFile,
    ) as error:
        raise OtaDumpError(f"could not read OTA ZIP: {error}") from error


def _stop(process: subprocess.Popen[str]) -> None:
    process_group = process.pid

    def group_exists() -> bool:
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            return False
        return True

    try:
        os.killpg(process_group, signal.SIGTERM)
    except ProcessLookupError:
        pass

    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        process.poll()
        if not group_exists():
            break
        time.sleep(0.05)
    else:
        try:
            os.killpg(process_group, signal.SIGKILL)
        except ProcessLookupError:
            pass

    process.wait()
    deadline = time.monotonic() + 5
    while group_exists() and time.monotonic() < deadline:
        time.sleep(0.05)


def _run(
    command: list[str], timeout: Optional[float]
) -> subprocess.CompletedProcess[str]:
    try:
        process = subprocess.Popen(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as error:
        raise OtaDumpError(
            f"could not start LineageOS ota_extractor: {error}"
        ) from error
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        _stop(process)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
        raise OtaDumpError(
            f"LineageOS ota_extractor timed out after {timeout} seconds"
        ) from error
    except BaseException:
        _stop(process)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
        raise
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _publish(
    staging: Path, output: Path, selected: Optional[list[str]], overwrite: bool
) -> None:
    images = list(staging.glob("*.img"))
    by_name = {image.stem: image for image in images}
    if selected is not None:
        missing = [name for name in selected if name not in by_name]
        if missing:
            raise OtaDumpError(
                f"requested partitions were not produced: {', '.join(missing)}"
            )
        images = [by_name[name] for name in selected]
    if not images:
        raise OtaDumpError("LineageOS ota_extractor produced no partition images")

    conflicts = [
        output / image.name for image in images if (output / image.name).exists()
    ]
    if conflicts and not overwrite:
        raise OtaDumpError(f"output file already exists: {conflicts[0]}")

    try:
        output.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise OtaDumpError(f"could not create output directory: {error}") from error
    backup = staging.parent / "backup"
    try:
        backup.mkdir()
    except OSError as error:
        raise OtaDumpError(f"could not create publication backup: {error}") from error
    publications = [
        (image, output / image.name, backup / image.name, (output / image.name).exists())
        for image in images
    ]
    try:
        for image, destination, saved, had_original in publications:
            if had_original:
                os.replace(destination, saved)
            os.replace(image, destination)
    except BaseException as error:
        try:
            for image, destination, saved, had_original in reversed(publications):
                if saved.exists():
                    destination.unlink(missing_ok=True)
                    os.replace(saved, destination)
                elif not had_original and not image.exists():
                    destination.unlink(missing_ok=True)
        except OSError as rollback_error:
            raise OtaDumpError(
                f"could not roll back extracted images: {rollback_error}"
            ) from error
        if isinstance(error, OSError):
            raise OtaDumpError(
                f"could not publish extracted images: {error}"
            ) from error
        raise


def extract(
    payload_file: PathLike,
    output_dir: PathLike,
    *,
    num_threads: Optional[int] = None,
    overwrite: bool = False,
    partitions: Optional[Iterable[str]] = None,
    verify: bool = True,
    source_dir: Optional[PathLike] = None,
    timeout: Optional[float] = None,
) -> None:
    """Extract partitions from a full or incremental Android OTA."""
    from . import _native

    selected = _partitions(partitions)
    num_threads = _num_threads(num_threads)
    if source_dir is None:
        if timeout is not None:
            raise ValueError("timeout is only supported with source_dir")
        return _native.extract(
            payload_file,
            output_dir,
            num_threads=num_threads,
            overwrite=overwrite,
            partitions=selected,
            verify=verify,
        )

    if not verify:
        raise ValueError("verify=False is not supported with source_dir")

    payload = Path(payload_file).expanduser().resolve()
    source = Path(source_dir).expanduser().resolve()
    output = Path(output_dir).expanduser().resolve()
    if not payload.is_file():
        raise OtaDumpError(f"payload does not exist: {payload}")
    if not source.is_dir():
        raise OtaDumpError(f"source directory does not exist: {source}")
    if timeout is not None and timeout <= 0:
        raise ValueError("timeout must be greater than zero")

    try:
        executable = _artifact.executable()
    except _artifact.ArtifactError as error:
        raise OtaDumpError(str(error)) from error

    try:
        output.parent.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise OtaDumpError(f"could not create output directory: {error}") from error
    deadline = None if timeout is None else time.monotonic() + timeout
    with ExitStack() as stack:
        native_payload, offset = _payload_path(payload, stack, deadline)
        try:
            staging_root = Path(
                stack.enter_context(
                    tempfile.TemporaryDirectory(prefix=".otadump-", dir=output.parent)
                )
            )
        except OSError as error:
            raise OtaDumpError(
                f"could not create extraction staging directory: {error}"
            ) from error
        staging = staging_root / "output"
        try:
            staging.mkdir()
        except OSError as error:
            raise OtaDumpError(
                f"could not create extraction staging directory: {error}"
            ) from error
        command = [
            str(executable),
            f"--payload={native_payload}",
            f"--input_dir={source}",
            f"--output_dir={staging}",
        ]
        if offset is not None:
            command.append(f"--payload_offset={offset}")
        if selected is not None:
            command.append(f"--partitions={','.join(selected)}")
        if num_threads is not None:
            command.extend(
                [
                    f"--operation_threads={num_threads}",
                    f"--verity_threads={num_threads}",
                ]
            )
        remaining = None if deadline is None else deadline - time.monotonic()
        if remaining is not None and remaining <= 0:
            raise OtaDumpError(
                "LineageOS ota_extractor timed out before it could start"
            )
        result = _run(command, remaining)
        if result.returncode:
            detail = (
                result.stderr.strip() or result.stdout.strip() or "no diagnostic output"
            )
            raise OtaDumpError(
                "LineageOS ota_extractor failed with status "
                f"{result.returncode}: {detail}"
            )
        _publish(staging, output, selected, overwrite)
