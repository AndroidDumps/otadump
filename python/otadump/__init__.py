import hashlib
import math
import os
import platform
import re
import signal
import shutil
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request
import zipfile
from collections.abc import Iterable
from contextlib import ExitStack
from pathlib import Path
from typing import Optional, Union

from ._native import OtaDumpError

__all__ = ["CancellationToken", "OtaDumpError", "extract"]

PathLike = Union[str, "Path"]
_PARTITION_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
_MAX_THREADS = 2**31 - 1
_MAX_PAYLOAD_SIZE = 64 * 1024**3
_DOWNLOAD_TIMEOUT = 30.0
_DOWNLOAD_CHUNK_SIZE = 1024 * 1024
_COMMUNICATE_POLL_SECONDS = 0.2
_PROCESS_TERM_GRACE_SECONDS = 1.0
_PROCESS_KILL_GRACE_SECONDS = 1.0

# Immutable LineageOS build; trust is anchored by the pinned digest below.
_ARTIFACT_URL = (
    "https://raw.githubusercontent.com/LineageOS/android_prebuilts_extract-tools/"
    "a8aabbbe42bdecba4c6d1a9e6e71fbc47de59f96/linux-x86/bin/ota_extractor"
)
_ARTIFACT_SOURCE_URL = (
    "https://github.com/LineageOS/android_prebuilts_extract-tools/tree/"
    "a8aabbbe42bdecba4c6d1a9e6e71fbc47de59f96"
)
_ARTIFACT_GERRIT_URL = (
    "https://review.lineageos.org/plugins/gitiles/"
    "LineageOS/android_prebuilts_extract-tools/+"
    "/a8aabbbe42bdecba4c6d1a9e6e71fbc47de59f96"
)
_ARTIFACT_LICENSE_URL = (
    "https://review.lineageos.org/plugins/gitiles/"
    "LineageOS/android_prebuilts_extract-tools/+"
    "/a8aabbbe42bdecba4c6d1a9e6e71fbc47de59f96/LICENSE"
)
_ARTIFACT_SHA256 = "7cf65d6c557cc6e761082e88aa225123d445be26dd1a18f618f87c142afaff8c"
_ARTIFACT_SIZE = 20_650_520
_download_notice_printed = False


class CancellationToken:
    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    def is_cancelled(self) -> bool:
        return self._event.is_set()


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


def _sha256(path: Path) -> Optional[str]:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _artifact_matches(binary: Path) -> bool:
    try:
        return (
            binary.is_file()
            and binary.stat().st_size == _ARTIFACT_SIZE
            and _sha256(binary) == _ARTIFACT_SHA256
        )
    except OSError:
        return False


def _valid(binary: Path) -> bool:
    return _artifact_matches(binary) and os.access(binary, os.X_OK)


def _emit_download_notice() -> None:
    global _download_notice_printed
    if _download_notice_printed:
        return
    _download_notice_printed = True
    print(
        "otadump: downloading external LineageOS ota_extractor "
        "(not bundled; LGPL-2.1-or-later). "
        f"source={_ARTIFACT_SOURCE_URL} gerrit={_ARTIFACT_GERRIT_URL} "
        f"license={_ARTIFACT_LICENSE_URL}",
        file=os.sys.stderr,
    )


def _download_executable(download: Path) -> None:
    copied = 0
    try:
        with urllib.request.urlopen(_ARTIFACT_URL, timeout=_DOWNLOAD_TIMEOUT) as source:
            with download.open("wb") as destination:
                while chunk := source.read(_DOWNLOAD_CHUNK_SIZE):
                    copied += len(chunk)
                    if copied > _ARTIFACT_SIZE:
                        raise OtaDumpError(
                            "LineageOS ota_extractor download exceeded the pinned size"
                        )
                    destination.write(chunk)
    except OtaDumpError:
        raise
    except (OSError, ValueError) as error:
        raise OtaDumpError(
            f"could not download LineageOS ota_extractor: {error}"
        ) from error
    if copied != _ARTIFACT_SIZE:
        raise OtaDumpError(
            "LineageOS ota_extractor download size mismatch: "
            f"expected {_ARTIFACT_SIZE} bytes, got {copied}"
        )


def _executable() -> Path:
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        raise OtaDumpError("the incremental backend supports Linux x86_64 only")

    cache_root = os.environ.get("OTADUMP_CACHE_DIR")
    if cache_root:
        root = Path(cache_root).expanduser()
    else:
        xdg_cache = os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")
        root = Path(xdg_cache) / "otadump"
    binary = root / _ARTIFACT_SHA256 / "ota_extractor"
    if _valid(binary):
        return binary

    try:
        root.mkdir(parents=True, exist_ok=True)
        binary.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="download-", dir=root) as temp_name:
            download = Path(temp_name) / "ota_extractor"
            _emit_download_notice()
            _download_executable(download)
            if not _artifact_matches(download):
                raise OtaDumpError("LineageOS ota_extractor checksum mismatch")
            download.chmod(0o555)
            os.replace(download, binary)
    except OSError as error:
        raise OtaDumpError(f"could not install LineageOS ota_extractor: {error}") from error

    if not _valid(binary):
        raise OtaDumpError("LineageOS ota_extractor cache installation failed")
    return binary


def _timeout(value: Optional[float]) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, bool):
        raise TypeError("timeout must be a finite positive number")
    if not isinstance(value, (int, float)):
        raise TypeError("timeout must be a finite positive number")
    timeout = float(value)
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be a finite positive number")
    return timeout


def _remaining(deadline: Optional[float]) -> Optional[float]:
    if deadline is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise OtaDumpError("LineageOS ota_extractor timed out")
    return remaining


def _payload_path(
    payload: Path,
    output_parent: Path,
    stack: ExitStack,
    deadline: Optional[float],
    cancellation_token: Optional[CancellationToken],
) -> tuple[Path, Optional[int]]:
    if not zipfile.is_zipfile(payload):
        return payload, None

    try:
        archive_size = payload.stat().st_size
        archive = stack.enter_context(zipfile.ZipFile(payload))
        info = archive.getinfo("payload.bin")
        if info.flag_bits & 1:
            raise OtaDumpError("encrypted payload.bin is not supported")
        if info.file_size > _MAX_PAYLOAD_SIZE:
            raise OtaDumpError("payload.bin exceeds the maximum supported size")

        if info.compress_type == zipfile.ZIP_STORED:
            if info.header_offset < 0 or info.header_offset + 30 > archive_size:
                raise OtaDumpError("invalid payload.bin local ZIP offset")
            with payload.open("rb") as stream:
                stream.seek(info.header_offset)
                header = stream.read(30)
            if len(header) != 30 or header[:4] != b"PK\x03\x04":
                raise OtaDumpError("invalid payload.bin local ZIP header")
            _, _, local_flags, _, _, _, _, compressed_size, uncompressed_size, name_len, extra_len = struct.unpack(
                "<IHHHHHIIIHH", header
            )
            if local_flags & 1:
                raise OtaDumpError("encrypted payload.bin is not supported")
            if uncompressed_size not in {0, info.file_size, 0xFFFFFFFF} or compressed_size not in {
                0,
                info.compress_size,
                0xFFFFFFFF,
            }:
                raise OtaDumpError("payload.bin ZIP headers disagree on payload size")
            data_offset = info.header_offset + 30 + name_len + extra_len
            if data_offset < 0 or data_offset + info.file_size > archive_size:
                raise OtaDumpError("payload.bin local ZIP data exceeds archive bounds")
            return payload, data_offset

        temporary = Path(
            stack.enter_context(
                tempfile.TemporaryDirectory(prefix=".otadump-payload-", dir=output_parent)
            )
        ) / "payload.bin"
        with archive.open(info) as source, temporary.open("wb") as destination:
            copied = 0
            while chunk := source.read(1024 * 1024):
                _remaining(deadline)
                if cancellation_token is not None and cancellation_token.is_cancelled():
                    raise OtaDumpError("LineageOS ota_extractor cancelled")
                copied += len(chunk)
                if copied > _MAX_PAYLOAD_SIZE:
                    raise OtaDumpError("payload.bin exceeds the maximum supported size")
                destination.write(chunk)
        if copied != info.file_size:
            raise OtaDumpError("payload.bin ZIP size mismatch")
        return temporary, None
    except (OSError, KeyError, RuntimeError, NotImplementedError, zipfile.BadZipFile) as error:
        raise OtaDumpError(f"could not read OTA ZIP: {error}") from error


def _stop(process: subprocess.Popen[str]) -> None:
    group = process.pid

    def group_alive() -> bool:
        try:
            os.killpg(group, 0)
        except ProcessLookupError:
            return False
        return True

    try:
        os.killpg(group, signal.SIGTERM)
    except ProcessLookupError:
        pass

    deadline = time.monotonic() + _PROCESS_TERM_GRACE_SECONDS
    while group_alive() and time.monotonic() < deadline:
        time.sleep(0.05)

    if group_alive():
        try:
            os.killpg(group, signal.SIGKILL)
        except ProcessLookupError:
            pass

    try:
        process.wait(timeout=_PROCESS_KILL_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=_PROCESS_KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            pass


def _run(
    command: list[str],
    deadline: Optional[float],
    cancellation_token: Optional[CancellationToken],
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
        raise OtaDumpError(f"could not start LineageOS ota_extractor: {error}") from error

    try:
        while True:
            if cancellation_token is not None and cancellation_token.is_cancelled():
                raise OtaDumpError("LineageOS ota_extractor cancelled")

            timeout = _COMMUNICATE_POLL_SECONDS
            if deadline is not None:
                timeout = min(timeout, _remaining(deadline))
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                break
            except subprocess.TimeoutExpired:
                continue
    except OtaDumpError as error:
        _stop(process)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()
        if str(error) == "LineageOS ota_extractor timed out":
            raise OtaDumpError("LineageOS ota_extractor timed out") from error
        raise
    except BaseException:
        _stop(process)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()
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

    try:
        output.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise OtaDumpError(f"could not create output directory: {error}") from error

    if not overwrite:
        published = []
        attempted_destination: Optional[Path] = None
        try:
            for image in images:
                destination = output / image.name
                attempted_destination = destination
                os.link(image, destination)
                image.unlink()
                published.append(destination)
        except FileExistsError as error:
            for destination in reversed(published):
                destination.unlink(missing_ok=True)
            conflict = attempted_destination or output / Path(error.filename or "unknown").name
            raise OtaDumpError(
                f"output file already exists: {conflict}"
            ) from error
        except OSError as error:
            for destination in reversed(published):
                destination.unlink(missing_ok=True)
            raise OtaDumpError(f"could not publish extracted images: {error}") from error
        return

    try:
        backup = Path(tempfile.mkdtemp(prefix=".otadump-backup-", dir=output.parent))
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
                    os.replace(saved, destination)
                elif not had_original and not image.exists():
                    destination.unlink(missing_ok=True)
            try:
                next(backup.iterdir())
            except StopIteration:
                backup.rmdir()
        except OSError as rollback_error:
            raise OtaDumpError(
                "could not roll back extracted images; backups preserved at "
                f"{backup}: {rollback_error}"
            ) from error
        if isinstance(error, OSError):
            raise OtaDumpError(f"could not publish extracted images: {error}") from error
        raise
    try:
        shutil.rmtree(backup)
    except OSError:
        pass


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
    cancellation_token: Optional[CancellationToken] = None,
) -> None:
    """Extract partitions from a full or incremental Android OTA."""
    from . import _native

    selected = _partitions(partitions)
    num_threads = _num_threads(num_threads)

    timeout = _timeout(timeout)
    if cancellation_token is not None and not isinstance(cancellation_token, CancellationToken):
        raise TypeError("cancellation_token must be a CancellationToken")

    if source_dir is None and cancellation_token is None:
        if timeout is not None:
            raise ValueError("timeout is only supported with source_dir or cancellation_token")
        return _native.extract(
            payload_file,
            output_dir,
            num_threads=num_threads,
            overwrite=overwrite,
            partitions=selected,
            verify=verify,
        )

    if not verify:
        raise ValueError("verify=False is not supported with external ota_extractor")

    payload = Path(payload_file).expanduser().resolve()
    source = None if source_dir is None else Path(source_dir).expanduser().resolve()
    output = Path(output_dir).expanduser().resolve()

    if not payload.is_file():
        raise OtaDumpError(f"payload does not exist: {payload}")
    if source is not None and not source.is_dir():
        raise OtaDumpError(f"source directory does not exist: {source}")
    executable = _executable()

    try:
        output.parent.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise OtaDumpError(f"could not create output directory: {error}") from error

    deadline = None if timeout is None else time.monotonic() + timeout
    with ExitStack() as stack:
        native_payload, offset = _payload_path(
            payload,
            output.parent,
            stack,
            deadline,
            cancellation_token,
        )
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
            f"--output_dir={staging}",
        ]
        if source is not None:
            command.append(f"--input_dir={source}")
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

        try:
            _remaining(deadline)
        except OtaDumpError:
            raise OtaDumpError("LineageOS ota_extractor timed out before it could start")

        result = _run(command, deadline, cancellation_token)
        if result.returncode:
            detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic output"
            raise OtaDumpError(
                "LineageOS ota_extractor failed with status "
                f"{result.returncode}: {detail}"
            )
        _publish(staging, output, selected, overwrite)
