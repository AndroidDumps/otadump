from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Optional

import otadump


def _varint(value: int) -> bytes:
    encoded = bytearray()
    while value >= 0x80:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _integer(field: int, value: int) -> bytes:
    return _varint(field << 3) + _varint(value)


def _bytes(field: int, value: bytes) -> bytes:
    return _varint((field << 3) | 2) + _varint(len(value)) + value


def _extent(length: int) -> bytes:
    return _integer(1, 0) + _integer(2, length)


def _partition_info(data: bytes) -> bytes:
    return _integer(1, len(data)) + _bytes(2, sha256(data).digest())


def _payload(target: bytes, source: Optional[bytes] = None) -> bytes:
    operation_type = 0 if source is None else 4
    operation = _integer(1, operation_type)
    if source is None:
        operation += _integer(2, 0) + _integer(3, len(target))
        operation += _bytes(8, sha256(target).digest())
    else:
        operation += _bytes(4, _extent(len(source))) + _integer(5, len(source))
        operation += _bytes(9, sha256(source).digest())
    operation += _bytes(6, _extent(len(target))) + _integer(7, len(target))

    partition = _bytes(1, b"system")
    if source is not None:
        partition += _bytes(6, _partition_info(source))
    partition += _bytes(7, _partition_info(target)) + _bytes(8, operation)
    manifest = _integer(3, 1) + _bytes(13, partition)
    operation_data = target if source is None else b""
    return (
        b"CrAU"
        + (2).to_bytes(8, "big")
        + len(manifest).to_bytes(8, "big")
        + bytes(4)
        + manifest
        + operation_data
    )


def main() -> None:
    with TemporaryDirectory() as temporary_directory:
        temporary_path = Path(temporary_directory)

        full_target = b"full partition image"
        full_payload = temporary_path / "full.bin"
        full_payload.write_bytes(_payload(full_target))
        full_output = temporary_path / "full-output"
        otadump.extract(full_payload, full_output)
        assert (full_output / "system.img").read_bytes() == full_target

        source = b"source partition image"
        source_dir = temporary_path / "source"
        source_dir.mkdir()
        source_image = source_dir / "system.img"
        source_image.write_bytes(source)
        delta_payload = temporary_path / "delta.bin"
        delta_payload.write_bytes(_payload(source, source))
        delta_output = temporary_path / "delta-output"
        otadump.extract(delta_payload, delta_output, source_dir=source_dir)
        assert (delta_output / "system.img").read_bytes() == source
        assert source_image.read_bytes() == source

        invalid_payload = temporary_path / "invalid.bin"
        invalid_payload.write_bytes(b"invalid")
        try:
            otadump.extract(invalid_payload, temporary_path / "invalid-output")
        except otadump.OtaDumpError as error:
            assert str(error) == "Invalid payload file"
        else:
            raise AssertionError("invalid payload unexpectedly succeeded")


if __name__ == "__main__":
    main()
