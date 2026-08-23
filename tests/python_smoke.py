from inspect import signature
from pathlib import Path
from tempfile import TemporaryDirectory

import otadump


def main() -> None:
    assert issubclass(otadump.OtaDumpError, Exception)
    assert "partitions" in str(signature(otadump.extract))

    with TemporaryDirectory() as temporary_directory:
        temporary_path = Path(temporary_directory)
        payload_file = temporary_path / "invalid.bin"
        payload_file.write_bytes(b"invalid")

        try:
            otadump.extract(payload_file, temporary_path / "output")
        except otadump.OtaDumpError as error:
            assert str(error) == "Invalid payload file"
        else:
            raise AssertionError("invalid payload unexpectedly succeeded")


if __name__ == "__main__":
    main()
