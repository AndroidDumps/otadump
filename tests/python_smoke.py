from inspect import signature
from pathlib import Path
from tempfile import TemporaryDirectory

import otadump


def main() -> None:
    assert issubclass(otadump.OtaDumpError, Exception)
    extract_signature = str(signature(otadump.extract))
    assert "partitions" in extract_signature
    assert "source_dir=None" in extract_signature

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

        cancellation_token = otadump.CancellationToken()
        cancellation_token.cancel()
        cancellation_token.cancel()
        cancelled_output = temporary_path / "cancelled-output"
        try:
            otadump.extract(
                payload_file,
                cancelled_output,
                cancellation_token=cancellation_token,
            )
        except KeyboardInterrupt:
            pass
        else:
            raise AssertionError("cancelled extraction unexpectedly succeeded")
        assert not cancelled_output.exists()


if __name__ == "__main__":
    main()
