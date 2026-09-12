import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import otadump


class ExtractTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.payload = self.root / "payload.bin"
        self.payload.write_bytes(b"CrAU payload")

    def tearDown(self):
        self.temp.cleanup()

    @mock.patch("otadump._extract._artifact.executable", return_value=Path("/tool"))
    @mock.patch("otadump._extract.subprocess.run")
    def test_raw_payload_arguments(self, run, _executable):
        run.return_value = subprocess.CompletedProcess([], 0, "", "")
        source = self.root / "source"
        source.mkdir()

        otadump.extract(
            self.payload,
            self.root / "output",
            source_dir=source,
            partitions=["boot", "system"],
            single_thread=True,
        )

        command = run.call_args.args[0]
        self.assertIn(f"--payload={self.payload}", command)
        self.assertIn(f"--input_dir={source}", command)
        self.assertIn("--partitions=boot,system", command)
        self.assertIn("--single_thread", command)

    @mock.patch("otadump._extract._artifact.executable", return_value=Path("/tool"))
    @mock.patch("otadump._extract.subprocess.run")
    def test_zip_payload_offset_points_to_payload(self, run, _executable):
        run.return_value = subprocess.CompletedProcess([], 0, "", "")
        ota = self.root / "ota.zip"
        with zipfile.ZipFile(ota, "w") as archive:
            archive.writestr("metadata", "value")
            archive.writestr("payload.bin", b"CrAU payload")

        otadump.extract(ota, self.root / "output")

        command = run.call_args.args[0]
        offset = int(next(arg.split("=", 1)[1] for arg in command if arg.startswith("--payload_offset=")))
        with ota.open("rb") as stream:
            stream.seek(offset)
            self.assertEqual(stream.read(4), b"CrAU")

    @mock.patch("otadump._extract._artifact.executable", return_value=Path("/tool"))
    @mock.patch("otadump._extract.subprocess.run")
    def test_native_failure_is_raised(self, run, _executable):
        run.return_value = subprocess.CompletedProcess([], 1, "", "bad manifest")
        with self.assertRaisesRegex(otadump.OtaDumpError, "bad manifest"):
            otadump.extract(self.payload, self.root / "output")

    def test_missing_inputs_fail_before_artifact_download(self):
        with self.assertRaisesRegex(otadump.OtaDumpError, "payload does not exist"):
            otadump.extract(self.root / "missing", self.root / "output")


if __name__ == "__main__":
    unittest.main()
