import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from otadump import _artifact


class ArtifactTest(unittest.TestCase):
    def test_download_verify_and_cache(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            download = root / "ota_extractor"
            download.write_bytes(b"#!/bin/sh\nexit 0\n")
            lock = {
                "url": download.as_uri(),
                "sha256": hashlib.sha256(download.read_bytes()).hexdigest(),
                "size": download.stat().st_size,
            }
            cache = root / "cache"
            with mock.patch.object(_artifact, "_lock", return_value=lock), mock.patch.dict(
                os.environ, {"OTADUMP_CACHE_DIR": str(cache)}
            ):
                executable = _artifact.executable()
                self.assertTrue(os.access(executable, os.X_OK))
                download.unlink()
                self.assertEqual(_artifact.executable(), executable)

    def test_checksum_is_enforced(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            download = root / "ota_extractor"
            download.write_bytes(b"not trusted")
            lock = {
                "url": download.as_uri(),
                "sha256": "0" * 64,
                "size": download.stat().st_size,
            }
            with (
                mock.patch.object(_artifact, "_lock", return_value=lock),
                mock.patch.dict(os.environ, {"OTADUMP_CACHE_DIR": str(root / "cache")}),
                self.assertRaisesRegex(_artifact.ArtifactError, "checksum mismatch"),
            ):
                _artifact.executable()


if __name__ == "__main__":
    unittest.main()
