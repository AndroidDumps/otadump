import hashlib
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from otadump import _artifact


class ArtifactTest(unittest.TestCase):
    def test_download_verify_and_cache(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            bundle = root / "bundle.zip"
            data = b"#!/bin/sh\nexit 0\n"
            with zipfile.ZipFile(bundle, "w") as archive:
                archive.writestr("bin/ota_extractor", data)
            lock = {
                "bundle_url": bundle.as_uri(),
                "bundle_sha256": hashlib.sha256(bundle.read_bytes()).hexdigest(),
                "files": {"bin/ota_extractor": hashlib.sha256(data).hexdigest()},
            }
            cache = root / "cache"
            with mock.patch.object(_artifact, "_lock", return_value=lock), mock.patch.dict(
                os.environ, {"OTADUMP_CACHE_DIR": str(cache)}
            ):
                executable = _artifact.executable()
                self.assertTrue(os.access(executable, os.X_OK))
                executable.write_bytes(b"tampered")
                repaired = _artifact.executable()
                self.assertEqual(repaired.read_bytes(), data)
                bundle.unlink()
                self.assertEqual(_artifact.executable(), executable)

    def test_bundle_checksum_is_enforced(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            bundle = root / "bundle.zip"
            bundle.write_bytes(b"not trusted")
            lock = {
                "bundle_url": bundle.as_uri(),
                "bundle_sha256": "0" * 64,
                "files": {"bin/ota_extractor": "1" * 64},
            }
            with mock.patch.object(_artifact, "_lock", return_value=lock), mock.patch.dict(
                os.environ, {"OTADUMP_CACHE_DIR": str(root / "cache")}
            ):
                with self.assertRaisesRegex(_artifact.ArtifactError, "checksum mismatch"):
                    _artifact.executable()


if __name__ == "__main__":
    unittest.main()
