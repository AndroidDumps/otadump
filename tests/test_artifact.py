import hashlib
import os
import shutil
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))
sys.modules.setdefault("otadump._native", mock.Mock(OtaDumpError=RuntimeError))

from otadump import _artifact  # noqa: E402


class ArtifactTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.write_bytes(b"#!/bin/sh\nexit 0\n")
        self.lock = {
            "url": self.source.as_uri(),
            "sha256": hashlib.sha256(self.source.read_bytes()).hexdigest(),
            "size": self.source.stat().st_size,
        }
        self.cache = self.root / "cache"

    def tearDown(self):
        self.temp.cleanup()

    def test_download_verify_and_reuse_read_only_cache(self):
        with (
            mock.patch.object(_artifact, "_lock", return_value=self.lock),
            mock.patch.dict(os.environ, {"OTADUMP_CACHE_DIR": str(self.cache)}),
        ):
            executable = _artifact.executable()
            self.assertEqual(executable.stat().st_mode & 0o777, 0o555)
            self.source.unlink()
            with mock.patch.object(
                Path, "chmod", side_effect=AssertionError("chmod called")
            ):
                self.assertEqual(_artifact.executable(), executable)

    def test_checksum_is_enforced(self):
        lock = dict(self.lock, sha256="0" * 64)
        with (
            mock.patch.object(_artifact, "_lock", return_value=lock),
            mock.patch.dict(os.environ, {"OTADUMP_CACHE_DIR": str(self.cache)}),
            self.assertRaisesRegex(_artifact.ArtifactError, "checksum mismatch"),
        ):
            _artifact.executable()

    def test_invalid_metadata_uses_artifact_error_hierarchy(self):
        resource = mock.Mock()
        resource.joinpath.return_value.read_text.return_value = (
            '{"url": "file:///tmp/tool"}'
        )
        with (
            mock.patch.object(_artifact, "files", return_value=resource),
            self.assertRaises(_artifact.ArtifactMetadataError) as raised,
        ):
            _artifact._lock()
        self.assertIsInstance(raised.exception, _artifact.ArtifactError)

    def test_concurrent_install_downloads_once(self):
        calls = 0
        calls_lock = threading.Lock()

        def download(_url, destination):
            nonlocal calls
            with calls_lock:
                calls += 1
            shutil.copyfile(self.source, destination)

        with (
            mock.patch.object(_artifact, "_lock", return_value=self.lock),
            mock.patch.dict(os.environ, {"OTADUMP_CACHE_DIR": str(self.cache)}),
            mock.patch.object(
                _artifact.urllib.request, "urlretrieve", side_effect=download
            ),
        ):
            results = []
            threads = [
                threading.Thread(target=lambda: results.append(_artifact.executable()))
                for _ in range(4)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        self.assertEqual(calls, 1)
        self.assertEqual(len(set(results)), 1)


if __name__ == "__main__":
    unittest.main()
