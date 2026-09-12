import hashlib
import json
import os
import pathlib
import subprocess
import tarfile
import tempfile
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
FETCH_SCRIPT = REPO_ROOT / "scripts" / "fetch-native-artifact.py"


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_tree(root: pathlib.Path, entries: dict[str, bytes]) -> None:
    for relpath, content in entries.items():
        target = root / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)


def write_bundle(
    root: pathlib.Path,
    entries: dict[str, bytes],
    *,
    include_traversal_entry: bool = False,
) -> pathlib.Path:
    extract_root = root / "linux-x86_64-gnu"
    write_tree(extract_root, entries)
    archive = root / "bundle.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(extract_root, arcname="linux-x86_64-gnu")
        if include_traversal_entry:
            attack = root / "attack.txt"
            attack.write_text("attack", encoding="utf-8")
            tar.add(attack, arcname="../attack.txt")
    return archive


def write_locks(root: pathlib.Path, archive: pathlib.Path, url: str) -> tuple[pathlib.Path, pathlib.Path]:
    checksums = {
        "lib/libotadump_zucchini.a": b"archive-bytes\n",
        "SHA256SUMS": b"sha-entry\n",
        "include/zucchini_ffi.h": b"#pragma once\n",
        "licenses/LICENSE.zucchini": b"license\n",
        "provenance.txt": b"provenance\n",
    }
    lock_path = root / "ARTIFACT_LOCK.sha256"
    lock_path.write_text(
        "\n".join(f"{hashlib.sha256(content).hexdigest()}  {relpath}" for relpath, content in checksums.items())
        + "\n",
        encoding="utf-8",
    )
    bundle = {
        "schema": 1,
        "commit": "9534f6e24296b1682d53cdac19da0b81fc97fcbc",
        "url": url,
        "sha256": sha256_file(archive),
        "extract_root": "linux-x86_64-gnu",
    }
    bundle_path = root / "ARTIFACT_BUNDLE_LOCK.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    return bundle_path, lock_path


class NativeArtifactFetchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tempdir.name)
        self.entries = {
            "lib/libotadump_zucchini.a": b"archive-bytes\n",
            "SHA256SUMS": b"sha-entry\n",
            "include/zucchini_ffi.h": b"#pragma once\n",
            "licenses/LICENSE.zucchini": b"license\n",
            "provenance.txt": b"provenance\n",
        }
        self.valid_url = (
            "https://raw.githubusercontent.com/AndroidDumps/otadump/"
            "9534f6e24296b1682d53cdac19da0b81fc97fcbc/native/artifacts/zucchini/"
            "zucchini-linux-x86_64-gnu.tar.gz"
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def run_fetch(
        self,
        bundle_lock: pathlib.Path,
        checksum_lock: pathlib.Path,
        out_dir: pathlib.Path,
        cache_dir: pathlib.Path,
        preseed: pathlib.Path,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["OTADUMP_NATIVE_PRESEED"] = str(preseed)
        env.pop("OTADUMP_NATIVE_OFFLINE", None)
        env.pop("OTADUMP_NATIVE_CACHE", None)
        return subprocess.run(
            [
                "python3",
                str(FETCH_SCRIPT),
                "--bundle-lock",
                str(bundle_lock),
                "--checksum-lock",
                str(checksum_lock),
                "--out",
                str(out_dir),
                "--cache",
                str(cache_dir),
            ],
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )

    def test_preseed_archive_fetch_populates_verified_output(self) -> None:
        archive = write_bundle(self.root, self.entries)
        bundle_lock, checksum_lock = write_locks(self.root, archive, self.valid_url)
        out_dir = self.root / "out" / "linux-x86_64-gnu"
        result = self.run_fetch(bundle_lock, checksum_lock, out_dir, self.root / "cache", archive)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((out_dir / "lib" / "libotadump_zucchini.a").is_file())

    def test_traversal_entry_is_rejected(self) -> None:
        archive = write_bundle(self.root, self.entries, include_traversal_entry=True)
        bundle_lock, checksum_lock = write_locks(self.root, archive, self.valid_url)
        result = self.run_fetch(
            bundle_lock,
            checksum_lock,
            self.root / "out" / "linux-x86_64-gnu",
            self.root / "cache",
            archive,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsafe entry", result.stderr)


if __name__ == "__main__":
    unittest.main()
