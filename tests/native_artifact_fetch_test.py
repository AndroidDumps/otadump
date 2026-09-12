import concurrent.futures
import hashlib
import json
import os
import pathlib
import subprocess
import tarfile
import tempfile
import unittest
from typing import Optional


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
    include_extra_file: bool = False,
    include_traversal_entry: bool = False,
) -> pathlib.Path:
    extract_root = root / "linux-x86_64-gnu"
    write_tree(extract_root, entries)
    if include_extra_file:
        (extract_root / "rogue.txt").write_text("rogue", encoding="utf-8")
    archive = root / "bundle.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(extract_root, arcname="linux-x86_64-gnu")
        if include_traversal_entry:
            attack = root / "attack.txt"
            attack.write_text("attack", encoding="utf-8")
            tar.add(attack, arcname="../attack.txt")
    return archive


def write_locks(
    root: pathlib.Path,
    archive: pathlib.Path,
    *,
    url: str,
    sha_override: Optional[str] = None,
) -> tuple[pathlib.Path, pathlib.Path]:
    checksums = {
        "lib/libotadump_zucchini.a": b"archive-bytes\n",
        "SHA256SUMS": b"sha-entry\n",
        "include/zucchini_ffi.h": b"#pragma once\n",
        "licenses/LICENSE.zucchini": b"license\n",
        "provenance.txt": b"provenance\n",
    }
    lock_path = root / "ARTIFACT_LOCK.sha256"
    lines = []
    for relpath, content in checksums.items():
        lines.append(f"{hashlib.sha256(content).hexdigest()}  {relpath}")
    lock_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    digest = sha_override or sha256_file(archive)
    bundle = {
        "schema": 1,
        "commit": "9534f6e24296b1682d53cdac19da0b81fc97fcbc",
        "url": url,
        "sha256": digest,
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
        extra_env: Optional[dict[str, str]] = None,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.pop("OTADUMP_NATIVE_PRESEED", None)
        env.pop("OTADUMP_NATIVE_OFFLINE", None)
        env.pop("OTADUMP_NATIVE_CACHE", None)
        if extra_env:
            env.update(extra_env)
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

    def test_parallel_fetches_share_cache_and_atomic_winner(self) -> None:
        archive = write_bundle(self.root, self.entries)
        bundle_lock, checksum_lock = write_locks(self.root, archive, url=self.valid_url)
        out_dir = self.root / "out" / "linux-x86_64-gnu"
        cache_dir = self.root / "cache"

        def run_once() -> subprocess.CompletedProcess[str]:
            return self.run_fetch(
                bundle_lock,
                checksum_lock,
                out_dir,
                cache_dir,
                {"OTADUMP_NATIVE_PRESEED": str(archive)},
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _index: run_once(), range(8)))

        for result in results:
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((out_dir / "lib" / "libotadump_zucchini.a").is_file())
        leftovers = [entry.name for entry in out_dir.parent.iterdir() if ".tmp-" in entry.name]
        self.assertEqual(leftovers, [])

    def test_url_policy_rejects_non_https(self) -> None:
        archive = write_bundle(self.root, self.entries)
        bundle_lock, checksum_lock = write_locks(self.root, archive, url=self.valid_url.replace("https://", "http://"))
        result = self.run_fetch(bundle_lock, checksum_lock, self.root / "out" / "dir", self.root / "cache")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must use HTTPS", result.stderr)

    def test_url_policy_rejects_unpinned_host_path(self) -> None:
        archive = write_bundle(self.root, self.entries)
        bad_url = "https://github.com/AndroidDumps/otadump/archive/refs/heads/mainline.tar.gz"
        bundle_lock, checksum_lock = write_locks(self.root, archive, url=bad_url)
        result = self.run_fetch(bundle_lock, checksum_lock, self.root / "out" / "dir", self.root / "cache")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("host must be raw.githubusercontent.com", result.stderr)

    def test_strict_tree_verification_rejects_extra_unpinned_file(self) -> None:
        preseed_dir = self.root / "preseed"
        write_tree(preseed_dir, self.entries)
        (preseed_dir / "extra.bin").write_bytes(b"x")
        archive = write_bundle(self.root, self.entries)
        bundle_lock, checksum_lock = write_locks(self.root, archive, url=self.valid_url)
        result = self.run_fetch(
            bundle_lock,
            checksum_lock,
            self.root / "out" / "dir",
            self.root / "cache",
            {"OTADUMP_NATIVE_PRESEED": str(preseed_dir)},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unexpected native artifact file", result.stderr)

    def test_tampered_archive_fails_checksum_lock(self) -> None:
        archive = write_bundle(self.root, self.entries)
        bundle_lock, checksum_lock = write_locks(
            self.root,
            archive,
            url=self.valid_url,
            sha_override="0" * 64,
        )
        result = self.run_fetch(
            bundle_lock,
            checksum_lock,
            self.root / "out" / "dir",
            self.root / "cache",
            {"OTADUMP_NATIVE_PRESEED": str(archive)},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("archive checksum mismatch", result.stderr)

    def test_traversal_entry_is_rejected(self) -> None:
        archive = write_bundle(self.root, self.entries, include_traversal_entry=True)
        bundle_lock, checksum_lock = write_locks(self.root, archive, url=self.valid_url)
        result = self.run_fetch(
            bundle_lock,
            checksum_lock,
            self.root / "out" / "dir",
            self.root / "cache",
            {"OTADUMP_NATIVE_PRESEED": str(archive)},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsafe entry", result.stderr)

    def test_offline_requires_cache_or_preseed(self) -> None:
        archive = write_bundle(self.root, self.entries)
        bundle_lock, checksum_lock = write_locks(self.root, archive, url=self.valid_url)
        result = self.run_fetch(
            bundle_lock,
            checksum_lock,
            self.root / "out" / "dir",
            self.root / "cache",
            {"OTADUMP_NATIVE_OFFLINE": "1"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("offline native artifact mode is enabled but cache is empty", result.stderr)


if __name__ == "__main__":
    unittest.main()
