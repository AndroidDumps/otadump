import os
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))


class PublicError(RuntimeError):
    pass


sys.modules.setdefault("otadump._native", mock.Mock(OtaDumpError=PublicError))
native = sys.modules["otadump._native"]
PublicError = native.OtaDumpError

import otadump  # noqa: E402
from otadump import _artifact, _extract  # noqa: E402


class IncrementalExtractTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.payload = self.root / "payload.bin"
        self.payload.write_bytes(b"CrAU payload")
        self.source = self.root / "source"
        self.source.mkdir()
        native.reset_mock()

    def tearDown(self):
        self.temp.cleanup()

    def _successful_run(self, command, _timeout):
        staging = Path(
            next(
                arg.split("=", 1)[1]
                for arg in command
                if arg.startswith("--output_dir=")
            )
        )
        (staging / "boot.img").write_bytes(b"new boot")
        return subprocess.CompletedProcess(command, 0, "", "")

    @mock.patch.object(_artifact, "executable", return_value=Path("/tool"))
    @mock.patch.object(_extract, "_run")
    def test_stages_then_publishes_requested_partition(self, run, _executable):
        run.side_effect = self._successful_run
        output = self.root / "output"
        otadump.extract(
            self.payload,
            output,
            source_dir=self.source,
            partitions=["boot"],
            num_threads=3,
        )
        self.assertEqual((output / "boot.img").read_bytes(), b"new boot")
        command = run.call_args.args[0]
        self.assertIn("--partitions=boot", command)
        self.assertIn("--operation_threads=3", command)
        self.assertNotEqual(
            next(arg for arg in command if arg.startswith("--output_dir=")),
            f"--output_dir={output}",
        )

    @mock.patch.object(_artifact, "executable", return_value=Path("/tool"))
    @mock.patch.object(_extract, "_run")
    def test_failure_does_not_modify_output(self, run, _executable):
        output = self.root / "output"
        output.mkdir()
        existing = output / "boot.img"
        existing.write_bytes(b"old boot")
        run.return_value = subprocess.CompletedProcess([], 1, "", "failed")
        with self.assertRaisesRegex(PublicError, "failed"):
            otadump.extract(
                self.payload, output, source_dir=self.source, overwrite=True
            )
        self.assertEqual(existing.read_bytes(), b"old boot")

    @mock.patch.object(_artifact, "executable", return_value=Path("/tool"))
    @mock.patch.object(_extract, "_run")
    def test_missing_requested_partition_fails(self, run, _executable):
        run.return_value = subprocess.CompletedProcess([], 0, "", "")
        with self.assertRaisesRegex(PublicError, "boot"):
            otadump.extract(
                self.payload,
                self.root / "output",
                source_dir=self.source,
                partitions=["boot"],
            )

    @mock.patch.object(_artifact, "executable", return_value=Path("/tool"))
    @mock.patch.object(_extract, "_run")
    def test_compressed_zip_payload_is_unpacked(self, run, _executable):
        ota = self.root / "ota.zip"
        with zipfile.ZipFile(ota, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("payload.bin", b"CrAU compressed")

        def inspect(command, timeout):
            payload = Path(
                next(
                    arg.split("=", 1)[1]
                    for arg in command
                    if arg.startswith("--payload=")
                )
            )
            self.assertNotEqual(payload, ota)
            self.assertEqual(payload.read_bytes(), b"CrAU compressed")
            return self._successful_run(command, timeout)

        run.side_effect = inspect
        otadump.extract(
            ota, self.root / "output", source_dir=self.source, partitions=["boot"]
        )

    @mock.patch.object(_artifact, "executable", return_value=Path("/tool"))
    def test_encrypted_payload_is_rejected_for_stored_and_deflated_zip(self, _tool):
        for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            ota = self.root / f"encrypted-{compression}.zip"
            with zipfile.ZipFile(ota, "w", compression=compression) as archive:
                archive.writestr("payload.bin", b"CrAU payload")
            contents = bytearray(ota.read_bytes())
            local = contents.index(b"PK\x03\x04") + 6
            central = contents.index(b"PK\x01\x02") + 8
            for offset in (local, central):
                flags = int.from_bytes(contents[offset : offset + 2], "little") | 1
                contents[offset : offset + 2] = flags.to_bytes(2, "little")
            ota.write_bytes(contents)
            with self.subTest(compression=compression), self.assertRaisesRegex(
                PublicError, "encrypted"
            ):
                otadump.extract(ota, self.root / "output", source_dir=self.source)

    @mock.patch.object(_artifact, "executable", return_value=Path("/tool"))
    def test_compressed_payload_size_and_materialization_timeout_are_bounded(self, _tool):
        ota = self.root / "compressed.zip"
        with zipfile.ZipFile(ota, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("payload.bin", b"CrAU payload")
        with (
            mock.patch.object(_extract, "_MAX_PAYLOAD_SIZE", 4),
            self.assertRaisesRegex(PublicError, "maximum supported size"),
        ):
            otadump.extract(ota, self.root / "output", source_dir=self.source)
        with (
            mock.patch.object(_extract.time, "monotonic", side_effect=[0, 2]),
            self.assertRaisesRegex(PublicError, "timed out while reading"),
        ):
            otadump.extract(
                ota, self.root / "output", source_dir=self.source, timeout=1
            )

    @mock.patch.object(_artifact, "executable", return_value=Path("/tool"))
    def test_output_directory_failure_uses_public_error(self, _tool):
        with (
            mock.patch.object(Path, "mkdir", side_effect=OSError("read-only")),
            self.assertRaisesRegex(PublicError, "create output directory"),
        ):
            otadump.extract(
                self.payload, self.root / "output", source_dir=self.source
            )

    def test_string_partitions_are_rejected_without_character_splitting(self):
        with self.assertRaisesRegex(PublicError, "safe|not a string"):
            otadump.extract(self.payload, self.root / "output", partitions="boot")
        native.extract.assert_not_called()

    def test_unsafe_partition_names_raise_public_error(self):
        for name in (".", "..", "../boot", "vendor/boot", "vendor\\boot", "boot\0x"):
            with self.subTest(name=name), self.assertRaises(PublicError):
                otadump.extract(self.payload, self.root / "output", partitions=[name])
        native.extract.assert_not_called()

    def test_source_options_are_validated_before_launch(self):
        for threads in (True, 0, 2**31):
            with self.subTest(threads=threads), self.assertRaises((TypeError, ValueError)):
                otadump.extract(
                    self.payload,
                    self.root / "output",
                    source_dir=self.source,
                    num_threads=threads,
                )
        with self.assertRaisesRegex(ValueError, "verify=False"):
            otadump.extract(
                self.payload,
                self.root / "output",
                source_dir=self.source,
                verify=False,
            )

    @mock.patch.object(
        _artifact, "executable", side_effect=_artifact.ArtifactError("offline")
    )
    def test_internal_artifact_error_is_mapped(self, _executable):
        with self.assertRaisesRegex(PublicError, "offline"):
            otadump.extract(self.payload, self.root / "output", source_dir=self.source)

    def test_unchanged_api_routes_to_native_backend(self):
        otadump.extract(
            self.payload, self.root / "output", partitions=["boot"], verify=False
        )
        native.extract.assert_called_once()


class ProcessTest(unittest.TestCase):
    def test_timeout_terminates_process_and_descendant(self):
        with tempfile.TemporaryDirectory() as temporary:
            child_pid = Path(temporary) / "child.pid"
            script = (
                "import pathlib,signal,subprocess,sys,time;"
                "child=subprocess.Popen([sys.executable,'-c',"
                "'import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60)']);"
                f"pathlib.Path({str(child_pid)!r}).write_text(str(child.pid));"
                "time.sleep(60)"
            )
            with self.assertRaisesRegex(PublicError, "timed out"):
                _extract._run([sys.executable, "-c", script], 0.2)
            pid = int(child_pid.read_text())
            deadline = time.monotonic() + 2
            while Path(f"/proc/{pid}").exists() and time.monotonic() < deadline:
                state = Path(f"/proc/{pid}/stat").read_text().split()[2]
                if state == "Z":
                    break
                time.sleep(0.02)
            if Path(f"/proc/{pid}").exists() and state != "Z":
                self.fail(f"descendant {pid} survived process-group cancellation")

    @mock.patch.object(_extract.subprocess, "Popen")
    def test_timeout_maps_to_public_error(self, popen):
        process = popen.return_value
        process.pid = 99999999
        process.communicate.side_effect = subprocess.TimeoutExpired(["tool"], 1)
        process.poll.return_value = 0
        process.wait.return_value = 0
        with self.assertRaisesRegex(PublicError, "timed out"):
            _extract._run(["tool"], 1)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])

    @mock.patch.object(_extract.subprocess, "Popen")
    def test_interrupt_terminates_process(self, popen):
        process = popen.return_value
        process.pid = 99999999
        process.communicate.side_effect = KeyboardInterrupt
        process.poll.return_value = 0
        process.wait.return_value = 0
        with self.assertRaises(KeyboardInterrupt):
            _extract._run(["tool"], None)


class PublicationTest(unittest.TestCase):
    def test_interrupt_rolls_back_overwrites_and_new_images(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staging = root / "staging"
            output = root / "output"
            staging.mkdir()
            output.mkdir()
            (staging / "boot.img").write_bytes(b"new boot")
            (staging / "vendor.img").write_bytes(b"new vendor")
            (output / "boot.img").write_bytes(b"old boot")
            real_replace = os.replace
            calls = 0

            def interrupt(source, destination):
                nonlocal calls
                calls += 1
                real_replace(source, destination)
                if calls == 3:
                    raise KeyboardInterrupt

            with mock.patch.object(_extract.os, "replace", side_effect=interrupt):
                with self.assertRaises(KeyboardInterrupt):
                    _extract._publish(staging, output, None, overwrite=True)

            self.assertEqual((output / "boot.img").read_bytes(), b"old boot")
            self.assertFalse((output / "vendor.img").exists())


if __name__ == "__main__":
    unittest.main()
