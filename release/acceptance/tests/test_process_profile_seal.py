"""Finite unit boundaries for confidential capture sealing; no network or cryptography."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("process_profile_seal", HERE / "process_profile_seal.py")
sealer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sealer)
ORIGINAL_ARCHIVE_BINARY = sealer.archive_binary

def fixture(path):
    path.mkdir(mode=0o700)
    raw = {"collector.stdout": b'{"cgroup":"/system.slice/docker-synthetic.scope"}\nSYNTHETIC\0\xff\n',
           "collector.stderr": b"S" * 64 + b"\n"}
    result = {"schema": "netops-process-profile-collector/1", "actual_rc": 17, "timed_out": False,
              "timeout_seconds": 150, "outcome": "completed", "mcp_token_scan": "FAIL"}
    for name in ("stdout", "stderr"):
        result[name + "_bytes"] = len(raw["collector." + name])
        result[name + "_sha256"] = sealer.sha(raw["collector." + name])
    raw["result.json"] = (json.dumps(result, sort_keys=True) + "\n").encode()
    for name, data in raw.items():
        sealer.create(path / name, data)
    return raw

class AgeSealer(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.capture = self.root / "process-profile-collector"
        self.raw = fixture(self.capture)
        self.tool = self.root / "tool"
        self.arch = sealer.MACHINES[platform.machine()]
        patcher = mock.patch.object(sealer, "archive_binary", return_value=b"SYNTHETIC_PINNED_BINARY")
        patcher.start(); self.addCleanup(patcher.stop)
        patcher = mock.patch.object(sealer.subprocess, "run", side_effect=self.child)
        patcher.start(); self.addCleanup(patcher.stop)
        with mock.patch.dict(os.environ, {}, clear=True):
            sealer.install(self.tool, self.arch, b"SYNTHETIC_ARCHIVE")

    def child(self, command, **kwargs):
        if command[-1] == "--version":
            return subprocess.CompletedProcess(command, 0, b"v1.3.2\n", b"")
        self.assertEqual(command[1:3], ["--encrypt", "--recipients-file"])
        self.plaintext = kwargs["input"]
        kwargs["stdout"].write(b"age-encryption.org/v1\n" + b"SYNTHETIC_CIPHERTEXT" * 16)
        kwargs["stdout"].flush()
        return subprocess.CompletedProcess(command, 0, None, b"")

    def test_native_install_exact_archive_binary_and_version(self):
        raw, _ = sealer.snapshot(self.tool, sealer.TOOL_FILES, ("age",))
        self.assertEqual(raw["archive.tar.gz"], b"SYNTHETIC_ARCHIVE")
        self.assertEqual(raw["age"], b"SYNTHETIC_PINNED_BINARY")
        self.assertEqual(raw["version.stdout"], b"v1.3.2\n")
        self.assertEqual(raw["version.stderr"], b"")
        with self.assertRaises(sealer.Refused):
            ORIGINAL_ARCHIVE_BINARY(b"wrong-unpinned-archive", self.arch)

    def test_full_confidential_capture_and_exact_original_tar(self):
        before = sealer.snapshot(self.capture, sealer.CAPTURES)
        metadata = sealer.seal(self.capture, self.tool)
        output = self.root / "process-profile-sealed"
        self.assertEqual(set(p.name for p in output.iterdir()), {"collector.tar.age", "sealed.json"})
        self.assertEqual(sealer.sha((output / "collector.tar.age").read_bytes()), metadata["ciphertext_sha256"])
        self.assertEqual(sealer.snapshot(self.capture, sealer.CAPTURES), before)
        self.assertNotIn("S" * 64, json.dumps(metadata))
        with tarfile.open(fileobj=io.BytesIO(self.plaintext)) as archive:
            rows = archive.getmembers()
            self.assertEqual([row.name for row in rows], list(sealer.CAPTURES))
            self.assertTrue(all(row.isfile() and row.mode == 0o600 for row in rows))
            self.assertEqual({row.name: archive.extractfile(row).read() for row in rows}, self.raw)

    def test_timeout_capture_null_rc_remains_sealable(self):
        result = json.loads((self.capture / "result.json").read_bytes())
        result.update(actual_rc=None, timed_out=True, outcome="timeout")
        (self.capture / "result.json").write_text(json.dumps(result))
        sealer.seal(self.capture, self.tool)
        self.assertIsNone(json.loads((self.capture / "result.json").read_bytes())["actual_rc"])

    def test_coherent_raw_edit_is_sealed_but_bad_binding_and_bool_rc_refuse(self):
        result_path = self.capture / "result.json"
        result = json.loads(result_path.read_bytes())
        result["actual_rc"] = True
        result_path.write_text(json.dumps(result))
        with mock.patch.object(sealer, "execute") as child:
            with self.assertRaises(sealer.Refused):
                sealer.seal(self.capture, self.tool)
            child.assert_not_called()
        result["actual_rc"] = 17
        result["stdout_sha256"] = "0" * 64
        result_path.write_text(json.dumps(result))
        with self.assertRaises(sealer.Refused):
            sealer.seal(self.capture, self.tool)
        changed = b"COHERENT_SYNTHETIC_FULL_RAW\0\xfe"
        (self.capture / "collector.stdout").write_bytes(changed)
        result.update(stdout_sha256=sealer.sha(changed), stdout_bytes=len(changed))
        result_path.write_text(json.dumps(result))
        sealer.seal(self.capture, self.tool)

    def test_missing_extra_symlink_hardlink_and_mode_refuse_before_child(self):
        target = self.capture / "collector.stderr"; original = target.read_bytes()
        for kind in ("missing", "extra", "symlink", "hardlink", "mode"):
            with self.subTest(kind=kind):
                if kind == "extra":
                    extra = self.capture / "unknown"; extra.write_bytes(b"foreign")
                elif kind == "mode":
                    target.chmod(0o644)
                else:
                    target.unlink()
                    if kind == "symlink":
                        target.symlink_to(self.capture / "collector.stdout")
                    elif kind == "hardlink":
                        os.link(self.capture / "collector.stdout", target)
                with mock.patch.object(sealer, "execute") as child:
                    with self.assertRaises((sealer.Refused, OSError)):
                        sealer.seal(self.capture, self.tool)
                    child.assert_not_called()
                if kind == "extra":
                    extra.unlink()
                elif kind == "mode":
                    target.chmod(0o600)
                else:
                    if target.is_symlink() or target.exists(): target.unlink()
                    sealer.create(target, original)

    def test_production_fourth_or_changed_recipient_rejected(self):
        original = sealer.recipient_bytes()
        example = b"age1" + b"q" * 58 + b"\n"
        copy = self.root / "process_profile_recipients.txt"
        for changed in (original + example, example + b"\n".join(original.splitlines()[1:]) + b"\n"):
            copy.write_bytes(changed); copy.chmod(0o600)
            with mock.patch.object(sealer, "__file__", str(self.root / "process_profile_seal.py")):
                with self.assertRaises(sealer.Refused):
                    sealer.recipient_bytes()
                
                with mock.patch.object(sealer, "RECIPIENT_FILE_SHA256", sealer.sha(changed)):
                    with self.assertRaises(sealer.Refused):
                        sealer.recipient_bytes()

    def test_output_collision_preserves_sentinel_and_never_runs_encrypt(self):
        output = self.root / "process-profile-sealed"; output.mkdir(mode=0o700)
        (output / "sentinel").write_bytes(b"unchanged")
        with mock.patch.object(sealer, "execute") as child:
            with self.assertRaises(FileExistsError):
                sealer.seal(self.capture, self.tool)
            child.assert_not_called()
        self.assertEqual((output / "sentinel").read_bytes(), b"unchanged")

    def test_age_timeout_partial_stderr_retained_and_no_success_manifest(self):
        error = subprocess.TimeoutExpired("synthetic-age", 150, output=b"", stderr=b"partial\0stderr\xff")
        with mock.patch.object(sealer.subprocess, "run", side_effect=error):
            with self.assertRaises(sealer.Refused):
                sealer.seal(self.capture, self.tool)
        private = self.root / "process-profile-seal-private"
        self.assertEqual((private / "encrypt.stderr").read_bytes(), error.stderr)
        self.assertEqual(json.loads((private / "encrypt.json").read_bytes()), {"actual_rc": None, "timed_out": True})
        self.assertFalse((self.root / "process-profile-sealed/sealed.json").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
