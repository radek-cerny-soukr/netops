import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import redteam
import process_profile_privacy
from test_redteam_process_profile import Context


class ProcessCollectorCapture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.capture = self.root / "process-profile-collector"
        self.token = "S" * 64
        self.current = "T" * 64
        self.token_file = self.root / "token"
        self.token_file.write_text(self.current)
        self.token_file.chmod(0o600)

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, *, rc=17, stdout="full collector output\n", stderr="full collector diagnostic\n", error=None):
        ctx = Context()
        ctx.args.process_profile_dir = str(self.capture)
        ctx.process_profile_token = self.token
        done = SimpleNamespace(returncode=rc, stdout=stdout, stderr=stderr)
        with mock.patch.dict(os.environ, {"HOME": "/synthetic/runner", "DOCKER_HOST": "unix:///var/run/docker.sock"}, clear=True), \
             mock.patch.object(redteam.sys, "platform", "linux"), mock.patch.object(redteam.os, "geteuid", return_value=0), \
             mock.patch.object(redteam.subprocess, "run", return_value=done, side_effect=error) as run:
            redteam.check_processes(ctx)
        self.assertEqual(len(ctx.items), 1)
        self.assertEqual(ctx.items[0][2], "FAIL")
        return run

    def captures(self):
        self.assertTrue(self.capture.is_dir(), "completed collector streams were not retained")
        self.assertEqual({p.name for p in self.capture.iterdir()}, {"collector.stdout", "collector.stderr", "result.json"})
        self.assertEqual(self.capture.stat().st_mode & 0o777, 0o700)
        for path in self.capture.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        return json.loads((self.capture / "result.json").read_bytes())

    def rewrite(self, *, stdout=None, stderr=None, change=None):
        result = self.captures()
        for key, value in (("stdout", stdout), ("stderr", stderr)):
            if value is not None:
                (self.capture / ("collector." + key)).write_bytes(value)
                result[key + "_bytes"] = len(value)
                result[key + "_sha256"] = hashlib.sha256(value).hexdigest()
        if change:
            change(result)
        (self.capture / "result.json").write_text(json.dumps(result))

    def privacy(self, env=None):
        return process_profile_privacy.check_captures(self.capture, self.token_file, env or {})

    def test_nonzero_retains_complete_streams_before_generic_failure(self):
        run = self.invoke()
        result = self.captures()
        self.assertEqual((self.capture / "collector.stdout").read_bytes(), b"full collector output\n")
        self.assertEqual((self.capture / "collector.stderr").read_bytes(), b"full collector diagnostic\n")
        self.assertEqual(result["actual_rc"], 17)
        self.assertFalse(result["timed_out"])
        self.assertEqual(run.call_args.kwargs["timeout"], 150)
        self.assertTrue(run.call_args.kwargs["text"])

    def test_malformed_zero_result_is_retained_and_cannot_pass(self):
        self.invoke(rc=0, stdout="not-json\n", stderr="entire diagnostic\n")
        self.assertEqual(self.captures()["actual_rc"], 0)
        self.assertEqual((self.capture / "collector.stdout").read_bytes(), b"not-json\n")

    def test_timeout_preserves_exact_partial_bytes_and_unknown_actual_rc(self):
        error = subprocess.TimeoutExpired("synthetic-collector", 150, output=b"partial\0stdout", stderr=b"partial-stderr\xff")
        self.invoke(error=error)
        result = self.captures()
        self.assertIsNone(result["actual_rc"])
        self.assertTrue(result["timed_out"])
        self.assertEqual((self.capture / "collector.stdout").read_bytes(), error.stdout)
        self.assertEqual((self.capture / "collector.stderr").read_bytes(), error.stderr)
        self.assertFalse(self.privacy()["upload_allowed"])

    def test_duplicate_file_directory_and_symlink_paths_never_run_child(self):
        foreign = self.root / "foreign"
        foreign.mkdir()
        (foreign / "sentinel").write_bytes(b"unchanged")
        for kind in ("file", "directory", "symlink"):
            with self.subTest(case=kind):
                if kind == "file":
                    self.capture.write_bytes(b"unchanged")
                elif kind == "directory":
                    self.capture.mkdir()
                else:
                    self.capture.symlink_to(foreign, target_is_directory=True)
                self.invoke().assert_not_called()
                if kind == "directory":
                    self.capture.rmdir()
                else:
                    self.capture.unlink()
        self.assertEqual((foreign / "sentinel").read_bytes(), b"unchanged")

    def test_safe_captures_use_existing_gate_without_changing_failure(self):
        self.invoke(rc=0, stdout="{}\n", stderr="")
        result = self.captures()
        self.assertEqual(result["mcp_token_scan"], "PASS")
        proof = self.privacy()
        self.assertTrue(proof["upload_allowed"], proof)

    def test_original_token_before_rotation_is_never_persisted_as_scan_input(self):
        self.invoke(stderr=self.token)
        self.assertEqual(self.captures()["mcp_token_scan"], "FAIL")
        proof = self.privacy()
        self.assertFalse(proof["upload_allowed"])
        self.assertEqual(proof["reason"], "original-token-scan-refused")
        self.assertNotIn(self.token, json.dumps(proof))

    def test_current_and_registry_tokens_refuse_coherent_updated_captures(self):
        self.invoke(rc=0, stdout="{}\n", stderr="")
        for name, value in (("MCP", self.current), ("GITHUB_TOKEN", "synthetic-github-token"), ("GHCR_TOKEN", "synthetic-registry-token"), ("REGISTRY_TOKEN", "synthetic-other-token")):
            with self.subTest(case=name):
                self.rewrite(stderr=value.encode())
                proof = self.privacy({} if name == "MCP" else {name: value})
                self.assertFalse(proof["upload_allowed"])
                self.assertEqual(proof["reason"], "known-token-found")
                self.assertNotIn(value, json.dumps(proof))

    def test_malformed_binding_unknown_file_modes_and_private_paths_refuse_upload(self):
        self.invoke(rc=0, stdout="{}\n", stderr="")
        good = (self.capture / "result.json").read_bytes()
        for change in (lambda result: result.update(actual_rc=True), lambda result: result.update(stdout_sha256="0" * 64), lambda result: result.update(mcp_token_scan="UNKNOWN")):
            with self.subTest(case="metadata"):
                self.rewrite(change=change)
                self.assertFalse(self.privacy()["upload_allowed"])
                (self.capture / "result.json").write_bytes(good)
        extra = self.capture / "unknown"
        extra.write_bytes(b"not uploaded")
        self.assertFalse(self.privacy()["upload_allowed"])
        extra.unlink()
        output = self.capture / "collector.stdout"
        output.chmod(0o644)
        self.assertFalse(self.privacy()["upload_allowed"])
        output.chmod(0o600)
        self.rewrite(stderr=("/" + "home" + "/synthetic-private/path").encode())
        proof = self.privacy()
        self.assertFalse(proof["upload_allowed"])
        self.assertEqual(proof["reason"], "public-privacy-findings")
        self.assertNotIn("synthetic-private", json.dumps(proof))
        self.rewrite(stderr=("-----BEGIN PRIVATE KEY-----\n" + "A" * 80 + "\n-----END PRIVATE KEY-----\n").encode())
        proof = self.privacy()
        self.assertFalse(proof["upload_allowed"])
        self.assertEqual(proof["findings"].get("private key material"), 1)
        self.assertFalse(self.privacy({"GITHUB_ACTIONS": "true"})["upload_allowed"])


if __name__ == "__main__":
    unittest.main()
