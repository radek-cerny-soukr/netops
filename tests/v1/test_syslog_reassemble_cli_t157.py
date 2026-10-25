import hashlib
import os
import subprocess
import time
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from netops.audit import Audit, SYSLOG_MIN_RATE
from netops.files import write_private
from netops.syslog_parts import MAX_MESSAGE_BYTES, encode_messages, decode_messages
import netops.cli as tested_cli

RID = "0123456789abcdef0123456789abcdef"
STAMP = "2026-10-24T12:34:56.123456+00:00"
MARKER = b" - netops - - - "

def archive(raw):
    return b"\n".join(message.split(MARKER, 1)[1] for message in encode_messages(raw, RID, STAMP)) + b"\n"

def foreign(length):
    head = b'{"record_id":"' + b"f" * 32 + b'","pad":"'
    return head + b"x" * (length - len(head) - 2) + b'"}'

def warning(code, line_number):
    return json.dumps({"schema": "netops-syslog-reassembly-warning/1", "code": code,
                       "line_number": line_number}, separators=(",", ":"), ensure_ascii=True) + "\n"

class ReassembleCLI(unittest.TestCase):
    def call(self, body, record_id=RID):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "receiver-msg.jsonl"
            source.write_bytes(body)
            source.chmod(0o600)
            before = source.stat()
            source_dir = Path(tested_cli.__file__).resolve().parents[1]
            if not (source_dir / "netops/cli.py").is_file():
                raise RuntimeError("APPARATUS_CLI_SOURCE_MISSING")
            launcher = "import sys;sys.path.insert(0," + repr(str(source_dir)) + ");from netops.cli import main;raise SystemExit(main())"
            argv = [sys.executable, "-I", "-B", "-c", launcher, "audit", "reassemble"]
            if record_id is not None:
                argv += ["--record-id", record_id]
            environment = {"HOME": str(root), "PATH": "/usr/bin:/bin", "LC_ALL": "C",
                           "NETOPS_STATE_DIR": str(root / "uninitialized-state"),
                           "NETOPS_RUNTIME_DIR": str(root / "unused-runtime")}
            clock = time.monotonic()
            start = time.time_ns()
            rc, timed, error = None, False, None
            with source.open("rb") as incoming, \
                    os.fdopen(os.open(root / "cli.stdout.raw", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output, \
                    os.fdopen(os.open(root / "cli.stderr.raw", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as errors:
                child = None
                try:
                    child = subprocess.Popen(argv, stdin=incoming, stdout=output, stderr=errors,
                                             cwd=root, env=environment)
                    try:
                        rc = child.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        timed = True
                        child.kill()
                        try:
                            rc = child.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            error = "WAIT_UNKNOWN"
                except OSError as exception:
                    error = type(exception).__name__
                output.flush()
                os.fsync(output.fileno())
                errors.flush()
                os.fsync(errors.fileno())
            actual = (root / "cli.stdout.raw").read_bytes()
            diagnostic = (root / "cli.stderr.raw").read_bytes()
            process = {"argv": argv, "pid": child.pid if child is not None else None, "parent_pid": os.getpid(),
                       "start_ns": start, "end_ns": time.time_ns(),
                       "elapsed_seconds": time.monotonic() - clock, "wait_rc": rc,
                       "timed_out": timed, "error_type": error,
                       "stdout_bytes": len(actual), "stdout_sha256": hashlib.sha256(actual).hexdigest(),
                       "stderr_bytes": len(diagnostic), "stderr_sha256": hashlib.sha256(diagnostic).hexdigest()}
            with os.fdopen(os.open(root / "cli.process.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as proof:
                proof.write((json.dumps(process, sort_keys=True) + "\n").encode())
                proof.flush()
                os.fsync(proof.fileno())
            if timed or error is not None:
                raise RuntimeError("APPARATUS_CLI_TIMEOUT_OR_WAIT_UNKNOWN")
            after = source.stat()
            self.assertEqual((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns),
                             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))
            self.assertEqual(source.read_bytes(), body)
        return rc, actual, diagnostic.decode("utf-8", "strict")

    def test_offline_exact_bytes_and_input_archive_unchanged(self):
        raw = '{"text":"ž🚦","value":null}\n'.encode("utf-8")
        rc, output, error = self.call(archive(raw))
        self.assertEqual((rc, output, error), (0, raw, ""))

    def test_required_and_invalid_explicit_record_id_never_write_output(self):
        for record_id in (None, RID.upper(), RID[:-1], RID + "0"):
            with self.subTest(record_id=record_id):
                rc, output, error = self.call(archive(b'{"ok":true}\n'), record_id)
                self.assertEqual((rc, output), (2, b""))
                if record_id is None:
                    self.assertIn("record", error.lower())
                else:
                    self.assertEqual(error, "netops: reassembly_argument_error line_0\n")

    def test_unattributable_late_row_reports_original_line_and_withholds_all_output(self):
        raw = b'{"text":"' + b"x" * 3000 + b'"}\n'
        healthy = archive(raw)
        line = healthy.count(b"\n") + 1
        for bad in (b"{\n", b"\xff\n", b"{}\n", b"[]\n"):
            with self.subTest(raw_sha=hashlib.sha256(bad).hexdigest()):
                rc, output, error = self.call(bad + healthy)
                self.assertEqual((rc, output, error),
                                 (2, b"", "netops: reassembly_validation_error line_1\n"))
                self.assertEqual(self.call(healthy + bad), (3, raw, warning("late_invalid", line)))

    def test_duplicate_id_after_complete_record_fails_entire_selection(self):
        healthy = archive(b'{"ok":true}\n')
        row = healthy.splitlines()[0]
        for record_id in (RID, "f" * 32):
            bad = b'{"record_id":"' + record_id.encode() + b'",' + row[1:]
            self.assertEqual(self.call(bad + b"\n" + healthy),
                             (2, b"", "netops: reassembly_validation_error line_1\n"))
            self.assertEqual(self.call(healthy + bad + b"\n"),
                             (3, b'{"ok":true}\n', warning("late_invalid", 2)))

    def test_foreign_unique_id_bad_fields_do_not_poison_selected_record(self):
        raw = b'{"ok":true}\n'
        foreign = b'{"record_id":"' + b"f" * 32 + b'","part":false,"part":true,"parts":"bad","schema":null}\n'
        rc, output, error = self.call(foreign + archive(raw))
        self.assertEqual((rc, output, error), (0, raw, ""))

    def test_selected_other_key_order_is_accepted_but_external_whitespace_is_not(self):
        raw = b'{"ok":true}\n'
        row = json.loads(archive(raw))
        reordered = json.dumps(dict(reversed(list(row.items()))), separators=(",", ":")).encode()
        self.assertEqual(self.call(reordered + b"\n"), (0, raw, ""))
        for body in (b" " + reordered + b"\n", reordered + b" \n"):
            rc, output, error = self.call(body)
            self.assertEqual((rc, output), (2, b""))
            self.assertEqual(error, "netops: reassembly_validation_error line_1\n")

    def test_missing_part_reports_archive_end_without_emitting_a_prefix(self):
        rows = archive(b'{"text":"' + b"x" * 3000 + b'"}\n').splitlines(keepends=True)
        rc, output, error = self.call(b"".join(rows[:-1]))
        self.assertEqual((rc, output), (2, b""))
        self.assertEqual(error, "netops: reassembly_validation_error after_line_" + str(len(rows) - 1) + "\n")

    def test_selected_type_error_is_not_hidden_by_healthy_duplicate(self):
        healthy = archive(b'{"ok":true}\n')
        row = json.loads(healthy)
        row["part"] = False
        bad = json.dumps(row, separators=(",", ":")).encode() + b"\n"
        self.assertEqual(self.call(bad + healthy),
                         (2, b"", "netops: reassembly_validation_error line_1\n"))
        self.assertEqual(self.call(healthy + bad),
                         (3, b'{"ok":true}\n', warning("late_invalid", 2)))

    def test_whole_sha_mismatch_reports_completion_line_before_later_rows(self):
        healthy = archive(b'{"text":"' + b"x" * 3000 + b'"}\n').splitlines()
        rows = []
        for body in healthy:
            row = json.loads(body)
            row["sha256"] = "0" * 64
            rows.append(json.dumps(row, separators=(",", ":")).encode())
        for tail in (b"", b"{\n"):
            with self.subTest(later_invalid=bool(tail)):
                self.assertEqual(self.call(b"\n".join(rows) + b"\n" + tail),
                                 (2, b"", "netops: reassembly_validation_error line_3\n"))

    def test_line_at_read_limit_is_a_line_and_longer_is_invalid(self):
        raw = b'{"ok":true}\n'
        healthy = archive(raw)
        for length in (MAX_MESSAGE_BYTES, MAX_MESSAGE_BYTES + 1):
            with self.subTest(length=length):
                self.assertEqual(len(foreign(length)), length)
                self.assertEqual(self.call(foreign(length) + b"\n" + healthy), (0, raw, ""))
        for length in (MAX_MESSAGE_BYTES + 2, MAX_MESSAGE_BYTES + 3, 5 * MAX_MESSAGE_BYTES + 7):
            with self.subTest(length=length):
                self.assertEqual(self.call(foreign(length) + b"\n" + healthy),
                                 (2, b"", "netops: reassembly_validation_error line_1\n"))

    def test_overlong_line_before_completion_is_validation_error_with_its_line(self):
        rows = archive(b'{"text":"' + b"x" * 3000 + b'"}\n').splitlines(keepends=True)
        long = foreign(3 * MAX_MESSAGE_BYTES) + b"\n"
        self.assertEqual(self.call(rows[0] + long + b"".join(rows[1:])),
                         (2, b"", "netops: reassembly_validation_error line_2\n"))

    def test_overlong_line_after_completion_is_late_invalid_and_numbering_continues(self):
        raw = b'{"text":"' + b"x" * 3000 + b'"}\n'
        healthy = archive(raw)
        line = healthy.count(b"\n") + 1
        long = foreign(3 * MAX_MESSAGE_BYTES)
        self.assertEqual(self.call(healthy + long + b"\n" + healthy + b"{\n"),
                         (3, raw, warning("late_invalid", line) + warning("late_invalid", 2 * line)))
        self.assertEqual(self.call(healthy + long), (3, raw, warning("late_invalid", line)))

class FramedBudget(unittest.TestCase):
    def test_timeout_uses_all_actual_framed_bytes_and_persistent_queue_id(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            audit = Audit(root / "audit", {"mode": "syslog", "host": "receiver.invalid", "port": 6514})
            queued = audit.directory / ("1792843200000000000-" + RID + ".queue")
            raw = b'{"text":"' + b"x" * 8192 + b'"}\n'
            write_private(queued, raw)
            context, channel = MagicMock(), MagicMock()
            context.wrap_socket.return_value.__enter__.return_value = channel
            with patch("netops.audit.socket.create_connection") as connection, \
                 patch("netops.audit.ssl.create_default_context", return_value=context):
                audit._send(queued)
            frames = [call.args[0] for call in channel.sendall.call_args_list]
            self.assertGreater(len(frames), 1)
            expected = 10 + sum(map(len, frames)) / SYSLOG_MIN_RATE
            self.assertEqual(connection.call_args.kwargs["timeout"], expected)
            channel.settimeout.assert_called_once_with(expected)
            self.assertGreater(sum(map(len, frames)), len(raw))
            messages = []
            for frame in frames:
                prefix, _, message = frame.partition(b" ")
                self.assertEqual(int(prefix), len(message))
                self.assertLessEqual(len(message), 1618)
                row = json.loads(message.split(MARKER, 1)[1])
                self.assertEqual(row["record_id"], RID)
                messages.append(message.split(MARKER, 1)[1])
            self.assertEqual(decode_messages(messages, RID), raw)
            self.assertFalse(queued.exists())

if __name__ == "__main__":
    unittest.main(verbosity=2)
