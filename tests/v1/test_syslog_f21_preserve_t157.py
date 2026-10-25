import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from netops import syslog_parts as codec
import netops.cli as tested_cli

RID = "0123456789abcdef0123456789abcdef"
FOREIGN = "f" * 32
STAMP = "2026-10-24T12:34:56.123456+00:00"
MARKER = b" - netops - - - "
FIRST = b'{"record":"first","text":"' + b"a" * 2048 + b'"}\n'
ALTERNATIVE = b'{"record":"later","text":"' + b"b" * 2048 + b'"}\n'
SHORT_ALTERNATIVE = b'{"alternative":true}\n'
WARNING_SCHEMA = "netops-syslog-reassembly-warning/1"

def rows(raw=FIRST):
    messages = list(codec.encode_messages(raw, RID, STAMP))
    result = []
    for message in messages:
        header, marker, body = message.partition(MARKER)
        if marker != MARKER or len(header + marker) != 55:
            raise RuntimeError("APPARATUS_ACTUAL_ENCODED_HEADER")
        result.append(body)
    if not result:
        raise RuntimeError("APPARATUS_EMPTY_ENCODED_RECORD")
    return result

def compact(row):
    return json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

def conflicting_part(healthy):
    row = json.loads(healthy[0])
    chunk = base64.b64decode(row["data_b64"], validate=True)
    if len(chunk) != 1024:
        raise RuntimeError("APPARATUS_MULTIPART_REQUIRED")
    row["data_b64"] = base64.b64encode(bytes([chunk[0] ^ 1]) + chunk[1:]).decode("ascii")
    return compact(row)

def invalid_lines(healthy):
    row = json.loads(healthy[0])
    bad_schema = dict(row, schema=None)
    bad_data = dict(row, data_b64="@@")
    bad_type = dict(row, part=False)
    duplicate = b'{"record_id":"' + FOREIGN.encode() + b'",' + healthy[0][1:]
    return [b"{", b"\xff", b"[]", b"{}", b'{"record_id":false}', duplicate,
            compact(bad_schema), compact(bad_data), compact(bad_type), b" " + healthy[0]]

def foreign_bad_fields():
    return b'{"record_id":"' + FOREIGN.encode() + b'","part":false,"part":true,"parts":"bad"}'

class F21BytesContract(unittest.TestCase):
    def preserved(self, archive, expected=FIRST):
        try:
            actual = codec.decode_messages(iter(archive), RID)
        except codec.ReassemblyError as error:
            self.fail("T157_F21_COMPLETED_RECORD_INVALIDATED: " + str(error))
        self.assertEqual(actual, expected, "T157_F21_FROZEN_BYTES_CHANGED")

    def test_completed_bytes_survive_later_conflicting_part(self):
        healthy = rows()
        self.preserved(healthy + [conflicting_part(healthy)])

    def test_completed_bytes_survive_later_complete_alternative_set(self):
        for alternative in (ALTERNATIVE, SHORT_ALTERNATIVE):
            with self.subTest(parts=len(rows(alternative))):
                self.preserved(rows() + rows(alternative))

    def test_completed_bytes_survive_later_invalid_and_many_rows(self):
        healthy = rows()
        for bad in invalid_lines(healthy):
            with self.subTest(late_sha=hashlib.sha256(bad).hexdigest()):
                self.preserved(healthy + [bad])
        bad = invalid_lines(healthy)
        self.preserved(healthy + [bad[i % len(bad)] for i in range(256)])

    def test_completion_order_identical_retries_and_foreign_are_idempotent(self):
        healthy = rows()
        if len(healthy) != 3:
            raise RuntimeError("APPARATUS_THREE_PARTS_REQUIRED")
        archive = [healthy[2], healthy[0], healthy[0], foreign_bad_fields(), healthy[1],
                   healthy[0], healthy[2], foreign_bad_fields()]
        self.assertEqual(codec.decode_messages(iter(archive), RID), FIRST)
        short = b'{"one_part":true}\n'
        self.assertEqual(codec.decode_messages(rows(short) + rows(short), RID), short)

    def test_precompletion_conflict_sha_and_missing_remain_errors(self):
        healthy = rows()
        wrong_sha = [compact(dict(json.loads(row), sha256="0" * 64)) for row in healthy]
        cases = [[healthy[0], conflicting_part(healthy)] + healthy[1:],
                 [healthy[0], rows(ALTERNATIVE)[0]] + healthy[1:],
                 [healthy[0], compact(dict(json.loads(healthy[0]), parts=4))] + healthy[1:],
                 [b"{"] + healthy, wrong_sha, [healthy[0]] + healthy[:-1]]
        for case in cases:
            with self.subTest(archive_sha=hashlib.sha256(b"\n".join(case)).hexdigest()):
                with self.assertRaises(codec.ReassemblyError):
                    codec.decode_messages(iter(case), RID)

    def test_reader_error_after_completion_is_not_a_warning_or_byte_result(self):
        def failing():
            yield from rows()
            raise OSError("controlled synthetic archive read failure")
        with self.assertRaises(OSError):
            codec.decode_messages(failing(), RID)

class F21WarningAPI(unittest.TestCase):
    def checked_warnings(self, warnings, expected):
        self.assertEqual([(w.code, w.line_number) for w in warnings], expected)
        for warning in warnings:
            self.assertEqual(type(warning).__name__, "ReassemblyWarning")
            self.assertEqual(type(warning).__module__, "netops.syslog_parts")
            self.assertIs(type(warning.line_number), int)
            self.assertIs(type(warning.code), str)

    def test_typed_warnings_have_original_lines_and_quiet_identical_retries(self):
        healthy = rows()
        archive = healthy + [healthy[0], foreign_bad_fields(), conflicting_part(healthy), b"{", healthy[1]]
        warnings = []
        actual = codec.decode_messages(iter(archive), RID, on_warning=warnings.append)
        self.assertEqual(actual, FIRST)
        self.checked_warnings(warnings, [("late_conflict", len(healthy) + 3),
                                         ("late_invalid", len(healthy) + 4)])

    def test_many_late_invalid_rows_preserve_bytes_and_deterministic_warning_order(self):
        healthy = rows()
        bad = invalid_lines(healthy)
        archive = healthy + [bad[i % len(bad)] for i in range(256)]
        observed = []
        for unused in range(2):
            warnings = []
            self.assertEqual(codec.decode_messages(iter(archive), RID, on_warning=warnings.append), FIRST)
            expected = [("late_invalid", len(healthy) + i + 1) for i in range(256)]
            self.checked_warnings(warnings, expected)
            observed.append([(w.code, w.line_number) for w in warnings])
        self.assertEqual(observed[0], observed[1])

    def test_warning_callback_exceptions_propagate_unchanged(self):
        for error in (ValueError("controlled callback failure"), OSError("controlled callback IO")):
            with self.subTest(kind=type(error).__name__):
                def reject(warning):
                    raise error
                with self.assertRaises(type(error)) as caught:
                    codec.decode_messages(iter(rows() + [b"{"]), RID, on_warning=reject)
                self.assertIs(caught.exception, error)

class F21CLIContract(unittest.TestCase):
    def call(self, archive, read_fault=False, record_id=RID):
        temporary = tempfile.TemporaryDirectory(prefix="t157-f21-cli-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        root.chmod(0o700)
        body = b"\n".join(archive) + b"\n"
        source = root / "receiver-msg.jsonl"
        with os.fdopen(os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
        nine = lambda x: [x.st_dev, x.st_ino, x.st_mode, x.st_uid, x.st_gid, x.st_nlink,
                          x.st_size, x.st_mtime_ns, x.st_ctime_ns]
        before = nine(source.stat())
        source_dir = Path(tested_cli.__file__).resolve().parents[1]
        if not (source_dir / "netops/cli.py").is_file():
            raise RuntimeError("APPARATUS_ACTUAL_CLI_SOURCE_MISSING")
        launcher = "import sys\nfrom pathlib import Path\nsys.path.insert(0," + repr(str(source_dir)) + ")\nimport netops.cli as cli\nassert Path(cli.__file__).resolve()==" + "Path(" + repr(str(source_dir / "netops/cli.py")) + ")" + "\n"
        if read_fault:
            launcher += "incoming=sys.stdin.buffer\nfault_reached=[False]\nclass Failure:\n def __iter__(self):\n  yield from incoming\n  fault_reached[0]=True\n  raise OSError('controlled synthetic archive read failure')\n def readline(self, limit):\n  line=incoming.readline(limit)\n  if line: return line\n  fault_reached[0]=True\n  raise OSError('controlled synthetic archive read failure')\nclass Input:\n buffer=Failure()\nsys.stdin=Input()\n"
        launcher += "status=cli.main()\n"
        if read_fault:
            launcher += "if not fault_reached[0]: raise RuntimeError('CONTROLLED_READ_FAULT_NOT_REACHED')\n"
        launcher += "raise SystemExit(status)\n"
        argv = [sys.executable, "-I", "-B", "-c", launcher, "audit", "reassemble", "--record-id", record_id]
        environment = {"HOME": str(root), "PATH": "/usr/bin:/bin", "LC_ALL": "C",
                       "NETOPS_STATE_DIR": str(root / "uninitialized-state"),
                       "NETOPS_RUNTIME_DIR": str(root / "unused-runtime")}
        clock = time.monotonic()
        start = time.time_ns()
        rc, timed, error, waited = None, False, None, False
        with source.open("rb") as incoming, \
                os.fdopen(os.open(root / "cli.stdout.raw", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output, \
                os.fdopen(os.open(root / "cli.stderr.raw", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as errors:
            child = None
            try:
                child = subprocess.Popen(argv, stdin=incoming, stdout=output, stderr=errors,
                                         cwd=root, env=environment)
                try:
                    rc = child.wait(timeout=10)
                    waited = True
                except subprocess.TimeoutExpired:
                    timed = True
                    child.kill()
                    try:
                        rc = child.wait(timeout=2)
                        waited = True
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
        after = nine(source.stat())
        after_bytes = source.read_bytes()
        process = {"argv": argv, "pid": None if child is None else child.pid, "parent_pid": os.getpid(),
                   "start_ns": start, "end_ns": time.time_ns(), "elapsed_seconds": time.monotonic() - clock,
                   "wait_rc": rc, "wait_observed": waited, "timed_out": timed, "error_type": error,
                   "stdout_bytes": len(actual), "stdout_sha256": hashlib.sha256(actual).hexdigest(),
                   "stderr_bytes": len(diagnostic), "stderr_sha256": hashlib.sha256(diagnostic).hexdigest(),
                   "archive_before9": before, "archive_after9": after,
                   "archive_before_sha256": hashlib.sha256(body).hexdigest(),
                   "archive_after_sha256": hashlib.sha256(after_bytes).hexdigest(),
                   "controlled_read_fault": read_fault}
        with os.fdopen(os.open(root / "cli.process.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as proof:
            proof.write((json.dumps(process, sort_keys=True) + "\n").encode())
            proof.flush()
            os.fsync(proof.fileno())
        if timed or error is not None or not waited:
            raise RuntimeError("APPARATUS_ACTUAL_CLI_TIMEOUT_OR_WAIT_UNKNOWN")
        self.assertEqual(after, before, "T157_F21_ARCHIVE_METADATA_CHANGED")
        self.assertEqual(after_bytes, body, "T157_F21_ARCHIVE_BYTES_CHANGED")
        return rc, actual, diagnostic

    def warnings(self, diagnostic, expected):
        self.assertTrue(diagnostic.endswith(b"\n"), "T157_F21_WARNING_MISSING_LF")
        self.assertTrue(all(value < 128 for value in diagnostic), "T157_F21_WARNING_NOT_ASCII")
        self.assertNotIn(b" ", diagnostic, "T157_F21_WARNING_NOT_COMPACT")
        self.assertNotIn(b"\t", diagnostic, "T157_F21_WARNING_TAB")
        self.assertNotIn(b"\r", diagnostic, "T157_F21_WARNING_CR")
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("Duplicate warning field")
                result[key] = value
            return result
        try:
            warnings = [json.loads(line, object_pairs_hook=unique) for line in diagnostic[:-1].split(b"\n")]
        except (ValueError, UnicodeError):
            self.fail("T157_F21_WARNING_NOT_JSON")
        for warning in warnings:
            self.assertIs(type(warning), dict)
            self.assertEqual(set(warning), {"schema", "code", "line_number"})
            self.assertEqual(warning["schema"], WARNING_SCHEMA)
            self.assertIs(type(warning["line_number"]), int)
        self.assertEqual([(w["code"], w["line_number"]) for w in warnings], expected,
                         "T157_F21_WARNING_CODE_OR_ARCHIVE_LINE")

    def test_cli_later_part_keeps_exact_first_bytes_and_warning_exit3(self):
        healthy = rows()
        rc, actual, diagnostic = self.call(healthy + [conflicting_part(healthy)])
        self.assertEqual((rc, actual), (3, FIRST), "T157_F21_CLI_LATE_PART_INVALIDATED_ACCEPTED_RECORD")
        self.warnings(diagnostic, [("late_conflict", len(healthy) + 1)])

    def test_cli_later_complete_alternative_set_keeps_first_bytes_and_exit3(self):
        healthy = rows()
        for raw in (ALTERNATIVE, SHORT_ALTERNATIVE):
            alternative = rows(raw)
            with self.subTest(parts=len(alternative)):
                rc, actual, diagnostic = self.call(healthy + alternative)
                self.assertEqual((rc, actual), (3, FIRST), "T157_F21_CLI_ALTERNATIVE_INVALIDATED_ACCEPTED_RECORD")
                self.warnings(diagnostic, [("late_conflict", len(healthy) + i + 1) for i in range(len(alternative))])

    def test_cli_many_later_invalid_rows_keep_bytes_and_deterministic_line_warnings(self):
        healthy = rows()
        bad = invalid_lines(healthy)
        archive = healthy + [bad[i % len(bad)] for i in range(256)]
        diagnostics = []
        for unused in range(2):
            rc, actual, diagnostic = self.call(archive)
            self.assertEqual((rc, actual), (3, FIRST), "T157_F21_CLI_LATE_INVALID_INVALIDATED_ACCEPTED_RECORD")
            self.warnings(diagnostic, [("late_invalid", len(healthy) + i + 1) for i in range(256)])
            diagnostics.append(diagnostic)
        self.assertEqual(diagnostics[0], diagnostics[1])

    def test_cli_clean_identical_retry_and_foreign_are_exit0_without_warnings(self):
        healthy = rows()
        rc, actual, diagnostic = self.call([foreign_bad_fields()] + healthy + [healthy[0], foreign_bad_fields()])
        self.assertEqual((rc, actual, diagnostic), (0, FIRST, b""))

    def test_cli_precompletion_invalid_or_conflict_are_error2_without_output(self):
        healthy = rows()
        cases = [([b"{"] + healthy, b"line_1"),
                 ([healthy[0], conflicting_part(healthy)] + healthy[1:], b"line_2"),
                 ([healthy[0], compact(dict(json.loads(healthy[0]), parts=4))] + healthy[1:], b"line_2"),
                 (healthy[:-1], b"after_line_2")]
        for archive, location in cases:
            with self.subTest(archive_sha=hashlib.sha256(b"\n".join(archive)).hexdigest()):
                rc, actual, diagnostic = self.call(archive)
                self.assertEqual((rc, actual), (2, b""))
                self.assertEqual(diagnostic, b"netops: reassembly_validation_error " + location + b"\n")

    def test_cli_read_failure_after_completion_is_error2_and_empty_stdout(self):
        healthy = rows()
        for late in ([], [b"{"]):
            with self.subTest(warning_before_io=bool(late)):
                rc, actual, diagnostic = self.call(healthy + late, read_fault=True)
                self.assertEqual((rc, actual), (2, b""))
                location = ("after_line_" + str(len(healthy) + len(late))).encode("ascii")
                expected_error = b"netops: reassembly_read_error " + location + b"\n"
                self.assertTrue(diagnostic.endswith(expected_error))
                self.assertNotIn(b"controlled synthetic", diagnostic)
                prefix = diagnostic[:-len(expected_error)]
                if late:
                    self.warnings(prefix, [("late_invalid", len(healthy) + 1)])
                else:
                    self.assertEqual(prefix, b"")

    def test_invalid_explicit_record_id_is_typed_argument_error_before_read(self):
        for record_id in (RID.upper(), RID[:-1]):
            with self.subTest(record_id=record_id):
                def unread():
                    raise RuntimeError("APPARATUS_ARGUMENT_VALIDATION_READ_INPUT")
                    yield b"{"
                with self.assertRaises(ValueError):
                    codec.decode_messages(unread(), record_id)
                rc, actual, diagnostic = self.call([b"{"], record_id=record_id)
                self.assertEqual((rc, actual, diagnostic),
                                 (2, b"", b"netops: reassembly_argument_error line_0\n"))

if __name__ == "__main__":
    unittest.main(verbosity=2)
