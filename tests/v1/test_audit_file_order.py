import contextlib
import io
import itertools
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from netops import cli
from netops.audit import Audit
from netops.files import UIDS, write_private

BASE = 1792000000000000000
SECOND = BASE // 10**9
NO_RESPONSE = "no response recorded; the operation may have completed; do not retry writes automatically"
LEFT = "client left before dispatch; the operation was not executed"
NOT_EXECUTED = "interrupted before dispatch; the operation was not executed"
MAY_INTERRUPTED = "interrupted before a result was recorded; the operation may have completed; inspect the device before any repeat"
WITHHELD = "response withheld because the token changed; the operation may have completed; inspect status and the device"
ABANDONED = {"phase": "before_dispatch", "complete_body": True, "received_bytes": 100, "operation_executed": False}
RECORDED_INTERRUPTED = "interrupted; a response is recorded; the client may not have received it; inspect audit export, status and the actual device before any repeat; do not retry writes automatically"
CANCELLED = {"delivery": "interrupted", "automatic_retry": False, "operation_may_have_completed": True}
FAILED = {"error": "operation_failed", "automatic_retry": False}


def record(direction, correlation, number, payload=None):
    if payload is None and direction == "request":
        payload = {"jsonrpc": "2.0", "id": number, "method": "tools/call", "params": {"name": "synthetic_tool", "arguments": {}}}
    elif payload is None:
        payload = {"jsonrpc": "2.0", "id": number, "result": {}}
    return {"time": "2026-01-01T00:00:%02d+00:00" % (number % 60), "direction": direction, "correlation": correlation, "payload": payload}


def admin(result):
    return {"jsonrpc": "2.0", "id": 1, "result": {"content": [], "structuredContent": {"result": {"result": result}}, "isError": False}}


def encode(*records):
    return b"".join(json.dumps(item).encode() + b"\n" for item in records)


def chain(correlation, number):
    return [record("request", correlation, number), record("response", correlation, number), record("connection_end", correlation, number)]


def queue_name(ns, unique):
    return "%d-%032x.queue" % (ns, unique)


def queue_files(count, start=BASE):
    files = []
    for number in range(count):
        for step, item in enumerate(chain("c%02d" % number, number)):
            files.append((queue_name(start + number * 1000 + step * 100, number * 3 + step), encode(item)))
    return files


def pairs(rows):
    return [(item["correlation"], item["direction"]) for item in rows]


class StateDirectory:
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.state = Path(self.temporary.name)
        self.audit = self.state / "gateway" / "audit"
        self.audit.mkdir(parents=True, mode=0o700)
        write_private(self.state / "gateway" / "config.json", b"{}", UIDS["gateway"])

    def put(self, name, data, second=SECOND):
        write_private(self.audit / name, data, UIDS["gateway"])
        os.utime(self.audit / name, ns=(second * 10**9, second * 10**9))

    def clear(self):
        for path in self.audit.iterdir():
            path.unlink()

    def cli(self, *arguments):
        env = dict(os.environ, NETOPS_STATE_DIR=str(self.state))
        process = subprocess.run([sys.executable, "-B", "-m", "netops", "audit", *arguments], capture_output=True, text=True, env=env, timeout=60)
        if process.returncode != 0:
            raise AssertionError("audit %s rc=%s stderr=%s" % (" ".join(arguments), process.returncode, process.stderr[-400:]))
        return [json.loads(line) for line in process.stdout.splitlines() if line.startswith("{")]

    def sequence(self):
        return pairs(self.cli("tail", "--lines", "10000"))

    def inline(self, action, rank=None):
        real_glob = Path.glob
        def glob(path, pattern, *args, **kwargs):
            found = list(real_glob(path, pattern, *args, **kwargs))
            return sorted(found, key=lambda item: rank[item.name]) if rank else found
        argv = ["netops", "audit", action] + (["--lines", "10000"] if action == "tail" else [])
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(cli, "STATE", self.state), patch.object(Path, "glob", glob), patch.object(sys, "argv", argv), contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            rc = cli.main()
        if (rc, errors.getvalue()) != (0, ""):
            raise AssertionError("audit %s rc=%s stderr=%s" % (action, rc, errors.getvalue()[-400:]))
        return [json.loads(line) for line in output.getvalue().splitlines()]

    def close(self):
        self.temporary.cleanup()


class AuditReadOrder(unittest.TestCase):
    def state(self):
        state = StateDirectory()
        self.addCleanup(state.close)
        return state

    def expected(self, files):
        return [(item["correlation"], item["direction"]) for _, data in sorted(files) for item in map(json.loads, data.splitlines())]

    def test_restored_queue_with_whole_second_mtimes_has_no_phantom_pending(self):
        for reverse in (False, True):
            with self.subTest(reverse=reverse):
                state = self.state()
                files = queue_files(16)
                for name, data in (reversed(files) if reverse else files):
                    state.put(name, data)
                self.assertEqual(state.cli("pending"), [])
                self.assertEqual(state.sequence(), self.expected(files))

    def test_restored_queue_with_extraction_order_mtimes_keeps_name_order(self):
        state = self.state()
        files = queue_files(4)
        for index, (name, data) in enumerate(reversed(files)):
            state.put(name, data, SECOND + index)
        self.assertEqual(state.cli("pending"), [])
        self.assertEqual(state.sequence(), self.expected(files))

    def test_every_directory_order_gives_the_same_pending_and_output(self):
        state = self.state()
        state.put("%d.jsonl" % BASE, encode(*chain("rotated", 1), record("request", "split", 2)))
        state.put("current.jsonl", encode(record("response", "split", 2), record("connection_end", "split", 2), record("request", "open", 3)))
        files = queue_files(1, BASE + 10 * 10**9)
        for name, data in files:
            state.put(name, data)
        names = sorted(path.name for path in state.audit.iterdir() if path.suffix in (".jsonl", ".queue"))
        expected = pairs(state.inline("tail"))
        self.assertEqual([correlation for correlation, _ in expected], ["rotated"] * 3 + ["split"] * 3 + ["open"] + ["c00"] * 3)
        for permutation in itertools.permutations(names):
            rank = {name: index for index, name in enumerate(permutation)}
            with self.subTest(order=permutation):
                self.assertEqual([(item["correlation"], item["outcome"]) for item in state.inline("pending", rank)], [("open", NO_RESPONSE)])
                self.assertEqual(pairs(state.inline("tail", rank)), expected)

    def test_switched_local_segments_precede_the_syslog_queue(self):
        state = self.state()
        files = queue_files(3, BASE + 10 * 10**9)
        for name, data in files:
            state.put(name, data, SECOND)
        state.put("%d.jsonl" % BASE, encode(*chain("rotated", 7)), SECOND + 5)
        state.put("current.jsonl", encode(*chain("current", 8)), SECOND + 9)
        self.assertEqual(state.sequence(), [("rotated", d) for d in ("request", "response", "connection_end")] + [("current", d) for d in ("request", "response", "connection_end")] + self.expected(files))
        self.assertEqual(state.cli("pending"), [])

    def test_clock_rollback_and_equal_times_cannot_create_a_phantom(self):
        state = self.state()
        state.put(queue_name(BASE + 500, 1), encode(record("request", "rollback", 1)))
        state.put(queue_name(BASE + 100, 2), encode(record("response", "rollback", 1)))
        state.put(queue_name(BASE + 900, 0xf), encode(record("request", "same-ns", 2)))
        state.put(queue_name(BASE + 900, 0x1), encode(record("response", "same-ns", 2)))
        self.assertEqual(state.cli("pending"), [])
        self.assertEqual(state.sequence(), [("rollback", "response"), ("rollback", "request"), ("same-ns", "response"), ("same-ns", "request")])

    def test_uncertain_outcomes_stay_pending_in_every_record_order(self):
        cases = {
            "no-response": ([record("request", "no-response", 1)], NO_RESPONSE),
            "done": ([record("request", "done", 2), record("response", "done", 2), record("connection_end", "done", 2)], None),
            "left": ([record("request", "left", 3), record("client_disconnect", "left", 3, ABANDONED), record("connection_end", "left", 3, {"delivery": "not_started"})], LEFT),
            "left-then-response": ([record("request", "left-then-response", 4), record("client_disconnect", "left-then-response", 4, ABANDONED), record("response", "left-then-response", 4)], None),
            "int-false": ([record("request", "int-false", 5), record("interrupted", "int-false", 5, {"operation_may_have_completed": False}), record("response", "int-false", 5, {"error": "operation_failed"})], NOT_EXECUTED),
            "int-may": ([record("request", "int-may", 6), record("interrupted", "int-may", 6, {"outcome": "unknown"}), record("response", "int-may", 6)], RECORDED_INTERRUPTED),
            "withheld": ([record("request", "withheld", 7), record("response_withheld", "withheld", 7, {"error": "token_rotated"})], WITHHELD),
            "admin-unknown": ([record("request", "admin-unknown", 8), record("response", "admin-unknown", 8, admin("unknown"))], "Admin result unknown; inspect admin_status and the actual device; never retry automatically"),
            "admin-revert": ([record("request", "admin-revert", 9), record("response", "admin-revert", 9, admin("revert-failed"))], "Admin result revert-failed; inspect admin_status and the actual device; never retry automatically"),
            "admin-ok": ([record("request", "admin-ok", 10), record("response", "admin-ok", 10, admin("applied"))], None),
            "orphan-response": ([record("response", "orphan-response", 11)], None),
            "orphan-interrupted": ([record("interrupted", "orphan-interrupted", 21, CANCELLED), record("connection_end", "orphan-interrupted", 21, {"delivery": "interrupted"})], None),
            "orphan-withheld": ([record("response_withheld", "orphan-withheld", 22, {"error": "token_rotated"})], None),
            "int-twice": ([record("request", "int-twice", 12), record("interrupted", "int-twice", 12, {"operation_may_have_completed": False}), record("interrupted", "int-twice", 12, {"operation_may_have_completed": True})], MAY_INTERRUPTED),
            "withheld-and-left": ([record("request", "withheld-and-left", 13), record("response_withheld", "withheld-and-left", 13, {"error": "token_rotated"}), record("client_disconnect", "withheld-and-left", 13, ABANDONED)], WITHHELD),
            "withheld-then-response": ([record("request", "withheld-then-response", 14), record("response_withheld", "withheld-then-response", 14, {"error": "token_rotated"}), record("response", "withheld-then-response", 14)], WITHHELD),
            "app-error": ([record("request", "app-error", 15), record("interrupted", "app-error", 15, {"outcome": "unknown", "automatic_retry": False}), record("response", "app-error", 15, FAILED)], RECORDED_INTERRUPTED),
            "cancel-during-app": ([record("request", "cancel-during-app", 16), record("interrupted", "cancel-during-app", 16, CANCELLED), record("connection_end", "cancel-during-app", 16, {"delivery": "interrupted"})], MAY_INTERRUPTED),
            "send-cancel": ([record("request", "send-cancel", 17), record("response", "send-cancel", 17), record("connection_end", "send-cancel", 17, {"delivery": "committed-before-send"}), record("interrupted", "send-cancel", 17, CANCELLED), record("connection_end", "send-cancel", 17, {"delivery": "interrupted"})], RECORDED_INTERRUPTED),
            "cancel-after-response-record": ([record("request", "cancel-after-response-record", 18), record("response", "cancel-after-response-record", 18), record("interrupted", "cancel-after-response-record", 18, CANCELLED)], RECORDED_INTERRUPTED),
            "not-dispatched-with-delivery": ([record("request", "not-dispatched-with-delivery", 19), record("interrupted", "not-dispatched-with-delivery", 19, {**CANCELLED, "operation_may_have_completed": False}), record("response", "not-dispatched-with-delivery", 19, FAILED)], NOT_EXECUTED),
            "admin-unknown-send-cancel": ([record("request", "admin-unknown-send-cancel", 20), record("response", "admin-unknown-send-cancel", 20, admin("unknown")), record("interrupted", "admin-unknown-send-cancel", 20, CANCELLED)], "Admin result unknown; inspect admin_status and the actual device; never retry automatically"),
        }
        state = self.state()
        for key, (records, outcome) in cases.items():
            for permutation in itertools.permutations(records):
                with self.subTest(case=key, order=[item["direction"] for item in permutation]):
                    state.clear()
                    for index, item in enumerate(permutation):
                        state.put(queue_name(BASE + index, index), encode(item))
                    result = [(item["correlation"], item["outcome"]) for item in state.inline("pending")]
                    self.assertEqual(result, [] if outcome is None else [(key, outcome)])

    def test_recorded_response_and_interruption_stay_pending_in_both_orders_and_every_file_order(self):
        cases = {
            "send-cancel": ([record("response", "mixed", 30), record("connection_end", "mixed", 30, {"delivery": "committed-before-send"})], [record("interrupted", "mixed", 30, CANCELLED), record("connection_end", "mixed", 30, {"delivery": "interrupted"})], RECORDED_INTERRUPTED),
            "app-error": ([record("response", "mixed", 30, FAILED)], [record("interrupted", "mixed", 30, {"outcome": "unknown", "automatic_retry": False})], RECORDED_INTERRUPTED),
            "contract-71": ([record("response", "mixed", 30, {"result": {}})], [record("interrupted", "mixed", 30, {"operation_may_have_completed": True})], RECORDED_INTERRUPTED),
        }
        for label, (responded, interrupted, outcome) in cases.items():
            for order, tail in (("response-then-interrupted", responded + interrupted), ("interrupted-then-response", interrupted + responded)):
                state = self.state()
                for index, item in enumerate([record("request", "mixed", 30), *tail]):
                    state.put(queue_name(BASE + index, index), encode(item))
                names = sorted(path.name for path in state.audit.iterdir() if path.suffix == ".queue")
                for permutation in itertools.permutations(names):
                    rank = {name: index for index, name in enumerate(permutation)}
                    with self.subTest(case=label, order=order, files=permutation):
                        self.assertEqual([(item["correlation"], item["outcome"]) for item in state.inline("pending", rank)], [("mixed", outcome)])

    def test_pending_entry_keeps_the_request_fields(self):
        state = self.state()
        state.put(queue_name(BASE, 1), encode(record("interrupted", "fields", 5, {"operation_may_have_completed": True})))
        state.put(queue_name(BASE + 1, 2), encode(record("request", "fields", 5)))
        self.assertEqual(state.cli("pending"), [{"correlation": "fields", "method": "tools/call", "outcome": MAY_INTERRUPTED, "request_id": 5, "time": "2026-01-01T00:00:05+00:00", "tool": "synthetic_tool"}])

    def test_unrecognized_names_are_read_first(self):
        state = self.state()
        files = queue_files(2)
        for name, data in files:
            state.put(name, data, SECOND)
        state.put("manual-copy.jsonl", encode(record("request", "c01", 1)), SECOND + 30)
        sequence = state.sequence()
        self.assertEqual(sequence[0], ("c01", "request"))
        self.assertEqual(sequence[1:], self.expected(files))
        self.assertEqual(state.cli("pending"), [])

    def test_identical_queue_prefixes_are_read_in_name_order(self):
        sequences = []
        for reverse in (False, True):
            state = self.state()
            files = [(queue_name(BASE, index), encode(record("connection_end", "same-%d" % index, index))) for index in range(8)]
            for name, data in (reversed(files) if reverse else files):
                state.put(name, data)
            sequences.append(state.sequence())
        self.assertEqual(sequences, [[("same-%d" % index, "connection_end") for index in range(8)]] * 2)


class AuditEviction(unittest.IsolatedAsyncioTestCase):
    async def evict(self, segments):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            now = time.time()
            for name, age in segments:
                write_private(path / name, b"x" * 7999999 + b"\n")
                os.utime(path / name, ns=(int((now - age) * 1e9) // 10**9 * 10**9,) * 2)
            write_private(path / "current.jsonl", b"y" * 799999 + b"\n")
            audit = Audit(directory, {"mode": "local", "budget_bytes": 16777216, "segment_bytes": 4194304})
            await audit.record("request", {"synthetic": True}, "budget")
            self.assertTrue((path / "current.jsonl").exists())
            return sorted(name for name, _ in segments if not (path / name).exists())

    async def test_older_mtime_stays_the_primary_eviction_policy(self):
        self.assertEqual(await self.evict([("%d.jsonl" % BASE, 100), ("%d.jsonl" % (BASE + 10**12), 200)]), ["%d.jsonl" % (BASE + 10**12)])

    async def test_equal_mtimes_evict_the_lowest_numeric_stem(self):
        self.assertEqual(await self.evict([("1000.jsonl", 100), ("999.jsonl", 100)]), ["999.jsonl"])
        self.assertEqual(await self.evict([("%d.jsonl" % (BASE + 10**12), 100), ("%d.jsonl" % BASE, 100)]), ["%d.jsonl" % BASE])

    async def test_retention_follows_mtime_not_the_name(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            now = time.time()
            old_name_fresh, new_name_stale = path / ("%d.jsonl" % 1000000000000000000), path / ("%d.jsonl" % int(now * 1e9))
            for segment, age in ((old_name_fresh, 60), (new_name_stale, 604800 + 60)):
                write_private(segment, b"z\n")
                os.utime(segment, (now - age, now - age))
            audit = Audit(directory, {"mode": "local"})
            await audit.record("request", {"synthetic": True}, "retention")
            self.assertEqual((old_name_fresh.exists(), new_name_stale.exists()), (True, False))


if __name__ == "__main__":
    unittest.main()
