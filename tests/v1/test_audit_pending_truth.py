import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

NOT_EXECUTED_LEFT = "client left before dispatch; the operation was not executed"
NOT_EXECUTED_INTERRUPTED = "interrupted before dispatch; the operation was not executed"
MAY_INTERRUPTED = "interrupted before a result was recorded; the operation may have completed; inspect the device before any repeat"
RECORDED_INTERRUPTED = "interrupted; a response is recorded; the client may not have received it; inspect audit export, status and the actual device before any repeat; do not retry writes automatically"
NO_RESPONSE = "no response recorded; the operation may have completed; do not retry writes automatically"
WITHHELD = "response withheld because the token changed; the operation may have completed; inspect status and the device"
ABANDONED = {"phase": "before_dispatch", "complete_body": True, "received_bytes": 70001, "operation_executed": False}
INTERRUPTED_FALSE = {"delivery": "interrupted", "automatic_retry": False, "operation_may_have_completed": False}


def request(cor):
    return {"direction": "request", "correlation": cor, "payload": {"jsonrpc": "2.0", "id": cor, "method": "tools/call", "params": {"name": "synthetic_tool", "arguments": {}}},
            "method": "POST", "path": "/mcp", "authenticated": True}


def event(direction, cor, payload, **extra):
    return {"direction": direction, "correlation": cor, "payload": payload, **extra}


def admin_response(cor, result):
    return event("response", cor, {"jsonrpc": "2.0", "id": cor, "result": {"content": [], "structuredContent": {"result": {"result": result}}, "isError": False}}, status=200)


def pending(chains):
    with tempfile.TemporaryDirectory() as directory:
        env = dict(os.environ, NETOPS_STATE_DIR=directory)
        script = (
            "import json,sys,pathlib\n"
            "from netops.files import STATE, UIDS, write_private\n"
            "(STATE / 'gateway' / 'audit').mkdir(parents=True, mode=0o700)\n"
            "write_private(STATE / 'gateway' / 'config.json', b'{}', UIDS['gateway'])\n"
            "records = json.loads(sys.stdin.read())\n"
            "data = b''.join(json.dumps({'time': '2026-01-01T00:00:%02d+00:00' % (i % 60), **r}).encode() + b'\\n' for i, r in enumerate(records))\n"
            "write_private(STATE / 'gateway' / 'audit' / '000001.jsonl', data, UIDS['gateway'])\n"
        )
        records = [record for chain in chains for record in chain]
        subprocess.run([sys.executable, "-B", "-c", script], input=json.dumps(records), text=True, env=env, check=True)
        process = subprocess.run([sys.executable, "-B", "-m", "netops", "audit", "pending"], capture_output=True, text=True, env=env, timeout=60)
        if process.returncode != 0:
            raise AssertionError("audit pending rc=%s stderr=%s" % (process.returncode, process.stderr[-400:]))
        return {item["correlation"]: item["outcome"] for item in (json.loads(line) for line in process.stdout.splitlines() if line.startswith("{"))}


class AuditPendingTruth(unittest.TestCase):
    def test_the_five_shapes_and_completed_chains(self):
        result = pending([
            [request("abandoned"), event("client_disconnect", "abandoned", ABANDONED), event("connection_end", "abandoned", {"delivery": "not_started"})],
            [request("int-false"), event("interrupted", "int-false", INTERRUPTED_FALSE), event("connection_end", "int-false", {"delivery": "interrupted"})],
            [request("int-true"), event("interrupted", "int-true", {**INTERRUPTED_FALSE, "operation_may_have_completed": True}), event("connection_end", "int-true", {"delivery": "interrupted"})],
            [request("no-response")],
            [request("withheld"), event("response_withheld", "withheld", {"error": "token_rotated"})],
            [request("done"), event("response", "done", {"jsonrpc": "2.0", "id": "done", "result": {}}, status=200), event("connection_end", "done", {"delivery": "committed-before-send"})],
            [request("admin-unknown"), admin_response("admin-unknown", "unknown")],
            [request("admin-revert"), admin_response("admin-revert", "revert-failed")],
            [request("admin-ok"), admin_response("admin-ok", "applied")],
        ])
        self.assertEqual(result, {
            "abandoned": NOT_EXECUTED_LEFT,
            "int-false": NOT_EXECUTED_INTERRUPTED,
            "int-true": MAY_INTERRUPTED,
            "no-response": NO_RESPONSE,
            "withheld": WITHHELD,
            "admin-unknown": "Admin result unknown; inspect admin_status and the actual device; never retry automatically",
            "admin-revert": "Admin result revert-failed; inspect admin_status and the actual device; never retry automatically",
        })

    def test_wrongly_typed_or_partial_fields_stay_conservative(self):
        left_variants = [{**ABANDONED, "operation_executed": value} for value in (0, None, "false")]
        left_variants += [{**ABANDONED, "complete_body": value} for value in (1, "true", None)]
        left_variants += [{**ABANDONED, "phase": "request_body"}, {k: v for k, v in ABANDONED.items() if k != "operation_executed"}, ["before_dispatch"], None]
        interrupted_variants = [{**INTERRUPTED_FALSE, "operation_may_have_completed": value} for value in (0, None, "false")]
        interrupted_variants += [{k: v for k, v in INTERRUPTED_FALSE.items() if k != "operation_may_have_completed"}, [False], None, {"outcome": "unknown", "automatic_retry": False}]
        chains = [[request("l%d" % n), event("client_disconnect", "l%d" % n, payload)] for n, payload in enumerate(left_variants)]
        chains += [[request("i%d" % n), event("interrupted", "i%d" % n, payload)] for n, payload in enumerate(interrupted_variants)]
        result = pending(chains)
        for n in range(len(left_variants)):
            self.assertEqual(result.get("l%d" % n), NO_RESPONSE, left_variants[n])
        for n in range(len(interrupted_variants)):
            self.assertEqual(result.get("i%d" % n), MAY_INTERRUPTED, interrupted_variants[n])

    def test_order_with_responses_is_preserved(self):
        result = pending([
            [request("int-false-then-response"), event("interrupted", "int-false-then-response", INTERRUPTED_FALSE), event("response", "int-false-then-response", {"error": "operation_failed"}, status=503)],
            [request("app-error"), event("interrupted", "app-error", {"outcome": "unknown", "automatic_retry": False}), event("response", "app-error", {"error": "operation_failed"}, status=503)],
            [request("left-then-response"), event("client_disconnect", "left-then-response", ABANDONED), event("response", "left-then-response", {"jsonrpc": "2.0", "id": "x", "result": {}}, status=200)],
        ])
        self.assertEqual(result.get("int-false-then-response"), NOT_EXECUTED_INTERRUPTED)
        self.assertEqual(result.get("app-error"), RECORDED_INTERRUPTED)
        self.assertNotIn("left-then-response", result, "a recorded response closes the request as before")

    def test_disconnect_without_a_request_is_not_listed(self):
        result = pending([[event("client_disconnect", "body", {"phase": "request_body"})],
                          [event("admission_cancelled", "adm", {"phase": "admission"}), event("connection_end", "adm", {"delivery": "not_started"})]])
        self.assertEqual(result, {})


if __name__ == "__main__":
    unittest.main()
