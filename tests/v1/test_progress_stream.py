"""Progress of the long Helper triage tools through the real HTTPS gateway (U4).

A real uvicorn TLS server runs the real AuditBoundary around the real FastMCP Streamable HTTP application;
only the worker socket (`rpc`) is replaced by a fake that reports progress like the Helper worker does.
"""

import asyncio
import datetime
import json
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport

from netops import gateway
from netops import ipc
from netops.audit import Audit
from netops.gateway import AuditBoundary, RemoteTool

TOKEN = "synthetic-gateway-token-for-test-only-123456"
SCHEMA = {"type": "object", "properties": {"target": {"type": "string"}, "virtual_server": {"type": "string"}},
          "required": ["target"], "additionalProperties": False}
CALL = {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "triage_slb", "arguments": {"target": "fortiadc-a", "virtual_server": "VS"},
                   "_meta": {"progressToken": "tok-1"}}}
HEADERS = {"Authorization": "Bearer " + TOKEN, "Accept": "application/json, text/event-stream",
           "Content-Type": "application/json"}
RESULT = {"content": [{"type": "text", "text": json.dumps({"ok": True})}], "structuredContent": {"ok": True},
          "isError": False}


def certificate(directory):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = Path(directory) / "cert.pem", Path(directory) / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert_path, key_path


class Boundary(AuditBoundary):
    def __init__(self, app, audit):
        super().__init__(app, audit)
        self.token = lambda: TOKEN


def sse_messages(text):
    messages = []
    for block in text.replace("\r\n", "\n").split("\n\n"):
        data = [line[6:] for line in block.split("\n") if line.startswith("data: ")]
        if data:
            messages.append(json.loads("\n".join(data)))
    return messages


class ProgressThroughTheGateway(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.cert_path, key_path = certificate(self.directory.name)
        self.calls = []
        self.script = []          # what the fake worker does: progress reports, then the outcome
        server = FastMCP("NetOps")
        for name in ("triage_slb", "triage_health", "tcp_probe"):
            server.add_tool(RemoteTool(name=name, parameters=SCHEMA, role="helper"))
        inner = server.http_app(path="/mcp", json_response=True, stateless_http=True)
        self.audit = Audit(Path(self.directory.name) / "audit", {"mode": "local"})
        self.boundary = Boundary(inner, self.audit)
        config = uvicorn.Config(self.boundary, host="127.0.0.1", port=0, ssl_certfile=str(self.cert_path),
                                ssl_keyfile=str(key_path), log_level="critical", lifespan="on", http="h11")
        self.server = uvicorn.Server(config)
        self.serving = asyncio.create_task(self.server.serve())
        while not self.server.started:
            await asyncio.sleep(0.01)
        self.url = "https://localhost:%d/mcp" % self.server.servers[0].sockets[0].getsockname()[1]

        async def fake_rpc(role, message, on_progress=None):
            self.calls.append((role, message, on_progress))
            for step in self.script:
                if isinstance(step, dict):
                    if on_progress is not None:
                        await on_progress(step)
                    await asyncio.sleep(0.01)
                elif isinstance(step, Exception):
                    raise step
            return {"result": RESULT}

        patcher = patch.object(gateway, "rpc", fake_rpc)
        patcher.start()
        self.addCleanup(patcher.stop)

    async def asyncTearDown(self):
        self.server.should_exit = True
        await asyncio.wait_for(self.serving, 10)
        self.directory.cleanup()

    def reports(self, count=3, total=21):
        return [{"progress": index, "total": total, "message": "triage_slb: %d of at most %d reads (step)" % (index, total)}
                for index in range(1, count + 1)]

    def audit_records(self):
        path = self.audit.current
        return [json.loads(line) for line in path.read_text().splitlines()]

    async def post(self, message):
        async with httpx.AsyncClient(verify=ssl.create_default_context(cafile=str(self.cert_path)), timeout=20) as client:
            return await client.post(self.url, headers=HEADERS, content=json.dumps(message))

    async def test_a_client_with_a_progress_token_gets_audited_progress_events_then_the_result(self):
        self.script = self.reports()
        response = await self.post(CALL)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.headers["content-type"].startswith("text/event-stream"))
        messages = sse_messages(response.text)
        progress = [m for m in messages if m.get("method") == "notifications/progress"]
        self.assertEqual([m["params"]["progress"] for m in progress], [1, 2, 3])
        self.assertTrue(all(m["params"]["progressToken"] == "tok-1" and m["params"]["total"] == 21 for m in progress))
        self.assertEqual(messages[-1]["id"], 7)
        self.assertEqual(messages[-1]["result"]["structuredContent"], {"ok": True})
        self.assertEqual(len(messages), 4)
        role, sent, on_progress = self.calls[0]
        self.assertEqual((role, sent["name"], sent["progress"]), ("helper", "triage_slb", True))
        self.assertIsNotNone(on_progress)
        directions = [record["direction"] for record in self.audit_records()]
        self.assertEqual(directions, ["request", "progress", "progress", "progress", "response", "connection_end"])
        notification = [r for r in self.audit_records() if r["direction"] == "progress"][0]["payload"]
        self.assertEqual(notification["params"]["progressToken"], "tok-1")

    async def test_malformed_tool_names_reach_mcp_validation_without_a_worker_call(self):
        for name in ([], {}):
            with self.subTest(name=name):
                message = json.loads(json.dumps(CALL))
                message["params"]["name"] = name
                self.assertIsNone(gateway.progress_request({"method": "POST", "path": "/mcp"}, json.dumps(message)))
                response = await self.post(message)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["error"]["code"], -32602)
                self.assertEqual(self.calls, [])
                self.assertNotIn("progress", [r["direction"] for r in self.audit_records()])

    async def test_without_a_progress_token_nothing_changes(self):
        self.script = self.reports()
        message = json.loads(json.dumps(CALL))
        del message["params"]["_meta"]
        response = await self.post(message)
        self.assertTrue(response.headers["content-type"].startswith("application/json"))
        self.assertEqual(response.json()["result"]["structuredContent"], {"ok": True})
        role, sent, on_progress = self.calls[0]
        self.assertEqual(sent, {"action": "call", "name": "triage_slb",
                                "arguments": {"target": "fortiadc-a", "virtual_server": "VS"}})
        self.assertIsNone(on_progress)
        self.assertNotIn("progress", [record["direction"] for record in self.audit_records()])

    async def test_only_the_triage_tools_stream(self):
        self.script = self.reports()
        message = json.loads(json.dumps(CALL))
        message["params"]["name"] = "tcp_probe"
        response = await self.post(message)
        self.assertTrue(response.headers["content-type"].startswith("application/json"))
        self.assertEqual(self.calls[0][1], {"action": "call", "name": "tcp_probe",
                                            "arguments": {"target": "fortiadc-a", "virtual_server": "VS"}})

    async def test_a_call_refused_before_any_read_is_an_ordinary_json_response(self):
        self.script = [RuntimeError("refused")]
        response = await self.post(CALL)
        self.assertTrue(response.headers["content-type"].startswith("application/json"))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["result"]["isError"])
        self.assertNotIn("progress", [record["direction"] for record in self.audit_records()])

    async def test_a_failure_after_progress_ends_the_stream_with_an_error_event_and_is_audited(self):
        self.script = [*self.reports(2), ipc.RoleUnavailable("Role is unavailable")]
        response = await self.post(CALL)
        self.assertEqual(response.status_code, 200)
        messages = sse_messages(response.text)
        self.assertEqual([m.get("method") for m in messages[:2]], ["notifications/progress"] * 2)
        self.assertEqual(messages[-1]["id"], 7)
        # the tool raised RoleUnavailable: FastMCP reports it as a tool error result, never a hung stream
        self.assertTrue("error" in messages[-1] or messages[-1]["result"]["isError"])
        directions = [record["direction"] for record in self.audit_records()]
        self.assertEqual(directions[:3], ["request", "progress", "progress"])
        self.assertEqual(directions[-2:], ["response", "connection_end"])

    async def test_a_gateway_failure_after_progress_is_the_last_event_and_leaves_no_retry_hint(self):
        self.script = self.reports(2)
        with patch.object(gateway, "validate_buffered_response", side_effect=ValueError("broken")):
            response = await self.post(CALL)
        last = sse_messages(response.text)[-1]
        self.assertEqual((last["id"], last["error"]["message"], last["error"]["data"]), (7, "operation_failed", {"automatic_retry": False}))
        records = self.audit_records()
        self.assertEqual([r["direction"] for r in records], ["request", "progress", "progress", "interrupted", "response", "connection_end"])
        self.assertEqual(records[-2]["payload"], last)
        self.assertEqual(records[-2]["status"], response.status_code)
        self.assertEqual(records[-2]["response_headers"], {name.decode(): [value.decode()] for name, value in gateway.STREAM_HEADERS})
        self.assertEqual(records[-1]["payload"], {"delivery": "committed-before-send"})

    async def test_the_audit_records_the_stream_event_that_is_really_delivered(self):
        # O9: an inner answer the stream cannot carry (here: a wrong id) is replaced by -32603; the audit records the replacement.
        self.script = self.reports(1)
        inner = self.boundary.app

        async def wrong_id(scope, receive, send):
            async def rewrite(event):
                if event["type"] == "http.response.body" and event.get("body"):
                    event = {**event, "body": event["body"].replace(b'"id":7', b'"id":8')}
                await send(event)
            await inner(scope, receive, rewrite)

        self.boundary.app = wrong_id
        response = await self.post(CALL)
        last = sse_messages(response.text)[-1]
        self.assertEqual((last["id"], last["error"]["code"]), (7, -32603))
        audited = [r for r in self.audit_records() if r["direction"] == "response"]
        self.assertEqual(len(audited), 1)
        self.assertEqual(audited[0]["payload"], last)
        self.assertEqual(audited[0]["status"], 200)
        self.assertEqual(audited[0]["response_headers"]["content-type"], ["text/event-stream"])

    async def test_a_streamed_result_is_audited_as_the_delivered_event(self):
        self.script = self.reports(1)
        response = await self.post(CALL)
        last = sse_messages(response.text)[-1]
        audited = [r for r in self.audit_records() if r["direction"] == "response"][0]
        self.assertEqual(audited["payload"], last)
        self.assertEqual(audited["payload"]["result"]["structuredContent"], {"ok": True})

    async def test_a_rotated_token_withholds_the_result_of_a_stream_too(self):
        self.script = self.reports(1)
        rotated = []
        original = self.boundary.token
        self.boundary.token = lambda: "rotated-" + TOKEN if rotated else original()
        script = self.script
        calls = self.calls

        async def rotating(role, message, on_progress=None):
            calls.append((role, message, on_progress))
            await on_progress(script[0])
            rotated.append(True)
            return {"result": RESULT}

        with patch.object(gateway, "rpc", rotating):
            response = await self.post(CALL)
        messages = sse_messages(response.text)
        self.assertEqual(messages[0]["method"], "notifications/progress")
        self.assertEqual(messages[-1]["error"]["message"], "token_rotated")
        self.assertNotIn("result", messages[-1])
        records = self.audit_records()
        self.assertEqual([r["direction"] for r in records], ["request", "progress", "response_withheld", "response", "connection_end"])
        self.assertEqual(records[-3]["status"], 401)
        self.assertEqual(records[-2]["payload"], messages[-1])
        self.assertEqual(records[-2]["status"], response.status_code)
        self.assertEqual(records[-2]["response_headers"], {name.decode(): [value.decode()] for name, value in gateway.STREAM_HEADERS})
        self.assertEqual(records[-1]["payload"], {"delivery": "committed-before-send"})

    async def test_progress_beyond_the_event_limit_is_not_relayed(self):
        self.script = self.reports(gateway.MAX_PROGRESS_EVENTS + 20, total=1000)
        response = await self.post(CALL)
        progress = [m for m in sse_messages(response.text) if m.get("method") == "notifications/progress"]
        self.assertEqual(len(progress), gateway.MAX_PROGRESS_EVENTS)

    async def test_progress_arrives_while_the_tool_still_runs(self):
        gate = asyncio.Event()
        original = gateway.rpc

        async def slow(role, message, on_progress=None):
            await on_progress(self.reports(1)[0])
            await gate.wait()
            return {"result": RESULT}

        with patch.object(gateway, "rpc", slow):
            async with httpx.AsyncClient(verify=ssl.create_default_context(cafile=str(self.cert_path)), timeout=20) as client:
                async with client.stream("POST", self.url, headers=HEADERS, content=json.dumps(CALL)) as response:
                    lines = response.aiter_lines()
                    first = ""
                    async for line in lines:
                        if line.startswith("data: "):
                            first = line
                            break
                    self.assertEqual(json.loads(first[6:])["method"], "notifications/progress")
                    self.assertFalse(gate.is_set())  # the call has not finished: the client saw progress early
                    gate.set()
                    rest = [line async for line in lines if line.startswith("data: ")]
                    self.assertEqual(json.loads(rest[-1][6:])["id"], 7)
        self.assertIsNotNone(original)

    async def test_a_real_mcp_client_receives_progress_callbacks_and_the_result(self):
        self.script = self.reports()
        seen = []

        async def handler(progress, total, message):
            seen.append((progress, total, message))

        transport = StreamableHttpTransport(self.url, headers={"Authorization": "Bearer " + TOKEN},
                                            httpx_client_factory=lambda **kw: httpx.AsyncClient(
                                                **{**kw, "verify": ssl.create_default_context(cafile=str(self.cert_path))}))
        async with Client(transport, progress_handler=handler) as client:
            result = await client.call_tool("triage_slb", {"target": "fortiadc-a", "virtual_server": "VS"})
        self.assertEqual(result.structured_content, {"ok": True})
        self.assertEqual([item[0] for item in seen], [1, 2, 3])
        self.assertEqual(seen[0][1], 21)
        self.assertTrue(seen[0][2].startswith("triage_slb: 1 of at most 21 reads"))


class StreamedFailureAudit(unittest.IsolatedAsyncioTestCase):
    async def exercise(self, outcome, *, progress=True):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(Path(directory) / "audit", {"mode": "local"})
            progress_sent = asyncio.Event()
            rotated = False

            async def app(scope, receive, send):
                nonlocal rotated
                if progress:
                    await gateway.PROGRESS_SINK.get()({"progress": 1, "total": 2, "message": "step"})
                    await progress_sent.wait()
                if outcome == "exception":
                    raise RuntimeError("operation failed")
                if outcome == "validation":
                    return  # No buffered HTTP start: validate_buffered_response must fail.
                rotated = True
                await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
                await send({"type": "http.response.body", "body": json.dumps({"jsonrpc": "2.0", "id": 7, "result": RESULT}).encode()})

            boundary = Boundary(app, audit)
            boundary.token = lambda: "rotated-" + TOKEN if rotated else TOKEN
            request = json.loads(json.dumps(CALL))
            request["params"]["name"] = "triage_health"
            scope = {"type": "http", "scheme": "https", "method": "POST", "path": "/mcp",
                     "headers": [(name.lower().encode(), value.encode()) for name, value in HEADERS.items()]}
            received = False
            events = []

            async def receive():
                nonlocal received
                if not received:
                    received = True
                    return {"type": "http.request", "body": json.dumps(request).encode(), "more_body": False}
                await asyncio.Event().wait()

            async def send(event):
                events.append(event)
                if event["type"] == "http.response.body" and b'notifications/progress' in event.get("body", b""):
                    progress_sent.set()

            await asyncio.wait_for(boundary(scope, receive, send), 5)
            starts = [event for event in events if event["type"] == "http.response.start"]
            self.assertEqual(len(starts), 1)
            bodies = [event for event in events if event["type"] == "http.response.body"]
            self.assertEqual(sum(not event.get("more_body", False) for event in bodies), 1)
            self.assertFalse(events[-1].get("more_body", False))
            raw = b"".join(event.get("body", b"") for event in bodies).decode()
            records = [json.loads(line) for line in audit.current.read_text().splitlines()]
            responses = [record for record in records if record["direction"] == "response"]
            self.assertEqual(len(responses), 1)
            if not progress:
                self.assertEqual(starts[0]["status"], 503)
                self.assertEqual(responses[0]["status"], 503)
                self.assertEqual(responses[0]["payload"], json.loads(raw))
                return
            messages = sse_messages(raw)
            self.assertEqual(len(messages), 2)
            self.assertEqual(messages[0]["method"], "notifications/progress")
            self.assertEqual(sum("id" in message for message in messages), 1)
            self.assertEqual(messages[-1]["id"], 7)
            self.assertEqual(messages[-1]["error"]["code"], -32001 if outcome == "rotation" else -32603)
            self.assertEqual(messages[-1]["error"]["data"]["automatic_retry"], False)
            self.assertEqual(starts[0], {"type": "http.response.start", "status": 200, "headers": gateway.STREAM_HEADERS})
            self.assertEqual(responses[0]["payload"], messages[-1])
            self.assertEqual(responses[0]["status"], 200)
            self.assertEqual(responses[0]["response_headers"], {name.decode(): [value.decode()] for name, value in starts[0]["headers"]})
            self.assertEqual([record["direction"] for record in records],
                             ["request", "progress", "response_withheld" if outcome == "rotation" else "interrupted", "response", "connection_end"])
            self.assertEqual(records[-1]["payload"], {"delivery": "committed-before-send"})
            self.assertEqual(records[-1]["correlation"], responses[0]["correlation"])
            if outcome == "rotation":
                self.assertEqual(records[-3]["status"], 401)
                self.assertEqual(records[-3]["payload"], {"error": "token_rotated", "operation_may_have_completed": True, "automatic_retry": False})

    async def test_exception_after_progress_has_one_final_response_matching_the_durable_audit(self):
        await self.exercise("exception")

    async def test_invalid_response_after_progress_has_one_final_response_matching_the_durable_audit(self):
        await self.exercise("validation")

    async def test_rotation_after_progress_preserves_withholding_and_audits_the_final_response(self):
        await self.exercise("rotation")

    async def test_exception_before_progress_keeps_the_ordinary_http_503_response(self):
        await self.exercise("exception", progress=False)


class WorkerProgressLines(unittest.IsolatedAsyncioTestCase):
    async def rpc(self, lines, on_progress):
        directory = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(directory.cleanup)
        (Path(directory.name) / "helper").mkdir()

        async def handle(reader, writer):
            await reader.readline()
            for line in lines:
                writer.write(line + b"\n")
            await writer.drain()
            writer.close()

        server = await asyncio.start_unix_server(handle, str(Path(directory.name) / "helper" / "worker.sock"))
        self.addCleanup(server.close)
        with patch.object(ipc, "RUNTIME", Path(directory.name)), patch.object(ipc, "peer_uid", lambda sock: ipc.UIDS["helper"]):
            return await ipc.rpc("helper", {"action": "call"}, on_progress)

    async def test_progress_lines_precede_the_result_and_are_validated(self):
        good = {"progress": {"progress": 1, "total": 5, "message": "triage_vpn: 1 of at most 5 reads (system_status)"}}
        bad = [{"progress": {"progress": 2, "total": 5, "message": "x\nforged"}},
               {"progress": {"progress": 9, "total": 5, "message": "ok"}},
               {"progress": {"progress": True, "total": 5, "message": "ok"}},
               {"progress": {"progress": 2, "total": 5, "message": "ok", "extra": 1}},
               {"progress": "text"}]
        got = []

        async def on_progress(report):
            got.append(report)

        lines = [json.dumps(item).encode() for item in (good, *bad)] + [json.dumps({"result": {"ok": 1}}).encode()]
        self.assertEqual(await self.rpc(lines, on_progress), {"result": {"ok": 1}})
        self.assertEqual(got, [good["progress"]])

    async def test_a_caller_that_did_not_ask_gets_no_progress_and_the_same_result(self):
        line = json.dumps({"progress": {"progress": 1, "total": 5, "message": "ok"}}).encode()
        result = json.dumps({"result": {"ok": 1}}).encode()
        self.assertEqual(await self.rpc([line, result], None), {"result": {"ok": 1}})

    async def test_the_number_of_relayed_reports_is_bounded(self):
        line = json.dumps({"progress": {"progress": 1, "total": 5, "message": "ok"}}).encode()
        got = []

        async def on_progress(report):
            got.append(report)

        await self.rpc([line] * (ipc.MAX_PROGRESS_LINES + 10) + [json.dumps({"result": {}}).encode()], on_progress)
        self.assertEqual(len(got), ipc.MAX_PROGRESS_LINES)


if __name__ == "__main__":
    unittest.main()
