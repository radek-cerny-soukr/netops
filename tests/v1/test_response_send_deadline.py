import asyncio
import json
import logging
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from netops import gateway
from netops.audit import Audit

TOKEN = "synthetic-delivery-test-token-123456789"


class ResponseSendDeadline(unittest.IsolatedAsyncioTestCase):
    async def run_case(self, sender, *, cancel=False, events=1, large=False,
                       response_events=None, incoming=None, control=None, caught=None, deadline=0.12):
        with tempfile.TemporaryDirectory() as directory:
            audit = Audit(Path(directory) / "audit", {"mode": "local"})
            app_finished = asyncio.Event()
            async def app(scope, receive, send):
                await receive()
                if response_events is None:
                    await send({"type": "http.response.start", "status": 200, "headers": []})
                    for index in range(events):
                        await send({"type": "http.response.body", "body": b"{}", "more_body": index < events - 1})
                else:
                    for event in response_events:
                        await send(event)
                app_finished.set()
            boundary = gateway.AuditBoundary(app, audit)
            boundary.token = lambda: TOKEN
            body = json.dumps({"pad": "a" * 100000}).encode() if large else b"{}"
            async def receive():
                if app_finished.is_set() and incoming is not None:
                    return await incoming()
                return {"type": "http.request", "body": body, "more_body": False}
            scope = {"type": "http", "scheme": "https", "method": "POST", "path": "/mcp", "http_version": "1.1",
                     "headers": [(b"authorization", ("Bearer " + TOKEN).encode()), (b"content-length", str(len(body)).encode())]}
            with patch.object(gateway, "RESPONSE_SEND_SECONDS", deadline, create=True):
                task = asyncio.create_task(boundary(scope, receive, sender))
                if control is not None:
                    await control(task)
                if cancel:
                    await asyncio.sleep(0.05)
                    task.cancel()
                done, _ = await asyncio.wait((task,), timeout=0.7)
                timely = bool(done)
                if not done:
                    task.cancel()
                try:
                    await task
                    error = None
                except BaseException as exc:
                    error = type(exc)
                    if caught is not None:
                        caught.append(exc)
            rows = [json.loads(line) for path in audit._files() for line in path.read_bytes().splitlines()]
            self.assertEqual(boundary.slots._value, gateway.MAX_CONCURRENT_REQUESTS)
            self.assertEqual(boundary.large_requests._value, 1)
            self.assertNotIn(TOKEN, json.dumps(rows))
            return timely, error, rows

    def interrupted(self, rows):
        self.assertEqual([r["direction"] for r in rows], ["request", "response", "connection_end", "interrupted", "connection_end"])
        self.assertEqual(rows[2]["payload"]["delivery"], "committed-before-send")
        self.assertEqual(rows[-1]["payload"]["delivery"], "interrupted")
        self.assertEqual(rows[-2]["payload"]["automatic_retry"], False)
        self.assertEqual(rows[-2]["payload"]["operation_may_have_completed"], True)
        self.assertEqual(len({r["correlation"] for r in rows}), 1)

    async def test_blocked_body_releases_slot_at_deadline(self):
        async def send(event):
            if event["type"] == "http.response.body":
                await asyncio.Event().wait()
        timely, error, rows = await self.run_case(send, large=True)
        self.assertTrue(timely, "blocked send held the slot past the delivery deadline")
        self.assertIs(error, TimeoutError)
        self.interrupted(rows)

    async def test_deadline_covers_all_events_without_reset(self):
        async def send(event):
            await asyncio.sleep(0.05)
        timely, error, rows = await self.run_case(send, events=3)
        self.assertTrue(timely)
        self.assertIs(error, TimeoutError, "per-event progress reset the delivery deadline")
        self.interrupted(rows)

    async def test_completed_response_before_deadline_is_unchanged(self):
        sent = []
        async def send(event):
            await asyncio.sleep(0.02)
            sent.append(event)
        # Four sends take about 0.08 s; the 0.5 s deadline leaves margin for
        # a loaded runner while an overrun still fails with TimeoutError.
        timely, error, rows = await self.run_case(send, deadline=0.5)
        self.assertTrue(timely)
        self.assertIsNone(error)
        self.assertEqual(sum(event["type"] == "http.response.start" for event in sent), 1)
        self.assertEqual(b"".join(event.get("body", b"") for event in sent), b"{}")
        self.assertFalse(sent[-1].get("more_body", False))
        self.assertEqual([r["direction"] for r in rows], ["request", "response", "connection_end"])

    async def test_cancel_has_one_interruption_tail(self):
        async def send(event):
            await asyncio.Event().wait()
        timely, error, rows = await self.run_case(send, cancel=True)
        self.assertTrue(timely)
        self.assertIs(error, asyncio.CancelledError)
        self.interrupted(rows)

    async def test_disconnected_send_has_one_interruption_tail(self):
        async def send(event):
            raise BrokenPipeError("synthetic peer closed")
        timely, error, rows = await self.run_case(send)
        self.assertTrue(timely)
        self.assertIs(error, BrokenPipeError)
        self.interrupted(rows)



    async def test_invalid_sequence_never_commits_response_delivery(self):
        start = {"type": "http.response.start", "status": 200, "headers": []}
        body = {"type": "http.response.body", "body": b"{}", "more_body": False}
        cases = ([body, start], [start], [start, {**body, "more_body": True}],
                 [start, body, body])
        for emitted in cases:
            with self.subTest(emitted=emitted):
                sent = []
                async def send(event):
                    sent.append(event)
                timely, error, rows = await self.run_case(send, response_events=emitted)
                self.assertTrue(timely)
                self.assertIsNone(error)
                self.assertEqual([r["direction"] for r in rows], ["request", "interrupted", "response"])
                self.assertNotIn("committed-before-send", json.dumps(rows))
                self.assertEqual(next(e["status"] for e in sent if e["type"] == "http.response.start"), 503)

    async def test_receive_failure_is_audited_and_preserves_cause(self):
        async def incoming():
            raise RuntimeError("synthetic receive failure")
        async def send(event):
            await asyncio.Event().wait()
        caught = []
        timely, error, rows = await self.run_case(send, incoming=incoming, caught=caught)
        self.assertTrue(timely)
        self.assertIs(error, ConnectionAbortedError)
        self.assertIsInstance(caught[0].__cause__, RuntimeError)
        self.interrupted(rows)

    async def test_unexpected_send_failure_is_audited_and_preserves_cause(self):
        for failing, failure in (("start", RuntimeError), ("payload", RuntimeError), ("terminal", ValueError),
                                 ("watcher-cleanup", RuntimeError)):
            with self.subTest(failing=failing):
                entered, terminal_sent = asyncio.Event(), []
                async def incoming():
                    # The receive channel fails only while the watcher is cancelled after normal delivery.
                    entered.set()
                    try:
                        await asyncio.Event().wait()
                    finally:
                        raise RuntimeError("synthetic receive failure during watcher cleanup")
                async def send(event):
                    body = event["type"] == "http.response.body"
                    where = {"start": event["type"] == "http.response.start",
                             "payload": body and bool(event.get("body")),
                             "terminal": body and not event.get("more_body", False),
                             "watcher-cleanup": False}
                    if where["terminal"]:
                        terminal_sent.append(event)
                    if failing == "watcher-cleanup" and body and not event.get("body") and event.get("more_body"):
                        await entered.wait()
                    if where[failing]:
                        raise failure("synthetic send failure")
                caught = []
                timely, error, rows = await self.run_case(send, caught=caught, incoming=incoming if failing == "watcher-cleanup" else None)
                self.assertTrue(timely)
                self.assertIs(error, ConnectionAbortedError)
                self.assertIs(type(caught[0].__cause__), failure)
                self.interrupted(rows)
                if failing == "watcher-cleanup":
                    self.assertEqual(terminal_sent, [])

    async def test_late_request_messages_are_not_disconnects(self):
        # ASGI HTTP receive yields http.request or http.disconnect; only the
        # latter is a disconnect, later request chunks are ignored.
        for disconnect in (False, True):
            with self.subTest(disconnect=disconnect):
                late = 0
                drained = asyncio.Event()
                async def incoming():
                    nonlocal late
                    late += 1
                    if late <= 3:
                        return {"type": "http.request", "body": b"late unread body", "more_body": late < 3}
                    drained.set()
                    if disconnect:
                        return {"type": "http.disconnect"}
                    await asyncio.Event().wait()
                sent = []
                async def send(event):
                    if event["type"] == "http.response.body" and event.get("more_body") and not event.get("body"):
                        await drained.wait()
                        if disconnect:
                            await asyncio.Event().wait()
                    sent.append(event)
                timely, error, rows = await self.run_case(send, incoming=incoming)
                self.assertTrue(timely)
                self.assertIsNone(error)
                self.assertGreaterEqual(late, 4)
                if disconnect:
                    self.interrupted(rows)
                else:
                    self.assertEqual([r["direction"] for r in rows], ["request", "response", "connection_end"])
                    self.assertFalse(sent[-1].get("more_body", False))

    async def test_immediate_receive_polling_is_bounded(self):
        polls = 0
        async def incoming():
            nonlocal polls
            polls += 1
            return {"type": "http.request", "body": b"", "more_body": False}
        async def send(event):
            await asyncio.Event().wait()
        timely, error, rows = await self.run_case(send, incoming=incoming)
        self.assertTrue(timely)
        self.assertIs(error, TimeoutError)
        self.assertGreater(polls, 0)
        self.assertLessEqual(polls, 20, "immediate receive caused a busy poll loop")
        self.interrupted(rows)

    async def test_double_cancel_during_watcher_cleanup_finishes_children(self):
        cleaning, recancelled, finished = asyncio.Event(), asyncio.Event(), asyncio.Event()
        release = asyncio.Event()
        children = []
        async def incoming():
            children.append(asyncio.current_task())
            try:
                await asyncio.Event().wait()
            finally:
                cleaning.set()
                count = 0
                try:
                    while count < 2:
                        try:
                            await release.wait()
                            break
                        except asyncio.CancelledError:
                            count += 1
                            recancelled.set()
                finally:
                    finished.set()
        async def send(event):
            children.append(asyncio.current_task())
        async def control(task):
            await asyncio.wait_for(cleaning.wait(), 0.3)
            task.cancel()
            await asyncio.wait_for(recancelled.wait(), 0.3)
            task.cancel()
            await asyncio.sleep(0)
            release.set()
        timely, error, rows = await self.run_case(send, incoming=incoming, control=control)
        self.assertTrue(timely)
        self.assertIs(error, asyncio.CancelledError)
        self.assertTrue(finished.is_set())
        self.assertTrue(children)
        self.assertTrue(all(child.done() for child in children), "delivery child escaped cleanup")
        self.interrupted(rows)

    async def test_single_payload_checks_backpressure_before_unbounded_write(self):
        paused = asyncio.Event()
        accepted = 0
        accepted_before_pause = []
        payload = b"x" * (3 * 32768)
        async def send(event):
            nonlocal accepted
            if event["type"] != "http.response.body":
                return
            if accepted >= 32768:
                accepted_before_pause.append(accepted)
                paused.set()
                await asyncio.Event().wait()
            accepted += len(event.get("body", b""))
        async def incoming():
            await paused.wait()
            return {"type": "http.disconnect"}
        emitted = [{"type": "http.response.start", "status": 200, "headers": []},
                   {"type": "http.response.body", "body": payload, "more_body": False}]
        timely, error, rows = await self.run_case(send, response_events=emitted, incoming=incoming)
        self.assertTrue(timely)
        self.assertIsNone(error)
        self.assertEqual(accepted_before_pause, [32768], "transport accepted an unbounded payload before its next pressure check")
        self.interrupted(rows)

    async def test_final_payload_pressure_is_observed_before_watcher_stops(self):
        pressure = asyncio.Event()
        buffered = False
        async def send(event):
            nonlocal buffered
            if event["type"] != "http.response.body":
                return
            if buffered:
                pressure.set()
                await asyncio.Event().wait()
            buffered = bool(event.get("body"))
        async def incoming():
            await pressure.wait()
            return {"type": "http.disconnect"}
        timely, error, rows = await self.run_case(send, incoming=incoming)
        self.assertTrue(timely)
        self.assertIsNone(error, "without the post-payload pressure check the watcher stops before the terminal send blocks")
        self.assertTrue(pressure.is_set())
        self.interrupted(rows)


class ResponseSendSocketDeadline(unittest.IsolatedAsyncioTestCase):
    async def test_unread_real_tls_response_releases_slot(self):
        import ssl
        import socket
        import uvicorn
        from uvicorn.protocols.http.h11_impl import H11Protocol
        from test_admission_uvicorn import Probe, certificate, TOKEN as SOCKET_TOKEN
        with tempfile.TemporaryDirectory() as directory:
            cert, key = certificate(directory)
            audit = Audit(Path(directory) / "audit", {"mode": "local"})
            payload = b'{"pad":"' + b"a" * (512 * 1024) + b'"}'
            paused = asyncio.Event()
            accepted = []
            class BackpressureProtocol(H11Protocol):
                def connection_made(self, transport):
                    peer = transport.get_extra_info("socket")
                    peer.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16384)
                    transport.set_write_buffer_limits(high=16384, low=4096)
                    accepted.append((peer.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF),
                                     transport.get_write_buffer_limits()))
                    super().connection_made(transport)

                def pause_writing(self):
                    super().pause_writing()
                    paused.set()
            async def app(scope, receive, send):
                await receive()
                await send({"type": "http.response.start", "status": 200,
                            "headers": [(b"content-length", str(len(payload)).encode())]})
                for offset in range(0, len(payload), 32768):
                    await send({"type": "http.response.body", "body": payload[offset:offset + 32768], "more_body": offset + 32768 < len(payload)})
            boundary = Probe(app, audit, [])
            server = uvicorn.Server(uvicorn.Config(boundary, host="127.0.0.1", port=0,
                ssl_certfile=str(cert), ssl_keyfile=str(key), log_level="critical", lifespan="off", http=BackpressureProtocol))
            serving = asyncio.create_task(server.serve())
            writer = None
            try:
                async with asyncio.timeout(3):
                    while not server.started:
                        await asyncio.sleep(0.01)
                listener = server.servers[0].sockets[0]
                port = listener.getsockname()[1]
                context = ssl.create_default_context(cafile=str(cert))
                def connect():
                    peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    try:
                        peer.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                        peer.settimeout(2)
                        receive_buffer = peer.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                        peer.connect(("127.0.0.1", port))
                        return context.wrap_socket(peer, server_hostname="localhost"), receive_buffer
                    except BaseException:
                        peer.close()
                        raise
                writer, receive_buffer = await asyncio.to_thread(connect)
                self.assertGreater(receive_buffer, 0)
                self.assertLessEqual(receive_buffer, 16384)
                request = ("POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + SOCKET_TOKEN +
                           "\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}").encode()
                with patch.object(gateway, "RESPONSE_SEND_SECONDS", 0.15, create=True):
                    await asyncio.to_thread(writer.sendall, request)
                    deadline = asyncio.get_running_loop().time() + 8
                    rows = []
                    while asyncio.get_running_loop().time() < deadline:
                        rows = [json.loads(line) for path in audit._files() for line in path.read_bytes().splitlines()]
                        if (any(r["direction"] == "interrupted" for r in rows)
                                and rows[-1]["direction"] == "connection_end"
                                and rows[-1]["payload"] == {"delivery": "interrupted"}
                                and boundary.slots._value == gateway.MAX_CONCURRENT_REQUESTS):
                            break
                        await asyncio.sleep(0.05)
                    self.assertEqual(len(accepted), 1)
                    self.assertGreater(accepted[0][0], 0)
                    self.assertLessEqual(accepted[0][0], 32768)
                    self.assertEqual(accepted[0][1], (4096, 16384))
                    self.assertTrue(paused.is_set(), "fixture never observed actual server write backpressure: " + str(accepted))
                    self.assertTrue(any(r["direction"] == "interrupted" for r in rows), "unread TLS response did not expire: " + str([(r["direction"], r.get("payload", {}).get("delivery")) for r in rows]))
                    self.assertEqual(boundary.slots._value, gateway.MAX_CONCURRENT_REQUESTS)
                    self.assertEqual(rows[-1]["direction"], "connection_end")
                    self.assertEqual(rows[-1]["payload"], {"delivery": "interrupted"})
            finally:
                if writer is not None:
                    writer.close()
                server.should_exit = True
                await asyncio.wait_for(serving, 10)


class ResponseDisconnectSocket(unittest.IsolatedAsyncioTestCase):
    async def real_delivery(self, disconnect, single_body=False):
        import importlib.metadata
        import socket
        import ssl
        import uvicorn
        from uvicorn.protocols.http.h11_impl import H11Protocol
        from test_admission_uvicorn import Probe, certificate, TOKEN as SOCKET_TOKEN

        self.assertEqual(importlib.metadata.version("uvicorn"), "0.53.0")
        with tempfile.TemporaryDirectory() as directory:
            cert, key = certificate(directory)
            audit = Audit(Path(directory) / "audit", {"mode": "local"})
            payload = b'{"pad":"' + b"a" * (512 * 1024) + b'"}'
            paused = asyncio.Event()
            unfinished_close = asyncio.Event()
            closed = asyncio.Event()
            response_finished = asyncio.Event()

            class ObservedH11(H11Protocol):
                def connection_made(self, transport):
                    transport.get_extra_info("socket").setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16384)
                    transport.set_write_buffer_limits(high=16384, low=4096)
                    super().connection_made(transport)

                def pause_writing(self):
                    super().pause_writing()
                    paused.set()

                def connection_lost(self, exc):
                    closed.set()
                    if self.cycle and not self.cycle.response_complete:
                        unfinished_close.set()
                    super().connection_lost(exc)

                def on_response_complete(self):
                    response_finished.set()
                    super().on_response_complete()

            async def app(scope, receive, send):
                await receive()
                await send({"type": "http.response.start", "status": 200,
                            "headers": [(b"content-length", str(len(payload)).encode())]})
                if single_body:
                    await send({"type": "http.response.body", "body": payload, "more_body": False})
                else:
                    for offset in range(0, len(payload), 32768):
                        await send({"type": "http.response.body", "body": payload[offset:offset + 32768],
                                    "more_body": offset + 32768 < len(payload)})

            boundary = Probe(app, audit, [])
            error_records = []
            error_logger = logging.getLogger("uvicorn.error")
            old_level = error_logger.level
            error_handler = logging.Handler(level=logging.ERROR)
            error_handler.emit = error_records.append
            error_logger.addHandler(error_handler)
            server = uvicorn.Server(uvicorn.Config(boundary, host="127.0.0.1", port=0,
                ssl_certfile=str(cert), ssl_keyfile=str(key), log_level="error", log_config=None,
                lifespan="off", http=ObservedH11))
            serving = asyncio.create_task(server.serve())
            peer = None
            try:
                async with asyncio.timeout(3):
                    while not server.started:
                        await asyncio.sleep(0.01)
                port = server.servers[0].sockets[0].getsockname()[1]
                context = ssl.create_default_context(cafile=str(cert))

                def connect():
                    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    try:
                        raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096 if disconnect else 65536)
                        raw.settimeout(5)
                        raw.connect(("127.0.0.1", port))
                        return context.wrap_socket(raw, server_hostname="localhost")
                    except BaseException:
                        raw.close()
                        raise

                peer = await asyncio.to_thread(connect)
                request = ("POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + SOCKET_TOKEN +
                           "\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}").encode()
                with patch.object(gateway, "RESPONSE_SEND_SECONDS", 5.0):
                    started = asyncio.get_running_loop().time()
                    await asyncio.to_thread(peer.sendall, request)
                    # Old h11 can mark a single final write complete without
                    # signalling application-level pause. Close on actual
                    # partial reception; require observed pressure only after
                    # the interruption oracle, so OLD fails by missing audit.
                    if not single_body:
                        await asyncio.wait_for(paused.wait(), 3)

                    def prefix():
                        data = b""
                        while b"\r\n\r\n" not in data or not data.split(b"\r\n\r\n", 1)[1]:
                            part = peer.recv(4096)
                            if not part:
                                raise AssertionError("server closed before a partial response")
                            data += part
                        return data.split(b"\r\n\r\n", 1)

                    headers, received = await asyncio.to_thread(prefix)
                    self.assertTrue(headers.startswith(b"HTTP/1.1 200"))
                    self.assertGreater(len(received), 0)
                    self.assertLess(len(received), len(payload))
                    if disconnect:
                        # This is a real socket close while h11 is unfinished,
                        # not a synthetic send() exception or deadline expiry.
                        await asyncio.to_thread(peer.close)
                        peer = None
                        await asyncio.wait_for(closed.wait(), 2)
                    else:
                        def remainder():
                            data = received
                            while len(data) < len(payload):
                                part = peer.recv(min(65536, len(payload) - len(data)))
                                if not part:
                                    raise AssertionError("incomplete successful response")
                                data += part
                            return data
                        self.assertEqual(await asyncio.to_thread(remainder), payload)
                        await asyncio.wait_for(response_finished.wait(), 2)
                    async with asyncio.timeout(2):
                        while boundary.slots._value != gateway.MAX_CONCURRENT_REQUESTS:
                            await asyncio.sleep(0.01)
                    rows = [json.loads(line) for path in audit._files() for line in path.read_bytes().splitlines()]
                    interruptions = [row for row in rows if row["direction"] == "interrupted"]
                    self.assertEqual([row["direction"] for row in rows],
                                     ["request", "response", "connection_end", "interrupted", "connection_end"]
                                     if disconnect else ["request", "response", "connection_end"])
                    self.assertEqual(len(interruptions), 1 if disconnect else 0)
                    self.assertEqual(rows[-1]["payload"]["delivery"],
                                     "interrupted" if disconnect else "committed-before-send")
                    if disconnect:
                        self.assertTrue(paused.is_set(), "no actual server write backpressure observed")
                        self.assertLess(asyncio.get_running_loop().time() - started, 4.0,
                                        "interruption may have been caused by the 5-second deadline")
                        self.assertTrue(unfinished_close.is_set())
                        self.assertFalse(interruptions[0]["payload"]["automatic_retry"])
                        self.assertTrue(interruptions[0]["payload"]["operation_may_have_completed"])
                        self.assertFalse(response_finished.is_set())
                    self.assertEqual(boundary.large_requests._value, 1)
                    self.assertNotIn(SOCKET_TOKEN, json.dumps(rows))
            finally:
                if peer is not None:
                    peer.close()
                server.should_exit = True
                try:
                    await asyncio.wait_for(serving, 10)
                finally:
                    error_logger.removeHandler(error_handler)
                    error_logger.setLevel(old_level)
            self.assertEqual([record.getMessage() for record in error_records], [],
                             "ordinary disconnect/success emitted uvicorn.error records")

    async def test_actual_h11_disconnect_mid_response_records_interruption(self):
        await self.real_delivery(True)

    async def test_actual_h11_single_final_payload_disconnect_records_interruption(self):
        await self.real_delivery(True, single_body=True)

    async def test_actual_h11_success_does_not_report_completion_as_disconnect(self):
        await self.real_delivery(False)


if __name__ == "__main__":
    unittest.main()
