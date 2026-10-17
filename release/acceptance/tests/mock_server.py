import json
import os
import ssl
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs


def make_handler(token, lax):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, status, body=None, headers=None, sse=False):
            data = b""
            if body is not None:
                data = ("event: message\ndata: %s\n\n" % json.dumps(body)).encode() if sse else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/event-stream" if sse else "application/json")
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            parts = urlsplit(self.path)
            query = parse_qs(parts.query)
            supplied = self.headers.get("Authorization", "")
            ok = supplied == "Bearer " + token
            if lax and (query.get("token") == [token] or not supplied):
                ok = True
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            if not ok:
                return self.reply(401, {"error": "unauthorized"})
            method = body.get("method")
            if method == "initialize":
                return self.reply(200, {"jsonrpc": "2.0", "id": body["id"], "result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "mock-netops", "version": "1.0.0"}}}, {"Mcp-Session-Id": uuid.uuid4().hex})
            if method == "notifications/initialized":
                return self.reply(202)
            if method == "tools/list":
                return self.reply(200, {"jsonrpc": "2.0", "id": body["id"], "result": {"tools": [{"name": "helper_status", "inputSchema": {"type": "object"}}, {"name": "audit_status", "inputSchema": {"type": "object"}}]}}, sse=True)
            return self.reply(400, {"jsonrpc": "2.0", "id": body.get("id"), "error": {"code": -32601, "message": "unknown"}})
    return Handler


def serve(port, cert, key, token, lax):
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(token, lax))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server
