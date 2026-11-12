import asyncio
import contextvars
import importlib
import json
import os
import sys
import uuid
from . import __version__
from .files import MAX_MESSAGE, RUNTIME, STATE, TARGET_LOCK_DIR, TARGET_LOCK_GID, TARGET_LOCK_ROLES, UIDS, read_private
from .ipc import peer_uid
from .bootstrap import role_environment
from .state import AUDITOR_DEFAULTS, admin_devices, auditor_settings
from .redaction import redact

PROGRESS_TOOLS = frozenset({"triage_health", "triage_routing", "triage_vpn", "triage_slb"})

def progress_line(done, total, text):
    return json.dumps({"progress": {"progress": done, "total": total, "message": text}}, separators=(",", ":")).encode() + b"\n"
MODULES = {"helper": "netops_helper.server", "auditor": "netops_auditor.mcp_server", "admin": "netops_admin.mcp_server"}

async def _owned_thread(function, *args):
    context = contextvars.copy_context()
    future = asyncio.get_running_loop().run_in_executor(None, context.run, function, *args)
    cancelled = False
    while not future.done():
        try:
            await asyncio.wait((future,))
        except asyncio.CancelledError:
            cancelled = True
    result = future.result()
    if cancelled:
        raise asyncio.CancelledError()
    return result

def _redacted_result(result, secrets, metadata=None):
    # Page metadata (hash, sizes, offsets, completion) is engine-computed, not device text; it is
    # kept out of the redaction and put back unchanged.
    restore = None
    if metadata is not None:
        from netops_helper.page_metadata import strip_page_metadata
        result, restore = strip_page_metadata(result, metadata)
    cleaned, paths = redact(result, secrets)
    if restore is not None:
        cleaned = restore(cleaned)
    cleaned.setdefault("_meta", {})["netops/redactions"] = paths
    return cleaned

def _encode_response(response):
    return json.dumps(response, separators=(",", ":")).encode() + b"\n"

def _pagination_refusal(error):
    """The engine's PaginationRefused anywhere in the __cause__/__context__ graph of error, else None.

    The type decides. A fallback accepts only an exception whose whole text is one of the fixed
    refusal messages (a wrapper that drops the cause); a longer or different text never matches.
    """
    from netops_helper.engine import PaginationRefused, _PAGINATION_CODES, _pagination_refused
    pending, seen, exact = [error], set(), None
    while pending:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, PaginationRefused):
            return current
        if exact is None:
            try:
                text = str(current)
            except Exception:
                text = None
            exact = text if text in _PAGINATION_CODES else None
        pending += [current.__context__, current.__cause__]
    return None if exact is None else _pagination_refused(exact)

_CONFIGURATION_FAILURES = {
    'configuration redaction-unverifiable; output withheld': (
        'redaction-unverifiable', 'Configuration redaction could not be verified; output withheld',
        'The configuration syntax could not be safely redacted; no snapshot or partial output was published.'),
    'configuration capture-limit-exceeded; output withheld': (
        'capture-limit-exceeded', 'Configuration capture exceeded its limit; output withheld',
        'Request a narrower section or ask the operator to review configuration capture limits; no snapshot or partial output was published.'),
    'configuration device-refused during capture; output withheld': (
        'device-refused', 'Configuration capture was refused by the device; output withheld',
        'Ask the operator to check device read permissions and command support; no snapshot or partial output was published.'),
    'configuration read refused; output withheld': (
        'read-refused', 'Configuration read was refused; output withheld',
        'Ask the operator to check read permissions and command support for the requested section; no snapshot or partial output was published.'),
}


def _configuration_refusal(error):
    """Accept only complete, fixed safe messages, including through MCP wrappers."""
    pending, seen = [error], set()
    while pending:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        failure = _CONFIGURATION_FAILURES.get(str(current))
        if failure is not None:
            return failure
        pending += [current.__cause__, current.__context__]
    return None


def _page_changes(result, page):
    """Names of the page fields whose final value differs from the engine page, in either representation."""
    def differing(document):
        if not isinstance(document, dict):
            return list(page)
        return [name for name, value in page.items()
                if name not in document or type(document[name]) is not type(value) or document[name] != value]
    changed = differing(result.get("structuredContent"))
    for item in result.get("content") or ():
        if isinstance(item, dict) and item.get("type") == "text":
            try:
                decoded = json.loads(item.get("text"))
            except (TypeError, ValueError):
                decoded = None
            changed += differing(decoded)
    return sorted(set(changed))

def _page_withheld_result(changed, size="max_bytes"):
    payload = {"ok": False, "error_code": "page_changed_by_redaction", "restart_offset": 0, "changed_fields": changed,
               "error": "Output redaction changed this page or its content_sha256, size, offset or completion fields after they were computed, so the page was withheld; restart at offset 0, with a different " + size + " if the page text changed"}
    return {"content": [{"type": "text", "text": json.dumps(payload, separators=(",", ":"))}], "structuredContent": payload, "isError": True, "_meta": {}}

def _pagination_refusal_result(refusal):
    payload = {"ok": False, "error_code": refusal.code, "error": str(refusal)}
    if refusal.restartable:
        payload["restart_offset"] = 0
    return {"content": [{"type": "text", "text": json.dumps(payload, separators=(",", ":"))}], "structuredContent": payload, "isError": True, "_meta": {}}

class HelperBridge:
    def __init__(self):
        from netops_helper import proxy
        from netops_core import vault
        class LocalProxy(proxy.Proxy):
            def __init__(self):
                super().__init__()
                self.emitted = None
            def _emit(self, value):
                self.emitted = value
            def _vault(self, names=None):
                return vault.load(STATE / "helper" / "vault.json", names=names)
            def _load_egress_policy(self):
                return {"dns_resolvers": ["system"]}
        self.proxy = LocalProxy()

    async def tools(self, server):
        from netops_helper.proxy import PRIVATE_ARGUMENTS
        descriptors = [(tool.to_mcp_tool().model_dump(by_alias=True, exclude_none=True)) for tool in await server.list_tools()]
        for descriptor in descriptors:
            schema = descriptor["inputSchema"]
            for private in PRIVATE_ARGUMENTS:
                schema.get("properties", {}).pop(private, None)
            schema["required"] = [item for item in schema.get("required", []) if item not in PRIVATE_ARGUMENTS]
        descriptors.append(self.proxy._target_scope_tool())
        return descriptors

    async def call(self, server, name, arguments, sink=None):
        from netops_helper.page_metadata import page_metadata
        if name == "ftp_list":
            return {"content": [{"type": "text", "text": "unencrypted_protocol: FTP/FTPS is unavailable in the SSH/HTTPS-only default profile"}], "isError": True}
        request_id = uuid.uuid4().hex
        request = {"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
        self.proxy.emitted = None
        page = None
        forwarded = self.proxy.request(json.dumps(request).encode())
        if forwarded is None:
            response = self.proxy.emitted or {"error": {"message": "Request refused"}}
        else:
            params = json.loads(forwarded)["params"]
            from netops_helper import progress
            reporting = progress.bind_transport(sink) if sink is not None else None
            try:
                result = await server.call_tool(params["name"], params["arguments"])
                structured = result.structured_content
                metadata = page_metadata(structured, name) if not result.is_error else None
                if metadata is not None and isinstance(structured.get("untrusted_device_output"), str):
                    page = {**metadata, "untrusted_device_output": structured["untrusted_device_output"]}
                payload = {"content": [item.model_dump(by_alias=True, exclude_none=True) for item in result.content], "structuredContent": result.structured_content, "isError": result.is_error, "_meta": result.meta or {}}
                response = {"jsonrpc": "2.0", "id": request_id, "result": payload}
            except Exception as error:
                refusal = _pagination_refusal(error)
                failure = _configuration_refusal(error) if name == "config_read" else None
                if failure is not None:
                    category, message, guidance = failure
                    response = {"jsonrpc": "2.0", "id": request_id, "error": {
                        "code": -32602, "message": message,
                        "data": {"category": category, "reason": category, "guidance": guidance}}}
                elif refusal is None:
                    print("Helper operation failed: " + type(error).__name__, file=sys.stderr, flush=True)
                    response = {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32603, "message": "Role operation failed"}}
                else:
                    response = {"jsonrpc": "2.0", "id": request_id, "result": _pagination_refusal_result(refusal)}
            finally:
                if reporting is not None:
                    progress.unbind_transport(reporting)
            transformed = self.proxy.response(json.dumps(response).encode())
            response = json.loads(transformed) if transformed else {"error": {"message": "Response refused"}}
        if "error" in response:
            return {"content": [{"type": "text", "text": json.dumps(response["error"], separators=(",", ":"))}], "isError": True}
        result = response["result"]
        if name == "helper_status":
            payload = {"version": __version__, "transport": "HTTPS Streamable HTTP", **self.proxy._helper_status_payload()}
            result = {"content": [{"type": "text", "text": json.dumps(payload)}], "structuredContent": payload, "isError": False}
        metadata = page_metadata(result.get("structuredContent"), name) if not result.get("isError") else None
        result = await _owned_thread(_redacted_result, result, (*self.proxy.session_secrets, *self.proxy.transport_secrets), metadata)
        if page is not None:
            changed = _page_changes(result, page)
            if changed:
                return _page_withheld_result(changed, "limit" if name in ("config_read", "config_diff") else "max_bytes")
        return result

def _admin_configuration_refusal(module):
    try:
        module.configuration()
    except module.ConfigurationError:
        return {"content": [{"type": "text", "text": "admin_not_configured: Stop NetOps, run docker compose run --rm -T netops configure admin with the documented config/vault input, then start NetOps."}], "isError": True}
    return None

async def run(role):
    if os.geteuid() != UIDS[role] or os.getegid() != UIDS[role]:
        raise ValueError("Internal workers require their isolated role UID/GID")
    supplementary = set(os.getgroups())
    expected_supplementary = {TARGET_LOCK_GID} if role in TARGET_LOCK_ROLES else set()
    if supplementary != expected_supplementary:
        raise ValueError("Internal worker has an invalid shared target lock group")
    if role in TARGET_LOCK_ROLES:
        os.environ["NETOPS_TARGET_LOCK_DIR"] = str(TARGET_LOCK_DIR)
    else:
        os.environ.pop("NETOPS_TARGET_LOCK_DIR", None)
    directory = role_environment(role)
    os.environ["NETOPS_INVENTORY_PATH"] = str(directory / "inventory.json")
    os.environ["NETOPS_VAULT_PATH"] = str(directory / "vault.json")
    os.environ["NETOPS_ADMIN_CONFIG"] = str(directory / "config.json")
    os.environ["NETOPS_AUDITOR_STORE"] = str(directory / "store.sqlite")
    auditor = auditor_settings(directory, read_private) if role == "auditor" else AUDITOR_DEFAULTS
    os.environ["NETOPS_AUDITOR_TENANT"] = auditor["tenant"]
    os.environ["NETOPS_AUDITOR_CATALOG"] = auditor["catalog"]
    module = importlib.import_module(MODULES[role])
    if role == "auditor":
        module.configure()
    elif role == "admin":
        if admin_devices(directory, read_private):
            module.configure(runtime_factory=lambda config: module.build_runtime(config, require_export=False))
    bridge = HelperBridge() if role == "helper" else None
    lock = asyncio.Lock()
    async def connection(reader, writer):
        try:
            if peer_uid(writer.get_extra_info("socket")) != UIDS["gateway"]:
                return
            raw = await asyncio.wait_for(reader.readline(), timeout=30)
            if not raw or len(raw) > MAX_MESSAGE:
                return
            message = json.loads(raw)
            if message.get("action") == "status":
                writer.write(b'{"ready":true}\n')
                await writer.drain()
                return
            async with lock:
                if message.get("action") == "list":
                    tools = await bridge.tools(module.mcp) if bridge else [tool.to_mcp_tool().model_dump(by_alias=True, exclude_none=True) for tool in await module.mcp.list_tools()]
                    response = {"tools": tools}
                elif message.get("action") == "call":
                    name, arguments = message.get("name"), message.get("arguments", {})
                    if not isinstance(name, str) or not isinstance(arguments, dict):
                        raise ValueError("Invalid tool request")
                    if bridge:
                        sink = None
                        if message.get("progress") is True and name in PROGRESS_TOOLS:
                            async def sink(done, total, text):
                                writer.write(progress_line(done, total, text))
                                await writer.drain()
                        result = await bridge.call(module.mcp, name, arguments, sink)
                    else:
                        result = _admin_configuration_refusal(module) if role == "admin" else None
                        if result is None:
                            output = await module.mcp.call_tool(name, arguments)
                            result = {"content": [item.model_dump(by_alias=True, exclude_none=True) for item in output.content], "structuredContent": output.structured_content, "isError": output.is_error, "_meta": output.meta or {}}
                            from netops_core import vault
                            secrets = ()
                            vault_path = directory / "vault.json"
                            if vault_path.exists():
                                store = vault.load(vault_path)
                                secrets = tuple(store.credential(item).use() for item in store.names())
                            result = await _owned_thread(_redacted_result, result, secrets)
                    response = {"result": result}
                else:
                    raise ValueError("Unsupported role action")
                encoded = await _owned_thread(_encode_response, response)
            if len(encoded) > MAX_MESSAGE:
                raise ValueError("Role response exceeds supported message size")
            writer.write(encoded)
            await writer.drain()
        except (Exception, asyncio.CancelledError) as error:
            print("Role operation failed: " + type(error).__name__, file=sys.stderr, flush=True)
            try:
                writer.write(b'{"error":"Role operation failed; no automatic retry"}\n')
                await writer.drain()
            except (OSError, ConnectionError):
                pass
        finally:
            writer.close()
            await writer.wait_closed()
    socket_path = RUNTIME / role / "worker.sock"
    server = await asyncio.start_unix_server(connection, str(socket_path), limit=MAX_MESSAGE + 1)
    os.chmod(socket_path, 0o666)
    async with server:
        await server.serve_forever()
