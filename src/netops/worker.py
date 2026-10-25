import asyncio
import contextvars
import importlib
import json
import os
import sys
import uuid
from . import __version__
from .files import MAX_MESSAGE, RUNTIME, STATE, UIDS, read_private
from .ipc import peer_uid
from .bootstrap import role_environment
from .state import AUDITOR_DEFAULTS, admin_devices, auditor_settings
from .redaction import redact

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

def _redacted_result(result, secrets):
    cleaned, paths = redact(result, secrets)
    cleaned.setdefault("_meta", {})["netops/redactions"] = paths
    return cleaned

def _encode_response(response):
    return json.dumps(response, separators=(",", ":")).encode() + b"\n"

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
        descriptors = [(tool.to_mcp_tool().model_dump(by_alias=True, exclude_none=True)) for tool in await server.list_tools()]
        for descriptor in descriptors:
            schema = descriptor["inputSchema"]
            schema.get("properties", {}).pop("auth_context", None)
            schema["required"] = [item for item in schema.get("required", []) if item != "auth_context"]
        descriptors.append(self.proxy._target_scope_tool())
        return descriptors

    async def call(self, server, name, arguments):
        if name == "snmp_get" or name == "ftp_list":
            return {"content": [{"type": "text", "text": "unencrypted_protocol: SNMPv2c and FTP/FTPS are unavailable in the SSH/HTTPS-only default profile"}], "isError": True}
        request_id = uuid.uuid4().hex
        request = {"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
        self.proxy.emitted = None
        forwarded = self.proxy.request(json.dumps(request).encode())
        if forwarded is None:
            response = self.proxy.emitted or {"error": {"message": "Request refused"}}
        else:
            params = json.loads(forwarded)["params"]
            try:
                result = await server.call_tool(params["name"], params["arguments"])
                payload = {"content": [item.model_dump(by_alias=True, exclude_none=True) for item in result.content], "structuredContent": result.structured_content, "isError": result.is_error, "_meta": result.meta or {}}
                response = {"jsonrpc": "2.0", "id": request_id, "result": payload}
            except Exception as error:
                print("Helper operation failed: " + type(error).__name__, file=sys.stderr, flush=True)
                response = {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32603, "message": "Role operation failed"}}
            transformed = self.proxy.response(json.dumps(response).encode())
            response = json.loads(transformed) if transformed else {"error": {"message": "Response refused"}}
        if "error" in response:
            return {"content": [{"type": "text", "text": json.dumps(response["error"], separators=(",", ":"))}], "isError": True}
        result = response["result"]
        if name == "helper_status":
            payload = {"version": __version__, "transport": "HTTPS Streamable HTTP", **self.proxy._helper_status_payload()}
            result = {"content": [{"type": "text", "text": json.dumps(payload)}], "structuredContent": payload, "isError": False}
        return await _owned_thread(_redacted_result, result, tuple(self.proxy.session_secrets))

def _admin_configuration_refusal(module):
    try:
        module.configuration()
    except module.ConfigurationError:
        return {"content": [{"type": "text", "text": "admin_not_configured: Stop NetOps, run docker compose run --rm -T netops configure admin with the documented config/vault input, then start NetOps."}], "isError": True}
    return None

async def run(role):
    if os.geteuid() != UIDS[role] or os.getegid() != UIDS[role]:
        raise ValueError("Internal workers require their isolated role UID/GID")
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
                        result = await bridge.call(module.mcp, name, arguments)
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
