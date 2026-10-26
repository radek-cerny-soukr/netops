import asyncio
import json
import os
from .state import OperatorAccessError, require_initialized
import socket
import ssl
from .bootstrap import demote
from .files import STATE, UIDS, read_private
from .ipc import rpc

async def check_role(role):
    result = await rpc(role, {"action": "status"})
    if not result.get("ready"):
        raise ValueError("A role is not ready")

async def check_roles(roles):
    await asyncio.wait_for(asyncio.gather(*(check_role(role) for role in roles)), timeout=5)

def check():
    if os.geteuid() == 0:
        demote(UIDS["gateway"])
    if os.geteuid() != UIDS["gateway"]:
        raise OperatorAccessError("Health runs only under the default container operator or gateway user")
    require_initialized(STATE)
    settings = json.loads(read_private(STATE / "gateway" / "config.json", owner=UIDS["gateway"]))
    from .audit import RECOVER_HINT, live_incomplete_tail
    from .certificates import CA_HEALTH, ROTATE_HINT, ca_remaining
    if settings["audit"]["mode"] == "local" and any(live_incomplete_tail(path) for path in (STATE / "gateway" / "audit").glob("*.jsonl")):
        raise ValueError("Incomplete final audit record; " + RECOVER_HINT)
    from .certificates import verify_pairs
    verify_pairs()
    if ca_remaining() <= CA_HEALTH:
        raise ValueError("Instance CA expires within 14 days; " + ROTATE_HINT)
    context = ssl.create_default_context(cafile=str(STATE / "gateway" / "ca.pem"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection(("127.0.0.1", 8443), timeout=3) as raw:
        with context.wrap_socket(raw, server_hostname=settings["server_name"]):
            pass
    roles = ["helper", "auditor"] + (["admin"] if settings["admin_enabled"] else [])
    asyncio.run(check_roles(roles))
    directory = STATE / "gateway" / "audit"
    if not directory.is_dir() or not os.access(directory, os.W_OK):
        raise ValueError("Audit storage is unavailable")
    if settings["audit"]["mode"] == "syslog":
        from .audit import SYSLOG_STALE_SECONDS, oldest_queued_age, queued_bytes
        if queued_bytes(directory) >= settings["audit"]["budget_bytes"]:
            raise ValueError("Audit queue is full")
        if oldest_queued_age(directory) > SYSLOG_STALE_SECONDS:
            raise ValueError("Syslog delivery is failing or behind; the oldest queued audit record is older than " + str(SYSLOG_STALE_SECONDS) + " seconds; check the receiver and `docker compose logs netops`")
    print("ready")
    return 0
