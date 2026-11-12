import asyncio
import json
import re
import socket
import struct
from .files import MAX_MESSAGE, RUNTIME, UIDS

class RoleUnavailable(Exception):
    pass

def peer_uid(sock):
    return struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))[1]

MAX_PROGRESS_LINES = 64
PROGRESS_TEXT = re.compile(r"[A-Za-z0-9_:. ()-]{1,200}")

def progress_report(value):
    """A well-formed progress report of a worker, or None; the worker is not trusted to shape client messages."""
    if not isinstance(value, dict) or set(value) != {"progress", "total", "message"}:
        return None
    done, total, text = value["progress"], value["total"], value["message"]
    if (type(done) is not int or type(total) is not int or not 0 <= done <= total <= 1000
            or not isinstance(text, str) or PROGRESS_TEXT.fullmatch(text) is None):
        return None
    return {"progress": done, "total": total, "message": text}

async def rpc(role, message, on_progress=None):
    try:
        reader, writer = await asyncio.open_unix_connection(str(RUNTIME / role / "worker.sock"), limit=MAX_MESSAGE + 1)
    except OSError as error:
        raise RoleUnavailable("Role is unavailable") from error
    try:
        if peer_uid(writer.get_extra_info("socket")) != UIDS[role]:
            raise RoleUnavailable("Role identity mismatch")
        encoded = json.dumps(message, separators=(",", ":")).encode() + b"\n"
        if len(encoded) > MAX_MESSAGE:
            raise ValueError("Request exceeds supported message size")
        writer.write(encoded)
        await writer.drain()
        reports = 0
        while True:
            reply = await reader.readline()
            if not reply or len(reply) > MAX_MESSAGE or not reply.endswith(b"\n"):
                raise RoleUnavailable("Invalid role response")
            result = json.loads(reply)
            if not isinstance(result, dict):
                raise RoleUnavailable("Invalid role response")
            if set(result) != {"progress"}:
                break
            # Only a caller that asked for progress is given it; anything else a worker sends early is dropped.
            report = progress_report(result["progress"]) if on_progress is not None and reports < MAX_PROGRESS_LINES else None
            reports += 1
            if report is not None:
                await on_progress(report)
        if "error" in result:
            raise RoleUnavailable(result["error"])
        return result
    finally:
        writer.close()
        await writer.wait_closed()
