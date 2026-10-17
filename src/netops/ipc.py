import asyncio
import json
import socket
import struct
from .files import MAX_MESSAGE, RUNTIME, UIDS

class RoleUnavailable(Exception):
    pass

def peer_uid(sock):
    return struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))[1]

async def rpc(role, message):
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
        reply = await reader.readline()
        if not reply or len(reply) > MAX_MESSAGE or not reply.endswith(b"\n"):
            raise RoleUnavailable("Invalid role response")
        result = json.loads(reply)
        if not isinstance(result, dict):
            raise RoleUnavailable("Invalid role response")
        if "error" in result:
            raise RoleUnavailable(result["error"])
        return result
    finally:
        writer.close()
        await writer.wait_closed()
