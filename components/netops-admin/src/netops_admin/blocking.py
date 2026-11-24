from __future__ import annotations

import hashlib
import json

from netops_admin.errors import SNAPSHOT_CATEGORIES

BLOCKING_RESULTS = ("unknown", "revert-failed")
BLOCKING_REASONS = ("administrator table", "foreign change", "not persisted", "foreign change during save",
                    "saved configuration unverified", "postcheck rejected") + SNAPSHOT_CATEGORIES
# 1.0.12 execution access: MCP admin_unblock lifts only the block of an operation that ended with one of these results; every
# other block (administrator table, foreign change, not persisted, ...) stays the operator command admin unblock.
# execution access r2 (review finding 2): revert-failed is not among them, a failed return needs a person (admin recover,
# admin unblock); and only the state after of a profile plan qualifies (execute._unblock_check)
MCP_UNBLOCK_RESULTS = ("unknown",)
MCP_UNBLOCK_SIDE = "after"
UNBLOCK_SIDES = ("before", "after")


def blocks(result, reason) -> bool:
    return (result in BLOCKING_RESULTS or reason in BLOCKING_REASONS
            or (reason is not None and reason.endswith("; not persisted")))


def unblock_digest(device: str, blocked: dict, record: dict, side: str, state) -> str:
    """The unblock_sha256 a person approves: the block, its operation and the state read on the device.

    Any change of the block, of the operation result or of the object state read again makes another digest."""
    if side not in UNBLOCK_SIDES:
        raise ValueError("side must be before or after")
    document = {
        "device": device,
        "block": {"reason": blocked.get("reason"), "change_id": blocked.get("change_id")},
        "operation": {"result": record.get("result"), "reason": record.get("reason"),
                      "plan_sha256": (record.get("plan") or {}).get("plan_sha256")},
        "observed": side,
        "object": state,
    }
    data = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(data).hexdigest()
