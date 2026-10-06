from __future__ import annotations

from netops_admin.errors import SNAPSHOT_CATEGORIES

BLOCKING_RESULTS = ("unknown", "revert-failed")
BLOCKING_REASONS = ("administrator table", "foreign change", "not persisted", "foreign change during save",
                    "saved configuration unverified", "postcheck rejected") + SNAPSHOT_CATEGORIES


def blocks(result, reason) -> bool:
    return result in BLOCKING_RESULTS or reason in BLOCKING_REASONS
