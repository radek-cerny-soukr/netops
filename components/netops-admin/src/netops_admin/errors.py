from __future__ import annotations


SHOWN_CHARACTERS = 64


def shown(value) -> str:
    text = str(value)
    if len(text) <= SHOWN_CHARACTERS:
        return repr(text)
    return "%r... (%d characters)" % (text[:SHOWN_CHARACTERS], len(text))


class Rejected(Exception):
    def __init__(self, reasons):
        self.reasons = [str(reason) for reason in reasons]
        super().__init__("; ".join(self.reasons))


SNAPSHOT_INCOMPLETE = "snapshot incomplete"
SNAPSHOT_SCOPE_UNSUPPORTED = "snapshot scope unsupported"
SNAPSHOT_UNREADABLE = "snapshot unreadable"
SNAPSHOT_FIRMWARE_MISMATCH = "snapshot firmware mismatch"
SNAPSHOT_CATEGORIES = (SNAPSHOT_INCOMPLETE, SNAPSHOT_SCOPE_UNSUPPORTED, SNAPSHOT_UNREADABLE, SNAPSHOT_FIRMWARE_MISMATCH)


class SnapshotRejected(Rejected):
    def __init__(self, reasons, category):
        super().__init__(reasons)
        self.category = category


class BudgetExhausted(Rejected):
    pass


class StateUnreadable(Rejected):
    pass
