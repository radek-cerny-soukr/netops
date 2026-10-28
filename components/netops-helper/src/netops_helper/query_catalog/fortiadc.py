"""FortiADC first-slice read query: the fixed system status only."""

from __future__ import annotations

from .model import NO_SLOTS, Query


QUERIES: dict[str, Query] = {
    "system_status": Query(
        "get system status",
        NO_SLOTS,
        "Show FortiADC version, system identity, and operating status.",
    ),
}
