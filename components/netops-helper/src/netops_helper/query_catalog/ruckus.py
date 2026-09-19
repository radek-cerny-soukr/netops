"""Curated Ruckus Unleashed 200.13 phase-1 diagnostic queries."""

from __future__ import annotations

from .model import NO_SLOTS, Query


QUERIES: dict[str, Query] = {
    "system_info": Query(
        "show sysinfo",
        NO_SLOTS,
        "Show controller identity, model, version, and uptime.",
    ),
    "ethernet_info": Query(
        "show ethinfo",
        NO_SLOTS,
        "Show the Ethernet port state of the access point.",
    ),
    "access_points": Query(
        "show ap all",
        NO_SLOTS,
        "Summarize every access point of the Unleashed network.",
        high_volume=True,
    ),
    "wlans": Query(
        "show wlan all",
        NO_SLOTS,
        "Summarize every configured WLAN service.",
        high_volume=True,
    ),
}
