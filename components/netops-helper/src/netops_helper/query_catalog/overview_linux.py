"""Linux overview declarations awaiting activation of the four fixed reads."""

from .model import NO_SLOTS, Query

QUERIES = {
    "overview_dmi_model": Query(
        "cat /sys/class/dmi/id/product_name", NO_SLOTS, "Show the DMI product name.",
    ),
    "overview_proc_uptime": Query(
        "cat /proc/uptime", NO_SLOTS, "Show uptime and idle time in seconds.",
    ),
    "overview_proc_stat": Query(
        "cat /proc/stat", NO_SLOTS, "Show cumulative kernel activity, including CPU times in clock ticks.",
    ),
    "overview_link_statistics": Query(
        "ip -s -j link show", NO_SLOTS, "Show interface flags, link state and cumulative counters as JSON.",
        high_volume=True,
    ),
}
