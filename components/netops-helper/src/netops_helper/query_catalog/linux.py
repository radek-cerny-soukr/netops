"""Curated Linux phase-1 diagnostic queries."""

from __future__ import annotations

from .model import INTERFACE, NO_SLOTS, Query, SERVICE


class _LinuxQueries(dict[str, Query]):
    """Adapt the engine's internal identity key without adding a public query.

    The identity reader indexes ['version']. Enrollment and query rendering use
    membership/get/iteration, which retain only the existing catalogue names.
    """

    def __missing__(self, key):
        if key == 'version':
            return self['kernel']
        raise KeyError(key)


# high_volume is a scheduling advisory. Global interface, route, socket,
# service, neighbor, FDB, and recent-log collections can require continuation;
# single-object status and inventory-bound queries deliberately remain False.
QUERIES: dict[str, Query] = _LinuxQueries({
    "hostname": Query("hostname", NO_SLOTS, "Show the system hostname."),
    "kernel": Query("uname -a", NO_SLOTS, "Show kernel and architecture details."),
    "uptime": Query("uptime", NO_SLOTS, "Show uptime and load averages."),
    "filesystems": Query("df -h", NO_SLOTS, "Show mounted filesystem usage."),
    "memory": Query("free -m", NO_SLOTS, "Show memory usage in MiB."),
    "links": Query("ip -brief link", NO_SLOTS, "Summarize network link state.", high_volume=True),
    "addresses": Query("ip -brief address", NO_SLOTS, "Summarize interface addresses.", high_volume=True),
    "routes": Query(
        "ip route show", NO_SLOTS, "Show the IPv4 routing table.", high_volume=True,
    ),
    "sockets": Query(
        "ss -lntup", NO_SLOTS, "Show listening TCP and UDP sockets.", high_volume=True,
    ),
    "running_services": Query(
        "systemctl --no-pager --state=running --type=service",
        NO_SLOTS,
        "Show running systemd services.",
        high_volume=True,
    ),
    "interface_addresses": Query(
        "ip -brief address show dev {interface}",
        INTERFACE,
        "Show addresses on one enrolled interface.",
    ),
    "interface_link": Query(
        "ip -details link show dev {interface}",
        INTERFACE,
        "Show detailed state for one enrolled interface.",
    ),
    "service_status": Query(
        "systemctl --no-pager --full status {service}",
        SERVICE,
        "Show status for one enrolled systemd service.",
    ),
    "service_logs_recent": Query(
        "journalctl --no-pager -u {service} --since -1h",
        SERVICE,
        "Show the last hour of logs for one enrolled service.",
        high_volume=True,
    ),
    "neighbors": Query(
        "ip neigh show", NO_SLOTS, "Show the IP neighbor table.", high_volume=True,
    ),
    "bridge_fdb": Query(
        "bridge fdb show", NO_SLOTS, "Show the bridge forwarding database.", high_volume=True,
    ),
})
