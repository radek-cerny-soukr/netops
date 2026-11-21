"""FortiOS targeted DHCP lease release (1.0.12 G20 FG-37): `execute dhcp lease-clear <IPv4>` for ONE lease.

Measured on a FortiGate-60F, FortiOS 7.6.8 build3744 (lab, accounts netops-test-ro/-rw, see
task-evidence/g20/fg37/ and tests/fixtures/fortios_7_6_8_g20/lease-*.txt):

* `execute dhcp lease-clear ?` offers `<IPv4> | <od-do> | all`; Admin renders only one explicit IPv4 address,
  never `all` and never a range.
* a successful `lease-clear <ip>` prints nothing and returns to the prompt; the same silence answers an address
  that holds no lease, so the only proof of the effect is the row leaving `execute dhcp lease-list`.
* `execute dhcp lease-list` groups the leases by interface (a line with the interface name, a header line, one row
  per lease: IP, MAC, hostname, VCI, SSID, AP, SERVER-ID, expiry). The columns hostname, VCI, SSID and AP may be empty,
  so Admin reads IP, MAC, SERVER-ID and the expiry by their shape and keeps the middle text only as a description.

An unrecognised row makes the list unreadable, never a success: Admin refuses to release a lease it cannot place.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from netops_admin.errors import Rejected

TABLE = "dhcp-lease"
KIND = "fortios-clear"
FIRMWARE = ("7.6.8 build3744",)
LIST = "execute dhcp lease-list"
CLEAR = "execute dhcp lease-clear "
ERROR_LINES = ("Unknown action", "Command fail", "command parse error", "Return code", "value parse error",
               "entry is not found")
MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")
HEADER = re.compile(r"\s+IP\s+MAC-Address\s+Hostname\s+VCI\s+SSID\s+AP\s+SERVER-ID\s+Expiry")
INTERFACE = re.compile(r"\S+")
ROW = re.compile(r"\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(" + MAC.pattern + r")\s*(.*?)\s*"
                 r"(\d+)\s+((?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) [A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d \d{4})", re.IGNORECASE)


@dataclass(frozen=True)
class Target:
    key: str
    ip: str
    read: str
    write: str


def target(table: str, key: str, changes: dict) -> Target:
    """The one IPv4 address of a lease; `all`, a range, a list or any other spelling is refused."""
    invalid = Rejected(["lease release needs one IPv4 address that holds a lease: `all`, ranges and lists are refused"],
                       reason_codes=["clear_invalid_target"])
    if table != TABLE or changes or not isinstance(key, str):
        raise invalid
    try:
        ip = ipaddress.IPv4Address(key)
    except ValueError:
        raise invalid from None
    if str(ip) != key or ip.is_unspecified or ip.is_multicast or ip.is_loopback or ip == ipaddress.IPv4Address("255.255.255.255"):
        raise invalid
    return Target(key, key, LIST, CLEAR + key)


def unreadable():
    return Rejected(["the FortiOS DHCP lease list is incomplete or unrecognised"], reason_codes=["clear_readback_unreadable"])


def observation(text: str) -> dict:
    """Every lease of `execute dhcp lease-list` (all interfaces) as {"leases": [...]}, or unreadable."""
    lines = [line.rstrip() for line in text.replace("\r", "").replace("\t", "  ").split("\n") if line.strip()]
    if any(line.strip().startswith(ERROR_LINES) for line in lines):
        raise unreadable()
    leases, interface, headed = [], None, False
    for line in lines:
        if not line[0].isspace():
            if (interface is not None and not headed) or INTERFACE.fullmatch(line) is None:
                raise unreadable()
            interface, headed = line, False
        elif HEADER.fullmatch(line):
            if interface is None or headed:
                raise unreadable()
            headed = True
        else:
            row = ROW.fullmatch(line) if interface is not None and headed else None
            if row is None:
                raise unreadable()
            ip, mac, detail, server, expiry = row.groups()
            try:
                address = str(ipaddress.IPv4Address(ip))
            except ValueError:
                raise unreadable() from None
            leases.append({"interface": interface, "ip": address, "mac": mac.lower(), "server_id": server,
                           "detail": " ".join(detail.split()), "expiry": " ".join(expiry.split())})
    if (interface is not None and not headed) or len({lease["ip"] for lease in leases}) != len(leases):
        raise unreadable()
    return {"leases": sorted(leases, key=lambda lease: (lease["interface"], lease["ip"]))}


def _core(lease) -> dict:
    """A lease without its expiry, which moves on a renewal."""
    return {name: value for name, value in lease.items() if name != "expiry"}


def state(observed: dict, tgt: Target) -> dict:
    """The state bound into the plan: the target lease and the leases that stay (no expiry, they renew by themselves)."""
    return {"target": tgt.ip, "leases": [_core(lease) for lease in observed["leases"]]}


def prediction(tgt: Target, before: dict, protected_interfaces=frozenset()):
    """(the state after the release, the preview lines); refuses an address that holds no lease."""
    held = [lease for lease in before["leases"] if lease["ip"] == tgt.ip]
    if not held:
        raise Rejected(["address %s holds no lease in the FortiOS lease list" % tgt.ip], reason_codes=["clear_no_entry"])
    lease = held[0]
    if lease["interface"].casefold() in protected_interfaces:
        raise Rejected(["the lease belongs to interface %s on the management path (protected system interface); Admin never"
                        " releases it" % lease["interface"]], reason_codes=["clear_protected_target"])
    others = [item for item in before["leases"] if item["ip"] != tgt.ip]
    return (dict(before, leases=others),
            ["DHCP lease %s on interface %s, MAC %s, DHCP server %s%s will be released; %d other leases stay"
             % (tgt.ip, lease["interface"], lease["mac"], lease["server_id"] or "?",
                ", " + lease["detail"] if lease["detail"] else "", len(others))])


def readback(plan, observed: dict):
    """The released row has left the list and every lease that stayed is still there (leases that other clients took in
    the meantime are reported as `added`). Returns (matches, readback)."""
    tgt = plan["predicted"]["after"]["target"]
    now = [_core(lease) for lease in observed["leases"]]
    expected = plan["predicted"]["after"]["leases"]
    gone = all(lease["ip"] != tgt for lease in now)
    kept = all(item in now for item in expected)
    added = [lease for lease in now if lease not in expected and lease["ip"] != tgt]
    return gone and kept, {"target": tgt, "released": gone, "others_kept": kept, "added": added,
                           "leases": now}


def config_digest(snapshot) -> str:
    """Bind the entire configuration using the FortiOS normalization for per-read ciphertext."""
    return snapshot.rest_digest(TABLE, "")
