"""VDOM scope of FortiOS reads: never present per-VDOM data as data of the whole device.

Measured on a FortiGate-60F, FortiOS 7.6.8 build 3744, in multi-VDOM mode (task 172, fixtures under
tests/fixtures/real/fortinet/fortigate60f_7.6.8_multivdom/):

1. The login prints no VDOM; only `get system status` names it (`Virtual domain configuration: multiple`,
   `Current virtual domain: <name>`), `root` for a global administrator.
2. Without a VDOM context a per-VDOM `get` answers `-61` and `diagnose` answers `-1`; inside
   `config vdom` / `edit <name>` the device prints `current vf=<name>:<index>` and the reads work.
4. A read-only profile has no `diagnose` at all: every `diagnose` answers `Unknown action 0`.
5. `diagnose sys session list` inside a VDOM still lists the sessions of every VDOM (each block carries
   `vd=<index>`); `diagnose sys session stat` prints the same device-wide counters in every VDOM.
6. `get system interface` and `get system interface physical` inside a VDOM list the interfaces of every
   VDOM without a VDOM field; only `show system interface` (`set vdom`) tells the owner.

A read in a multi-VDOM FortiGate therefore runs inside `config vdom` / `edit <vdom>` / ... / `end` for the
current VDOM of the session, verified by its `current vf=` marker, and only when that VDOM is enrolled in the
target's `diagnostic_vdoms`; otherwise the read is refused before any per-VDOM command is sent.

A per-VDOM administrator (an account with `set vdom <one VDOM>`, logged in through an interface of that VDOM) was
measured too (task 197, `ref/scenare-197-vdom/60f-cli/44-vd1acct-exec-run2`/`-run3`): `get system status` names
its own VDOM (`Current virtual domain: nops172-vd1`), `config vdom` answers `Unknown action 0` even with
`cli-config`, and the per-VDOM `get system arp` answers its table right after the login, where a global
administrator gets `-61` (`503-A-noctx-arp`). Only after `config vdom` was refused, the same SSH session is
taken for the login context of that VDOM when both device signals hold: the status read in the session names
exactly the VDOM of the read and the probe `get system arp` answers its table header without a refusal. Reads
of a scope beyond one VDOM (device-wide state, listings of every VDOM) are then refused with
`vdom_admin_global_scope_unavailable`, before their command is sent.
"""
from __future__ import annotations

import re

VDOM_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,30}")
_MODE_LINE = re.compile(r"(?m)^[ \t]*Virtual domain configuration:[ \t]*([^\r\n]*?)[ \t]*\r?$")
_CURRENT_LINE = re.compile(r"(?m)^[ \t]*Current virtual domain:[ \t]*([^\r\n]*?)[ \t]*\r?$")
# `Virtual domains status: <n> in NAT mode, <m> in TP mode`: the VDOM count of the whole device, the same for a
# global and a per-VDOM administrator (measured, task 197: `21-status-multivdom` 1 in NAT mode with only `root`,
# `40-ctx-pre` and the VDOM account's `44-vd1acct-exec-run2` both 2 with `root` and `nops172-vd1`).
_COUNT_LINE = re.compile(
    r"(?m)^[ \t]*Virtual domains status:[ \t]*([0-9]{1,5}) in NAT mode, ([0-9]{1,5}) in TP mode[ \t]*\r?$")
_MARKER = re.compile(r"(?m)^[ \t]*current vf=([^\r\n:]*):([0-9]{1,5})[ \t]*\r?$")
_MODES = {"disable": "disable", "multiple": "multiple"}
# The catalogue query whose command (`show system interface`) names the VDOM of every interface. Its text is
# never returned by the VDOM membership join; only the interface name and its `set vdom` value are used.
MEMBERSHIP_QUERY = "interface_vlan_ids"
MEMBERSHIP_COMMAND = "show system interface"
# Reads whose data is not limited to the VDOM they are read in. Measured (task 172, see the module docstring):
# the status and the session counters are device-wide, the interface listings (`get system interface [physical]`,
# `show system interface`) list the interfaces of every VDOM. Global system state (resources, HA, NTP, FortiGuard
# packages) describes the whole device by its nature; these reads are labelled `device`, never as data of the
# session VDOM. The LLDP neighbour summary lists physical ports whose VDOM scope was not measured: `unverified`.
DATA_SCOPES = {
    "session_stats": "device",
    "system_status": "device",
    "physical_interfaces": "all_vdoms",
    "system_interfaces": "all_vdoms",
    "interface_vlan_ids": "all_vdoms",
    "lldp_summary": "unverified",
    **dict.fromkeys((
        "performance", "conserve_state", "cpu_cores", "hardware_memory", "disk_status", "system_top",
        "ha_status", "ha_checksum", "ha_nonsync_checksum", "ha_sync_statistics", "ha_history",
        "ntp_status", "autoupdate_status", "autoupdate_versions", "fortiguard_communication",
        "hardware_sensors", "crash_log", "config_error_log",
        # G11: `diagnose netlink interface list` lists every kernel interface; its VDOM scope was not measured.
        "interface_list", "local_stp_ports", "local_switch_vlans",
    ), "device"),
}
# The global system state reads of triage_health. Measured (task 197, `35-diag-ctx-cliconfig`): inside
# `config vdom` / `edit <vdom>` FortiOS 7.6.8 refuses `get system performance status` with `-61`; these are
# global commands, so in multi-VDOM the triage reads them inside `config global` (task 202). `config global`
# prints no marker; the context is verified by an empty answer and the `<host> (global) # ` / `$ ` prompt
# (measured, `34-gdiag-cliconfig`). An account that may not enter it (`config vdom` without the right answers
# `Unknown action 0` / `Command fail. Return code -1`, `33-diag-ctx`) gets these parts refused, never guessed.
GLOBAL_QUERIES = frozenset((
    "performance", "conserve_state", "ha_status", "ha_checksum", "ntp_status", "autoupdate_versions",
))
GLOBAL_CONTEXT = "global"
# Per-VDOM administrator (task 206, see the module docstring): the reads it is refused, because their data is not
# limited to its VDOM (the identity status excepted), and the probe whose answer proves the login VDOM context.
VDOM_ADMIN_GLOBAL = "vdom_admin_global_scope_unavailable"
VDOM_ADMIN_REFUSED_QUERIES = frozenset(query for query, data_scope in DATA_SCOPES.items()
                                       if data_scope in ("device", "all_vdoms") and query != "system_status")
LOGIN_CONTEXT_PROBE = "get system arp"
_PROBE_HEADER = re.compile(r"^Address[ \t]+Age\(min\)[ \t]+Hardware Addr[ \t]+Interface[ \t]*$")
# Data scopes whose rows must be assigned to their owner VDOM before any row is presented as a row of the VDOM.
OWNER_SCOPES = ("all_vdoms", "unverified")
# switch_read tables whose FortiOS rows name an interface that the VDOM membership join assigns.
MEMBERSHIP_TABLES = {"ip_interface": "interface", "interface": "name", "lldp_neighbor": "local_port"}
# Reads whose rows name an interface of any VDOM: their owners come from `show system interface` (set vdom).
MEMBERSHIP_READS = frozenset(query for query, data_scope in DATA_SCOPES.items()
                             if data_scope in OWNER_SCOPES and query != MEMBERSHIP_QUERY)

ADVICE = {
    "vdom_unverified": "The FortiGate status does not name exactly one VDOM mode and current VDOM (a missing "
                       "'Virtual domain configuration' or 'Current virtual domain' line is unverified, never "
                       "assumed to be no-VDOM); no per-VDOM data was read",
    "vdom_scope_required": "The FortiGate runs multiple VDOMs and the VDOM of this session is not enrolled in the "
                           "target's diagnostic_vdoms; per-VDOM data is not presented as data of the whole device, so "
                           "nothing was read. Enroll the VDOM to read it in its own VDOM context",
    "vdom_not_found": "The FortiGate runs multiple VDOMs but its status counts exactly one VDOM, the VDOM of this "
                      "session, so no VDOM enrolled in the target's diagnostic_vdoms exists on the device; nothing "
                      "per-VDOM was read. Enroll the session VDOM or correct diagnostic_vdoms",
    "vdom_context_unverified": "The FortiGate did not enter the VDOM context with its 'current vf=<vdom>:<index>' "
                               "marker, nor did the session prove the login context of a per-VDOM administrator of "
                               "that VDOM; no per-VDOM data was returned",
    VDOM_ADMIN_GLOBAL: "The account is a per-VDOM administrator: FortiOS gives it only its own VDOM, read directly in "
                       "its login context, and this read covers the whole device or every VDOM (global system state, "
                       "device-wide counters or the interfaces of every VDOM), which FortiOS gives only to a global "
                       "administrator; nothing was read. Use a target with a global account for it",
    "vdom_membership_unverified": "The VDOM of the listed interfaces could not be verified from 'show system "
                                  "interface' (set vdom); interfaces of other VDOMs are not mixed into this VDOM",
    "global_context_not_permitted": "The FortiGate refused 'config global' for this account; the global system state "
                                    "(resources, HA, NTP, FortiGuard packages) was not read. Use a global account "
                                    "whose profile permits 'config global' (cli-config)",
    "global_context_unverified": "The FortiGate did not show the '(global)' prompt after 'config global'; no global "
                                 "system state was returned",
    "diagnose_not_permitted": "The account profile has no diagnose commands in this VDOM (FortiOS answers "
                              "'Unknown action 0', as a read-only profile does); the result is a refusal, not an "
                              "empty table. Use an account whose profile permits diagnose for this query",
}


class VdomRefused(Exception):
    """A FortiOS read refused for its VDOM scope; `code` is one ADVICE key, `scope` the verified scope or None."""

    def __init__(self, code: str, scope: dict | None = None) -> None:
        super().__init__(ADVICE[code])
        self.code = code
        self.scope = scope


def scope(status: str) -> dict:
    """The VDOM scope of a FortiOS session from its `get system status` text.

    `{"vdom_mode": "disable"|"multiple", "vdom": <current VDOM>}` only when the status prints exactly one
    `Virtual domain configuration` line with a known mode. `multiple` also needs exactly one `Current virtual
    domain` line; `disable` is the single VDOM `root` (a `Current virtual domain` line, if printed, must name
    it). A missing, duplicate, unknown or inconsistent line raises VdomRefused("vdom_unverified"): an
    unreadable or incomplete identity is never taken for a no-VDOM device.
    """
    modes = _MODE_LINE.findall(status)
    currents = _CURRENT_LINE.findall(status)
    if len(modes) != 1 or modes[0] not in _MODES:
        raise VdomRefused("vdom_unverified")
    mode = _MODES[modes[0]]
    if len(currents) > 1 or (currents and not VDOM_NAME.fullmatch(currents[0])):
        raise VdomRefused("vdom_unverified", {"vdom_mode": mode, "vdom": None})
    current = currents[0] if currents else None
    if mode == "disable":
        if current not in (None, "root"):
            raise VdomRefused("vdom_unverified", {"vdom_mode": mode, "vdom": None})
        return {"vdom_mode": "disable", "vdom": "root"}
    if current is None:
        raise VdomRefused("vdom_unverified", {"vdom_mode": mode, "vdom": None})
    return {"vdom_mode": "multiple", "vdom": current}


def require(found: dict | None, inventory, status: str | None = None) -> dict:
    """The scope a read may use: no-VDOM as it is; multi-VDOM only for a VDOM enrolled in diagnostic_vdoms.

    A scope that was not verified (None) is refused: no read proceeds on an assumed VDOM mode. A session VDOM that
    is not enrolled refuses with `vdom_scope_required`, or with `vdom_not_found` when the status text proves that
    no enrolled VDOM exists (see `only_session_vdom`); both refuse before any per-VDOM command.
    """
    if found is None or found.get("vdom") is None:
        raise VdomRefused("vdom_unverified", found)
    if found["vdom_mode"] == "disable":
        return found
    enrolled = tuple(inventory.get("diagnostic_vdoms", ()))
    if found["vdom"] not in enrolled:
        missing = bool(enrolled) and status is not None and only_session_vdom(status)
        raise VdomRefused("vdom_not_found" if missing else "vdom_scope_required", found)
    return found


def only_session_vdom(status: str) -> bool:
    """True only when the multi-VDOM status counts exactly one VDOM on the device (`1 in NAT mode, 0 in TP mode`).

    The only VDOM is then the session's own current VDOM, so any other VDOM name provably does not exist. With
    more VDOMs the status does not name them and nothing is inferred; a missing or repeated line is not a proof.
    """
    counts = _COUNT_LINE.findall(status)
    return len(counts) == 1 and int(counts[0][0]) + int(counts[0][1]) == 1


def contextual(found: dict | None) -> bool:
    """True when per-VDOM commands must run inside `config vdom` / `edit <vdom>`."""
    return found is not None and found["vdom_mode"] == "multiple"


def context_index(edit_answer: str, vdom: str) -> int:
    """The VDOM index of the `current vf=<vdom>:<index>` marker `edit <vdom>` printed; anything else refuses."""
    found = _MARKER.findall(edit_answer)
    if len(found) != 1 or found[0][0] != vdom:
        raise VdomRefused("vdom_context_unverified")
    return int(found[0][1])


def login_probe_answered(answer: str) -> bool:
    """True when the probe `get system arp` answered its table (header first) and no refusal (measured, task 197)."""
    lines = [line for line in answer.splitlines() if line.strip()]
    return bool(lines) and _PROBE_HEADER.fullmatch(lines[0]) is not None and not any(
        line.strip().startswith(("Command fail", "command parse error", "Unknown action")) for line in lines)


def login_status(status: str, vdom: str) -> bool:
    """True when the status names multi-VDOM mode and exactly `vdom` as the current VDOM of the session."""
    try:
        return scope(status) == {"vdom_mode": "multiple", "vdom": vdom}
    except VdomRefused:
        return False


def login_context(status: str, probe: str, vdom: str) -> bool:
    """The device signals of a per-VDOM administrator's login context of `vdom` (after a refused `config vdom`).

    The status read in the same session must name multi-VDOM mode and exactly `vdom` as the current VDOM, and the
    per-VDOM probe must have answered its table: a global session answers it `-61` outside a VDOM context.
    """
    return login_status(status, vdom) and login_probe_answered(probe)


def global_prompt(prompt: bytes) -> bool:
    """True when the prompt is the measured `config global` prompt `<host> (global) # ` or `<host> (global) $ `."""
    return prompt.endswith(b" (" + GLOBAL_CONTEXT.encode("ascii") + b") # ") or \
        prompt.endswith(b" (" + GLOBAL_CONTEXT.encode("ascii") + b") $ ")


def label(found: dict | None, query: str | None = None, index: int | None = None) -> dict:
    """Additive result fields: vdom_mode and vdom, and in multi-VDOM the context index and the data scope."""
    if found is None:
        return {}
    fields = {"vdom_mode": found["vdom_mode"], "vdom": found["vdom"]}
    if found["vdom_mode"] == "multiple":
        if index is not None:
            fields["vdom_index"] = index
        fields["data_scope"] = DATA_SCOPES.get(query, "vdom")
    return fields


def diagnose_refused(command: str, answer: str) -> bool:
    """A `diagnose` command answered only with `Unknown action 0`: the profile has no diagnose (measured)."""
    return command.lstrip().startswith("diagnose ") and answer.strip() == "Unknown action 0"


_EDIT = re.compile(r'^    edit "([^"\r\n]+)"[ \t]*\r?$')
_SET_VDOM = re.compile(r'^        set vdom "([^"\r\n]+)"[ \t]*\r?$')


def memberships(text: str) -> dict[str, str]:
    """Interface name -> VDOM from `show system interface`: one `set vdom` in each top-level `edit` entry.

    Only the top-level entries (four spaces) and their own attributes (eight spaces) count, so a nested
    `config` block cannot assign a VDOM. A repeated entry, a second `set vdom` or an entry without one raises
    VdomRefused("vdom_membership_unverified").
    """
    owners: dict[str, str] = {}
    current = None
    names: list[str] = []
    for line in text.splitlines():
        entry = _EDIT.match(line)
        if entry:
            current = entry.group(1)
            if current in names:
                raise VdomRefused("vdom_membership_unverified")
            names.append(current)
            continue
        owner = _SET_VDOM.match(line)
        if owner and current is not None:
            if current in owners or not VDOM_NAME.fullmatch(owner.group(1)):
                raise VdomRefused("vdom_membership_unverified")
            owners[current] = owner.group(1)
    if not names or set(names) != set(owners):
        raise VdomRefused("vdom_membership_unverified")
    return owners


def assign(rows: list[dict], key: str, owners: dict[str, str], vdom: str) -> tuple[list[dict], int]:
    """Rows of this VDOM, each with its `vdom`; rows of other VDOMs are dropped and counted.

    A row whose interface `show system interface` does not name refuses: its VDOM is not known.
    """
    kept = []
    other = 0
    for row in rows:
        owner = owners.get(row.get(key))
        if owner is None:
            raise VdomRefused("vdom_membership_unverified")
        if owner == vdom:
            kept.append({**row, "vdom": owner})
        else:
            other += 1
    return kept, other


_SESSION_VD = re.compile(r"(?m)(?:^|[ \t])vd=([0-9]{1,5})(?=[ \t]|$)")


def sessions_in_vdom(text: str, index: int) -> bool:
    """True when every `session info:` block names exactly `vd=<index>` (sessions of other VDOMs are refused)."""
    blocks = re.split(r"(?m)^(?=session info:)", text)[1:]
    for block in blocks:
        found = _SESSION_VD.findall(block)
        if found != [str(index)]:
            return False
    return True
