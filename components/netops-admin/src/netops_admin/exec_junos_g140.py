"""Independent Junos operational readback for the Admin LAG and RSTP profiles."""
from __future__ import annotations

import re

from netops_admin import junos, junos_g140 as link
from netops_admin.errors import Rejected


STP_OFF = "Spanning-tree is not enabled at global level."
BRIDGE = "show spanning-tree bridge detail"
LACP_OFF = "warning: lacp subsystem not running - not needed by configuration."
MAC = r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"
ACTOR = re.compile(r"\s*(\S+)\s+(Actor|Partner)\s+(?:(?:Yes|No)\s+){6}(?:Fast|Slow)\s+(Active|Passive)")
MUX = re.compile(r"\s*(\S+)\s{2,}\S.*?\s{2,}\S.*?\s+(Detached|Waiting|Attached|Collecting(?: distributing)?|Distributing)",
                 re.IGNORECASE)
LACP_HEADER = "LACP state: Role Exp Def Dist Col Syn Aggr Timeout Activity"
MUX_HEADER = "LACP protocol: Receive State Transmit State Mux State"


def _clean(text):
    if any(marker in text for marker in ("---(more", "\r\x1b", "\x1b", "\x08")):
        raise junos.unreadable("paged or truncated link readback")
    return [row.strip() for row in junos.answer_rows(text)]


def aggregate_row(text, key):
    rows = _clean(text)
    if rows == ["error: device %s not found" % key]:
        return None
    row = junos.interface_row(text, key)
    if row is None or not set(row.values()) <= {"up", "down"}:
        raise junos.unreadable("aggregate interface %s" % key)
    return row


def lacp(text, key):
    """Return complete actor activity and Mux state for each member of the selected aggregate."""
    rows = _clean(text)
    if not rows or rows in ([LACP_OFF], ["error: device %s not found" % key]):
        return {}
    if rows[0] != "Aggregated interface: " + key or len(rows) < 3:
        raise junos.unreadable("LACP response for " + key)
    if " ".join(rows[1].split()) != LACP_HEADER:
        raise junos.unreadable("LACP state header for " + key)
    headings = [index for index, row in enumerate(rows) if " ".join(row.split()) == MUX_HEADER]
    if len(headings) != 1:
        raise junos.unreadable("LACP protocol header for " + key)
    divider = headings[0]
    actors, partners, mux = {}, set(), {}
    for row in rows[2:divider]:
        match = ACTOR.fullmatch(row)
        if match is None or not junos.PHYSICAL.fullmatch(match[1]):
            raise junos.unreadable("LACP member state for " + key)
        port, role, mode = match.groups()
        if (role == "Actor" and port in actors) or (role == "Partner" and port in partners):
            raise junos.unreadable("duplicate LACP member for " + key)
        if role == "Actor":
            actors[port] = mode.lower()
        else:
            partners.add(port)
    for row in rows[divider + 1:]:
        match = MUX.fullmatch(row)
        if match is None or match[1] in mux:
            raise junos.unreadable("LACP Mux state for " + key)
        mux[match[1]] = match[2].lower()
    if not actors or actors.keys() != partners or actors.keys() != mux.keys():
        raise junos.unreadable("incomplete LACP state for " + key)
    return {port: (mode, mux[port]) for port, mode in actors.items()}


def _stp_fields(rows):
    fields = {}
    for row in rows:
        label, sep, value = row.partition(":")
        if sep:
            if label.strip() in fields:
                raise junos.unreadable("duplicate spanning-tree field")
            fields[label.strip()] = value.strip()
    return fields


def bridge(text):
    rows = _clean(text)
    if rows == [STP_OFF]:
        return None
    if not rows or rows[0] != "STP bridge parameters" or rows.count("Local parameters") != 1:
        raise junos.unreadable("RSTP bridge detail")
    local = rows.index("Local parameters")
    top, body = _stp_fields(rows[1:local]), _stp_fields(rows[local + 1:])
    identity = re.fullmatch(r"([0-9]+)\." + MAC, body.get("Bridge ID", ""))
    if (top.get("Routing instance name") != "GLOBAL" or top.get("Enabled protocol") != "RSTP"
            or top.get("Context ID") != "0" or identity is None or "Path cost method" not in body):
        raise junos.unreadable("local RSTP bridge identity")
    return link.bridge_priority(identity[1])


def stp_port(text, key):
    rows = _clean(text)
    if not rows or rows == [STP_OFF]:
        return None
    if rows[0] != "Spanning tree interface parameters for instance 0":
        raise junos.unreadable("RSTP interface detail")
    fields = _stp_fields(rows[1:])
    cost, kind = fields.get("Port cost", ""), fields.get("Link type", "")
    if (fields.get("Interface name") not in {key, link.port_name(key), link.port_name(key) + ".0"}
            or not re.fullmatch(r"[1-9][0-9]*", cost)
            or not re.fullmatch(r"(?:Pt-Pt|Shared|P2P)(?:/EDGE)?", kind, re.IGNORECASE)
            or not fields.get("Port state") or not fields.get("Port role") or not fields.get("Boundary port")):
        raise junos.unreadable("RSTP interface parameters")
    return cost, kind.upper().endswith("/EDGE")


def observe(access, plan, side):
    table, key, state = plan["table"], plan["key"], plan["predicted"][side]
    if table == link.LAG:
        text = access.check_query("show interfaces %s terse" % key)
        row = aggregate_row(text, key)
        seen = lacp(access.check_query("show lacp interfaces %s" % key), key)
        if state is None:
            return None if row is None and not seen else {}
        if (row is None and not state.get("empty-aggregate")) or set(seen) != link.members(state):
            raise junos.unreadable("operational membership of " + key)
        if state.get("switching") and not any(
                columns[:1] == [key + ".0"] and columns[3:4] == ["eth-switch"]
                for columns in (line.split() for line in _clean(text))):
            raise junos.unreadable("Ethernet switching unit of " + key)
        if any(mode != state.get("lacp-mode") for mode, _mux in seen.values()):
            raise junos.unreadable("operational LACP mode of " + key)
        return state
    if table == link.RSTP:
        seen = bridge(access.check_query(BRIDGE))
        if state and seen != state.get("bridge-priority", link.BRIDGE_DEFAULT):
            raise junos.unreadable("operational RSTP bridge priority")
        if not state and seen not in (None, link.BRIDGE_DEFAULT):
            raise junos.unreadable("default RSTP bridge priority")
        # The snapshot verifies the BPDU flag. The read-only account independently checks the live RSTP bridge.
        return state
    text = access.check_query("show spanning-tree interface %s detail" % key)
    seen = stp_port(text, key)
    if state and (seen is None or ("cost" in state and seen[0] != state["cost"]) or seen[1] != ("edge" in state)):
        raise junos.unreadable("operational RSTP interface parameters")
    if side == "after" and not state and plan["predicted"]["before"].get("edge") and seen is not None and seen[1]:
        raise junos.unreadable("removed RSTP edge setting is still operational")
    if not _clean(text) and bridge(access.check_query(BRIDGE)) is None:
        raise junos.unreadable("empty RSTP interface response")
    return state
