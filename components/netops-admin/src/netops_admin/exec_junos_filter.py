"""Junos firewall filter preflight (management path) and readback (1.0.12 junos firewall filters, J26)."""

from __future__ import annotations

import ipaddress
import json
import re

from . import junos_filter as flt
from .access import AccessError
from .errors import Rejected

BINDING_QUERY = "show interfaces filters %s | display json | no-more"


def _unreadable(what):
    return Rejected(["Junos %s readback is incomplete or unrecognised" % what],
                    reason_codes=["junos_filter_readback_unreadable"])


def _read_failure(exc, what):
    if isinstance(exc, TimeoutError) or any(word in str(exc).lower() for word in ("timeout", "timed out")):
        raise Rejected(["Junos %s timed out" % what], reason_codes=["junos_filter_read_timeout"]) from None
    raise _unreadable(what) from None


def _config(access, plan, table, key):
    """The committed configuration of one filter or binding, read by the write account."""
    from . import junos

    text = access.query("show configuration " + flt._path(table, key) + " | display set | no-more")
    rows = junos.answer_rows(text)
    if (text and not text.endswith("\n")) or any(not row.startswith("set ") for row in rows):
        raise _unreadable("configuration")
    scoped = junos.load("set version " + plan["firmware"] + "\n" + "".join(row + "\n" for row in rows), None)
    found = scoped.entries(table)
    if set(found) - {key}:
        raise _unreadable("configuration")
    entry = found.get(key)
    if (rows and entry is None) or (entry is not None and entry.unsupported):
        raise _unreadable("configuration")
    return None if entry is None else entry.attributes


def _data(record, name):
    item, = record[name]
    value = item["data"]
    if not isinstance(value, str) or not value:
        raise ValueError("missing Junos field")
    return value


def _operational_binding(text, interface, family):
    """The input and output filter names of one family of a logical interface, or None when the interface is
    not on the device. Returns {} for an interface whose family has no filter."""
    from .junos import answer_rows

    rows = answer_rows(text)
    if len(rows) == 1 and re.fullmatch(r"error: (?:interface|device) \S+ not found", rows[0]):
        return None
    document = json.loads("\n".join(rows))
    root, = document["interface-filter-information"]
    row, = root["logical-interface"]
    if _data(row, "name") != interface:
        raise ValueError("unexpected logical interface")
    found = []
    for item in row["filter-information"]:
        if "filter-family" in item and _data(item, "filter-family") == family:
            found.append(item)
    if len(found) > 1:
        raise ValueError("duplicate filter family")
    state = {}
    for item in found:
        for direction in flt.DIRECTIONS:
            if "filter-" + direction in item:
                state[direction] = _data(item, "filter-" + direction)
    return state


def observe(access, plan, operational):
    table, key = plan["table"], plan["key"]
    try:
        configured = _config(access, plan, table, key)
        if table == flt.FILTER:
            return configured
        interface, family = flt.split_key(key)
        # The check account cannot read firewall configuration; it confirms the binding the device reports.
        reported = _operational_binding(access.check_query(BINDING_QUERY % interface), interface, family)
        if reported is None:
            if configured is not None:
                raise _unreadable("configured interface")
            return None
        if reported != (configured or {}):
            raise _unreadable("interface filter binding")
        return configured
    except (AccessError, TimeoutError) as exc:
        _read_failure(exc, "firewall filter")
    except (KeyError, TypeError, ValueError, AttributeError):
        raise _unreadable("firewall filter operational") from None


def _management_read(access, command):
    from .junos import refused_answer

    answer = access.query(command)
    if refused_answer(answer):
        raise _unreadable("management path")
    return answer


def prechecks(access, device, plan, snapshot_text):
    """Refuse a filter on an interface that carries the management session or its return route."""
    from . import junos
    from .exec_junos import SSH_CONNECTIONS, _interface_addresses, _ssh_connections
    from .exec_junos_routing import _active_paths

    table, key = plan["table"], plan["key"]
    name, family = flt.split_key(key)
    try:
        snapshot = junos.load(snapshot_text, plan["firmware"])
        interfaces = ([name] if table == flt.BINDING else
                      [item.rsplit("@", 1)[0] for item in flt.bound_interfaces(snapshot, name, family)])
        if not interfaces:
            return []
        ports = {line.split()[-1] for line in snapshot.lines
                 if re.fullmatch(r"set system services ssh port [0-9]+", line)}
        if len(ports) > 1:
            raise ValueError("ambiguous SSH port")
        sockets = _ssh_connections(_management_read(access, SSH_CONNECTIONS), next(iter(ports), "22"))
        if device.check_address and device.check_address != device.address:
            sockets.update(_ssh_connections(access.check_query(SSH_CONNECTIONS), next(iter(ports), "22")))
        if not sockets:
            raise ValueError("no management connection")
        local_text = _management_read(access, "show interfaces terse | no-more")
        if not local_text.startswith("Interface ") or "(more" in local_text.lower():
            raise ValueError("invalid local interface addresses")
        local = _interface_addresses(local_text)
        if any(address not in local for address, _peer in sockets):
            raise ValueError("missing local SSH address")
        if any(interface in local[address] for address, _peer in sockets for interface in interfaces):
            raise Rejected(["the filter would apply to an interface that terminates a management connection"],
                           reason_codes=["junos_filter_management"])
        for peer in sorted({peer for _address, peer in sockets}, key=str):
            command = f"show route {peer} active-path | display json | no-more"
            if any(interface in hops for _protocol, hops in _active_paths(_management_read(access, command), peer)
                   for interface in interfaces):
                raise Rejected(["the filter would apply to the return path of the management session"],
                               reason_codes=["junos_filter_management"])
    except (AccessError, TimeoutError) as exc:
        _read_failure(exc, "management preflight")
    except (KeyError, TypeError, ValueError, AttributeError, ipaddress.AddressValueError):
        raise Rejected(["the Junos management path could not be established"],
                       reason_codes=["junos_filter_readback_unreadable"]) from None
    plan["prechecks"].append("management connections and their return routes do not use the filtered interface")
    return []
