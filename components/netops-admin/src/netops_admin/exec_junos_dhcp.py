"""1.0.12 G144: readback of Junos DHCP pools, host reservations and relay groups.

The read-only check account cannot read the configuration and the operational views do not list these objects
(measured on vJunos-switch 26.2R1.7: ``show network-access address-assignment pool`` is empty without a DHCP local
server, ``show dhcp relay`` lists counters and client bindings only), so the object is read back from the scoped
configuration with the write account, like the G145 objects."""

from __future__ import annotations

from . import junos_dhcp as dhcp
from .access import AccessError
from .errors import Rejected

UNREADABLE = "junos_dhcp_readback_unreadable"
TIMEOUT = "junos_dhcp_read_timeout"


def _unreadable():
    return Rejected(["Junos DHCP configuration readback is incomplete or unrecognised"], reason_codes=[UNREADABLE])


def command(table, key):
    if table in (dhcp.POOL, dhcp.RESERVATION):
        return "show configuration access address-assignment pool %s | display set | no-more" % key.partition("@")[0]
    return "show configuration forwarding-options dhcp-relay | display set | no-more"


def observe(access, plan):
    from . import junos

    table, key = plan["table"], plan["key"]
    try:
        text = access.query(command(table, key))
    except (AccessError, TimeoutError) as exc:
        if isinstance(exc, TimeoutError) or any(word in str(exc).lower() for word in ("timeout", "timed out")):
            raise Rejected(["Junos DHCP configuration read timed out"], reason_codes=[TIMEOUT]) from None
        raise _unreadable() from None
    rows = junos.answer_rows(text)
    if (text and not text.endswith("\n")) or junos.refused_answer(text) is not None \
            or any(not row.startswith("set ") for row in rows):
        raise _unreadable()
    scoped = junos.load("set version " + plan["firmware"] + "\n" + "".join(row + "\n" for row in rows), None)
    if dhcp._scope_refusal(scoped):
        raise _unreadable()
    entry = dhcp.entries(scoped, table).get(key)
    if entry is None:
        return None
    if entry.unsupported:
        raise _unreadable()
    return dict(entry.attributes)
