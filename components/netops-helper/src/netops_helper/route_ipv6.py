"""One FortiOS IPv6 route lookup ("get router info6 routing-table <address>") as route records.

Only the grammar measured on FortiGate-60F 7.6.8 build 3744 (VDOM disabled, VRF 0) is recognized:
one "Routing entry for <IPv6 prefix>" block of a best connected route whose next hop is
"* directly connected, <interface>" (one next hop), and the exact answer "% Network not in table" (no route).
Every other shape (gateways, several entries, non-best or other protocols, another VRF, IPv4 or mixed
notation, refusals, a lone header) is returned whole as unparsed lines with no records, so it is
never reported as an empty table. This is no qualification of IPv6 forwarding, static, BGP, ECMP,
recursive routes or multi-VDOM operation.
"""
from __future__ import annotations

import ipaddress
import re

from netops_core import prompt as core_prompt

# (profile, table, query) whose blank capture is not the recognized no-route answer.
QUERIES = frozenset({('fortinet', 'route', 'ipv6_route_lookup')})
NO_ROUTE = '% Network not in table'
_VRF = re.compile(r'Routing table for VRF=0')
_ENTRY = re.compile(r'Routing entry for ([0-9A-Fa-f:]+/[0-9]{1,3})')
_KNOWN = re.compile(r'Known via "connected", distance [0-9]+, metric [0-9]+, best')
_UPDATE = re.compile(r'Last update [0-9A-Za-z:]+ ago')
_CONNECTED = re.compile(r'\* directly connected, ([A-Za-z0-9_][A-Za-z0-9_.-]{0,14})')


def _prefix(value):
    # Strict IPv6 network in its canonical form; IPv4 and IPv4-mapped/mixed notation are refused.
    if '.' in value:
        raise ValueError('not an IPv6 prefix')
    network = ipaddress.IPv6Network(value, strict=True)
    if str(network) != value.lower():
        raise ValueError('not a canonical IPv6 prefix')
    return str(network)


def blank(text):
    """True when nothing but the known CLI prompt framing and blank lines remains: no answer at all."""
    return not core_prompt.cleaned(text, 'fortinet').strip()


def routes(table, text):
    """(rows, unparsed) of one lookup; unparsed holds every non-blank line when the shape is not recognized."""
    from . import tables

    numbered = [(number, raw) for number, raw in
                enumerate(core_prompt.cleaned(text, 'fortinet').splitlines(), 1) if raw.strip()]
    unknown = [{'line': number, 'text': raw} for number, raw in numbered]
    body = [raw.strip() for _, raw in numbered]
    if body == [NO_ROUTE]:
        return [], []
    if body[:1] and _VRF.fullmatch(body[0]):
        body = body[1:]
    if len(body) < 3 or not _ENTRY.fullmatch(body[0]) or not _KNOWN.fullmatch(body[1]):
        return [], unknown
    rest = body[2:]
    if rest and _UPDATE.fullmatch(rest[0]):
        rest = rest[1:]
    hop = _CONNECTED.fullmatch(rest[0]) if len(rest) == 1 else None
    if hop is None:
        return [], unknown
    try:
        prefix = _prefix(_ENTRY.fullmatch(body[0])[1])
    except ValueError:
        return [], unknown
    # VRF 0 is "default", as in the IPv4 route records; a connected route has no gateway.
    return [tables.record(table, prefix=prefix, next_hop=None, interface=hop[1], protocol='connected', vrf='default')], []
