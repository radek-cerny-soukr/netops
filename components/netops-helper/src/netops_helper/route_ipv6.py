"""IPv6 route parsing: EXOS and EOS route tables and one FortiOS IPv6 route lookup ("get router info6 routing-table <address>") as route records.

For FortiOS, only the grammar measured on FortiGate-60F 7.6.8 build 3744 (VDOM disabled, VRF 0) is recognized:
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
QUERIES = frozenset({('fortinet', 'route', 'ipv6_route_lookup'),
                     ('extreme_exos', 'route', 'ipv6_route_table'),
                     ('extreme_exos', 'route', 'ipv6_route_table_vr')} | {
    ('arista_eos', 'route', query) for query in
    ('ipv6_route_table', 'ipv6_route_table_vrf', 'ipv6_route_lookup', 'ipv6_route_lookup_vrf')
})
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


def exos_routes(table, text):
    """EXOS IPv6 two-line routes; a header and final route count prove completion.

    Live empty captures: EXOS-VM 33.6.1.14 and X440/X435 33.7.1.6-patch1-11.
    Populated shape: vendor show_iproute_ipv6.shtml example (G37 evidence).
    """
    from . import tables
    numbered = [(n, raw) for n, raw in enumerate(text.splitlines(), 1) if raw.strip()]
    rows, unknown = [], []
    pending = None
    header = False
    count = None
    for number, raw in numbered:
        value = raw.strip()
        if re.fullmatch(r'Ori Destination\s+Mtr\s+Flags\s+Duration', value):
            header = True
            continue
        if re.fullmatch(r'Gateway\s+Interface', value):
            continue
        total = re.fullmatch(r'Total number of routes\s*=\s*(\d+)', value)
        if total:
            count = int(total[1])
            continue
        head = re.fullmatch(r'[#*@]?([a-z0-9]{1,3})\s+(\S+/\d+)\s+\d+\s+\S+\s+\S+', value)
        if head and header:
            if pending is not None:
                unknown.append({'line': pending[0], 'text': pending[1]})
            pending = (number, raw, head[1], head[2])
            continue
        hop = re.fullmatch(r'([0-9a-fA-F:]+(?:%[A-Za-z0-9_.:-]+)?)\s+(\S+)', value)
        if hop and pending is not None:
            try:
                prefix = pending[3].split('%')[0] + ('/' + pending[3].rsplit('/', 1)[1] if '%' in pending[3] else '')
                prefix = str(ipaddress.IPv6Network(prefix, strict=False))
                gateway = str(ipaddress.IPv6Address(hop[1].split('%')[0]))
                origin = pending[2]
                protocol = {'d': 'connected', 's': 'static', 'or': 'ospfv3', 'oa': 'ospfv3', 'o': 'ospfv3',
                            'o1': 'ospfv3', 'o2': 'ospfv3', 'oe': 'ospfv3', 'be': 'bgp', 'bi': 'bgp', 'bg': 'bgp'}.get(origin, origin)
                rows.append(tables.record('route', prefix=prefix, next_hop=None if origin == 'd' else gateway,
                                          interface=hop[2], protocol=protocol, vrf='VR-Default'))
            except ValueError:
                unknown.extend([{'line': pending[0], 'text': pending[1]}, {'line': number, 'text': raw}])
            pending = None
            continue
        if tables.matches(value, tables.EXOS_HEADINGS['route']):
            continue
        unknown.append({'line': number, 'text': raw})
    if pending is not None:
        unknown.append({'line': pending[0], 'text': pending[1]})
    if not header or count is None or count != len(rows):
        # No optimistic empty/complete result from a partial capture.
        return [], [{'line': n, 'text': raw} for n, raw in numbered]
    return rows, sorted(unknown, key=lambda item: item['line'])


def ios_table(table, text):
    """IOS IPv6 RIB: validate the printed entry count and emit one record per next hop."""
    from . import tables as t
    current = None
    rows, unknown = [], []
    numbered = list(enumerate(core_prompt.cleaned(text, 'cisco_ios').splitlines(), 1))
    pending = []
    header = None
    expected_entries = parsed_entries = 0
    legend = False
    for number, raw in numbered:
        value = raw.strip()
        if not value:
            continue
        heading = re.fullmatch(r'IPv6 Routing Table - (?:(\S+) - )?(\d+) entr(?:y|ies)', value)
        if heading:
            if header is not None and expected_entries != parsed_entries:
                unknown.append(header)
            unknown.extend(pending)
            current, pending = None, []
            header = {'line': number, 'text': raw}
            vrf = heading[1] or 'default'
            expected_entries, parsed_entries = int(heading[2]), 0
            continue
        if value.startswith('Codes:'):
            legend = True
            continue
        if legend and re.match(r'\s{5,}\S+ - ', raw):
            continue
        legend = False
        # IOS XE 17.18.2 appends the route tag to BGP/redistributed entries:
        # "B   2001:DB8::/64 [20/0], tag 65001" (measured, G69 task 473).
        entry = re.fullmatch(r'([A-Z][A-Za-z0-9]*)\s+([0-9A-Fa-f:]+/\d+)\s+\[\d+/\d+\](?:, tag \d+)?', value)
        if entry:
            if pending:
                unknown.extend(pending)
            current = None
            pending = [{'line': number, 'text': raw}]
            protocol = {'C': 'connected', 'L': 'local', 'LC': 'local', 'S': 'static', 'B': 'bgp', 'R': 'rip',
                        'O': 'ospf', 'OI': 'ospf', 'OE1': 'ospf', 'OE2': 'ospf', 'ON1': 'ospf', 'ON2': 'ospf',
                        'D': 'eigrp', 'EX': 'eigrp', 'I1': 'isis', 'I2': 'isis', 'IA': 'isis',
                        'ND': 'nd', 'NDp': 'nd'}.get(entry[1])
            try:
                if header is None or protocol is None:
                    raise ValueError
                current = (str(ipaddress.IPv6Network(entry[2], strict=False)), protocol, vrf)
            except ValueError:
                pass
            continue
        hop = re.fullmatch(r'via (\S+), (\S+(?: connected)?)', value)
        if current and hop:
            try:
                if hop[2] in ('directly connected', 'receive'):
                    interface, gateway = t.port(hop[1]), None
                else:
                    gateway, interface = str(ipaddress.IPv6Address(hop[1])), ('Null0' if hop[2] == 'Null' else _ios_port(hop[2]))
                    if gateway == '::':
                        gateway = None
                rows.append(t.record('route', prefix=current[0], protocol=current[1], vrf=current[2],
                                     next_hop=gateway, interface=interface))
                if pending:
                    parsed_entries += 1
                pending = []
                continue
            except ValueError:
                pass
        unknown.extend(pending)
        pending = []
        current = None
        unknown.append({'line': number, 'text': raw})
    unknown.extend(pending)
    if header is None:
        return rows, [{'line': n, 'text': raw} for n, raw in numbered if raw.strip()]
    if expected_entries != parsed_entries:
        unknown.append(header)
    return rows, sorted(unknown, key=lambda item: item['line'])


def _ios_port(value):
    from . import tables as t
    if re.fullmatch(r'(?:Serial|Se|POS|ATM)[0-9]+(?:/[0-9]+){0,3}(?:\.[0-9]+)?', value):
        return value
    return t.port(value)


def nxos(table, text):
    """Measured NX-OS IPv6 RIB grammar, including an explicitly empty RIB.

    A prefix without a next hop is an incomplete capture, never an empty RIB.
    """
    from . import tables
    rows, unknown = tables.route_nxos(text)
    if not re.search(r'^IPv6 Routing Table for VRF "[^\"]+"', text, re.M):
        return [], [{'line': n, 'text': raw} for n, raw in enumerate(text.splitlines(), 1) if raw.strip()]
    prefixes = {row['prefix'] for row in rows}
    for number, raw in enumerate(text.splitlines(), 1):
        match = re.match(r'([0-9a-fA-F:]+/\d+), ubest/mbest:', raw.strip())
        if match and str(ipaddress.IPv6Network(match[1], strict=False)) not in prefixes:
            unknown.append({'line': number, 'text': raw})
    return rows, unknown


def eos_routes(table, text):
    """Reuse EOS multipath records; a header or an unfinished route is not an empty RIB."""
    from . import tables
    rows, unknown = tables.route_eos(text)
    if not rows and not unknown and not re.search(r'Displaying 0 of [0-9]+ IPv6 routing table entries', text):
        unknown = [{'line': n, 'text': line} for n, line in enumerate(text.splitlines(), 1) if line.strip()]
    # A trailing prefix without its forwarding line is a cut capture, even after valid records.
    numbered = [(n, line) for n, line in enumerate(text.splitlines(), 1) if line.strip()]
    if numbered and re.fullmatch(r'[A-Z][A-Z0-9 ]*\s+[0-9A-Fa-f:]+/[0-9]+(?: \[\d+/\d+\])?', numbered[-1][1].strip()):
        n, line = numbered[-1]
        if not any(item['line'] == n for item in unknown):
            unknown.append({'line': n, 'text': line})
    return rows, unknown


# G11 (1.0.12, FG-21): the whole FortiOS IPv6 table, `get router info6 routing-table`. Measured on FortiGate-60F
# 7.6.8 build3744 (only the connected loopback) and FortiGate-80F 8.0.2 build0251 (a static default route via a
# link-local gateway and connected prefixes): `<code>[*] <prefix> [<distance>/<metric>] via <address>, <interface>,
# <uptime>[, [<weight>/<priority>]]`; `via ::` is a directly connected route.
FORTIOS_CODES = {'K': 'kernel', 'C': 'connected', 'S': 'static', 'R': 'rip', 'O': 'ospf', 'B': 'bgp', 'i': 'isis',
                 'V': 'bgp', 'L': 'leaked', 'D': 'leaked'}
_FORTIOS_LEGEND_ITEM = re.compile(r'(?:[A-Za-z][A-Za-z0-9]*|\*|>) - [A-Za-z][A-Za-z0-9 /-]*')
_FORTIOS_HEADINGS = re.compile(r'IPv6 Routing Table|Timers: Uptime')
_FORTIOS_ROW = re.compile(
    r'(?:(?P<code>[KCSROBiVLD])\*?(?: (?:IA|N1|N2|E1|E2|L1|L2|ia))?\s+(?P<prefix>[0-9A-Fa-f:]+/\d{1,3})\s+)?'
    r'(?:\[\d+/\d+\] )?via (?P<via>[0-9A-Fa-f:]+)'
    r'(?:, (?P<interface>[A-Za-z0-9_][A-Za-z0-9_.-]{0,15})'
    r'| +\(recursive via (?P<resolved>[0-9A-Fa-f:]+), (?P<egress>[A-Za-z0-9_][A-Za-z0-9_.-]{0,15})\)), [^,\s]+'
    r'(?:, \[\d+/\d+\])?')


def fortios_table(table, text):
    """(rows, unparsed) of the whole FortiOS IPv6 routing table; an unknown line is kept as unparsed."""
    from . import tables

    rows, unknown, vrf, prefix, protocol = [], [], 'default', None, None
    for number, raw in enumerate(core_prompt.cleaned(text, 'fortinet').splitlines(), 1):
        value = raw.strip()
        heading = re.fullmatch(r'Routing table for VRF=(\S+)', value)
        if heading:
            name = heading[1].split('(')[0]
            vrf = 'default' if name in ('0', 'default') else name
            prefix = None
            continue
        items = [item.strip() for item in value.removeprefix('Codes: ').split(',') if item.strip()]
        # The IPv6 legend lines end with "," (measured), so an empty last item is no legend item.
        if not value or _FORTIOS_HEADINGS.fullmatch(value) or items and all(
                _FORTIOS_LEGEND_ITEM.fullmatch(item) for item in items):
            continue
        row = _FORTIOS_ROW.fullmatch(value)
        continuation = row is not None and row['prefix'] is None and raw[:1].isspace() and prefix is not None
        if row is None or (row['prefix'] is None and not continuation):
            prefix = None
            unknown.append({'line': number, 'text': raw})
            continue
        try:
            if row['prefix'] is not None:
                if '.' in row['prefix']:
                    raise ValueError('not an IPv6 prefix')
                prefix, protocol = str(ipaddress.IPv6Network(row['prefix'], strict=True)), FORTIOS_CODES[row['code']]
            gateway = ipaddress.IPv6Address(row['via'])
            if row['resolved']:
                ipaddress.IPv6Address(row['resolved'])
        except ValueError:
            prefix = None
            unknown.append({'line': number, 'text': raw})
            continue
        connected = gateway == ipaddress.IPv6Address('::')
        rows.append(tables.record(table, prefix=prefix, next_hop=None if connected else str(gateway),
                                  interface=row['interface'] or row['egress'], protocol=protocol, vrf=vrf))
    return rows, unknown
