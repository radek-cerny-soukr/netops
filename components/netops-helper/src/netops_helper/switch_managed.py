"""FortiLink selectors and captured FortiOS MAC/LLDP output variants."""
from __future__ import annotations

import re

from .read_policy import _validate_slot

TABLES = {'mac_entry': 'managed_switch_mac', 'lldp_neighbor': 'managed_switch_lldp',
          'interface': 'managed_switch_port_stats', 'interface_errors': 'managed_switch_port_stats',
          'port_vlan': 'managed_switch_port_vlans'}
SERIAL = r'S[A-Z0-9]{11,15}'


def parameters(profile, table, managed_switch):
    if profile == 'fortinet' and table in TABLES:
        if managed_switch is None:
            raise ValueError('managed_switch is required for FortiSwitch tables')
        return {'managed_switch': _validate_slot(managed_switch, 'managed_switch_serial')}
    if managed_switch is not None:
        raise ValueError('managed_switch applies only to FortiOS managed-switch tables')
    return {}


def parse(table, text):
    # Keep the documented parser, including its MAC flag continuation handling.
    # Blank only known transcript metadata, preserving original line numbers.
    from . import tables
    if table in ('interface', 'interface_errors', 'port_vlan'):
        from . import fortiswitch_ports
        return fortiswitch_ports.parse(table, text)
    if table == 'route':
        return routes(table, text)
    if table not in TABLES:
        return tables.fortinet(table, text)
    metadata = (
        r'Vdom:\s*[A-Za-z0-9_-]+',
        r'Total Displayed:\s*\d+',
        r'diagnose switch-controller switch-info mac-table(?: ' + SERIAL + r')?',
        r'diagnose switch-controller switch-info lldp (?:neighbors-summary|neighbor (?:\x08)?s-summary) ' + SERIAL,
        r'[A-Za-z0-9_-]+(?:\((?:Primary|Secondary)\))?\s*[#$]',
    )
    text = '\n'.join('' if any(re.fullmatch(pattern, raw.strip()) for pattern in metadata) else raw
                     for raw in text.splitlines())
    if table != 'lldp_neighbor' or not re.search(r'Portname\s+Status\s+Device-name\s+TTL\s+Capability\s+MED-type\s+Port-ID', text):
        return tables.fortinet(table, text)

    def row(value):
        match = re.fullmatch(r'(port\d+(?:\.\d+)?)\s++(?:Up|Down)\s++(\S(?:.*?\S)?)\s++(\d+|-)\s++([A-Z]+|-)\s++(\S+)\s++(\S+)', value)
        if match:
            if all(match[index] == '-' for index in range(2, 7)):
                return []  # An empty LLDP slot is no neighbour or interface-state evidence.
            return tables.record(table, local_port=match[1], neighbor=match[2] if match[2] != '-' else None,
                                 neighbor_port=match[6] if match[6] != '-' else None,
                                 capabilities=tables.capabilities(','.join(match[4])) if match[4] != '-' else None)
        return None

    return tables.lines(text, row, (
        r'Managed Switch\s*:\s*' + SERIAL + r'\s+\d+',
        r'Capability codes:', r'R:Router, B:Bridge, T:Telephone, C:DOCSIS Cable Device',
        r'W:WLAN Access Point, P:Repeater, S:Station, O:Other', r'MED type codes:',
        r'Generic:Generic Endpoint \(Class 1\), Media:Media Endpoint \(Class 2\)',
        r'Comms:Communications Endpoint \(Class 3\), Network:Network Connectivity Device',
        r'Portname\s+Status\s+Device-name\s+TTL\s+Capability\s+MED-type\s+Port-ID', r'[_ ]+',
    ))


def supported_tables():
    from . import tables
    return sorted(key for key in tables.BINDINGS['fortinet'] if key in tables.FIELDS)


def routes(table, text, *, lookup=False):
    """Adapt the existing FortiOS lookup parser and the compact IPv4 table."""
    import ipaddress
    from . import tables, triage_routing
    from .triage_health import Unparsed

    vrf = 'default'
    numbered = []
    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        match = re.fullmatch(r'Routing table for VRF=(\S+)', value)
        if match:
            vrf = match[1].split('(')[0]
            vrf = 'default' if vrf == '0' else vrf
        numbered.append((number, raw))
    if lookup:
        try:
            route = triage_routing.route_lookup(text)
        except (Unparsed, ValueError):
            return [], [{'line': n, 'text': raw} for n, raw in numbered if raw.strip()]
        return ([tables.record('route', prefix=route['prefix'], next_hop=hop['gateway'],
                               interface=hop['interface'], protocol=route['protocol'], vrf=vrf)
                 for hop in route['next_hops']] if route else []), []

    vrf = 'default'
    rows, unknown, prefix, protocol = [], [], None, None
    codes = {'K': 'kernel', 'C': 'connected', 'S': 'static', 'R': 'rip', 'B': 'bgp',
             'O': 'ospf', 'i': 'isis', 'V': 'bgp', 'E': 'bgp', 'L': 'leaked', 'D': 'leaked'}
    headings = (r'Codes: K - kernel, C - connected, S - static, R - RIP, B - BGP',
                r'O - OSPF, IA - OSPF inter area',
                r'N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2',
                r'E1 - OSPF external type 1, E2 - OSPF external type 2',
                r'i - IS-IS, L1 - IS-IS level-1, L2 - IS-IS level-2, ia - IS-IS inter area',
                r'V - BGP VPNv4, E - BGP EVPN, L - Leaked, D - Directly leaked', r'\* - candidate default',
                r'Routing table for VRF=\S+')
    for number, raw in numbered:
        value = raw.strip()
        vrf_heading = re.fullmatch(r'Routing table for VRF=(\S+)', value)
        if vrf_heading:
            vrf = vrf_heading[1].split('(')[0]
            vrf = 'default' if vrf == '0' else vrf
        if not value or any(re.fullmatch(h, value) for h in headings):
            continue
        head = re.fullmatch(r'([KCSRBOVELDi](?:\*| [A-Za-z0-9]+)?)\s+(\d+(?:\.\d+){3}/\d+)\s+(.+)', value)
        if head:
            try:
                prefix = str(ipaddress.IPv4Network(head[2], strict=False))
            except ValueError:
                prefix = None
            protocol, rest = codes[head[1][0]], head[3]
        elif raw[:1].isspace() and value.startswith('[') and prefix:
            rest = value
        else:
            prefix = None
            unknown.append({'line': number, 'text': raw})
            continue
        connected = re.fullmatch(r'is directly connected, ([^,\s]+)(?:, .*)?', rest)
        hop = re.fullmatch(r'\[\d+/\d+\] via (\d+(?:\.\d+){3}), ([^,\s]+)(?:, .*)?', rest)
        tunnel = re.fullmatch(r'\[\d+/\d+\] via ([^,\s]+) tunnel (\d+(?:\.\d+){3})(?:, .*)?', rest)
        try:
            gateway = str(ipaddress.IPv4Address(hop[1] if hop else tunnel[2])) if hop or tunnel else None
            interface = connected[1] if connected else hop[2] if hop else tunnel[1] if tunnel else None
            if prefix is None or interface is None:
                raise ValueError()
        except ValueError:
            unknown.append({'line': number, 'text': raw})
        else:
            rows.append(tables.record('route', prefix=prefix, next_hop=gateway, interface=interface,
                                      protocol=protocol, vrf=vrf))
    return rows, unknown
