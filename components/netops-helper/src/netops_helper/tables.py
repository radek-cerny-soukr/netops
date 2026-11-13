"""Dependency-free operational records above the canonical read catalogue.

Only explicitly recognized headings/metadata are skipped. Every other line is
retained with its line number in unparsed, including unsupported output variants.
"""
from __future__ import annotations

import ipaddress
import re

from .normalization import (normalize_mac, normalize_port,
                            exos_exit_250, output_status, refusal_hint, response_envelope, source_record)
from .query_catalog import READ_QUERIES
from .read_policy import _validate_slot
from . import port_vlan
from . import switch_managed, fortiswitch_ports

FIELDS = {
    'interface': ('name', 'description', 'admin_status', 'oper_status', 'speed', 'vlan_id', 'trunk', 'mac', 'mtu'),
    'vlan': ('vlan_id', 'name', 'ports'),
    'mac_entry': ('mac', 'vlan_id', 'port', 'type', 'vlan_name'),
    'neighbor_l3': ('ip', 'mac', 'interface', 'vlan_id', 'vrf', 'type'),
    'lldp_neighbor': ('local_port', 'neighbor', 'neighbor_port', 'management_ip', 'capabilities'),
    'route': ('prefix', 'next_hop', 'interface', 'protocol', 'vrf'),
    'ospf_neighbor': ('neighbor_id', 'address', 'interface', 'state', 'role', 'vrf'),
    'bgp_peer': ('neighbor', 'remote_as', 'state', 'prefixes', 'vrf'),
    'lag': ('name', 'protocol', 'status', 'members'),
    'stp_port': ('instance', 'port', 'role', 'state', 'cost'),
    'aggregate': ('name', 'member_count'),
    'port_vlan': port_vlan.FIELDS,
    'ip_interface': ('interface', 'ip', 'prefix_length', 'vlan_id', 'admin_status', 'oper_status', 'vrf', 'mac', 'gateway'),
}
# Parser bindings reference catalogue names, never CLI strings or permissions.
BINDINGS = {}
PARSERS = {}
TABLE_PARSERS = {}
# Parsers of one (profile, table, query) output and the bindings of a target declared as router
# without switch; both are registered by the table modules (ip_interfaces.py) at the end of this file.
QUERY_PARSERS = {}
ROUTER_BINDINGS = {}
MAC = r'(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}|(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}'


def record(table, **values):
    return {key: values.get(key) for key in FIELDS[table]}


def port(value):
    value = value.rstrip(',*')
    # normalize_port returns any safe name as kind "other"; a table cell is a
    # port only when it is physical/aggregate or a known logical interface name.
    try:
        found = normalize_port(value)
    except ValueError:
        found = None
    if found and found['kind'] != 'other':
        return found['name']
    if found:
        value = found['name']
    if re.fullmatch(r'(?:Vlan|Vl|vlan|irb\.|lo|Lo|Loopback|Null|mgmt|Ma|Management|Vxlan|Vx|Tunnel|Tu|nve|BDI|PEt|fxp|em|me|bme|jsrv)[0-9]+(?:[./][0-9]+)*|vme(?:\.[0-9]+)?', value):
        return value
    raise ValueError('not a port name')


def vlan(value):
    match = re.fullmatch(r'(?:Vlan|Vl|vlan|irb\.)?([0-9]+)', value)
    return int(match[1]) if match and 1 <= int(match[1]) <= 4094 else None


def literal(value):
    try:
        return 'ip', _validate_slot(value, 'ip_literal')
    except ValueError:
        return 'mac', _validate_slot(value, 'mac_literal')


def request(profile, table, vlan_id=None, mac=None, ip=None, device_types=None, interface=None, managed_switch=None):
    if table not in FIELDS:
        raise ValueError('unknown normalized table')
    if profile == 'linux' and table == 'interface' and interface is not None:
        if any(value is not None for value in (vlan_id, mac, ip, managed_switch)):
            raise ValueError('filter does not apply to this table')
        return 'interface_link', {'interface': _validate_slot(interface, 'interface')}, {}
    from . import fortigate_tables
    if profile == 'fortinet' and managed_switch is None and table in fortigate_tables.QUERIES:
        return fortigate_tables.request(table, vlan_id, mac, ip, interface)
    parameters = switch_managed.parameters(profile, table, managed_switch)
    if profile == 'fortinet' and table in ('interface', 'interface_errors', 'port_vlan'):
        from . import fortiswitch_ports
        return fortiswitch_ports.request(table, parameters, vlan_id, mac, ip, interface)
    if table == 'interface_errors':
        from . import port_errors
        if any(value is not None for value in (vlan_id, mac, ip)):
            raise ValueError('filter does not apply to this table')
        return port_errors.request(profile, interface)
    filters = {}
    if interface is not None and table == 'port_vlan':
        if not isinstance(interface, str):
            raise ValueError('interface only filters interface, port_vlan, ip_interface and interface_errors')
        filters['port'] = port(interface)
    elif interface is not None:
        from . import linux_tables
        validate_name = linux_tables.name if profile == 'linux' else ip_interfaces.name
        filters['name' if table == 'interface' else 'interface'] = validate_name(_validate_slot(interface, 'interface'))
    if vlan_id is not None:
        filters['vlan_id'] = int(_validate_slot(vlan_id, 'vlan_id'))
    if mac is not None:
        filters['mac'] = _validate_slot(mac, 'mac_literal')
    if ip is not None:
        filters['ip'] = _validate_slot(ip, 'ip_literal')
    if (mac is not None and table not in ('mac_entry', 'neighbor_l3')
            or ip is not None and table not in ('neighbor_l3', 'route')
            or vlan_id is not None and table not in ('interface', 'vlan', 'mac_entry', 'neighbor_l3')
            or interface is not None and table not in ('interface', 'port_vlan', 'ip_interface')):
        raise ValueError('filter does not apply to this table')
    key = 'neighbor_l3_v6' if table == 'neighbor_l3' and ip and ':' in ip else table
    if table == 'route':
        if ip is None:
            # the whole table, where the catalogue has a plain table template (route_all)
            if 'route_all' not in BINDINGS.get(profile, {}):
                raise ValueError('route requires ip (an enrolled address for catalogue lookup)')
            key = 'route_all'
        else:
            key = 'route_v6' if ':' in ip else 'route'
    query = BINDINGS.get(profile, {}).get(key)
    if device_types and 'router' in device_types and 'switch' not in device_types:
        query = ROUTER_BINDINGS.get(profile, {}).get(key, query)
    template = READ_QUERIES.get(profile, {}).get(query)
    if template is None:
        return None, {}, filters
    # L2 and routing templates are template groups: a group needs the matching
    # device type on the target. A template without a group serves any type.
    if device_types is not None and template.group is not None and template.group not in device_types:
        return None, {}, filters
    # A lookup template takes the address as a slot; a plain route table (EXOS) is read whole
    # and narrowed to the longest matching prefix by longest_prefix().
    address = filters.pop('ip', None) if table == 'route' else None
    return query, {**parameters, **({'address': address} if '{address}' in template.command else {})}, filters


def longest_prefix(records, ip):
    """The routes that win a lookup of `ip` in a whole table: all entries of the longest matching prefix."""
    address = ipaddress.ip_address(ip)
    matches = []
    for row in records:
        try:
            network = ipaddress.ip_network(row['prefix'])
        except (TypeError, ValueError):
            continue
        if address in network:
            matches.append((network.prefixlen, row))
    best = max((length for length, _ in matches), default=None)
    return [row for length, row in matches if length == best]


def parse(profile, table, query, text, *, rc=0, status=None, filters=None, command=None, refused=False):
    entry = READ_QUERIES.get(profile, {}).get(query)
    if command is None and entry is not None and not entry.slots:
        command = entry.command
    state = status or output_status(text, rc=rc, profile=profile, command=command)
    if table == 'interface_errors':
        state = _port_errors.output_state(profile, query, text, state, rc)
    refusal_states = {'permission_denied', 'unsupported', 'not_applicable'}
    refusal_like = refused or output_status(text, profile=profile) in refusal_states
    rows, unknown = [], []
    parser = QUERY_PARSERS.get((profile, table, query), PARSERS.get(profile))
    if table in TABLE_PARSERS and profile in _port_errors.PROFILES:
        parser = lambda selected, output: TABLE_PARSERS[selected](profile, output, command=command)
    protected = False
    # Refusal data cannot turn a failed command/transport into a successful read.
    guard_allowed = state in refusal_states and (rc in (0, None) or exos_exit_250(profile, rc, text))
    if parser and (state == 'ok' or refusal_like and guard_allowed):
        rows, unknown = port_vlan.parse(profile, query, text) if table == 'port_vlan' and profile != 'fortinet' else parser(table, text)
        if table == 'vlan' and profile in ('cisco_ios', 'cisco_xe'):
            for row in rows:
                if not row['ports']:
                    row['ports'] = None
        protected = bool(rows) and refusal_like and guard_allowed
        if protected:
            state = 'unparsed' if unknown else 'ok'
        elif state != 'ok':
            rows, unknown = [], []
        elif unknown:
            state = 'unparsed'
        elif not rows:
            state = 'empty'
    elif state == 'ok':
        state = 'unsupported'
    # A field counts as missing when the catalogue output never supplies it; a value that is
    # absent in some rows (no description on a port, no speed on a down link) is normal.
    missing = sorted(field for field in (FIELDS[table] if rows else ())
                     if field not in optional_fields(profile, table) and all(row.get(field) is None for row in rows))
    result = response_envelope(profile, state, [source_record(query, text, state)] if query else [])
    result.update(ok=state in ('ok', 'empty'), table=table, records=[row for row in rows if all(row.get(k) == v for k, v in (filters or {}).items())],
                  unparsed=unknown)
    result['coverage'] = {'complete': state in ('ok', 'empty') and not missing and not unknown and not protected,
                          'parsed_records': len(rows), 'unparsed_lines': len(unknown), 'missing_fields': missing}
    if protected:
        result['coverage']['warnings'] = ['refusal_like_line_in_data']
        result['warnings'].append('refusal_like_line_in_data')
    if missing:
        result['warnings'].append('fields_absent_in_catalogue_output')
    if unknown:
        result['warnings'].append('unrecognized_output_lines')
    hint = refusal_hint(profile, text, command=command) if state == 'permission_denied' else None
    if hint:
        result['hint'] = hint
    return _port_errors.finalize(result) if table == 'interface_errors' else result


def lines(text, parse_line, headings=()):
    rows, unknown = [], []
    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value or re.fullmatch(r'[-=+ ]+', value) or any(re.fullmatch(h, value, re.I) for h in headings):
            continue
        try:
            parsed = parse_line(value)
        except (ValueError, IndexError):
            parsed = None
        if parsed is None:
            unknown.append({'line': number, 'text': raw})
        else:
            rows.extend(parsed if isinstance(parsed, list) else [parsed])
    return rows, unknown


def neighbor_line(value, style):
    parts = value.split()
    mac_match = re.search(MAC, value)
    addresses = []
    for item in parts:
        try:
            addresses.append(str(ipaddress.ip_address(item)))
        except ValueError:
            pass
    if not addresses:
        return None
    address = addresses[0]
    if style == 'junos':
        interface = parts[3] if ':' not in address else parts[-1]
    elif style == 'exos':
        interface = parts[-1]
    elif style == 'eos' and mac_match:
        # "<MAC> <state> <Interface cell>": the cell may hold several interfaces ("Vlan10, Ethernet2"), same as in ARP.
        cell = value[mac_match.end():].split(None, 1)
        interface = interface_cell(cell[1]) if len(cell) > 1 else parts[-1]
    else:
        interface = parts[-1]
    # Incomplete ARP/ND is a useful record, never a made-up MAC.
    if not mac_match and not re.search(r'\b(?:Incomplete|INCOMPLETE|FAILED)\b', value):
        return None
    if interface == 'Incomplete':
        interface = None
    elif interface:
        try:
            interface = port(interface)
        except ValueError:
            if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}', interface):
                return None
    return record('neighbor_l3', ip=address, mac=normalize_mac(mac_match[0]) if mac_match else None,
                  interface=interface, vlan_id=vlan(interface or ''))


CAPABILITY_CODES = (('O', 'other'), ('P', 'repeater'), ('B', 'bridge'), ('W', 'wlan ap'), ('R', 'router'),
                    ('T', 'telephone'), ('C', 'docsis'), ('S', 'station'))
_CAPABILITY_WORDS = {'other': 'O', 'repeater': 'P', 'bridge': 'B', 'switch': 'B', 'wlan ap': 'W', 'wlan access point': 'W',
                     'access point': 'W', 'router': 'R', 'telephone': 'T', 'phone': 'T', 'docsis cable device': 'C',
                     'docsis': 'C', 'cable device': 'C', 'station only': 'S', 'station': 'S'}


def capabilities(value):
    """IEEE 802.1AB capability set as one canonical string ("B,W"); None when nothing was advertised.

    Accepts the letter form (Cisco "B,T") and the word form (EXOS "Bridge, WLAN AP").
    """
    text = (value or '').strip().strip('"')
    letters = re.fullmatch(r'[A-Za-z](?:\s*,\s*[A-Za-z]|\s+[A-Za-z])*', text)
    items = [item.lower() for item in (re.split(r'[,\s]+', text) if letters else (part.strip() for part in text.split(','))) if item]
    if not items:
        return None
    found = set()
    for item in items:
        code = item.upper() if len(item) == 1 and item.upper() in dict(CAPABILITY_CODES) else _CAPABILITY_WORDS.get(item, 'O')
        found.add(code)
    return ','.join(code for code, _ in CAPABILITY_CODES if code in found)


def columns(header, *names):
    """Start offsets of fixed-width columns, taken from the header line the device printed."""
    return [header.index(name) for name in names]


def cut(raw, starts, index):
    end = starts[index + 1] if index + 1 < len(starts) else None
    return raw[starts[index]:end].strip()


EXOS_PORT_STATE = {'E': 'up', 'D': 'down', 'F': 'down', 'L': 'down'}
EXOS_ORIGIN = {'d': 'connected', 'div': 'connected', 's': 'static', 'bo': 'bootp', 'h': 'hardcoded', 'b': 'blackhole', 'i': 'icmp',
               'r': 'rip', 'o': 'ospf', 'o1': 'ospf', 'o2': 'ospf', 'oa': 'ospf', 'oe': 'ospf', 'or': 'ospf', 'oiv': 'ospf',
               'bg': 'bgp', 'be': 'bgp', 'bi': 'bgp', 'un': 'unknown'}


def exos_lldp(text):
    """`show lldp neighbors detailed`: one record per "Neighbor:" block; TLV lines are recognized by structure."""
    rows, unknown, current, port_name = [], [], None, None
    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value or re.fullmatch(r'-{20,}', value):
            continue
        m = re.fullmatch(r'LLDP Port (\S+) detected (\d+) neighbors?', value)
        if m:
            current = None
            try:
                port_name = m[1] if m[1] == 'mgmt' else port(m[1])      # the out-of-band port is only called "mgmt"
            except ValueError:
                port_name = None
                unknown.append({'line': number, 'text': raw})
            continue
        if re.fullmatch(r'Neighbor: .+, age \d+ seconds?', value) and re.match(r' {2}\S', raw):
            current = record('lldp_neighbor', local_port=port_name)
            rows.append(current)
            continue
        if current is None:
            unknown.append({'line': number, 'text': raw})
            continue
        m = re.fullmatch(r'Chassis ID +: (.*)', value) and re.match(r' {6}Chassis ID ', raw)
        if m:
            continue
        m = re.fullmatch(r'Port ID +: "?(.*?)"?', value) if re.match(r' {6}Port ID ', raw) else None
        if m:
            current['neighbor_port'] = m[1] or None
            continue
        m = re.fullmatch(r'- System Name: "(.*)"', value)
        if m:
            current['neighbor'] = m[1] or None
            continue
        m = re.fullmatch(r'Enabled Capabilities: "(.*)"', value)
        if m:
            current['capabilities'] = capabilities(m[1])
            continue
        m = re.fullmatch(r'Management Address +: (\S+)', value)
        if m and current['management_ip'] is None:
            try:
                current['management_ip'] = str(ipaddress.ip_address(m[1]))
            except ValueError:
                pass            # a MAC or other address subtype is not a management IP
            continue
        # TLV headers ("    - ..."), their attributes (6 spaces) and wrapped quoted strings
        # (deeper indent) keep the structure of the output; anything else is unknown.
        if re.match(r' {4}- \S', raw) or re.match(r' {6,}\S', raw):
            continue
        unknown.append({'line': number, 'text': raw})
    return rows, unknown


def exos_lacp(text):
    """`show lacp`: one record per LAG row; the LAG is named by its master port, which is what the FDB shows."""
    def handle(raw, value):
        if matches(value, (r'LACP (?:Up|Enabled)\s*:\s*\S+', r'System MAC\s*:\s*(?:' + MAC + ')', r'LACP PDUs dropped on non-LACP ports\s*:\s*\d+',
                           r'Lag\s+Actor\s+Actor\s+Partner\s+Partner\s+Partner\s+Agg', r'Sys-Pri\s+Key\s+MAC\s+Sys-Pri\s+Key\s+Count')):
            return []
        m = re.fullmatch(r'(\d+(?::\d+)?)\s+\d+\s+0x[0-9a-fA-F]+\s+(?:' + MAC + r')\s+\d+\s+0x[0-9a-fA-F]+\s+(\d+)', value)
        if m:
            return record('aggregate', name=port(m[1]), member_count=int(m[2]))
        return None
    return scan(text, handle)


def exos_sharing(text):
    """Load Sharing Monitor: config master names the group; Agg Mbr and Link State describe members."""
    current = [None]
    number_of_groups = [None]
    def handle(raw, value):
        if matches(value, (r'show sharing', r'\*?\s*[A-Za-z0-9_.-]+\.\d+\s+[>#]', r'Load Sharing Monitor', r'Config\s+Current Agg\s+Min\s+Ld Share\s+Ld Share\s+Agg Link\s+Link Up',
                           r'Master\s+Master\s+Control Active Algorithm Flags Group\s+Mbr State Transitions',
                           r'Link State: A-Active, D-Disabled, R-Ready, NP-Port not present, L-Loopback',
                           r'Minimum Active: \(<\) Group is down\. # active links less than configured minimum',
                           r'Flags:',
                           r'A - All: Distribute to all members,', r'd - Dynamically created shared port,',
                           r'L - Local Slot: Distribute to members local to ingress slot,',
                           r'P - Port Lists: Distribute to per-slot configurable subset of members,',
                           r'R - Resilient Hashing enabled\.')):
            return []
        # Split at commas first: each item has a disjoint token/description grammar,
        # so a malformed or long legend cannot cause nested-regex backtracking.
        legend = value.removeprefix('Load Sharing Algorithm: ')
        if (legend != value or value.startswith('(L')) and all(
                re.fullmatch(r'\(L[0-9][A-Za-z0-9_]*\)[ \t]+[A-Za-z][^,()\r\n]*', item.strip())
                for item in legend.split(',')):
            return []
        m = re.fullmatch(r'Number of load sharing trunks:\s*(\d+)', value)
        if m:
            number_of_groups[0] = int(m[1])
            return []
        # Flags may be blank on continuation rows; '-' is an unaggregated member.
        m = re.fullmatch(r'(\d+(?::\d+)?)\s+(\d+(?::\d+)?|-)\s+(LACP|STATIC)\s+(<?\d+)\s+'
                         r'(L2|L3_L4|L3|custom)\s+([AdLPR-]+)\s+(\d+(?::\d+)?)\s+(Y|N|-)\s+(A|D|R|NP|L)\s+(\d+)', value, re.I)
        if m:
            current[0] = record('lag', name=port(m[1]), protocol='LACP' if m[3].upper() == 'LACP' else 'Static',
                                status='down' if m[4].startswith('<') else None, members=[])
            member, aggregated, link = m[7], m[8], m[9]
            result = current[0]
        else:
            m = re.fullmatch(r'(L2|L3_L4|L3|custom)[ \t]+(?:([AdLPR-]+)[ \t]+)?(\d+(?::\d+)?)[ \t]+(Y|N|-)[ \t]+(A|D|R|NP|L)[ \t]+\d+', value, re.I)
            if not m or current[0] is None:
                return None
            member, aggregated, link = m[3], m[4], m[5]
            result = []
        bundled = aggregated.upper() == 'Y' and link.upper() == 'A'
        current[0]['members'].append({'port': port(member), 'state': 'bundled' if bundled else 'down' if link.upper() in ('D', 'R', 'NP', 'L') else 'suspended'})
        if current[0]['status'] is None or current[0]['status'] == 'up':
            current[0]['status'] = 'up' if any(m['state'] == 'bundled' for m in current[0]['members']) else None
        return result
    rows, unknown = scan(text, handle)
    for row in rows:
        if row['status'] is None:
            row['status'] = 'down'
    if number_of_groups[0] != len(rows):
        unknown.append({'line': len(text.splitlines()), 'text': 'load sharing group count missing or mismatched'})
    return rows, unknown


def exos(table, text):
    if table == 'lldp_neighbor':
        return exos_lldp(text)
    if table == 'route':
        return exos_routes(text)
    if table == 'aggregate':
        return exos_lacp(text)
    if table == 'lag':
        return exos_sharing(text)
    pending = [None]
    incomplete = []

    def row(value):
        if table == 'interface':
            m = re.fullmatch(r'(\d+(?::\d+)?)\s+(?:(\S+)\s+)??(\(\d+\)|\S+)\s+([DEFL])\s+(A|R|NP|L|D|d|B)'
                             r'(?:\s+(\d+|-)\s+(HALF|FULL))?', value)
            if m:
                count = re.fullmatch(r'\((\d+)\)', m[3])
                return record(table, name=port(m[1]), description=m[2], admin_status=EXOS_PORT_STATE[m[4]],
                              oper_status='up' if m[5] == 'A' else 'down', speed=None if m[6] in (None, '-') else m[6],
                              trunk=int(count[1]) > 1 if count else False)
        elif table == 'mac_entry':
            m = re.fullmatch(r'('+MAC+r')\s+(\S+?)\((\d{4})\)\s++\d+\s++(\S(?:.*?\S)?)\s++(\S+)', value)
            if m:
                flags = m[4].replace(' ', '')
                kind = 'dynamic' if 'd' in flags else 'static' if 's' in flags else 'permanent' if 'p' in flags else None
                return record(table, mac=normalize_mac(m[1]), vlan_id=int(m[3]), vlan_name=m[2], port=port(m[5].split('(')[0]), type=kind)
        elif table == 'vlan':
            m = re.fullmatch(r'(\S+)\s+(\d+)\s+(?:\S+\s+/\d+\s+\S+|[-\w]{20,})\s+(\S+)\s+\d+\s*/\s*\d+\s+VR-\S+', value)
            if m and 1 <= int(m[2]) <= 4095:
                return record(table, vlan_id=int(m[2]), name=m[1])
        elif table == 'neighbor_l3':
            m = re.fullmatch(r'(VR-\S+)\s+([0-9a-fA-F:]+)', value)
            if m and ':' in m[2]:
                if pending[0] is not None:
                    incomplete.append(pending[0][2])
                pending[0] = (str(ipaddress.ip_address(m[2])), m[1], value)
                return []
            m = re.fullmatch(r'('+MAC+r')\s+\d+\s+(?:YES|NO)\s+(\S+)\s+(\d+)(?:\s+(\S+))?', value)
            if m and pending[0]:
                address, vrf, _ = pending[0]
                pending[0] = None
                return record(table, ip=address, vrf=vrf, mac=normalize_mac(m[1]), vlan_id=int(m[3]),
                              interface=port(m[4]) if m[4] else None)
            m = re.fullmatch(r'(VR-\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+('+MAC+r'|-+|\(?[Ii]ncomplete\)?)\s+\d+\s+(?:YES|NO)\s+(\S+)\s+(\d+)(?:\s+(\S+))?', value)
            if m:
                known = re.fullmatch(MAC, m[3])
                return record(table, ip=str(ipaddress.ip_address(m[2])), vrf=m[1], mac=normalize_mac(m[3]) if known else None,
                              interface=port(m[6]) if m[6] else None, vlan_id=int(m[5]))
        return None
    rows, unknown = lines(text, row, EXOS_HEADINGS[table])
    if pending[0]:
        incomplete.append(pending[0][2])
    for value in incomplete:
        number, raw = next((n, line) for n, line in enumerate(text.splitlines(), 1) if line.strip() == value)
        unknown.append({'line': number, 'text': raw})
    return rows, sorted(unknown, key=lambda item: item['line'])


def exos_routes(text):
    """`show iproute`: a route row is "Ori Destination Gateway Mtr Flags VLAN Duration"; the rest is legend."""
    def row(value):
        m = re.fullmatch(r'[#*@]?(\w{1,3})\s+(Default Route|\d+\.\d+\.\d+\.\d+/\d+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(?:\d+d:\d+h:\d+m:\d+s|\S+)', value)
        if not m:
            return None
        prefix = '0.0.0.0/0' if m[2] == 'Default Route' else str(ipaddress.ip_network(m[2], strict=False))
        try:
            hop = str(ipaddress.ip_address(m[3]))
        except ValueError:
            hop = None
        protocol = EXOS_ORIGIN.get(m[1], m[1])
        # EXOS prints the local VLAN address in Gateway for direct routes.
        return record('route', prefix=prefix, next_hop=None if protocol == 'connected' else hop,
                      interface=m[6], protocol=protocol, vrf='VR-Default')
    return lines(text, row, EXOS_HEADINGS['route'])


_EXOS_LEGEND = (r'\(\w{1,3}\) .*', r'[A-Za-z]-[A-Za-z!$#?*].*')
EXOS_HEADINGS = {
    'interface': (r'Port Summary', r'Port\s+Display\s+VLAN Name\s+Port\s+Link\s+Speed\s+Duplex',
                  r'#\s+String\s+\(or # VLANs\)\s+State State Actual Actual', r'Port State: .*', r'Link State: .*',
                  r'[A-Za-z]-[A-Za-z][^:]*,?'),
    'mac_entry': (r'MAC\s+VLAN Name\( Tag\)\s+Age\s+Flags\s+Port / Virtual Port List', r'Flags : .*',
                  r'[a-zA-Z] ?- .*', r'Total: \d+ Static: \d+ +Perm: \d+ +Dyn: \d+ +Dropped: \d+ +Locked: \d+ +Locked with Timeout: \d+',
                  r'FDB Aging time: \d+', r'No FDB entries.*'),
    'vlan': (r'Untagged ports auto-move: \w+', r'Name\s+VID\s+Protocol Addr\s+Flags\s+Proto\s+Ports\s+Virtual',
             r'Active router', r'/Total', r'Flags : .*', r'\(\w\) .*', r'Total number of VLAN\(s\)\s*: \d+'),
    'neighbor_l3': (r'VR\s+Destination\s+Mac\s+Age\s+Static\s+VLAN\s+VID\s+Port', r'VR\s+Destination',
                    r'Mac\s+Age\s+Static\s+VLAN\s+VID\s+Port',
                    r'Total Entries\s*:\s*\d+', r'Dynamic Entries\s*:\s*\d+\s+Static Entries\s*:\s*\d+', r'Pending Entries\s*:\s*\d+',
                    r'ARP address check:\s*\w+\s+ARP refresh\s*:\s*\w+', r'Timeout\s*:\s*\d+ minutes\s+(?:ARP Sender-Mac Learning|Refresh)\s*:\s*\w+',
                    r'Locktime\s*:\s*\d+ milliseconds', r'Retransmit Time\s*:\s*\d+ milliseconds',
                    r'Reachable Time\s*:\s*\d+ milliseconds \(\w+\)', r'Fast Convergence\s*:\s*\w+',
                    r'ARP Global Settings', r'Neighbor Discovery Global Settings',
                    r'Max (?:Pending |Proxy )?Entries\s*:\s*\d+'),
    'route': (r'Ori\s+Destination\s+Gateway\s+Mtr\s+Flags\s+VLAN\s+Duration', r'Origin\(Ori\):.*', r'\(\W?\w{0,3}\W?\) .*',
              r'Flags:.*', r'MPLS Label: .*', r'Mask distribution:', r'\d+ default routes.*', r'\d+ routes at length \d+.*',
              r'Route [Oo]rigin distribution:', r'\d+ routes from \w+.*', r'Total number of (?:compressed )?routes\s*=\s*\d+'),
}


BINDINGS['extreme_exos'] = {'interface': 'ports', 'vlan': 'vlan_summary', 'mac_entry': 'mac_table',
                            'neighbor_l3': 'arp_table', 'neighbor_l3_v6': 'ipv6_neighbors',
                            'lldp_neighbor': 'lldp_neighbors_detail', 'route': 'route_table', 'route_all': 'route_table',
                            'aggregate': 'lacp', 'lag': 'lag_summary'}
PARSERS['extreme_exos'] = exos


# --- shared scanning helpers for the table-shaped OS outputs ---------------------------------

SYSTEM_PORTS = re.compile(r'(?:CPU|Cpu|Router|Switch|[Ss]up-eth\d+|Vl\d+|Vlan\d+|nve\d+.*|--)(?:\(R\))?')
# Fields a table may legitimately leave empty without the output being incomplete.
OPTIONAL_FIELDS = {'mac_entry': {'vlan_name'}, 'neighbor_l3': {'vrf', 'type'}, 'ospf_neighbor': {'role', 'vrf'}, 'bgp_peer': {'prefixes', 'vrf'},
                   'port_vlan': {'access_vlan', 'native_vlan'},
                   'lag': {'protocol'}, 'stp_port': {'cost'}, 'route': {'next_hop', 'interface', 'vrf'},
                   'interface': {'description', 'speed', 'admin_status', 'mac', 'mtu'}, 'ip_interface': {'vlan_id', 'vrf', 'mac', 'gateway'}}


# Only catalogue fields unavailable on this profile; other platforms keep their coverage.
PROFILE_OPTIONAL_FIELDS = {'linux': {'interface': {'vlan_id', 'trunk'},
                                    'ip_interface': {'admin_status'},
                                    'neighbor_l3': {'vlan_id'}}}


def optional_fields(profile, table):
    return set(OPTIONAL_FIELDS.get(table, ())) | PROFILE_OPTIONAL_FIELDS.get(profile, {}).get(table, set())


def scan(text, handle):
    """handle(raw, value) -> list of records, [] for a recognized line, None for an unknown one."""
    rows, unknown = [], []
    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value or re.fullmatch(r'[-=+ ]+', value):
            continue
        try:
            parsed = handle(raw, value)
        except (ValueError, IndexError, KeyError):
            parsed = None
        if parsed is None:
            unknown.append({'line': number, 'text': raw})
        else:
            rows.extend(parsed if isinstance(parsed, list) else [parsed])
    return rows, unknown


def matches(value, patterns):
    return any(re.fullmatch(pattern, value, re.I) for pattern in patterns)


def port_list(text):
    """Comma separated ports of a VLAN or MAC row; the CPU/system pseudo ports are not member ports."""
    return [port(item) for item in re.split(r'[,\s]+', text) if item and not SYSTEM_PORTS.fullmatch(item.rstrip(',*'))]


STATUS_UP = {'connected', 'monitoring'}
STATUS_DOWN = {'notconnect', 'notconnec', 'disabled', 'err-disabled', 'errdisabled', 'inactive', 'sfpabsent', 'xcvrabsen',
               'xcvrabsent', 'noopermem', 'down', 'suspended', 'faulty', 'linkflape', 'sfpinvali', 'xcvrinval', 'channeldo',
               'suspndbyv', 'sfpinvalid', 'noconnect', 'err-disabl'}


def status_table(text):
    """`show interface(s) status` (IOS/XE/NX-OS/EOS): columns are cut where the header prints them."""
    starts = []

    def handle(raw, value):
        if re.match(r'Port\s+Name\s+Status\s+Vlan\s+Duplex\s+Speed', value):
            starts[:] = columns(raw, 'Name', 'Status', 'Vlan', 'Duplex', 'Speed')
            return []
        if not starts:
            return None
        name = raw[:starts[0]].strip()
        state = cut(raw, starts, 1)
        vlan_cell = cut(raw, starts, 2)
        if not name or ' ' in name or not state or ' ' in state and not state.startswith('in '):
            return None
        status = state.lower()
        if status not in STATUS_UP | STATUS_DOWN:
            return None
        description = raw[starts[0]:starts[1]].strip()
        speed = raw[starts[4]:].split()
        trunk = True if vlan_cell == 'trunk' else False if vlan(vlan_cell) or vlan_cell in ('routed', '--') or vlan_cell.startswith('in ') else None
        return record('interface', name=port(name), description=None if description in ('', '--') else description,
                      admin_status='down' if status == 'disabled' else None,
                      oper_status='up' if status in STATUS_UP else 'down',
                      speed=speed[0] if speed else None, vlan_id=vlan(vlan_cell), trunk=trunk)
    return scan(text, handle)


def vlan_sections(text, style):
    """`show vlan [brief]` (IOS/XE/NX-OS/EOS): the VLAN/Name/Status/Ports table plus its continuation lines;
    NX-OS also prints Type, Remote SPAN and Private-VLAN sections, which carry no ports of the main table."""
    state = {'section': None, 'last': None}
    active = r'(?:active|act/unsup|act/lshut|sus/lshut|suspend|shutdown|act/ishut|sus/ishut)'

    def handle(raw, value):
        if re.match(r'VLAN\s+Name\s+Status\s+Ports', value):
            state['section'] = 'vlan'
            return []
        if re.match(r'VLAN\s+Type\s+Vlan-mode', value):
            state['section'] = 'type'
            return []
        if re.match(r'Primary\s+Secondary\s+Type\s+Ports', value):
            state['section'] = 'private'
            return []
        if re.fullmatch(r'Remote SPAN VLANs', value):
            state['section'] = 'remote'
            return []
        section = state['section']
        if section == 'vlan':
            m = re.fullmatch(r'(\d+)\s++(\S(?:.*?\S)?)\s++(' + active + r')(?:\s+(.*))?', value)
            if m:
                result = record('vlan', vlan_id=int(m[1]), name=m[2], ports=port_list(m[4] or ''))
                state['last'] = result
                return result
            if state['last'] is not None and re.fullmatch(r'[A-Za-z][A-Za-z0-9/.,\- ]*', value) and raw.startswith(' '):
                state['last']['ports'].extend(port_list(value))
                return []
        elif section == 'type':
            if re.fullmatch(r'\d+\s+\S+\s+\S+', value):
                return []
        elif section == 'remote':
            if re.fullmatch(r'[\d,\- ]+|-', value):
                return []
        elif section == 'private':
            if re.fullmatch(r'\d+\s+\d+\s+\S+(?:\s+.*)?', value):
                return []
        return None
    return scan(text, handle)


def mac_type(word):
    word = word.lower()
    return 'dynamic' if word in ('dynamic', 'd', 'learn', 'learned') else 'static' if 'static' in word or word in ('s', 'secure') else word


def mac_ios(text):
    """IOS / IOS XE `show mac address-table`; "All ... CPU" and SVI rows are the switch itself, not a host."""
    def handle(raw, value):
        if matches(value, (r'Mac Address Table', r'Vlan\s+Mac Address\s+Type\s+Ports?', r'Total Mac Addresses for this criterion:\s*\d+',
                           r'Unicast Entries', r'Multicast Entries')):
            return []
        m = re.fullmatch(r'(\d+|All)\s+(' + MAC + r')\s+(\S+)\s+(.+)', value)
        if not m:
            return None
        cell = m[4].strip()
        if m[1] == 'All' or SYSTEM_PORTS.fullmatch(cell):
            return []
        return [record('mac_entry', mac=normalize_mac(m[2]), vlan_id=int(m[1]), type=mac_type(m[3]), port=port(item))
                for item in cell.split(',')]
    return scan(text, handle)


def mac_nxos(text):
    legend = {'on': False}

    def handle(raw, value):
        if value == 'Legend:':
            legend['on'] = True
            return []
        if re.match(r'VLAN\s+MAC Address\s+Type\s+age\s+Secure\s+NTFY\s+Ports', value):
            legend['on'] = False
            return []
        if legend['on']:
            return [] if re.match(r'(?:[*+GOC] - |age - |\(T\) - |\(R\) - |\*\s*-)', value) or ' - ' in value else None
        m = re.fullmatch(r'(?:[*+GOC~]|\(R\))*\s*(\d+|-)\s+(' + MAC + r')\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)', value)
        if not m:
            return None
        cell = m[7].strip()
        if m[1] == '-' or SYSTEM_PORTS.fullmatch(cell):
            return []
        if cell.startswith('vPC Peer-Link'):
            return record('mac_entry', mac=normalize_mac(m[2]), vlan_id=int(m[1]), type='trunk', port='vPC Peer-Link')
        return [record('mac_entry', mac=normalize_mac(m[2]), vlan_id=int(m[1]), type=mac_type(m[3]), port=port(item))
                for item in cell.split(',')]
    return scan(text, handle)


def mac_eos(text):
    """`show mac address-table`: Type may hold two words and Ports a comma list, so the line is read from
    the left up to the first plain number (the Moves column of the unicast table)."""
    def handle(raw, value):
        if matches(value, (r'(?:Multicast )?Mac Address Table', r'Total Mac Addresses for this criterion:\s*\d+',
                           r'Vlan\s+Mac Address\s+Type\s+Ports(?:\s+Moves\s+Last Move)?')):
            return []
        m = re.fullmatch(r'(\d+)\s+(' + MAC + r')\s+([A-Z]+(?: [A-Z]+)*)\s+(\S.*)', value)
        if not m:
            return None
        cell = []
        for token in m[4].split():
            if token.isdigit():
                break
            cell.append(token)
        cell = ' '.join(cell)
        if SYSTEM_PORTS.fullmatch(cell):
            return []
        return [record('mac_entry', mac=normalize_mac(m[2]), vlan_id=int(m[1]), type=mac_type(m[3]), port=port(item))
                for item in re.split(r',\s*', cell)]
    return scan(text, handle)


JUNOS_IFL = re.compile(r'(?:(?:[a-z]{2}-\d+/\d+/\d+(?::\d+)?|ae\d+|reth\d+|lag\d+|irb|vtep\S*|esi\.\d+)(?:\.\d+)?|\.local\.\.\d+)')


def mac_junos(text):
    def handle(raw, value):
        if matches(value, (r'MAC flags \(.*', r'[A-Z]{1,2} - .*', r'Ethernet switching table\s*:\s*\d+ entries.*', r'Routing instance\s*:\s*\S+',
                           r'Vlan\s+MAC\s+MAC\s+Logical\s+Active', r'name\s+address\s+flags\s+interface\s+source',
                           r'Vlan\s+MAC\s+MAC\s+Logical', r'name\s+address\s+flags\s+interface', r'MAC database for switching instance.*',
                           r'Vlan\s+MAC\s+MAC\s+Age\s+GBP\s+Logical\s+NH\s+MAC\s+RTR', r'name\s+address\s+flags\s+Tag\s+interface\s+Index\s+property\s+ID',
                           r'VLAN\s+MAC address\s+Type.*', r'\s*(?:\w+ )?entries?.*')):
            return []
        if value.startswith('(') or re.match(r'\s+\S+, ', raw) and ' - ' in value or re.match(r'\s+[A-Z]{1,4} - .*\)?$', raw):
            return []           # wrapped legend of the MAC flags
        m = re.fullmatch(r'(\S+)\s+(' + MAC + r'|\*)\s+(\S+)\s+(.*)', value)
        if not m:
            return None
        if m[2] == '*':
            return []           # flood entry
        flags = m[3].upper()
        # The logical interface is the first token that is an interface name: later releases insert Age and GBP Tag columns
        # (a dash or a number) before it and NH Index, MAC property and RTR ID after it.
        cell = next((token for token in m[4].split() if JUNOS_IFL.fullmatch(token)), None)
        if cell is None:
            return None
        # ELS prints the VLAN by name; the tag comes from a join with `show vlans`, never from a guess.
        return record('mac_entry', mac=normalize_mac(m[2]), vlan_id=vlan(m[1]), vlan_name=m[1], port=port(cell),
                      type='dynamic' if flags.startswith('D') else 'static' if flags.startswith(('S', 'P')) else None)
    return scan(text, handle)


# --- ARP -----------------------------------------------------------------------------------

# EOS prints a legend above the ARP and ND tables ("not learned" marks an entry without a MAC table row).
EOS_NEIGHBOR_LEGEND = (r'Legend:', r'not learned: .*', r'-: Static .*', r'\*: .*',
                       r'Flags: .*', r'(?:G|R|CP|PS|RO|CC|#) - .*')      # NX-OS flag legend above ARP and ND


def ipv6_table(text):
    first = next((line.strip() for line in text.splitlines() if line.strip() and not matches(line.strip(), EOS_NEIGHBOR_LEGEND)), '')
    if first.startswith('IPv6 '):
        return True
    try:
        return ipaddress.ip_address(first.split()[0]).version == 6
    except (ValueError, IndexError):
        return False


def neighbors(text, style):
    """ARP (IPv4) or ND (IPv6) cache: the two queries share the normalized table, the header tells them apart."""
    if ipv6_table(text):
        return scan(text, lambda raw, value: [] if matches(value, (r'IPv6 Address.*', r'IPv6 Adjacency Table.*', r'Address\s+Age\s+MAC Address\s+Pref.*', r'Total number of entries:\s*\d+', r'Flags:.*', r'[*+#]\s*-\s.*') + EOS_NEIGHBOR_LEGEND)
                    else neighbor_line(value, style))
    return arp_rows(text, style)


def interface_cell(cell):
    """First interface of an ARP interface cell ("Vlan10, Ethernet1", "irb.10 [ge-0/0/1.0]"); None if blank."""
    cell = (cell or '').strip()
    if not cell:
        return None
    return port(re.split(r'[,\s]', cell)[0])


def arp_rows(text, style):
    def handle(raw, value):
        if matches(value, (r'Protocol\s+Address\s+Age.*', r'Address\s+Age.*', r'MAC Address\s+Address\s+Name.*', r'MAC Address\s+Address\s+Interface.*',
                           r'IP ARP Table for context.*', r'Total number of entries:\s*\d+', r'Total entries:\s*\d+', r'Flags:.*',
                           r'[*+#]\s*-\s.*', r'(?:CP|PS|RO|D)\s*-\s.*') + EOS_NEIGHBOR_LEGEND):
            return []
        if style == 'ios':
            m = re.fullmatch(r'Internet\s+(\S+)\s+(\S+)\s+(' + MAC + r'|Incomplete)\s+ARPA(?:\s+(\S+))?', value)
            fields = (m[1], m[3], m[4]) if m else None
        elif style == 'nxos':
            m = re.fullmatch(r'(\S+)\s+(\S+)\s+(' + MAC + r'|INCOMPLETE)(?:\s+(\S+))?(?:\s+(?:[*+#]|CP|PS|RO|D))*', value)
            fields = (m[1], m[3], m[4]) if m else None
        elif style == 'eos':
            m = re.fullmatch(r'(\S+)\s+(\S+)\s+(' + MAC + r')\s+(\S.*)', value)
            fields = (m[1], m[3], m[4]) if m else None
        else:       # junos: MAC address interface [physical] flags
            m = re.fullmatch(r'(' + MAC + r')\s+(\S+)\s+(\S+)(?:\s+\[\S+\])?(?:\s+[a-z][a-z-]*)+', value)       # flags: none, permanent published, ...
            fields = (m[2], m[1], m[3]) if m else None
        if not fields:
            return None
        address = str(ipaddress.ip_address(fields[0]))
        interface = interface_cell(fields[2])
        known = re.fullmatch(MAC, fields[1])
        return record('neighbor_l3', ip=address, mac=normalize_mac(fields[1]) if known else None, interface=interface,
                      vlan_id=vlan(interface or ''),
                      type='interface' if style == 'ios' and m[2] == '-' and interface and known else None)
    return scan(text, handle)


# --- LLDP ---------------------------------------------------------------------------------

def cisco_lldp(text, style='ios'):
    """`show lldp neighbors detail`: one block per neighbour. System Description, the management address list,
    media capabilities and the MED section are free text; they are recognized by their section, not parsed."""
    rows, unknown = [], []
    current, section = None, None
    start = 'Local Intf:' if style == 'ios' else 'Chassis id:'
    simple = {'chassis id', 'chassis type', 'port type', 'port description', 'time remaining', 'time to live', 'system capabilities',
              'vlan id', 'peer source mac', 'auto negotiation', 'media attachment unit type', 'mtu', 'max frame size',
              'tac support', 'technical support', 'management address ipv6', 'local port id', 'local intf service instance'}
    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value:
            section = None if section == 'description' else section
            continue
        if re.fullmatch(r'-{10,}', value) or re.fullmatch(r'Total (?:entries|neighbors) displayed:\s*\d+', value, re.I):
            continue
        if current is None and matches(value, (r'Capability codes:', r'\(\w\) .*', r'Device ID\s+Local Intf\s+Hold-time\s+Capability\s+Port ID')):
            continue            # NX-OS prints the legend and a summary header above the detail blocks
        if value.startswith(start):
            current = record('lldp_neighbor')
            rows.append(current)
            section = None
        if current is None:
            unknown.append({'line': number, 'text': raw})
            continue
        indented = raw[:1].isspace()
        if re.fullmatch(r'Auto Negotiation - .*', value) or re.fullmatch(r'[A-Za-z][A-Za-z ]* - not advertised', value):
            continue
        m = re.fullmatch(r'([A-Za-z][A-Za-z0-9 /().-]*?):\s*(.*)', value)
        key = m[1].lower() if m else None
        if section == 'description' and key not in ('time remaining', 'time to live', 'system capabilities', 'enabled capabilities'):
            continue        # System Description is wrapped over several lines, some with a colon
        if section in ('media', 'med', 'addresses') and indented and key not in ('ip', 'ipv6'):
            continue
        if m is None:
            unknown.append({'line': number, 'text': raw})
            continue
        argument = m[2].strip()
        if key == 'other' and section == 'addresses' and indented:
            continue        # a non-IP management address (OID/MAC) is listed beside the IP
        if not (indented and section == 'addresses'):
            section = None if section in ('media', 'addresses') or section == 'description' else section
        try:
            if key in ('local intf', 'local port id') and argument:
                current['local_port'] = port(argument)
            elif key == 'system name':
                current['neighbor'] = None if argument.lower() in ('not advertised', '') else argument
            elif key == 'port id':
                current['neighbor_port'] = argument
            elif key == 'enabled capabilities':
                current['capabilities'] = capabilities(argument)
            elif key in ('management address', 'ip'):
                if argument and argument.lower() != 'not advertised':
                    address = str(ipaddress.ip_address(argument))
                    if current['management_ip'] not in (None, address):
                        unknown.append({'line': number, 'text': raw})       # several addresses: never overwritten
                    current['management_ip'] = current['management_ip'] or address
            elif key == 'ipv6':
                ipaddress.ip_address(argument)
            elif key == 'management addresses':
                section = 'addresses'
            elif key == 'system description':
                section = 'description'
            elif key == 'physical media capabilities':
                section = 'media'
            elif key == 'med information':
                section = 'med'
            elif key in simple or section == 'med':
                continue
            else:
                unknown.append({'line': number, 'text': raw})
        except ValueError:
            unknown.append({'line': number, 'text': raw})
    return rows, unknown


def eos_lldp_detail(text):
    """EOS `show lldp neighbors detail`: "Interface E detected N LLDP neighbors", then a block per `Neighbor`.
    TLVs are "  - Name: value" lines with attributes indented below; wrapped strings and hex dumps are not parsed."""
    rows, unknown = [], []
    local, current, tlv = None, None, None
    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value:
            continue
        m = re.fullmatch(r'Interface (\S+) detected \d+ LLDP neighbors?:?', value)
        if m and not raw[:1].isspace():
            try:
                local = port(m[1])
            except ValueError:
                local = None
                unknown.append({'line': number, 'text': raw})
            current = tlv = None
            continue
        if local is None:
            unknown.append({'line': number, 'text': raw})
            continue
        if re.fullmatch(r'Neighbor \S+/".*", age \d+ seconds?', value) and re.match(r' {2}\S', raw):
            current = record('lldp_neighbor', local_port=local)
            rows.append(current)
            tlv = None
            continue
        if current is None:
            unknown.append({'line': number, 'text': raw})
            continue
        duration = r'(?:\d+ days?, )?\d+:\d{2}:\d{2}'
        if re.fullmatch(r' {2}Discovered ' + duration + r' ago; Last changed ' + duration + r' ago', raw):
            continue
        m = re.match(r' {2}- ([^:]+):\s*(.*)', raw)
        if m:
            tlv, argument = m[1].rstrip(), m[2].strip()
            if tlv == 'System Name':
                current['neighbor'] = argument.strip('"') or None
            elif tlv.startswith('Unknown organizationally-defined TLV'):
                tlv = None
            continue
        m = re.match(r' {2}- (\S.*)', raw)
        if m:                         # a TLV header without a value ("- IEEE802.3 MAC/PHY Configuration/Status")
            tlv = m[1].rstrip(':')
            continue
        m = re.match(r' {4}(\S[^:]*):\s*(.*)', raw)
        if m and tlv is not None:
            key, argument = m[1].rstrip(), m[2].strip()
            if key == 'Port ID' and tlv.startswith('Port ID type'):
                current['neighbor_port'] = argument.strip('"') or None
            elif key == 'Enabled Capabilities' and tlv.startswith('System Capabilities'):
                current['capabilities'] = capabilities(argument)
            elif key == 'Management Address' and tlv.startswith('Management Address') and current['management_ip'] is None:
                try:
                    current['management_ip'] = str(ipaddress.ip_address(argument))
                except ValueError:
                    pass            # a MAC or other address subtype is not a management IP
            continue
        if re.match(r' {5,}\S', raw) or (tlv is not None and re.match(r' {4}\S', raw)):
            continue                # wrapped values, hex dumps, MAU type lists
        unknown.append({'line': number, 'text': raw})
    return rows, unknown


def lldp_summary(text, style):
    """EOS / Junos `show lldp neighbors`: fixed columns taken from the header, so names may hold spaces."""
    starts = []

    def handle(raw, value):
        if matches(value, (r'Last table change time.*', r'Number of table (?:inserts|deletes|drops|age-outs)\s*:.*')):
            return []
        if style == 'eos' and re.match(r'Port\s+Neighbor Device ID\s+Neighbor Port ID\s+TTL', value):
            starts[:] = columns(raw, 'Neighbor Device ID', 'Neighbor Port ID', 'TTL')
            return []
        if style == 'junos' and re.match(r'Local Interface\s+Parent Interface\s+Chassis Id\s+Port info\s+System Name', value):
            starts[:] = columns(raw, 'Parent Interface', 'Chassis Id', 'Port info', 'System Name')
            return []
        if not starts:
            return None
        local = raw[:starts[0]].strip()
        if style == 'eos':
            name, remote_port = cut(raw, starts, 0), cut(raw, starts, 1)
            return record('lldp_neighbor', local_port=port(local), neighbor=name or None, neighbor_port=remote_port or None)
        name, remote_port = cut(raw, starts, 3), cut(raw, starts, 2)
        return record('lldp_neighbor', local_port=port(local), neighbor=name or None, neighbor_port=remote_port or None)
    return scan(text, handle)


# --- routing peers, port-channels, spanning tree -------------------------------------------

OSPF_ROLES = {'DR', 'BDR', 'DROTHER', '-'}
# EOS separates the words in `2 WAYS`; the slash/role is a separate optional cell part.
OSPF_STATE_CELL = r'(\S+(?:[ \t]+WAYS)?(?:[ \t]*/[ \t]*\S+)?)'


def ospf_neighbors(text, style):
    """IOS `show ip ospf neighbor` (Neighbor ID, Pri, State, Dead Time, Address, Interface), EOS (Instance and VRF added),
    NX-OS (Up Time instead of Dead Time, VRF in the process line) and Junos (Address first, state without a DR role)."""
    nx_vrf = [None]

    def handle(raw, value):
        if style == 'nxos':
            m = re.fullmatch(r'OSPF Process ID \S+ VRF (\S+)', value)
            if m:
                nx_vrf[0] = m[1]
                return []
            if matches(value, (r'Total number of neighbors: \d+', r'Neighbor ID\s+Pri\s+State\s+Up Time\s+Address\s+Interface')):
                return []
            m = re.fullmatch(r'(\d+\.\d+\.\d+\.\d+)\s+\d+\s+'+OSPF_STATE_CELL+r'\s+\S+\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)', value)
            vrf = nx_vrf[0]
            fields = (m[1], m[2], m[3], m[4]) if m else None
        elif style == 'junos':
            if matches(value, (r'Address\s+Interface\s+State\s+ID\s+Pri\s+Dead',)):
                return []
            m = re.fullmatch(r'(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(Down|Attempt|Init|2Way|ExStart|Exchange|Loading|Full)\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\d+', value)
            vrf = None
            fields = (m[4], m[3].upper(), m[1], m[2]) if m else None
        elif style == 'eos':
            if matches(value, (r'Neighbor ID\s+Instance\s+VRF\s+Pri\s+State\s+Dead Time\s+Address\s+Interface',)):
                return []
            m = re.fullmatch(r'(\d+\.\d+\.\d+\.\d+)\s+\S+\s+(\S+)\s+\d+\s+'+OSPF_STATE_CELL+r'\s+\S+\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)', value)
            vrf = m[2] if m else None
            fields = (m[1], m[3], m[4], m[5]) if m else None
        else:
            if matches(value, (r'Neighbor ID\s+Pri\s+State\s+Dead Time\s+Address\s+Interface',)):
                return []
            m = re.fullmatch(r'(\d+\.\d+\.\d+\.\d+)\s+\d+\s+'+OSPF_STATE_CELL+r'\s+\S+\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)', value)
            vrf = None
            fields = (m[1], m[2], m[3], m[4]) if m else None
        if not fields:
            return None
        state, _, role = re.sub(r'\s+', '', fields[1]).partition('/')
        state = {'twoway': '2way', '2ways': '2way'}.get(state.lower(), state.lower())
        role = role or None
        if role is not None and role not in OSPF_ROLES:
            return None
        return record('ospf_neighbor', neighbor_id=str(ipaddress.ip_address(fields[0])), address=str(ipaddress.ip_address(fields[2])),
                      interface=port(fields[3]), state=state, role=None if role == '-' else role, vrf=vrf)
    return scan(text, handle)


BGP_STATE_NAMES = {word.lower(): word for word in ('Idle', 'Connect', 'Active', 'OpenSent', 'OpenConfirm', 'Established',
                                                'Idle(admin)', 'Idle(prefixlimit)')}
BGP_STATE_NAMES.update({'estab': 'Established', 'establ': 'Established', 'idle (admin)': 'Idle(admin)',
                        'shut (admin)': 'Idle(admin)', 'shut(admin)': 'Idle(admin)',
                        'idle (pfxct)': 'Idle(prefixlimit)', 'idle(pfxct)': 'Idle(prefixlimit)',
                        'idle (prefixlimit)': 'Idle(prefixlimit)'})
BGP_STATES = set(BGP_STATE_NAMES)


def bgp_peers(text, style):
    """IOS `show ip bgp summary` (State/PfxRcd: a number means Established) and EOS (State and PfxRcd columns)."""
    vrf = ['default'] if style == 'eos' else [None]

    def handle(raw, value):
        m = re.fullmatch(r'BGP summary information for VRF (\S+?)(?:, address family .*)?', value)
        if m:
            vrf[0] = m[1]
            return []
        if matches(value, (r'BGP router identifier .*', r'BGP table version .*', r'BGP (?:attribute|community) entries .*', r'Router identifier .*', r'Neighbor\s+V\s+AS\s+.*',
                           r'\d+(?:/\d+)? .* (?:using|entries) .*', r'BGP using .*', r'BGP activity .*', r'Dampening .*', r'% BGP (?:not active|inactive)', r'(?:\d+ )?Neighbor.*')) or matches(value, (r'.*, local AS number \d+',)):
            return []
        if style == 'eos':
            m = re.fullmatch(r'(\S+)\s+(\d)\s+(\d+(?:\.\d+)?)\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+\s+(\S+(?:\s+\([^()\s]+\))?)(?:\s+(\d+)\s+(\d+))?', value)
            fields = (m[1], m[3], m[4], m[5]) if m else None
        else:
            m = re.fullmatch(r'(\S+)\s+(\d)\s+(\d+(?:\.\d+)?)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+\s+(\S+(?:\s+\([^()\s]+\))?)', value)
            fields = (m[1], m[3], m[4], None) if m else None
        if not fields:
            return None
        address = str(ipaddress.ip_address(fields[0].split('%')[0]))
        state, prefixes = re.sub(r'\s+', ' ', fields[2]), fields[3]
        if style in ('ios', 'nxos'):
            prefixes = state if state.isdigit() else None
            state = 'Established' if state.isdigit() else state
        elif state.lower() == 'estab':
            state = 'Established'
        if state.lower() not in BGP_STATES:
            return None
        return record('bgp_peer', neighbor=address, remote_as=fields[1], state=BGP_STATE_NAMES[state.lower()],
                      prefixes=int(prefixes) if prefixes else None, vrf=vrf[0])
    return scan(text, handle)


LAG_FLAGS = (('P', 'bundled'), ('D', 'down'), ('I', 'standalone'), ('H', 'hot-standby'), ('s', 'suspended'), ('w', 'waiting'), ('u', 'unsuitable'),
             ('d', 'default'), ('m', 'min-links'), ('M', 'min-links'), ('f', 'failed'), ('N', 'not-in-use'), ('i', 'incompatible'),
             ('C', 'transmit-disabled'), ('U', 'in-use'), ('b', 'bfd-wait'), ('r', 'module-removed'))
LAG_FLAG_CHARS = set('PDIHswudmMfNiCURSAGEFapbr+-^*')


def lag_state(flags):
    """Member state from the flag letters ("P", "PG+"); a flag letter this parser does not know is an unrecognized line."""
    if not set(flags) <= LAG_FLAG_CHARS:
        raise ValueError
    return next((name for letter, name in LAG_FLAGS if letter in flags), None) or 'unknown'


def lag_summary(text, style):
    """IOS `show etherchannel summary` / EOS `show port-channel dense`: legend, counters, then `Po1(SU) proto Gi0/1(P) ...`
    with the member list wrapped onto indented continuation lines."""
    state = {'lag': None}

    def members(items):
        out = []
        for item in items:
            m = re.fullmatch(r'([A-Za-z]+[0-9/.]+)\(([A-Za-z+^*-]+)\)', item)
            if m is None:
                raise ValueError
            out.append({'port': port(m[1]), 'state': lag_state(m[2])})
        return out

    def handle(raw, value):
        if matches(value, (r'Flags:.*', r'Flags', r'Number of (?:channel-groups|aggregators|channels)(?: in use)?:\s*\d+', r'Group\s+Port-channel\s+Protocol\s+Ports',
                           r'Port-Channel\s+Protocol\s+Ports', r'Group\s+Port-\s+Type\s+Protocol\s+Member Ports', r'Channel',
                           r'E - Inactive.*', r'[A-Za-z*^+-] - [A-Za-z].*', r'\s*\S ?-\s.*')) and not re.match(r'\s*\d', value):
            return []
        if style == 'nxos':
            m = re.fullmatch(r'(?:(\d+)\s+)?(Po\d+)\(([A-Za-z]+)\)\s+(\S+)\s+(\S+)\s*(.*)', value)      # NX-OS adds a Type column (Eth)
            m = m and (m[0], m[1], m[2], m[3], m[5], m[6])
        else:
            m = re.fullmatch(r'(?:(\d+)\s+)?(Po\d+)\(([A-Za-z]+)\)\s+(\S+)\s*(.*)', value)
            m = m and (m[0], m[1], m[2], m[3], m[4], m[5])
        if m:
            flags = m[3]
            if not set(flags) <= LAG_FLAG_CHARS:
                return None
            status = 'down' if 'D' in flags else 'up' if 'U' in flags else 'not in use' if 'N' in flags else None
            protocol = re.sub(r'\(.\)$', '', m[4])
            protocol = {'-': None, 'none': None, 'lacp': 'LACP', 'pagp': 'PAgP', 'static': 'Static'}.get(protocol.lower(), protocol)
            state['lag'] = record('lag', name=port(m[2]), protocol=protocol, status=status, members=members(m[5].split()))
            return state['lag']
        if state['lag'] is not None and re.match(r'\s+\S', raw):
            state['lag']['members'].extend(members(value.split()))
            return []
        return None
    return scan(text, handle)


STP_ROLE = {'desg': 'designated', 'root': 'root', 'altn': 'alternate', 'back': 'backup', 'mstr': 'master', 'dis': 'disabled', 'bdrg': 'boundary',
            'designated': 'designated', 'alternate': 'alternate', 'backup': 'backup', 'master': 'master', 'disabled': 'disabled'}
STP_STATE = {'fwd': 'forwarding', 'blk': 'blocking', 'lrn': 'learning', 'lis': 'listening', 'bkn': 'broken', 'dis': 'disabled', 'off': 'disabled',
             'forwarding': 'forwarding', 'discarding': 'discarding', 'blocking': 'blocking', 'learning': 'learning', 'listening': 'listening',
             'disabled': 'disabled'}


def stp_tree(text, style):
    """IOS `show spanning-tree` / EOS: one block per VLAN or MST instance; only the port table is a record."""
    state = {'instance': None, 'ports': False}

    def handle(raw, value):
        m = re.fullmatch(r'(VLAN\d{4}|MST\d+|Vlan\d+|RSTP\d*|PVST\d*)', value)
        if m and not raw[:1].isspace():
            state.update(instance=m[1], ports=False)
            return []
        if value in ('No spanning tree instances exist.', 'No spanning tree instance exists.'):
            return []
        if state['instance'] is None:
            return None
        if re.fullmatch(r'Interface\s+Role\s+(?:Sts|State)\s+Cost\s+Prio\.Nbr\s+Type', value):
            state['ports'] = True
            return []
        if not state['ports']:
            if matches(value, (r'Spanning tree enabled protocol \S+', r'Root ID\s+Priority\s+\d+', r'Bridge ID\s+Priority\s+\d+.*', r'Address\s+[0-9a-fA-F.:]+',
                               r'This bridge is the root', r'Hello Time\s+.*', r'Aging Time\s+.*', r'Port\s+\d+ \(.*\) of \S+ is .*', r'Port path cost.*',
                               r'Designated .*', r'Number of transitions .*', r'Spanning tree.*', r'Bridge Identifier .*', r'Configured hello .*',
                               r'Current root .*', r'Root port .*', r'Cost\s+\d+.*', r'Port\s+\d+.*')):
                return []
            return None
        m = re.fullmatch(r'(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+\.\d+)\s+(.+)', value)
        if m is None:
            return None
        role, status = STP_ROLE.get(m[2].lower()), STP_STATE.get(m[3].lower())
        if role is None or status is None:
            return None
        return record('stp_port', instance=state['instance'], port=port(m[1]), role=role, state=status, cost=int(m[4]))
    return scan(text, handle)


# --- routes -------------------------------------------------------------------------------

IOS_ROUTE_DETAIL = (r'Route metric is .*', r'Last update from .*', r'Tag \S+.*', r'AS Hops .*', r'Route tag .*', r'MPLS label: .*',
                    r'Redistributing via .*', r'Advertised by .*', r'Originating router is .*', r'Routing Descriptor Blocks:',
                    r'Distance: .*', r'Traffic Share .*', r'Multipath .*', r'Forwarding .*', r'Installed .*',
                    r'% (?:Network|Subnet) not in table', r'% Route not found', r'Gateway of last resort .*', r'Codes: .*', r'\S[^,]* - [^,]+,?',
                    r'[<>].*', r'\d+\.\d+\.\d+\.\d+/\d+ is (?:variably )?subnetted.*', r'Known via ".*')


def protocol_of(via):
    word = via.split()[0].lower() if via else None
    return {'connected': 'connected', 'static': 'static', 'rip': 'rip', 'ospf': 'ospf', 'bgp': 'bgp', 'eigrp': 'eigrp',
            'isis': 'isis', 'local': 'local'}.get(word, word)


IOS_ROUTE_CODES = {'L': 'local', 'C': 'connected', 'S': 'static', 'R': 'rip', 'M': 'mobile', 'B': 'bgp', 'D': 'eigrp', 'EX': 'eigrp',
                   'O': 'ospf', 'IA': 'ospf', 'N1': 'ospf', 'N2': 'ospf', 'E1': 'ospf', 'E2': 'ospf', 'i': 'isis', 'su': 'isis',
                   'L1': 'isis', 'L2': 'isis', 'ia': 'isis', 'o': 'odr', 'P': 'static', 'H': 'nhrp', 'l': 'lisp', 'U': 'static',
                   'a': 'application'}
_IOS_PREFIX = r'(\d+\.\d+\.\d+\.\d+(?:/\d+|\s+\d+\.\d+\.\d+\.\d+)?)'


def route_ios_table(text):
    """IOS / IOS XE `show ip route`: legend, "Gateway of last resort", "P is variably subnetted" parents and the
    route lines ("C  P is directly connected, X", "O  P [110/2] via N, age, X", prefix alone + `[ad/m] via` continuation)."""
    state = {'prefix': None, 'protocol': None, 'in_codes': False, 'group_mask': None}

    def prefix_of(raw_prefix):
        parts = raw_prefix.split()
        if len(parts) == 2 or '/' in parts[0]:
            return str(ipaddress.ip_network('/'.join(parts), strict=False))
        if state['group_mask'] is None:
            raise ValueError('route prefix has no known mask')
        return str(ipaddress.ip_network(f"{parts[0]}/{state['group_mask']}", strict=False))

    def hop(address, rest):
        found = re.fullmatch(r'(?:, \d[\d:wdhm]*)?(?:, (\S+))?', rest or '')
        if found is None:
            raise ValueError
        return record('route', prefix=state['prefix'], next_hop=str(ipaddress.ip_address(address)),
                      interface=port(found[1]) if found[1] else None, protocol=state['protocol'])

    def handle(raw, value):
        if value.startswith('Codes:'):
            state['in_codes'] = True
            return []
        if state['in_codes'] and re.match(r' {7}\S.* - ', raw):
            return []
        state['in_codes'] = False
        if matches(value, (r'Gateway of last resort is .*', r'Gateway of last resort not set', r'Gateway of last resort is not set')):
            state.update(prefix=None, protocol=None, group_mask=None)
            return []
        group = re.fullmatch(_IOS_PREFIX + r' is (variably )?subnetted, \d+ subnets?(?:, \d+ masks?)?', value)
        if group:
            state.update(prefix=None, protocol=None, group_mask=None)
            if not group[2] and ('/' in group[1] or len(group[1].split()) == 2):
                state['group_mask'] = ipaddress.ip_network('/'.join(group[1].split()), strict=False).prefixlen
            return []
        m = re.fullmatch(r'\[\d+/\d+\] via (\S+?)(,.*)?', value)
        if m and state['prefix']:
            return hop(m[1], m[2])
        m = re.fullmatch(r'([A-Za-z][A-Za-z0-9]?(?: [A-Za-z][A-Za-z0-9]?)?)[*+%]*\s+' + _IOS_PREFIX + r'(?:\s+(.*))?', value)
        if not m:
            return None
        state.update(prefix=None, protocol=None)
        codes = m[1].split()
        if not all(code in IOS_ROUTE_CODES for code in codes):
            return None
        state.update(prefix=prefix_of(m[2]), protocol=IOS_ROUTE_CODES[codes[0]])
        tail = (m[3] or '').strip()
        if not tail:
            return []                       # next hops follow on continuation lines
        d = re.fullmatch(r'is directly connected, (\S+)', tail)
        if d:
            return record('route', prefix=state['prefix'], interface=port(d[1]), protocol=state['protocol'])
        d = re.fullmatch(r'is a summary(?:, [\d:wdhm]+)?, (\S+)', tail)
        if d:
            return record('route', prefix=state['prefix'], interface=port(d[1]), protocol=state['protocol'])
        d = re.fullmatch(r'\[\d+/\d+\](?: via (\S+?)(,.*)?)?', tail)
        if d:
            return hop(d[1], d[2]) if d[1] else []
        return None
    return scan(text, handle)


def route_ios(text):
    """IOS / IOS XE IPv4/IPv6 detail lookup: "Routing entry for P[ M]", one record per next hop."""
    if re.search(r'(?m)^Codes: ', text) or re.search(r'(?m)^Gateway of last resort', text):
        return route_ios_table(text)
    state = {'prefix': None, 'protocol': None, 'hops': 0, 'ipv6_paths': False}
    rows = []

    def prefix_of(raw_prefix):
        if ':' in raw_prefix:
            return str(ipaddress.IPv6Network(raw_prefix, strict=False))
        found = re.fullmatch(r'(\d+\.\d+\.\d+\.\d+)(?:/(\d+)|\s+(\d+\.\d+\.\d+\.\d+))?', raw_prefix)
        if found is None:
            raise ValueError
        if found[2]:
            return str(ipaddress.ip_network(f'{found[1]}/{found[2]}', strict=False))
        if found[3]:
            return str(ipaddress.ip_network(f'{found[1]}/{found[3]}', strict=False))
        return str(ipaddress.ip_network(found[1] + '/32'))      # classful host route without a mask

    def handle(raw, value):
        m = re.fullmatch(r'Routing entry for (\S+(?: \d+\.\d+\.\d+\.\d+)?)(?:,.*)?', value)
        if m:
            state.update(prefix=prefix_of(m[1]), protocol=None, hops=0, ipv6_paths=False)
            return []
        if state['prefix'] is None:
            return [] if matches(value, IOS_ROUTE_DETAIL) else None
        m = re.match(r'Known via "([^"]+)"', value)
        if m:
            state['protocol'] = protocol_of(m[1])
            return []
        if ':' in state['prefix']:
            if value == 'Routing paths:':
                state['ipv6_paths'] = True
                return []
            if matches(value, (r'Route count is \d+/\d+, share count \d+',
                               r'Last updated [\d:wdhm]+ ago', r'From [0-9a-fA-F:.]+(?:%\S+)?')):
                return []
            if state['ipv6_paths']:
                m = re.fullmatch(r'([0-9a-fA-F:.]+)(?:%[^,\s]+)?, (\S+)', value)
                if m:
                    state['hops'] += 1
                    return record('route', prefix=state['prefix'], next_hop=str(ipaddress.IPv6Address(m[1])),
                                  interface=port(m[2]), protocol=state['protocol'])
                m = re.fullmatch(r'directly connected via (\S+)', value)
                if m:
                    state['hops'] += 1
                    return record('route', prefix=state['prefix'], interface=port(m[1]), protocol=state['protocol'])
        m = re.fullmatch(r'\*?\s*directly connected, via (\S+)', value)
        if m:
            state['hops'] += 1
            return record('route', prefix=state['prefix'], interface=port(m[1]), protocol='connected')
        m = re.fullmatch(r'\*?\s*(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)(?:%\S+)?(?:, from \S+)?(?:, [\d:wdhm]+ ago)?(?:, via (\S+))?', value)
        if m and not value.startswith('Route'):
            state['hops'] += 1
            return record('route', prefix=state['prefix'], next_hop=str(ipaddress.ip_address(m[1])),
                          interface=port(m[2]) if m[2] else None, protocol=state['protocol'])
        return [] if matches(value, IOS_ROUTE_DETAIL) else None
    rows, unknown = scan(text, handle)
    for row in rows:
        row['protocol'] = row['protocol'] or state['protocol']
    if state['prefix'] and not state['hops']:
        rows.append(record('route', prefix=state['prefix'], protocol=state['protocol']))
    return rows, unknown


def route_nxos(text):
    state = {'prefix': None, 'vrf': None}

    def protocol(value):
        word = value.lower()
        if word == 'is-is' or word.startswith('is-is-'):
            return 'isis'
        word = word.split('-')[0]
        return {'direct': 'connected', 'ospfv3': 'ospf'}.get(word, word)

    def handle(raw, value):
        m = re.fullmatch(r'IP(?:v6)? Rout(?:e Table|ing Table) for VRF "([^"]+)"', value)
        if m:
            state['vrf'] = m[1]
            return []
        if matches(value, (r"'\*' denotes .*", r"'\*\*' denotes .*", r"'\[x/y\]' denotes .*", r"'%<string>' in via output .*",
                           r"'%<string>'.*", r"'\[x/y\]'.*", r"'\*'.*", r'Route not found')):
            return []
        m = re.fullmatch(r'([0-9a-fA-F:.]+/\d+), ubest/mbest: \d+/\d+(?:, .*)?', value)
        if m:
            state['prefix'] = str(ipaddress.ip_network(m[1], strict=False))
            return []
        m = re.fullmatch(r'\*{0,2}via ([0-9a-fA-F:.]+)(?:%\S+)?(?:, ([A-Za-z][^\s,]*))?, \[\d+/\d+\], [^,]+, ([\w-]+)(?:, .*)?', value)
        if m and state['prefix']:
            return record('route', prefix=state['prefix'], next_hop=None if protocol(m[3]) in ('connected', 'local') else str(ipaddress.ip_address(m[1])),
                          interface=port(m[2]) if m[2] else None, protocol=protocol(m[3]), vrf=state['vrf'])
        m = re.fullmatch(r'\*{0,2}via ([A-Za-z][^\s,]*), \[\d+/\d+\], [^,]+, ([\w-]+)(?:, .*)?', value)
        if m and state['prefix']:
            return record('route', prefix=state['prefix'], interface=port(m[1]), protocol=protocol(m[2]), vrf=state['vrf'])
        return None
    return scan(text, handle)


def route_eos(text):
    state = {'vrf': None, 'prefix': None, 'protocol': None, 'in_codes': False}
    # Full source codes from the cEOS legend; L means VRF leaked, not local.
    codes = {'C': 'connected', 'S': 'static', 'K': 'kernel', 'B': 'bgp', 'B I': 'bgp', 'B E': 'bgp',
             'I': 'isis', 'I L1': 'isis', 'I L2': 'isis', 'R': 'rip',
             'A': 'aggregate', 'A B': 'aggregate', 'A O': 'aggregate', 'DH': 'dhcp'}
    codes.update({base + suffix: 'ospf' for base in ('O', 'O3')
                  for suffix in ('', ' IA', ' E1', ' E2', ' N1', ' N2')})

    def route(prefix, hop, interface, code):
        return record('route', prefix=prefix, next_hop=hop, interface=port(interface) if interface else None,
                      protocol=codes.get(code, code.lower()), vrf=state['vrf'])

    def handle(raw, value):
        m = re.fullmatch(r'VRF:\s*(\S+)', value)
        if m:
            state['vrf'] = m[1]
            return []
        if value.startswith(('Codes:', 'Source Codes:')):
            state['in_codes'] = True
            return []
        if state['in_codes'] and re.match(r'\s+\S.* - ', raw):
            return []
        state['in_codes'] = False
        if matches(value, (r'Gateway of last resort(?: is not set|:)?', r'Gateway of last resort is .*', r'Routing entry for .*')):
            return []
        m = re.fullmatch(r'directly connected, (\S+)', value)       # 4.36: the interface is on the line below the prefix
        if m and state['prefix']:
            return route(state['prefix'], None, m[1], state['protocol'])
        m = re.fullmatch(r'([A-Z]{1,2}\d?(?: [A-Z]{1,2}\d?)?)\s+([0-9a-fA-F:.]+/\d+) is directly connected, (\S+)', value)
        if m:
            return route(str(ipaddress.ip_network(m[2], strict=False)), None, m[3], m[1])
        m = re.fullmatch(r'([A-Z]{1,2}\d?(?: [A-Z]{1,2}\d?)?)\s+([0-9a-fA-F:.]+/\d+)(?: \[\d+/\d+\])?(?: via ([0-9a-fA-F:.]+)(?:, (\S+))?)?(?:,? .*)?', value)
        if m:
            prefix = str(ipaddress.ip_network(m[2], strict=False))
            state.update(prefix=prefix, protocol=m[1])
            return route(prefix, str(ipaddress.ip_address(m[3])), m[4], m[1]) if m[3] else []
        m = re.fullmatch(r'via ([0-9a-fA-F:.]+)(?:, (\S+))?', value)
        if m and state['prefix']:
            return route(state['prefix'], str(ipaddress.ip_address(m[1])), m[2], state['protocol'])
        return None
    return scan(text, handle)


def route_junos(text):
    """`show route A detail`: only active entries, like the whole-table parser."""
    state = {'prefix': None, 'protocol': None, 'vrf': None, 'hops': [], 'active': False}
    out = []

    def close_entry():
        if state['prefix'] is None or state['protocol'] is None or not state['active']:
            return
        if not state['hops']:
            out.append(record('route', prefix=state['prefix'], protocol=state['protocol'], vrf=state['vrf']))
        for hop, interface, protocol in state['hops']:
            out.append(record('route', prefix=state['prefix'], next_hop=hop, interface=interface,
                              protocol=protocol, vrf=state['vrf']))

    def close():
        close_entry()
        state.update(prefix=None, protocol=None, hops=[], active=False)

    def handle(raw, value):
        m = re.fullmatch(r'(?:(\S+)\.)?inet6?\.\d+: \d+ destinations, \d+ routes \(.*\)', value)
        if m:
            close()
            state['vrf'] = m[1] or 'default'
            return []
        m = re.fullmatch(r'([0-9a-fA-F:.]+/\d+) \(\d+ entr(?:y|ies), \d+ announced\)', value)
        if m:
            close()
            state['prefix'] = str(ipaddress.ip_network(m[1], strict=False))
            return []
        if state['prefix'] is None:
            return [] if value in ('inet.0:', 'inet6.0:') or value.startswith('Limit/Threshold: ') else None
        m = re.match(r'([*@]?)\s*(\w[\w-]*)\s+Preference: \d+', value)
        if m:
            close_entry()
            state.update(protocol=JUNOS_ROUTE_PROTOCOL.get(m[2].lower(), m[2].lower()),
                         active=m[1] == '*', hops=[])
            return []
        m = re.fullmatch(r'State: <([^>]*)>', value)
        if m:
            state['active'] = 'Active' in m[1].split()
            return []
        m = re.fullmatch(r'Next hop:[ \t]+(?:([0-9a-fA-F:.]+)[ \t]+)?via[ \t]+(\S+?)(?:, selected)?', value)
        if m:
            state['hops'].append((str(ipaddress.ip_address(m[1])) if m[1] else None, port(m[2]), state['protocol']))
            return []
        if value.startswith('Next hop:'):
            return None
        if raw[:1].isspace():
            return []           # the attribute lines of a route entry (Age, State, AS path ...)
        return None
    rows, unknown = scan(text, handle)
    close()
    return out, unknown



JUNOS_ROUTE_PROTOCOL = {'static': 'static', 'direct': 'connected', 'local': 'local', 'ospf': 'ospf', 'ospf3': 'ospf', 'bgp': 'bgp', 'is-is': 'isis',
                        'rip': 'rip', 'ripng': 'rip', 'access': 'access', 'access-internal': 'access', 'aggregate': 'aggregate', 'inet6': 'local',
                        'igmp': 'igmp', 'pim': 'pim', 'evpn': 'evpn', 'l2circuit': 'l2circuit', 'ldp': 'ldp', 'rsvp': 'rsvp', 'multicast': 'multicast'}


def route_junos_table(text):
    """`show route`: a block per routing table ("inet.0: N destinations ..."), a prefix line with the protocol entries
    (`*[OSPF/10] age, metric N`, `[BGP/170] ...`) and the next hops (`> to A via ifl`, `via ifl`, `Local via ifl`) below it.
    One record per next hop of the active entry (marked `+` or `*`), or one record for the entry when it has no next hop."""
    state = {'vrf': None, 'prefix': None, 'entries': [], 'continued': False}
    out = []

    def close():
        if state['prefix'] is None:
            return
        entries = state['entries']
        active = next((e for e in entries if e['active']), None)
        if active is not None:
            if not active['hops']:
                out.append(record('route', prefix=state['prefix'], protocol=active['protocol'], vrf=state['vrf']))
            for hop, interface in active['hops']:
                out.append(record('route', prefix=state['prefix'], next_hop=hop, interface=interface, protocol=active['protocol'], vrf=state['vrf']))
        state.update(prefix=None, entries=[])

    def entry(marker, name, rest):
        protocol = JUNOS_ROUTE_PROTOCOL.get(name.lower())
        if protocol is None:
            raise ValueError
        if not re.fullmatch(r'(?:(?:\d+w)?(?:\d+d)? ?\d{1,2}:\d{2}:\d{2}|(?:\d+[wdhms])+|\d+)(?:,.*)?', rest.strip()) and rest.strip():
            raise ValueError
        state['entries'].append({'active': marker in ('+', '*'), 'protocol': protocol, 'hops': []})

    def handle(raw, value):
        m = re.fullmatch(r'(?:(\S+)\.)?(?:inet6?|mpls|iso|inet6color|inetcolor|bgp\.[a-z0-9.]+)\.?\d*: \d+ destinations?, \d+ routes? \(.*\)', value)
        if m:
            close()
            state['vrf'] = m[1] or 'default'
            return []
        if matches(value, (r'Limit/Threshold: .*', r'\+ = Active Route, - = Last Active, \* = Both', r'Restart Complete', r'[a-z0-9._-]+: \d+ destinations?, .*')):
            return []
        m = re.fullmatch(r'([0-9a-fA-F:.]+(?:/\d+)?)(?:\s+([*+-]?)\[([A-Za-z0-9-]+)/\d+\]\s*(.*))?', value)
        if m and not raw[:1].isspace():
            close()
            prefix = m[1] if '/' in m[1] else m[1] + ('/128' if ':' in m[1] else '/32')
            state['prefix'] = str(ipaddress.ip_network(prefix, strict=False))
            if m[3]:
                entry(m[2], m[3], m[4])
            return []
        if state['prefix'] is None:
            return None
        m = re.fullmatch(r'([*+-]?)\[([A-Za-z0-9-]+)/\d+\]\s*(.*)', value)
        if m:
            entry(m[1], m[2], m[3])
            return []
        if not state['entries']:
            return None
        m = re.fullmatch(r'>?\s*to\s+([0-9a-fA-F:.]+)(?:%\S+)?\s+via\s+(\S+?)(?:\s+(?:weight|Push|Pop|Swap)\b.*|,.*)?', value)
        if m:
            state['entries'][-1]['hops'].append((str(ipaddress.ip_address(m[1])), port(m[2])))
            return []
        m = re.fullmatch(r'>?\s*(?:Local\s+)?via\s+(\S+?)(?:\s+(?:weight|Push|Pop|Swap)\b.*|,.*)?', value)
        if m:
            state['entries'][-1]['hops'].append((None, port(m[1])))
            return []
        if matches(value, (r'MultiRecv', r'Discard', r'Reject', r'Receive', r'Multicast', r'Indirect', r'AS path:.*', r'Aggregate', r'>?\s*to table \S+')):
            return []
        return None
    rows, unknown = scan(text, handle)
    close()
    return out, unknown



JUNOS_CAPABILITY_WORDS = {'other': 'O', 'repeater': 'P', 'bridge': 'B', 'wlan-access-point': 'W', 'router': 'R', 'telephone': 'T',
                          'docsis-cable-device': 'C', 'station-only': 'S'}


def junos_capabilities(value):
    words = [word.lower() for word in value.split()]
    if not words:
        return None
    found = {JUNOS_CAPABILITY_WORDS.get(word, 'O') for word in words}
    return ','.join(code for code, _ in CAPABILITY_CODES if code in found)


def junos_lldp_detail(text):
    """`show lldp neighbors detail`: a "Local Information:" block and a "Neighbor Information:" block per neighbor, then
    "Organization Info" blocks (Index/OUI/Subtype/Info). System Description is free text and not parsed."""
    rows, unknown = [], []
    current, section = None, None
    known = {'local interface', 'parent interface', 'local port id', 'ageout count', 'chassis id', 'chassis type', 'port type', 'port id',
             'port description', 'system name', 'system description', 'address', 'address type', 'interface number', 'interface subtype',
             'oid', 'index', 'oui', 'subtype', 'info', 'supported', 'enabled'}
    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value:
            continue
        if value in ('LLDP Neighbor Information:', 'LLDP Neighbour Information:'):
            continue
        if value == 'Local Information:':
            current = record('lldp_neighbor')
            rows.append(current)
            section = 'local'
            continue
        if current is None:
            unknown.append({'line': number, 'text': raw})
            continue
        if value in ('Neighbor Information:', 'Neighbour Information:'):
            section = 'neighbor'
            continue
        if value == 'System capabilities':
            section = 'capabilities'
            continue
        if value == 'Management address':
            section = 'management'
            continue
        if value == 'Organization Info':
            section = 'organization'
            continue
        m = re.match(r'Index: \d+ Time to live: \d+ Time mark: .* Age: \d+ secs\s*$', value)
        if m:
            continue
        label, separator, argument = value.partition(':')
        label = label.rstrip()
        key = label.lower() if separator and re.fullmatch(r'[A-Za-z][A-Za-z0-9 /().-]*', label) else None
        if section == 'description' and key not in known:
            continue                    # the System Description is free text and may wrap over several lines
        if key is None or not (key in known or key.startswith('med ')):
            unknown.append({'line': number, 'text': raw})
            continue
        argument = argument.strip()
        if key == 'system description':
            section = 'description'
            continue
        if section == 'description':
            section = 'neighbor'
        try:
            if key == 'local interface':
                current['local_port'] = port(argument)
            elif key == 'port id' and section == 'neighbor':
                current['neighbor_port'] = argument
            elif key == 'system name' and section == 'neighbor':
                current['neighbor'] = argument or None
            elif key == 'enabled' and section == 'capabilities':
                current['capabilities'] = junos_capabilities(argument)
            elif key == 'address' and section == 'management' and current['management_ip'] is None:
                current['management_ip'] = str(ipaddress.ip_address(argument))
        except ValueError:
            unknown.append({'line': number, 'text': raw})
    return rows, unknown



def junos_bgp_peers(text):
    """`show bgp summary`: counters, a table block, then `Peer AS InPkt OutPkt OutQ Flaps Last Up/Dwn State` rows;
    an established peer lists `table: active/received/accepted/damped` lines below it, and a peer that is not
    established prints its state (Active, Idle, Connect ...). Older layouts print the counters in the State column."""
    state = {'peer': None, 'table_name': False}

    def handle(raw, value):
        if matches(value, (r'Threading mode: .*', r'Default eBGP mode: .*', r'Groups: \d+ Peers: \d+ Down peers: \d+',
                           r'Table\s+Tot Paths\s+Act Paths\s+Suppressed\s+History\s+Damp State\s+Pending',
                           r'Peer\s+AS\s+InPkt\s+OutPkt\s+OutQ\s+Flaps\s+Last Up/Dwn\s+State\|.*',
                           r'Warning: License key missing.*', r'BGP is not running', r'[0-9]+(?:\s+[0-9]+){5}',
                           r'\d+/\d+/\d+(?:/\d+)?', r'[a-z0-9._-]+\.(?:inet6?|l3vpn|l2vpn|evpn|mvpn|iso|isovpn)\.\d+\s*', r'[a-z0-9._-]+\.\d+\s*')):
            return []
        if re.fullmatch(r'[a-z0-9._-]+\.\d+(?:\s+\d+){6}', value):
            return []                       # a table row: name and six counters
        m = re.fullmatch(r'([0-9a-fA-F:.]+)(?:%\S+)?\s+(\d+(?:\.\d+)?)\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+\s+(\S+)', value)
        if m and not raw[:1].isspace():
            address = str(ipaddress.ip_address(m[1]))
            word = m[3]
            counts = re.fullmatch(r'(\d+)/(\d+)/(\d+)(?:/(\d+))?', word)
            if counts:
                established, prefixes = 'Established', int(counts[2])
            elif word.lower() in ('establ', 'established'):
                established, prefixes = 'Established', None
            elif word.lower() in BGP_STATES:
                established, prefixes = BGP_STATE_NAMES[word.lower()], None
            else:
                return None
            state['peer'] = record('bgp_peer', neighbor=address, remote_as=m[2], state=established, prefixes=prefixes, vrf='default')
            return state['peer']
        m = re.fullmatch(r'([a-z0-9._-]+\.(?:inet6?|l3vpn|l2vpn|evpn|mvpn|iso|isovpn)\.\d+|[a-z0-9._-]+\.\d+): (\d+)/(\d+)/(\d+)(?:/(\d+))?', value)
        if m and state['peer'] is not None and raw[:1].isspace():
            if state['peer']['prefixes'] is None:
                state['peer']['prefixes'] = int(m[3])
            return []
        return None
    return scan(text, handle)


JUNOS_MUX = {'collecting distributing': 'bundled', 'detached': 'down', 'waiting': 'waiting', 'attached': 'standalone'}


def junos_lacp(text):
    """`show lacp interfaces`: an "Aggregated interface:" block per bundle with actor/partner rows and the mux state per member."""
    state = {'lag': None, 'section': None}

    def member(name):
        lag = state['lag']
        found = next((item for item in lag['members'] if item['port'] == name), None)
        if found is None:
            found = {'port': name, 'state': 'unknown'}
            lag['members'].append(found)
        return found

    def handle(raw, value):
        m = re.fullmatch(r'Aggregated interface: (\S+)', value)
        if m:
            state.update(lag=record('lag', name=port(m[1]), protocol='LACP', status=None, members=[]), section=None)
            return state['lag']
        if state['lag'] is None:
            return None
        if re.fullmatch(r'LACP state:\s+Role\s+Exp\s+Def\s+Dist\s+Col\s+Syn\s+Aggr\s+Timeout\s+Activity', value, re.I):
            state['section'] = 'state'
            return []
        if re.fullmatch(r'LACP protocol:\s+Receive State\s+Transmit State\s+Mux State', value, re.I):
            state['section'] = 'protocol'
            return []
        if state['section'] == 'state':
            m = re.fullmatch(r'(\S+?)(?:\s+\(FUP\))?\s+(Actor|Partner)\s+(Yes|No)\s+(Yes|No)\s+(Yes|No)\s+(Yes|No)\s+(Yes|No)\s+(Yes|No)\s+(Fast|Slow)\s+(Active|Passive)', value)
            if m:
                item = member(port(m[1]))
                if m[2] == 'Actor' and item['state'] == 'unknown':
                    item['state'] = 'bundled' if m[5] == 'Yes' and m[6] == 'Yes' else 'down'
                return []
        elif state['section'] == 'protocol':
            fields = value.split()
            name = fields.pop(0) if fields else None
            if fields[:1] == ['(FUP)']:
                fields.pop(0)
            # Receive is one token, transmit may contain multiple words; mux is
            # a fixed suffix. Split once so malformed whitespace cannot backtrack.
            mux = ' '.join(fields[-2:]) if fields[-2:] == ['Collecting', 'distributing'] else (fields[-1] if fields else '')
            mux_width = 2 if mux == 'Collecting distributing' else 1
            if len(fields) >= 2 + mux_width and mux in ('Collecting distributing', 'Detached', 'Waiting', 'Attached'):
                member(port(name))['state'] = JUNOS_MUX[mux.lower()]
                return []
        return None
    rows, unknown = scan(text, handle)
    for lag in rows:
        lag['status'] = 'up' if any(item['state'] == 'bundled' for item in lag['members']) else 'down'
    return rows, unknown


JUNOS_STP_ROLE = {'root': 'root', 'desg': 'designated', 'altn': 'alternate', 'alt': 'alternate', 'back': 'backup', 'bkup': 'backup', 'mstr': 'master',
                  'dis': 'disabled', 'bdrg': 'boundary'}
JUNOS_STP_STATE = {'fwd': 'forwarding', 'blk': 'blocking', 'lrn': 'learning', 'lis': 'listening', 'dis': 'disabled', 'dsc': 'discarding', 'bkn': 'broken'}


def junos_stp(text):
    """ELS `show spanning-tree interface`: "Spanning tree interface parameters for instance N", then one row per port."""
    state = {'instance': None}

    def handle(raw, value):
        m = re.fullmatch(r'Spanning tree interface parameters for instance (\d+)', value)
        if m:
            state['instance'] = int(m[1])
            return []
        if re.fullmatch(r'Spanning-tree is not enabled at global level\.', value):
            return []
        if matches(value, (r'Interface\s+Port ID\s+Designated\s+Designated\s+Port\s+State\s+Role', r'port ID\s+bridge ID\s+Cost')):
            return []
        m = re.fullmatch(r'(\S+)\s+\d+:\d+\s+\d+:\d+\s+\d+\.[0-9a-fA-F]+\s+(\d+)\s+(\S+)\s+(\S+)', value)
        if m and state['instance'] is not None:
            role, status = JUNOS_STP_ROLE.get(m[4].lower()), JUNOS_STP_STATE.get(m[3].lower())
            if role is None or status is None:
                return None
            return record('stp_port', instance=str(state['instance']), port=port(m[1]), role=role, state=status, cost=int(m[2]))
        return None
    return scan(text, handle)


# --- per-OS entry points --------------------------------------------------------------------

def cisco(table, text, style='ios'):
    if table == 'ospf_neighbor':
        return ospf_neighbors(text, style)
    if table == 'bgp_peer':
        return bgp_peers(text, style)
    if table == 'lag':
        return lag_summary(text, style)
    if table == 'stp_port':
        return stp_tree(text, style)
    if table == 'lldp_neighbor':
        return cisco_lldp(text, style)
    if table == 'route':
        return route_nxos(text) if style == 'nxos' else route_ios(text)
    if table == 'interface':
        return status_table(text)
    if table == 'vlan':
        return vlan_sections(text, style)
    if table == 'mac_entry':
        return mac_nxos(text) if style == 'nxos' else mac_ios(text)
    return neighbors(text, style)


for _profile in ('cisco_ios', 'cisco_xe'):
    BINDINGS[_profile] = {'interface': 'interfaces', 'vlan': 'vlans', 'mac_entry': 'mac_table',
                          'neighbor_l3': 'arp_table', 'neighbor_l3_v6': 'ipv6_neighbors',
                          'lldp_neighbor': 'lldp_neighbors', 'route': 'route_lookup', 'route_v6': 'ipv6_route_lookup',
                          'route_all': 'route_table', 'ospf_neighbor': 'ospf_neighbors', 'bgp_peer': 'bgp_summary',
                          'lag': 'lag_summary', 'stp_port': 'stp_tree'}
    PARSERS[_profile] = cisco


BINDINGS['cisco_nxos'] = dict(BINDINGS['cisco_ios'])
PARSERS['cisco_nxos'] = lambda table, text: cisco(table, text, 'nxos')


def eos(table, text):
    if table == 'lldp_neighbor':
        return eos_lldp_detail(text) if re.search(r'detected \d+ LLDP neighbors?', text) else lldp_summary(text, 'eos')
    if table == 'route':
        return route_eos(text)
    if table == 'mac_entry':
        return mac_eos(text)
    return cisco(table, text, 'eos')


BINDINGS['arista_eos'] = {**BINDINGS['cisco_ios'], 'lldp_neighbor': 'lldp_neighbors_detail'}
PARSERS['arista_eos'] = eos


JUNOS_NAME = r'[A-Za-z][A-Za-z0-9]*(?:[-/][0-9]+)*(?:[./:][0-9]+)*'


def junos_interfaces(text):
    """`show interfaces terse`: every row has Admin and Link; address-family lines continue the row above."""
    def handle(raw, value):
        if re.match(r'Interface\s+Admin\s+Link\s+Proto\s+Local\s+Remote', value):
            return []
        if raw[:1].isspace() and (re.fullmatch(r'(?:inet6?|iso|mpls|eth-switch|tnp|multiservice|vpls|ccc|bridge|aenet)\s*.*', value)
                                  or re.fullmatch(r'[0-9a-fA-Fx:.]+(?:/\d+)?(?:\s*-->\s*\S+)?', value)):
            return []           # address-family lines continue the interface row above
        m = re.fullmatch(r'(' + JUNOS_NAME + r')\s+(up|down)\s+(up|down)(?:\s+(.*))?', value)
        if not m:
            return None
        return record('interface', name=m[1], admin_status=m[2], oper_status=m[3])
    return scan(text, handle)


def junos_vlans(text):
    state = {'last': None}

    def handle(raw, value):
        if re.match(r'Routing instance\s+VLAN name\s+Tag\s+Interfaces', value):
            return []
        m = re.fullmatch(r'(\S+)\s+(\S+)\s+(\d+|NA)\s*(.*)', value)
        if m and not raw[:1].isspace():
            result = record('vlan', name=m[2], vlan_id=int(m[3]) if m[3].isdigit() else None, ports=port_list(m[4]))
            state['last'] = result
            return result
        if state['last'] is not None and raw[:1].isspace() and re.fullmatch(r'[\w/.:*, -]+', value):
            state['last']['ports'].extend(port_list(value))
            return []
        return None
    return scan(text, handle)


def junos_neighbors(text):
    """IPv4 `show arp no-resolve` or IPv6 `show ipv6 neighbors`, told apart by their headers."""
    if ipv6_table(text):
        return scan(text, lambda raw, value: [] if value.startswith(('IPv6 Address', 'Total entries')) else neighbor_line(value, 'junos'))
    return arp_rows(text, 'junos')


def junos(table, text):
    if table == 'ospf_neighbor':
        return ospf_neighbors(text, 'junos')
    if table == 'bgp_peer':
        return junos_bgp_peers(text)
    if table == 'lag':
        return junos_lacp(text)
    if table == 'stp_port':
        return junos_stp(text)
    if table == 'route':
        return route_junos(text) if re.search(r'\(\d+ entr(?:y|ies), \d+ announced\)', text) else route_junos_table(text)
    if table == 'lldp_neighbor':
        return junos_lldp_detail(text) if 'Local Information:' in text else lldp_summary(text, 'junos')
    if table == 'interface':
        return junos_interfaces(text)
    if table == 'vlan':
        return junos_vlans(text)
    if table == 'mac_entry':
        return mac_junos(text)
    return junos_neighbors(text)


for _profile in ('juniper_junos', 'juniper_junos_els'):
    BINDINGS[_profile] = {k: v for k, v in BINDINGS['cisco_ios'].items()
                          if k not in ('stp_port', 'lag') and (_profile.endswith('_els') or k not in ('vlan', 'mac_entry'))}
    BINDINGS[_profile].update(lldp_neighbor='lldp_neighbors_detail', route_all='route_table', lag='lacp_interfaces')
    if _profile.endswith('_els'):
        BINDINGS[_profile]['stp_port'] = 'stp_interfaces'
    PARSERS[_profile] = junos


def fortinet(table, text):
    pending = [None]
    def row(value):
        if table == 'neighbor_l3':
            m = re.fullmatch(r'ifindex=\d+ ifname=(\S+) (\S+) ('+MAC+r') state=\S+.*', value)
            if m:
                return record(table, ip=str(ipaddress.ip_address(m[2])), mac=normalize_mac(m[3]), interface=m[1], vlan_id=vlan(m[1]))
            return neighbor_line(value, 'fortinet')
        if table == 'mac_entry':
            m = re.fullmatch(r'MAC:\s*('+MAC+r')\s+VLAN:\s*(\d+)\s+(Port|Trunk):\s*([^\s(]+)\s*\((?:port|trunk)-id\s+\d+\)', value)
            if m:
                r = record(table, mac=normalize_mac(m[1]), vlan_id=int(m[2]), port=m[4],
                           type='trunk' if m[3] == 'Trunk' else None)
                pending[0] = r
                return r
            m = re.fullmatch(r'Flags:\s*0x[0-9a-fA-F]+\s*\[([^\]]*)\]', value)
            if m and pending[0]:
                if pending[0]['type'] != 'trunk':
                    flags = m[1].split()
                    pending[0]['type'] = 'dynamic' if 'dynamic' in flags else 'static' if 'static' in flags else None
                return []
        if table == 'lldp_neighbor':
            m = re.fullmatch(r'(port\d+(?:\.\d+)?)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)', value)
            if m:
                return record(table, local_port=m[1], neighbor=m[4], neighbor_port=m[3], capabilities=m[5] or None)
        return None
    return lines(text, row, (r'Address\s+Age\(min\)\s+Hardware Addr\s+Interface',
                            r'Managed Switch\s*:\s*[A-Z0-9]+\s+\d+', r'flag bit (?:pattern|Mask):\s*0x[0-9a-fA-F]+',
                            r'(?:vlan|port-id|trunk-id) map:\s*\d+-\d+',
                            r'Port\s+Chassis ID\s+Port ID\s+System Name(?:\s+Capabilities)?', r'No LLDP neighbors found\.?'))


BINDINGS['fortinet'] = {'neighbor_l3': 'arp_table', 'neighbor_l3_v6': 'ipv6_neighbors', 'route': 'route_lookup',
                        'route_all': 'routing_table', **switch_managed.TABLES}
from . import fortigate_tables  # noqa: E402
fortigate_tables.register(QUERY_PARSERS)
QUERY_PARSERS[('fortinet', 'route', 'route_lookup')] = lambda table, text: switch_managed.routes(table, text, lookup=True)
PARSERS['fortinet'] = switch_managed.parse

for _profile, _query in port_vlan.BINDINGS.items():
    BINDINGS[_profile]['port_vlan'] = _query


# --- ip_interface: parsers and the second read live in ip_interfaces.py -----------------------

from . import ip_interfaces  # noqa: E402  (imports this module; everything above is defined)

for _profile, _query in ip_interfaces.QUERIES.items():
    BINDINGS[_profile]['ip_interface'] = _query
    QUERY_PARSERS[(_profile, 'ip_interface', _query)] = ip_interfaces.PARSERS[_profile]
for _profile in ip_interfaces.ROUTER_INTERFACES:
    ROUTER_BINDINGS[_profile] = {'interface': 'ip_interfaces'}
    QUERY_PARSERS[(_profile, 'interface', 'ip_interfaces')] = ip_interfaces.PARSERS[_profile]

# Registration only: parsers and multi-source reads live in their own module.
from . import port_errors as _port_errors
_port_errors.register(FIELDS, OPTIONAL_FIELDS, BINDINGS, TABLE_PARSERS)

from . import cdp as _cdp
_cdp.register(FIELDS, OPTIONAL_FIELDS, BINDINGS, QUERY_PARSERS)

from . import linux_tables as _linux_tables
_linux_tables.register(BINDINGS, PARSERS, QUERY_PARSERS)
