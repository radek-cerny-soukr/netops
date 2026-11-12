"""FortiGate-local tables, distinct from FortiLink managed-switch selectors.

Layouts come from the 80F / FortiOS 8.0.2 build0251 RO captures of
2026-11-09/10. Unknown lines remain evidence, including populated bridge
layouts for which this lab supplied no positive sample.
"""
from __future__ import annotations

import ipaddress
import json
import re

QUERIES = {'interface': 'physical_interfaces', 'vlan': 'interface_vlan_ids',
           'lldp_neighbor': 'lldp_summary', 'mac_entry': None}


def request(table, vlan_id, mac, ip, interface):
    from .read_policy import _validate_slot
    if ip is not None or interface is not None or (mac is not None and table != 'mac_entry') or (
            vlan_id is not None and table not in ('vlan', 'mac_entry')):
        raise ValueError('filter does not apply to this table')
    filters = {}
    if vlan_id is not None:
        filters['vlan_id'] = int(_validate_slot(vlan_id, 'vlan_id'))
    if mac is not None:
        filters['mac'] = _validate_slot(mac, 'mac_literal')
    return QUERIES[table], {}, filters


def physical(table, text):
    from . import tables as t
    rows, unknown, current, seen = [], [], None, set()

    def close(number):
        if current is not None and not {'status', 'speed'} <= seen:
            unknown.append({'line': number, 'text': 'incomplete physical interface: ' + current['name']})

    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value or value == '== [onboard]':
            continue
        head = re.fullmatch(r'==\[([A-Za-z0-9_.:-]+)\]', value)
        if head:
            close(number)
            current = t.record(table, name=head[1])
            current['duplex'] = None
            rows.append(current)
            seen = set()
            continue
        state = re.fullmatch(r'status: (up|down)', value)
        speed = re.fullmatch(r'speed: (?:(\d+)(Mbps|Gbps) \(Duplex: (full|half)\)|(n/a))', value)
        if current is not None and state and 'status' not in seen:
            current['oper_status'] = state[1]
            seen.add('status')
        elif current is not None and speed and 'speed' not in seen:
            if speed[1]:
                current.update(speed=speed[1] + ('M' if speed[2] == 'Mbps' else 'G'), duplex=speed[3])
            seen.add('speed')
        elif current is not None and re.fullmatch(
                r'(?:mode: (?:static|dhcp|pppoe)|ip: \S+ \S+|ipv6: \S+|medium: \S+|FEC(?:_cap)?: \S+)', value):
            continue
        else:
            unknown.append({'line': number, 'text': raw})
    close(len(text.splitlines()) or 1)
    return rows, unknown


def lldp(table, text):
    from . import tables as t

    def row(value):
        match = re.fullmatch(r"\d+ port '([^']+)' \d+\s+mac (" + t.MAC +
                             r")\s+chassis (" + t.MAC + r") port '([^']+)' system '([^']*)'", value)
        if match:
            return t.record(table, local_port=match[1], neighbor=match[5] or None, neighbor_port=match[4])
        return None

    return t.lines(text, row)


def configuration_view(text):
    """Project only VLAN identity, parent and IPv4; never expose full config."""
    from .fortiswitch_ports import _entries
    entries, unknown = _entries(text, ('system interface',))
    output = ['config system interface']
    for name, fields in entries:
        if 'vlanid' not in fields:
            continue
        output.append('    edit ' + json.dumps(name, ensure_ascii=False))
        for field in ('vlanid', 'interface', 'ip'):
            if field in fields:
                output.append('        set ' + field + ' ' + ' '.join(json.dumps(v, ensure_ascii=False) for v in fields[field]))
        output.append('    next')
    output.append('end')
    output.extend('unrecognized configuration syntax from source line ' + str(item['line']) for item in unknown)
    return '\n'.join(output) + '\n'


def vlans(table, text):
    from . import tables as t
    from .fortiswitch_ports import _entries
    entries, unknown = _entries(text, ('system interface',))
    rows = []
    for name, fields in entries:
        if 'vlanid' not in fields:
            continue
        try:
            value = fields['vlanid']
            if len(value) != 1 or not value[0].isdigit() or not 1 <= int(value[0]) <= 4094:
                raise ValueError()
            parent = fields.get('interface', [])
            if parent and len(parent) != 1:
                raise ValueError()
            address = fields.get('ip', [])
            if address and len(address) != 2:
                raise ValueError()
            ipv4 = ipaddress.IPv4Interface('/'.join(address)) if address else None
            row = t.record(table, name=name, vlan_id=int(value[0]))
            row.update(interface=parent[0] if parent else None, ip=str(ipv4.ip) if ipv4 else None,
                       prefix_length=ipv4.network.prefixlen if ipv4 else None, source='configuration')
            rows.append(row)
        except ValueError:
            unknown.append({'line': 1, 'text': 'invalid VLAN interface: ' + name})
    return rows, unknown


def bridge(table, text):
    """Only the observed empty bridge layout is qualified; populated rows stay unknown."""
    from . import tables as t
    return t.lines(text, lambda value: None, (
        r'show bridge control interface [A-Za-z0-9_.:-]+ host\.',
        r'Bridge [A-Za-z0-9_.:-]+ host table',
        r'fdb: hash size=0, used=0, num=0, depth=0, gc_time=0, ageing_time=0, version_count=0',
    ))


def read_mac(auth, read):
    from . import tables as t, port_vlan
    switches = auth.read_inventory.get('switches', ())
    if 'bridge_mac_table' not in auth.enabled_queries or not switches:
        result = t.parse('fortinet', 'mac_entry', None, '', status='not_applicable')
        result['reason'] = 'FortiGate je L3; MAC klient\u016f viz arp a FortiSwitch'
        return result
    result = None
    for switch in switches:
        other = read('bridge_mac_table', 'mac_entry', {'switch': switch})
        other['bridge'] = switch
        if result is None:
            result = other
        else:
            port_vlan.combine(result, other)
            result['records'].extend(other['records'])
            result['coverage']['parsed_records'] += other['coverage']['parsed_records']
    result['bridges'] = list(switches)
    return result


def register(parsers):
    for table, query, parser in (
            ('interface', 'physical_interfaces', physical),
            ('vlan', 'interface_vlan_ids', vlans),
            ('lldp_neighbor', 'lldp_summary', lldp),
            ('mac_entry', 'bridge_mac_table', bridge)):
        parsers[('fortinet', table, query)] = parser
