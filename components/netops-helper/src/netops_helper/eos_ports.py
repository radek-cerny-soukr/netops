"""EOS port rates, STP detail and IGMP snooping tables for measured and documented formats.

Registered next to exos_ports: the generic switch_read paths, filters and coverage of
tables.py apply. Rates are the device's own load-interval averages, not a Helper
measurement; counter deltas between two reads stay in interface_errors (baseline).
"""
from __future__ import annotations

import re
from decimal import Decimal

FIELDS = {
    'port_rates': ('port', 'interval', 'rx_kbps', 'rx_percent', 'rx_pps', 'tx_kbps', 'tx_percent', 'tx_pps'),
    'stp_topology': ('instance', 'protocol', 'root_bridge', 'root_port', 'topology_changes',
                     'last_change_seconds', 'last_change_from'),
    'stp_port_counters': ('instance', 'port', 'role', 'state', 'cost', 'link_type', 'boundary', 'forward_transitions',
                          'bpdu_sent', 'bpdu_received', 'bpdu_tagged_errors', 'bpdu_other_errors', 'portfast',
                          'bpdu_filter'),
    'igmp_group': ('vlan_id', 'group', 'members'),
    'igmp_mrouter': ('vlan_id', 'port', 'learned'),
}
BINDINGS = {'port_rates': 'interfaces_counters_rates', 'stp_topology': 'stp_detail',
            'stp_port_counters': 'stp_detail', 'igmp_group': 'igmp_snooping_groups',
            'igmp_mrouter': 'igmp_snooping_mrouter'}
# The interface selector of these tables is a device-side slot, not a local filter.
INTERFACE_QUERIES = {'port_rates': 'interface_counters_rates', 'stp_port_counters': 'stp_interface_detail',
                     'mac_entry': 'mac_table_interface'}
OPTIONAL = {'port_rates': {'rx_pps', 'tx_pps'},
            'stp_topology': {'root_port', 'last_change_seconds', 'last_change_from'},
            'stp_port_counters': {'cost', 'portfast', 'bpdu_filter'},
            'igmp_mrouter': {'learned'}}

_NUMBER = r'\d+(?:\.\d+)?'


def mac_queries(vlan_id, mac, interface):
    """Queries that can answer a mac_entry selection; `mac_table` is the full-table query kept for backward compatibility."""
    if interface is not None:
        return ['mac_table_interface']
    return (['mac_table_address'] if mac is not None else []) + (['mac_table_vlan'] if vlan_id is not None else []) + ['mac_table']


def request(table, vlan_id, mac, interface, enabled_queries=None):
    """Device-side EOS query and slots for one table selection; None when the generic path applies."""
    from .read_policy import _validate_slot
    if table == 'mac_entry':
        # The most selective device-side filter; the other selectors stay local filters.
        filters = {}
        if vlan_id is not None:
            filters['vlan_id'] = int(_validate_slot(vlan_id, 'vlan_id'))
        if mac is not None:
            filters['mac'] = _validate_slot(mac, 'mac_literal')
        if interface is not None:
            value = _validate_slot(interface, 'eos_switchport_interface')
            from .tables import port
            filters['port'] = port(value)
            return 'mac_table_interface', {'interface': value}, filters
        candidates = []
        if mac is not None:
            candidates.append(('mac_table_address', {'mac': filters['mac']}))
        if vlan_id is not None:
            candidates.append(('mac_table_vlan', {'vlan_id': str(filters['vlan_id'])}))
        if candidates:
            if enabled_queries is not None:
                candidates.append(('mac_table', {}))
                for query, parameters in candidates:
                    if query in enabled_queries:
                        return query, parameters, filters
            query, parameters = candidates[0]
            return query, parameters, filters
        return None
    if table not in FIELDS:
        return None
    if mac is not None or vlan_id is not None and table not in ('igmp_group', 'igmp_mrouter'):
        raise ValueError('filter does not apply to this table')
    filters = {'vlan_id': int(_validate_slot(vlan_id, 'vlan_id'))} if vlan_id is not None else {}
    if interface is None:
        return BINDINGS[table], {}, filters
    if table not in INTERFACE_QUERIES:
        raise ValueError('filter does not apply to this table')
    kind = 'eos_interface' if table == 'port_rates' else 'eos_stp_interface'
    return INTERFACE_QUERIES[table], {'interface': _validate_slot(interface, kind)}, filters


def _rates(text):
    """`show interfaces counters rates`; a narrow terminal wraps the last columns into a second table."""
    from . import tables as t
    rows, extra = {}, {}
    rate_unit = packet_unit = None
    has_tx_packets = wrapped = False

    def packets(value):
        if packet_unit == 'Pps':
            return int(value) if value.isascii() and value.isdecimal() else None
        return int(Decimal(value) * 1000) if re.fullmatch(r'\d+(?:\.\d{1,3})?', value) else None

    def handle(raw, value):
        nonlocal rate_unit, packet_unit, has_tx_packets, wrapped
        header = re.fullmatch(r'Port\s+(?:Name\s+)?Intvl\s+In (Kbps|Mbps)\s+%\s+In (Pps|Kpps)'
                              r'\s+Out \1\s+%(?:\s+(Out \2))?', value)
        if header:
            rate_unit, packet_unit, has_tx_packets, wrapped = header[1], header[2], bool(header[3]), False
            return []
        if packet_unit is not None and not has_tx_packets and re.fullmatch(r'Port\s+Out ' + packet_unit, value):
            wrapped = True
            return []
        if rate_unit is None:
            return None
        if wrapped:
            match = re.fullmatch(r'(\S+)\s+(\S+)', value)
            if not match or t.port(match[1]) not in rows or t.port(match[1]) in extra:
                return None
            pps = packets(match[2])
            if pps is None:
                return None
            extra[t.port(match[1])] = pps
            return []
        cells = value.split()
        count = 7 if has_tx_packets else 6
        if len(cells) < count + 1:
            return None
        values, name = cells[-count:], cells[0]
        if not re.fullmatch(r'\d+:\d{2}', values[0]):
            return None
        numbers = values[1:]
        rx_pps = packets(numbers[2])
        tx_pps = packets(numbers[5]) if has_tx_packets else None
        if not (re.fullmatch(_NUMBER, numbers[0]) and re.fullmatch(_NUMBER + '%', numbers[1]) and rx_pps is not None
                and re.fullmatch(_NUMBER, numbers[3]) and re.fullmatch(_NUMBER + '%', numbers[4])
                and (not has_tx_packets or tx_pps is not None)):
            return None
        minutes, seconds = values[0].split(':')
        multiplier = 1000 if rate_unit == 'Mbps' else 1
        row = t.record('port_rates', port=t.port(name), interval=int(minutes) * 60 + int(seconds),
                       rx_kbps=float(numbers[0]) * multiplier, rx_percent=float(numbers[1][:-1]), rx_pps=rx_pps,
                       tx_kbps=float(numbers[3]) * multiplier, tx_percent=float(numbers[4][:-1]), tx_pps=tx_pps)
        rows[row['port']] = row
        return [row]
    records, unknown = t.scan(text, handle)
    for port_name, value in extra.items():
        rows[port_name]['tx_pps'] = value
    if records and any(row['tx_pps'] is None for row in records):
        unknown.append({'line': 1, 'text': 'missing output packet-rate column'})
    return records, unknown


_PORT_HEAD = re.compile(r'Port (\d+) \((\S+)\) of (\S+) is (\S+) (\S+)')


def _stp_port(name):
    """A port of the STP detail; an MLAG peer's port (PeerEthernet5) keeps its EOS name."""
    from . import tables as t
    if re.fullmatch(r'PeerEthernet\d+(?:/\d+){0,2}', name):
        return name
    return t.port(name)


def _stp(table, text):
    """`show spanning-tree [interface X] detail`: instance blocks with per-port blocks."""
    from . import tables as t
    instances, ports, unknown = [], [], []
    instance = current = None
    pending_from = False
    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value:
            continue
        m = re.fullmatch(r'(\S+) is executing the (\S+) Spanning Tree protocol', value)
        if m:
            instance = t.record('stp_topology', instance=m[1], protocol=m[2], root_bridge=False)
            instances.append(instance)
            current = None
            continue
        m = _PORT_HEAD.fullmatch(value)
        if m:
            try:
                current = t.record('stp_port_counters', instance=m[3], port=_stp_port(m[2]), role=m[4], state=m[5])
            except ValueError:
                unknown.append({'line': number, 'text': raw})
                current = None
                continue
            ports.append(current)
            continue
        if instance is not None and current is None:
            if value == 'We are the root of the spanning tree':
                instance['root_bridge'] = True
                continue
            m = re.fullmatch(r'Root port is \d+ \((\S+)\), cost of root path is .*', value)
            if m:
                instance['root_port'] = _stp_port(m[1])
                continue
            m = re.fullmatch(r'Number of topology changes (\d+) last change occurred (\d+) seconds ago', value)
            if m:
                instance['topology_changes'], instance['last_change_seconds'] = int(m[1]), int(m[2])
                pending_from = True
                continue
            m = re.fullmatch(r'from (\S+)', value)
            if m and pending_from:
                instance['last_change_from'] = _stp_port(m[1])
                pending_from = False
                continue
            if re.match(r'(?:Bridge Identifier has priority|Configured hello time|Current root has priority) ', value):
                continue
        if current is not None:
            m = re.fullmatch(r'Port path cost (\d+), Port priority \d+, Port Identifier [\d.]+\.?', value)
            if m:
                current['cost'] = int(m[1])
                continue
            m = re.fullmatch(r'Number of transitions to forwarding state: (\d+)', value)
            if m:
                current['forward_transitions'] = int(m[1])
                continue
            m = re.fullmatch(r'Link type is (\S+) .*?, (Internal|Boundary)', value)
            if m:
                current['link_type'], current['boundary'] = m[1], m[2] == 'Boundary'
                continue
            m = re.fullmatch(r'BPDU: sent (\d+), received (\d+), taggedErr (\d+), otherErr (\d+), rateLimiterCount \d+', value)
            if m:
                current.update(bpdu_sent=int(m[1]), bpdu_received=int(m[2]),
                               bpdu_tagged_errors=int(m[3]), bpdu_other_errors=int(m[4]))
                continue
            if re.match(r'(?:Designated root has|Designated bridge has|Designated port id is|Timers: |Rate-Limiter: )', value):
                continue
        unknown.append({'line': number, 'text': raw})
    return (instances if table == 'stp_topology' else ports), unknown


def _igmp(table, text):
    from . import tables as t
    def handle(raw, value):
        if table == 'igmp_group':
            if (value in ('IGMP Snooping Group Membership', 'EX : Filter mode Exclude', 'IN : Filter mode Include',
                          'IR : Ingress Replication') or re.fullmatch(r'VLAN\s+Group\s+Members', value)):
                return []
            m = re.fullmatch(r'(\d+)\s+(\*|\d+\.\d+\.\d+\.\d+)\s+(\S.*)', value)
            if m:
                return t.record(table, vlan_id=int(m[1]), group=m[2],
                                members=[item for item in re.split(r',\s*', m[3]) if item])
            return None
        if re.fullmatch(r'Vlan\s+Interface-ports', value):
            return []
        m = re.fullmatch(r'(\d+)\s+(\S.*)', value)
        if not m:
            return None
        rows = []
        for item in re.split(r',\s*', m[2]):
            cell = re.fullmatch(r'([A-Za-z][\w/.-]*)(?:\((\w+)\))?', item)
            if not cell:
                return None
            rows.append(t.record(table, vlan_id=int(m[1]), port=cell[1] if cell[1] == 'Cpu' else t.port(cell[1]),
                                 learned=cell[2]))
        return rows
    return t.scan(text, handle)


def parse(table, text):
    if table == 'port_rates':
        return _rates(text)
    if table in ('stp_topology', 'stp_port_counters'):
        return _stp(table, text)
    return _igmp(table, text)


def register(t):
    t.FIELDS.update(FIELDS)
    t.BINDINGS['arista_eos'].update(BINDINGS)
    for table, query in BINDINGS.items():
        t.QUERY_PARSERS['arista_eos', table, query] = parse
    for table, query in INTERFACE_QUERIES.items():
        if table != 'mac_entry':
            t.QUERY_PARSERS['arista_eos', table, query] = parse
    profile = t.PROFILE_OPTIONAL_FIELDS.setdefault('arista_eos', {})
    profile.update({table: set(fields) for table, fields in OPTIONAL.items()})
