"""IOS port rates, STP detail, LACP member state, PoE detail, DOM and per-port neighbors (1.0.12 G53).

Registered next to eos_ports/exos_ports so the generic switch_read paths, filters and coverage of
tables.py apply. Formats are those measured on IOSvL2 15.2 (rates, STP, neighbors, load-balance) and
the Cisco command-reference outputs for what the lab image cannot print (LACP members, PoE, DOM).
Rates are the device's own load-interval averages; counter deltas between two reads stay in
interface_errors (baseline). Every line that is not recognized stays in `unparsed`.
"""
from __future__ import annotations

import re

PROFILE = 'cisco_ios'
XE_PROFILE = 'cisco_xe'
PROFILES = (PROFILE, XE_PROFILE)
FIELDS = {
    'lag_member': ('group', 'port', 'flags', 'mode', 'state', 'bundled', 'priority', 'admin_key', 'oper_key',
                   'port_number', 'port_state', 'port_state_flags', 'reason'),
}
# Default (no interface) query of each table; poe_port and optics_port need one enrolled port.
BINDINGS = {'port_rates': 'interfaces_details', 'stp_topology': 'stp_detail', 'stp_port_counters': 'stp_detail',
            'lag_member': 'lacp_internal'}
INTERFACE_QUERIES = {'port_rates': 'interface_details', 'stp_port_counters': 'stp_interface_detail',
                     'poe_port': 'power_inline_detail', 'optics_port': 'interface_transceiver',
                     'cdp_neighbor': 'cdp_neighbor_interface', 'lldp_neighbor': 'lldp_neighbor_interface'}
TABLES = set(BINDINGS) | set(INTERFACE_QUERIES)
# Fields the IOS formats never print (EOS-only BPDU error counters and MST boundary; PoE voltage/current).
OPTIONAL = {'stp_topology': {'root_port', 'last_change_seconds', 'last_change_from'},
            'stp_port_counters': {'boundary', 'bpdu_tagged_errors', 'bpdu_other_errors', 'portfast', 'bpdu_filter'},
            'port_rates': {'rx_percent', 'tx_percent'},
            'lag_member': {'mode', 'reason'},
            'poe_port': {'class', 'voltage', 'current_ma', 'power_w', 'fault'},
            'optics_port': {'tx_bias_ma', 'voltage', 'tx_dbm', 'rx_dbm'}}
# Query -> table of the normalized envelope ssh_read adds to the raw output.
QUERY_TABLES = {'stp_detail': 'stp_topology', 'stp_interface_detail': 'stp_port_counters',
                'lacp_internal': 'lag_member', 'power_inline_detail': 'poe_port',
                'cdp_neighbor_interface': 'cdp_neighbor', 'lldp_neighbor_interface': 'lldp_neighbor'}


def request(table, vlan_id, mac, interface, *, profile=PROFILE):
    """Device-side IOS query, slots and local filters of one table selection; None for the generic path."""
    from .query_catalog import READ_QUERIES
    from .read_policy import _validate_slot
    from . import tables as t
    if table not in TABLES:
        return None
    if table in ('cdp_neighbor', 'lldp_neighbor') and interface is None:
        return None
    if vlan_id is not None or mac is not None:
        raise ValueError('filter does not apply to this table')
    if interface is None:
        if table not in BINDINGS:
            raise ValueError('interface is required for this IOS port table')
        return BINDINGS[table], {}, {}
    if table == 'lag_member':
        # One read of every channel group; the member port is a local filter.
        return BINDINGS[table], {}, {'port': t.port(_validate_slot(interface, 'interface'))}
    if table not in INTERFACE_QUERIES:
        raise ValueError('filter does not apply to this table')
    query = INTERFACE_QUERIES[table]
    value = _validate_slot(interface, READ_QUERIES[profile][query].slots['interface'].kind)
    # A device answer about another port never becomes this port's reading.
    filters = {'port': t.port(value)} if table in ('port_rates', 'poe_port', 'optics_port') else {}
    if profile == XE_PROFILE:
        field = 'local_port' if table.endswith('_neighbor') else 'port'
        return query, {'interface': interface}, {field: t.port(value)}
    return query, {'interface': value}, filters


# --- port_rates: `show interfaces [<if>]` -------------------------------------------------------------

_RATE = re.compile(r'(\d+) (minute|second) (input|output) rate (\d+) bits/sec, (\d+) packets/sec')


def rates(table, text):
    """Device load-interval averages; utilisation is bits/sec over the configured BW."""
    from . import port_errors
    from . import tables as t
    _, unknown = port_errors.ios_details(text)  # the same recognized line set as the error counters
    rows, current, bandwidth = [], None, None
    for raw in text.splitlines():
        value = raw.strip()
        match = re.fullmatch(r'(\S+) is (?:up|down|administratively down|reset), line protocol is (?:up|down)(?: \([\w -]+\))?', value)
        if match:
            try:
                name = t.port(match[1])
            except ValueError:
                current = None
                continue
            current, bandwidth = t.record('port_rates', port=name), None
            rows.append(current)
            continue
        if current is None:
            continue
        match = re.fullmatch(r'MTU \d+ bytes, BW (\d+) Kbit/sec, DLY \d+ usec,', value)
        if match:
            bandwidth = int(match[1])
            continue
        match = _RATE.fullmatch(value)
        if match:
            interval = int(match[1]) * (60 if match[2] == 'minute' else 1)
            direction = 'rx' if match[3] == 'input' else 'tx'
            bits = int(match[4])
            current.update({'interval': interval, direction + '_kbps': bits / 1000, direction + '_pps': int(match[5]),
                            direction + '_percent': round(bits / (bandwidth * 10), 3) if bandwidth else None})
    rows = [row for row in rows if row['interval'] is not None]
    return rows, unknown


# --- STP: `show spanning-tree [interface <if>] detail` ------------------------------------------------

_DURATION = re.compile(r'(?:(\d+):(\d+):(\d+)|(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?)')


def _seconds(text):
    """IOS ages: hh:mm:ss, 1d19h, 2w3d; the device rounds days/weeks to its own resolution."""
    match = _DURATION.fullmatch(text)
    if not match or not text:
        return None
    if match[1] is not None:
        return int(match[1]) * 3600 + int(match[2]) * 60 + int(match[3])
    weeks, days, hours = (int(group or 0) for group in match.groups()[3:])
    return ((weeks * 7 + days) * 24 + hours) * 3600


# Exact PortFast lines of `show spanning-tree interface <if> detail` -> the portfast field.
_PORTFAST = {'The port is in the portfast edge mode': 'edge',
             'The port is in the portfast edge mode by default': 'edge',
             'The port is in the portfast edge trunk mode': 'edge trunk',
             'The port is in the portfast mode by portfast trunk configuration': 'trunk'}
_STATES = ('forwarding', 'blocking', 'listening', 'learning', 'disabled', 'broken')
_ROLES = ('root', 'designated', 'alternate', 'backup', 'master', 'boundary')


def stp(table, text, *, nxos=False, xe=False):
    from . import tables as t
    instances, ports, unknown = [], [], []
    instance = current = None
    pending_from = False
    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value:
            continue
        match = re.fullmatch(r'(\S+) is executing the (\S+) compatible Spanning Tree protocol', value)
        if match:
            instance = t.record('stp_topology', instance=match[1], protocol=match[2], root_bridge=False)
            instances.append(instance)
            current, pending_from = None, False
            continue
        annotation = r'(?:, vPC(?: Peer-link)?)?' if nxos else ''
        match = re.fullmatch(r'Port (\d+) \(([^ ,()]+)' + annotation + r'\) of (\S+) is (.+)', value)
        if match:
            words = match[4].split()
            role = ' '.join(words[:-1]) or None
            if words[-1] not in _STATES or role not in (None, *_ROLES):
                unknown.append({'line': number, 'text': raw})
                current = None
                continue
            try:
                current = t.record('stp_port_counters', instance=match[3], port=t.port(match[2]), role=role, state=words[-1])
            except ValueError:
                unknown.append({'line': number, 'text': raw})
                current = None
                continue
            ports.append(current)
            continue
        if re.fullmatch(r'no spanning tree info available for \S+', value) or (
                nxos and re.fullmatch(r'No spanning tree information available for \S+', value)):
            continue
        if instance is not None and current is None:
            if value == 'We are the root of the spanning tree':
                instance['root_bridge'] = True
                continue
            match = re.fullmatch(r'Root port is \d+ \((\S+)\), cost of root path is \d+', value)
            if match:
                instance['root_port'] = t.port(match[1])
                continue
            match = re.fullmatch(r'Number of topology changes (\d+) last change occurred (\S+) ago', value)
            if match:
                instance['topology_changes'] = int(match[1])
                instance['last_change_seconds'] = _seconds(match[2])
                pending_from = True
                continue
            match = re.fullmatch(r'from (\S+)', value)
            if match and pending_from:
                instance['last_change_from'] = t.port(match[1])
                pending_from = False
                continue
            if t.matches(value, (r'Bridge Identifier has priority \d+, sysid \d+, address \S+',
                                 r'Configured hello time \d+, max age \d+, forward delay \d+(?:, transmit hold-count \d+)?',
                                 r'Current root has priority \d+, address \S+',
                                 r'Topology change flag (?:not )?set, detected flag (?:not )?set',
                                 r'Times:\s+hold \d+, topology change \d+, notification \d+',
                                 r'hello \d+, max age \d+, forward delay \d+',
                                 r'Timers: hello \d+, topology change \d+, notification \d+' +
                                 (r'(?:, aging \d+)?' if nxos else r', aging \d+'))):
                continue
        if current is not None:
            match = re.fullmatch(r'Port path cost (\d+), Port priority \d+, Port Identifier [\d.]+\.?', value)
            if match:
                current['cost'] = int(match[1])
                continue
            match = re.fullmatch(r'Number of transitions to forwarding state:\s*(\d+)', value)
            if match:
                current['forward_transitions'] = int(match[1])
                continue
            # Only the one-port detail prints it; None elsewhere means "not stated", not "off". The edge form is
            # measured on IOSvL2 15.2, the others are the Cisco IOS 15.4SY examples (Optional STP Features);
            # any other portfast or BPDU filter form stays unparsed.
            if value in _PORTFAST:
                current['portfast'] = _PORTFAST[value]
                continue
            if value == 'Bpdu filter is enabled':
                current['bpdu_filter'] = True
                continue
            if nxos and value == 'The port type is network':
                continue
            peer = r'(?:, Peer is STP)?' if nxos or xe else ''
            match = re.fullmatch(r'Link type is (\S+)(?: by default)?' + peer, value)
            if match:
                current['link_type'] = match[1]
                continue
            match = re.fullmatch(r'BPDU:\s*sent (\d+), received (\d+)', value)
            if match:
                current.update(bpdu_sent=int(match[1]), bpdu_received=int(match[2]))
                continue
            if t.matches(value, (r'Designated root has priority \d+, address \S+',
                                 r'Designated bridge has priority \d+, address \S+',
                                 r'Designated port id is [\d.]+, designated path cost \d+',
                                 r'Timers:\s*message age \d+, forward delay \d+, hold \d+',
                                 r'(?i:(?:loop|root|bpdu) guard)(?: is |:\s*)enabled(?: by default)?(?: on the port)?')):
                continue
        unknown.append({'line': number, 'text': raw})
    return (instances if table == 'stp_topology' else ports), unknown


# --- LACP members: `show lacp internal` ---------------------------------------------------------------

# IEEE 802.1AX actor state bits as IOS prints them in the "Port State" column.
PORT_STATE_BITS = ((0x01, 'lacp_active'), (0x02, 'short_timeout'), (0x04, 'aggregatable'), (0x08, 'in_sync'),
                   (0x10, 'collecting'), (0x20, 'distributing'), (0x40, 'defaulted'), (0x80, 'expired'))
STATE_REASONS = {
    'susp': 'suspended: the port does not match the channel or its partner (speed, duplex, VLANs, keys)',
    'hot-sby': 'hot-standby: the channel already has its maximum number of active members',
    'indep': 'individual: no LACPDUs from a partner, the port forwards on its own',
    'down': 'link down',
}


def reason(state, port_state):
    """Why a member is not bundled, from the IOS state word and the actor state bits; None when bundled."""
    if state == 'bndl':
        return None
    found = [STATE_REASONS.get(state, 'not bundled: state ' + state)]
    if port_state is not None:
        if port_state & 0x40:
            found.append('partner information defaulted: no LACPDUs received')
        if port_state & 0x80:
            found.append('partner LACPDUs expired')
        if not port_state & 0x08:
            found.append('not in sync with the partner')
        if not port_state & 0x04:
            found.append('port is not aggregatable')
    return '; '.join(found)


def lacp(table, text):
    from . import tables as t
    group = None
    def handle(raw, value):
        nonlocal group
        if value.startswith('Flags:') or re.fullmatch(r'(?:[A-Za-z] - Device [^-]+?\.?\s*)+', value):
            return []
        match = re.fullmatch(r'Channel group (\d+)', value)
        if match:
            group = int(match[1])
            return []
        if t.matches(value, (r'(?:LACPDUs\s+)?LACP [Pp]ort\s+Admin\s+Oper\s+Port\s+Port',
                             r'Port\s+Flags\s+State\s+(?:Interval\s+)?Priority\s+Key\s+Key\s+Number\s+State')):
            return []
        match = re.fullmatch(r'(\S+)\s+([A-Za-z]+)\s+([a-z-]+)\s+(?:\d+s\s+)?(\d+)\s+(0x[0-9A-Fa-f]+|\d+)\s+'
                             r'(0x[0-9A-Fa-f]+|\d+)\s+(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)', value)
        if not match or group is None:
            return None
        state, port_state = match[3], int(match[8], 16)
        flags = match[2]
        return t.record(table, group=group, port=t.port(match[1]), flags=flags,
                        mode='active' if 'A' in flags.upper() else 'passive' if 'P' in flags.upper() else None,
                        state=state, bundled=state == 'bndl', priority=int(match[4]),
                        admin_key=int(match[5], 0), oper_key=int(match[6], 0), port_number=int(match[7], 16),
                        port_state=port_state,
                        port_state_flags=[name for bit, name in PORT_STATE_BITS if port_state & bit],
                        reason=reason(state, port_state))
    return t.scan(text, handle)


# --- `show etherchannel load-balance` ---------------------------------------------------------------

def load_balance(text, state, *, version=None):
    """Configured method and the address fields per protocol; incomplete output is never `ok`."""
    found = {'method': None, 'non_ip': None, 'ipv4': None, 'ipv6': None}
    status = state or 'unparsed'
    method = text.strip()
    if re.fullmatch(r'(?:Source|Destination) MAC address', method):
        found['method'] = method
        if status == 'ok' and not text.endswith('\n'):
            status = 'unparsed'
        return {'status': status, **found, 'unparsed': []}

    unknown, section = [], None
    awaiting_bridged, missing_bridged = False, False
    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value:
            continue
        if awaiting_bridged:
            awaiting_bridged = False
            if raw[0] in ' \t' and re.fullmatch(r'.+ \(bridged packets\)', value):
                found['ipv6'] += '\n' + value
                continue
            missing_bridged = True
        if value == 'EtherChannel Load-Balancing Configuration:':
            section = 'method'
            continue
        if value == 'EtherChannel Load-Balancing Addresses Used Per-Protocol:':
            section = 'protocols'
            continue
        match = re.fullmatch(r'(Non-IP|IPv4|IPv6): (.+)', value)
        if section == 'protocols' and match:
            found[{'Non-IP': 'non_ip', 'IPv4': 'ipv4', 'IPv6': 'ipv6'}[match[1]]] = match[2]
            awaiting_bridged = match[1] == 'IPv6' and match[2].endswith(' (routed packets)')
            continue
        if section == 'method' and found['method'] is None and re.fullmatch(r'[a-z0-9-]+(?: [a-z0-9-]+)*', value):
            found['method'] = value
            continue
        unknown.append({'line': number, 'text': raw})
    if status == 'ok':
        # Cisco added the IPv6 row to the Catalyst 6500 display in 12.2(17a)SX1.
        # A capture ending at IPv4 is ambiguous on any release without that documented exception.
        legacy = version in {'12.0(7)XE', '12.1(3a)E3', '12.1(5c)EX', '12.2(14)SX'}
        if (unknown or awaiting_bridged or missing_bridged or not text.endswith('\n')
                or any(found[key] is None for key in ('method', 'non_ip', 'ipv4'))
                or (found['ipv6'] is None and not legacy)):
            status = 'unparsed'
    return {'status': status, **found, 'unparsed': unknown}


# --- PoE: `show power inline <if> detail` -------------------------------------------------------------

_POE_NUMBERS = {'Admin Value': 'admin_value_w', 'Power drawn from the source': 'allocated_w',
                'Power available to the device': 'available_to_device_w', 'Measured at the port': 'measured_w',
                'Maximum Power drawn by the device since powered on': 'max_measured_w',
                'Absolute Max Allocation': 'absolute_max_w'}
_POE_TEXT = {'Inline Power Mode': 'admin_mode', 'Operational status': 'oper_status', 'Device Detected': 'device_detected',
             'Device Type': 'device_type', 'IEEE Class': 'ieee_class',
             'Discovery mechanism used/configured': 'discovery', 'Police': 'police'}
_POE_COUNTERS = {'Absent Counter': 'absent', 'Over Current Counter': 'over_current',
                 'Short Current Counter': 'short_current', 'Invalid Signature Counter': 'invalid_signature',
                 'Power Denied Counter': 'power_denied'}
_XE_POE_PAIRS = {'Operational status (Alt-A,B)': 'oper_status', 'IEEE Class (Alt-A,B)': 'ieee_class',
                 'Measured at the port(watts) (Alt-A,B)': 'measured_w'}
_POE_FAULT_STATES = {'faulty', 'power-deny', 'err-disable', 'errdisable'}


def poe_detail(text, *, xe=False):
    """Every `Label: value` line is kept; the known labels become typed values and power-fault evidence."""
    detail = {'interface': None, **dict.fromkeys(_POE_TEXT.values()), **dict.fromkeys(_POE_NUMBERS.values()),
              'counters': {}, 'faults': [], 'attributes': {}}
    unknown = []
    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value:
            continue
        match = re.fullmatch(r'([A-Za-z][A-Za-z0-9 /(),-]*?)\s*:\s*(.*)', value)
        if not match:
            if xe and re.fullmatch(r'LLDP Power Negotiation\s+--Sent to PD--\s+--Rcvd from PD--', value):
                continue
            if re.fullmatch(r'[A-Z][A-Za-z ]+', value):  # section titles such as "Power Allocated"
                continue
            unknown.append({'line': number, 'text': raw})
            continue
        label, item = match[1], match[2].strip()
        detail['attributes'][label] = item
        if label == 'Interface':
            detail['interface'] = item
        elif label in _POE_TEXT:
            detail[_POE_TEXT[label]] = int(item) if label == 'IEEE Class' and item.isdigit() else (item or None)
        elif label in _POE_NUMBERS:
            if re.fullmatch(r'\d+(?:\.\d+)?', item):
                detail[_POE_NUMBERS[label]] = float(item)
            elif item not in ('n/a', '-'):
                unknown.append({'line': number, 'text': raw})
        elif xe and label in _XE_POE_PAIRS:
            field = _XE_POE_PAIRS[label]
            decimal = r'\d+(?:\.\d+)?'
            if field == 'oper_status' and re.fullmatch(r'[a-z-]+,[a-z-]+', item):
                detail[field] = item
            elif field == 'ieee_class' and re.fullmatch(r'\d,\d', item):
                detail[field] = item
            elif field == 'measured_w' and re.fullmatch(fr'{decimal},{decimal}', item):
                readings = [float(value) for value in item.split(',')]
                detail['measured_pair_w'] = readings
                detail[field] = round(sum(readings), 3)
            else:
                unknown.append({'line': number, 'text': raw})
        elif label in _POE_COUNTERS:
            if not item.isdigit():
                unknown.append({'line': number, 'text': raw})
                continue
            detail['counters'][_POE_COUNTERS[label]] = int(item)
    detail['faults'] = [name for name, count in detail['counters'].items() if count]
    detail['faults'].extend('oper_status_' + state for state in (detail['oper_status'] or '').split(',')
                            if state in _POE_FAULT_STATES)
    if xe and (any(detail[field] is None for field in ('admin_mode', 'oper_status', 'allocated_w'))
               or set(detail['counters']) != set(_POE_COUNTERS.values())):
        unknown.append({'line': 1, 'text': 'PoE mode, state, allocation or fault counters missing'})
    return detail, unknown


def poe(table, text, *, xe=False):
    from . import tables as t
    detail, unknown = poe_detail(text, xe=xe)
    if detail['interface'] is None:
        return [], unknown or [{'line': 1, 'text': text.strip()[:200]}]
    try:
        port = t.port(detail['interface'])
    except ValueError:
        return [], [{'line': 1, 'text': detail['interface']}]
    row = t.record(table, port=port, state=detail['oper_status'], power_w=detail['measured_w'],
                   fault=', '.join(detail['faults']) or None,
                   **{'class': detail['ieee_class']})
    return [row], unknown


def _optics_rows(table, text, *, nxos=False, xe=False):
    from . import optics
    from . import tables as t
    summary = optics.nxos_transceiver(text, '') if nxos else optics.ios_transceiver(text, '', xe=xe)
    if nxos and summary['state'] in ('not_present', 'unsupported'):
        return [t.record(table, port=t.port(summary['interface']), state=summary['state'], alerts=[])], []
    if summary['state'] not in ('measured', 'partial', 'incomplete'):
        return [], summary.get('unparsed') or [{'line': 1, 'text': summary.get('reason', 'transceiver output not recognized')}]
    def values(readings):
        return dict(temperature_c=readings['temperature']['value'], tx_dbm=readings['tx_power']['value'],
                    rx_dbm=readings['rx_power']['value'], voltage=readings['voltage']['value'],
                    tx_bias_ma=readings['tx_bias_current']['value'])

    row = t.record(table, port=t.port(summary['interface']), state=summary['state'],
                   alerts=summary['alarms'], **values(summary['readings']))
    if 'lanes' in summary:
        row['lanes'] = [dict(lane=lane['lane'], **values(lane['readings'])) for lane in summary['lanes']]
    if (nxos or xe) and summary['missing_fields']:
        row['missing_fields'] = summary['missing_fields']
    return [row], summary['unparsed']


def parse(table, text, *, xe=False):
    if table == 'port_rates':
        return rates(table, text)
    if table in ('stp_topology', 'stp_port_counters'):
        return stp(table, text, xe=xe)
    if table == 'lag_member':
        return lacp(table, text)
    if table == 'poe_port':
        return poe(table, text, xe=xe)
    return _optics_rows(table, text, xe=xe)


def read(query, text, parameters, state, *, version=None, profile=PROFILE):
    """ssh_read additions: a normalized envelope of the table form and the detail summaries."""
    from . import tables as t
    out = {}
    if query == 'etherchannel_load_balance':
        from .normalization import response_envelope, source_record
        out['load_balance'] = load_balance(text, state, version=version)
        status = out['load_balance']['status']
        envelope = response_envelope(profile, status, [source_record(query, text, status)], identity_coverage=False)
        envelope['coverage']['complete'] = status == 'ok'
        out['normalized'] = envelope
    if profile == XE_PROFILE and query == 'etherchannel_detail':
        out['etherchannel'] = etherchannel_detail(text, parameters['group_id'], state)
    if query == 'power_inline_detail' and state == 'ok':
        from .normalization import normalize_port
        detail, unknown = poe_detail(text, xe=profile == XE_PROFILE)
        try:
            same = normalize_port(detail['interface'])['name'] == normalize_port((parameters or {})['interface'])['name']
        except (KeyError, TypeError, ValueError):
            same = False
        out['poe'] = {**detail, 'complete': not unknown and same}
        if not same:
            out['poe']['faults'] = []
            out['poe']['warning'] = 'answer_for_another_interface'
    if query in QUERY_TABLES:
        table = QUERY_TABLES[query]
        interface = (parameters or {}).get('interface')
        filters = None
        if profile == XE_PROFILE and interface:
            filters = {'local_port' if table.endswith('_neighbor') else 'port': t.port(interface)}
        out['normalized'] = t.parse(profile, table, query, text, status=state, filters=filters)
    return out


def etherchannel_detail(text, group, state):
    """Report channel-level data alongside the full scoped CLI output."""
    result = {'group': int(group), 'status': state, 'complete': state == 'empty'}
    if state != 'ok':
        return result
    header = re.search(r'(?m)^\s*Group state = (.+)\n\s*Ports: (\d+)\s+Maxports = \d+\n'
                       r'\s*Port-channels: (\d+)\s+Max Port-channels = \d+\n\s*Protocol:\s*([^\n]+)', text)
    if not header:
        return result | {'status': 'unparsed'}
    groups = re.findall(r'(?m)^\s*Channel group\s*=\s*(\d+)\b', text)
    channels = re.findall(r'(?m)^\s*Port-channel:\s*(Po\d+)\b', text)
    complete = len(groups) == int(header[2]) and all(item == group for item in groups) and len(channels) == int(header[3])
    return result | {'status': 'ok' if complete else 'unparsed', 'complete': complete,
                     'group_state': header[1].strip(), 'protocol': header[4].strip(),
                     'port_count': int(header[2]), 'port_channels': channels}


def _ios_lldp(table, text):
    from .tables import cisco_lldp
    return cisco_lldp(text, 'ios')


def _xe_lldp(table, text):
    from .tables import cisco_lldp
    return cisco_lldp(text, 'ios', check_total=True)


def register(t):
    from functools import partial
    from . import cdp
    t.FIELDS.update(FIELDS)
    for profile in PROFILES:
        t.BINDINGS[profile].update(BINDINGS)
        for table, query in list(BINDINGS.items()) + list(INTERFACE_QUERIES.items()):
            if table == 'cdp_neighbor':
                parser = partial(cdp.parse, check_total=profile == XE_PROFILE)
            elif table == 'lldp_neighbor':
                parser = _xe_lldp if profile == XE_PROFILE else _ios_lldp
            else:
                parser = partial(parse, xe=profile == XE_PROFILE)
            t.QUERY_PARSERS[profile, table, query] = parser
        profile_optional = t.PROFILE_OPTIONAL_FIELDS.setdefault(profile, {})
        profile_optional.update({table: set(fields) for table, fields in OPTIONAL.items()})
