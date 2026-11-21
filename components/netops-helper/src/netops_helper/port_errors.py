"""Read-only port counters and flap evidence above the existing catalogue.

Counters are cumulative since the device last cleared them; absent totals stay
None. In particular EXOS categories overlap and must never be summed into a total.
"""
from __future__ import annotations

import re

from .normalization import normalize_port
from .query_catalog import READ_QUERIES
from .read_policy import _validate_slot, enrolled_interface

FIELDS = ('port', 'rx_errors', 'crc', 'tx_errors', 'discards_in', 'discards_out',
          'last_flap', 'link_flaps', 'carrier_transitions')
PROFILES = ('cisco_ios', 'cisco_xe', 'cisco_nxos', 'arista_eos', 'extreme_exos',
            'juniper_junos', 'juniper_junos_els')
IGNORED_COLUMNS = {'Align-Err', 'UnderSize', 'Single-Col', 'Multi-Col', 'Late-Col',
                   'Excess-Col', 'Exces-Col', 'Carri-Sen', 'Runts', 'Giants', 'Symbol', 'Align',
                   'Stomped-CRC', 'SQETest-Err', 'Deferred-Tx', 'IntMacTx-Er', 'IntMacRx-Er', 'Symbol-Err'}
COLUMNS = {
    'FCS': 'crc', 'FCS-Err': 'crc', 'CRC': 'crc',
    'Rx': 'rx_errors', 'Rcv-Err': 'rx_errors', 'Rx-Err': 'rx_errors',
    'Tx': 'tx_errors', 'Xmit-Err': 'tx_errors', 'Tx-Err': 'tx_errors',
    'InDiscards': 'discards_in', 'OutDiscards': 'discards_out',
}


def record(name):
    return dict.fromkeys(FIELDS) | {'port': normalize_port(name)['name']}


# Junos port overview fields are present in every row, None when the device did not state them.
JUNOS_STATUS_FIELDS = ('admin_status', 'oper_status', 'description', 'speed', 'mtu')
# First field of the `Physical interface:` header (Junos Common Output Fields, "Enabled").
JUNOS_ADMIN_STATES = {'Enabled': 'up', 'Disabled': 'down', 'Administratively down': 'down'}


def junos_record(name):
    return record(name) | dict.fromkeys(JUNOS_STATUS_FIELDS)


def request(profile, interface):
    """Return the first binding and a local port filter; slots retain enrolment checks."""
    if profile not in PROFILES:
        if interface is not None:
            normalize_port(interface)
        return None, {}, {}
    query = ('interface_details' if profile.startswith('juniper_') else
             'ports_rx_errors' if profile == 'extreme_exos' else 'interfaces_counters_errors')
    filters, parameters = {}, {}
    if interface is not None:
        if profile == 'extreme_exos':
            if not isinstance(interface, str) or not re.fullmatch(r'[1-9]\d*(?::[1-9]\d*){0,2}', interface):
                raise ValueError('invalid EXOS port')
            value = interface
        elif profile == 'arista_eos':
            # This is a local filter over whole-port reads, not a CLI slot.
            value = normalize_port(interface)['name']
        else:
            slot_query = 'interface_details' if profile.startswith('juniper_') else 'interface_errors'
            value = _validate_slot(normalize_port(interface)['name'], READ_QUERIES[profile][slot_query].slots['interface'].kind)
        filters['port'] = normalize_port(value)['name']
        if profile == 'cisco_nxos' and '.' in value:
            # NX-OS accepts the bounded counter command on configured Ethernet subinterfaces.
            # A switch-wide counter read cannot substitute for it.
            query = 'interface_errors'
            parameters['interface'] = value
        if profile.startswith('juniper_'):
            parameters['interface'] = value
    if profile.startswith('juniper_') and not parameters:
        raise ValueError('interface is required for Junos interface_errors; provide an enrolled interface')
    return query, parameters, filters


def _metadata(value):
    # Transport captures can include command echo and a terminal prompt. Never
    # discard an arbitrary indented line: unknown data must affect coverage.
    return (value.startswith('show ') or
            re.fullmatch(r'(?:[\w.-]+@)?[\w.-]+> (?:show |\.\.\.).*', value) or
            re.fullmatch(r'(?:\* )?[\w.-]+\.\d+ [#>]\s*', value) or
            re.fullmatch(r'(?:[\w.-]+@)?[\w.-]+[#>]\s*', value))


def tabular(profile, text):
    rows, unknown, header = {}, [], None
    for number, raw in enumerate(text.splitlines(), 1):
        value = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', raw).strip()
        if not value or re.fullmatch(r'[-= ]+', value) or _metadata(value):
            continue
        cells = value.split()
        if cells[0] in ('Port', 'Interface') and cells[1:] and set(cells[1:]) <= set(COLUMNS) | IGNORED_COLUMNS:
            header = cells[1:]
            continue
        if header and cells[0] == 'Totals' and all(c.isdigit() for c in cells[1:]):
            continue
        if header and len(cells) == len(header) + 1 and all(re.fullmatch(r'\d+|--?|N/A', c) for c in cells[1:]):
            try:
                row = record(cells[0])
            except ValueError:
                row = None
            if row:
                row = rows.setdefault(row['port'], row)
                for label, item in zip(header, cells[1:]):
                    field = COLUMNS.get(label)
                    if field:
                        row[field] = int(item) if item.isdigit() else None
                continue
        unknown.append({'line': number, 'text': raw})
    return list(rows.values()), unknown


def exos(text):
    rows, unknown, direction = [], [], None
    for number, raw in enumerate(text.splitlines(), 1):
        value = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', raw).strip()
        if value == 'Port Rx Error Monitor':
            direction = 'rx'
            continue
        if value == 'Port Tx Error Monitor':
            direction = 'tx'
            continue
        if (not value or re.fullmatch(r'[= -]+', value) or _metadata(value) or
                re.fullmatch(r'Port\s+Link\s+(?:Rx\s+){6}Rx|Port\s+Link\s+(?:Tx\s+){5}Tx', value) or
                re.fullmatch(r'State\s+Crc\s+Over\s+Under\s+Frag\s+Jabber\s+Align\s+Lost', value) or
                re.fullmatch(r'State\s+Coll\s+Late coll\s+Deferred\s+Errors\s+Lost\s+Parity', value) or
                value.startswith(('Link State: ', '> indicates Port Display Name ')) or
                value == 'Press <SPACE> to continue or <Q> to quit:'):
            continue
        m = re.fullmatch(r'(\d+(?::\d+){0,2})\s+(?:\S+\s+)?(?:A|R|NP|L)\s+((?:\d+\s+){5,6}\d+)', value)
        if m and direction:
            counts = [int(c) for c in m[2].split()]
            if len(counts) == (7 if direction == 'rx' else 6):
                row = record(m[1])
                if direction == 'rx':
                    row['crc'] = counts[0]
                else:
                    row['tx_errors'] = counts[3]
                rows.append(row)
                continue
        unknown.append({'line': number, 'text': raw})
    return rows, unknown


def junos(text, interface=None):
    current = junos_record(interface) if interface else None
    rows, unknown, direction = ([current] if current else []), [], None
    for number, raw in enumerate(text.splitlines(), 1):
        value = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', raw).strip()
        m = re.match(r'Physical interface: (\S+),', value)
        if m:
            if not current or current['port'] != normalize_port(m[1])['name']:
                current = junos_record(m[1])
                rows.append(current)
            state = re.fullmatch(r'Physical interface: \S+, (Enabled|Disabled|Administratively down), '
                                 r'Physical link is (Up|Down)', value)
            current.update(dict.fromkeys(JUNOS_STATUS_FIELDS))
            if state:
                current.update(admin_status=JUNOS_ADMIN_STATES[state[1]], oper_status=state[2].lower())
            direction = None
            continue
        if not value or _metadata(value):
            continue
        # Descriptions are arbitrary device text, including counter-like strings.
        if value.startswith('Description:'):
            if current is not None and len(raw) - len(raw.lstrip()) == 2:
                current['description'] = value.partition(':')[2].strip() or None
            continue
        if current is not None and value.startswith('Link-level type:'):
            mtu = re.search(r', MTU: (\d+)(?=,|$)', value)
            speed = re.search(r', Speed: ([^,]+)', value)
            current.update(mtu=int(mtu[1]) if mtu else None, speed=speed[1].strip() if speed else None)
            continue
        if current is None:
            unknown.append({'line': number, 'text': raw})
            continue
        m = re.fullmatch(r'Last flapped\s*:\s*(.+)', value)
        if m:
            current['last_flap'] = m[1]
            continue
        if value in ('Input errors:', 'Output errors:'):
            direction = 'in' if value.startswith('Input') else 'out'
            continue
        # Split at the delimiter, then validate each complete item once. Neither
        # an unanchored label search nor repeated, overlapping groups are needed.
        pairs = ([re.fullmatch(r'([A-Za-z0-9 /-]+):\s*(\d+)', item.strip())
                  for item in value.removesuffix(',').split(',')] if direction else [])
        if pairs and all(pairs):
            for pair in pairs:
                label, count = pair.groups()
                field = {'Errors': 'rx_errors' if direction == 'in' else 'tx_errors',
                         'Drops': 'discards_' + direction, 'Carrier transitions': 'carrier_transitions',
                         'CRC errors': 'crc'}.get(label.strip())
                if field:
                    current[field] = int(count)
            continue
        # Extensive output contains unrelated nested sections. Recognize only
        # known labels/structures, and keep unknown lines visible.
        if re.match(r'(?:Enabled,|Link-level type:|Description:|Interface index:|Link flags\s*:|'
                    r'Current address:|Last cleared\s*:|Statistics last cleared:|'
                    r'Traffic statistics:|Input\s+(?:bytes|packets|rate)\s*:|Output\s+(?:bytes|packets|rate)\s*:|'
                    r'Active alarms\s*:|Active defects\s*:|PCS statistics|Ethernet FEC statistics|'
                    r'MAC statistics:|Filter statistics:|Policer:|Logical interface |Flags:|Encapsulation:|'
                    r'Protocol |Addresses,|Destination:|Local:|Input Filters:|Output Filters:|'
                    r'Device flags\s*:|Interface Specific flags:|Interface flags:|CoS queues\s*:|Hold-times\s*:|'
                    r'Dropped traffic statistics due to STP State:|Autonegotiation information:|'
                    r'Negotiation status:|Packet Forwarding Engine configuration:|Destination slot:|'
                    r'CoS information:|Direction\s*:|CoS transmit queue\s+|%\s+bps\s+%\s+usec|'
                    r'Interface transmit statistics:|Local statistics:|Transit statistics:|CAM destination filters:)', value):
            continue
        crc = re.fullmatch(r'CRC/Align errors\s+(\d+)\s+\d+', value)
        if crc:
            current['crc'] = int(crc[1])
            continue
        if re.fullmatch(r'(?:Bit|FIFO|Total) errors\s+\d+(?:\s+\d+)?', value):
            continue  # MAC/PCS counters are not the interface aggregate.
        if re.fullmatch(r'(?:Errored blocks|Total octets|Total packets|Unicast packets|Broadcast packets|'
                        r'Multicast packets|MAC control frames|MAC pause frames|Oversized frames|Jabber frames|'
                        r'Fragment frames|VLAN tagged frames|Code violations|Input packet count|Input packet rejects|'
                        r'Input DA rejects|Input SA rejects|Output packet count|Output packet pad count|'
                        r'Output packet error count)\s+\d+(?:\s+\d+)?', value):
            continue
        if re.fullmatch(r'\d+ [\w-]+\s+\d+\s+\d+\s+\d+\s+\d+\s+\w+\s+\w+', value):
            continue
        unknown.append({'line': number, 'text': raw})
    return rows, unknown


_IOS_CLEARING = re.compile(r'Last clearing of "show interface" counters (.+)')
_IOS_CLEARING_CLOCK = re.compile(r'([0-9]{1,8}):([0-5][0-9]):([0-5][0-9])')
_IOS_CLEARING_AGE = re.compile(r'(?:[0-9]{1,8}[ywdhms]){1,6}')
_IOS_CLEARING_UNITS = {'y': 31536000, 'w': 604800, 'd': 86400, 'h': 3600, 'm': 60, 's': 1}


def _ios_clearing_value(value):
    return (isinstance(value, str) and (value == 'never' or _IOS_CLEARING_CLOCK.fullmatch(value)
                                       or _IOS_CLEARING_AGE.fullmatch(value)))


def _ios_clearing_age(value):
    """Age and display resolution of an IOS last-clearing duration."""
    if clock := _IOS_CLEARING_CLOCK.fullmatch(value):
        hours, minutes, seconds = map(int, clock.groups())
        return hours * 3600 + minutes * 60 + seconds, 1
    parts = [(int(count), _IOS_CLEARING_UNITS[unit])
             for count, unit in re.findall(r'([0-9]+)([ywdhms])', value)]
    return sum(count * unit for count, unit in parts), parts[-1][1]


def _ios_clearing_changed(before, after, interval):
    if before is None or after is None or interval is None or interval <= 0:
        return False
    if 'never' in (before, after):
        return before != after
    old_age, old_resolution = _ios_clearing_age(before)
    new_age, new_resolution = _ios_clearing_age(after)
    # The displayed durations are rounded down. Compare the possible clearing times
    # and allow one second for capture timing on opposite sides of a CLI refresh.
    shift = interval + old_age - new_age
    return shift > new_resolution + 1 or shift < -old_resolution - 1


def ios_details(text, *, xe=False):
    """Whole `show interfaces`; resets and Last input/output are not flap evidence."""
    rows, unknown, current = [], [], None
    operational = False
    metadata = (
        r'Hardware is .+', r'Description:.*', r'Internet address is \S+',
        r'MTU \d+ bytes, BW \d+ Kbit/sec, DLY \d+ usec,',
        r'reliability \d+/\d+, txload \d+/\d+, rxload \d+/\d+',
        r'Encapsulation .+', r'Keepalive (?:set \(.+\)|not supported)',
        r'(?:Auto|Full|Half)[ -]Duplex, .*', r'(?:Full|Half)-duplex, .*',
        r'(?:output flow-control is \w+, input flow-control is \w+|input flow-control is \w+, output flow-control is \w+)',
        r'ARP type: .+', r'Last input .+, output .+, output hang .+',
        r'Queueing strategy: .+',
        r'Output queue: \d+/\d+(?:/\d+/\d+)? \(size/max(?: total/threshold/drops)?\)',
        r'\d+ minute (?:input|output) rate \d+ bits/sec, \d+ packets/sec',
        r'\d+ packets (?:input|output), \d+ bytes(?:, \d+ (?:no buffer|underruns))?',
        r'(?:Received|Output) \d+ broadcasts \(\d+ (?:IP )?multicasts\)',
        r'\d+ runts, \d+ giants, \d+ throttles',
        r'\d+ watchdog, \d+ multicast, \d+ pause input',
        r'\d+ input packets with dribble condition detected', r'\d+ unknown protocol drops',
        r'\d+ babbles, \d+ late collision, \d+ deferred',
        r'\d+ lost carrier, \d+ no carrier(?:, \d+ pause output)?',
        r'\d+ output buffer failures, \d+ output buffers swapped out',
        r'Restart-Delay is \d+ secs', r'Conversations\s+\d+/\d+/\d+ \(active/max active/max total\)',
        r'Reserved Conversations \d+/\d+ \(allocated/max allocated\)',
        r'Available Bandwidth \d+ kilobits/sec',
    )
    for number, raw in enumerate(text.splitlines(), 1):
        value = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', raw).strip()
        if not value or _metadata(value):
            continue
        match = re.fullmatch(r'(\S+) is (up|down|administratively down|reset), line protocol is (?:up|down)(?: \([\w -]+\))?', value)
        if match:
            current = record(match[1])
            operational = match[2] == 'up'
            rows.append(current)
            if xe:
                current.update(dict.fromkeys(TRAFFIC_FIELDS))
            continue
        if current is not None:
            if clearing := _IOS_CLEARING.fullmatch(value):
                if _ios_clearing_value(clearing[1]):
                    current['last_counter_clear'] = clearing[1]
                continue
            if xe:
                packets = re.fullmatch(r'\d+ packets (input|output), (\d+) bytes(?:, \d+ (?:no buffer|underruns))?', value)
                if packets:
                    current['rx_octets' if packets[1] == 'input' else 'tx_octets'] = int(packets[2])
                    continue
                speed = re.fullmatch(r'(?:Full|Half)-duplex, (\d+(?:\.\d+)?)\s*(Mb/s|Gb/s)(?:, .*)?', value)
                if speed and operational:
                    current['link_speed_bps'] = int(float(speed[1]) * (1_000_000 if speed[2] == 'Mb/s' else 1_000_000_000))
                    continue
            match = re.fullmatch(r'(\d+) input errors, (\d+) CRC(?:, \d+ (?:frame|overrun|ignored|abort))*', value)
            if match:
                current.update(rx_errors=int(match[1]), crc=int(match[2]))
                continue
            match = re.fullmatch(r'(\d+) output errors(?:, \d+ collisions)?, \d+ interface resets', value)
            if match:
                current['tx_errors'] = int(match[1])
                continue
            match = re.fullmatch(r'Input queue: \d+/\d+/(\d+)/\d+ \(size/max/drops/flushes\)(?:; Total output drops: (\d+))?', value)
            if match:
                current['discards_in'] = int(match[1])
                if match[2] is not None:
                    current['discards_out'] = int(match[2])
                continue
            match = re.fullmatch(r'(\d+) carrier transitions\s+DCD=\w+\s+DSR=\w+\s+DTR=\w+\s+RTS=\w+\s+CTS=\w+', value)
            if match:
                current['carrier_transitions'] = int(match[1])
                continue
            if any(re.fullmatch(pattern, value) for pattern in metadata):
                continue
        unknown.append({'line': number, 'text': raw})
    return rows, unknown


def nxos_details(text):
    """Read the cumulative counters and operational speed of one Ethernet port."""
    header = re.findall(r'(?m)^(Ethernet[0-9/]+) is (up|down)(?:[ \t]+[^\n]*)?[ \t]*$', text)
    if len(header) != 1:
        return [], [{'line': 1, 'text': 'missing or ambiguous NX-OS interface header'}]
    name, state = header[0]
    row = record(name)
    row.update(dict.fromkeys(TRAFFIC_FIELDS))
    patterns = {
        'rx_octets': r'[0-9]+ input packets[ \t]+([0-9]+) bytes',
        'tx_octets': r'[0-9]+ output packets[ \t]+([0-9]+) bytes',
        'rx_errors': r'([0-9]+) input errors?[ \t]+[0-9]+ short frame',
        'tx_errors': r'([0-9]+) output errors?[ \t]+[0-9]+ collision',
        'crc': r'[0-9]+ runts[ \t]+[0-9]+ giants[ \t]+([0-9]+) CRC',
        'discards_in': r'[0-9]+ input with dribble[ \t]+([0-9]+) input discard',
        'discards_out': r'[0-9]+ lost carrier[ \t]+[0-9]+ no carrier[ \t]+[0-9]+ babble[ \t]+([0-9]+) output discard',
    }
    unknown = []
    for field, pattern in patterns.items():
        hits = re.findall(r'(?m)^[ \t]+' + pattern + r'(?:[ \t].*)?$', text)
        if len(hits) == 1:
            row[field] = int(hits[0])
        else:
            unknown.append({'line': 1, 'text': 'missing or ambiguous NX-OS counter: ' + field})
    speeds = re.findall(r'(?m)^[ \t]+(?:full|half)-duplex, ([0-9]+) (Mb|Gb)/s(?:,.*)?[ \t]*$', text)
    if state == 'up' and len(speeds) == 1:
        value, scale = speeds[0]
        row['link_speed_bps'] = int(value) * (1_000_000 if scale == 'Mb' else 1_000_000_000)
    flaps = re.findall(r'(?m)^[ \t]+Last link flapped[ \t]+([^\r\n]*\S)[ \t]*$', text)
    if len(flaps) == 1:
        row['last_flap'] = flaps[0]
    return [row], unknown


def parse(profile, text, command=None):
    # Whole `show interfaces` or the bounded `show interfaces <if>` (G53); not `... counters errors`.
    if profile in ('cisco_ios', 'cisco_xe') and command and re.fullmatch(r'show interfaces(?: \S+)?', command):
        return ios_details(text, xe=profile == 'cisco_xe' and command != 'show interfaces')
    if profile == 'cisco_nxos' and command and re.fullmatch(r'show interface Ethernet[0-9/]+', command):
        return nxos_details(text)
    if profile == 'extreme_exos':
        return exos(text)
    if profile.startswith('juniper_'):
        match = re.match(r'show interfaces (\S+) extensive', command or '')
        return junos(text, match[1] if match else None)
    return tabular(profile, text)


def register(fields, optional, bindings, parsers):
    fields['interface_errors'] = FIELDS
    optional['interface_errors'] = set(FIELDS) - {'port'}
    parsers['interface_errors'] = parse
    for profile in PROFILES:
        # Catalogue registration has no caller-supplied selector to validate.
        query = 'interface_details' if profile.startswith('juniper_') else request(profile, None)[0]
        bindings[profile]['interface_errors'] = query


def _merge(results):
    """Preserve failed/partial sources, never turn a partial join into healthy data."""
    result = dict(results[0])
    rows = {}
    for item in results:
        for row in item['records']:
            merged = rows.setdefault(row['port'], dict(row))
            merged.update({k: v for k, v in row.items() if v is not None})
    result['records'] = list(rows.values())
    result['sources'] = [source for item in results for source in item['sources']]
    result['unparsed'] = [line | {'query': item['sources'][0]['query'] if item['sources'] else None}
                          for item in results for line in item['unparsed']]
    result['warnings'] = list(dict.fromkeys(w for item in results for w in item['warnings']))
    failures = [item for item in results if item['status'] not in ('ok', 'empty')]
    result['status'] = failures[0]['status'] if failures else 'ok' if rows else 'empty'
    # The reported status and its cause come from the same (first failed) source.
    for key in ('error_code', 'error'):
        result.pop(key, None)
        if failures and key in failures[0]:
            result[key] = failures[0][key]
    result['ok'] = result['status'] in ('ok', 'empty')
    result['coverage'] = {'complete': all(item['coverage']['complete'] for item in results),
                          'parsed_records': len(rows), 'unparsed_lines': len(result['unparsed']),
                          'missing_fields': sorted(set(f for item in results for f in item['coverage']['missing_fields']))}
    return result


def finalize(result):
    """No ports means no counter evidence, even after a local port filter."""
    if not result['records']:
        result['ok'] = False
        result['coverage']['complete'] = False
        if result['status'] in ('ok', 'empty'):
            result['status'] = 'empty'
            if 'no_counter_records' not in result['warnings']:
                result['warnings'].append('no_counter_records')
    elif result['status'] == 'ok' and not any(
            row[field] is not None for row in result['records'] for field in FIELDS[1:]):
        result['status'] = 'unparsed'
        result['ok'] = result['coverage']['complete'] = False
        result['warnings'].append('counter_values_absent')
    if (result.get('profile') in ('juniper_junos', 'juniper_junos_els') and result['records']
            and any(row['rx_errors'] is None or row['tx_errors'] is None for row in result['records'])):
        result['coverage']['complete'] = False
    if result.get('profile') == 'cisco_xe' and any(
            'rx_octets' in row and any(row.get(field) is None for field in ('rx_octets', 'tx_octets', 'rx_errors', 'tx_errors'))
            for row in result['records']):
        result['coverage']['complete'] = False
        if 'interface_sample_incomplete' not in result['warnings']:
            result['warnings'].append('interface_sample_incomplete')
    return result


def read(auth, interface, query_read):
    from . import tables
    profile = auth.ssh_platform
    query, parameters, filters = request(profile, interface)

    def fetch(name, params=None):
        if name not in auth.enabled_queries:
            return tables.parse(profile, 'interface_errors', name, '', status='permission_denied')
        return query_read(auth, profile, name, 'interface_errors', params)

    if query is None:
        return tables.parse(profile, 'interface_errors', None, '', status='unsupported')
    primary, fallback_query, fallback_parameters = query, 'interfaces_details', {}
    bounded = {}
    if profile == 'cisco_nxos' and interface is not None:
        scope = nxos_detail_scope(interface, auth.enabled_queries, auth.read_inventory)
        if scope is not None:
            primary, parameters = 'interface_details', scope
    if profile == 'cisco_xe' and interface is not None:
        bounded = bounded_queries(profile, interface, auth.enabled_queries, auth.read_inventory)
        if bounded:
            if 'interface_details' in bounded:
                primary, parameters = 'interface_details', bounded['interface_details']
                fallback_query, fallback_parameters = 'interface_errors', bounded.get('interface_errors', {})
            else:
                primary, parameters = 'interface_errors', bounded['interface_errors']
                fallback_query = 'interface_details'
    if profile == 'cisco_ios' and interface is not None:
        # G53 (IOS only, verified on IOSvL2): an enrolled port with a slot query enabled is read only with its per-port
        # queries (`show interfaces <if> counters errors`, then `show interfaces <if>`), exactly the set the proxy
        # authorizes for it (proxy.py, bounded_queries); a missing one is skipped, never replaced by a whole-switch read.
        # Without any usable per-port query the whole tables stay the source.
        bounded = bounded_queries(profile, interface, auth.enabled_queries, auth.read_inventory)
        if bounded:
            primary, parameters = 'interface_errors', bounded.get('interface_errors', {})
            fallback_query, fallback_parameters = 'interface_details', bounded.get('interface_details', {})
    if bounded and primary not in bounded:
        result = tables.parse(profile, 'interface_errors', primary, '', status='permission_denied')
    else:
        result = fetch(primary, parameters)
    if bounded and fallback_query not in bounded and result['status'] in ('unsupported', 'permission_denied', 'empty'):
        result['warnings'].append('one_port_details_query_not_enabled')
        result['hint'] = ('interface_details is not enabled for this port; the whole-switch `show interfaces` '
                          'is not read for a one-port request, so the counters are incomplete')
    elif profile in ('cisco_ios', 'cisco_xe') and result['status'] in ('unsupported', 'permission_denied', 'empty'):
        fallback = fetch(fallback_query, fallback_parameters)
        if fallback['status'] in ('ok', 'empty', 'unparsed'):
            fallback['sources'] = result['sources'] + fallback['sources']
            fallback['warnings'].append('counters_unavailable_used_interfaces_details'
                                        if fallback_query != 'interface_errors' else 'details_unavailable_used_interface_errors')
            result = fallback
        else:
            result = _merge([result, fallback])
    elif profile == 'extreme_exos' and result['status'] in ('ok', 'empty', 'unparsed'):
        result = _merge([result, fetch('ports_tx_errors')])
    elif profile == 'arista_eos' and result['status'] in ('ok', 'empty', 'unparsed'):
        if 'interfaces_counters_discards' in auth.enabled_queries:
            result = _merge([result, fetch('interfaces_counters_discards')])
        else:
            result['warnings'].append('discards_query_not_enabled')
    if profile == 'cisco_xe' and bounded and any(row['port'] != filters['port'] for row in result['records']):
        result.update(status='unparsed', ok=False)
        result['coverage']['complete'] = False
        result['warnings'].append('answer_for_another_interface')
    result['records'] = [row for row in result['records'] if all(row.get(k) == v for k, v in filters.items())]
    return finalize(result)


def nxos_detail_scope(interface, enabled_queries, inventory):
    if 'interface_details' not in enabled_queries:
        return None
    kind = READ_QUERIES['cisco_nxos']['interface_errors'].slots['interface'].kind
    port = _validate_slot(normalize_port(interface)['name'], kind)
    listed = inventory.get('interfaces', ())
    if '.' not in port and port in listed:
        return {'interface': port}
    return None


def bounded_queries(profile, interface, enabled_queries, inventory):
    """IOS/IOS XE per-port slot queries usable for an enrolled interface, with their parameters."""
    listed = set((inventory or {}).get('interfaces', ()))
    found = {}
    for name in ('interface_errors', 'interface_details'):
        if name not in enabled_queries:
            continue
        try:
            value = _validate_slot(interface, READ_QUERIES[profile][name].slots['interface'].kind)
        except (ValueError, TypeError):
            continue
        kind = READ_QUERIES[profile][name].slots['interface'].kind
        enrolled = [item for item in (interface, value) if enrolled_interface(item, kind, listed)]
        if enrolled:
            found[name] = {'interface': enrolled[0]}
    return found


def read_cost(profile, interface, enabled_queries):
    return 1 + (profile == 'extreme_exos' or
                profile == 'arista_eos' and 'interfaces_counters_discards' in enabled_queries or
                profile in ('cisco_ios', 'cisco_xe'))


def output_state(profile, query, text, state, rc):
    # IOS hides commands behind syntax errors too. For this optional switch
    # counter table report unsupported; the fallback is separately authorized.
    if (profile in ('cisco_ios', 'cisco_xe') and query in ('interfaces_counters_errors', 'interface_errors')
            and state == 'permission_denied' and rc in (0, None)):
        from .normalization import output_status
        if output_status(text) == 'unsupported':
            return 'unsupported'
    return state


# Counter deltas and short output modes (1.0.12 X-08). The Helper keeps no state
# between calls: an `ok` result carries `counter_baseline`, an opaque token with its
# own capture time and counters; a later call of the same target and port selection
# passes it back as `baseline`. The token is compressed, base64url text that the
# engine builds from already redacted, parsed integers and port names.
COUNTERS = ('rx_errors', 'crc', 'tx_errors', 'discards_in', 'discards_out', 'link_flaps', 'carrier_transitions')
TRAFFIC_FIELDS = ('rx_octets', 'tx_octets', 'link_speed_bps')
SUMMARY_MODES = ('counts', 'changes')
BASELINE_PREFIX = 'nb1.'
BASELINE_MAX_CHARS = 32_000
from .page_metadata import BASELINE_PATTERN  # noqa: E402  one pattern for engine and proxy
_BASELINE_MAX_JSON = 1_000_000


def _key(alias, profile, interface, managed_switch=None):
    import hashlib
    import json
    return hashlib.sha256(json.dumps([alias, profile, interface, managed_switch]).encode()).hexdigest()[:24]


def _epoch(captured_at):
    from datetime import datetime
    return datetime.fromisoformat(captured_at).timestamp()


def encode_baseline(key, captured_at, records):
    """Opaque token of one complete read, or None when it would exceed BASELINE_MAX_CHARS."""
    import base64
    import json
    import zlib
    document = {'v': 1, 'k': key, 't': round(_epoch(captured_at), 3),
                'r': {row['port']: [row.get(field) for field in COUNTERS + (
                    TRAFFIC_FIELDS if 'rx_octets' in row else ())] for row in records}}
    clearing = {row['port']: row['last_counter_clear'] for row in records if 'last_counter_clear' in row}
    if clearing:
        document['c'] = clearing
    raw = zlib.compress(json.dumps(document, separators=(',', ':'), sort_keys=True).encode(), 9)
    token = BASELINE_PREFIX + base64.urlsafe_b64encode(raw).decode().rstrip('=')
    return token if len(token) <= BASELINE_MAX_CHARS else None


def decode_baseline(token, key):
    """Validated baseline of this target and selection; ValueError before any device read."""
    import base64
    import json
    import math
    import zlib
    if not isinstance(token, str) or not re.fullmatch(BASELINE_PATTERN, token):
        raise ValueError('baseline must be the counter_baseline of an earlier interface_errors result')
    body = token[len(BASELINE_PREFIX):]
    try:
        raw = base64.urlsafe_b64decode(body + '=' * (-len(body) % 4))
        inflater = zlib.decompressobj()
        text = inflater.decompress(raw, _BASELINE_MAX_JSON)
        if inflater.unconsumed_tail or not inflater.eof:
            raise ValueError
        document = json.loads(text)
    except (ValueError, zlib.error, RecursionError):
        raise ValueError('baseline must be the counter_baseline of an earlier interface_errors result') from None
    rows = document.get('r') if isinstance(document, dict) else None
    clearing = document.get('c', {}) if isinstance(document, dict) else None
    if (not isinstance(document, dict) or set(document) - {'c'} != {'v', 'k', 't', 'r'} or document['v'] != 1
            or not isinstance(document['k'], str) or type(document['t']) not in (int, float)
            or not math.isfinite(document['t']) or not isinstance(rows, dict)
            or not isinstance(clearing, dict)
            or not all(port in rows and _ios_clearing_value(value) for port, value in clearing.items())
            or not all(isinstance(port, str) and isinstance(values, list) and len(values) in (len(COUNTERS), len(COUNTERS + TRAFFIC_FIELDS))
                       and all(value is None or type(value) is int and value >= 0 for value in values)
                       for port, values in rows.items())):
        raise ValueError('baseline must be the counter_baseline of an earlier interface_errors result')
    if document['k'] != key:
        raise ValueError('baseline belongs to another target, platform, interface selection or managed_switch; '
                         'pass the counter_baseline of the same switch_read')
    decoded = {port: dict(zip(COUNTERS + TRAFFIC_FIELDS, values)) for port, values in rows.items()}
    for port, value in clearing.items():
        decoded[port]['last_counter_clear'] = value
    return document['t'], decoded


def _nonzero(row):
    return [field for field in COUNTERS if isinstance(row.get(field), int) and row[field] > 0]


def _nxos_flap_in_interval(age, interval):
    """One observed flap is possible evidence; NX-OS supplies no cumulative flap count."""
    if interval is None or interval <= 0 or age is None:
        return None
    if age.lower() == 'never':
        return False
    from .ios_ports import _seconds
    weeks = re.fullmatch(r'([0-9]{1,6})week\(s\)[ \t]+([0-9]{1,6})day\(s\)', age)
    if weeks:  # NX-OS ages over a week, e.g. `1week(s) 0day(s)`, have a resolution of one day
        seconds, resolution = (int(weeks[1]) * 7 + int(weeks[2])) * 86400, 86400
    else:
        seconds = _seconds(age)
        if seconds is None:
            return None
        resolution = 1 if ':' in age else 3600 if age.endswith('h') else 86400 if age.endswith('d') else 604800
    if seconds >= interval:
        return False
    return True if seconds + resolution <= interval else None


def shape(result, key, baseline=None, summary=None):
    """Add counter_baseline, a summary and, with a baseline, per-port deltas; then apply the mode.

    Runs on the complete, filtered read before paging. `counts` drops record and
    unparsed lists (coverage keeps their counts); `changes` keeps only ports whose
    counters increased or went down (reset_or_wrap), new ports, or without a
    baseline ports with any nonzero counter. Statuses and coverage never change.
    """
    from datetime import datetime, timezone
    from .normalization import counter_delta
    if summary is not None and summary not in SUMMARY_MODES:
        raise ValueError('summary is counts or changes')
    records = result.get('records', [])
    # Only a complete read issues a baseline or proves a port vanished: a status of `ok`
    # can still join an empty source (EXOS RX rows, empty TX answer) with incomplete coverage.
    complete = (result.get('status') == 'ok' and bool(records)
                and (result.get('coverage') or {}).get('complete') is True)
    result['counter_baseline'] = (encode_baseline(key, result['captured_at'], records)
                                  if complete and result.get('captured_at') else None)
    if complete and result['counter_baseline'] is None:
        result['warnings'].append('counter_baseline_too_large')
    nonzero = {field: sum(1 for row in records if field in _nonzero(row)) for field in COUNTERS}
    report = {'mode': summary or 'full', 'ports': len(records),
              'ports_with_nonzero_counters': sum(1 for row in records if _nonzero(row)),
              'nonzero_ports_by_counter': nonzero,
              # Ports with a value per counter: 0 nonzero ports of 0 measured means "not measured".
              'measured_ports_by_counter': {field: sum(1 for row in records if type(row.get(field)) is int)
                                            for field in COUNTERS}}
    changed = []
    if baseline is not None:
        started, previous = baseline
        captured = result.get('captured_at')
        interval = _epoch(captured) - started if captured else None
        increased = dict.fromkeys(COUNTERS, 0)
        comparable = dict.fromkeys(COUNTERS, 0)
        resets = new = 0
        for row in records:
            before = previous.get(row['port'])
            if before is None:
                row['delta'], row['counter_reset_or_wrap'] = None, []
                new += 1
                changed.append(row)
                continue
            clearing_changed = _ios_clearing_changed(before.get('last_counter_clear'),
                                                     row.get('last_counter_clear'), interval)
            if clearing_changed:
                row['counter_status'] = 'counters_reset'
            delta, reset = {}, []
            for field in COUNTERS:
                delta[field], state = counter_delta(before[field], row.get(field))
                if clearing_changed and state != 'absent':
                    delta[field], state = None, 'reset_or_wrap'
                if state == 'ok':
                    comparable[field] += 1
                if state == 'reset_or_wrap':
                    reset.append(field)
                elif delta[field]:
                    increased[field] += 1
            row['delta'], row['counter_reset_or_wrap'] = delta, reset
            resets += bool(reset or clearing_changed)
            if reset or clearing_changed or any(delta.values()):
                changed.append(row)
        if result.get('profile') in ('juniper_junos', 'juniper_junos_els', 'cisco_nxos', 'cisco_xe'):
            for row in records:
                delta = row['delta'] or {}
                row['errors_per_minute'] = {
                    field: round(delta[field] * 60 / interval, 3) if interval and interval > 0
                    and delta.get(field) is not None else None
                    for field in ('rx_errors', 'tx_errors', 'crc')
                }
        for row in records:
            if 'rx_octets' not in row or (result.get('profile') == 'cisco_xe' and not complete):
                continue
            before = previous.get(row['port'], {})
            speed = row['link_speed_bps']
            stable_speed = speed if speed and speed == before.get('link_speed_bps') else None
            sample = {'interval_seconds': round(interval, 3) if interval is not None else None,
                      'flap_observed_since_baseline': _nxos_flap_in_interval(row['last_flap'], interval)}
            clearing_changed = row.get('counter_status') == 'counters_reset'
            if clearing_changed:
                sample['status'] = 'counters_reset'
            for direction in ('rx', 'tx'):
                field = direction + '_octets'
                delta, status = counter_delta(before.get(field), row[field])
                if clearing_changed and status != 'absent':
                    delta, status = None, 'reset_or_wrap'
                if delta is not None and delta > 0 and row not in changed:
                    changed.append(row)
                if status == 'reset_or_wrap':
                    if row not in changed:
                        changed.append(row)
                    row['counter_reset_or_wrap'].append(field)
                rate = delta * 8 / interval if delta is not None and interval and interval > 0 else None
                sample[direction] = {'octets_delta': delta, 'bits_per_second': round(rate, 3) if rate is not None else None,
                                     'utilization_percent': round(rate * 100 / stable_speed, 6)
                                     if rate is not None and stable_speed else None}
            if sample['flap_observed_since_baseline'] is True and row not in changed:
                changed.append(row)
            row['interval_traffic'] = sample
        current = {row['port'] for row in records}
        report['baseline'] = {
            'captured_at': datetime.fromtimestamp(started, timezone.utc).isoformat(),
            'interval_seconds': round(interval, 1) if interval is not None else None,
            'ports_compared': len(records) - new,
            'ports_increased': sum(1 for row in records if row['delta'] and any(row['delta'].values())),
            'increased_ports_by_counter': increased,
            # Ports with a computed delta per counter; absent values and reset_or_wrap are not comparable.
            'compared_ports_by_counter': comparable,
            'ports_reset_or_wrap': resets,
            'new_ports': [row['port'] for row in records if row['delta'] is None],
            # Only a complete read can show that a port disappeared.
            'missing_ports': sorted(set(previous) - current) if complete else None,
        }
    else:
        changed = [row for row in records if _nonzero(row)]
    if summary == 'changes':
        result['records'] = changed
    elif summary == 'counts':
        result['records'], result['unparsed'] = [], []
    report['ports_listed'] = len(result['records'])
    result['summary'] = report
    return result
