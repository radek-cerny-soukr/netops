"""Read-only port counters and flap evidence above the existing catalogue.

Counters are cumulative since the device last cleared them; absent totals stay
None. In particular EXOS categories overlap and must never be summed into a total.
"""
from __future__ import annotations

import re

from .normalization import normalize_port
from .query_catalog import READ_QUERIES
from .read_policy import _validate_slot

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
    current = record(interface) if interface else None
    rows, unknown, direction = ([current] if current else []), [], None
    for number, raw in enumerate(text.splitlines(), 1):
        value = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', raw).strip()
        m = re.match(r'Physical interface: (\S+),', value)
        if m:
            if current and current['port'] == normalize_port(m[1])['name']:
                pass
            else:
                current = record(m[1])
                rows.append(current)
            direction = None
            continue
        if not value or _metadata(value):
            continue
        # Descriptions are arbitrary device text, including counter-like strings.
        if value.startswith('Description:'):
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
                    r'Interface transmit statistics:|Local statistics:|Transit statistics:)', value):
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


def ios_details(text):
    """Whole `show interfaces`; resets and Last input/output are not flap evidence."""
    rows, unknown, current = [], [], None
    metadata = (
        r'Hardware is .+', r'Description:.*', r'Internet address is \S+',
        r'MTU \d+ bytes, BW \d+ Kbit/sec, DLY \d+ usec,',
        r'reliability \d+/\d+, txload \d+/\d+, rxload \d+/\d+',
        r'Encapsulation .+', r'Keepalive (?:set \(.+\)|not supported)',
        r'(?:Auto|Full|Half)[ -]Duplex, .*', r'(?:Full|Half)-duplex, .*',
        r'output flow-control is \w+, input flow-control is \w+',
        r'ARP type: .+', r'Last input .+, output .+, output hang .+',
        r'Last clearing of "show interface" counters .+', r'Queueing strategy: .+',
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
        match = re.fullmatch(r'(\S+) is (?:up|down|administratively down|reset), line protocol is (?:up|down)(?: \([\w -]+\))?', value)
        if match:
            current = record(match[1])
            rows.append(current)
            continue
        if current is not None:
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


def parse(profile, text, command=None):
    if profile in ('cisco_ios', 'cisco_xe') and command == 'show interfaces':
        return ios_details(text)
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
    failures = [item['status'] for item in results if item['status'] not in ('ok', 'empty')]
    result['status'] = failures[0] if failures else 'ok' if rows else 'empty'
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
    result = fetch(query, parameters)
    if profile in ('cisco_ios', 'cisco_xe') and result['status'] in ('unsupported', 'permission_denied', 'empty'):
        fallback = fetch('interfaces_details')
        if fallback['status'] in ('ok', 'empty', 'unparsed'):
            fallback['sources'] = result['sources'] + fallback['sources']
            fallback['warnings'].append('counters_unavailable_used_interfaces_details')
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
    result['records'] = [row for row in result['records'] if all(row.get(k) == v for k, v in filters.items())]
    return finalize(result)


def read_cost(profile, interface, enabled_queries):
    return 1 + (profile == 'extreme_exos' or
                profile == 'arista_eos' and 'interfaces_counters_discards' in enabled_queries or
                profile in ('cisco_ios', 'cisco_xe'))


def output_state(profile, query, text, state, rc):
    # IOS hides commands behind syntax errors too. For this optional switch
    # counter table report unsupported; the fallback is separately authorized.
    if (profile in ('cisco_ios', 'cisco_xe') and query == 'interfaces_counters_errors'
            and state == 'permission_denied' and rc in (0, None)):
        from .normalization import output_status
        if output_status(text) == 'unsupported':
            return 'unsupported'
    return state
