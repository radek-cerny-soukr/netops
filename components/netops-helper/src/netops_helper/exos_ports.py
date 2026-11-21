"""EXOS port operational tables; only measured formats become records.

STP domain selection is available through stp_domain_ports/stp_port_detail;
the normalized stp_port table retains the compatible s0 default.
"""
from __future__ import annotations

import re

from . import optics

FIELDS = {
    'poe_budget': ('state', 'budget_w', 'power_w'),
    'poe_port': ('port', 'state', 'class', 'voltage', 'current_ma', 'power_w', 'fault'),
    'optics_port': ('port', 'state', 'temperature_c', 'tx_dbm', 'rx_dbm', 'voltage', 'tx_bias_ma', 'alerts'),
    'port_utilization': ('port', 'oper_status', 'speed_mbps', 'rx_percent', 'peak_rx_percent', 'tx_percent', 'peak_tx_percent'),
    'port_packets': ('port', 'oper_status', 'rx_pps', 'peak_rx_pps', 'tx_pps', 'peak_tx_pps'),
    'lacp_member': ('port', 'priority', 'rx_state', 'selection', 'mux_state', 'actor_flags', 'partner_port', 'actor_key', 'partner_key'),
}
BINDINGS = {'poe_budget': 'inline_power', 'poe_port': 'inline_power_port', 'optics_port': 'interface_transceiver',
            'port_utilization': 'port_utilization', 'port_packets': 'port_packets', 'lacp_member': 'lacp_member'}


def not_applicable(table, text, command):
    """Only whole, observed negative answers for the selected port query."""
    if table == 'lacp_member':
        return bool(command and re.fullmatch(r'show lacp member-port \d+(?::\d+)? detail', command)
                    and text.strip() == 'Error: LACP member-port does not exist')
    if table == 'poe_port' and command:
        match = re.fullmatch(r'show inline-power info ports (\d+(?::\d+)?)', command)
        return bool(match and text.strip() == f'Port {match[1]} is not inline-power capable')
    return False


def parse(table, text):
    from . import tables as t
    if table == 'poe_budget':
        m = re.search(r'(?m)^(Operational|Not Operational)\s+(\d+(?:\.\d+)?) W\s+(?:(\d+(?:\.\d+)?) W|n/a)\s*$', text)
        if not m:
            return [], [{'line': 1, 'text': 'unrecognized power budget'}]
        def budget_line(raw, value):
            if (value.startswith(('Inline Power System Information', 'Configured ', 'Power Usage Threshold ',
                                  'Disconnect Precedence ', 'Inline Power budget ', 'Firmware Status '))
                    or re.fullmatch(r'Budgeted\s+Measured|Power \(Watts\)\s+Power \(Watts\)|(?:Operational|Not Operational)\s+\d+(?:\.\d+)? W\s+(?:\d+(?:\.\d+)? W|n/a)', value)):
                return []
            return None
        _, unknown = t.scan(text, budget_line)
        return [t.record(table, state=m[1], budget_w=float(m[2]), power_w=float(m[3]) if m[3] else None)], unknown
    # The DOM parser already validates port identity, metric blocks and thresholds.
    if table == 'optics_port':
        ports = re.findall(r'(?m)^Port\s*:\s*(\S+)\s*$', text)
        if len(ports) != 1:
            return [], [{'line': 1, 'text': 'missing or ambiguous DOM port'}]
        result = optics.transceiver(text, ports[0])
        if result['state'] not in ('measured', 'partial', 'not_present', 'unsupported'):
            return [], [{'line': 1, 'text': 'unrecognized DOM output'}]
        names = {'temperature_c': 'temperature', 'tx_dbm': 'tx_power', 'rx_dbm': 'rx_power',
                 'voltage': 'voltage', 'tx_bias_ma': 'tx_bias_current'}
        row = t.record(table, port=ports[0], state=result['state'], alerts=[{'metric': key, 'status': value['status']} for key, value in result['readings'].items() if value['status'] not in (None, 'Normal')], **{
            key: result['readings'].get(metric, {}).get('value') for key, metric in names.items()})
        unknown = [{'line': 1, 'text': 'missing DOM field: ' + f} for f in result['missing_fields']]
        return [row], unknown
    if table == 'interface':
        columns = []
        def handle(raw, value):
            if re.fullmatch(r'Port\s+Display String\s+Description String', value):
                columns[:] = [raw.index('Display String'), raw.index('Description String')]
                return []
            if columns and re.fullmatch(r'\d+(?::\d+)?', raw[:columns[0]].strip()):
                display = raw[columns[0]:columns[1]].strip()
                description = raw[columns[1]:].strip()
                return t.record(table, name=raw[:columns[0]].strip(), description=description or display or None)
            return None
        return t.scan(text, handle)
    if table == 'stp_port':
        def handle(raw, value):
            m = re.fullmatch(r'(\d+(?::\d+)?)\s+(\S+)\s+(FORWARDING|DISABLED|BLOCKING|LISTENING|LEARNING)\s+(\d+)\s+(\S{10})\s+\d+\s+[\da-fA-F]+\s+[\da-fA-F:]+', value)
            if m:
                role = {'R': 'root', 'D': 'designated', 'A': 'alternate', 'B': 'backup', 'M': 'master', '?': None}.get(m[5][1])
                return t.record(table, instance='s0', port=m[1], role=role, state=m[3].lower(), cost=int(m[4]))
            if (value.startswith(('Port ', 'Total Ports:', '------------------------- Flags:')) or
                    re.match(r'\d+:\s+', value) or re.match(r'[sg]\s*= ', value)):
                return []
            return None
        return t.scan(text, handle)
    if table == 'lacp_member':
        match = re.search(r'(?m)^(\d+(?::\d+)?)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+([ATGSCD FE-]+?)\s+(\d+)\s*$', text)
        actor = re.search(r'S\.pri:\d+\s*, S\.id:[\da-fA-F:]+, K:(0x[\da-fA-F]+)', text)
        partner = re.search(r'T\.pri:\d+\s*, T\.id:[\da-fA-F:]+, L:(0x[\da-fA-F]+)', text)
        if not match:
            return [], [{'line': 1, 'text': text}]
        row = t.record(table, **dict(zip(FIELDS[table][:7], (match[1], int(match[2]), *match.group(3, 4, 5, 6), int(match[7])))),
                       actor_key=actor[1] if actor else None, partner_key=partner[1] if partner else None)
        # These labelled sections are the observed detail format; a truncated body is incomplete.
        missing = [name for name, found in [('actor_key', actor), ('partner_key', partner), ('stats', 'Stats:' in text),
                                               ('actor_flags_legend', 'Actor Flags:' in text)] if not found]
        def lacp_line(raw, value):
            if (value.startswith(('Member ', 'Port ', 'Up ', 'Enabled ', 'Link State ', 'Actor Churn ', 'Partner Churn ',
                                  'Ready_N ', 'Wait pending ', 'Ack pending ', 'LAG Id:', 'S.pri:', 'T.pri:', 'Stats:',
                                  'Rx - ', 'Tx - ', 'Actor Flags:', 'C-Collecting,')) or match[0].strip() == value):
                return []
            return None
        _, unknown = t.scan(text, lacp_line)
        return [row], unknown + [{'line': 1, 'text': 'missing LACP field: ' + key} for key in missing]
    def handle(raw, value):
        if table == 'poe_port':
            m = re.fullmatch(r'(\d+(?::\d+)?)\s+(\S+)\s+(\S+)\s+(\d+\.\d+)\s+(\d+)\s+(\d+\.\d+)\s+(\S+)', value)
            if m:
                return t.record(table, port=m[1], state=m[2], **{'class': None if set(m[3]) == {'-'} else m[3]},
                                voltage=float(m[4]), current_ma=int(m[5]), power_w=float(m[6]), fault=None if m[7] == 'None' else m[7])
            if re.fullmatch(r'Port\s+State\s+Class\s+Volts\s+Curr\s+Power\s+Fault|\(mA\)\s+\(Watts\)', value):
                return []
        if table in ('port_utilization', 'port_packets'):
            count = 5 if table == 'port_utilization' else 4
            m = re.fullmatch(r'(\d+(?::\d+)?)\s+(A|R|NP|L)\s+' + r'\s+'.join([r'(\d+(?:\.\d+)?)'] * count), value)
            if m:
                vals = [float(v) if table == 'port_utilization' else int(v) for v in m.groups()[2:]]
                return t.record(table, **dict(zip(FIELDS[table], [m[1], 'up' if m[2] == 'A' else 'down', *vals])))
            if (re.fullmatch(r'Port\s+Link(?:\s+Link)?\s+Rx\s+Peak Rx\s+Tx\s+Peak Tx|State\s+Speed\s+% bandwidth\s+% bandwidth\s+% bandwidth\s+% bandwidth|State\s+pkts/sec\s+pkts/sec\s+pkts/sec\s+pkts/sec', value)
                    or value.startswith(('> indicates Port Display Name', 'Link State:'))):
                return []
        return None
    rows, unknown = t.scan(re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', text), handle)
    if not rows and not unknown:
        unknown.append({'line': 1, 'text': 'no complete port records'})
    return rows, unknown


def register(t):
    t.FIELDS.update(FIELDS)
    t.QUERY_PARSERS['extreme_exos', 'interface', 'ports_description'] = parse
    t.BINDINGS['extreme_exos'].update(BINDINGS, stp_port='stp_ports')
    for table, query in {**BINDINGS, 'stp_port': 'stp_ports'}.items():
        t.QUERY_PARSERS['extreme_exos', table, query] = parse
    t.PROFILE_OPTIONAL_FIELDS.setdefault('extreme_exos', {}).update({
        'poe_budget': {'power_w'}, 'poe_port': {'class', 'fault'}, 'optics_port': set(FIELDS['optics_port']) - {'port', 'state'},
        'stp_port': {'role'},
        'lldp_neighbor': {'neighbor', 'management_ip', 'capabilities'},
    })
