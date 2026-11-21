"""Normalized PoE data from the Junos EX operational tables."""
from __future__ import annotations

import re

from .optics import _number

_WATTS = r'([0-9]+(?:\.[0-9]+)?)\s*W'
_PORT_HEADER = r'Interface\s+Admin\s+Oper\s+Max\s+Priority\s+Power\s+Class'
_PORT_ROW = re.compile(r'([a-z]+-\d+/\d+/\d+)\s+(Enabled|Disabled)\s+(\S+)\s+'
                       + _WATTS + r'\s+(\S+)\s+' + _WATTS + r'\s+(\d+|-)')
_CONTROLLER_HEADER = r'Controller\s+Maximum\s+Power(?:\s+Power)?\s+Guard\s+Management\s+Status\s+Lldp'
_CONTROLLER_ROW = re.compile(r'(\d+)(?:\*\*)?\s+' + _WATTS + r'\s+(?:' + _WATTS
                             + r'\s+)?' + _WATTS + r'\s+' + _WATTS + r'\s+(\S+)\s+(.+?)\s+(\S+)')


def parse(query, text, capture_state):
    ports = query == 'poe_interfaces'
    header = _PORT_HEADER if ports else _CONTROLLER_HEADER
    continuation = (r'status\s+status\s+power\s+consumption' if ports
                    else r'index\s+power\s+(?:reserved\s+)?consumption\s+band\s+Priority')
    seen_header = False
    rows, unparsed = [], []
    if capture_state != 'ok':
        return {'state': capture_state, 'records': rows, 'unparsed_lines': unparsed}
    for number, line in enumerate(text.splitlines(), 1):
        value = line.strip()
        if re.fullmatch(header, value):
            seen_header = True
            continue
        if not value or re.fullmatch(continuation, value):
            continue
        match = (_PORT_ROW if ports else _CONTROLLER_ROW).fullmatch(value) if seen_header else None
        if match is None:
            unparsed.append(number)
            continue
        if ports:
            name, admin, oper, maximum, priority, consumption, poe_class = match.groups()
            rows.append({'port': name, 'admin_status': admin.lower(), 'oper_status': oper.lower(),
                         'max_power_w': _number(maximum), 'power_w': _number(consumption),
                         'priority': priority.lower(), 'class': int(poe_class) if poe_class.isdigit() else None})
        else:
            index, maximum, reserved, consumption, guard, management, status, lldp = match.groups()
            rows.append({'controller': int(index), 'max_power_w': _number(maximum),
                         'reserved_power_w': _number(reserved) if reserved else None,
                         'power_w': _number(consumption), 'guard_band_w': _number(guard),
                         'management': management, 'status': status, 'lldp_priority': lldp})
    state = 'partial' if rows and unparsed else 'measured' if rows else 'unparsed'
    return {'state': state, 'records': rows, 'unparsed_lines': unparsed}


def payload(profile, query, text, capture_state):
    if profile == 'juniper_junos_els' and query in ('poe_interfaces', 'poe_controller'):
        return {'poe': parse(query, text, capture_state)}
    return {}
