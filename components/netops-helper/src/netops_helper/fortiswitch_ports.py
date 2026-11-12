"""FortiSwitch port state/counters and explicitly labelled configuration membership."""
from __future__ import annotations

import re
import shlex

from .read_policy import _validate_slot

STATS = 'managed_switch_port_stats'
CONFIG = 'managed_switch_port_vlans'
VLAN_IDS = 'interface_vlan_ids'


def request(table, parameters, vlan_id, mac, ip, interface):
    if any(value is not None for value in (vlan_id, mac, ip)):
        raise ValueError('filter does not apply to this table')
    filters = {}
    if interface is not None:
        interface = _validate_slot(interface, 'managed_switch_port')
        filters['name' if table == 'interface' else 'port'] = interface
        if table != 'port_vlan':
            parameters = {**parameters, 'port': interface}
    return CONFIG if table == 'port_vlan' else STATS, parameters, filters


def parse(table, text):
    if table == 'port_vlan':
        return port_config(text)
    from . import tables
    rows, unknown, current = [], [], None
    seen = set()
    required = {'speed'} if table == 'interface' else {'input', 'output'}

    def close(number):
        if current is not None and not required <= seen:
            unknown.append({'line': number, 'text': 'incomplete port-stats block: ' + current.get('name', current.get('port', ''))})

    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value or re.fullmatch(r'Vdom:\s*\S+|S[A-Z0-9]{11,15}:', value):
            continue
        head = re.fullmatch(r'Port\(([^()\s]+)\) is HW Admin (up|down), SW Admin (up|down), line protocol is (up|down)', value)
        if head:
            close(number)
            current = tables.record(table, **({'name': head[1], 'admin_status': 'up' if head[2] == head[3] == 'up' else 'down',
                                               'oper_status': head[4]} if table == 'interface' else {'port': head[1]}))
            rows.append(current)
            seen = set()
            continue
        speed = re.fullmatch(r'(?:full|half)-duplex, (\d+) (Mb|Gb)/s, link type is (?:auto|manual)', value)
        counts = re.fullmatch(r'(input|output)\s*:\s*\d+ bytes, \d+ packets, (\d+) errors, (\d+) drops, \d+ oversizes', value)
        if current is not None and speed and 'speed' not in seen:
            seen.add('speed')
            if table == 'interface':
                current['speed'] = speed[1] + ('M' if speed[2] == 'Mb' else 'G')
            continue
        if current is not None and counts and counts[1] not in seen:
            seen.add(counts[1])
            if table == 'interface_errors':
                current['rx_errors' if counts[1] == 'input' else 'tx_errors'] = int(counts[2])
                current['discards_in' if counts[1] == 'input' else 'discards_out'] = int(counts[3])
            continue
        if current is not None and any(re.fullmatch(pattern, value) for pattern in (
                r'Interface Type is .+', r'Address is [0-9A-Fa-f:]+, None loopback',
                r'MTU \d+ bytes, Encapsulation IEEE 802.3/Ethernet-II',
                r'\d+ unicasts, \d+ multicasts, \d+ broadcasts(?:, \d+ unknowns)?',
                r'\d+ fragments, \d+ undersizes, \d+ collisions, \d+ jabbers')):
            continue
        unknown.append({'line': number, 'text': raw})
    close(len(text.splitlines()) or 1)
    return rows, unknown


def _entries(text, family):
    """Select direct object fields in a syntactically complete configuration tree."""
    stack, entries, unknown, names = [], [], [], set()
    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value or value.startswith('#'):
            continue
        try:
            words = shlex.split(value)
            if words[:1] == ['config'] and len(words) >= 2:
                stack.append(('config', ' '.join(words[1:]), None))
            elif words[:1] == ['edit'] and len(words) == 2:
                fields = {}
                configs = tuple(item[1] for item in stack if item[0] == 'config')
                if configs == family:
                    if words[1] in names:
                        raise ValueError()
                    names.add(words[1])
                    entries.append((words[1], fields))
                stack.append(('edit', words[1], fields))
            elif words[:1] == ['set'] and len(words) >= 3 and stack and stack[-1][0] == 'edit':
                if words[1] in stack[-1][2]:
                    raise ValueError()
                stack[-1][2][words[1]] = words[2:]
            elif words[:1] == ['unset'] and len(words) == 2 and stack and stack[-1][0] == 'edit':
                stack[-1][2][words[1]] = []
            elif words == ['next'] and stack and stack[-1][0] == 'edit':
                stack.pop()
            elif words == ['end'] and stack and stack[-1][0] == 'config':
                stack.pop()
            else:
                raise ValueError()
        except ValueError:
            unknown.append({'line': number, 'text': 'unrecognized configuration syntax'})
    if stack:
        unknown.append({'line': len(text.splitlines()) or 1, 'text': 'incomplete configuration tree'})
    return entries, unknown


def port_config(text):
    from . import port_vlan
    entries, unknown = _entries(text, ('switch-controller managed-switch', 'ports'))
    rows = []
    for name, fields in entries:
        row = port_vlan.row(name)
        row.update(source='configuration', vlan=fields.get('vlan'),
                   allowed_vlans=fields.get('allowed-vlans', []), untagged_vlan_names=fields.get('untagged-vlans', []),
                   untagged_vlans=None, allowed_vlans_all=fields.get('allowed-vlans-all', ['disable']))
        if row['allowed_vlans_all'] not in (['enable'], ['disable'], []):
            unknown.append({'line': 1, 'text': 'invalid allowed-vlans-all for ' + name})
        rows.append(row)
    return rows, unknown


def vlan_ids(text):
    from . import tables
    entries, unknown = _entries(text, ('system interface',))
    rows = []
    for name, fields in entries:
        if 'vlanid' not in fields:
            continue
        values = fields['vlanid']
        if len(values) != 1 or not values[0].isdigit() or not 1 <= int(values[0]) <= 4094:
            unknown.append({'line': 1, 'text': 'invalid VLAN ID for ' + name})
        else:
            rows.append(tables.record('vlan', name=name, vlan_id=int(values[0])))
    return rows, unknown


def read_vlan(auth, parameters, read):
    from . import tables, port_vlan
    from .auth import PolicyScopeError
    serial = _validate_slot((parameters or {}).get('managed_switch'), 'managed_switch_serial')
    if serial not in auth.read_inventory.get('managed_switches', ()):
        raise PolicyScopeError('managed switch is outside target policy')
    # Both opt-in queries must be enrolled before contacting the device.
    if not all(query in auth.enabled_queries for query in (CONFIG, VLAN_IDS)):
        result = tables.parse('fortinet', 'port_vlan', None, '', status='unsupported')
        result.update(source='configuration', reason='configured_vlan_reads_not_enabled',
                      data={'field': 'enabled_queries', 'required_queries': [CONFIG, VLAN_IDS]})
        return result
    result = read(CONFIG, 'port_vlan', parameters)
    result['source'] = 'configuration'
    if result['status'] not in ('ok', 'empty'):
        if result['status'] == 'permission_denied':
            result.update(status='unsupported', reason='managed_switch_configuration_not_readable')
        return result
    mapping = read(VLAN_IDS, 'vlan', None)
    port_vlan.combine(result, mapping)
    if mapping['status'] == 'permission_denied':
        result.update(status='unsupported', ok=False, reason='vlan_configuration_not_readable')
    ids = {r['name']: r['vlan_id'] for r in mapping['records']}
    parents = {r['name']: r.get('interface') for r in mapping['records']}
    unresolved = False
    for row in result['records']:
        names = (row['vlan'] or []) + row['allowed_vlans'] + row['untagged_vlan_names']
        if (not row['vlan'] or len(row['vlan']) != 1 or any(name not in ids for name in names)
                or row['allowed_vlans_all'] not in (['enable'], ['disable'], [])):
            unresolved = True
            continue
        native = ids[row['vlan'][0]]
        allowed = {ids[name] for name in row['allowed_vlans']}
        if row['allowed_vlans_all'] == ['enable']:
            context = parents.get(row['vlan'][0])
            if (not context or any(not parent for parent in parents.values())
                    or mapping['status'] not in ('ok', 'empty') or mapping['unparsed']):
                result['warnings'].append('allowed_vlans_all_context_missing')
                continue
            allowed = {ids[name] for name, parent in parents.items() if parent == context}
        untagged = {ids[name] for name in row['untagged_vlan_names']} & allowed
        row.update(mode='trunk' if allowed else 'access', native_vlan=native,
                   tagged_vlans=sorted(allowed - untagged - {native}), untagged_vlans=sorted(untagged | {native}))
    if unresolved:
        result['warnings'].append('vlan_name_not_resolved')
    # Link state is obtained independently from port-stats; a configuration read never promises it.
    result['warnings'] = [w for w in result['warnings'] if w != 'fields_absent_in_catalogue_output']
    result['coverage'].update(parsed_records=len(result['records']), missing_fields=['oper_status'],
                              complete=False)
    return result


def configuration_view(query, text, parameters):
    """The raw SSH tool also exposes only the fields needed for VLAN membership."""
    import json
    family = ('switch-controller managed-switch', 'ports') if query == CONFIG else ('system interface',)
    entries, unknown = _entries(text, family)
    lines = ['config ' + family[0]]
    if query == CONFIG:
        lines += ['    edit ' + json.dumps(parameters['managed_switch']), '        config ports']
    for name, fields in entries:
        if query == VLAN_IDS and 'vlanid' not in fields:
            continue
        lines.append('            edit ' + json.dumps(name, ensure_ascii=False))
        for field in (('vlan', 'allowed-vlans', 'allowed-vlans-all', 'untagged-vlans') if query == CONFIG else ('vlanid', 'interface')):
            if field not in fields:
                continue
            values = fields[field]
            if field == 'vlanid' and (len(values) != 1 or not values[0].isdigit() or not 1 <= int(values[0]) <= 4094):
                unknown.append({'line': 1})
                continue
            lines.append('                ' + ('set ' if values else 'unset ') + field +
                         ((' ' + ' '.join(json.dumps(value, ensure_ascii=False) for value in values)) if values else ''))
        lines.append('            next')
    if query == CONFIG:
        lines += ['        end', '    next']
    lines.append('end')
    lines += ['unrecognized configuration syntax from source line ' + str(item['line']) for item in unknown]
    return '\n'.join(lines) + '\n'
