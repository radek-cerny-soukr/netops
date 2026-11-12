"""Port VLAN membership from existing, explicitly enabled read-only queries."""
from __future__ import annotations

import re

CAMPUS = frozenset({'cisco_ios', 'cisco_xe', 'cisco_nxos', 'arista_eos'})
BINDINGS = {**dict.fromkeys(CAMPUS, 'interfaces_trunk'),
            'juniper_junos_els': 'ethernet_switching_interfaces',
            'extreme_exos': 'vlan_detail'}
FIELDS = ('port', 'mode', 'access_vlan', 'native_vlan', 'tagged_vlans', 'oper_status')


def row(name, mode='unknown', access=None, native=None, tagged=None, status=None):
    return dict(zip(FIELDS, (name, mode, access, native, tagged, status)))


def vlan_list(value):
    """Allowed VLANs, bounded by the 802.1Q VLAN space, including wrapped lists."""
    value = re.sub(r'\s+', '', value).lower()
    if value in ('none', '--'):
        return []
    if value == 'all':
        return list(range(1, 4095))
    found = set()
    for item in value.split(','):
        match = re.fullmatch(r'(\d+)(?:-(\d+))?', item)
        if not match:
            raise ValueError('invalid VLAN list')
        low, high = int(match[1]), int(match[2] or match[1])
        if not 1 <= low <= high <= 4094:
            raise ValueError('invalid VLAN range')
        found.update(range(low, high + 1))
    return sorted(found)


def campus_interfaces(text):
    from . import tables
    records, unknown = tables.status_table(text)
    # Preserve the routed cell, which the general interface schema cannot express.
    routed = set()
    starts = None
    for raw in text.splitlines():
        if re.match(r'Port\s+Name\s+Status\s+Vlan\s+Duplex\s+Speed', raw.strip()):
            starts = tables.columns(raw, 'Name', 'Status', 'Vlan', 'Duplex', 'Speed')
        elif starts and tables.cut(raw, starts, 2) == 'routed':
            routed.add(tables.port(raw[:starts[0]].strip()))
    result = []
    for item in records:
        mode = ('routed' if item['name'] in routed else 'access' if item['vlan_id'] is not None
                else 'trunk' if item['trunk'] else 'unknown')
        result.append(row(item['name'], mode, access=item['vlan_id'],
                          tagged=[] if mode in ('access', 'routed') else None, status=item['oper_status']))
    return result, unknown


def trunks(text):
    from . import tables
    ports, allowed, native = {}, {}, {}
    section, previous = None, None

    def handle(raw, value):
        nonlocal section, previous
        if re.match(r'Port\s+', value, re.I):
            previous = None
            lower = value.lower()
            section = ('native' if 'native' in lower else 'allowed' if re.search(r'vlans? allowed(?: on trunk)?$', lower)
                       else 'other' if any(word in lower for word in ('active', 'forwarding', 'err-disabled', 'pruned')) else None)
            return [] if section else None
        if value in ('Vlan                  Channel', 'Vlan', 'Channel'):
            return []
        fields = value.split()
        try:
            name = tables.port(fields[0])
        except ValueError:
            name = None
        if len(fields) == 1:
            name = None
        if section == 'native' and name:
            match = re.search(r'\b(trunking|not-trunking|down|up)\b', value, re.I)
            # NX-OS puts native VLAN before status, IOS/EOS after it.
            number = fields[1] if fields[1].isdigit() else fields[-1]
            if not match or tables.vlan(number) is None:
                return None
            native[name] = int(number)
            ports[name] = row(name, 'trunk', status='up' if match[1].lower() in ('trunking', 'up') else 'down')
            return []
        if section in ('allowed', 'other'):
            if name:
                previous = name
                cell = value[len(fields[0]):].strip()
            elif previous and (re.fullmatch(r'[\d,\s-]+', value) or section == 'other' and value == 'none'):
                # NX-OS can wrap the empty forwarding list below its VTP notice.
                name, cell = previous, value
            else:
                return None
            if section == 'other' and cell == 'Feature VTP is not enabled':
                return []
            numbers = vlan_list(cell.rstrip(','))
            if section == 'allowed':
                allowed.setdefault(name, set()).update(numbers)
                ports.setdefault(name, row(name, 'trunk'))
            return []
        return None

    _, unknown = tables.scan(text, handle)
    for name, item in ports.items():
        if name in allowed and name in native:
            # native_vlan is the untagged VLAN actually carried, not a native
            # default excluded from the allowed list.
            item['native_vlan'] = native.get(name) if native.get(name) in allowed[name] else None
            item['tagged_vlans'] = sorted(allowed[name] - {native.get(name)})
    return list(ports.values()), unknown


def junos(text):
    from . import tables
    ports = {}
    starts, current, in_legend = None, None, False

    def handle(raw, value):
        nonlocal starts, current, in_legend
        if value.startswith('Logical Interface flags ('):
            in_legend = True
            return []
        if in_legend:
            if value.endswith(')'):
                in_legend = False
            return []
        if value.startswith('Routing') and 'Tagging' in value:
            starts = tables.columns(raw, 'Logical', 'Vlan', 'TAG', 'MAC', 'STP', 'Logical          Tagging')
            return []
        if value.startswith('Instance') and 'interface' in value:
            return []
        if starts is None:
            return None
        name = raw[starts[0]:starts[1]].strip()
        if name:
            current = row(tables.port(name), tagged=[], status='down' if re.search(r'\bDN\b', raw) else 'up')
            ports[current['port']] = current
        if current is None:
            return None
        tagging = raw.split()[-1]
        if tagging not in ('tagged', 'untagged'):
            return None
        tag = raw[starts[2]:starts[3]].strip()
        if tag:
            number = tables.vlan(tag)
            if number is None:
                return None
            if tagging == 'tagged':
                current['tagged_vlans'].append(number)
            else:
                current['access_vlan'] = number
        current['mode'] = 'trunk' if current['mode'] == 'trunk' or tagging == 'tagged' or current['tagged_vlans'] else 'access'
        if current['mode'] == 'trunk' and current['access_vlan'] is not None:
            current['native_vlan'], current['access_vlan'] = current['access_vlan'], None
        return []

    _, unknown = tables.scan(text, handle)
    for item in ports.values():
        item['tagged_vlans'] = sorted(set(item['tagged_vlans']))
    return list(ports.values()), unknown


def exos(text):
    from . import tables
    ports = {}
    current_vlan, membership, in_flags = None, None, False
    # These are metadata fields of show vlan detail, not arbitrary lines to discard.
    metadata = re.compile(r'(?:Admin State|Description|Virtual router|IP Anycast|IPv[46](?: MC)? Forwarding|'
                          r'Primary IP|Secondary IP|IPv6|STPD|Layer 2 Forwarding|Protocol|Loopback|NetLogin|'
                          r'QosProfile|Flood Rate Limit QosProfile|Suppress ARP|Suppress ND|Proxy ARP|Ports):')

    def handle(raw, value):
        nonlocal current_vlan, membership, in_flags
        if value.startswith('VLAN Interface with name '):
            current_vlan, membership, in_flags = None, None, False
            return []
        if 'Tagging:' in value:
            match = re.search(r'802\.1Q Tag\s+(\d+)\b', value)
            if not match:
                return None
            current_vlan = int(match[1])
            return []
        if value.startswith('Flags:'):
            membership, in_flags = None, True
            return []
        if in_flags and re.match(r'\([A-Za-z*!]\) ', value):
            return []
        if value == '#':
            return []
        if metadata.match(value):
            membership = None
            return []
        match = re.match(r'(Tag|Untag):\s*(.*)', value)
        if match:
            membership, value = match[1], match[2]
        if membership:
            if current_vlan == 4095 and value in ('Mgmt-port on Mgmt is active', 'Mgmt-port on Mgmt is down'):
                return []
            if not current_vlan or not 1 <= current_vlan <= 4094:
                return None
            if value in ('None', 'none', ''):
                return []
            for token in value.split(','):
                if not token.strip():
                    continue
                match = re.fullmatch(r'\s*([*!]*)(\d+(?::\d+)?)(?:-([0-9:]+))?([A-Za-z]*)(?:\([^)]*\))?[A-Za-z]*\s*', token)
                if not match:
                    return None
                first, last = match[2], match[3] or match[2]
                prefix = first.rsplit(':', 1)[0] + ':' if ':' in first else ''
                low, high = int(first.split(':')[-1]), int(last.split(':')[-1])
                if not 1 <= low <= high <= 4096:
                    return None
                for number in range(low, high + 1):
                    name = tables.port(prefix + str(number))
                    item = ports.setdefault(name, row(name, tagged=[]))
                    if '*' in match[1]:
                        item['oper_status'] = 'up'
                    # Lack of an active VLAN flag does not prove physical link down.
                    if membership == 'Tag':
                        item['tagged_vlans'].append(current_vlan)
                    else:
                        item['access_vlan'] = current_vlan
            return []
        return None

    _, unknown = tables.scan(text, handle)
    for item in ports.values():
        item['tagged_vlans'] = sorted(set(item['tagged_vlans']))
        item['mode'] = 'trunk' if item['tagged_vlans'] else 'access'
        if item['mode'] == 'trunk':
            item['native_vlan'], item['access_vlan'] = item['access_vlan'], None
    return list(ports.values()), unknown


def parse(profile, query, text):
    if profile in CAMPUS:
        return campus_interfaces(text) if query == 'interfaces' else trunks(text)
    if profile == 'juniper_junos_els':
        return junos(text)
    if profile == 'extreme_exos':
        return exos(text)
    return [], []


def read(auth, read_query):
    """Combine sources before filtering/paging; never enable an additional query."""
    from . import tables
    profile = auth.ssh_platform
    query = BINDINGS.get(profile)
    if query is None:
        return tables.parse(profile, 'port_vlan', None, '', status='unsupported')
    result = read_query(query, 'port_vlan') if query in auth.enabled_queries else tables.parse(
        profile, 'port_vlan', query, '', status='permission_denied')
    secondary = 'interfaces' if profile in CAMPUS else 'ports' if profile == 'extreme_exos' else None
    joined = not secondary
    if secondary:
        if secondary in auth.enabled_queries:
            other = read_query(secondary, 'port_vlan' if profile in CAMPUS else 'interface')
            ports = {item['port']: item for item in result['records']}
            for item in other['records']:
                if profile == 'extreme_exos':
                    if item['name'] in ports:
                        ports[item['name']]['oper_status'] = item['oper_status']
                elif item['port'] in ports:
                    ports[item['port']]['oper_status'] = item['oper_status']
                else:
                    ports[item['port']] = item
            result['records'] = list(ports.values())
            combine(result, other)
            joined = other['status'] in ('ok', 'empty')
        else:
            result['warnings'].append('port_vlan_status_join_not_enabled')
            result['coverage']['complete'] = False
    result['coverage']['parsed_records'] = len(result['records'])
    result['coverage']['missing_fields'] = sorted(field for field in ('tagged_vlans', 'oper_status')
                                                 if any(item[field] is None for item in result['records']))
    if result['coverage']['missing_fields']:
        result['coverage']['complete'] = False
    else:
        result['warnings'] = [w for w in result['warnings'] if w != 'fields_absent_in_catalogue_output']
    if result['status'] == 'empty' and result['records']:
        result['status'] = 'ok'
    result['coverage']['complete'] = (joined and result['status'] in ('ok', 'empty') and not result['unparsed']
                                      and not result['coverage']['missing_fields']
                                      and 'refusal_like_line_in_data' not in result['warnings'])
    return result


def combine(result, other):
    result['sources'].extend(other['sources'])
    result['unparsed'].extend(other['unparsed'])
    result['warnings'] = list(dict.fromkeys(result['warnings'] + other['warnings']))
    result['coverage']['unparsed_lines'] = len(result['unparsed'])
    result['coverage']['complete'] &= other['coverage']['complete']
    if other['status'] not in ('ok', 'empty') and result['status'] in ('ok', 'empty'):
        result['status'], result['ok'] = other['status'], False


def join_vlans(auth, result, read_query):
    """IOS show vlan brief omits trunks; unavailable membership stays unknown."""
    if auth.ssh_platform not in ('cisco_ios', 'cisco_xe') or not result['records']:
        return result
    if 'interfaces_trunk' not in auth.enabled_queries:
        result['warnings'].append('trunk_vlan_join_not_enabled')
        result['coverage']['complete'] = False
        return result
    trunks_result = read_query('interfaces_trunk', 'port_vlan')
    complete = (trunks_result['status'] in ('ok', 'empty') and not trunks_result['unparsed']
                and 'refusal_like_line_in_data' not in trunks_result['warnings']
                and all(item['tagged_vlans'] is not None for item in trunks_result['records']))
    for item in result['records']:
        members = set(item['ports'] or [])
        for trunk in trunks_result['records']:
            if membership(trunk, item['vlan_id'])['carries_vlan']:
                members.add(trunk['port'])
        item['ports'] = sorted(members) if members or complete else None
    combine(result, trunks_result)
    if not complete:
        result['coverage']['complete'] = False
    if complete:
        result['coverage']['missing_fields'] = [field for field in result['coverage']['missing_fields']
                                                 if field != 'ports' or all(item['ports'] is None for item in result['records'])]
        result['coverage']['complete'] = (result['status'] in ('ok', 'empty') and not result['unparsed']
                                          and not result['coverage']['missing_fields'] and not result['coverage'].get('warnings'))
        if not result['coverage']['missing_fields']:
            result['warnings'] = [w for w in result['warnings'] if w != 'fields_absent_in_catalogue_output']
    return result


def membership(item, vlan_id):
    if not item or vlan_id is None or item['tagged_vlans'] is None:
        return {'carries_vlan': None, 'tagging': 'missing'}
    if vlan_id in (item['access_vlan'], item['native_vlan']) or vlan_id in (item.get('untagged_vlans') or []):
        return {'carries_vlan': True, 'tagging': 'untagged'}
    if vlan_id in item['tagged_vlans']:
        return {'carries_vlan': True, 'tagging': 'tagged'}
    return {'carries_vlan': False, 'tagging': None}
