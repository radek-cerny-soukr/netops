"""Normalized `ip_interface` table: IPv4 address, prefix length, SVI VLAN and state of each interface.

One record per IPv4 address the output prints; an interface without an address is no record
(its state is in the `interface` table). The parsers are bound per (profile, table, query) in
`tables.QUERY_PARSERS`. IOS, IOS XE and NX-OS print no mask: `join` takes the prefix length from
the connected route of the same interface in a second read (`route_table`), and EXOS the VLAN tag
from `vlan_summary`. A value no output gives stays null; nothing is guessed from a name or a
subinterface number. On an IOS/IOS XE router the `interface` table comes from the same
`show ip interface brief` (name, Status, Protocol), because the router has no `show interfaces status`.
"""
from __future__ import annotations

import ipaddress
import re

TABLE = 'ip_interface'
# The catalogue output each profile reads for the table.
QUERIES = {'cisco_ios': 'ip_interfaces', 'cisco_xe': 'ip_interfaces', 'cisco_nxos': 'ip_interfaces',
           'arista_eos': 'ip_interfaces', 'extreme_exos': 'ipconfig', 'juniper_junos': 'interfaces',
           'juniper_junos_els': 'interfaces', 'fortinet': 'system_interfaces'}
# Profiles whose `interface` table comes from `ip_interfaces` on a target declared as router (not switch).
ROUTER_INTERFACES = ('cisco_ios', 'cisco_xe')
SVI = re.compile(r'(?:Vlan|Vl|vlan|irb\.)([0-9]+)')
NAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.:/-]{0,63}')


def name(value):
    """Canonical interface name: the shared port normalizer, else the safe name as printed (EXOS VLAN, FortiOS)."""
    try:
        return t.port(value)
    except ValueError:
        if NAME.fullmatch(value):
            return value
        raise


def address(row, ip, vrf=None):
    """A record for one IPv4 address; `ip` is "A.B.C.D" (no mask printed), "A.B.C.D/len" or "A.B.C.D mask"."""
    length = None
    if ' ' in ip or '/' in ip:
        found = ipaddress.IPv4Interface(ip.replace(' ', '/'))
        ip, length = str(found.ip), found.network.prefixlen
    svi = SVI.fullmatch(row['interface'])
    return t.record(TABLE, interface=row['interface'], ip=str(ipaddress.IPv4Address(ip)), prefix_length=length,
                    vlan_id=int(svi[1]) if svi and 1 <= int(svi[1]) <= 4094 else None,
                    admin_status=row['admin_status'], oper_status=row['oper_status'], vrf=vrf)


def ios(table, text):
    """IOS / IOS XE `show ip interface brief`: Status is the administrative and link state, Protocol the line protocol."""
    def handle(raw, value):
        if re.fullmatch(r'Interface\s+IP-Address\s+OK\?\s+Method\s+Status\s+Protocol', value):
            return []
        m = re.fullmatch(r'(\S+)\s+(\S+)\s+(?:YES|NO)\s+\S+\s+(up|down|administratively down)\s+(up|down)', value)
        if not m:
            return None
        row = {'interface': name(m[1]), 'admin_status': 'down' if m[3].startswith('admin') else 'up',
               'oper_status': m[4]}
        if table == 'interface':
            return t.record('interface', name=row['interface'], admin_status=row['admin_status'], oper_status=row['oper_status'])
        return [] if m[2] == 'unassigned' else address(row, m[2])
    return t.scan(text, handle)


def nxos(table, text):
    """NX-OS `show ip interface brief`: one section per VRF, state as protocol-/link-/admin-."""
    state = {'vrf': None}

    def handle(raw, value):
        m = re.fullmatch(r'IP Interface Status for VRF "([^"]+)"(?:\(\d+\))?', value)
        if m:
            state['vrf'] = m[1]
            return []
        if re.fullmatch(r'Interface\s+IP Address\s+Interface Status', value):
            return []
        m = re.fullmatch(r'(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+protocol-(up|down)/link-(?:up|down)/admin-(up|down)', value)
        if not m or state['vrf'] is None:
            return None
        return address({'interface': name(m[1]), 'admin_status': m[4], 'oper_status': m[3]}, m[2], vrf=state['vrf'])
    return t.scan(text, handle)


def eos(table, text):
    """EOS `show ip interface brief`: the address carries its prefix length."""
    def handle(raw, value):
        if value == 'Address' or re.fullmatch(r'Interface\s+IP Address\s+Status\s+Protocol\s+MTU(?:\s+Owner)?', value):
            return []
        m = re.fullmatch(r'(\S+)\s+(\S+)\s+(up|down|admin down)\s+(\S+)\s+\d+(?:\s+\S+)?', value)
        if not m:
            return None
        row = {'interface': name(m[1]), 'admin_status': 'down' if m[3] == 'admin down' else 'up',
               'oper_status': 'up' if m[4] == 'up' else 'down'}
        return [] if m[2] == 'unassigned' else address(row, m[2])
    return t.scan(text, handle)


def exos(table, text):
    """EXOS `show ipconfig`: settings, the routed VLANs (flag E = enabled, U = up) and the flag legend."""
    def handle(raw, value):
        if (re.fullmatch(r'[A-Za-z][A-Za-z0-9()/-]*(?: [A-Za-z0-9()/-]+)* +: .*|IRDP:|Flags: .*|\(\w+\) .*', value)
                or re.fullmatch(r'(?:Advertisement Address|Minimum Interval): .*', value)
                or re.fullmatch(r'Interface\s+IP Address\s+Flags\s+nSIA', value)):
            return []
        m = re.fullmatch(r'(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+/(\d+)\s+([A-Za-z-]{8,})\s+\d+', value)
        if not m:
            return None
        row = {'interface': name(m[1]), 'admin_status': 'up' if 'E' in m[4] else 'down',
               'oper_status': 'up' if 'U' in m[4] else 'down'}
        return address(row, m[2] + '/' + m[3])
    return t.scan(text, handle)


JUNOS_FAMILIES = r'inet6?|iso|mpls|eth-switch|tnp|multiservice|vpls|ccc|bridge|aenet'
JUNOS_ADDRESS = re.compile(r'([0-9a-fA-Fx:.]+(?:/\d+)?)?(?:\s*-->\s*\S+)?')


def junos(table, text):
    """Junos `show interfaces terse`: the `inet` addresses of each logical interface, continuation lines included."""
    state = {'row': None, 'family': None}

    def addresses(cell):
        if not cell:
            return []
        m = JUNOS_ADDRESS.fullmatch(cell)
        if not m:
            raise ValueError('not an address')
        return [address(state['row'], m[1])] if state['family'] == 'inet' and m[1] else []

    def handle(raw, value):
        if re.match(r'Interface\s+Admin\s+Link\s+Proto\s+Local\s+Remote', value):
            return []
        if raw[:1].isspace():
            if state['row'] is None:
                return None
            m = re.fullmatch(r'(' + JUNOS_FAMILIES + r')(?:\s+(.*))?', value)
            if m:
                state['family'] = m[1]
                return addresses(m[2])
            return addresses(value)
        m = re.fullmatch(r'(' + t.JUNOS_NAME + r')\s+(up|down)\s+(up|down)(?:\s+(' + JUNOS_FAMILIES + r')(?:\s+(.*))?)?', value)
        if not m:
            return None
        state.update(row={'interface': name(m[1]), 'admin_status': m[2], 'oper_status': m[3]}, family=m[4])
        return addresses(m[5])
    return t.scan(text, handle)


def fortinet(table, text):
    """FortiOS `get system interface`: one `== [ name ]` heading and one attribute line per interface.
    `status` is the configured (administrative) state; the output has no link state and no VLAN ID."""
    def handle(raw, value):
        if re.fullmatch(r'== \[ \S+ \]', value):
            return []
        if not value.startswith('name: '):
            return None
        fields = dict(part.split(': ', 1) for part in re.split(r'\s{2,}', value))
        if fields.get('status') not in ('up', 'down'):
            return None
        ip = fields.get('ip')
        if ip is None or ip.split()[0] == '0.0.0.0':
            return []
        return address({'interface': name(fields['name']), 'admin_status': fields['status'], 'oper_status': None}, ip)
    return t.scan(text, handle)


PARSERS = {'cisco_ios': ios, 'cisco_xe': ios, 'cisco_nxos': nxos, 'arista_eos': eos, 'extreme_exos': exos,
           'juniper_junos': junos, 'juniper_junos_els': junos, 'fortinet': fortinet}


def masks(rows, routes):
    """Prefix length of an address from the connected route of its interface that contains it."""
    for row in rows:
        if row['prefix_length'] is not None:
            continue
        ip = ipaddress.IPv4Address(row['ip'])
        lengths = {network.prefixlen for route in routes if route['protocol'] == 'connected' and route['interface'] == row['interface']
                   for network in (ipaddress.ip_network(route['prefix']),) if network.version == 4 and ip in network}
        if len(lengths) == 1:
            row['prefix_length'] = lengths.pop()


def tags(rows, vlans):
    """EXOS: the routed interface is the VLAN itself; its tag comes from the VLAN table by name."""
    for row in rows:
        ids = {vlan['vlan_id'] for vlan in vlans if vlan['name'] == row['interface']}
        if len(ids) == 1 and row['vlan_id'] is None:
            row['vlan_id'] = ids.pop()


def gateways(rows, routes):
    """Join an unambiguous IPv4 default gateway via the same interface."""
    for row in rows:
        if ipaddress.ip_address(row['ip']).version != 4:
            continue
        choices = {route['next_hop'] for route in routes
                   if route['prefix'] == '0.0.0.0/0' and route['interface'] == row['interface']
                   and route['next_hop'] is not None}
        if len(choices) == 1:
            row['gateway'] = choices.pop()


# The second read that supplies what the main output lacks: (query, table, fill).
JOINS = {'linux': ('routes', 'route', gateways), 'cisco_ios': ('route_table', 'route', masks), 'cisco_xe': ('route_table', 'route', masks),
         'cisco_nxos': ('route_table', 'route', masks), 'extreme_exos': ('vlan_summary', 'vlan', tags)}


def join_query(profile, enabled_queries):
    """The query of the second read when it will run (for the rate cost), else None."""
    query = JOINS.get(profile, (None,))[0]
    return query if query in enabled_queries else None


def link_addresses(rows, links):
    """Join the printed MAC and administrative state by the Linux interface name."""
    for row in rows:
        matches = [link for link in links if link['name'] == row['interface']]
        if len(matches) == 1:
            row['mac'] = matches[0]['mac']
            row['admin_status'] = matches[0]['admin_status']


def join_queries(profile, enabled_queries):
    """All enrolled auxiliary queries, also used to charge the proxy read budget."""
    if profile == 'linux':
        return tuple(query for query in ('links', 'routes') if query in enabled_queries)
    query = join_query(profile, enabled_queries)
    return (query,) if query else ()


def join(profile, result, enabled_queries, read):
    """Complete addresses within this read, using only enrolled catalogue queries."""
    if profile not in JOINS or not result['records']:
        return result
    joins = [('links', 'interface', link_addresses), JOINS[profile]] if profile == 'linux' else [JOINS[profile]]
    for query, table, fill in joins:
        if query not in enabled_queries:
            result['warnings'].append(query + '_join_not_enabled')
            continue
        other = read(query, table)
        result['sources'].extend(other['sources'])
        # Keep recognized gateways even when other routes cannot be parsed.
        # Only unknown defaults can affect the gateway join.
        partial_routes = profile == 'linux' and query == 'routes' and other['status'] == 'unparsed'
        if other['status'] in ('ok', 'empty') or partial_routes:
            fill(result['records'], other['records'])
            if partial_routes:
                defaults = []
                for line in other['unparsed']:
                    value = line['text'].strip()
                    if re.match(r'default(?:\s|$)', value):
                        defaults.append([line])
                    elif (defaults and value.startswith('nexthop ')
                          and line['line'] == defaults[-1][-1]['line'] + 1):
                        defaults[-1].append(line)
                if defaults:
                    result['warnings'].append('routes_partial')
                    # A default without a printed device has unknown scope.
                    devices = [set(re.findall(r'(?:^|\s)dev\s+(\S+)',
                                              ' '.join(line['text'] for line in group)))
                               for group in defaults]
                    if any(ipaddress.ip_address(row['ip']).version == 4 and row['gateway'] is None
                           and any(not names or row['interface'] in names for names in devices)
                           for row in result['records']):
                        result['coverage'].setdefault('warnings', []).append('routes_partial')
        elif result['status'] in ('ok', 'empty'):
            result['status'] = other['status']
        if not partial_routes:
            result['unparsed'].extend({**line, 'query': query} for line in other['unparsed'])
        coverage = result['coverage']
        coverage['unparsed_lines'] = len(result['unparsed'])
        warnings = list(dict.fromkeys(coverage.get('warnings', []) + ([] if partial_routes else other['coverage'].get('warnings', []))))
        if warnings:
            coverage['warnings'] = warnings
        coverage['missing_fields'] = sorted(field for field in t.FIELDS[TABLE] if field not in t.optional_fields(profile, TABLE)
                                            and all(row.get(field) is None for row in result['records']))
        result['warnings'] = [warning for warning in dict.fromkeys(result['warnings'] + ([] if partial_routes else other['warnings']))
                              if warning != 'fields_absent_in_catalogue_output' or coverage['missing_fields']]
        coverage['complete'] = (result['status'] in ('ok', 'empty') and not coverage['missing_fields']
                                and not result['unparsed'] and not coverage.get('warnings'))
    return result


# tables.py registers this module at its end; importing it last lets either module be imported first.
from . import tables as t  # noqa: E402
