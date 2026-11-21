"""Dependency-free operational records above the canonical read catalogue.

Only explicitly recognized headings/metadata are skipped. Every other line is
retained with its line number in unparsed, including unsupported output variants.
"""
from __future__ import annotations

import ipaddress
import re

from .normalization import (normalize_mac, normalize_port,
                            exos_exit_250, output_status, refusal_hint, response_envelope, source_record)
from .query_catalog import READ_QUERIES
from .read_policy import _validate_slot
from . import port_vlan
from . import switch_dhcp, switch_managed, fortiswitch_ports
from . import route_ipv6 as _route_ipv6

FIELDS = {
    'interface': ('name', 'description', 'admin_status', 'oper_status', 'speed', 'vlan_id', 'trunk', 'mac', 'mtu'),
    'vlan': ('vlan_id', 'name', 'ports'),
    'mac_entry': ('mac', 'vlan_id', 'port', 'type', 'vlan_name'),
    'neighbor_l3': ('ip', 'mac', 'interface', 'vlan_id', 'vrf', 'type'),
    'dhcp_binding': ('ip', 'mac', 'interface', 'vlan_id', 'lease_seconds', 'type'),
    'lldp_neighbor': ('local_port', 'neighbor', 'neighbor_port', 'management_ip', 'capabilities'),
    'route': ('prefix', 'next_hop', 'interface', 'protocol', 'vrf'),
    'ospf_neighbor': ('neighbor_id', 'address', 'interface', 'state', 'role', 'vrf'),
    'bgp_peer': ('neighbor', 'remote_as', 'state', 'prefixes', 'vrf'),
    'lag': ('name', 'protocol', 'status', 'members'),
    'stp_port': ('instance', 'port', 'role', 'state', 'cost'),
    'aggregate': ('name', 'member_count'),
    'port_vlan': port_vlan.FIELDS,
    'ip_interface': ('interface', 'ip', 'prefix_length', 'vlan_id', 'admin_status', 'oper_status', 'vrf', 'mac', 'gateway'),
    'ip_interface_v6': ('interface', 'ip', 'prefix_length', 'admin_status', 'oper_status', 'address_family'),
}
# Parser bindings reference catalogue names, never CLI strings or permissions.
BINDINGS = {}
IOS_FORWARDING_PROFILES = frozenset({'cisco_ios', 'cisco_xe'})
PARSERS = {}
TABLE_PARSERS = {}
# Parsers of one (profile, table, query) output and the bindings of a target declared as router
# without switch; both are registered by the table modules (ip_interfaces.py) at the end of this file.
QUERY_PARSERS = {}
ROUTER_BINDINGS = {}
MAC = r'(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}|(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}'


def record(table, **values):
    return {key: values.get(key) for key in FIELDS[table]}


def port(value):
    value = value.rstrip(',*')
    # normalize_port returns any safe name as kind "other"; a table cell is a
    # port only when it is physical/aggregate or a known logical interface name.
    try:
        found = normalize_port(value)
    except ValueError:
        found = None
    if found and found['kind'] != 'other':
        return found['name']
    if found:
        value = found['name']
    if re.fullmatch(r'(?:Vlan|Vl|vlan|irb\.|lo|Lo|Loopback|Null|mgmt|Ma|Management|Vxlan|Vx|Tunnel|Tu|nve|BDI|PEt|fxp|em|me|bme|jsrv)[0-9]+(?:[./][0-9]+)*|vme(?:\.[0-9]+)?', value):
        return value
    raise ValueError('not a port name')


def vlan(value):
    match = re.fullmatch(r'(?:Vlan|Vl|vlan|irb\.)?([0-9]+)', value)
    return int(match[1]) if match and 1 <= int(match[1]) <= 4094 else None


def literal(value):
    try:
        return 'ip', _validate_slot(value, 'ip_literal')
    except ValueError:
        return 'mac', _validate_slot(value, 'mac_literal')


def request(profile, table, vlan_id=None, mac=None, ip=None, device_types=None, interface=None, managed_switch=None, vr=None,
            vrf=None, address_family=None, *, enabled_queries=None):
    if vr is not None:
        if profile != 'extreme_exos' or table not in ('route', 'neighbor_l3'):
            raise ValueError('vr only selects EXOS route and neighbor_l3 tables')
        _validate_slot(vr, 'vr')
    from . import fortigate_tables
    if profile == 'fortinet' and managed_switch is None and (
            table in fortigate_tables.QUERIES or table == 'route' and address_family == 'ipv6' and ip is None):
        if vr is not None or vrf is not None:
            raise ValueError('vr and vrf do not apply to FortiGate tables')
        return fortigate_tables.request(table, vlan_id, mac, ip, interface, address_family)
    if address_family is not None:
        if profile.startswith('juniper_junos') and table in ('ospf_neighbor', 'bgp_peer') and address_family in ('ipv4', 'ipv6'):
            pass
        elif profile == 'fortinet' and table == 'route' and managed_switch is None and address_family in ('ipv4', 'ipv6'):
            pass
        elif profile == 'arista_eos' and table in ('route', 'bgp_peer', 'ospf_neighbor', 'neighbor_l3') and address_family in ('ipv4', 'ipv6'):
            pass
        elif profile in IOS_FORWARDING_PROFILES and table == 'neighbor_l3' and address_family in ('ipv4', 'ipv6'):
            pass
        elif profile != 'cisco_nxos' or table not in ('route', 'bgp_peer', 'ospf_neighbor', 'neighbor_l3') or address_family not in ('ipv4', 'ipv6'):
            raise ValueError('address_family must be ipv4 or ipv6 on a supported routing or neighbor table')
        if ip is not None and ipaddress.ip_address(ip).version != (6 if address_family == 'ipv6' else 4):
            raise ValueError('ip and address_family disagree')
    if vrf is not None:
        if not (profile in IOS_FORWARDING_PROFILES and table == 'neighbor_l3'
                or profile == 'cisco_nxos' and table in ('route', 'neighbor_l3', 'ospf_neighbor', 'bgp_peer', 'ip_interface')):
            raise ValueError('vrf applies only to IOS and IOS XE neighbor_l3 and NX-OS L3 tables')
        _validate_slot(vrf, 'vrf')
    if table not in FIELDS:
        raise ValueError('unknown normalized table')
    if table == 'dhcp_binding':
        if profile not in IOS_FORWARDING_PROFILES | {'cisco_nxos'} or managed_switch is not None:
            raise ValueError('dhcp_binding requires a local IOS, IOS XE or NX-OS switch')
        selectors = {}
        if interface is not None:
            selectors['interface'] = port(_validate_slot(interface, 'interface'))
        if mac is not None:
            selectors['mac'] = _validate_slot(mac, 'mac_literal')
        if ip is not None:
            selectors['ip'] = _validate_slot(ip, 'ipv4_neighbor')
        if vlan_id is not None:
            selectors['vlan_id'] = int(_validate_slot(vlan_id, 'vlan_id'))
        return 'dhcp_snooping_binding', {}, selectors
    if profile == 'linux' and table == 'interface' and interface is not None:
        if any(value is not None for value in (vlan_id, mac, ip, managed_switch)):
            raise ValueError('filter does not apply to this table')
        return 'interface_link', {'interface': _validate_slot(interface, 'interface')}, {}
    parameters = switch_managed.parameters(profile, table, managed_switch)
    if profile == 'fortinet' and table in ('interface', 'interface_errors', 'port_vlan'):
        from . import fortiswitch_ports
        return fortiswitch_ports.request(table, parameters, vlan_id, mac, ip, interface)
    if table == 'interface_errors':
        from . import port_errors
        if any(value is not None for value in (vlan_id, mac, ip)):
            raise ValueError('filter does not apply to this table')
        return port_errors.request(profile, interface)
    if profile == 'extreme_exos' and table in _exos_ports.BINDINGS:
        if any(v is not None for v in (vlan_id, mac, ip, managed_switch)):
            raise ValueError('filter does not apply to this table')
        if table == 'poe_budget':
            if interface is not None:
                raise ValueError('interface does not apply to the switch power budget')
            return 'inline_power', {}, {}
        if interface is None:
            raise ValueError('interface is required for this EXOS port table')
        return _exos_ports.BINDINGS[table], {'interface': _validate_slot(interface, 'extreme_physical_port')}, {}
    if profile == 'arista_eos' and (table in _eos_ports.FIELDS or table == 'mac_entry'):
        if ip is not None or managed_switch is not None:
            raise ValueError('filter does not apply to this table')
        selected = _eos_ports.request(table, vlan_id, mac, interface, enabled_queries)
        if selected is not None:
            return selected
    if profile in _ios_ports.PROFILES and table in _ios_ports.TABLES:
        if ip is not None or managed_switch is not None:
            raise ValueError('filter does not apply to this table')
        selected = _ios_ports.request(table, vlan_id, mac, interface, profile=profile)
        if selected is not None:
            return selected
    if profile == 'cisco_nxos':
        default = {'stp_topology': 'stp_detail', 'stp_port_counters': 'stp_detail'}
        scoped = {'stp_port_counters': 'stp_interface_detail', 'lag_member': 'lacp_interface',
                  'optics_port': 'interface_transceiver', 'cdp_neighbor': 'cdp_neighbor_interface',
                  'lldp_neighbor': 'lldp_neighbor_interface'}
        if table in default or table in scoped and (interface is not None or table in ('lag_member', 'optics_port')):
            if any(value is not None for value in (vlan_id, mac, ip, managed_switch)):
                raise ValueError('filter does not apply to this table')
            if interface is None and table in default:
                return default[table], {}, {}
            if table not in scoped or interface is None:
                raise ValueError('interface is required for NX-OS lag_member and optics_port, or selects a port detail')
            query = scoped[table]
            value = _validate_slot(interface, READ_QUERIES[profile][query].slots['interface'].kind)
            return query, {'interface': value}, {('local_port' if table.endswith('_neighbor') else 'port'): port(value)}
    ios_forwarding = profile in IOS_FORWARDING_PROFILES and table in ('mac_entry', 'neighbor_l3')
    filters = {}
    if interface is not None and ios_forwarding:
        query, field = ('mac_table_interface', 'port') if table == 'mac_entry' else ('ipv6_neighbors_interface', 'interface')
        kind = READ_QUERIES[profile][query].slots['interface'].kind
        filters[field] = port(_validate_slot(interface, kind))
    elif interface is not None and table == 'port_vlan':
        if not isinstance(interface, str):
            raise ValueError('interface only filters interface, port_vlan, ip_interface and interface_errors')
        filters['port'] = port(interface)
    elif interface is not None:
        from . import linux_tables
        validate_name = linux_tables.name if profile == 'linux' else ip_interfaces.name
        filters['name' if table == 'interface' else 'interface'] = validate_name(_validate_slot(interface, 'interface'))
    if vlan_id is not None:
        filters['vlan_id'] = int(_validate_slot(vlan_id, 'vlan_id'))
    if mac is not None:
        filters['mac'] = _validate_slot(mac, 'mac_literal')
    if ip is not None:
        filters['ip'] = _validate_slot(ip, 'ip_literal')
    if (mac is not None and table not in ('mac_entry', 'neighbor_l3')
            or ip is not None and table not in ('neighbor_l3', 'route')
            or vlan_id is not None and table not in ('interface', 'vlan', 'mac_entry', 'neighbor_l3')
            or interface is not None and not ios_forwarding
            and table not in ('interface', 'port_vlan', 'ip_interface', 'ip_interface_v6')):
        raise ValueError('filter does not apply to this table')
    ipv6 = address_family == 'ipv6' or ip is not None and ':' in ip
    if ios_forwarding:
        selected = _ios_forwarding_request(table, filters, interface, vrf, address_family, ipv6, enabled_queries)
        if selected is not None:
            return selected
    key = 'neighbor_l3_v6' if table == 'neighbor_l3' and ipv6 else table
    if table == 'route':
        if ip is None:
            # the whole table, where the catalogue has a plain table template (route_all)
            if 'route_all' not in BINDINGS.get(profile, {}):
                raise ValueError('route requires ip (an enrolled address for catalogue lookup)')
            key = 'route_all'
        else:
            key = 'route_v6' if ':' in ip else 'route'
    query = BINDINGS.get(profile, {}).get(key)
    scoped_parameters = {}
    if profile == 'extreme_exos' and vr is None:
        # Keep combined filters local after choosing the most selective supported
        # device-side lookup. No device-wide FDB/ARP read for a scoped request.
        if table == 'mac_entry' and mac is not None:
            query, scoped_parameters = 'mac_address', {'mac': filters['mac']}
        elif table in ('mac_entry', 'neighbor_l3') and key != 'neighbor_l3_v6' and vlan_id is not None:
            query = 'mac_vlan' if table == 'mac_entry' else 'arp_vlan'
            scoped_parameters = {'vlan_id': str(filters['vlan_id'])}
    if profile == 'cisco_nxos' and table in ('mac_entry', 'neighbor_l3') and enabled_queries is not None:
        scope = {'vrf': vrf} if vrf is not None else {}
        if table == 'mac_entry':
            options = [(name, {field: str(filters[field])}) for field, name in
                       (('mac', 'mac_table_address'), ('vlan_id', 'mac_table_vlan')) if field in filters]
        elif ip is not None:
            lookup = 'ipv6_neighbor_lookup' if ipv6 else 'arp_lookup'
            options = [(lookup + ('_vrf' if scope else ''), {**scope, 'address': filters['ip']})]
        else:
            options = []
        # Existing enrollments with only whole-table queries can still use local filters.
        for selected, selected_parameters in options:
            if selected in enabled_queries:
                return selected, selected_parameters, filters
    if device_types and 'router' in device_types and 'switch' not in device_types:
        query = ROUTER_BINDINGS.get(profile, {}).get(key, query)
    if address_family and profile.startswith('juniper_junos'):
        if table == 'ospf_neighbor' and address_family == 'ipv6':
            query = 'ospfv3_neighbors'
        if table == 'bgp_peer':
            filters['address_family'] = address_family
    elif address_family == 'ipv6' and profile == 'arista_eos':
        query = {'route': 'ipv6_route_lookup' if ip else 'ipv6_route_table', 'neighbor_l3': 'ipv6_neighbors',
                 'bgp_peer': 'ipv6_bgp_summary', 'ospf_neighbor': 'ospfv3_neighbors'}[table]
    elif address_family == 'ipv6' and table != 'neighbor_l3':
        query = {'route': 'ipv6_route_lookup' if ip else 'ipv6_route_table',
                 'bgp_peer': 'bgp_ipv6_summary', 'ospf_neighbor': 'ospfv3_neighbors'}[table]
    if vrf is not None and query is not None:
        query += '_vrf'
        parameters['vrf'] = vrf
    template = READ_QUERIES.get(profile, {}).get(query)
    if template is None:
        return None, {}, filters
    # L2 and routing templates are template groups: a group needs the matching
    # device type on the target. A template without a group serves any type.
    if device_types is not None and template.group is not None and template.group not in device_types:
        return None, {}, filters
    # A lookup template takes the address as a slot; a plain route table (EXOS) is read whole
    # and narrowed to the longest matching prefix by longest_prefix().
    address = filters.pop('ip', None) if table == 'route' else None
    if profile == 'extreme_exos' and vr is not None:
        # A VR-qualified read is already scoped to one VR; vlan/mac filters stay local.
        query += '_vr'
        parameters['vr'] = vr
        template = READ_QUERIES[profile][query]
    return query, {**parameters, **scoped_parameters, **({'address': address} if '{address}' in template.command else {})}, filters



def _ios_forwarding_request(table, filters, interface, vrf, family, ipv6, enabled_queries):
    def enabled(query):
        # Only the switch_read authorization and engine pass the target's query set.
        # Callers without that set retain the whole-table reads for local selectors.
        return enabled_queries is not None and query in enabled_queries

    if table == 'mac_entry':
        if interface is not None:
            return 'mac_table_interface', {'interface': interface}, filters
        for field, query in (('mac', 'mac_table_address'), ('vlan_id', 'mac_table_vlan')):
            if field in filters and enabled(query):
                return query, {field: str(filters[field])}, filters
        return None
    if interface is not None and (family == 'ipv4' or 'ip' in filters and not ipv6):
        raise ValueError('interface selects an IPv6 neighbor table on IOS')
    scope = {'vrf': vrf} if vrf is not None else {}
    suffix = '_vrf' if scope else ''
    if ipv6 or interface is not None:
        if interface is not None:
            return 'ipv6_neighbors_interface' + suffix, {**scope, 'interface': interface}, filters
        return 'ipv6_neighbors' + suffix, scope, filters
    if 'ip' in filters and (scope or enabled('arp_lookup')):
        return 'arp_lookup' + suffix, {**scope, 'address': filters['ip']}, filters
    if scope:
        query = 'vrf_arp_table' if not enabled('arp_table_vrf') and enabled('vrf_arp_table') else 'arp_table_vrf'
        return query, scope, filters
    return None

def longest_prefix(records, ip):
    """The routes that win a lookup of `ip` in a whole table: all entries of the longest matching prefix."""
    address = ipaddress.ip_address(ip)
    matches = []
    for row in records:
        try:
            network = ipaddress.ip_network(row['prefix'])
        except (TypeError, ValueError):
            continue
        if address in network:
            matches.append((network.prefixlen, row))
    best = max((length for length, _ in matches), default=None)
    return [row for length, row in matches if length == best]


def parse(profile, table, query, text, *, rc=0, status=None, filters=None, command=None, refused=False):
    entry = READ_QUERIES.get(profile, {}).get(query)
    if command is None and entry is not None and not entry.slots:
        command = entry.command
    state = status or output_status(text, rc=rc, profile=profile, command=command)
    ios_scoped = profile in IOS_FORWARDING_PROFILES and query in IOS_FORWARDING_TABLES
    if ios_scoped and state == 'empty' and table in ('mac_entry', 'dhcp_binding'):
        # A successful IOS MAC/snooping read prints a header even when no rows match.
        state = 'unparsed'
    if ios_scoped and state == 'ok' and rc in (0, None) and command:
        scope = re.search(r'\bvrf (\S+)', command)
        if scope and text.strip() == f'% VRF {scope[1]} does not exist.':
            state = 'not_applicable'
    blank_lookup = (profile, table, query) in _route_ipv6.QUERIES and (
        state == 'empty' or state == 'ok' and _route_ipv6.blank(text))
    if profile == 'cisco_nxos' and table == 'route' and query in ('ipv6_route_table', 'ipv6_route_table_vrf', 'ipv6_route_lookup', 'ipv6_route_lookup_vrf') and state == 'empty':
        state = 'unparsed'
    if profile == 'cisco_xe' and state == 'empty' and query in (
            'stp_detail', 'stp_interface_detail', 'cdp_neighbor_interface', 'lldp_neighbor_interface',
            'power_inline_detail', 'interface_transceiver'):
        state = 'unparsed'
    if profile == 'cisco_nxos' and query in NXOS_SCOPED_TABLES and state == 'empty':
        # These commands display a header even when no rows match.
        state = 'unparsed'
    if blank_lookup:
        # A blank capture, or one holding only the prompt framing, is not the recognized
        # "% Network not in table" answer: no route is shown.
        state = 'unparsed'
    if profile == 'cisco_nxos' and query == 'interface_transceiver' and state == 'ok':
        from .optics import nxos_dom_not_applicable
        if nxos_dom_not_applicable(text) and (not filters or filters.get('port') == text.strip().splitlines()[0].strip()):
            state = 'not_applicable'
            result = response_envelope(profile, state, [source_record(query, text, state)])
            result.update(ok=True, table=table, records=[], unparsed=[],
                          coverage={'complete': True, 'parsed_records': 0, 'unparsed_lines': 0, 'missing_fields': []})
            return result
    if table == 'interface_errors':
        state = _port_errors.output_state(profile, query, text, state, rc)
    # Exact EXOS negative answers are evidence of absence, not failed reads.
    # Keep transport/pager failures and every unrecognized error fail-closed.
    if (profile == 'extreme_exos' and rc in (0, None, 250)
            and state not in ('truncated', 'timeout')
            and _exos_ports.not_applicable(table, text, command)):
        result = response_envelope(profile, 'not_applicable', [source_record(query, text, 'not_applicable')])
        result.update(ok=True, table=table, records=[], unparsed=[],
                      coverage={'complete': True, 'parsed_records': 0, 'unparsed_lines': 0, 'missing_fields': []})
        return result
    refusal_states = {'permission_denied', 'unsupported', 'not_applicable'}
    refusal_like = refused or output_status(text, profile=profile) in refusal_states
    rows, unknown = [], []
    cisco_optics = profile in ('cisco_nxos', 'cisco_xe') and table == 'optics_port' and query == 'interface_transceiver'
    parser = QUERY_PARSERS.get((profile, table, query), PARSERS.get(profile))
    if table in TABLE_PARSERS and profile in _port_errors.PROFILES:
        parser = lambda selected, output: TABLE_PARSERS[selected](profile, output, command=command)
    protected = False
    # Refusal data cannot turn a failed command/transport into a successful read.
    guard_allowed = state in refusal_states and (rc in (0, None) or exos_exit_250(profile, rc, text))
    if parser and (state == 'ok' or refusal_like and guard_allowed):
        rows, unknown = port_vlan.parse(profile, query, text) if table == 'port_vlan' and profile != 'fortinet' else parser(table, text)
        if (profile, table, query) == ('fortinet', 'lag', 'lacp_detail'):
            # The FortiOS aggregate detail does not print its own name; it is the argument of the rendered command.
            named = re.fullmatch(r'diagnose netlink aggregate name (\S+) show', command or '')
            for row in rows:
                row['name'] = named[1] if named else None
        if table == 'vlan' and profile in ('cisco_ios', 'cisco_xe'):
            for row in rows:
                if not row['ports']:
                    row['ports'] = None
        protected = bool(rows) and refusal_like and guard_allowed
        if protected:
            state = 'unparsed' if unknown else 'ok'
        elif state != 'ok':
            rows, unknown = [], []
        elif cisco_optics and rows and rows[0]['state'] in ('partial', 'incomplete'):
            state = 'incomplete'
        elif unknown:
            state = 'unparsed'
        elif not rows:
            state = 'empty'
    elif state == 'ok':
        state = 'unsupported'
    if profile == 'cisco_nxos' and query in NXOS_SCOPED_TABLES and state in ('ok', 'empty'):
        if query in NXOS_LOOKUPS and table == 'neighbor_l3':
            parts = (command or '').split()
            selected_vrf = parts[-1] if len(parts) > 4 and parts[-2] == 'vrf' else 'default'
            for row in rows:
                # The default IPv4 heading sometimes omits the context.
                if row['vrf'] is None and selected_vrf == 'default':
                    row['vrf'] = 'default'
            if rows and selected_vrf != 'all' and any(row['vrf'] != selected_vrf for row in rows):
                unknown.append({'line': 1, 'text': 'NX-OS response identifies a different VRF'})
        selector = None
        if command:
            value = command.split()[3 if query in NXOS_LOOKUPS else -1]
            if query in NXOS_LOOKUPS:
                selector = ('ip', str(ipaddress.ip_address(value)))
            elif query == 'mac_table_address':
                selector = ('mac', normalize_mac(value))
            elif query == 'mac_table_vlan':
                selector = ('vlan_id', int(value))
        if selector and any(row[selector[0]] != selector[1] for row in rows):
            unknown.append({'line': 1, 'text': 'NX-OS response does not match the lookup selector'})
        if unknown:
            state = 'unparsed'
    if ios_scoped and rows and command:
        unknown.extend(_ios_forwarding_scope(query, command, rows))
        if unknown:
            state = 'unparsed'
    if profile == 'extreme_exos' and table == 'route' and command:
        selected_vr = re.search(r' vr ([A-Za-z0-9][A-Za-z0-9_.:-]{0,63})$', command)
        if selected_vr:
            for row in rows:
                row['vrf'] = selected_vr[1]
    scoped_cisco = profile == 'cisco_nxos' or (
        profile == 'cisco_xe' and _ios_ports.INTERFACE_QUERIES.get(table) == query and query is not None)
    if scoped_cisco and filters and state in ('ok', 'incomplete') and any(
            row.get(key) != value for row in rows for key, value in filters.items()):
        state = 'unparsed'
        platform_name = 'NX-OS' if profile == 'cisco_nxos' else 'IOS XE'
        unknown.append({'line': 1, 'text': f'{platform_name} response identifies a different interface'})
    # A field counts as missing when the catalogue output never supplies it; a value that is
    # absent in some rows (no description on a port, no speed on a down link) is normal.
    # Each EOS STP port block must include its required counters and state.
    absent = any if (profile in ('arista_eos', 'cisco_nxos', 'cisco_xe') and table == 'stp_port_counters'
                     or profile == 'cisco_xe' and table == 'stp_topology') else all
    optional = optional_fields(profile, table)
    if ((profile == 'cisco_nxos' and query in NXOS_NEIGHBOR_QUERIES)
            or (ios_scoped and table == 'neighbor_l3')):
        optional.add('vlan_id')
    if profile in IOS_FORWARDING_PROFILES and table == 'neighbor_l3' and rows and all(row.get('state') == 'INCMP' for row in rows):
        optional.add('mac')
    if profile == 'cisco_nxos' and query == 'dhcp_snooping_binding':
        # A documented infinite static lease has no duration in seconds.
        optional.add('lease_seconds')
    if profile == 'fortinet':
        if query == 'local_stp_ports':
            optional.add('role')
        elif query == 'local_switch_vlans':
            optional.add('oper_status')
    missing = sorted(field for field in (FIELDS[table] if rows else ())
                     if field not in optional and absent(row.get(field) is None for row in rows))
    if cisco_optics and rows:
        row = rows[0]
        if 'temperature_c' in missing and any(lane['temperature_c'] is not None for lane in row.get('lanes', [])):
            missing.remove('temperature_c')
        missing = sorted(set(missing) | set(row.get('missing_fields', [])))
    result = response_envelope(profile, state, [source_record(query, text, state)] if query else [])
    result.update(ok=state in ('ok', 'empty'), table=table, records=[row for row in rows if all(row.get(k) == v for k, v in (filters or {}).items())],
                  unparsed=unknown)
    result['coverage'] = {'complete': state in ('ok', 'empty') and not missing and not unknown and not protected,
                          'parsed_records': len(rows), 'unparsed_lines': len(unknown), 'missing_fields': missing}
    if protected:
        result['coverage']['warnings'] = ['refusal_like_line_in_data']
        result['warnings'].append('refusal_like_line_in_data')
    if profile == 'cisco_ios' and table == 'lag_member' and state == 'empty':
        # G53 r3: an empty `show lacp internal` (no channel group) is a valid answer, not complete member data.
        result['coverage']['complete'] = False
        result['warnings'].append('no_channel_groups')
    if missing:
        result['warnings'].append('fields_absent_in_catalogue_output')
    if unknown:
        result['warnings'].append('unrecognized_output_lines')
    if blank_lookup:
        result['warnings'].append('blank_output_not_a_route_answer')
    hint = refusal_hint(profile, text, command=command) if state == 'permission_denied' else None
    if hint:
        result['hint'] = hint
    return _port_errors.finalize(result) if table == 'interface_errors' else result


def lines(text, parse_line, headings=()):
    rows, unknown = [], []
    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value or re.fullmatch(r'[-=+ ]+', value) or any(re.fullmatch(h, value, re.I) for h in headings):
            continue
        try:
            parsed = parse_line(value)
        except (ValueError, IndexError):
            parsed = None
        if parsed is None:
            unknown.append({'line': number, 'text': raw})
        else:
            rows.extend(parsed if isinstance(parsed, list) else [parsed])
    return rows, unknown


def neighbor_line(value, style):
    parts = value.split()
    mac_match = re.search(MAC, value)
    addresses = []
    for item in parts:
        try:
            addresses.append(str(ipaddress.ip_address(item)))
        except ValueError:
            pass
    if not addresses:
        return None
    address = addresses[0]
    if style == 'junos':
        interface = parts[3] if ':' not in address else parts[-1]
    elif style == 'exos':
        interface = parts[-1]
    elif style == 'eos' and mac_match:
        # "<MAC> <state> <Interface cell>": the cell may hold several interfaces ("Vlan10, Ethernet2"), same as in ARP.
        cell = value[mac_match.end():].split(None, 1)
        interface = interface_cell(cell[1]) if len(cell) > 1 else parts[-1]
    else:
        interface = parts[-1]
    ios_incomplete = (style == 'ios' and len(parts) == 5 and parts[2:4] == ['-', 'INCMP']
                      and str(ipaddress.IPv6Address(parts[0])) == address
                      and re.fullmatch(r'[0-9]+|-', parts[1]) is not None)
    # Incomplete ARP/ND is a useful record, never a made-up MAC.
    if not mac_match and not ios_incomplete and not re.search(r'\b(?:Incomplete|INCOMPLETE|FAILED)\b', value):
        return None
    if interface == 'Incomplete':
        interface = None
    elif interface:
        try:
            interface = port(interface)
        except ValueError:
            if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}', interface):
                return None
    row = record('neighbor_l3', ip=address, mac=normalize_mac(mac_match[0]) if mac_match else None,
                 interface=interface, vlan_id=vlan(interface or ''))
    if ios_incomplete:
        row.update(mac=None, state='INCMP')
    return row


CAPABILITY_CODES = (('O', 'other'), ('P', 'repeater'), ('B', 'bridge'), ('W', 'wlan ap'), ('R', 'router'),
                    ('T', 'telephone'), ('C', 'docsis'), ('S', 'station'))
_CAPABILITY_WORDS = {'other': 'O', 'repeater': 'P', 'bridge': 'B', 'switch': 'B', 'wlan ap': 'W', 'wlan access point': 'W',
                     'access point': 'W', 'router': 'R', 'telephone': 'T', 'phone': 'T', 'docsis cable device': 'C',
                     'docsis': 'C', 'cable device': 'C', 'station only': 'S', 'station': 'S'}


def capabilities(value):
    """IEEE 802.1AB capability set as one canonical string ("B,W"); None when nothing was advertised.

    Accepts the letter form (Cisco "B,T") and the word form (EXOS "Bridge, WLAN AP").
    """
    text = (value or '').strip().strip('"')
    letters = re.fullmatch(r'[A-Za-z](?:\s*,\s*[A-Za-z]|\s+[A-Za-z])*', text)
    items = [item.lower() for item in (re.split(r'[,\s]+', text) if letters else (part.strip() for part in text.split(','))) if item]
    if not items:
        return None
    found = set()
    for item in items:
        code = item.upper() if len(item) == 1 and item.upper() in dict(CAPABILITY_CODES) else _CAPABILITY_WORDS.get(item, 'O')
        found.add(code)
    return ','.join(code for code, _ in CAPABILITY_CODES if code in found)


def columns(header, *names):
    """Start offsets of fixed-width columns, taken from the header line the device printed."""
    return [header.index(name) for name in names]


def cut(raw, starts, index):
    end = starts[index + 1] if index + 1 < len(starts) else None
    return raw[starts[index]:end].strip()


EXOS_PORT_STATE = {'E': 'up', 'D': 'down', 'F': 'down', 'L': 'down'}
EXOS_ORIGIN = {'d': 'connected', 'div': 'connected', 's': 'static', 'bo': 'bootp', 'h': 'hardcoded', 'b': 'blackhole', 'i': 'icmp',
               'r': 'rip', 'o': 'ospf', 'o1': 'ospf', 'o2': 'ospf', 'oa': 'ospf', 'oe': 'ospf', 'or': 'ospf', 'oiv': 'ospf',
               'bg': 'bgp', 'be': 'bgp', 'bi': 'bgp', 'un': 'unknown'}


def exos_lldp(text):
    """`show lldp neighbors detailed`: one record per "Neighbor:" block; TLV lines are recognized by structure."""
    rows, unknown, current, port_name = [], [], None, None
    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value or re.fullmatch(r'-{20,}', value):
            continue
        m = re.fullmatch(r'LLDP Port (\S+) detected (\d+) neighbors?', value)
        if m:
            current = None
            try:
                port_name = m[1] if m[1] == 'mgmt' else port(m[1])      # the out-of-band port is only called "mgmt"
            except ValueError:
                port_name = None
                unknown.append({'line': number, 'text': raw})
            continue
        if re.fullmatch(r'Neighbor: .+, age \d+ seconds?', value) and re.match(r' {2}\S', raw):
            current = record('lldp_neighbor', local_port=port_name)
            rows.append(current)
            continue
        if current is None:
            unknown.append({'line': number, 'text': raw})
            continue
        m = re.fullmatch(r'Chassis ID +: (.*)', value) and re.match(r' {6}Chassis ID ', raw)
        if m:
            continue
        m = re.fullmatch(r'Port ID +: "?(.*?)"?', value) if re.match(r' {6}Port ID ', raw) else None
        if m:
            current['neighbor_port'] = m[1] or None
            continue
        m = re.fullmatch(r'- System Name: "(.*)"', value)
        if m:
            current['neighbor'] = m[1] or None
            continue
        m = re.fullmatch(r'Enabled Capabilities: "(.*)"', value)
        if m:
            current['capabilities'] = capabilities(m[1])
            continue
        m = re.fullmatch(r'Management Address +: (\S+)', value)
        if m and current['management_ip'] is None:
            try:
                current['management_ip'] = str(ipaddress.ip_address(m[1]))
            except ValueError:
                pass            # a MAC or other address subtype is not a management IP
            continue
        # TLV headers ("    - ..."), their attributes (6 spaces) and wrapped quoted strings
        # (deeper indent) keep the structure of the output; anything else is unknown.
        if re.match(r' {4}- \S', raw) or re.match(r' {6,}\S', raw):
            continue
        unknown.append({'line': number, 'text': raw})
    return rows, unknown


def exos_lacp(text):
    """`show lacp`: one record per LAG row; the LAG is named by its master port, which is what the FDB shows."""
    def handle(raw, value):
        if matches(value, (r'LACP (?:Up|Enabled)\s*:\s*\S+', r'System MAC\s*:\s*(?:' + MAC + ')', r'LACP PDUs dropped on non-LACP ports\s*:\s*\d+',
                           r'Lag\s+Actor\s+Actor\s+Partner\s+Partner\s+Partner\s+Agg', r'Sys-Pri\s+Key\s+MAC\s+Sys-Pri\s+Key\s+Count')):
            return []
        m = re.fullmatch(r'(\d+(?::\d+)?)\s+\d+\s+0x[0-9a-fA-F]+\s+(?:' + MAC + r')\s+\d+\s+0x[0-9a-fA-F]+\s+(\d+)', value)
        if m:
            return record('aggregate', name=port(m[1]), member_count=int(m[2]))
        return None
    return scan(text, handle)


def exos_sharing(text):
    """Load Sharing Monitor: config master names the group; Agg Mbr and Link State describe members."""
    current = [None]
    number_of_groups = [None]
    def handle(raw, value):
        if matches(value, (r'show sharing', r'\*?\s*[A-Za-z0-9_.-]+\.\d+\s+[>#]', r'Load Sharing Monitor', r'Config\s+Current Agg\s+Min\s+Ld Share\s+Ld Share\s+Agg Link\s+Link Up',
                           r'Master\s+Master\s+Control Active Algorithm Flags Group\s+Mbr State Transitions',
                           r'Link State: A-Active, D-Disabled, R-Ready, NP-Port not present, L-Loopback',
                           r'Minimum Active: \(<\) Group is down\. # active links less than configured minimum',
                           r'Flags:',
                           r'A - All: Distribute to all members,', r'd - Dynamically created shared port,',
                           r'L - Local Slot: Distribute to members local to ingress slot,',
                           r'P - Port Lists: Distribute to per-slot configurable subset of members,',
                           r'R - Resilient Hashing enabled\.')):
            return []
        # Split at commas first: each item has a disjoint token/description grammar,
        # so a malformed or long legend cannot cause nested-regex backtracking.
        legend = value.removeprefix('Load Sharing Algorithm: ')
        if (legend != value or value.startswith('(L')) and all(
                re.fullmatch(r'\(L[0-9][A-Za-z0-9_]*\)[ \t]+[A-Za-z][^,()\r\n]*', item.strip())
                for item in legend.split(',')):
            return []
        m = re.fullmatch(r'Number of load sharing trunks:\s*(\d+)', value)
        if m:
            number_of_groups[0] = int(m[1])
            return []
        # Flags may be blank on continuation rows; '-' is an unaggregated member.
        m = re.fullmatch(r'(\d+(?::\d+)?)\s+(\d+(?::\d+)?|-)\s+(LACP|STATIC)\s+(<?\d+)\s+'
                         r'(?:(L2|L3_L4|L3|custom)\s+)?([AdLPR-]+)\s+(\d+(?::\d+)?)\s+(Y|N|-)\s+(A|D|R|NP|L)\s+(\d+)', value, re.I)
        # The EXOS-VM 33.6 LACP group reads blank under Algorithm. The group
        # number and member link state are still printed.
        if m and (m[5] or m[3].upper() == 'LACP'):
            current[0] = record('lag', name=port(m[1]), protocol='LACP' if m[3].upper() == 'LACP' else 'Static',
                                status='down' if m[4].startswith('<') else None, members=[])
            member, aggregated, link = m[7], m[8], m[9]
            result = current[0]
        else:
            m = re.fullmatch(r'(L2|L3_L4|L3|custom)[ \t]+(?:([AdLPR-]+)[ \t]+)?(\d+(?::\d+)?)[ \t]+(Y|N|-)[ \t]+(A|D|R|NP|L)[ \t]+\d+', value, re.I)
            if not m or current[0] is None:
                return None
            member, aggregated, link = m[3], m[4], m[5]
            result = []
        bundled = aggregated.upper() == 'Y' and link.upper() == 'A'
        current[0]['members'].append({'port': port(member), 'state': 'bundled' if bundled else 'down' if link.upper() in ('D', 'R', 'NP', 'L') else 'suspended'})
        if current[0]['status'] is None or current[0]['status'] == 'up':
            current[0]['status'] = 'up' if any(m['state'] == 'bundled' for m in current[0]['members']) else None
        return result
    rows, unknown = scan(text, handle)
    for row in rows:
        if row['status'] is None:
            row['status'] = 'down'
    if number_of_groups[0] != len(rows):
        unknown.append({'line': len(text.splitlines()), 'text': 'load sharing group count missing or mismatched'})
    return rows, unknown


def exos(table, text):
    if table == 'lldp_neighbor':
        return exos_lldp(text)
    if table == 'route':
        return exos_routes(text)
    if table == 'aggregate':
        return exos_lacp(text)
    if table == 'lag':
        return exos_sharing(text)
    pending = [None]
    incomplete = []

    def row(value):
        if table == 'interface':
            m = re.fullmatch(r'(\d+(?::\d+)?)\s+(?:(\S+)\s+)??(\(\d+\)|\S+)\s+([DEFL])\s+(A|R|NP|L|D|d|B)'
                             r'(?:\s+(\d+|-)\s+(HALF|FULL))?', value)
            if m:
                count = re.fullmatch(r'\((\d+)\)', m[3])
                return record(table, name=port(m[1]), description=m[2], admin_status=EXOS_PORT_STATE[m[4]],
                              oper_status='up' if m[5] == 'A' else 'down', speed=None if m[6] in (None, '-') else m[6],
                              trunk=int(count[1]) > 1 if count else False)
        elif table == 'mac_entry':
            m = re.fullmatch(r'('+MAC+r')\s+(\S+?)\((\d{4})\)\s++\d+\s++(\S(?:.*?\S)?)\s++(\S+)', value)
            if m:
                flags = m[4].replace(' ', '')
                kind = 'dynamic' if 'd' in flags else 'static' if 's' in flags else 'permanent' if 'p' in flags else None
                return record(table, mac=normalize_mac(m[1]), vlan_id=int(m[3]), vlan_name=m[2], port=port(m[5].split('(')[0]), type=kind)
        elif table == 'vlan':
            m = re.fullmatch(r'(\S+)\s+(\d+)\s+(?:\S+\s+/\d+\s+\S+|[-\w]{20,})\s+(\S+)\s+\d+\s*/\s*\d+\s+VR-\S+', value)
            if m and 1 <= int(m[2]) <= 4095:
                return record(table, vlan_id=int(m[2]), name=m[1])
        elif table == 'neighbor_l3':
            m = re.fullmatch(r'(VR-\S+)\s+([0-9a-fA-F:]+)', value)
            if m and ':' in m[2]:
                if pending[0] is not None:
                    incomplete.append(pending[0][2])
                pending[0] = (str(ipaddress.ip_address(m[2])), m[1], value)
                return []
            m = re.fullmatch(r'('+MAC+r')\s+\d+\s+(?:YES|NO)\s+(\S+)\s+(\d+)(?:\s+(\S+))?', value)
            if m and pending[0]:
                address, vrf, _ = pending[0]
                pending[0] = None
                return record(table, ip=address, vrf=vrf, mac=normalize_mac(m[1]), vlan_id=int(m[3]),
                              interface=port(m[4]) if m[4] else None)
            m = re.fullmatch(r'(VR-\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+('+MAC+r'|-+|\(?[Ii]ncomplete\)?)\s+\d+\s+(?:YES|NO)\s+(\S+)\s+(\d+)(?:\s+(\S+))?', value)
            if m:
                known = re.fullmatch(MAC, m[3])
                return record(table, ip=str(ipaddress.ip_address(m[2])), vrf=m[1], mac=normalize_mac(m[3]) if known else None,
                              interface=port(m[6]) if m[6] else None, vlan_id=int(m[5]))
        return None
    rows, unknown = lines(text, row, EXOS_HEADINGS[table])
    if pending[0]:
        incomplete.append(pending[0][2])
    for value in incomplete:
        number, raw = next((n, line) for n, line in enumerate(text.splitlines(), 1) if line.strip() == value)
        unknown.append({'line': number, 'text': raw})
    return rows, sorted(unknown, key=lambda item: item['line'])


def exos_routes(text):
    """`show iproute`: a route row is "Ori Destination Gateway Mtr Flags VLAN Duration"; the rest is legend."""
    def row(value):
        m = re.fullmatch(r'[#*@]?(\w{1,3})\s+(Default Route|\d+\.\d+\.\d+\.\d+/\d+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(?:\d+d:\d+h:\d+m:\d+s|\S+)', value)
        if not m:
            return None
        prefix = '0.0.0.0/0' if m[2] == 'Default Route' else str(ipaddress.ip_network(m[2], strict=False))
        try:
            hop = str(ipaddress.ip_address(m[3]))
        except ValueError:
            hop = None
        protocol = EXOS_ORIGIN.get(m[1], m[1])
        # EXOS prints the local VLAN address in Gateway for direct routes.
        return record('route', prefix=prefix, next_hop=None if protocol == 'connected' else hop,
                      interface=m[6], protocol=protocol, vrf='VR-Default')
    return lines(text, row, EXOS_HEADINGS['route'])


_EXOS_LEGEND = (r'\(\w{1,3}\) .*', r'[A-Za-z]-[A-Za-z!$#?*].*')
EXOS_HEADINGS = {
    'interface': (r'Port Summary', r'Port\s+Display\s+VLAN Name\s+Port\s+Link\s+Speed\s+Duplex',
                  r'#\s+String\s+\(or # VLANs\)\s+State State Actual Actual', r'Port State: .*', r'Link State: .*',
                  r'[A-Za-z]-[A-Za-z][^:]*,?'),
    'mac_entry': (r'VLAN \d+: show fdb vlan \S+', r'MAC\s+VLAN Name\( Tag\)\s+Age\s+Flags\s+Port / Virtual Port List', r'Flags : .*',
                  r'[a-zA-Z] ?- .*', r'Total: \d+ Static: \d+ +Perm: \d+ +Dyn: \d+ +Dropped: \d+ +Locked: \d+ +Locked with Timeout: \d+',
                  r'FDB Aging time: \d+', r'No FDB entries.*'),
    'vlan': (r'Untagged ports auto-move: \w+', r'Name\s+VID\s+Protocol Addr\s+Flags\s+Proto\s+Ports\s+Virtual',
             r'Active router', r'/Total', r'Flags : .*', r'\(\w\) .*', r'Total number of VLAN\(s\)\s*: \d+'),
    'neighbor_l3': (r'VLAN \d+: show iparp vlan \S+', r'VR\s+Destination\s+Mac\s+Age\s+Static\s+VLAN\s+VID\s+Port', r'VR\s+Destination',
                    r'Mac\s+Age\s+Static\s+VLAN\s+VID\s+Port',
                    r'Total Entries\s*:\s*\d+', r'Dynamic Entries\s*:\s*\d+\s+Static Entries\s*:\s*\d+', r'Pending Entries\s*:\s*\d+',
                    r'ARP address check:\s*\w+\s+ARP refresh\s*:\s*\w+', r'Timeout\s*:\s*\d+ minutes\s+(?:ARP Sender-Mac Learning|Refresh)\s*:\s*\w+',
                    r'Locktime\s*:\s*\d+ milliseconds', r'Retransmit Time\s*:\s*\d+ milliseconds',
                    r'Reachable Time\s*:\s*\d+ milliseconds \(\w+\)', r'Fast Convergence\s*:\s*\w+',
                    r'ARP Global Settings', r'Neighbor Discovery Global Settings',
                    r'Max (?:Pending |Proxy )?Entries\s*:\s*\d+'),
    'route': (r'Ori\s+Destination\s+Gateway\s+Mtr\s+Flags\s+VLAN\s+Duration', r'Origin\(Ori\):.*', r'\(\W?\w{0,3}\W?\) .*',
              r'Flags:.*', r'MPLS Label: .*', r'Mask distribution:', r'\d+ default routes.*', r'\d+ routes at length \d+.*',
              r'Route [Oo]rigin distribution:', r'\d+ routes from \w+.*', r'Total number of (?:compressed )?routes\s*=\s*\d+'),
}


BINDINGS['extreme_exos'] = {'interface': 'ports', 'vlan': 'vlan_summary', 'mac_entry': 'mac_table',
                            'neighbor_l3': 'arp_table', 'neighbor_l3_v6': 'ipv6_neighbors',
                            'lldp_neighbor': 'lldp_neighbors_detail', 'route': 'route_table', 'route_all': 'route_table', 'route_v6': 'ipv6_route_table',
                            'aggregate': 'lacp', 'lag': 'lag_summary'}
PARSERS['extreme_exos'] = exos


# --- shared scanning helpers for the table-shaped OS outputs ---------------------------------

SYSTEM_PORTS = re.compile(r'(?:CPU|Cpu|Router|Switch|[Ss]up-eth\d+|Vl\d+|Vlan\d+|nve\d+.*|--)(?:\(R\))?')
# Fields a table may legitimately leave empty without the output being incomplete.
OPTIONAL_FIELDS = {'mac_entry': {'vlan_name'}, 'neighbor_l3': {'vrf', 'type'}, 'ospf_neighbor': {'role', 'vrf'}, 'bgp_peer': {'prefixes', 'vrf'},
                   'port_vlan': {'access_vlan', 'native_vlan'},
                   'lag': {'protocol'}, 'stp_port': {'cost'}, 'route': {'next_hop', 'interface', 'vrf'},
                   'interface': {'description', 'speed', 'admin_status', 'mac', 'mtu'}, 'ip_interface': {'vlan_id', 'vrf', 'mac', 'gateway'}}


# Only catalogue fields unavailable on this profile; other platforms keep their coverage.
PROFILE_OPTIONAL_FIELDS = {'linux': {'interface': {'vlan_id', 'trunk'},
                                    'ip_interface': {'admin_status'},
                                    'neighbor_l3': {'vlan_id'}}}


def optional_fields(profile, table):
    return set(OPTIONAL_FIELDS.get(table, ())) | PROFILE_OPTIONAL_FIELDS.get(profile, {}).get(table, set())


def scan(text, handle):
    """handle(raw, value) -> list of records, [] for a recognized line, None for an unknown one."""
    rows, unknown = [], []
    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value or re.fullmatch(r'[-=+ ]+', value):
            continue
        try:
            parsed = handle(raw, value)
        except (ValueError, IndexError, KeyError):
            parsed = None
        if parsed is None:
            unknown.append({'line': number, 'text': raw})
        else:
            rows.extend(parsed if isinstance(parsed, list) else [parsed])
    return rows, unknown


def matches(value, patterns):
    return any(re.fullmatch(pattern, value, re.I) for pattern in patterns)


def port_list(text):
    """Comma separated ports of a VLAN or MAC row; the CPU/system pseudo ports are not member ports."""
    return [port(item) for item in re.split(r'[,\s]+', text) if item and not SYSTEM_PORTS.fullmatch(item.rstrip(',*'))]


STATUS_UP = {'connected', 'monitoring'}
STATUS_DOWN = {'notconnect', 'notconnec', 'disabled', 'err-disabled', 'errdisabled', 'inactive', 'sfpabsent', 'xcvrabsen',
               'xcvrabsent', 'noopermem', 'down', 'suspended', 'faulty', 'linkflape', 'sfpinvali', 'xcvrinval', 'channeldo',
               'suspndbyv', 'sfpinvalid', 'noconnect', 'err-disabl'}


def status_table(text):
    """`show interface(s) status` (IOS/XE/NX-OS/EOS): columns are cut where the header prints them."""
    starts = []

    def handle(raw, value):
        if re.match(r'Port\s+Name\s+Status\s+Vlan\s+Duplex\s+Speed', value):
            starts[:] = columns(raw, 'Name', 'Status', 'Vlan', 'Duplex', 'Speed')
            return []
        if not starts:
            return None
        name = raw[:starts[0]].strip()
        state = cut(raw, starts, 1)
        vlan_cell = cut(raw, starts, 2)
        if not name or ' ' in name or not state or ' ' in state and not state.startswith('in '):
            return None
        status = state.lower()
        if status not in STATUS_UP | STATUS_DOWN:
            return None
        description = raw[starts[0]:starts[1]].strip()
        speed = raw[starts[4]:].split()
        trunk = True if vlan_cell == 'trunk' else False if vlan(vlan_cell) or vlan_cell in ('routed', '--') or vlan_cell.startswith('in ') else None
        return record('interface', name=port(name), description=None if description in ('', '--') else description,
                      admin_status='down' if status == 'disabled' else None,
                      oper_status='up' if status in STATUS_UP else 'down',
                      speed=speed[0] if speed else None, vlan_id=vlan(vlan_cell), trunk=trunk)
    return scan(text, handle)


def vlan_sections(text, style):
    """`show vlan [brief]` (IOS/XE/NX-OS/EOS): the VLAN/Name/Status/Ports table plus its continuation lines;
    NX-OS also prints Type, Remote SPAN and Private-VLAN sections, which carry no ports of the main table."""
    state = {'section': None, 'last': None}
    active = r'(?:active|act/unsup|act/lshut|sus/lshut|suspend|shutdown|act/ishut|sus/ishut)'

    def handle(raw, value):
        if re.match(r'VLAN\s+Name\s+Status\s+Ports', value):
            state['section'] = 'vlan'
            return []
        if re.match(r'VLAN\s+Type\s+Vlan-mode', value):
            state['section'] = 'type'
            return []
        if re.match(r'Primary\s+Secondary\s+Type\s+Ports', value):
            state['section'] = 'private'
            return []
        if re.fullmatch(r'Remote SPAN VLANs', value):
            state['section'] = 'remote'
            return []
        section = state['section']
        if section == 'vlan':
            m = re.fullmatch(r'(\d+)\s++(\S(?:.*?\S)?)\s++(' + active + r')(?:\s+(.*))?', value)
            if m:
                result = record('vlan', vlan_id=int(m[1]), name=m[2], ports=port_list(m[4] or ''))
                state['last'] = result
                return result
            if state['last'] is not None and re.fullmatch(r'[A-Za-z][A-Za-z0-9/.,\- ]*', value) and raw.startswith(' '):
                state['last']['ports'].extend(port_list(value))
                return []
        elif section == 'type':
            if re.fullmatch(r'\d+\s+\S+\s+\S+', value):
                return []
        elif section == 'remote':
            if re.fullmatch(r'[\d,\- ]+|-', value):
                return []
        elif section == 'private':
            if re.fullmatch(r'\d+\s+\d+\s+\S+(?:\s+.*)?', value):
                return []
        return None
    return scan(text, handle)


def mac_type(word):
    word = word.lower()
    return 'dynamic' if word in ('dynamic', 'd', 'learn', 'learned') else 'static' if 'static' in word or word in ('s', 'secure') else word


def mac_ios(text):
    """IOS / IOS XE `show mac address-table`; "All ... CPU" and SVI rows are the switch itself, not a host."""
    def handle(raw, value):
        if matches(value, (r'Mac Address Table', r'Vlan\s+Mac Address\s+Type\s+Ports?', r'Total Mac Addresses for this criterion:\s*\d+',
                           r'Unicast Entries', r'Multicast Entries')):
            return []
        m = re.fullmatch(r'(\d+|All)\s+(' + MAC + r')\s+(\S+)\s+(.+)', value)
        if not m:
            return None
        cell = m[4].strip()
        if m[1] == 'All' or SYSTEM_PORTS.fullmatch(cell):
            return []
        return [record('mac_entry', mac=normalize_mac(m[2]), vlan_id=int(m[1]), type=mac_type(m[3]), port=port(item))
                for item in cell.split(',')]
    return scan(text, handle)


def mac_nxos(text, *, include_remote=False):
    legend = {'on': False}

    def handle(raw, value):
        if value == 'Legend:':
            legend['on'] = True
            return []
        if re.match(r'VLAN\s+MAC Address\s+Type\s+age\s+Secure\s+NTFY\s+Ports', value):
            legend['on'] = False
            return []
        if legend['on']:
            return [] if re.match(r'(?:[*+GOC] - |age - |\(T\) - |\(R\) - |\*\s*-)', value) or ' - ' in value else None
        m = re.fullmatch(r'(?:[*+GOC~]|\(R\))*\s*(\d+|-)\s+(' + MAC + r')\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)', value)
        if not m:
            return None
        cell = m[7].strip()
        if m[1] == '-':
            return []
        peer = re.fullmatch(r'(nve\d+)\(([^()]+)\)', cell) if include_remote else None
        if peer:
            return record('mac_entry', mac=normalize_mac(m[2]), vlan_id=int(m[1]), type=mac_type(m[3]),
                          port=peer[1]) | {'remote': True, 'peer_ip': str(ipaddress.ip_address(peer[2]))}
        if SYSTEM_PORTS.fullmatch(cell):
            return []
        if cell.startswith('vPC Peer-Link'):
            return record('mac_entry', mac=normalize_mac(m[2]), vlan_id=int(m[1]), type='trunk', port='vPC Peer-Link')
        return [record('mac_entry', mac=normalize_mac(m[2]), vlan_id=int(m[1]), type=mac_type(m[3]), port=port(item))
                for item in cell.split(',')]
    return scan(text, handle)


def mac_eos(text):
    """`show mac address-table`: Type may hold two words and Ports a comma list, so the line is read from
    the left up to the first plain number (the Moves column of the unicast table)."""
    def handle(raw, value):
        if matches(value, (r'(?:Multicast )?Mac Address Table', r'Total Mac Addresses for this criterion:\s*\d+',
                           r'Vlan\s+Mac Address\s+Type\s+Ports(?:\s+Moves\s+Last Move)?')):
            return []
        m = re.fullmatch(r'(\d+)\s+(' + MAC + r')\s+([A-Z]+(?: [A-Z]+)*)\s+(\S.*)', value)
        if not m:
            return None
        cell = []
        for token in m[4].split():
            if token.isdigit():
                break
            cell.append(token)
        cell = ' '.join(cell)
        if SYSTEM_PORTS.fullmatch(cell):
            return []
        return [record('mac_entry', mac=normalize_mac(m[2]), vlan_id=int(m[1]), type=mac_type(m[3]), port=port(item))
                for item in re.split(r',\s*', cell)]
    return scan(text, handle)


JUNOS_IFL = re.compile(r'(?:(?:[a-z]{2}-\d+/\d+/\d+(?::\d+)?|ae\d+|reth\d+|lag\d+|irb|vtep\S*|esi\.\d+)(?:\.\d+)?|\.local\.\.\d+)')


def mac_junos(text):
    def handle(raw, value):
        if matches(value, (r'MAC flags \(.*', r'[A-Z]{1,2} - .*', r'Ethernet switching table\s*:\s*\d+ entries.*', r'Routing instance\s*:\s*\S+',
                           r'Vlan\s+MAC\s+MAC\s+Logical\s+Active', r'name\s+address\s+flags\s+interface\s+source',
                           r'Vlan\s+MAC\s+MAC\s+Logical', r'name\s+address\s+flags\s+interface', r'MAC database for switching instance.*',
                           r'Vlan\s+MAC\s+MAC\s+Age\s+GBP\s+Logical\s+NH\s+MAC\s+RTR', r'name\s+address\s+flags\s+Tag\s+interface\s+Index\s+property\s+ID',
                           r'VLAN\s+MAC address\s+Type.*', r'\s*(?:\w+ )?entries?.*')):
            return []
        if value.startswith('(') or re.match(r'\s+\S+, ', raw) and ' - ' in value or re.match(r'\s+[A-Z]{1,4} - .*\)?$', raw):
            return []           # wrapped legend of the MAC flags
        m = re.fullmatch(r'(\S+)\s+(' + MAC + r'|\*)\s+(\S+)\s+(.*)', value)
        if not m:
            return None
        if m[2] == '*':
            return []           # flood entry
        flags = m[3].upper()
        # The logical interface is the first token that is an interface name: later releases insert Age and GBP Tag columns
        # (a dash or a number) before it and NH Index, MAC property and RTR ID after it.
        cell = next((token for token in m[4].split() if JUNOS_IFL.fullmatch(token)), None)
        if cell is None:
            return None
        # ELS prints the VLAN by name; the tag comes from a join with `show vlans`, never from a guess.
        return record('mac_entry', mac=normalize_mac(m[2]), vlan_id=vlan(m[1]), vlan_name=m[1], port=port(cell),
                      type='dynamic' if flags.startswith('D') else 'static' if flags.startswith(('S', 'P')) else None)
    return scan(text, handle)


# --- ARP -----------------------------------------------------------------------------------

# EOS prints a legend above the ARP and ND tables ("not learned" marks an entry without a MAC table row).
EOS_NEIGHBOR_LEGEND = (r'Legend:', r'not learned: .*', r'-: Static .*', r'\*: .*',
                       r'Flags: .*', r'(?:G|R|CP|PS|RO|CC|#) - .*')      # NX-OS flag legend above ARP and ND


IOS_ND_CACHE_TIMER = r'ND cache expire time is [0-9]+ seconds'


def ipv6_table(text):
    first = next((line.strip() for line in text.splitlines() if line.strip() and not matches(line.strip(), EOS_NEIGHBOR_LEGEND + (IOS_ND_CACHE_TIMER,))), '')
    if first.startswith('IPv6 '):
        return True
    try:
        return ipaddress.ip_address(first.split()[0]).version == 6
    except (ValueError, IndexError):
        return False


def neighbors(text, style):
    """ARP (IPv4) or ND (IPv6) cache: the two queries share the normalized table, the header tells them apart."""
    if ipv6_table(text):
        return scan(text, lambda raw, value: [] if matches(value, (r'IPv6 Address.*', r'IPv6 Adjacency Table.*', IOS_ND_CACHE_TIMER, r'Address\s+Age\s+MAC Address\s+Pref.*', r'Total number of entries:\s*\d+', r'Flags:.*', r'[*+#]\s*-\s.*') + EOS_NEIGHBOR_LEGEND)
                    else neighbor_line(value, style))
    return arp_rows(text, style)


def interface_cell(cell):
    """First interface of an ARP interface cell ("Vlan10, Ethernet1", "irb.10 [ge-0/0/1.0]"); None if blank."""
    cell = (cell or '').strip()
    if not cell:
        return None
    return port(re.split(r'[,\s]', cell)[0])


def arp_rows(text, style, *, nxos_bare_header=False):
    vrf = [None]

    def handle(raw, value):
        m = re.fullmatch(r'IP ARP Table for context (\S+)', value) if style == 'nxos' else None
        if m:
            vrf[0] = m[1]
            return []
        if nxos_bare_header and value == 'IP ARP Table':
            return []
        if matches(value, (r'Protocol\s+Address\s+Age.*', r'Address\s+Age.*', r'MAC Address\s+Address\s+Name.*', r'MAC Address\s+Address\s+Interface.*',
                           r'IP ARP Table for context.*', r'Total number of entries:\s*\d+', r'Total entries:\s*\d+', r'Flags:.*',
                           r'[*+#]\s*-\s.*', r'(?:CP|PS|RO|D)\s*-\s.*') + EOS_NEIGHBOR_LEGEND):
            return []
        if style == 'ios':
            m = re.fullmatch(r'Internet\s+(\S+)\s+(\S+)\s+(' + MAC + r'|Incomplete)\s+ARPA(?:\s+(\S+))?', value)
            fields = (m[1], m[3], m[4]) if m else None
        elif style == 'nxos':
            m = re.fullmatch(r'(\S+)\s+(\S+)\s+(' + MAC + r'|INCOMPLETE)(?:\s+(\S+))?(?:\s+(?:[*+#]|CP|PS|RO|D))*', value)
            fields = (m[1], m[3], m[4]) if m else None
        elif style == 'eos':
            m = re.fullmatch(r'(\S+)\s+(\S+)\s+(' + MAC + r')\s+(\S.*)', value)
            fields = (m[1], m[3], m[4]) if m else None
        else:       # junos: MAC address interface [physical] flags
            m = re.fullmatch(r'(' + MAC + r')\s+(\S+)\s+(\S+)(?:\s+\[\S+\])?(?:\s+[a-z][a-z-]*)+', value)       # flags: none, permanent published, ...
            fields = (m[2], m[1], m[3]) if m else None
        if not fields:
            return None
        address = str(ipaddress.ip_address(fields[0]))
        interface = interface_cell(fields[2])
        known = re.fullmatch(MAC, fields[1])
        return record('neighbor_l3', ip=address, mac=normalize_mac(fields[1]) if known else None, interface=interface, vrf=vrf[0],
                      vlan_id=vlan(interface or ''),
                      type='interface' if style == 'ios' and m[2] == '-' and interface and known else None)
    return scan(text, handle)


# --- LLDP ---------------------------------------------------------------------------------

def cisco_lldp(text, style='ios', *, check_total=False):
    """`show lldp neighbors detail`: one block per neighbour. System Description, the management address list,
    media capabilities and the MED section are free text; they are recognized by their section, not parsed."""
    rows, unknown = [], []
    current, section, total = None, None, None
    start = 'Local Intf:' if style == 'ios' else 'Chassis id:'
    simple = {'chassis id', 'chassis type', 'port type', 'port description', 'time remaining', 'time to live', 'system capabilities',
              'vlan id', 'peer source mac', 'auto negotiation', 'media attachment unit type', 'mtu', 'max frame size',
              'tac support', 'technical support', 'management address ipv6', 'local port id', 'local intf service instance'}
    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value:
            section = None if section == 'description' else section
            continue
        count = re.fullmatch(r'Total (?:entries|neighbors) displayed:\s*(\d+)', value, re.I)
        if count:
            total = int(count[1])
            continue
        if re.fullmatch(r'-{10,}', value):
            continue
        if current is None and matches(value, (r'Capability codes:', r'\(\w\) .*', r'Device ID\s+Local Intf\s+Hold-time\s+Capability\s+Port ID')):
            continue            # NX-OS prints the legend and a summary header above the detail blocks
        if value.startswith(start):
            current = record('lldp_neighbor')
            rows.append(current)
            section = None
        if current is None:
            unknown.append({'line': number, 'text': raw})
            continue
        indented = raw[:1].isspace()
        if re.fullmatch(r'Auto Negotiation - .*', value) or re.fullmatch(r'[A-Za-z][A-Za-z ]* - not advertised', value):
            continue
        m = re.fullmatch(r'([A-Za-z][A-Za-z0-9 /().-]*?):\s*(.*)', value)
        key = m[1].lower() if m else None
        if section == 'description' and key not in ('time remaining', 'time to live', 'system capabilities', 'enabled capabilities'):
            continue        # System Description is wrapped over several lines, some with a colon
        if section in ('media', 'med', 'addresses') and indented and key not in ('ip', 'ipv6'):
            continue
        if m is None:
            unknown.append({'line': number, 'text': raw})
            continue
        argument = m[2].strip()
        if key == 'other' and section == 'addresses' and indented:
            continue        # a non-IP management address (OID/MAC) is listed beside the IP
        if not (indented and section == 'addresses'):
            section = None if section in ('media', 'addresses') or section == 'description' else section
        try:
            if key in ('local intf', 'local port id') and argument:
                current['local_port'] = port(argument)
            elif key == 'system name':
                current['neighbor'] = None if argument.lower() in ('not advertised', '') else argument
            elif key == 'port id':
                current['neighbor_port'] = argument
            elif key == 'enabled capabilities':
                current['capabilities'] = capabilities(argument)
            elif key in ('management address', 'ip'):
                if argument and argument.lower() != 'not advertised':
                    address = str(ipaddress.ip_address(argument))
                    if current['management_ip'] not in (None, address):
                        unknown.append({'line': number, 'text': raw})       # several addresses: never overwritten
                    current['management_ip'] = current['management_ip'] or address
            elif key == 'ipv6':
                ipaddress.ip_address(argument)
            elif key == 'management addresses':
                section = 'addresses'
            elif key == 'system description':
                section = 'description'
            elif key == 'physical media capabilities':
                section = 'media'
            elif key == 'med information':
                section = 'med'
            elif key in simple or section == 'med':
                continue
            else:
                unknown.append({'line': number, 'text': raw})
        except ValueError:
            unknown.append({'line': number, 'text': raw})
    if check_total and total != len(rows):
        unknown.append({'line': 1, 'text': f'LLDP entry total {total} differs from the {len(rows)} parsed blocks'})
    if check_total and any(not row['local_port'] or not row['neighbor_port'] for row in rows):
        unknown.append({'line': 1, 'text': 'incomplete LLDP neighbor block'})
    return rows, unknown


def eos_lldp_detail(text):
    """EOS `show lldp neighbors detail`: "Interface E detected N LLDP neighbors", then a block per `Neighbor`.
    TLVs are "  - Name: value" lines with attributes indented below; wrapped strings and hex dumps are not parsed."""
    rows, unknown = [], []
    local, current, tlv = None, None, None
    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value:
            continue
        m = re.fullmatch(r'Interface (\S+) detected \d+ LLDP neighbors?:?', value)
        if m and not raw[:1].isspace():
            try:
                local = port(m[1])
            except ValueError:
                local = None
                unknown.append({'line': number, 'text': raw})
            current = tlv = None
            continue
        if local is None:
            unknown.append({'line': number, 'text': raw})
            continue
        if re.fullmatch(r'Neighbor \S+/".*", age \d+ seconds?', value) and re.match(r' {2}\S', raw):
            current = record('lldp_neighbor', local_port=local)
            rows.append(current)
            tlv = None
            continue
        if current is None:
            unknown.append({'line': number, 'text': raw})
            continue
        duration = r'(?:\d+ days?, )?\d+:\d{2}:\d{2}'
        if re.fullmatch(r' {2}Discovered ' + duration + r' ago; Last changed ' + duration + r' ago', raw):
            continue
        m = re.match(r' {2}- ([^:]+):\s*(.*)', raw)
        if m:
            tlv, argument = m[1].rstrip(), m[2].strip()
            if tlv == 'System Name':
                current['neighbor'] = argument.strip('"') or None
            elif tlv.startswith('Unknown organizationally-defined TLV'):
                tlv = None
            continue
        m = re.match(r' {2}- (\S.*)', raw)
        if m:                         # a TLV header without a value ("- IEEE802.3 MAC/PHY Configuration/Status")
            tlv = m[1].rstrip(':')
            continue
        m = re.match(r' {4}(\S[^:]*):\s*(.*)', raw)
        if m and tlv is not None:
            key, argument = m[1].rstrip(), m[2].strip()
            if key == 'Port ID' and tlv.startswith('Port ID type'):
                current['neighbor_port'] = argument.strip('"') or None
            elif key == 'Enabled Capabilities' and tlv.startswith('System Capabilities'):
                current['capabilities'] = capabilities(argument)
            elif key == 'Management Address' and tlv.startswith('Management Address') and current['management_ip'] is None:
                try:
                    current['management_ip'] = str(ipaddress.ip_address(argument))
                except ValueError:
                    pass            # a MAC or other address subtype is not a management IP
            continue
        if re.match(r' {5,}\S', raw) or (tlv is not None and re.match(r' {4}\S', raw)):
            continue                # wrapped values, hex dumps, MAU type lists
        unknown.append({'line': number, 'text': raw})
    return rows, unknown


def lldp_summary(text, style):
    """EOS / Junos `show lldp neighbors`: fixed columns taken from the header, so names may hold spaces."""
    starts = []

    def handle(raw, value):
        if matches(value, (r'Last table change time.*', r'Number of table (?:inserts|deletes|drops|age-outs)\s*:.*')):
            return []
        if style == 'eos' and re.match(r'Port\s+Neighbor Device ID\s+Neighbor Port ID\s+TTL', value):
            starts[:] = columns(raw, 'Neighbor Device ID', 'Neighbor Port ID', 'TTL')
            return []
        if style == 'junos' and re.match(r'Local Interface\s+Parent Interface\s+Chassis Id\s+Port info\s+System Name', value):
            starts[:] = columns(raw, 'Parent Interface', 'Chassis Id', 'Port info', 'System Name')
            return []
        if not starts:
            return None
        local = raw[:starts[0]].strip()
        if style == 'eos':
            name, remote_port = cut(raw, starts, 0), cut(raw, starts, 1)
            return record('lldp_neighbor', local_port=port(local), neighbor=name or None, neighbor_port=remote_port or None)
        name, remote_port = cut(raw, starts, 3), cut(raw, starts, 2)
        return record('lldp_neighbor', local_port=port(local), neighbor=name or None, neighbor_port=remote_port or None)
    return scan(text, handle)


# --- routing peers, port-channels, spanning tree -------------------------------------------

OSPF_ROLES = {'DR', 'BDR', 'DROTHER', '-'}
# EOS separates the words in `2 WAYS`; the slash/role is a separate optional cell part.
OSPF_STATE_CELL = r'(\S+(?:[ \t]+WAYS)?(?:[ \t]*/[ \t]*\S+)?)'
EOS_OSPF_HEADER = re.compile(r'Neighbor ID\s+Instance\s+VRF\s+Pri\s+State\s+Dead Time\s+Address\s+Interface')
_EOS_OSPF_ROW = re.compile(r'(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s+' + OSPF_STATE_CELL
                           + r'\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)')


def ospf_neighbors(text, style, *, eos_details=False):
    """IOS `show ip ospf neighbor` (Neighbor ID, Pri, State, Dead Time, Address, Interface), EOS (Instance and VRF added),
    NX-OS (Up Time instead of Dead Time, VRF in the process line) and Junos (Address first, state without a DR role)."""
    nx_vrf = [None]

    def handle(raw, value):
        if style == 'nxos':
            m = re.fullmatch(r'OSPF Process ID \S+ VRF (\S+)', value)
            if m:
                nx_vrf[0] = m[1]
                return []
            if matches(value, (r'Total number of neighbors: \d+', r'Neighbor ID\s+Pri\s+State\s+Up Time\s+Address\s+Interface')):
                return []
            m = re.fullmatch(r'(\d+\.\d+\.\d+\.\d+)\s+\d+\s+'+OSPF_STATE_CELL+r'\s+\S+\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)', value)
            vrf = nx_vrf[0]
            fields = (m[1], m[2], m[3], m[4]) if m else None
        elif style == 'junos':
            if matches(value, (r'Address\s+(?:Intf|Interface)\s+State\s+ID\s+Pri\s+Dead',)):
                return []
            m = re.fullmatch(r'(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(Down|Attempt|Init|2Way|ExStart|Exchange|Loading|Full)\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\d+', value)
            vrf = None
            fields = (m[4], m[3].upper(), m[1], m[2]) if m else None
        elif style == 'eos':
            if EOS_OSPF_HEADER.fullmatch(value):
                return []
            m = _EOS_OSPF_ROW.fullmatch(value)
            vrf = m[3] if m else None
            fields = (m[1], m[5], m[7], m[8]) if m else None
        else:
            if matches(value, (r'Neighbor ID\s+Pri\s+State\s+Dead Time\s+Address\s+Interface',)):
                return []
            m = re.fullmatch(r'(\d+\.\d+\.\d+\.\d+)\s+\d+\s+'+OSPF_STATE_CELL+r'\s+\S+\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)', value)
            vrf = None
            fields = (m[1], m[2], m[3], m[4]) if m else None
        if not fields:
            return None
        state, _, role = re.sub(r'\s+', '', fields[1]).partition('/')
        state = {'twoway': '2way', '2ways': '2way'}.get(state.lower(), state.lower())
        role = role or None
        if role is not None and role not in OSPF_ROLES:
            return None
        address = ipaddress.ip_address(fields[2])
        row = record('ospf_neighbor', neighbor_id=str(ipaddress.ip_address(fields[0])), address=str(address),
                     interface=port(fields[3]), state=state, role=None if role == '-' else role, vrf=vrf)
        if style == 'junos':
            row['address_family'] = 'ipv4'
        elif style == 'eos' and eos_details:
            if not re.fullmatch(r'\d\d:\d\d:\d\d', m[6]):
                return None
            row.update(instance=int(m[2]), priority=int(m[4]), dead_time=m[6])
        return row
    return scan(text, handle)


BGP_STATE_NAMES = {word.lower(): word for word in ('Idle', 'Connect', 'Active', 'OpenSent', 'OpenConfirm', 'Established',
                                                'Idle(admin)', 'Idle(prefixlimit)')}
BGP_STATE_NAMES.update({'estab': 'Established', 'establ': 'Established', 'idle (admin)': 'Idle(admin)',
                        'shut (admin)': 'Idle(admin)', 'shut(admin)': 'Idle(admin)',
                        'idle (pfxct)': 'Idle(prefixlimit)', 'idle(pfxct)': 'Idle(prefixlimit)',
                        'idle (prefixlimit)': 'Idle(prefixlimit)'})
BGP_STATES = set(BGP_STATE_NAMES)


NXOS_BGP_WRAPPED_COUNTERS = re.compile(r'[ \t]+\d[ \t]+\d+(?:\.\d+)?(?:[ \t]+\d+){5}[ \t]+\S+[ \t]+\S.*')


def _nxos_bgp_address_only(line):
    try:
        ipaddress.ip_address(line.rstrip().split('%')[0])
    except ValueError:
        return False
    return not line[:1].isspace()


def nxos_join_wrapped_peers(text):
    """NX-OS prints a neighbor longer than the 15-character column (IPv6) alone and its counters indented on the next
    line. Such a pair becomes one row on the address line and the counter line is left blank, so line numbers of
    `unparsed` stay those of the capture; an address or counter line without its partner stays as printed."""
    lines = text.split('\n')
    for i in range(len(lines) - 1):
        if _nxos_bgp_address_only(lines[i]) and NXOS_BGP_WRAPPED_COUNTERS.fullmatch(lines[i + 1].rstrip('\r')):
            lines[i] = lines[i].rstrip() + ' ' + lines[i + 1].strip()
            lines[i + 1] = ''
    return '\n'.join(lines)


def bgp_peers(text, style):
    """IOS `show ip bgp summary` (State/PfxRcd: a number means Established) and EOS (State and PfxRcd columns)."""
    vrf = ['default'] if style in ('eos', 'fortinet') else [None]
    if style == 'nxos':
        text = nxos_join_wrapped_peers(text)

    def handle(raw, value):
        m = re.fullmatch(r'BGP summary information for VRF (\S+?)(?:, address family .*)?', value)
        if m:
            vrf[0] = m[1]
            return []
        # FortiOS (80F 8.0.2): `VRF default(0) BGP router identifier ..., local AS number ...`; VRF 0 is default.
        m = re.fullmatch(r'VRF (\S+?)(?:\((\d+)\))? BGP router identifier .*', value) if style == 'fortinet' else None
        if m:
            vrf[0] = 'default' if m[1] in ('0', 'default') else m[1]
            return []
        if style == 'fortinet' and re.fullmatch(r'Total number of neighbors \d+', value):
            return []
        if matches(value, (r'BGP router identifier .*', r'BGP table version .*', r'BGP (?:attribute|community) entries .*', r'BGP community <REDACTED> \[\d+/\d+\].*', r'Router identifier .*', r'Neighbor\s+V\s+AS\s+.*',
                           r'\d+(?:/\d+)? .* (?:using|entries) .*', r'BGP using .*', r'BGP activity .*', r'Dampening .*', r'% BGP (?:not active|inactive)', r'(?:\d+ )?Neighbor.*')) or matches(value, (r'.*, local AS number \d+',)):
            return []
        if style == 'eos':
            m = re.fullmatch(r'(\S+)\s+(\d)\s+(\d+(?:\.\d+)?)\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+\s+(\S+(?:\s+\([^()\s]+\))?)(?:\s+(\d+)\s+(\d+))?', value)
            fields = (m[1], m[3], m[4], m[5]) if m else None
        else:
            m = re.fullmatch(r'(\S+)\s+(\d)\s+(\d+(?:\.\d+)?)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+\s+(\S+(?:\s+\([^()\s]+\))?)', value)
            fields = (m[1], m[3], m[4], None) if m else None
        if not fields:
            return None
        address = str(ipaddress.ip_address(fields[0].split('%')[0]))
        state, prefixes = re.sub(r'\s+', ' ', fields[2]), fields[3]
        if style in ('ios', 'nxos', 'fortinet'):
            prefixes = state if state.isdigit() else None
            state = 'Established' if state.isdigit() else state
        elif state.lower() == 'estab':
            state = 'Established'
        if state.lower() not in BGP_STATES:
            return None
        return record('bgp_peer', neighbor=address, remote_as=fields[1], state=BGP_STATE_NAMES[state.lower()],
                      prefixes=int(prefixes) if prefixes else None, vrf=vrf[0])
    return scan(text, handle)


LAG_FLAGS = (('P', 'bundled'), ('D', 'down'), ('I', 'standalone'), ('H', 'hot-standby'), ('s', 'suspended'), ('w', 'waiting'), ('u', 'unsuitable'),
             ('d', 'default'), ('m', 'min-links'), ('M', 'min-links'), ('f', 'failed'), ('N', 'not-in-use'), ('i', 'incompatible'),
             ('C', 'transmit-disabled'), ('U', 'in-use'), ('b', 'bfd-wait'), ('r', 'module-removed'))
LAG_FLAG_CHARS = set('PDIHswudmMfNiCURSAGEFapbr+-^*')


def lag_state(flags):
    """Member state from the flag letters ("P", "PG+"); a flag letter this parser does not know is an unrecognized line."""
    if not set(flags) <= LAG_FLAG_CHARS:
        raise ValueError
    return next((name for letter, name in LAG_FLAGS if letter in flags), None) or 'unknown'


def lag_summary(text, style):
    """IOS `show etherchannel summary` / EOS `show port-channel dense`: legend, counters, then `Po1(SU) proto Gi0/1(P) ...`
    with the member list wrapped onto indented continuation lines."""
    state = {'lag': None}

    def members(items):
        out = []
        for item in items:
            m = re.fullmatch(r'([A-Za-z]+[0-9/.]+)\(([A-Za-z+^*-]+)\)', item)
            if m is None:
                raise ValueError
            out.append({'port': port(m[1]), 'state': lag_state(m[2])})
        return out

    def handle(raw, value):
        if matches(value, (r'Flags:.*', r'Flags', r'Number of (?:channel-groups|aggregators|channels)(?: in use)?:\s*\d+', r'Group\s+Port-channel\s+Protocol\s+Ports',
                           r'Port-Channel\s+Protocol\s+Ports', r'Group\s+Port-\s+Type\s+Protocol\s+Member Ports', r'Channel',
                           r'E - Inactive.*', r'[A-Za-z*^+-] - [A-Za-z].*', r'\s*\S ?-\s.*')) and not re.match(r'\s*\d', value):
            return []
        if style == 'nxos':
            m = re.fullmatch(r'(?:(\d+)\s+)?(Po\d+)\(([A-Za-z]+)\)\s+(\S+)\s+(\S+)\s*(.*)', value)      # NX-OS adds a Type column (Eth)
            m = m and (m[0], m[1], m[2], m[3], m[5], m[6])
        else:
            m = re.fullmatch(r'(?:(\d+)\s+)?(Po\d+)\(([A-Za-z]+)\)\s+(\S+)\s*(.*)', value)
            m = m and (m[0], m[1], m[2], m[3], m[4], m[5])
        if m:
            flags = m[3]
            if not set(flags) <= LAG_FLAG_CHARS:
                return None
            status = 'down' if 'D' in flags else 'up' if 'U' in flags else 'not in use' if 'N' in flags else None
            protocol = re.sub(r'\(.\)$', '', m[4])
            protocol = {'-': None, 'none': None, 'lacp': 'LACP', 'pagp': 'PAgP', 'static': 'Static'}.get(protocol.lower(), protocol)
            state['lag'] = record('lag', name=port(m[2]), protocol=protocol, status=status, members=members(m[5].split()))
            return state['lag']
        if state['lag'] is not None and re.match(r'\s+\S', raw):
            state['lag']['members'].extend(members(value.split()))
            return []
        return None
    return scan(text, handle)


STP_ROLE = {'desg': 'designated', 'root': 'root', 'altn': 'alternate', 'back': 'backup', 'mstr': 'master', 'dis': 'disabled', 'bdrg': 'boundary',
            'designated': 'designated', 'alternate': 'alternate', 'backup': 'backup', 'master': 'master', 'disabled': 'disabled'}
STP_STATE = {'fwd': 'forwarding', 'blk': 'blocking', 'lrn': 'learning', 'lis': 'listening', 'bkn': 'broken', 'dis': 'disabled', 'off': 'disabled',
             'forwarding': 'forwarding', 'discarding': 'discarding', 'blocking': 'blocking', 'learning': 'learning', 'listening': 'listening',
             'disabled': 'disabled'}


def stp_tree(text, style):
    """IOS `show spanning-tree` / EOS: one block per VLAN or MST instance; only the port table is a record."""
    state = {'instance': None, 'ports': False}

    def handle(raw, value):
        m = re.fullmatch(r'(VLAN\d{4}|MST\d+|Vlan\d+|RSTP\d*|PVST\d*)', value)
        if m and not raw[:1].isspace():
            state.update(instance=m[1], ports=False)
            return []
        if value in ('No spanning tree instances exist.', 'No spanning tree instance exists.'):
            return []
        if state['instance'] is None:
            return None
        if re.fullmatch(r'Interface\s+Role\s+(?:Sts|State)\s+Cost\s+Prio\.Nbr\s+Type', value):
            state['ports'] = True
            return []
        if not state['ports']:
            if matches(value, (r'Spanning tree enabled protocol \S+', r'Root ID\s+Priority\s+\d+', r'Bridge ID\s+Priority\s+\d+.*', r'Address\s+[0-9a-fA-F.:]+',
                               r'This bridge is the root', r'Hello Time\s+.*', r'Aging Time\s+.*', r'Port\s+\d+ \(.*\) of \S+ is .*', r'Port path cost.*',
                               r'Designated .*', r'Number of transitions .*', r'Spanning tree.*', r'Bridge Identifier .*', r'Configured hello .*',
                               r'Current root .*', r'Root port .*', r'Cost\s+\d+.*', r'Port\s+\d+.*')):
                return []
            return None
        m = re.fullmatch(r'(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+\.\d+)\s+(.+)', value)
        if m is None:
            return None
        role, status = STP_ROLE.get(m[2].lower()), STP_STATE.get(m[3].lower())
        if role is None or status is None:
            return None
        return record('stp_port', instance=state['instance'], port=port(m[1]), role=role, state=status, cost=int(m[4]))
    return scan(text, handle)


# --- routes -------------------------------------------------------------------------------

IOS_ROUTE_DETAIL = (r'Route metric is .*', r'Last update from .*', r'Tag \S+.*', r'AS Hops .*', r'Route tag .*', r'MPLS label: .*',
                    r'Redistributing via .*', r'Advertised by .*', r'Originating router is .*', r'Routing Descriptor Blocks:',
                    r'Distance: .*', r'Traffic Share .*', r'Multipath .*', r'Forwarding .*', r'Installed .*',
                    r'% (?:Network|Subnet) not in table', r'% Route not found', r'Gateway of last resort .*', r'Codes: .*', r'\S[^,]* - [^,]+,?',
                    r'[<>].*', r'\d+\.\d+\.\d+\.\d+/\d+ is (?:variably )?subnetted.*', r'Known via ".*')


def protocol_of(via):
    word = via.split()[0].lower() if via else None
    return {'connected': 'connected', 'static': 'static', 'rip': 'rip', 'ospf': 'ospf', 'bgp': 'bgp', 'eigrp': 'eigrp',
            'isis': 'isis', 'local': 'local'}.get(word, word)


IOS_ROUTE_CODES = {'L': 'local', 'C': 'connected', 'S': 'static', 'R': 'rip', 'M': 'mobile', 'B': 'bgp', 'D': 'eigrp', 'EX': 'eigrp',
                   'O': 'ospf', 'IA': 'ospf', 'N1': 'ospf', 'N2': 'ospf', 'E1': 'ospf', 'E2': 'ospf', 'i': 'isis', 'su': 'isis',
                   'L1': 'isis', 'L2': 'isis', 'ia': 'isis', 'o': 'odr', 'P': 'static', 'H': 'nhrp', 'l': 'lisp', 'U': 'static',
                   'a': 'application'}
_IOS_PREFIX = r'(\d+\.\d+\.\d+\.\d+(?:/\d+|\s+\d+\.\d+\.\d+\.\d+)?)'


def route_ios_table(text):
    """IOS / IOS XE `show ip route`: legend, "Gateway of last resort", "P is variably subnetted" parents and the
    route lines ("C  P is directly connected, X", "O  P [110/2] via N, age, X", prefix alone + `[ad/m] via` continuation)."""
    state = {'prefix': None, 'protocol': None, 'in_codes': False, 'group_mask': None}

    def prefix_of(raw_prefix):
        parts = raw_prefix.split()
        if len(parts) == 2 or '/' in parts[0]:
            return str(ipaddress.ip_network('/'.join(parts), strict=False))
        if state['group_mask'] is None:
            raise ValueError('route prefix has no known mask')
        return str(ipaddress.ip_network(f"{parts[0]}/{state['group_mask']}", strict=False))

    def hop(address, rest):
        found = re.fullmatch(r'(?:, \d[\d:wdhm]*)?(?:, (\S+))?', rest or '')
        if found is None:
            raise ValueError
        return record('route', prefix=state['prefix'], next_hop=str(ipaddress.ip_address(address)),
                      interface=port(found[1]) if found[1] else None, protocol=state['protocol'])

    def handle(raw, value):
        if value.startswith('Codes:'):
            state['in_codes'] = True
            return []
        if state['in_codes'] and re.match(r' {7}\S.* - ', raw):
            return []
        state['in_codes'] = False
        if matches(value, (r'Gateway of last resort is .*', r'Gateway of last resort not set', r'Gateway of last resort is not set')):
            state.update(prefix=None, protocol=None, group_mask=None)
            return []
        group = re.fullmatch(_IOS_PREFIX + r' is (variably )?subnetted, \d+ subnets?(?:, \d+ masks?)?', value)
        if group:
            state.update(prefix=None, protocol=None, group_mask=None)
            if not group[2] and ('/' in group[1] or len(group[1].split()) == 2):
                state['group_mask'] = ipaddress.ip_network('/'.join(group[1].split()), strict=False).prefixlen
            return []
        m = re.fullmatch(r'\[\d+/\d+\] via (\S+?)(,.*)?', value)
        if m and state['prefix']:
            return hop(m[1], m[2])
        m = re.fullmatch(r'([A-Za-z][A-Za-z0-9]?(?: [A-Za-z][A-Za-z0-9]?)?)[*+%]*\s+' + _IOS_PREFIX + r'(?:\s+(.*))?', value)
        if not m:
            return None
        state.update(prefix=None, protocol=None)
        codes = m[1].split()
        if not all(code in IOS_ROUTE_CODES for code in codes):
            return None
        state.update(prefix=prefix_of(m[2]), protocol=IOS_ROUTE_CODES[codes[0]])
        tail = (m[3] or '').strip()
        if not tail:
            return []                       # next hops follow on continuation lines
        d = re.fullmatch(r'is directly connected, (\S+)', tail)
        if d:
            return record('route', prefix=state['prefix'], interface=port(d[1]), protocol=state['protocol'])
        d = re.fullmatch(r'is a summary(?:, [\d:wdhm]+)?, (\S+)', tail)
        if d:
            return record('route', prefix=state['prefix'], interface=port(d[1]), protocol=state['protocol'])
        d = re.fullmatch(r'\[\d+/\d+\](?: via (\S+?)(,.*)?)?', tail)
        if d:
            return hop(d[1], d[2]) if d[1] else []
        return None
    return scan(text, handle)


def route_ios(text):
    """IOS / IOS XE IPv4/IPv6 detail lookup: "Routing entry for P[ M]", one record per next hop."""
    if re.search(r'(?m)^Codes: ', text) or re.search(r'(?m)^Gateway of last resort', text):
        return route_ios_table(text)
    state = {'prefix': None, 'protocol': None, 'hops': 0, 'ipv6_paths': False}
    rows = []

    def prefix_of(raw_prefix):
        if ':' in raw_prefix:
            return str(ipaddress.IPv6Network(raw_prefix, strict=False))
        found = re.fullmatch(r'(\d+\.\d+\.\d+\.\d+)(?:/(\d+)|\s+(\d+\.\d+\.\d+\.\d+))?', raw_prefix)
        if found is None:
            raise ValueError
        if found[2]:
            return str(ipaddress.ip_network(f'{found[1]}/{found[2]}', strict=False))
        if found[3]:
            return str(ipaddress.ip_network(f'{found[1]}/{found[3]}', strict=False))
        return str(ipaddress.ip_network(found[1] + '/32'))      # classful host route without a mask

    def handle(raw, value):
        m = re.fullmatch(r'Routing entry for (\S+(?: \d+\.\d+\.\d+\.\d+)?)(?:,.*)?', value)
        if m:
            state.update(prefix=prefix_of(m[1]), protocol=None, hops=0, ipv6_paths=False)
            return []
        if state['prefix'] is None:
            return [] if matches(value, IOS_ROUTE_DETAIL) else None
        m = re.match(r'Known via "([^"]+)"', value)
        if m:
            state['protocol'] = protocol_of(m[1])
            return []
        if ':' in state['prefix']:
            if value == 'Routing paths:':
                state['ipv6_paths'] = True
                return []
            if matches(value, (r'Route count is \d+/\d+, share count \d+',
                               r'Last updated [\d:wdhm]+ ago', r'From [0-9a-fA-F:.]+(?:%\S+)?')):
                return []
            if state['ipv6_paths']:
                m = re.fullmatch(r'([0-9a-fA-F:.]+)(?:%[^,\s]+)?, (\S+)', value)
                if m:
                    state['hops'] += 1
                    return record('route', prefix=state['prefix'], next_hop=str(ipaddress.IPv6Address(m[1])),
                                  interface=port(m[2]), protocol=state['protocol'])
                m = re.fullmatch(r'directly connected via (\S+)', value)
                if m:
                    state['hops'] += 1
                    return record('route', prefix=state['prefix'], interface=port(m[1]), protocol=state['protocol'])
        m = re.fullmatch(r'\*?\s*directly connected, via (\S+)', value)
        if m:
            state['hops'] += 1
            return record('route', prefix=state['prefix'], interface=port(m[1]), protocol=state['protocol'])
        m = re.fullmatch(r'\*?\s*(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)(?:%\S+)?(?:, from \S+)?(?:, [\d:wdhm]+ ago)?(?:, via (\S+))?', value)
        if m and not value.startswith('Route'):
            state['hops'] += 1
            return record('route', prefix=state['prefix'], next_hop=str(ipaddress.ip_address(m[1])),
                          interface=port(m[2]) if m[2] else None, protocol=state['protocol'])
        return [] if matches(value, IOS_ROUTE_DETAIL) else None
    rows, unknown = scan(text, handle)
    if state['prefix'] and not state['hops']:
        rows.append(record('route', prefix=state['prefix'], protocol=state['protocol']))
    return rows, unknown


def route_nxos(text):
    state = {'prefix': None, 'vrf': None}

    def protocol(value):
        word = value.lower()
        if word == 'is-is' or word.startswith('is-is-'):
            return 'isis'
        word = word.split('-')[0]
        return {'direct': 'connected', 'ospfv3': 'ospf'}.get(word, word)

    def handle(raw, value):
        m = re.fullmatch(r'IP(?:v6)? Rout(?:e Table|ing Table) for VRF "([^"]+)"', value)
        if m:
            state['vrf'] = m[1]
            return []
        if matches(value, (r"'\*' denotes .*", r"'\*\*' denotes .*", r"'\[x/y\]' denotes .*", r"'%<string>' in via output .*",
                           r"'%<string>'.*", r"'\[x/y\]'.*", r"'\*'.*", r'Route not found')):
            return []
        m = re.fullmatch(r'([0-9a-fA-F:.]+/\d+), ubest/mbest: \d+/\d+(?:, .*)?', value)
        if m:
            state['prefix'] = str(ipaddress.ip_network(m[1], strict=False))
            return []
        m = re.fullmatch(r'\*{0,2}via ([0-9a-fA-F:.]+)(?:%\S+)?(?:, ([A-Za-z][^\s,]*))?, \[\d+/\d+\], [^,]+, ([\w-]+)(?:, .*)?', value)
        if m and state['prefix']:
            return record('route', prefix=state['prefix'], next_hop=None if protocol(m[3]) in ('connected', 'local') else str(ipaddress.ip_address(m[1])),
                          interface=port(m[2]) if m[2] else None, protocol=protocol(m[3]), vrf=state['vrf'])
        m = re.fullmatch(r'\*{0,2}via ([A-Za-z][^\s,]*), \[\d+/\d+\], [^,]+, ([\w-]+)(?:, .*)?', value)
        if m and state['prefix']:
            return record('route', prefix=state['prefix'], interface=port(m[1]), protocol=protocol(m[2]), vrf=state['vrf'])
        return None
    return scan(text, handle)


def route_eos(text, *, missing_hops=None):
    """Parse EOS route rows and report prefix lines with no continuation to a lookup caller."""
    state = {'vrf': None, 'prefix': None, 'protocol': None, 'in_codes': False, 'pending': False}
    # Full source codes from the cEOS legend; L means VRF leaked, not local.
    codes = {'C': 'connected', 'S': 'static', 'K': 'kernel', 'B': 'bgp', 'B I': 'bgp', 'B E': 'bgp',
             'I': 'isis', 'I L1': 'isis', 'I L2': 'isis', 'R': 'rip',
             'A': 'aggregate', 'A B': 'aggregate', 'A O': 'aggregate', 'DH': 'dhcp'}
    codes.update({base + suffix: 'ospf' for base in ('O', 'O3')
                  for suffix in ('', ' IA', ' E1', ' E2', ' N1', ' N2')})

    def route(prefix, hop, interface, code):
        return record('route', prefix=prefix, next_hop=hop, interface=port(interface) if interface else None,
                      protocol=codes.get(code, code.lower()), vrf=state['vrf'])

    def close_prefix():
        if state['pending'] and missing_hops is not None:
            missing_hops.append(state['prefix'])
        state.update(prefix=None, protocol=None, pending=False)

    def handle(raw, value):
        m = re.fullmatch(r'VRF:\s*(\S+)', value)
        if m:
            close_prefix()
            state['vrf'] = m[1]
            return []
        if re.fullmatch(r'(?:Displaying [0-9]+ of [0-9]+ IPv6 routing table entries|IPv6 Routing Table - [0-9]+ entries)', value):
            return []
        if value.startswith(('Codes:', 'Source Codes:')):
            close_prefix()
            state['in_codes'] = True
            return []
        if state['in_codes'] and (re.match(r'\s+\S.* - ', raw) or value == 'Aggregate'):
            return []
        state['in_codes'] = False
        if matches(value, (r'Gateway of last resort(?: is not set|:)?', r'Gateway of last resort is .*', r'Routing entry for .*')):
            close_prefix()
            return []
        m = re.fullmatch(r'directly connected, (\S+)', value)       # 4.36: the interface is on the line below the prefix
        if m and state['prefix']:
            row = route(state['prefix'], None, m[1], state['protocol'])
            state['pending'] = False
            return row
        m = re.fullmatch(r'([A-Z]{1,2}\d?(?: [A-Z]{1,2}\d?)?)\s+([0-9a-fA-F:.]+/\d+) is directly connected, (\S+)', value)
        if m:
            close_prefix()
            return route(str(ipaddress.ip_network(m[2], strict=False)), None, m[3], m[1])
        m = re.fullmatch(r'([A-Z]{1,2}\d?(?: [A-Z]{1,2}\d?)?)\s+([0-9a-fA-F:.]+/\d+)(?: \[\d+/\d+\])?(?: via ([0-9a-fA-F:.]+)(?:, (\S+))?)?(?:,? .*)?', value)
        if m:
            close_prefix()
            prefix = str(ipaddress.ip_network(m[2], strict=False))
            state.update(prefix=prefix, protocol=m[1], pending=not m[3])
            return route(prefix, str(ipaddress.ip_address(m[3])), m[4], m[1]) if m[3] else []
        m = re.fullmatch(r'via ([0-9a-fA-F:.]+)(?:, (\S+))?', value)
        if m and state['prefix']:
            row = route(state['prefix'], str(ipaddress.ip_address(m[1])), m[2], state['protocol'])
            state['pending'] = False
            return row
        return None
    parsed = scan(text, handle)
    close_prefix()
    return parsed


def route_junos(text, *, include_next_hop_type=False):
    """`show route A detail`: only active entries, like the whole-table parser."""
    state = {'prefix': None, 'protocol': None, 'vrf': None, 'hops': [], 'active': False, 'hop_type': None}
    out = []

    def close_entry():
        if state['prefix'] is None or state['protocol'] is None or not state['active']:
            return
        for hop, interface in state['hops'] or [(None, None)]:
            row = record('route', prefix=state['prefix'], next_hop=hop, interface=interface,
                         protocol=state['protocol'], vrf=state['vrf'])
            if include_next_hop_type and state['hop_type'] is not None:
                row['next_hop_type'] = state['hop_type']
            out.append(row)

    def close():
        close_entry()
        state.update(prefix=None, protocol=None, hops=[], active=False, hop_type=None)

    def handle(raw, value):
        m = re.fullmatch(r'(?:(\S+)\.)?inet6?\.\d+: \d+ destinations, \d+ routes \(.*\)', value)
        if m:
            close()
            state['vrf'] = m[1] or 'default'
            return []
        m = re.fullmatch(r'([0-9a-fA-F:.]+/\d+) \(\d+ entr(?:y|ies), \d+ announced\)', value)
        if m:
            close()
            state['prefix'] = str(ipaddress.ip_network(m[1], strict=False))
            return []
        if state['prefix'] is None:
            return [] if value in ('inet.0:', 'inet6.0:') or value.startswith('Limit/Threshold: ') else None
        m = re.match(r'([*@]?)\s*(\w[\w-]*)\s+Preference: \d+', value)
        if m:
            close_entry()
            state.update(protocol=JUNOS_ROUTE_PROTOCOL.get(m[2].lower(), m[2].lower()),
                         active=m[1] == '*', hops=[], hop_type=None)
            return []
        m = re.fullmatch(r'State: <([^>]*)>', value)
        if m:
            state['active'] = 'Active' in m[1].split()
            return []
        m = re.fullmatch(r'Next hop type: ([A-Za-z][A-Za-z -]*?)(?:, Next hop index: \d+)?', value)
        if m:
            state['hop_type'] = m[1]
            return []
        m = re.fullmatch(r'Next hop:[ \t]+(?:([0-9a-fA-F:.]+)[ \t]+)?via[ \t]+(\S+?)(?:, selected)?', value)
        if m:
            state['hops'].append((str(ipaddress.ip_address(m[1])) if m[1] else None, port(m[2])))
            return []
        if value.startswith(('Next hop:', 'Next hop type:')):
            return None
        if raw[:1].isspace():
            return []           # the attribute lines of a route entry (Age, State, AS path ...)
        return None
    rows, unknown = scan(text, handle)
    close()
    return out, unknown



JUNOS_ROUTE_PROTOCOL = {'static': 'static', 'direct': 'connected', 'local': 'local', 'ospf': 'ospf', 'ospf3': 'ospf', 'bgp': 'bgp', 'is-is': 'isis',
                        'rip': 'rip', 'ripng': 'rip', 'access': 'access', 'access-internal': 'access', 'aggregate': 'aggregate', 'inet6': 'local',
                        'igmp': 'igmp', 'pim': 'pim', 'evpn': 'evpn', 'l2circuit': 'l2circuit', 'ldp': 'ldp', 'rsvp': 'rsvp', 'multicast': 'multicast'}


def route_junos_table(text):
    """`show route`: a block per routing table ("inet.0: N destinations ..."), a prefix line with the protocol entries
    (`*[OSPF/10] age, metric N`, `[BGP/170] ...`) and the next hops (`> to A via ifl`, `via ifl`, `Local via ifl`) below it.
    One record per next hop of the active entry (marked `+` or `*`), or one record for the entry when it has no next hop."""
    state = {'vrf': None, 'prefix': None, 'entries': [], 'continued': False}
    out = []

    def close():
        if state['prefix'] is None:
            return
        entries = state['entries']
        active = next((e for e in entries if e['active']), None)
        if active is not None:
            if not active['hops']:
                out.append(record('route', prefix=state['prefix'], protocol=active['protocol'], vrf=state['vrf']))
            for hop, interface in active['hops']:
                out.append(record('route', prefix=state['prefix'], next_hop=hop, interface=interface, protocol=active['protocol'], vrf=state['vrf']))
        state.update(prefix=None, entries=[])

    def entry(marker, name, rest):
        protocol = JUNOS_ROUTE_PROTOCOL.get(name.lower())
        if protocol is None:
            raise ValueError
        if not re.fullmatch(r'(?:(?:\d+w)?(?:\d+d)? ?\d{1,2}:\d{2}:\d{2}|(?:\d+[wdhms])+|\d+)(?:,.*)?', rest.strip()) and rest.strip():
            raise ValueError
        state['entries'].append({'active': marker in ('+', '*'), 'protocol': protocol, 'hops': []})

    def handle(raw, value):
        m = re.fullmatch(r'(?:(\S+)\.)?(?:inet6?|mpls|iso|inet6color|inetcolor|bgp\.[a-z0-9.]+)\.?\d*: \d+ destinations?, \d+ routes? \(.*\)', value)
        if m:
            close()
            state['vrf'] = m[1] or 'default'
            return []
        if matches(value, (r'Limit/Threshold: .*', r'\+ = Active Route, - = Last Active, \* = Both', r'Restart Complete', r'[a-z0-9._-]+: \d+ destinations?, .*')):
            return []
        m = re.fullmatch(r'([0-9a-fA-F:.]+(?:/\d+)?)(?:\s+([*+-]?)\[([A-Za-z0-9-]+)/\d+\]\s*(.*))?', value)
        if m and not raw[:1].isspace():
            close()
            prefix = m[1] if '/' in m[1] else m[1] + ('/128' if ':' in m[1] else '/32')
            state['prefix'] = str(ipaddress.ip_network(prefix, strict=False))
            if m[3]:
                entry(m[2], m[3], m[4])
            return []
        if state['prefix'] is None:
            return None
        m = re.fullmatch(r'([*+-]?)\[([A-Za-z0-9-]+)/\d+\]\s*(.*)', value)
        if m:
            entry(m[1], m[2], m[3])
            return []
        if not state['entries']:
            return None
        m = re.fullmatch(r'>?\s*to\s+([0-9a-fA-F:.]+)(?:%\S+)?\s+via\s+(\S+?)(?:\s+(?:weight|Push|Pop|Swap)\b.*|,.*)?', value)
        if m:
            state['entries'][-1]['hops'].append((str(ipaddress.ip_address(m[1])), port(m[2])))
            return []
        m = re.fullmatch(r'>?\s*(?:Local\s+)?via\s+(\S+?)(?:\s+(?:weight|Push|Pop|Swap)\b.*|,.*)?', value)
        if m:
            state['entries'][-1]['hops'].append((None, port(m[1])))
            return []
        if matches(value, (r'MultiRecv', r'Discard', r'Reject', r'Receive', r'Multicast', r'Indirect', r'AS path:.*', r'Aggregate', r'>?\s*to table \S+')):
            return []
        return None
    rows, unknown = scan(text, handle)
    close()
    return out, unknown



JUNOS_CAPABILITY_WORDS = {'other': 'O', 'repeater': 'P', 'bridge': 'B', 'wlan-access-point': 'W', 'router': 'R', 'telephone': 'T',
                          'docsis-cable-device': 'C', 'station-only': 'S'}


def junos_capabilities(value):
    words = [word.lower() for word in value.split()]
    if not words:
        return None
    found = {JUNOS_CAPABILITY_WORDS.get(word, 'O') for word in words}
    return ','.join(code for code, _ in CAPABILITY_CODES if code in found)


def junos_lldp_detail(text):
    """`show lldp neighbors detail`: a "Local Information:" block and a "Neighbor Information:" block per neighbor, then
    "Organization Info" blocks (Index/OUI/Subtype/Info). System Description is free text and not parsed."""
    rows, unknown = [], []
    current, section = None, None
    known = {'local interface', 'parent interface', 'local port id', 'ageout count', 'chassis id', 'chassis type', 'port type', 'port id',
             'port description', 'system name', 'system description', 'address', 'address type', 'interface number', 'interface subtype',
             'oid', 'index', 'oui', 'subtype', 'info', 'supported', 'enabled'}
    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value:
            continue
        if value in ('LLDP Neighbor Information:', 'LLDP Neighbour Information:'):
            continue
        if value == 'Local Information:':
            current = record('lldp_neighbor')
            rows.append(current)
            section = 'local'
            continue
        if current is None:
            unknown.append({'line': number, 'text': raw})
            continue
        if value in ('Neighbor Information:', 'Neighbour Information:'):
            section = 'neighbor'
            continue
        if value == 'System capabilities':
            section = 'capabilities'
            continue
        if value == 'Management address':
            section = 'management'
            continue
        if value == 'Organization Info':
            section = 'organization'
            continue
        m = re.match(r'Index: \d+ Time to live: \d+ Time mark: .* Age: \d+ secs\s*$', value)
        if m:
            continue
        label, separator, argument = value.partition(':')
        label = label.rstrip()
        key = label.lower() if separator and re.fullmatch(r'[A-Za-z][A-Za-z0-9 /().-]*', label) else None
        if section == 'description' and key not in known:
            continue                    # the System Description is free text and may wrap over several lines
        if key is None or not (key in known or key.startswith('med ')):
            unknown.append({'line': number, 'text': raw})
            continue
        argument = argument.strip()
        if key == 'system description':
            section = 'description'
            continue
        if section == 'description':
            section = 'neighbor'
        try:
            if key == 'local interface':
                current['local_port'] = port(argument)
            elif key == 'port id' and section == 'neighbor':
                current['neighbor_port'] = argument
            elif key == 'system name' and section == 'neighbor':
                current['neighbor'] = argument or None
            elif key == 'enabled' and section == 'capabilities':
                current['capabilities'] = junos_capabilities(argument)
            elif key == 'address' and section == 'management' and current['management_ip'] is None:
                current['management_ip'] = str(ipaddress.ip_address(argument))
        except ValueError:
            unknown.append({'line': number, 'text': raw})
    return rows, unknown



def junos_bgp_peers(text):
    """`show bgp summary`: counters, a table block, then `Peer AS InPkt OutPkt OutQ Flaps Last Up/Dwn State` rows;
    an established peer lists `table: active/received/accepted/damped` lines below it, and a peer that is not
    established prints its state (Active, Idle, Connect ...). Older layouts print the counters in the State column."""
    state = {'peer': None, 'table_name': False}

    def handle(raw, value):
        if matches(value, (r'Threading mode: .*', r'Default eBGP mode: .*', r'Groups: \d+ Peers: \d+ Down peers: \d+',
                           r'Table\s+Tot Paths\s+Act Paths\s+Suppressed\s+History\s+Damp State\s+Pending',
                           r'Peer\s+AS\s+InPkt\s+OutPkt\s+OutQ\s+Flaps\s+Last Up/Dwn\s+State\|.*',
                           r'Warning: License key missing.*', r'BGP is not running', r'[0-9]+(?:\s+[0-9]+){5}',
                           r'\d+/\d+/\d+(?:/\d+)?', r'[a-z0-9._-]+\.(?:inet6?|l3vpn|l2vpn|evpn|mvpn|iso|isovpn)\.\d+\s*', r'[a-z0-9._-]+\.\d+\s*')):
            return []
        if re.fullmatch(r'[a-z0-9._-]+\.\d+(?:\s+\d+){6}', value):
            return []                       # a table row: name and six counters
        m = re.fullmatch(r'([0-9a-fA-F:.]+)(?:%\S+)?\s+(\d+(?:\.\d+)?)\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+\s+(\S+)', value)
        if m and not raw[:1].isspace():
            address = str(ipaddress.ip_address(m[1]))
            word = m[3]
            counts = re.fullmatch(r'(\d+)/(\d+)/(\d+)(?:/(\d+))?', word)
            if counts:
                established, prefixes = 'Established', int(counts[2])
            elif word.lower() in ('establ', 'established'):
                established, prefixes = 'Established', None
            elif word.lower() in BGP_STATES:
                established, prefixes = BGP_STATE_NAMES[word.lower()], None
            else:
                return None
            state['peer'] = record('bgp_peer', neighbor=address, remote_as=m[2], state=established, prefixes=prefixes, vrf='default')
            state['peer']['address_family'] = 'ipv6' if ':' in address else 'ipv4'
            return state['peer']
        m = re.fullmatch(r'([a-z0-9._-]+\.(?:inet6?|l3vpn|l2vpn|evpn|mvpn|iso|isovpn)\.\d+|[a-z0-9._-]+\.\d+): (\d+)/(\d+)/(\d+)(?:/(\d+))?', value)
        if m and state['peer'] is not None and raw[:1].isspace():
            if state['peer']['prefixes'] is None:
                state['peer']['prefixes'] = int(m[3])
            return []
        return None
    return scan(text, handle)


JUNOS_MUX = {'collecting distributing': 'bundled', 'detached': 'down', 'waiting': 'waiting', 'attached': 'standalone'}


def junos_lacp(text):
    """`show lacp interfaces`: an "Aggregated interface:" block per bundle with actor/partner rows and the mux state per member."""
    state = {'lag': None, 'section': None}

    def member(name):
        lag = state['lag']
        found = next((item for item in lag['members'] if item['port'] == name), None)
        if found is None:
            found = {'port': name, 'state': 'unknown'}
            lag['members'].append(found)
        return found

    def handle(raw, value):
        m = re.fullmatch(r'Aggregated interface: (\S+)', value)
        if m:
            state.update(lag=record('lag', name=port(m[1]), protocol='LACP', status=None, members=[]), section=None)
            return state['lag']
        if state['lag'] is None:
            return None
        if re.fullmatch(r'LACP state:\s+Role\s+Exp\s+Def\s+Dist\s+Col\s+Syn\s+Aggr\s+Timeout\s+Activity', value, re.I):
            state['section'] = 'state'
            return []
        if re.fullmatch(r'LACP protocol:\s+Receive State\s+Transmit State\s+Mux State', value, re.I):
            state['section'] = 'protocol'
            return []
        if state['section'] == 'state':
            m = re.fullmatch(r'(\S+?)(?:\s+\(FUP\))?\s+(Actor|Partner)\s+(Yes|No)\s+(Yes|No)\s+(Yes|No)\s+(Yes|No)\s+(Yes|No)\s+(Yes|No)\s+(Fast|Slow)\s+(Active|Passive)', value)
            if m:
                item = member(port(m[1]))
                if m[2] == 'Actor' and item['state'] == 'unknown':
                    item['state'] = 'bundled' if m[5] == 'Yes' and m[6] == 'Yes' else 'down'
                return []
        elif state['section'] == 'protocol':
            fields = value.split()
            name = fields.pop(0) if fields else None
            if fields[:1] == ['(FUP)']:
                fields.pop(0)
            # Receive is one token, transmit may contain multiple words; mux is
            # a fixed suffix. Split once so malformed whitespace cannot backtrack.
            mux = ' '.join(fields[-2:]) if fields[-2:] == ['Collecting', 'distributing'] else (fields[-1] if fields else '')
            mux_width = 2 if mux == 'Collecting distributing' else 1
            if len(fields) >= 2 + mux_width and mux in ('Collecting distributing', 'Detached', 'Waiting', 'Attached'):
                member(port(name))['state'] = JUNOS_MUX[mux.lower()]
                return []
        return None
    rows, unknown = scan(text, handle)
    for lag in rows:
        lag['status'] = 'up' if any(item['state'] == 'bundled' for item in lag['members']) else 'down'
    return rows, unknown


JUNOS_STP_ROLE = {'root': 'root', 'desg': 'designated', 'altn': 'alternate', 'alt': 'alternate', 'back': 'backup', 'bkup': 'backup', 'mstr': 'master',
                  'dis': 'disabled', 'bdrg': 'boundary'}
JUNOS_STP_STATE = {'fwd': 'forwarding', 'blk': 'blocking', 'lrn': 'learning', 'lis': 'listening', 'dis': 'disabled', 'dsc': 'discarding', 'bkn': 'broken'}


def junos_stp(text):
    """ELS `show spanning-tree interface`: "Spanning tree interface parameters for instance N", then one row per port."""
    state = {'instance': None}

    def handle(raw, value):
        m = re.fullmatch(r'Spanning tree interface parameters for instance (\d+)', value)
        if m:
            state['instance'] = int(m[1])
            return []
        if re.fullmatch(r'Spanning-tree is not enabled at global level\.', value):
            return []
        if matches(value, (r'Interface\s+Port ID\s+Designated\s+Designated\s+Port\s+State\s+Role', r'port ID\s+bridge ID\s+Cost')):
            return []
        m = re.fullmatch(r'(\S+)\s+\d+:\d+\s+\d+:\d+\s+\d+\.[0-9a-fA-F]+\s+(\d+)\s+(\S+)\s+(\S+)', value)
        if m and state['instance'] is not None:
            role, status = JUNOS_STP_ROLE.get(m[4].lower()), JUNOS_STP_STATE.get(m[3].lower())
            if role is None or status is None:
                return None
            return record('stp_port', instance=str(state['instance']), port=port(m[1]), role=role, state=status, cost=int(m[2]))
        return None
    return scan(text, handle)


# --- per-OS entry points --------------------------------------------------------------------

def cisco(table, text, style='ios'):
    if table == 'ospf_neighbor':
        return ospf_neighbors(text, style)
    if table == 'bgp_peer':
        return bgp_peers(text, style)
    if table == 'lag':
        return lag_summary(text, style)
    if table == 'stp_port':
        return stp_tree(text, style)
    if table == 'lldp_neighbor':
        return cisco_lldp(text, style)
    if table == 'route':
        return route_nxos(text) if style == 'nxos' else route_ios(text)
    if table == 'interface':
        return status_table(text)
    if table == 'vlan':
        return vlan_sections(text, style)
    if table == 'mac_entry':
        return mac_nxos(text) if style == 'nxos' else mac_ios(text)
    return neighbors(text, style)


for _profile in ('cisco_ios', 'cisco_xe'):
    BINDINGS[_profile] = {'interface': 'interfaces', 'vlan': 'vlans', 'mac_entry': 'mac_table',
                          'neighbor_l3': 'arp_table', 'neighbor_l3_v6': 'ipv6_neighbors',
                          'lldp_neighbor': 'lldp_neighbors', 'route': 'route_lookup', 'route_v6': 'ipv6_route_lookup',
                          'route_all': 'route_table', 'ospf_neighbor': 'ospf_neighbors', 'bgp_peer': 'bgp_summary',
                          'lag': 'lag_summary', 'stp_port': 'stp_tree'}
    PARSERS[_profile] = cisco


BINDINGS['cisco_nxos'] = dict(BINDINGS['cisco_ios'])
PARSERS['cisco_nxos'] = lambda table, text: cisco(table, text, 'nxos')


def eos(table, text):
    if table == 'lldp_neighbor':
        return eos_lldp_detail(text) if re.search(r'detected \d+ LLDP neighbors?', text) else lldp_summary(text, 'eos')
    if table == 'route':
        return route_eos(text)
    if table == 'mac_entry':
        return mac_eos(text)
    return cisco(table, text, 'eos')


BINDINGS['arista_eos'] = {**BINDINGS['cisco_ios'], 'lldp_neighbor': 'lldp_neighbors_detail'}
PARSERS['arista_eos'] = eos
for _query in ('ipv6_route_table', 'ipv6_route_table_vrf', 'ipv6_route_lookup', 'ipv6_route_lookup_vrf'):
    QUERY_PARSERS[('arista_eos', 'route', _query)] = _route_ipv6.eos_routes


JUNOS_NAME = r'[A-Za-z][A-Za-z0-9]*(?:[-/][0-9]+)*(?:[./:][0-9]+)*'


def junos_interfaces(text):
    """`show interfaces terse`: every row has Admin and Link; address-family lines continue the row above."""
    def handle(raw, value):
        if re.match(r'Interface\s+Admin\s+Link\s+Proto\s+Local\s+Remote', value):
            return []
        if raw[:1].isspace() and (re.fullmatch(r'(?:inet6?|iso|mpls|eth-switch|tnp|multiservice|vpls|ccc|bridge|aenet)\s*.*', value)
                                  or re.fullmatch(r'[0-9a-fA-Fx:.]+(?:/\d+)?(?:\s*-->\s*\S+)?', value)):
            return []           # address-family lines continue the interface row above
        m = re.fullmatch(r'(' + JUNOS_NAME + r')\s+(up|down)\s+(up|down)(?:\s+(.*))?', value)
        if not m:
            return None
        return record('interface', name=m[1], admin_status=m[2], oper_status=m[3])
    return scan(text, handle)


def junos_vlans(text):
    state = {'last': None}

    def handle(raw, value):
        if re.match(r'Routing instance\s+VLAN name\s+Tag\s+Interfaces', value):
            return []
        m = re.fullmatch(r'(\S+)\s+(\S+)\s+(\d+|NA)\s*(.*)', value)
        if m and not raw[:1].isspace():
            result = record('vlan', name=m[2], vlan_id=int(m[3]) if m[3].isdigit() else None, ports=port_list(m[4]))
            state['last'] = result
            return result
        if state['last'] is not None and raw[:1].isspace() and re.fullmatch(r'[\w/.:*, -]+', value):
            state['last']['ports'].extend(port_list(value))
            return []
        return None
    return scan(text, handle)


def junos_neighbors(text):
    """IPv4 `show arp no-resolve` or IPv6 `show ipv6 neighbors`, told apart by their headers."""
    if ipv6_table(text):
        return scan(text, lambda raw, value: [] if value.startswith(('IPv6 Address', 'Total entries')) else neighbor_line(value, 'junos'))
    return arp_rows(text, 'junos')


def junos(table, text):
    if table == 'ospf_neighbor':
        return ospf_neighbors(text, 'junos')
    if table == 'bgp_peer':
        return junos_bgp_peers(text)
    if table == 'lag':
        return junos_lacp(text)
    if table == 'stp_port':
        return junos_stp(text)
    if table == 'route':
        return route_junos(text) if re.search(r'\(\d+ entr(?:y|ies), \d+ announced\)', text) else route_junos_table(text)
    if table == 'lldp_neighbor':
        return junos_lldp_detail(text) if 'Local Information:' in text else lldp_summary(text, 'junos')
    if table == 'interface':
        return junos_interfaces(text)
    if table == 'vlan':
        return junos_vlans(text)
    if table == 'mac_entry':
        return mac_junos(text)
    return junos_neighbors(text)


for _profile in ('juniper_junos', 'juniper_junos_els'):
    BINDINGS[_profile] = {k: v for k, v in BINDINGS['cisco_ios'].items()
                          if k not in ('stp_port', 'lag') and (_profile.endswith('_els') or k not in ('vlan', 'mac_entry'))}
    BINDINGS[_profile].update(lldp_neighbor='lldp_neighbors_detail', route_all='route_table', lag='lacp_interfaces')
    if _profile.endswith('_els'):
        BINDINGS[_profile]['stp_port'] = 'stp_interfaces'
    PARSERS[_profile] = junos


def fortinet(table, text):
    pending = [None]
    def row(value):
        if table == 'neighbor_l3':
            m = re.fullmatch(r'ifindex=\d+ ifname=(\S+) (\S+) ('+MAC+r') state=\S+.*', value)
            if m:
                return record(table, ip=str(ipaddress.ip_address(m[2])), mac=normalize_mac(m[3]), interface=m[1], vlan_id=vlan(m[1]))
            return neighbor_line(value, 'fortinet')
        if table == 'mac_entry':
            m = re.fullmatch(r'MAC:\s*('+MAC+r')\s+VLAN:\s*(\d+)\s+(Port|Trunk):\s*([^\s(]+)\s*\((?:port|trunk)-id\s+\d+\)', value)
            if m:
                r = record(table, mac=normalize_mac(m[1]), vlan_id=int(m[2]), port=m[4],
                           type='trunk' if m[3] == 'Trunk' else None)
                pending[0] = r
                return r
            m = re.fullmatch(r'Flags:\s*0x[0-9a-fA-F]+\s*\[([^\]]*)\]', value)
            if m and pending[0]:
                if pending[0]['type'] != 'trunk':
                    flags = m[1].split()
                    pending[0]['type'] = 'dynamic' if 'dynamic' in flags else 'static' if 'static' in flags else None
                return []
        if table == 'lldp_neighbor':
            m = re.fullmatch(r'(port\d+(?:\.\d+)?)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)', value)
            if m:
                return record(table, local_port=m[1], neighbor=m[4], neighbor_port=m[3], capabilities=m[5] or None)
        return None
    return lines(text, row, (r'Address\s+Age\(min\)\s+Hardware Addr\s+Interface',
                            r'Managed Switch\s*:\s*[A-Z0-9]+\s+\d+', r'flag bit (?:pattern|Mask):\s*0x[0-9a-fA-F]+',
                            r'(?:vlan|port-id|trunk-id) map:\s*\d+-\d+',
                            r'Port\s+Chassis ID\s+Port ID\s+System Name(?:\s+Capabilities)?', r'No LLDP neighbors found\.?'))


BINDINGS['fortinet'] = {'neighbor_l3': 'arp_table', 'neighbor_l3_v6': 'ipv6_neighbors', 'route': 'route_lookup',
                        'route_v6': 'ipv6_route_lookup', 'route_all': 'routing_table', **switch_managed.TABLES}
from . import fortigate_tables  # noqa: E402
fortigate_tables.register(QUERY_PARSERS)
QUERY_PARSERS[('fortinet', 'route', 'route_lookup')] = lambda table, text: switch_managed.routes(table, text, lookup=True)
QUERY_PARSERS[('fortinet', 'route', 'ipv6_route_lookup')] = _route_ipv6.routes
QUERY_PARSERS[('fortinet', 'route', 'ipv6_routing_table')] = _route_ipv6.fortios_table
# G11 (FP-07): FortiGate-local routing and aggregate tables (requests are built by fortigate_tables.request).
BINDINGS['fortinet'].update(ospf_neighbor='ospf_neighbors', bgp_peer='bgp_summary', lag='lacp_detail',
                           stp_port='local_stp_ports', port_vlan='local_switch_vlans')
PARSERS['fortinet'] = switch_managed.parse

for _profile, _query in port_vlan.BINDINGS.items():
    BINDINGS[_profile]['port_vlan'] = _query


# --- ip_interface: parsers and the second read live in ip_interfaces.py -----------------------

from . import ip_interfaces  # noqa: E402  (imports this module; everything above is defined)

for _profile, _query in ip_interfaces.QUERIES.items():
    BINDINGS[_profile]['ip_interface'] = _query
    QUERY_PARSERS[(_profile, 'ip_interface', _query)] = ip_interfaces.PARSERS[_profile]
for _profile in ('juniper_junos', 'juniper_junos_els'):
    BINDINGS[_profile]['ip_interface_v6'] = 'interfaces'
    QUERY_PARSERS[(_profile, 'ip_interface_v6', 'interfaces')] = ip_interfaces.junos
    for _query in ('ospfv3_neighbors', 'ospfv3_neighbors_interface'):
        QUERY_PARSERS[(_profile, 'ospf_neighbor', _query)] = ip_interfaces.junos_ospfv3
for _profile in ip_interfaces.ROUTER_INTERFACES:
    ROUTER_BINDINGS[_profile] = {'interface': 'ip_interfaces'}
    QUERY_PARSERS[(_profile, 'interface', 'ip_interfaces')] = ip_interfaces.PARSERS[_profile]

# Registration only: parsers and multi-source reads live in their own module.
from . import port_errors as _port_errors
_port_errors.register(FIELDS, OPTIONAL_FIELDS, BINDINGS, TABLE_PARSERS)

from . import cdp as _cdp
_cdp.register(FIELDS, OPTIONAL_FIELDS, BINDINGS, QUERY_PARSERS)

from . import linux_tables as _linux_tables
_linux_tables.register(BINDINGS, PARSERS, QUERY_PARSERS)


for _query in ('ipv6_route_table', 'ipv6_route_table_vr'):
    QUERY_PARSERS[('extreme_exos', 'route', _query)] = _route_ipv6.exos_routes

from . import exos_ports as _exos_ports
_exos_ports.register(__import__(__name__, fromlist=['']))
from . import eos_ports as _eos_ports  # noqa: E402
_eos_ports.register(__import__(__name__, fromlist=['']))
from . import ios_ports as _ios_ports  # noqa: E402  (G53 IOS port/STP/LACP/PoE/DOM tables)
_ios_ports.register(__import__(__name__, fromlist=['']))
# NX-OS shares the Cisco detail layout with two vPC port annotations.
def _nxos_stp(table, text):
    return _ios_ports.stp(table, text, nxos=True)


def _nxos_optics(table, text):
    return _ios_ports._optics_rows(table, text, nxos=True)


def _nxos_lacp(table, text):
    from .ios_ports import PORT_STATE_BITS

    # These counters and state values appear in both the valid-member and
    # unconfigured-port responses. A timestamp of 1970 is printed in the latter.
    patterns = {
        'port': r'Interface (Ethernet[0-9/]+) is (.+)',
        'group': r'Channel group is ([0-9]+) port channel is *(Po[0-9]+)?',
        'pdus_sent': r'PDUs sent: ([0-9]+)',
        'pdus_received': r'PDUs rcvd: ([0-9]+)',
        'actor': r'Actor Oper State=([0-9]{1,3})',
        'partner': r'Partner Oper State=([0-9]{1,3})',
        'aggregate': r'Aggregate or Individual\(True=1\)= ([12])',
    }
    found = {key: re.findall(r'(?m)^[ \t]*' + pattern + r'[ \t]*$', text) for key, pattern in patterns.items()}
    if any(len(matches) != 1 for matches in found.values()):
        return [], [{'line': 1, 'text': 'incomplete or ambiguous NX-OS LACP interface response'}]
    name, state = found['port'][0]
    group, channel = found['group'][0]
    actor, partner = (int(found[key][0]) for key in ('actor', 'partner'))
    if actor > 255 or partner > 255 or bool(int(group)) != bool(channel):
        return [], [{'line': 1, 'text': 'contradictory NX-OS LACP interface response'}]
    flags = [key for bit, key in PORT_STATE_BITS if actor & bit]
    bundled = bool(int(group)) and found['aggregate'][0] == '1' and (actor & 0x38) == 0x38
    reason = None
    if not int(group):
        reason = 'no channel group'
    elif found['aggregate'][0] != '1':
        reason = 'device reports an individual link'
    elif not actor & 8:
        reason = 'actor is out of sync'
    elif not bundled:
        reason = 'actor is not collecting or distributing'
    values = dict(port=port(name), group=int(group), state=state.strip(), bundled=bundled, port_state=actor,
                  port_state_flags=flags, mode='active' if actor & 1 else 'passive', reason=reason,
                  port_channel=channel or None, partner_state=partner,
                  pdus_sent=int(found['pdus_sent'][0]), pdus_received=int(found['pdus_received'][0]))
    extra = ('port_channel', 'partner_state', 'pdus_sent', 'pdus_received')
    return [record(table, **values) | {key: values[key] for key in extra}], []


for _table, _query, _parser in (
    ('stp_topology', 'stp_detail', _nxos_stp),
    ('stp_port_counters', 'stp_detail', _nxos_stp),
    ('stp_port_counters', 'stp_interface_detail', _nxos_stp),
    ('optics_port', 'interface_transceiver', _nxos_optics),
    ('lag_member', 'lacp_interface', _nxos_lacp),
    ('lldp_neighbor', 'lldp_neighbor_interface', PARSERS['cisco_nxos']),
):
    QUERY_PARSERS[('cisco_nxos', _table, _query)] = _parser
PROFILE_OPTIONAL_FIELDS.setdefault('cisco_nxos', {}).update(
    {table: _ios_ports.OPTIONAL[table] for table in ('stp_topology', 'stp_port_counters', 'optics_port')})
PROFILE_OPTIONAL_FIELDS['cisco_nxos']['lag_member'] = set(FIELDS['lag_member']) - {
    'group', 'port', 'state', 'bundled', 'port_state', 'port_state_flags'}
BINDINGS['cisco_nxos'].update(stp_topology='stp_detail', stp_port_counters='stp_detail',
                             optics_port='interface_transceiver', lag_member='lacp_interface')
# G51: direct catalogue reads have table adapters without changing existing
# table_read defaults or adding implicit device reads.
from . import triage_routing as _triage_routing
FIELDS['vrf'] = ('name', 'rd', 'interfaces')
OPTIONAL_FIELDS['vrf'] = {'rd', 'interfaces'}
QUERY_PARSERS[('cisco_ios', 'vrf', 'vrfs')] = _triage_routing.ios_vrfs
QUERY_PARSERS[('cisco_ios', 'route', 'vrf_route_lookup')] = _triage_routing.ios_vrf_routes
QUERY_PARSERS[('cisco_ios', 'neighbor_l3', 'vrf_arp_table')] = lambda table, text: neighbors(text, 'ios')
QUERY_PARSERS[('cisco_ios', 'ip_interface', 'vrf_ip_interfaces')] = _triage_routing.ios_vrf_interfaces
QUERY_PARSERS[('cisco_ios', 'route', 'ipv6_route_table')] = _route_ipv6.ios_table
for _query in ('ip_interface_details', 'ipv6_interface_details'):
    QUERY_PARSERS[('cisco_ios', 'ip_interface', _query)] = ip_interfaces.ios_addresses
# VRF variants use the same measured output grammar as the default queries.
QUERY_PARSERS[('cisco_nxos', 'ip_interface', 'ip_interfaces_vrf')] = ip_interfaces.nxos
QUERY_PARSERS[('cisco_nxos', 'bgp_peer', 'bgp_ipv6_summary')] = lambda table, text: bgp_peers(text, 'nxos')
QUERY_PARSERS[('cisco_nxos', 'bgp_peer', 'bgp_ipv6_summary_vrf')] = lambda table, text: bgp_peers(text, 'nxos')

for _query in ('ipv6_route_table', 'ipv6_route_table_vrf', 'ipv6_route_lookup', 'ipv6_route_lookup_vrf'):
    QUERY_PARSERS[('cisco_nxos', 'route', _query)] = _route_ipv6.nxos


def nxos_ospfv3_neighbors(table, text):
    """NX-OS OSPFv3 shows the link-local neighbor address on a continuation."""
    vrf, pending = None, None
    rows, unknown = [], []
    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value:
            continue
        match = re.fullmatch(r'OSPFv3 Process ID \S+ VRF (\S+)', value)
        if match:
            vrf = match[1]
            continue
        if matches(value, (r'Total number of neighbors: \d+', r'Neighbor ID\s+Pri\s+State\s+Up Time\s+Interface ID\s+Interface')):
            continue
        match = re.fullmatch(r'(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\w+)/(DR|BDR|DROTHER|-)\s+\S+\s+\d+\s+(\S+)', value)
        if match and vrf is not None:
            if pending:
                unknown.append(pending[1])
            pending = (match, {'line': number, 'text': raw})
            continue
        match = re.fullmatch(r'Neighbor address ([0-9A-Fa-f:]+)', value)
        if match and pending:
            peer, evidence = pending
            try:
                address = str(ipaddress.IPv6Address(match[1]))
                rows.append(record(table, neighbor_id=str(ipaddress.IPv4Address(peer[1])), address=address,
                                   interface=port(peer[4]), state=peer[2].lower(),
                                   role=None if peer[3] == '-' else peer[3], vrf=vrf))
            except ValueError:
                unknown.extend((evidence, {'line': number, 'text': raw}))
            pending = None
            continue
        unknown.append({'line': number, 'text': raw})
    if pending:
        unknown.append(pending[1])
    return rows, unknown


for _query in ('ospfv3_neighbors', 'ospfv3_neighbors_vrf'):
    QUERY_PARSERS[('cisco_nxos', 'ospf_neighbor', _query)] = nxos_ospfv3_neighbors

# G69: IOS XE uses the verified IOS address/RIB/VRF grammars.
for _query, _table in _triage_routing.IOS_TABLES.items():
    QUERY_PARSERS[("cisco_xe", _table, _query)] = QUERY_PARSERS[("cisco_ios", _table, _query)]


_JUNOS_FILTER_NAME = r"[A-Za-z0-9_][A-Za-z0-9_.:/-]{0,63}"
_JUNOS_BINDING_LINE = re.compile(
    rf"(?m)^[ \t]*(inactive:[ \t]+)?(input|output)(?:-list)?[ \t]+"
    rf"(\[[ \t\n]*{_JUNOS_FILTER_NAME}(?:[ \t\n]+{_JUNOS_FILTER_NAME})*[ \t\n]*\]|{_JUNOS_FILTER_NAME});[ \t]*$"
)


def junos_firewall_bindings(text):
    """Accept only the IPv4 filter leaf output from the reviewed configuration command."""
    rows = []
    for match in _JUNOS_BINDING_LINE.finditer(text):
        inactive, direction, names = match.groups()
        rows.extend({"filter": name, "direction": direction, "inactive": bool(inactive)}
                    for name in names.strip("[] ").split())
    complete = not _JUNOS_BINDING_LINE.sub("", text).strip()
    return {"records": rows, "complete": complete}


def junos_firewall_counters(text):
    filters = []
    current, section = None, None
    complete = True
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        match = re.fullmatch(rf"Filter:\s*({_JUNOS_FILTER_NAME})", line)
        if match:
            current = {"filter": match[1], "counters": [], "policers": []}
            filters.append(current)
            section = None
        elif current is not None and line in {"Counters:", "Policers:"}:
            section = line[:-1].lower()
        elif section and re.fullmatch(r"Name\s+(?:Bytes\s+)?Packets", line):
            continue
        else:
            counter = re.fullmatch(r"(\S+)\s+(?:(\d+)\s+)?(\d+)", line)
            if not (section and counter and (section == "policers" or counter[2] is not None)):
                complete = False
                continue
            current[section].append({"name": counter[1], "bytes": int(counter[2]) if counter[2] else None,
                                     "packets": int(counter[3])})
    return {"records": filters, "complete": complete and bool(filters)}


def junos_cluster_status(text):
    cluster = re.search(r"(?m)^Cluster ID:\s*(\d+)", text)
    groups = list(re.finditer(r"(?m)^Redundancy group:\s*(\d+)\s*,\s*Failover count:\s*(\d+)", text))
    rows = []
    for index, group in enumerate(groups):
        end = groups[index + 1].start() if index + 1 < len(groups) else len(text)
        nodes = re.findall(r"(node\d+)\s+(\d+)\s+(\S+)\s+(yes|no)\s+(yes|no)\s+(.+?)(?=\s+node\d+\s+|$)",
                           text[group.end():end], re.M)
        rows.append({"group": int(group[1]), "failovers": int(group[2]), "nodes": [
            {"node": node, "priority": int(priority), "status": status, "preempt": preempt == "yes",
             "manual": manual == "yes", "monitor_failures": [] if failures.strip() == "None" else failures.split()}
            for node, priority, status, preempt, manual, failures in nodes
        ]})
    return {"cluster_id": int(cluster[1]) if cluster else None, "records": rows,
            "complete": bool(cluster and rows) and all(len({node["node"] for node in row["nodes"]}) == 2 for row in rows)}


def junos_cluster_interfaces(text):
    links = {}
    rows = []
    section = None
    headings = {"Control interfaces:": "control", "Fabric interfaces:": "fabric",
                "Redundant-ethernet Information:": "reth", "Redundant-pseudo-interface Information:": "pseudo"}
    complete = True
    for raw in text.splitlines():
        line = raw.strip()
        status = re.fullmatch(r"(Control|Fabric) link status:\s*(.+)", line)
        if status:
            links[status[1].lower()] = status[2]
        elif line in headings:
            section = headings[line]
        elif not line or line.startswith(("Index ", "Name ", "(Physical/Monitored)")):
            continue
        elif section == "control" and (match := re.fullmatch(r"\d+\s+(\S+)\s+(Up|Down|Admin Down)(?:\s+.*)?", line, re.I)):
            rows.append({"kind": section, "interface": match[1], "status": match[2]})
        elif section == "fabric" and (match := re.fullmatch(r"(fab\d+)(?:\s+(\S+)\s+(\w+)\s*/\s*(\w+)(?:\s+\S+)?)?", line)):
            rows.append({"kind": section, "interface": match[1], "child": match[2],
                         "physical_status": match[3], "monitored_status": match[4]})
        elif section in {"reth", "pseudo"} and (match := re.fullmatch(r"(\S+)\s+(Up|Down)\s+(\d+|Not configured)", line, re.I)):
            rows.append({"kind": section, "interface": match[1], "status": match[2],
                         "group": int(match[3]) if match[3].isdecimal() else None})
        else:
            complete = False
    return {"records": rows, "links": links, "complete": complete and bool(rows) and links.keys() == {"control", "fabric"}}


def junos_cluster_statistics(text):
    rows = []
    section = None
    services = False
    for raw in text.splitlines():
        line = raw.strip()
        link = re.fullmatch(r"(Control link|Child link)\s+(\d+):?", line)
        if link:
            services = False
            section = {"kind": link[1].lower(), "index": int(link[2]), "counters": {}}
            rows.append(section)
        elif line == "Services Synchronized:":
            services = True
            section = None
        elif section and (counter := re.fullmatch(r"([\w ]+):\s*(\d+)", line)):
            field = counter[1].replace("Heartbeat packets errors", "Heartbeat packet errors")
            section["counters"][field] = int(counter[2])
        elif services:
            fields = line.rsplit(maxsplit=2)
            if len(fields) == 3 and all(value.isascii() and value.isdecimal() for value in fields[1:]):
                name, sent, received = fields
                rows.append({"kind": "service", "name": name, "sent": int(sent), "received": int(received)})
    required = {"control link": {"Heartbeat packets sent", "Heartbeat packets received", "Heartbeat packet errors"},
                "child link": {"Probes sent", "Probes received"}}
    complete = {row["kind"] for row in rows} >= required.keys() | {"service"} and all(
        required.get(row["kind"], set()) <= row.get("counters", {}).keys() for row in rows)
    return {"records": rows, "complete": complete}


def junos_firewall_diagnostics(profile, query, text, status, parameters, *, count_verified=True):
    from . import triage_flow, triage_vpn
    from .query_catalog.junos import FILTER_BINDING_QUERY

    if profile not in {"juniper_junos", "juniper_junos_els"} or status not in {"ok", "empty"}:
        return {}
    parsers = {
        "firewall_filters": junos_firewall_counters,
        "firewall_filter": junos_firewall_counters,
        FILTER_BINDING_QUERY: junos_firewall_bindings,
        "security_policies": triage_flow.srx_policies,
        "security_match_policies": triage_flow.srx_policies,
        "security_policy_hits": triage_flow.srx_policy_hits,
        "security_flow_sessions": triage_flow.srx_sessions,
        "security_source_nat_rules": triage_flow.srx_nat_rules,
        "security_destination_nat_rules": triage_flow.srx_nat_rules,
        "chassis_cluster_status": junos_cluster_status,
        "chassis_cluster_interfaces": junos_cluster_interfaces,
        "chassis_cluster_statistics": junos_cluster_statistics,
        "ike_security_associations": triage_vpn.srx_ike_associations,
        "ipsec_security_associations": triage_vpn.srx_ipsec_associations,
        "ipsec_statistics": triage_vpn.srx_ipsec_statistics,
    }
    if query not in parsers:
        return {}
    if status == "empty":
        parsed = {"records": [], "complete": query == FILTER_BINDING_QUERY}
    else:
        parsed = parsers[query](text)
    if query == "security_policies":
        parsed["complete"] = parsed["complete"] and count_verified
    if query == FILTER_BINDING_QUERY:
        parsed["interface"] = parameters["interface"]
    if query == "firewall_filter" and parsed["records"]:
        parsed["complete"] = parsed["complete"] and [row["filter"] for row in parsed["records"]] == [parameters["filter"]]
    state = status if parsed["complete"] else "unparsed"
    envelope = response_envelope(profile, state, [source_record(query, text, state)],
                                 warnings=[] if parsed["complete"] else ["incomplete_output"],
                                 identity_coverage=False)
    envelope["coverage"]["complete"] = parsed["complete"]
    return {"diagnostics": parsed, "normalized": envelope}


NXOS_LOOKUPS = frozenset({'arp_lookup', 'arp_lookup_vrf', 'ipv6_neighbor_lookup', 'ipv6_neighbor_lookup_vrf'})
NXOS_NEIGHBOR_QUERIES = NXOS_LOOKUPS | {'arp_table_vrf', 'ipv6_neighbors_vrf'}
NXOS_SCOPED_TABLES = NXOS_LOOKUPS | {'mac_table_address', 'mac_table_vlan', 'dhcp_snooping_binding'}


def _nxos_mac_scope(table, text):
    rows, unknown = mac_nxos(text, include_remote=True)
    if not re.search(r'(?m)^[ \t]*VLAN[ \t]+MAC Address[ \t]+Type[ \t]+age[ \t]+Secure[ \t]+NTFY[ \t]+Ports[ \t]*\r?$', text):
        unknown.append({'line': 1, 'text': 'NX-OS MAC table header is missing'})
    return rows, unknown


def _nxos_neighbor_scope(table, text):
    # NX-OS wraps a long IPv6 address onto its own line above the rest of its row.
    text = re.sub(r'(?m)^([0-9a-fA-F]{0,4}:[0-9a-fA-F:]{1,38})[ \t]*\r?\n[ \t]+(?=\d)', r'\1 ', text)
    if ipv6_table(text):
        vrf = None

        def nd_line(raw, value):
            nonlocal vrf
            header = re.fullmatch(r'IPv6 Adjacency Table for VRF (\S+)', value)
            if header:
                vrf = header[1]
                return []
            if re.fullmatch(r'(?:Flags:.*|(?:[\#GR]|CP|PS|RO|CC)\s*-\s+.*|'
                            r'Total number of entries:\s*\d+|Address\s+Age\s+MAC Address\s+Pref Source\s+Interface(?:\s+Flags)?)', value):
                return []
            row = re.fullmatch(rf'(\S+)\s+\S+\s+({MAC}|INCOMPLETE)\s+\d+\s+\S+\s+(\S+)'
                               r'(?:\s+(?:[#GR]|CP|PS|RO|CC))*', value)
            if not row or vrf is None:
                return None
            iface = port(row[3])
            return record(table, ip=str(ipaddress.IPv6Address(row[1])), interface=iface, vlan_id=vlan(iface),
                          mac=None if row[2] == 'INCOMPLETE' else normalize_mac(row[2]), vrf=vrf)

        rows, unknown = scan(text, nd_line)
    else:
        rows, unknown = arp_rows(text, 'nxos', nxos_bare_header=True)
    totals = re.findall(r'(?m)^Total number of entries:[ \t]*(\d{1,10})[ \t]*\r?$', text)
    if not totals or sum(map(int, totals)) != len(rows):
        unknown.append({'line': 1, 'text': 'NX-OS neighbor entry total is missing or disagrees with the rows'})
    if not re.search(r'(?m)^Address\s+Age\s+MAC Address\s+', text):
        unknown.append({'line': 1, 'text': 'NX-OS neighbor table header is missing'})
    return rows, unknown


for _query in NXOS_NEIGHBOR_QUERIES:
    QUERY_PARSERS['cisco_nxos', 'neighbor_l3', _query] = _nxos_neighbor_scope
for _query in ('mac_table_address', 'mac_table_vlan'):
    QUERY_PARSERS['cisco_nxos', 'mac_entry', _query] = _nxos_mac_scope


def _nxos_dhcp_bindings(table, text):
    return switch_dhcp.nxos_bindings(text, port)


QUERY_PARSERS['cisco_nxos', 'dhcp_binding', 'dhcp_snooping_binding'] = _nxos_dhcp_bindings


IOS_FORWARDING_TABLES = {
    **dict.fromkeys(('mac_table_address', 'mac_table_interface', 'mac_table_vlan'), 'mac_entry'),
    **dict.fromkeys(('arp_lookup', 'arp_lookup_vrf', 'arp_table_vrf', 'vrf_arp_table',
                     'ipv6_neighbors_interface', 'ipv6_neighbors_vrf', 'ipv6_neighbors_interface_vrf'), 'neighbor_l3'),
    'dhcp_snooping_binding': 'dhcp_binding',
}


def _ios_forwarding_scope(query, command, rows):
    parts = command.split()
    selector = None
    if 'vrf' in parts:
        vrf = parts[parts.index('vrf') + 1]
        for row in rows:
            row['vrf'] = vrf
    if query == 'mac_table_address':
        selector = 'mac', normalize_mac(parts[-1])
    elif query == 'mac_table_vlan':
        selector = 'vlan_id', int(parts[-1])
    elif query == 'mac_table_interface':
        selector = 'port', port(parts[-1])
    elif query in ('arp_lookup', 'arp_lookup_vrf'):
        selector = 'ip', str(ipaddress.IPv4Address(parts[-1]))
    elif query in ('ipv6_neighbors_interface', 'ipv6_neighbors_interface_vrf'):
        selector = 'interface', port(parts[-1])
    if selector and any(row[selector[0]] != selector[1] for row in rows):
        return [{'line': 1, 'text': 'IOS response does not match the command selector'}]
    return []


def _ios_scoped_mac(table, text):
    rows, unknown = mac_ios(text)
    totals = re.findall(r'(?mi)^\s*Total Mac Addresses for this criterion:[ \t]*(\d+)[ \t]*$', text)
    entries = re.findall(r'(?mi)^[ \t]*(?:\d+|All)[ \t]+(?:' + MAC + r')[ \t]+\S+[ \t]+\S+', text)
    header = re.search(r'(?mi)^[ \t]*Vlan[ \t]+Mac Address[ \t]+Type[ \t]+Ports?[ \t]*$', text)
    # IOSvL2 omits the total when there are no entries.
    if not header or len(totals) > 1 or (totals or entries) and (not totals or int(totals[0]) != len(entries)):
        unknown.append({'line': 1, 'text': 'IOS MAC table header or entry total could not be verified'})
    return rows, unknown


def _ios_scoped_neighbors(table, text):
    rows, unknown = neighbors(text, 'ios')
    header = r'(?mi)^[ \t]*(?:Protocol[ \t]+Address[ \t]+Age|IPv6 Address[ \t]+Age)\b'
    totals = re.findall(r'(?mi)^[ \t]*Total (?:number of )?entries:[ \t]*(\d+)[ \t]*$', text)
    if not re.search(header, text) or totals and sum(map(int, totals)) != len(rows):
        unknown.append({'line': 1, 'text': 'IOS neighbor table header or entry total could not be verified'})
    return rows, unknown


for _profile in IOS_FORWARDING_PROFILES:
    for _query, _table in IOS_FORWARDING_TABLES.items():
        if _table == 'mac_entry':
            QUERY_PARSERS[_profile, _table, _query] = _ios_scoped_mac
        elif _table == 'neighbor_l3':
            QUERY_PARSERS[_profile, _table, _query] = _ios_scoped_neighbors
        else:
            QUERY_PARSERS[_profile, _table, _query] = lambda table, text: switch_dhcp.ios_snooping_bindings(text, port)


_NXOS_ACL_FAMILIES = {
    'access_lists': 'ipv4', 'ipv4_access_lists': 'ipv4', 'ipv4_access_lists_summary': 'ipv4',
    'ipv6_access_lists': 'ipv6', 'ipv6_access_lists_summary': 'ipv6',
    'mac_access_lists': 'mac', 'mac_access_lists_summary': 'mac',
}


def _nxos_acl(text, family, name, summary):
    acl = None
    section = None
    seen = set()
    complete = True
    records, unknown = [], []
    family_label = {'ipv4': 'IPV4 ACL' if summary else 'IP access list',
                    'ipv6': 'IPV6 ACL' if summary else 'IPv6 access list',
                    'mac': 'MAC ACL' if summary else 'MAC access list'}[family]

    def finished():
        return not summary or acl is None or {'total_entries', 'configured_interfaces', 'active_interfaces'} <= seen

    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        header = re.fullmatch(re.escape(family_label) + r'\s+(\S+)', line)
        if header:
            complete = complete and finished() and (name is None or header[1] == name)
            acl = {'family': family, 'name': header[1], 'statistics_enabled': False}
            if summary:
                acl.update(total_entries=None, configured_interfaces=[], active_interfaces=[])
            else:
                acl['entries'] = []
            records.append(acl)
            section = None
            seen = set()
            continue
        if acl is None:
            unknown.append({'line': number, 'text': raw})
            continue
        if line == ('Statistics enabled' if summary else 'statistics per-entry'):
            acl['statistics_enabled'] = True
            continue
        if summary:
            section_name = {'Configured on interfaces:': 'configured_interfaces',
                            'Active on interfaces:': 'active_interfaces'}.get(line)
            count = re.fullmatch(r'Total ACEs Configured:\s*(\d+)', line)
            binding = re.fullmatch(r'(\S+)\s+-\s+(ingress|egress)\s+\(([^()]+)\)', line)
            if section_name and section_name not in seen:
                section = section_name
                seen.add(section)
                continue
            if count and 'total_entries' not in seen:
                acl['total_entries'] = int(count[1])
                seen.add('total_entries')
                continue
            if binding and section:
                acl[section].append({'interface': binding[1], 'direction': binding[2], 'type': binding[3]})
                continue
        else:
            ace = re.fullmatch(r'(\d+)\s+(permit|deny|remark)\s+(.+)', line)
            if ace:
                rule, hits = ace[3], None
                count = re.search(r'\s+\[match=(\d+)\]$', rule) if ace[2] != 'remark' else None
                if count:
                    rule, hits = rule[:count.start()], int(count[1])
                elif ace[2] != 'remark' and '[match=' in rule:
                    unknown.append({'line': number, 'text': raw})
                    continue
                acl['entries'].append({'sequence': int(ace[1]), 'action': ace[2], 'rule': rule, 'hit_count': hits})
                continue
            if re.fullmatch(r'fragments (?:permit-all|deny-all)', line):
                acl['fragment_policy'] = line.split()[1]
                continue
        unknown.append({'line': number, 'text': raw})
    return records, unknown, complete and finished() and bool(records) and not unknown


def nxos_g94_diagnostics(query, text, parameters, state):
    """Parse redacted CLI output. Keep recognized records when another line is incomplete."""
    if state not in ('ok', 'empty'):
        return None
    if state == 'empty':
        if query not in _NXOS_ACL_FAMILIES and query not in {
            'arp_inspection_statistics', 'arp_inspection_statistics_vlan',
        }:
            return None
        records, unknown, complete = [], [], True
    elif query in _NXOS_ACL_FAMILIES:
        records, unknown, complete = _nxos_acl(text, _NXOS_ACL_FAMILIES[query],
                                                parameters.get('name'), query.endswith('_summary'))
    else:
        if query == 'dhcp_snooping_status':
            fields, complete = switch_dhcp.nxos_snooping(text)
        elif query == 'dhcp_relay_status':
            fields, complete = switch_dhcp.nxos_relay(text)
        elif query in ('dhcp_snooping_statistics', 'dhcp_relay_statistics'):
            fields, complete = switch_dhcp.nxos_dhcp_counters(text, relay=query == 'dhcp_relay_statistics')
        elif query in ('arp_inspection_statistics', 'arp_inspection_statistics_vlan'):
            fields, complete = switch_dhcp.nxos_dai(text, parameters.get('vlan_id'))
        else:
            return None
        records, unknown = fields if isinstance(fields, list) else [fields], []
    status = ('ok' if records else 'empty') if complete else 'incomplete'
    result = response_envelope('cisco_nxos', status, [source_record(query, text, status)], identity_coverage=False)
    result.update(records=records, unparsed=unknown, coverage={'complete': complete, 'parsed_records': len(records),
                                                               'unparsed_lines': len(unknown), 'missing_fields': []})
    return result


_NXOS_QOS_INTERFACE = r'Eth(?:ernet)?\d+/\d+(?:/\d+)?'
_NXOS_QOS_SLOT = r'slot\s+\d+'
_NXOS_QUEUE_COUNTERS = {
    'Tx Pkts': 'tx_packets',
    'Tx Byts': 'tx_bytes',
    'Dropped Pkts': 'dropped_packets',
    'Dropped Byts': 'dropped_bytes',
    'Tail Drop Pkts': 'tail_drop_packets',
    'Tail Drop Byts': 'tail_drop_bytes',
    'WRED/AFD & Tail Drop Pkts': 'wred_afd_tail_drop_packets',
    'WRED/AFD & Tail Drop Byts': 'wred_afd_tail_drop_bytes',
    'WD & Tail Drop Pkts': 'watchdog_tail_drop_packets',
    'Q Depth Byts': 'depth_bytes',
}
_NXOS_QUEUE_TRAFFIC = {'Unicast': 'unicast', 'OOBFC Unicast': 'oobfc_unicast', 'Multicast': 'multicast'}


def _nxos_qos_queues(text, interface):
    queue = None
    port_seen = False
    schedule = {}
    groups = set()
    span = None
    traffic = []

    def handle(raw, value):
        nonlocal queue, port_seen, traffic, span
        heading = re.fullmatch(rf'Egress Queuing for ({_NXOS_QOS_INTERFACE}) \[[^\]]+\]', value)
        if heading and not port_seen and port(heading[1]) == interface:
            port_seen = True
            return []
        if re.fullmatch(_NXOS_QOS_SLOT, value):
            return []
        if not port_seen:
            return None
        if re.fullmatch(r'QoS-Group#\s+Bandwidth%\s+PrioLevel\s+Shape(?:\s+QLimit)?|Min\s+Max\s+Units', value):
            return []
        scheduling = re.fullmatch(r'(\d+)\s+(\d+|-)\s+(\d+|-)\s+\S+\s+\S+\s+\S+(?:\s+\d+\(D\))?', value)
        if scheduling and queue is None:
            group = int(scheduling[1])
            if group in schedule:
                return None
            schedule[group] = {
                'bandwidth_percent': int(scheduling[2]) if scheduling[2] != '-' else None,
                'priority_level': int(scheduling[3]) if scheduling[3] != '-' else None,
            }
            return []
        if value.startswith('|') and value.endswith('|'):
            cells = [cell.strip() for cell in value[1:-1].split('|')]
            heading = re.fullmatch(r'QOS GROUP (\d+)|(CONTROL|SPAN) QOS GROUP', cells[0])
            if len(cells) == 1 and heading:
                group = int(heading[1]) if heading[1] is not None else heading[2].lower()
                if group in groups:
                    return None
                groups.add(group)
                traffic = []
                queue = {'interface': interface, 'qos_group': group, 'counters': {}}
                if group in schedule:
                    queue.update(schedule[group])
                return [queue]
            if queue is None or span is not None:
                return None
            if not cells[0] and cells[1:] in (['Unicast', 'Multicast'], ['Unicast', 'OOBFC Unicast', 'Multicast']):
                traffic = [_NXOS_QUEUE_TRAFFIC[item] for item in cells[1:]]
                return []
            key = _NXOS_QUEUE_COUNTERS.get(cells[0])
            if not key or not traffic or len(cells) != len(traffic) + 1 or key in queue['counters']:
                return None
            queue['counters'][key] = dict(zip(traffic, map(int, cells[1:]), strict=True))
            return []
        if value == 'Per Slice Egress SPAN Statistics':
            span = {'interface': interface, 'section': 'per_slice_egress_span', 'counters': {}}
            return [span]
        if span is not None:
            counter = re.fullmatch(r'(SPAN (?:Copies Tail Drop|Input Queue Drop|Copies/Transit Tail Drop|Input Desc Drop))\s+Pkts\s+(\d+)', value)
            if counter:
                span['counters']['_'.join(counter[1].lower().replace('/', ' ').split()) + '_packets'] = int(counter[2])
                return []
        return None

    rows, unknown = scan(text, handle)
    if rows and re.search(r'(?m)^[ \t]*\|[^\n]+\|[ \t]*(?:\n[ \t]*)*\Z', text):
        unknown.append({'line': len(text.splitlines()), 'text': 'NX-OS queue table footer is missing'})
    queue_rows = [row for row in rows if 'qos_group' in row]
    mandatory = {'tx_packets', 'tx_bytes'}
    missing = []
    if not queue_rows or set(schedule) != {group for group in groups if isinstance(group, int)}:
        missing.append('queue_groups')
    if any(not mandatory <= row['counters'].keys() or isinstance(row['qos_group'], int) and not (
        {'dropped_packets', 'tail_drop_packets', 'wred_afd_tail_drop_packets'} & row['counters'].keys()
    ) for row in queue_rows):
        missing.append('queue_counters')
    if span is not None and len(span['counters']) != 4:
        missing.append('span_counters')
    return rows, unknown, missing


def _nxos_qos_policy(text, interface):
    stats = None
    port_seen = False
    policy = None
    policy_class = None

    def handle(raw, value):
        nonlocal stats, port_seen, policy, policy_class
        state = re.fullmatch(r'Global statistics status\s*:\s*(enabled|disabled)', value)
        if state and stats is None:
            stats = state[1] == 'enabled'
            return []
        if re.fullmatch(_NXOS_QOS_INTERFACE, value) and not port_seen and port(value) == interface:
            port_seen = True
            return []
        if not port_seen:
            return None
        service = re.fullmatch(r'Service-policy \((qos|queuing|network-qos)\) (input|output):\s+(\S+)', value)
        if service:
            policy = {'interface': interface, 'policy_type': service[1], 'direction': service[2],
                      'name': service[3], 'statistics_enabled': stats, 'classes': []}
            policy_class = None
            return [policy]
        if policy is None:
            return None
        index = re.fullmatch(r'SNMP Policy Index:\s+(\d+)', value)
        if index and policy_class is None:
            policy['snmp_policy_index'] = int(index[1])
            return []
        class_map = re.fullmatch(r'Class-map \((qos|queuing|network-qos)\):\s+(\S+)\s+\((match-any|match-all)\)', value)
        if class_map and class_map[1] == policy['policy_type']:
            policy_class = {'name': class_map[2], 'match_mode': class_map[3], 'rules': [], 'counters': {}}
            policy['classes'].append(policy_class)
            return []
        if policy_class is None or not raw[:1].isspace():
            return None
        if re.fullmatch(r'(?:(?:match|set|police|shape|queue-limit|random-detect)\s+.+|'
                        r'priority level \d+|bandwidth (?:remaining )?percent \d+)', value):
            policy_class['rules'].append(value)
            return []
        counter = re.fullmatch(r'((?:Match|Transmitted|Dropped) (?:Packets|Bytes))\s*:\s*(\d+)', value, re.I)
        if counter:
            policy_class['counters']['_'.join(counter[1].lower().split())] = int(counter[2])
            return []
        return None

    rows, unknown = scan(text, handle)
    missing = []
    if stats is None or not port_seen or not rows:
        missing.append('interface_policy')
    if any(not row['classes'] or any(not (item['rules'] or item['counters']) for item in row['classes'])
           for row in rows):
        missing.append('policy_classes')
    return rows, unknown, missing


def _nxos_pfc(text):
    header = False
    ports = set()

    def handle(_raw, value):
        nonlocal header
        if re.fullmatch(_NXOS_QOS_SLOT, value):
            return []
        if re.fullmatch(r'Port\s+Mode\s+Oper\s*\(VL bmap\)\s+RxPPP\s+TxPPP', value, re.I):
            header = True
            return []
        row = re.fullmatch(rf'({_NXOS_QOS_INTERFACE})\s+(Auto|On|Off)\s+(On|Off)'
                           r'(?:\s+\((\d+)\))?\s+(\d+)\s+(\d+)', value, re.I)
        if not header or not row or port(row[1]) in ports:
            return None
        interface = port(row[1])
        ports.add(interface)
        return [{'interface': interface, 'admin_mode': row[2].lower(), 'oper_mode': row[3].lower(),
                 'vl_bitmap': int(row[4]) if row[4] is not None else None,
                 'rx_pause_frames': int(row[5]), 'tx_pause_frames': int(row[6])}]

    rows, unknown = scan(text, handle)
    return rows, unknown, [] if rows else ['pfc_counters']


# Only try the column separator at the start of a whitespace run.
_NXOS_TCAM_ROW = re.compile(r'([A-Za-z][\w ,()/.:\[\]-]*?)(?<!\s)\s{2,}+(\d++)'
                           r'(?:\s++(?:(\d++)\s++)?(\d++\.\d++)%?)?')
_NXOS_CAPACITY_SECTION = re.compile(r'`show [^`]+`')
_NXOS_CAPACITY_ACL = re.compile(r'`show (?:system internal|hardware) access-list resource utilization'
                                r'(?: module \d+)?`')


def _nxos_tcam(text, capacity):
    in_acl = not capacity
    module = instance = slot = None
    header = False
    row_keys = set()

    def handle(_raw, value):
        nonlocal in_acl, module, instance, slot, header
        if capacity and _NXOS_CAPACITY_SECTION.fullmatch(value):
            in_acl = _NXOS_CAPACITY_ACL.fullmatch(value) is not None
            module = instance = slot = None
            header = False
            return []
        if capacity and (value == 'Cmd exec error.' or value.startswith('Failed to get ')):
            return None
        if not in_acl:
            return []
        slot_heading = re.fullmatch(r'slot\s+(\d+)', value)
        if slot_heading:
            slot = int(slot_heading[1])
            module = instance = None
            header = False
            return []
        asic = re.fullmatch(r'INSTANCE (0x[0-9a-fA-F]+)', value)
        if asic:
            instance = int(asic[1], 16)
            module = None
            header = False
            return []
        heading = re.fullmatch(r'ACL Hardware Resource Utilization \(Mod (\d+)\)', value)
        if heading and (slot is None or slot == int(heading[1])):
            module = int(heading[1])
            return []
        if module is not None and re.fullmatch(r'Used\s+Free\s+Percent(?:\s+Utilization)?', value):
            header = True
            return []
        if header and value == 'Utilization':
            return []
        if header and value == 'Note: Ingress SUP region includes the Redirect region':
            return []
        row = _NXOS_TCAM_ROW.fullmatch(value)
        if not header or not row:
            return None
        resource, used, free, percent = row.groups()
        if percent is None and not re.fullmatch(r'(?:Both|Single) LOU Operands|LOU [\w ]+:', resource):
            return None
        key = module, instance, resource
        if key in row_keys:
            return None
        row_keys.add(key)
        return [{'module': module, 'instance': instance, 'resource': resource, 'used': int(used),
                 'free': int(free) if free is not None else None,
                 'utilization_percent': float(percent) if percent is not None else None}]

    rows, unknown = scan(text, handle)
    has_regions = any(row['free'] is not None and (
        re.search(r'\b(?:[PRV]ACL|TCAM|ACL|QOS|SUP|SPAN)\b', row['resource'], re.I)
        and not row['resource'].startswith('L4 op labels,')
    ) for row in rows)
    return rows, unknown, [] if has_regions else ['tcam_regions']


def nxos_g96_diagnostics(query, text, parameters, state, rc):
    """Return available QoS and ACL observations with conservative coverage."""
    slot_only = re.fullmatch(r'\s*(?:slot\s+\d+\s+=+\s*)+(?:Cmd exec error\.\s*)?', text) is not None
    partial_exit = state == 'transport_error' and rc == 244 and (
        query == 'priority_flow_control' and slot_only or
        query == 'tcam_utilization' and text.rstrip().endswith('Cmd exec error.')
        and 'ACL Hardware Resource Utilization (Mod ' in text
    )
    if state != 'ok' and not partial_exit:
        return None
    if query == 'qos_queues':
        records, unknown, missing = _nxos_qos_queues(text, port(parameters['interface']))
    elif query == 'qos_policy':
        records, unknown, missing = _nxos_qos_policy(text, port(parameters['interface']))
    elif query == 'priority_flow_control':
        records, unknown, missing = _nxos_pfc(text)
    else:
        records, unknown, missing = _nxos_tcam(text, capacity=query == 'hardware_capacity')

    complete = not (unknown or missing or partial_exit)
    status = 'ok' if complete else 'incomplete'
    warnings = ['device_command_partial'] if partial_exit else []
    result = response_envelope('cisco_nxos', status, [source_record(query, text, status)],
                               warnings=warnings, identity_coverage=False)
    result.update(records=records, unparsed=unknown, coverage={
        'complete': complete, 'parsed_records': len(records), 'unparsed_lines': len(unknown), 'missing_fields': missing,
    })
    return result


_NVE_PEER_HEADER = r'Interface\s+Peer-IP\s+State\s+LearnType\s+Uptime\s+Router-Mac'
_NVE_VNI_HEADER = r'Interface\s+VNI\s+Multicast-group\s+State\s+Mode\s+Type\s+\[BD/VRF\]\s+Flags'
_EVPN_MAC_IP_HEADERS = (
    r'Topology(?: ID)?\s+Mac Address\s+Prod\s+Host IP\s+Next Hop \(s\)',
    r'Topology(?: ID)?\s+Mac Address\s+Host IP\s+Prod\s+Flags\s+Seq No\s+Next-Hops',
)


def _nxos_overlay_rows(query, text):
    headers = {'nve_peers': (_NVE_PEER_HEADER,), 'nve_vni': (_NVE_VNI_HEADER,),
               'evpn_mac_ip': _EVPN_MAC_IP_HEADERS}[query]
    layout = None

    def handle(raw, line):
        nonlocal layout
        for index, header in enumerate(headers):
            if re.fullmatch(header, line):
                layout = index
                return []
        if query == 'nve_vni' and matches(line, (r'Codes: CP - Control Plane\s+DP - Data Plane(?:\s+.*)?',
                                                r'(?:UC - Unconfigured|SU - Suppress Unknown Unicast|'
                                                r'Xconn - Crossconnect|MS-IR - Multisite Ingress Replication).*')):
            return []
        if query == 'evpn_mac_ip' and matches(line, (r'Flags\s*-\s*\(Rmac\):Router MAC.*',
                                                    r'\(Dup\):Duplicate.*', r'\(Ps\):Peer Sync.*')):
            return []
        if layout is None:
            return None
        if query == 'nve_peers':
            match = re.fullmatch(r'(nve\d+)\s+(\S+)\s+(Up|Down)\s+(\S+)\s+(\S+)\s+(\S+)', line)
            if match:
                interface, peer, state, learn_type, uptime, mac = match.groups()
                return dict(interface=interface, peer_ip=str(ipaddress.ip_address(peer)), state=state,
                            learn_type=learn_type, uptime=uptime,
                            router_mac=None if mac.lower() in {'n/a', '--'} else normalize_mac(mac))
        elif query == 'nve_vni':
            match = re.fullmatch(r'(nve\d+)\s+(\d+)\s+(\S+)\s+(Up|Down)\s+(\S+)\s+'
                                 r'(L[23])\s+\[([^\]]+)\](?:\s+(.*))?', line)
            if match:
                interface, vni, multicast, state, mode, layer, binding, flags = match.groups()
                return dict(interface=interface, vni=int(vni), state=state, mode=mode, type=layer,
                            multicast_group=None if multicast.lower() in {'n/a', '--'} else str(ipaddress.ip_address(multicast)),
                            bridge_domain=binding if layer == 'L2' else None,
                            vrf=binding if layer == 'L3' else None, flags=flags.split() if flags else [])
        else:
            pattern = (rf'(\d+)\s+({MAC})\s+(?P<producer>\S+)\s+(?P<ip>\S+)\s+(?P<next_hops>.+)'
                       if layout == 0 else rf'(\d+)\s+({MAC})\s+(?P<ip>\S+)\s+(?P<producer>\S+)\s+'
                       r'(?P<flags>\S+)\s+(?P<sequence>\d+)\s+(?P<next_hops>.+)')
            match = re.fullmatch(pattern, line)
            if match:
                fields = match.groupdict()
                fields['ip'] = str(ipaddress.ip_address(fields['ip']))
                if not re.fullmatch(r'Ifindex \d+', fields['next_hops']):
                    ipaddress.ip_address(fields['next_hops'].split()[0].rstrip(','))
                if layout == 1:
                    fields['sequence'] = int(fields['sequence'])
                return dict(topology_id=int(match[1]), mac=normalize_mac(match[2]), **fields)
        return None

    rows, unknown = scan(text, handle)
    return rows, unknown, layout is not None


_NVE_DETAIL_FIELDS = {
    'VPC Capability', 'Local Router MAC', 'Host Learning Mode', 'Source-Interface', 'Anycast-Interface',
    'Source Interface State', 'Anycast Interface State', 'Virtual RMAC Advertisement', 'NVE Flags',
    'Interface Handle', 'Source Interface hold-down-time', 'Source Interface hold-up-time',
    'Remaining hold-down time', 'Virtual Router MAC', 'Interface state', 'Fabric convergence time',
    'Fabric convergence time left', 'ESI multihoming delay-restore time', 'ESI multihoming delay-restore time left',
    'ESI multihoming FRR anycast source IP',
}


def _nxos_nve_interface(text):
    details = {}
    interface = None

    def handle(raw, line):
        nonlocal interface
        if match := re.fullmatch(r'Interface: (nve1), State: (\w+), encapsulation: (VXLAN)', line):
            if interface is None:
                interface = dict(interface=match[1], state=match[2], encapsulation=match[3], details=details)
                return interface
            return None
        key, sep, value = line.partition(':')
        if interface is not None and sep and key in _NVE_DETAIL_FIELDS and key not in details:
            if value.strip() or key == 'NVE Flags':
                details[key] = value.strip()
                return []
        return None

    rows, unknown = scan(text, handle)
    required = {'Source-Interface', 'Source Interface State', 'Host Learning Mode', 'Interface state'}
    return rows, unknown, required <= details.keys()


def _nxos_evpn_summary(text):
    # The existing NX-OS BGP table parser handles wrapped IPv6 neighbors and multiword states.
    filtered = re.sub(r'(?m)^[ \t]*\d+ received paths for inbound soft reconfiguration[ \t]*$', '', text)
    rows, unknown = bgp_peers(filtered, 'nxos')
    contexts = re.findall(r'(?m)^\s*BGP summary information for VRF (\S+), address family L2VPN EVPN\s*$', text)
    counts = re.findall(r'(?m)^\s*BGP table version is \d+, L2VPN EVPN config peers (\d+), capable peers \d+\s*$', text)
    header = re.search(r'(?m)^[ \t]*Neighbor\s+V\s+AS\s+MsgRcvd\s+MsgSent\s+TblVer\s+InQ\s+OutQ\s+Up/Down'
                       r'\s+State/PfxRcd[ \t]*$', text)
    complete = len(contexts) == len(counts) == 1 and int(counts[0]) == len(rows)
    return rows, unknown, complete and (header is not None or not rows)


_EVPN_PATH_ATTRIBUTES = (
    r'AS-Path: .+', r'Imported (?:to|from) .+', r'Gateway IP: \S+',
    # The shared CLI redactor can mask the optional extended community line.
    r'Received (?:label|path-id) \d+', r'Ext(?:community: .+|\[REDACTED\])', r'Router MAC:\s*\S+',
)


def _nxos_evpn_prefix(text):
    vrf = rd = route = path = None

    def handle(raw, line):
        nonlocal vrf, rd, route, path
        if match := re.fullmatch(r'BGP routing table information for VRF (\S+), address family L2VPN EVPN', line):
            vrf = match[1]
            rd = route = path = None
        elif match := re.fullmatch(r'Route Distinguisher: (\S+)(?:\s+\(L[23]VNI \d+\))?', line):
            rd = match[1]
            route = path = None
        elif match := re.fullmatch(r'BGP routing table entry for (\[(\d+)\]\S+), version (\d+)', line):
            if rd is None or vrf is None:
                return None
            route = dict(vrf=vrf, rd=rd, nlri=match[1], route_type=int(match[2]),
                         version=int(match[3]), paths=[])
            path = None
            return route
        elif route is None:
            return None
        elif match := re.fullmatch(r'Paths: \((\d+) available, (?:best #(\d+)|no best path)\)', line):
            if 'path_count' in route:
                return None
            route.update(path_count=int(match[1]), best_path=int(match[2]) if match[2] else None)
        elif match := re.fullmatch(r'Path type: (.+)', line):
            path = {'description': match[1], 'attributes': []}
            route['paths'].append(path)
        elif match := re.fullmatch(r'(\S+)(?: \(metric \d+\))? from (\S+) \((\S+)\)', line):
            if path is None or 'next_hop' in path:
                return None
            path.update(next_hop=str(ipaddress.ip_address(match[1])), received_from=str(ipaddress.ip_address(match[2])))
        elif re.fullmatch(r'Origin (?:IGP|EGP|incomplete), .*\bweight \d+(?:,.*)?', line, re.I):
            if path is None or 'origin' in path:
                return None
            path['origin'] = line
        elif path is not None and matches(line, _EVPN_PATH_ATTRIBUTES):
            path['attributes'].append(line)
        elif not matches(line, (r'Flags: \(.+\).+', r'Multipath: .+', r'Advertised path-id \d+',
                                r'Path-id \d+ (?:not advertised to any peer|advertised to peers:)')):
            return None
        return []

    rows, unknown = scan(text, handle)
    complete = bool(rows) and route is not None and all(
        row.get('path_count') == len(row['paths'])
        and (row['best_path'] is None or 1 <= row['best_path'] <= len(row['paths']))
        and all(path.keys() >= {'next_hop', 'received_from', 'origin'} for path in row['paths'])
        for row in rows
    )
    return rows, unknown, complete


def nxos_overlay_diagnostics(query, text, state):
    """Build records from one redacted NX-OS overlay capture and retain unknown lines."""
    if state == 'empty':
        rows, unknown, shape_complete = [], [], False
    elif query == 'nve_interface_detail':
        rows, unknown, shape_complete = _nxos_nve_interface(text)
    elif query == 'evpn_bgp_summary':
        rows, unknown, shape_complete = _nxos_evpn_summary(text)
    elif query == 'evpn_bgp_prefix':
        rows, unknown, shape_complete = _nxos_evpn_prefix(text)
    else:
        rows, unknown, shape_complete = _nxos_overlay_rows(query, text)
    complete = state in {'ok', 'empty'} and shape_complete and not unknown
    if complete:
        state = 'ok' if rows else 'empty'
    elif state in {'ok', 'empty'}:
        state = 'incomplete'
    result = response_envelope('cisco_nxos', state, [source_record(query, text, state)], identity_coverage=False)
    result.update(records=rows, unparsed=unknown, coverage={'complete': complete, 'parsed_records': len(rows),
                                                           'unparsed_lines': len(unknown)})
    return result


def ios_security_diagnostic(profile, query, text, state, parameters):
    """Recognize IOS ACL data and verified empty responses for DHCP/port security."""
    if state not in ('ok', 'empty'):
        return None
    records, unknown = [], []
    if query in ('ipv4_access_lists', 'ipv6_access_lists'):
        records, unknown = _ios_acl_rows(text)
    elif not _ios_security_empty(profile, query, text, parameters):
        return None
    state = 'unparsed' if unknown else 'ok' if records else 'empty'
    result = response_envelope(profile, state, [source_record(query, text, state)], identity_coverage=False)
    result.update(records=records, unparsed=unknown, coverage={
        'complete': not unknown, 'parsed_records': len(records), 'unparsed_lines': len(unknown),
    })
    return result


def _ios_acl_rows(text):
    acl = None

    def handle(raw, value):
        nonlocal acl
        heading = re.fullmatch(r'(IPv6|Standard IP|Extended IP) access list (\S+)(?: \([^()]+\))*', value)
        if heading:
            family = 'ipv6' if heading[1] == 'IPv6' else 'ipv4'
            acl = {'name': heading[2], 'family': family, 'rules': []}
            return [acl]
        rule = re.fullmatch(r'(?:(\d+) )?((?:permit|deny|remark|evaluate|dynamic)\s+.+?)(?: sequence (\d+))?', value)
        if not raw[0].isspace() or acl is None or not rule:
            return None
        body = rule[2]
        count = re.search(r' \((\d+) match(?:es)?\)$', body)
        seq = rule[1] or rule[3]
        acl['rules'].append({'sequence': int(seq) if seq else None,
                             'rule': body[:count.start()] if count else body,
                             'hits': int(count[1]) if count else None})
        return []

    return scan(text, handle)


def _ios_security_empty(profile, query, text, parameters):
    lines = [' '.join(line.split()) for line in text.splitlines() if line.strip()]
    if query == 'dhcp_server_binding_address':
        address = parameters.get('address')
        prefixes = ('Address', 'Adddress') if profile == 'cisco_xe' else ('Address',)
        return any(lines == [f'% {prefix} {address} is not in the database.'] for prefix in prefixes)
    if query == 'dhcp_server_bindings':
        columns = 'IP address Client-ID/ Lease expiration Type'
        if profile == 'cisco_xe' and len(lines) == 4 and lines[1] == columns + ' State Interface':
            columns = lines[1]
        return lines == ['Bindings from all pools not associated with VRF:', columns, 'Hardware address/', 'User name']
    if query == 'dhcp_server_conflicts':
        return lines == ['IP address Detection method Detection time VRF']
    if query == 'port_security_addresses':
        return (len(lines) == 8
                and lines[0] == 'Secure Mac Address Table'
                and lines[2:4] == ['Vlan Mac Address Type Ports Remaining Age', '(mins)']
                and all(re.fullmatch(r'-+(?: -+)*', lines[i]) for i in (1, 4, 5))
                and re.fullmatch(r'Total Addresses in System \(excluding one mac per port\) *: 0', lines[6]) is not None
                and re.fullmatch(r'Max Addresses limit in System \(excluding one mac per port\) *: [0-9]+', lines[7]) is not None)
    if query == 'authentication_sessions_interface':
        return lines == ['No sessions match supplied criteria.']
    if query == 'arp_inspection_statistics':
        return lines == ['Source Mac Validation : Disabled', 'Destination Mac Validation : Disabled',
                         'IP Address Validation : Disabled', 'No active or enabled vlans on switch.']
    if query == 'ip_source_guard':
        if profile == 'cisco_xe' and not lines:
            return True
        return len(lines) == 2 and lines[0] == 'Interface Filter-type Filter-mode IP-address Mac-address Vlan' and bool(
            re.fullmatch(r'[- ]+', lines[1]))
    return query in ('dhcp_server_pools', 'dot1x_interface') and not lines


# G57 operational reads use the ssh_read envelope and retain partial, sourced results.
_IOS_QOS_PORT = r'[A-Za-z][A-Za-z-]*\d+(?:/\d+)*(?:\.\d+)?'
_IOS_QOS_CLASS = re.compile(r'Class-map:\s*(\S+)\s+\(match[- ](?:all|any)\)(?: fragment \S+)?', re.I)
_IOS_QOS_POLICY = re.compile(r'Service-policy(?: (input|output))?\s*:\s*(\S+)(?: \(\d+\))?', re.I)
_IOS_QOS_COUNTERS = [
    (r'(\d+) packets, (\d+) bytes', ('packets', 'bytes')),
    (r'\d+ (?:seconds?|minute) offered rate (\d+) bps, drop rate (\d+) bps', ('offered_rate_bps', 'drop_rate_bps')),
    (r'\((?:queue )?depth/total drops/no-buffer drops\)\s*(\d+)/(\d+)/(\d+)',
     ('queue_depth', 'total_drops', 'no_buffer_drops')),
    (r'\(pkts output/bytes output\)\s*(\d+)/(\d+)', ('output_packets', 'output_bytes')),
    (r'Packets dropped (\d+) packets/(\d+) bytes', ('dropped_packets', 'dropped_bytes')),
    (r'Priority: .+, b/w exceed drops: (\d+)', ('bandwidth_exceed_drops',)),
]
_IOS_QOS_DETAILS = re.compile(
    r'Match:\s*.+|Queueing|queue limit \d+ (?:packets|bytes)|shape \(average\) cir .+|target shape rate \d+'
    r'|bandwidth (?:remaining ratio \d+|\d+% \(\d+ kbps\))|\d+ (?:second|minute) rate \d+ bps'
    r'|QoS Set|(?:cos|dscp) \w+|No packet marking statistics available|Account QoS statistics', re.I,
)
_IOS_QOS_POLICER_ACTION = r'(?:transmit|drop|set-[\w-]+(?: [\w./-]+)*)'
_IOS_QOS_POLICER_COUNTER = re.compile(
    rf'(conformed|exceeded|violated) (\d+) packets, (\d+) bytes; actions?:(?:\s+({_IOS_QOS_POLICER_ACTION}))?', re.I,
)
_IOS_QOS_POLICER_LIMIT = re.compile(
    r'cir \d+ bps, (?:bc \d+ bytes|conform-burst \d+)'
    r'(?:, (pir) \d+(?: bps)?, (?:be \d+ bytes|peak-burst \d+)|, be \d+ bytes)?'
    r'|(pir) \d+ bps, be \d+ bytes', re.I,
)
_IOS_QOS_POLICER_RATES = re.compile(
    r'conformed \d+ bps, exceed(?:ed)? \d+ bps(?:,? (violate(?:d)? \d+ bps))?', re.I,
)


def _ios_qos_policer(lines, *, classic_ios):
    outcomes, unknown = {}, []
    required = {'conformed', 'exceeded'}
    actions = None
    action_indent = 0
    for number, indent, line in lines:
        if match := _IOS_QOS_POLICER_COUNTER.fullmatch(line):
            outcome, packets, octets, action = match.groups()
            outcome = outcome.lower()
            actions = None
            if outcome in outcomes:
                unknown.append(number)
                continue
            action_indent = indent
            entry = {'packets': int(packets), 'bytes': int(octets), 'actions': [action] if action else []}
            outcomes[outcome] = entry
            if action is None:
                actions = entry['actions']
        elif actions is not None and indent > action_indent and re.fullmatch(_IOS_QOS_POLICER_ACTION, line, re.I):
            actions.append(line)
        else:
            actions = None
            if limit := _IOS_QOS_POLICER_LIMIT.fullmatch(line):
                if limit[1] or limit[2]:
                    required.add('violated')
            elif rates := _IOS_QOS_POLICER_RATES.fullmatch(line):
                if classic_ios and rates[1]:
                    required.add('violated')
            else:
                unknown.append(number)
    return outcomes, unknown, required <= outcomes.keys() and all(entry['actions'] for entry in outcomes.values())


def _ios_qos_policy(lines, interface, *, classic_ios=False):
    records, unknown, policies = [], [], []
    active = None
    class_indent = 0
    queueing = set()
    policers = {}
    policer_indent = None
    complete = True
    port = normalize_port(interface)['name']
    for number, raw in lines:
        line = raw.strip()
        indent = len(raw.expandtabs()) - len(raw.expandtabs().lstrip())
        if policer_indent is not None and indent <= policer_indent:
            policer_indent = None
        if re.fullmatch(_IOS_QOS_PORT, line):
            if normalize_port(line)['name'].lower() != port.lower():
                return [], [number], False
            continue
        while policies and indent <= policies[-1][0]:
            complete &= policies.pop()[3]
            active = None
        if policy := _IOS_QOS_POLICY.fullmatch(line):
            policer_indent = None
            direction = policy[1] or (policies[-1][1] if policies else None)
            if direction is None:
                unknown.append(number)
                continue
            policies.append([indent, direction.lower(), policy[2], False])
            active = None
        elif (match := _IOS_QOS_CLASS.fullmatch(line)) and policies:
            policer_indent = None
            policies[-1][3] = True
            active = {'interface': port, 'direction': policies[-1][1],
                      'policy_path': [item[2] for item in policies], 'class_name': match[1]}
            class_indent = indent
            records.append(active)
        elif active is not None and indent >= class_indent:
            index = len(records) - 1
            if policer_indent is not None:
                policers[index].append((number, indent, line))
                continue
            if line.casefold() == 'police:' and index not in policers:
                policer_indent = indent
                policers[index] = []
                continue
            if line.casefold() == 'queueing':
                queueing.add(index)
            for pattern, fields in _IOS_QOS_COUNTERS:
                if match := re.fullmatch(pattern, line, re.I):
                    # Deeper packet counters under Match describe the criterion, not the class.
                    active.update({name: int(value) for name, value in zip(fields, match.groups())
                                   if name not in active})
                    break
            else:
                if not _IOS_QOS_DETAILS.fullmatch(line):
                    unknown.append(number)
        else:
            unknown.append(number)
    complete &= bool(records) and all(item[3] for item in policies)
    complete &= all({'packets', 'bytes', 'drop_rate_bps'} <= row.keys() for row in records)
    complete &= all({'total_drops', 'dropped_packets'} & records[index].keys() for index in queueing)
    for index, block in policers.items():
        records[index]['policer'], unparsed, finished = _ios_qos_policer(block, classic_ios=classic_ios)
        unknown.extend(unparsed)
        complete &= finished
    return records, sorted(unknown), complete


def _ios_qos_queues(lines, interface):
    records, unknown = {}, []
    category = None
    complete = True
    port = normalize_port(interface)['name']
    policer = None
    header = re.fullmatch(rf'({_IOS_QOS_PORT})(?: \(All statistics are in packets\))?', lines[0][1].strip(), re.I)
    if not header or normalize_port(header[1])['name'].lower() != port.lower():
        return [], [lines[0][0]], False
    for number, raw in lines[1:]:
        line = raw.strip()
        if match := re.fullmatch(r'output queues (enqueued|dropped):', line, re.I):
            category = match[1].lower()
        elif (match := re.fullmatch(r'queue (\d+):\s+(\d+)\s+(\d+)\s+(\d+)', line, re.I)) and category:
            row = records.setdefault(int(match[1]), {'interface': port, 'queue': int(match[1])})
            complete &= category not in row
            row[category] = [int(value) for value in match.groups()[1:]]
        elif match := re.fullmatch(r'Policer:\s+Inprofile:\s*(\d+)\s+OutofProfile:\s*(\d+)', line, re.I):
            policer = {'interface': port, 'policer_in_profile': int(match[1]), 'policer_out_of_profile': int(match[2])}
        elif not re.fullmatch(r'(?:dscp|cos):\s*(?:incoming|outgoing)|-+|'
                              r'\d+\s*-\s*\d+\s*:\s*\d+(?:\s+\d+)*|'
                              r'queue:\s+threshold1\s+threshold2\s+threshold3', line, re.I):
            unknown.append(number)
    # The documented Catalyst format has four egress queues, with three thresholds each.
    complete &= set(records) == {0, 1, 2, 3} and all({'enqueued', 'dropped'} <= row.keys() for row in records.values())
    return [*records.values(), *([policer] if policer else [])], unknown, complete and policer is not None


_XE_FED_COLUMNS = {
    'Enqueue': ('Buffers', 'Enqueue-TH0', 'Enqueue-TH1', 'Enqueue-TH2', 'Qpolicer'),
    'Drop': ('Drop-TH0', 'Drop-TH1', 'Drop-TH2', 'SBufDrop', 'QebDrop', 'QpolicerDrop'),
}


def _xe_fed_qos_queues(lines, interface):
    records, unknown = {}, []
    queues = {'Enqueue': set(), 'Drop': set()}
    section, port, column_count = None, None, 0
    sections = set()
    for number, raw in lines:
        line = raw.strip()
        if heading := re.fullmatch(r'DATA Port:(\d+) (Enqueue|Drop) Counters', line):
            section, port, column_count = heading[2], int(heading[1]), 0
            if section in sections:
                unknown.append(number)
                section = None
            else:
                sections.add(section)
            continue
        if re.fullmatch(r'-+(?:\s+-+)*', line):
            continue
        parts = line.split()
        if section and not column_count and parts[0] in {'Q', 'Queue'}:
            expected = _XE_FED_COLUMNS[section]
            if tuple(parts[1:]) in (expected, expected[:-1]):
                column_count = len(parts) - 1
                continue
        if column_count:
            units = ['(Bytes)'] * column_count
            if section == 'Enqueue':
                units[0] = '(Count)'
            if parts == units:
                continue
            if len(parts) == column_count + 1 and all(value.isdecimal() for value in parts):
                queue, *values = map(int, parts)
                key = (port, queue)
                if key not in queues[section]:
                    queues[section].add(key)
                    row = records.setdefault(key, {'interface': interface, 'data_port': port, 'queue': queue})
                    if section == 'Enqueue':
                        row.update(buffer_count=values[0], enqueued_bytes=values[1:4])
                        if len(values) == 5:
                            row['policer_enqueued_bytes'] = values[4]
                    else:
                        row.update(dropped_bytes=values[:3], shared_buffer_drop_bytes=values[3],
                                   queue_buffer_drop_bytes=values[4])
                        if len(values) == 6:
                            row['policer_drop_bytes'] = values[5]
                    continue
        unknown.append(number)
    complete = bool(queues['Enqueue']) and queues['Enqueue'] == queues['Drop']
    return list(records.values()), unknown, complete


_IOS_NAT_HEADER = re.compile(r'Pro\s+Inside global\s+Inside local\s+Outside local\s+Outside global', re.I)


def _ios_nat_endpoint(value):
    if value in {'---', '--'}:
        return None
    address, sep, port = value.partition(':')
    if sep and (not port.isdecimal() or int(port) > 65535):
        raise ValueError('invalid NAT port')
    return {'address': str(ipaddress.IPv4Address(address)), 'port': int(port) if sep else None}


def _ios_nat_translations(lines, _interface):
    records, unknown = [], []
    total, header = None, False
    for number, raw in lines:
        line = raw.strip()
        if _IOS_NAT_HEADER.fullmatch(line) and not header and total is None:
            header = True
            continue
        if (match := re.fullmatch(r'Total number of translations:\s*(\d+)', line, re.I)) and total is None:
            total = int(match[1])
            continue
        parts = line.split()
        if header and total is None and len(parts) == 5 and re.fullmatch(r'---|[a-z][a-z0-9-]*', parts[0]):
            try:
                endpoints = [_ios_nat_endpoint(value) for value in parts[1:]]
            except ValueError:
                pass
            else:
                records.append(dict(zip(('inside_global', 'inside_local', 'outside_local', 'outside_global'),
                                        endpoints), protocol=None if parts[0] == '---' else parts[0]))
                continue
        unknown.append(number)
    complete = (header or total == 0) and (total is None or total == len(records))
    return records, unknown, complete


_IOS_NAT_COUNTS = [
    (r'Total (?:active )?translations:\s*(\d+) \((\d+) static, (\d+) dynamic; (\d+) extended\)',
     ('total_translations', 'static_translations', 'dynamic_translations', 'extended_translations')),
    (r'Hits:\s*(\d+)\s+Misses:\s*(\d+)', ('hits', 'misses')),
    (r'Expired translations:\s*(\d+)', ('expired_translations',)),
    (r'Peak translations:\s*(\d+)(?:, occurred .+ ago)?', ('peak_translations',)),
    (r'max entry: max allowed (\d+), used (\d+), missed (\d+)',
     ('translation_limit', 'translation_limit_used', 'translation_limit_misses')),
    (r'In-to-out drops: (\d+)\s+Out-to-in drops: (\d+)', ('outbound_drops', 'inbound_drops')),
    (r'Pool stats drop: (\d+)\s+Mapping stats drop: (\d+)', ('pool_drops', 'mapping_drops')),
    (r'Port block alloc fail: (\d+)', ('port_block_allocation_failures',)),
    (r'IP alias add fail: (\d+)', ('ip_alias_creation_failures',)),
    (r'Limit entry add fail: (\d+)', ('limit_entry_creation_failures',)),
]
_IOS_NAT_DETAIL = re.compile(
    r'Dynamic mappings:|-- (?:Inside|Outside) (?:Source|Destination)|nat-limit statistics:'
    r'|(?:\[Id: \d+\] )?(?:access-list|route-map) \S+ (?:pool|interface) \S+ refcount \d+'
    r'|Reserved port setting (?:enabled|disabled) provisioned (?:yes|no)|start [\d.]+\s+end [\d.]+', re.I,
)


def _ios_nat_statistics(lines, _interface):
    summary, pools, unknown = {}, [], []
    direction = None
    port_list = rf'{_IOS_QOS_PORT}(?:,\s*{_IOS_QOS_PORT})*,?'
    for number, raw in lines:
        line = raw.strip()
        if match := re.fullmatch(rf'(Inside|Outside) interfaces:(?:\s+({port_list}))?', line, re.I):
            direction = match[1].lower() + '_interfaces'
            summary[direction] = re.findall(_IOS_QOS_PORT, match[2] or '')
            continue
        if direction and re.fullmatch(port_list, line):
            summary[direction].extend(re.findall(_IOS_QOS_PORT, line))
            continue
        direction = None
        if match := re.fullmatch(r'pool (\S+):\s*(?:id \d+, )?(?:netmask [\d.]+|prefix-length \d+)', line, re.I):
            pools.append({'pool': match[1]})
        elif (match := re.fullmatch(r'type \S+, total addresses (\d+), allocated (\d+) \((\d+)%\), misses (\d+)',
                                    line, re.I)) and pools and 'total_addresses' not in pools[-1]:
            pools[-1].update(zip(('total_addresses', 'allocated_addresses', 'allocated_percent', 'allocation_misses'),
                                 map(int, match.groups())))
        else:
            for pattern, fields in _IOS_NAT_COUNTS:
                if (match := re.fullmatch(pattern, line, re.I)) and fields[0] not in summary:
                    summary.update(zip(fields, map(int, match.groups())))
                    break
            else:
                if not _IOS_NAT_DETAIL.fullmatch(line):
                    unknown.append(number)
    complete = {'total_translations', 'hits', 'misses', 'expired_translations'} <= summary.keys()
    if complete:
        complete = (summary['total_translations'] == summary['static_translations'] + summary['dynamic_translations']
                    and summary['extended_translations'] <= summary['total_translations'])
    complete &= all('total_addresses' in pool and pool['allocated_addresses'] <= pool['total_addresses']
                    and pool['allocated_percent'] <= 100 for pool in pools)
    return [*([summary] if summary else []), *pools], unknown, complete


_IOS_IKE_V1_HEADER = re.compile(r'dst\s+src\s+state\s+conn-id(?P<slot>\s+slot)?(?P<status>\s+status)?', re.I)
_IOS_IKE_V2_HEADER = re.compile(r'Tunnel-id\s+Local\s+Remote\s+fvrf/ivrf\s+Status', re.I)


def _ios_ikev1(lines, _interface):
    records, unknown = [], []
    fields = ()
    saw_header = False
    for number, raw in lines:
        line = raw.strip()
        if re.fullmatch(r'IPv[46] Crypto ISAKMP SA', line, re.I):
            fields = ()
        elif (header := _IOS_IKE_V1_HEADER.fullmatch(line)) and (header['slot'] or header['status']):
            saw_header = True
            fields = ('connection_id',)
            if header['slot']:
                fields += ('slot',)
            if header['status']:
                fields += ('sa_status',)
        elif fields and len(parts := line.split(maxsplit=2 + len(fields))) == 3 + len(fields):
            try:
                destination, source = map(lambda value: str(ipaddress.ip_address(value)), parts[:2])
                if not re.fullmatch(r'[A-Z0-9_]+', parts[2]):
                    raise ValueError('invalid IKEv1 state')
                row = {'destination': destination, 'source': source, 'state': parts[2]}
                for field, value in zip(fields, parts[3:]):
                    if field == 'sa_status' and re.fullmatch(r'[A-Z0-9_]+(?: \(deleted\))?', value):
                        row[field] = value
                    elif field != 'sa_status' and value.isdecimal():
                        row[field] = int(value)
                    else:
                        raise ValueError('invalid IKEv1 table value')
            except ValueError:
                unknown.append(number)
            else:
                records.append(row)
        else:
            unknown.append(number)
    return records, unknown, saw_header


def _ios_ikev2(lines, _interface):
    records, unknown = [], []
    active = None
    header = False
    for number, raw in lines:
        line = raw.strip()
        if re.fullmatch(r'IPv[46] Crypto IKEv2 SA', line, re.I):
            header, active = False, None
        elif _IOS_IKE_V2_HEADER.fullmatch(line):
            header, active = True, None
        elif header and (match := re.fullmatch(r'(\d+)\s+(\S+)/(\d+)\s+(\S+)/(\d+)\s+(\S+)/(\S+)\s+([A-Z_]+)', line)):
            active = None
            try:
                local, remote = (str(ipaddress.ip_address(match[i])) for i in (2, 4))
            except ValueError:
                unknown.append(number)
            else:
                active = {'tunnel_id': int(match[1]), 'local_address': local, 'local_port': int(match[3]),
                          'remote_address': remote, 'remote_port': int(match[5]), 'front_vrf': match[6],
                          'inside_vrf': match[7], 'sa_status': match[8]}
                records.append(active)
        elif active is not None and (match := re.fullmatch(r'Life/Active Time:\s*(\d+)/(\d+) sec', line, re.I)):
            active.update(lifetime_seconds=int(match[1]), active_seconds=int(match[2]))
        elif active is not None and re.fullmatch(r'Encr: [\w/-]+(?: \(keysize: \d+\)|, keysize: \d+)?, '
                                                 r'(?:Hash|PRF): [\w/-]+(?:, Hash: [\w/-]+)?, DH Grp:\s*\d+, '
                                                 r'Auth(?: sign)?: [\w/-]+(?:, Auth verify: [\w/-]+)?', line, re.I):
            active['algorithms'] = line
        else:
            unknown.append(number)
    return records, unknown, (header or bool(records)) and all(
        row['sa_status'] != 'READY' or {'algorithms', 'active_seconds'} <= row.keys() for row in records
    )


_IOS_IPSEC_COUNTER = re.compile(r'#(?:pkts )?([a-z][\w .()-]*?)\s*:?\s+(\d+)', re.I)
_IOS_IPSEC_DETAIL = re.compile(
    r'Group: \S+|(?:PERMIT|DENY), flags=\{[^}]*\}|(?:plaintext|path|media) mtu \d+.*'
    r'|PFS \(Y/N\): [YN], DH group: \S+|in use settings\s*=\s*\{[^}]*\}'
    r'|(?:slot: \d+, )?conn id: \d+,.+|sa timing: remaining key lifetime \((?:k/sec|sec)\): .+'
    r'|HA last key lifetime sent\(k\): \(\d+\)|ike_cookies: (?:[0-9a-f]{8} ){3}[0-9a-f]{8}'
    r'|Kilobyte Volume Rekey has been disabled|IV size: \d+ bytes|replay detection support: [YN]'
    r'|ecn bit support: [YN] status: \w+|local crypto endpt\.: \S+, remote crypto endpt\.: \S+', re.I,
)


def _ios_ipsec(lines, _interface):
    if len(lines) == 1 and lines[0][1].strip().lower() == 'no sas found':
        return [], [], True
    records, unknown = [], []
    context, row, sa, direction = {}, None, None, None
    for number, raw in lines:
        line = raw.strip()
        if match := re.fullmatch(r'interface:\s*(\S+)', line, re.I):
            context = {'interface': match[1]}
            row, sa, direction = None, None, None
        elif 'interface' in context and (match := re.fullmatch(r'Crypto map tag:\s*(\S+), local addr\.?\s+(\S+)', line, re.I)):
            context.update(crypto_map=match[1], local_address=match[2])
        elif 'interface' in context and (match := re.fullmatch(r'protected vrf:\s*(\S+)', line, re.I)):
            context['vrf'] = match[1]
        elif 'interface' in context and (match := re.fullmatch(r'local\s+ident \(addr/mask/prot/port\):\s*\((\S+)\)', line, re.I)):
            row = {**context, 'local_selector': match[1], 'counters': {}, 'associations': []}
            records.append(row)
            sa, direction = None, None
        elif row is None:
            unknown.append(number)
        elif match := re.fullmatch(r'remote\s+ident \(addr/mask/prot/port\):\s*\((\S+)\)', line, re.I):
            row['remote_selector'] = match[1]
        elif match := re.fullmatch(r'current_peer\s+(\S+) port (\d+)', line, re.I):
            row.update(peer=match[1], peer_port=int(match[2]))
        elif match := re.fullmatch(r'current outbound spi:\s*((?:0x)?[0-9a-f]+)(?:\(\d+\))?', line, re.I):
            row['outbound_spi'] = match[1]
        elif match := re.fullmatch(r'(inbound|outbound) (esp|ah|pcp) sas:', line, re.I):
            direction = (match[1].lower(), match[2].lower())
            sa = None
            if direction == ('outbound', 'esp'):
                row['outbound_esp_reported'] = True
        elif direction and (match := re.fullmatch(r'spi:\s*((?:0x)?[0-9a-f]+)(?:\(\d+\))?', line, re.I)):
            sa = {'direction': direction[0], 'protocol': direction[1], 'spi': match[1]}
            row['associations'].append(sa)
        elif sa is not None and (match := re.fullmatch(r'transform:\s*([\w-]+(?:\s+[\w-]+)*)\s*,?', line, re.I)):
            sa['transforms'] = match[1].split()
        elif sa is not None and (match := re.fullmatch(r'Status:\s*(\S+)', line, re.I)):
            sa['sa_status'] = match[1]
        elif sa is not None and (match := re.fullmatch(r'replay detection support: [YN]\s+replay window size: (\d+)',
                                                      line, re.I)):
            sa['replay_window_size'] = int(match[1])
        elif line.startswith('#') and all(_IOS_IPSEC_COUNTER.fullmatch(part.strip()) for part in line.rstrip(',').split(',')):
            for part in line.rstrip(',').split(','):
                counter = _IOS_IPSEC_COUNTER.fullmatch(part.strip())
                row['counters'][counter[1]] = int(counter[2])
        elif not _IOS_IPSEC_DETAIL.fullmatch(line):
            unknown.append(number)
    complete = bool(records)
    for row in records:
        complete &= (row.pop('outbound_esp_reported', False) and
                     {'crypto_map', 'peer', 'remote_selector', 'outbound_spi'} <= row.keys() and
                     {'encaps', 'decaps', 'send errors', 'recv errors'} <= row['counters'].keys() and
                     all('transforms' in sa for sa in row['associations']))
    return records, unknown, complete


_IOS_G57_PARSERS = {
    'qos_policy': _ios_qos_policy, 'qos_queues': _ios_qos_queues,
    'nat_translations': _ios_nat_translations, 'nat_statistics': _ios_nat_statistics,
    'ikev1_sa': _ios_ikev1, 'ikev2_sa': _ios_ikev2, 'ipsec_sa': _ios_ipsec,
}


def ios_g57_diagnostics(profile, query, text, parameters, state):
    lines = [(number, raw) for number, raw in enumerate(text.splitlines(), 1) if raw.strip()]
    records, unknown, complete = [], [], state == 'empty'
    if state == 'ok':
        parser = _xe_fed_qos_queues if profile == 'cisco_xe' and query == 'qos_queues' else _IOS_G57_PARSERS[query]
        options = {'classic_ios': True} if profile == 'cisco_ios' and query == 'qos_policy' else {}
        records, unknown, complete = parser(lines, parameters.get('interface'), **options)
        complete &= not unknown
        state = ('ok' if records else 'empty') if complete else ('incomplete' if records else 'unparsed')
    result = response_envelope(profile, state, [source_record(query, text, state)], identity_coverage=False)
    result.update(records=records, unparsed=[{'line': number} for number in unknown],
                  coverage={'complete': complete, 'parsed_records': len(records),
                            'unparsed_lines': len(unknown), 'missing_fields': []})
    return result


# G89 — Cisco IOS XE hardware Quantum Flow Processor.
_QFP_DROP_HEADER = re.compile(r"Global Drop Stats\s+Packets\s+Octets")
_QFP_DROP_ROW = re.compile(r"([A-Za-z][A-Za-z0-9_/-]*)\s+(\d+)\s+(\d+)")
_QFP_SEPARATOR = re.compile(r"-+")
_QFP_WINDOWS = {"5_seconds": 5, "1_minute": 60, "5_minutes": 300, "60_minutes": 3600}
_QFP_CPP = re.compile(r"CPP\s+(\d+):?\s+5 secs\s+1 min\s+5 min\s+60 min")
_QFP_DIRECTION = re.compile(r"(Input|Output):")
_QFP_TRAFFIC = re.compile(r"(Priority|Non-Priority|Total)?\s*\((pps|bps)\)")
_QFP_PROCESSING = re.compile(r"(Processing|Crypto|RX|TX):\s+Load \(pct\)|Idle \(pct\)")


def _qfp_drops(lines):
    last_clearing = None
    if lines:
        label, _, value = lines[0].partition(":")
        if label.rstrip() == "Last clearing of QFP drops statistics" and value:
            last_clearing = value.lstrip()
            lines = lines[1:]
    if lines and _QFP_SEPARATOR.fullmatch(lines[0]):
        lines = lines[1:]
    if len(lines) < 2 or not _QFP_DROP_HEADER.fullmatch(lines[0]) or not _QFP_SEPARATOR.fullmatch(lines[1]):
        return {}, [], False
    rows = []
    for line in lines[2:]:
        match = _QFP_DROP_ROW.fullmatch(line)
        if match:
            rows.append(dict(reason=match[1], packets=int(match[2]), octets=int(match[3])))
    summary = {"last_clearing": last_clearing}
    complete = bool(rows) and len(rows) == len(lines) - 2 == len({row["reason"] for row in rows})
    return summary, rows, complete


def _qfp_utilization(lines):
    records = []
    crypto_processors = set()
    unknown = False
    for line in lines:
        processor = _QFP_CPP.fullmatch(line)
        if processor:
            records.append({"cpp": int(processor[1]), "input": {}, "output": {}, "load_percent": {}})
            crypto_seen = False
            direction = None
            priority = None
            continue
        if not records:
            unknown = True
            continue
        if line == "Crypto/IO" and not crypto_seen:
            crypto_seen = True
            crypto_processors.add(records[-1]["cpp"])
            continue
        fields = line.rsplit(maxsplit=4)
        if len(fields) != 5 or not all(value.isdecimal() for value in fields[1:]):
            unknown = True
            continue
        label, *measurements = fields
        values = dict(zip(_QFP_WINDOWS, map(int, measurements)))
        data = records[-1]
        prefix = _QFP_DIRECTION.match(label)
        traffic_label = label[prefix.end():].lstrip() if prefix else label
        traffic = _QFP_TRAFFIC.fullmatch(traffic_label)
        load = _QFP_PROCESSING.fullmatch(label)
        if traffic and not crypto_seen:
            category, unit = traffic.groups()
            if prefix:
                direction = prefix[1].lower()
            if category:
                priority = category.lower().replace("-", "_")
            if direction is None or priority is None or unit == "pps" and category is None:
                unknown = True
                continue
            kind = data[direction].setdefault(priority, {})
            if unit in kind:
                unknown = True
            kind[unit] = values
        elif load and all(0 <= value <= 100 for value in values.values()):
            field = (load[1] or "Idle").lower()
            if (field == "processing") == crypto_seen or field in data["load_percent"]:
                unknown = True
            data["load_percent"][field] = values
        else:
            unknown = True
    for record in records:
        for direction in ("input", "output"):
            traffic = record[direction]
            if ("total" not in traffic or any(set(rates) != {"pps", "bps"} for rates in traffic.values())
                    or set(traffic) not in ({"total"}, {"priority", "non_priority", "total"})):
                unknown = True
        loads = set(record["load_percent"])
        expected = {"processing", "crypto", "rx", "tx", "idle"} if record["cpp"] in crypto_processors else {"processing"}
        if loads != expected:
            unknown = True
    complete = bool(records) and not unknown and len(records) == len({row["cpp"] for row in records})
    return {"window_seconds": _QFP_WINDOWS}, records, complete


def ios_xe_qfp_diagnostic(query, text, status, *, full_page):
    """Decode only the documented hardware formats and keep partial observations distinct."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if full_page:
        summary, records, complete = _qfp_drops(lines) if query == "qfp_drops" else _qfp_utilization(lines)
    else:
        summary, records, complete = {}, [], False
    complete = complete and status == "ok"
    verdict = "ok" if complete else "incomplete"
    result = response_envelope("cisco_xe", verdict, [source_record(query, text, status)], identity_coverage=False)
    result.update(summary=summary, records=records, coverage={"complete": complete})
    return result
