"""Linux iproute2 text adapters; catalogue queries and permissions stay authoritative.

Brief links have no MTU. Only the existing, inventory-bound interface_link query
supplies it. Unknown tokens/lines are retained rather than inferred as defaults.
"""
from __future__ import annotations

import ipaddress
import re

from .normalization import normalize_mac

STATES = frozenset({'UP', 'DOWN', 'UNKNOWN', 'DORMANT', 'LOWERLAYERDOWN', 'NOTPRESENT', 'TESTING'})
NUD = frozenset({'INCOMPLETE', 'REACHABLE', 'STALE', 'DELAY', 'PROBE', 'FAILED', 'NOARP', 'PERMANENT', 'NONE'})
NAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.:/-]{0,63}')


def name(value):
    # ip prints the peer/master suffix on veth/VLAN links; it is not the name.
    value = value.split('@', 1)[0]
    if not NAME.fullmatch(value):
        raise ValueError('invalid Linux interface name')
    return value


def _state(value):
    if value not in STATES:
        raise ValueError('unknown Linux link state')
    return value.lower()


def _flags(value):
    if not re.fullmatch(r'<[A-Z0-9_,\-]+>', value):
        raise ValueError('invalid link flags')
    return 'up' if 'UP' in value[1:-1].split(',') else 'down'


def _brief_link(value):
    parts = value.split()
    if len(parts) not in (3, 4):
        return None
    mac = normalize_mac(parts[2]) if len(parts) == 4 and parts[2] != 'link/none' else None
    return t.record('interface', name=name(parts[0]), oper_status=_state(parts[1]),
                    mac=mac, admin_status=_flags(parts[-1]))


def addresses(table, text):
    """ip -brief address: one row per printed IPv4/IPv6 address, including aliases."""
    def parse(value):
        parts = value.split()
        interface, state = name(parts[0]), _state(parts[1])
        rows = []
        index = 2
        while index < len(parts):
            if parts[index] == 'metric':
                if index + 1 >= len(parts) or not parts[index + 1].isdigit():
                    return None
                index += 2
                continue
            address = ipaddress.ip_interface(parts[index])
            index += 1
            if index < len(parts) and parts[index] == 'peer':
                peer = parts[index + 1]
                if '/' not in peer:
                    return None
                peer_address = ipaddress.ip_interface(peer)
                if peer_address.version != address.version:
                    return None
                # Point-to-point brief output prints the prefix on the peer.
                address = ipaddress.ip_interface(f'{address.ip}/{peer_address.network.prefixlen}')
                index += 2
            rows.append(t.record('ip_interface', interface=interface, ip=str(address.ip),
                                 prefix_length=address.network.prefixlen, oper_status=state))
        return rows
    return t.lines(text, parse)


def _route(value):
    parts = value.split()
    prefix = '0.0.0.0/0' if parts[0] == 'default' else str(ipaddress.IPv4Network(parts[0]))
    values, index = {}, 1
    while index < len(parts):
        key = parts[index]
        if key in ('linkdown', 'onlink'):
            index += 1
            continue
        item = parts[index + 1]
        if key in values:
            return None
        if key in ('via', 'src'):
            item = str(ipaddress.IPv4Address(item))
        elif key == 'dev':
            item = name(item)
        elif key == 'metric':
            if not item.isdigit():
                return None
        elif key in ('proto', 'scope'):
            if not re.fullmatch(r'[A-Za-z0-9_-]+', item):
                return None
        else:
            return None
        values[key] = item
        index += 2
    return t.record('route', prefix=prefix, next_hop=values.get('via'),
                    interface=values.get('dev'), protocol=values.get('proto'))


def _neighbor(value):
    parts = value.split()
    address = str(ipaddress.ip_address(parts[0]))
    values, index, state = {}, 1, None
    while index < len(parts):
        key = parts[index]
        if key in NUD:
            if state is not None:
                return None
            state = key.lower()
            index += 1
        elif key in ('router', 'proxy', 'extern_learn', 'managed', 'use'):
            index += 1
        elif key in ('dev', 'lladdr') and key not in values:
            values[key] = name(parts[index + 1]) if key == 'dev' else normalize_mac(parts[index + 1])
            index += 2
        else:
            return None
    if 'dev' not in values:
        return None
    return t.record('neighbor_l3', ip=address, mac=values.get('lladdr'),
                    interface=values['dev'], type=state)


def _fdb(value):
    parts = value.split()
    mac = normalize_mac(parts[0])
    values, index, kind = {}, 1, None
    while index < len(parts):
        key = parts[index]
        if key in ('permanent', 'static', 'dynamic'):
            selected = 'static' if key != 'dynamic' else 'dynamic'
            if kind is not None and kind != selected:
                return None
            kind = selected
            index += 1
        elif key in ('self', 'offload', 'extern_learn', 'sticky', 'router', 'stale'):
            index += 1
        elif key in ('dev', 'master', 'vlan') and key not in values:
            item = parts[index + 1]
            if key == 'vlan':
                if not item.isdigit() or not 1 <= int(item) <= 4094:
                    return None
                item = int(item)
            else:
                item = name(item)
            values[key] = item
            index += 2
        else:
            return None
    if 'dev' not in values:
        return None
    return t.record('mac_entry', mac=mac, port=values['dev'], vlan_id=values.get('vlan'), type=kind)


# Explicitly recognized ip -details metadata (not exposed by the shared schema).
LINK_META = frozenset('qdisc state mode group qlen master promiscuity allmulti minmtu maxmtu '
                     'link-netnsid addrgenmode numtxqueues numrxqueues gso_max_size gso_max_segs tso_max_size '
                     'tso_max_segs gro_max_size gso_ipv4_max_size gro_ipv4_max_size parentbus parentdev brd permaddr'.split())
BRIDGE_META = frozenset('forward_delay hello_time max_age ageing_time stp_state priority vlan_filtering '
                       'vlan_protocol bridge_id designated_root root_port root_path_cost topology_change '
                       'topology_change_detected hello_timer tcn_timer topology_change_timer gc_timer '
                       'vlan_default_pvid vlan_stats_enabled vlan_stats_per_port group_fwd_mask group_address '
                       'mcast_snooping no_linklocal_learn mcast_vlan_snooping mcast_router mcast_query_use_ifaddr '
                       'mcast_querier mcast_hash_elasticity mcast_hash_max mcast_last_member_count '
                       'mcast_startup_query_count mcast_last_member_interval mcast_membership_interval '
                       'mcast_querier_interval mcast_query_interval mcast_query_response_interval '
                       'mcast_startup_query_interval mcast_stats_enabled mcast_igmp_version mcast_mld_version '
                       'nf_call_iptables nf_call_ip6tables nf_call_arptables fdb_n_learned fdb_max_learned mst_enabled'.split())

BRIDGE_SLAVE_META = frozenset('state priority cost hairpin guard root_block fastleave learning flood '
                              'port_id port_no designated_port designated_cost designated_bridge designated_root '
                              'hold_timer message_age_timer forward_delay_timer topology_change_ack config_pending '
                              'proxy_arp proxy_arp_wifi mcast_router mcast_fast_leave mcast_flood bcast_flood '
                              'mcast_to_unicast neigh_suppress neigh_vlan_suppress vlan_tunnel isolated locked mab '
                              'group_fwd_mask group_fwd_mask_str backup_port backup_nhid'.split())


def _vlan_metadata(parts):
    if (len(parts) < 4 or parts[0] != 'protocol' or parts[1] not in ('802.1Q', '802.1ad')
            or parts[2] != 'id' or not parts[3].isdigit() or not 1 <= int(parts[3]) <= 4094):
        return False
    remaining = parts[4:]
    if remaining and remaining[0].startswith('<'):
        if not re.fullmatch(r'<(?:REORDER_HDR|GVRP|LOOSE_BINDING|MVRP|BRIDGE_BINDING)(?:,(?:REORDER_HDR|GVRP|LOOSE_BINDING|MVRP|BRIDGE_BINDING))*>', remaining[0]):
            return False
        remaining = remaining[1:]
    return _metadata(remaining, LINK_META)


def _metadata(parts, allowed):
    return len(parts) % 2 == 0 and all(parts[index] in allowed for index in range(0, len(parts), 2))


def detail(table, text):
    rows, unknown = [], []
    current = None
    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value:
            continue
        recognized = False
        try:
            header = re.fullmatch(r'\d+: (\S+): (<[^>]+>) mtu (\d+)(?: (.*))?', value)
            if header:
                current = None
                meta = (header[4] or '').split()
                if _metadata(meta, LINK_META):
                    fields = dict(zip(meta[::2], meta[1::2]))
                    current = t.record('interface', name=name(header[1]), admin_status=_flags(header[2]),
                                       oper_status=_state(fields['state']) if 'state' in fields else None,
                                       mtu=int(header[3]))
                    rows.append(current)
                    recognized = True
            elif current is not None:
                parts = value.split()
                if parts[0] in ('link/ether', 'link/loopback') and _metadata(parts[2:], LINK_META):
                    current['mac'] = normalize_mac(parts[1])
                    recognized = True
                elif parts[0] == 'link/none' and _metadata(parts[1:], LINK_META):
                    recognized = True
                elif parts[0] == 'altname' and len(parts) == 2:
                    name(parts[1])
                    recognized = True
                elif parts[0] == 'bridge' and _metadata(parts[1:], BRIDGE_META | LINK_META):
                    recognized = True
                elif parts[0] == 'bridge_slave' and _metadata(parts[1:], BRIDGE_SLAVE_META | LINK_META):
                    recognized = True
                elif parts[0] == 'vlan' and _vlan_metadata(parts[1:]):
                    recognized = True
        except (ValueError, IndexError):
            pass
        if not recognized:
            unknown.append({'line': number, 'text': raw})
    return rows, unknown


def parse(table, text):
    if table == 'ip_interface':
        return addresses(table, text)
    parser = {'interface': _brief_link, 'route': _route,
              'neighbor_l3': _neighbor, 'mac_entry': _fdb}.get(table)
    return t.lines(text, parser) if parser else ([], [])


def register(bindings, parsers, query_parsers):
    bindings['linux'] = {'interface': 'links', 'ip_interface': 'addresses', 'route': 'routes',
                         'route_all': 'routes', 'neighbor_l3': 'neighbors', 'neighbor_l3_v6': 'neighbors',
                         'mac_entry': 'bridge_fdb'}
    parsers['linux'] = parse
    query_parsers[('linux', 'interface', 'interface_link')] = detail


# tables imports this module after defining the shared record/scanning helpers.
from . import tables as t  # noqa: E402
