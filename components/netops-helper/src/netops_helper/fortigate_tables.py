"""FortiGate-local tables, distinct from FortiLink managed-switch selectors.

Layouts come from the 80F / FortiOS 8.0.2 build0251 RO captures of
2026-11-09/10. Unknown lines remain evidence, including populated bridge
layouts for which this lab supplied no positive sample.
"""
from __future__ import annotations

import ipaddress
import json
import re


def policy_hits(rows):
    """Project the real 80F / 8.0.2 monitor/firewall/policy counter layout.

    A missing counter stays unknown. Zero hits describe only the lifetime of
    the device counters, not proof that a configured policy can be removed.
    Policy 0 is the implicit rule and is never an unused-policy candidate.
    """
    from datetime import datetime, timezone
    from .wifi_rest import RestError

    records, seen = [], set()
    for row in rows:
        policy_id = row.get('policyid')
        if type(policy_id) is not int or not 0 <= policy_id <= 4294967294 or policy_id in seen:
            raise RestError('invalid_response', 'fortios_rest_invalid_policy_id')
        seen.add(policy_id)
        missing = []

        def counter(name, required=True):
            value = row.get(name)
            if type(value) is int and value >= 0:
                return value
            if required or name in row:
                missing.append(name)
            return None

        hits, size, packets = counter('hit_count'), counter('bytes'), counter('packets')
        last = counter('last_used', required=hits != 0)
        utc = None
        if last:
            try:
                utc = datetime.fromtimestamp(last, timezone.utc).isoformat()
            except (ValueError, OverflowError, OSError):
                missing.append('last_used')
                last = None
        inconsistent = hits == 0 and (size not in (None, 0) or packets not in (None, 0) or bool(last))
        if inconsistent:
            missing.append('inconsistent_counters')
        complete = not missing
        records.append({'policy_id': policy_id, 'hit_count': hits, 'bytes': size, 'packets': packets,
                        'last_used': last, 'last_used_utc': utc,
                        'unused_candidate': (policy_id != 0 and hits == 0) if complete else None,
                        'state': 'ok' if complete else 'incomplete', 'missing_fields': missing})
    return records

QUERIES = {'interface': 'physical_interfaces', 'vlan': 'interface_vlan_ids',
           'lldp_neighbor': 'lldp_summary', 'mac_entry': None,
           # G11 (1.0.12, FP-07): FortiGate-local routing, aggregate and counter tables.
           'ospf_neighbor': 'ospf_neighbors', 'bgp_peer': 'bgp_summary', 'lag': 'lacp_detail',
           'interface_errors': 'interface_details', 'stp_port': 'local_stp_ports',
           'port_vlan': 'local_switch_vlans'}
# IPv6 OSPF neighbors print another column layout that was not measured; ospf_neighbor stays IPv4 here.
IPV6_QUERIES = {'bgp_peer': 'ipv6_bgp_summary', 'route': 'ipv6_routing_table'}
# Tables that read one enrolled interface: the interface filter is the CLI argument of the read.
INTERFACE_SLOTS = {'lag': 'aggregate', 'interface_errors': 'interface'}
def request(table, vlan_id, mac, ip, interface, address_family=None):
    from .read_policy import _validate_slot
    if ip is not None or (interface is not None and table not in ('interface', 'stp_port', 'port_vlan') + tuple(INTERFACE_SLOTS)) or (
            mac is not None and table != 'mac_entry') or (
            vlan_id is not None and table not in ('vlan', 'mac_entry')):
        raise ValueError('filter does not apply to this table')
    if address_family is not None and (table not in IPV6_QUERIES or address_family not in ('ipv4', 'ipv6')):
        raise ValueError('address_family applies to the FortiGate route and bgp_peer tables')
    filters, parameters = {}, {}
    if vlan_id is not None:
        filters['vlan_id'] = int(_validate_slot(vlan_id, 'vlan_id'))
    if mac is not None:
        filters['mac'] = _validate_slot(mac, 'mac_literal')
    if table in INTERFACE_SLOTS:
        if interface is None:
            raise ValueError('interface is required for the FortiGate ' + table + ' table; provide an enrolled '
                             + ('aggregate' if table == 'lag' else 'interface'))
        parameters[INTERFACE_SLOTS[table]] = _validate_slot(interface, 'fortios_interface')
    elif interface is not None:
        field = 'port' if table in ('stp_port', 'port_vlan') else 'name'
        filters[field] = _validate_slot(interface, 'fortios_interface')
    if address_family == 'ipv6':
        return IPV6_QUERIES[table], parameters, filters
    return QUERIES.get(table), parameters, filters


def physical(table, text):
    from . import tables as t
    rows, unknown, current, seen = [], [], None, set()

    def close(number):
        if current is not None and not {'status', 'speed'} <= seen:
            unknown.append({'line': number, 'text': 'incomplete physical interface: ' + current['name']})

    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value or value == '== [onboard]':
            continue
        head = re.fullmatch(r'==\[([A-Za-z0-9_.:-]+)\]', value)
        if head:
            close(number)
            current = t.record(table, name=head[1])
            current['duplex'] = None
            rows.append(current)
            seen = set()
            continue
        state = re.fullmatch(r'status: (up|down)', value)
        speed = re.fullmatch(r'speed: (?:(\d+)(Mbps|Gbps) \(Duplex: (full|half)\)|(n/a))', value)
        if current is not None and state and 'status' not in seen:
            current['oper_status'] = state[1]
            seen.add('status')
        elif current is not None and speed and 'speed' not in seen:
            if speed[1]:
                current.update(speed=speed[1] + ('M' if speed[2] == 'Mbps' else 'G'), duplex=speed[3])
            seen.add('speed')
        elif current is not None and re.fullmatch(
                r'(?:mode: (?:static|dhcp|pppoe)|ip: \S+ \S+|ipv6: \S+|medium: \S+|FEC(?:_cap)?: \S+)', value):
            continue
        else:
            unknown.append({'line': number, 'text': raw})
    close(len(text.splitlines()) or 1)
    return rows, unknown


def lldp(table, text):
    from . import tables as t

    def row(value):
        match = re.fullmatch(r"\d+ port '([^']+)' \d+\s+mac (" + t.MAC +
                             r")\s+chassis (" + t.MAC + r") port '([^']+)' system '([^']*)'", value)
        if match:
            return t.record(table, local_port=match[1], neighbor=match[5] or None, neighbor_port=match[4])
        return None

    return t.lines(text, row)


def configuration_view(text, keep=None):
    """Project only VLAN identity, parent and IPv4; never expose full config.

    `keep` (multi-VDOM): the names of the VLAN interfaces that may be projected; the others are left out.
    """
    from .fortiswitch_ports import _entries
    entries, unknown = _entries(text, ('system interface',))
    output = ['config system interface']
    for name, fields in entries:
        if 'vlanid' not in fields or (keep is not None and name not in keep):
            continue
        output.append('    edit ' + json.dumps(name, ensure_ascii=False))
        for field in ('vlanid', 'interface', 'ip'):
            if field in fields:
                output.append('        set ' + field + ' ' + ' '.join(json.dumps(v, ensure_ascii=False) for v in fields[field]))
        output.append('    next')
    output.append('end')
    output.extend('unrecognized configuration syntax from source line ' + str(item['line']) for item in unknown)
    return '\n'.join(output) + '\n'


def vdom_configuration_view(text, vdom):
    """The VLAN projection of one VDOM from `show system interface`, owners assigned before the projection.

    Measured (task 172): in multi-VDOM `show system interface` lists the interfaces of every VDOM, each with its
    own `set vdom`. Only VLAN interfaces whose own `set vdom` names `vdom` are projected; the projection never
    carries `set vdom`, so the owner is decided here, on the full entry. A VLAN interface without exactly one
    valid `set vdom` refuses (VdomRefused("vdom_membership_unverified")). Returns (projection, other VLANs).
    """
    from . import fortios_vdom
    from .fortiswitch_ports import _entries
    entries, unknown = _entries(text, ('system interface',))
    if unknown:
        raise fortios_vdom.VdomRefused('vdom_membership_unverified')
    keep, other = set(), 0
    for name, fields in entries:
        if 'vlanid' not in fields:
            continue
        owner = fields.get('vdom', [])
        if len(owner) != 1 or not fortios_vdom.VDOM_NAME.fullmatch(owner[0]):
            raise fortios_vdom.VdomRefused('vdom_membership_unverified')
        if owner[0] == vdom:
            keep.add(name)
        else:
            other += 1
    return configuration_view(text, keep), other


def vlans(table, text):
    from . import tables as t
    from .fortiswitch_ports import _entries
    entries, unknown = _entries(text, ('system interface',))
    rows = []
    for name, fields in entries:
        if 'vlanid' not in fields:
            continue
        try:
            value = fields['vlanid']
            if len(value) != 1 or not value[0].isdigit() or not 1 <= int(value[0]) <= 4094:
                raise ValueError()
            parent = fields.get('interface', [])
            if parent and len(parent) != 1:
                raise ValueError()
            address = fields.get('ip', [])
            if address and len(address) != 2:
                raise ValueError()
            ipv4 = ipaddress.IPv4Interface('/'.join(address)) if address else None
            row = t.record(table, name=name, vlan_id=int(value[0]))
            row.update(interface=parent[0] if parent else None, ip=str(ipv4.ip) if ipv4 else None,
                       prefix_length=ipv4.network.prefixlen if ipv4 else None, source='configuration')
            rows.append(row)
        except ValueError:
            unknown.append({'line': 1, 'text': 'invalid VLAN interface: ' + name})
    return rows, unknown


def bridge(table, text):
    """Only the observed empty bridge layout is qualified; populated rows stay unknown."""
    from . import tables as t
    return t.lines(text, lambda value: None, (
        r'show bridge control interface [A-Za-z0-9_.:-]+ host\.',
        r'Bridge [A-Za-z0-9_.:-]+ host table',
        r'fdb: hash size=0, used=0, num=0, depth=0, gc_time=0, ageing_time=0, version_count=0',
    ))


def read_mac(auth, read):
    from . import tables as t, port_vlan
    switches = auth.read_inventory.get('switches', ())
    if 'bridge_mac_table' not in auth.enabled_queries or not switches:
        result = t.parse('fortinet', 'mac_entry', None, '', status='not_applicable')
        result['reason'] = 'FortiGate je L3; MAC klient\u016f viz arp a FortiSwitch'
        return result
    result = None
    for switch in switches:
        other = read('bridge_mac_table', 'mac_entry', {'switch': switch})
        other['bridge'] = switch
        if result is None:
            result = other
        else:
            port_vlan.combine(result, other)
            result['records'].extend(other['records'])
            result['coverage']['parsed_records'] += other['coverage']['parsed_records']
    result['bridges'] = list(switches)
    return result


def bgp_peers(table, text):
    """`get router info bgp summary` / `get router info6 bgp summary` (80F 8.0.2 measured, populated; 60F 7.6.8
    without BGP answers nothing): the IOS column layout under a `VRF default(0) BGP router identifier` line."""
    from . import tables as t
    return t.bgp_peers(text, 'fortinet')


def ospf_neighbors(table, text):
    """FortiOS IPv4 OSPF status, with process/VRF headings and FortiOS interface names."""
    from . import tables as t

    vrf = None
    row = re.compile(r'(\S+)\s+\d+\s+' + t.OSPF_STATE_CELL +
                     r'\s+\S+\s+(\S+)\s+([A-Za-z0-9_][A-Za-z0-9_.-]{0,15})')

    def handle(_raw, value):
        nonlocal vrf
        process = re.fullmatch(r'OSPF process \d+, VRF (\d+):', value)
        if process:
            vrf = 'default' if process[1] == '0' else process[1]
            return []
        if re.fullmatch(r'Neighbor ID\s+Pri\s+State\s+Dead Time\s+Address\s+Interface', value):
            return []
        match = row.fullmatch(value)
        if not match:
            return None
        state, _, role = re.sub(r'\s+', '', match[2]).partition('/')
        if role and role not in t.OSPF_ROLES:
            return None
        state = {'twoway': '2way', '2ways': '2way'}.get(state.lower(), state.lower())
        return t.record(table, neighbor_id=str(ipaddress.IPv4Address(match[1])), state=state,
                        role=role if role and role != '-' else None, vrf=vrf,
                        address=str(ipaddress.IPv4Address(match[3])), interface=match[4])

    return t.scan(text, handle)


_STP_BRIDGE = re.compile(r"bridge '([^']+)'\s+prio \d+\s+mac \S+\s+vd '[^']+'")
_STP_ROOT = re.compile(r'root prio \d+\s+mac \S+\s+cost \d+')
_STP_PORT = re.compile(
    r"port '([^']+)'\s+(?:down|role (\w+) state (\w+) cost (\d+) edge (?:yes|no) rx \d+ tx \d+)"
)
_STP_STATES = {'forward': 'forwarding', 'discard': 'discarding', 'learn': 'learning', 'block': 'blocking'}


def local_stp_ports(table, text):
    from . import tables
    bridge = None
    root_seen = False

    def handle(_raw, value):
        nonlocal bridge, root_seen
        head = _STP_BRIDGE.fullmatch(value)
        if head:
            bridge = head[1]
            root_seen = False
            return []
        if bridge and _STP_ROOT.fullmatch(value):
            root_seen = True
            return []
        port = _STP_PORT.fullmatch(value)
        if bridge and port and (root_seen or not port[3]):
            state = _STP_STATES[port[3]] if port[3] else 'down'
            return tables.record(table, instance=bridge, port=port[1], role=port[2],
                                 state=state, cost=int(port[4]) if port[4] else None)
        return None

    return tables.scan(text, handle)


LOCAL_SWITCH_INTERFACE_COMMAND = 'get system interface'
LOCAL_SWITCH_INTERFACES = '\n--- Local switch interfaces ---\n'


def local_switch_vlans(table, text):
    """Project switch membership and the switch VLAN from `show system virtual-switch`."""
    from . import port_vlan
    text, _, interfaces = text.partition(LOCAL_SWITCH_INTERFACES)
    rows, unknown = [], []
    stack = []
    members, vlan, hardware = [], None, None
    number = 0
    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        edit = re.fullmatch(r'edit "([^"]+)"', value)
        vlan_id = re.fullmatch(r'set vlan (\d+)', value)
        if not value:
            continue
        if not stack and value == 'config system virtual-switch':
            stack.append('switches')
        elif stack[-1:] == ['switches'] and edit:
            stack.append('switch')
            members, vlan, hardware = [], None, None
        elif stack[-1:] == ['switch'] and vlan_id and 0 <= int(vlan_id[1]) <= 4094:
            vlan = int(vlan_id[1]) or None
        elif stack[-1:] == ['switch'] and (physical := re.fullmatch(r'set physical-switch "([^"]+)"', value)):
            hardware = physical[1]
        elif stack[-1:] == ['switch'] and value == 'config port':
            stack.append('ports')
        elif stack[-1:] == ['ports'] and edit and edit[1] not in members:
            stack.append('port')
            members.append(edit[1])
        elif stack[-1:] == ['port'] and value == 'next':
            stack.pop()
        elif stack[-1:] == ['switch'] and value == 'next':
            stack.pop()
            if not hardware:
                unknown.append({'line': number, 'text': 'virtual switch has no physical-switch'})
            rows.extend(port_vlan.row(member, 'access', access=vlan, tagged=[]) for member in members)
        elif stack[-1:] in (['ports'], ['switches']) and value == 'end':
            stack.pop()
        elif stack[-1:] == ['switch'] and re.fullmatch(r'set span(?:-\S+)? .+', value):
            continue
        elif stack[-1:] == ['port'] and value.startswith('set alias '):
            continue
        else:
            unknown.append({'line': number, 'text': raw})
    if stack:
        unknown.append({'line': number, 'text': 'incomplete virtual switch configuration'})
    trunk_ports = set(re.findall(r'(?m)^name:\s+(\S+)[^\r\n]*\btype:\s+physical\b[^\r\n]*\btrunk:\s+enable\b',
                                interfaces))
    if rows and not re.search(r'(?m)^name:\s+\S+', interfaces):
        unknown.append({'line': number, 'text': 'local trunk configuration unavailable'})
    if trunk_ports:
        unknown.append({'line': number, 'text': 'trunk VLAN membership unavailable from local switch reads'})
        rows = [row for row in rows if row['port'] not in trunk_ports]
        rows.extend(port_vlan.row(name, 'trunk') for name in sorted(trunk_ports))
    return rows, unknown


_LACP_KNOWN = re.compile(
    r'LACP flags: .*|\((?:A\|P|S\|F|A\|I|I\|O|E\|D)\) - .*|(?:npu|flush|asic helper|ha|oid|link-up-delay|'
    r'min-links|distribution algorithm|LACP speed|LACP HA|aggregator ID|actor key|actor MAC address|partner key|'
    r'partner MAC address): .*')
_MEMBER_KNOWN = re.compile(
    r'(?:index|link failure count|permanent MAC addr|LACPDUs RX/TX|actor state|actor port number/key/priority|'
    r'partner state|partner port number/key/priority|partner system|aggregator ID|speed/duplex|RX state): .*')


def lag(table, text):
    """`diagnose netlink aggregate name <aggregate> show` (60F 7.6.8 measured: an LACP aggregate with one member up
    and one down; a name that is no aggregate answers nothing). The output does not name the aggregate; the engine
    sets it from the enrolled argument. A member is `bundled` only when its link is up, LACP is established and
    its MUX state is COLLECTING_DISTRIBUTING, `down` when its link is down; any other state stays unknown."""
    from . import tables as t
    rows, unknown, member = [], [], None
    current = None
    expected_ports = None
    member_names = set()
    number = 0

    def close():
        if member is not None:
            facts = member.pop('_facts')
            if facts.get('link status') == 'down':
                member['state'] = 'down'
            elif (facts.get('link status') == 'up' and facts.get('LACP state') == 'established'
                  and (facts.get('MUX state') or '').split()[:1] == ['COLLECTING_DISTRIBUTING']):
                member['state'] = 'bundled'

    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value:
            continue
        status = re.fullmatch(r'status: (up|down)', value)
        ports = re.fullmatch(r'ports: (\d+)', value)
        mode = re.fullmatch(r'LACP mode: (active|passive)', value)
        head = re.fullmatch(r'member: ([A-Za-z0-9_][A-Za-z0-9_.-]{0,14})', value)
        fact = re.fullmatch(r'(link status|LACP state|MUX state): (.+)', value)
        if status and current is None and member is None:
            current = t.record(table, name=None, protocol=None, status=status[1], members=[])
            rows.append(current)
        elif ports and member is None and expected_ports is None:
            expected_ports = int(ports[1])
        elif mode and current is not None and member is None:
            current['protocol'] = 'lacp'
        elif head and current is not None and head[1] not in member_names:
            close()
            member_names.add(head[1])
            member = {'port': head[1], 'state': None, '_facts': {}}
            current['members'].append(member)
        elif fact and member is not None:
            member['_facts'][fact[1]] = fact[2]
        elif current is not None and (_MEMBER_KNOWN.fullmatch(value) if member is not None else _LACP_KNOWN.fullmatch(value)):
            continue
        elif current is None and _LACP_KNOWN.fullmatch(value):
            continue
        else:
            unknown.append({'line': number, 'text': raw})
    close()
    if current is not None and (expected_ports is None or expected_ports != len(member_names)):
        unknown.append({'line': number, 'text': f'ports: expected {expected_ports}, read {len(member_names)} members'})
    return rows, unknown


_NETLINK_STAT = re.compile(r'stat: rxp=(\d+) txp=(\d+) rxb=(\d+) txb=(\d+) rxe=(\d+) txe=(\d+) rxd=(\d+) txd=(\d+) '
                           r'mc=(\d+) collision=(\d+) @ time=\d+')
# An interface with an alias prints `alias=<alias>` after its name (measured on 80F 8.0.2).
_NETLINK_HEAD = re.compile(r'if=([A-Za-z0-9_][A-Za-z0-9_.-]{0,15})(?: alias=(\S+))? family=\d+ type=(\d+) index=(\d+) '
                           r'mtu=(\d+) link=\d+ master=(\d+)')
_NETLINK_STATE = re.compile(r'ref=\d+ state=(.*?) ?fw_flags=[0-9a-f]+ flags=(.*)')


def interface_errors(table, text):
    """`diagnose netlink interface list <interface>` (60F 7.6.8 measured): kernel counters of one interface.
    rx/tx errors are rxe/txe, CRC is rxc of the `re:` line, discards are rxd/txd."""
    from . import port_errors
    rows, unknown, row = [], [], None
    for number, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value:
            continue
        head = _NETLINK_HEAD.fullmatch(value)
        stat = _NETLINK_STAT.fullmatch(value)
        receive = re.fullmatch(r're: rxl=\d+ rxo=\d+ rxc=(\d+) rxf=\d+ rxfi=\d+ rxm=\d+', value)
        if head and row is None:
            row = dict.fromkeys(port_errors.FIELDS) | {'port': head[1]}
            rows.append(row)
        elif stat and row is not None and row['rx_errors'] is None:
            row.update(rx_errors=int(stat[5]), tx_errors=int(stat[6]), discards_in=int(stat[7]), discards_out=int(stat[8]))
        elif receive and row is not None and row['crc'] is None:
            row['crc'] = int(receive[1])
        elif row is not None and (_NETLINK_STATE.fullmatch(value) or re.fullmatch(
                r'Qdisc=\S+ hw_addr=\S+ broadcast_addr=\S+|te: txa=\d+ txc=\d+ txfi=\d+ txh=\d+ txw=\d+|'
                r'misc rxc=\d+ txc=\d+|input_type=\d+ state=\d+ arp_entry=\d+ refcnt=\d+|'
                r'session_count4=\d+, session_count6=\d+', value)):  # the session line is printed by 8.0.2
            continue
        else:
            unknown.append({'line': number, 'text': raw})
    required = ('rx_errors', 'tx_errors', 'crc', 'discards_in', 'discards_out')
    if row is not None and any(row[field] is None for field in required):
        unknown.append({'line': number, 'text': 'incomplete interface error counters'})
    return rows, unknown


INTERFACE_LIST_QUERY = 'interface_list'
INTERFACE_COUNTERS_COMMAND = 'diagnose netlink device list'
INTERFACE_SPEED_COMMAND = 'diagnose netlink interface packet-rate'
_INTERFACE_SAMPLES = '\n--- Interface telemetry ---\n'
_INTERFACE_SAMPLE_SEPARATOR = '\n---\n'


def interface_samples(seconds, before, speed, after):
    return _INTERFACE_SAMPLES + _INTERFACE_SAMPLE_SEPARATOR.join((f'{seconds:.6f}', before, speed, after))


def _interface_counters(text):
    counters, unreadable = {}, 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(('Inter-|', 'face |bytes')):
            continue
        name, sep, cells = line.partition(':')
        values = cells.split()
        if sep and re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,15}', name) and name not in counters and (
                len(values) == 16 and all(value.isascii() and value.isdecimal() for value in values)):
            counters[name] = (int(values[0]), int(values[8]))
        else:
            unreadable += 1
    return counters, unreadable


def _interface_speeds(text):
    speed, unreadable = {}, 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or re.fullmatch(r'Interface\s+Interface-Status\s+Link-Status\s+Speed\(Mbps\)\s+RX-rate\(per second\)\s+TX-rate\(per second\)', line):
            continue
        row = re.fullmatch(r'([A-Za-z0-9_][A-Za-z0-9_.-]{0,15})\s+(?:UP|DOWN)\s+(?:Running|Down)\s+(\d+|N/A)\s+\d+\s+\d+', line)
        if row and row[1] not in speed:
            speed[row[1]] = int(row[2]) * 1_000_000 if row[2] != 'N/A' else None
        else:
            unreadable += 1
    return speed, unreadable


def _traffic_rate(before, after, elapsed):
    return round((after - before) * 8 / elapsed) if before is not None and after is not None and after >= before and elapsed else None


def interface_list(text, start, end):
    """Parse `diagnose netlink interface list` without an argument (60F 7.6.8 and 80F 8.0.2 measured): two lines per
    kernel interface, `if=<name> ... index=<n> mtu=<n> ... master=<index>` and `ref=... state=<words> fw_flags=...
    flags=<words>`. admin_status is `up` when flags hold `up`; link is `up` when flags hold `run` and the state does
    not hold `no_carrier`. Only interfaces whose block starts inside [start, end) of the UTF-8 output are returned
    (the ssh_read page). Join byte counters from the two bulk samples and speed by interface name."""
    text, _, samples = text.partition(_INTERFACE_SAMPLES)
    parts = samples.split(_INTERFACE_SAMPLE_SEPARATOR, 3)
    if len(parts) == 4 and re.fullmatch(r'\d+\.\d{6}', parts[0]):
        seconds, before, speed, after = parts
        elapsed = float(seconds)
    else:
        elapsed, before, speed, after = 0, '', '', ''
    previous, previous_unknown = _interface_counters(before)
    latest, latest_unknown = _interface_counters(after)
    speeds, speed_unknown = _interface_speeds(speed)
    rows, page, unreadable, position, current = [], [], 0, 0, None
    for raw in text.splitlines(keepends=True):
        line_start, position = position, position + len(raw.encode('utf-8'))
        value = raw.strip()
        if not value:
            continue
        head = _NETLINK_HEAD.fullmatch(value)
        state = _NETLINK_STATE.fullmatch(value) if current is not None and current['flags'] is None else None
        if head:
            current = {'name': head[1], 'alias': head[2], 'index': int(head[4]), 'type': int(head[3]),
                       'mtu': int(head[5]), 'master_index': int(head[6]) or None, 'master': None,
                       'admin_status': None, 'link': None,
                       'role': None, 'state': None, 'flags': None}
            rows.append(current)
            if start <= line_start < end:
                page.append(current)
        elif state:
            words, flags = state[1].split(), state[2].split()
            current.update(state=words, flags=flags, admin_status='up' if 'up' in flags else 'down',
                           link='up' if 'run' in flags and 'no_carrier' not in words else 'down',
                           role='aggregate' if 'master' in flags else 'aggregate_member' if 'slave' in flags
                           else 'loopback' if 'loopback' in flags else 'point_to_point' if 'p2p' in flags else None)
        else:
            unreadable += 1
    names = {row['index']: row['name'] for row in rows}
    for row in rows:
        name = row['name']
        rx, tx = latest.get(name, (None, None))
        rx_before, tx_before = previous.get(name, (None, None))
        row.update(master=names.get(row['master_index']), speed_bps=speeds.get(name), rx_bytes=rx, tx_bytes=tx,
                   rx_bps=_traffic_rate(rx_before, rx, elapsed), tx_bps=_traffic_rate(tx_before, tx, elapsed))
    without_state = sum(1 for row in rows if row['flags'] is None)
    unreadable += previous_unknown + latest_unknown + speed_unknown
    without_traffic = sum(1 for row in rows if row['rx_bps'] is None or row['tx_bps'] is None
                          or row['name'] not in speeds)
    state = 'incomplete' if unreadable or without_state or without_traffic else 'ok' if rows else 'empty'
    return {'state': state, 'total_interfaces': len(rows), 'link_up': sum(1 for row in rows if row['link'] == 'up'),
            'link_down': sum(1 for row in rows if row['link'] == 'down'),
            'unreadable_lines': unreadable, 'interfaces_without_state_line': without_state,
            'interfaces_without_traffic_sample': without_traffic, 'sample_seconds': elapsed or None,
            **({'reason': 'traffic_sample_incomplete'} if without_traffic else {}),
            'interfaces': page,
            'note': 'RX/TX rates are averages over the counter sample interval. Link speed is reported where available.'}


def register(parsers):
    for table, query, parser in (
            ('interface', 'physical_interfaces', physical),
            ('vlan', 'interface_vlan_ids', vlans),
            ('lldp_neighbor', 'lldp_summary', lldp),
            ('mac_entry', 'bridge_mac_table', bridge),
            ('bgp_peer', 'bgp_summary', bgp_peers),
            ('bgp_peer', 'ipv6_bgp_summary', bgp_peers),
            ('ospf_neighbor', 'ospf_neighbors', ospf_neighbors),
            ('stp_port', 'local_stp_ports', local_stp_ports),
            ('port_vlan', 'local_switch_vlans', local_switch_vlans),
            ('lag', 'lacp_detail', lag),
            ('interface_errors', 'interface_details', interface_errors)):
        parsers[('fortinet', table, query)] = parser


USER_DEVICES_QUERY = 'user_devices'
_DEVICE_HEAD = re.compile(r'[ \t]*((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})[ \t]+scan (?:on|off)[ \t]*')
_DEVICE_SEEN = re.compile(r'[ \t]+created (\d+)s[ \t]+seen (\d+)s(?:[ \t]+(\S+))?[ \t]*')
_DEVICE_IP = re.compile(r'[ \t]+(?:ip (\d{1,3}(?:\.\d{1,3}){3})[ \t]+src \S+)?[ \t]*(?:ip6 ([0-9A-Fa-f:]+)[ \t]+src \S+)?[ \t]*')
_DEVICE_ATTRIBUTE = re.compile(r"[ \t]+([a-z][a-z ]*?) '(.*)'[ \t]+src \S+(?:[ \t]+id \d+[ \t]+weight \d+)?[ \t]*")
_DEVICE_FIELDS = {'host': 'hostname', 'os': 'os', 'software version': 'os_version', 'hardware vendor': 'vendor',
                  'type': 'device_type', 'family': 'family', 'hardware version': 'hardware_version'}


def user_devices(text, start, end):
    """Parse `diagnose user device list` (measured on 80F / FortiOS 8.0.2 build0251, 2026-11-17).

    Each device is a block: `<mac>  scan on|off`, `created <n>s  seen <n>s  <interface>`, an optional
    `ip ... ip6 ...` line and `<attribute> '<value>'  src ...` lines. Only devices whose block starts inside
    [start, end) of the UTF-8 output are returned (the ssh_read page); the counts cover the whole output.
    A line of another shape, or a block without its created/seen line, makes the state incomplete.
    """
    devices, current, unreadable, position, page = [], None, 0, 0, []
    for raw in text.splitlines(keepends=True):
        line_start, position = position, position + len(raw.encode('utf-8'))
        line = raw.rstrip('\r\n')
        if not line.strip():
            continue
        head = _DEVICE_HEAD.fullmatch(line)
        if head:
            current = dict.fromkeys(('mac', 'ip', 'ipv6', 'hostname', 'os', 'os_version', 'vendor', 'device_type',
                                     'family', 'hardware_version', 'interface', 'created_seconds_ago',
                                     'seen_seconds_ago'))
            current['mac'] = head[1].lower()
            devices.append(current)
            if start <= line_start < end:
                page.append(current)
            continue
        seen = _DEVICE_SEEN.fullmatch(line) if current is not None else None
        address = _DEVICE_IP.fullmatch(line) if current is not None and seen is None else None
        attribute = _DEVICE_ATTRIBUTE.fullmatch(line) if current is not None else None
        if seen and current['seen_seconds_ago'] is None:
            current.update(created_seconds_ago=int(seen[1]), seen_seconds_ago=int(seen[2]), interface=seen[3])
        elif address and (address[1] or address[2]) and current['ip'] is None and current['ipv6'] is None:
            try:
                current['ip'] = str(ipaddress.IPv4Address(address[1])) if address[1] else None
                current['ipv6'] = str(ipaddress.IPv6Address(address[2])) if address[2] else None
            except ValueError:
                unreadable += 1
        elif attribute:
            if attribute[1] in _DEVICE_FIELDS:
                current[_DEVICE_FIELDS[attribute[1]]] = attribute[2]
        else:
            unreadable += 1
    unseen = sum(1 for device in devices if device['seen_seconds_ago'] is None)
    state = 'incomplete' if unreadable or unseen else 'ok' if devices else 'empty'
    return {'state': state, 'total_devices': len(devices), 'unreadable_lines': unreadable,
            'devices_without_seen_line': unseen, 'devices': page,
            'seen_note': 'created_seconds_ago and seen_seconds_ago count back from the moment of this read.'}
