"""Bounded endpoint correlation. Device facts never expand the enrolled scope."""
from __future__ import annotations

import re
import ipaddress
import time
import threading
from concurrent.futures import ThreadPoolExecutor

from .audit import AuditPersistenceError
from . import tables, port_vlan
from .normalization import normalize_port

MAX_TARGETS = 64
MAX_PARALLEL = 8
MAX_READS = 40
MAX_SECONDS = 59.5
# IOS and IOS XE list their own interface addresses in the ARP cache (age "-"); a complete ARP
# read of these profiles without such an entry rules the target out as the owner.
ARP_LISTS_OWN = ('cisco_ios', 'cisco_xe')
# A FortiSwitch MAC table shows the switch's own address on its internal (CPU) port.
MANAGED_OWN_PORT = 'internal'
# FortiAP system names ("FortiAP-231K", "FAP-221E"); the LLDP tables carry no system description.
AP_NAME = re.compile(r'(?:fortiap|fap)(?![a-z])', re.IGNORECASE)


# Readers are chosen by the inventory device type, never by the SSH profile:
# ARP/ND caches come from router/firewall targets, MAC tables from switch targets
# and FortiLink-managed switch tables from firewall targets. A target also needs
# the matching query in enabled_queries.
L3_TYPES = ('router', 'firewall')


class LimitReached(Exception):
    pass


def l3_queries(target):
    """ARP/ND catalogue queries this target may serve as an L3 reader."""
    if not set(L3_TYPES) & set(target.device_types):
        return ()
    return tuple(q for q in ('arp_table', 'ipv6_neighbors') if q in target.enabled_queries)


def mac_reader(target):
    return 'switch' in target.device_types and 'mac_table' in target.enabled_queries


def profile_of(target):
    """Catalogue profile of an auth context or an inventory section ('fortios' and 'fortinet' are one)."""
    from .inventory import catalog_platform
    return catalog_platform(target.ssh_platform)


def managed_switch_reader(target):
    return ('firewall' in target.device_types and profile_of(target) == 'fortinet'
            and 'managed_switch_mac' in target.enabled_queries)


def is_reader(target):
    return bool(l3_queries(target)) or mac_reader(target) or managed_switch_reader(target)


class Budget:
    def __init__(self, now=time.monotonic):
        self.now, self.started, self.reads = now, now(), 0
        self.on_read = lambda reads: None
        self.lock = threading.RLock()
        self.stopped = threading.Event()
        self.lanes = threading.BoundedSemaphore(MAX_PARALLEL)
        self.max_reads = MAX_READS
        self.deadline = self.started + MAX_SECONDS

    def remaining(self):
        if self.stopped.is_set():
            raise LimitReached('cancelled')
        left = self.deadline - self.now()
        if left <= 0:
            raise LimitReached('timeout')
        return left

    def take(self):
        with self.lock:
            self.remaining()
            if self.reads >= self.max_reads:
                raise LimitReached('read_limit')
            self.reads += 1
            self.on_read(self.reads)


def physical(value):
    try:
        return normalize_port(value)['physical']
    except ValueError:
        return value


def aggregate(value):
    try:
        return normalize_port(value)['aggregate']
    except ValueError:
        return False


def peer_kind(neighbor, aliases, hosts=frozenset()):
    """What an LLDP neighbour is, from its advertised capabilities and the enrolled targets.

    switch: an enrolled target (alias or management address) or a bridge/router;
    phone / ap: telephone (T) or WLAN AP (W) without router (R): clients sit behind it;
    a WLAN AP that is also a station (FortiAP advertises B,W,R,S) or is named FortiAP/FAP is an ap too;
    unknown: a neighbour that advertises no capabilities cannot be classified;
    endpoint: anything else (station only, other).
    """
    if neighbor.get('neighbor') in aliases or neighbor.get('management_ip') in hosts:
        return 'switch'
    codes = set((tables.capabilities(neighbor.get('capabilities')) or '').split(','))
    codes.discard('')
    if AP_NAME.match(neighbor.get('neighbor') or '') or 'W' in codes and ('R' not in codes or 'S' in codes):
        return 'ap'
    if not codes:
        return 'unknown'
    if 'R' not in codes and 'T' in codes:
        return 'phone'
    if codes & {'B', 'R'}:
        return 'switch'
    return 'endpoint'


def system_name(value):
    """An LLDP system name or host name compared without case and without a domain."""
    name = (value or '').strip().lower()
    try:
        return str(ipaddress.ip_address(name))
    except ValueError:
        return name.split('.')[0] or None


def is_switch_neighbor(neighbor, aliases, hosts=frozenset()):
    return peer_kind(neighbor, aliases, hosts) == 'switch'


def is_switch_peer_port(peers, aliases, hosts=frozenset()):
    """A port with an LLDP switch neighbour is transit: no further read can make it an edge."""
    return any(is_switch_neighbor(n, aliases, hosts) for n in peers)


def run(auths, endpoint, read, budget=None, progress=lambda result: None, identify=None):
    """`identify(auth)` answers the host names of an enrolled target from its identity reads (or nothing)."""
    kind, value = tables.literal(endpoint)
    if not 1 <= len(auths) <= MAX_TARGETS or len({a.alias for a in auths}) != len(auths):
        raise ValueError(f'locate_endpoint requires 1 to {MAX_TARGETS} distinct enrolled targets')
    budget = budget or Budget()
    # Retain the existing small-scope cap, scale the shared cap for larger inventories.
    budget.max_reads = MAX_READS if len(auths) <= 8 else 8 * len(auths)
    state_lock = threading.RLock()
    emit = progress
    def progress(result):
        with state_lock:
            emit(result)
    result = {'ok': True, 'endpoint': {kind: value}, 'verdict': 'incomplete',
              'findings': [], 'missing': [], 'vantage': [], 'reads': 0,
              'coverage': {'complete': False, 'requested_targets': [a.alias for a in auths],
                           'completed_targets': [], 'unfinished_targets': [a.alias for a in auths]},
              'limits': {'targets': MAX_TARGETS, 'reads': budget.max_reads, 'seconds': MAX_SECONDS, 'parallel': MAX_PARALLEL,
                         'target_reads': {a.alias: a.locate_read_limit for a in auths if hasattr(a, 'locate_read_limit')}}}
    def count_read(reads):
        result['reads'] = reads
        progress(result)
    budget.on_read = count_read
    macs = {value} if kind == 'mac' else set()
    aliases = {a.alias for a in auths}
    hosts = {a.host for a in auths}
    host_names = {}
    identity_locks = {a.alias: threading.Lock() for a in auths}
    observations = []
    own_interfaces = []
    result['own_interfaces'] = own_interfaces
    arp_complete = set()
    unavailable = set()
    # IPv4 addresses sought in interface address tables: the IP itself, or for a MAC the
    # addresses that enrolled ARP caches resolve to it.
    owned_addresses = set()

    def own(target, interface, ip, mac, source):
        item = {'target': target, 'interface': interface, 'ip': ip, 'mac': mac, 'source': source}
        if item not in own_interfaces:
            own_interfaces.append(item)

    def observe_ownership(auth, table, rows):
        for row in rows:
            interface = row.get('interface') if table != 'interface' else row.get('name')
            if table == 'ip_interface':
                if interface and row.get('ip') in owned_addresses:
                    own(auth.alias, interface, row['ip'],
                        value if kind == 'mac' else next(iter(macs)) if len(macs) == 1 else None, table)
                continue
            if (not interface or row.get(kind) != value
                    or table == 'neighbor_l3' and row.get('type') not in ('local', 'interface')):
                continue
            own(auth.alias, interface, row.get('ip'), row.get('mac'), table)

    def may_own(auth):
        """An interface address read can still name this target as the owner."""
        from . import ip_interfaces
        query = ip_interfaces.QUERIES.get(profile_of(auth))
        if auth.alias in unavailable or not is_reader(auth) or query not in auth.enabled_queries:
            return False
        # A complete ARP cache that lists the endpoint learned it from the wire, and IOS would
        # have listed its own address: neither target can own it.
        return auth.alias not in arp_complete or (
            profile_of(auth) not in ARP_LISTS_OWN and all(o['vantage'] != auth.alias for o in observations))

    def enrolled_peer(neighbor, reader):
        """Match a different enrolled target by alias, enrolled address or verified host name."""
        name = system_name(neighbor.get('neighbor'))
        for other in auths:
            if other.alias == reader.alias:
                continue
            if (name and name in (system_name(other.alias), system_name(other.host))
                    or neighbor.get('management_ip') == other.host
                    or neighbor.get('neighbor') == other.host):
                return True
            if identify is None or not name:
                continue
            with identity_locks[other.alias]:
                if other.alias not in host_names:
                    names = {system_name(n) for n in identify(other)} - {None}
                    if names:
                        host_names[other.alias] = names
            if name in host_names.get(other.alias, ()):
                return True
        return False

    def miss(target, table, reason, port=None, error_code=None, error=None):
        item = {'vantage': target, 'table': table, 'reason': reason}
        if port is not None:
            item['port'] = port
        if error_code is not None:
            item['error_code'] = error_code
            if error is not None:
                item['error'] = error
        if item not in result['missing']:
            result['missing'].append(item)

    def capture(auth, table, query=None, parameters=None, vantage=None, ip=None):
        vantage = vantage or auth.alias
        try:
            budget.remaining()
            if auth.alias in unavailable:
                return [], False
            found = read(auth, table, query, parameters, ip)
        except LimitReached as exc:
            with state_lock:
                miss(vantage, 'budget', str(exc))
            return [], False
        except AuditPersistenceError:
            raise
        except Exception:
            miss(vantage, table, 'read_failed')
            return [], False
        with state_lock:
            state = found['status']
            if state in ('transport_error', 'timeout'):
                unavailable.add(auth.alias)
            result['vantage'].append({'target': vantage, 'profile': auth.ssh_platform, 'device_types': list(auth.device_types), 'table': table,
                                      'status': state, 'captured_at': found['captured_at'], 'sources': found['sources'],
                                      'coverage': found['coverage'], 'warnings': list(found.get('warnings', ()))})
            result['reads'] = budget.reads
            warning = 'refusal_like_line_in_data'
            refusal_data = warning in found['coverage'].get('warnings', ()) or warning in found.get('warnings', ())
            # Catalogue field gaps do not imply a failed or partial capture.
            complete = state in ('ok', 'empty') and not refusal_data
            if state not in ('ok', 'empty'):
                miss(vantage, table, state, error_code=found.get('error_code'), error=found.get('error'))
            if refusal_data:
                miss(vantage, table, warning)
            if complete and vantage == auth.alias and table in ('neighbor_l3', 'ip_interface', 'interface'):
                observe_ownership(auth, table, found['records'])
            progress(result)
            if budget.now() >= budget.deadline:
                miss(vantage, 'budget', 'timeout')
            return found['records'], complete

    def parallel(items, operation, workers=MAX_PARALLEL):
        def work(item):
            auth = item[0] if isinstance(item, tuple) else item
            try:
                operation(item)
            except LimitReached as exc:
                with state_lock:
                    miss(auth.alias, 'budget', str(exc))
            except AuditPersistenceError:
                budget.stopped.set()
                raise
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix='locate') as pool:
            # Read every future, including audit errors, before returning to correlation.
            futures = [pool.submit(work, item) for item in items]
            for future in futures:
                future.result()

    l3_background = ThreadPoolExecutor(max_workers=1, thread_name_prefix='locate-l3')
    mac_ready = threading.Event()
    try:
        # Start with ARP/ND only for an IP, in its own address family.
        l3_auths = []
        for auth in auths:
            if not is_reader(auth) and auth.enabled_queries and not auth.device_types:
                miss(auth.alias, 'device_type', 'device_type_not_declared')
            query = 'ipv6_neighbors' if ':' in value else 'arp_table'
            if kind == 'ip' and query in l3_queries(auth):
                l3_auths.append(auth)
        l3_count = len(l3_auths)
        def read_l3(auth):
            rows, complete = capture(auth, 'neighbor_l3', ip=value)
            with state_lock:
                if complete:
                    arp_complete.add(auth.alias)
                for row in rows:
                    if row.get(kind) == value:
                        observations.append({'vantage': auth.alias, **row})
                        if row.get('mac'):
                            macs.add(row['mac'])
                if macs:
                    mac_ready.set()
        # An unrelated slow ARP reader must not hold up a MAC already resolved
        # by another target. The shared transport semaphore caps both phases together.
        l3_future = l3_background.submit(parallel, l3_auths, read_l3)
        l3_future.add_done_callback(lambda future: mac_ready.set())
        mac_ready.wait()
        if not l3_count and kind == 'ip':
            miss(None, 'neighbor_l3', 'no_enrolled_l3_reader')
        if kind == 'ip' and not macs:
            miss(None, 'neighbor_l3', 'mac_not_observed')
        result['neighbors_l3'] = observations
        # Each device follows its MAC table with auxiliary reads only where the MAC was seen,
        # so a switch without the MAC (a branch away from the endpoint) costs one read.
        switch_count, target_count = 0, len(auths)
        mac_scopes, deferred, captures = [], [], []
        detail_captures = {}
        def detail_capture(auth, table, query=None, parameters=None, vantage=None):
            key = (vantage or auth.alias, table)
            if key not in detail_captures:
                detail_captures[key] = capture(auth, table, query, parameters, vantage)
            return detail_captures[key]
        for auth in auths:
            scopes = [(None, auth.alias)] if mac_reader(auth) else []
            if managed_switch_reader(auth):
                for serial in auth.read_inventory.get('managed_switches', ()):
                    if target_count >= MAX_TARGETS:
                        miss(auth.alias, 'mac_entry', 'target_limit')
                        break
                    target_count += 1
                    scopes.append((serial, auth.alias + '/' + serial))
            for serial, vantage in scopes:
                switch_count += 1
                if not macs:
                    continue
                mac_scopes.append((auth, serial, vantage))
        def read_mac(scope):
            auth, serial, vantage = scope
            query = 'managed_switch_mac' if serial else None
            parameters = {'managed_switch': serial} if serial else None
            rows, mac_complete = capture(auth, 'mac_entry', query, parameters, vantage)
            with state_lock:
                searched = set(macs)
                captures.append((*scope, rows, mac_complete, searched))
            matches = [row for row in rows if row['mac'] in searched]
            if matches:
                read_details((auth, serial, vantage, parameters, matches, mac_complete))
        def read_details(item):
            auth, serial, vantage, parameters, matches, mac_complete = item[:6]
            if serial and mac_complete:
                # The switch's own address on its internal port: nothing behind it to read.
                for row in matches:
                    if row['port'] == MANAGED_OWN_PORT and row.get('type') == 'static':
                        own(vantage, row['port'], None, row['mac'], 'mac_entry')
                matches = [row for row in matches if not (row['port'] == MANAGED_OWN_PORT and row.get('type') == 'static')]
                if not matches:
                    progress(result)
                    return
            # The MAC table names a FortiLink/ICL trunk, LLDP and port reads only its member ports:
            # such a row is transit whatever they say, so it costs no further read.
            ports = [row for row in matches if not (serial and row.get('type') == 'trunk')]
            lldp, lldp_complete = [], True
            if len(item) == 8:
                lldp, lldp_complete = item[6:]
            elif ports:
                lldp_query = 'managed_switch_lldp' if serial else None
                lldp, lldp_complete = detail_capture(auth, 'lldp_neighbor', lldp_query, parameters, vantage)
            peers_of = {}
            for row in matches:
                local = physical(row['port'])
                peers_of[local] = [n for n in lldp if physical(n['local_port'] or '') == local]
                for n in peers_of[local]:
                    if peer_kind(n, aliases, hosts) == 'unknown' and enrolled_peer(n, auth):
                        aliases.add(n['neighbor'])      # from now on named like an enrolled target
            if len(item) == 6 and any(peer_kind(n, aliases, hosts) == 'unknown'
                                      for peers in peers_of.values() for n in peers):
                # Another target's identity can still be queued. Correlate again after
                # all primary reads, reusing this LLDP capture without extra SSH.
                deferred.append((*item, lldp, lldp_complete))
                return
            # A port with an LLDP switch neighbour is transit whatever its interface,
            # VLAN membership or LAG says; port reads serve only edge candidates.
            candidates = any(not is_switch_peer_port(peers_of[physical(row['port'])], aliases, hosts) for row in ports)
            vlan_rows, interfaces = [], []
            memberships, memberships_complete = [], False
            if serial and candidates:
                from . import fortiswitch_ports
                if fortiswitch_ports.STATS in auth.enabled_queries:
                    interfaces, _ = detail_capture(auth, 'interface', fortiswitch_ports.STATS, parameters, vantage)
                else:
                    miss(vantage, 'interface', 'managed_switch_port_stats_not_enabled')
            if not serial and candidates:
                interfaces, _ = detail_capture(auth, 'interface')
                if port_vlan.BINDINGS.get(profile_of(auth)) in auth.enabled_queries:
                    memberships, memberships_complete = detail_capture(auth, 'port_vlan')
            # The VLAN table only names a tag the MAC table printed as a VLAN name (Junos ELS).
            if not serial and any(row['vlan_id'] is None and row.get('vlan_name') for row in matches):
                vlan_rows, _ = detail_capture(auth, 'vlan')
            # EXOS shows a LAG in the FDB by its master port number, indistinguishable from a
            # physical port. `show sharing` covers both static and LACP groups; an
            # empty `show lacp` alone cannot establish that a port is not aggregated.
            lag_ports, lag_complete = set(), True
            if not serial and candidates and profile_of(auth) == 'extreme_exos':
                if 'lag_summary' in auth.enabled_queries:
                    lag_rows, lag_complete = detail_capture(auth, 'lag', 'lag_summary')
                else:
                    lag_rows, _ = detail_capture(auth, 'aggregate')
                    lag_complete = False
                lag_ports = {physical(r['name']) for r in lag_rows}
            judged = []
            for row in matches:
                local = physical(row['port'])
                peers = peers_of[local]
                interface = next((r for r in interfaces if physical(r['name'] or '') == local), {})
                vlan_id = row['vlan_id']
                if vlan_id is None and row.get('vlan_name'):
                    ids = {r['vlan_id'] for r in vlan_rows if r['name'] == row['vlan_name']}
                    if len(ids) == 1:
                        vlan_id = ids.pop()
                kinds = [peer_kind(n, aliases, hosts) for n in peers]
                behind = 'ap' if 'ap' in kinds else 'phone' if 'phone' in kinds else None
                # A phone or access point with clients behind it is the edge as far as this
                # switch can see; a multi-VLAN port is then expected and says nothing.
                uplink = ('switch' in kinds or local in lag_ports or (behind is None and (
                    row.get('type') == 'trunk' or aggregate(row['port']) or interface.get('trunk') is True
                    or any(word in (interface.get('description') or '').lower()
                           for word in ('uplink', 'peer-link', 'peer_link', 'isl', 'icl')))))
                # Unknown LLDP capabilities on an advertised neighbor cannot
                # establish that it is an endpoint. No neighbor is normal.
                unknown_peer = 'unknown' in kinds
                edge = not uplink and lldp_complete and mac_complete and lag_complete and not unknown_peer
                judged.append((row, local, peers, interface, vlan_id, behind, uplink, unknown_peer, edge))
            # FortiLink VLAN configuration only describes a confirmed edge port: one read, then.
            if serial and any(item[-1] for item in judged):
                from . import fortiswitch_ports
                if all(q in auth.enabled_queries for q in (fortiswitch_ports.CONFIG, fortiswitch_ports.VLAN_IDS)):
                    memberships, memberships_complete = detail_capture(auth, 'port_vlan', fortiswitch_ports.CONFIG, parameters, vantage)
                else:
                    miss(vantage, 'port_vlan', 'configured_vlan_reads_not_enabled')
            for row, local, peers, interface, vlan_id, behind, uplink, unknown_peer, edge in judged:
                if not uplink and not edge:
                    miss(vantage, 'edge', 'aggregation_not_verified' if not lag_complete and lldp_complete and mac_complete and not unknown_peer
                         else 'lldp_or_mac_incomplete')
                member = next((r for r in memberships if physical(r['port']) == local), None)
                membership = port_vlan.membership(member, vlan_id) if memberships_complete else port_vlan.membership(None, vlan_id)
                if member and member.get('source') == 'configuration':
                    membership['source'] = 'configuration'
                if (membership['tagging'] == 'missing' and (edge if serial else candidates)
                        and (serial or port_vlan.BINDINGS.get(profile_of(auth)) in auth.enabled_queries)):
                    miss(vantage, 'port_vlan', 'vlan_membership_missing', row['port'])
                result['findings'].append({'vantage': vantage, 'mac': row['mac'], 'port': row['port'],
                                            'vlan_id': vlan_id, 'vlan_name': row.get('vlan_name'),
                                            'vlan_membership': membership,
                                            'edge': edge, 'behind': behind if edge else None,
                                            'role': ('transit' if uplink else
                                                     'edge_behind_' + behind if edge and behind else
                                                     'edge' if edge else 'unverified'),
                                            'lldp_neighbors': peers, 'interface': interface or None})
                if vlan_id is None:
                    miss(vantage, 'vlan', 'vlan_id_absent')
            progress(result)
        parallel(mac_scopes, read_mac)
        l3_future.result()
        # Late ARP/ND replies may resolve a different MAC for the same IP. Reuse
        # every captured MAC table and its auxiliary reads before claiming coverage.
        def correlate_late(captured):
            auth, serial, vantage, rows, complete, searched = captured
            matches = [row for row in rows if row['mac'] in macs - searched]
            if matches:
                read_details((auth, serial, vantage, {'managed_switch': serial} if serial else None, matches, complete))
        parallel(captures, correlate_late)
        parallel(deferred, read_details)
        if not switch_count:
            miss(None, 'mac_entry', 'no_enrolled_switch_reader')
        # An unresolved MAC may be a router's own address. Only then consult
        # the enrolled IPv4 ARP readers, within the same transport/time budget.
        # Ordinary MAC edge lookups keep their existing reads.
        if (kind == 'mac' and not own_interfaces
                and (not switch_count or any(item['role'] == 'transit' for item in result['findings']))
                and not any(item['edge'] for item in result['findings'])):
            def fallback(auth):
                rows, complete = capture(auth, 'neighbor_l3')
                with state_lock:
                    if complete:
                        arp_complete.add(auth.alias)
                    observations.extend({'vantage': auth.alias, **row} for row in rows if row.get('mac') == value)
            parallel([a for a in auths if 'arp_table' in l3_queries(a)], fallback)
        # EOS, NX-OS, Junos, EXOS and FortiOS do not list their own addresses in ARP. Only when
        # nothing located the endpoint, the interface address table of each target that can
        # still own it is read once, within the same budget.
        if not own_interfaces and not any(item['edge'] for item in result['findings']):
            owned_addresses.update(a for a in ({value} if kind == 'ip' else {o['ip'] for o in observations if o.get('ip')})
                                   if ':' not in a)
            parallel([a for a in auths if owned_addresses and may_own(a)],
                     lambda auth: capture(auth, 'ip_interface'))
    except LimitReached as exc:
        miss(None, 'budget', str(exc))
    finally:
        l3_background.shutdown(wait=True)
    result['reads'] = budget.reads
    result['elapsed_seconds'] = round(budget.now() - budget.started, 3)
    edges = [item for item in result['findings'] if item['edge']]
    result['own_interfaces'] = own_interfaces
    if not edges and not own_interfaces:
        # A transit observation cannot locate an endpoint; distinguish enrolled neighbours
        # from links that lead beyond the checked inventory.
        for item in result['findings']:
            if item['role'] == 'transit':
                reader = next(a for a in auths if item['vantage'] == a.alias
                              or item['vantage'].startswith(a.alias + '/'))
                try:
                    known = any(enrolled_peer(n, reader) for n in item['lldp_neighbors'])
                except LimitReached as exc:
                    miss(None, 'budget', str(exc))
                    continue
                miss(item['vantage'], 'edge', 'endpoint_not_seen_on_neighbor_target' if known
                     else 'edge_beyond_enrolled_targets', item['port'])
    result['reads'] = budget.reads
    result['elapsed_seconds'] = round(budget.now() - budget.started, 3)
    if len(macs) > 1 or len({item['target'] for item in own_interfaces}) > 1 or not own_interfaces and len(edges) > 1:
        result['verdict'] = 'ambiguous'
    elif own_interfaces:
        result['verdict'] = 'own_interface_of_target'
    elif result['missing']:
        result['verdict'] = 'incomplete'
    elif len(edges) == 1:
        result['verdict'] = 'located'
    else:
        result['verdict'] = 'not_found_in_checked_data'
    order = {a.alias: index for index, a in enumerate(auths)}
    def vantage_order(item):
        return order.get((item.get('vantage') or item.get('target') or '').split('/')[0], -1)
    for items in (result['findings'], result['vantage'], result['missing'], own_interfaces, observations):
        items.sort(key=vantage_order)
    unfinished = [a.alias for a in auths if any(
        m['vantage'] == a.alias or (m['vantage'] or '').startswith(a.alias + '/')
        for m in result['missing'])]
    result['coverage'] = {'complete': not result['missing'], 'requested_targets': [a.alias for a in auths],
                          'completed_targets': [a.alias for a in auths if a.alias not in unfinished],
                          'unfinished_targets': unfinished}
    return result
