"""Tunnelled Wi-Fi client -> AP/radio -> wired AP port.

Small orchestration over two existing pieces: the FortiOS REST station/AP join
(`stations`, i.e. engine._wifi_clients_result) and the existing wired
correlation (`wired`, i.e. one locate.run over the same enrolled targets,
callbacks and Budget). The AP's wired port is reported only as
`wireless.ap_location`; it is never the client's own physical port.
"""
from __future__ import annotations

import ipaddress

from . import locate, tables

# Station fields that identify this client and its association; nothing else
# from the station or RF tables is copied.
_CLIENT_FIELDS = ('mac', 'ip', 'ssid')


def controllers(auths):
    """Enrolled FortiOS targets that already carry a REST credential and a certificate pin or CA."""
    return [a for a in auths if a.ssh_platform == 'fortinet' and a.fortios_rest_token
            and (a.fortios_rest_certificate_sha256 or a.tls_ca_certificate)]


def _management_ip(value):
    """The AP management address as a canonical unicast IP literal, else None."""
    if not isinstance(value, str):
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if (str(address) != value or address.is_unspecified or address.is_loopback
            or address.is_multicast or address.is_link_local):
        return None
    try:
        kind, literal = tables.literal(value)
    except (ValueError, TypeError):
        return None
    return literal if kind == 'ip' else None


def _text(value):
    return value if isinstance(value, str) and value else None


def _candidate(alias, row):
    detail = row.get('ap_detail') if isinstance(row.get('ap_detail'), dict) else None
    radio = row.get('radio')
    return {
        'controller': alias,
        'client': {key: row.get(key) for key in _CLIENT_FIELDS},
        'ap': {'id': _text(row.get('ap_id')),
               'serial': _text(detail.get('serial')) if detail else None,
               'name': _text(detail.get('name')) if detail else None,
               'management_ip': _management_ip(detail.get('local_addr')) if detail else None},
        # 0 is a valid radio identifier.
        'radio': radio if type(radio) is int and radio >= 0 else None,
        'band': row.get('band'),
        'joined': detail is not None,
    }


def _candidates(alias, row):
    """One candidate per AP the existing join matched for this station: several
    distinct matching APs stay visible instead of reading as an unjoined AP."""
    matches = row.get('ap_matches')
    if not (isinstance(matches, list) and len(matches) > 1):
        return [_candidate(alias, row)]
    found = []
    for detail in matches:
        item = _candidate(alias, {**row, 'ap_detail': detail})
        if item not in found:
            found.append(item)
    # Identical duplicates are not distinct APs: the original join outcome is kept.
    return found if len(found) > 1 else [_candidate(alias, row)]


def _limits(auths, budget):
    return {'targets': locate.MAX_TARGETS, 'reads': budget.max_reads, 'seconds': locate.MAX_SECONDS,
            'parallel': locate.MAX_PARALLEL,
            'target_reads': {a.alias: a.locate_read_limit for a in auths if hasattr(a, 'locate_read_limit')}}


def _coverage(auths, missing, extra_unfinished=()):
    unfinished = [a.alias for a in auths if a.alias in extra_unfinished or any(
        m.get('vantage') == a.alias or (m.get('vantage') or '').startswith(a.alias + '/') for m in missing)]
    return {'complete': not missing and not unfinished, 'requested_targets': [a.alias for a in auths],
            'completed_targets': [a.alias for a in auths if a.alias not in unfinished],
            'unfinished_targets': unfinished}


def run(auths, endpoint, budget, wired, stations, progress=lambda result: None, ruckus=None,
        c9800=None, c9800_port=None, *, expected_ip=None):
    """`stations(auth, mac, ip)` returns the joined station records of one controller;
    `wired(endpoint, progress)` is one run of the existing wired correlation;
    `ruckus(auth, mac, ip)` (wireless path) returns the client/AP join of one Ruckus Unleashed controller."""
    kind, value = tables.literal(endpoint)
    if not 1 <= len(auths) <= locate.MAX_TARGETS or len({a.alias for a in auths}) != len(auths):
        raise ValueError(f'locate_endpoint requires 1 to {locate.MAX_TARGETS} distinct enrolled targets')
    ruckus_sources = [a for a in auths if ruckus is not None and locate.ruckus_reader(a)]
    c9800_sources = [a for a in auths if c9800 is not None and locate.c9800_reader(a)]
    fortios_sources = controllers(auths)
    if not (fortios_sources or ruckus_sources or c9800_sources):
        return wired(endpoint, progress)
    if kind == 'ip' and ':' in value:
        if not (ruckus_sources or c9800_sources):
            return wired(endpoint, progress)
        gaps = [{'vantage': a.alias, 'table': 'wifi_client', 'reason': 'address_family_not_supported'}
                for a in ruckus_sources + c9800_sources]
        def report(result):
            progress(_with_wireless_coverage(auths, result, gaps, ()))
        return _with_wireless_coverage(auths, wired(endpoint, report), gaps, ())
    # Wireless and wired reads share the same cap.
    budget.max_reads = locate.MAX_READS if len(auths) <= 8 else 8 * len(auths)

    missing, vantage, evidence, candidates = [], [], [], []
    checked, failed = [], []
    stations_seen, ap_ambiguous = [], False
    sources = fortios_sources + ruckus_sources + c9800_sources
    unfinished = {a.alias for a in sources}

    def miss(target, table, reason, **extra):
        item = {'vantage': target, 'table': table, 'reason': reason, **extra}
        if item not in missing:
            missing.append(item)

    def checkpoint(verdict='incomplete', wireless=None, ap_location=None):
        result = {'ok': True, 'endpoint': {kind: value}, 'verdict': verdict,
                  'findings': [], 'own_interfaces': [], 'neighbors_l3': [],
                  'missing': list(missing), 'vantage': list(vantage), 'reads': budget.reads,
                  'coverage': _coverage(auths, missing, unfinished.union(
                      ap_location['coverage']['unfinished_targets'] if ap_location else ())),
                  'limits': _limits(auths, budget),
                  'elapsed_seconds': round(budget.now() - budget.started, 3)}
        if wireless is not None:
            result['wireless'] = wireless
        return result

    budget.on_read = lambda reads: progress(checkpoint())
    mac, ip = (value, None) if kind == 'mac' else (None, value)
    for auth in sources:
        is_ruckus = locate.ruckus_reader(auth)
        is_c9800 = locate.c9800_reader(auth)
        cli_controller = is_ruckus or is_c9800
        table = 'wifi_client' if cli_controller else 'wifi_station'
        try:
            answer = (c9800 if is_c9800 else ruckus if is_ruckus else stations)(auth, mac, ip)
        except locate.LimitReached as exc:
            miss(auth.alias, 'budget', str(exc))
            failed.append(auth.alias)
            continue
        unfinished.discard(auth.alias)
        reads = answer.get('sources') or ()
        evidence.extend({'target': auth.alias, **item} for item in reads)
        fallback = 'device_cli_error' if cli_controller else 'rest_unavailable'
        status = 'ok' if answer.get('ok') else answer.get('error_code') or fallback
        vantage.append({'target': auth.alias, 'profile': auth.ssh_platform, 'device_types': list(auth.device_types),
                        'table': table, 'status': status,
                        'captured_at': reads[0].get('captured_at') if reads else None,
                        'sources': [item.get('query' if cli_controller else 'endpoint') for item in reads],
                        'coverage': {}, 'warnings': []})
        if not answer.get('ok'):
            step = answer.get('failed_step')
            if cli_controller:
                miss(auth.alias, step or table, status)
            else:
                miss(auth.alias, table, 'rest_unavailable', error_code=status, **({'failed_step': step} if step else {}))
            failed.append(auth.alias)
            continue
        checked.append(auth.alias)
        if cli_controller:
            for gap in answer.get('missing', ()):
                miss(auth.alias, gap['step'], gap['reason'])
            for row in answer.get('records', ()):
                item = _ruckus_candidate(auth.alias, row)
                if item not in candidates:
                    candidates.append(item)
            continue
        identity = answer.get('identity_missing')
        if isinstance(identity, dict):
            # The planned device/query read failed: station/AP facts stay, the gap is admitted.
            vantage[-1]['status'] = 'partial'
            vantage[-1]['warnings'].append('device_identity_unavailable')
            miss(auth.alias, 'wifi_device_identity', identity.get('reason') or 'rest_unavailable',
                 **{key: identity[key] for key in ('error_code', 'http_status', 'failed_step') if key in identity})
        records = [r for r in answer.get('records', ())
                   if (kind == 'mac' and r.get('mac') == value) or (kind == 'ip' and r.get('ip') == value)]
        if answer.get('unparsed_rows'):
            # A skipped row may be this client, even if another binding was found.
            vantage[-1]['status'] = 'partial'
            miss(auth.alias, 'wifi_station', 'unparsed_rows')
        for row in records:
            items = _candidates(auth.alias, row)
            if len(items) > 1:
                ap_ambiguous = True
            station = _candidate(auth.alias, {**row, 'ap_detail': None})
            if station not in stations_seen:
                stations_seen.append(station)
            for item in items:
                if item not in candidates:
                    candidates.append(item)

    summary = {'controllers_checked': checked, 'controllers_failed': failed, 'sources': evidence,
               'device_output_trust': 'untrusted'}
    station_table = 'wifi_station' if fortios_sources else 'wifi_client'
    if not candidates:
        # A failed supplementary identity read does not make the full station read unverified.
        station_gaps = any(m['table'] != 'wifi_device_identity' for m in missing)
        wireless = {'status': 'not_in_station_table' if not failed and not station_gaps else 'not_verified', **summary}
        def report(result):
            progress(_with_wireless_coverage(auths, result, missing, vantage))
        result = _with_wireless_coverage(auths, wired(endpoint, report), missing, vantage)
        return {**result, 'wireless': wireless}

    if expected_ip and any(item['client']['ip'] not in (None, expected_ip) for item in candidates):
        miss(None, station_table, 'lease_station_address_mismatch')
        return checkpoint('ambiguous', {'status': 'ambiguous', **summary, 'candidates': candidates,
                                        'ap_location': None, 'ap_port': None})

    if len(candidates) > 1:
        if len(stations_seen) > 1 or any('channel' in item for item in candidates):
            miss(None, station_table, 'multiple_station_candidates')
        if ap_ambiguous:
            miss(None, 'wifi_ap', 'multiple_ap_matches')
        wireless = {'status': 'ambiguous', **summary, 'candidates': candidates, 'ap_location': None, 'ap_port': None}
        return checkpoint('ambiguous', wireless)

    found = candidates[0]
    controller = found['controller']
    if failed:
        miss(None, station_table, 'other_controller_unverified')
    if any(a.alias == controller for a in c9800_sources + ruckus_sources):
        return _locate_cli_ap(found, summary, wired, checkpoint, progress, miss, missing,
                              locally_switched=(found.get('locally_switched') or any(a.alias == controller for a in ruckus_sources)),
                              port_health=c9800_port if any(a.alias == controller for a in c9800_sources) else None)
    if not found['joined']:
        miss(controller, 'wifi_ap', 'ap_not_joined')
    if found['radio'] is None:
        miss(controller, 'wifi_station', 'radio_absent')
    ap_ip = found['ap']['management_ip']
    if found['joined'] and ap_ip is None:
        miss(controller, 'wifi_ap', 'ap_management_ip_invalid')
    wireless = {'status': 'associated', **summary, 'controller': controller,
                'client': found['client'], 'ap': found['ap'], 'radio': found['radio'], 'band': found['band'],
                'ap_location': None, 'ap_port': None}
    if ap_ip is None:
        miss(None, 'wifi_ap_backhaul', 'ap_management_ip_unavailable')
        return checkpoint('incomplete', wireless)

    # One run of the existing wired correlation for the AP's own management address,
    # with the same targets, callbacks and Budget. It never re-enters this Wi-Fi phase.
    def nested(ap_result):
        progress(checkpoint('incomplete', {**wireless, 'ap_location': ap_result}, ap_result))
    location = wired(ap_ip, nested, ap_backhaul=True, client_mac=found['client']['mac'])
    wireless['ap_location'] = location
    edges = [f for f in location.get('findings', ()) if f.get('edge')]
    if location['verdict'] == 'ambiguous':
        miss(None, 'wifi_ap_backhaul', 'ap_location_ambiguous')
        return checkpoint('ambiguous', wireless, location)
    # Only one proven switch edge port is a backhaul; an AP that is a target's own
    # interface is not a switch port observation.
    if not (location['verdict'] == 'located' and len(edges) == 1):
        miss(None, 'wifi_ap_backhaul', 'ap_location_' + location['verdict'])
    wireless['ap_port'] = ({'vantage': edges[0]['vantage'], 'port': edges[0]['port'],
                            'vlan_id': edges[0].get('vlan_id'), 'role': edges[0].get('role')}
                           if location['verdict'] == 'located' and len(edges) == 1 else None)
    return checkpoint('incomplete' if missing else 'located', wireless, location)


def _ruckus_candidate(alias, row):
    ap = row.get('ap') or {}
    return {'controller': alias,
            'client': {key: row.get(key) for key in ('mac', 'ip', 'wlan', 'vlan_id')},
            'ap': {'mac': ap.get('mac'), 'name': _text(ap.get('name')),
                   'management_ip': _management_ip(ap.get('ip')), 'role': _text(ap.get('role')),
                   'uplink_ports': list(ap.get('uplink_ports') or ())},
            'channel': row.get('channel'), 'radio': row.get('radio'), 'joined': bool(ap.get('mac')),
            **({'locally_switched': row['locally_switched']} if 'locally_switched' in row else {})}


def _with_wireless_coverage(auths, result, missing, vantage):
    gaps = [*result['missing'], *(item for item in missing if item not in result['missing'])]
    verdict = result['verdict']
    if missing and verdict == 'not_found_in_checked_data':
        verdict = 'incomplete'
    return {**result, 'vantage': [*vantage, *result['vantage']], 'missing': gaps, 'verdict': verdict,
            'coverage': _coverage(auths, gaps, result['coverage']['unfinished_targets'])}


def _locate_cli_ap(found, summary, wired, checkpoint, progress, miss, missing, *, locally_switched, port_health):
    # The AP's Ethernet MAC is the endpoint of the wired lookup. The client's VLAN
    # is checked at that port only when the controller establishes local switching.
    client_vlan_id = found['client']['vlan_id']
    known_vlan = locally_switched and type(client_vlan_id) is int
    wireless = {'status': 'associated', **summary, 'controller': found['controller'], 'client': found['client'],
                'ap': found['ap'], 'radio': found['radio'], 'channel': found['channel'],
                'ap_location': None, 'ap_port': None,
                'ssid_binding': {'wlan': found['client']['wlan'], 'client_vlan_id': client_vlan_id,
                                 'ap_uplink_ports': found['ap']['uplink_ports']}}
    if locally_switched and not known_vlan:
        # The client record was read completely, it just prints no VLAN: the AP port check stays, the client VLAN
        # membership of that port cannot be judged and says why.
        miss(None, 'ssid_binding', 'client_vlan_not_reported', controller=found['controller'],
             detail='the controller printed no VLAN for this client; the AP switch port membership in the client '
                    'VLAN was not checked')
    if not found['joined']:
        miss(found['controller'], 'wifi_ap', 'ap_not_joined')
        return checkpoint('incomplete', wireless)

    def nested(ap_result):
        progress(checkpoint('incomplete', {**wireless, 'ap_location': ap_result}, ap_result))
    location = wired(found['ap']['mac'], nested, port_vlan_id=client_vlan_id if known_vlan else None,
                     ap_backhaul=True, client_mac=found['client']['mac'])
    wireless['ap_location'] = location
    edges = [f for f in location.get('findings', ()) if f.get('edge')]
    if location['verdict'] == 'ambiguous':
        miss(None, 'wifi_ap_backhaul', 'ap_location_ambiguous')
        return checkpoint('ambiguous', wireless, location)

    edge = edges[0] if len(edges) == 1 else None
    # VLAN membership is read separately from the FDB and LLDP evidence for this port.
    vlan_gaps = [gap for gap in location['missing'] if edge is not None
                 and gap['table'] == 'port_vlan' and gap['vantage'] == edge['vantage']
                 and gap.get('port', edge['port']) == edge['port']]
    only_vlan_missing = (known_vlan and location['verdict'] == 'incomplete'
                         and bool(vlan_gaps) and len(vlan_gaps) == len(location['missing']))
    if edge is None or (location['verdict'] != 'located' and not only_vlan_missing):
        miss(None, 'wifi_ap_backhaul', 'ap_location_' + location['verdict'])
        return checkpoint('incomplete', wireless, location)

    wireless['ap_port'] = {'vantage': edge['vantage'], 'port': edge['port'], 'vlan_id': edge.get('vlan_id'),
                           'role': edge.get('role'),
                           'lldp_neighbor': next((n.get('neighbor') for n in edge.get('lldp_neighbors') or ()), None)}
    membership = edge.get('requested_vlan_membership') if known_vlan else None
    wireless['ssid_binding']['switch_port_vlan_membership'] = membership
    if known_vlan and (membership is None or membership.get('tagging') == 'missing'):
        read_gap = next((gap for gap in vlan_gaps if 'port' not in gap), {})
        diagnostics = {key: read_gap[key] for key in ('error_code', 'error') if key in read_gap}
        if read_gap:
            diagnostics['read_status'] = read_gap['reason']
        miss(edge['vantage'], 'port_vlan', 'client_vlan_membership_missing', port=edge['port'],
             vlan_id=client_vlan_id,
             detail='the VLAN membership of the AP switch port was not read completely; whether it carries '
                    'the client VLAN is unknown',
             **diagnostics)
    if port_health is not None:
        health = port_health(edge)
        wireless['ap_port']['diagnostics'] = health
        for table, observation in health.items():
            if not observation['complete']:
                miss(edge['vantage'], table, observation['status'], port=edge['port'])
    return checkpoint('incomplete' if missing else 'located', wireless, location)
