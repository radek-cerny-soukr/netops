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
    return {'complete': not missing, 'requested_targets': [a.alias for a in auths],
            'completed_targets': [a.alias for a in auths if a.alias not in unfinished],
            'unfinished_targets': unfinished}


def run(auths, endpoint, budget, wired, stations, progress=lambda result: None):
    """`stations(auth, mac, ip)` returns the joined station records of one controller;
    `wired(endpoint, progress)` is one run of the existing wired correlation."""
    kind, value = tables.literal(endpoint)
    if not 1 <= len(auths) <= locate.MAX_TARGETS or len({a.alias for a in auths}) != len(auths):
        raise ValueError(f'locate_endpoint requires 1 to {locate.MAX_TARGETS} distinct enrolled targets')
    sources = controllers(auths)
    if not sources or not (kind == 'mac' or kind == 'ip' and ':' not in value):
        return wired(endpoint, progress)          # unchanged wired flow
    # The cap locate.run applies; REST reads are charged to it from the first GET.
    budget.max_reads = locate.MAX_READS if len(auths) <= 8 else 8 * len(auths)

    missing, vantage, rest_sources, candidates = [], [], [], []
    checked, failed = [], []
    stations_seen, ap_ambiguous = [], False

    def miss(target, table, reason, **extra):
        item = {'vantage': target, 'table': table, 'reason': reason, **extra}
        if item not in missing:
            missing.append(item)

    def checkpoint(verdict='incomplete', wireless=None, ap_location=None):
        result = {'ok': True, 'endpoint': {kind: value}, 'verdict': verdict,
                  'findings': [], 'own_interfaces': [], 'neighbors_l3': [],
                  'missing': list(missing), 'vantage': list(vantage), 'reads': budget.reads,
                  'coverage': _coverage(auths, missing,
                                        ap_location['coverage']['unfinished_targets'] if ap_location else ()),
                  'limits': _limits(auths, budget),
                  'elapsed_seconds': round(budget.now() - budget.started, 3)}
        if wireless is not None:
            result['wireless'] = wireless
        return result

    budget.on_read = lambda reads: progress(checkpoint())
    for auth in sources:
        try:
            answer = stations(auth, value if kind == 'mac' else None, value if kind == 'ip' else None)
        except locate.LimitReached as exc:
            miss(auth.alias, 'budget', str(exc))
            failed.append(auth.alias)
            continue
        rest_sources.extend({'target': auth.alias, **s} for s in answer.get('sources', ()))
        status = 'ok' if answer.get('ok') else answer.get('error_code') or 'rest_unavailable'
        vantage.append({'target': auth.alias, 'profile': auth.ssh_platform, 'device_types': list(auth.device_types),
                        'table': 'wifi_station', 'status': status,
                        'captured_at': (answer.get('sources') or [{}])[0].get('captured_at'),
                        'sources': [s.get('endpoint') for s in answer.get('sources', ())],
                        'coverage': {}, 'warnings': []})
        if not answer.get('ok'):
            extra = {'error_code': status}
            if answer.get('failed_step'):
                extra['failed_step'] = answer['failed_step']
            miss(auth.alias, 'wifi_station', 'rest_unavailable', **extra)
            failed.append(auth.alias)
            continue
        checked.append(auth.alias)
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

    summary = {'controllers_checked': checked, 'controllers_failed': failed, 'sources': rest_sources,
               'device_output_trust': 'untrusted'}

    if not candidates:
        # Not an associated station (or REST unreadable): the original wired flow decides,
        # and a REST gap can never turn into a claim of absence.
        result = wired(endpoint, progress)
        result['vantage'] = vantage + result.get('vantage', [])
        for item in missing:
            if item not in result['missing']:
                result['missing'].append(item)
        if missing and result['verdict'] == 'not_found_in_checked_data':
            result['verdict'] = 'incomplete'
        result['coverage'] = _coverage(auths, result['missing'])
        result['reads'] = budget.reads
        # A failed supplementary identity read does not make the full station read unverified.
        station_gaps = [m for m in missing if m['table'] != 'wifi_device_identity']
        result['wireless'] = {'status': 'not_in_station_table' if not failed and not station_gaps else 'not_verified',
                              **summary}
        return result

    if len(candidates) > 1:
        # Distinct station/AP bindings: never first- or last-wins.
        if len(stations_seen) > 1:
            miss(None, 'wifi_station', 'multiple_station_candidates')
        if ap_ambiguous:
            miss(None, 'wifi_ap', 'multiple_ap_matches')
        wireless = {'status': 'ambiguous', **summary, 'candidates': candidates, 'ap_location': None, 'ap_port': None}
        return checkpoint('ambiguous', wireless)

    found = candidates[0]
    controller = found['controller']
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
    if failed:
        miss(None, 'wifi_station', 'other_controller_unverified')
    if ap_ip is None:
        miss(None, 'wifi_ap_backhaul', 'ap_management_ip_unavailable')
        return checkpoint('incomplete', wireless)

    # One run of the existing wired correlation for the AP's own management address,
    # with the same targets, callbacks and Budget. It never re-enters this Wi-Fi phase.
    def nested(ap_result):
        progress(checkpoint('incomplete', {**wireless, 'ap_location': ap_result}, ap_result))
    location = wired(ap_ip, nested)
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
