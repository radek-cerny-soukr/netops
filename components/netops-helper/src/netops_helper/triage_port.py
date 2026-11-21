"""Read-only EXOS port triage with query-level evidence and explicit gaps."""
from __future__ import annotations


def run(interface, domain, read_table, read_raw):
    evidence, missing, findings = {}, [], []
    for table in ('interface', 'port_vlan', 'interface_errors', 'lldp_neighbor', 'poe_port', 'optics_port', 'lacp_member'):
        item = read_table(table)
        evidence[table] = item
        if item.get('status') not in ('ok', 'empty', 'not_applicable') or not item.get('coverage', {}).get('complete'):
            missing.append(table)
    for query, parameters in (('stp_port_detail', {'interface': interface, 'domain': domain}),
                              ('mlag_peer', None), ('mlag_ports', None)):
        item = read_raw(query, parameters)
        evidence[query] = item
        # Unsupported MLAG is optional on standalone switches. Preserve the raw
        # refusal and its status so a caller can distinguish it from a read error.
        if (query in ('mlag_peer', 'mlag_ports') and item.get('status') in ('unsupported', 'not_applicable')
                and item.get('rc') in (0, 250, 254) and not item.get('truncated') and item.get('next_offset') is None):
            item = {**item, 'status': 'not_applicable', 'original_status': item['status'], 'ok': True}
            evidence[query] = item
            continue
        import re
        cli_error = re.search(r'(?m)^\s*(?:Error:|%% |Invalid input|Incomplete command)', item.get('untrusted_device_output', ''))
        if cli_error or not item.get('ok') or item.get('truncated') or item.get('next_offset') is not None or item.get('status') in ('truncated', 'permission_denied', 'transport_error', 'timeout', 'unsupported', 'not_applicable'):
            missing.append(query)
    for row in evidence['interface'].get('records', []):
        if row.get('oper_status') == 'down':
            findings.append({'code': 'link_down', 'source': 'interface', 'port': interface})
    for row in evidence['interface_errors'].get('records', []):
        counters = {key: row[key] for key in ('crc', 'rx_errors', 'tx_errors') if row.get(key)}
        if counters:
            findings.append({'code': 'cumulative_errors_present', 'source': 'interface_errors', 'counters': counters,
                             'meaning': 'Cumulative counters do not prove an ongoing fault; compare another measurement.'})
    for row in evidence['lacp_member'].get('records', []):
        if row.get('mux_state') != 'Collect-Dist':
            findings.append({'code': 'lacp_not_collecting_distributing', 'source': 'lacp_member'})
    for row in evidence['poe_port'].get('records', []):
        if row.get('fault'):
            findings.append({'code': 'poe_fault', 'source': 'poe_port', 'fault': row['fault']})
    for row in evidence['optics_port'].get('records', []):
        if row.get('alerts'):
            findings.append({'code': 'optical_alarm', 'source': 'optics_port', 'alerts': row['alerts']})
        if row.get('state') == 'partial':
            findings.append({'code': 'dom_incomplete', 'source': 'optics_port'})
    detail = evidence['stp_port_detail']
    if 'stp_port_detail' not in missing:
        import re
        if re.search(r'Port State\s*:\s*(BLOCKING|DISCARDING|LEARNING|LISTENING)\b', detail.get('untrusted_device_output', ''), re.I):
            findings.append({'code': 'stp_not_forwarding', 'source': 'stp_port_detail'})
    # No causal assertion based only on missing/empty evidence or cumulative errors.
    return {'ok': not missing, 'interface': interface, 'domain': domain, 'evidence': evidence,
            'findings': findings, 'missing': missing,
            'verdict': 'incomplete' if missing else 'findings' if findings else 'no_fault_observed'}


# G118 EP02: EOS port triage over the existing EOS reads. Absent optional features are
# reported with the device's own answer and never turned into a fault or a healthy claim.
EOS_TABLES = ('interface', 'port_vlan', 'interface_errors', 'stp_port_counters', 'mac_entry')
EOS_RAW = ('lldp_neighbors_interface', 'lacp_peer_interface', 'mlag_interfaces', 'interface_poe',
           'interface_optics', 'interfaces_errdisabled')
# Exact, observed cEOS 4.36 answers that mean "this feature does not apply to the port/switch".
_EOS_ABSENT = {
    'lacp_peer_interface': r'Interface \S+ is not a member of a port channel\.',
    'mlag_interfaces': r'No MLAG ports configured',
    'interface_poe': r'(?:> show poe interface \S+\n)?% (?:Invalid input|Unavailable command \(not supported on this hardware platform\)) at line 1',
}


def _raw_text(item):
    return (item.get('untrusted_device_output') or '').replace('\r\n', '\n').strip()


def run_eos(interface, read_table, read_raw):
    import re
    from .normalization import normalize_port

    evidence, missing, unavailable, findings = {}, [], [], []
    for table in EOS_TABLES:
        item = read_table(table)
        evidence[table] = item
        complete = item.get('coverage', {}).get('complete')
        if table == 'port_vlan':
            # The whole-switch join can lack fields of other ports; the selected port decides.
            complete = (item.get('status') == 'ok' and bool(item.get('records')) and not item.get('unparsed')
                        and all(row.get('mode') != 'unknown' for row in item['records']))
        if item.get('status') not in ('ok', 'empty', 'not_applicable') or not complete:
            missing.append(table)
    aggregate = bool(re.fullmatch(r'Port-Channel\d+', interface))
    for query in EOS_RAW:
        if aggregate and query in ('lacp_peer_interface', 'lldp_neighbors_interface', 'interface_poe', 'interface_optics'):
            continue        # physical-port reads: the members of a Port-Channel carry LACP, LLDP, PoE and optics
        params = {'interface': interface} if query not in ('mlag_interfaces', 'interfaces_errdisabled') else None
        item = read_raw(query, params)
        evidence[query] = item
        text = _raw_text(item)
        pattern = _EOS_ABSENT.get(query)
        complete = not item.get('truncated') and item.get('next_offset') is None
        if pattern and complete and item.get('rc') in (0, 1) and re.fullmatch(pattern, text):
            evidence[query] = {**item, 'status': 'not_applicable', 'ok': True}
            if query == 'interface_poe':
                # cEOS without PoE hardware; a read-only account sees the same command as invalid input.
                unavailable.append(query)
            continue
        if query in ('interface_optics', 'interfaces_errdisabled') and complete and item.get('rc') == 0 and not text:
            # No transceiver data for this port / no err-disabled port on the switch.
            evidence[query] = {**item, 'status': 'not_present' if query == 'interface_optics' else 'empty', 'ok': True}
            continue
        status = (item.get('normalized') or {}).get('status', item.get('status'))
        if not item.get('ok') or not complete or status in ('truncated', 'permission_denied', 'transport_error', 'timeout', 'unsupported'):
            missing.append(query)
    lacp = evidence.get('lacp_peer_interface')
    channel = re.search(r'(?m)^Port Channel (Port-Channel\d+):', _raw_text(lacp)) if lacp and 'lacp_peer_interface' not in missing else None
    vlan = evidence['port_vlan']
    if (channel and 'port_vlan' in missing and vlan['status'] == 'ok' and vlan['records'] and not vlan['unparsed']
            and vlan.get('next_offset') is None and all(row.get('mode') == 'unknown' for row in vlan['records'])
            and {source['query'] for source in vlan['sources'] if source['status'] in ('ok', 'empty')}
            >= {'interfaces_trunk', 'interfaces'}):
        # A bundled member has no VLAN membership of its own; the Port-Channel carries it.
        missing.remove('port_vlan')
        evidence['port_vlan'] = {**vlan, 'status': 'not_applicable', 'member_of': channel[1]}
    for row in evidence['interface'].get('records', []):
        if row.get('oper_status') == 'down':
            findings.append({'code': 'link_down', 'source': 'interface', 'port': interface})
    if 'interfaces_errdisabled' not in missing:
        name = normalize_port(interface)['name']
        for line in _raw_text(evidence['interfaces_errdisabled']).splitlines():
            cells = line.split()
            if cells and not line.startswith('Port') and _same_port(cells[0], name):
                findings.append({'code': 'errdisabled', 'source': 'interfaces_errdisabled', 'line': line.strip()})
    for row in evidence['interface_errors'].get('records', []):
        counters = {key: row[key] for key in ('crc', 'rx_errors', 'tx_errors', 'discards_in', 'discards_out') if row.get(key)}
        if counters:
            findings.append({'code': 'cumulative_errors_present', 'source': 'interface_errors', 'counters': counters,
                             'meaning': 'Cumulative counters do not prove an ongoing fault; compare another measurement.'})
    for row in evidence['stp_port_counters'].get('records', []):
        if row.get('state') != 'forwarding':
            findings.append({'code': 'stp_not_forwarding', 'source': 'stp_port_counters', 'instance': row['instance'],
                             'role': row['role'], 'state': row['state']})
        errors = {key: row[key] for key in ('bpdu_tagged_errors', 'bpdu_other_errors') if row.get(key)}
        if errors:
            findings.append({'code': 'stp_bpdu_errors', 'source': 'stp_port_counters', 'counters': errors})
    if lacp and 'lacp_peer_interface' not in missing and lacp.get('status') != 'not_applicable':
        for line in _raw_text(lacp).splitlines():
            m = re.match(r'\s*(\S+)\s+(\S+)\s+\|', line)
            if m and m[1] not in ('Port',) and m[2] != 'Bundled':
                findings.append({'code': 'lacp_not_bundled', 'source': 'lacp_peer_interface', 'status': m[2]})
    mlag = evidence['mlag_interfaces']
    if 'mlag_interfaces' not in missing:
        selected_port = normalize_port(channel[1] if channel else interface)['name']
        summary = mlag.get('mlag_members', {})
        selected = [member for member in summary.get('members', []) if _same_port(member['local_port'], selected_port)]
        table_gap = {'table', 'members', 'capture'}.intersection(summary.get('missing_fields', []))
        if (summary.get('state') == 'partial' and (table_gap or not selected)
                or any(member['missing_fields'] for member in selected)):
            # A gap confined to another identified row does not affect the selected port.
            missing.append('mlag_interfaces')
        for member in selected:
            if (member['state'] in ('disabled', 'inactive', 'active-partial')
                    or 'down' in (member['local_status'], member['remote_status'])):
                findings.append({'code': 'mlag_member_degraded', 'source': 'mlag_interfaces', 'mlag_id': member['id'],
                                 'port': selected_port, 'state': member['state'], 'local_status': member['local_status'],
                                 'remote_status': member['remote_status']})
    return {'ok': not missing, 'interface': interface, 'evidence': evidence, 'findings': findings,
            'missing': missing, 'unavailable': unavailable,
            'verdict': 'incomplete' if missing else 'findings' if findings else 'no_fault_observed'}


def _same_port(cell, name):
    from .normalization import normalize_port
    try:
        return normalize_port(cell)['name'] == name
    except ValueError:
        return False


def run_junos(interface, read_raw):
    """Correlate the selected physical port's Junos operational evidence."""
    import re
    from . import port_errors

    parameters = {'interface': interface}
    evidence = {}
    missing, unavailable, findings = [], [], []
    no_switching_family = False
    last_flap = None
    for query, scoped in (
        ('interface_details', True), ('ethernet_switching_interface', True),
        ('stp_interface_detail', True), ('lacp_interface', True), ('poe_interfaces', False),
        ('interface_optics', True), ('lldp_neighbors_interface', True),
    ):
        item = read_raw(query, parameters if scoped else None)
        evidence[query] = item
        text = _raw_text(item)
        status = item.get('status')
        truncated = item.get('truncated') or item.get('next_offset') is not None or status == 'truncated'
        if truncated:
            evidence[query] = {**item, 'truncated': True, 'complete': False}
            missing.append(query)
            continue
        if (query == 'ethernet_switching_interface' and no_switching_family and not text
                and item.get('rc') == 0 and item.get('error_code') == 'empty'):
            evidence[query] = {
                **{key: value for key, value in item.items() if key not in ('error', 'error_code')},
                'ok': True, 'status': 'not_applicable', 'complete': True,
                'normalized': {**item['normalized'], 'status': 'not_applicable'},
            }
            unavailable.append(query)
            continue
        if item.get('ok') and status == 'not_applicable' and item.get('rc') == 0:
            unavailable.append(query)
            continue
        if item.get('rc') == 0 and not text and query in ('interface_optics', 'lldp_neighbors_interface'):
            evidence[query] = {**item, 'ok': True, 'status': 'empty'}
            continue
        if not item.get('ok') or status not in ('ok', 'unparsed'):
            missing.append(query)
            continue
        if query == 'interface_details':
            rows, _ = port_errors.junos(text)
            row = next((row for row in rows if row['port'] == interface), {})
            last_flap = row.get('last_flap')
            no_switching_family = (row.get('oper_status') is not None
                                   and not re.search(r'(?mi)^[ \t]*Protocol (?:eth-switch|ethernet-switching)\b', text))
            if row.get('oper_status') is None:
                missing.append(query)
            elif row['oper_status'] == 'down':
                findings.append({'code': 'link_down', 'source': query, 'port': interface,
                                 'admin_status': row['admin_status']})
            counters = {field: row[field] for field in ('rx_errors', 'tx_errors', 'crc') if row.get(field)}
            if counters:
                findings.append({'code': 'cumulative_errors_present', 'source': query, 'counters': counters})
        if query == 'ethernet_switching_interface':
            reasons = sorted(set(re.findall(
                r'(?mi)[,·][ \t]*(disabled by bpdu[- ]control|blocked by stp)[ \t]*$', text)))
            for reason in reasons:
                findings.append({'code': 'spanning_tree_protection', 'source': query,
                                 'port': interface, 'device_reason': reason})
        if query == 'stp_interface_detail' and re.search(
                r'(?mi)^\s*Port state\s*:\s*(?:BLK|Blocking|Discarding)\b', text):
            findings.append({'code': 'stp_not_forwarding', 'source': query, 'port': interface})
    verdict = 'incomplete' if missing or unavailable else 'findings' if findings else 'no_fault_observed'
    return {'ok': not missing, 'interface': interface, 'last_flap': last_flap, 'evidence': evidence, 'missing': missing,
            'unavailable': unavailable, 'findings': findings, 'verdict': verdict}
