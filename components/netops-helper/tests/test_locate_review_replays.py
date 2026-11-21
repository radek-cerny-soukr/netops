"""A19: late conflicting ARP MACs and FortiOS elapsed-time limits."""
import json
import pytest

from netops_helper import engine, port_vlan
from test_locate_acceptance_107 import forti_outputs, SERIALS, AP_IP, REAL
from review_replay_support import device, configure, locate, switch


def test_late_conflicting_arp_mac_is_correlated_from_the_same_capture(tmp_path, monkeypatch):
    # IOSvL2 acceptance output; a second cache and second access port model an IP conflict.
    root = REAL / 'lab_endpoints_20261110/iosvl2'
    identity = (REAL / 'lab_endpoints/iosvl2/version.txt').read_text()
    arp = (root / 'arp_table.txt').read_text()
    import re
    from netops_helper import tables
    neighbor = next(r for r in tables.parse('cisco_ios', 'neighbor_l3', 'arp_table', arp)['records'] if r['mac'] and r['type'] != 'local')
    ip, first = neighbor['ip'], neighbor['mac']
    dotted = first.replace(':', '')
    dotted = '.'.join(dotted[i:i+4] for i in range(0, 12, 4))
    second = '0000.5e00.53fe'
    mac = (root / 'mac_table.txt').read_text()
    matching = next(line for line in mac.splitlines() if dotted.lower() in line.lower())
    mac += '\n' + matching.replace(dotted, second).replace('Gi0/1', 'Gi0/3').replace('Gi0/2', 'Gi0/3') + '\n'
    queries = ['arp_table', 'mac_table', 'lldp_neighbors', 'interfaces']
    a, b, sw = device('arp-a', 'cisco_ios', ['arp_table']), device('arp-b', 'cisco_ios', ['arp_table']), device('sw', 'cisco_ios', queries)
    a['helper']['device_types'] = b['helper']['device_types'] = ['router']
    sw['helper']['device_types'] = ['switch']
    outputs = {'arp-a': {'show version': identity, 'show ip arp': arp},
               'arp-b': {'show version': identity, 'show ip arp': re.sub(re.escape(dotted), second, arp, flags=re.I)},
               'sw': {'show version': identity, 'show mac address-table': mac,
                      'show lldp neighbors detail': '', 'show interfaces status': (root / 'interfaces.txt').read_text()}}
    proxy, _, wire = configure(tmp_path, monkeypatch, [a,b,sw], outputs, late=True)
    result = locate(proxy, ip, ['arp-a', 'arp-b', 'sw'])
    assert result['verdict'] == 'ambiguous', result
    assert {f['mac'] for f in result['findings']} == {first, '00:00:5e:00:53:fe'}, result
    assert result['coverage']['complete'] and not result['missing'], result
    calls = [json.loads(line) for line in wire.read_text().splitlines()]
    assert sum(c['command'] == 'show mac address-table' for c in calls) == 1
    assert sum(c['command'] == 'show interfaces status' for c in calls) == 1
    assert result['limits']['target_reads'] == {'arp-a': 7, 'arp-b': 7, 'sw': 7}


@pytest.mark.parametrize('clock_start', [0.0, 10_000_000.0])
@pytest.mark.parametrize('capture_seconds', [1.0, 5.6])
@pytest.mark.parametrize('count', [2, 4, 5, 12, 30])
def test_fortilink_uses_one_paced_session_and_keeps_read_and_time_ceilings(
        tmp_path, monkeypatch, count, capture_seconds, clock_start):
    from netops_helper.query_catalog import READ_QUERIES
    serials = ['S000SSSS%08d' % n for n in range(1, count + 1)]
    queries = ['arp_table', 'managed_switch_mac', 'managed_switch_lldp', 'managed_switch_port_stats',
               'managed_switch_port_vlans', 'interface_vlan_ids']
    gate = device('gate', 'fortinet', queries, managed_switches=serials)
    outputs = forti_outputs()
    command = READ_QUERIES['fortinet']['managed_switch_mac'].command
    for serial in serials[2:]:
        outputs[command.format(managed_switch=serial)] = outputs[command.format(managed_switch=SERIALS[1])].replace(
            SERIALS[1], serial).replace('00:00:5e:00:53:02', '00:00:5e:00:53:fe')
    proxy, _, wire = configure(
        tmp_path, monkeypatch, [gate], {'gate': outputs}, virtual=True,
        clock_start=clock_start, capture_seconds=capture_seconds)
    result = locate(proxy, AP_IP, ['gate'])
    assert result.get('error_code') is None, result
    calls = [json.loads(line) for line in wire.read_text().splitlines()]
    # Commands share one connection: each start follows the last capture.
    # Reconnecting would introduce real lane delays into the 1 s case.
    required = count + 6
    read_cap = min(30, 7 + 5 * count)
    starts = [capture_seconds * index for index in range(min(required, read_cap))]
    inside_budget = [start for start in starts if start < 59.5]
    expected_calls = len(inside_budget)
    assert len(calls) == expected_calls
    assert result['reads'] == expected_calls
    assert result['limits']['target_reads'] == {'gate': read_cap}
    assert [c['started'] - clock_start for c in calls] == pytest.approx(inside_budget)
    trace = wire.with_suffix('.clock.jsonl')
    sleeps = [json.loads(line)['seconds'] for line in trace.read_text().splitlines()] if trace.exists() else []
    assert sleeps == []
    planned_seconds = starts[-1] + capture_seconds
    complete = planned_seconds <= 59.5 and required <= read_cap
    assert result['elapsed_seconds'] == pytest.approx(min(planned_seconds, 59.5))
    assert result['coverage']['complete'] is complete
    if complete:
        assert result['verdict'] == 'located' and not result['missing'], result
        mac_command = READ_QUERIES['fortinet']['managed_switch_mac'].command
        assert {c['command'] for c in calls if c['command'].startswith(mac_command.split('{')[0])} == {
            mac_command.format(managed_switch=serial) for serial in serials}
    else:
        assert result['verdict'] == 'incomplete', result
        limiter = 'timeout' if planned_seconds > 59.5 else 'target_read_limit'
        assert any(m['reason'] == limiter for m in result['missing'])
        assert result['coverage']['unfinished_targets'] == ['gate']
    print('FortiLink virtual start=%s switches=%s capture=%s starts=%s sleeps=%s reads=%s elapsed=%s verdict=%s' % (
        clock_start, count, capture_seconds, [c['started'] - clock_start for c in calls],
        sleeps, result['reads'], result['elapsed_seconds'], result['verdict']), flush=True)




def test_transport_failure_is_not_retried_for_interface_ownership(tmp_path, monkeypatch):
    root = REAL / 'cisco_nxos/nexus9300v_9.3.12'
    target = device('router', 'cisco_nxos', ['arp_table', 'ip_interfaces'])
    target['helper']['device_types'] = ['router']
    outputs = {'router': {'show version': (root / 'version.txt').read_text(), 'show ip arp': None}}
    proxy, _, wire = configure(tmp_path, monkeypatch, [target], outputs)
    result = locate(proxy, '192.0.2.200', ['router'])
    calls = [json.loads(line)['command'] for line in wire.read_text().splitlines()]
    assert calls == ['show version', 'show ip arp']
    assert result['verdict'] == 'incomplete' and not result['coverage']['complete']
    assert any(m['vantage'] == 'router' and m['reason'] == 'timeout' for m in result['missing'])


def test_failed_hostname_supplement_is_cached_after_verified_identity(tmp_path, monkeypatch):
    from netops_helper import locate as correlation, endpoint_worker
    import test_proxy_contracts as c
    root = REAL / 'exos/exosvm_33.6.1.14'
    target = device('core', 'extreme_exos', ['mac_table', 'switch'])
    outputs = {'core': {'show version': (root / 'version.txt').read_text(), 'show fdb': '', 'show switch': None}}
    proxy, code, wire = configure(tmp_path, monkeypatch, [target], outputs)
    forwarded = proxy.request(c._request(1, 'locate_endpoint', {'targets': ['core'], 'endpoint': '00:00:5e:00:53:fe'}))
    assert forwarded is not None
    args = json.loads(forwarded)['params']['arguments']
    auths = endpoint_worker.decode(args['targets'], args['auth_context'])
    def correlate(auths, endpoint, read, budget, progress, identify):
        read(auths[0], 'mac_entry', None, None, None)
        assert identify(auths[0]) == identify(auths[0]) == ()
        return {'ok': True}
    monkeypatch.setattr(correlation, 'run', correlate)
    with monkeypatch.context() as scoped:
        scoped.setattr(engine, 'host_key_line', engine.host_key_line)
        scoped.setattr(engine, '_lane_directory', engine._lane_directory)
        scoped.setattr(engine.core_ssh, 'run_command', engine.core_ssh.run_command)
        scoped.setattr(engine.core_session, 'fortinet_session', engine.core_session.fortinet_session)
        exec(code, {})
        engine._locate_endpoint_run(auths, '00:00:5e:00:53:fe')
    calls = [json.loads(line)['command'] for line in wire.read_text().splitlines()]
    assert calls.count('show switch') == 1
