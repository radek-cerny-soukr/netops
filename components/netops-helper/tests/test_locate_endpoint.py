from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from netops_helper import engine, locate, tables
from conftest import _target

MAC = '00:00:5e:00:53:81'


def auth(alias='sw1', profile='cisco_ios', device_types=('switch', 'router')):
    return replace(_target(profile, 'mac_table'), alias=alias, device_types=device_types,
                   enabled_queries=('arp_table', 'ipv6_neighbors', 'mac_table', 'lldp_neighbors', 'interfaces', 'vlans'))


def envelope(table, rows, state='ok'):
    result = tables.parse('cisco_ios', table, 'fixture', '', status=state)
    result['records'] = rows
    return result


def reader(budget, *, port='Gi1/0/5', peer=None, state='ok', ip='192.0.2.10'):
    def read(auth, table, query, parameters, family):
        budget.take()
        if table == 'neighbor_l3':
            return envelope(table, [tables.record(table, ip=ip, mac=MAC, interface='Vlan101', vlan_id=101)])
        if table == 'mac_entry':
            return envelope(table, [tables.record(table, mac=MAC, port=port, vlan_id=101, type='dynamic')], state)
        if table == 'lldp_neighbor':
            return envelope(table, [peer] if peer else [], state)
        if table == 'interface':
            return envelope(table, [tables.record(table, name=port, trunk=False)])
        return envelope(table, [tables.record(table, vlan_id=101, name='lab-data', ports=[port])])
    return read


def test_locate_ip_edge_and_evidence():
    budget = locate.Budget()
    result = locate.run([auth()], '192.0.2.10', reader(budget), budget)
    assert result['verdict'] == 'located'
    assert result['findings'][0]['edge']
    assert result['findings'][0]['vlan_id'] == 101
    assert all(v['target'] == 'sw1' for v in result['vantage'])
    assert result['reads'] == 4          # ARP, MAC, LLDP, interfaces: the MAC table already gives the VLAN tag


@pytest.mark.parametrize('port,peer', [
    ('Po1', None),
    ('Gi1/0/5', {'local_port': 'GigabitEthernet1/0/5', 'neighbor': 'core', 'capabilities': 'B, R'}),
    ('Gi1/0/5', {'local_port': 'Gi1/0/5', 'neighbor': 'sw1', 'capabilities': None}),
])
def test_uplink_lag_or_lldp_switch_is_never_edge(port, peer):
    budget = locate.Budget()
    r = locate.run([auth()], MAC, reader(budget, port=port, peer=peer), budget)
    assert not any(f['edge'] for f in r['findings'])
    assert r['findings'][0]['role'] == 'transit'


def test_unknown_lldp_peer_is_incomplete():
    budget = locate.Budget()
    peer = {'local_port': 'Gi1/0/5', 'neighbor': 'unknown', 'capabilities': None}
    r = locate.run([auth()], MAC, reader(budget, peer=peer), budget)
    assert r['verdict'] == 'incomplete'
    assert not r['findings'][0]['edge']


def test_multiple_edges_and_multiple_macs_remain_ambiguous():
    b = locate.Budget()
    r = locate.run([auth('sw1'), auth('sw2')], MAC, reader(b), b)
    assert r['verdict'] == 'ambiguous'
    assert {f['vantage'] for f in r['findings']} == {'sw1', 'sw2'}


@pytest.mark.parametrize('state', ['unparsed', 'truncated', 'permission_denied', 'timeout', 'transport_error'])
def test_partial_table_never_establishes_an_edge(state):
    b = locate.Budget()
    r = locate.run([auth()], MAC, reader(b, state=state), b)
    assert r['verdict'] == 'incomplete'
    assert not r['findings'][0]['edge']


def test_budget_counts_every_read_and_stops_at_40():
    b = locate.Budget()
    # Eight EXOS edge candidates with every read enabled: ARP, MAC, LLDP, ports, port VLAN and LACP each.
    exos = replace(auth(profile='extreme_exos'), enabled_queries=auth().enabled_queries + ('lacp', 'vlan_detail'))
    r = locate.run([replace(exos, alias='sw'+str(n)) for n in range(8)], '192.0.2.10', reader(b), b)
    assert b.reads == 40 and r['reads'] == 40
    assert any(m['reason'] == 'read_limit' for m in r['missing'])


def test_deadline_and_target_limit():
    now = [0]
    b = locate.Budget(lambda: now[0])
    def slow(*args):
        b.take()
        now[0] += 61
        return envelope('neighbor_l3', [])
    r = locate.run([auth()], '192.0.2.10', slow, b)
    assert r['reads'] == 1 and any(m['reason'] == 'timeout' for m in r['missing'])
    with pytest.raises(ValueError):
        locate.run([auth(str(i)) for i in range(locate.MAX_TARGETS + 1)], MAC, slow)


def test_junos_logical_port_matches_physical_lldp():
    b = locate.Budget()
    peer = {'local_port': 'ge-0/0/5', 'neighbor': 'core', 'capabilities': 'Bridge'}
    r = locate.run([auth()], MAC, reader(b, port='ge-0/0/5.0', peer=peer), b)
    assert r['findings'][0]['role'] == 'transit'


def test_real_adapter_counts_identity_once_and_enforces_catalogue(monkeypatch):
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    root = Path(__file__).parent / 'fixtures'
    data = json.loads((root / 'tables/cisco_ios.json').read_text())
    # No LLDP is normal for a directly connected client.
    data['lldp_neighbor'] = ''
    version = (root / 'identity/cisco_ios.txt').read_text()
    from netops_helper.query_catalog import READ_QUERIES
    outputs = {READ_QUERIES['cisco_ios'][q].command: data[t] for t, q in tables.BINDINGS['cisco_ios'].items()
               if t in data and q != 'route_lookup'}
    calls = []
    def device(auth, profile, command):
        calls.append(command)
        return 0, version if command == 'show version' else outputs[command]
    monkeypatch.setattr(engine, 'read_from_device', device)
    result = engine._locate_endpoint_run([auth()], '203.0.113.55')
    assert result['verdict'] == 'located', result
    assert calls.count('show version') == 1 and result['reads'] == len(calls) == 5
    assert 'show vlan brief' not in calls                  # the MAC table already prints the VLAN tag
    assert result['findings'][0]['port'] == 'GigabitEthernet0/0' and result['findings'][0]['vlan_id'] == 99


def test_proxy_validates_literals_and_target_scope():
    from netops_helper.proxy import Proxy, ToolArgumentsError
    args = {'targets': ['sw1'], 'endpoint': '192.0.2.10'}
    assert Proxy._validate_tool_arguments('locate_endpoint', args) == args
    for bad in ['host.example', '192.0.2.1;reload', '192.0.2.0/24', 'fe80::1%port1']:
        with pytest.raises(ToolArgumentsError):
            Proxy._validate_tool_arguments('locate_endpoint', {**args, 'endpoint': bad})
    for targets in [[], ['sw1'] * 2, ['s'+str(i) for i in range(locate.MAX_TARGETS + 1)], 'sw1']:
        with pytest.raises(ToolArgumentsError):
            Proxy._validate_tool_arguments('locate_endpoint', {**args, 'targets': targets})


def test_proxy_injects_only_explicit_enrolled_targets(tmp_path, monkeypatch):
    import test_proxy_contracts as c
    from netops_helper import proxy as p
    inventory, _, _, _ = c._configure(p, tmp_path)
    section = c._section()
    section['ssh_platform'] = 'cisco_ios'
    section['enabled_queries'] = ['arp_table', 'mac_table']
    section['device_types'] = ['switch', 'router']
    first = c._device(section, 'cisco_ios')
    second = {**first, 'name': 'device-b'}
    c._write(inventory, c._inventory(first, second))
    proxy = p.Proxy()
    emitted = []
    monkeypatch.setattr(proxy, '_emit', emitted.append)
    forward = proxy.request(c._request(1, 'locate_endpoint', {'targets': ['device-a', 'device-b'], 'endpoint': MAC}))
    assert forward is not None, emitted
    args = json.loads(forward)['params']['arguments']
    from netops_helper.endpoint_worker import decode
    auths = decode(args['targets'], args['auth_context'])
    assert [a.alias for a in auths] == ['device-a', 'device-b']
    assert len(proxy.rate_history['device-a']) == 7
    assert len(proxy.rate_history['device-b']) == 7
    assert proxy.request(c._request(2, 'locate_endpoint', {'targets': ['unknown'], 'endpoint': MAC})) is None
    assert proxy.request(c._request(3, 'locate_endpoint', {**args, 'auth_context': 'injected'})) is None


def test_endpoint_reads_are_charged_to_every_target_or_to_none(tmp_path, monkeypatch):
    import collections
    import time
    import test_proxy_contracts as c
    from netops_helper import proxy as p
    inventory, _, _, _ = c._configure(p, tmp_path)
    section = c._section()
    section['ssh_platform'] = 'cisco_ios'
    section['enabled_queries'] = ['arp_table', 'mac_table']
    section['device_types'] = ['switch', 'router']
    first = c._device(section, 'cisco_ios')
    c._write(inventory, c._inventory(first, {**first, 'name': 'device-b'}))
    proxy = p.Proxy()
    emitted = []
    monkeypatch.setattr(proxy, '_emit', emitted.append)
    # device-b has 5 of 30 requests left, fewer than the 7 reads planned on it.
    proxy.rate_history['device-b'] = collections.deque([time.monotonic()] * 25)
    assert proxy.request(c._request(1, 'locate_endpoint', {'targets': ['device-a', 'device-b'], 'endpoint': MAC})) is None
    assert emitted[-1]['error']['data']['category'] == 'rate_limit'
    assert len(proxy.rate_history.get('device-a', ())) == 0 and len(proxy.rate_history['device-b']) == 25
    assert proxy.request(c._request(2, 'locate_endpoint', {'targets': ['device-a'], 'endpoint': MAC})) is not None
    assert len(proxy.rate_history['device-a']) == 7 and len(proxy.rate_history['device-b']) == 25


def test_worker_scope_is_exact_and_timeout_stops_process(monkeypatch):
    from netops_helper import endpoint_worker as w
    import subprocess
    import sys
    from types import SimpleNamespace
    with pytest.raises(ValueError):
        w.decode(['sw1'], '{}')
    original = subprocess.Popen
    children = []
    def child(*args, **kwargs):
        process = original([sys.executable, '-c', 'import sys,time; sys.stdin.readline(); time.sleep(5)'], **kwargs)
        children.append(process)
        return process
    monkeypatch.setattr(w.subprocess, 'Popen', child)
    clock = [0.0]
    waits = []
    monkeypatch.setattr(w, 'time', SimpleNamespace(monotonic=lambda: clock[0]))
    real_selector = w.selectors.DefaultSelector
    class ExpiredSelector:
        def __enter__(self):
            self.selector = real_selector()
            return self
        def __exit__(self, *args):
            self.selector.close()
        def register(self, *args):
            return self.selector.register(*args)
        def select(self, timeout):
            waits.append(timeout)
            clock[0] += timeout
            return []
    monkeypatch.setattr(w.selectors, 'DefaultSelector', ExpiredSelector)
    r = w.call(['sw1'], MAC, '{}', seconds=0.1)
    assert r['verdict'] == 'incomplete' and r['missing'][-1]['reason'] == 'timeout'
    assert waits == [0.1]
    assert r["elapsed_seconds"] == 0.1
    assert children[0].poll() is not None


@pytest.mark.parametrize('line', ['not json', '{"final": true}', '{"result": 1, "final": true}', '[1]', '{"result": {}, "final": "yes"}',
                                  '{"result": {}, "final": false}', '{"result": {"missing": []}, "final": true}',
                                  '{"result": {"missing": [], "verdict": "maybe"}, "final": true}'])
def test_malformed_worker_line_is_a_failed_worker_not_a_crash(monkeypatch, line):
    from netops_helper import endpoint_worker as w
    import subprocess
    import sys
    original = subprocess.Popen
    code = 'import sys; sys.stdin.readline(); print(%r, flush=True); import time; time.sleep(5)' % line
    monkeypatch.setattr(w.subprocess, 'Popen', lambda *a, **k: original([sys.executable, '-c', code], **k))
    r = w.call(['sw1'], MAC, '{}', seconds=3)
    assert r['verdict'] == 'incomplete'
    assert r['missing'][-1] == {'vantage': None, 'table': 'worker', 'reason': 'worker_failed'}


def test_worker_runs_isolated_with_a_minimal_environment(monkeypatch):
    from netops_helper import endpoint_worker as w
    import subprocess
    import sys
    seen = {}
    original = subprocess.Popen
    def child(args, **kwargs):
        seen.update(args=args, env=kwargs['env'])
        return original([sys.executable, '-c', 'import sys; sys.stdin.readline()'], **kwargs)
    monkeypatch.setattr(w.subprocess, 'Popen', child)
    monkeypatch.setenv('PYTHONPATH', '/nonexistent-injected')
    monkeypatch.setenv('LD_PRELOAD', '/nonexistent-injected.so')
    monkeypatch.setenv('NETOPS_HELPER_AUDIT_PATH', '/proc/netops-fixture-no-audit/audit.jsonl')
    w.call(['sw1'], MAC, '{}', seconds=1)
    assert seen['args'][:4] == [sys.executable, '-I', '-B', '-c'] and 'endpoint_worker import main' in seen['args'][4]
    assert 'PYTHONPATH' not in seen['env'] and 'LD_PRELOAD' not in seen['env']
    assert seen['env']['NETOPS_HELPER_AUDIT_PATH'] == '/proc/netops-fixture-no-audit/audit.jsonl'
    assert set(seen['env']) <= set(w.ENVIRONMENT) | {name for name in seen['env'] if name.startswith('NETOPS_')}


@pytest.mark.parametrize('verdict', ['not_found_in_checked_data', 'own_interface_of_target'])
def test_a_worker_that_stays_after_its_final_line_is_stopped_without_an_error(monkeypatch, verdict):
    from netops_helper import endpoint_worker as w
    import subprocess
    import sys
    original = subprocess.Popen
    final = json.dumps({'result': {'ok': True, 'missing': [], 'verdict': verdict}, 'final': True})
    code = 'import sys, time; sys.stdin.readline(); print(%r, flush=True); time.sleep(30)' % final
    children = []
    waits = []
    def child(*args, **kwargs):
        children.append(original([sys.executable, '-c', code], **kwargs))
        process = children[-1]
        original_wait = process.wait
        def wait(timeout=None):
            waits.append(timeout)
            if len(waits) == 1:
                raise subprocess.TimeoutExpired(process.args, timeout)
            return original_wait(timeout=timeout)
        monkeypatch.setattr(process, 'wait', wait)
        return process
    monkeypatch.setattr(w.subprocess, 'Popen', child)
    r = w.call(['sw1'], MAC, '{}', seconds=10)
    assert r == {'ok': True, 'missing': [], 'verdict': verdict}
    assert waits == [2, 2]
    assert children[0].poll() is not None


def test_terminate_gives_up_quietly_on_a_process_that_outlives_kill():
    from netops_helper import endpoint_worker as w
    import subprocess
    class Stuck:
        killed = False
        def terminate(self):
            pass
        def kill(self):
            self.killed = True
        def wait(self, timeout):
            raise subprocess.TimeoutExpired('worker', timeout)
    process = Stuck()
    w._terminate(process)
    assert process.killed


def test_fortigate_to_managed_switch_uses_existing_catalogue_and_registered_serial(monkeypatch):
    from netops_helper.query_catalog import READ_QUERIES
    from conftest import FORTIOS_STATUS
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    serial = 'S108EPXXXXXXXXXX'
    gate = replace(auth('gateway', 'fortinet', ('firewall',)),
                   enabled_queries=('arp_table', 'managed_switch_mac', 'managed_switch_lldp'),
                   read_inventory={'managed_switches': (serial,)})
    data = json.loads((Path(__file__).parent / 'fixtures/tables/fortinet.json').read_text())
    calls = []
    outputs = {
        READ_QUERIES['fortinet']['system_status'].command: FORTIOS_STATUS,
        READ_QUERIES['fortinet']['arp_table'].command: data['neighbor_l3'].split('ifindex')[0],
        READ_QUERIES['fortinet']['managed_switch_mac'].command.format(managed_switch=serial): data['mac_entry'],
        READ_QUERIES['fortinet']['managed_switch_lldp'].command.format(managed_switch=serial): data['lldp_neighbor'],
    }
    def device(auth, profile, command):
        calls.append(command)
        return 0, outputs[command]
    monkeypatch.setattr(engine, 'read_from_device', device)
    r = engine._locate_endpoint_run([gate], '192.0.2.10')
    assert r['verdict'] == 'incomplete', r
    assert {m['table'] for m in r['missing']} == {'interface', 'port_vlan'}
    assert r['reads'] == len(calls) == 4
    assert r['findings'][0]['vantage'] == 'gateway/' + serial
    assert r['findings'][0]['port'] == 'port5' and r['findings'][0]['vlan_id'] == 101
    assert calls[-1].endswith(serial)
    assert '192.0.2.10' not in '\n'.join(calls)


def test_transport_read_budget_is_40_including_identity(monkeypatch):
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    root = Path(__file__).parent / 'fixtures'
    data = json.loads((root / 'tables/cisco_ios.json').read_text())
    version = (root / 'identity/cisco_ios.txt').read_text()
    from netops_helper.query_catalog import READ_QUERIES
    outputs = {READ_QUERIES['cisco_ios'][q].command: data[t] for t, q in tables.BINDINGS['cisco_ios'].items()
               if t in data and q != 'route_lookup'}
    outputs['show ipv6 neighbors'] = ''
    outputs['show lldp neighbors detail'] = ''
    outputs['show interfaces trunk'] = ''
    calls = []
    def device(auth, platform, command):
        calls.append(command)
        return 0, version if command == 'show version' else outputs[command]
    monkeypatch.setattr(engine, 'read_from_device', device)
    # Eight edge candidates, each with identity, ARP, MAC, LLDP, interfaces and both port VLAN reads.
    targets = [replace(auth('sw'+str(i)), enabled_queries=auth().enabled_queries + ('interfaces_trunk',)) for i in range(8)]
    endpoint = next(row['ip'] for row in tables.parse('cisco_ios', 'neighbor_l3', 'arp_table', data['neighbor_l3'])['records']
                    if row['mac'] == '00:00:5e:00:53:08')
    r = engine._locate_endpoint_run(targets, endpoint)
    assert len(calls) == r['reads'] == 40
    assert any(m['reason'] == 'read_limit' for m in r['missing'])


def test_audit_failure_prevents_endpoint_device_reads(monkeypatch):
    def fail(*args, **kw):
        raise OSError('audit full')
    monkeypatch.setattr(engine, 'record', fail)
    monkeypatch.setattr(engine, 'read_from_device', lambda *args: pytest.fail('unlogged device access'))
    from netops_helper.audit import AuditPreflightError
    with pytest.raises(AuditPreflightError):
        engine._locate_endpoint_run([auth()], MAC)


def test_real_worker_returns_structured_result_without_audit_or_network_access(tmp_path, monkeypatch):
    import test_proxy_contracts as c
    from netops_helper import proxy as p
    from netops_helper import endpoint_worker as w
    inventory, _, _, _ = c._configure(p, tmp_path)
    section = c._section()
    section['ssh_platform'] = 'cisco_ios'
    section['enabled_queries'] = ['arp_table', 'mac_table']
    section['device_types'] = ['switch', 'router']
    c._write(inventory, c._inventory(c._device(section, 'cisco_ios')))
    proxy = p.Proxy()
    forwarded = proxy.request(c._request(1, 'locate_endpoint', {'targets': ['device-a'], 'endpoint': MAC}))
    args = json.loads(forwarded)['params']['arguments']
    # /proc cannot create an audit file, so the real child must fail its audit
    # preflight before any SSH operation, even in a network-enabled environment.
    monkeypatch.setenv('NETOPS_HELPER_AUDIT_PATH', '/proc/netops-fixture-no-audit/audit.jsonl')
    result = w.call(args['targets'], MAC, args['auth_context'], seconds=5)
    assert result['verdict'] == 'incomplete' and result['reads'] == 0
    assert result['endpoint'] == {'mac': MAC}
    assert result['ok'] is False and result['error_code'] == 'audit_preflight_failed'
    assert all(m['reason'] == 'audit_preflight_failed' for m in result['missing'])
    assert result['limits']['reads'] == 40


def test_readers_are_chosen_by_device_type_attribute_not_profile():
    # Same OS profile and enabled queries; only the declared type differs.
    for types, l3, mac in [(('switch',), (), True), (('router',), ('arp_table', 'ipv6_neighbors'), False),
                           (('firewall',), ('arp_table', 'ipv6_neighbors'), False),
                           (('switch', 'router'), ('arp_table', 'ipv6_neighbors'), True), ((), (), False)]:
        target = auth(device_types=types)
        assert locate.l3_queries(target) == l3 and locate.mac_reader(target) is mac
    assert not locate.managed_switch_reader(auth('gateway', 'fortinet', ('switch', 'router')))


def test_switch_only_target_is_not_an_l3_source_and_router_only_not_a_mac_source():
    b = locate.Budget()
    r = locate.run([auth(device_types=('switch',))], '192.0.2.10', reader(b), b)
    assert {'vantage': None, 'table': 'neighbor_l3', 'reason': 'no_enrolled_l3_reader'} in r['missing']
    assert not any(v['table'] == 'neighbor_l3' for v in r['vantage'])
    b = locate.Budget()
    r = locate.run([auth(device_types=('router',))], MAC, reader(b), b)
    assert {'vantage': None, 'table': 'mac_entry', 'reason': 'no_enrolled_switch_reader'} in r['missing']
    assert not any(v['table'] == 'mac_entry' for v in r['vantage'])
    assert r['verdict'] == 'incomplete'


def test_target_without_device_type_is_reported_and_never_read():
    b = locate.Budget()
    r = locate.run([auth(device_types=())], MAC, reader(b), b)
    assert r['reads'] == 0 and r['verdict'] == 'incomplete'
    assert {'vantage': 'sw1', 'table': 'device_type', 'reason': 'device_type_not_declared'} in r['missing']


def test_proxy_refuses_endpoint_location_on_a_target_without_reader_type(tmp_path):
    import test_proxy_contracts as c
    from netops_helper import proxy as p
    inventory, _, _, _ = c._configure(p, tmp_path)
    section = c._section()
    section['ssh_platform'] = 'cisco_ios'
    section['enabled_queries'] = ['arp_table', 'mac_table']
    c._write(inventory, c._inventory(c._device(section, 'cisco_ios')))
    proxy = p.Proxy()
    emitted = []
    proxy._emit = emitted.append
    assert proxy.request(c._request(1, 'locate_endpoint', {'targets': ['device-a'], 'endpoint': MAC})) is None
    assert emitted[-1]['error']['data'] == {'category': 'policy_scope', 'target': 'device-a'}


def test_managed_switch_reader_accepts_the_inventory_spelling_of_the_fortigate_profile():
    from types import SimpleNamespace as NS
    section = NS(ssh_platform='fortios', device_types=('firewall',), enabled_queries=('managed_switch_mac',))
    assert locate.managed_switch_reader(section) and locate.is_reader(section)
    assert locate.managed_switch_reader(NS(ssh_platform='fortinet', device_types=('firewall',), enabled_queries=('managed_switch_mac',)))
    assert not locate.managed_switch_reader(NS(ssh_platform='fortios', device_types=('switch',), enabled_queries=('managed_switch_mac',)))


def test_refused_identity_is_unparsed_with_the_reason_like_a_normalized_read(monkeypatch):
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    monkeypatch.setattr(engine, 'read_from_device', lambda auth, profile, command: (0, 'Arista vEOS\nSoftware image version: 4.30.1F\n'))
    r = engine._locate_endpoint_run([auth()], MAC)         # alias says IOS, the box says EOS
    assert r['reads'] == len(r['vantage'])       # only identity reads: nothing else is read from a device that is not what the alias says
    assert all(v['status'] == 'unparsed' and 'identity_os_mismatch' in v['warnings'] for v in r['vantage'])
    assert r['verdict'] == 'incomplete'
    assert not r['findings']


def test_a_transport_failure_of_a_locate_read_is_a_status_of_that_vantage_not_a_crash(monkeypatch):
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    def refuse(*args, **kwargs):
        raise TimeoutError('deadline')
    monkeypatch.setattr(engine, 'read_from_device', refuse)
    r = engine._locate_endpoint_run([auth()], MAC)
    assert r['verdict'] == 'incomplete' and not r['findings']
    assert r['vantage'] and all(v['status'] == 'timeout' for v in r['vantage'])


@pytest.mark.parametrize('table', ['mac_entry', 'lldp_neighbor', 'aggregate', 'interface', 'vlan', 'neighbor_l3'])
@pytest.mark.parametrize('state', ['ok', 'unparsed'])
@pytest.mark.parametrize('warning_source', ['coverage', 'envelope'])
def test_refusal_warning_makes_locate_incomplete_even_when_parser_is_ok(table, state, warning_source):
    budget = locate.Budget()
    target = replace(auth(profile='extreme_exos'), enabled_queries=auth().enabled_queries + ('lacp',))
    base = reader(budget)
    def read(*args):
        found = base(*args)
        if args[1] == 'mac_entry' and table == 'vlan':
            # The VLAN table is read only to name a tag the MAC table printed as a VLAN name.
            found['records'] = [{**row, 'vlan_id': None, 'vlan_name': 'lab-data'} for row in found['records']]
        if args[1] == table:
            found['status'] = state
            found['coverage']['complete'] = False
            if warning_source == 'coverage':
                found['coverage']['warnings'] = ['refusal_like_line_in_data']
            else:
                found['warnings'] = ['refusal_like_line_in_data']
        return found
    result = locate.run([target], '192.0.2.10', read, budget)
    assert result['verdict'] == 'incomplete'
    assert {'vantage': 'sw1', 'table': table, 'reason': 'refusal_like_line_in_data'} in result['missing']
    if table in ('mac_entry', 'lldp_neighbor', 'aggregate'):
        assert not any(f['edge'] for f in result['findings'])
    if state == 'unparsed':
        assert {'vantage': 'sw1', 'table': table, 'reason': state} in result['missing']


@pytest.mark.parametrize('warning', [False, True])
def test_catalogue_gaps_allow_not_found_but_refusal_warning_does_not(warning):
    budget = locate.Budget()
    base = reader(budget)
    def read(*args):
        found = base(*args)
        if args[1] == 'mac_entry':
            found['records'] = []
            found['coverage']['complete'] = False
            if warning:
                found['coverage']['warnings'] = ['refusal_like_line_in_data']
        return found
    result = locate.run([auth()], MAC, read, budget)
    assert result['verdict'] == ('incomplete' if warning else 'not_found_in_checked_data')
    assert result['missing'] == ([{'vantage': 'sw1', 'table': 'mac_entry', 'reason': 'refusal_like_line_in_data'}] if warning else [])


def test_unrelated_catalogue_fields_do_not_block_edge():
    budget = locate.Budget()
    base = reader(budget)
    def read(*args):
        found = base(*args)
        found['coverage']['complete'] = False
        found['coverage']['missing_fields'] = ['management_ip', 'description']
        found['warnings'] = ['fields_absent_in_catalogue_output']
        return found
    result = locate.run([auth()], MAC, read, budget)
    assert result['verdict'] == 'located' and result['missing'] == []
    assert result['findings'][0]['edge']


@pytest.mark.parametrize('endpoint', ['192.0.2.10', MAC])
@pytest.mark.parametrize('state', ['ok', 'unparsed', 'truncated', 'permission_denied'])
def test_own_interface_requires_a_successful_local_observation(endpoint, state):
    b = locate.Budget()
    def read(auth, table, query, parameters, ip):
        b.take()
        return envelope(table, [tables.record(table, ip='192.0.2.10', mac=MAC,
                                              interface='GigabitEthernet0/1.10', type='interface')], state)
    r = locate.run([auth(device_types=('router',))], endpoint, read, b)
    assert r['verdict'] == ('own_interface_of_target' if state == 'ok' else 'incomplete')
    assert bool(r['own_interfaces']) == (state == 'ok')
    assert r['reads'] == 1
    assert not any(m['reason'] == 'edge_beyond_enrolled_targets' for m in r['missing'])


def test_conflicting_owners_are_ambiguous():
    b = locate.Budget()
    def read(auth, table, query, parameters, ip):
        b.take()
        return envelope(table, [tables.record(table, ip='192.0.2.10', mac=MAC,
                                              interface='Vlan10', type='local')])
    r = locate.run([auth('r1', device_types=('router',)), auth('r2', device_types=('router',))],
                   '192.0.2.10', read, b)
    assert r['verdict'] == 'ambiguous' and {o['target'] for o in r['own_interfaces']} == {'r1', 'r2'}


def test_a_mac_edge_does_not_read_arp_for_ownership():
    b = locate.Budget()
    base = reader(b)
    def read(auth, table, *args):
        assert table != 'neighbor_l3'
        return base(auth, table, *args)
    r = locate.run([auth()], MAC, read, b)
    assert r['verdict'] == 'located' and r['reads'] == 3


def test_ownership_from_an_already_read_interface_mac():
    b = locate.Budget()
    base = reader(b)
    def read(*args):
        found = base(*args)
        if args[1] == 'interface':
            found['records'] = [{'name': 'Vlan10', 'mac': MAC}]
        return found
    r = locate.run([auth()], MAC, read, b)
    assert r['verdict'] == 'own_interface_of_target'
    assert r['own_interfaces'] == [{'target': 'sw1', 'interface': 'Vlan10', 'mac': MAC,
                                   'ip': None, 'source': 'interface'}]
    assert r['reads'] == 3


def test_ios_local_and_static_arp_evidence_from_real_gns3_capture():
    text = (Path(__file__).parent / 'fixtures/real/lab_endpoints/iosv/arp_table.txt').read_text()
    rows = tables.parse('cisco_ios', 'neighbor_l3', 'arp_table', text)['records']
    assert next(r for r in rows if r['ip'] == '192.0.2.1')['type'] == 'interface'
    assert all(r['type'] is None for r in rows if r['interface'] is None)
    assert all(r['type'] is None for r in rows if r['ip'] in ('192.0.2.3', '192.0.2.5'))


def test_mac_ownership_fallback_cannot_exceed_the_transport_budget():
    b = locate.Budget()
    b.reads = locate.MAX_READS - 1
    def read(auth, table, *args):
        b.take()
        assert table == 'neighbor_l3'
        return envelope(table, [])
    r = locate.run([auth('r1', device_types=('router',)), auth('r2', device_types=('router',))], MAC, read, b)
    assert r['reads'] == locate.MAX_READS and r['verdict'] == 'incomplete'
    assert any(m['reason'] == 'read_limit' for m in r['missing'])


@pytest.mark.parametrize('limit', [0, 41, True, 2.5, '30'])
def test_worker_refuses_invalid_injected_read_reservation(tmp_path, limit):
    import base64
    import test_proxy_contracts as c
    from netops_helper import proxy as p, endpoint_worker
    from netops_helper.auth import AuthenticationContextError
    inventory, _, _, _ = c._configure(p, tmp_path)
    section = c._section()
    section.update(device_types=['firewall'], enabled_queries=['arp_table'])
    c._write(inventory, c._inventory(c._device(section)))
    forwarded = p.Proxy().request(c._request(1, 'locate_endpoint', {'targets': ['device-a'], 'endpoint': MAC}))
    contexts = json.loads(json.loads(forwarded)['params']['arguments']['auth_context'])
    context = contexts['device-a']
    decoded = json.loads(base64.urlsafe_b64decode(context + '=' * (-len(context) % 4)))
    decoded['locate_read_limit'] = limit
    contexts['device-a'] = base64.urlsafe_b64encode(json.dumps(decoded).encode()).decode()
    with pytest.raises(AuthenticationContextError):
        endpoint_worker.decode(['device-a'], json.dumps(contexts))
