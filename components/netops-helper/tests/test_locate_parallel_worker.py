"""Real proxy -> engine -> isolated worker, with controlled concurrency, timeout plans and audit."""
import json
from pathlib import Path

import pytest

from netops_helper import engine, endpoint_worker, locate, proxy as p
import test_proxy_contracts as c
from support.virtual_clock import Clock, install, worker_source

MAC = '00:00:5e:00:53:81'


@pytest.mark.parametrize('clock_start', [0.0, 10_000_000.0])
@pytest.mark.parametrize('count,slow', [(7, False), (20, False), (20, True), (7, True)])
def test_parallel_location_through_proxy_and_worker(tmp_path, monkeypatch, count, slow, clock_start):
    inventory, _, _, _ = c._configure(p, tmp_path)
    devices = []
    for index in range(count):
        section = c._section()
        section.update(ssh_platform='cisco_ios', device_types=['switch', 'router'],
                       enabled_queries=['arp_table', 'mac_table', 'lldp_neighbors', 'interfaces'])
        address = '192.0.2.' + str(index + 10)
        section['egress']['addresses'] = [address]
        devices.append({**c._device(section, 'cisco_ios'), 'name': 'sw%d' % index, 'address': address})
    # Two aliases of one enrolled endpoint must share the same transport lane too.
    duplicate = 1 if count == 7 else count - 3
    devices[duplicate + 1]['address'] = devices[duplicate]['address']
    devices[duplicate + 1]['helper']['egress']['addresses'] = [devices[duplicate]['address']]
    c._write(inventory, c._inventory(*devices))
    proxy = p.Proxy()
    forwarded = proxy.request(c._request(1, 'locate_endpoint', {
        'targets': [d['name'] for d in devices], 'endpoint': '192.0.2.200' if not slow or count == 7 else MAC}))
    assert forwarded is not None
    args = json.loads(forwarded)['params']['arguments']
    audit = tmp_path / 'audit.jsonl'
    wire = tmp_path / 'wire.jsonl'
    monkeypatch.setenv('NETOPS_HELPER_AUDIT_PATH', str(audit))
    # Only the transport is replaced in the real isolated worker; catalogue,
    # identity checking, parsing, audit, budgets and subprocess protocol are real.
    version = (Path(__file__).parent / 'fixtures/identity/cisco_ios.txt').read_text()
    bootstrap = endpoint_worker.command()
    clock = Clock(clock_start, tmp_path / 'parallel-clock')
    install(monkeypatch, clock)
    code = '''
import json, threading
from netops_helper import engine, locate
version = %r
wire = %r
slow = %r
slow_l3 = %r
active = set()
lock = threading.Lock()
wave_size = %r
wave = threading.Barrier(wave_size, timeout=30)
gated = set()
healthy_done = threading.Event()
slow_mac_waiting = threading.Event()
count = %r
exec(%r)
original_run = locate.run
def run(auths, endpoint, read, budget, progress, identify):
    def report(result):
        mac_targets = {v['target'] for v in result['vantage'] if v['table'] == 'mac_entry' and v['status'] in ('ok', 'empty')}
        edge_ready = any(v['target'] == 'sw0' and v['table'] == 'interface' for v in result['vantage'])
        if len(mac_targets - {'sw' + str(count - 1)}) == count - 1 and edge_ready:
            healthy_done.set()
        progress(result)
    def observed_read(auth, table, *args):
        if slow_l3 and auth.alias == 'sw' + str(count - 1) and table == 'mac_entry':
            slow_mac_waiting.set()
        return read(auth, table, *args)
    return original_run(auths, endpoint, observed_read, budget, report, identify)
locate.run = run
def transport(auth, profile, command):
    key = (auth.host, auth.port)
    with lock:
        assert key not in active, 'concurrent SSH on one device'
        assert len(active) < 8, 'parallel device cap exceeded'
        active.add(key)
        gate = key not in gated and len(gated) < wave_size
        if gate:
            gated.add(key)
        with open(wire, 'a') as handle:
            handle.write(json.dumps({'device': auth.alias, 'command': command, 'active': len(active)}) + '\\n')
    try:
        if gate:
            wave.wait()
        index = int(auth.alias[2:])
        stalled = slow and index == (6 if slow_l3 else 19) and command == ('show ip arp' if slow_l3 else 'show mac address-table')
        delay = 70 if stalled else 5 + 5 * (index %% 3) if command == 'show mac address-table' else 0.02
        left = engine._read_timeout(delay)
        # A fixed monotonic clock gives an exact timeout plan. Events force the
        # stalled read to overlap all healthy work; no scheduler speed is asserted.
        assert left == min(delay, 59.5)
        if stalled:
            assert healthy_done.wait(30), 'healthy targets were held behind a stalled read'
            if slow_l3:
                assert slow_mac_waiting.wait(30), 'MAC phase did not reach the slow ARP target'
        if left < delay:
            raise TimeoutError('SSH timed out at shared deadline')
        if command == 'show version':
            return 0, version
        if command == 'show ip arp':
            return 0, 'Internet  192.0.2.200  2  0000.5e00.5381  ARPA  Vlan101\\n'
        if command == 'show mac address-table':
            return 0, '  101    0000.5e00.5381    DYNAMIC    Gi1/0/5\\n' if index == 0 else ''
        if command == 'show lldp neighbors detail':
            return 0, ''
        if command == 'show interfaces status':
            return 0, 'Port      Name               Status       Vlan       Duplex  Speed Type\\nGi1/0/5                      connected    101        a-full  a-1000 10/100/1000BaseTX\\n'
        raise AssertionError(command)
    finally:
        with lock:
            active.remove(key)
engine.read_from_device = transport
from netops_helper.endpoint_worker import main
main()
''' % (version, str(wire), slow, slow and count == 7, min(8, count - 1), count, worker_source(clock))
    roots = bootstrap[-1].split('; from netops_helper.endpoint_worker import main; main()')[0]
    monkeypatch.setattr(endpoint_worker, 'command', lambda: bootstrap[:-1] + [roots + '\n' + code])
    result = engine.locate_endpoint(**args)
    assert result['ok'] is True and result['reads'] <= result['limits']['reads']
    assert result['coverage']['requested_targets'] == args['targets']
    assert result['findings'][0]['edge'] and result['findings'][0]['vantage'] == 'sw0'
    if slow:
        assert result['verdict'] == 'incomplete'
        assert result['coverage']['unfinished_targets'] == ['sw%d' % (count - 1)]
        assert not result['coverage']['complete']
        assert any(m['vantage'] == 'sw%d' % (count - 1) and m['reason'] == 'timeout' for m in result['missing'])
        assert not any(m['table'] == 'worker' for m in result['missing'])
    else:
        assert result['verdict'] == 'located', result
        assert result['coverage']['complete'] and result['coverage']['unfinished_targets'] == []
    records = [json.loads(line) for line in audit.read_text().splitlines()]
    reads = [json.loads(line) for line in wire.read_text().splitlines()]
    # Every transport read is inside an audited operation; the initial identity
    # belongs to that device's first table operation, exactly as in production.
    starts = [r for r in records if r['status'] == 'started']
    ends = [r for r in records if r['status'] != 'started']
    assert len(starts) == len(ends)
    assert {r['operation_id'] for r in starts} == {r['operation_id'] for r in ends}
    assert {r['device'] for r in starts} == {r['device'] for r in reads} == set(args['targets'])
    expected_reads = 42 if slow and count == 20 else 3 * count + 2
    assert len(reads) == result['reads'] == expected_reads
    assert max(r['active'] for r in reads) >= min(8, count - 1)
    assert max(r['active'] for r in reads) <= locate.MAX_PARALLEL
    assert all(r['command'].startswith('show ') for r in reads)
    print('locate targets=%d slow=%s reads=%d max_active=%d unfinished=%s' % (
        count, slow, result['reads'], max(r['active'] for r in reads), result['coverage']['unfinished_targets']), flush=True)


def test_shared_hostname_supplement_is_read_once_for_parallel_lldp_neighbors():
    import threading
    readers = threading.Barrier(2, timeout=30)
    from test_locate_endpoint import auth, envelope
    from netops_helper import tables
    targets = [auth('leaf1'), auth('leaf2'), auth('core')]
    budget = locate.Budget()
    identities = []
    def identify(target):
        if target.alias == 'core':
            identities.append(target.alias)
            return ('core-system',)
        return ()
    def read(target, table, *args):
        budget.take()
        if table == 'mac_entry':
            return envelope(table, [] if target.alias == 'core' else [tables.record(
                table, mac=MAC, port='Gi1/0/1', vlan_id=101, type='dynamic')])
        if table == 'lldp_neighbor':
            readers.wait()
            return envelope(table, [tables.record(table, local_port='Gi1/0/1', neighbor='core-system')])
        return envelope(table, [])
    result = locate.run(targets, MAC, read, budget, identify=identify)
    assert identities == ['core']
    assert {f['role'] for f in result['findings']} == {'transit'}
    assert all(m['reason'] == 'endpoint_not_seen_on_neighbor_target' for m in result['missing'])


@pytest.mark.parametrize('clock_start', [0.0, 10_000_000.0])
@pytest.mark.parametrize('count', [5, 12, 30])
@pytest.mark.parametrize('edge_queries', [False, True])
def test_fortilink_reservation_only_without_transport_timing_through_proxy_and_worker(tmp_path, monkeypatch, count, edge_queries, clock_start):
    # Reservation arithmetic only: test_review_replays models FortiOS connection timing.
    from test_locate_acceptance_107 import forti_outputs, SERIALS, AP_IP
    from types import SimpleNamespace
    clock = Clock(clock_start, tmp_path / 'reservation-clock')
    install(monkeypatch, clock)
    monkeypatch.setattr(p, 'time', SimpleNamespace(monotonic=clock.monotonic))
    inventory, _, _, _ = c._configure(p, tmp_path)
    section = c._section()
    queries = ['arp_table', 'managed_switch_mac', 'managed_switch_lldp']
    if edge_queries:
        queries += ['managed_switch_port_stats', 'managed_switch_port_vlans', 'interface_vlan_ids']
    serials = ['S000SSSS%08d' % n for n in range(1, count + 1)]
    section.update(device_types=['firewall'], enabled_queries=queries)
    section['read_inventory']['managed_switches'] = serials
    # Exercise the inventory default, rather than a test-specific higher limit.
    del section['rate_limit']
    c._write(inventory, c._inventory(c._device(section)))
    proxy = p.Proxy()
    forwarded = proxy.request(c._request(1, 'locate_endpoint', {'targets': ['device-a'], 'endpoint': AP_IP}))
    assert forwarded is not None
    args = json.loads(forwarded)['params']['arguments']
    reservation = min(30, 7 + (5 if edge_queries else 2) * count)
    assert len(proxy.rate_history['device-a']) == reservation
    assert endpoint_worker.decode(args['targets'], args['auth_context'])[0].locate_read_limit == reservation
    outputs = forti_outputs()
    from netops_helper.query_catalog import READ_QUERIES
    mac_command = READ_QUERIES['fortinet']['managed_switch_mac'].command
    for serial in serials[2:]:
        outputs[mac_command.format(managed_switch=serial)] = outputs[
            mac_command.format(managed_switch=SERIALS[1])].replace(SERIALS[1], serial).replace(
                '00:00:5e:00:53:02', '00:00:5e:00:53:fe')
    audit, wire = tmp_path / 'audit.jsonl', tmp_path / 'wire.jsonl'
    monkeypatch.setenv('NETOPS_HELPER_AUDIT_PATH', str(audit))
    bootstrap = endpoint_worker.command()
    roots = bootstrap[-1].split('; from netops_helper.endpoint_worker import main; main()')[0]
    code = '''
import json
from netops_helper import engine
outputs, wire = %r, %r
def transport(auth, profile, command):
    with open(wire, 'a') as handle:
        handle.write(json.dumps({'device': auth.alias, 'command': command}) + '\\n')
    return 0, outputs[command]
engine.read_from_device = transport
from netops_helper.endpoint_worker import main
main()
''' % (outputs, str(wire))
    code = worker_source(clock) + code
    monkeypatch.setattr(endpoint_worker, 'command', lambda: bootstrap[:-1] + [roots + '\n' + code])
    result = engine.locate_endpoint(**args)
    reads = [json.loads(line) for line in wire.read_text().splitlines()]
    assert result['ok'] is True, result
    assert len(reads) == result['reads'] <= reservation
    assert all(r['device'] == 'device-a' for r in reads)
    mac_reads = [r for r in reads if r['command'].startswith('diagnose switch-controller switch-info mac-table ')]
    if count < 30:
        assert len(mac_reads) == count
        assert result['reads'] == count + (6 if edge_queries else 3)
        assert any(f['edge'] for f in result['findings'])
        if edge_queries:
            assert result['verdict'] == 'located' and result['coverage']['complete'], result
    else:
        assert result['reads'] == reservation == 30
        assert result['verdict'] == 'incomplete' and not result['coverage']['complete']
        assert any(m['reason'] == 'target_read_limit' for m in result['missing'])
    records = [json.loads(line) for line in audit.read_text().splitlines()]
    assert {r['device'] for r in records} == {'device-a'}
    assert {r['operation_id'] for r in records if r['status'] == 'started'} == {
        r['operation_id'] for r in records if r['status'] != 'started'}
    emitted = []
    monkeypatch.setattr(proxy, '_emit', emitted.append)
    request = {'targets': ['device-a'], 'endpoint': AP_IP}
    assert proxy.request(c._request(2, 'locate_endpoint', request)) is None
    assert emitted[-1]['error']['data']['category'] == 'rate_limit'
    clock.value = clock_start + 59.999
    assert proxy.request(c._request(3, 'locate_endpoint', request)) is None
    assert len(proxy.rate_history['device-a']) == reservation
    clock.value = clock_start + 60.0
    assert proxy.request(c._request(4, 'locate_endpoint', request)) is not None
    assert len(proxy.rate_history['device-a']) == reservation
    print('FortiLink switches=%d edge_queries=%s reserved=%d reads=%d verdict=%s' % (
        count, edge_queries, reservation, result['reads'], result['verdict']), flush=True)
