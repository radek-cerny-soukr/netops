"""A failed second read of a joined switch_read names its cause like a direct read (triage 158).

Only the device transport is fake (`read_from_device`): the first catalogue read answers real
captured output, the joined read fails the way the SSH transport does. The real identity check,
parser, join, engine envelope and the persisted Helper audit run unchanged.
"""
from dataclasses import replace
import json
from pathlib import Path

import pytest

from conftest import _target
from netops_core.audit import Recorder
from netops_helper import audit as helper_audit, engine
from netops_helper.query_catalog import READ_QUERIES

FIXTURES = Path(__file__).parent / 'fixtures'
REAL = FIXTURES / 'real'
PRIVATE = 'synthetic-private-transport-text'
FAILURES = [
    (lambda: ConnectionRefusedError(PRIVATE), 'transport_error', 'connection_refused'),
    (lambda: TimeoutError(PRIVATE), 'timeout', 'timeout'),
]
IDS = ['connection_refused', 'timeout']


@pytest.fixture()
def device(tmp_path, monkeypatch):
    audit = tmp_path / 'operations.jsonl'
    monkeypatch.setattr(helper_audit, '_RECORDER', Recorder(audit, 'helper'))
    engine._SSH_PAGE_CACHE.clear()

    def use(profile, outputs, failing, error):
        version = (FIXTURES / 'identity' / (profile + '.txt')).read_text()
        commands = {READ_QUERIES[profile][query].command: body for query, body in outputs.items()}
        refused = READ_QUERIES[profile][failing].command
        calls = []

        def read(auth, platform, command, **_):
            calls.append(command)
            if command == READ_QUERIES[profile]['version'].command:
                return 0, version
            if command == refused:
                raise error()
            return 0, commands[command]
        monkeypatch.setattr(engine, 'read_from_device', read)
        return calls

    def events():
        return [json.loads(line) for line in audit.read_text().splitlines()]

    yield use, events
    engine._SSH_PAGE_CACHE.clear()


def _failed_details(events, event):
    return [e.get('detail') for e in events if e['event'] == event and e['status'] == 'failed']


def _assert_named(result, events, status, code):
    assert result['ok'] is False and result['status'] == status
    assert (result['error_code'], result['error']) == (code, engine._TRANSPORT_ADVICE[code])
    assert not result['coverage']['complete']
    assert _failed_details(events, 'switch_read') == [code]
    assert PRIVATE not in json.dumps([result, events])


@pytest.mark.parametrize('error,status,code', FAILURES, ids=IDS)
def test_junos_els_mac_entry_vlans_join_failure_names_the_cause(device, error, status, code):
    use, events = device
    data = json.loads((FIXTURES / 'tables/juniper_junos_els.json').read_text())
    calls = use('juniper_junos_els', {'mac_table': data['mac_entry']}, 'vlans', error)
    auth = replace(_target('juniper_junos_els', 'mac_table'), enabled_queries=('mac_table', 'vlans'))
    result = engine.switch_read(auth, 'mac_entry')
    assert result['records'] and [s['query'] for s in result['sources']][0] == 'mac_table'
    assert READ_QUERIES['juniper_junos_els']['vlans'].command in calls
    _assert_named(result, events(), status, code)


@pytest.mark.parametrize('error,status,code', FAILURES, ids=IDS)
def test_ip_interface_route_join_failure_names_the_cause(device, error, status, code):
    use, events = device
    directory = REAL / 'cisco_ios/iosv_15.9.3M12'
    calls = use('cisco_ios', {'ip_interfaces': (directory / 'ip_interfaces.txt').read_text()}, 'route_table', error)
    auth = replace(_target('cisco_ios', 'ip_interfaces'), enabled_queries=('ip_interfaces', 'route_table'))
    result = engine.switch_read(auth, 'ip_interface')
    assert result['records']
    assert READ_QUERIES['cisco_ios']['route_table'].command in calls
    _assert_named(result, events(), status, code)


@pytest.mark.parametrize('error,status,code', FAILURES, ids=IDS)
def test_interface_errors_failure_of_a_later_source_names_the_cause(device, error, status, code):
    use, events = device
    directory = REAL / 'exos/x435-8p-4s_33.7.1.6'
    calls = use('extreme_exos', {'ports_rx_errors': (directory / 'ports_rx_errors.txt').read_text()},
                'ports_tx_errors', error)
    auth = replace(_target('extreme_exos', 'ports_rx_errors'), enabled_queries=('ports_rx_errors', 'ports_tx_errors'))
    result = engine.switch_read(auth, 'interface_errors')
    assert result['records'] and len(result['sources']) >= 1
    assert READ_QUERIES['extreme_exos']['ports_tx_errors'].command in calls
    _assert_named(result, events(), status, code)


def test_joins_that_succeed_carry_no_error_code(device):
    use, events = device
    directory = REAL / 'exos/x435-8p-4s_33.7.1.6'
    bodies = {q: (directory / (q + '.txt')).read_text() for q in ('ports_rx_errors', 'ports_tx_errors')}
    use('extreme_exos', bodies, 'ports_configuration', ConnectionRefusedError)
    auth = replace(_target('extreme_exos', 'ports_rx_errors'), enabled_queries=tuple(bodies))
    result = engine.switch_read(auth, 'interface_errors')
    assert result['ok'] is True and result['status'] == 'ok'
    assert 'error_code' not in result and 'error' not in result
    assert _failed_details(events(), 'switch_read') == []
