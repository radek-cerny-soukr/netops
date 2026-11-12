"""Route fallback against anonymized IOS and IOS XE lab captures."""
from dataclasses import replace
from pathlib import Path

import pytest

from conftest import _target
from netops_helper import engine, route_fallback, tables

REAL = Path(__file__).parent / 'fixtures/real'


@pytest.mark.parametrize('profile,directory', [
    ('cisco_ios', 'cisco_ios/iosv_15.9.3M12'),
    ('cisco_xe', 'cisco_xe/iolxe_17.18.2'),
])
def test_real_lookup_falls_back_to_real_table(monkeypatch, profile, directory):
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    path = REAL / directory
    # Captures include the command and terminal prompt; transport returns only output.
    capture = (path / 'show-ip-route-203.0.113.1.txt').read_text().splitlines()
    missing = '\n'.join(capture[1:-1])
    default = (path / 'show-ip-route-0.0.0.0.txt').read_text().splitlines()
    assert tables.parse(profile, 'route', 'route_lookup', '\n'.join(default[1:-1]))['records'][0]['prefix'] == '0.0.0.0/0'
    outputs = {'route_lookup': missing, 'route_table': (path / 'route_table.txt').read_text()}
    calls = []
    def read(auth, profile, query, table, parameters=None):
        calls.append(query)
        return tables.parse(profile, table, query, outputs[query])
    monkeypatch.setattr(engine, 'normalized_query', read)
    auth = replace(_target(profile, 'route_lookup'), enabled_queries=('route_lookup', 'route_table'), device_types=('router',))
    result = engine.switch_read(auth, 'route', ip='127.0.0.2')
    assert calls == ['route_lookup', 'route_table']
    assert result['source'] == 'longest_prefix_from_table'
    assert result['status'] == 'ok'
    assert [r['prefix'] for r in result['records']] == ['0.0.0.0/0']
    assert [s['query'] for s in result['sources']] == calls


def test_fallback_does_not_bypass_query_permission(monkeypatch):
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    monkeypatch.setattr(engine, 'normalized_query', lambda auth, profile, query, table, parameters=None:
                        tables.parse(profile, table, query, '', status='empty'))
    auth = replace(_target('cisco_ios', 'route_lookup'), device_types=('router',))
    result = engine.switch_read(auth, 'route', ip='203.0.113.1')
    assert result['status'] == 'permission_denied' and not result['records']


def test_partial_table_is_still_filtered_and_remains_unparsed():
    path = REAL / 'cisco_ios/iosv_15.9.3M12/route_table.txt'
    initial = tables.parse('cisco_ios', 'route', 'route_lookup', '', status='empty')
    partial = tables.parse('cisco_ios', 'route', 'route_table', path.read_text() + '\nunrecognized route line\n')
    result = route_fallback.lookup(initial, '127.0.0.2', lambda: partial)
    assert result['status'] == 'unparsed' and not result['coverage']['complete']
    assert [row['prefix'] for row in result['records']] == ['0.0.0.0/0']


@pytest.mark.parametrize('profile', ['cisco_ios', 'cisco_xe', 'cisco_nxos'])
@pytest.mark.parametrize('enabled', [False, True])
@pytest.mark.parametrize('ip', [None, '192.0.2.1', '2001:db8::1'])
def test_route_reservation_covers_only_the_enabled_ios_lookup_fallback(profile, enabled, ip):
    from types import SimpleNamespace
    from netops_helper.proxy import Proxy
    section = SimpleNamespace(catalog_platform=lambda: profile,
                              enabled_queries=('route_lookup', 'route_table') if enabled else ('route_lookup',))
    cost = Proxy._rate_cost('switch_read', None, section, {'table': 'route', 'ip': ip})
    assert cost == (2 if profile in ('cisco_ios', 'cisco_xe') and enabled and ip is not None and ':' not in ip else 1)
