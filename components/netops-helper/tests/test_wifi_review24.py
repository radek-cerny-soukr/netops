"""Review regressions through the real worker, proxy, MCP tool and engine.

Only device transports and the station sampling delay are replaced. Inputs are
anonymized 80F 8.0.2 captures with explicit multi-AP/migration scenario edits.
"""
import asyncio
import copy
import functools
import json

import pytest

from netops import worker
from netops_helper import engine, proxy, server, triage_wifi, wifi_rest as rest
from test_proxy_contracts import _device, _inventory, _section, _vault_document, _write
from test_wifi_rest import fixture, PIN, TOKEN
from test_triage_wifi import outputs, CLIENT


@pytest.fixture
def call(tmp_path, monkeypatch):
    helper = tmp_path / 'helper'
    helper.mkdir(mode=0o700)
    monkeypatch.setattr(worker, 'STATE', tmp_path)
    monkeypatch.setattr(proxy, 'INVENTORY', helper / 'inventory.json')
    monkeypatch.setattr(engine, 'record', lambda *a, **k: None)
    monkeypatch.setattr(engine, 'read_from_device', lambda *a, **k: pytest.fail('unexpected real SSH'))
    monkeypatch.setattr(triage_wifi, 'run', functools.partial(triage_wifi.run, pause=lambda s: None))

    def invoke(tool, arguments, *, rest_enabled=True):
        section = _section()
        section['enabled_queries'] = list(outputs())
        section['read_inventory']['wtp_ids'] = ['name-1', 'name-10']
        section['rate_limit'] = {'requests': 60, 'window_seconds': 60}
        section['egress']['tcp_ports'] += [22, 443]
        if rest_enabled:
            section.update(fortios_rest_credential='api-ro', fortios_rest_certificate_sha256=PIN)
        _write(helper / 'inventory.json', _inventory(_device(section)))
        vault = _vault_document()
        vault['credentials']['api-ro'] = {'kind': 'api-token', 'login': None, 'value': TOKEN}
        _write(helper / 'vault.json', vault, 0o600)
        bridge = worker.HelperBridge()
        result = asyncio.run(bridge.call(server.mcp, tool, {'target': 'device-a', **arguments}))
        assert not result.get('isError'), result
        assert TOKEN not in json.dumps(result)
        assert not bridge.proxy.pending
        return result['structuredContent']
    return invoke


def neighbor_documents():
    docs = {n: copy.deepcopy(fixture('monitor_wifi_' + n))
            for n in ('managed_ap', 'client', 'rogue_ap', 'interfering_ap')}
    a, b = docs['managed_ap']['results']
    a['radio'][1].update(oper_chan=124, channel_bonding='40MHz')
    b['radio'][1].update(oper_chan=116, channel_bonding='40MHz')
    docs['client']['results'][1].update(wtp_id=b['wtp_id'], wtp_radio=2, channel=116)
    rogue = docs['rogue_ap']['results'][0]
    rogue.update(channel=116, band='11ACVHT40', bw='40', signal_strength=-40)
    for obs, ap, strength in zip(rogue['detected_by_wtp'], (a, b), (-40, -85)):
        obs.update(name=ap['name'], serial=ap['serial'], wtp_id=ap['wtp_id'],
                   wtp_radio=2, channel=116, signal_strength=strength)
    docs['rogue_ap']['results'] = [rogue]
    docs['interfering_ap']['results'] = [{'mac': rogue['mac'], 'wtps': [
        {'wtp_id': ap['wtp_id'], 'radio': 2, 'signal': strength} for ap, strength in ((a, -40), (b, -85))]}]
    return docs


@pytest.mark.parametrize('selector', ['all', 'ap', 'mac'])
@pytest.mark.parametrize('threshold', [None, -90])
def test_nonoverlapping_ap_never_supplies_summary_signal(call, monkeypatch, selector, threshold):
    docs = neighbor_documents()
    monkeypatch.setattr(rest, 'get', lambda auth, path: copy.deepcopy(docs[path.rsplit('/', 1)[-1]]))
    args = {} if selector == 'all' else {'ap': docs['managed_ap']['results'][1]['name']} if selector == 'ap' else {
        'mac': docs['client']['results'][1]['mac']}
    if threshold is not None:
        args['min_signal'] = threshold
    out = call('wifi_rogue', args)
    for kind in ('rogue', 'interfering'):
        if threshold is None:
            assert out[kind] == []
        else:
            row, = out[kind]
            assert row['signal_strength'] == -85
            assert row['heard_by'] == row['signal_observers'] == [docs['managed_ap']['results'][1]['name']]
            assert row['signal_scope'] == 'relevant_observers'


def test_full_retains_controller_observations_and_scoped_groups_order_by_signal(call, monkeypatch):
    docs = neighbor_documents()
    original = copy.deepcopy(docs['rogue_ap']['results'][0])
    stronger = copy.deepcopy(original)
    stronger['detected_by_wtp'][1]['signal_strength'] = -80
    other = copy.deepcopy(original)
    other.update(mac='00:00:5e:00:53:99', signal_strength=-42)
    other['detected_by_wtp'][1]['signal_strength'] = -82
    docs['rogue_ap']['results'] += [stronger, other]
    monkeypatch.setattr(rest, 'get', lambda auth, path: copy.deepcopy(docs[path.rsplit('/', 1)[-1]]))
    scoped = call('wifi_rogue', {'min_signal': -90})['rogue']
    assert [row['signal_strength'] for row in scoped] == [-80, -82]
    assert scoped[0]['deduplicated_bssid'] and scoped[0]['observation_count'] == 2
    full = call('wifi_rogue', {'full': True})['rogue']
    assert full[0]['signal_strength'] == -40
    assert [(w['name'], w['signal_strength']) for w in full[0]['observations'][0]['detected_by_wtp']] == [(w['name'], w['signal_strength']) for w in original['detected_by_wtp']]
