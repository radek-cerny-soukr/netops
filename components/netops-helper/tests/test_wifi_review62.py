"""Regressions for the Wi-Fi review: failed snapshots never revive old errors."""
from datetime import timedelta

import pytest

from netops_helper import triage_wifi as t, wifi_rest as r
from test_wifi_diagnostic import triage, live_answer
from test_wifi_history_selection import event
from test_triage_wifi import NOW


@pytest.fixture(autouse=True)
def audit(monkeypatch):
    from netops_helper import engine
    monkeypatch.setattr(engine, "record", lambda *a, **kw: None)


@pytest.mark.parametrize('latest_error', [True, False])
@pytest.mark.parametrize('last', [{'ok': False, 'error_code': 'rate_limited'},
                                  {'ok': True, 'records': [], 'sources': []}])
def test_recovery_uses_last_successful_client_observation(latest_error, last):
    failure = event(1, 'Wireless client authentication failed', reason='invalid credential')
    failure['time'] = (NOW - timedelta(minutes=10)).isoformat()
    records = [failure]
    if not latest_error:
        connection = event(2, 'Wireless client associated')
        connection['time'] = (NOW - timedelta(minutes=1)).isoformat()
        records.insert(0, connection)
    def history(mac):
        return {'ok': True, 'events': {'records': records},
                'sources': [{'endpoint': r.WIRELESS_LOG, 'content_sha256': 'a'*64}]}
    following = iter([live_answer(), last])
    result = triage(event_read=history, sample_live=lambda: next(following), pause=lambda s: None)
    for view in (result, t.overview(result)):
        finding = next(f for f in view['findings'] if f['id'] == 'F-WIFI-CLIENT-ERROR')
        assert finding['historical'] and finding['severity'] == 'notice'
        assert view['verdict'] != 'fault_found'
        assert view['chain']['association']['last_observed_status'] == 'associated'
    assert result['chain']['events']['timeline'][0]['historical']


def test_signal_gap_is_reported_once_per_snapshot():
    following = iter([live_answer(snr=None), live_answer(snr=None)])
    result = triage(live=live_answer(snr=None), sample_live=lambda: next(following), pause=lambda s: None)
    for view in (result, t.overview(result)):
        gaps = [m for m in view['missing'] if m['step'] == 'client_rssi' and m['reason'] == 'unparsed']
        assert [m.get('sample') for m in gaps] == [1, 2, 3]


def test_full_history_pages_bound_the_entire_result_and_keep_every_event():
    import copy
    import json
    records = [event(i % 50 + 1, 'Wireless client disassociated', reason='idle timeout ' + str(i))
               for i in range(200)]
    for i, row in enumerate(records):
        row.update(index=i + 1, logdesc=row['logdesc'] + ' Ž' * 40)
    result = triage(event_read=lambda mac: {'ok': True, 'events': {'records': records},
                    'sources': [{'endpoint': r.WIRELESS_LOG, 'content_sha256': 'a' * 64}]})
    original = copy.deepcopy(result)
    seen = []
    args = {'history_limit': 500, 'history_offset': 0}
    while args:
        page = t.full_page(result, **args)
        assert page['ok'] and len(json.dumps(page).encode()) <= 48_000
        assert page['findings'] == original['findings']
        assert page['chain']['events']['summary'] == original['chain']['events']['summary']
        rows = page['chain']['events']['timeline']
        assert rows and page['page']['returned'] == len(rows)
        assert all(row['source_sha256'] == 'a' * 64 for row in rows)
        assert all(set(row) <= set(t.compact_event(row)) | {'source_sha256'} for row in rows)
        seen.extend(row['index'] for row in rows)
        if page['next']:
            assert page['next']['history_offset'] > args['history_offset']
        args = page['next']
    assert seen == [e['index'] for e in original['chain']['events']['timeline']]
    assert result == original
    assert not t.full_page(result, history_offset=8_000_000)['chain']['events']['timeline']
    assert t.full_page(result, history_offset=8_000_000)['next'] is None
    assert len(t.full_page(result, history_limit=1)['chain']['events']['timeline']) == 1
    result['chain']['observation']['oversized'] = 'x' * 48_000
    assert t.full_page(result)['error_code'] == 'result_too_large'


@pytest.mark.parametrize('field,value', [('history_limit', True), ('history_limit', 0),
    ('history_limit', 501), ('history_offset', -1), ('history_offset', 8_000_001), ('history_offset', '0')])
def test_history_arguments_fail_before_device_access(monkeypatch, field, value):
    from netops_helper import engine
    from netops_helper.proxy import Proxy, ToolArgumentsError
    from test_wifi_rest import auth
    from test_triage_wifi import CLIENT
    monkeypatch.setattr(engine, 'triage_wifi_read', lambda *a: pytest.fail('device contacted'))
    with pytest.raises(ValueError, match=field):
        engine.triage_wifi(auth(), mac=CLIENT, **{field: value})
    with pytest.raises(ToolArgumentsError):
        Proxy._validate_tool_arguments('wifi_triage', {'target': 'example', 'mac': CLIENT, field: value})


def test_ssh_scan_cannot_trigger_observer_rule():
    from netops_helper import wifi_parse
    from test_triage_wifi import outputs
    parsed = wifi_parse.summarize('wifi_neighbors', outputs()['wifi_neighbors'])
    assert parsed['records'] and not parsed['unparsed_count']
    assert all('detected_by_wtp' not in row for row in parsed['records'])
    result = triage()
    assert result['chain']['neighbors']['relevance_status'] == 'observer_unavailable'
    assert not any(f['id'] == 'F-WIFI-STRONG-COCHANNEL-NEIGHBOR' for f in result['findings'])


@pytest.mark.parametrize('credential,port,ports,ranges,allowed', [
    ('api-ro', 8443, [443], [], False), ('api-ro', 8443, [8443], [], True),
    ('api-ro', 8443, [], [[8400, 8500]], True), ('api-ro', 443, [8443], [], False),
    (None, 8443, [22], [], True)])
def test_proxy_enforces_triage_rest_port(credential, port, ports, ranges, allowed):
    from dataclasses import replace
    from netops_helper import inventory
    from netops_helper.proxy import Proxy, PolicyScopeError
    from netops_core import inventory as core
    from test_proxy_contracts import _device, _section
    section = inventory.section(core._device(0, _device(_section())))
    section = replace(section, fortios_rest_credential=credential, fortios_rest_port=port,
                      egress={**section.egress, 'tcp_ports': ports, 'tcp_port_ranges': ranges})
    if allowed:
        Proxy._authorize_tool('wifi_triage', {}, None, section)
    else:
        with pytest.raises(PolicyScopeError) as caught:
            Proxy._authorize_tool('wifi_triage', {}, None, section)
        assert caught.value.data['field'] == 'egress'


def test_documentation_review_contracts_and_whitespace():
    from pathlib import Path
    root = Path(__file__).resolve().parents[3]
    guide = (root / 'docs/fortios-wifi-rest.md').read_text()
    quick = (root / 'docs/quickstart-1.0.md').read_text()
    helper = (root / 'docs/helper-configuration.md').read_text()
    tools = (root / 'components/netops-helper/docs/tools.md').read_text()
    assert 'fixed TCP 443' not in quick and 'allow egress 443' not in quick
    assert 'fortios_rest_port' in quick and 'fortios_rest_port' in helper
    assert 'reachable\n`admin-sport` 443' not in helper
    for text in (tools, (root / 'CHANGELOG.md').read_text(), (root / 'release/notes-1.0.7.md').read_text()):
        assert 'only for TCP 443' not in text
        assert 'fortios_rest_port' in text and 'port=8443' in text
        assert '15-read' in text
    assert 'helper.fortios_rest_port is invalid' in guide
    assert '48 000 bytes' in guide and 'history_offset' in guide and 'source_sha256' in guide
    assert '`netops-test-ro` reading `show system api-user netops-test-api-ro`' in guide
    assert 'netops-20261109-53' in guide and 'cleanup' in guide
    assert 'All-read is the measured baseline' not in guide and '`authgrp read`' in guide
    assert 'verify `fortios_rest_port` equals the effective `admin-sport`' in guide
    dns = guide.split('openssl s_client -connect fg.example.net:443')[0].rsplit('```sh', 1)[1]
    assert 'Replace 443 with admin-sport' in dns
    readme = (root / 'README.md').read_text()
    assert 'newest client events' not in readme
    assert 'identity_trust: client_supplied' in readme
    common = (root / 'components/netops-helper/src/netops_helper/wifi_common.py').read_text()
    assert common.endswith('\n') and not common.endswith('\n\n')
    rest = (root / 'components/netops-helper/src/netops_helper/wifi_rest.py').read_text()
    assert '\n\n\n\n_AP_OVERVIEW' not in rest


def test_interfering_observer_uses_matching_rogue_spectrum_and_own_signal():
    import copy
    from test_wifi_rest import fixture
    from test_triage_wifi import AP2
    rogue = copy.deepcopy(fixture('monitor_wifi_rogue_ap'))
    rogue['results'] = [rogue['results'][0]]
    rogue['results'][0].update(channel=116, band='11ACVHT40', bw='40',
                               detected_by_wtp=[{'serial': 'other-ap', 'signal_strength': -10}])
    interfering = copy.deepcopy(fixture('monitor_wifi_interfering_ap'))
    interfering['results'] = [interfering['results'][0]]
    interfering['results'][0]['wtps'] = [{'wtp_id': AP2, 'radio': 2, 'signal': -42}]
    answer = {'ok': True, 'rogue': r.parse(r.MONITOR+'rogue_ap', rogue),
              'interfering': r.parse(r.MONITOR+'interfering_ap', interfering), 'sources': []}
    result = triage(neighbor_read=lambda: answer)
    assert result['chain']['neighbors']['strongest_relevant_dbm'] == -42
    assert any(f['id'] == 'F-WIFI-STRONG-COCHANNEL-NEIGHBOR' for f in result['findings'])
    answer['rogue'][0]['detected_by_wtp'] = [{'serial': AP2, 'signal_strength': -50}]
    assert triage(neighbor_read=lambda: answer)['chain']['neighbors']['relevant_entries'] == 1
    answer['rogue'] = []
    assert triage(neighbor_read=lambda: answer)['chain']['neighbors']['strongest_relevant_dbm'] is None
    failed = triage(neighbor_read=lambda: {'ok': False, 'error_code': 'authorization_failed', 'http_status': 403})
    assert failed['chain']['neighbors']['relevance_status'] == 'context_read_failed'
    assert any(m['step'] == 'wifi_neighbors_rest' and m['http_status'] == 403 for m in failed['missing'])
