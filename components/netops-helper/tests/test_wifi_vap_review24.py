"""VAP migration scenarios over the production worker/proxy/engine path."""
import copy

import pytest

from netops_helper import engine, wifi_rest as rest
from test_wifi_review24 import call  # shared real worker/proxy harness
from test_wifi_rest import fixture
from test_triage_wifi import outputs, CLIENT, AP2


@pytest.mark.parametrize('summary', [False, True])
@pytest.mark.parametrize('source', ['ssh-id', 'rest-id', 'rest-log-id', 'rest-ssid', 'rest-ssid-reversed', 'rest-radio-ssid', 'rest-id-down'])
def test_migrated_ssid_cannot_select_first_disabled_vap(call, monkeypatch, summary, source):
    values = outputs()
    original = values['wifi_vap_status']
    old = original.replace('WLAN: ssid-17', 'WLAN: old-vap').replace(
        'name             : ssid-17', 'name             : old-vap').replace('downup_oper      : up', 'downup_oper      : down')
    values['wifi_vap_status'] = original + '\n' + old if source == 'rest-ssid-reversed' else old + '\n' + original
    if source == 'rest-id-down':
        values['wifi_vap_status'] = old + '\n' + original.replace('downup_oper      : up', 'downup_oper      : down')

    def ssh(auth, platform, command):
        commands = {'get system status': 'system_status', 'get wireless-controller wtp-status': 'wifi_ap_status',
                    'get wireless-controller vap-status': 'wifi_vap_status', 'get wireless-controller scan': 'wifi_neighbors'}
        key = 'wifi_rf_analysis' if command.startswith('get wireless-controller rf-analysis') else commands[command]
        return 0, values[key]
    monkeypatch.setattr(engine, 'read_from_device', ssh)
    monkeypatch.setattr(engine, '_sequence_read', lambda *a: (0, values['wifi_events']))

    def get(auth, path):
        key = 'device_query' if path == rest.DEVICES else 'wireless_log' if path.startswith(rest.WIRELESS_LOG) else 'monitor_wifi_' + path.rsplit('/', 1)[-1]
        doc = copy.deepcopy(fixture(key))
        if path.endswith('/client'):
            client = doc['results'][0]
            client.update(mac=CLIENT, ssid='ssid-17')
            if source in ('rest-id', 'rest-id-down'):
                client['vap_name'] = 'ssid-17'
            else:
                client.pop('vap_name', None)
            doc['results'] = [client]
        elif path.endswith('/managed_ap'):
            # The station is currently on AP1; its older log belongs to AP2.
            if source == 'rest-log-id':
                doc['results'][0]['serial'] = AP2
            for ap in doc['results']:
                ap['ssid'] = [{'radio': 2, 'list': ['ssid-17']}] if source == 'rest-radio-ssid' else []
        return doc
    monkeypatch.setattr(rest, 'get', get)
    out = call('wifi_triage', {'mac': CLIENT, 'summary': summary}, rest_enabled=source != 'ssh-id')
    assert any(f['id'] == 'F-WIFI-VAP-DOWN' for f in out['findings']) == (source == 'rest-id-down')
    if source in ('rest-ssid', 'rest-ssid-reversed'):
        assert any(m['step'] == 'vap' and m['reason'] == 'ambiguous' for m in out['missing'])
        if not summary:
            assert out['chain']['vap'] is None
    elif not summary:
        assert out['chain']['vap']['name'] == 'ssid-17'
        assert out['chain']['vap']['state'] == ('down' if source == 'rest-id-down' else 'up')
