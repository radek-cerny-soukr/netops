"""Radio context and source time must not masquerade as client signal measurements."""
from netops_helper import triage_wifi as t, wifi_rest as r, wifi_parse
from test_wifi_diagnostic import triage, live_answer
from test_wifi_rest import auth, fixture
from test_triage_wifi import fixture as cli_fixture


def test_radio_findings_name_sharing_source_and_known_or_unknown_interval():
    live = live_answer()
    radio = live['records'][0]['ap_detail']['radio'][1]
    radio.update(client_count=2, channel_utilization_percent=87, tx_retries_percent=30)
    result = triage(live=live)
    for view in (result, t.overview(result)):
        findings = [f for f in view['findings'] if f['id'] in ('F-WIFI-RADIO-BUSY', 'F-WIFI-RADIO-RETRIES')]
        assert len(findings) == 2
        for finding in findings:
            assert 'radio-wide, shared by 2 clients, not specific to this client' in finding['text']
            assert r.MONITOR + 'managed_ap' in finding['text']
            assert 'interval unknown' in finding['text']
        context = view['chain']['radio_context']
        assert context['client_count'] == 2 and context['tx_retries_interval_seconds'] is None
        assert view['chain']['client_state']['rssi_dbm'] == -45
    parsed = wifi_parse.parse_wtp_status(cli_fixture('wtp_status'))
    radio = parsed['records'][1]['radios'][1]
    assert radio['chutil_interval_seconds'] == 15  # measured CLI text supplies this interval


def test_fetch_time_does_not_establish_measurement_age(monkeypatch):
    from netops_helper import engine
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    def get(a, path):
        return fixture('device_query' if path == r.DEVICES else 'monitor_wifi_' + path.rsplit('/', 1)[-1])
    monkeypatch.setattr(r, 'get', get)
    client = engine.wifi_clients(auth())['records'][0]
    assert client['fetched_at'] == client['captured_at']
    assert client['measurement_age_seconds'] is None
    assert 'no RSSI/SNR measurement timestamp' in client['measurement_age_note']
    result = triage()
    for view in (result, t.overview(result)):
        observation = view['chain']['observation']
        assert observation['fetched_at'] is not None
        assert observation['measurement_age_seconds'] is None
        assert observation['radio_measurement_age_seconds'] is None
        assert observation['channel_utilization_age_seconds'] == 0
        assert view['chain']['radio_context']['tx_retries_measurement_age_seconds'] is None
    doc = fixture('monitor_wifi_managed_ap')
    for radio in doc['results'][0]['radio']:
        radio.pop('channel_utilization_timestamp', None)
    ap = r.ap_overview(r.parse(r.MONITOR + 'managed_ap', doc)[0])
    assert all(radio['measurement_age_seconds'] is None for radio in ap['radios'])
    assert 'measurement_age_note' in ap


def test_serialized_target_blocking_and_sampling_are_documented():
    from pathlib import Path
    root = Path(__file__).resolve().parents[3]
    for path in (root / 'docs/fortios-wifi-rest.md', root / 'components/netops-helper/docs/tools.md'):
        text = path.read_text()
        assert 'serialized' in text and '25–30 seconds' in text
        assert 'blocks' in text and '15' in text


def test_ap_engine_keeps_utilization_age_separate_in_full_and_summary(monkeypatch):
    from netops_helper import engine
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    def get(a, path):
        return fixture('monitor_wifi_' + path.rsplit('/', 1)[-1])
    monkeypatch.setattr(r, 'get', get)
    for summary in (False, True):
        result = engine.wifi_aps_live(auth(), summary=summary)
        assert result['ok']
        for access in result['records']:
            for radio in access['radios' if summary else 'radio']:
                assert radio['measurement_age_seconds'] is None
                assert radio['channel_utilization_age_seconds'] >= 0
