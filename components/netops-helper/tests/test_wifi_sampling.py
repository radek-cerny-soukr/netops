"""Three controller snapshots retain transient signal trouble and missing samples."""
from netops_helper import triage_wifi as t
from test_wifi_diagnostic import triage, live_answer


def sampled(answers):
    ticks = [0.0]
    waits = []
    def pause(seconds):
        waits.append(seconds)
        ticks[0] += seconds
    following = iter(answers[1:])
    result = triage(live=answers[0], sample_live=lambda: next(following),
                    pause=pause, monotonic=lambda: ticks[0])
    return result, waits


def test_transient_minimum_and_last_are_retained_in_both_views():
    result, waits = sampled([live_answer(-81, 14), live_answer(-61, 34), live_answer(-43, 52)])
    assert waits == [3.0, 3.0]
    for view in (result, t.overview(result)):
        samples = view['chain']['signal_samples']
        assert samples['requested'] == samples['collected'] == 3
        assert samples['rssi_dbm'] == {'min': -81, 'max': -43, 'last': -43}
        assert samples['snr_db'] == {'min': 14, 'max': 52, 'last': 52}
        finding = next(f for f in view['findings'] if f['id'] == 'F-WIFI-WEAK-SIGNAL')
        assert not finding['fault_level'] and finding['severity'] == 'warning' and 'transient weakness' in finding['text']
        assert 'last -43' in finding['text']


def test_last_snapshot_can_still_be_weak_and_sampling_never_changes_mac():
    result, _ = sampled([live_answer(-43), live_answer(-61), live_answer(-74)])
    finding = next(f for f in result['findings'] if f['id'] == 'F-WIFI-WEAK-SIGNAL')
    assert 'weak at last snapshot' in finding['text']
    other = live_answer(-90)
    other['records'][0]['mac'] = '00:00:5e:00:53:aa'
    result, _ = sampled([live_answer(), live_answer(), other])
    assert result['verdict'] == 'client_not_associated'
    assert result['chain']['signal_samples']['rssi_dbm']['last'] is None
    assert result['chain']['signal_samples']['rssi_dbm']['min'] == -45


def test_failed_snapshot_is_a_gap_and_is_not_a_zero_or_absence():
    result, _ = sampled([live_answer(), live_answer(-60), {'ok': False, 'error_code': 'timeout'}])
    assert result['client']['association_status'] == 'unknown'
    samples = result['chain']['signal_samples']
    assert samples['samples'][-1]['status'] == 'unavailable'
    assert samples['rssi_dbm'] == {'min': -60, 'max': -45, 'last': None}
    assert result['rf_verdict'] == 'incomplete'


def test_weak_signal_survives_last_failure_or_absence_and_middle_failure_stays_visible():
    for last in ({'ok': False, 'error_code': 'rate_limited'}, {'ok': True, 'records': []}):
        result, _ = sampled([live_answer(-81, 14), live_answer(-80, 15), last])
        for view in (result, t.overview(result)):
            finding = next(f for f in view['findings'] if f['id'] == 'F-WIFI-WEAK-SIGNAL')
            assert finding['severity'] == 'warning' and not finding['fault_level']
            assert 'last snapshot unavailable or client absent' in finding['text']
            assert view['chain']['association']['last_observed_status'] == 'associated'
            assert view['chain']['association']['last_observed_at']
    result, _ = sampled([live_answer(-81), {'ok': False, 'error_code': 'timeout'}, live_answer()])
    assert any(m.get('sample') == 2 and m.get('error_code') == 'timeout' for m in result['missing'])
    assert result['client']['association_status'] == 'associated'
    assert result['rf_verdict'] == 'rf_concern_found'


def test_severity_is_monotonic_and_fault_requires_last_value_below_severe_threshold():
    for values, severity, fault in (([-72]*3, 'warning', False), ([-80]*3, 'fault', True),
                                    ([-81, -43, -43], 'warning', False), ([-81, -74, -74], 'warning', False)):
        result, _ = sampled([live_answer(v) for v in values])
        finding = next(f for f in result['findings'] if f['id'] == 'F-WIFI-WEAK-SIGNAL')
        assert (finding['severity'], finding['fault_level']) == (severity, fault)


def test_absent_client_keeps_fault_in_summary_secondary_severity():
    from test_triage_wifi import outputs, NOW, CLIENT
    import hashlib
    values = outputs()
    values['wifi_ap_status'] = values['wifi_ap_status'].replace('Connected', 'Disconnected')
    def read(query, params):
        text = values[query]
        return {'ok': True, 'text': text, 'content_sha256': hashlib.sha256(text.encode()).hexdigest()}
    result = t.run(read, lambda: NOW, CLIENT, None, 'example', live=lambda: {'ok': True, 'records': []})
    for view in (result, t.overview(result)):
        assert view['verdict'] == 'client_not_associated'
        assert view['findings_max_severity'] == 'fault'
        assert any(f['id'] == 'F-WIFI-AP-NOT-CONNECTED' for f in view['findings'])


def test_engine_reads_enrichment_once_and_samples_only_station_endpoint(monkeypatch):
    from netops_helper import engine, wifi_rest as r
    from test_wifi_rest import auth, fixture
    from test_triage_wifi import outputs, CLIENT
    import hashlib
    paths = []
    def get(a, path):
        paths.append(path)
        if path == r.DEVICES:
            return fixture('device_query')
        if path.startswith(r.WIRELESS_LOG):
            doc = fixture('wireless_log')
            doc['results'] = [row for row in doc['results'] if row.get('stamac') == CLIENT]
            return doc
        doc = fixture('monitor_wifi_' + path.rsplit('/', 1)[-1])
        if path.endswith('/client'):
            doc['results'][0]['mac'] = CLIENT
        return doc
    def read(a, platform, query, parameters):
        text = outputs()[query]
        return {'ok': True, 'text': text, 'content_sha256': hashlib.sha256(text.encode()).hexdigest()}
    original = t.run
    monkeypatch.setattr(r, 'get', get)
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    monkeypatch.setattr(engine, 'triage_wifi_read', read)
    monkeypatch.setattr(engine, '_run_triage', lambda auth, run, read, tool: run(read))
    monkeypatch.setattr(t, 'run', lambda *a, **kw: original(*a, **kw, pause=lambda seconds: None))
    result = engine.triage_wifi(auth(), mac=CLIENT)
    assert result['ok'] and result['chain']['signal_samples']['collected'] == 3
    assert paths == [r.MONITOR+'client', r.MONITOR+'managed_ap', r.DEVICES,
                     r.MONITOR+'client', r.MONITOR+'client', r.wireless_log_path(CLIENT),
                     r.MONITOR+'rogue_ap', r.MONITOR+'interfering_ap']
    assert result['chain']['live_client']['ap_serial']
    assert result['chain']['radio_context']['source']['endpoint'] == r.MONITOR+'managed_ap'
