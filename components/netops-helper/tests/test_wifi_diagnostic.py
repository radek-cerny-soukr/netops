"""Operator diagnostic acceptance: measured shapes and explicit missing evidence."""
import copy
import dataclasses
from datetime import timedelta
import hashlib
import json

import pytest

from netops_helper import engine, wifi_parse, wifi_policy, wifi_rest as r, triage_wifi as t
from netops_helper.proxy import Proxy, ToolArgumentsError
from test_wifi_rest import auth, fixture
from test_triage_wifi import outputs, NOW, CLIENT, AP2


@pytest.fixture(autouse=True)
def audit(monkeypatch):
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)


def live_answer(rssi=-45, snr=50):
    client = r.parse(r.MONITOR + 'client', fixture('monitor_wifi_client'))[0]
    ap = r.parse(r.MONITOR + 'managed_ap', fixture('monitor_wifi_managed_ap'))[0]
    ap.update(serial=AP2, name='Example AP', wtp_id=AP2)
    radio = ap['radio'][1]
    radio.update(oper_chan=116, channel_width_mhz=40, channel_utilization_percent=1,
                 tx_retries_percent=0, channel_utilization_timestamp=NOW.isoformat())
    client.update(mac=CLIENT, hostname='TabletExample', ap_serial=AP2, ap_id=AP2,
                  ap_name='Example AP', ap_detail=ap, channel=116, band='5ghz', rssi_dbm=rssi,
                  snr_db=snr, captured_at=NOW.isoformat(), association_time=(NOW-timedelta(minutes=1)).isoformat())
    return {'ok':True, 'records':[client], 'sources':[
        {'endpoint':r.MONITOR+'client', 'captured_at':NOW.isoformat(), 'content_sha256':'a'*64},
        {'endpoint':r.MONITOR+'managed_ap', 'captured_at':NOW.isoformat(), 'content_sha256':'b'*64}]}


def triage(live=None, event_read=None, refused=(), **kw):
    values = outputs()
    def read(query, params):
        if query in refused:
            return {'ok':False, 'reason':'permission_denied'}
        text = values[query]
        return {'ok':True, 'text':text, 'content_sha256':hashlib.sha256(text.encode()).hexdigest()}
    return t.run(read, lambda: NOW, CLIENT if 'name' not in kw else None, None, 'example',
                 live=lambda: live or live_answer(), event_read=event_read, **kw)


def test_rest_history_is_preferred_and_missing_ssh_history_does_not_block_live_rf():
    calls=[]
    def events(mac):
        calls.append('REST')
        return {'ok':True, 'events':r.parse(r.WIRELESS_LOG, fixture('wireless_log')),
                'sources':[{'endpoint':r.WIRELESS_LOG,'content_sha256':'c'*64,'captured_at':NOW.isoformat()}]}
    result=triage(event_read=events, refused=('wifi_events',))
    assert calls == ['REST'] and 'wifi_events_rest' in result['checked']
    assert result['chain']['events']['timeline']
    assert result['chain']['events']['window']['from'] and 'History' in result['chain']['events']['window']['text']
    result=triage(refused=('wifi_events',))
    assert any(m['step']=='wifi_events' for m in result['missing'])
    assert result['chain']['observation']['rssi_dbm']==-45
    assert result['rf_verdict']=='no_rf_fault_found'


def test_identity_hostname_exact_casefold_and_unknown(monkeypatch):
    def get(a,path):
        key='device_query' if path==r.DEVICES else 'monitor_wifi_'+path.rsplit('/',1)[-1]
        return fixture(key)
    monkeypatch.setattr(r,'get',get)
    answer=engine.wifi_clients(auth(),name='tabletexample')
    client=answer['records'][0]
    assert (client['hostname'],client['os'],client['vendor'],client['device_type'])==('TabletExample','iPadOS','Apple','Tablet')
    assert client['identity_sources']['hostname']==r.DEVICES
    assert not engine.wifi_clients(auth(),name='Tablet')['records']
    assert r.parse(r.MONITOR+'client',fixture('monitor_wifi_client'))[0]['hostname']=='unknown'
    assert triage(name='tabletexample')['client']['mac']==CLIENT
    duplicated=live_answer(); duplicated['records']*=2
    assert any(m['reason']=='ambiguous' for m in triage(live=duplicated,name='TabletExample')['missing'])


@pytest.mark.parametrize('rssi,snr,rule,severity,fault',[(-70,20,None,None,False),(-71,20,'F-WIFI-WEAK-SIGNAL','warning',False),(-75,20,'F-WIFI-WEAK-SIGNAL','warning',False),(-76,20,'F-WIFI-WEAK-SIGNAL','fault',True),(-45,19,'F-WIFI-LOW-SNR','warning',False)])
def test_signal_threshold_boundaries_and_explained_findings(rssi,snr,rule,severity,fault):
    result=triage(live=live_answer(rssi,snr))
    findings=[f for f in result['findings'] if f['id'] in ('F-WIFI-WEAK-SIGNAL','F-WIFI-LOW-SNR')]
    if rule is None:
        assert not findings
    else:
        finding=next(f for f in findings if f['id']==rule)
        assert finding['severity']==severity and finding.get('fault_level',False)==fault
        assert 'threshold' in finding['text'] and 'First step' in finding['text'] and '2026-' in finding['text']
    custom=triage(live=live_answer(-65,50),thresholds={'weak_signal_dbm':-60})
    assert any(f['id']=='F-WIFI-WEAK-SIGNAL' for f in custom['findings'])


@pytest.mark.parametrize('bad',[{'unknown':1},{'low_snr_db':True},{'very_weak_signal_dbm':-60},{'retry_percent':101}])
def test_inventory_thresholds_validate(bad):
    with pytest.raises(ValueError): wifi_policy.thresholds(bad)


def test_summary_and_full_keep_radio_evidence_and_separate_wired_gap():
    result=triage(); brief=t.overview(result)
    assert brief['chain']['observation']==result['chain']['observation']
    observation=brief['chain']['observation']
    assert (observation['ap'],observation['radio'],observation['band'],observation['channel'],observation['channel_width_mhz'])==('Example AP',2,'5ghz',116,40)
    assert observation['channel_utilization_percent']==1 and observation['tx_retries_percent']==0
    assert observation['measurement_age_seconds'] is None and observation['radio_measurement_age_seconds'] is None
    assert observation['channel_utilization_age_seconds']==0
    assert result['rf_verdict']==result['verdict']=='no_rf_fault_found'
    assert any(m['step']=='locate_endpoint' and m['lldp_uplink'] for m in result['missing'])
    assert triage(refused=('wifi_rf_analysis',))['rf_verdict']=='no_rf_fault_found'
    live=live_answer(); live['records'][0]['snr_db']=None
    assert triage(live=live)['rf_verdict']=='incomplete'
    ap=r.parse(r.MONITOR+'managed_ap',fixture('monitor_wifi_managed_ap'))[0]
    ap['radio'].append({'radio_id':5,'mode':'unknown','radio_type':'unknown','noise_floor':0})
    assert len(r.ap_overview(ap)['radios'])==len([x for x in ap['radio'] if r.real_radio(x)])
    assert all(x.get('noise_floor')!=0 for x in r.ap_overview(ap)['radios'])


def test_link_rates_are_separate_and_traffic_retry_discard_retained():
    client=r.parse(r.MONITOR+'client',fixture('monitor_wifi_client'))[0]
    assert client['link_rx_mbps']==client['link_tx_mbps']==573.5
    assert 'data_rate_bps' not in client
    assert client['bandwidth_rx']==0 and client['tx_retry_percentage']==client['tx_discard_percentage']==0


def test_rogue_relevance_overlap_band_signal_and_dedup(monkeypatch):
    from netops_helper.wifi_relevance import relevant
    context=[{'ap_id':'name-2','band':'5ghz','channel':44,'channel_width_mhz':40}]
    row=r.parse(r.MONITOR+'rogue_ap',fixture('monitor_wifi_rogue_ap'))[0]
    assert relevant(row,context)  # neighbor primary 48 overlaps client's 44/40 MHz
    assert not relevant(row,[{**context[0],'band':'24ghz'}])
    assert not relevant(row,[{**context[0],'channel':124}])
    def get(a,path):
        doc=fixture('monitor_wifi_'+path.rsplit('/',1)[-1])
        if path.endswith('managed_ap'):
            doc['results'][0].update(serial='name-2',wtp_id='name-2')
            doc['results'][0]['radio'][1].update(oper_chan=44,channel_bonding='40MHz')
        if path.endswith('client'): doc['results'][0]['wtp_id']='name-2'
        if path.endswith('rogue_ap'): doc['results'].append(copy.deepcopy(doc['results'][0]))
        return doc
    monkeypatch.setattr(r,'get',get)
    result=engine.wifi_rogue(auth(),mac='00:00:5e:00:53:81')
    assert len(result['rogue'])==1 and result['rogue'][0]['deduplicated_bssid']
    assert result['counts']['rogue']['total']==3 and result['counts']['rogue']['unique_bssid']==1
    assert result['filters']['min_signal']==-75
    original_get=get
    def weak_at_selected_ap(a,path):
        doc=original_get(a,path)
        if path.endswith('rogue_ap'):
            for row in doc['results']:
                for observer in row.get('detected_by_wtp',[]):
                    if observer.get('serial')=='name-2': observer['signal_strength']=-90
        return doc
    monkeypatch.setattr(r,'get',weak_at_selected_ap)
    assert not engine.wifi_rogue(auth(),mac='00:00:5e:00:53:81')['rogue']
    monkeypatch.setattr(r,'get',get)
    full=engine.wifi_rogue(auth(),full=True)
    assert len(full['rogue'])==2 and 'observations' in full['rogue'][0]


def test_history_error_recovery_and_reason_status_classification():
    doc=fixture('wireless_log')
    record=next(row for row in doc['results'] if row.get('stamac')==CLIENT)
    record.update(logdesc='Wireless client authentication',reason='invalid credential',status='failed')
    event=wifi_parse.event_record(record,1)
    assert event['class']=='client_error'
    record.update(reason='accepted',status='pass',logdesc='Wireless client authenticated')
    assert wifi_parse.event_record(record,1)['class']=='client_connect'
    record.update(logdesc='DHCP server sent DHCP ACK')
    assert wifi_parse.event_record(record,1)['class']=='client_dhcp'
    error=event
    def events(mac):
        return {'ok':True,'events':{'records':[error],'returned':1,'found':1},
                'sources':[{'endpoint':r.WIRELESS_LOG,'content_sha256':'d'*64,'captured_at':NOW.isoformat()}]}
    result=triage(event_read=events)
    finding=next(f for f in result['findings'] if f['id']=='F-WIFI-CLIENT-ERROR')
    assert finding['severity']=='notice' and finding['historical']
    assert 'historical error, client connected at last observed association' in finding['text']
    live=live_answer();live['records'][0]['association_time']='2026-11-01T00:00:00+00:00'
    result=triage(live=live,event_read=events)
    assert any(f['severity']=='fault' for f in result['findings'])


@pytest.mark.parametrize('tool,args',[('wifi_clients',{'name':'TabletExample'}),('wifi_triage',{'name':'TabletExample'}),('wifi_rogue',{'ap':'Example AP','full':True})])
def test_proxy_new_selectors(tool,args):
    assert Proxy._validate_tool_arguments(tool,{'target':'example',**args})
    with pytest.raises(ToolArgumentsError): Proxy._validate_tool_arguments('wifi_triage',{'target':'example','name':'x','mac':CLIENT})


def test_untrusted_identity_and_radio_types_stay_unknown():
    doc=fixture('monitor_wifi_client')
    doc['results'][0].update(host=['bad'],os={'bad':1},manufacturer=True)
    row=r.parse(r.MONITOR+'client',doc)[0]
    assert row['hostname']==row['os']==row['vendor']=='unknown'
    doc=fixture('monitor_wifi_managed_ap')
    doc['results'][0]['radio'][0].update(channel_utilization_percent='wrong',noise_floor=0,tx_retries_percent=True)
    radio=r.parse(r.MONITOR+'managed_ap',doc)[0]['radio'][0]
    assert radio['noise_floor'] is radio['channel_utilization_percent'] is radio['tx_retries_percent'] is None


def test_proxy_does_not_require_ssh_events_for_live_triage(tmp_path):
    from test_proxy_contracts import _load_proxy, _configure, _section, _inventory, _device, _write, _request
    module=_load_proxy();inventory,_,_,_=_configure(module,tmp_path)
    section=_section();section['enabled_queries']=['system_status']
    _write(inventory,_inventory(_device(section)))
    proxy=module.Proxy();proxy._emit=lambda *a: None
    assert proxy.request(_request(1,'wifi_triage',{'target':'device-a','mac':CLIENT})) is not None


@pytest.mark.parametrize('missing', ['wifi_rf_analysis', 'wifi_neighbors', 'both'])
def test_operating_radio_counters_decide_rf_without_background_scan(missing):
    refused = ('wifi_rf_analysis', 'wifi_neighbors') if missing == 'both' else (missing,)
    live = live_answer()
    client = live['records'][0]
    client['channel'] = client['ap_detail']['radio'][1]['oper_chan'] = 124
    result = triage(live=live, refused=refused)
    assert result['rf_verdict'] == 'no_rf_fault_found'
    assert result['chain']['observation']['noise_dbm'] == -95
    if missing != 'wifi_neighbors':
        assert result['chain']['rf']['source'] == r.MONITOR + 'managed_ap'
        assert result['chain']['rf']['channel'] == 124
        assert result['chain']['rf']['radio'] == 2
        assert any(m.get('required_for_rf_verdict') is False for m in result['missing'])
    live['records'][0]['ap_detail']['radio'][1]['channel_utilization_percent'] = 80
    assert triage(live=live, refused=refused)['rf_verdict'] == 'rf_concern_found'


@pytest.mark.parametrize('field', ['noise_floor', 'interfering_aps', 'channel_utilization_percent', 'tx_retries_percent'])
def test_decisive_missing_radio_counter_stays_incomplete(field):
    live = live_answer()
    live['records'][0]['ap_detail']['radio'][1][field] = None
    assert triage(live=live, refused=('wifi_rf_analysis',))['rf_verdict'] == 'incomplete'


def test_changed_station_channel_requires_a_fresh_snapshot():
    live = live_answer()
    live['records'][0]['channel'] = 124
    result = triage(live=live)
    assert result['rf_verdict'] == 'incomplete'
    assert any(m['step'] == 'client_radio' for m in result['missing'])


def test_targeted_history_reaches_client_older_than_global_window():
    path = r.wireless_log_path(CLIENT)
    doc = fixture('wireless_log')
    doc['results'] = [row for row in doc['results'] if row.get('stamac') == CLIENT]
    doc.update(total_lines=len(doc['results']), ready=True, percent_logs_processed=100)
    requested=[]
    def events(mac):
        requested.append(mac)
        return {'ok': True, 'events': r.parse(path, doc),
                'sources': [{'endpoint': path, 'content_sha256': 'a'*64, 'captured_at': NOW.isoformat()}]}
    result=triage(event_read=events)
    assert requested == [CLIENT]
    window = result['chain']['events']['window']
    assert window['scope'] == 'client_records' and window['filter_mac'] == CLIENT
    assert window['complete'] is True
    assert window['device_found'] == window['device_returned'] == window['client_records'] == len(doc['results'])
    assert 'complete retained history' in window['text']
    doc['total_lines'] = 518
    assert triage(event_read=events)['chain']['events']['window']['complete'] is False
    assert 'bounded or incomplete window' in triage(event_read=events)['chain']['events']['window']['text']


def test_product_wifi_messages_are_english():
    from pathlib import Path
    for path in Path(t.__file__).parent.glob('*.py'):
        assert not any(c in path.read_text() for c in 'ěščřžýáíéůúďťň'), path.name


@pytest.mark.parametrize('code', ['authorization_failed', 'response_too_large'])
def test_hostname_identity_failures_reach_triage_missing_in_both_views(code):
    live = live_answer()
    live['records'][0]['hostname'] = 'unknown'
    live['identity_missing'] = {'step': 'device_identity', 'reason': 'rest_unavailable', 'error_code': code,
                                'failed_step': r.DEVICES, 'http_status': 403 if code == 'authorization_failed' else 200}
    result = triage(live=live, name='TabletExample')
    for view in (result, t.overview(result)):
        assert live['identity_missing'] in view['missing']
        assert any(m['step'] == 'client_rssi' and m['reason'] == 'dependency_missing' for m in view['missing'])
        assert view['identity_trust'] == 'client_supplied'
    assert triage(name='TabletExample')['identity_trust'] == 'client_supplied'


@pytest.mark.parametrize('value', ['a'+chr(0x85)+'b', 'a'+chr(0x202e)+'b', 'a'+chr(0x2066)+'b'])
def test_unicode_controls_are_not_valid_identity_or_selectors(value):
    assert r._identity_text(value) == 'unknown'
    with pytest.raises(ValueError, match='name must be bounded printable text'):
        r.checked_filters(name=value)
    with pytest.raises(ToolArgumentsError) as exc:
        Proxy._validate_tool_arguments('wifi_triage', {'target': 'example', 'name': value})
    assert exc.value.data['field'] == 'name'


def test_selector_error_names_all_three_choices_and_name_is_client_supplied(monkeypatch):
    with pytest.raises(ToolArgumentsError) as exc:
        Proxy._validate_tool_arguments('wifi_triage', {'target': 'example'})
    assert exc.value.data['field'] == 'mac/ip/name'
    def get(a, path):
        return fixture('device_query' if path == r.DEVICES else 'monitor_wifi_'+path.rsplit('/',1)[-1])
    monkeypatch.setattr(r, 'get', get)
    assert engine.wifi_clients(auth(), name='TabletExample')['identity_trust'] == 'client_supplied'


def test_engine_identity_failure_preserves_fixed_failure_fields(monkeypatch):
    def get(a, path):
        if path == r.DEVICES:
            raise r.RestError('authorization_failed', 'fixed', http_status=403)
        return fixture('monitor_wifi_'+path.rsplit('/',1)[-1])
    monkeypatch.setattr(r, 'get', get)
    missing = engine.wifi_clients(auth(), name='TabletExample')['identity_missing']
    assert missing == {'step': 'device_identity', 'reason': 'rest_unavailable', 'error_code': 'authorization_failed',
                       'http_status': 403, 'failed_step': r.DEVICES}


@pytest.mark.parametrize('rest_ok,enrolled,expected', [(True, True, None), (True, False, None),
                                                       (False, True, 'ssh_read'), (False, False, 'target_scope')])
def test_history_next_steps_obey_rest_availability_and_ssh_enrollment(rest_ok, enrolled, expected):
    def history(mac):
        return ({'ok': True, 'events': {'records': [], 'scope': 'client_records'},
                 'sources': [{'endpoint': r.WIRELESS_LOG, 'content_sha256': 'a'*64}]} if rest_ok else
                {'ok': False, 'error_code': 'authorization_failed'})
    result = triage(event_read=history, enabled_queries=('wifi_events',) if enrolled else ())
    recommendations = [step for step in result['next_steps']
                       if step['arguments'].get('query') == 'wifi_events' or step['tool'] == 'target_scope']
    assert [step['tool'] for step in recommendations] == ([] if expected is None else [expected])
    if expected == 'ssh_read':
        assert 'global records' in recommendations[0]['why']


def test_full_and_summary_do_not_duplicate_ap_or_hashes():
    result = triage()
    brief = t.overview(result)
    assert 'ap_detail' not in result['chain']['live_client']
    assert 'recent' not in result['chain']['events']
    assert 'content_sha256' not in json.dumps(brief)
    assert 'content_sha256' in json.dumps(result)
    assert all('message' not in event for event in brief['chain']['events']['timeline'])


def test_client_public_response_uses_one_ap_label_and_one_phy_unit(monkeypatch):
    def get(a, path):
        return fixture('device_query' if path == r.DEVICES else 'monitor_wifi_'+path.rsplit('/',1)[-1])
    monkeypatch.setattr(r, 'get', get)
    row = engine.wifi_clients(auth())['records'][0]
    assert row['ap'] and 'ap_name' not in row
    assert 'rx_rate_bps' not in row and 'tx_rate_bps' not in row
    assert row['link_rx_mbps'] is not None
    assert not ('ap_id' in row and 'ap_serial' in row)


@pytest.mark.parametrize('changes,expected', [({}, True), ({'detected_by_wtp': []}, False),
    ({'detected_by_wtp': [{'serial': 'other-ap', 'signal_strength': -40}]}, False),
    ({'band': '11AX6G'}, False), ({'channel': 124}, False),
    ({'channel': 120, 'bw': '80'}, True)])
def test_triage_neighbor_finding_requires_scoped_spectral_relevance(changes, expected):
    # Transform real REST fixture INPUT, then exercise the actual parser.
    document = copy.deepcopy(fixture('monitor_wifi_rogue_ap'))
    document['results'] = [document['results'][0]]
    raw = document['results'][0]
    raw.update(channel=116, band='11ACVHT40', bw='40', signal_strength=-40)
    raw['detected_by_wtp'][0].update(serial=AP2, name='Example AP', signal_strength=-40)
    raw['detected_by_wtp'][1]['signal_strength'] = -10  # unrelated AP is not the selected observer
    raw.update(changes)
    observations = {'ok': True, 'rogue': r.parse(r.MONITOR+'rogue_ap', document),
                    'interfering': r.parse(r.MONITOR+'interfering_ap', fixture('monitor_wifi_interfering_ap')),
                    'sources': [{'endpoint': r.MONITOR+'rogue_ap', 'content_sha256': 'd'*64}]}
    result = triage(neighbor_read=lambda: observations)
    assert any(f['id'] == 'F-WIFI-STRONG-COCHANNEL-NEIGHBOR' for f in result['findings']) is expected
    assert result['rf_verdict'] == ('rf_concern_found' if expected else 'no_rf_fault_found')
    if expected:
        assert result['chain']['neighbors']['strongest_relevant_dbm'] == -40


@pytest.mark.parametrize('code,status', [('rate_limited', None), ('authorization_failed', 403)])
@pytest.mark.parametrize('endpoint', ['client', 'managed_ap'])
def test_rogue_preserves_context_read_failures(monkeypatch, code, status, endpoint):
    def get(a, path):
        if path == r.MONITOR + endpoint:
            raise r.RestError(code, 'fixed', http_status=status)
        return fixture('monitor_wifi_'+path.rsplit('/',1)[-1])
    monkeypatch.setattr(r, 'get', get)
    result = engine.wifi_rogue(auth())
    context = result['relevance']
    assert result['ok'] and context['status'] == 'context_read_failed'
    assert context['error_code'] == code and context['failed_step'] == r.MONITOR+endpoint
    if status:
        assert context['http_status'] == status


def test_unknown_own_width_retains_exact_primary_and_reports_incomplete_overlap(monkeypatch):
    from netops_helper.wifi_relevance import relevant, context_status
    contexts = [{'ap_id': 'name-2', 'band': '5ghz', 'channel': 48, 'channel_width_mhz': None}]
    row = r.parse(r.MONITOR+'rogue_ap', fixture('monitor_wifi_rogue_ap'))[0]
    assert relevant(row, contexts)
    assert context_status(contexts) == 'width_unknown'
    assert not relevant(row, [{**contexts[0], 'channel': 44}])
    assert not relevant({**row, 'band': '6ghz'}, contexts)
    def get(a, path):
        doc = fixture('monitor_wifi_'+path.rsplit('/',1)[-1])
        if path.endswith('/managed_ap'):
            doc['results'][0].update(serial='name-2', wtp_id='name-2')
            doc['results'][0]['radio'][1].update(oper_chan=48, channel_bonding='240MHz')
        if path.endswith('/client'):
            doc['results'][0]['wtp_id'] = 'name-2'
        return doc
    monkeypatch.setattr(r, 'get', get)
    result = engine.wifi_rogue(auth(), mac='00:00:5e:00:53:81')
    assert result['relevance']['status'] == result['relevance']['overlap'] == 'width_unknown'
    assert result['rogue']
