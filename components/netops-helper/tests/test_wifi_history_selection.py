"""Scenario regressions using anonymized measured 80F event envelopes."""
from copy import deepcopy

from netops_helper import triage_wifi as t, wifi_parse, wifi_rest as r
from test_wifi_rest import fixture
from test_triage_wifi import CLIENT, AP2


def event(index, description, **changes):
    row = deepcopy(next(row for row in fixture('wireless_log')['results'] if row.get('stamac') == CLIENT))
    row.update(time='20:%02d:00' % index, logdesc=description, ap=AP2, reason='N/A')
    row.update(changes)
    return wifi_parse.event_record(row, index)


def test_significant_history_keeps_failures_disconnect_ap_change_and_only_last_dhcp():
    records = [event(1, 'Wireless client authentication failed', reason='invalid credential'),
               event(2, 'Wireless client associated', radioband='11AXA'),
               event(3, 'Wireless client disassociated', reason='idle timeout'),
               event(4, 'Wireless client associated', ap='FAPEXAMPLE0000001', radioband='11NG'),
               event(5, 'WPA client key handshake completed', level='warning')]
    records += [event(i, 'DHCP server sent DHCP ACK') for i in range(6, 16)]
    summary = t.significant_history(list(reversed(records)), {'complete': True})
    assert [e['index'] for e in summary['timeline']] == [1, 3, 4, 5, 15]
    assert summary['authentication_failures'] == [1]
    assert summary['last_disconnect']['reason'] == 'idle timeout'
    change = summary['timeline'][2]['ap_change']
    assert (change['from_ap'], change['to_ap'], change['from_band'], change['to_band']) == (
        AP2, 'FAPEXAMPLE0000001', '5ghz', '24ghz')
    assert change['time'] == records[3]['time']
    assert summary['last_connection']['level'] == 'warning'
    assert records[4]['class'] == 'client_connect' and not records[4]['authentication_failure']


def test_no_auth_failure_is_explicit_and_coverage_is_not_overclaimed():
    handshake = event(1, 'WPA client key handshake completed', level='warning')
    summary = t.significant_history([handshake], {'complete': True})
    assert summary['authentication_note'] == 'no authentication failure in retained history of this MAC'
    assert not summary['authentication_failures']
    assert 'bounded or incomplete' in t.significant_history([], {'complete': False})['authentication_note']
    assert 'unavailable' in t.significant_history([], None)['authentication_note']


def test_nonassociated_client_returns_history_and_cause_in_both_views():
    from test_wifi_diagnostic import triage
    records = [event(3, 'Wireless client disassociated', reason='idle timeout'),
               event(2, 'Wireless client authentication failed', reason='invalid credential')]
    def history(mac):
        return {'ok': True, 'events': {'records': records, 'returned': 2, 'found': 2, 'complete': True},
                'sources': [{'endpoint': r.WIRELESS_LOG, 'content_sha256': 'a'*64, 'captured_at': records[0]['time']}]}
    result = triage(live={'ok': True, 'records': [], 'sources': []}, event_read=history)
    for view in (result, t.overview(result)):
        assert view['ok'] and view['verdict'] == 'client_not_associated'
        assert view['client']['association_status'] == 'not_associated'
        assert view['chain']['association']['cause'] == 'idle timeout'
        summary = view['chain']['events'].get('summary', view['chain']['events'])
        assert summary['last_ap'] == AP2
        assert summary['last_disconnect']['reason'] == 'idle timeout'
        assert summary['authentication_failures'] == [2]


def test_nonassociated_client_with_no_history_has_unknown_cause():
    from test_wifi_diagnostic import triage
    result = triage(live={'ok': True, 'records': [], 'sources': []}, refused=('wifi_events',))
    assert result['ok'] and result['verdict'] == 'client_not_associated'
    assert result['chain']['association']['cause'] == 'unknown'
    result = triage(live={'ok': False, 'error_code': 'timeout'})
    assert result['client']['association_status'] == 'unknown'
    assert result['verdict'] != 'client_not_associated'


def test_measured_primary_channels_supply_band_but_ambiguous_channels_stay_unknown():
    for channel, expected in ((6, '24ghz'), (116, '5ghz'), (124, '5ghz'), (1, None), (149, None), (0, None)):
        record = event(1, 'Wireless client associated', channel=str(channel))
        assert record['band'] == expected
        assert record['band_source'] == ('unambiguous_primary_channel' if expected else None)
    records = [event(1, 'Wireless client associated', channel='124'),
               event(2, 'Wireless client authenticated', channel='0'),
               event(3, 'Wireless client associated', ap='FAPEXAMPLE0000001', channel='6')]
    change = t.significant_history(list(reversed(records)), {'complete': True})['timeline'][0]['ap_change']
    assert (change['from_band'], change['to_band']) == ('5ghz', '24ghz')


def test_reserved_disconnect_reason_is_retained_but_cause_is_unknown():
    from test_wifi_diagnostic import triage
    result = triage(live={'ok': True, 'records': [], 'sources': []})
    assert result['verdict'] == 'client_not_associated'
    assert result['chain']['events']['summary']['last_disconnect']['reason'] == 'Reserved 0'
    assert result['chain']['association']['cause'] == 'unknown'


def test_dhcp_failures_survive_classification_and_history_selection():
    from test_wifi_diagnostic import triage
    for description in ("Wireless station DHCP process failed with no server response", "Wireless station DHCP NAK"):
        failure = event(2, description)
        assert failure['class'] == 'client_error'
        assert failure['timeline_type'] == 'error'
        assert failure['index'] in [e['index'] for e in t.significant_history([failure, event(1, 'DHCP server sent DHCP ACK')], {'complete': True})['timeline']]
        answer = {'ok': True, 'events': {'records': [failure]},
                  'sources': [{'endpoint': r.WIRELESS_LOG, 'content_sha256': 'a'*64}]}
        assert any(f['id'] == 'F-WIFI-CLIENT-ERROR' for f in triage(event_read=lambda mac: answer)['findings'])


def test_auth_failure_reasons_are_independent_of_disconnect_class():
    for reason in ('4-way handshake timeout', 'Previous authentication no longer valid', '15'):
        for description in ('Wireless client deauthenticated', 'Wireless client disassociated'):
            row = event(1, description, reason=reason)
            assert row['class'] == 'client_disconnect' and row['timeline_type'] == 'disconnect'
            assert row['authentication_failure']
            assert t.significant_history([row], {'complete': True})['authentication_failures']
    assert not event(1, 'Wireless client deauthenticated', reason='idle timeout')['authentication_failure']
    assert not event(1, 'WPA client key handshake completed', level='warning')['authentication_failure']


def test_timeline_type_uses_the_complete_classification():
    row = event(1, 'Wireless client associated', reason='invalid credential', status='failed')
    assert row['class'] == 'client_error' and row['timeline_type'] == 'error'
    # Both import orders work without transport/parser imports of each other.
    import subprocess, sys
    for order in ('wifi_parse, wifi_rest', 'wifi_rest, wifi_parse'):
        subprocess.run([sys.executable, '-B', '-c', 'import sys; sys.path[:] = ' + repr(sys.path) + '; from netops_helper import ' + order], check=True)


def test_flapping_history_is_bounded_with_omitted_and_repeat_counts():
    repeated = [event(i % 50 + 1, 'Wireless client disassociated', reason='idle timeout') for i in range(200)]
    for index, row in enumerate(repeated):
        row['index'] = index + 1
    summary = t.significant_history(list(reversed(repeated)), {'complete': True})
    assert len(summary['timeline']) == 1
    assert summary['timeline'][0]['repetitions'] == 200
    assert summary['timeline_aggregated'] == 199 and summary['timeline_omitted'] == 0
    flapping = [{**row, 'reason': 'idle timeout' if i % 2 else 'invalid credential',
                 'authentication_failure': i % 2 == 0} for i, row in enumerate(repeated)]
    summary = t.significant_history(list(reversed(flapping)), {'complete': True})
    assert len(summary['timeline']) == t.HISTORY_LIMIT
    assert summary['timeline_total'] == 200 and summary['timeline_omitted'] == 180
    assert summary['authentication_failure_count'] == 100
    assert len(summary['authentication_failures']) == 20 and summary['authentication_failures_omitted'] == 80
