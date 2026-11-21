"""FG-18: captured 80F / 8.0.2 REST output through fake HTTP transport and real parser/engine."""
import dataclasses
import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from conftest import _target
from netops_helper import engine, fortigate_tables, wifi_rest as r
from netops_helper.auth import EgressPolicy

FIXTURE = Path(__file__).parent / 'fixtures/real/fortinet/fortigate80f_8.0.2_build0251/g12_20261117/policy.json'
TOKEN = 'synthetic-g12-token-123456789'
CERT = b'synthetic-g12-certificate'


def document():
    return json.loads(FIXTURE.read_text())


def auth(**changes):
    fields = dict(fortios_rest_token=TOKEN, fortios_rest_certificate_sha256=hashlib.sha256(CERT).hexdigest(),
                  egress=EgressPolicy(addresses=('127.0.0.1',), tcp_ports=(443,)))
    fields.update(changes)
    return dataclasses.replace(_target('fortinet', 'system_status'), **fields)


@pytest.fixture
def http(monkeypatch):
    response = {'status': 200, 'body': document()}
    calls = []
    peer = MagicMock()
    peer.getpeercert.return_value = CERT
    context = MagicMock()
    context.wrap_socket.return_value = peer
    monkeypatch.setattr(r.ssl, 'SSLContext', lambda *a: context)
    monkeypatch.setattr(r.socket, 'create_connection', lambda *a, **k: MagicMock())
    monkeypatch.setattr(engine, 'record', lambda *a, **k: None)
    r._rates.clear()

    def connection(*args, **kwargs):
        conn = MagicMock()

        def request(method, path, headers):
            calls.append((method, path))
            answer = conn.getresponse.return_value
            answer.status = response['status']
            answer.chunked = False
            answer.getheader.side_effect = lambda key, default=None: default
            answer.read1.side_effect = [json.dumps(response['body']).encode(), b'']
        conn.request.side_effect = request
        return conn
    monkeypatch.setattr(r.http.client, 'HTTPSConnection', connection)
    return response, calls


def test_live_fixture_through_get_lists_hits_bytes_last_use_and_unused_candidate(http):
    _, calls = http
    result = engine.firewall_policy_hits(auth())
    assert result['ok'] and result['state'] == 'ok'
    assert calls == [('GET', r.POLICY_HITS)]
    assert result['counts'] == {'policies': 5, 'unused_candidates': 1, 'incomplete': 0}
    rows = {row['policy_id']: row for row in result['records']}
    assert (rows[10]['hit_count'], rows[10]['bytes'], rows[10]['last_used']) == (4561, 885682515, 1794910850)
    assert rows[10]['last_used_utc'] == '2026-11-17T10:20:50+00:00'
    assert (rows[1]['hit_count'], rows[1]['bytes'], rows[1]['last_used'], rows[1]['unused_candidate']) == (0, 0, None, True)
    assert rows[0]['unused_candidate'] is False
    assert result['firmware_support']['status'] == 'tested'
    assert result['warnings'] == []
    assert result['sources'][0]['endpoint'] == r.POLICY_HITS
    assert TOKEN not in json.dumps(result) and 'uuid' not in json.dumps(result['records'])


def test_unused_only_and_record_pagination_keep_whole_capture_counts(http):
    result = engine.firewall_policy_hits(auth(), unused_only=True)
    assert [row['policy_id'] for row in result['records']] == [1]
    assert result['counts']['policies'] == 5 and result['page']['total'] == 1
    assert 'counter lifetime' in result['counter_note']
    response, _ = http
    pages = []
    for offset in (0, 2, 4):
        response['body']['results'].reverse()  # The monitor can change order between requests.
        pages.append(engine.firewall_policy_hits(auth(), limit=2, offset=offset))
    assert [row['policy_id'] for p in pages for row in p['records']] == [0, 1, 3, 6, 10]
    assert pages[-1]['next'] is None and pages[0]['next']['offset'] == 2


@pytest.mark.parametrize('field,value', [('hit_count', None), ('bytes', None), ('packets', True),
                                         ('last_used', None), ('hit_count', -1), ('last_used', 10**100)])
def test_missing_or_invalid_counter_never_becomes_zero_or_an_unused_policy(http, field, value):
    response, _ = http
    response['body']['results'][0][field] = value
    result = engine.firewall_policy_hits(auth())
    row = next(row for row in result['records'] if row['policy_id'] == 10)
    assert result['ok'] and result['state'] == row['state'] == 'incomplete'
    assert field in row['missing_fields'] and row['unused_candidate'] is None
    assert result['counts']['incomplete'] == 1


def test_zero_hit_count_with_traffic_is_inconsistent(http):
    response, _ = http
    response['body']['results'][0]['hit_count'] = 0
    result = engine.firewall_policy_hits(auth(), unused_only=True)
    assert result['state'] == 'incomplete' and result['counts']['unused_candidates'] == 1
    assert [row['policy_id'] for row in result['records']] == [1]


@pytest.mark.parametrize('status,error', [(401, 'authentication_failed'), (403, 'authorization_failed')])
def test_http_refusal_is_not_an_empty_policy_list(http, status, error):
    response, calls = http
    response.update(status=status, body={})
    result = engine.firewall_policy_hits(auth())
    assert not result['ok'] and result['error_code'] == error
    assert result['http_status'] == status and result['records'] == []
    assert 'counts' not in result and calls == [('GET', r.POLICY_HITS)]


@pytest.mark.parametrize('field,value', [('results', {}), ('vdom', 'other'), ('status', 'error'),
                                        ('http_method', 'POST'), ('path', 'other'), ('name', 'other')])
def test_foreign_or_incomplete_envelope_is_refused(http, field, value):
    response, _ = http
    response['body'][field] = value
    result = engine.firewall_policy_hits(auth())
    assert not result['ok'] and result['records'] == []
    assert result['error_code'] == 'unparsed_envelope'


def test_duplicate_policy_identity_is_refused(http):
    response, _ = http
    response['body']['results'][1]['policyid'] = 10
    result = engine.firewall_policy_hits(auth())
    assert not result['ok'] and result['error_code'] == 'invalid_response'


def test_empty_monitor_is_explicitly_empty_not_a_configuration_inventory(http):
    response, _ = http
    response['body']['results'] = []
    result = engine.firewall_policy_hits(auth())
    assert result['ok'] and result['state'] == 'empty' and result['counts']['policies'] == 0


def test_unknown_version_warns_and_still_runs(http):
    response, _ = http
    response['body']['version'] = 'v9.1.0'
    result = engine.firewall_policy_hits(auth())
    assert result['ok'] and result['firmware_support']['status'] == 'untested'
    assert result['warnings'][0]['code'] == 'firmware_untested'


def test_implicit_policy_is_never_candidate_even_when_zero():
    rows = fortigate_tables.policy_hits([{'policyid': 0, 'hit_count': 0, 'bytes': 0, 'packets': 0}])
    assert rows[0]['unused_candidate'] is False


def test_missing_token_sends_no_request(http):
    _, calls = http
    result = engine.firewall_policy_hits(auth(fortios_rest_token=None))
    assert not result['ok'] and result['error_code'] == 'unsupported' and calls == []


@pytest.mark.parametrize('kwargs', [{'unused_only': 'yes'}, {'offset': -1}, {'limit': True}, {'max_bytes': 999}])
def test_arguments_are_checked_before_any_read(http, kwargs):
    _, calls = http
    with pytest.raises(ValueError):
        engine.firewall_policy_hits(auth(), **kwargs)
    assert calls == []


def test_path_is_fixed_get_and_has_no_server_side_filter():
    assert r.POLICY_HITS in r.PATHS
    assert not r._allowed_path(r.POLICY_HITS + '?policyid=1')
    with pytest.raises(ValueError, match='policy_scope'):
        r.get(auth(), r.POLICY_HITS, method='POST')


def test_proxy_validates_bool_and_charges_exactly_one_get():
    from netops_helper import proxy
    assert 'firewall_policy_hits' in proxy.WIFI_REST_TOOLS
    assert proxy.Proxy._rate_cost('firewall_policy_hits', TOKEN) == 1


@pytest.mark.parametrize('value', ['yes', 1, None])
def test_proxy_refuses_nonboolean_unused_filter(value):
    from netops_helper import proxy
    with pytest.raises(proxy.ToolArgumentsError):
        proxy.Proxy._validate_tool_arguments('firewall_policy_hits', {'target': 'lab', 'unused_only': value})


def test_proxy_accepts_only_the_documented_policy_arguments():
    from netops_helper import proxy
    args = {'target': 'lab', 'unused_only': True, 'limit': 10, 'offset': 0, 'max_bytes': 16000}
    assert proxy.Proxy._validate_tool_arguments('firewall_policy_hits', args) == args
    with pytest.raises(proxy.ToolArgumentsError):
        proxy.Proxy._validate_tool_arguments('firewall_policy_hits', {'target': 'lab', 'url': '/arbitrary'})
