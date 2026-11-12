"""Reproductions for the tool-result findings in the 1.0.7 review."""
from dataclasses import replace
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from conftest import _target
from netops_helper import engine, endpoint_worker, locate, switch_pages, tables
from netops_helper.audit import AuditPreflightError, AuditPostOperationError
from netops_helper.proxy import Proxy, ToolArgumentsError
from netops.results import tool_failed


def tool_result(payload):
    result = {'content': [{'type': 'text', 'text': json.dumps(payload)}], 'structuredContent': payload}
    result['isError'] = tool_failed('helper', 'switch_read', result)
    return result


@pytest.fixture(autouse=True)
def no_audit(monkeypatch):
    monkeypatch.setattr(engine, 'record', lambda *a, **k: None)


def test_40000_mac_rows_fit_ipc_and_have_a_continuation(monkeypatch):
    text = '          Mac Address Table\n-------------------------------------------\nVlan    Mac Address       Type        Ports\n----    -----------       --------    -----\n' + ''.join(
        ' 101    0000.5e00.%04x    DYNAMIC     Gi1/0/5\n' % n for n in range(40000))
    parsed = tables.parse('cisco_ios', 'mac_entry', 'mac_table', text)
    assert len(parsed['records']) == 40000
    monkeypatch.setattr(engine, 'normalized_query', lambda *a, **k: parsed.copy())
    auth = _target('cisco_ios', 'mac_table')
    first = engine.switch_read(auth, 'mac_entry', limit=500)
    assert first['ok'] and first['has_more'] and 0 < len(first['records']) <= 500
    assert first['coverage']['returned'] == len(first['records'])
    assert len(json.dumps(first).encode()) <= 16000
    second = engine.switch_read(auth, 'mac_entry', **first['next'])
    assert first['records'][-1]['mac'] != second['records'][0]['mac']
    # The actual MCP response contains both text and structured content.
    assert len(json.dumps(tool_result(first)).encode()) < 4 * 1024 * 1024


def test_unparsed_lines_and_multibyte_json_are_bounded_and_all_recoverable():
    original = {'ok': False, 'records': [], 'unparsed': [{'line': n, 'text': 'ž' * 20} for n in range(250)]}
    args = {'max_bytes': 1000}
    collected = []
    while args:
        result = switch_pages.page(original, ('records', 'unparsed'), **args)
        assert len(json.dumps(result).encode()) <= 1000
        collected.extend(result['unparsed'])
        args = result['next']
    assert collected == original['unparsed']


def test_indivisible_record_fails_with_a_structured_error():
    result = switch_pages.page({'ok': True, 'records': [{'description': 'x' * 100000}]})
    assert not result['ok'] and result['error_code'] == 'result_too_large' and result['next'] is None


@pytest.mark.parametrize('tool,required', [('switch_read', {'table': 'mac_entry'}), ('wifi_clients', {}),
                                           ('wifi_aps_live', {}), ('wifi_rogue', {})])
@pytest.mark.parametrize('field,value', [('limit', 0), ('limit', 501), ('limit', True), ('offset', -1),
                                         ('offset', 8000001), ('max_bytes', 999), ('max_bytes', 48001)])
def test_record_page_bounds_are_validated_before_dispatch(tool, required, field, value):
    with pytest.raises(ToolArgumentsError) as exc:
        Proxy._validate_tool_arguments(tool, {'target': 'sw', **required, field: value})
    assert exc.value.code == -32602 and exc.value.data['field'] == field


@pytest.mark.parametrize('error', [AuditPreflightError, AuditPostOperationError])
def test_locate_audit_failure_stops_after_one_attempt(error):
    from test_locate_endpoint import auth
    reads = []
    def read(*args):
        reads.append(args)
        raise error('synthetic audit failure')
    with pytest.raises(error):
        locate.run([auth(), auth('sw2')], '192.0.2.1', read)
    assert len(reads) == 1


def test_worker_exit_three_is_a_tool_error(monkeypatch):
    monkeypatch.setattr(endpoint_worker, 'command', lambda: [sys.executable, '-I', '-c',
                        'import sys;sys.stdin.readline();sys.exit(3)'])
    result = endpoint_worker.call(['sw'], '192.0.2.1', '{}', seconds=3)
    assert result['ok'] is False and result['error_code'] == 'worker_failed'
    assert result['missing'] == [{'vantage': None, 'table': 'worker', 'reason': 'worker_failed'}]
    assert tool_result(result)['isError'] is True


@pytest.mark.parametrize('error,code', [(AuditPreflightError, 'audit_preflight_failed'),
                                       (AuditPostOperationError, 'audit_post_operation_failed')])
def test_worker_audit_failure_is_a_structured_final_result(monkeypatch, capsys, error, code):
    import io
    monkeypatch.setattr(endpoint_worker.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(
        json.dumps({'targets': ['sw'], 'endpoint': '192.0.2.1', 'auth_context': '{}'}).encode())))
    monkeypatch.setattr(endpoint_worker, 'decode', lambda *a: [])
    def fail(*args, **kwargs):
        raise error('synthetic audit failure')
    monkeypatch.setattr(engine, '_locate_endpoint_run', fail)
    endpoint_worker.main()
    output = json.loads(capsys.readouterr().out)
    assert output['final'] is True and output['result']['ok'] is False
    assert output['result']['error_code'] == code and output['result']['failed_step'] == 'audit'


def test_fortios_route_without_ip_requires_routing_table_enrollment_through_proxy(tmp_path, monkeypatch):
    import test_proxy_contracts as c
    from netops_helper import proxy as p
    inventory, _, _, _ = c._configure(p, tmp_path)
    section = c._section()
    section['ssh_platform'] = 'fortios'
    section['enabled_queries'] = ['route_lookup', 'system_status']
    c._write(inventory, c._inventory(c._device(section, 'fortios')))
    proxy = p.Proxy()
    emitted = []
    monkeypatch.setattr(proxy, '_emit', emitted.append)
    assert proxy.request(c._request(1, 'switch_read', {'target': 'device-a', 'table': 'route'})) is None
    assert emitted[-1]['error']['code'] == -32009
    assert emitted[-1]['error']['data']['field'] == 'enabled_queries'


def test_unconfigured_bgp_is_a_valid_mcp_response(monkeypatch):
    result = tables.parse('cisco_ios', 'bgp_peer', 'bgp_summary', 'BGP is not running\n')
    assert result['status'] == 'not_applicable'
    monkeypatch.setattr(engine, 'normalized_query', lambda *a, **k: result)
    answer = engine.switch_read(_target('cisco_ios', 'bgp_summary'), 'bgp_peer')
    assert answer['ok'] is True and answer['status'] == 'not_applicable'
    assert tool_result(answer)['isError'] is False


def test_log_and_locate_budget_documentation_tracks_the_implementation():
    root = Path(__file__).resolve().parents[3]
    tools = (root / 'components/netops-helper/docs/tools.md').read_text()
    assert 'min(40, helper.rate_limit.requests, 7 + exos + vlan_reads + managed_reads * managed_switches)' in tools
    assert 'target_read_limit' in tools
    for profile in engine._OLDEST_FIRST_LOG_PROFILES:
        assert profile in tools
    log, meta = engine._limit_log_lines('Syslog logging: enabled\n' + '\n'.join(str(n) for n in range(300)), oldest_first=True)
    assert meta['returned_lines'] == 200 and len(log.splitlines()) == 201 and log.splitlines()[-1] == '299'
    assert 'Syslog logging:' not in log
    assert '200' in tools and 'line_limit' in tools and 'log_line_limit' in tools


def test_worker_launch_failure_is_a_structured_error(monkeypatch):
    def fail(*a, **k):
        raise OSError('synthetic launch failure')
    monkeypatch.setattr(endpoint_worker.subprocess, 'Popen', fail)
    result = endpoint_worker.call(['sw'], '192.0.2.1', '{}')
    assert result['ok'] is False and result['error_code'] == 'worker_failed'


@pytest.mark.parametrize('status', ['ok', 'truncated'])
@pytest.mark.parametrize('offset,limit,more', [(0, 1, True), (0, 3, False), (2, 3, False),
                                              (3, 1, False), (4, 1, False)])
def test_capture_status_and_page_continuation_are_independent(status, offset, limit, more):
    result = switch_pages.page({'ok': status == 'ok', 'status': status,
                                'records': [1, 2, 3]}, offset=offset, limit=limit)
    assert result['status'] == status
    assert result['ok'] == (status == 'ok')
    assert 'truncated' not in result
    assert result['has_more'] is more
    assert (result['next'] is not None) is more
    if more:
        assert result['next']['offset'] == offset + result['page']['returned']


def test_oversized_result_has_no_usable_continuation():
    for original in ({'records': ['x' * 50000]}, {'metadata': 'x' * 50000}):
        result = switch_pages.page(original)
        assert result['error_code'] == 'result_too_large'
        assert result['has_more'] is False and result['next'] is None
        assert 'truncated' not in result


@pytest.mark.parametrize('tool', ['switch_read', 'wifi_clients', 'wifi_aps_live', 'wifi_rogue'])
def test_documented_record_tool_signatures_include_the_public_parameters(tool):
    import inspect
    import re
    root = Path(__file__).resolve().parents[3]
    documents = [root / 'components/netops-helper/docs/tools.md']
    if tool.startswith('wifi_'):
        documents.append(root / 'docs/fortios-wifi-rest.md')
    expected = list(inspect.signature(getattr(engine, tool)).parameters)
    expected[0] = 'target'
    for document in documents:
        signatures = re.findall(r'`' + tool + r'\(([^)]*)\)`', document.read_text())
        full_signatures = [signature for signature in signatures if ',' in signature]
        assert full_signatures, document
        for signature in full_signatures:
            names = [argument.strip().split('=')[0] for argument in signature.split(',')]
            assert names == expected, (document, tool, signature)

