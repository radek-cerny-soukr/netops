"""Public ssh_read through the proxy and MCP with source-backed Cisco responses."""

import asyncio
import json
from pathlib import Path

import pytest

from netops_helper import engine, proxy, server
from test_proxy_contracts import _configure, _device, _inventory, _request, _section, _write


FIXTURES = Path(__file__).parent / 'fixtures/real/cisco_ios/router-diagnostics'
XE_FIXTURES = FIXTURES.parent.parent / 'cisco_ios_xe/xe-diagnostics'
PROFILES = {'iosv': 'cisco_ios', 'iolxe': 'cisco_xe'}
PORTS = {'iosv': 'GigabitEthernet0/2', 'iolxe': 'Ethernet0/2'}
COMMANDS = {
    'qos_policy': 'show policy-map interface {interface}',
    'qos_queues': 'show mls qos interface {interface} statistics',
    'nat_translations': 'show ip nat translations',
    'nat_statistics': 'show ip nat statistics',
    'ikev1_sa': 'show crypto isakmp sa',
    'ikev2_sa': 'show crypto ikev2 sa',
    'ipsec_sa': 'show crypto ipsec sa',
}


def capture(source, query):
    return (FIXTURES / source / f'{query}.out').read_text()


def xe_capture(source, query):
    return (XE_FIXTURES / source / f'{query}.out').read_text()


@pytest.fixture
def invoke(tmp_path, monkeypatch):
    # The proxy's test configuration helper writes files and points the real gateway at them.
    for name in ('INVENTORY', 'VAULT', 'EGRESS_POLICY', 'RUNNER'):
        monkeypatch.setattr(proxy, name, getattr(proxy, name))
    inventory, _, _, _ = _configure(proxy, tmp_path)
    monkeypatch.setattr(engine, 'host_key_line', lambda *args: 'pinned-fixture-host-key')
    monkeypatch.setattr(engine, 'record', lambda *args, **kwargs: None)

    def read(node, query, body, *, interface=None, supplied=None, version=None, enabled=True, rc=0, stderr='', **page):
        interface = interface or PORTS[node]
        profile = PROFILES[node]
        template = COMMANDS[query]
        if profile == 'cisco_xe' and query == 'qos_queues':
            template = 'show platform hardware fed switch active qos queue stats interface {interface}'
        section = dict(_section(), ssh_platform=profile, device_types=['router', 'switch'],
                       read_inventory={'interfaces': [interface]}, enabled_queries=[query] if enabled else [])
        section['egress']['tcp_ports'].append(22)
        _write(inventory, _inventory(_device(section, profile)))
        calls = []

        def fake_exec(_auth, _address, _known_hosts, _credential, command, selected_platform):
            assert selected_platform == profile
            calls.append(command)
            outcome, stdout, diagnostics = ((0, version or capture(node, 'version'), '') if command == 'show version'
                                            else (rc, body, stderr))
            return engine.core_ssh.Result(rc=outcome, stdout=stdout.encode(), stderr=diagnostics.encode(),
                                          said='', started_at='', finished_at='')

        monkeypatch.setattr(engine, '_exec_command', fake_exec)
        arguments = {'interface': supplied or interface} if '{interface}' in template else {}
        errors = []
        gateway = proxy.Proxy()
        gateway._emit = errors.append
        forwarded = gateway.request(_request(57, 'ssh_read', {
            'target': 'device-a', 'platform': profile, 'query': query, 'parameters': arguments, **page,
        }))
        if forwarded is None:
            assert not calls
            return errors[-1]
        request = json.loads(forwarded)
        answer = asyncio.run(server.mcp.call_tool('ssh_read', request['params']['arguments']))
        assert calls == ['show version', template.format(interface=interface)]
        wire = gateway.response(json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'result': {
            'structuredContent': answer.structured_content, 'content': [], 'isError': False,
        }}).encode())
        return json.loads(wire)['result']['structuredContent']

    return read


@pytest.mark.parametrize(('query', 'interface', 'count'), [
    ('qos_policy', 'GigabitEthernet1/0/0.10', 5),
    ('qos_queues', 'GigabitEthernet1/0/1', 5),
    ('nat_translations', None, 3),
    ('nat_statistics', None, 2),
    ('ikev1_sa', None, 2),
    ('ikev2_sa', None, 1),
    ('ipsec_sa', None, 1),
])
def test_vendor_records(invoke, query, interface, count):
    result = invoke('iosv', query, capture('vendor', query), interface=interface)
    assert result['ok'] and result['status'] == 'ok' and result['complete'], result
    data = result['normalized']
    assert data['coverage']['complete'] and len(data['records']) == count
    row = data['records'][0]
    if query == 'qos_policy':
        assert (row['direction'], row['policy_path'], row['queue_depth'], row['total_drops']) == (
            'output', ['vlan10_policy'], 0, 0)
        assert data['records'][1]['policy_path'] == ['vlan10_policy', 'child_policy']
    elif query == 'qos_queues':
        assert row['dropped'] == [0, 0, 0]
        assert data['records'][1]['enqueued'] == [0, 341, 441525]
    elif query == 'nat_translations':
        assert row['protocol'] == 'udp'
        assert row['inside_global']['port'] == 1220 and row['outside_local']['port'] == 53
        assert row['inside_global']['address'] != row['inside_local']['address']
    elif query == 'nat_statistics':
        assert (row['total_translations'], row['misses']) == (2, 5)
        pool = data['records'][1]
        assert (pool['total_addresses'], pool['allocated_addresses'], pool['allocation_misses']) == (14, 2, 0)
    elif query == 'ikev1_sa':
        assert (row['state'], row['sa_status'], row['slot']) == ('QM_IDLE', 'STDBY', 0)
    elif query == 'ikev2_sa':
        assert (row['sa_status'], row['local_port'], row['active_seconds']) == ('READY', 500, 361)
        assert 'Auth: PSK' in result['untrusted_device_output']
    else:
        assert row['counters']['encaps'] == row['counters']['decaps'] == 0
        assert [sa['direction'] for sa in row['associations']] == ['inbound', 'outbound']
        assert row['associations'][0]['transforms'] == ['esp-3des', 'esp-sha-hmac']


@pytest.mark.parametrize('node', PROFILES)
@pytest.mark.parametrize('query', [name for name in COMMANDS if name != 'qos_queues'])
def test_unconfigured_lab_reply(invoke, node, query):
    body = xe_capture('lab', query) if (node, query) == ('iolxe', 'ikev1_sa') else capture(node, query)
    result = invoke(node, query, body)
    assert result['ok'] and result['status'] == 'empty' and result['complete'], result
    assert result['firmware_support']['status'] == 'tested'
    assert result['normalized']['coverage']['complete'] and result['normalized']['records'] == []


def test_measured_unsupported_mls_is_a_refusal(invoke):
    result = invoke('iosv', 'qos_queues', capture('iosv', 'qos_queues'))
    assert result['ok'] is False and result['status'] in {'permission_denied', 'unsupported'}
    assert not result['complete']


def test_xe_fed_hardware_queues(invoke):
    result = invoke('iolxe', 'qos_queues', xe_capture('vendor', 'qos_queues'), interface='GigabitEthernet1/0/1')
    assert result['ok'] and result['status'] == 'ok' and result['complete']
    assert result['firmware_support']['status'] == 'untested'
    data = result['normalized']
    assert not data['unparsed'] and data['coverage']['complete']
    assert len(data['records']) == 8
    queue = data['records'][1]
    assert (queue['interface'], queue['queue'], queue['data_port']) == ('GigabitEthernet1/0/1', 1, 0)
    assert queue['enqueued_bytes'] == [0, 0, 488393930284]
    assert queue['dropped_bytes'] == [0, 0, 192308101]
    assert (queue['buffer_count'], queue['policer_drop_bytes']) == (0, 0)


def test_xe_fed_avb_missing_drop_rows_keeps_available_counters(invoke):
    result = invoke('iolxe', 'qos_queues', xe_capture('vendor', 'qos_queues_avb'),
                    interface='TenGigabitEthernet1/0/15')
    assert result['status'] == 'incomplete' and not result['complete']
    data = result['normalized']
    assert not data['unparsed'] and len(data['records']) == 8
    assert data['records'][2]['enqueued_bytes'] == [0, 12616270, 13164040]
    assert data['records'][2]['dropped_bytes'] == [0, 0, 0]
    assert 'dropped_bytes' not in data['records'][7]


def test_xe_fed_pager_is_truncated(invoke):
    body = xe_capture('vendor', 'qos_queues').split('DATA Port:0 Drop Counters', 1)[0] + '--More--'
    result = invoke('iolxe', 'qos_queues', body, interface='GigabitEthernet1/0/1')
    assert result['status'] == 'truncated' and not result['complete']
    assert not result['normalized']['coverage']['complete']


def test_iolxe_fed_refusal_stays_distinct_from_empty_output(invoke):
    result = invoke('iolxe', 'qos_queues', xe_capture('lab', 'qos_queues'))
    assert not result['ok'] and result['status'] in {'permission_denied', 'unsupported'}
    assert not result['complete'] and not result['normalized']['coverage']['complete']


def test_xe_fed_rejects_subinterface_before_transport(invoke):
    result = invoke('iolxe', 'qos_queues', '', interface='GigabitEthernet1/0/1', supplied='GigabitEthernet1/0/1.10')
    assert 'error' in result
    assert result['error']['data']['category'] == 'policy_scope'


def test_xe_ikev1_table_with_slot_and_no_status(invoke):
    result = invoke('iolxe', 'ikev1_sa', xe_capture('vendor', 'ikev1_sa'))
    assert result['ok'] and result['status'] == 'ok' and result['complete']
    assert len(result['normalized']['records']) == 3
    row = result['normalized']['records'][0]
    assert (row['state'], row['connection_id'], row['slot']) == ('QM_IDLE', 2, 0)
    assert 'sa_status' not in row


def test_xe_ipsec_replay_window_with_aes_gcm(invoke):
    result = invoke('iolxe', 'ipsec_sa', xe_capture('vendor', 'ipsec_sa'))
    assert result['ok'] and result['status'] == 'ok' and result['complete']
    data = result['normalized']
    assert not data['unparsed']
    row, = data['records']
    assert (row['counters']['encaps'], row['counters']['decaps']) == (2674, 2677)
    assert [(sa['direction'], sa['sa_status'], sa['transforms']) for sa in row['associations']] == [
        ('inbound', 'ACTIVE(ACTIVE)', ['esp-gcm', '256']),
        ('outbound', 'ACTIVE(ACTIVE)', ['esp-gcm', '256']),
    ]
    assert all(sa['replay_window_size'] == 512 for sa in row['associations'])


@pytest.mark.parametrize('query', COMMANDS)
def test_device_pager_never_yields_a_complete_result(invoke, query):
    result = invoke('iosv', query, capture('vendor', query).rstrip() + '\n--More--')
    assert result['status'] == 'truncated' and not result['complete']
    assert not result['normalized']['coverage']['complete']


def test_translation_count_mismatch_keeps_available_rows(invoke):
    body = capture('vendor', 'nat_translations') + 'Total number of translations: 4\n'
    result = invoke('iosv', 'nat_translations', body)
    assert result['status'] == 'incomplete' and not result['complete']
    assert len(result['normalized']['records']) == 3


def test_unfamiliar_row_and_unfinished_ikev2_keeps_recognized_data(invoke):
    body = capture('vendor', 'ikev2_sa').rsplit('Life/Active Time:', 1)[0] + 'Unexpected field\n'
    result = invoke('iosv', 'ikev2_sa', body)
    assert result['status'] == 'incomplete' and not result['complete']
    assert result['normalized']['unparsed']
    assert result['normalized']['records'][0]['sa_status'] == 'READY'


def test_enrollment_checked_before_transport(invoke):
    result = invoke('iosv', 'qos_policy', '', supplied='GigabitEthernet9/9')
    assert result['error']['data']['category'] == 'policy_scope'


def test_current_firmware_warning_keeps_operational_result(invoke):
    version = capture('iosv', 'version').replace('15.9(3)M12', '15.9(3)M99')
    result = invoke('iosv', 'nat_statistics', capture('vendor', 'nat_statistics'), version=version)
    assert result['ok'] and result['status'] == 'ok'
    assert result['firmware_support']['status'] == 'untested'
    assert result['warnings'][0]['code'] == 'firmware_untested'


def test_short_and_wrapped_sa_keys_are_removed_before_paging(invoke):
    body = capture('vendor', 'ipsec_sa') + 'Session key: q!\n  4e a3 4f b5\n'
    result = invoke('iosv', 'ipsec_sa', body)
    serialized = json.dumps(result)
    assert 'q!' not in serialized and '4e a3 4f b5' not in serialized
    assert 'remaining key lifetime' in result['untrusted_device_output']
    assert not result['complete'] and result['normalized']['records'][0]['associations']


def test_failed_exec_without_output_is_not_empty(invoke):
    result = invoke('iosv', 'nat_translations', '', rc=1, stderr='Host key verification failed.')
    assert not result['ok'] and result['status'] != 'empty'


def test_xe_reports_exhausted_pool_and_compares_translation_total(invoke):
    result = invoke('iolxe', 'nat_statistics', capture('vendor', 'nat_statistics_xe'))
    assert result['ok'] and result['status'] == 'ok' and result['complete'], result
    summary, pool = result['normalized']['records']
    assert (summary['total_translations'], summary['outbound_drops']) == (6, 3559337007)
    assert summary['translation_limit_misses'] == 0
    assert summary['inside_interfaces'] == ['GigabitEthernet0/0/3']
    assert (pool['allocated_addresses'], pool['total_addresses'], pool['allocation_misses']) == (3, 3, 3559386331)
    body = capture('vendor', 'nat_translations_xe')
    translations = invoke('iolxe', 'nat_translations', body)
    assert translations['status'] == 'ok' and translations['complete']
    assert len(translations['normalized']['records']) == 6
    assert translations['normalized']['records'][0]['outside_local'] is None


@pytest.mark.parametrize(('query', 'interface'), [
    ('qos_policy', 'GigabitEthernet1/0/0.11'),
    ('qos_queues', 'GigabitEthernet1/0/2'),
])
def test_qos_result_for_other_port_is_not_attributed_to_request(invoke, query, interface):
    body = capture('vendor', query)
    if query == 'qos_policy':
        # This vendor example omits the optional interface header; add a different interface header.
        body = 'GigabitEthernet1/0/0.10\n' + body
    result = invoke('iosv', query, body, interface=interface)
    assert result['status'] == 'unparsed' and not result['complete']
    assert not result['normalized']['records']


@pytest.mark.parametrize('node,stderr', [
    ('iosv', capture('iosv', 'login_banner')),
    ('iolxe', 'Connection to 192.0.2.10 closed by remote host.\n'),
])
def test_successful_blank_cli_after_ssh_notice(invoke, node, stderr):
    result = invoke(node, 'qos_policy', capture(node, 'qos_policy'), stderr=stderr)
    assert result['ok'] and result['status'] == 'empty' and result['complete'], result


def test_unrecognized_stderr_is_not_a_successful_empty_read(invoke):
    result = invoke('iolxe', 'nat_translations', capture('iolxe', 'nat_translations'),
                    stderr='Connection to 192.0.2.11 closed by remote host.\n')
    assert not result['ok'] and result['status'] == 'unparsed'
    assert result['firmware_support']['device_version'] == '17.18.2'


def test_retains_device_pager_after_masking_key(invoke):
    body = capture('vendor', 'ipsec_sa') + 'Session key: q! --More--'
    result = invoke('iosv', 'ipsec_sa', body)
    assert result['status'] == 'truncated' and not result['complete']
    assert 'q!' not in json.dumps(result)


@pytest.mark.parametrize('node', ['iosv', 'iolxe'])
@pytest.mark.parametrize('query', ['ipsec_sa', 'ikev2_sa'])
@pytest.mark.parametrize('ending', [
    ' --More--', ' --More--\n', ' diagnostic annotation',
    ';note', ',note', '.note', ')note', 'note',
])
def test_wrapped_sa_keys_do_not_change_output_or_digest(invoke, node, query, ending):
    base = (xe_capture('vendor', query) if node == 'iolxe' and query == 'ipsec_sa'
            else capture('vendor', 'ikev2_sa_hsrp' if node == 'iolxe' else query))
    keys = [('a1 b2', 'c3 d4 e5 f6'), ('07 18', '29 3a 4b 5c')]
    results = [invoke(node, query, base + f'Session key: {first}\n  {last}{ending}')
               for first, last in keys]
    for result, (first, last) in zip(results, keys):
        output = result['untrusted_device_output']
        assert first not in output and last not in output
        assert output.startswith(base.rstrip())
        assert result['status'] == ('truncated' if '--More--' in ending else 'incomplete')
        assert not result['complete']
        assert output.rstrip('\n').endswith(f'Session key: <REDACTED>\n{ending.strip()}')
    for field in ('untrusted_device_output', 'content_sha256'):
        assert results[0][field] == results[1][field]
    assert results[0]['normalized']['sources'][0]['content_sha256'] == results[0]['content_sha256']


@pytest.mark.parametrize('node', ['iosv', 'iolxe'])
@pytest.mark.parametrize('prefix', ['  :', '-', '', '--More--\n  ', '--More--\n:'])
def test_cisco_sa_masks_wrapped_keys_after_separator_column_one_or_pager(invoke, node, prefix):
    base = xe_capture('vendor', 'ipsec_sa') if node == 'iolxe' else capture('vendor', 'ipsec_sa')
    values = ('aa11:bb22-cc33', 'dd44-ee55:ff66')
    results = [invoke(node, 'ipsec_sa', base + f'Session key: a1 b2\n{prefix}{value}\n')
               for value in values]
    for result, value in zip(results, values):
        output = result['untrusted_device_output']
        assert value not in output
        assert output.startswith(base.rstrip())
        assert 'Session key: <REDACTED>' in output
        if '--More--' in prefix:
            assert result['status'] == 'truncated'
    for field in ('untrusted_device_output', 'content_sha256'):
        assert results[0][field] == results[1][field]


def test_ikev2_accepts_comma_delimited_key_size(invoke):
    result = invoke('iolxe', 'ikev2_sa', capture('vendor', 'ikev2_sa_hsrp'))
    assert result['ok'] and result['status'] == 'ok' and result['complete']
    data = result['normalized']
    assert not data['unparsed']
    row, = data['records']
    assert (row['sa_status'], row['lifetime_seconds'], row['active_seconds']) == ('READY', 86400, 444)
    assert row['algorithms'] == ('Encr: AES-CBC, keysize: 256, PRF: SHA256, Hash: SHA256, '
                                 'DH Grp:14, Auth sign: PSK, Auth verify: PSK')


@pytest.mark.parametrize(('node', 'fixture', 'interface', 'class_name', 'expected'), [
    ('iosv', 'qos_policy_two_rate', 'Serial3/0', 'police', {
        'conformed': {'packets': 59538, 'bytes': 14646348, 'actions': ['transmit']},
        'exceeded': {'packets': 59538, 'bytes': 14646348, 'actions': ['set-prec-transmit 2']},
        'violated': {'packets': 29731, 'bytes': 7313826, 'actions': ['drop']},
    }),
    ('iolxe', 'qos_policy_single_rate', 'GigabitEthernet1/0/0', 'class-default', {
        'conformed': {'packets': 337, 'bytes': 167152, 'actions': ['transmit']},
        'exceeded': {'packets': 0, 'bytes': 0, 'actions': ['drop']},
    }),
])
def test_qos_policer_counts_and_actions(invoke, node, fixture, interface, class_name, expected):
    result = invoke(node, 'qos_policy', capture('vendor', fixture), interface=interface)
    assert result['ok'] and result['status'] == 'ok' and result['complete']
    data = result['normalized']
    assert not data['unparsed']
    rows = data['records']
    assert rows[0]['class_name'] == class_name and rows[0]['policer'] == expected
    assert all('policer' not in row for row in rows[1:])


def test_qos_two_rate_vendor_offered_rates(invoke):
    result = invoke('iosv', 'qos_policy', capture('vendor', 'qos_policy_two_rate'), interface='Serial3/0')
    data = result['normalized']
    classes = {row['class_name']: row for row in data['records']}
    assert classes['police']['drop_rate_bps'] == 249000
    assert classes['class-default']['offered_rate_bps'] == 0
    assert classes['class-default']['drop_rate_bps'] == 0
    assert result['status'] == 'ok' and result['complete'] and data['coverage']['complete']
    assert not data['unparsed']


@pytest.mark.parametrize('problem', ['missing', 'unknown'])
def test_qos_policer_preserves_partial_results(invoke, problem):
    body = capture('vendor', 'qos_policy_two_rate')
    row = '    violated 29731 packets, 7313826 bytes; action: drop\n'
    assert row in body
    body = body.replace(row, '' if problem == 'missing' else '    violated unknown counters\n')
    result = invoke('iosv', 'qos_policy', body, interface='Serial3/0')
    assert result['status'] == 'incomplete' and not result['complete']
    data = result['normalized']
    assert set(data['records'][0]['policer']) == {'conformed', 'exceeded'}
    assert bool(data['unparsed']) == (problem == 'unknown')


def test_ios_single_rate_policer_needs_the_reported_violated_counter(invoke):
    body = capture('vendor', 'qos_policy_two_rate')
    body = body.replace('conform-burst 10000, pir 1000000, peak-burst 100000', 'bc 10000 bytes, be 100000 bytes')
    body = body.replace('    violated 29731 packets, 7313826 bytes; action: drop\n', '')
    result = invoke('iosv', 'qos_policy', body, interface='Serial3/0')
    assert result['status'] == 'incomplete' and not result['complete']
    assert set(result['normalized']['records'][0]['policer']) == {'conformed', 'exceeded'}


def test_classic_ios_reports_a_pager_appended_to_qos_data_with_line_ending(invoke):
    rows = capture('vendor', 'qos_policy').splitlines()
    final = next(index for index, row in enumerate(rows) if 'shape (average) cir' in row)
    body = '\n'.join(rows[:final] + [rows[final] + ' --More--']) + '\n'
    result = invoke('iosv', 'qos_policy', body, interface='GigabitEthernet0/2')
    assert result['status'] == 'truncated' and not result['complete']


@pytest.mark.parametrize('query', ['ikev1_sa', 'ipsec_sa'])
def test_blank_reply_does_not_confirm_absence_for_explicit_sa_formats(invoke, query):
    result = invoke('iosv', query, '')
    assert not result['ok'] and result['error_code'] == 'empty'
    assert not result['normalized']['coverage']['complete']
