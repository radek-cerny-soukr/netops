"""G92 through the Helper device read path with redacted Nexus and Cisco captures."""
from dataclasses import replace
from pathlib import Path
import re

import pytest

from conftest import _target
from netops_helper import engine, port_errors
from netops_helper.proxy import Proxy
from netops_helper.query_catalog import READ_QUERIES

PROFILE = 'cisco_nxos'
ROOT = Path(__file__).parent / 'fixtures'
CAPTURES = ROOT / 'real/cisco_nxos/g92_nexus9300v_9.3.12'
INTERFACES = ('Ethernet1/2', 'Ethernet1/4', 'Ethernet1/5', 'Port-channel128', 'mgmt0', 'Ethernet1/33')


def fixture(name):
    return (CAPTURES / f'{name}.out').read_text()


@pytest.fixture
def fake_nx(monkeypatch):
    auth = replace(_target(PROFILE, 'version'), alias='nexus-a',
                   enabled_queries=tuple(READ_QUERIES[PROFILE]), read_inventory={'interfaces': INTERFACES})
    version = (ROOT / 'identity/cisco_nxos.txt').read_text()
    responses, calls = {}, []

    def read(target, profile, command):
        assert profile == PROFILE
        if command == 'show version':
            return responses.get(command, (0, version))
        calls.append((target.alias, command))
        return responses.get((target.alias, command), responses.get(command))

    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    monkeypatch.setattr(engine, 'read_from_device', read)
    return auth, responses, calls


def test_port_counter_samples_and_old_baseline(fake_nx):
    auth, responses, calls = fake_nx
    command = 'show interface Ethernet1/2'
    responses[command] = 0, fixture('2255-interface')
    first = engine.switch_read(auth, 'interface_errors', interface='Ethernet1/2')
    assert first['status'] == 'ok', first
    first_row, = first['records']
    assert first_row['link_speed_bps'] == 1_000_000_000
    assert first['counter_baseline']
    key = port_errors._key(auth.alias, PROFILE, 'Ethernet1/2')
    sample_time = '2025-01-01T10:00:00+00:00'
    time_token = port_errors.encode_baseline(key, sample_time, [first_row])
    second_text = fixture('2255-interface-t2')
    responses[command] = 0, second_text
    second = engine.switch_read(auth, 'interface_errors', interface='Ethernet1/2', baseline=time_token)
    assert second['status'] == 'ok', second
    row, = second['records']
    traffic = row['interval_traffic']
    assert traffic['interval_seconds'] > 0
    for direction in ('rx', 'tx'):
        field = direction + '_octets'
        delta = row[field] - first_row[field]
        if delta >= 0:
            assert traffic[direction]['octets_delta'] == delta
            assert traffic[direction]['bits_per_second'] == pytest.approx(delta * 8 / traffic['interval_seconds'], abs=.001)
        else:
            assert traffic[direction]['octets_delta'] is None
            assert field in row['counter_reset_or_wrap']

    legacy_row = {field: first_row[field] for field in ('port', *port_errors.COUNTERS)}
    legacy = port_errors.encode_baseline(key, sample_time, [legacy_row])
    result = engine.switch_read(auth, 'interface_errors', interface='Ethernet1/2', baseline=legacy)
    assert result['records'][0]['interval_traffic']['rx']['bits_per_second'] is None
    assert calls == [(auth.alias, command)] * 3


def test_port_incomplete_sample_has_no_baseline(fake_nx):
    auth, responses, _ = fake_nx
    command = 'show interface Ethernet1/2'
    output = fixture('2255-interface')
    responses[command] = 0, output.split('  TX', 1)[0]
    read = engine.switch_read(auth, 'interface_errors', interface='Ethernet1/2')
    assert read['status'] == 'unparsed' and read['counter_baseline'] is None


def test_stp_topology_ports_and_mst_mode(fake_nx):
    auth, responses, _ = fake_nx
    responses['show spanning-tree detail'] = 0, fixture('2255-stp-detail')
    responses['show spanning-tree interface Ethernet1/2 detail'] = 0, fixture('2255-stp-port')
    responses['show spanning-tree interface Port-channel128 detail'] = 0, fixture('2261-stp-po')
    responses['show spanning-tree mst'] = 244, fixture('2255-stp-mst')
    topology = engine.switch_read(auth, 'stp_topology')
    assert topology['status'] == 'ok', topology
    assert {row['instance'] for row in topology['records']} == {'VLAN0010', 'VLAN0020'}
    assert all(row['topology_changes'] > 0 for row in topology['records'])
    for interface in ('Ethernet1/2', 'Port-channel128'):
        ports = engine.switch_read(auth, 'stp_port_counters', interface=interface)
        assert ports['status'] == 'ok' and ports['coverage']['complete'], ports
        assert ports['records'][0]['state'] == 'forwarding'
        assert ports['records'][0]['bpdu_sent'] > 0
    mst = engine.ssh_read(auth, PROFILE, 'stp_mst', None, 0, 16000)
    assert mst['status'] == 'not_applicable'
    assert 'Switch is not in mst mode' in mst['untrusted_device_output']


def test_lacp_member_and_load_distribution(fake_nx):
    auth, responses, _ = fake_nx
    cmd = 'show lacp interface Ethernet1/4'
    responses[cmd] = 0, fixture('2261-lacp-port-compact')
    responses['show lacp interface Ethernet1/5'] = 0, fixture('2261-lacp-unbundled')
    responses['show port-channel database'] = 0, fixture('2261-lag-database')
    responses['show port-channel load-balance'] = 0, fixture('2261-lag-load')
    bundled, = engine.switch_read(auth, 'lag_member', interface='Ethernet1/4')['records']
    assert bundled['bundled'] is True and bundled['group'] == 128
    assert bundled['pdus_received'] > 0 and bundled['partner_state'] == 61
    unbundled, = engine.switch_read(auth, 'lag_member', interface='Ethernet1/5')['records']
    assert unbundled['bundled'] is False and unbundled['reason'] == 'no channel group'
    for query, word in (('port_channel_database', 'First operational port'),
                        ('port_channel_load_balance', 'src-dst ip-l4port')):
        raw = engine.ssh_read(auth, PROFILE, query, None, 0, 16000)
        assert raw['ok'] and word in raw['untrusted_device_output']
    responses[cmd] = 0, fixture('2261-lacp-port-compact').split('Partner Oper State')[0]
    assert engine.switch_read(auth, 'lag_member', interface='Ethernet1/4')['status'] == 'unparsed'


def test_vpc_compare_and_incomplete_peer(fake_nx):
    auth, responses, calls = fake_nx
    peer = replace(auth, alias='nexus-b', port=auth.port + 1)
    for target, prefix in ((auth, '2261'), (peer, '2262')):
        responses[target.alias, 'show vpc brief'] = 0, fixture(prefix + '-vpc-brief')
        responses[target.alias, 'show vpc consistency-parameters vpc 128'] = 0, fixture(prefix + '-vpc-member')
    responses['show vpc consistency-parameters interface Port-channel128'] = 0, fixture('2261-vpc-interface-compact')
    direct = engine.ssh_read(auth, PROFILE, 'vpc_interface_consistency', {'interface': 'Port-channel128'}, 0, 16000)
    assert direct['vpc_consistency']['parameters']['MTU']['local'] == '1500'
    result = engine.vpc_compare([auth, peer], '128')
    assert result['state'] == 'matched', result
    assert [p['member']['id'] for p in result['peers']] == [128, 128]
    assert all(p['consistency']['parameters']['lag-id']['type'] == '1' for p in result['peers'])

    responses[peer.alias, 'show vpc consistency-parameters vpc 128'] = 0, fixture('2261-vpc-absent')
    assert engine.vpc_compare([auth, peer], '128')['state'] == 'incomplete'
    calls.clear()
    with pytest.raises(ValueError):
        engine.vpc_compare([auth, replace(peer, enabled_queries=('vpc_status',))], '128')
    assert calls == []


@pytest.mark.parametrize(('port', 'query', 'source', 'rc', 'expected'), [
    ('mgmt0', 'lldp', '2255-lldp-mgmt-compact', 0, 'ok'),
    ('Ethernet1/2', 'lldp', '2255-lldp-port', 244, 'empty'),
    ('Ethernet1/2', 'cdp', '2261-cdp-port', 0, 'ok'),
    ('Ethernet1/2', 'cdp', '2255-cdp-port', 0, 'empty'),
])
def test_bounded_neighbors(fake_nx, port, query, source, rc, expected):
    auth, responses, calls = fake_nx
    command = f'show {query} neighbors interface {port} detail'
    responses[command] = rc, fixture(source)
    result = engine.switch_read(auth, query + '_neighbor', interface=port)
    assert result['status'] == expected, result
    if expected == 'ok':
        assert [row['local_port'] for row in result['records']] == [port]
    else:
        assert result['records'] == []
    assert calls == [(auth.alias, command)]


def test_dom_vendor_data_and_partial_capture(fake_nx):
    auth, responses, _ = fake_nx
    query = 'interface_transceiver'
    params = {'interface': 'Ethernet1/5'}
    command = 'show interface Ethernet1/5 transceiver details'
    responses[command] = 0, fixture('dom-sfp')
    responses['show interface Ethernet1/33 transceiver details'] = 0, fixture('dom-pon')
    optics = engine.ssh_read(auth, PROFILE, query, params, 0, 16000)['optics']
    assert optics['state'] == 'measured' and not optics['alarms']
    assert optics['readings']['rx_power']['value'] == -2.4
    assert optics['readings']['rx_power']['thresholds']['low_alarm'] == -13.97
    assert engine.switch_read(auth, 'optics_port', interface='Ethernet1/5')['records'][0]['temperature_c'] == 36.52
    pon = engine.ssh_read(auth, PROFILE, query, {'interface': 'Ethernet1/33'}, 0, 16000)['optics']
    assert pon['readings']['rx_power']['value'] is None and pon['readings']['rx_power']['status'] is None
    responses[command] = 0, fixture('dom-sfp').replace('36.52 C', '76.52 C ++', 1)
    flagged = engine.ssh_read(auth, PROFILE, query, params, 0, 16000)['optics']
    assert flagged['alarms'] == ['temperature: high_alarm']
    assert flagged['readings']['temperature']['device_flag'] == 'high_alarm'
    responses[command] = 0, fixture('dom-sfp').split('Rx Power')[0]
    assert engine.ssh_read(auth, PROFILE, query, params, 0, 16000)['optics']['state'] == 'partial'


def test_proxy_accepts_nexus_switch_read_selectors():
    for table, interface in (('lag_member', 'Ethernet1/4'), ('stp_port_counters', 'Port-channel128'),
                             ('optics_port', 'Ethernet1/5'), ('lldp_neighbor', 'mgmt0')):
        args = {'target': 'nexus-a', 'table': table, 'interface': interface}
        assert Proxy._validate_tool_arguments('switch_read', args) == args


def test_unmeasured_firmware_warns_and_still_reads(fake_nx):
    auth, responses, _ = fake_nx
    version = (ROOT / 'identity/cisco_nxos.txt').read_text()
    responses['show version'] = 0, version.replace('9.3(12)', '9.3(13)')
    responses['show spanning-tree detail'] = 0, fixture('2255-stp-detail')
    result = engine.switch_read(auth, 'stp_topology')
    assert result['ok'] and result['records']
    assert result['firmware_support']['status'] == 'untested'
    assert any(isinstance(w, dict) and w['code'] == 'firmware_untested' for w in result['warnings'])


# Review 498-rv (task 498-r2): regressions through the engine with the fake device transport.
MTU_ROW = r'(?m)^(MTU +1 +)1500( +)1500$'
MEMBER_ROW = r'(?m)^(128 +Po128 +up +)success'


def _vpc_pair(fake_nx, member=(None, None), brief=(None, None)):
    auth, responses, _ = fake_nx
    peer = replace(auth, alias='nexus-b', port=auth.port + 1)
    for index, (target, prefix) in enumerate(((auth, '2261'), (peer, '2262'))):
        edit_member, edit_brief = member[index] or (lambda text: text), brief[index] or (lambda text: text)
        responses[target.alias, 'show vpc brief'] = 0, edit_brief(fixture(prefix + '-vpc-brief'))
        responses[target.alias, 'show vpc consistency-parameters vpc 128'] = 0, edit_member(fixture(prefix + '-vpc-member'))
    return engine.vpc_compare([auth, peer], '128')


def _sub(pattern, replacement):
    def edit(text):
        changed, count = re.subn(pattern, replacement, text)
        assert count == 1, pattern
        return changed
    return edit


def test_vpc_compare_mirrored_type1_mismatch_is_different(fake_nx):
    failed = _sub(MEMBER_ROW, r'\1failed ')
    result = _vpc_pair(fake_nx, member=(_sub(MTU_ROW, r'\g<1>1500\g<2>9000'), _sub(MTU_ROW, r'\g<1>9000\g<2>1500')),
                       brief=(failed, failed))
    assert result['peers'][0]['consistency']['parameters']['MTU'] == {'type': '1', 'local': '1500', 'peer': '9000'}
    assert result['peers'][1]['consistency']['parameters']['MTU'] == {'type': '1', 'local': '9000', 'peer': '1500'}
    assert result['state'] == 'different' and result['ok'] is True, result
    assert result['differences'] == ['parameter:MTU', 'member:consistency']


def test_vpc_compare_reported_inconsistency_alone_is_different(fake_nx):
    failed = _sub(MEMBER_ROW, r'\1failed ')
    assert _vpc_pair(fake_nx, brief=(failed, failed))['differences'] == ['member:consistency']
    reason = ('Configuration consistency status  : failed\nConfiguration inconsistency reason: '
              'vPC type-1 configuration incompatible - STP Mode inconsistent')
    globally = _sub(r'(?m)^Configuration consistency status  : success$', reason)
    result = _vpc_pair(fake_nx, brief=(globally, globally))
    assert result['state'] == 'different' and result['differences'] == ['peer:consistency_status'], result
    down = _sub(r'(?m)^(Peer status +: )peer adjacency formed ok$', r'\1peer link is down')
    result = _vpc_pair(fake_nx, brief=(down, down))
    assert result['state'] == 'different' and result['differences'] == ['peer:peer_status'], result
    assert _vpc_pair(fake_nx)['state'] == 'matched'


def test_vpc_compare_rate_cost_counts_identity_checks(fake_nx):
    auth, _, _ = fake_nx
    counted = {}
    inner = engine.read_from_device

    def count(target, profile, command):
        counted[target.alias] = counted.get(target.alias, 0) + 1
        return inner(target, profile, command)

    engine.read_from_device = count
    try:
        assert _vpc_pair(fake_nx)['state'] == 'matched'
    finally:
        engine.read_from_device = inner
    assert set(counted) == {'nexus-a', 'nexus-b'}
    assert Proxy._rate_cost('vpc_compare', None) == max(counted.values()), counted


@pytest.mark.parametrize('age', ['1week(s) 0day(s)', '1week(s)  2day(s)', 'never'])
def test_port_flap_age_in_weeks(fake_nx, age):
    from datetime import datetime, timedelta, timezone
    auth, responses, _ = fake_nx
    command = 'show interface Ethernet1/2'
    text = fixture('2255-interface').replace('Last link flapped 2d11h', f'Last link flapped {age}')
    assert text != fixture('2255-interface')
    responses[command] = 0, text
    row, = engine.switch_read(auth, 'interface_errors', interface='Ethernet1/2')['records']
    assert row['last_flap'] == age
    key = port_errors._key(auth.alias, PROFILE, 'Ethernet1/2')
    for started, expected in (((datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(), False),
                              ('2025-01-01T10:00:00+00:00', age != 'never')):
        token = port_errors.encode_baseline(key, started, [row])
        later, = engine.switch_read(auth, 'interface_errors', interface='Ethernet1/2', baseline=token)['records']
        assert later['interval_traffic']['flap_observed_since_baseline'] is expected, later


def test_nexus_subinterface_error_counters_are_scoped(fake_nx):
    from types import SimpleNamespace
    auth, responses, calls = fake_nx
    interface = 'Ethernet1/48.521'
    command = f'show interface {interface} counters errors'
    auth = replace(auth, read_inventory={'interfaces': INTERFACES + (interface,)})
    # d-nxos returned rc 0 without counter rows for this temporary subinterface.
    responses[command] = 0, ''
    section = SimpleNamespace(catalog_platform=lambda: PROFILE, ssh_platform=PROFILE, device_types=('switch',), egress={},
                              account_role=auth.account_role, enabled_queries=auth.enabled_queries,
                              read_inventory=auth.read_inventory)
    args = {'target': 'nexus-a', 'table': 'interface_errors', 'interface': interface}
    Proxy._validate_tool_arguments('switch_read', args)
    Proxy._authorize_tool('switch_read', args, None, section)
    result = engine.switch_read(auth, 'interface_errors', interface=interface)
    assert result['status'] == 'empty' and not result['coverage']['complete'], result
    assert result['records'] == [] and result['counter_baseline'] is None
    assert calls == [(auth.alias, command)]


@pytest.mark.parametrize('table', ['lag_member', 'optics_port'])
def test_proxy_nexus_port_table_without_interface_names_interface(fake_nx, table):
    from types import SimpleNamespace
    from netops_helper.proxy import ToolArgumentsError
    auth, _, calls = fake_nx
    section = SimpleNamespace(catalog_platform=lambda: PROFILE, device_types=('switch',), egress={},
                              account_role=auth.account_role, enabled_queries=auth.enabled_queries,
                              read_inventory=auth.read_inventory)
    args = {'target': 'nexus-a', 'table': table}
    with pytest.raises(ToolArgumentsError) as caught:  # optics_port: already the platform-neutral schema check
        Proxy._validate_tool_arguments('switch_read', args)
        Proxy._authorize_tool('switch_read', args, None, section)
    assert caught.value.data['field'] == 'interface', caught.value.data
    assert 'route' not in caught.value.data['hint'] and 'interface' in caught.value.data['hint']
    with pytest.raises(ValueError):
        engine.switch_read(auth, table)
    assert calls == []


QSFP_RX = ' Rx Power          N/A           N/A       N/A          N/A            N/A'


def test_dom_multi_lane_qsfp(fake_nx):
    auth, responses, _ = fake_nx
    auth = replace(auth, read_inventory={'interfaces': INTERFACES + ('Ethernet2/2', 'Ethernet1/11')})
    command, params = 'show interface Ethernet2/2 transceiver details', {'interface': 'Ethernet2/2'}
    text = fixture('dom-qsfp-sr4')
    responses[command] = 0, text
    optics = engine.ssh_read(auth, PROFILE, 'interface_transceiver', params, 0, 16000)['optics']
    assert optics['state'] == 'measured', optics
    assert [lane['lane'] for lane in optics['lanes']] == [1, 2, 3, 4]
    assert optics['readings']['temperature']['value'] == 24.65 and optics['readings']['voltage']['value'] == 3.40
    assert all(lane['readings']['rx_power']['availability'] == 'not_applicable' for lane in optics['lanes'])
    assert not optics['alarms']

    lanes = text.split('Lane Number:')
    assert lanes[3].count(QSFP_RX) == 1
    lanes[3] = lanes[3].replace(QSFP_RX, ' Rx Power     -12.40 dBm --    1.00 dBm -10.00 dBm   -1.00 dBm      -7.60 dBm')
    lanes[3] = _sub(r'(?m)^ Tx Power +N/A +N/A +N/A +N/A +N/A$',
                    ' Tx Power      -0.22 dBm       6.99 dBm   -6.90 dBm    3.99 dBm   -2.90 dBm')(lanes[3])
    lanes[3] = _sub(r'(?m)^ Current +N/A +N/A +N/A +N/A +N/A$',
                    ' Current       23.65 mA      100.00 mA     8.00 mA    83.00 mA    10.00 mA')(lanes[3])
    lanes[3] = _sub(r'(?m)^( Temperature +)24\.65', r'\g<1>25.25')(lanes[3])
    responses[command] = 0, 'Lane Number:'.join(lanes)
    flagged = engine.ssh_read(auth, PROFILE, 'interface_transceiver', params, 0, 16000)['optics']
    assert flagged['alarms'] == ['lane 3 rx_power: low_alarm'], flagged
    assert flagged['lanes'][2]['readings']['rx_power']['value'] == -12.4
    assert flagged['lanes'][2]['readings']['rx_power']['device_flag'] == 'low_alarm'
    assert flagged['readings']['rx_power']['value'] is None
    assert flagged['readings']['rx_power']['availability'] == 'per_lane'
    result = engine.switch_read(auth, 'optics_port', interface='Ethernet2/2')
    row, = result['records']
    assert row.get('lanes'), row
    assert [lane['lane'] for lane in row['lanes']] == [1, 2, 3, 4]
    assert row['lanes'][2] == {'lane': 3, 'temperature_c': 25.25, 'voltage': 3.4,
                               'tx_bias_ma': 23.65, 'tx_dbm': -0.22, 'rx_dbm': -12.4}
    assert row['temperature_c'] is None and row['rx_dbm'] is None and row['alerts'] == flagged['alarms']
    assert flagged['state'] == row['state'] == 'measured'
    assert result['status'] == 'ok' and result['coverage']['complete'], result

    responses[command] = 0, text.replace('Lane Number:2 ', 'Lane Number:1 ')
    assert engine.ssh_read(auth, PROFILE, 'interface_transceiver', params, 0, 16000)['optics']['state'] == 'unparsed'

    responses['show interface Ethernet1/11 transceiver details'] = 0, fixture('dom-qsfp-dr')
    single = engine.ssh_read(auth, PROFILE, 'interface_transceiver', {'interface': 'Ethernet1/11'}, 0, 16000)['optics']
    assert single['state'] == 'measured' and single['readings']['rx_power']['value'] == 0.16
    assert single['readings']['tx_bias_current']['value'] == 23.65 and not single['alarms']


@pytest.mark.parametrize('lane_count', [1, 3])
def test_dom_declared_lanes_missing(fake_nx, lane_count):
    auth, responses, _ = fake_nx
    auth = replace(auth, read_inventory={'interfaces': ('Ethernet2/2',)})
    text = fixture('dom-qsfp-sr4')
    assert 'number of lanes 4' in text
    responses['show interface Ethernet2/2 transceiver details'] = 0, text.split(f'Lane Number:{lane_count + 1} ')[0]

    result = engine.switch_read(auth, 'optics_port', interface='Ethernet2/2')
    assert result['status'] == 'incomplete' and not result['coverage']['complete'], result
    row, = result['records']
    assert [lane['lane'] for lane in row['lanes']] == list(range(1, lane_count + 1))
    assert 'lanes' in result['coverage']['missing_fields']
    optics = engine.ssh_read(auth, PROFILE, 'interface_transceiver', {'interface': 'Ethernet2/2'}, 0, 16000)['optics']
    assert row['state'] == optics['state'] == 'incomplete' and 'lanes' in optics['missing_fields'], optics


def test_dom_declared_lanes_without_dom_blocks(fake_nx):
    auth, responses, _ = fake_nx
    auth = replace(auth, read_inventory={'interfaces': ('Ethernet2/2',)})
    command = 'show interface Ethernet2/2 transceiver details'
    responses[command] = 0, fixture('dom-qsfp-sr4').split('Lane Number:', 1)[0]

    result = engine.switch_read(auth, 'optics_port', interface='Ethernet2/2')
    assert result['status'] == 'unparsed' and result['records'] == [], result
    assert not result['coverage']['complete']
    reason = 'NX-OS declares 4 transceiver lanes but reports no DOM lane blocks'
    assert result['unparsed'][0]['text'] == reason
    raw = engine.ssh_read(auth, PROFILE, 'interface_transceiver', {'interface': 'Ethernet2/2'}, 0, 16000)
    assert raw['optics']['state'] == 'unparsed' and raw['optics']['reason'] == reason


def test_vpc_compare_live_mtu_mismatch_with_wrapped_reason(fake_nx):
    """Real b04 pair state with mtu 9216 on b04-nx-a Po128: the secondary wraps the Reason column."""
    secondary = fixture('2262-vpc-brief-mtu')
    result = _vpc_pair(fake_nx, member=(_sub(MTU_ROW, r'\g<1>9216\g<2>1500'), _sub(MTU_ROW, r'\g<1>1500\g<2>9216')),
                       brief=(None, lambda _: secondary))
    a, b = result['peers']
    assert [source['status'] for peer in result['peers'] for source in peer['sources']] == ['measured'] * 4, result
    assert b['member'] == {'id': 128, 'port': 'Po128', 'status': 'down*', 'consistency': 'failed',
                           'reason': 'Compatibility check failed for MTU', 'active_vlans': '-'}
    assert result['state'] == 'different' and result['ok'] is True, result
    assert result['differences'] == ['parameter:MTU', 'member:status', 'member:consistency', 'member:active_vlans']
