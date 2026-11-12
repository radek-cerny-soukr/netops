from pathlib import Path

import pytest

from netops_helper import normalization as n
from netops_helper import engine
from netops_helper.query_catalog import READ_QUERIES
from conftest import _target

FIXTURES = Path(__file__).parent / 'fixtures/identity'


@pytest.fixture(autouse=True)
def quiet_audit(monkeypatch):
    monkeypatch.setattr(engine, 'record', lambda *args, **kwargs: None)


def version(profile):
    return (FIXTURES / (profile + '.txt')).read_text()


def fixture(name):
    return (FIXTURES / (name + '.txt')).read_text()


@pytest.mark.parametrize('profile', ['extreme_exos', 'cisco_ios', 'cisco_xe', 'cisco_nxos', 'arista_eos', 'juniper_junos', 'juniper_junos_els'])
def test_identity_fields_and_wrong_os(profile):
    record = n.parse_identity(profile, version(profile))
    assert set(record) == set(n.IDENTITY_FIELDS)
    assert record['os_version']
    if not profile.startswith('juniper'):
        assert record['serial_number'].startswith('LAB')
    for other in ['extreme_exos', 'cisco_ios', 'cisco_xe', 'cisco_nxos', 'arista_eos', 'juniper_junos']:
        if other != profile and not (other.startswith('juniper') and profile.startswith('juniper')):
            with pytest.raises(n.IdentityError):
                n.parse_identity(profile, version(other))


@pytest.mark.parametrize('profile', ['extreme_exos', 'cisco_ios', 'cisco_xe', 'cisco_nxos', 'arista_eos', 'juniper_junos', 'juniper_junos_els'])
def test_preflight_stops_query_on_wrong_identity(monkeypatch, profile):
    calls = []
    def read(auth, platform, command):
        calls.append(command)
        return 0, 'unrecognized device output'
    monkeypatch.setattr(engine, 'read_from_device', read)
    result = engine.ssh_read(_target(profile, 'version'), profile, 'version', {}, 0, 16000)
    assert result['error_code'] == 'product_identity'
    assert result['reason'] in {'identity_os_mismatch', 'identity_unparsed'}
    assert 'untrusted_device_output' not in result
    assert calls == [READ_QUERIES[profile]['version'].command]


def test_preflight_success_orders_reads(monkeypatch):
    calls = []
    def read(auth, platform, command):
        calls.append(command)
        return 0, version(platform) if command == 'show version' else 'clock result'
    monkeypatch.setattr(engine, 'read_from_device', read)
    result = engine.ssh_read(_target('cisco_ios', 'clock'), 'cisco_ios', 'clock', {}, 0, 16000)
    assert result['ok']
    assert calls == ['show version', 'show clock']


@pytest.mark.parametrize('value', ['aabbccddeeff', 'AABB.CCDD.EEFF', 'AA-BB-CC-DD-EE-FF', 'aa:bb:cc:dd:ee:ff'])
def test_mac_spellings(value):
    assert n.normalize_mac(value) == 'aa:bb:cc:dd:ee:ff'


@pytest.mark.parametrize('value', ['', 'aabb.ccdd.eef', 'aa:bb-cc:dd:ee:ff', 'aa:bb:cc:dd:ee:ff\n', 'aa:bb:cc:dd:ee:ff;id'])
def test_mac_rejects_malformed(value):
    with pytest.raises(ValueError):
        n.normalize_mac(value)


@pytest.mark.parametrize('left,right', [('Gi1/0/1', 'GigabitEthernet1/0/1'), ('Eth1/1', 'Ethernet1/1'), ('Po10', 'Port-channel10'), ('Port-Channel10', 'Port-channel10'), ('LAG5', 'lag5')])
def test_port_aliases(left, right):
    assert n.normalize_port(left) == n.normalize_port(right)


def test_port_units_and_aggregates():
    physical = n.normalize_port('ge-0/0/1')
    logical = n.normalize_port('ge-0/0/1.0')
    assert physical['name'] != logical['name']
    assert logical['physical'] == physical['name']
    assert logical['unit'] == 0
    assert n.normalize_port('1:5')['name'] == '1:5'
    assert n.normalize_port('ae4.0')['aggregate']
    assert n.normalize_port('Po4')['name'] != n.normalize_port('ae4')['name']
    with pytest.raises(ValueError):
        n.normalize_port('Gi1/0/1 | clear')


@pytest.mark.parametrize('kind,good,expected', [('vlan_id', '4094', '4094'), ('mac_literal', 'AABB.CCDD.EEFF', 'aa:bb:cc:dd:ee:ff'), ('ip_literal', '2001:DB8::1', '2001:db8::1'), ('ip_literal', '192.0.2.1', '192.0.2.1'), ('vrf', 'tenant-1', 'tenant-1'), ('vr', 'VR-Default', 'VR-Default'), ('routing_instance', 'customer.inet', 'customer.inet')])
def test_typed_slots(kind, good, expected):
    from netops_helper.read_policy import _validate_slot
    assert _validate_slot(good, kind) == expected


@pytest.mark.parametrize('kind', ['vlan_id', 'mac_literal', 'ip_literal', 'vrf', 'vr', 'routing_instance'])
@pytest.mark.parametrize('attack', ['1;id', '1|show', 'a b', 'a\nb', "a'b", 'a"b', 'a\x00b', 'a\tb', 'a\x7fb', '$(id)'])
def test_each_slot_rejects_injection(kind, attack):
    from netops_helper.read_policy import _validate_slot
    with pytest.raises(ValueError):
        _validate_slot(attack, kind, lookup_only=True)


def test_cidr_and_inventory_boundary(monkeypatch):
    from netops_helper import read_policy as p
    from netops_helper.query_catalog.model import Query, Slot
    queries = {'lookup': Query('show route {ip}', {'ip': Slot(None, 'ip_literal', lookup_only=True)}, 'Lookup only.'),
               'vrf_lookup': Query('show route vrf {vrf}', {'vrf': Slot('vrfs', 'vrf')}, 'Enrolled VRF.')}
    p._validate_query_catalogs({'cisco_ios': queries})
    monkeypatch.setattr(p, 'READ_QUERIES', {'cisco_ios': queries})
    assert p.render_read_query('cisco_ios', 'lookup', {'ip': '2001:db8::12/64'}, {})[1] == 'show route 2001:db8::/64'
    with pytest.raises(ValueError):
        p._validate_slot('192.0.2.1/24', 'ip_literal')
    with pytest.raises(ValueError):
        p.render_read_query('cisco_ios', 'vrf_lookup', {'vrf': 'other'}, {'vrfs': ('tenant',)})
    assert p.render_read_query('cisco_ios', 'vrf_lookup', {'vrf': 'tenant'}, {'vrfs': ('tenant',)})[1] == 'show route vrf tenant'
    for value in ['0', '4095', '-1', '01', '١']:
        with pytest.raises(ValueError):
            p._validate_slot(value, 'vlan_id')
    for value in ['host.example', 'fe80::1%eth0', '192.0.002.1', '192.0.2.4/33']:
        with pytest.raises(ValueError):
            p._validate_slot(value, 'ip_literal', lookup_only=True)


@pytest.mark.parametrize('profile,body', [('extreme_exos', 'This user does not have permissions for this command.'), ('cisco_ios', "% Invalid input detected at '^' marker."), ('cisco_xe', '% Authorization failed.'), ('cisco_nxos', '% Permission denied for the role'), ('arista_eos', '% Authorization denied'), ('juniper_junos', 'error: permission denied: system')])
def test_permission_denied_preflight(monkeypatch, profile, body):
    monkeypatch.setattr(engine, 'read_from_device', lambda *a: (0, body))
    result = engine.ssh_read(_target(profile, 'version'), profile, 'version', {}, 0, 16000)
    assert not result['ok']
    assert result['status'] == 'permission_denied'
    assert result['reason'] == 'identity_permission_denied'


def test_identity_envelope_and_cache(monkeypatch):
    calls = []
    capture = version("cisco_ios") + "!" * 2000 + "\n"
    def read(auth, platform, command):
        calls.append(command)
        return 0, capture
    monkeypatch.setattr(engine, 'read_from_device', read)
    target = _target('cisco_ios', 'version')
    first = engine.ssh_read(target, 'cisco_ios', 'version', {}, 0, 1000)
    normalized = first['normalized']
    assert first['ok'] and first['status'] == 'ok'
    assert normalized['schema_version'] == 1
    assert normalized['coverage']['complete']
    assert normalized['identity']['serial_number'] == 'LAB00000001'
    assert normalized['sources'] == [n.source_record('version', capture, 'ok')]
    second = engine.ssh_read(target, 'cisco_ios', 'version', {}, first['next_offset'], 1000, first['content_sha256'])
    assert second['normalized'] == normalized
    assert calls == ['show version']


def _junos_target(*queries):
    import dataclasses
    return dataclasses.replace(_target('juniper_junos', 'version'), enabled_queries=queries)


def test_identity_supplements_and_missing_fields(monkeypatch):
    outputs = {'show version | no-more': version('juniper_junos'),
               'show chassis hardware | no-more': 'Hardware inventory:\nChassis LABSERIAL vSRX\n',
               'show system uptime | no-more': 'System booted: 2026-11-01 (1 day, 02:03 ago)\n'}
    monkeypatch.setattr(engine, 'read_from_device', lambda auth, platform, command: (0, outputs[command]))
    target = _junos_target('version', 'hardware', 'uptime')
    result = engine.ssh_read(target, 'juniper_junos', 'version', {}, 0, 16000)
    assert result['status'] == 'ok'
    assert result['normalized']['identity']['serial_number'] == 'LABSERIAL'
    assert len(result['normalized']['sources']) == 3
    outputs['show chassis hardware | no-more'] = 'error: permission denied: chassis'
    result = engine.ssh_read(target, 'juniper_junos', 'version', {}, 0, 16000)
    # The failed supplement is reported per source; the successful version read keeps its own state.
    assert result['ok'] and result['status'] == 'unparsed'
    assert [source['status'] for source in result['normalized']['sources']] == ['ok', 'permission_denied', 'ok']
    assert 'identity_source_hardware_permission_denied' in result['normalized']['warnings']
    assert not result['normalized']['coverage']['complete']
    assert 'serial_number' in result['normalized']['coverage']['missing_fields']


def test_supplements_run_only_for_enabled_queries(monkeypatch):
    calls = []
    def read(auth, platform, command):
        calls.append(command)
        return 0, version('juniper_junos')
    monkeypatch.setattr(engine, 'read_from_device', read)
    result = engine.ssh_read(_junos_target('version'), 'juniper_junos', 'version', {}, 0, 16000)
    assert calls == ['show version | no-more']
    assert result['ok'] and result['status'] == 'unparsed'
    assert {'identity_source_hardware_not_enabled', 'identity_source_uptime_not_enabled'} <= set(result['normalized']['warnings'])
    assert [source['query'] for source in result['normalized']['sources']] == ['version']
    calls.clear()
    engine.ssh_read(_junos_target('version', 'uptime'), 'juniper_junos', 'version', {}, 0, 16000)
    assert calls == ['show version | no-more', 'show system uptime | no-more']


def test_supplement_transport_error_keeps_version_state(monkeypatch):
    def read(auth, platform, command):
        if command != 'show version | no-more':
            raise TimeoutError('deadline')
        return 0, version('juniper_junos')
    monkeypatch.setattr(engine, 'read_from_device', read)
    result = engine.ssh_read(_junos_target('version', 'hardware'), 'juniper_junos', 'version', {}, 0, 16000)
    assert result['ok'] and result['status'] != 'timeout'
    assert [source['status'] for source in result['normalized']['sources']] == ['ok', 'timeout']
    assert 'identity_source_hardware_timeout' in result['normalized']['warnings']


def test_identity_coverage_only_for_version_and_paging_is_not_truncated(monkeypatch):
    body = 'Interface  Status\n' + 'Gi1/0/1  connected\n' * 400
    monkeypatch.setattr(engine, 'read_from_device', lambda auth, platform, command: (0, version('cisco_ios') if command == 'show version' else body))
    first = engine.ssh_read(_target('cisco_ios', 'interfaces'), 'cisco_ios', 'interfaces', {}, 0, 1000)
    assert first['next_offset'] is not None
    assert first['status'] == 'unparsed'  # raw output without an adapter, but not "truncated"
    assert first['normalized']['coverage'] == {'complete': False, 'parsed_fields': [], 'missing_fields': []}
    monkeypatch.setattr(engine, 'read_from_device', lambda auth, platform, command: (0, version('cisco_ios') if command == 'show version' else body + '--More--'))
    capped = engine.ssh_read(_target('cisco_ios', 'interfaces'), 'cisco_ios', 'interfaces', {}, 0, 1000)
    assert capped['status'] == 'truncated'
    monkeypatch.setattr(engine, 'read_from_device', lambda auth, platform, command: (0, version('cisco_ios')))
    identity = engine.ssh_read(_target('cisco_ios', 'version'), 'cisco_ios', 'version', {}, 0, 16000)
    assert identity['normalized']['coverage']['parsed_fields']


@pytest.mark.parametrize('error,expected', [(TimeoutError('deadline'), 'timeout'), (OSError('connection refused'), 'transport_error'), (engine.core_ssh.OutputLimitError(), 'truncated')])
def test_transport_states(monkeypatch, error, expected):
    def fail(*a):
        raise error
    monkeypatch.setattr(engine, 'read_from_device', fail)
    result = engine.ssh_read(_target('cisco_ios', 'clock'), 'cisco_ios', 'clock', {}, 0, 16000)
    assert result['status'] == expected
    assert result['normalized']['identity'] is None


def test_state_contract():
    assert n.output_status('') == 'empty'
    assert n.output_status('anything', truncated=True) == 'truncated'
    assert n.output_status('Method is not implemented on this platform.') == 'unsupported'
    for state in n.RESULT_STATES:
        assert n.response_envelope('cisco_ios', state, [])['status'] == state
    with pytest.raises(ValueError):
        n.response_envelope('cisco_ios', 'healthy', [])


def test_documented_xe_isr_version():
    record = n.parse_identity('cisco_xe', (FIXTURES / 'cisco_xe_isr4331.txt').read_text())
    assert record['model'] == 'ISR4331/K9'
    assert record['os_version'] == '03.13.03.S'
    assert record['uptime'] == '1 minute'


@pytest.mark.parametrize('kind,good', [('vlan_id', '10'), ('mac_literal', 'aabb.ccdd.eeff'), ('ip_literal', '2001:db8::1'), ('vrf', 'tenant'), ('vr', 'VR-Default'), ('routing_instance', 'tenant')])
def test_proxy_uses_strict_slot_types(kind, good):
    from netops_helper.proxy import _valid_typed_inventory_value
    assert _valid_typed_inventory_value(good, kind)
    for attack in ['x;id', 'x|show', 'x y', 'x\ny', 'x"y', "x'y", 'x\x00y']:
        assert not _valid_typed_inventory_value(attack, kind)
    if kind == 'ip_literal':
        assert not _valid_typed_inventory_value('2001:db8::/64', kind)
        assert _valid_typed_inventory_value('2001:db8::/64', kind, lookup_only=True)


def test_truncated_identity_is_not_trusted(monkeypatch):
    monkeypatch.setattr(engine, 'read_from_device', lambda *args: (0, version('cisco_ios') + '--More--'))
    result = engine.ssh_read(_target('cisco_ios', 'clock'), 'cisco_ios', 'clock', {}, 0, 16000)
    assert result['status'] == 'truncated'
    assert result['reason'] == 'identity_truncated'


def test_identity_version_and_cidr_are_literals():
    from netops_helper.read_policy import _validate_slot
    with pytest.raises(n.IdentityError, match='identity_unparsed'):
        n.parse_identity('cisco_ios', version('cisco_ios').replace('12.2(0.0.16)FX', 'unknown'))
    with pytest.raises(ValueError):
        _validate_slot('192.0.2.1/255.255.255.0', 'ip_literal', lookup_only=True)


def test_refusal_patterns_do_not_cross_os_boundaries():
    assert not engine._cli_refused('juniper_junos', "%% Unrecognized command\n")
    assert not engine._cli_refused('extreme_exos', 'error: permission denied: system\n')
    assert not engine._cli_refused('juniper_junos', 'error: unknown command: x\rY\n')
    assert engine._cli_refused('cisco_xe', '% Authorization failed.\n')


@pytest.mark.parametrize('profile,name,expected', [
    ('cisco_ios', 'full_cisco_ios_3660', dict(model='3660', os_version='12.3(4)T', serial_number='LAB00000011', hostname='lab-ios-router', uptime='1 week, 3 days, 6 hours, 41 minutes')),
    ('cisco_nxos', 'full_cisco_nxos_n5548', dict(model='Nexus5548', os_version='5.1(3)N2(1)', serial_number='LAB00000012', hostname='lab-n5k', uptime='7 day(s), 22 hour(s), 50 minute(s), 34 second(s)')),
    ('arista_eos', 'full_arista_eos_dcs7150', dict(model='DCS-7150S-64-CL-F', os_version='4.13.2F', serial_number='LAB00000013', uptime='16 hours and 39 minutes')),
    ('extreme_exos', 'full_extreme_exos', dict(os_version='31.1.0.631', serial_number='LAB00000014')),
    ('juniper_junos', 'full_juniper_junos_mx480', dict(model='mx480', os_version='24.4R1.9', hostname='lab-mx480')),
    ('juniper_junos_els', 'full_juniper_junos_mx480', dict(model='mx480', os_version='24.4R1.9')),
    ('cisco_xe', 'synthetic_cisco_xe_stack_16', dict(model='C9300-48P', os_version='16.12.04', serial_number='LAB00000015', hostname='lab-xe')),
])
def test_complete_vendor_outputs_parse_without_family_tables(profile, name, expected):
    warnings = []
    record = n.parse_identity(profile, fixture(name), warnings)
    assert {key: record[key] for key in expected} == expected
    assert warnings == []


@pytest.mark.parametrize('profile,line,model', [
    ('cisco_ios', 'Cisco CISCO2901/K9 (revision 1.0) with 999424K/49152K bytes of memory.', 'CISCO2901/K9'),
    ('cisco_ios', 'Cisco CISCO2911/K9 (revision 1.0) with 487424K/36864K bytes of memory.', 'CISCO2911/K9'),
    ('cisco_ios', 'Cisco IOSv (revision 1.0) with 484609K/37888K bytes of memory.', 'IOSv'),
    ('cisco_ios', 'cisco C1000-24T-4G-L (ARM) processor (revision B0) with 1000K/100K bytes of memory.', 'C1000-24T-4G-L'),
    ('cisco_ios', 'cisco WS-C2960X-48FPD-L (APM86XXX) processor (revision A0) with 524288K/4K bytes of memory.', 'WS-C2960X-48FPD-L'),
    ('cisco_ios', 'cisco ISR4331/K9 (1RU) processor with 1687301K/6147K bytes of memory.', 'ISR4331/K9'),
])
def test_ios_model_lines_of_routers_and_switches(profile, line, model):
    text = 'Cisco IOS Software, Test Software (TEST-M), Version 15.2(7)E1, RELEASE SOFTWARE\nlab uptime is 1 day\n' + line + '\nProcessor board ID LAB1\n'
    assert n.parse_identity(profile, text)['model'] == model


@pytest.mark.parametrize('chassis,model', [
    ('cisco Nexus5548 Chassis ("O2 32X10GE/Modular Universal Platform Supervisor")', 'Nexus5548'),
    ('cisco Nexus3048 Chassis', 'Nexus3048'),
    ('cisco Nexus9000 C9336C-FX2 Chassis', 'C9336C-FX2'),
    ('cisco Nexus9000 C93180YC-EX Chassis ("40x10/25G + 6x40/100G Supervisor")', 'C93180YC-EX'),
    ('cisco Nexus7000 C7010 (10 Slot) Chassis ("Supervisor Module-2")', 'C7010'),
])
def test_nxos_model_is_sku_only(chassis, model):
    text = 'Cisco Nexus Operating System (NX-OS) Software\n  NXOS: version 9.3(5)\nHardware\n  ' + chassis + '\n  Processor Board ID LAB1\n'
    record = n.parse_identity('cisco_nxos', text)
    assert record['model'] == model


@pytest.mark.parametrize('profile,header,model', [
    ('arista_eos', 'Arista CCS-720XP-48ZC2\nSoftware image version: 4.31.2F\n', 'CCS-720XP-48ZC2'),
    ('arista_eos', 'Arista AWE-5310\nSoftware image version: 4.31.2F\n', 'AWE-5310'),
    ('juniper_junos_els', 'Hostname: v\nModel: vqfx-10000\nJunos: 19.4R1.10\n', 'vqfx-10000'),
    ('cisco_ios', 'Cisco IOS Software, X Software (X), Version 15.2(7)E1\ncisco C1000-24T-4G-L (ARM) processor with 1K/1K bytes of memory.\n', 'C1000-24T-4G-L'),
])
def test_model_is_data_not_a_family_gate(profile, header, model):
    assert n.parse_identity(profile, header)['model'] == model


@pytest.mark.parametrize('profile,text', [
    ('cisco_ios', 'Cisco IOS Software, X Software (X), Version 15.2(7)E1\n'),
    ('cisco_nxos', 'Cisco Nexus Operating System (NX-OS) Software\n  NXOS: version 9.3(5)\n'),
    ('juniper_junos', 'Hostname: h\nJunos: 22.1R1.10\n'),
])
def test_unread_model_never_blocks_reading(monkeypatch, profile, text):
    assert n.parse_identity(profile, text)['model'] is None
    calls = []
    def read(auth, platform, command):
        calls.append(command)
        return 0, text if command == READ_QUERIES[platform]['version'].command else 'clock result'
    monkeypatch.setattr(engine, 'read_from_device', read)
    other = next(name for name, query in sorted(READ_QUERIES[profile].items()) if name != 'version' and not query.slots)
    result = engine.ssh_read(_target(profile, other), profile, other, {}, 0, 16000)
    assert result['ok'] and len(calls) == 2
    version_result = engine.ssh_read(_target(profile, 'version'), profile, 'version', {}, 0, 16000)
    assert version_result['ok'] and 'identity_missing_model' in version_result['normalized']['warnings']


def test_os_mismatch_still_refuses_but_hardware_never_does():
    with pytest.raises(n.IdentityError, match='identity_os_mismatch'):
        n.parse_identity('cisco_nxos', fixture('full_cisco_ios_3660'))
    with pytest.raises(n.IdentityError, match='identity_os_mismatch'):
        n.parse_identity('cisco_xe', fixture('full_cisco_ios_3660'))
    assert not hasattr(n, 'ROUTER_BASES')
    assert not any(name.endswith('_router') for name in READ_QUERIES)


def test_junos_virtual_chassis_uses_first_member_and_tolerates_mixed_models():
    warnings = []
    record = n.parse_identity('juniper_junos_els', fixture('synthetic_juniper_junos_vc_mixed'), warnings)
    assert record['model'] == 'ex4300-48p' and record['os_version'] == '21.4R3-S5.4'
    assert warnings == []


def test_conflicting_descriptive_fields_warn_but_conflicting_version_refuses():
    warnings = []
    record = n.parse_identity('cisco_ios', version('cisco_ios') + '\nProcessor board ID OTHER\n', warnings)
    assert record['serial_number'] is None and warnings == ['identity_serial_number_ambiguous']
    with pytest.raises(n.IdentityError, match='identity_ambiguous'):
        n.parse_identity('arista_eos', version('arista_eos') + 'Software image version: 4.1\n')


def test_device_types_only_enable_template_groups(monkeypatch):
    from netops_helper import inventory
    from netops_helper.query_catalog.model import Query
    catalogue = {'version': READ_QUERIES['cisco_ios']['version'],
                 'bgp': Query('show ip bgp summary', {}, 'Routing group.', group='router'),
                 'zones': Query('show zone', {}, 'Firewall group.', group='firewall')}
    monkeypatch.setattr(inventory, 'READ_QUERIES', {'cisco_ios': catalogue})
    monkeypatch.setattr(inventory, 'catalog_platform', lambda platform: platform)
    assert inventory._checked_device_types('d', []) == ()
    assert inventory._checked_device_types('d', ['switch', 'router']) == ('switch', 'router')
    for bad in (['bridge'], ['router', 'router'], 'router', [['router']]):
        with pytest.raises(inventory.InventoryError):
            inventory._checked_device_types('d', bad)
    assert inventory._checked_queries('d', 'cisco_ios', ['version']) == ('version',)
    assert inventory._checked_queries('d', 'cisco_ios', ['version', 'bgp'], ('router',)) == ('version', 'bgp')
    for types in ((), ('switch',), ('firewall',)):
        with pytest.raises(inventory.InventoryError, match='device type'):
            inventory._checked_queries('d', 'cisco_ios', ['bgp'], types)
    # The attribute never touches identity: the same OS profile reads the same version output.
    assert 'device_types' in inventory.SECTION_FIELDS


def test_query_group_must_be_a_device_type():
    from netops_helper import read_policy
    from netops_helper.query_catalog.model import Query
    with pytest.raises(RuntimeError):
        read_policy._validate_query_catalogs({'cisco_ios': {'x': Query('show x', {}, 'Bad group.', group='wireless')}})


@pytest.mark.parametrize('name,canonical,physical,unit,kind', [
    ('Twe1/0/1', 'TwentyFiveGigE1/0/1', 'TwentyFiveGigE1/0/1', None, 'physical'),
    ('TwentyFiveGigE1/0/1', 'TwentyFiveGigE1/0/1', 'TwentyFiveGigE1/0/1', None, 'physical'),
    ('Fo1/1/1', 'FortyGigabitEthernet1/1/1', 'FortyGigabitEthernet1/1/1', None, 'physical'),
    ('Hu1/0/49', 'HundredGigE1/0/49', 'HundredGigE1/0/49', None, 'physical'),
    ('Tw1/0/1', 'TwoGigabitEthernet1/0/1', 'TwoGigabitEthernet1/0/1', None, 'physical'),
    ('TwoGigabitEthernet1/0/1', 'TwoGigabitEthernet1/0/1', 'TwoGigabitEthernet1/0/1', None, 'physical'),
    ('xe-0/0/0:1', 'xe-0/0/0:1', 'xe-0/0/0:1', None, 'physical'),
    ('xe-0/0/0:1.0', 'xe-0/0/0:1.0', 'xe-0/0/0:1', 0, 'physical'),
    ('Po10', 'Port-channel10', 'Port-channel10', None, 'aggregate'),
    ('Vlan10', 'Vlan10', 'Vlan10', None, 'other'),
    ('Loopback0', 'Loopback0', 'Loopback0', None, 'other'),
    ('mgmt0', 'mgmt0', 'mgmt0', None, 'other'),
    ('Ma0', 'Management0', 'Management0', None, 'other'),
    ('Management0', 'Management0', 'Management0', None, 'other'),
    ('irb.10', 'irb.10', 'irb.10', None, 'other'),
])
def test_port_aliases_and_unknown_safe_names(name, canonical, physical, unit, kind):
    port = n.normalize_port(name)
    assert (port['name'], port['physical'], port['unit'], port['kind']) == (canonical, physical, unit, kind)


def test_tw_and_twe_are_different_speeds_and_unsafe_names_still_fail():
    assert n.normalize_port('Tw1/0/1')['name'] != n.normalize_port('Twe1/0/1')['name']
    for bad in ('Vlan10; reload', 'Gi1/0/1|x', '', 'a b', 'x' * 65):
        with pytest.raises(ValueError):
            n.normalize_port(bad)


@pytest.mark.parametrize('profile,body,state', [
    ('cisco_ios', "% Invalid input detected at '^' marker.", 'permission_denied'),
    ('cisco_xe', "% Invalid input detected at '^' marker.", 'permission_denied'),
    ('cisco_ios', '% Incomplete command.', 'unsupported'),
    ('cisco_xe', '% Ambiguous command:  "show s"', 'unsupported'),
    ('arista_eos', '% Invalid input (at token 1: \'x\')', 'unsupported'),
    ('arista_eos', '% Incomplete command', 'unsupported'),
    ('arista_eos', '% Authorization denied for command \'show x\'', 'permission_denied'),
    ('cisco_nxos', "% Invalid command at '^' marker.", 'unsupported'),
    ('cisco_nxos', '% Permission denied for the role', 'permission_denied'),
    ('juniper_junos', 'error: permission denied', 'permission_denied'),
])
def test_message_classification_by_os(profile, body, state):
    assert n.output_status(body, profile=profile) == state


@pytest.mark.parametrize('profile,body', [('cisco_ios', '% Incomplete command.'), ('cisco_nxos', "% Invalid command at '^' marker."), ('arista_eos', '% Ambiguous command')])
def test_template_errors_are_cli_errors_not_permission(monkeypatch, profile, body):
    monkeypatch.setattr(engine, 'read_from_device', lambda auth, platform, command: (0, version(profile) if command == READ_QUERIES[profile]['version'].command else body))
    other = next(name for name, query in sorted(READ_QUERIES[profile].items()) if name != 'version' and not query.slots)
    result = engine.ssh_read(_target(profile, other), profile, other, {}, 0, 16000)
    assert not result['ok'] and result['error_code'] == 'device_cli_error'
    assert result['status'] == 'unsupported'


def test_a_version_that_does_not_parse_is_an_unparsed_envelope_and_no_supplement_is_read(monkeypatch):
    monkeypatch.setattr(engine, 'read_from_device', lambda *args: pytest.fail('a supplement was read'))
    result = engine._normalized_identity(_junos_target('version', 'hardware', 'uptime'), 'juniper_junos', 0, 'not a Junos banner')
    assert result['status'] == 'unparsed'
    assert [source['query'] for source in result['sources']] == ['version']
    assert result['warnings']


def test_an_ambiguous_supplement_is_reported_per_source_and_keeps_the_version_state(monkeypatch):
    def read(auth, platform, command):
        return 0, version('juniper_junos') if command == 'show version | no-more' else 'Chassis A\nChassis B\n'
    def ambiguous(record, query, text):
        raise n.IdentityError('identity_ambiguous')
    monkeypatch.setattr(engine, 'read_from_device', read)
    monkeypatch.setattr(n, 'supplement_identity', ambiguous)
    result = engine.ssh_read(_junos_target('version', 'hardware'), 'juniper_junos', 'version', {}, 0, 16000)
    assert result['ok'] and 'identity_source_hardware_ambiguous' in result['normalized']['warnings']
    assert result['normalized']['sources'][0]['status'] == 'ok'


@pytest.mark.parametrize("secret", ["Cisco", "12.2(0.0.16)FX"])
def test_identity_uses_original_banner_and_only_returns_redacted_text(monkeypatch, secret):
    from dataclasses import replace
    target = replace(_target("cisco_ios", "clock"), secret=secret)
    monkeypatch.setattr(engine, "_resolve_target_ipv4", lambda auth: ("127.0.0.1",))
    monkeypatch.setattr(engine, "host_key_line", lambda *args: "unused")
    monkeypatch.setattr(engine, "_exec_command", lambda *a, **k: engine.core_ssh.Result(
        rc=0, stdout=version("cisco_ios").encode(), said="", started_at="", finished_at=""))
    command, rc, status = engine._check_identity(target, "cisco_ios", engine.read_from_device)
    assert command == "show version" and rc == 0
    assert secret not in status and "REDACTED" in status
    assert not engine._IDENTITY_PROBE.get()
    # Ordinary reads still redact literal secrets before downstream parsers.
    assert secret not in engine._exec_read(target, "cisco_ios", "show clock")[1]


def test_identity_probe_context_is_reset_after_failed_identity(monkeypatch):
    monkeypatch.setattr(engine, "read_from_device", lambda *a: (0, "wrong product"))
    with pytest.raises(engine._ProductIdentityError):
        engine._check_identity(_target("cisco_ios", "version"), "cisco_ios", engine.read_from_device)
    assert not engine._IDENTITY_PROBE.get()


@pytest.mark.parametrize('text,status', [
    ('Interface  Status\nGi1/0/1  connected\n--More--', 'truncated'),
    ('Interface  Status\n --More-- \n', 'truncated'),
    ('last line--More--', 'truncated'),
    ('port7 00:00:5e:00:53:99 eth0 --More--', 'truncated'),
    ('ge-0/0/1 00:00:5e:00:53:99 eth0 x---(more)---\n', 'ok'),
    ('ge-0/0/1 00:00:5e:00:53:99 eth0 ---(more)---\r\n', 'ok'),
    ('log: Press <SPACE> to continue', 'truncated'),
    ('heading\r\n\t --More-- \r\n \t\n', 'truncated'),
    ('heading\n --More--\nnext', 'ok'),
    ('log\n---(more 42%)---\n', 'truncated'),
    ('Press <SPACE> to continue or <Q> to quit:', 'truncated'),
    # device-controlled text that only contains a pager mark is complete output
    ('Gi1/0/1  uplink --More-- spare  connected\nGi1/0/2  connected\n', 'ok'),
    ('System Description: lab ---(more)--- box\nPort ID: 1\n', 'ok'),
    ('Nov  9 01:00:00 host app: Press <SPACE> to continue was logged\nnext\n', 'ok'),
])
def test_pager_marks_count_at_the_end_of_the_capture(text, status):
    assert n.output_status(text) == status


@pytest.mark.parametrize('text,complete', [
    ('Port  Display String\n1     uplink Error: none\n', True),
    ('Vlan: x\n  Description: Incomplete command list\n', True),
    ('Vlan: x\n  Incomplete command\n', False),
    ('Vlan: x\nError: something failed\n', False),
    ('Port  Display String\n2     %% not an error\n', True),
])
def test_exos_error_marks_count_only_at_the_start_of_a_line(text, complete):
    assert n.exos_exit_250('extreme_exos', 250, text) is complete


@pytest.mark.parametrize('prefix', ['data row ', 'x', 'data row\nnext ', 'data row\r'])
@pytest.mark.parametrize('mark', ['--More--', '---(more)---', '---(more 42%)---',
                                  'Press <SPACE> to continue', 'Press <SPACE> to continue trailing words'])
@pytest.mark.parametrize('suffix', ['', ' \t\r', '\n', '\r\n', '\n \t\n'])
def test_appended_pager_requires_no_following_newline(prefix, mark, suffix):
    text = prefix + mark + suffix
    assert n.output_status(text) == ('ok' if '\n' in suffix else 'truncated')
