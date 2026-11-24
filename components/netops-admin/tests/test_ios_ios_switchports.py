"""IOS-SWITCHPORTS plans and guards for IOS (IOSvL2 15.2) over real anonymized answers through fake transport.

The fixtures in fixtures/ios_ios_switchports were captured on the GNS3 IOSvL2 lab switch (test port GigabitEthernet1/0,
VLANs 3780-3782) with independent CLI sessions of the write and check accounts, not produced by the adapter under
test. The scenarios mirror XE-SWITCHPORTS (IOS XE) including its review lessons: a trunk with the default allowed set "all"
never blocks VLAN create/rename/delete, and an allowed set with missing or reserved VLANs can be planned.
"""
import copy
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import request_bytes
from fake_ios import FakeIos
from netops_admin import engine, exec_ios, exec_ios_vlan, ios
from netops_admin.errors import Rejected
from netops_admin.profiles import find_profile
from netops_admin.request import parse_request
from approved_apply import approved_apply

F = Path(__file__).parent / 'fixtures' / 'ios_ios_switchports'
PORT = 'GigabitEthernet1/0'
FW = '15.2(20200924:215240)'
DEVICE = SimpleNamespace(platform='ios', firmware=FW)


def fixture(name):
    return (F / name).read_text()


def request(changes=None, table='vlan-membership', key=PORT, op='update', impact=False):
    fields = dict(table=table, key=key, op=op, changes=changes or {})
    if impact:
        fields['endpoint_impact'] = key
    return parse_request(request_bytes(**fields))


def baseline():
    return ios.with_vlan_database(fixture('baseline.conf'), fixture('vlan-brief-before.txt'))


def plan(req, text=None):
    return engine.build_plan('ios', (text or baseline()).encode(), req, firmware=FW)


class Transport(FakeIos):
    """Normal IOSvL2 fake transport plus the exact measured answers of the IOS-SWITCHPORTS reads."""
    def __init__(self):
        super().__init__('iosvl2')
        self.vlans |= {'3780', '3781'}
        self.query_override['show mac address-table interface ' + PORT] = fixture('occupied-mac.txt')
        self.check_override = {'show interfaces ' + PORT + ' switchport': fixture('switchport-before.txt')}


def test_ios_switchports_profiles_cover_ios_switch_tables():
    membership = find_profile('ios', 'vlan-membership', FW)
    assert set(membership.attributes) == {'access-vlan', 'mode', 'trunk-encapsulation', 'allowed-vlans',
                                          'native-vlan', 'voice-vlan'}
    vlan = find_profile('ios', 'vlan', FW)
    assert vlan.ops == ('create', 'update', 'delete') or set(vlan.ops) == {'create', 'update', 'delete'}
    assert 'IOSv 15.9(3)M12' in find_profile('ios', 'interface', FW).rollback_evidence


# ---- IOS-C001: occupied port only after an explicit endpoint impact ----

def test_occupied_port_requires_explicit_impact_and_acknowledgement_is_bound():
    target = Transport()
    p = plan(request({'access-vlan': 3780}))
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(target, DEVICE, p, baseline())
    assert caught.value.reason_codes == ['port_learned_mac']
    acknowledged = plan(request({'access-vlan': 3780}, impact=True))
    exec_ios.plan_prechecks(target, DEVICE, acknowledged, baseline())
    assert acknowledged['plan_sha256'] != p['plan_sha256']
    assert any('MACs 1' in check and 'interrupted' in check for check in acknowledged['prechecks'])
    forged = copy.deepcopy(acknowledged)
    del forged['endpoint_impact']
    with pytest.raises(Rejected):
        engine._read_plan(forged)


def test_occupied_port_state_change_requires_impact():
    target = Transport()
    p = plan(request({'admin-state': 'enabled'}, table='interface'))
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(target, DEVICE, p, baseline())
    assert caught.value.reason_codes == ['port_learned_mac']
    exec_ios.plan_prechecks(target, DEVICE, plan(request({'admin-state': 'enabled'}, table='interface', impact=True)),
                            baseline())


@pytest.mark.parametrize('command', ['show lldp neighbors', 'show cdp neighbors',
                                     'show mac address-table interface ' + PORT])
def test_impact_never_waives_unreadable_usage(command):
    target = Transport()
    target.query_override[command] = fixture('ro-denied.txt')
    p = plan(request({'access-vlan': 3780}, impact=True))
    with pytest.raises(Rejected):
        exec_ios.plan_prechecks(target, DEVICE, p, baseline())


@pytest.mark.parametrize('key', ['GigabitEthernet0/0'])
def test_management_port_cannot_be_confirmed_away(key):
    target = Transport()
    p = plan(request({'admin-state': 'disabled'}, table='interface', key=key, impact=True))
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(target, DEVICE, p, baseline())
    assert caught.value.reason_codes == ['port_management_vlan']


def test_voice_management_vlan_cannot_be_confirmed_away():
    target = Transport()
    target.query_override['show interfaces ' + PORT + ' switchport'] = fixture('switchport-before.txt').replace(
        'Voice VLAN: none', 'Voice VLAN: 99 (D-MGMT)')
    p = plan(request({'admin-state': 'enabled'}, table='interface', impact=True))
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(target, DEVICE, p, baseline())
    assert caught.value.reason_codes == ['port_management_vlan']


def test_impact_is_refused_for_the_vlan_table():
    with pytest.raises(Rejected, match='endpoint_impact'):
        plan(request({'name': 'netops-ios-switchports'}, table='vlan', key='3780', op='create', impact=True))


def test_occupied_access_vlan_change_runs_apply_readback_and_undo(tmp_path):
    from netops_admin import execute
    from test_ios import make_runtime
    target = FakeIos('iosvl2')
    target.vlans.add('3780')
    target.learned_macs[PORT] = 1
    runtime = make_runtime(tmp_path, target)
    denied = execute.preview(runtime, 'lab-ios', request({'access-vlan': 3780}))
    assert denied['result'] == 'rejected' and 'port_learned_mac' in denied['reason_codes']
    req = request({'access-vlan': 3780}, impact=True)
    preview = execute.preview(runtime, 'lab-ios', req)
    assert preview['result'] == 'ready', preview
    assert not target.applied_blocks
    result = execute.apply(runtime, 'lab-ios', req, expected_plan_sha256=preview['plan_sha256'])
    assert result['result'] == 'confirmed', result
    assert 'switchport access vlan 3780' in target.interface(PORT)
    undo = execute.undo(runtime, result['change_id'], 'return the reserved test port')
    assert undo['result'] == 'confirmed', undo
    assert not any(line.startswith('switchport access vlan') for line in target.interface(PORT))


# ---- IOS-M004 / IOS-M022: trunk, allowed/native and voice ----

def test_voice_plan_renders_measured_command_and_independent_check():
    p = plan(request({'voice-vlan': 3781}, impact=True))
    assert p['commands'] == ['configure terminal', 'interface ' + PORT, 'switchport voice vlan 3781', 'end']
    assert p['inverse'] == ['configure terminal', 'interface ' + PORT, 'no switchport voice vlan', 'end']
    target = Transport()
    target.check_override['show interfaces ' + PORT + ' switchport'] = fixture('switchport-voice.txt')
    state = exec_ios.observe(target, p)
    assert state['voice-vlan'] == '3781' and state['access-vlan'] == '3780'
    assert engine.observed_state(p, state)['voice-vlan'] == '3781'


def test_voice_vlan_must_exist():
    target = Transport()
    target.vlans.discard('3781')
    p = plan(request({'voice-vlan': 3781}, impact=True))
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(target, DEVICE, p, baseline())
    assert caught.value.reason_codes == ['vlan_missing']


def test_full_trunk_plan_has_dot1q_before_mode_and_canonical_allowed_set():
    p = plan(request({'mode': 'trunk', 'trunk-encapsulation': 'dot1q', 'allowed-vlans': '3781,3780',
                      'native-vlan': 3780}, impact=True))
    assert p['commands'].index('switchport trunk encapsulation dot1q') < p['commands'].index('switchport mode trunk')
    assert 'switchport trunk allowed vlan 3780-3781' in p['commands']
    assert 'switchport trunk native vlan 3780' in p['commands']
    assert 'switchport mode access' in p['inverse']


def test_trunk_requires_explicit_impact_and_encapsulation():
    with pytest.raises(Rejected, match='dot1q'):
        plan(request({'mode': 'trunk'}, impact=True))
    target = Transport()
    p = plan(request({'mode': 'trunk', 'trunk-encapsulation': 'dot1q', 'allowed-vlans': '3780'}))
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(target, DEVICE, p, baseline())
    assert caught.value.reason_codes == ['endpoint_impact_required']


def test_trunk_membership_without_impact_is_refused_before_any_write():
    # Former plan refusal port_uplink of an IOS trunk (test_ios.py) is now the live endpoint_impact precheck.
    target = Transport()
    target.query_override['show interfaces GigabitEthernet0/2 switchport'] = fixture('switchport-trunk.txt').replace(
        'Name: Gi1/0', 'Name: Gi0/2').replace('Trunking VLANs Enabled: 3780,3781', 'Trunking VLANs Enabled: 10,20')
    p = plan(request({'access-vlan': 20}, key='GigabitEthernet0/2'))
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(target, DEVICE, p, baseline())
    assert caught.value.reason_codes == ['endpoint_impact_required']
    assert not target.applied_blocks


@pytest.mark.parametrize('changes', [{'admin-state': 'disabled'}, {'description': 'uplink'}])
def test_trunk_port_state_stays_refused_and_description_allowed(changes):
    if 'admin-state' in changes:
        with pytest.raises(Rejected) as caught:
            plan(request(changes, table='interface', key='GigabitEthernet0/1', impact=True))
        assert caught.value.reason_codes == ['port_uplink']
    else:
        assert plan(request(changes, table='interface', key='GigabitEthernet0/1'))['commands']


def test_measured_trunk_refusal_without_dot1q_is_an_error():
    assert ios.cli_error(fixture('trunk-auto-refused.txt')).startswith('Command rejected')


@pytest.mark.parametrize('value', ['0', '4095', '20-10', '10,,20', '10;end', 'all\nend'])
def test_bad_allowed_lists_refused(value):
    with pytest.raises(Rejected):
        plan(request({'allowed-vlans': value}, impact=True))


@pytest.mark.parametrize('name', ['switchport-before.txt', 'switchport-voice.txt', 'switchport-trunk.txt',
                                  'switchport-removed.txt'])
def test_independent_switchport_refused_or_cut_output(name):
    text = fixture(name)
    assert ios.switchport_membership(text, PORT) is not None
    with pytest.raises(Rejected):
        ios.switchport_membership(text.split('Voice VLAN:')[0], PORT)
    assert ios.switchport_membership(fixture('ro-denied.txt'), PORT) is None


def test_measured_switchport_states():
    assert ios.switchport_membership(fixture('switchport-before.txt'), PORT) == {
        'mode': 'access', 'access-vlan': '1', 'native-vlan': '1', 'voice-vlan': 'none', 'allowed-vlans': 'all',
        'trunk-encapsulation': 'negotiate'}
    trunk = ios.switchport_membership(fixture('switchport-trunk.txt'), PORT)
    assert trunk['mode'] == 'trunk' and trunk['allowed-vlans'] == '3780-3781' and trunk['native-vlan'] == '3780'
    assert ios.switchport_membership(fixture('switchport-removed.txt'), PORT)['allowed-vlans'] == '3780'


def port_snapshot(name, base=None):
    """Replay the real interface stanza in the real baseline; unrelated configuration stays constant."""
    measured = fixture(name)
    stanza = measured[measured.index('interface ' + PORT):measured.rindex('end')].rstrip()
    return re.sub(r'interface GigabitEthernet1/0\n(?: [^\n]*\n)*', stanza + '\n', base or baseline())


def enabled_baseline():
    # The measurement enabled the port in the same session; hold the admin state constant for this table.
    return baseline().replace('interface GigabitEthernet1/0\n switchport mode access\n shutdown\n',
                              'interface GigabitEthernet1/0\n switchport mode access\n')


@pytest.mark.parametrize('name,changes', [
    ('access-voice.conf', {'access-vlan': 3780, 'voice-vlan': 3781}),
    ('trunk.conf', {'access-vlan': 3780, 'mode': 'trunk', 'trunk-encapsulation': 'dot1q', 'native-vlan': 3780,
                    'allowed-vlans': '3780,3781'}),
    ('trunk-removed.conf', {'access-vlan': 3780, 'mode': 'trunk', 'trunk-encapsulation': 'dot1q',
                            'native-vlan': 3780, 'allowed-vlans': '3780'}),
])
def test_planned_membership_matches_independently_captured_running_stanza(name, changes):
    before = enabled_baseline()
    assert 'interface GigabitEthernet1/0\n switchport mode access\n negotiation auto\n' in before
    p = plan(request(changes, impact=True), before)
    verdict = engine.verify(p, port_snapshot(name, before).encode())
    assert verdict['result'] == 'match', verdict
    assert engine.verify(p, before.encode(), expect='before')['result'] == 'match'


def test_allowed_vlan_remove_has_exact_inverse_and_readback():
    before = port_snapshot('trunk.conf')
    p = plan(request({'allowed-vlans': '3780'}, impact=True), before)
    assert 'switchport trunk allowed vlan 3780' in p['commands']
    assert 'switchport trunk allowed vlan 3780-3781' in p['inverse']
    assert engine.verify(p, port_snapshot('trunk-removed.conf').encode())['result'] == 'match'


def trunk_precheck_target(allowed):
    """Measured trunk answers, varying only the VLAN list; management moved out of band (all includes VLAN 99)."""
    target = Transport()
    text = port_snapshot('trunk.conf').replace(' switchport trunk allowed vlan 3780,3781\n',
                                               '' if allowed == 'all' else ' switchport trunk allowed vlan ' + allowed + '\n')
    answer = fixture('switchport-trunk.txt').replace('Trunking VLANs Enabled: 3780,3781',
                                                   'Trunking VLANs Enabled: ' + allowed.upper())
    target.query_override['show interfaces ' + PORT + ' switchport'] = answer
    target.query_override['show ip interface brief'] = target.query('show ip interface brief').replace('Vlan99', 'Loopback0')
    text = text.replace('interface Vlan99\n', 'interface Loopback0\n')
    target.query_override['show running-config'] = text
    return target


@pytest.mark.parametrize('before,after', [
    ('all', '1-98,100-4094'),
    ('all', '10-20'),
    ('10-20', '10-14,16-20'),
    ('10', '10,1002-1005'),
])
def test_trunk_allowed_changes_validate_only_added_vlans(before, after):
    target = trunk_precheck_target(before)
    text = target.query('show running-config')
    p = plan(request({'allowed-vlans': after}, impact=True), text)
    exec_ios.plan_prechecks(target, DEVICE, p, text)
    assert 'switchport trunk allowed vlan ' + after in p['commands']
    assert {q for q in target.queries if q.startswith('show vlan id ')} == {'show vlan id 3780'}
    assert not target.applied_blocks


@pytest.mark.parametrize('vid,exists', [('3781', True), ('3782', False)])
def test_trunk_new_allowed_vlan_still_requires_existence(vid, exists):
    target = trunk_precheck_target('3780')
    target.query_override['show vlan id 3782'] = fixture('vlan-missing.txt')
    text = target.query('show running-config')
    p = plan(request({'allowed-vlans': '3780,' + vid}, impact=True), text)
    if exists:
        exec_ios.plan_prechecks(target, DEVICE, p, text)
    else:
        with pytest.raises(Rejected) as caught:
            exec_ios.plan_prechecks(target, DEVICE, p, text)
        assert caught.value.reason_codes == ['vlan_missing']
    assert 'show vlan id ' + vid in target.queries


@pytest.mark.parametrize('request_id,undo', [
    ('req-forward', False), ('undo-0001', False),
    ('req-trusted-undo', True), ('undo-0001', True),
])
def test_missing_allowed_vlan_restored_only_with_trusted_undo(request_id, undo):
    target = trunk_precheck_target('3780')
    target.query_override['show vlan id 3782'] = fixture('vlan-missing.txt')
    text = target.query('show running-config')
    req = parse_request(request_bytes(table='vlan-membership', key=PORT, op='update',
                                      changes={'allowed-vlans': '3780,3782'},
                                      endpoint_impact=PORT, request_id=request_id))
    p = plan(req, text)
    if undo:
        exec_ios.plan_prechecks(target, DEVICE, p, text, undo=True)
        assert 'show vlan id 3782' not in target.queries
    else:
        with pytest.raises(Rejected) as caught:
            exec_ios.plan_prechecks(target, DEVICE, p, text)
        assert caught.value.reason_codes == ['vlan_missing']
    assert not target.applied_blocks


def test_trunk_carrying_management_vlan_stays_protected():
    target = Transport()
    target.query_override['show interfaces ' + PORT + ' switchport'] = fixture('switchport-trunk.txt').replace(
        'Trunking VLANs Enabled: 3780,3781', 'Trunking VLANs Enabled: ALL')
    text = port_snapshot('trunk.conf').replace(' switchport trunk allowed vlan 3780,3781\n', '')
    p = plan(request({'allowed-vlans': '1-98,100-4094'}, impact=True), text)
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(target, DEVICE, p, text)
    assert caught.value.reason_codes == ['port_management_vlan']


def test_router_image_refuses_membership():
    from fake_ios import fixture as c45
    router = FakeIos('iosv')
    text = c45('iosv', 'show-running-config__exec.txt')
    p = engine.build_plan('ios', text.encode(), request({'access-vlan': 10}, key=router.port, impact=True),
                          firmware='15.9(3)M12')
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(router, SimpleNamespace(platform='ios', firmware='15.9(3)M12'), p, text)
    assert caught.value.reason_codes == ['port_routed']


# ---- IOS-M003: VLAN lifecycle ----

def test_vlan_database_real_table_is_required_and_cut_or_refused_is_rejected():
    table = fixture('vlan-brief-before.txt')
    assert ios.vlan_database(table)['99'][0] == 'D-MGMT'
    assert ios.vlan_database(fixture('vlan-brief-created.txt'))['3781'] == ('netops-ios-switchports-voice', 'active')
    for text in (fixture('ro-denied.txt'), table[:table.index('1004')]):
        with pytest.raises(Rejected):
            ios.vlan_database(text)
    with pytest.raises(Rejected):
        plan(request({'name': 'netops-ios-switchports'}, table='vlan', key='3780', op='create'), fixture('baseline.conf'))


def test_vlan_lifecycle_and_inverse_use_separate_database_state():
    p = plan(request({'name': 'netops-ios-switchports'}, table='vlan', key='3780', op='create'))
    assert p['commands'] == ['configure terminal', 'vlan 3780', 'name netops-ios-switchports', 'end']
    assert p['inverse'] == ['configure terminal', 'no vlan 3780', 'end']
    text = baseline().replace('end\n', '! netops-vlan 3780 netops-ios-switchports active\nend\n')
    rename = plan(request({'name': 'netops-ios-switchports-renamed'}, table='vlan', key='3780'), text)
    assert rename['inverse'] == ['configure terminal', 'vlan 3780', 'name netops-ios-switchports', 'end']
    delete = plan(request(table='vlan', key='3780', op='delete'), text)
    assert delete['inverse'] == p['commands']
    assert exec_ios_vlan.COMPENSATING and 'recover' in exec_ios_vlan.RETURN_MECHANISM


def test_extended_vlan_rename_matches_measured_running_config_stanza():
    # IOSvL2 in VTP server mode shows an extended-range VLAN also as a vlan stanza (measured).
    created = ios.with_vlan_database(fixture('access-voice.full.conf'), fixture('vlan-brief-created.txt'))
    p = plan(request({'name': 'netops-ios-switchports-renamed'}, table='vlan', key='3780'), created)
    assert p['predicted']['before'] == {'name': 'netops-ios-switchports'}
    renamed = ios.with_vlan_database(fixture('vlan-renamed.full.conf'),
                                     fixture('vlan-brief-created.txt').replace('netops-ios-switchports      ', 'netops-ios-switchports-renamed'))
    assert engine.verify(p, renamed.encode())['result'] == 'match'


@pytest.mark.parametrize('key', ['1', '1002', '4095'])
def test_reserved_vlan_lifecycle_refused(key):
    with pytest.raises(Rejected):
        plan(request({'name': 'bad'}, table='vlan', key=key, op='create'))


def test_management_vlan_lifecycle_refused():
    target = Transport()
    text = baseline()
    p = plan(request({'name': 'renamed'}, table='vlan', key='99'), text)
    with pytest.raises(Rejected) as caught:
        exec_ios_vlan.plan_prechecks(target, DEVICE, p, text)
    assert caught.value.reason_codes == ['port_management_vlan']


def test_used_vlan_cannot_be_deleted():
    text = baseline().replace('end\n', '! netops-vlan 3780 netops-ios-switchports active\nend\n').replace(
        'interface GigabitEthernet1/0\n switchport mode access\n',
        'interface GigabitEthernet1/0\n switchport access vlan 3780\n switchport mode access\n')
    with pytest.raises(Rejected, match='referenced'):
        plan(request(table='vlan', key='3780', op='delete'), text)


def test_vlan_check_account_reads_real_database_and_refuses_bad_table():
    target = Transport()
    target.check_override['show vlan brief'] = fixture('vlan-brief-before.txt')
    p = plan(request({'name': 'netops-ios-switchports'}, table='vlan', key='3780', op='create'))
    assert exec_ios_vlan.observe(target, p) is None
    target.check_override['show vlan brief'] = fixture('vlan-brief-created.txt')
    assert exec_ios_vlan.observe(target, p) == {'name': 'netops-ios-switchports'}
    target.check_override['show vlan brief'] = fixture('ro-denied.txt')
    with pytest.raises(Rejected):
        exec_ios_vlan.observe(target, p)


@pytest.mark.parametrize('allowed', ['', ' switchport trunk allowed vlan all\n'])
@pytest.mark.parametrize('op', ['create', 'update', 'delete'])
def test_vlan_lifecycle_with_default_all_trunk(op, allowed):
    # XE-SWITCHPORTS review lesson: an ordinary uplink with the default allowed set never blocks the VLAN lifecycle.
    text = baseline().replace('interface GigabitEthernet0/1\n switchport trunk allowed vlan 10,20\n',
                              'interface GigabitEthernet0/1\n' + allowed)
    if op != 'create':
        text = text.replace('end\n', '! netops-vlan 3780 netops-ios-switchports active\nend\n')
    target = Transport()
    p = plan(request({} if op == 'delete' else {'name': 'renamed'}, table='vlan', key='3780', op=op), text)
    exec_ios_vlan.plan_prechecks(target, DEVICE, p, text)
    assert p['commands'] and p['inverse']
    assert not target.applied_blocks


@pytest.mark.parametrize('reference', ['switchport access vlan 3780', 'switchport voice vlan 3780',
                                       'switchport trunk native vlan 3780', 'switchport trunk allowed vlan 3780-3781'])
def test_vlan_lifecycle_keeps_explicit_references(reference):
    text = baseline().replace('interface GigabitEthernet1/1\n', 'interface GigabitEthernet1/1\n switchport mode trunk\n '
                              + reference + '\n')
    target = Transport()
    p = plan(request({'name': 'unused'}, table='vlan', key='3780', op='create'))
    with pytest.raises(Rejected, match='used by an interface or trunk'):
        exec_ios_vlan.plan_prechecks(target, DEVICE, p, text)


def test_vlan_lifecycle_refuses_unreadable_dynamic_port_usage():
    target = Transport()
    target.query_override['show interfaces GigabitEthernet1/1 switchport'] = fixture('ro-denied.txt')
    p = plan(request({'name': 'netops-ios-switchports'}, table='vlan', key='3780', op='create'))
    with pytest.raises(Rejected):
        exec_ios_vlan.plan_prechecks(target, DEVICE, p, baseline())


def test_vlan_lifecycle_refused_on_router_image():
    router = FakeIos('iosv')
    p = plan(request({'name': 'netops-ios-switchports'}, table='vlan', key='3780', op='create'))
    with pytest.raises(Rejected) as caught:
        exec_ios_vlan.plan_prechecks(router, DEVICE, p, baseline())
    assert caught.value.reason_codes == ['port_routed']


class VlanTransport(FakeIos):
    """Replay the measured IOSvL2 VLAN table layout and config-mode lifecycle (vlan/name/no vlan)."""
    def __init__(self):
        super().__init__('iosvl2')
        self.database = {vid: (name, status) for vid, name, status in (
            ('1', 'default', 'active'), ('10', 'D10', 'active'), ('20', 'D20', 'active'), ('99', 'D-MGMT', 'active'),
            ('1002', 'fddi-default', 'act/unsup'), ('1003', 'token-ring-default', 'act/unsup'),
            ('1004', 'fddinet-default', 'act/unsup'), ('1005', 'trnet-default', 'act/unsup'))}

    def snapshot(self):
        raw = super().snapshot()
        rows = ''.join('! netops-vlan %s %s %s\n' % (vid, *self.database[vid]) for vid in sorted(self.database, key=int))
        return raw.rsplit('end', 1)[0] + '! netops-vlan-database\n' + rows + 'end\n'

    def _line(self, line, mode):
        if line.startswith('vlan ') and mode[0] == 'config':
            key = line.split()[1]
            self.database.setdefault(key, ('VLAN' + key.zfill(4), 'active'))
            mode[0] = 'vlan:' + key
            return ''
        if line.startswith('no vlan ') and mode[0] == 'config':
            self.database.pop(line.split()[2], None)
            return ''
        if line.startswith('name ') and mode[0].startswith('vlan:'):
            self.database[mode[0][5:]] = (line[5:], 'active')
            return ''
        return super()._line(line, mode)

    def check_query(self, command):
        if command == 'show vlan brief':
            self.check_queries.append(command)
            if self.check_override and command in self.check_override:
                return self.check_override[command]
            text = fixture('vlan-brief-before.txt')
            if '730' in self.database:
                measured = next(line for line in fixture('vlan-brief-created.txt').splitlines() if line.startswith('3780 '))
                name = self.database['730'][0]
                added = '730 ' + measured[4:].replace('netops-ios-switchports', name.ljust(len('netops-ios-switchports')), 1)
                text = text.rstrip('\n') + '\n' + added + '\n'
            return text
        return super().check_query(command)


def test_vlan_lifecycle_runs_preview_apply_readback_undo_and_compensation(tmp_path):
    from netops_admin import execute
    from test_ios import make_runtime
    target = VlanTransport()
    runtime = make_runtime(tmp_path, target)
    req = request({'name': 'netops-ios-switchports'}, table='vlan', key='730', op='create')
    preview = execute.preview(runtime, 'lab-ios', req)
    assert preview['result'] == 'ready', preview
    assert 'recover' in preview['return_mechanism']
    assert not target.applied_blocks
    result = execute.apply(runtime, 'lab-ios', req, expected_plan_sha256=preview['plan_sha256'])
    assert result['result'] == 'confirmed', result
    assert target.database['730'] == ('netops-ios-switchports', 'active')
    assert not any('revert timer' in line for line in target.sent_lines)
    assert 'show vlan brief' in target.check_queries
    undo = execute.undo(runtime, result['change_id'], 'return unused lab VLAN')
    assert undo['result'] == 'confirmed', undo
    assert '730' not in target.database


def test_vlan_readback_failure_writes_inverse_and_verifies_return(tmp_path):
    from netops_admin import execute
    from test_ios import make_runtime
    target = VlanTransport()
    runtime = make_runtime(tmp_path, target)

    def unavailable_after_write(device, commands):
        if 'vlan 730' in commands:
            device.check_override = {'show vlan brief': fixture('ro-denied.txt')}
    target.on_apply = unavailable_after_write
    result = approved_apply(runtime, 'lab-ios', request({'name': 'netops-ios-switchports'}, table='vlan', key='730', op='create'))
    assert result['result'] == 'reverted', result
    assert '730' not in target.database
    assert 'no vlan 730' in target.sent_lines


@pytest.mark.parametrize('listing', [None, 'ro-denied.txt', 'vlan-missing.txt'])
def test_real_device_access_collects_database_separately_and_refuses_incomplete_source(listing):
    from netops_admin.access import DeviceAccess
    target = object.__new__(DeviceAccess)
    target.device = SimpleNamespace(platform='ios')
    target.credential = object()
    calls = []

    def transport(credential, command):
        calls.append(command)
        if command == 'show running-config':
            return fixture('baseline.conf')
        assert command == 'show vlan brief'
        return fixture(listing or 'vlan-brief-before.txt')
    target._query = transport
    if listing is not None:
        with pytest.raises(Rejected):
            target.snapshot()
    else:
        snapshot = ios.load(target.snapshot(), FW)
        assert snapshot.entries('vlan')['10'].attributes == {'name': 'D10'}
        assert snapshot.entries('vlan')['99'].attributes == {'name': 'D-MGMT'}
    assert calls == ['show running-config', 'show vlan brief']


def test_measurement_was_returned_to_the_baseline():
    operations = json.loads(fixture('operations.json'))
    final = operations[-1]
    assert final['restored'] and final['vlan_db_match']
    assert final['before_sha256'] == final['after_sha256']
    assert final['port'] == ['switchport mode access', 'shutdown', 'negotiation auto']
    assert 'No changes were found' in final['startup_running']
