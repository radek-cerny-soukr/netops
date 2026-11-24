"""XE-SWITCHPORTS plans and guards over real anonymized IOL-L2 17.18.2 answers through fake transport.

The fixtures were captured with independent CLI sessions, not produced by the adapter/prediction under test.
"""
import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import request_bytes
from fake_ios import FakeIos
from netops_admin import engine, exec_ios, exec_ios_vlan, ios
from netops_admin.errors import Rejected, SnapshotRejected
from netops_admin.request import parse_request
from approved_apply import approved_apply

F = Path(__file__).parent / 'fixtures' / 'ios_xe_switchports'
PORT = 'Ethernet0/1'
FW = '17.18.2'

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
    return engine.build_plan('iosxe', (text or baseline()).encode(), req, firmware=FW)


class Transport(FakeIos):
    """Normal fake transport plus exact measured answers for independent XE-SWITCHPORTS reads."""
    def __init__(self):
        super().__init__('iolxe-l2')
        self.vlans |= {'3780', '3781'}
        self.query_override['show mac address-table interface ' + PORT] = fixture('occupied-mac.txt')
        self.check_override = {'show interfaces ' + PORT + ' switchport': fixture('switchport-before.txt')}


def test_occupied_port_requires_explicit_impact_and_acknowledgement_is_bound():
    target = Transport()
    req = request({'access-vlan': 3780})
    p = plan(req)
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(target, SimpleNamespace(platform='iosxe',firmware=FW), p, baseline())
    assert caught.value.reason_codes == ['port_learned_mac']
    acknowledged = plan(request({'access-vlan':3780}, impact=True))
    exec_ios.plan_prechecks(target, SimpleNamespace(platform='iosxe',firmware=FW), acknowledged, baseline())
    assert acknowledged['plan_sha256'] != p['plan_sha256']
    assert any('phone' in check and 'interrupted' in check for check in acknowledged['prechecks'])
    forged = copy.deepcopy(acknowledged)
    del forged['endpoint_impact']
    with pytest.raises(Rejected):
        engine._read_plan(forged)


@pytest.mark.parametrize('impact',[True, 1, 'Ethernet0/2', 'yes'])
def test_impact_must_name_exact_port(impact):
    with pytest.raises(Rejected):
        parse_request(request_bytes(table='interface',key=PORT,endpoint_impact=impact))


@pytest.mark.parametrize('command', ['show lldp neighbors','show cdp neighbors','show mac address-table interface '+PORT])
def test_impact_never_waives_unreadable_usage(command):
    target=Transport()
    target.query_override[command] = fixture('ro-denied.txt')
    p=plan(request({'access-vlan':3780},impact=True))
    with pytest.raises(Rejected):
        exec_ios.plan_prechecks(target,SimpleNamespace(platform='iosxe',firmware=FW),p,baseline())


@pytest.mark.parametrize('key,code', [('Ethernet0/0','port_management_vlan')])
def test_management_protection_cannot_be_confirmed_away(key,code):
    target=Transport()
    p=plan(request({'admin-state':'disabled'},table='interface',key=key,impact=True))
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(target,SimpleNamespace(platform='iosxe',firmware=FW),p,baseline())
    assert caught.value.reason_codes == [code]


def test_voice_plan_renders_real_measured_command_and_independent_check():
    p=plan(request({'voice-vlan':3781},impact=True))
    assert p['commands'] == ['configure terminal','interface '+PORT,'switchport voice vlan 3781','end']
    assert p['inverse'] == ['configure terminal','interface '+PORT,'no switchport voice vlan','end']
    target=Transport()
    target.check_override['show interfaces '+PORT+' switchport']=fixture('switchport-voice.txt')
    state=exec_ios.observe(target,p)
    assert state['voice-vlan']=='3781' and state['access-vlan']=='3780'
    assert engine.observed_state(p,state)['voice-vlan']=='3781'


def test_full_trunk_plan_has_dot1q_before_mode_and_canonical_allowed_set():
    p=plan(request({'mode':'trunk','trunk-encapsulation':'dot1q','allowed-vlans':'3781,3780','native-vlan':3780},impact=True))
    assert p['commands'].index('switchport trunk encapsulation dot1q') < p['commands'].index('switchport mode trunk')
    assert 'switchport trunk allowed vlan 3780-3781' in p['commands']
    assert 'switchport trunk native vlan 3780' in p['commands']
    assert 'switchport mode access' in p['inverse']


def test_trunk_requires_explicit_impact_and_encapsulation():
    with pytest.raises(Rejected,match='dot1q'):
        plan(request({'mode':'trunk'},impact=True))
    target=Transport()
    p=plan(request({'mode':'trunk','trunk-encapsulation':'dot1q','allowed-vlans':'3780'}))
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(target,SimpleNamespace(platform='iosxe',firmware=FW),p,baseline())
    assert caught.value.reason_codes == ['endpoint_impact_required']


@pytest.mark.parametrize('value',['0','4095','20-10','10,,20','10;end','all\nend'])
def test_bad_allowed_lists_refused(value):
    with pytest.raises(Rejected):
        plan(request({'allowed-vlans':value},impact=True))


@pytest.mark.parametrize('name',['switchport-before.txt','switchport-voice.txt','switchport-trunk.txt'])
def test_independent_switchport_refused_or_cut_output(name):
    text=fixture(name)
    assert ios.switchport_membership(text,PORT) is not None
    with pytest.raises(Rejected):
        ios.switchport_membership(text.split('Voice VLAN:')[0],PORT)
    with pytest.raises(Rejected):
        ios.switchport_membership(fixture('ro-denied.txt'),PORT) or (_ for _ in ()).throw(Rejected(['refused']))


def test_real_command_rejected_is_an_error_even_without_percent_prefix():
    operations=json.loads(fixture('operations.json'))
    # First capture measured the encapsulation refusal; subsequent measured run uses dot1q.
    answer=fixture('trunk-auto-refused.txt')
    assert ios.cli_error(answer).startswith('Command rejected')


def test_vlan_database_real_table_is_required_and_cut_or_refused_is_rejected():
    table=fixture('vlan-brief-before.txt')
    assert ios.vlan_database(table)['99'][0]=='D-MGMT'
    for text in (fixture('ro-denied.txt'),table[:table.index('1004')]):
        with pytest.raises(Rejected):
            ios.vlan_database(text)
    with pytest.raises(Rejected):
        plan(request({'name':'netops-xe-switchports'},table='vlan',key='3780',op='create'),fixture('baseline.conf'))


def test_vlan_lifecycle_and_inverse_use_separate_database_state():
    p=plan(request({'name':'netops-xe-switchports'},table='vlan',key='3780',op='create'))
    assert p['commands']==['configure terminal','vlan 3780','name netops-xe-switchports','end']
    assert p['inverse']==['configure terminal','no vlan 3780','end']
    text=baseline().replace('end\n','! netops-vlan 3780 netops-xe-switchports active\nend\n')
    rename=plan(request({'name':'netops-xe-switchports-renamed'},table='vlan',key='3780'),text)
    assert rename['inverse']==['configure terminal','vlan 3780','name netops-xe-switchports','end']
    delete=plan(request(table='vlan',key='3780',op='delete'),text)
    assert delete['inverse']==p['commands']
    assert exec_ios_vlan.COMPENSATING and 'recover' in exec_ios_vlan.RETURN_MECHANISM


@pytest.mark.parametrize('key',['1','1002','4095'])
def test_reserved_vlan_lifecycle_refused(key):
    with pytest.raises(Rejected):
        plan(request({'name':'bad'},table='vlan',key=key,op='create'))


def test_used_vlan_cannot_be_deleted():
    text=baseline().replace('end\n','! netops-vlan 3780 netops-xe-switchports active\nend\n').replace(' switchport mode access\n shutdown',' switchport access vlan 3780\n switchport mode access\n shutdown')
    with pytest.raises(Rejected,match='referenced'):
        plan(request(table='vlan',key='3780',op='delete'),text)


def test_vlan_check_account_reads_real_database_and_refuses_bad_table():
    target=Transport()
    target.check_override['show vlan brief']=fixture('vlan-brief-before.txt')
    p=plan(request({'name':'netops-xe-switchports'},table='vlan',key='3780',op='create'))
    assert exec_ios_vlan.observe(target,p) is None
    target.check_override['show vlan brief']=fixture('ro-denied.txt')
    with pytest.raises(Rejected):exec_ios_vlan.observe(target,p)


def port_snapshot(name):
    """Replay the real interface stanza in the real baseline; unrelated configuration stays constant."""
    import re
    measured = fixture(name)
    stanza = measured[measured.index('interface '+PORT):measured.rindex('end')].rstrip()
    return re.sub(r'interface Ethernet0/1\n(?: [^\n]*\n)*',stanza+'\n',baseline())


@pytest.mark.parametrize('name,changes',[
 ('access-voice.conf',{'access-vlan':3780,'voice-vlan':3781}),
 ('trunk.conf',{'access-vlan':3780,'mode':'trunk','trunk-encapsulation':'dot1q','native-vlan':3780,'allowed-vlans':'3780,3781'}),
 ('trunk-removed.conf',{'access-vlan':3780,'mode':'trunk','trunk-encapsulation':'dot1q','native-vlan':3780,'allowed-vlans':'3780'}),
])
def test_planned_membership_matches_independently_captured_running_stanza(name,changes):
    # Fixture measurement enabled the port in the same session; hold admin state constant for this table.
    before=baseline().replace('interface Ethernet0/1\n switchport mode access\n shutdown\n',
                              'interface Ethernet0/1\n switchport mode access\n')
    p=plan(request(changes,impact=True),before)
    verdict=engine.verify(p,port_snapshot(name).encode())
    assert verdict['result']=='match',verdict
    assert engine.verify(p,before.encode(),expect='before')['result']=='match'


def test_allowed_vlan_remove_has_exact_inverse_and_readback():
    before=port_snapshot('trunk.conf')
    p=plan(request({'allowed-vlans':'3780'},impact=True),before)
    assert 'switchport trunk allowed vlan 3780' in p['commands']
    assert 'switchport trunk allowed vlan 3780-3781' in p['inverse']
    assert engine.verify(p,port_snapshot('trunk-removed.conf').encode())['result']=='match'


class VlanTransport(FakeIos):
    """Replay measured VLAN table layout and config-mode lifecycle; no production renderer in fake device."""
    def __init__(self):
        super().__init__('iolxe-l2')
        self.database={vid:(name,status) for vid,name,status in (
            ('1','default','active'),('10','D10','active'),('20','D20','active'),('99','D-MGMT','active'),
            ('1002','fddi-default','act/unsup'),('1003','token-ring-default','act/unsup'),
            ('1004','fddinet-default','act/unsup'),('1005','trnet-default','act/unsup'))}

    def snapshot(self):
        raw=super().snapshot()
        marker='! netops-vlan-database\n'
        rows=''.join('! netops-vlan %s %s %s\n'%(vid,*self.database[vid]) for vid in sorted(self.database,key=int))
        return raw.rsplit('end',1)[0]+marker+rows+'end\n'

    def _line(self,line,mode):
        if line.startswith('vlan ') and mode[0]=='config':
            key=line.split()[1]
            self.database.setdefault(key,('VLAN'+key.zfill(4),'active'))
            mode[0]='vlan:'+key
            return ''
        if line.startswith('no vlan ') and mode[0]=='config':
            self.database.pop(line.split()[2],None)
            return ''
        if line.startswith('name ') and mode[0].startswith('vlan:'):
            self.database[mode[0][5:]]=(line[5:],'active')
            return ''
        return super()._line(line,mode)

    def check_query(self,command):
        if command=='show vlan brief':
            self.check_queries.append(command)
            if self.check_override and command in self.check_override:
                return self.check_override[command]
            # Reuse the real table, insert the sole test VLAN using its measured row layout.
            text=fixture('vlan-brief-before.txt')
            if '730' in self.database:
                row=fixture('vlan-created.txt').splitlines()
                measured=next(line for line in row if line.startswith('3780 '))
                old=self.database['730'][0]
                added=measured.replace('3780','730 ',1).replace('netops-xe-switchports',old).split('active')[0]+'active\n'
                text=text[:text.index('1002 ')]+added+text[text.index('1002 '):]
            return text
        return super().check_query(command)


def test_vlan_lifecycle_runs_preview_apply_readback_undo_and_compensation(tmp_path):
    from netops_admin import execute
    from test_ios import make_runtime
    target=VlanTransport()
    runtime=make_runtime(tmp_path,target)
    req=request({'name':'netops-xe-switchports'},table='vlan',key='730',op='create')
    preview=execute.preview(runtime,'lab-ios',req)
    assert preview['result']=='ready',preview
    assert 'recover' in preview['return_mechanism']
    assert not target.applied_blocks
    result=execute.apply(runtime,'lab-ios',req,expected_plan_sha256=preview['plan_sha256'])
    assert result['result']=='confirmed',result
    assert '730' in target.database
    assert not any('revert timer' in line for line in target.sent_lines)
    assert 'show vlan brief' in target.check_queries
    undo=execute.undo(runtime,result['change_id'],'return unused lab VLAN')
    assert undo['result']=='confirmed',undo
    assert '730' not in target.database


def test_vlan_readback_failure_writes_inverse_and_verifies_return(tmp_path):
    from netops_admin import execute
    from test_ios import make_runtime
    target=VlanTransport()
    runtime=make_runtime(tmp_path,target)
    def unavailable_after_write(device,commands):
        if 'vlan 730' in commands:
            device.check_override={'show vlan brief':fixture('ro-denied.txt')}
    target.on_apply=unavailable_after_write
    result=approved_apply(runtime,'lab-ios',request({'name':'netops-xe-switchports'},table='vlan',key='730',op='create'))
    assert result['result']=='reverted',result
    assert '730' not in target.database
    assert 'no vlan 730' in target.sent_lines


def test_voice_management_vlan_cannot_be_confirmed_away():
    target=Transport()
    target.query_override['show interfaces '+PORT+' switchport']=fixture('switchport-before.txt').replace('Voice VLAN: none','Voice VLAN: 99 (D-MGMT)')
    p=plan(request({'admin-state':'enabled'},table='interface',impact=True))
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(target,SimpleNamespace(platform='iosxe',firmware=FW),p,baseline())
    assert caught.value.reason_codes==['port_management_vlan']


def test_vlan_lifecycle_refuses_unreadable_dynamic_port_usage():
    target=VlanTransport()
    target.query_override['show interfaces Ethernet0/2 switchport']=fixture('ro-denied.txt')
    p=plan(request({'name':'netops-xe-switchports'},table='vlan',key='3780',op='create'))
    with pytest.raises(Rejected):
        exec_ios_vlan.plan_prechecks(target,SimpleNamespace(platform='iosxe',firmware=FW),p,baseline())


@pytest.mark.parametrize('listing',[None,'ro-denied.txt','vlan-missing.txt'])
def test_real_device_access_collects_database_separately_and_refuses_incomplete_source(listing):
    from netops_admin.access import DeviceAccess
    target=object.__new__(DeviceAccess)
    target.device=SimpleNamespace(platform='iosxe')
    target.credential=object()
    calls=[]
    def transport(credential,command):
        calls.append(command)
        if command=='show running-config':return fixture('baseline.conf')
        assert command=='show vlan brief'
        return fixture(listing or 'vlan-brief-before.txt')
    target._query=transport
    if listing is not None:
        with pytest.raises(Rejected):target.snapshot()
    else:
        snapshot=ios.load(target.snapshot(),FW)
        assert snapshot.entries('vlan')['10'].attributes=={'name':'D10'}
        assert snapshot.entries('vlan')['99'].attributes=={'name':'D-MGMT'}
    assert calls==['show running-config','show vlan brief']


@pytest.mark.parametrize('allowed', ['', ' switchport trunk allowed vlan all\n'])
@pytest.mark.parametrize('op', ['create', 'update', 'delete'])
def test_vlan_lifecycle_with_default_all_trunk(op, allowed):
    # Review reproduction: an ordinary uplink added to the measured baseline.
    text = baseline().replace('interface Ethernet0/3\n shutdown\n',
        'interface Ethernet0/3\n switchport mode trunk\n' + allowed + ' shutdown\n')
    if op != 'create':
        text = text.replace('end\n', '! netops-vlan 3780 netops-xe-switchports active\nend\n')
    target = Transport()
    target.query_override['show running-config'] = text
    p = plan(request({} if op == 'delete' else {'name': 'renamed'},
                     table='vlan', key='3780', op=op), target.query('show running-config'))
    exec_ios_vlan.plan_prechecks(target, SimpleNamespace(platform='iosxe', firmware=FW), p, text)
    assert p['commands'] and p['inverse']
    assert not target.applied_blocks


@pytest.mark.parametrize('reference', [
    'switchport access vlan 3780', 'switchport voice vlan 3780',
    'switchport trunk native vlan 3780', 'switchport trunk allowed vlan 3780-3781',
])
def test_vlan_lifecycle_keeps_explicit_trunk_references(reference):
    text = baseline().replace('interface Ethernet0/3\n shutdown\n',
        'interface Ethernet0/3\n switchport mode trunk\n ' + reference + '\n shutdown\n')
    target = Transport()
    p = plan(request({'name': 'unused'}, table='vlan', key='3780', op='create'))
    with pytest.raises(Rejected, match='used by an interface or trunk'):
        exec_ios_vlan.plan_prechecks(target, SimpleNamespace(platform='iosxe', firmware=FW), p, text)


def trunk_precheck_target(allowed, routed_management=True):
    """Measured switchport/config answers, varying only the scenario's VLAN list and management interface."""
    target = Transport()
    text = port_snapshot('trunk.conf').replace(' switchport trunk allowed vlan 3780,3781\n',
        '' if allowed == 'all' else ' switchport trunk allowed vlan ' + allowed + '\n')
    answer = fixture('switchport-trunk.txt').replace('Trunking VLANs Enabled: 3780,3781',
                                                   'Trunking VLANs Enabled: ' + allowed.upper())
    target.query_override['show interfaces ' + PORT + ' switchport'] = answer
    if routed_management:
        # all includes every SVI: use out-of-band routed management for this valid scenario.
        command = 'show ip interface brief'
        target.query_override[command] = target.query(command).replace('Vlan99', 'Loopback0')
        text = text.replace('interface Vlan99\n', 'interface Loopback0\n')
    target.query_override['show running-config'] = text
    return target


@pytest.mark.parametrize('before,after', [
    ('all', '1-99,101-4094'),  # remove 100 from default all, including reserved and missing VLANs
    ('all', '10-20'),         # retained range with holes in the VLAN database
    ('10-20', '10-14,16-20'), # remove a VLAN from a sparse explicit range
    ('10', '10,1002-1005'),   # reserved VLANs are valid in allowed sets
])
def test_trunk_allowed_changes_validate_only_added_vlans(before, after):
    target = trunk_precheck_target(before)
    text = target.query('show running-config')
    p = plan(request({'allowed-vlans': after}, impact=True), text)
    exec_ios.plan_prechecks(target, SimpleNamespace(platform='iosxe', firmware=FW), p, text)
    assert 'switchport trunk allowed vlan ' + after in p['commands']
    assert 'switchport trunk allowed vlan ' + before in p['inverse'] or (
        before == 'all' and 'no switchport trunk allowed vlan' in p['inverse'])
    assert {q for q in target.queries if q.startswith('show vlan id ')} == {'show vlan id 3780'}
    assert not target.applied_blocks


@pytest.mark.parametrize('vid,exists', [('3781', True), ('15', False)])
def test_trunk_new_allowed_vlan_still_requires_existence(vid, exists):
    target = trunk_precheck_target('3780')
    text = target.query('show running-config')
    p = plan(request({'allowed-vlans': '3780,' + vid}, impact=True), text)
    if exists:
        exec_ios.plan_prechecks(target, SimpleNamespace(platform='iosxe', firmware=FW), p, text)
    else:
        with pytest.raises(Rejected) as caught:
            exec_ios.plan_prechecks(target, SimpleNamespace(platform='iosxe', firmware=FW), p, text)
        assert caught.value.reason_codes == ['vlan_missing']
    assert 'show vlan id ' + vid in target.queries


def test_default_all_trunk_management_guard_still_applies():
    target = trunk_precheck_target('all', routed_management=False)
    text = target.query('show running-config')
    p = plan(request({'allowed-vlans': '1-99,101-4094'}, impact=True), text)
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(target, SimpleNamespace(platform='iosxe', firmware=FW), p, text)
    assert caught.value.reason_codes == ['port_management_vlan']


def test_undo_restores_allowed_range_with_missing_vlan():
    # Live (verification): removing absent VLAN 100 from 1-98,100-4094 worked, its undo was refused vlan_missing.
    # Review: the exemption comes from the trusted undo context, never from a user-chosen request_id.
    target = trunk_precheck_target('1-98,101-4094')
    text = target.query('show running-config')
    device = SimpleNamespace(platform='iosxe', firmware=FW)
    for request_id, undo, ok in (('undo-3916a15d759813b4ee330a6a892257bb', True, True),
                                 ('req-0002-forward', False, False),
                                 ('undo-0001', False, False)):
        req = parse_request(request_bytes(table='vlan-membership', key=PORT, op='update',
                                          changes={'allowed-vlans': '1-98,100-4094'}, endpoint_impact=PORT,
                                          request_id=request_id))
        p = plan(req, text)
        if ok:
            exec_ios.plan_prechecks(target, device, p, text, undo=undo)
        else:
            with pytest.raises(Rejected) as caught:
                exec_ios.plan_prechecks(target, device, p, text, undo=undo)
            assert caught.value.reason_codes == ['vlan_missing']


def test_ordinary_request_with_undo_like_request_id_still_requires_vlan():
    # Review: request_id `undo-0001` chosen by the user must not skip the existence check.
    target = trunk_precheck_target('1-98,101-4094')
    text = target.query('show running-config')
    req = parse_request(request_bytes(table='vlan-membership', key=PORT, op='update',
                                      changes={'allowed-vlans': '1-98,100-4094'}, endpoint_impact=PORT,
                                      request_id='undo-0001'))
    with pytest.raises(Rejected) as caught:
        exec_ios.plan_prechecks(target, SimpleNamespace(platform='iosxe', firmware=FW), plan(req, text), text)
    assert caught.value.reason_codes == ['vlan_missing']
