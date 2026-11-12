"""A20 B1: all-VLAN configuration through projection and engine."""
import json
import pytest

from netops_helper import engine, port_vlan
from test_locate_acceptance_107 import forti_outputs, SERIALS, AP_IP, REAL
from review_replay_support import device, configure, locate, switch


@pytest.mark.parametrize('all_mode', ['enable', 'disable', 'missing_context'])
def test_allowed_vlans_all_survives_projection_and_respects_context(tmp_path, monkeypatch, all_mode):
    outputs = forti_outputs()
    config_command = 'show switch-controller managed-switch ' + SERIALS[0]
    outputs[config_command] = outputs[config_command].replace('set vlan "ap-mgmt"',
        'set vlan "ap-mgmt"\n                set allowed-vlans-all ' + ('disable' if all_mode == 'disable' else 'enable'), 1)
    # Synthetic FortiLink parent metadata; a VLAN on another parent must stay excluded.
    if all_mode != 'missing_context':
        outputs['show system interface'] = outputs['show system interface'].replace('set vlanid', 'set interface "fortilink"\n                set vlanid').replace(
            'edit "video"\n                set interface "fortilink"', 'edit "video"\n                set interface "other-fortilink"')
    gate = device('gate', 'fortinet', ['managed_switch_port_vlans', 'interface_vlan_ids'], managed_switches=list(SERIALS))
    proxy, code, _ = configure(tmp_path, monkeypatch, [gate], {'gate': outputs})
    # Keep test-scoped monkeypatch cleanup for the transport setup executed above.
    with monkeypatch.context() as scoped:
        for name in ('host_key_line', '_lane_directory', '_now', '_sleep'):
            scoped.setattr(engine, name, getattr(engine, name))
        scoped.setattr(engine.core_ssh, 'run_command', engine.core_ssh.run_command)
        result = switch(proxy, code, scoped, {'table': 'port_vlan', 'managed_switch': SERIALS[0], 'interface': 'port3'})
    assert result['status'] == 'ok', result
    row = result['records'][0]
    if all_mode == 'missing_context':
        assert port_vlan.membership(row, 4091)['carries_vlan'] is None
        assert 'allowed_vlans_all_context_missing' in result['warnings']
    else:
        assert port_vlan.membership(row, 4091)['carries_vlan'] is (all_mode == 'enable')
        assert port_vlan.membership(row, 4093)['tagging'] == 'untagged'
        assert port_vlan.membership(row, 4090)['carries_vlan'] is False
