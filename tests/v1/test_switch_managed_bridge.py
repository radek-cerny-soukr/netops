"""FortiLink selectors through the real Helper proxy, MCP worker and engine.

Only device transport is replaced. The snippets preserve the layout of the
2026-11-09 FortiGate-80F 8.0.2 build0251 read-only captures in Helper's real fixtures.
"""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from netops import worker
from netops.files import write_private
from netops_core.audit import Recorder
from netops_helper import audit as helper_audit, engine, proxy, server

SERIAL = 'S000SSSS00000001'
MAC = '''Vdom: root
Managed Switch : S000SSSS00000001 0
MAC: 00:00:5e:00:53:02 VLAN: 100 Port: port3(port-id 3)
  Flags: 0x00010441 [ hit dynamic src-hit native ]
MAC: 00:00:5e:00:53:05 VLAN: 4092 Port: internal(port-id 29)
  Flags: 0x00000030 [ static l3-lookup ]
Total Displayed: 2
'''
STATS = '''Vdom: root
S000SSSS00000001:
Port(port3) is HW Admin up, SW Admin up, line protocol is up
Interface Type is Serial Gigabit Media Independent Interface(SGMII/SerDes)
Address is 00:00:5E:00:53:03, None loopback
MTU 9216 bytes, Encapsulation IEEE 802.3/Ethernet-II
full-duplex, 1000 Mb/s, link type is auto
input  : 1743880420 bytes, 2188124 packets, 0 errors, 30 drops, 0 oversizes
         2176681 unicasts, 11428 multicasts, 15 broadcasts, 0 unknowns
output : 8958491778 bytes, 6778715 packets, 0 errors, 1 drops, 0 oversizes
         6711270 unicasts, 67397 multicasts, 48 broadcasts
0 fragments, 0 undersizes, 0 collisions, 0 jabbers
'''
PORT_CONFIG = '''config switch-controller managed-switch
    edit "S000SSSS00000001"
        config ports
            edit "port3"
                set vlan "ap-mgmt"
                set allowed-vlans "quarantine"
                set untagged-vlans "quarantine"
            next
        end
    next
end
'''
VLAN_CONFIG = '''config system interface
    edit "ap-mgmt"
        set vlanid 100
    next
    edit "quarantine"
        set vlanid 4093
    next
end
'''
ROUTE = '''Routing table for VRF=default(0)
Routing entry for 0.0.0.0/0
  Known via "static", distance 1, metric 0, best
  * vrf default(0) 192.0.2.1, via wan1, origin 2
  * vrf default(0) 198.51.100.121, via LTE-OP1, origin 2
  * vrf default(0) 203.0.113.129, via LTE-OP2, origin 2
'''
LLDP = '''Managed Switch : S000SSSS00000001 0
  Portname    Status   Device-name                 TTL   Capability  MED-type  Port-ID
  __________  _______  __________________________  ____  __________  ________  _______
  port1       Down     -                           -     -           -         -
  port2       Up       host03                     120   BR          Network   a
  port3       Up       host04                     120   BRWS        -         00:00:5e:00:53:02
'''


class ManagedSwitchBridge(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.state = Path(self.enterContext(tempfile.TemporaryDirectory()))
        helper = self.state / 'helper'
        helper.mkdir(mode=0o700)
        self.device = {'name': 'fw-a', 'platform': 'fortios', 'address': '192.0.2.10', 'port': 22,
                       'role': 'lab', 'credential': 'fixture-ro', 'host_key_fingerprint': 'SHA256:' + 'A' * 43,
                       'legacy_ssh': None, 'auditor': None, 'helper': {
                           'account_role': 'read-only', 'ssh_platform': 'fortios', 'device_types': ['firewall'],
                           'fortios_output_standard_verified': True,
                           'enabled_queries': ['system_status', 'managed_switch_mac', 'managed_switch_lldp'],
                           'read_inventory': {'managed_switches': [SERIAL]},
                           'rate_limit': {'requests': 60, 'window_seconds': 1},
                           'egress': {'addresses': ['192.0.2.10'], 'tcp_ports': [22], 'udp_ports': [],
                                      'tcp_port_ranges': [], 'udp_port_ranges': [], 'allow_icmp': False,
                                      'allow_dns': False, 'tls_server_names': []}}}
        self.inventory = helper / 'inventory.json'
        self.save_inventory()
        write_private(helper / 'vault.json', json.dumps({'version': 2, 'credentials': {
            'fixture-ro': {'kind': 'password', 'login': 'fixture-user', 'value': 'synthetic-managed-password-only'}}}).encode())
        self.enterContext(patch.object(worker, 'STATE', self.state))
        self.enterContext(patch.object(proxy, 'INVENTORY', self.inventory))
        self.enterContext(patch.object(helper_audit, '_RECORDER', Recorder(helper / 'operations.jsonl', 'helper')))
        self.read = self.enterContext(patch.object(engine, 'read_from_device', side_effect=self.device_read))
        self.bridge = worker.HelperBridge()
        self.descriptors = await self.bridge.tools(server.mcp)

    def save_inventory(self):
        write_private(self.inventory, json.dumps({'version': 2, 'devices': [self.device]}).encode(), replace=True)

    def device_read(self, auth, platform, command):
        self.assertEqual((auth.alias, platform), ('fw-a', 'fortinet'))
        return 0, {
            'get system status': 'Version: FortiGate-80F v8.0.2,build0251,260928 (GA.F)\n',
            'diagnose switch-controller switch-info port-stats ' + SERIAL: STATS,
            'diagnose switch-controller switch-info port-stats ' + SERIAL + ' port3': STATS,
            'show switch-controller managed-switch ' + SERIAL: PORT_CONFIG,
            'show system interface': VLAN_CONFIG,
            'get router info routing-table details 192.0.2.8': ROUTE,
            'get router info routing-table all': 'Routing table for VRF=default(0)\nS* 0.0.0.0/0 [1/0] via 192.0.2.1, wan1, 00:07:33, [1/0]\n',
            'diagnose switch-controller switch-info mac-table ' + SERIAL: MAC,
            'diagnose switch-controller switch-info lldp neighbors-summary ' + SERIAL: LLDP,
        }[command]

    async def call(self, table, **kwargs):
        return await self.bridge.call(server.mcp, 'switch_read', {'target': 'fw-a', 'table': table, **kwargs})

    async def test_descriptor_and_both_tables_round_trip(self):
        descriptor = next(d for d in self.descriptors if d['name'] == 'switch_read')
        self.assertIn('managed_switch', descriptor['inputSchema']['properties'])
        self.assertNotIn('auth_context', descriptor['inputSchema']['properties'])
        for table, expected in (('mac_entry', 'managed_switch_mac'), ('lldp_neighbor', 'managed_switch_lldp')):
            with self.subTest(table=table):
                self.read.reset_mock()
                result = await self.call(table, managed_switch=SERIAL)
                self.assertFalse(result['isError'], result)
                data = result['structuredContent']
                self.assertEqual(json.loads(result['content'][0]['text']), data)
                self.assertEqual((data['status'], data['managed_switch']), ('ok', SERIAL))
                self.assertEqual(len(data['records']), 2)
                self.assertEqual(data['sources'][0]['query'], expected)
                self.assertEqual(len(data['sources'][0]['content_sha256']), 64)
                self.assertEqual(self.read.call_count, 2)
                self.assertFalse(data['unparsed'])
        self.assertEqual(data['records'][1]['capabilities'], 'B,W,R,S')
        self.assertEqual(data['coverage']['missing_fields'], ['management_ip'])

    def enable_ports(self):
        self.device['helper']['enabled_queries'] += ['managed_switch_port_stats', 'managed_switch_port_vlans', 'interface_vlan_ids']
        self.device['helper']['read_inventory']['managed_switch_ports'] = ['port3']
        self.save_inventory()

    async def test_port_state_errors_and_configuration_through_mcp(self):
        self.enable_ports()
        for table in ('interface', 'interface_errors', 'port_vlan'):
            with self.subTest(table=table):
                result = await self.call(table, managed_switch=SERIAL, interface='port3')
                self.assertFalse(result['isError'], result)
                data = result['structuredContent']
                self.assertEqual(data['status'], 'ok')
                row = data['records'][0]
                if table == 'interface':
                    self.assertEqual((row['oper_status'], row['speed']), ('up','1000M'))
                elif table == 'interface_errors':
                    self.assertEqual((row['rx_errors'], row['discards_in'], row['discards_out']), (0,30,1))
                    self.assertIsNone(row['crc'])
                else:
                    self.assertEqual((row['native_vlan'], row['untagged_vlans'], row['source']), (100,[100,4093],'configuration'))
                    self.assertEqual(len(data['sources']), 2)
        for table in ('interface', 'interface_errors'):
            self.read.reset_mock()
            result = await self.call(table, managed_switch=SERIAL, interface='port4')
            self.assertTrue(result['isError'], result)
            self.read.assert_not_called()

    async def test_configuration_ssh_view_omits_unrelated_and_malformed_values(self):
        self.enable_ports()
        private = 'private-fixture-value-only'
        full = PORT_CONFIG.replace('set vlan "ap-mgmt"', 'set vlan "ap-mgmt"\n                set other-field "' + private + '"')
        with patch.object(engine, 'read_from_device', side_effect=lambda a,p,c:
                          (0, full) if c.startswith('show switch-controller') else self.device_read(a,p,c)):
            result = await self.bridge.call(server.mcp, 'ssh_read', {'target':'fw-a', 'platform':'fortinet',
                'query':'managed_switch_port_vlans', 'parameters':{'managed_switch':SERIAL}})
        self.assertFalse(result['isError'], result)
        self.assertNotIn(private, json.dumps(result))
        self.assertIn('set vlan',result['structuredContent']['untrusted_device_output'])
        malformed = PORT_CONFIG + 'malformed-' + private + '\n'
        with patch.object(engine, 'read_from_device', side_effect=lambda a,p,c:
                          (0, malformed) if c.startswith('show switch-controller') else self.device_read(a,p,c)):
            result = await self.call('port_vlan',managed_switch=SERIAL)
        self.assertNotIn(private,json.dumps(result))
        self.assertEqual(result['structuredContent']['status'],'unparsed')

    async def test_refused_configuration_returns_unsupported_with_reason(self):
        self.enable_ports()
        with patch.object(engine, 'read_from_device', side_effect=lambda a,p,c:
                          (0, 'Command fail. Return code -61\n') if c.startswith('show ') else self.device_read(a,p,c)):
            result = await self.call('port_vlan', managed_switch=SERIAL)
        self.assertFalse(result['isError'], result)
        data = result['structuredContent']
        self.assertEqual(data['status'],'unsupported')
        self.assertEqual(data['reason'],'managed_switch_configuration_not_readable')
        self.assertEqual(data['records'],[])

    async def test_route_lookup_and_whole_table_through_mcp(self):
        self.device['helper']['enabled_queries'] += ['route_lookup', 'routing_table']
        self.device['helper']['read_inventory']['addresses'] = ['192.0.2.8']
        self.save_inventory()
        result = await self.call('route', ip='192.0.2.8')
        self.assertFalse(result['isError'], result)
        self.assertEqual(len(result['structuredContent']['records']), 3)
        result = await self.call('route')
        self.assertFalse(result['isError'], result)
        self.assertEqual(result['structuredContent']['records'][0]['next_hop'], '192.0.2.1')
        self.read.reset_mock()
        result = await self.call('route', ip='192.0.2.9')
        self.assertTrue(result['isError'], result)
        self.read.assert_not_called()

    async def test_locate_managed_endpoint_includes_port_state_and_config_vlan(self):
        self.enable_ports()
        from netops_helper import endpoint_worker
        with patch.object(endpoint_worker, 'call', side_effect=lambda targets, endpoint, context:
                          engine._locate_endpoint_run(endpoint_worker.decode(targets, context), endpoint)):
            result = await self.bridge.call(server.mcp, 'locate_endpoint', {'targets':['fw-a'], 'endpoint':'00:00:5e:00:53:02'})
        self.assertFalse(result['isError'],result)
        data = result['structuredContent']
        row = data['findings'][0]
        self.assertEqual(row['interface']['oper_status'],'up')
        self.assertEqual(row['vlan_membership'],{'carries_vlan':True,'tagging':'untagged','source':'configuration'})

    async def test_unsupported_table_is_explained_without_device_access(self):
        result = await self.call('ospf_neighbor')
        data = result['structuredContent']
        self.assertEqual(data['status'], 'unsupported')
        self.assertEqual(data['data']['field'], 'table')
        self.assertIn('mac_entry', data['data']['supported_tables'])
        self.assertNotIn('ospf_neighbor', data['data']['supported_tables'])
        self.assertEqual(data['sources'], [])
        self.read.assert_not_called()

    async def test_mac_filter_and_empty_lldp_preserve_semantics(self):
        result = await self.call('mac_entry', managed_switch=SERIAL, vlan_id='100', mac='0000.5e00.5302', limit=1)
        data = result['structuredContent']
        self.assertEqual([(r['vlan_id'], r['port']) for r in data['records']], [(100, 'port3')])
        self.assertFalse(data['has_more'])
        with patch.object(engine, 'read_from_device', side_effect=lambda a, p, c: self.device_read(a, p, c)
                          if c == 'get system status' else (0, 'No LLDP neighbors found.\n')):
            result = await self.call('lldp_neighbor', managed_switch=SERIAL)
        self.assertEqual(result['structuredContent']['status'], 'empty')
        self.assertEqual(result['structuredContent']['records'], [])

    async def test_bad_unenrolled_and_disabled_serial_requests_never_read(self):
        for table in ('mac_entry', 'lldp_neighbor'):
            for selector in ({'managed_switch': ''}, {'managed_switch': SERIAL + ';show'},
                             {'managed_switch': 'S000SSSS00000002'}, {'managed_switch': 1}):
                with self.subTest(table=table, selector=selector):
                    self.read.reset_mock()
                    result = await self.call(table, **selector)
                    self.assertTrue(result['isError'], result)
                    refusal = json.loads(result['content'][0]['text'])
                    if selector.get('managed_switch') == 'S000SSSS00000002':
                        self.assertEqual((refusal['code'], refusal['data']['field']), (-32009, 'managed_switches'))
                    else:
                        self.assertEqual((refusal['code'], refusal['data']['field']), (-32602, 'managed_switch'))
                    self.read.assert_not_called()
        result = await self.call('neighbor_l3', managed_switch=SERIAL)
        self.assertTrue(result['isError'], result)
        self.read.assert_not_called()
        self.device['helper']['enabled_queries'] = ['system_status']
        self.save_inventory()
        result = await self.call('mac_entry', managed_switch=SERIAL)
        self.assertTrue(result['isError'], result)
        self.read.assert_not_called()

    async def test_without_serial_selects_local_mac_and_checks_local_lldp_permission(self):
        result = await self.call('mac_entry')
        self.assertFalse(result['isError'], result)
        self.assertEqual(result['structuredContent']['status'], 'not_applicable')
        self.assertEqual(result['structuredContent']['records'], [])
        self.read.assert_not_called()
        result = await self.call('lldp_neighbor')
        self.assertTrue(result['isError'], result)
        refusal = json.loads(result['content'][0]['text'])
        self.assertEqual((refusal['code'], refusal['data']['field']), (-32009, 'enabled_queries'))
        self.read.assert_not_called()

    async def test_enabled_local_lldp_uses_local_catalogue_command(self):
        self.device['helper']['enabled_queries'].append('lldp_summary')
        self.save_inventory()
        # Two anonymized rows of the 2026-11-10 80F local summary capture.
        output = ("0 port 'a' 13  mac 00:00:5e:00:53:12  chassis 00:00:5e:00:53:10 port 'port2' system 'S000SSSS00000001'\n"
                  "1 port 'b' 14  mac 00:00:5e:00:53:21  chassis 00:00:5e:00:53:20 port 'port1' system 'S000SSSS00000002'\n")
        def read(auth, profile, command):
            if command == 'get system status':
                return self.device_read(auth, profile, command)
            self.assertEqual(command, 'diagnose lldp rx neighbor summary')
            return 0, output
        with patch.object(engine, 'read_from_device', side_effect=read) as transport:
            result = await self.call('lldp_neighbor')
        self.assertFalse(result['isError'], result)
        data = result['structuredContent']
        self.assertEqual(data['status'], 'ok')
        self.assertEqual([row['local_port'] for row in data['records']], ['a', 'b'])
        self.assertEqual(data['sources'][0]['query'], 'lldp_summary')
        self.assertEqual([call.args[2] for call in transport.call_args_list],
                         ['get system status', 'diagnose lldp rx neighbor summary'])


if __name__ == '__main__':
    unittest.main()
