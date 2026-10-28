from dataclasses import replace
from unittest import TestCase, mock
import json
import unittest

from netops_helper import engine
from netops_helper.auth import TargetAuth, EgressPolicy

A = 'CANARY-old-42'
B = 'CANARY-new-43'

def fixture(status, secret):
    return ('config system interface\n edit "port1"\n set status ' + status +
            '\n set password "' + secret + '"\n set x-unlisted-attr "shortK4"\n next\nend\n')

STATUS = ('Version: FortiGate-VM64-KVM v7.6.7,build3658,260101 (GA)\n'
          'Virtual domain configuration: disable\nCurrent virtual domain: root\n')

def reading(*outputs, status=STATUS, rc=0, identity_rc=0):
    values = iter(outputs)
    def wire(auth, platform, command, **kwargs):
        if command == 'get system status':
            return identity_rc, status
        if command in ('show system interface', 'show'):
            output = next(values)
            if 'stdout_consumer' in kwargs:
                kwargs['stdout_consumer'](output.encode())
                return rc, ''
            return rc, output
        raise AssertionError('unexpected device command')
    return wire

def enrolled(rights=('read', 'compare')):
    return TargetAuth(alias='fixture', host='192.0.2.20', port=22, login='reader',
                      secret='auth-canary-91', host_key_fingerprint='SHA256:fixture',
                      ssh_platform='fortinet', enabled_queries=('system_status',),
                      fortios_output_standard_verified=True,
                      read_inventory={'config_access': rights},
                      egress=EgressPolicy(addresses=('192.0.2.20',), tcp_ports=(22,)))

class ConfigurationBlock(TestCase):
    def setUp(self):
        self.assertTrue(callable(getattr(engine, 'config_read', None)), 'H1_MISSING_CONFIG_READ')
        self.assertTrue(callable(getattr(engine, 'config_diff', None)), 'H1_MISSING_CONFIG_DIFF')
        import inspect
        self.assertIn('section', inspect.signature(engine.config_read).parameters, 'H1_REQUIRED_SECTION_MISSING')
        self.audit = mock.patch.object(engine, 'record')
        self.events = self.audit.start()
        self.addCleanup(self.audit.stop)

    def test_positive_read_redact_compare_block(self):
        auth = enrolled()
        with mock.patch.object(engine, 'read_from_device',
                               side_effect=reading(fixture('up', A), fixture('down', B))) as wire:
            first = engine.config_read(auth, 'fortios', 'system interface')
            second = engine.config_read(auth, 'fortios', 'system interface')
            diff = engine.config_diff(auth, 'fortios', first['snapshot_id'], second['snapshot_id'])
            self.assertEqual(wire.call_args_list, [mock.call(auth, 'fortinet', 'get system status'), mock.call(auth, 'fortinet', 'show system interface', stdout_consumer=mock.ANY)] * 2)
        self.assertNotEqual(first['snapshot_id'], second['snapshot_id'])
        self.assertFalse(diff['identical'])
        self.assertIn('-    set status up', diff['untrusted_device_output'])
        self.assertIn('+    set status down', diff['untrusted_device_output'])
        rendered = json.dumps([first, second, diff], default=str) + repr(self.events.call_args_list)
        from netops_helper import configuration
        rendered += repr(configuration._SNAPSHOTS)
        for value in (A, B, auth.secret, 'port1', 'shortK4'):
            self.assertNotIn(value, rendered, 'H1_SECRET_LEAK')
        self.assertTrue(diff['secrets_changed'])
        with mock.patch.object(engine, 'read_from_device', side_effect=reading(fixture('down', B))):
            third = engine.config_read(auth, 'fortios', 'system interface')
        self.assertTrue(engine.config_diff(auth, 'fortios', second['snapshot_id'],
                                          third['snapshot_id'])['identical'])
        with mock.patch.object(engine, 'read_from_device', side_effect=reading(fixture('down', A))):
            fourth = engine.config_read(auth, 'fortios', 'system interface')
        secret_diff = engine.config_diff(auth, 'fortios', third['snapshot_id'], fourth['snapshot_id'])
        self.assertFalse(secret_diff['identical'])
        self.assertEqual(secret_diff['untrusted_device_output'], '')
        self.assertTrue(secret_diff['secrets_changed'])

    def test_inventory_proxy_mcp_block(self):
        import asyncio
        from base64 import b64encode
        from types import SimpleNamespace
        from fastmcp import Client
        from netops_core.hostkey import fingerprint_of
        from netops_helper import inventory, proxy, server
        pin = fingerprint_of(b64encode(b"fixture-host-key").decode())
        entry = SimpleNamespace(credential='fixture-account', name='fixture', address='192.0.2.20', port=22,
                                host_key_fingerprint=pin, legacy_ssh=None,
                                helper={'account_role': 'read-only', 'ssh_platform': 'fortios',
                                        'enabled_queries': ['system_status'],
                                        'fortios_output_standard_verified': True,
                                        'read_inventory': {'config_access': ['read', 'compare']},
                                        'egress': {'addresses': ['192.0.2.20'], 'tcp_ports': [22],
                                                   'udp_ports': [], 'tcp_port_ranges': [],
                                                   'udp_port_ranges': [], 'allow_icmp': False,
                                                   'allow_dns': False, 'tls_server_names': []}})
        section = inventory.section(entry)
        gateway = proxy.Proxy()
        credential = SimpleNamespace(login='reader', kind='password', use=lambda: 'auth-canary-91')
        envelope = gateway._auth_context(entry, section, credential, None, 'config_read')
        auth = TargetAuth.decode('fixture', envelope)
        self.assertEqual(auth.read_inventory['config_access'], ('read', 'compare'))
        args = gateway._validate_tool_arguments('config_read',
                                                 {'target': 'fixture', 'platform': 'fortios', 'section': 'system interface'})
        gateway._authorize_tool('config_read', args, entry, section)

        for tool, arguments, minimum in (
                ('config_read', args, 660),
                ('config_diff', {'target':'fixture','platform':'fortios',
                    'base_snapshot':'cfg_'+'a'*32,'other_snapshot':'cfg_'+'b'*32},660),
                ('ssh_read', {'target':'fixture','platform':'fortios','query':'system_status'},300)):
            relay=proxy.Proxy()
            with mock.patch.object(relay,'_target',return_value=(entry,section,None)),mock.patch.object(
                    relay,'_credential',return_value=credential),mock.patch.object(
                    relay,'_consume_rate_limit'),mock.patch.object(proxy.time,'monotonic',return_value=100):
                forwarded=relay.request(json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/call',
                    'params':{'name':tool,'arguments':dict(arguments)}}).encode())
            self.assertIsNotNone(forwarded)
            self.assertGreaterEqual(relay.pending_deadlines[1]-100,minimum,
                                    'H1_PROXY_DEADLINE_SHORTER_THAN_CAPTURE')
            if tool=='ssh_read':
                self.assertEqual(relay.pending_deadlines[1]-100,300)

        async def calls():
            async with Client(server.mcp) as client:
                tools = await client.list_tools()
                self.assertIn('config_read', [tool.name for tool in tools])
                captures = []
                for unused in range(2):
                    result = await client.call_tool('config_read', dict(args, auth_context=envelope))
                    self.assertFalse(result.is_error)
                    captures.append(result.data)
                page_args = dict(args, snapshot_id=captures[0]['snapshot_id'], offset=0, limit=19)
                gateway._validate_tool_arguments('config_read', page_args)
                page = await client.call_tool('config_read', dict(page_args, auth_context=envelope))
                self.assertFalse(page.is_error)
                self.assertEqual(page.data['returned_bytes'], 19)
                self.assertIsNotNone(page.data['next_offset'])
                diff_args = {'target': 'fixture', 'platform': 'fortios', 'secret_offset': 0,
                             'base_snapshot': captures[0]['snapshot_id'],
                             'other_snapshot': captures[1]['snapshot_id'], 'limit': 19}
                validated = gateway._validate_tool_arguments('config_diff', diff_args)
                gateway._authorize_tool('config_diff', validated, entry, section)
                diff = await client.call_tool('config_diff', dict(diff_args, auth_context=envelope))
                self.assertFalse(diff.is_error)
                self.assertFalse(diff.data['identical'])
                self.assertLessEqual(diff.data['returned_bytes'], 19)
                self.assertIsNotNone(diff.data['next_offset'])
                with self.assertRaises(Exception):
                    await client.call_tool('config_read', dict(args, platform='linux',
                                                              auth_context=envelope))
                return captures, diff.data
        with mock.patch.object(engine, 'read_from_device',
                               side_effect=reading(fixture('up', A), fixture('down', B))) as wire:
            results = asyncio.run(calls())
            self.assertEqual(wire.call_count, 4)
        self.assertNotIn(A, json.dumps(results), 'H1_MCP_SECRET_LEAK')
        self.assertNotIn(B, json.dumps(results), 'H1_MCP_SECRET_LEAK')
        with self.assertRaises(proxy.PolicyScopeError):
            gateway._authorize_tool('config_read', args, entry,
                                    replace(section, read_inventory={}))
        for rights in (['compare'], ['read', 'unknown']):
            with self.assertRaises(inventory.InventoryError):
                inventory._checked_read_inventory('fixture', {'config_access': rights})
            from netops_helper.auth import _normalize_inventory
            with self.assertRaises(ValueError):
                _normalize_inventory({'config_access': rights})

    def test_real_module_server_lists_configuration_tools(self):
        import asyncio
        import os
        import sys
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        async def listed():
            parameters = StdioServerParameters(
                command=sys.executable, args=['-B', '-m', 'netops_helper.server'],
                env={'PYTHONPATH': os.pathsep.join(path for path in sys.path if path)})
            async with stdio_client(parameters) as (reader, writer):
                async with ClientSession(reader, writer) as session:
                    await session.initialize()
                    response = await session.list_tools()
                    return [tool.name for tool in response.tools]

        async def bounded():
            return await asyncio.wait_for(listed(), timeout=30)

        names = asyncio.run(bounded())
        self.assertIn('config_read', names, 'H1_MODULE_CONFIG_READ_MISSING')
        self.assertIn('config_diff', names, 'H1_MODULE_CONFIG_DIFF_MISSING')

    def test_multi_vdom_and_unknown_status_stop_before_show(self):
        auth = enrolled()
        variants = [STATUS.replace('disable', 'enable'),
                    STATUS.replace('disable', 'unknown'),
                    STATUS.replace('Virtual domain configuration: disable\n', ''),
                    STATUS + 'Virtual domain configuration: disable\n',
                    STATUS.replace('FortiGate-VM64-KVM', 'FortiADC-VM'),
                    STATUS.replace('Version:', 'Malformed:')]
        for status in variants:
            with self.subTest(case='VDOM-status'), mock.patch.object(
                    engine, 'read_from_device',
                    side_effect=reading(fixture('up', A), status=status)) as wire:
                with self.assertRaises(ValueError, msg='H1_MULTI_VDOM_MUST_STOP'):
                    engine.config_read(auth, 'fortios', 'system interface')
                self.assertEqual(wire.call_args_list,
                                 [mock.call(auth, 'fortinet', 'get system status')],
                                 'H1_SHOW_BEFORE_SINGLE_VDOM_VERIFICATION')

        for identity_rc in (1, None):
            with self.subTest(case='identity-rc'), mock.patch.object(
                    engine, 'read_from_device',
                    side_effect=reading(fixture('up', A), identity_rc=identity_rc)) as wire:
                with self.assertRaises(ValueError):
                    engine.config_read(auth, 'fortios', 'system interface')
                self.assertEqual(wire.call_args_list,
                                 [mock.call(auth, 'fortinet', 'get system status')],
                                 'H1_SHOW_AFTER_FAILED_IDENTITY')

    def test_negative_optin_transport_grammar_and_snapshot_block(self):
        auth = enrolled()
        with mock.patch.object(engine, 'read_from_device') as wire:
            for target, platform in ((enrolled(()), 'fortios'), (auth, 'exos'),
                                     (replace(auth, ssh_platform='linux'), 'fortios')):
                with self.assertRaises(ValueError):
                    engine.config_read(target, platform, 'system interface')
            wire.assert_not_called()
        bad = ['xyzzy "' + A + '"\n', 'config system interface\n set password "' + A,
               fixture('up', A) + 'prompt # ', 'config system interface\n',
               'config system interface\n set password "' + A + '"\nend\nCommand fail.\n']
        bad.append('config system global\n' + 'set a x\n' * 5000 + 'end\n')
        for output in bad:
            with self.subTest(case='invalid-grammar-' + str(len(output))), mock.patch.object(
                    engine, 'read_from_device', side_effect=reading(output)):
                with self.assertRaises(ValueError) as error:
                    engine.config_read(auth, 'fortios', 'system interface')
                self.assertNotIn(A, str(error.exception))
        for rc in (1, None):
            with mock.patch.object(engine, 'read_from_device', side_effect=reading(fixture('up', A), rc=rc)):
                with self.assertRaises(ValueError):
                    engine.config_read(auth, 'fortios', 'system interface')
        with mock.patch.object(engine, 'read_from_device', side_effect=RuntimeError(A)):
            with self.assertRaises(ValueError) as error:
                engine.config_read(auth, 'fortios', 'system interface')
            self.assertNotIn(A, str(error.exception))
        with self.assertRaises(ValueError):
            engine.config_diff(auth, 'fortios', 'cfg_unknown', 'cfg_unknown')
        with mock.patch.object(engine, 'read_from_device', side_effect=reading(fixture('up', A))):
            first = engine.config_read(auth, 'fortios', 'system interface')
        with self.assertRaises(ValueError):
            engine.config_diff(replace(auth, alias='other'), 'fortios', first['snapshot_id'],
                               first['snapshot_id'])
        with self.assertRaises(ValueError):
            engine.config_diff(enrolled(('read',)), 'fortios', first['snapshot_id'],
                               first['snapshot_id'])


    def test_headers_multiline_and_fail_closed_block(self):
        from netops_helper import configuration
        auth = enrolled()
        raw = ('\n#config-version=synthetic\n#conf_file_ver=1\n#buildno=0251\n#global_vdom=0\n'
               'config system interface\n edit "port1"\n set description "first\\\"quoted\n'
               'set password CANARY-continuation\nlast"\n set status up\n next\nend\n')
        with mock.patch.object(engine, 'read_from_device', side_effect=reading(raw, raw.replace('last"', 'CANARY-changed-tail"'))):
            a = engine.config_read(auth, 'fortios', 'system interface')
            b = engine.config_read(auth, 'fortios', 'system interface')
        d = engine.config_diff(auth, 'fortios', a['snapshot_id'], b['snapshot_id'])
        self.assertFalse(d['identical'])
        self.assertTrue(d['secrets_changed'])
        rendered = json.dumps([a,b,d]) + repr(configuration._SNAPSHOTS)
        for secret in ('first', 'CANARY-continuation', 'last', 'CANARY-changed-tail', 'port1'):
            self.assertNotIn(secret, rendered)
        with self.assertRaises(TypeError):
            configuration.redact(raw, ())
        single = fixture('up', A).replace('set password "' + A + '"',
                                          "set password '" + A + chr(92) + "'")
        with mock.patch.object(engine, 'read_from_device', side_effect=reading(single)):
            literal = engine.config_read(auth, 'fortios', 'system interface')
        self.assertNotIn(A, json.dumps(literal))
        for separator in ('\n', '\x85'):
            outside = fixture('up', A).replace(' set status up',
                                               ' set description ordinary' + separator + 'CANARY-invalid')
            with self.subTest(separator=repr(separator)), mock.patch.object(
                    engine, 'read_from_device', side_effect=reading(outside)):
                before = set(configuration._SNAPSHOTS)
                with self.assertRaises(ValueError):
                    engine.config_read(auth, 'fortios', 'system interface')
                self.assertEqual(before, set(configuration._SNAPSHOTS))
        for bad in ('#unknown=1\n'+raw, raw.replace(' set status', ' #buildno=1\n set status'),
                    raw.replace('last"', 'last'), raw.replace('first', '--More--'), raw.replace('config system interface','config router static'), single.replace(chr(92) + "'", chr(92))):
            with self.subTest(invalid=True), mock.patch.object(engine,'read_from_device',side_effect=reading(bad)):
                before = set(configuration._SNAPSHOTS)
                with self.assertRaises(ValueError):
                    engine.config_read(auth, 'fortios', 'system interface')
                self.assertEqual(before, set(configuration._SNAPSHOTS))

    def test_section_contract_and_snapshot_scope_block(self):
        from netops_helper import proxy
        auth = enrolled()
        with mock.patch.object(engine, 'read_from_device') as wire:
            for section, include in (('all',False),('system interface\nshow',False),('router unknown',False),
                                     ('system interface',True),('all',1)):
                with self.assertRaises(ValueError):
                    engine.config_read(auth,'fortios',section,include_all=include)
            wire.assert_not_called()
        gateway=proxy.Proxy()
        for args in ({'target':'fixture','platform':'fortios'},
                     {'target':'fixture','platform':'fortios','section':'all'},
                     {'target':'fixture','platform':'fortios','section':'system interface','include_all':1}):
            with self.assertRaises(Exception):
                gateway._validate_tool_arguments('config_read',args)
        with mock.patch.object(engine,'read_from_device',side_effect=reading(fixture('up',A))):
            a=engine.config_read(auth,'fortios','system interface')
        with mock.patch.object(engine,'read_from_device',side_effect=reading(fixture('up',A))) as wire:
            b=engine.config_read(auth,'fortios','all',include_all=True)
        self.assertEqual(a['section'],'system interface')
        self.assertEqual(a['firmware']['version'],'7.6.7')
        self.assertEqual(a['firmware']['build'],'3658')
        with self.assertRaises(ValueError):
            engine.config_diff(auth,'fortios',a['snapshot_id'],b['snapshot_id'])
        with mock.patch.object(engine,'read_from_device',side_effect=reading(fixture('up',A),status=STATUS.replace('7.6.7','8.0.2'))):
            c=engine.config_read(auth,'fortios','system interface')
        with self.assertRaises(ValueError):
            engine.config_diff(auth,'fortios',a['snapshot_id'],c['snapshot_id'])


    def test_keyed_insert_reorder_and_secret_change_block(self):
        from netops_helper import configuration
        auth = enrolled()
        def body(rows, visible=False):
            return 'config system interface\n' + ''.join(
                ' edit "' + name + '"\n' + (' set status up\n' if visible else '') +
                ' set password "' + password + '"\n next\n' for name, password in rows) + 'end\n'
        original = [('private-port-a', A), ('private-port-b', B)]
        variants = [
            ('insert', [('private-new-port', 'UniqueInsertCanary77')] + original, False, 2),
            ('reorder', list(reversed(original)), False, 0),
            ('one-secret', [('private-port-a', 'UniqueChangedCanary88'), original[1]], False, 1),
            ('visible-only', original, True, 0),
        ]
        for name, rows, visible, expected in variants:
            with self.subTest(case=name):
                configuration._SNAPSHOTS.clear()
                with mock.patch.object(engine, 'read_from_device',
                        side_effect=reading(body(original), body(rows, visible))):
                    left = engine.config_read(auth, 'fortios', 'system interface')
                    right = engine.config_read(auth, 'fortios', 'system interface')
                result = engine.config_diff(auth, 'fortios', left['snapshot_id'], right['snapshot_id'])
                self.assertFalse(result['identical'])
                self.assertEqual(result['secrets_changed_count'], expected,
                                 'H1_POSITIONAL_IDENTITY_FALSE_CHANGE')
                if name == 'reorder':
                    self.assertIn('record order changed', result['untrusted_device_output'],
                                  'H1_REORDER_MUST_REMAIN_VISIBLE')
                rendered = json.dumps(result) + repr(configuration._SNAPSHOTS)
                for private in (A, B, 'private-port-a', 'private-port-b',
                                'private-new-port', 'UniqueInsertCanary77', 'UniqueChangedCanary88'):
                    self.assertNotIn(private, rendered)

    def test_duplicate_hidden_identity_withholds_snapshot(self):
        from netops_helper import configuration
        configuration._SNAPSHOTS.clear()
        auth = enrolled()
        raw = fixture('up', A).replace(' set password "' + A + '"',
                                      ' set password "' + A + '"\n set password "' + B + '"')
        with mock.patch.object(engine, 'read_from_device', side_effect=reading(raw)):
            with self.assertRaises(ValueError, msg='H1_AMBIGUOUS_RECORD_MUST_WITHHOLD'):
                engine.config_read(auth, 'fortios', 'system interface')
        self.assertEqual(len(configuration._SNAPSHOTS), 0)


    def test_snapshot_and_diff_pages_without_device_reread(self):
        import hashlib
        import inspect
        from netops_helper import configuration, proxy
        self.assertIn('snapshot_id', inspect.signature(engine.config_read).parameters,
                      'H1_SNAPSHOT_PAGING_MISSING')
        configuration._SNAPSHOTS.clear()
        auth = enrolled()
        with mock.patch.object(engine, 'read_from_device',
                               side_effect=reading(fixture('up', A), fixture('down', B))) as wire:
            first = engine.config_read(auth, 'fortios', 'system interface', limit=19)
            second = engine.config_read(auth, 'fortios', 'system interface')
            self.assertEqual(wire.call_count, 4)
        def collect(call, first_page):
            pages = [first_page['untrusted_device_output']]
            current = first_page
            while current['next_offset'] is not None:
                current = call(current['next_offset'])
                self.assertEqual(current['content_sha256'], first_page['content_sha256'])
                self.assertLessEqual(current['returned_bytes'], 19)
                pages.append(current['untrusted_device_output'])
            text = ''.join(pages)
            self.assertEqual(len(text.encode()), first_page['total_bytes'])
            self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), first_page['content_sha256'])
            return text
        with mock.patch.object(engine, 'read_from_device', side_effect=AssertionError('H1_PAGE_REREAD_DEVICE')) as wire:
            text = collect(lambda offset: engine.config_read(auth, 'fortios', 'system interface',
                snapshot_id=first['snapshot_id'], offset=offset, limit=19), first)
            full = engine.config_diff(auth, 'fortios', first['snapshot_id'], second['snapshot_id'])
            start = engine.config_diff(auth, 'fortios', first['snapshot_id'], second['snapshot_id'], limit=19)
            diff = collect(lambda offset: engine.config_diff(auth, 'fortios',
                first['snapshot_id'], second['snapshot_id'], offset=offset, limit=19), start)
            self.assertEqual(diff, full['untrusted_device_output'])
            for changes in ({'offset':-1},{'offset':True},{'limit':0},{'limit':48001},{'offset':1}):
                with self.assertRaises(ValueError):
                    engine.config_read(auth, 'fortios', 'system interface', **changes)
            for other_auth, section in ((replace(auth, login='different-reader'),'system interface'),
                                        (auth,'firewall policy')):
                with self.assertRaises(ValueError):
                    engine.config_read(other_auth, 'fortios', section, snapshot_id=first['snapshot_id'])
            created = configuration._SNAPSHOTS[first['snapshot_id']].created
            with mock.patch.object(configuration.time, 'monotonic', return_value=created+86401):
                with self.assertRaises(ValueError):
                    engine.config_read(auth, 'fortios', 'system interface', snapshot_id=first['snapshot_id'])
            wire.assert_not_called()
        gateway = proxy.Proxy()
        args = {'target':'fixture','platform':'fortios','section':'system interface',
                'snapshot_id':first['snapshot_id'],'offset':19,'limit':19}
        self.assertEqual(gateway._validate_tool_arguments('config_read',args),args)
        for changes in ({'snapshot_id':'bad'},{'limit':0},{'offset':True}):
            with self.assertRaises(proxy.ToolArgumentsError):
                gateway._validate_tool_arguments('config_read',dict(args,**changes))
        self.assertNotIn(A,text)
        self.assertNotIn(B,diff)

if __name__ == '__main__':
    unittest.main()

class StreamingConfigurationBlock(TestCase):
    def setUp(self):
        audit = mock.patch.object(engine, 'record')
        audit.start()
        self.addCleanup(audit.stop)

    def test_chunked_capture_transport_and_withholding_block(self):
        from netops_helper import configuration
        from types import SimpleNamespace
        self.assertTrue(callable(getattr(configuration, 'StreamRedactor', None)),
                        'H1_INCREMENTAL_REDACTOR_MISSING')
        auth = enrolled()
        raw = ('#config-version=synthetic\r\nconfig system interface\r\n'
               ' edit "private-é"\r\n set description "CANARY-first\r\n'
               'set password CANARY-continuation\r\nlast"\r\n set status up\r\n next\r\nend\r\n')
        expected = ('# configuration\nconfig system interface\nedit <REDACTED>\n'
                    '    set description <REDACTED>\n    set status up\nnext\nend\n')
        for size in (1, 2, 7, 4096):
            configuration._SNAPSHOTS.clear()
            def wire(target, platform, command, **kwargs):
                if command == 'get system status':
                    self.assertFalse(kwargs)
                    return 0, STATUS
                consume = kwargs.get('stdout_consumer')
                self.assertTrue(callable(consume), 'H1_ENGINE_MUST_STREAM')
                data = raw.encode()
                for offset in range(0, len(data), size):
                    consume(data[offset:offset+size])
                return 0, ''
            with mock.patch.object(engine, 'read_from_device', side_effect=wire):
                first = engine.config_read(auth, 'fortios', 'system interface')
            self.assertEqual(first['untrusted_device_output'], expected)
            self.assertEqual(first['redacted_count'], 2)
            rendered = json.dumps(first) + repr(configuration._SNAPSHOTS)
            for value in ('private-é', 'CANARY-first', 'CANARY-continuation', 'last'):
                self.assertNotIn(value, rendered)
        for data, rc, extra in (
                (raw.encode()[:-5], 0, ''),
                (raw.encode()+b'\xff', 0, ''),
                (raw.encode(), 1, ''),
                (raw.encode(), 0, 'unexpected raw fallback'),
                (raw.encode()+b'Command fail.\n', 0, ''),
                (raw.encode()+b'--More--', 0, ''),
                (raw.encode()+b'X'*48001, 0, '')):
            before = set(configuration._SNAPSHOTS)
            def bad_wire(target, platform, command, **kwargs):
                if command == 'get system status':
                    return 0, STATUS
                kwargs['stdout_consumer'](data)
                return rc, extra
            with mock.patch.object(engine, 'read_from_device', side_effect=bad_wire):
                with self.assertRaises(ValueError):
                    engine.config_read(auth, 'fortios', 'system interface')
            self.assertEqual(before, set(configuration._SNAPSHOTS), 'H1_PARTIAL_SNAPSHOT_PUBLISHED')
        capture = configuration.StreamRedactor(auth.secrets, 'system interface')
        with self.assertRaises(ValueError):
            capture.feed(b'\xff')
        with self.assertRaises(ValueError):
            capture.finish()
        consume = mock.Mock()
        def native(*args, **kwargs):
            self.assertIs(kwargs['stdout_consumer'], consume)
            kwargs['stdout_consumer'](b'fixture bytes')
            return SimpleNamespace(rc=0, stdout=b'')
        with mock.patch.object(engine, '_resolve_target_ipv4', return_value=['192.0.2.20']), \
                mock.patch.object(engine, 'host_key_line', return_value='fixture pin'), \
                mock.patch.object(engine.core_ssh, 'run_command', side_effect=native):
            self.assertEqual(engine.read_from_device(auth, 'fortinet', 'show system interface',
                                                    stdout_consumer=consume), (0, ''))
        consume.assert_called_once_with(b'fixture bytes')
        with self.assertRaises(ValueError):
            engine.read_from_device(auth, 'linux', 'show', stdout_consumer=consume)

class ConfigurationCapacityPolicyBlock(TestCase):
    def test_completed_capture_diff_pages_memory_and_withholding_block(self):
        from netops_helper import configuration, proxy
        configuration._SNAPSHOTS.clear()
        configuration._DIFFS.clear()
        auth = enrolled()
        def fixture_many(value):
            return 'config system interface\n'+''.join(
                ' edit "private-'+str(i)+'"\n set password "'+value+'"\n next\n'
                for i in range(600))+'end\n'
        with mock.patch.object(engine, 'record'), mock.patch.object(
                engine,'read_from_device',side_effect=reading(fixture_many(A),fixture_many(B))) as wire:
            left=engine.config_read(auth,'fortios','system interface')
            right=engine.config_read(auth,'fortios','system interface')
            pages=[];offset=0
            while True:
                page=engine.config_diff(auth,'fortios',left['snapshot_id'],right['snapshot_id'],secret_offset=offset)
                self.assertEqual(page['untrusted_device_output'],'')
                self.assertFalse(page['identical'])
                self.assertEqual(page['secrets_changed_count'],600)
                self.assertLessEqual(len(page['secrets_changed']),256)
                pages.extend(page['secrets_changed'])
                if page['next_secret_offset'] is None:break
                offset=page['next_secret_offset']
            self.assertEqual(len(set(pages)),600)
            self.assertEqual(wire.call_count,4)
            for bad in (-1,True,'1',601):
                with self.assertRaises(ValueError):
                    engine.config_diff(auth,'fortios',left['snapshot_id'],right['snapshot_id'],secret_offset=bad)
        gateway=proxy.Proxy()
        args={'target':'fixture','platform':'fortios','base_snapshot':left['snapshot_id'],
              'other_snapshot':right['snapshot_id'],'secret_offset':256}
        self.assertEqual(gateway._validate_tool_arguments('config_diff',args)['secret_offset'],256)
        with self.assertRaises(proxy.ToolArgumentsError):
            gateway._validate_tool_arguments('config_diff',dict(args,secret_offset=True))
        before=set(configuration._SNAPSHOTS)
        with mock.patch.object(engine,'record'),mock.patch.object(engine,'read_from_device') as wire:
            with configuration.capture():
                with self.assertRaises(ValueError):
                    engine.config_read(auth,'fortios','system interface')
                with self.assertRaises(ValueError):
                    engine.config_read(auth,'fortios','system interface',snapshot_id=left['snapshot_id'])
            wire.assert_not_called()
            with mock.patch.object(configuration,'_available_memory',return_value=32*1024*1024):
                with self.assertRaises(ValueError):
                    engine.config_read(auth,'fortios','system interface')
            wire.assert_not_called()
            with mock.patch.object(configuration,'_BYTE_BUDGET',1):
                with self.assertRaises(ValueError):
                    engine.config_read(auth,'fortios','system interface')
            wire.assert_not_called()
        bad=['config system interface\n set description "'+'x'*65537+'"\nend\n',
             'config system interface\n set description "'+('x'*1024+'\n')*1025+'"\nend\n']
        for body in bad:
            with mock.patch.object(engine,'record'),mock.patch.object(
                    engine,'read_from_device',side_effect=reading(body)):
                with self.assertRaises(ValueError):
                    engine.config_read(auth,'fortios','system interface')
            self.assertEqual(before,set(configuration._SNAPSHOTS))
