from dataclasses import replace
from pathlib import Path
import hashlib
import json
from types import SimpleNamespace
from unittest import TestCase, IsolatedAsyncioTestCase, mock
from fastmcp import FastMCP
from netops import worker
from netops_helper import configuration as c, engine, server
from test_config_block import enrolled
from test_config_full_engine import STATUS

FIXTURE = Path(__file__).parent / 'fixtures/fortios_60f_7_6_8_show.conf'


def wire(raw):
    def read(auth, platform, command, **kwargs):
        if command == 'get system status': return 0, STATUS
        assert command == 'show'
        data = raw.encode()
        for start in range(0, len(data), 37):
            kwargs['stdout_consumer'](data[start:start + 37])
        return 0, ''
    return read


class MinimalRealFortiOS(TestCase):
    def setUp(self):
        c._SNAPSHOTS.clear(); c._DIFFS.clear()
        patch = mock.patch.object(engine, 'record'); patch.start(); self.addCleanup(patch.stop)

    def test_whole_anonymized_60f_configuration_through_engine_and_pages(self):
        raw = FIXTURE.read_text()
        self.assertIn('config system replacemsg admin "pre_admin-disclaimer-text"', raw)
        self.assertIn('set append_padding', raw)
        for eol in ('\n', '\r\n'):
            with self.subTest(eol=repr(eol)), mock.patch.object(engine, 'read_from_device', side_effect=wire(raw.replace('\n',eol))) as transport:
                page = engine.config_read(enrolled(), 'fortios', 'all', True, limit=4096)
                first = page; parts = []
                while True:
                    parts.append(page['untrusted_device_output'])
                    if page['next_offset'] is None: break
                    page = engine.config_read(enrolled(), 'fortios', 'all', True,
                        snapshot_id=first['snapshot_id'], offset=page['next_offset'], limit=4096)
                output = ''.join(parts)
                self.assertEqual(len(output.encode()), first['total_bytes'])
                self.assertEqual(hashlib.sha256(output.encode()).hexdigest(), first['content_sha256'])
                self.assertNotIn('fixture-value-', output)
                self.assertIn('config system replacemsg admin pre_admin-disclaimer-text', output)
                self.assertIn('set append_padding <REDACTED>', output)
                self.assertEqual([call.args[2] for call in transport.call_args_list], ['get system status','show'])

    def test_new_grammar_retains_fail_closed_behavior(self):
        for raw in ('config system interface\n set bad/field CANARY-value\nend\n',
                    'config system "CANARY bad header"\nend\n',
                    'config system global\n set hostname "CANARY-unclosed\n'):
            with self.subTest(raw=raw), mock.patch.object(engine, 'read_from_device', side_effect=wire(raw)):
                with self.assertRaisesRegex(ValueError, '^configuration redaction-unverifiable; output withheld$'):
                    engine.config_read(enrolled(), 'fortios', 'all', True)
                self.assertFalse(c._SNAPSHOTS)


class MinimalConfigurationClientError(IsolatedAsyncioTestCase):
    async def test_real_mcp_wrapper_keeps_safe_error_category(self):
        c._SNAPSHOTS.clear(); c._DIFFS.clear()
        mcp = FastMCP('configuration-errors')
        @mcp.tool(name='config_read')
        @server._refusals
        def read():
            return engine.config_read(enrolled(), 'fortios', 'all', True)
        bridge = worker.HelperBridge.__new__(worker.HelperBridge)
        bridge.proxy = SimpleNamespace(emitted=None, session_secrets=(), transport_secrets=(),
            request=lambda payload: payload, response=lambda payload: payload)
        with mock.patch.object(engine, 'read_from_device', side_effect=wire('CANARY-private-error\n')), mock.patch.object(engine, 'record'):
            result = await bridge.call(mcp, 'config_read', {})
        self.assertTrue(result['isError'])
        error = json.loads(result['content'][0]['text'])
        self.assertEqual(error['code'], -32602)
        self.assertEqual(error['data']['category'], 'redaction-unverifiable')
        self.assertNotIn('CANARY', json.dumps(result))
        self.assertFalse(c._SNAPSHOTS)

    async def test_capture_limit_and_device_refusal_keep_categories_through_real_mcp(self):
        for category in ('capture-limit-exceeded', 'read-refused', 'device-refused'):
            with self.subTest(category=category):
                c._SNAPSHOTS.clear(); c._DIFFS.clear()
                auth = replace(enrolled(), configuration_limits=c.ConfigurationLimits(physical_line_bytes=32))
                mcp = FastMCP('configuration-errors')
                @mcp.tool(name='config_read')
                @server._refusals
                def read():
                    return engine.config_read(auth, 'fortios', 'all', True,
                        redaction='full' if category == 'device-refused' else 'minimal')
                bridge = worker.HelperBridge.__new__(worker.HelperBridge)
                bridge.proxy = SimpleNamespace(emitted=None, session_secrets=(), transport_secrets=(),
                    request=lambda payload: payload, response=lambda payload: payload)
                capture = wire('config system global\nset hostname "CANARY-' + 'x' * 64 + '"\nend\n')
                def transport(auth, platform, command, **kwargs):
                    if category in ('read-refused', 'device-refused') and command == 'show':
                        return 1, 'CANARY-private-device-error'
                    return capture(auth, platform, command, **kwargs)
                with mock.patch.object(engine, 'read_from_device', side_effect=transport), mock.patch.object(engine, 'record'):
                    result = await bridge.call(mcp, 'config_read', {})
                self.assertTrue(result['isError'])
                error = json.loads(result['content'][0]['text'])
                self.assertEqual(error['code'], -32602)
                self.assertEqual(error['data']['category'], category)
                self.assertEqual(error['data']['reason'], category)
                self.assertTrue(error['data']['guidance'])
                self.assertNotIn('CANARY', json.dumps(result))
                self.assertFalse(c._SNAPSHOTS)

    async def test_unknown_failure_and_other_tools_retain_generic_error(self):
        for name, text in (('config_read', 'CANARY-private'),
                           ('ssh_read', 'configuration capture-limit-exceeded; output withheld')):
            mcp = FastMCP('configuration-errors')
            @mcp.tool(name=name)
            @server._refusals
            def read():
                raise ValueError(text)
            bridge = worker.HelperBridge.__new__(worker.HelperBridge)
            bridge.proxy = SimpleNamespace(emitted=None, session_secrets=(), transport_secrets=(),
                request=lambda payload: payload, response=lambda payload: payload)
            result = await bridge.call(mcp, name, {})
            error = json.loads(result['content'][0]['text'])
            self.assertEqual(error, {'code': -32603, 'message': 'Role operation failed'})
            self.assertNotIn('CANARY', json.dumps(result))

    def test_only_exact_safe_failure_is_recognized_even_with_cyclic_causes(self):
        for message, failure in worker._CONFIGURATION_FAILURES.items():
            error = ValueError(message)
            wrapped = RuntimeError('opaque'); wrapped.__cause__ = error; error.__context__ = wrapped
            self.assertEqual(worker._configuration_refusal(wrapped), failure)
            for text in ('CANARY ' + message, message + ' CANARY', 'CANARY-private', ''):
                self.assertIsNone(worker._configuration_refusal(ValueError(text)))
