"""Exercise prompts through the actual audited gateway MCP application."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
from netops import gateway, __version__
from netops.files import write_private


class HelperPrompts(unittest.IsolatedAsyncioTestCase):
    async def exercise(self, roles):
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw)
            directory = state / 'gateway'
            directory.mkdir(mode=0o700)
            token = 'synthetic-gateway-token-for-public-test-only-12345'
            write_private(directory / 'token', token.encode())
            write_private(directory / 'config.json', json.dumps({'version': 1, 'product_version': __version__, 'audit': {'mode': 'local'}}).encode())
            with patch.object(gateway, 'STATE', state), patch.object(gateway, 'startup_rpc', AsyncMock(return_value={'tools': []})), patch.object(gateway, 'rpc', AsyncMock()) as rpc:
                app = await gateway.application({'audit': {'mode': 'local'}}, roles, [])
                inner = app.app
                failure = None
                async with inner.router.lifespan_context(inner):
                    try:
                        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='https://test.invalid', headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/json, text/event-stream'}) as client:
                            async def request(method, params=None):
                                data = {'jsonrpc': '2.0', 'id': 1, 'method': method}
                                if params is not None:
                                    data['params'] = params
                                response = await client.post('/mcp', json=data)
                                self.assertEqual(response.status_code, 200, response.text)
                                return response.json()
                            init = await request('initialize', {'protocolVersion': '2025-03-26', 'capabilities': {}, 'clientInfo': {'name': 'test', 'version': '1'}})
                            client.headers['MCP-Protocol-Version'] = init['result']['protocolVersion']
                            await client.post('/mcp', json={'jsonrpc': '2.0', 'method': 'notifications/initialized'})
                            listed = await request('prompts/list')
                            if 'helper' not in roles:
                                self.assertFalse(listed.get('result', {}).get('prompts', []))
                                return
                            prompts = listed['result']['prompts']
                            self.assertEqual({p['name'] for p in prompts}, {'internet_or_vpn', 'everything_slow', 'fortiadc_backend_down', 'tls_certificate_error', 'wifi_client_connectivity'})
                            for prompt in prompts:
                                self.assertTrue(prompt['description'])
                                self.assertIn('target', {a['name'] for a in prompt['arguments']})
                                value = '$(touch /tmp/netops-prompt-must-not-run)'
                                result = await request('prompts/get', {'name': prompt['name'], 'arguments': {'target': value, 'address': '198.51.100.99'}})
                                text = result['result']['messages'][0]['content']['text']
                                for fragment in (value, '198.51.100.99', 'target_scope', '-32009', 'Helper host'):
                                    self.assertIn(fragment, text)
                                self.assertLess(len(text), 3000)
                                self.assertEqual(text.count("## Before you start"), 1)
                                if prompt['name'] == 'wifi_client_connectivity':
                                    self.assertIn('REST tool', text)
                                    self.assertIn('wifi_clients', text)
                                    self.assertNotIn('cannot show whether the client is associated', text)
                                    self.assertNotIn('triage_slb', text)
                                if prompt['name'] == 'internet_or_vpn':
                                    self.assertIn('triage_routing', text)
                                if prompt['name'] == 'everything_slow':
                                    self.assertIn('triage_health', text)
                            with self.assertNoLogs('fastmcp', level='ERROR'):
                                missing = await request('prompts/get', {'name': 'wifi_client_connectivity', 'arguments': {}})
                            self.assertEqual(missing['error']['code'], -32602)
                            self.assertEqual(missing['error']['data']['field'], 'target')
                            unknown = await request('prompts/get', {'name': 'does_not_exist', 'arguments': {}})
                            self.assertIn('error', unknown)
                            rpc.assert_not_awaited()
                            self.assertFalse(Path('/tmp/netops-prompt-must-not-run').exists())
                    except Exception as error:
                        failure = error
                if failure is not None:
                    raise failure

    async def test_helper_prompts(self):
        await self.exercise(['helper'])

    async def test_other_roles_do_not_add_prompts(self):
        await self.exercise(['auditor', 'admin'])

    def test_packaged_runbook_has_all_sections(self):
        from netops import prompts
        guide = Path(prompts.__file__).with_name('troubleshooting-by-symptom.md').read_text(encoding='utf-8')
        common, sections = prompts.load_sections(guide)
        self.assertTrue(common)
        self.assertEqual(len(sections), 5)
