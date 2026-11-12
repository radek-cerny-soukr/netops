from unittest import TestCase, mock
import asyncio
import hashlib
import json

from netops_helper import engine, configuration, proxy
from test_config_block import enrolled, reading, fixture, A


class ConfigurationFilterBlock(TestCase):
    def setUp(self):
        import inspect
        parameters = inspect.signature(engine.config_read).parameters
        for name in ('contains', 'context', 'content_sha256', 'filter_sha256'):
            self.assertIn(name, parameters, 'H5_MISSING_FILTER_ARGUMENT')
        with configuration._LOCK:
            configuration._SNAPSHOTS.clear()
            configuration._DIFFS.clear()
        self.audit = mock.patch.object(engine, 'record')
        self.events = self.audit.start()
        self.addCleanup(self.audit.stop)

    def test_redaction_paging_and_filter_binding(self):
        auth = enrolled()
        with mock.patch.object(engine, 'read_from_device', side_effect=reading(fixture('up', A))) as wire, mock.patch.object(
                configuration, 'filtered_content', wraps=configuration.filtered_content) as filtering:
            first = engine.config_read(auth, 'fortios', 'system interface',
                                       contains='set', context=0, limit=9)
            args = dict(snapshot_id=first['snapshot_id'], contains='set', context=0,
                        content_sha256=first['content_sha256'], filter_sha256=first['filter_sha256'])
            parts = [first['untrusted_device_output']]
            page = first
            while page['next_offset'] is not None:
                page = engine.config_read(auth, 'fortios', 'system interface',
                                          offset=page['next_offset'], limit=9, **args)
                parts.append(page['untrusted_device_output'])
            self.assertEqual(filtering.call_count, 1)
            full = engine.config_read(auth, 'fortios', 'system interface',
                                      snapshot_id=first['snapshot_id'])
            text = ''.join(parts)
            self.assertEqual(text, ''.join(x for x in full['untrusted_device_output'].splitlines(True) if 'set' in x))
            # `set password` now remains searchable after response redaction.
            self.assertEqual(first['matched_lines'], 3)
            self.assertEqual(first['total_lines'], 7)
            self.assertEqual(first['content_sha256'], hashlib.sha256(text.encode()).hexdigest())
            self.assertEqual(first['snapshot_sha256'], full['snapshot_sha256'])
            self.assertNotEqual(first['content_sha256'], first['snapshot_sha256'])
            for change in ({'contains':'password'}, {'contains':None}, {'context':1},
                           {'content_sha256':'0'*64}, {'filter_sha256':'0'*64}):
                with self.subTest(change=change), self.assertRaises(ValueError):
                    engine.config_read(auth, 'fortios', 'system interface', offset=1,
                                       limit=9, **(args | change))
            with self.assertRaises(ValueError):
                engine.config_read(auth, 'fortios', 'system interface',
                                   snapshot_id=first['snapshot_id'], contains='set', offset=1)
            hidden = engine.config_read(auth, 'fortios', 'system interface',
                                        snapshot_id=first['snapshot_id'], contains=A)
            self.assertEqual(wire.call_count, 2)
            self.assertEqual(hidden['matched_lines'], 0)
            self.assertEqual(hidden['untrusted_device_output'], '')
        self.assertNotIn(A, json.dumps([first, full, hidden]) + repr(self.events.call_args_list))
        self.assertNotIn('contains', repr(self.events.call_args_list))
        self.assertEqual(len(configuration._SNAPSHOTS[first['snapshot_id']].filtered), 4)
        with mock.patch.object(engine, 'read_from_device', side_effect=reading(fixture('up', A))), mock.patch.object(
                configuration, 'filtered_content', side_effect=ValueError('configuration memory budget exhausted')):
            before = set(configuration._SNAPSHOTS)
            with self.assertRaises(ValueError):
                engine.config_read(auth, 'fortios', 'system interface', contains='status')
            self.assertEqual(set(configuration._SNAPSHOTS), before)

    def test_literal_context_and_chunk_boundaries(self):
        from netops_helper.config_buffers import ContentBuilder
        builder = ContentBuilder(200000)
        lines = ['q'*65530+'\n', 'a.b|c*$;\n', 'axb|c*$;\n', 'a.b|c*$;\n', 'tail\n']
        for line in lines:
            builder.add(line)
        content = builder.finish()
        with mock.patch.object(configuration, '_budget', wraps=configuration._budget) as budget:
            selected, total, matched = configuration.filtered_content(content, 'a.b|c*$;', 1)
        # The selected lines, then the text the client receives after the response redaction.
        self.assertEqual(budget.call_count, 4)
        self.assertEqual(total, 5)
        self.assertEqual(matched, 2)
        self.assertEqual(b''.join(selected.lines()).decode(), ''.join(lines))
        selected, _, matched = configuration.filtered_content(content, 'a.b|c*$;', 0)
        self.assertEqual(matched, 2)
        self.assertEqual(b''.join(selected.lines()).decode(), lines[1]+lines[3])

    def test_invalid_arguments_refused_before_device(self):
        auth = enrolled()
        invalid = [{'contains':''}, {'contains':'x'*65}, {'contains':'x\n'}, {'contains':True},
                   {'contains':'x','context':True}, {'contains':'x','context':11},
                   {'context':1}, {'contains':'x','context':-1}, {'filter_sha256':'bad'},
                   {'contains':'x','filter_sha256':'0'*64}, {'content_sha256':'0'*64},
                   {'contains':'x','content_sha256':'0'*64,'filter_sha256':'0'*64}]
        with mock.patch.object(engine, 'read_from_device') as wire:
            for extra in invalid:
                with self.subTest(extra=extra), self.assertRaises(ValueError):
                    engine.config_read(auth, 'fortios', 'system interface', **extra)
                with self.subTest(proxy=extra), self.assertRaises(proxy.ToolArgumentsError):
                    proxy.Proxy._validate_tool_arguments('config_read',
                        {'target':'fixture','platform':'fortios','section':'system interface'} | extra)
            wire.assert_not_called()

    def test_snapshot_lifetime_and_shared_view_budget(self):
        auth = enrolled()
        with configuration._LOCK:
            configuration._SNAPSHOTS.clear()
            configuration._DIFFS.clear()
        with mock.patch.object(engine, 'read_from_device', side_effect=reading(fixture('up', A), fixture('down', A))):
            first = engine.config_read(auth, 'fortios', 'system interface')
            engine.config_read(auth, 'fortios', 'system interface')
        identity = first['snapshot_id']
        source = configuration.get_snapshot(auth, identity, 'system interface').text
        view, _, _ = configuration.filtered_content(source, 'set', 0)
        retained = sum(s.memory_bytes for s in configuration._SNAPSHOTS.values())
        with mock.patch.object(configuration, '_BYTE_BUDGET', retained+view.memory_bytes-1):
            with self.assertRaisesRegex(ValueError, 'memory budget exhausted'):
                engine.config_read(auth, 'fortios', 'system interface', snapshot_id=identity, contains='set')
            self.assertIsNone(configuration._SNAPSHOTS[identity].filtered)
        with mock.patch.object(configuration, '_BYTE_BUDGET', retained+4096):
            engine.config_read(auth, 'fortios', 'system interface', snapshot_id=identity, contains='set')
            self.assertLessEqual(sum(s.memory_bytes for s in configuration._SNAPSHOTS.values()),
                                 configuration._BYTE_BUDGET)
        original = configuration.filtered_content
        def deleted_during_filter(*args):
            with configuration._LOCK:
                configuration._SNAPSHOTS.pop(identity)
            return original(*args)
        with mock.patch.object(configuration, 'filtered_content', side_effect=deleted_during_filter):
            with self.assertRaisesRegex(ValueError, 'snapshot not found or expired'):
                engine.config_read(auth, 'fortios', 'system interface', snapshot_id=identity, contains='status')

    def test_proxy_and_mcp_expose_same_filter(self):
        from fastmcp import Client
        from netops_helper import server
        args = {'target':'fixture','platform':'fortios','section':'system interface',
                'contains':'status','context':1,'limit':48000}
        checked = proxy.Proxy._validate_tool_arguments('config_read', args)
        self.assertEqual(checked, args)
        continuation = args | {'snapshot_id':'cfg_'+'0'*32, 'offset':5, 'content_sha256':'0'*64,
                               'filter_sha256':'0'*64}
        self.assertEqual(proxy.Proxy._validate_tool_arguments('config_read', continuation), continuation)
        async def run():
            async with Client(server.mcp) as client:
                with mock.patch.object(server, '_auth', return_value=enrolled()), mock.patch.object(
                        engine, 'read_from_device', side_effect=reading(fixture('up', A))):
                    result = await client.call_tool('config_read', args)
                return result
        result = asyncio.run(run())
        self.assertFalse(result.is_error)
        text = ''.join(getattr(c, 'text', '') for c in result.content)
        data = json.loads(text)
        self.assertEqual(data['matched_lines'], 1)
        self.assertIn('set status up', data['untrusted_device_output'])
        self.assertNotIn(A, text)


if __name__ == '__main__':
    import unittest
    unittest.main()
