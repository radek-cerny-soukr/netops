import asyncio
from datetime import datetime, timezone
import json
import tempfile
import time
import uuid
import unittest
from pathlib import Path
from unittest.mock import patch

from netops.audit import Audit
from netops.gateway import HEALTH_PENDING_SECONDS, AuditBoundary

TOKEN = 'synthetic-gateway-token-for-test-only-123456'
ROLES = ('helper', 'auditor', 'admin')
SCHEMA = {'status': {'ok', 'degraded', 'failed'}, 'version': {'1.0.7'}, 'uptime_s': int,
          'audit': {'writable': bool, 'queue_pending': int, 'oldest_pending_s': float, 'syslog_delivery_errors': int},
          'roles': dict.fromkeys(ROLES, {'running', 'unavailable', 'disabled'}), 'admin_devices': {'not_available'}}


class Child:
    def poll(self):
        return None


class Healthz(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.audit = Audit(self.temp.name, {'mode': 'local'})
        async def not_found(scope, receive, send):
            await send({'type': 'http.response.start', 'status': 404, 'headers': []})
            await send({'type': 'http.response.body', 'body': b'{}'})
        self.boundary = AuditBoundary(not_found, self.audit)
        self.boundary.roles = {role: Child() for role in ROLES}
        self.boundary.token = lambda: TOKEN

    async def request(self, authenticated=True, query=b''):
        events = []
        scope = {'type': 'http', 'scheme': 'https', 'method': 'GET', 'path': '/healthz', 'query_string': query,
                 'http_version': '1.1', 'headers': [(b'authorization', ('Bearer ' + TOKEN).encode())] if authenticated else []}
        async def receive():
            return {'type': 'http.request', 'body': b'', 'more_body': False}
        async def send(event):
            events.append(event)
        await self.boundary(scope, receive, send)
        return events[0]['status'], json.loads(events[1]['body'])

    def audit_records(self):
        path = Path(self.temp.name) / 'current.jsonl'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def queue(self, age_s=0.0):
        name = str(time.time_ns() - int(age_s * 1e9)) + '-' + uuid.uuid4().hex + '.queue'
        (Path(self.temp.name) / name).write_bytes(b'{}\n')

    def assert_schema(self, value, schema, where='response'):
        if isinstance(schema, dict):
            self.assertIsInstance(value, dict, where)
            self.assertEqual(set(value), set(schema), where)
            for key, expected in schema.items():
                self.assert_schema(value[key], expected, where + '.' + key)
        elif isinstance(schema, set):
            self.assertTrue(any(type(value) is type(item) and value == item for item in schema), where)
        else:
            self.assertIs(type(value), schema, where)

    async def test_ok_and_no_identity(self):
        status, result = await self.request()
        self.assertEqual(status, 200)
        self.assert_schema(result, SCHEMA)
        self.assertEqual(result['status'], 'ok')
        self.assertTrue(result['audit']['writable'])
        self.assertEqual(result['audit']['queue_pending'], 0)
        self.assertEqual(result['roles'], dict.fromkeys(ROLES, 'running'))
        self.assertEqual(result['admin_devices'], 'not_available')

    async def test_success_is_not_audited(self):
        await self.request()
        await self.request()
        self.assertEqual(self.audit_records(), [])

    async def test_query_rejection_is_audited_without_query(self):
        self.audit.write_failed = True
        with patch.object(self.audit, '_append', side_effect=PermissionError):
            await self.request()
        self.audit.write_failed = True
        status, _ = await self.request(query=b'x=1')
        self.assertEqual(status, 400)
        records = self.audit_records()
        self.assertEqual([record['direction'] for record in records], ['rejection'])
        self.assertEqual(records[0]['payload'], {'reason': 'query_parameters_are_not_supported'})
        self.assertNotIn('x=1', json.dumps(records))

    async def test_failure_record_has_no_response_body(self):
        self.audit.write_failed = True
        timestamp = datetime(2026, 1, 2, tzinfo=timezone.utc)
        correlation = uuid.UUID(int=1)
        with patch('netops.audit.datetime') as clock, patch('netops.gateway.uuid.uuid4', return_value=correlation):
            clock.now.return_value = timestamp
            status, result = await self.request()
        self.assertEqual((status, result['status']), (503, 'failed'))
        records = self.audit_records()
        self.assertEqual(len(records), 1)
        self.assert_schema(records[0], {
            'time': {timestamp.isoformat()}, 'direction': {'response'},
            'correlation': {correlation.hex}, 'payload': {'status': {'failed'}},
            'redaction': {'paths': list, 'complete_content': {True},
                          'representation': {'parsed-json'}, 'byte_transcript': {False}},
            'method': {'GET'}, 'path': {'/healthz'}, 'authenticated': {True}, 'status': {status},
        })
        self.assertEqual(records[0]['redaction']['paths'], [])
        self.assertEqual((await self.request())[0], 200)

    async def test_query_rejected(self):
        status, result = await self.request(query=b'x=')
        self.assertEqual((status, result), (400, {'error': 'query_parameters_are_not_supported'}))

    async def test_full_queue(self):
        self.audit.settings['mode'] = 'syslog'
        with (Path(self.temp.name) / (str(time.time_ns()) + '-' + uuid.uuid4().hex + '.queue')).open('wb') as queue:
            queue.truncate(self.audit.budget)
        status, result = await self.request()
        self.assert_schema(result, SCHEMA)
        self.assertEqual((status, result['status'], result['audit']['queue_pending']), (503, 'failed', 1))

    async def test_unwritable(self):
        self.audit.write_failed = True
        with patch.object(self.audit, '_append', side_effect=PermissionError):
            status, result = await self.request()
        self.assertEqual((status, result['status'], result['audit']['writable']), (503, 'failed', False))

    async def test_unauthenticated(self):
        status, result = await self.request(False)
        self.assertEqual((status, result['error']), (401, 'authentication_required'))

    async def test_role_unavailable(self):
        self.boundary.roles['helper'].poll = lambda: 1
        status, result = await self.request()
        self.assertEqual((status, result['status'], result['roles']['helper']), (200, 'degraded', 'unavailable'))

    async def test_admin_disabled(self):
        del self.boundary.roles['admin']
        status, result = await self.request()
        self.assert_schema(result, SCHEMA)
        self.assertEqual((status, result['status'], result['roles']['admin']), (200, 'ok', 'disabled'))

    async def test_syslog_pending_below_threshold(self):
        self.audit.settings['mode'] = 'syslog'
        self.queue(5)
        status, result = await self.request()
        self.assert_schema(result, SCHEMA)
        self.assertEqual((status, result['status'], result['audit']['queue_pending']), (200, 'ok', 1))

    async def test_syslog_pending_above_threshold_and_recovery(self):
        self.audit.settings['mode'] = 'syslog'
        self.queue(HEALTH_PENDING_SECONDS + 30)
        status, result = await self.request()
        self.assertEqual((status, result['status']), (200, 'degraded'))
        self.assertGreater(result['audit']['oldest_pending_s'], HEALTH_PENDING_SECONDS)
        for path in Path(self.temp.name).glob('*.queue'):
            path.unlink()
        status, result = await self.request()
        self.assertEqual((status, result['status'], result['audit']['oldest_pending_s']), (200, 'ok', 0.0))

    async def test_syslog_failing_and_recovery(self):
        self.audit.settings['mode'] = 'syslog'
        self.queue()
        calls = []
        def deliver(batch):
            calls.append(len(batch))
            if len(calls) == 1:
                raise OSError('controlled failure')
        async def wait_for(predicate):
            async with asyncio.timeout(8):
                while not predicate():
                    await asyncio.sleep(0.01)
        with patch.object(self.audit, '_deliver', side_effect=deliver):
            task = asyncio.create_task(self.audit.forward())
            try:
                await wait_for(lambda: self.audit.syslog_failing)
                status, result = await self.request()
                self.assertEqual((status, result['status'], result['audit']['syslog_delivery_errors']), (200, 'degraded', 1))
                await wait_for(lambda: len(calls) >= 2 and not self.audit.syslog_failing)
                status, result = await self.request()
                self.assertEqual((status, result['status'], result['audit']['syslog_delivery_errors']), (200, 'ok', 1))
            finally:
                self.audit.stop.set()
                await task

    async def test_foreign_queue_name_is_ignored(self):
        self.audit.settings['mode'] = 'syslog'
        with (Path(self.temp.name) / 'foreign.queue').open('wb') as foreign:
            foreign.truncate(self.audit.budget)
        (Path(self.temp.name) / (str(time.time_ns()) + '-' + uuid.uuid4().hex + '.queue')).symlink_to('missing')
        (Path(self.temp.name) / 'x-y.queue').write_bytes(b'')
        status, result = await self.request()
        self.assertEqual((status, result['status'], result['audit']['queue_pending']), (200, 'ok', 0))
