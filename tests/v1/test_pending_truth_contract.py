from netops import cli
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

def event(direction, payload=None, correlation='synthetic-request'):
    return {'time': '2026-01-01T00:00:00Z', 'direction': direction, 'correlation': correlation, 'payload': payload}

def request():
    return event('request', {'id': 7, 'method': 'tools/call', 'params': {'name': 'synthetic'}})

class PendingTruthContract(unittest.TestCase):

    def run_pending(self, records):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            audit = state / 'gateway' / 'audit'
            audit.mkdir(parents=True)
            (audit / 'one.jsonl').write_text(''.join((json.dumps(item) + '\n' for item in records)))
            output = io.StringIO()
            errors = io.StringIO()
            with patch.object(cli, 'STATE', state), patch.object(cli, 'require_initialized'), patch.object(cli, 'read_private', side_effect=lambda path, *a, **kw: path.read_bytes()), patch.object(sys, 'argv', ['netops', 'audit', 'pending']), contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                rc = cli.main()
            self.assertEqual((rc, errors.getvalue()), (0, ''))
            return [json.loads(line) for line in output.getvalue().splitlines()]

    def test_abandoned_before_dispatch_stays_visible_with_truthful_outcome(self):
        result = self.run_pending([request(), event('client_disconnect', {'phase': 'before_dispatch', 'complete_body': True, 'received_bytes': 100, 'operation_executed': False}), event('connection_end', {'delivery': 'not_started'})])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['outcome'], 'client left before dispatch; the operation was not executed')
        self.assertEqual((result[0]['request_id'], result[0]['tool']), (7, 'synthetic'))

    def test_interrupted_before_dispatch_stays_visible_with_truthful_outcome(self):
        result = self.run_pending([request(), event('interrupted', {'operation_may_have_completed': False}), event('connection_end', {'delivery': 'interrupted'})])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['outcome'], 'interrupted before dispatch; the operation was not executed')

    def test_unknown_or_malformed_disconnect_remains_conservative(self):
        base = {'phase': 'before_dispatch', 'complete_body': True, 'operation_executed': False}
        variations = [None, [], {}, dict(base, phase='request_body'), dict(base, complete_body=1), dict(base, complete_body=False), dict(base, operation_executed=0), dict(base, operation_executed=True), dict(base, operation_executed=None)]
        for payload in variations:
            with self.subTest(payload=payload):
                result = self.run_pending([request(), event('client_disconnect', payload)])
                self.assertEqual(len(result), 1)
                self.assertIn('the operation may have completed', result[0]['outcome'])

    def test_unknown_or_malformed_interruption_remains_conservative(self):
        for payload in (None, [], {}, {'operation_may_have_completed': True}, {'operation_may_have_completed': 0}, {'operation_may_have_completed': None}, {'operation_may_have_completed': 'false'}):
            with self.subTest(payload=payload):
                result = self.run_pending([request(), event('interrupted', payload)])
                self.assertEqual(len(result), 1)
                self.assertIn('the operation may have completed', result[0]['outcome'])

    def test_withheld_and_uncertain_admin_results_remain_pending(self):
        result = self.run_pending([request(), event('response_withheld', {})])
        self.assertEqual(len(result), 1)
        self.assertIn('response withheld', result[0]['outcome'])
        for outcome in ('unknown', 'revert-failed'):
            with self.subTest(outcome=outcome):
                payload = {'result': {'structuredContent': {'result': {'result': outcome}}}}
                result = self.run_pending([request(), event('response', payload)])
                self.assertEqual(len(result), 1)
                self.assertIn(outcome, result[0]['outcome'])
        self.assertEqual(self.run_pending([request(), event('response', {'result': {}})]), [])

    def test_interrupted_marker_still_prevents_later_response_from_hiding_pending(self):
        for marker in (True, False):
            result = self.run_pending([request(), event('interrupted', {'operation_may_have_completed': marker}), event('response', {'result': {}})])
            self.assertEqual(len(result), 1)
