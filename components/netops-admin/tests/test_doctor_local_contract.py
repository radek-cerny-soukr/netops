import unittest
from types import SimpleNamespace
from unittest.mock import patch
from netops_admin import readiness


class LocalDoctorTest(unittest.TestCase):
    def test_local_does_not_select_adapter_or_contact_device(self):
        for platform in ('fortios', 'exos', 'fortiadc'):
            for schema in (None, object()):
                device = SimpleNamespace(name='lab', platform=platform, schema=schema, protected={})
                runtime = SimpleNamespace(config=SimpleNamespace(devices={'lab': device}), access_factory=lambda d: self.fail('remote access'))
                with patch.object(readiness.execute, '_adapter', side_effect=AssertionError('adapter')), patch.object(readiness, '_local', side_effect=lambda report, runtime, device: report.add('local', readiness.OK)), patch.object(readiness, 'configuration_summary', return_value={}):
                    result = readiness.doctor(runtime, 'lab', local=True)
                self.assertTrue(result['local_ready'])
                self.assertFalse(result['ready'])
                self.assertEqual(result['remote_readiness'], 'unverified')
                self.assertEqual(result['operations'], {})


class DoctorIntegrationTest(unittest.TestCase):
    def test_real_local_and_default(self):
        import tempfile
        from pathlib import Path
        from fake_fortios import FakeFortiOS
        from test_execute import make_runtime
        with tempfile.TemporaryDirectory() as directory:
            runtime = make_runtime(Path(directory), FakeFortiOS())
            calls = []
            def forbidden(device):
                calls.append(device)
                raise RuntimeError('remote access forbidden')
            runtime.access_factory = forbidden
            local = readiness.doctor(runtime, 'lab', local=True)
            self.assertFalse(calls)
            self.assertEqual(local['scope'], 'local')
            self.assertFalse(local['local_ready'])  # no notification configured
            self.assertFalse(local['ready'])
            default = readiness.doctor(runtime, 'lab')
            self.assertEqual(len(calls), 1)
            self.assertNotIn('scope', default)
            self.assertNotIn('local_ready', default)
            self.assertFalse(default['ready'])

    def test_cli_exit_and_mcp_default(self):
        import inspect
        import json
        from io import StringIO
        from netops_admin import cli, config, mcp_server
        self.assertFalse(inspect.signature(mcp_server.admin_doctor).parameters['local'].default)
        for ready in (True, False):
            with patch.object(config, 'load_config'), patch.object(cli, 'build_runtime') as build, patch.object(readiness, 'doctor', return_value={'local_ready': ready, 'ready': False}) as doctor, patch('sys.stdout', new_callable=StringIO) as output:
                code = cli.main(['doctor', '--config', 'unused', '--device', 'lab', '--local'])
                self.assertEqual(code, 0 if ready else cli.EXIT_NOT_READY)
                self.assertEqual(json.loads(output.getvalue())['local_ready'], ready)
                doctor.assert_called_once_with(build.return_value, 'lab', local=True)
        for ready in (True, False):
            with patch.object(config, 'load_config'), patch.object(cli, 'build_runtime') as build, patch.object(readiness, 'doctor', return_value={'local_ready': True, 'ready': ready}) as doctor, patch('sys.stdout', new_callable=StringIO):
                code = cli.main(['doctor', '--config', 'unused', '--device', 'lab'])
                self.assertEqual(code, 0 if ready else cli.EXIT_NOT_READY)
                doctor.assert_called_once_with(build.return_value, 'lab', local=False)

    def test_mcp_passes_local_to_readiness(self):
        from netops_admin import mcp_server
        sentinel = object()
        for arguments, expected in (({}, False), ({'local': False}, False), ({'local': True}, True)):
            with patch.object(mcp_server, 'configured_runtime', return_value=sentinel), patch.object(readiness, 'doctor', return_value={'ready': False}) as doctor:
                self.assertEqual(mcp_server.admin_doctor('lab', **arguments), {'ready': False})
                doctor.assert_called_once_with(sentinel, 'lab', local=expected)

    def test_checks_carry_reason_codes_from_the_real_journal(self):
        import tempfile
        from dataclasses import replace
        from pathlib import Path
        from fake_fortios import FakeFortiOS
        from test_execute import make_runtime

        def check(report, name):
            return [item for item in report['checks'] if item['check'] == name][0]

        with tempfile.TemporaryDirectory() as directory:
            runtime = make_runtime(Path(directory), FakeFortiOS())
            report = readiness.doctor(runtime, 'lab', local=True)
            self.assertNotIn('reason_codes', check(report, 'device state'))
            self.assertNotIn('reason_codes', check(report, 'budgets'))
            runtime.store.save({'change_id': 'a' * 32, 'request_id': 'req-running-1', 'device': 'lab',
                                'status': 'running', 'created_at_epoch': 1.0})
            self.assertEqual(check(readiness.doctor(runtime, 'lab', local=True), 'device state')['reason_codes'], ['operation_unfinished'])
            runtime.store.save({'change_id': 'b' * 32, 'request_id': 'req-failed-1', 'device': 'lab', 'status': 'finished',
                                'result': 'confirmed', 'notification': 'failed', 'created_at_epoch': 1.0})
            self.assertEqual(check(readiness.doctor(runtime, 'lab', local=True), 'device state')['reason_codes'], ['notification_pending'])
            runtime.store.block('lab', None, 'investigate')
            self.assertEqual(check(readiness.doctor(runtime, 'lab', local=True), 'device state')['reason_codes'], ['device_blocked'])
            runtime.config = replace(runtime.config, limits=dict(runtime.config.limits, changes_per_day=0))
            budgets = check(readiness.doctor(runtime, 'lab', local=True), 'budgets')
            self.assertEqual(budgets['status'], readiness.REFUSED)
            self.assertEqual(budgets['reason_codes'], ['budget_exhausted'])

    def test_full_doctor_reports_real_enrollment_failures(self):
        import tempfile
        from pathlib import Path
        from fake_fortios import FakeFortiOS
        from test_execute import make_runtime

        with tempfile.TemporaryDirectory() as directory:
            runtime = make_runtime(Path(directory), FakeFortiOS())
            path = runtime.store.enrollments / 'lab.json'
            path.unlink()
            for content, status, code in ((None, readiness.MISSING, 'enrollment_required'),
                                          ('{broken', readiness.REFUSED, 'state_unreadable')):
                if content is not None:
                    path.write_text(content)
                checks = readiness.doctor(runtime, 'lab')['checks']
                check = next(item for item in checks if item['check'] == 'enrollment')
                self.assertEqual(check['status'], status)
                self.assertEqual(check['reason_codes'], [code])

    def test_real_local_all_platforms_and_schema_variants(self):
        import tempfile
        from dataclasses import replace
        from pathlib import Path
        from fake_fortios import FakeFortiOS
        from test_execute import make_runtime

        for platform in ('fortios', 'exos', 'fortiadc'):
            for schema in (None, {'fixture': True}):
                with self.subTest(platform=platform, schema=schema), tempfile.TemporaryDirectory() as directory:
                    runtime = make_runtime(Path(directory), FakeFortiOS())
                    device = replace(runtime.config.devices['lab'], platform=platform, schema=schema)
                    runtime.config = replace(runtime.config, devices={'lab': device})
                    runtime.access_factory = lambda device: self.fail('remote access')
                    with patch.object(readiness.execute, '_adapter', side_effect=AssertionError('adapter')):
                        result = readiness.doctor(runtime, 'lab', local=True)
                    self.assertEqual(result['scope'], 'local')
                    self.assertEqual(result['remote_readiness'], 'unverified')
                    self.assertFalse(result['ready'])
                    self.assertEqual(result['operations'], {})
                    self.assertIn('journal and audit log writable', [c['check'] for c in result['checks']])

    def test_journal_is_read_once_per_doctor_and_rechecked_next_time(self):
        import tempfile
        from pathlib import Path
        from fake_fortios import FakeFortiOS
        from test_execute import make_runtime

        with tempfile.TemporaryDirectory() as directory:
            runtime = make_runtime(Path(directory), FakeFortiOS())
            runtime.store.save({'change_id': 'a' * 32, 'request_id': 'req-running-1', 'device': 'lab',
                                'status': 'running', 'created_at_epoch': 1.0})
            runtime.access_factory = lambda device: self.fail('remote access')
            with patch.object(runtime.store, '_operation', wraps=runtime.store._operation) as read:
                report = readiness.doctor(runtime, 'lab', local=True)
                self.assertEqual(read.call_count, 1)
            checks = {item['check']: item for item in report['checks']}
            self.assertEqual(checks['device state']['reason_codes'], ['operation_unfinished'])
            self.assertEqual(checks['budgets']['status'], readiness.OK)
            (runtime.store.operations / ('a' * 32 + '.json')).write_text('{broken')
            report = readiness.doctor(runtime, 'lab', local=True)
            checks = {item['check']: item for item in report['checks']}
            for name in ('device state', 'budgets'):
                self.assertEqual(checks[name]['status'], readiness.REFUSED)
                self.assertEqual(checks[name]['reason_codes'], ['state_unreadable'])
