import asyncio
from contextlib import nullcontext
from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from conftest import _target
from netops_helper import adc_monitoring as m, engine, proxy, read_policy

F = Path(__file__).parent / 'fixtures/fortiadc_g33r2'
STATUS = (F / 'status.out').read_text()
DF = (F / 'disk.out').read_text()
ROTATION = (F / 'rotation.out').read_text()
NTP = (F / 'ntp.out').read_text()
RUNTIME = (F / 'ntp-runtime.out').read_text()


class Shell:
    def __init__(self, changes=None):
        self.commands = []
        self.timeouts = {}
        self.answers = {m.STATUS: STATUS, m.COMMANDS['disk_usage'][0]: DF,
                        m.COMMANDS['disk_usage'][1]: ROTATION, m.COMMANDS['ntp_status'][0]: NTP, m.COMMANDS['ntp_status'][1]: RUNTIME}
        self.answers.update(changes or {})

    def command(self, command, timeout=10):
        self.commands.append(command)
        self.timeouts[command] = timeout
        value = self.answers[command]
        if isinstance(value, Exception):
            raise value
        return value


def test_measured_disk_capacity_rotation_and_duplicate_mounts():
    result = m.run(Shell(), 'disk_usage', 10)
    assert result['state'] == 'data'
    disk = result['disk']
    assert disk['log_storage'] == [{'filesystem': '/dev/vdb1', 'size': '29.4G', 'used': '664.3M',
                                    'available': '27.2G', 'used_percent': 2, 'mount': '/var/log'}]
    assert disk['rotation_configuration'] == {'status': 'enable', 'rotation-size': '200', 'disk-full': 'overwrite'}
    assert len([r for r in disk['filesystems'] if r['mount'] == '/home']) == 1


def test_measured_runtime_reports_unsynchronized_and_disabled_config():
    result = m.run(Shell(), 'ntp_status', 10)
    assert result['state'] == 'data'
    assert result['ntp']['ntpsync_configured'] is False
    assert result['ntp']['sync_status'] == 'unsynchronized'
    assert result['ntp']['offset_ms'] is None
    assert result['ntp']['system_time'] == 'Tue Nov 17 06:51:45 PST 2026'
    assert result['ntp']['server_visibility'] == 'hidden_when_disabled'


@pytest.mark.parametrize('df,rotation', [('', ROTATION), (DF.replace('2% /var/log', 'bad /var/log'), ROTATION),
                                       (DF + 'unrecognized row\n', ROTATION), (DF, ''),
                                       (DF, ROTATION.replace('200', 'bad')), (DF + '--More--', ROTATION)])
def test_incomplete_disk_is_not_complete(df, rotation):
    assert m.run(Shell({m.COMMANDS['disk_usage'][0]: df, m.COMMANDS['disk_usage'][1]: rotation}),
                 'disk_usage', 10)['state'] == 'incomplete'


@pytest.mark.parametrize('config,status', [('', STATUS), (NTP.removesuffix('end\n'), STATUS),
                                         (NTP, STATUS.replace('System Time:', 'Time:')),
                                         (NTP.replace('disable', 'enable'), STATUS),
                                         (NTP + '--More--', STATUS)])
def test_missing_or_clipped_configuration_is_incomplete(config, status):
    result = m.run(Shell({m.STATUS: status, m.COMMANDS['ntp_status'][0]: config}), 'ntp_status', 10)
    assert result['state'] == 'incomplete'
    assert result['ntp']['sync_status'] in ('unsynchronized', 'unknown')


def test_documented_enabled_ntp_grammar_and_authentication_key_redaction():
    # Vendor 7.6.1 grammar, synthetic values. Enabled mode was not changed on the lab appliance.
    config = '''config system time ntp
 set ntpsync enable
 set syncinterval 60
 config ntp-server
  edit 1
   set server "time.example.test"
   set authentication enable
   set key ENC fixture-secret-value
  next
 end
end
'''
    result = m.run(Shell({m.COMMANDS['ntp_status'][0]: config}), 'ntp_status', 10)
    assert result['state'] == 'data'
    assert 'fixture-secret-value' not in json.dumps(result)
    assert result['ntp']['configured_servers'] == [{'id': '1', 'servers': ['time.example.test']}]
    assert result['ntp']['syncinterval_minutes'] == 60
    assert result['ntp']['sync_status'] == 'unsynchronized'


@pytest.mark.parametrize('recipe', sorted(m.RECIPES))
def test_device_refusal_never_exposes_measurement(recipe):
    result = m.run(Shell({m.COMMANDS[recipe][0]: 'Command fail. Return code is -284 (CLI parsing error.)'}), recipe, 10)
    assert result['state'] == 'device_refused'
    assert not {'disk', 'ntp'} & result.keys()


@pytest.mark.parametrize('recipe', sorted(m.RECIPES))
def test_proxy_and_enrollment_boundaries(recipe):
    args = {'target': 'fixture', 'recipe': recipe, 'address': '', 'interface': ''}
    p = proxy.Proxy()
    checked = p._validate_tool_arguments('fortios_diagnostics', args)
    section = SimpleNamespace(egress={}, read_inventory={'diagnostic_recipes': (recipe,)},
                              enabled_queries=('system_status',), catalog_platform=lambda: 'fortiadc')
    p._authorize_tool('fortios_diagnostics', checked, SimpleNamespace(port=22), section)
    section.read_inventory = {}
    with pytest.raises(proxy.PolicyScopeError):
        p._authorize_tool('fortios_diagnostics', checked, SimpleNamespace(port=22), section)
    for key, value in [('address', '192.0.2.1'), ('interface', 'port1'), ('vdom', 'root'), ('count', 1),
                       ('health_check', 'hc'), ('since', '2026-11-17'), ('source_address', '192.0.2.2')]:
        with pytest.raises(proxy.ToolArgumentsError):
            p._validate_tool_arguments('fortios_diagnostics', {**args, key: value})
    read_policy.validate_query_inventory('fortiadc', ('system_status',), {'diagnostic_recipes': (recipe,)})
    with pytest.raises(ValueError):
        read_policy.validate_query_inventory('fortinet', ('system_status',), {'diagnostic_recipes': (recipe,)})


@pytest.fixture
def wire_monitor(monkeypatch):
    shell = Shell()
    monkeypatch.setattr(engine, 'record', lambda *a, **k: None)
    monkeypatch.setattr(engine, '_resolve_target_ipv4', lambda *a: ['127.0.0.1'])
    monkeypatch.setattr(engine, 'host_key_line', lambda *a: 'pinned')
    monkeypatch.setattr(engine, '_paced_connection', lambda *a: nullcontext())
    monkeypatch.setattr(engine.core_session, 'fortinet_session', lambda *a, **k: nullcontext(shell))
    monkeypatch.setattr(engine, '_FortiosDiagnosticShell', lambda session, *a, **k: session)
    return shell


@pytest.mark.parametrize('recipe,field', [('disk_usage', 'disk'), ('ntp_status', 'ntp')])
def test_engine_runs_only_fixed_reads_and_requires_enrollment(wire_monitor, recipe, field):
    auth = replace(_target('fortiadc', 'system_status'), read_inventory={'diagnostic_recipes': (recipe,)})
    result = engine.fortios_diagnostics(auth, recipe, '', '', 3, 10, 16000)
    assert result['ok'] and result['complete'] and result['cleanup'] == 'not_required'
    assert result[field]['status'] == 'complete'
    assert wire_monitor.commands == [m.STATUS, *m.COMMANDS[recipe]]
    wire_monitor.commands.clear()
    with pytest.raises(ValueError, match='not enrolled'):
        engine.fortios_diagnostics(replace(auth, read_inventory={}), recipe, '', '', 3, 10, 16000)
    assert not wire_monitor.commands


def test_engine_byte_limit_withholds_derived_measurement(wire_monitor):
    auth = replace(_target('fortiadc', 'system_status'), read_inventory={'diagnostic_recipes': ('disk_usage',)})
    result = engine.fortios_diagnostics(auth, 'disk_usage', '', '', 3, 10, 1000)
    assert not result['ok'] and result['truncated'] and not result['complete']
    assert 'disk' not in result


def test_identity_mismatch_stops_before_diagnostic_commands():
    shell = Shell({m.STATUS: 'Version: FortiGate-VM64 v7.6.7,build3704,240101'})
    with pytest.raises(ValueError):
        m.run(shell, 'disk_usage', 10)
    assert shell.commands == [m.STATUS]


@pytest.mark.parametrize('runtime', ['', RUNTIME.replace('no', 'maybe'), RUNTIME + '--More--',
                                    'Command fail. Return code is -284 (CLI parsing error.)',
                                    RUNTIME + 'Command fail. Return code is -284 (CLI parsing error.)'])
def test_missing_refused_or_truncated_runtime_does_not_infer_sync(runtime):
    result = m.run(Shell({m.COMMANDS['ntp_status'][1]: runtime}), 'ntp_status', 10)
    assert result['state'] == 'incomplete'
    assert result['ntp']['sync_status'] == 'unknown'
    assert result['ntp']['offset_ms'] is None


def test_positive_sync_marker_without_inventing_offset():
    result = m.run(Shell({m.COMMANDS['ntp_status'][1]: RUNTIME.replace('synchronized: no', 'synchronized: yes')}), 'ntp_status', 10)
    assert result['ntp']['sync_status'] == 'synchronized'
    assert result['ntp']['offset_ms'] is None


def test_ntp_status_accepts_bounded_long_runtime_read():
    args = proxy.Proxy()._validate_tool_arguments('fortios_diagnostics',
        {'target': 'fixture', 'recipe': 'ntp_status', 'address': '', 'interface': '', 'timeout': 60})
    assert args['timeout'] == 60
    with pytest.raises(proxy.ToolArgumentsError):
        proxy.Proxy()._validate_tool_arguments('fortios_diagnostics', {**args, 'timeout': 61})


@pytest.mark.parametrize('recipe,options,expected', [
    ('ntp_status', {}, 60), ('ntp_status', {'timeout': 12}, 12), ('disk_usage', {}, 10),
])
def test_monitoring_read_uses_recipe_default_or_explicit_timeout(wire_monitor, recipe, options, expected):
    auth = replace(_target('fortiadc', 'system_status'), read_inventory={'diagnostic_recipes': (recipe,)})
    result = engine.fortios_diagnostics(auth, recipe, '', '', **options)
    assert result['ok'] and result['complete']
    assert wire_monitor.timeouts == dict.fromkeys([m.STATUS, *m.COMMANDS[recipe]], expected)


def test_mcp_ntp_status_uses_the_recipe_default_when_timeout_is_omitted(wire_monitor, monkeypatch):
    from netops_helper import server

    auth = replace(_target('fortiadc', 'system_status'), read_inventory={'diagnostic_recipes': ('ntp_status',)})
    monkeypatch.setattr(server, '_auth', lambda *_: auth)
    result = asyncio.run(server.mcp.call_tool('fortios_diagnostics', {
        'target': auth.alias, 'recipe': 'ntp_status', 'address': '', 'interface': '',
    }))
    assert result.structured_content['ntp']['sync_status'] == 'unsynchronized'
    assert wire_monitor.timeouts == dict.fromkeys([m.STATUS, *m.COMMANDS['ntp_status']], 60)


def test_source_gate_accepts_only_the_exact_ntp_section(tmp_path):
    import shutil
    from test_phase1_gate_source import _load_gate
    source = Path(__file__).parents[1] / 'src'
    shutil.copytree(source, tmp_path / 'src')
    gate = _load_gate()
    assert gate._phase1_surface_errors(tmp_path) == []
    monitor = tmp_path / 'src/netops_helper/adc_monitoring.py'
    monitor.write_text(monitor.read_text().replace('show full-configuration system time ntp',
                                                  'show full-configuration system'))
    assert any('adc_monitoring.py' in error and 'configuration export pattern' in error
               for error in gate._phase1_surface_errors(tmp_path))
