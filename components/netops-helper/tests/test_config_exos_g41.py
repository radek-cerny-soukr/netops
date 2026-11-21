"""G41 public MCP calls with real-derived ExtremeXOS fixtures and a fake SSH transport."""

import asyncio
from pathlib import Path
import sys

import pytest

from netops import worker
from netops.files import write_private
from netops_helper import config_exos, engine, server
from test_config_exos_public import EXOSVM_VERSION, VERSION, Wire, _wire, env
from test_proxy import _rewrite

FIXTURES = Path(__file__).parent / 'fixtures' / 'real' / 'exos' / 'g41-20261118'
DIFF = (FIXTURES / 'vm-dirty.out').read_bytes()
COMMAND = 'show configuration difference primary context 0'


@pytest.fixture(autouse=True)
def _worker_state(env):
    state = env['inventory'].parent
    directory = state / 'helper'
    directory.mkdir()
    write_private(directory / 'vault.json', (state / 'vault.json').read_bytes())
    env['monkeypatch'].setattr(worker, 'STATE', state)


def _access(env):
    helper = env['document']['devices'][0]['helper']
    helper['read_inventory']['config_access'] = ['read', 'compare']
    helper['rate_limit']['requests'] = 15
    _rewrite(env['inventory'], env['document'])


def _compare(**overrides):
    return asyncio.run(worker.HelperBridge().call(server.mcp, 'config_diff', {
        'target': 'device-a', 'platform': 'extreme_exos', 'base_snapshot': 'saved',
        'other_snapshot': 'running', **overrides,
    }))


def _prompt(env, transcript):
    spawn = engine.core_session._spawn

    def replay(call, environment):
        assert '-tt' in call
        script = f'import os, tty; tty.setraw(1); os.write(1, {transcript!r})'
        return spawn([sys.executable, '-I', '-c', script], environment)

    env['monkeypatch'].setattr(engine.core_session, '_spawn', replay)


def _standalone_prompt(dirty):
    hostname = (FIXTURES / 'vm-switch.out').read_text().splitlines()[0].split()[1].encode()
    return b'\r\n' + (b'* ' if dirty else b'') + hostname + b'.1 # '


@pytest.mark.parametrize('output,dirty,rc,changed,missing', [
    (b'', False, 0, False, []),
    (b'', True, 0, False, []),
    (DIFF, True, 0, True, []),
    (DIFF.rsplit(b'+', 1)[0], True, 0, None, ['difference_unverified']),
    (b'\x07%% Invalid input detected.\r\n', False, 254, None, ['difference_refused']),
    (DIFF, None, 0, True, ['prompt_unverified']),
])
def test_running_vs_saved_public(env, output, dirty, rc, changed, missing):
    _access(env)
    wire = _wire(env, Wire(version=EXOSVM_VERSION, switch=(FIXTURES / 'vm-switch.out').read_text(),
                           identity_rc={COMMAND: rc}))
    wire.identity[COMMAND] = output
    _prompt(env, b'' if dirty is None else _standalone_prompt(dirty))
    result = _compare()
    assert result['isError'] is False
    data = result['structuredContent']
    assert data['ok'] is True and data['comparison_complete'] is (not missing)
    assert data['saved_configuration'] == 'primary.cfg'
    assert data['dirty'] is dirty
    assert data.get('content_changed') is changed
    assert data['missing'] == missing
    if changed:
        assert data['added_lines'] == data['hidden_changed_lines'] == 1
        assert data['removed_lines'] == 0
    assert 'g41-probe-534' not in str(result)
    assert wire.commands == ['show version', 'show switch', COMMAND]


@pytest.mark.parametrize('base,configuration', [('saved', 'primary'), ('saved:secondary', 'secondary')])
def test_running_vs_saved_after_factory_default(env, base, configuration):
    _access(env)
    switch = (FIXTURES / 'vm-factory-default-switch.out').read_text()
    wire = _wire(env, Wire(version=EXOSVM_VERSION, switch=switch))
    command = f'show configuration difference {configuration} context 0'
    wire.identity.update({'ls': b'primary.cfg\nsecondary.cfg\n', command: b''})
    _prompt(env, _standalone_prompt(False))

    result = _compare(base_snapshot=base)
    assert result['isError'] is False
    data = result['structuredContent']
    assert data['comparison_complete'] is True
    assert data['saved_configuration'] == configuration + '.cfg'
    assert data['selected_configuration'] == 'primary.cfg'
    assert data['booted_configuration'] is None
    assert data['dirty'] is data['content_changed'] is False
    assert data['missing'] == []
    commands = ['show version', 'show switch']
    if configuration == 'secondary':
        commands.append('ls')
    assert wire.commands == [*commands, command]


@pytest.mark.parametrize('dirty', [False, True])
def test_running_vs_saved_stack_prompt(env, dirty):
    _access(env)
    switch = (FIXTURES / 'vm-switch.out').read_text().replace('host06', 'Stack')
    wire = _wire(env, Wire(version=EXOSVM_VERSION, switch=switch))
    wire.identity[COMMAND] = DIFF if dirty else b''
    prompt = (FIXTURES / 'documented-stack-prompt.out').read_bytes().rstrip(b'\n')
    _prompt(env, b'\r\n' + (b'* ' if dirty else b'') + prompt + b' ')

    result = _compare()
    assert result['isError'] is False
    data = result['structuredContent']
    assert data['comparison_complete'] is True
    assert data['dirty'] is data['content_changed'] is dirty
    assert data['missing'] == []
    assert wire.commands == ['show version', 'show switch', COMMAND]


def test_live_diff_requires_both_permissions(env):
    wire = _wire(env, Wire())
    assert _compare()['isError'] is True
    assert wire.commands == []


@pytest.mark.parametrize('model,version', [('vm', EXOSVM_VERSION), ('x440', VERSION)])
def test_real_configuration_redaction_public(env, model, version):
    _wire(env, Wire(version=version, switch=(FIXTURES / f'{model}-switch.out').read_text(),
                    config=(FIXTURES / f'{model}-running.out').read_bytes()))
    response = asyncio.run(worker.HelperBridge().call(server.mcp, 'config_read', {
        'target': 'device-a', 'platform': 'extreme_exos', 'section': 'all', 'include_all': True,
        'redaction': 'full',
    }))
    assert response['isError'] is False
    data = response['structuredContent']
    text = data['untrusted_device_output']
    assert data['capture_complete'] and not data['configuration_complete']
    assert 'enable ssh2\n' in text and 'disable telnet\n' in text
    assert config_exos.MARKER in text and '[fixture-opaque]' not in text
    assert 'firmware_support' not in data


@pytest.mark.parametrize("stage, failure, missing", [
    ("show version", "transport", None),
    (COMMAND, "transport", "difference_transport_failed"),
    (COMMAND, "limit", "difference_unverified"),
])
def test_saved_comparison_handles_ssh_failure(env, stage, failure, missing):
    from netops_core.ssh import OutputLimitError, SshError

    _access(env)
    wire = Wire(version=EXOSVM_VERSION, switch=(FIXTURES / 'vm-switch.out').read_text())
    wire.identity[COMMAND] = DIFF
    _wire(env, wire)

    def read(*args, **kwargs):
        command = args[5]
        if command == stage:
            if failure == "limit":
                raise OutputLimitError()
            raise SshError("fixture private detail", rc=255, final="Connection timed out")
        return wire(*args, **kwargs)

    env["monkeypatch"].setattr(engine.core_ssh, "run_command", read)
    _prompt(env, _standalone_prompt(True))
    response = _compare()["structuredContent"]
    if missing is None:
        assert not response["ok"] and response["error_code"] == "timeout"
        assert wire.commands == []
    else:
        assert response["ok"] and not response["comparison_complete"]
        assert response["missing"] == [missing] and response["dirty"]
        assert wire.commands == ["show version", "show switch"]
    assert "content_changed" not in response and "fixture private detail" not in str(response)


def test_booted_comparison_with_no_verified_filename_never_reads_diff(env):
    _access(env)
    wire = _wire(env, Wire(version=EXOSVM_VERSION, switch=(FIXTURES / "vm-factory-default-switch.out").read_text()))
    result = _compare(base_snapshot="booted")["structuredContent"]
    assert not result["ok"] and not result["comparison_complete"]
    assert result["reason"] == "saved_configuration_unverified"
    assert wire.commands == ["show version", "show switch"]
