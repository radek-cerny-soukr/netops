"""Transport-only fakes keep real switch/locate reads, parsing and audit paths."""
from dataclasses import replace
import errno
import json
from pathlib import Path
import socket
import subprocess

import pytest

from conftest import _target
from netops_core import hostkey, ssh
from netops_core.audit import Recorder
from netops_helper import audit as helper_audit, engine
from netops_helper.auth import EgressPolicy

PRIVATE = 'private-device-text-and-password'
CASES = [
    (TimeoutError(PRIVATE), 'timeout'),
    (subprocess.TimeoutExpired([PRIVATE], 60), 'timeout'),
    (ssh.SshError('ssh did not finish within 60.0 seconds ' + PRIVATE), 'timeout'),
    (ssh.SshError('failure ' + PRIVATE, 255, 'Connection refused ' + PRIVATE), 'connection_refused'),
    (ConnectionRefusedError(PRIVATE), 'connection_refused'),
    (ConnectionResetError(PRIVATE), 'disconnected'),
    (ssh.SshError('Connection reset ' + PRIVATE), 'disconnected'),
    (ssh.SshError('Permission denied ' + PRIVATE), 'auth'),
    (hostkey.HostKeyError(PRIVATE), 'host_key_mismatch'),
    (hostkey.HostKeyUnavailable(PRIVATE), 'host_key_unavailable'),
    (EOFError(PRIVATE), 'disconnected'),
    (ssh.SshError('Connection closed ' + PRIVATE), 'disconnected'),
    (ssh.SshError('No route to host ' + PRIVATE), 'unreachable'),
    (OSError(errno.EHOSTUNREACH, PRIVATE), 'unreachable'),
    (ssh.SshError('Could not resolve hostname ' + PRIVATE), 'dns'),
    (ssh.SshError('no matching key exchange ' + PRIVATE), 'negotiation'),
    (RuntimeError(PRIVATE), 'transport_failure'),
    # Every resolver failure is dns by its type, before any text it carries.
    (socket.gaierror(socket.EAI_NONAME, PRIVATE), 'dns'),
    (socket.gaierror(getattr(socket, 'EAI_NODATA', socket.EAI_NONAME), 'No address associated with hostname'), 'dns'),
    (socket.gaierror(socket.EAI_FAIL, 'Non-recoverable failure in name resolution'), 'dns'),
    (socket.gaierror(socket.EAI_AGAIN, 'timed out; connection refused ' + PRIVATE), 'dns'),
    # The client's closing message decides; a banner naming the negotiation marker before it does not.
    (ssh.SshError('failure ' + PRIVATE, 255, 'Banner: no matching access request ' + PRIVATE
                  + ' Permission denied (password).', 'Permission denied (password).'), 'auth'),
]


@pytest.fixture(autouse=True)
def persisted_audit(monkeypatch, tmp_path):
    path = tmp_path / 'operations.jsonl'
    monkeypatch.setattr(helper_audit, '_RECORDER', Recorder(path, 'helper'))
    return path


def install(monkeypatch, error):
    calls = []
    def transport(auth, profile, command, **kwargs):
        calls.append(command)
        if command == 'show version':
            return 0, (Path(__file__).parent / 'fixtures/identity/extreme_exos.txt').read_text()
        raise error
    monkeypatch.setattr(engine, '_exec_read', transport)
    auth = replace(_target('extreme_exos', 'mac_table'), device_types=('switch',),
                   egress=EgressPolicy(addresses=('127.0.0.1',), tcp_ports=(2222,)))
    return auth, calls


@pytest.mark.parametrize('error,code', CASES, ids=[c for _, c in CASES])
def test_switch_transport_failure_explained_in_result_and_audit(monkeypatch, persisted_audit, error, code):
    auth, calls = install(monkeypatch, error)
    result = engine.switch_read(auth, 'mac_entry')
    assert not result['ok']
    assert result['status'] == ('timeout' if code == 'timeout' else 'transport_error')
    assert result['error_code'] == code and result['error'] == engine._TRANSPORT_ADVICE[code]
    assert calls == ['show version', 'show fdb']
    audit = [json.loads(line) for line in persisted_audit.read_text().splitlines()]
    assert [e['detail'] for e in audit if e.get('detail')] == [code, code]
    assert PRIVATE not in json.dumps([result, audit])
    assert result['records'] == [] and not result['coverage']['complete']


@pytest.mark.parametrize('error,code', CASES[:4])
def test_locate_transport_missing_has_diagnosis(monkeypatch, persisted_audit, error, code):
    auth, _ = install(monkeypatch, error)
    result = engine._locate_endpoint_run([auth], '00:00:5e:00:53:fe')
    assert {'vantage': auth.alias, 'table': 'mac_entry',
            'reason': 'timeout' if code == 'timeout' else 'transport_error', 'error_code': code,
            'error': engine._TRANSPORT_ADVICE[code]} in result['missing']
    audit = [json.loads(line) for line in persisted_audit.read_text().splitlines()]
    assert any(e.get('detail') == code for e in audit)
    assert PRIVATE not in json.dumps([result, audit])


def test_wrapped_host_key_error_preserves_cause_without_text(monkeypatch, persisted_audit):
    try:
        raise hostkey.HostKeyError(PRIVATE)
    except hostkey.HostKeyError as cause:
        error = RuntimeError('outer failure')
        error.__cause__ = cause
    auth, _ = install(monkeypatch, error)
    assert engine.switch_read(auth, 'mac_entry')['error_code'] == 'host_key_mismatch'
    assert PRIVATE not in persisted_audit.read_text()


def test_nonzero_exit_has_local_diagnosis_without_returning_device_text(monkeypatch, persisted_audit):
    auth, _ = install(monkeypatch, RuntimeError('unused'))
    def transport(auth, profile, command, **kwargs):
        if command == 'show version':
            return 0, (Path(__file__).parent / 'fixtures/identity/extreme_exos.txt').read_text()
        return 1, ''
    monkeypatch.setattr(engine, '_exec_read', transport)
    result = engine.switch_read(auth, 'mac_entry')
    assert result['status'] == 'transport_error' and result['error_code'] == 'exit_status'
    audit = [json.loads(line) for line in persisted_audit.read_text().splitlines()]
    assert [e['detail'] for e in audit if e.get('detail')] == ['exit_status', 'exit_status']
