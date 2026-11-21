"""Admin CLI backup and extraction through the real bounded SFTP and encrypted storage paths."""

import hashlib
import json
import os
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from netops_admin import cli
from netops_core import sftp

SOURCE = (Path(__file__).parent / 'fixtures' / 'exos-g41-derived.cfg').read_bytes()
PIN = 'SHA256:' + 'd' * 43


@pytest.fixture
def operator(tmp_path, monkeypatch):
    destination = tmp_path / 'private'
    destination.mkdir(mode=0o700)
    monkeypatch.setenv('NETOPS_BACKUP_KEY', 'b0' * 32)
    monkeypatch.setenv('NETOPS_BACKUP_PASSWORD', 'fixture-secret')
    flags = ['backup-exos', '--host', '192.0.2.10', '--login', 'operator', '--ssh-sha256', PIN,
             '--file', 'primary.cfg', '--directory', str(destination), '--keep', '1']
    return destination, flags


@pytest.fixture
def wire(monkeypatch, tmp_path):
    calls = []
    state = {'payload': SOURCE, 'get_rc': 0, 'listed_size': None}

    def scan(host, port, pin, *_args, **_options):
        assert (host, port, pin) == ('192.0.2.10', 22, PIN)
        return '192.0.2.10 ssh-rsa Zml4dHVyZQ=='

    def run(argv, *, input, capture_output, timeout, env, pass_fds=()):
        assert argv[0] == 'sftp'
        assert argv.index('BatchMode=no') < argv.index('-b')
        assert 'StrictHostKeyChecking=yes' in argv
        assert os.stat(env['NETOPS_ASKPASS_FILE']).st_mode & 0o777 == 0o600
        Path(env['NETOPS_ASKPASS_FILE'] + '.used').touch(exist_ok=False)
        if input.startswith(b'ls -ln '):
            size = state['listed_size']
            size = len(state['payload']) if size is None else size
            calls.append('ls')
            listing = f'sftp> ls -ln primary.cfg\n-rw-rw-rw- ? 1001 1001 {size} Nov 18 10:00 primary.cfg\n'
            return CompletedProcess(argv, 0, listing.encode(), b'')
        assert input == f'get primary.cfg /proc/self/fd/{pass_fds[0]}\n'.encode()
        calls.append('get')
        os.pwrite(pass_fds[0], state['payload'], 0)
        return CompletedProcess(argv, state['get_rc'], b'', b'')

    monkeypatch.setattr(sftp.hostkey, 'scan', scan)
    monkeypatch.setattr(sftp.subprocess, 'run', run)
    # The suite guards filesystem effects. Use an unnamed inode inside the test mount.
    monkeypatch.setattr(sftp.os, 'memfd_create', lambda *_: os.open(tmp_path, os.O_TMPFILE | os.O_RDWR, 0o600))
    return calls, state


def _invoke(capsys, args, rc=0):
    assert cli.main(args) == rc
    return json.loads(capsys.readouterr().out)


def test_preview_confirm_extract_and_keep_one(operator, wire, capsys):
    destination, flags = operator
    calls, _ = wire
    preview = _invoke(capsys, flags)
    assert preview['result'] == 'ready' and calls == [] and list(destination.iterdir()) == []
    apply = flags + ['--confirm', preview['plan_sha256']]
    archived = _invoke(capsys, apply)
    assert calls == ['ls', 'get'] and archived['retention_ok']
    first = destination / archived['artifact']
    assert first.stat().st_mode & 0o777 == 0o600
    assert SOURCE not in first.read_bytes()
    assert hashlib.sha256(first.read_bytes()).hexdigest() == archived['sha256']
    restored = destination / 'g41-restored.cfg'
    report = _invoke(capsys, ['backup-exos-unseal', '--input', str(first), '--output', str(restored)])
    assert report['bytes'] == len(SOURCE)
    assert restored.read_bytes() == SOURCE and restored.stat().st_mode & 0o777 == 0o600
    repeated = _invoke(capsys, apply)
    assert (destination / repeated['artifact']).is_file() and not first.exists()


@pytest.mark.parametrize('change,reason', [
    ({'listed_size': len(SOURCE) + 1}, 'backup_transport_failed'),
    ({'get_rc': 1}, 'backup_transport_failed'),
    ({'payload': SOURCE.removesuffix(b'</xos-configuration>')}, 'backup_incomplete'),
    ({'payload': SOURCE.replace(b'<xos-module-aaa />', b'')}, 'backup_incomplete'),
])
def test_refusal_preserves_previous_backup(operator, wire, capsys, change, reason):
    destination, flags = operator
    calls, state = wire
    preview = _invoke(capsys, flags)
    apply = flags + ['--confirm', preview['plan_sha256']]
    first = _invoke(capsys, apply)
    state.update(change)
    refusal = _invoke(capsys, apply, 3)
    assert refusal['reason_codes'] == [reason]
    assert list(destination.iterdir()) == [destination / first['artifact']]
    assert calls == ['ls', 'get', 'ls', 'get']
