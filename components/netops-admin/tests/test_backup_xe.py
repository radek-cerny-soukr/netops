"""Operator CLI with the pinned SSH transport replaying real, sanitized IOS XE output."""

import hashlib
import json
from pathlib import Path
import re
import stat

import pytest

from netops_admin import backup_xe, cli
from netops_core import ssh

FIXTURES = Path(__file__).resolve().parents[2] / 'netops-helper/tests/fixtures/real/cisco_xe/xe-config'
PIN = 'SHA256:AEDEktUNmcPvCUTzy+fdyqWAbjUm+gT5GdG985wWBuc'


@pytest.fixture(params=['iol-xe-router', 'iol-xe-switch'])
def lab(request, monkeypatch, tmp_path, capsys):
    directory = tmp_path / 'private'
    directory.mkdir(mode=0o700)
    options = ['--host', '192.0.2.10', '--directory', str(directory)]
    args = ['backup-xe', *options, '--login', 'netops-admin', '--ssh-sha256', PIN, '--keep', '1']
    replies = {command: (FIXTURES / f'{request.param}-{label}.out').read_bytes()
               for command, label in [('show version', 'version'), ('show running-config', 'running')]}
    calls = []

    def scan(host, port, pin, timeout, **_options):
        assert (host, port, pin, timeout) == ('192.0.2.10', 22, PIN, 10)
        return 'pinned-transport-fixture'

    def command(_host, _port, _login, credential, pin, command, **_options):
        assert credential.use() == 'test-only-backup-password'
        assert pin == 'pinned-transport-fixture'
        calls.append(command)
        return ssh.Result(rc=0, stdout=replies[command], said='', started_at='t0', finished_at='t1')

    monkeypatch.setattr(backup_xe.hostkey, 'scan', scan)
    monkeypatch.setattr(ssh, 'run_command', command)
    monkeypatch.setenv('NETOPS_BACKUP_KEY', 'ab' * 32)
    monkeypatch.setenv('NETOPS_BACKUP_PASSWORD', 'test-only-backup-password')

    def invoke(argv):
        rc = cli.main(argv)
        result = capsys.readouterr()
        assert 'hostname ' not in result.out + result.err
        assert 'test-only-backup-password' not in result.out + result.err
        assert 'ab' * 32 not in result.out + result.err
        return rc, json.loads(result.out)

    return invoke, args, options, directory, calls, replies


def test_preview_retention_authenticated_status_and_local_restore(lab):
    invoke, args, options, path, calls, replies = lab
    assert invoke(['backup-xe-status', *options]) == (4, {'result': 'missing', 'last_backup': None})
    rc, plan = invoke(args)
    assert rc == 0 and plan['result'] == 'ready'
    assert calls == [] and list(path.iterdir()) == []
    confirm = [*args, '--confirm', plan['plan_sha256']]
    rc, first = invoke(confirm)
    assert rc == 0 and first['result'] == 'confirmed'
    rc, second = invoke(confirm)
    assert rc == 0 and second['retention_ok'] and second['artifact'] != first['artifact']
    assert calls == ['show version', 'show running-config'] * 2
    encrypted, = path.iterdir()
    assert encrypted.name == second['artifact']
    assert hashlib.sha256(encrypted.read_bytes()).hexdigest() == second['sha256']
    assert stat.S_IMODE(encrypted.stat().st_mode) == 0o600
    rc, status = invoke(['backup-xe-status', *options])
    assert rc == 0 and status['artifact'] == encrypted.name and status['last_backup'].endswith('Z')

    restore = path / 'restore.cfg'
    unseal = ['backup-unseal', '--platform', 'xe', '--input', str(encrypted), '--output', str(restore)]
    assert invoke(unseal)[0] == 0
    body = re.split(rb'Current configuration : \d+ bytes\n', replies['show running-config'], maxsplit=1)[1]
    assert restore.read_bytes() == body.lstrip(b'\n') and stat.S_IMODE(restore.stat().st_mode) == 0o600
    restore.unlink()
    data = encrypted.read_bytes()
    encrypted.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
    assert invoke(unseal)[1]['reason_codes'] == ['backup_invalid']
    assert invoke(['backup-xe-status', *options])[1]['reason_codes'] == ['backup_invalid']
    assert not restore.exists()


@pytest.mark.parametrize('broken,reason', [('end', 'backup_incomplete'), ('size', 'backup_incomplete'),
                                           ('refused', 'backup_refused')])
def test_invalid_capture_creates_no_archive(lab, broken, reason):
    invoke, args, _, path, _, replies = lab
    data = replies['show running-config']
    replies['show running-config'] = {
        'end': data.rsplit(b'end', 1)[0],
        'size': re.sub(rb'(?<=Current configuration : )\d+', b'9216', data),
        'refused': (FIXTURES / 'iol-xe-router-refused.out').read_bytes(),
    }[broken]
    _, plan = invoke(args)
    rc, result = invoke([*args, '--confirm', plan['plan_sha256']])
    assert rc == 3 and result['reason_codes'] == [reason]
    assert list(path.iterdir()) == []
