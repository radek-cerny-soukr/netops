"""Operator backup against a measured G98 NX-OS SSH replay and real private files."""
import hashlib
import json
from pathlib import Path
import stat

import pytest

from netops_admin import backup_nxos, cli
from netops_core import hostkey, ssh

REAL = Path(__file__).resolve().parents[2] / 'netops-helper/tests/fixtures/real/cisco_nxos'
RUNNING = (REAL / 'g98_9.3.12/b04-nx-a-running.out').read_bytes()
VERSION = (REAL / 'nexus9300v_9.3.12/version.txt').read_bytes()
PIN = 'SHA256:' + 'A' * 43
COMMAND = 'show running-config'
COUNT = COMMAND + ' | count'
# Derived replay: preserve measured line framing, replacing opaque lines with comments and
# two inert fields. The canary stands for an unredacted value only inside the private archive.
CANARY = b'g98-fixture-private-credential'
MARKER = b'<UNVERIFIED:cisco-nxos-opaque-line>'
CONFIG = (RUNNING.replace(MARKER, b'version 9.3(12) Bios:version', 1)
          .replace(MARKER, b'username fixture password 5 ' + CANARY + b' role network-admin', 1)
          .replace(MARKER, b'! redacted lab statement'))


@pytest.fixture
def wire(monkeypatch):
    replies = {'show version': (0, VERSION), COMMAND: (0, CONFIG),
               COUNT: (0, (REAL / 'g98_9.3.12/b04-nx-a-count-running.out').read_bytes())}
    events = []

    def pin(host, port, fingerprint, timeout):
        assert (host, port, fingerprint) == ('192.0.2.10', 2255, PIN)
        events.append('pin')
        return 'fixture pinned SSH key'

    def read(host, port, login, credential, known_host, command, **options):
        assert (host, port, login, known_host) == ('192.0.2.10', 2255, 'admin', 'fixture pinned SSH key')
        assert credential.use() == 'fixture-password'
        assert 0 < options['capture_max_bytes'] <= ssh.CAPTURE_MAX_BYTES
        events.append(command)
        rc, data = replies[command]
        return ssh.Result(rc=rc, stdout=data, said='', started_at='t0', finished_at='t1')

    monkeypatch.setenv('NETOPS_BACKUP_PASSWORD', 'fixture-password')
    monkeypatch.setenv('NETOPS_BACKUP_KEY', '3b' * 32)
    monkeypatch.setattr(hostkey, 'scan', pin)
    monkeypatch.setattr(ssh, 'run_command', read)
    return replies, events


@pytest.fixture
def operator(tmp_path, capsys):
    directory = tmp_path / 'private'
    directory.mkdir(mode=0o700)
    args = ['backup-nxos', '--host', '192.0.2.10', '--port', '2255', '--login', 'admin',
            '--ssh-host-key', PIN, '--directory', str(directory), '--keep', '1']

    def run(command):
        rc = cli.main(command)
        shown = capsys.readouterr()
        for value in (CANARY.decode(), 'fixture-password', '!Command: show running-config'):
            assert value not in shown.out + shown.err
        return rc, json.loads(shown.out)

    return directory, args, run


def test_preview_apply_retention_status_and_private_roundtrip(wire, operator):
    _, events = wire
    directory, args, run = operator
    rc, plan = run(args)
    assert rc == 0 and plan['result'] == 'ready'
    assert run([*args, '--status'])[1]['result'] == 'missing'
    assert not events and not list(directory.iterdir())
    command = [*args, '--confirm', plan['plan_sha256']]
    assert run([*args, '--confirm', 'wrong'])[1]['reason_codes'] == ['plan_changed']
    assert not events and not list(directory.iterdir())
    rc, first = run(command)
    assert rc == 0 and first['result'] == 'confirmed'
    rc, second = run(command)
    assert rc == 0 and second['retention_ok'] and second['firmware_support']['status'] == 'tested'
    assert events == ['pin', 'show version', COMMAND, COUNT] * 2
    encrypted, = directory.iterdir()
    assert encrypted.name == second['artifact'] != first['artifact']
    assert encrypted.read_bytes().startswith(backup_nxos.MAGIC)
    assert CANARY not in encrypted.read_bytes()
    assert hashlib.sha256(encrypted.read_bytes()).hexdigest() == second['sha256']
    assert stat.S_IMODE(encrypted.stat().st_mode) == 0o600
    rc, status = run([*args, '--status'])
    assert rc == 0 and status['result'] == 'available' and status['artifact'] == encrypted.name
    assert status['retained'] == 1 and status['retention_ok']
    assert len(events) == 8

    restored = directory / 'restore.cfg'
    extract = ['backup-unseal', '--platform', 'nxos', '--input', str(encrypted), '--output', str(restored)]
    rc, result = run(extract)
    assert rc == 0 and restored.read_bytes() == CONFIG
    assert stat.S_IMODE(restored.stat().st_mode) == 0o600
    assert result['sha256'] == hashlib.sha256(CONFIG).hexdigest()
    assert run(extract)[0] == 3
    restored.unlink()
    data = encrypted.read_bytes()
    encrypted.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
    assert run(extract)[1]['reason_codes'] == ['backup_invalid'] and not restored.exists()
    assert run([*args, '--status'])[1]['result'] == 'unverified'


@pytest.mark.parametrize(('mode', 'reason'), [
    ('refused', 'backup_refused'), ('line-truncated', 'backup_incomplete'),
    ('invalid-count', 'backup_incomplete'), ('pager', 'backup_incomplete'), ('missing-frame', 'backup_incomplete'),
])
def test_refused_or_incomplete_capture_leaves_previous_backup(wire, operator, mode, reason):
    replies, _ = wire
    directory, args, run = operator
    _, plan = run(args)
    command = [*args, '--confirm', plan['plan_sha256']]
    rc, first = run(command)
    assert rc == 0
    previous = directory / first['artifact']
    original = previous.read_bytes()
    bad_config = {
        'refused': (30, (REAL / 'g98_9.3.12/d-nxos-startup-refused.out').read_bytes()),
        'line-truncated': (0, b'\n'.join(CONFIG.split(b'\n')[:80]) + b'\n'),
        'pager': (0, CONFIG.replace(b'! redacted lab statement', b'--More--', 1)),
        'missing-frame': (0, CONFIG.replace(b'!Command:', b'!Unrecognized:', 1)),
    }
    if mode == 'invalid-count':
        replies[COUNT] = (0, b'')
    else:
        replies[COMMAND] = bad_config[mode]
    rc, failure = run(command)
    assert rc == 3 and failure['reason_codes'] == [reason]
    assert list(directory.iterdir()) == [previous] and previous.read_bytes() == original


def test_other_backup_key_preserves_previous_archive(wire, operator, monkeypatch):
    directory, args, run = operator
    _, plan = run(args)
    command = [*args, '--confirm', plan['plan_sha256']]
    _, first = run(command)
    previous = directory / first['artifact']
    original = previous.read_bytes()
    monkeypatch.setenv('NETOPS_BACKUP_KEY', '5a' * 32)
    rc, second = run(command)
    assert rc == 0 and second['retention_ok'] is False
    assert previous.read_bytes() == original and len(list(directory.iterdir())) == 2
    assert run([*args, '--status'])[1]['unverified'] == 1
