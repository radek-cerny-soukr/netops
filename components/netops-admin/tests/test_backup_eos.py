"""Local Admin CLI with pinned SSH transport replayed from measured cEOS responses."""

import hashlib
import json
from pathlib import Path
import stat

import pytest

from netops_admin import backup, backup_eos, cli
from netops_core import hostkey, ssh

REAL = Path(__file__).resolve().parents[2] / 'netops-helper/tests/fixtures/real/arista_eos'
EOS_CONFIG = REAL / 'eos_config_ceos_4.36.1F'
RUNNING = (EOS_CONFIG / 'running.out').read_bytes()
PIN = 'SHA256:' + 'A' * 43
KEY = '3b' * 32


def _without_configuration(data):
    # Keep the measured device header and EOS framing, with only separators in the body.
    lines = data.splitlines(keepends=True)
    header = next(index for index, line in enumerate(lines) if line.startswith(b'! device: '))
    return b''.join(lines[:header + 1]) + b'!\nend\n'


@pytest.fixture
def wire(monkeypatch):
    replies = {
        'show privilege': (0, (EOS_CONFIG / 'privilege-admin.out').read_bytes()),
        'show version': (0, (REAL / 'ceos_4.36.1F/version.txt').read_bytes()),
        'show running-config': (0, RUNNING),
    }
    events = []

    def pin(host, port, fingerprint, timeout):
        assert (host, port, fingerprint) == ('192.0.2.10', 2253, PIN)
        events.append('pin')
        return 'fixture pinned SSH key'

    def read(host, port, login, credential, known_host, command, **options):
        assert (host, port, login, known_host) == ('192.0.2.10', 2253, 'admin', 'fixture pinned SSH key')
        assert credential.use() == 'capability-fixture-password'
        assert 0 < options['capture_max_bytes'] <= ssh.CAPTURE_MAX_BYTES
        events.append(command)
        rc, stdout = replies[command]
        return ssh.Result(rc=rc, stdout=stdout, said='', started_at='t0', finished_at='t1')

    monkeypatch.setenv('NETOPS_BACKUP_PASSWORD', 'capability-fixture-password')
    monkeypatch.setenv('NETOPS_BACKUP_KEY', KEY)
    monkeypatch.setattr(hostkey, 'scan', pin)
    monkeypatch.setattr(ssh, 'run_command', read)
    return replies, events


@pytest.fixture
def operator(tmp_path, capsys):
    directory = tmp_path / 'private'
    directory.mkdir(mode=0o700)
    args = ['backup-eos', '--host', '192.0.2.10', '--port', '2253', '--login', 'admin',
            '--ssh-host-key', PIN, '--directory', str(directory), '--keep', '1']

    def execute(command):
        rc = cli.main(command)
        shown = capsys.readouterr()
        for value in ('capability-fixture-password', '! device:', 'fixture-opaque-statement'):
            assert value not in shown.out + shown.err
        return rc, json.loads(shown.out)

    return directory, args, execute


def test_eos_preview_confirm_retention_and_restore_readback(wire, operator):
    replies, events = wire
    directory, args, run = operator
    rc, plan = run(args)
    assert rc == 0 and plan['result'] == 'ready'
    assert plan['plan']['platform'] == 'arista_eos'
    assert not events and not list(directory.iterdir())
    cmd = [*args, '--confirm', plan['plan_sha256']]
    rc, first = run(cmd)
    assert rc == 0 and first['result'] == 'confirmed'
    replies['show running-config'] = (0, (EOS_CONFIG / 'running-changed.out').read_bytes())
    rc, second = run(cmd)
    assert rc == 0 and second['retention_ok'] and second['firmware_support']['status'] == 'tested'
    assert events == ['pin', 'show privilege', 'show version', 'show running-config'] * 2
    encrypted, = directory.iterdir()
    assert encrypted.name == second['artifact'] and encrypted.name != first['artifact']
    assert encrypted.read_bytes().startswith(b'NETOPS-EOS-BACKUP\x00\x01')
    assert hashlib.sha256(encrypted.read_bytes()).hexdigest() == second['sha256']
    assert stat.S_IMODE(encrypted.stat().st_mode) == 0o600
    assert b'EOS-CONFIG-VERIFY' not in encrypted.read_bytes()

    restored = directory / 'restore.cfg'
    unseal = ['backup-unseal', '--platform', 'eos', '--input', str(encrypted), '--output', str(restored)]
    rc, result = run(unseal)
    expected = replies['show running-config'][1].split(b'! device:', 1)[1]
    assert rc == 0 and restored.read_bytes() == b'! device:' + expected
    assert stat.S_IMODE(restored.stat().st_mode) == 0o600
    assert result['metadata']['version'] == '4.36.1F'
    assert result['sha256'] == hashlib.sha256(restored.read_bytes()).hexdigest()
    assert run(unseal)[0] == 3  # Existing restore files are preserved.

    tampered = bytearray(encrypted.read_bytes())
    tampered[-1] ^= 1
    encrypted.write_bytes(tampered)
    restored.unlink()
    rc, rejected = run(unseal)
    assert rc == 3 and rejected['reason_codes'] == ['backup_invalid'] and not restored.exists()


@pytest.mark.parametrize('mode, reason', [('incomplete', 'backup_incomplete'), ('empty-body', 'backup_incomplete'),
                                          ('no-hostname', 'backup_incomplete'), ('no-interface', 'backup_incomplete'),
                                          ('wrong-header', 'backup_incomplete'),
                                          ('unprivileged', 'backup_refused'), ('wrong-plan', 'plan_changed')])
def test_eos_refusal_preserves_prior_backup(wire, operator, mode, reason):
    replies, events = wire
    directory, args, run = operator
    _, plan = run(args)
    cmd = [*args, '--confirm', plan['plan_sha256']]
    rc, first = run(cmd)
    assert rc == 0
    file = directory / first['artifact']
    before = file.read_bytes()
    events.clear()
    if mode == 'incomplete':
        replies['show running-config'] = (0, RUNNING.removesuffix(b'end\n'))
    elif mode == 'empty-body':
        replies['show running-config'] = (0, _without_configuration(RUNNING))
    elif mode in ('no-hostname', 'no-interface'):
        prefix = b'hostname ' if mode == 'no-hostname' else b'interface '
        replies['show running-config'] = (0, b''.join(
            line for line in RUNNING.splitlines(keepends=True) if not line.startswith(prefix)
        ))
    elif mode == 'wrong-header':
        replies['show running-config'] = (0, (EOS_CONFIG / 'startup.out').read_bytes())
    elif mode == 'unprivileged':
        replies['show privilege'] = (0, (EOS_CONFIG / 'privilege-ro.out').read_bytes())
    else:
        cmd[-1] = '0' * 64
    rc, rejected = run(cmd)
    assert rc == 3 and rejected['reason_codes'] == [reason]
    assert list(directory.iterdir()) == [file] and file.read_bytes() == before
    if mode == 'wrong-plan':
        assert not events
    if mode == 'unprivileged':
        assert events == ['pin', 'show privilege']


def test_eos_unseal_refuses_authenticated_archive_without_configuration(wire, operator):
    directory, args, run = operator
    _, plan = run(args)
    rc, first = run([*args, '--confirm', plan['plan_sha256']])
    assert rc == 0
    archive = directory / first['artifact']
    key = bytes.fromhex(KEY)
    data = backup._read_backup(archive, key, magic=backup_eos.MAGIC, maximum=backup_eos.MAX_BYTES + backup_eos.MAX_METADATA)
    header, config = data.split(b'\n', 1)
    incomplete = _without_configuration(config)
    metadata = json.loads(header)
    metadata['bytes'] = len(incomplete)
    archive.write_bytes(backup._seal(json.dumps(metadata).encode() + b'\n' + incomplete, key, backup_eos.MAGIC))

    restored = directory / 'restore.cfg'
    rc, result = run(['backup-unseal', '--platform', 'eos', '--input', str(archive), '--output', str(restored)])
    assert rc == 3 and result['reason_codes'] == ['backup_invalid'] and not restored.exists()


def test_eos_untested_firmware_warns_and_keeps_backup(wire, operator):
    replies, _ = wire
    directory, args, run = operator
    for command in ('show version', 'show running-config'):
        rc, data = replies[command]
        replies[command] = (rc, data.replace(b'4.36.1F', b'4.36.2F'))
    _, plan = run(args)
    rc, result = run([*args, '--confirm', plan['plan_sha256']])
    assert rc == 0 and len(list(directory.iterdir())) == 1
    assert result['firmware_support']['status'] == 'untested' and result['warnings']
