"""Operator CLI and authenticated IOS backup with anonymized lab capture replay."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat

import pytest

from netops.files import write_private
from netops_admin import backup, backup_ios, cli
from netops_core import hostkey, ssh

FIXTURES = Path(__file__).resolve().parents[2] / 'netops-helper/tests/fixtures/real/cisco_ios/g58'
PIN = 'SHA256:' + 'A' * 43
REPLACEMENT_PIN = 'SHA256:' + 'B' * 43
PASSWORD = 'fixture-device-password'
OPAQUE = b'fixture-config-secret'


@pytest.fixture(params=('iosv', 'iosvl2'))
def wire(monkeypatch, request):
    device = request.param
    raw = (FIXTURES / f'{device}-running.out').read_bytes()
    head = backup_ios.HEADER.match(raw.lstrip(b" \t\n"))
    # Derived from the measured wrapper and anonymized body. Substitute one
    # fictional credential and adjust the header for the redacted lengths.
    data = raw.lstrip(b" \t\n")[head.end():].replace(
        b'<UNVERIFIED:cisco-ios-opaque-line>', b'username fixture secret ' + OPAQUE, 1)
    framed = re.sub(rb'Current configuration : [0-9]+ bytes',
                    f'Current configuration : {len(data)} bytes'.encode(),
                    raw.lstrip(b" \t\n")[:head.end()]) + data
    replies = {'show version': (FIXTURES / f'{device}-version.out').read_bytes(),
               backup_ios.COMMAND: framed, 'denied': (FIXTURES / f'{device}-refused.out').read_bytes()}
    events = []

    def pin(host, port, fingerprint, timeout, *, legacy):
        assert (host, port, legacy) == ('192.0.2.10', 2251, 'rsa-sha1-dh14')
        assert fingerprint in (PIN, REPLACEMENT_PIN)
        events.append('pin')
        return 'pinned test key'

    def read(host, port, login, credential, key, command, **options):
        assert (host, port, login, key) == ('192.0.2.10', 2251, 'netops-admin', 'pinned test key')
        assert credential.use() == PASSWORD
        assert options['capture_max_bytes'] == backup_ios.MAX_BYTES
        events.append(command)
        return ssh.Result(rc=0, stdout=replies[command], said='', started_at='t0', finished_at='t1')

    monkeypatch.setattr(hostkey, 'scan', pin)
    monkeypatch.setattr(ssh, 'run_command', read)
    monkeypatch.setenv('NETOPS_BACKUP_PASSWORD', PASSWORD)
    monkeypatch.setenv('NETOPS_BACKUP_KEY', '3d' * 32)
    return events, replies, data


@pytest.fixture
def operator(tmp_path, capsys):
    directory = tmp_path / 'private'
    directory.mkdir(mode=0o700)
    options = ['--host', '192.0.2.10', '--port', '2251', '--directory', str(directory)]
    args = ['backup-ios', *options, '--login', 'netops-admin', '--ssh-sha256', PIN,
            '--legacy-ssh', 'rsa-sha1-dh14', '--keep', '1']

    def run(arguments):
        rc = cli.main(arguments)
        shown = capsys.readouterr()
        assert all(value not in shown.out + shown.err for value in (PASSWORD, OPAQUE.decode(), 'hostname host01'))
        return rc, json.loads(shown.out)

    return directory, args, ['backup-ios-status', *options], run


def _confirmed(args, run):
    rc, plan = run(args)
    assert rc == 0 and plan['result'] == 'ready'
    return [*args, '--confirm', plan['plan_sha256']]


def _publish(directory, args, run):
    rc, result = run(args)
    assert rc == 0 and result['result'] == 'confirmed' and result['retention_ok']
    return directory / result['artifact']


def test_ios_retention_preserves_previous_device_on_same_endpoint(wire, operator):
    events, _, _ = wire
    directory, args, _, run = operator
    old = _publish(directory, _confirmed(args, run), run)
    old_bytes = old.read_bytes()
    replacement = [REPLACEMENT_PIN if arg == PIN else arg for arg in args]
    confirm = _confirmed(replacement, run)
    new = _publish(directory, confirm, run)
    assert old.exists() and old.read_bytes() == old_bytes
    old_prefix, stamp, suffix = old.name.rsplit('-', 2)
    new_prefix = new.name.rsplit('-', 2)[0]
    assert old_prefix != new_prefix

    # Archives moved within the store still need to prove their identity.
    misplaced = directory / f'{new_prefix}-{stamp}-{suffix}'
    write_private(misplaced, old_bytes)
    os.utime(misplaced, ns=(1, 1))
    latest = _publish(directory, confirm, run)
    assert set(directory.iterdir()) == {old, misplaced, latest}
    assert misplaced.read_bytes() == old_bytes
    assert events == ['pin', 'show version', backup_ios.COMMAND] * 3


def test_ios_retention_authenticates_every_candidate_after_key_rotation(wire, operator, monkeypatch):
    directory, args, status, run = operator
    keep_two = [*args[:-1], '2']
    confirm = _confirmed(keep_two, run)
    previous_key = _publish(directory, confirm, run)
    old_bytes = previous_key.read_bytes()
    os.utime(previous_key, ns=(1, 1))
    parked = directory / 'previous-key.backup'
    previous_key.rename(parked)

    monkeypatch.setenv('NETOPS_BACKUP_KEY', '4c' * 32)
    current_key = _publish(directory, confirm, run)
    parked.rename(previous_key)
    latest = _publish(directory, _confirmed(args, run), run)
    assert set(directory.iterdir()) == {previous_key, latest}
    assert not current_key.exists() and previous_key.read_bytes() == old_bytes
    assert run(status)[1]['artifact'] == latest.name


def test_ios_legacy_backup_remains_usable_and_outside_retention(wire, operator):
    _, _, config = wire
    directory, args, status, run = operator
    endpoint = hashlib.sha256(b'192.0.2.10:2251').hexdigest()[:32]
    old = directory / f'ios-{endpoint}-20261119T000000Z-{"a" * 32}.netops-backup'
    sealed = backup._seal(config, bytes.fromhex('3d' * 32), b'NETOPS-IOS-BACKUP\x00\x01')
    write_private(old, sealed)
    assert run(status)[1]['artifact'] == old.name
    restored = directory / 'previous.cfg'
    assert run(['backup-unseal', '--platform', 'ios', '--input', str(old), '--output', str(restored)])[0] == 0
    assert restored.read_bytes() == config

    new = _publish(directory, _confirmed(args, run), run)
    assert old.exists() and old.read_bytes() == sealed
    assert run(status)[1]['artifact'] == new.name


def test_ios_backup_refuses_older_ios_xe_identity_before_config_read(wire, operator):
    events, replies, _ = wire
    directory, args, _, run = operator
    replies['show version'] = (FIXTURES.parents[2] / 'identity/cisco_xe_isr4331.txt').read_bytes()
    rc, result = run(_confirmed(args, run))
    assert rc != 0 and result.get('reason_codes') == ['backup_identity_mismatch']
    assert events == ['pin', 'show version']
    assert not list(directory.iterdir())


def test_ios_preview_scheduled_capture_retention_status_and_unseal(wire, operator, monkeypatch):
    events, _, expected = wire
    directory, args, status, run = operator
    with monkeypatch.context() as without_secrets:
        without_secrets.delenv('NETOPS_BACKUP_KEY')
        without_secrets.delenv('NETOPS_BACKUP_PASSWORD')
        rc, plan = run(args)
        assert rc == 0 and plan['result'] == 'ready'
        assert run(status)[1] == {'result': 'missing', 'last_backup': None}
    assert events == [] and not list(directory.iterdir())
    command = [*args, '--confirm', plan['plan_sha256']]
    rc, first = run(command)
    assert rc == 0 and first['result'] == 'confirmed'
    rc, second = run(command)
    assert rc == 0 and second['retention_ok']
    assert events == ['pin', 'show version', backup_ios.COMMAND] * 2
    encrypted, = directory.iterdir()
    assert encrypted.name == second['artifact'] and first['artifact'] != encrypted.name
    assert stat.S_IMODE(encrypted.stat().st_mode) == 0o600
    assert encrypted.read_bytes().startswith(backup_ios.MAGIC)
    assert OPAQUE not in encrypted.read_bytes()
    rc, latest = run(status)
    assert rc == 0 and latest['artifact'] == encrypted.name and latest['last_backup'].endswith('Z')
    restored = directory / 'restore.cfg'
    unseal = ['backup-unseal', '--platform', 'ios', '--input', str(encrypted), '--output', str(restored)]
    assert run(unseal) == (0, {'result': 'confirmed', 'bytes': len(expected)})
    assert restored.read_bytes() == expected and stat.S_IMODE(restored.stat().st_mode) == 0o600
    assert run(unseal)[0] != 0  # Existing restore files are preserved.
    assert restored.read_bytes() == expected
    damaged = bytearray(encrypted.read_bytes())
    damaged[-1] ^= 1
    encrypted.write_bytes(damaged)
    assert run(status)[1]['reason_codes'] == ['backup_invalid']


@pytest.mark.parametrize('case', ['denied', 'no-end', 'size-mismatch'])
def test_ios_refused_or_incomplete_capture_preserves_existing_backup(wire, operator, case):
    events, replies, _ = wire
    directory, args, status, run = operator
    plan = run(args)[1]
    confirmed = [*args, '--confirm', plan['plan_sha256']]
    assert run(confirmed)[0] == 0
    existing, = directory.iterdir()
    before = existing.read_bytes()
    command = backup_ios.COMMAND
    if case == 'denied':
        replies[command] = replies['denied']
    elif case == 'no-end':
        replies[command] = replies[command].removesuffix(b'end\n')
    else:
        replies[command] = replies[command].replace(b'username fixture secret ' + OPAQUE + b'\n', b'')
    rc, result = run(confirmed)
    assert rc != 0
    assert result['reason_codes'] == ['backup_refused' if case == 'denied' else 'backup_incomplete']
    assert events == ['pin', 'show version', backup_ios.COMMAND] * 2
    assert list(directory.iterdir()) == [existing] and existing.read_bytes() == before
    assert run(status)[1]['artifact'] == existing.name
