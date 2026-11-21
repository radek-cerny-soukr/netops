"""Local Admin CLI, with only the HTTPS wire replayed."""
import hashlib
import json
import os
from pathlib import Path
import stat

import pytest

from netops_admin import backup, cli

PROJECTED = (Path(__file__).parent / 'fixtures/g16/fg60f-global.conf').read_bytes()
# Extend the real transport projection with synthetic global sections for a positive replay.
HEADER, INTERFACES = PROJECTED.split(b'\n', 1)
EXPORT = (HEADER + b'\nconfig system global\n    set hostname "fixture-60f"\nend\n' + INTERFACES +
          b'config system admin\n    edit "fixture-admin"\n        set accprofile "super_admin"\n    next\nend\n'
          b'config firewall address\n    edit "all"\n    next\nend\n')
PINNED_CERTIFICATE = b'fixture certificate for the transport boundary'
PIN = hashlib.sha256(PINNED_CERTIFICATE).hexdigest()


class Reply:
    def __init__(self, status, body, headers=()):
        self.status = status
        self.body = body
        self.headers = dict(headers)
        self.headers.setdefault('Content-Length', str(len(body)))

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, maximum):
        return self.body[:maximum]

    def getheader(self, name):
        return self.headers.get(name)

    def getheaders(self):
        return list(self.headers.items())


@pytest.fixture
def wire(monkeypatch):
    replies = {
        ('POST', backup.AUTH): Reply(200, b'{"status_message":"LOGIN_SUCCESS"}'),
        ('POST', backup.EXPORT): Reply(200, EXPORT),
        ('DELETE', backup.AUTH): Reply(200, b'{}'),
    }
    events = []

    class Transport:
        def __init__(self, host, port, **options):
            assert (host, port) == ('192.0.2.10', 443)
            self.sock = self

        def connect(self):
            pass

        def getpeercert(self, binary_form):
            assert binary_form
            return PINNED_CERTIFICATE

        def request(self, method, path, *, body, headers):
            self.endpoint = method, path
            events.append(self.endpoint)
            if path == backup.EXPORT:
                assert headers['Cookie'] == 'session_key_443_fixture=fixture-session'
                assert headers['X-CSRFTOKEN'] == 'fixture-csrf'

        def getresponse(self):
            reply = replies[self.endpoint]
            if self.endpoint != ('POST', backup.AUTH):
                return reply
            original = reply.getheaders
            # HTTP supports multiple Set-Cookie fields with the same name.
            reply = Reply(reply.status, reply.body)
            reply.getheaders = lambda: [*original(), ('Set-Cookie', 'session_key_443_fixture=fixture-session; Secure'),
                                       ('Set-Cookie', 'ccsrf_token_443_fixture=fixture-csrf; Secure')]
            return reply

        def close(self):
            pass

    monkeypatch.setenv('NETOPS_BACKUP_PASSWORD', 'fixture-only-password')
    monkeypatch.setenv('NETOPS_BACKUP_KEY', 'c3' * 32)
    monkeypatch.setattr(backup, 'HTTPSConnection', Transport)
    return replies, events


@pytest.fixture
def operator(tmp_path, capsys):
    directory = tmp_path / 'private'
    directory.mkdir(mode=0o700)
    args = ['backup', '--host', '192.0.2.10', '--login', 'netops-test-rw',
            '--tls-sha256', PIN, '--directory', str(directory), '--keep', '1']

    def execute(arguments):
        rc = cli.main(arguments)
        result = capsys.readouterr()
        assert 'fixture-only-password' not in result.out + result.err
        assert '#config-version=' not in result.out + result.err
        return rc, json.loads(result.out)
    return directory, args, execute


def test_preview_confirm_retention_and_round_trip(wire, operator):
    replies, events = wire
    directory, args, cli = operator
    rc, plan = cli(args)
    assert rc == 0 and plan['result'] == 'ready'
    assert not events and not list(directory.iterdir())
    cmd = [*args, '--confirm', plan['plan_sha256']]
    rc, first = cli(cmd)
    assert rc == 0 and first['firmware_support']['status'] == 'tested'
    rc, second = cli(cmd)
    assert rc == 0 and second['result'] == 'confirmed' and second['retention_ok']
    encrypted, = directory.iterdir()
    assert encrypted.name == second['artifact'] and encrypted.name != first['artifact']
    assert stat.S_IMODE(encrypted.stat().st_mode) == 0o600
    assert hashlib.sha256(encrypted.read_bytes()).hexdigest() == second['sha256']
    assert encrypted.stat().st_size == second['bytes']
    assert b'config system interface' not in encrypted.read_bytes()
    assert events == [('POST', backup.AUTH), ('POST', backup.EXPORT), ('DELETE', backup.AUTH)] * 2

    restored = directory / 'restore.conf'
    rc, readback = cli(['backup-unseal', '--input', str(encrypted), '--output', str(restored)])
    assert rc == 0 and readback['sha256'] == hashlib.sha256(EXPORT).hexdigest()
    assert restored.read_bytes() == EXPORT and stat.S_IMODE(restored.stat().st_mode) == 0o600
    damaged = bytearray(encrypted.read_bytes())
    damaged[-1] ^= 1
    encrypted.write_bytes(damaged)
    restored.unlink()
    rc, rejected = cli(['backup-unseal', '--input', str(encrypted), '--output', str(restored)])
    assert rc == 3 and rejected['reason_codes'] == ['backup_invalid'] and not restored.exists()


@pytest.mark.parametrize('projection', [PROJECTED, EXPORT.split(b'config firewall address')[0]],
                         ids=['interface-only', 'missing-late-section'])
def test_balanced_partial_export_does_not_replace_prior_backup(wire, operator, projection):
    replies, events = wire
    directory, args, cli = operator
    _, plan = cli(args)
    cmd = [*args, '--confirm', plan['plan_sha256']]
    rc, first = cli(cmd)
    assert rc == 0 and first['result'] == 'confirmed'
    previous = (directory / first['artifact']).read_bytes()
    replies[('POST', backup.EXPORT)] = Reply(200, projection)
    rc, result = cli(cmd)
    assert rc == 3 and result['reason_codes'] == ['backup_incomplete']
    remaining, = directory.iterdir()
    assert remaining.name == first['artifact'] and remaining.read_bytes() == previous
    assert events[-1] == ('DELETE', backup.AUTH)


def _policy_exports(layout):
    fixture = (Path(__file__).parent / 'fixtures/fortios_8_0_0.conf').read_bytes()
    policy = b'config firewall policy\n' + fixture.split(b'config firewall policy\n', 1)[1]
    full, truncated = EXPORT + policy, EXPORT
    if layout != 'top-level':
        header, _, body = EXPORT.partition(b'\n')
        global_config, address = body.split(b'config firewall address\n', 1)
        vdom = header + b'\nconfig global\n' + global_config + b'end\nconfig vdom\n    edit root\n'
        address = b'config firewall address\n' + address
        if layout == 'multi-vdom':
            # Derived: root retains its policy, while the later VDOM can lose the entire policy section.
            vdom += address + policy + b'    next\n    edit "VD1"\n'
        full = vdom + address + policy + b'    next\nend\n'
        truncated = vdom + address + b'    next\nend\n'
    return full, truncated


@pytest.mark.parametrize('layout', ['top-level', 'vdom', 'multi-vdom'])
def test_export_missing_previously_confirmed_policy_preserves_backup(wire, operator, layout):
    replies, events = wire
    directory, args, cli = operator
    full, truncated = _policy_exports(layout)
    _, plan = cli(args)
    cmd = [*args, '--confirm', plan['plan_sha256']]
    replies[('POST', backup.EXPORT)] = Reply(200, full)
    rc, first = cli(cmd)
    assert rc == 0 and first['result'] == 'confirmed'
    previous = (directory / first['artifact']).read_bytes()

    # Reply derives Content-Length from the shortened body, whose last block is closed.
    replies[('POST', backup.EXPORT)] = Reply(200, truncated)
    rc, result = cli(cmd)
    assert rc == 3 and result['result'] == 'rejected'
    assert result['reason_codes'] == ['backup_incomplete']
    assert any('firewall policy' in reason for reason in result['reasons'])
    if layout == 'multi-vdom':
        assert any('VD1' in reason for reason in result['reasons'])
    remaining, = directory.iterdir()
    assert remaining.name == first['artifact'] and remaining.read_bytes() == previous
    assert events == [('POST', backup.AUTH), ('POST', backup.EXPORT), ('DELETE', backup.AUTH)] * 2


@pytest.mark.parametrize('unreadable', ['rotated-key', 'damaged-tag'])
def test_backup_compares_with_newest_readable_archive(wire, operator, monkeypatch, unreadable):
    replies, _ = wire
    directory, args, cli = operator
    full, truncated = _policy_exports('multi-vdom')
    _, plan = cli(args)
    cmd = [*args, '--confirm', plan['plan_sha256']]
    replies[('POST', backup.EXPORT)] = Reply(200, full)

    rc, first = cli(cmd)
    assert rc == 0 and first['result'] == 'confirmed'
    readable = directory / first['artifact']
    os.utime(readable, (1, 1))  # Make the archive ordering independent of timestamp resolution.
    if unreadable == 'rotated-key':
        with monkeypatch.context() as rotated:
            rotated.setenv('NETOPS_BACKUP_KEY', 'd4' * 32)
            rc, second = cli(cmd)
    else:
        # Keep the first archive until the second one's authentication tag is damaged.
        keep_two = [*args[:-1], '2']
        _, plan = cli(keep_two)
        rc, second = cli([*keep_two, '--confirm', plan['plan_sha256']])
    assert rc == 0 and second['result'] == 'confirmed'
    newer = directory / second['artifact']
    if unreadable == 'damaged-tag':
        damaged = bytearray(newer.read_bytes())
        damaged[-1] ^= 1
        newer.write_bytes(damaged)
    originals = {readable: readable.read_bytes(), newer: newer.read_bytes()}

    replies[('POST', backup.EXPORT)] = Reply(200, truncated)
    rc, result = cli(cmd)
    assert rc == 3 and result['result'] == 'rejected'
    assert result['reason_codes'] == ['backup_incomplete']
    assert any('VD1 / firewall policy' in reason for reason in result['reasons'])
    assert {path: path.read_bytes() for path in directory.iterdir()} == originals

    replies[('POST', backup.EXPORT)] = Reply(200, full)
    rc, result = cli(cmd)
    assert rc == 0 and result['result'] == 'confirmed' and result['retention_ok']
    assert not any('comparison skipped' in warning for warning in result.get('warnings', []))
    assert set(directory.iterdir()) == {newer, directory / result['artifact']}
    assert newer.read_bytes() == originals[newer]


def test_rotated_key_preserves_old_archive_and_uses_retention_for_new_key(wire, operator, monkeypatch):
    replies, _ = wire
    directory, args, cli = operator
    _, plan = cli(args)
    cmd = [*args, '--confirm', plan['plan_sha256']]
    rc, first = cli(cmd)
    assert rc == 0 and first['result'] == 'confirmed'
    old = directory / first['artifact']
    previous = old.read_bytes()
    monkeypatch.setenv('NETOPS_BACKUP_KEY', 'd4' * 32)

    replies[('POST', backup.EXPORT)] = Reply(200, PROJECTED)
    rc, incomplete = cli(cmd)
    assert rc == 3 and incomplete['reason_codes'] == ['backup_incomplete']
    assert list(directory.iterdir()) == [old] and old.read_bytes() == previous

    replies[('POST', backup.EXPORT)] = Reply(200, EXPORT)
    rc, rotated = cli(cmd)
    assert rc == 0 and rotated['result'] == 'confirmed' and rotated['retention_ok']
    assert any('comparison skipped' in warning for warning in rotated['warnings'])
    assert {path.name for path in directory.iterdir()} == {old.name, rotated['artifact']}

    rc, latest = cli(cmd)
    assert rc == 0 and latest['result'] == 'confirmed' and latest['retention_ok']
    assert {path.name for path in directory.iterdir()} == {old.name, latest['artifact']}
    assert old.read_bytes() == previous


@pytest.fixture(params=['gitdir', 'gitfile', 'symlink-in', 'symlink-out'])
def git_destination(tmp_path, request):
    repository = tmp_path / 'repo'
    repository.mkdir()
    marker = repository / '.git'
    if request.param == 'gitfile':
        marker.write_text('gitdir: ../metadata/worktrees/checkout\n')
    else:
        marker.mkdir()
    destination = repository / 'nested' / 'private'
    if request.param == 'symlink-out':
        outside = tmp_path / 'outside'
        outside.mkdir()
        destination.parent.symlink_to(outside, target_is_directory=True)
    destination.mkdir(mode=0o700, parents=True)
    if request.param == 'symlink-in':
        shortcut = tmp_path / 'shortcut'
        shortcut.symlink_to(repository, target_is_directory=True)
        return shortcut / destination.relative_to(repository)
    return destination


def test_backup_rejects_destination_in_git_before_transfer(wire, operator, git_destination):
    _, events = wire
    _, args, cli = operator
    _, safe_plan = cli(args)
    args[args.index('--directory') + 1] = str(git_destination)
    for command in (args, [*args, '--confirm', safe_plan['plan_sha256']]):
        rc, result = cli(command)
        assert rc == 3 and result['reason_codes'] == ['backup_destination_unsafe']
    assert not events and not list(git_destination.iterdir())


def test_unseal_rejects_destination_in_git(wire, operator, git_destination):
    directory, args, cli = operator
    _, plan = cli(args)
    rc, result = cli([*args, '--confirm', plan['plan_sha256']])
    assert rc == 0
    encrypted = directory / result['artifact']
    rc, result = cli(['backup-unseal', '--input', str(encrypted),
                      '--output', str(git_destination / 'restore.conf')])
    assert rc == 3 and result['reason_codes'] == ['backup_destination_unsafe']
    assert not list(git_destination.iterdir())


@pytest.mark.parametrize('failure', ['permission', 'incomplete', 'length', 'masked'])
def test_refused_or_partial_download_leaves_no_artifact(wire, operator, failure):
    replies, events = wire
    directory, args, cli = operator
    _, plan = cli(args)
    body = EXPORT.removesuffix(b'end\n')
    replies[('POST', backup.EXPORT)] = {
        'permission': Reply(403, b'{}'),
        'incomplete': Reply(200, body),
        'length': Reply(200, body, [('Content-Length', str(len(EXPORT)))]),
        # Fortinet's documented marker for an obfuscated export; inject it into the real projection.
        'masked': Reply(200, EXPORT.replace(b'\n', b'\n#password_mask=1\n', 1)),
    }[failure]
    rc, result = cli([*args, '--confirm', plan['plan_sha256']])
    expected = 'backup_refused' if failure == 'permission' else 'backup_incomplete'
    assert rc == 3 and result['reason_codes'] == [expected]
    assert events[-1] == ('DELETE', backup.AUTH) and not list(directory.iterdir())


def test_tls_pin_and_confirmation_are_checked_before_credentials(wire, operator):
    _, events = wire
    directory, args, cli = operator
    _, plan = cli(args)
    wrong = [*args, '--tls-sha256', 'a' * 64]
    rc, result = cli([*wrong, '--confirm', plan['plan_sha256']])
    assert rc == 3 and result['reason_codes'] == ['plan_changed']
    _, new_plan = cli(wrong)
    rc, result = cli([*wrong, '--confirm', new_plan['plan_sha256']])
    assert rc == 3 and result['reason_codes'] == ['backup_identity_mismatch']
    assert not events and not list(directory.iterdir())
