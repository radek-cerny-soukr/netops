"""G136 (J43): encrypted Junos backup with rescue save, unseal, and restore with load override + commit confirmed.

The Admin CLI and ``backup_junos`` run unchanged; only the physical transport is replaced: ``ssh.run_command``
(SSH exec) and ``session.Session`` (the interactive CLI) by ``FakeJunos``, which answers with the REAL
d-vjunos captures in ``fixtures/junos_g136`` (vJunos-switch 26.2R1.7, task 553; password hashes are sentinels)
and the session texts measured there: ``configure exclusive`` (discard warning), ``load override terminal``
(``[Type ^D at a new line to end input]``), Ctrl-D (``^D`` + ``load complete``), ``commit confirmed N`` (two
lines and the banner), ``exit configuration-mode``.
"""

import hashlib
import json
import re
from pathlib import Path

import pytest

from netops_admin import backup_junos, cli
from netops_core import session as core_session, ssh as core_ssh

FIX = Path(__file__).parent / 'fixtures' / 'junos_g136'
CONFIG = (FIX / 'config_hierarchical_admin.out').read_text()
CONFIG_RO = (FIX / 'config_hierarchical_ro.out').read_text()
VERSION = (FIX / 'version_admin.out').read_text()
NO_RESCUE = (FIX / 'rescue_absent_admin.out').read_text()
RESCUE_SHOW = 'show system configuration rescue | no-more'
PIN = 'SHA256:' + 'd' * 43
HOST = '192.0.2.10'
SENTINEL = 'SECRET-HASH-SENTINEL'
PASSWORD = 'fixture-backup-password'
MESSAGE = '    login {\n        message "netops-g136-test";\n'


def body(text):
    return backup_junos.normalized(text)


def canonical(text):
    """Junos prints a value without spaces unquoted (measured: message "netops-g136-test" -> message netops-g136-test)."""
    return re.sub(r'"([A-Za-z0-9._-]+)"', r'\1', text)


def with_message(text):
    """DERIVED: the measured configuration with the one test change of the live run (system login message)."""
    return text.replace('    login {\n', MESSAGE, 1)


class FakeJunos:
    def __init__(self, config=CONFIG):
        self.config = config
        self.history = [['2026-11-19 01:51:03', 'user01', None, 'netops-g136-confirm-empty']]
        self.pending = None
        self.rescue = None
        self.calls, self.sessions = [], 0
        self.mangle = False          # the device stores something else than the loaded text
        self.load_errors = False
        self.readback_failure = None
        self.revert_failure = False
        self.clock = 0

    # -- SSH exec --------------------------------------------------------------------------------------
    def run_command(self, host, port, login, credential, known, command, *, timeout_seconds=None,
                    capture_max_bytes=None, **_):
        assert (host, port, credential.use(), known) == (HOST, 22, PASSWORD, HOST + ' ssh-ed25519 Zml4dHVyZQ==')
        self.calls.append(command)
        if self.pending and command == self.readback_failure:
            raise core_ssh.SshError('fixture disconnect after commit complete')
        if command == backup_junos.VERSION:
            out = VERSION
        elif command == backup_junos.SHOW:
            out = self.config
        elif command == backup_junos.COMMITS:
            out = self.commits()
        elif command == backup_junos.RESCUE_SAVE:
            self.rescue, out = self.config, ''
        elif command == RESCUE_SHOW:
            out = self.rescue if self.rescue is not None else NO_RESCUE
        elif command == backup_junos.RESCUE_COUNT:
            # measured: without a rescue configuration the error line itself is counted ('Count: 1 lines')
            out = 'Count: 1 lines\n' if self.rescue is None else 'Count: %d lines\n' % len(self.rescue.splitlines())
        else:
            raise AssertionError(command)
        return core_ssh.Result(rc=0, stdout=out.encode(), said='', started_at='t0', finished_at='t1')

    def commits(self):
        rows = []
        for index, (at, user, minutes, comment) in enumerate(self.history):
            confirmed = ' commit confirmed, rollback in %dmins' % minutes if minutes else ''
            rows.append('%-3d %s UTC by %s via cli%s' % (index, at, user, confirmed))
            rows.append('    ' + comment)
            if index == 0 and self.pending:
                rows.append('    rollback pending')
        if self.rescue is not None:
            rows.append('rescue  2026-11-19 02:10:53 UTC by user01 via cli')
        return '\n'.join(rows) + '\n'

    def commit(self, candidate, comment, minutes=None):
        self.clock += 1
        stored = with_message(candidate) if self.mangle and minutes else candidate
        self.config = '## Last commit: 2026-11-19 03:00:%02d UTC by user01\n' % self.clock + canonical(body(stored))
        self.history.insert(0, ['2026-11-19 03:00:%02d' % self.clock, 'user01', minutes, comment])
        self.pending = bool(minutes)

    # -- interactive CLI -------------------------------------------------------------------------------
    def session(self, host, port, login, credential, known, *, timeout_seconds=None, capture_max_bytes=None):
        assert (host, port, credential.use()) == (HOST, 22, PASSWORD)
        self.sessions += 1
        return FakeShell(self)


class FakeShell:
    PROMPT = b'user01@host02'

    def __init__(self, device):
        self.device, self.out, self.mode, self.lines, self.candidate = device, b'', '>', None, None
        self.out = b'Last login: Thu Nov 19 01:50:59 2026\r\n--- JUNOS 26.2R1.7 Kernel 64-bit\r\n' + self._prompt()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def _prompt(self):
        banner = b'# commit confirmed will be rolled back in 10 minutes\r\n' if self.device.pending else b''
        context = b'[edit]\r\n' if self.mode == '#' else b''
        return b'\r\n' + banner + context + self.PROMPT + self.mode.encode() + b' '

    def send(self, line):
        assert '\n' not in line
        if self.lines is not None:
            if line == '\x04':
                errors = b' (1 errors)' if self.device.load_errors else b''
                self.candidate = '\n'.join(self.lines) + '\n'
                self.lines = None
                # measured: the newline the session adds after Ctrl-D is an empty line with a prompt of its own
                self.out += b'^D\x08\x08\r\nload complete' + errors + b'\r\n' + self._prompt() + self._prompt()
            else:
                self.lines.append(line)
                self.out += line.encode() + b'\r\n'
            return
        self.out += line.encode() + b' \r\n'
        if line == 'configure exclusive':
            self.mode = '#'
            self.out += b'warning: uncommitted changes will be discarded on exit\r\nEntering configuration mode\r\n'
        elif line == 'load override terminal':
            self.lines = []
            self.out += b'[Type ^D at a new line to end input]\r\n'
            return
        elif line.startswith('commit confirmed '):
            minutes, comment = re.fullmatch(r'commit confirmed ([0-9]+) comment "([^"]+)"', line).groups()
            self.device.commit(self.candidate, comment, int(minutes))
            self.out += (b'commit confirmed will be automatically rolled back in %s minutes unless confirmed\r\n'
                         b'commit complete\r\n' % minutes.encode())
        elif line.startswith('commit comment '):
            comment = re.fullmatch(r'commit comment "([^"]+)"', line).group(1)
            if self.device.revert_failure and comment.endswith('-revert'):
                self.out += b'error: fixture revert refused\r\n'
            else:
                if self.candidate is not None:
                    self.device.commit(self.candidate, comment)
                else:
                    self.device.history.insert(0, ['2026-11-19 03:01:00', 'user01', None, comment])
                    self.device.pending = False
                self.out += b'commit complete\r\n'
        elif line == 'show | compare | count':
            wanted, active = canonical(body(self.candidate)).split('\n'), body(self.device.config).split('\n')
            self.out += b'Count: %d lines\r\n' % (0 if wanted == active else abs(len(wanted) - len(active)) + 1)
        elif line == 'exit configuration-mode':
            self.mode = '>'
            self.out += b'Exiting configuration mode\r\n'
        else:
            raise AssertionError(line)
        self.out += self._prompt()

    def expect(self, patterns, timeout, quiet_seconds=None):
        best = None
        for index, pattern in enumerate(patterns):
            found = pattern.search(self.out) if isinstance(pattern, re.Pattern) else None
            if not isinstance(pattern, re.Pattern):
                position = self.out.find(pattern)
                found = (position, position + len(pattern)) if position >= 0 else None
            else:
                found = found.span() if found else None
            if found and (best is None or found[0] < best[1][0]):
                best = (index, found)
        if best is None:
            raise core_session.SessionError('no pattern in the fake answer')
        index, (_, end) = best
        data, self.out = self.out[:end], self.out[end:]
        return index, data


@pytest.fixture
def lab(tmp_path, monkeypatch):
    destination = tmp_path / 'private'
    destination.mkdir(mode=0o700)
    monkeypatch.setenv('NETOPS_BACKUP_KEY', 'c1' * 32)
    monkeypatch.setenv('NETOPS_BACKUP_PASSWORD', PASSWORD)
    device = FakeJunos()
    monkeypatch.setattr(backup_junos.hostkey, 'scan', lambda host, port, pin, timeout:
                        HOST + ' ssh-ed25519 Zml4dHVyZQ==')
    monkeypatch.setattr(backup_junos.ssh, 'run_command', device.run_command)
    monkeypatch.setattr(backup_junos.session, 'Session', device.session)
    return destination, device


def _invoke(capsys, args, rc=0):
    assert cli.main(args) == rc
    out = capsys.readouterr().out
    assert SENTINEL not in out and '$6$' not in out and '$9$' not in out and PASSWORD not in out
    return json.loads(out)


def _backup(capsys, destination, rescue=True):
    flags = ['backup-junos', '--host', HOST, '--login', 'user01', '--ssh-sha256', PIN, '--directory',
             str(destination), '--keep', '3'] + (['--rescue'] if rescue else [])
    preview = _invoke(capsys, flags)
    return preview, _invoke(capsys, flags + ['--confirm', preview['plan_sha256']])


def _restore(capsys, artifact, confirm=None, rc=0, minutes='5'):
    flags = ['restore-junos', '--host', HOST, '--login', 'user01', '--ssh-sha256', PIN, '--input', str(artifact),
             '--minutes', minutes]
    return _invoke(capsys, flags + (['--confirm', confirm] if confirm else []), rc)


def test_backup_with_rescue_is_sealed_private_and_unseals_to_the_device_text(lab, capsys):
    destination, device = lab
    preview, done = _backup(capsys, destination)
    assert preview['result'] == 'ready' and preview['plan']['rescue'] is True
    assert done['result'] == 'confirmed' and done['rescue_saved'] is True and done['rescue_lines'] == 191
    assert device.calls == [backup_junos.VERSION, RESCUE_SHOW, backup_junos.RESCUE_SAVE, backup_junos.RESCUE_COUNT,
                            backup_junos.SHOW]
    assert 'rescue_artifact' not in done
    assert device.sessions == 0 and device.rescue == CONFIG
    assert done['firmware_support']['status'] == 'tested' and done['configuration_release'] == '26.2R1.7'
    artifact = destination / done['artifact']
    assert artifact.stat().st_mode & 0o777 == 0o600
    sealed = artifact.read_bytes()
    assert SENTINEL.encode() not in sealed and b'host-name' not in sealed
    assert hashlib.sha256(sealed).hexdigest() == done['sha256']
    assert done['configuration_sha256'] == hashlib.sha256(body(CONFIG).encode()).hexdigest()
    restored = destination / 'restored.conf'
    report = _invoke(capsys, ['backup-junos-unseal', '--input', str(artifact), '--output', str(restored)])
    assert restored.read_text() == CONFIG and restored.stat().st_mode & 0o777 == 0o600
    assert report['configuration_sha256'] == done['configuration_sha256']


def test_existing_rescue_is_exported_before_overwrite_even_with_keep_one(lab, capsys):
    destination, device = lab
    # DERIVED: the real hierarchical capture with the rescue header and a differing system login message.
    previous = with_message(CONFIG).replace('## Last commit:', '## Last changed:', 1)
    device.rescue = previous
    flags = ['backup-junos', '--host', HOST, '--login', 'user01', '--ssh-sha256', PIN,
             '--directory', str(destination), '--keep', '1', '--rescue']
    preview = _invoke(capsys, flags)
    done = _invoke(capsys, flags + ['--confirm', preview['plan_sha256']])
    assert device.calls.index(RESCUE_SHOW) < device.calls.index(backup_junos.RESCUE_SAVE)
    assert device.rescue == CONFIG
    rescue = destination / done['rescue_artifact']
    assert rescue != destination / done['artifact'] and rescue.stat().st_mode & 0o777 == 0o600
    assert rescue.read_bytes().startswith(backup_junos.MAGIC) and SENTINEL.encode() not in rescue.read_bytes()
    output = destination / 'rescue.conf'
    _invoke(capsys, ['backup-junos-unseal', '--input', str(rescue), '--output', str(output)])
    assert output.read_text() == previous and output.stat().st_mode & 0o777 == 0o600
    preview = _restore(capsys, rescue)
    assert preview['result'] == 'ready' and preview['identical'] is False


@pytest.mark.parametrize('failure', ['unreadable', 'storage'])
def test_rescue_export_failure_never_overwrites_existing_rescue(lab, capsys, failure):
    destination, device = lab
    previous = with_message(CONFIG).replace('## Last commit:', '## Last changed:', 1)
    device.rescue = 'error: permission denied\n' if failure == 'unreadable' else previous
    if failure == 'storage':
        # Same target and rescue series, but the previous local artifact cannot be authenticated.
        broken = destination / f'{backup_junos._target_prefix(HOST, 22)}-rescue-20261119T020000Z-{"0" * 32}.netops-backup'
        broken.write_bytes(b'unreadable fixture')
        broken.chmod(0o600)
    flags = ['backup-junos', '--host', HOST, '--login', 'user01', '--ssh-sha256', PIN,
             '--directory', str(destination), '--rescue']
    preview = _invoke(capsys, flags)
    assert _invoke(capsys, flags + ['--confirm', preview['plan_sha256']], rc=3)['result'] == 'rejected'
    assert RESCUE_SHOW in device.calls and backup_junos.RESCUE_SAVE not in device.calls
    assert device.rescue == ('error: permission denied\n' if failure == 'unreadable' else previous)


def test_backup_confirmation_must_match_and_a_read_only_view_is_refused(lab, capsys):
    destination, device = lab
    flags = ['backup-junos', '--host', HOST, '--login', 'user01', '--ssh-sha256', PIN, '--directory', str(destination)]
    refused = _invoke(capsys, flags + ['--confirm', '0' * 64], rc=3)
    assert refused['reason_codes'] == ['plan_changed'] and device.calls == []
    preview = _invoke(capsys, flags)
    for config, code in ((CONFIG_RO, 'backup_refused'), (CONFIG[:-3], 'backup_incomplete'),
                         ('\nerror: permission denied\n', 'backup_incomplete')):
        device.config = config
        refused = _invoke(capsys, flags + ['--confirm', preview['plan_sha256']], rc=3)
        assert refused['reason_codes'] == [code], config[:40]
    assert list(destination.iterdir()) == []


def test_restore_preview_reads_only_and_apply_restores_confirms_and_undo_returns(lab, capsys):
    destination, device = lab
    _, done = _backup(capsys, destination, rescue=True)
    original = body(CONFIG)
    # someone changes the device after the backup (the one live test change)
    device.config = canonical(with_message(CONFIG))
    device.calls.clear()
    preview = _restore(capsys, destination / done['artifact'])
    assert preview['result'] == 'ready' and device.sessions == 0
    assert (preview['added_lines'], preview['removed_lines'], preview['identical']) == (0, 1, False)
    assert device.calls == [backup_junos.VERSION, backup_junos.SHOW]
    applied = _restore(capsys, destination / done['artifact'], preview['plan_sha256'])
    assert applied['result'] == 'confirmed' and applied['changed'] is True
    assert body(device.config) == original and device.pending is False
    label = applied['commit_label']
    assert [row[3] for row in device.history[:2]] == [label + '-ok', label] and device.history[1][2] == 5
    # the return: the automatic backup of the state before, restored the same way
    undo = destination / applied['undo_artifact']
    back = _restore(capsys, undo)
    assert (back['added_lines'], back['removed_lines']) == (1, 0)
    returned = _restore(capsys, undo, back['plan_sha256'])
    assert returned['result'] == 'confirmed' and body(device.config) == body(canonical(with_message(CONFIG)))
    assert 'message netops-g136-test;' in device.config


def test_restore_refuses_a_changed_device_a_pending_timer_and_a_foreign_backup(lab, capsys, tmp_path):
    destination, device = lab
    _, done = _backup(capsys, destination, rescue=False)
    artifact = destination / done['artifact']
    device.config = with_message(CONFIG)
    preview = _restore(capsys, artifact)
    device.config = CONFIG.replace('host-name host02;', 'host-name host03;')
    assert _restore(capsys, artifact, preview['plan_sha256'], rc=3)['reason_codes'] == ['plan_changed']
    device.config = with_message(CONFIG)
    device.history.insert(0, ['2026-11-19 02:59:00', 'user09', 10, 'someone else'])
    device.pending = True
    refused = _restore(capsys, artifact, preview['plan_sha256'], rc=3)
    assert refused['reason_codes'] == ['foreign_config_session'] and device.sessions == 0
    device.pending = False
    other = destination / artifact.name.replace(artifact.name[6:38], '0' * 32)
    other.write_bytes(artifact.read_bytes())
    other.chmod(0o600)
    assert _restore(capsys, other, rc=3)['reason_codes'] == ['backup_target_mismatch']
    assert _restore(capsys, artifact, preview['plan_sha256'], rc=3, minutes='1')['reason_codes'] == [
        'backup_request_invalid']


def test_a_readback_mismatch_is_returned_at_once_and_a_load_error_commits_nothing(lab, capsys):
    destination, device = lab
    _, done = _backup(capsys, destination, rescue=False)
    artifact = destination / done['artifact']
    before = canonical(with_message(CONFIG)).replace('host-name host02;', 'host-name host04;')
    device.config = before
    device.mangle = True
    preview = _restore(capsys, artifact)
    result = _restore(capsys, artifact, preview['plan_sha256'], rc=4)
    assert result['result'] == 'reverted' and result['reason_codes'] == ['backup_restore_refused']
    assert body(device.config) == body(before) and device.pending is False
    assert device.history[0][3] == result['commit_label'] + '-revert'
    device.mangle, device.load_errors = False, True
    preview = _restore(capsys, artifact)
    commits = len(device.history)
    result = _restore(capsys, artifact, preview['plan_sha256'], rc=3)
    assert result['result'] == 'rejected' and result['state'] == 'unchanged'
    assert len(device.history) == commits and body(device.config) == body(before)


@pytest.mark.parametrize('command', [backup_junos.COMMITS, backup_junos.SHOW], ids=['history', 'configuration'])
def test_failed_readback_keeps_the_acknowledged_commit_and_undo_visible(lab, capsys, command):
    destination, device = lab
    _, done = _backup(capsys, destination, rescue=False)
    artifact = destination / done['artifact']
    device.config = with_message(CONFIG)
    preview = _restore(capsys, artifact)
    device.readback_failure = command
    result = _restore(capsys, artifact, preview['plan_sha256'], rc=7)
    assert result['result'] == 'unknown' and result['pending'] is True and result['rollback_minutes'] == 5
    assert result['commit_label'] == device.history[0][3] and device.pending
    assert (destination / result['undo_artifact']).stat().st_mode & 0o777 == 0o600
    assert result['reason_codes'] == ['backup_transport_failed']


def test_failed_revert_uses_a_nonzero_cli_exit(lab, capsys):
    destination, device = lab
    _, done = _backup(capsys, destination, rescue=False)
    artifact = destination / done['artifact']
    device.config = CONFIG.replace('host-name host02;', 'host-name host04;')
    preview = _restore(capsys, artifact)
    device.mangle = device.revert_failure = True
    result = _restore(capsys, artifact, preview['plan_sha256'], rc=7)
    assert result['result'] == 'revert-failed' and result['commit_label'] == device.history[0][3]
    assert (destination / result['undo_artifact']).is_file()


def test_configuration_framing():
    text, release = backup_junos.configuration_text(CONFIG.encode())
    assert release == '26.2R1.7' and text == CONFIG
    for broken in (CONFIG.replace('version 26.2R1.7;', 'version x y;'), CONFIG + '}\n',
                   CONFIG.replace('host-name host02;', 'host-name "host02;'), CONFIG.replace('\n', '\r\n')[:-4]):
        with pytest.raises(Exception) as raised:
            backup_junos.configuration_text(broken.encode())
        assert raised.value.reason_codes in (['backup_incomplete'], ['backup_refused'])


def test_the_rescue_row_of_the_real_commit_history_is_no_commit():
    # REAL show system commit right after rescue save: the last row names the rescue configuration
    from netops_admin import junos
    text = (FIX / 'commits_with_rescue_admin.out').read_text()
    assert text.splitlines()[-1].startswith('rescue  ')
    found = junos.commits(text)
    assert len(found) == 50 and found[0].comment == 'netops-g136-confirm-empty' and not found[0].pending
    assert [commit.index for commit in found] == list(range(50))


def test_a_rescue_save_without_a_rescue_configuration_is_refused(lab, capsys, monkeypatch):
    destination, device = lab
    original = device.run_command

    def ignoring(host, port, login, credential, known, command, **options):
        if command == backup_junos.RESCUE_SAVE:
            device.calls.append(command)
            return core_ssh.Result(rc=0, stdout=b'', said='', started_at='t0', finished_at='t1')
        return original(host, port, login, credential, known, command, **options)
    monkeypatch.setattr(backup_junos.ssh, 'run_command', ignoring)
    flags = ['backup-junos', '--host', HOST, '--login', 'user01', '--ssh-sha256', PIN, '--directory',
             str(destination), '--rescue']
    preview = _invoke(capsys, flags)
    refused = _invoke(capsys, flags + ['--confirm', preview['plan_sha256']], rc=3)
    assert refused['reason_codes'] == ['backup_refused'] and list(destination.iterdir()) == []
