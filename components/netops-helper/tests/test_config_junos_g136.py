"""G136 (JP10): Junos ``config_read`` (redacted ``display set``) and ``config_diff`` (two snapshots, or the running
configuration against a committed rollback on the device).

Fixtures are REAL captures of d-vjunos (vJunos-switch, Junos 26.2R1.7, task 553), anonymised with
``tests/support/anonymize_fixture.py``; every password hash was replaced by the sentinel
``$6$SENTINELSALT$SECRET-HASH-SENTINEL`` in the capture pipe (committed as the Junos ``$9$`` form) before anything was stored (see the README of the
fixture directory).  Texts marked DERIVED are edited copies of those captures.

The public reads run through the real ``netops.worker.HelperBridge.call`` -> ``Proxy.request`` -> FastMCP
``server.config_read``/``server.config_diff`` -> ``engine`` -> ``read_from_device`` -> ``_exec_read`` ->
``config_junos_adapter`` -> ``Proxy.response`` -> the worker's final redaction.  Only the physical SSH exec
backend (``core_ssh.run_command``), the host-key scan and the audit file location are replaced.
"""

import asyncio
import hashlib
import json
from pathlib import Path

import pytest

from netops import worker
from netops.files import write_private
from netops_core import ssh as core_ssh
from netops_core.audit import Recorder
from netops_helper import audit as helper_audit, configuration, engine, server
from netops_helper import config_junos_adapter as adapter
from netops_helper import proxy as proxy_module
from netops_helper.auth import TargetAuth
from netops_helper.config_junos_adapter import JUNOS_MARKER as M, JunosSetRedactor
from netops_helper.configuration import ConfigurationRedactionError, ConfigurationRefusedError
from test_proxy import DEVICE_PIN, _section

FIX = Path(__file__).parent / 'fixtures' / 'real' / 'juniper_junos_els' / 'g136_vjunosswitch_26.2R1.7'
VERSION = (FIX / 'version_admin.out').read_text()
CONFIG = (FIX / 'config_display_set_admin.out').read_text()
CONFIG_RO = (FIX / 'config_display_set_ro.out').read_text()
COMPARE_4 = (FIX / 'compare_rollback_4_admin.out').read_text()
COMPARE_EMPTY = (FIX / 'compare_rollback_1_admin.out').read_text()
COMPARE_RO = (FIX / 'compare_rollback_3_ro.out').read_text()
COMPARE_99 = (FIX / 'compare_rollback_99_admin.out').read_text()
DESCRIPTION = (FIX / 'config_display_set_description_admin.out').read_text().rstrip('\n')
CANDIDATE = (FIX / 'compare_candidate_description_admin.out').read_text()
ASCII_DESCRIPTION = (FIX / 'config_display_set_quoted_description_admin.out').read_text()
SENTINEL = 'SECRET-HASH-SENTINEL'
HOST_KEY = 'ssh-ed25519 ' + 'AAAAC3NzaC1lZDI1NTE5AAAAIFakeFixtureHostKeyMaterialForTask553Only'
ADDRESS = {'sw-a': '192.0.2.10', 'sw-b': '192.0.2.20'}
B_SECRET = 'b-switch-sesame-only'
LIMITS = {'section_bytes': 1048576, 'all_bytes': 4194304, 'physical_line_bytes': 4096,
          'logical_record_bytes': 65536, 'idle_seconds': 17, 'total_seconds': 123}
HIDDEN = ('set system root-authentication encrypted-password',
          'set system login user user01 authentication encrypted-password',
          'set system login user user02 authentication encrypted-password')
# DERIVED from the real compare of rollback 4: a changed password of a login user and of root, as Junos prints
# a secret statement in the hierarchical format (encrypted-password "..."; ## SECRET-DATA, see
# config_hierarchical_admin.out), an added syslog host and an unknown line shape.
COMPARE_SECRET = (
    '[edit system]\n'
    '-  host-name host01;\n'
    '+  host-name host02;\n'
    '[edit system root-authentication]\n'
    '-  encrypted-password "$6$SENTINELSALT$SECRET-HASH-SENTINEL-OLD"; ## SECRET-DATA\n'
    '+  encrypted-password "$6$SENTINELSALT$SECRET-HASH-SENTINEL"; ## SECRET-DATA\n'
    '[edit system login]\n'
    '+    user user03 {\n'
    '+        uid 2003;\n'
    '+        class read-only;\n'
    '+        authentication {\n'
    '+            encrypted-password "$6$SENTINELSALT$SECRET-HASH-SENTINEL"; ## SECRET-DATA\n'
    '+        }\n'
    '+    }\n'
    '[edit system syslog]\n'
    '+   host 192.0.2.10 {\n'
    '+       any notice;\n'
    '+   }\n')


def _redact(text, forbidden=()):
    capture = JunosSetRedactor(forbidden, 'all')
    try:
        capture.feed(text.encode())
        content, hidden, count = capture.finish()
        return content.page(0, content.total)[0], count, capture.summary()
    finally:
        capture.close()


# ------------------------------------------------------------------------------ redactor (real capture)

def test_real_display_set_keeps_the_allowlist_and_hides_every_password_hash():
    text, count, summary = _redact(CONFIG)
    lines, source = text.splitlines(), CONFIG.splitlines()
    assert len(lines) == len(source) == 54
    assert SENTINEL not in text and '$6$' not in text and '$9$' not in text
    for original, shown in zip(source, lines):
        if original.startswith(HIDDEN):
            assert shown == M
        else:
            assert shown == original
    assert count == 3 and summary['unverified_count'] == 3 and summary['credential_redactions'] == 0
    for kept in ('set version 26.2R1.7', 'set system host-name host02', 'set system login user user01 class super-user',
                 'set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members D20',
                 'set vlans D20 l3-interface irb.20', 'set routing-options static route 0.0.0.0/0 next-hop 192.0.2.1',
                 'set firewall policer g135-pol then discard', 'set protocols ospf area 0.0.0.0 interface lo0.0 passive'):
        assert kept in lines


def test_secret_in_an_allowed_section_and_a_forbidden_value_are_hidden():
    # DERIVED: an OSPF MD5 key and an NTP key in allowed sections; a description holding the session secret.
    extra = ('set protocols ospf area 0.0.0.0 interface irb.10 authentication md5 1 key "$9$abcdefgh"\n'
             'set system ntp authentication-key 1 type md5 value "$9$ijklmnop"\n'
             'set interfaces ge-0/0/1 description "uplink ' + B_SECRET + '"\n'
             'set snmp community public authorization read-only\n'
             'deactivate interfaces ge-0/0/2\n')
    text, count, summary = _redact(CONFIG + extra, (B_SECRET,))
    tail = text.splitlines()[-5:]
    assert tail == [M, M, M, M, 'deactivate interfaces ge-0/0/2']
    assert '$9$' not in text and B_SECRET not in text and 'public' not in text
    assert summary['credential_redactions'] == 3 and count == 3 + 4


@pytest.mark.parametrize('raw, reason', [
    (CONFIG_RO, ConfigurationRefusedError),
    ('\nerror: permission denied: system\n', ConfigurationRefusedError),
    (CONFIG[:-1], 'stream-incomplete'),
    ('', 'stream-incomplete'),
    (CONFIG.replace('set version 26.2R1.7\n', ''), 'redaction-unverifiable'),
    (CONFIG + 'set interfaces ge-0/0/1 description "open\n', 'redaction-unverifiable'),
    (CONFIG + '---(more 100%)---\n', 'redaction-unverifiable'),
], ids=['ro-access-denied', 'error', 'truncated', 'empty', 'no-version', 'open-quote', 'pager'])
def test_refused_or_incomplete_capture_never_returns_text(raw, reason):
    capture = JunosSetRedactor((), 'all')
    try:
        with pytest.raises((ConfigurationRedactionError, ConfigurationRefusedError)) as raised:
            if raw:
                capture.feed(raw.encode())
            capture.finish()
    finally:
        capture.close()
    if isinstance(reason, str):
        assert raised.value.reason == reason
    else:
        assert isinstance(raised.value, reason)


def test_identity_of_the_real_show_version():
    firmware, metadata = adapter.verify_identity(VERSION)
    assert firmware == ('ex9214', '26.2R1.7', '26.2R1.7') and adapter.firmware_record(firmware)
    assert adapter.firmware_support(firmware)['status'] == 'tested'
    other = adapter.version_identity(VERSION.replace('Junos: 26.2R1.7', 'Junos: 23.4R2-S4.11'))
    assert adapter.firmware_support(other)['status'] == 'untested'
    with pytest.raises(ValueError):
        adapter.version_identity(VERSION.replace('Model: ex9214\n', ''))


def test_compare_lines_of_real_and_derived_answers():
    lines, counts = adapter.compare_lines(COMPARE_4)
    assert lines == ['[edit system]', '-  host-name host01;', '+  host-name host02;']
    assert counts == {'added_lines': 1, 'removed_lines': 1, 'hidden_added_lines': 0, 'hidden_removed_lines': 0,
                      'unparsed_lines': 0}
    assert adapter.compare_lines(COMPARE_EMPTY) == ([], dict.fromkeys(counts, 0))
    lines, counts = adapter.compare_lines(COMPARE_SECRET)
    text = '\n'.join(lines)
    assert SENTINEL not in text and '$6$' not in text and '$9$' not in text
    assert lines == ['[edit system]', '-  host-name host01;', '+  host-name host02;',
                     '[edit system root-authentication]', '- ' + M, '+ ' + M,
                     '[edit system login]', '+ ' + M, '+        uid 2003;', '+        class read-only;', '+ ' + M,
                     '+ ' + M, '+        }', '+    }',
                     '[edit system syslog]', '+   host 192.0.2.10 {', '+       any notice;', '+   }']
    assert counts == {'added_lines': 12, 'removed_lines': 2, 'hidden_added_lines': 4, 'hidden_removed_lines': 1,
                      'unparsed_lines': 0}
    with pytest.raises(ConfigurationRefusedError):
        adapter.compare_lines(COMPARE_99)
    lines, counts = adapter.compare_lines('[edit system]\n+  /* note */\n')
    assert counts['unparsed_lines'] == 1 and lines[-1] == '+ ' + M
    assert adapter.visible('Count: 0 lines\n') and not adapter.visible('Count: 8 lines\n')
    assert not adapter.visible('\nerror: permission denied\n')


# ---------------------------------------------------------------------------------- public chain

class Wire:
    """Stands in for core_ssh.run_command; answers by command and streams the capture into the consumer."""

    def __init__(self, config=CONFIG, compare=COMPARE_4, probe='Count: 0 lines\n'):
        self.config, self.compare, self.probe = config, compare, probe
        self.calls = []

    def __call__(self, host, port, login, credential, host_key_line, command, *, legacy_ssh=None,
                 timeout_seconds=None, capture_max_bytes=None, stdout_consumer=None,
                 idle_timeout_seconds=None, run=None, now=None):
        self.calls.append({'host': host, 'command': command, 'login': login, 'consumer': stdout_consumer})
        if stdout_consumer is not None:
            assert command == adapter.COMMAND
            data = self.config.encode()
            for start in range(0, len(data), 11):
                try:
                    stdout_consumer(data[start:start + 11])
                except core_ssh.OutputLimitError:
                    raise
                except Exception:
                    raise core_ssh.OutputConsumerError() from None
            return core_ssh.Result(rc=0, stdout=b'', said='', started_at='t0', finished_at='t1')
        answer = {'show version | no-more': VERSION, adapter.VISIBILITY_COMMAND: self.probe}.get(command)
        if answer is None and command.startswith('show configuration | compare rollback '):
            answer = self.compare
        assert answer is not None, command
        return core_ssh.Result(rc=0, stdout=answer.encode(), said='', started_at='t0', finished_at='t1')

    def commands(self):
        return [call['command'] for call in self.calls]


def _junos_section(alias, access=('read', 'compare'), platform='juniper_junos_els'):
    section = _section()
    section.pop('snmp_credential')
    section['egress']['addresses'] = [ADDRESS[alias]]
    section.update(ssh_platform=platform, enabled_queries=['version'], fortios_output_standard_verified=False,
                   configuration_limits=dict(LIMITS), rate_limit={'requests': 30, 'window_seconds': 60})
    section['read_inventory'] = {'interfaces': [], 'services': [], 'addresses': [], 'config_access': list(access)}
    return section


def _device(alias, platform, section):
    return {'name': alias, 'platform': platform, 'address': ADDRESS[alias], 'port': 22, 'role': 'internal',
            'credential': alias + '-account', 'host_key_fingerprint': DEVICE_PIN, 'legacy_ssh': None,
            'auditor': None, 'helper': section}


@pytest.fixture
def env(tmp_path, monkeypatch):
    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()
    state = tmp_path / 'state'
    helper = state / 'helper'
    helper.mkdir(parents=True, mode=0o700)
    write_private(helper / 'inventory.json', json.dumps({'version': 2, 'devices': [
        _device('sw-a', 'juniper_junos_els', _junos_section('sw-a', ('read',))),
        _device('sw-b', 'juniper_junos_els', _junos_section('sw-b')),
    ]}).encode())
    write_private(helper / 'vault.json', json.dumps({'version': 2, 'credentials': {
        'sw-a-account': {'kind': 'password', 'login': 'a-user', 'value': 'a-switch-password-only'},
        'sw-b-account': {'kind': 'password', 'login': 'b-user', 'value': B_SECRET},
    }}).encode())
    monkeypatch.setattr(worker, 'STATE', state)
    monkeypatch.setattr(proxy_module, 'INVENTORY', helper / 'inventory.json')
    monkeypatch.setattr(helper_audit, '_RECORDER', Recorder(helper / 'operations.jsonl', 'helper'))
    monkeypatch.setattr(engine.core_hostkey, 'scan', lambda address, port, pin, timeout, legacy=None:
                        address + ' ' + HOST_KEY)
    wire = Wire()
    monkeypatch.setattr(engine.core_ssh, 'run_command', wire)
    yield {'bridge': worker.HelperBridge(), 'wire': wire, 'monkeypatch': monkeypatch}
    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()


def _call(env, name, arguments):
    return asyncio.run(env['bridge'].call(server.mcp, name, dict(arguments)))


def _read_args(target='sw-b', **options):
    return {'target': target, 'platform': 'juniper_junos_els', 'section': 'all', 'include_all': True,
            'redaction': 'full', **options}


def _ok(result):
    assert result['isError'] is False, result
    data = result['structuredContent']
    assert data['ok'] is True, data
    return data


def _assert_clean(value):
    shown = json.dumps(value, default=repr)
    assert SENTINEL not in shown and '$6$' not in shown and '$9$' not in shown and B_SECRET not in shown


def test_public_config_read_returns_the_redacted_capture_and_pages_without_more_ssh(env):
    first = _ok(_call(env, 'config_read', _read_args(limit=400)))
    expected, count, summary = _redact(CONFIG, (B_SECRET,))
    assert env['wire'].commands() == ['show version | no-more', adapter.COMMAND]
    assert first['platform'] == 'juniper_junos_els' and first['command'] == adapter.COMMAND
    assert first['redaction_profile'] == adapter.PROFILE and first['redacted_count'] == count == 3
    assert first['firmware'] == {'model': 'ex9214', 'version': '26.2R1.7', 'build': '26.2R1.7'}
    assert 'firmware_support' not in first and 'warnings' not in first
    assert first['capture_complete'] is True and first['configuration_complete'] is False
    text, page = first['untrusted_device_output'], first
    while page['next_offset'] is not None:
        page = _ok(_call(env, 'config_read', _read_args(snapshot_id=first['snapshot_id'], offset=page['next_offset'],
                                                        limit=400, content_sha256=first['content_sha256'])))
        text += page['untrusted_device_output']
    assert text == expected and env['wire'].commands() == ['show version | no-more', adapter.COMMAND]
    _assert_clean(first)


def test_read_only_account_capture_is_a_device_refusal_not_a_configuration(env):
    env['wire'].config = CONFIG_RO
    result = _call(env, 'config_read', _read_args())
    assert result['isError'] is True
    shown = result['content'][0]['text']
    assert 'device-refused' in shown and 'ACCESS-DENIED' not in shown
    assert not configuration._SNAPSHOTS


def test_public_config_read_preserves_utf8_description_and_masks_secrets(env):
    # The first added line is a real d-vjunos capture. The other three are derived.
    literal = r'set interfaces ge-0/0/5 description "P\u0159\xedpojka"'
    mixed = r'set interfaces ge-0/0/6 description "Přípojka \"core\""'
    env['wire'].config = (CONFIG + DESCRIPTION + '\n'
                          + f'set interfaces ge-0/0/4 description "Přípojka {B_SECRET}"\n'
                          + literal + '\n' + mixed + '\n')
    data = _ok(_call(env, 'config_read', _read_args()))
    assert data['capture_complete'] is True and data['credential_redactions'] == 1
    assert data['untrusted_device_output'].splitlines()[-4:] == [
        r'set interfaces ge-0/0/4 description "P\u0159\xedpojka"', M, literal,
        r'set interfaces ge-0/0/6 description "P\u0159\xedpojka \\"core\\""']
    _assert_clean(data)


def test_ascii_description_matches_a_pre_r2_approved_baseline(env, tmp_path):
    # DERIVED: move the captured description from the free lab port onto ge-0/0/0.
    description = ASCII_DESCRIPTION.replace('ge-0/0/4', 'ge-0/0/0')
    anchor = 'set interfaces ge-0/0/0 unit 0 family ethernet-switching interface-mode trunk\n'
    baselines = tmp_path / 'baselines'
    env['monkeypatch'].setenv('NETOPS_CONFIG_BASELINE_DIR', str(baselines))
    initial = _ok(_call(env, 'config_read', _read_args()))
    approval = _ok(_call(env, 'config_read', _read_args(
        snapshot_id=initial['snapshot_id'], content_sha256=initial['content_sha256'], approve_baseline=True)))
    assert approval['baseline_approved'] is True
    saved = next(baselines.glob('*.json'))
    record = json.loads(saved.read_text())
    # Before r2 the redactor stored the verified ASCII line exactly as received.
    assert anchor in record['text']
    record['text'] = record['text'].replace(anchor, description + anchor, 1)
    record['content_sha256'] = hashlib.sha256(record['text'].encode('ascii')).hexdigest()
    write_private(saved, json.dumps(record).encode('ascii'), replace=True)
    configuration._SNAPSHOTS.clear()

    env['wire'].config = CONFIG.replace(anchor, description + anchor, 1)
    current = _ok(_call(env, 'config_read', _read_args()))
    diff = _ok(_call(env, 'config_diff', {'target': 'sw-b', 'platform': 'juniper_junos_els',
                                          'base_snapshot': 'baseline', 'other_snapshot': current['snapshot_id']}))
    assert diff['identical'] is True
    assert diff['baseline_snapshot'] == initial['snapshot_id'] and diff['untrusted_device_output'] == ''
    assert current['untrusted_device_output'].encode('ascii') == record['text'].encode('ascii')
    assert current['content_sha256'] == record['content_sha256']


def test_config_diff_of_two_snapshots_shows_the_visible_change_only(env):
    base = _ok(_call(env, 'config_read', _read_args()))
    # DERIVED: the same capture after a login message, a changed root hash and a new syslog host.
    env['wire'].config = CONFIG.replace(
        'set system services ssh\n', 'set system services ssh\nset system syslog host 192.0.2.10 any notice\n').replace(
        '"$9$SENTINELSALT$SECRET-HASH-SENTINEL"\nset system login user user01 uid',
        '"$9$OTHERSALT$SECRET-HASH-SENTINEL"\nset system login user user01 uid', 1)
    other = _ok(_call(env, 'config_read', _read_args()))
    diff = _ok(_call(env, 'config_diff', {'target': 'sw-b', 'platform': 'juniper_junos_els',
                                          'base_snapshot': base['snapshot_id'],
                                          'other_snapshot': other['snapshot_id']}))
    assert diff['identical'] is False and diff['hidden_lines_compared'] is False
    assert diff['untrusted_device_output'] == '--- base\n+++ other\n+set system syslog host 192.0.2.10 any notice\n'
    _assert_clean(diff)


def test_live_rollback_comparison_through_the_public_chain(env):
    data = _ok(_call(env, 'config_diff', {'target': 'sw-b', 'platform': 'juniper_junos_els',
                                          'base_snapshot': 'rollback:4', 'other_snapshot': 'running'}))
    assert env['wire'].commands() == ['show version | no-more', adapter.VISIBILITY_COMMAND,
                                      'show configuration | compare rollback 4 | no-more']
    assert data['comparison_complete'] is True and data['missing'] == []
    assert data['identical'] is False and data['content_changed'] is True
    assert (data['added_lines'], data['removed_lines'], data['hidden_added_lines']) == (1, 1, 0)
    assert data['untrusted_device_output'] == '[edit system]\n-  host-name host01;\n+  host-name host02;\n'
    env['wire'].compare = COMPARE_SECRET
    data = _ok(_call(env, 'config_diff', {'target': 'sw-b', 'platform': 'juniper_junos_els',
                                          'base_snapshot': 'rollback:1', 'other_snapshot': 'running'}))
    assert data['comparison_complete'] is True and data['hidden_added_lines'] == 4
    _assert_clean(data)
    env['wire'].compare = COMPARE_EMPTY
    data = _ok(_call(env, 'config_diff', {'target': 'sw-b', 'platform': 'juniper_junos_els',
                                          'base_snapshot': 'rollback:1', 'other_snapshot': 'running'}))
    assert data['identical'] is True and data['untrusted_device_output'] == ''


class CandidateShell:
    """SSH PTY with the vJunos command echo, mode prompts and shared-edit exit warning."""

    def __init__(self, diff):
        self.commands = []
        self.diff = diff
        self.pending = b'\r\nb-user@host02> '

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def send(self, line):
        self.commands.append(line)
        output, prompt = {
            'configure': ('Entering configuration mode\n\n[edit]\n', '#'),
            'show | compare | no-more': (self.diff + '\n[edit]\n', '#'),
            'exit configuration-mode': ('The configuration has been changed but not committed\n'
                                        'Exiting configuration mode\n\n', '>'),
        }[line]
        self.pending = (line + ' \n' + output + 'b-user@host02' + prompt + ' ').replace('\n', '\r\n').encode()

    def expect(self, patterns, timeout, **_):
        for index, pattern in enumerate(patterns):
            if pattern.search(self.pending):
                result, self.pending = self.pending, b''
                return index, result
        raise AssertionError('unexpected PTY prompt request')


@pytest.mark.parametrize('base, other, added, removed', [('candidate', 'running', 0, 3),
                                                       ('running', 'candidate', 3, 0)])
def test_live_candidate_diff_signs_follow_snapshot_order(env, base, other, added, removed):
    shell = CandidateShell(CANDIDATE)
    env['monkeypatch'].setattr(engine.core_session, 'Session', lambda *args, **kwargs: shell)
    data = _ok(_call(env, 'config_diff', {'target': 'sw-b', 'platform': 'juniper_junos_els',
                                          'base_snapshot': base, 'other_snapshot': other}))
    assert (data['base_snapshot'], data['other_snapshot']) == (base, other)
    assert data['comparison_complete'] is True and data['identical'] is False
    assert (data['added_lines'], data['removed_lines']) == (added, removed)
    expected = CANDIDATE if added else CANDIDATE.replace('\n+', '\n-')
    assert data['untrusted_device_output'] == expected
    assert env['wire'].commands() == ['show version | no-more', adapter.VISIBILITY_COMMAND]
    assert shell.commands == ['configure', 'show | compare | no-more', 'exit configuration-mode']


@pytest.mark.parametrize('diff, complete', [(COMPARE_4 + COMPARE_SECRET, True),
                                           ('error: permission denied\n', False)],
                         ids=['foreign-candidate-redacted', 'device-refused'])
def test_live_shared_candidate_comparison_through_proxy(env, diff, complete):
    shell = CandidateShell(diff)
    env['monkeypatch'].setattr(engine.core_session, 'Session', lambda *args, **kwargs: shell)
    data = _ok(_call(env, 'config_diff', {'target': 'sw-b', 'platform': 'juniper_junos_els',
                                          'base_snapshot': 'candidate', 'other_snapshot': 'running'}))
    assert env['wire'].commands() == ['show version | no-more', adapter.VISIBILITY_COMMAND]
    assert shell.commands == ['configure', 'show | compare | no-more', 'exit configuration-mode']
    assert data['origin'] == 'device' and data['comparison_complete'] is complete
    if complete:
        assert data['identical'] is False
        assert (data['hidden_added_lines'], data['hidden_removed_lines']) == (1, 4)
        assert '[edit system]\n+  host-name host01;\n-  host-name host02;\n' in data['untrusted_device_output']
    else:
        assert data['missing'] == ['difference_refused'] and 'identical' not in data
    _assert_clean(data)


@pytest.mark.parametrize('probe, compare, missing', [
    ('Count: 8 lines\n', COMPARE_RO, 'configuration_not_visible'),
    ('Count: 0 lines\n', COMPARE_99, 'difference_refused'),
    ('Count: 0 lines\n', '[edit system]\n+  /* unknown */\n', 'difference_unparsed'),
], ids=['read-only-empty-compare', 'out-of-range', 'unparsed'])
def test_live_rollback_comparison_is_never_identical_when_unverified(env, probe, compare, missing):
    env['wire'].probe, env['wire'].compare = probe, compare
    data = _ok(_call(env, 'config_diff', {'target': 'sw-b', 'platform': 'juniper_junos_els',
                                          'base_snapshot': 'rollback:3', 'other_snapshot': 'running'}))
    assert data['comparison_complete'] is False and missing in data['missing']
    assert 'identical' not in data
    if missing == 'configuration_not_visible':
        assert 'show configuration | compare rollback 3 | no-more' not in env['wire'].commands()


def test_proxy_refuses_bad_selectors_and_missing_compare_before_ssh(env):
    for base in ('rollback:0', 'rollback:50', 'rollback:x'):
        result = _call(env, 'config_diff', {'target': 'sw-b', 'platform': 'juniper_junos_els',
                                            'base_snapshot': base, 'other_snapshot': 'running'})
        assert result['isError'] is True
    result = _call(env, 'config_diff', {'target': 'sw-a', 'platform': 'juniper_junos_els',
                                        'base_snapshot': 'rollback:1', 'other_snapshot': 'running'})
    assert result['isError'] is True
    result = _call(env, 'config_read', _read_args(target='sw-b', platform='juniper_junos'))
    assert result['isError'] is True
    result = _call(env, 'config_read', _read_args(redaction='minimal'))
    assert result['isError'] is True
    assert env['wire'].calls == []
    proxy = env['bridge'].proxy
    _, section, _ = proxy._target('sw-b')
    assert proxy._rate_cost('config_diff', None, section, {'platform': 'juniper_junos_els',
                                                           'base_snapshot': 'rollback:2',
                                                           'other_snapshot': 'running'}) == 3
    assert proxy._rate_cost('config_read', None, section, {'platform': 'juniper_junos_els'}) == 2


def test_engine_auth_decodes_for_the_junos_capture(env):
    message = {'jsonrpc': '2.0', 'id': 'engine-auth', 'method': 'tools/call',
               'params': {'name': 'config_read', 'arguments': _read_args()}}
    raw = env['bridge'].proxy.request(json.dumps(message).encode())
    auth = TargetAuth.decode('sw-b', json.loads(raw)['params']['arguments']['auth_context'])
    assert auth.ssh_platform == 'juniper_junos_els'
    with pytest.raises(ValueError, match='config_platform_not_supported'):
        engine.config_read(auth, 'juniper_junos_els', 'all', False, redaction='full')


def test_live_rollback_diff_honors_client_byte_limit(env):
    arguments = {'target': 'sw-b', 'platform': 'juniper_junos_els',
                 'base_snapshot': 'rollback:4', 'other_snapshot': 'running'}
    data = _ok(_call(env, 'config_diff', {**arguments, 'limit': 25}))
    assert not data['comparison_complete'] and data['missing'] == ['difference_too_large']
    assert 'untrusted_device_output' not in data
    data = _ok(_call(env, 'config_diff', {**arguments, 'limit': 100}))
    assert data['comparison_complete'] and len(data['untrusted_device_output'].encode()) <= 100


@pytest.mark.parametrize("stage, failure, missing", [
    ("show version | no-more", "transport", None),
    ("show configuration | compare rollback 4 | no-more", "transport", "difference_transport_failed"),
    ("show configuration | compare rollback 4 | no-more", "limit", "difference_too_large"),
])
def test_live_rollback_ssh_failure_withholds_comparison(env, monkeypatch, stage, failure, missing):
    from netops_core.ssh import OutputLimitError, SshError

    wire = env["wire"]
    attempted = []

    def read(*args, **kwargs):
        command = args[5]
        attempted.append(command)
        if command == stage:
            if failure == "limit":
                raise OutputLimitError()
            raise SshError("fixture private detail", rc=255, final="Connection timed out")
        return wire(*args, **kwargs)

    monkeypatch.setattr(engine.core_ssh, "run_command", read)
    result = _call(env, "config_diff", {"target": "sw-b", "platform": "juniper_junos_els",
                                         "base_snapshot": "rollback:4", "other_snapshot": "running"})
    assert not result["isError"]
    response = result["structuredContent"]
    if missing is None:
        assert not response["ok"] and response["error_code"] == "timeout"
        assert attempted == [stage]
    else:
        assert response["ok"] and not response["comparison_complete"]
        assert response["missing"] == [missing]
        assert attempted == ["show version | no-more", adapter.VISIBILITY_COMMAND, stage]
    assert "identical" not in response and "untrusted_device_output" not in response
    assert "fixture private detail" not in str(response)
