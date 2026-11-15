"""Task 186: regressions of the accepted findings of the live scenarios of task 178 (1.0.9 items 06/07/10).

1. ``config_diff`` of the ExtremeXOS, Cisco IOS, IOS XE, NX-OS and Arista EOS snapshots is a line diff along a
   shortest edit script, not positional: one inserted line is one ``+`` line, a device-rewritten header is one
   ``-``/``+`` pair, nothing after them shifts.  FortiOS/FortiADC stay positional.
2. cEOS ``show mlag interfaces`` answering ``No MLAG ports configured`` is the complete empty member table.
3. N1: a device refusal of the IOS/IOS XE/EXOS read is the same ``device-refused`` answer as on EOS/NX-OS, and an
   unsupported or unverifiable identity is ``config_platform_not_supported``, not ``-32603 Role operation failed``.

End-to-end cases run through the real root ``netops.worker.HelperBridge.call`` -> ``Proxy.request`` -> FastMCP
``server.config_read``/``server.config_diff`` -> engine -> ``Proxy.response`` -> the worker (fixture ``env`` of
``test_config_diff_ios_family``); only the physical SSH backend, the host-key scan and the audit file are replaced.

Data labels:
* REAL    - ``fixtures/real/live_178/captures.json`` (anonymised captures of task 178, see its README; credential lines DERIVED)
            and the existing real identity captures (IOSvL2 15.2, EXOS-VM 33.6.1.14).
* DERIVED - one-line edits of those captures or of the synthetic configurations of ``test_config_diff_ios_family``,
            the EXOS read-only refusal text (the documented text of ``engine._CLI_REFUSALS``; the 178 log redacted
            it), and the random sequences of the edit-script property test.
"""
import json
import random
import time
from pathlib import Path

import pytest

from netops_helper import configuration, engine, switch_mlag_eos_interfaces
from netops_helper.config_buffers import ChangedRecords, ContentBuilder, HiddenRecords

import test_config_diff_ios_family as family
from test_config_diff_ios_family import env  # noqa: F401  (pytest fixture, parametrized by platform)

HERE = Path(__file__).parent
LIVE = HERE / 'fixtures' / 'real' / 'live_178'
REAL = HERE / 'fixtures' / 'real'
# One JSON file (name -> captured text), not .txt files: every *.txt fixture is also a capture of the classifier
# baseline (test_classification_baseline); the fixture privacy check reads the JSON strings as well.
CAPTURES = json.loads((LIVE / 'captures.json').read_text())
DEVICE = {'cisco_ios': 'iosv', 'cisco_xe': 'iolxe', 'cisco_nxos': 'nxos'}
EXOS_REFUSAL = 'This user does not have permissions for this command.\n'   # DERIVED (see module docstring)
DEVICE_REFUSED = {'code': -32602, 'message': 'Configuration capture was refused by the device; output withheld',
                  'data': {'category': 'device-refused', 'reason': 'device-refused',
                           'guidance': 'Ask the operator to check device read permissions and command support; '
                                       'no snapshot or partial output was published.'}}


def _live(platform, name):
    """A REAL config_diff capture of task 178; IOSv and IOL XE sent CRLF (restored), NX-OS LF."""
    text = CAPTURES[f'config_diff/{DEVICE[platform]}_{name}']
    return text if platform == 'cisco_nxos' else text.replace('\n', '\r\n')


def _content(text):
    builder = ContentBuilder(1 << 30, serialized_markers=False)
    builder.add(text.encode())
    return builder.finish()


def _text(content):
    return content.page(0, content.total)[0]


def _diff_text(base, other):
    out = ContentBuilder(1 << 30, serialized_markers=False)
    configuration._line_diff(_content(base), _content(other), out, ChangedRecords())
    return _text(out.finish())


def _lines(*rows):
    return ''.join(row + '\n' for row in rows)


def _diff_lines(result):
    data = family._ok(result)
    text = data['untrusted_device_output']
    if data['identical']:
        assert text == ''
        return None
    assert text.startswith('--- base\n+++ other\n'), text
    return text[len('--- base\n+++ other\n'):].split('\n')[:-1]


@pytest.fixture(autouse=True)
def _clean():
    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()
    yield
    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()


# ------------------------------------------------------------------------- 1. line diff, unit level

def test_one_inserted_line_in_the_middle_is_one_added_line():
    base = _lines(*(f'line {n}' for n in range(200)))
    other = _lines(*(f'line {n}' for n in range(100)), ' description netops-178', *(f'line {n}' for n in range(100, 200)))
    assert _diff_text(base, other) == '--- base\n+++ other\n+ description netops-178\n'
    assert _diff_text(other, base) == '--- base\n+++ other\n- description netops-178\n'


def test_header_change_and_insertion_do_not_shift_the_rest():
    head = ['Building configuration...', '', 'Current configuration : 3803 bytes', '!']
    body = [f'interface GigabitEthernet0/{n}' if n % 3 == 0 else ('!' if n % 3 == 1 else ' shutdown')
            for n in range(300)]
    base = _lines(*head, *body, 'end')
    changed_head = head[:2] + ['Current configuration : 3827 bytes'] + head[3:]
    other = _lines(*changed_head, *body[:150], ' description netops-178', *body[150:], 'end')
    assert _diff_text(base, other) == ('--- base\n+++ other\n-Current configuration : 3803 bytes\n'
                                       '+Current configuration : 3827 bytes\n+ description netops-178\n')


def test_replaced_block_lists_its_removed_then_its_added_lines_in_order():
    base = _lines('a', 'b', 'c', 'd', 'e', 'f')
    other = _lines('a', 'B1', 'B2', 'B3', 'e', 'f', 'g')
    assert _diff_text(base, other) == '--- base\n+++ other\n-b\n-c\n-d\n+B1\n+B2\n+B3\n+g\n'


def test_whole_text_added_removed_and_a_last_line_without_line_feed():
    assert _diff_text('', _lines('x', 'y')) == '--- base\n+++ other\n+x\n+y\n'
    assert _diff_text(_lines('x', 'y'), '') == '--- base\n+++ other\n-x\n-y\n'
    # A line without its final line feed still ends with one in the diff (no joined lines).
    assert _diff_text('a\nend', 'a\nb\nend') == '--- base\n+++ other\n+b\n'
    assert _diff_text('a\nend', 'a\nend\n') == '--- base\n+++ other\n-end\n+end\n'


def _lcs(a, b):
    row = [0] * (len(b) + 1)
    for x in a:
        diagonal = 0
        for j, y in enumerate(b, 1):
            diagonal, row[j] = row[j], diagonal + 1 if x == y else max(row[j], row[j - 1])
    return row[-1]


def test_edit_script_is_a_shortest_one_on_random_sequences():
    from array import array
    rng = random.Random(186)
    for _ in range(400):
        a = array('i', (rng.randrange(4) for _ in range(rng.randrange(0, 25))))
        b = array('i', (rng.randrange(4) for _ in range(rng.randrange(0, 25))))
        hunks = configuration._edit_script(a, b, [0])
        deleted = [i for hunk in hunks for i in hunk[0]]
        inserted = [j for hunk in hunks for j in hunk[1]]
        assert deleted == sorted(set(deleted)) and inserted == sorted(set(inserted))
        kept_a = [a[i] for i in range(len(a)) if i not in set(deleted)]
        kept_b = [b[j] for j in range(len(b)) if j not in set(inserted)]
        assert kept_a == kept_b, (list(a), list(b), hunks)          # the rest is a common subsequence
        assert len(kept_a) == _lcs(a, b), (list(a), list(b), hunks)  # ... and a longest one
        assert all(hunk[0] or hunk[1] for hunk in hunks)


def test_large_snapshot_with_small_changes_is_fast_and_exact():
    body = [f' ip address 192.0.2.{n % 250} 255.255.255.0' if n % 2 else f'interface Vlan{n}' for n in range(60000)]
    base = _lines('Current configuration : 1 bytes', *body, 'end')
    other = _lines('Current configuration : 2 bytes', *body[:59990], '!', *body[59990:], 'end')
    started = time.monotonic()
    assert _diff_text(base, other) == ('--- base\n+++ other\n-Current configuration : 1 bytes\n'
                                       '+Current configuration : 2 bytes\n+!\n')
    assert time.monotonic() - started < 60


def test_edit_and_work_limits_refuse_instead_of_running_without_bound(monkeypatch):
    monkeypatch.setattr(configuration, 'LINE_DIFF_MAX_EDITS', 50)
    near = _lines(*(f'line {n}' for n in range(400)))
    assert _diff_text(near, near.replace('line 7\n', 'line 7b\n')) == '--- base\n+++ other\n-line 7\n+line 7b\n'
    different = _lines(*(f'other {n}' for n in range(400)))
    with pytest.raises(configuration.DiffLimitExceeded) as raised:
        _diff_text(near, different)                       # 800 edits > 50
    assert str(raised.value) == configuration.DIFF_LIMIT_EXCEEDED
    with pytest.raises(configuration.DiffLimitExceeded):
        _diff_text(_lines('h', 'x', 't'), _lines('h', *(f'n{n}' for n in range(60)), 't'))   # |n - m| > 50, no pass
    monkeypatch.setattr(configuration, 'LINE_DIFF_MAX_EDITS', 3000)
    monkeypatch.setattr(configuration, 'LINE_DIFF_MAX_WORK', 100)
    with pytest.raises(configuration.DiffLimitExceeded):
        _diff_text(near, _lines(*(f'line {n}' if n % 7 else f'x {n}' for n in range(400))))


def test_fortios_compare_stays_positional(monkeypatch):
    # FortiOS/FortiADC are unchanged (positional); the same insertion that is one '+' line above shifts here.
    monkeypatch.setattr(configuration, 'scope', lambda auth, platform='fortios': ('scope', platform))

    class Auth:
        secrets = ()

    def snapshot(text):
        return configuration.Snapshot(('scope', 'fortios'), _content(text), HiddenRecords(), time.monotonic(), 0,
                                      'system interface', ('FortiGate-VM64', 'v7.6.8', '3744'), configuration.PROFILE)
    base = _lines('config system interface', '    edit "port1"', '    next', 'end')
    other = _lines('config system interface', '    edit "port0"', '    next', '    edit "port1"', '    next', 'end')
    configuration._SNAPSHOTS['cfg_' + 'a' * 32] = snapshot(base)
    configuration._SNAPSHOTS['cfg_' + 'b' * 32] = snapshot(other)
    text, changed, identical = configuration.compare(Auth(), 'cfg_' + 'a' * 32, 'cfg_' + 'b' * 32, platform='fortios')
    assert identical is False and len(changed) == 0
    assert _text(text) == ('--- base\n+++ other\n-    edit "port1"\n+    edit "port0"\n-end\n+    edit "port1"\n'
                           '+    next\n+end\n')


# ---------------------------------------------------- 1. line diff, public path with the 178 captures

LIVE_DIFFS = {
    'cisco_ios': {
        ('base', 'changed'): ['-', '-Current configuration : 3803 bytes', '+Current configuration : 3827 bytes',
                              '+ description netops-178'],
        ('changed', 'reverted'): ['-Current configuration : 3827 bytes', '+Current configuration : 3803 bytes',
                                  '- description netops-178'],
        ('base', 'reverted'): ['-'],   # the exec channel printed three, then two leading empty lines
    },
    'cisco_xe': {
        ('base', 'changed'): ['-', '-Current configuration : 4822 bytes', '+Current configuration : 4863 bytes',
                              '+ description netops-178'],
        ('changed', 'reverted'): ['-Current configuration : 4863 bytes', '+Current configuration : 4839 bytes',
                                  '- description netops-178'],
        ('base', 'reverted'): ['-', '-Current configuration : 4822 bytes', '+Current configuration : 4839 bytes'],
    },
    'cisco_nxos': {
        ('base', 'changed'): ['+  description netops-178'],
        ('changed', 'reverted'): ['-  description netops-178'],
        ('base', 'reverted'): None,     # only hidden header lines (!Running configuration..., !Time:) changed
    },
}


@pytest.mark.parametrize('env', ['cisco_ios', 'cisco_xe', 'cisco_nxos'], indirect=True)
def test_live_178_change_and_revert_show_only_the_change(env):
    platform = env['platform']
    captures = {name: family._capture(env, _live(platform, name)) for name in ('base', 'changed', 'reverted')}
    ssh = list(env['wire'].calls)
    for (left, right), expected in LIVE_DIFFS[platform].items():
        result = family._diff(env, captures[left], captures[right])
        assert _diff_lines(result) == expected, (left, right, result['structuredContent']['untrusted_device_output'])
        data = result['structuredContent']
        assert data['hidden_lines_compared'] is False and data['secrets_changed'] == []
        family._assert_clean(result, env['spec']['b_secret'])
    # Same counts of hidden lines in all three captures (only visible lines changed), no device contact.
    assert len({capture['unverified_count'] for capture in captures.values()}) == 1
    assert env['wire'].calls == ssh


@pytest.mark.parametrize('env', ['cisco_xe'], indirect=True)
def test_live_178_header_change_alone_is_one_pair(env):
    base = _live('cisco_xe', 'base')
    header = 'Current configuration : 4822 bytes'
    assert base.count(header) == 1
    first = family._capture(env, base)
    second = family._capture(env, base.replace(header, 'Current configuration : 4999 bytes'))
    assert _diff_lines(family._diff(env, first, second)) == [
        '-Current configuration : 4822 bytes', '+Current configuration : 4999 bytes']


@pytest.mark.parametrize('env', ['cisco_nxos'], indirect=True)
def test_live_178_line_inserted_in_the_middle_of_a_real_capture(env):
    base = _live('cisco_nxos', 'base')
    anchor = '\ninterface Ethernet1/30\n'
    assert base.count(anchor) == 1
    first = family._capture(env, base)
    second = family._capture(env, base.replace(anchor, anchor + '  description inserted-in-the-middle\n'))
    assert _diff_lines(family._diff(env, first, second)) == ['+  description inserted-in-the-middle']
    assert _diff_lines(family._diff(env, second, first)) == ['-  description inserted-in-the-middle']


def test_inserted_visible_line_is_one_added_line_on_every_platform(env):
    # All five platforms of item 07 (EXOS, IOS, IOS XE, NX-OS, EOS), synthetic configurations of task 157.
    spec = env['spec']
    old, new = spec['visible']
    base = family._capture(env)
    inserted = family._capture(env, family._edit(spec['config'], old, old + '\n' + new))
    assert _diff_lines(family._diff(env, base, inserted)) == ['+' + new]
    assert _diff_lines(family._diff(env, inserted, base)) == ['-' + new]
    replaced = family._capture(env, family._edit(spec['config'], old, new))
    assert _diff_lines(family._diff(env, base, replaced)) == ['-' + old, '+' + new]


@pytest.mark.parametrize('env', ['cisco_ios'], indirect=True)
def test_diff_over_its_limit_is_refused_with_a_machine_code(env, monkeypatch):
    spec = env['spec']
    base = family._capture(env)
    changed = family._capture(env, family._edit(spec['config'], *spec['visible']))
    monkeypatch.setattr(configuration, 'LINE_DIFF_MAX_EDITS', 1)
    result = family._diff(env, base, changed)
    data = result['structuredContent']
    assert result['isError'] is True and data['ok'] is False, result
    assert data['error_code'] == 'config_diff_limit_exceeded'
    assert data['error'] == configuration.DIFF_LIMIT_EXCEEDED
    assert 'restart_offset' not in data and 'untrusted_device_output' not in data
    assert not configuration._DIFFS


# ------------------------------------------------------------------- 2. cEOS show mlag interfaces

NO_PORTS = CAPTURES['ceos_4.36.1F_mlag_interfaces_no_ports']


def test_no_mlag_ports_configured_is_the_complete_empty_table():
    assert NO_PORTS == 'No MLAG ports configured\n'
    empty = {'state': 'measured', 'members': [], 'missing_fields': []}
    assert switch_mlag_eos_interfaces.summarize(NO_PORTS) == empty
    assert switch_mlag_eos_interfaces.summarize('d-ceos#show mlag interfaces\r\nNo MLAG ports configured\r\nd-ceos#') == empty
    assert switch_mlag_eos_interfaces.summarize('\nNo MLAG ports configured  \n\n') == empty
    assert switch_mlag_eos_interfaces.summarize(NO_PORTS, 'truncated') == {
        'state': 'partial', 'members': [], 'missing_fields': ['capture']}


@pytest.mark.parametrize('text', [
    'No MLAG ports configured.\n', 'no mlag ports configured\n', 'No MLAG ports configured\nsomething else\n',
    'NEW UNRECOGNIZED OUTPUT\n', '% Invalid input (privileged mode required) at line 1\n',
])
def test_other_text_without_a_table_stays_unparsed(text):
    assert switch_mlag_eos_interfaces.summarize(text) == {
        'state': 'unparsed', 'members': [], 'missing_fields': ['table', 'members']}


def test_no_mlag_ports_configured_on_the_public_ssh_read_path(tmp_path, monkeypatch):
    import test_switch_mlag_eos_interfaces_public as public
    contracts, gateway, calls = public._gateway(tmp_path, monkeypatch, {'show mlag interfaces': NO_PORTS})
    answer = public._ssh_read(contracts, gateway, 1, query='mlag_interfaces', offset=0)
    assert answer['ok'] is True and answer['untrusted_device_output'] == NO_PORTS
    assert answer['mlag_members'] == {'state': 'measured', 'members': [], 'missing_fields': []}
    assert calls.count('show mlag interfaces') == 1


# -------------------------------------------------------------------------- 3. N1 refusal codes

def _error(result):
    assert result['isError'] is True, result
    return json.loads(result['content'][0]['text'])


def _identity(env, **identity):
    env['wire'].spec = {**env['spec'], 'identity': {**env['spec']['identity'], **identity}}


def _read(env):
    return family._call(env, 'config_read', family._read_arguments(env))


def _config_commands(env):
    return [call for call in env['wire'].calls if call[2]]


@pytest.mark.parametrize('env', ['cisco_ios', 'cisco_xe'], indirect=True)
def test_ios_autocommand_refusal_is_device_refused(env):
    name = 'iosv_15.9.3M12' if env['platform'] == 'cisco_ios' else 'iolxe_17.18.2'
    env['wire'].config = CAPTURES[f'{name}_show_running_config_ro'].replace('\n', '\r\n')
    error = _error(_read(env))
    assert error == DEVICE_REFUSED
    assert not configuration._SNAPSHOTS


@pytest.mark.parametrize('env', ['cisco_ios'], indirect=True)
def test_autocommand_line_inside_a_configuration_is_not_a_refusal(env):
    # Only the answer before any configuration line is the refusal; inside the body the line is just hidden.
    spec = env['spec']
    config = family._edit(spec['config'], 'hostname lab-r1', 'hostname lab-r1\nLine has invalid autocommand "x"')
    data = family._ok(_read_with(env, config))
    assert 'Line has invalid autocommand' not in data['untrusted_device_output']


def _read_with(env, config):
    env['wire'].config = config
    return _read(env)


@pytest.mark.parametrize('env', ['cisco_ios', 'cisco_xe', 'extreme_exos'], indirect=True)
def test_refused_identity_read_is_device_refused(env):
    refusal = (EXOS_REFUSAL if env['platform'] == 'extreme_exos'
               else 'Line has invalid autocommand "show version"')
    _identity(env, **{'show version': refusal})
    error = _error(_read(env))
    assert error == DEVICE_REFUSED
    assert not _config_commands(env) and not configuration._SNAPSHOTS
    with pytest.raises(ValueError, match='^configuration device-refused during identity read; output withheld$'):
        engine.config_read(family._engine_auth(env), env['platform'], 'all', True, '', 0, 48000, 'full')


@pytest.mark.parametrize('env', ['extreme_exos'], indirect=True)
@pytest.mark.parametrize('rc', [254, 0])
def test_exos_read_only_capture_refusal_is_device_refused(env, rc):
    # Live 178: the read-only account got this single line with exit status 254 (review 186-rv: check rc too).
    env['wire'].config_rc = rc
    env['wire'].config = EXOS_REFUSAL
    assert _error(_read(env)) == DEVICE_REFUSED
    assert not configuration._SNAPSHOTS


@pytest.mark.parametrize('env', ['cisco_nxos', 'arista_eos'], indirect=True)
def test_eos_and_nxos_refusals_are_the_same_answer(env):
    env['wire'].config = ('% Permission denied for the role\n' if env['platform'] == 'cisco_nxos'
                          else '% Invalid input (privileged mode required) at line 1\n')
    assert _error(_read(env)) == DEVICE_REFUSED


UNSUPPORTED = {
    # REAL identities of task 178 that are not the admitted one.
    'cisco_ios': ({'show version': (REAL / 'cisco_ios/iosvl2_15.2.20200924/version.txt').read_text()},
                  'configuration firmware-not-supported for cisco_ios; supported IOSv 15.9(3)M12 fc1 '
                  'VIOS-ADVENTERPRISEK9-M; output withheld'),
    'extreme_exos': ({'show version': (REAL / 'exos/exosvm_33.6.1.14/version.txt').read_text(),
                      'show switch': (REAL / 'exos/exosvm_33.6.1.14/switch.txt').read_text()},
                     'configuration identity-unverifiable; output withheld'),
}


@pytest.mark.parametrize('env', ['cisco_ios', 'extreme_exos'], indirect=True)
def test_unsupported_identity_is_config_platform_not_supported(env):
    identity, text = UNSUPPORTED[env['platform']]
    _identity(env, **identity)
    result = _read(env)
    data = result['structuredContent']
    assert result['isError'] is True and data['ok'] is False, result
    assert data['error_code'] == 'config_platform_not_supported' and data['error'] == text
    assert 'restart_offset' not in data and 'untrusted_device_output' not in data and 'snapshot_id' not in data
    shown = json.loads(result['content'][0]['text'])
    assert shown['error_code'] == 'config_platform_not_supported' and shown['error'] == text
    assert 'Role operation failed' not in json.dumps(result)
    assert not _config_commands(env) and not configuration._SNAPSHOTS
    with pytest.raises(engine.ConfigurationRefusal) as raised:
        engine.config_read(family._engine_auth(env), env['platform'], 'all', True, '', 0, 48000, 'full')
    assert raised.value.code == 'config_platform_not_supported' and raised.value.restartable is False
    assert str(raised.value) == text


@pytest.mark.parametrize('env', ['cisco_xe', 'cisco_nxos', 'arista_eos'], indirect=True)
def test_other_release_of_the_family_is_config_platform_not_supported(env):
    # DERIVED: the admitted identity text with another release number.
    version = env['spec']['identity']['show version']
    release = {'cisco_xe': '17.18.2', 'cisco_nxos': '9.3(12)', 'arista_eos': '4.36.1F'}[env['platform']]
    assert release in version
    _identity(env, **{'show version': version.replace(release, release.replace('1', '7', 1))})
    data = _read(env)['structuredContent']
    assert data['ok'] is False and data['error_code'] == 'config_platform_not_supported', data
    assert data['error'].startswith('configuration ') and data['error'].endswith('; output withheld')
    assert not _config_commands(env)
