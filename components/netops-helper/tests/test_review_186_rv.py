"""Task 186-r2: regressions of the accepted findings of review 186-rv (inputs taken from the review).

1. [P2] A pure insertion or deletion (one side empty after the common head and tail) is subject to the fixed
   bound of LINE_DIFF_MAX_EDITS changed lines like every other path.
2. [P1] The line diff does not copy the line tables (offsets instead of slices), so its peak memory stays within
   what it charges to the configuration memory budget; a budget refusal of the new diff path is the controlled
   ``config_diff_limit_exceeded`` answer, not an internal error.
3. [P2] The EXOS read-only refusal ``This user does not have permissions for this command.`` is a device refusal
   only as the exact whole answer line before the first configuration line, never inside a quoted multi-line
   value, a UPM block, after a configuration line, or with a suffix.

Data labels: DERIVED - the review inputs (synthetic IOS/EXOS configurations), the synthetic configurations of
``test_config_diff_ios_family`` with one-line edits, and the EXOS refusal text (the 178 log redacted it).
"""
import time
import tracemalloc

import pytest

from netops_helper import config_exos, configuration
from netops_helper.config_buffers import ChangedRecords, ContentBuilder, HiddenRecords
from netops_helper.configuration import ConfigurationRefusedError

import test_config_diff_ios_family as family
from test_config_diff_ios_family import env  # noqa: F401  (pytest fixture, parametrized by platform)
from test_live_scenarios_178 import DEVICE_REFUSED, EXOS_REFUSAL, _content, _diff_text, _error, _lines, _read, _text

A_ID, B_ID = 'cfg_' + 'a' * 32, 'cfg_' + 'b' * 32


@pytest.fixture(autouse=True)
def _clean():
    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()
    yield
    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()


# ----------------------------------------------------------- 1. the edit bound on every path

def _loopbacks(count):
    return ''.join(f'interface Loopback{n}\n' for n in range(count))


BASE = 'hostname lab-r1\n!\nend\n'                     # the review input


def _inserted(count):
    return 'hostname lab-r1\n' + _loopbacks(count) + '!\nend\n'


def test_pure_insertion_or_deletion_over_the_bound_is_refused():
    # After the common head ('hostname lab-r1') and tail ('!', 'end') the base side is empty: 0 against 3001.
    assert configuration.LINE_DIFF_MAX_EDITS == 3000
    with pytest.raises(configuration.DiffLimitExceeded) as raised:
        _diff_text(BASE, _inserted(3001))
    assert str(raised.value) == configuration.DIFF_LIMIT_EXCEEDED
    with pytest.raises(configuration.DiffLimitExceeded):
        _diff_text(_inserted(3001), BASE)               # the reverse comparison: 3001 deletions
    with pytest.raises(configuration.DiffLimitExceeded):
        _diff_text('', _loopbacks(3001))                # whole text added / removed
    with pytest.raises(configuration.DiffLimitExceeded):
        _diff_text(_loopbacks(3001), '')


def test_pure_insertion_or_deletion_at_the_bound_is_listed():
    added = _diff_text(BASE, _inserted(3000)).split('\n')
    assert added[:2] == ['--- base', '+++ other'] and added[-1] == ''
    assert added[2:-1] == ['+interface Loopback%d' % n for n in range(3000)]
    removed = _diff_text(_inserted(3000), BASE).split('\n')
    assert removed[2:-1] == ['-interface Loopback%d' % n for n in range(3000)]


def test_edit_script_checks_the_bound_before_the_empty_side_shortcut():
    from array import array
    a, b = array('i', [7]), array('i', [7] + [1] * 3001 + [9])
    with pytest.raises(configuration.DiffLimitExceeded):
        configuration._edit_script(a, b, [0])
    # With offsets: the compared ranges are a[1:1] (empty) and b[1:3002] (3001 lines).
    tail = array('i', [7, 9])
    with pytest.raises(configuration.DiffLimitExceeded):
        configuration._edit_script(tail, b, [0], 1, 1)
    assert configuration._edit_script(tail, array('i', [7, 1, 1, 9]), [0], 1, 1) == [(range(0), range(2))]


def _snapshot(text, platform='cisco_ios'):
    return configuration.Snapshot(('scope', platform), _content(text), HiddenRecords(), time.monotonic(), 0,
                                  'all', ('IOSv', '15.9(3)M12', 'fc1'), 'full')


class _Auth:
    secrets = ()


def test_compare_refuses_the_review_insertion_and_caches_nothing(monkeypatch):
    monkeypatch.setattr(configuration, 'scope', lambda auth, platform='fortios': ('scope', platform))
    configuration._SNAPSHOTS[A_ID] = _snapshot(BASE)
    configuration._SNAPSHOTS[B_ID] = _snapshot(_inserted(3001))
    for pair in ((A_ID, B_ID), (B_ID, A_ID)):
        with pytest.raises(configuration.DiffLimitExceeded):
            configuration.compare(_Auth(), *pair, platform='cisco_ios')
    assert not configuration._DIFFS


# ----------------------------------------------------------- 2. no copies of the line tables; budget

def _review_pair(blank_lines):
    # The review shape: different hostname at the start, a large middle of blank lines, a different interface
    # description just before the common tail, so the common head/tail do not remove the middle block.
    middle = '\n' * blank_lines
    tail = 'interface Ethernet0/1\n!\nend\n'
    return ('hostname lab-r1\n' + middle + ' description left\n' + tail,
            'hostname lab-r2\n' + middle + ' description right\n' + tail)


def test_peak_memory_of_the_line_diff_stays_within_what_it_charges(monkeypatch):
    left, right = _review_pair(1_000_000)   # two line tables of about 4 MB each
    left, right = _content(left), _content(right)
    charged = []
    original = configuration._budget

    def recording(staged=0):
        charged.append(staged)
        return original(staged)

    monkeypatch.setattr(configuration, '_budget', recording)
    out = ContentBuilder(1 << 30, serialized_markers=False)
    tracemalloc.start()
    try:
        configuration._line_diff(left, right, out, ChangedRecords())
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert _text(out.finish()) == ('--- base\n+++ other\n-hostname lab-r1\n+hostname lab-r2\n'
                                   '- description left\n+ description right\n')
    tables = 2 * 4 * 1_000_005
    assert max(charged) >= tables
    # Slices of both tables (the finding) would add about another `tables` bytes (8 MB) on top of the charged
    # ones; the 2 MiB margin covers the transient split of one 64 KiB content chunk in Content.lines() and the
    # interpreter's own small allocations (frames, the output builder).
    assert peak <= max(charged) + 2 * 1024 * 1024, (peak, max(charged))


def test_line_diff_charges_both_whole_tables_before_comparing(monkeypatch):
    left, right = (_content(text) for text in _review_pair(200_000))
    charged = []
    original = configuration._budget
    monkeypatch.setattr(configuration, '_budget', lambda staged=0: (charged.append(staged), original(staged))[1])
    out = ContentBuilder(1 << 30, serialized_markers=False)
    configuration._line_diff(left, right, out, ChangedRecords())
    out.close()
    assert max(charged) >= 2 * 4 * 200_005


def test_budget_exhaustion_of_the_line_diff_is_the_controlled_limit_refusal(monkeypatch):
    monkeypatch.setattr(configuration, 'scope', lambda auth, platform='fortios': ('scope', platform))
    left, right = _review_pair(200_000)
    configuration._SNAPSHOTS[A_ID] = _snapshot(left)
    configuration._SNAPSHOTS[B_ID] = _snapshot(right)
    retained = sum(s.memory_bytes for s in configuration._SNAPSHOTS.values())
    # Room for the snapshots and less than the two line tables (2 x 800 kB).
    monkeypatch.setattr(configuration, '_ACTIVE_BUDGET', retained + 1024 * 1024)
    with pytest.raises(configuration.DiffLimitExceeded) as raised:
        configuration.compare(_Auth(), A_ID, B_ID, platform='cisco_ios')
    assert str(raised.value) == configuration.DIFF_BUDGET_EXCEEDED
    assert not configuration._DIFFS
    monkeypatch.setattr(configuration, '_ACTIVE_BUDGET', retained + 64 * 1024 * 1024)
    text, changed, identical = configuration.compare(_Auth(), A_ID, B_ID, platform='cisco_ios')
    assert identical is False and _text(text).startswith('--- base\n+++ other\n-hostname lab-r1\n')


@pytest.mark.parametrize('env', ['cisco_ios'], indirect=True)
def test_budget_refusal_on_the_public_diff_path_has_the_machine_code(env, monkeypatch):
    spec = env['spec']
    base = family._capture(env)
    changed = family._capture(env, family._edit(spec['config'], *spec['visible']))
    retained = sum(s.memory_bytes for s in configuration._SNAPSHOTS.values())
    original = configuration._line_ids

    def tight(*args):
        # Inside the diff's configuration.capture() context, after the admit check of both snapshots (which
        # stages a redacted copy): leave 64 bytes above the stored snapshots, less than the line tables.
        configuration._ACTIVE_BUDGET = retained + 64      # capture() resets it to _BYTE_BUDGET on exit
        return original(*args)

    monkeypatch.setattr(configuration, '_line_ids', tight)
    result = family._diff(env, base, changed)
    data = result['structuredContent']
    assert result['isError'] is True and data['ok'] is False, result
    assert data['error_code'] == 'config_diff_limit_exceeded'
    assert data['error'] == configuration.DIFF_BUDGET_EXCEEDED
    assert 'Role operation failed' not in str(result)
    assert 'restart_offset' not in data and 'untrusted_device_output' not in data
    assert not configuration._DIFFS
    assert configuration._ACTIVE_BUDGET == configuration._BYTE_BUDGET


# ----------------------------------------------------------- 3. EXOS read-only refusal, exact and in preamble

REFUSAL_LINE = EXOS_REFUSAL.rstrip('\n')


def _exos(data):
    redactor = config_exos.StreamRedactor((), 'all')
    try:
        redactor.feed(data.encode())
        content, hidden, count = redactor.finish()
        return _text(content)
    finally:
        redactor.close()


def _exos_refused(data):
    redactor = config_exos.StreamRedactor((), 'all')
    with pytest.raises(ConfigurationRefusedError):
        try:
            redactor.feed(data.encode())
            redactor.finish()
        finally:
            redactor.close()


VERIFIED = 'enable ports 1\n'   # a verified EXOS sentence: a capture without any is withheld anyway


@pytest.mark.parametrize('data', [
    # The review input: the second physical line of a quoted multi-line value.
    'enable ports 1\nconfigure snmp sysLocation "first\n' + EXOS_REFUSAL + 'last"\n',
    # Inside a UPM block.
    'create upm profile p1\n' + EXOS_REFUSAL + '.\n',
    # After a configuration line.
    'enable ports 1\n' + EXOS_REFUSAL,
    # A suffix after the full stop, or another prefix (not the exact refusal answer).
    REFUSAL_LINE + ' additional text\n',
    REFUSAL_LINE + '.\n',
    'x ' + EXOS_REFUSAL,
])
def test_exos_refusal_text_in_configuration_content_is_hidden_not_a_refusal(data):
    text = _exos(data + VERIFIED)
    assert 'does not have permissions' not in text and 'enable ports 1\n' in text
    assert config_exos.MARKER in text


@pytest.mark.parametrize('data', [
    EXOS_REFUSAL,                                      # the live 178 answer (rc 254)
    REFUSAL_LINE,                                      # without the final line feed
    '\r\n  ' + REFUSAL_LINE + ' \t\r\n',               # blank preamble lines, CRLF, surrounding blanks
])
def test_exos_exact_refusal_answer_before_any_configuration_is_a_refusal(data):
    _exos_refused(data)


@pytest.mark.parametrize('env', ['extreme_exos'], indirect=True)
def test_exos_refusal_text_inside_a_quoted_value_keeps_the_snapshot(env):
    config = family._edit(env['spec']['config'], 'disable ports 12',
                          'disable ports 12\nconfigure snmp sysLocation "first\n' + EXOS_REFUSAL + 'last"')
    data = family._capture(env, config)
    assert 'does not have permissions' not in data['untrusted_device_output']
    assert len(configuration._SNAPSHOTS) == 1


@pytest.mark.parametrize('env', ['extreme_exos'], indirect=True)
@pytest.mark.parametrize('rc', [254, 0])
def test_exos_read_only_refusal_with_its_live_exit_status_is_device_refused(env, rc):
    # Live 178: rc 254 and the single refusal line; rc 0 with the exact answer is refused by the parser too.
    env['wire'].config_rc = rc
    env['wire'].config = EXOS_REFUSAL
    assert _error(_read(env)) == DEVICE_REFUSED
    assert not configuration._SNAPSHOTS


@pytest.mark.parametrize('env', ['extreme_exos'], indirect=True)
def test_exos_nonzero_exit_status_with_a_suffixed_text_is_still_device_refused(env):
    # The parser no longer takes the suffixed text as the refusal; the device exit status 254 still refuses.
    env['wire'].config_rc = 254
    env['wire'].config = REFUSAL_LINE + ' additional text\n'
    assert _error(_read(env)) == DEVICE_REFUSED
    assert not configuration._SNAPSHOTS
