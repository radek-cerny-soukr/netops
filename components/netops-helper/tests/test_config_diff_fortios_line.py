"""Task 298 (1.0.10 B1): FortiOS config_diff is a line diff (Myers), FortiADC stays positional.

FortiOS: the base configuration is the REAL anonymized ``show system interface`` capture of the FortiGate-80F
8.0.2 build 0251 (fixtures/real/fortinet/fortigate80f_8.0.2_build0251/captures_20261110/vlan_config.txt) and
the identity the REAL ``get system status`` of the same device (fixtures/fortios_80f_802_flow_status.txt).
The changed variants (DERIVED) insert, remove or change one line of that capture, using only the syntax it
already has (``edit``/``set vlanid``/``next``) and ``set status up|down`` (the one value the minimal profile
shows).  Both snapshots go through the real ``engine.config_read`` (minimal profile ``fortios-minimal-4``,
serialized markers) and the real ``engine.config_diff``; only the OpenSSH client is the substituted one of
tests/conftest.py (``wire``), answering each remote command from a table.

FortiADC: the REAL capture ``schedule_group_sg_now_full.txt`` of FortiADC-KVM 7.6.7 build 0676 through the
``schedule_wire`` fixture of test_triage_slb (the configuration stream transport replaced), one line removed.
Nothing here is a live measurement.
"""

from dataclasses import replace
import json
from pathlib import Path

import pytest

from conftest import FORTIOS_STATUS
from netops_helper import configuration
import netops_helper.engine as engine
from test_error_branches_helper_config_read import _device, _fortios
from test_triage_slb import real, schedule_auth, schedule_wire  # noqa: F401  (pytest fixture)

FIXTURES = Path(__file__).parent / 'fixtures'
STATUS = (FIXTURES / 'fortios_80f_802_flow_status.txt').read_text(encoding='utf-8')
CONFIG = (FIXTURES / 'real/fortinet/fortigate80f_8.0.2_build0251/captures_20261110/vlan_config.txt').read_text(
    encoding='utf-8')
SECTION = 'system interface'
COMMAND = 'show system interface'
HEADER = '--- base\n+++ other\n'
VOICE = '                set vlanid "4091"\n'      # a line in the middle of the capture (edit "voice")
VIDEO = '                set vlanid "4090"\n'      # a hidden value (edit "video")


@pytest.fixture(autouse=True)
def _clean():
    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()
    yield
    configuration._SNAPSHOTS.clear()
    configuration._DIFFS.clear()


def _auth():
    auth = _fortios()
    return replace(auth, read_inventory={**auth.read_inventory, 'config_access': ('read', 'compare')})


def _after(config, line, added):
    """DERIVED: ``config`` with ``added`` inserted right after the one occurrence of ``line``."""
    assert config.count(line) == 1, line
    return config.replace(line, line + added, 1)


def _read(wire, auth, config, status=STATUS):
    _device(wire, {'get system status': [0, status], COMMAND: [0, config]})
    result = engine.config_read(auth, 'fortios', SECTION)
    assert result['ok'] is True and result['redaction_profile'] == configuration.PROFILE, result
    assert result['next_offset'] is None
    return result


def _diff(wire, base, other, base_status=STATUS, other_status=STATUS):
    auth = _auth()
    first = _read(wire, auth, base, base_status)
    second = _read(wire, auth, other, other_status)
    return first, second, engine.config_diff(auth, 'fortios', first['snapshot_id'], second['snapshot_id'])


def _body(diff):
    text = diff['untrusted_device_output']
    assert text.startswith(HEADER), text
    return text[len(HEADER):]


def test_the_real_capture_reads_in_the_minimal_profile_with_hidden_values(wire):
    result = _read(wire, _auth(), CONFIG)
    output = result['untrusted_device_output']
    # Minimal profile: every edit name and every value is hidden (8 interfaces: 16 hidden lines).
    assert result['redacted_count'] == 16 and output.count('    set vlanid <REDACTED>\n') == 8
    assert '"4091"' not in output and 'edit <REDACTED>\n' in output
    assert configuration.LINE_DIFF_MAX_EDITS == 3000 and 'fortios' in configuration.LINE_DIFF_PLATFORMS


def test_one_inserted_line_in_the_middle_is_one_plus_line(wire):
    _, _, diff = _diff(wire, CONFIG, _after(CONFIG, VOICE, '                set status down\n'))
    assert diff['ok'] is True and diff['platform'] == 'fortios' and diff['identical'] is False
    assert _body(diff) == '+    set status down\n'
    assert diff['secrets_changed'] == [] and diff['secrets_changed_count'] == 0
    assert 'hidden_lines_compared' not in diff and 'base_capture' not in diff


def test_one_removed_line_is_one_minus_line(wire):
    _, _, diff = _diff(wire, _after(CONFIG, VOICE, '                set status down\n'), CONFIG)
    assert diff['identical'] is False and _body(diff) == '-    set status down\n'
    assert diff['secrets_changed_count'] == 0


def test_one_changed_value_is_one_minus_plus_pair(wire):
    _, _, diff = _diff(wire, _after(CONFIG, VOICE, '                set status up\n'),
                       _after(CONFIG, VOICE, '                set status down\n'))
    assert _body(diff) == '-    set status up\n+    set status down\n'
    assert diff['secrets_changed_count'] == 0


def test_hidden_values_never_reach_the_diff_and_their_changes_are_secrets_changed(wire):
    other = _after(CONFIG.replace(VIDEO, '                set vlanid "4087"\n'), VOICE,
                   '                set status down\n')
    _, _, diff = _diff(wire, CONFIG, other)
    # The changed hidden value: text unchanged (constant marker), one changed record; the visible insertion
    # stays one '+' line.
    assert _body(diff) == '+    set status down\n'
    assert diff['secrets_changed_count'] == 1 and len(diff['secrets_changed']) == 1
    assert diff['secrets_changed'][0].startswith('record:') and diff['identical'] is False
    for value in ('4087', '4090', '"4091"'):
        assert value not in diff['untrusted_device_output']
    # Only the hidden value changed: an empty diff text, still not identical, still one record.
    configuration._DIFFS.clear()
    _, _, hidden_only = _diff(wire, CONFIG, CONFIG.replace(VIDEO, '                set vlanid "4087"\n'))
    assert hidden_only['untrusted_device_output'] == '' and hidden_only['identical'] is False
    assert hidden_only['secrets_changed_count'] == 1
    # A new hidden line: one '+' marker line, never the value, and one new record.
    configuration._DIFFS.clear()
    _, _, added = _diff(wire, CONFIG, _after(CONFIG, VOICE, '            next\n            edit "lab-vlan"\n'
                                                               '                set vlanid "4087"\n'))
    # Three '+' lines (the repeated marker lines may align either way round), one record for the edit name
    # and one for the value.
    body = _body(added).split('\n')
    assert body[-1] == '' and sorted(body[:-1]) == ['+    set vlanid <REDACTED>', '+edit <REDACTED>', '+next']
    assert '4087' not in added['untrusted_device_output'] and 'lab-vlan' not in added['untrusted_device_output']
    assert added['secrets_changed_count'] == 2
    assert 'lab-vlan' not in json.dumps(added)


def test_the_same_pair_is_identical(wire):
    _, _, diff = _diff(wire, CONFIG, CONFIG)
    assert diff['identical'] is True and diff['untrusted_device_output'] == ''


def test_another_firmware_stays_a_plain_incomparable_refusal(wire):
    auth = _auth()
    first = _read(wire, auth, CONFIG)
    second = _read(wire, auth, _after(CONFIG, VOICE, '                set status down\n'), FORTIOS_STATUS)
    assert first['firmware'] != second['firmware']
    with pytest.raises(ValueError, match='^configuration snapshot section, firmware or profile mismatch$') as raised:
        engine.config_diff(auth, 'fortios', first['snapshot_id'], second['snapshot_id'])
    assert not isinstance(raised.value, engine.PaginationRefused)
    assert not configuration._DIFFS


def _vlans(count):
    """DERIVED: ``count`` more VLAN interfaces in the shape of the capture (3 lines, 2 hidden, each)."""
    return ''.join('            edit "lab-%d"\n                set vlanid "%d"\n            next\n' % (n, 2000 + n)
                   for n in range(count))


def test_more_than_the_edit_bound_is_config_diff_limit_exceeded(wire):
    marker = '            next\n            edit "video"\n'
    many = CONFIG.replace(marker, '            next\n' + _vlans(1001) + '            edit "video"\n', 1)
    assert many.count('\n') - CONFIG.count('\n') == 3003 > configuration.LINE_DIFF_MAX_EDITS
    auth = _auth()
    first = _read(wire, auth, CONFIG)
    _device(wire, {'get system status': [0, STATUS], COMMAND: [0, many]})
    second = engine.config_read(auth, 'fortios', SECTION, limit=1000)
    assert second['ok'] is True
    with pytest.raises(engine.ConfigurationRefusal) as raised:
        engine.config_diff(auth, 'fortios', first['snapshot_id'], second['snapshot_id'])
    assert raised.value.code == 'config_diff_limit_exceeded'
    assert str(raised.value) == configuration.DIFF_LIMIT_EXCEEDED
    assert not configuration._DIFFS
    # At the bound (1000 interfaces, 3000 lines) the diff is listed, one '+' line per inserted line.
    at_bound = CONFIG.replace(marker, '            next\n' + _vlans(1000) + '            edit "video"\n', 1)
    _device(wire, {'get system status': [0, STATUS], COMMAND: [0, at_bound]})
    third = engine.config_read(auth, 'fortios', SECTION, limit=1000)
    diff = engine.config_diff(auth, 'fortios', first['snapshot_id'], third['snapshot_id'], limit=48000)
    assert diff['next_offset'] is not None   # paged: the first page only
    lines = diff['untrusted_device_output'].split('\n')
    assert lines[:2] == ['--- base', '+++ other'] and all(line[:1] == '+' for line in lines[2:-1])
    assert diff['secrets_changed_count'] == 2000


def test_fortiadc_keeps_the_positional_comparison(schedule_wire):
    section = 'system schedule-group netops-173-sg-now'
    auth = replace(schedule_auth(), read_inventory={**schedule_auth().read_inventory,
                                                    'config_access': ('read', 'compare')})
    first = engine.config_read(auth, 'fortiadc', section, redaction='full', include_defaults=True)
    view = real('schedule_group_sg_now_full.txt')
    removed = '        set starttime-of-startdate 00:00\n'
    assert view.count(removed) == 1
    schedule_wire.views[section] = view.replace(removed, '', 1)
    second = engine.config_read(auth, 'fortiadc', section, redaction='full', include_defaults=True)
    diff = engine.config_diff(auth, 'fortiadc', first['snapshot_id'], second['snapshot_id'])
    assert diff['platform'] == 'fortiadc' and diff['identical'] is False
    # Positional: every later line shifts (a line diff would be the one '-' line of the removed field).
    assert _body(diff) == ('-    set starttime-of-startdate 00:00\n+    set endtime-of-enddate 23:59\n'
                           '-    set endtime-of-enddate 23:59\n+    set day-of-week saturday\n'
                           '-    set day-of-week saturday\n+next\n'
                           '-next\n+end\n'
                           '-end\n+next\n'
                           '-next\n+end\n'
                           '-end\n')


# Task 298-r2: the full profile numbers its hidden values (<REDACTED:credential#N>); an added or removed hidden
# line renumbers the later markers.  The input of review-298-rv (SYNTHETIC, made-up secrets FAKE-*): the
# psksecret of peer-a removed, one added to peer-c, the peers between them unchanged.  Both snapshots go through
# the real config_read (full profile of the FortiGate-80F 8.0.2 build 0251 policy) and config_diff.
IPSEC = 'vpn ipsec phase1-interface'


def _peers(middle, *, first_secret, last_secret, middle_secret='FAKE-B'):
    def peer(name, secret):
        body = '        set psksecret "%s"\n' % secret if secret else ''
        return '    edit "%s"\n%s    next\n' % (name, body)
    names = ['peer-b'] if middle == 1 else ['peer-b%d' % n for n in range(1, middle + 1)]
    return ('config vpn ipsec phase1-interface\n' + peer('peer-a', first_secret)
            + ''.join(peer(name, middle_secret + name[-1]) for name in names)
            + peer('peer-c', last_secret) + 'end\n')


def _read_full(wire, auth, config):
    _device(wire, {'get system status': [0, STATUS], 'show ' + IPSEC: [0, config]})
    result = engine.config_read(auth, 'fortios', IPSEC, redaction='full')
    assert result['ok'] is True and result['redaction'] == 'full', result
    assert result['redaction_profile'] != configuration.PROFILE and result['next_offset'] is None
    assert result['unverified_count'] == 0
    return result


def _psk(number):
    return '    set psksecret <REDACTED:credential#%d>\n' % number


@pytest.mark.parametrize('middle', [1, 3])
def test_full_profile_added_and_removed_hidden_lines_do_not_renumber_unchanged_peers(wire, middle):
    base = _peers(middle, first_secret='FAKE-A', last_secret=None)
    other = _peers(middle, first_secret=None, last_secret='FAKE-C')
    auth = _auth()
    first, second = _read_full(wire, auth, base), _read_full(wire, auth, other)
    assert first['credential_redactions'] == second['credential_redactions'] == middle + 1
    # The stored lines of the unchanged middle peers do carry other numbers in the two snapshots.
    assert _psk(2) in first['untrusted_device_output'] and _psk(1) in second['untrusted_device_output']
    forward = engine.config_diff(auth, 'fortios', first['snapshot_id'], second['snapshot_id'])
    # Only the removed psksecret of peer-a and the added one of peer-c, each with its own snapshot's number.
    assert _body(forward) == '-' + _psk(1) + '+' + _psk(middle + 1)
    assert forward['identical'] is False and forward['secrets_changed_count'] == 0
    backward = engine.config_diff(auth, 'fortios', second['snapshot_id'], first['snapshot_id'])
    assert _body(backward) == '+' + _psk(1) + '-' + _psk(middle + 1)
    assert backward['identical'] is False
    for diff in (forward, backward):
        shown = json.dumps(diff)
        assert 'FAKE' not in shown and 'peer-b' not in shown and '<REDACTED:credential>' not in shown


def test_full_profile_does_not_show_a_changed_hidden_value(wire):
    # Documented limit (unchanged by 298-r2): the full profile keeps no secrets_changed records, so a pair that
    # differs only in a hidden value is reported identical; the minimal profile reports it (next test).
    auth = _auth()
    first = _read_full(wire, auth, _peers(1, first_secret='FAKE-A', last_secret=None))
    second = _read_full(wire, auth, _peers(1, first_secret='FAKE-X', last_secret=None))
    diff = engine.config_diff(auth, 'fortios', first['snapshot_id'], second['snapshot_id'])
    assert diff['untrusted_device_output'] == '' and diff['secrets_changed_count'] == 0
    assert diff['identical'] is True and 'FAKE' not in json.dumps(diff)


def test_minimal_profile_same_scenario_stays_correct(wire):
    auth = _auth()

    def read(config):
        _device(wire, {'get system status': [0, STATUS], 'show ' + IPSEC: [0, config]})
        result = engine.config_read(auth, 'fortios', IPSEC)
        assert result['ok'] is True and result['redaction_profile'] == configuration.PROFILE, result
        return result

    first = read(_peers(1, first_secret='FAKE-A', last_secret=None))
    second = read(_peers(1, first_secret=None, last_secret='FAKE-C'))
    diff = engine.config_diff(auth, 'fortios', first['snapshot_id'], second['snapshot_id'])
    # (psksecret is a secret key name: the response redaction shows its marker as '[REDACTED]'.)
    assert _body(diff) == '-    set psksecret [REDACTED]\n+    set psksecret [REDACTED]\n'
    # The removed secret of peer-a and the added one of peer-c; peer-b unchanged.
    assert diff['secrets_changed_count'] == 2 and diff['identical'] is False
    configuration._DIFFS.clear()
    value = read(_peers(1, first_secret='FAKE-X', last_secret=None))
    changed = engine.config_diff(auth, 'fortios', first['snapshot_id'], value['snapshot_id'])
    assert changed['untrusted_device_output'] == '' and changed['secrets_changed_count'] == 1
    assert changed['identical'] is False
    for result in (diff, changed):
        shown = json.dumps(result)
        assert 'FAKE' not in shown and 'peer-' not in shown


# Task 298-r3: the input of review-298-r2rv finding 1 (SYNTHETIC, made-up secret FAKE-*).  A psksecret added to
# peer-a changes credential_redactions (1 -> 2); for a FortiOS full pair that count is not part of the
# comparability identity any more, so the pair is one '+' (or, reversed, one '-') line instead of
# config_snapshot_incomparable.  The stored counts are still returned per capture.
PEER_A = '    edit "peer-a"\n'
R3_BASE = ('config vpn ipsec phase1-interface\n'
           '    edit "peer-a"\n'
           '    next\n'
           '    edit "peer-b"\n'
           '        set psksecret "FAKE-B"\n'
           '    next\n'
           'end\n')
R3_OTHER = _after(R3_BASE, PEER_A, '        set psksecret "FAKE-A"\n')


def test_full_profile_added_or_removed_secret_line_with_other_redaction_count_is_one_line(wire):
    auth = _auth()
    first, second = _read_full(wire, auth, R3_BASE), _read_full(wire, auth, R3_OTHER)
    assert first['credential_redactions'] == 1 and second['credential_redactions'] == 2
    # Stored text: peer-b is #1 in the base and #2 in the other snapshot.
    assert _psk(1) in first['untrusted_device_output'] and _psk(2) in second['untrusted_device_output']
    forward = engine.config_diff(auth, 'fortios', first['snapshot_id'], second['snapshot_id'])
    assert forward['ok'] is True and forward['identical'] is False
    assert _body(forward) == '+' + _psk(1)
    backward = engine.config_diff(auth, 'fortios', second['snapshot_id'], first['snapshot_id'])
    assert backward['ok'] is True and backward['identical'] is False
    assert _body(backward) == '-' + _psk(1)
    # The real per-capture metadata stays as recorded (1 and 2), each in its own object.
    assert forward['base_capture']['credential_redactions'] == 1
    assert forward['other_capture']['credential_redactions'] == 2
    assert backward['base_capture']['credential_redactions'] == 2
    assert backward['other_capture']['credential_redactions'] == 1
    for diff in (forward, backward):
        assert diff['secrets_changed_count'] == 0
        assert {key: value for key, value in diff['base_capture'].items() if key != 'credential_redactions'} == \
            {key: value for key, value in diff['other_capture'].items() if key != 'credential_redactions'}
        shown = json.dumps(diff)
        assert 'FAKE' not in shown and 'peer-b' not in shown and '<REDACTED:credential>' not in shown
        assert '#2' not in diff['untrusted_device_output']
    # The stored snapshots keep their own counts (nothing was rewritten by the comparison).
    counts = sorted(dict(s.metadata)['credential_redactions'] for s in configuration._SNAPSHOTS.values())
    assert counts == [1, 2]


def _read_full_status(wire, auth, config, status):
    _device(wire, {'get system status': [0, status], 'show ' + IPSEC: [0, config]})
    result = engine.config_read(auth, 'fortios', IPSEC, redaction='full')
    assert result['ok'] is True and result['redaction'] == 'full', result
    return result


@pytest.mark.parametrize('other_status', [
    STATUS.replace('FortiGate-80F', 'FortiGate-60F', 1),                    # another firmware (model)
    STATUS.replace('v8.0.2,build0251', 'v7.6.8,build3744', 1),              # another firmware and profile
], ids=['firmware', 'firmware-and-profile'])
def test_full_profile_other_firmware_or_profile_with_other_redaction_count_stays_incomparable(wire, other_status):
    assert other_status != STATUS
    auth = _auth()
    first = _read_full_status(wire, auth, R3_BASE, STATUS)
    second = _read_full_status(wire, auth, R3_OTHER, other_status)
    assert first['firmware'] != second['firmware']
    assert first['credential_redactions'] == 1 and second['credential_redactions'] == 2
    for pair in ((first, second), (second, first)):
        with pytest.raises(ValueError, match='^configuration snapshot section, firmware or profile mismatch$') as raised:
            engine.config_diff(auth, 'fortios', pair[0]['snapshot_id'], pair[1]['snapshot_id'])
        assert not isinstance(raised.value, engine.PaginationRefused)
    assert not configuration._DIFFS


def test_full_profile_other_include_defaults_with_other_redaction_count_stays_incomparable(wire):
    auth = _auth()
    first = _read_full(wire, auth, R3_BASE)
    _device(wire, {'get system status': [0, STATUS], 'show full-configuration ' + IPSEC: [0, R3_OTHER]})
    second = engine.config_read(auth, 'fortios', IPSEC, redaction='full', include_defaults=True)
    assert second['ok'] is True and second['include_defaults'] is True, second
    assert first['credential_redactions'] == 1 and second['credential_redactions'] == 2
    with pytest.raises(ValueError, match='^configuration snapshot section, firmware or profile mismatch$'):
        engine.config_diff(auth, 'fortios', first['snapshot_id'], second['snapshot_id'])
    assert not configuration._DIFFS
