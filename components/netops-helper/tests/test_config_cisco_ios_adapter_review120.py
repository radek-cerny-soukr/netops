"""Task123: targeted regression cases for review120 findings 120-1, 120-2 and 120-3.

REAL input: tests/fixtures/real/cisco_ios/iosv_15.9.3M12/version.txt (read only, never written).
All other inputs are DERIVED from it in memory.  The real adapter is used, without mocks.
"""
import copy
import pathlib

import pytest

from netops_helper import config_cisco_ios_adapter as ad

REAL = pathlib.Path(__file__).parent / 'fixtures' / 'real' / 'cisco_ios' / 'iosv_15.9.3M12' / 'version.txt'
IOSV = REAL.read_text()
BAD = 'configuration identity could not be verified'
HW = 'Cisco IOSv (revision 1.0) with  with 460021K/62464K bytes of memory.'
REQUIRED = ('account-rights-not-verified', 'formats-not-verified')


def _refused(text):
    with pytest.raises(ValueError) as info:
        ad.verify_identity(text)
    assert not isinstance(info.value, ad.UnsupportedIosFirmware)
    assert str(info.value) == BAD
    return info.value


def test_n1_assess_forces_unverified_identity_and_required_notes():
    meta = {'config_scope': 'device-account-visible', 'configuration_complete': True,
            'identity_scope_verified': True, 'visibility_limitations': ['formats-not-verified']}
    summary = {'credential_redactions': 0, 'unverified_count': 0, 'unsupported_format_count': 0,
               'unverified_fields': [], 'unverified_truncated': False}
    mbefore, sbefore = copy.deepcopy(meta), copy.deepcopy(summary)
    out = ad.assess(meta, summary)
    assert meta == mbefore and summary == sbefore
    assert out['configuration_complete'] is False
    assert out['identity_scope_verified'] is False
    for note in REQUIRED:
        assert out['visibility_limitations'].count(note) == 1
    assert out['config_scope'] == 'device-account-visible'
    for key, value in summary.items():
        assert out[key] == value


def test_n2_truncated_duplicate_hardware_line_refused():
    _refused(IOSV + '\nCisco IOSv (revision 1.0) with\n')


def test_n3_lone_surrogate_constant_refusal_without_context():
    err = _refused(IOSV + '\ud800')
    assert type(err) is ValueError
    assert err.__context__ is None and err.__cause__ is None


def test_real_iosv_admitted_exact_supported_honest_metadata():
    firmware, meta = ad.verify_identity(IOSV)
    assert firmware == ad.SUPPORTED == ('IOSv', '15.9(3)M12', 'fc1')
    assert meta == {'config_scope': 'device-account-visible', 'configuration_complete': False,
                    'identity_scope_verified': False, 'visibility_limitations': list(REQUIRED)}


def test_normal_assess_keeps_counters_and_notes_without_mutation():
    meta = ad.metadata()
    meta['visibility_limitations'].append('other-note')
    summary = {'credential_redactions': 2, 'unverified_count': 3, 'unsupported_format_count': 1,
               'unverified_fields': ['a', 'b'], 'unverified_truncated': True}
    mbefore, sbefore = copy.deepcopy(meta), copy.deepcopy(summary)
    out = ad.assess(meta, summary)
    assert meta == mbefore and summary == sbefore
    for key, value in summary.items():
        assert out[key] == value
    limits = out['visibility_limitations']
    assert limits is not meta['visibility_limitations']
    assert limits.count('other-note') == 1 and limits.count('schema-fields-unverified') == 1
    for note in REQUIRED:
        assert limits.count(note) == 1
    assert out['configuration_complete'] is False and out['identity_scope_verified'] is False


def test_complete_duplicate_hardware_line_still_refused():
    assert IOSV.count(HW) == 1
    _refused(IOSV + HW + '\n')
