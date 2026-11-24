import copy
import hashlib
import json
import pathlib

import pytest

from netops_helper import config_cisco_ios_adapter as ad
from netops_helper.config_cisco_ios import MARKER, StreamRedactor

REAL = pathlib.Path(__file__).parent / 'fixtures' / 'real' / 'cisco_ios'
IOSV = (REAL / 'iosv_15.9.3M12' / 'version.txt').read_text()
IOSVL2 = (REAL / 'iosvl2_15.2.20200924' / 'version.txt').read_text()
BAD = 'configuration identity could not be verified'
HEADER = ('Cisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.9(3)M12, '
          'RELEASE SOFTWARE (fc1)')
HW = 'Cisco IOSv (revision 1.0) with  with 460021K/62464K bytes of memory.'


TESTED_RECORD = ('IOSv', '15.9(3)M12', 'fc1', 'VIOS-ADVENTERPRISEK9-M')


def test_real_iosv_tested():
    firmware, meta = ad.verify_identity(IOSV)
    assert firmware == TESTED_RECORD and firmware[:3] == ad.TESTED
    assert ad.firmware_record(firmware)
    assert ad.firmware_support(firmware) == {
        'status': 'tested', 'platform': 'Cisco IOS', 'device_version': '15.9(3)M12 fc1 (VIOS-ADVENTERPRISEK9-M)',
        'model': 'IOSv', 'tested_versions': ['IOSv 15.9(3)M12 fc1 (VIOS-ADVENTERPRISEK9-M)'], 'message': None}
    assert meta['config_scope'] == 'device-account-visible'
    assert meta['configuration_complete'] is False and meta['identity_scope_verified'] is False
    assert 'account-rights-not-verified' in meta['visibility_limitations']
    assert 'formats-not-verified' in meta['visibility_limitations']
    assert ad.version_identity(IOSV) == ('IOSv', '15.9(3)M12', 'fc1', ad.IMAGE_FAMILY)


def test_real_iosvl2_is_read_as_untested():
    """STARTUP: the real IOSvL2 capture (another software, image family and release) is no refusal."""
    firmware, meta = ad.verify_identity(IOSVL2)
    assert firmware == ('IOSv', '15.2(20200924:215240)', None, 'vios_l2-ADVENTERPRISEK9-M')
    assert meta == ad.metadata() and ad.firmware_record(firmware)
    support = ad.firmware_support(firmware)
    assert support['status'] == 'untested' and support['model'] == 'IOSv'
    assert support['device_version'] == '15.2(20200924:215240) (vios_l2-ADVENTERPRISEK9-M)'
    assert support['message'] == (
        'Cisco IOS 15.2(20200924:215240) (vios_l2-ADVENTERPRISEK9-M) on IOSv is not among the versions '
        'config_read was tested on (IOSv 15.9(3)M12 fc1 (VIOS-ADVENTERPRISEK9-M)). It may or may not work as '
        'designed and tested; check the result.')


def test_catalyst_header_and_hardware_are_read_as_untested():
    """A classic Catalyst show version (derived header and hardware line, no other lines changed)."""
    text = IOSV.replace(HEADER, 'Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, '
                                'RELEASE SOFTWARE (fc3)').replace(
        HW, 'cisco WS-C2960-24TT-L (PowerPC405) processor (revision B0) with 65536K bytes of memory.')
    firmware = ad.verify_identity(text)[0]
    assert firmware == ('WS-C2960-24TT-L', '15.0(2)SE11', 'fc3', 'C2960-LANBASEK9-M')
    assert ad.firmware_support(firmware)['status'] == 'untested'
    # No recognized hardware line: the model is unknown, the identity is still read and untested.
    firmware = ad.verify_identity(text.replace('cisco WS-C2960-24TT-L (PowerPC405) processor', 'unknown board'))[0]
    assert firmware == (None, '15.0(2)SE11', 'fc3', 'C2960-LANBASEK9-M')
    support = ad.firmware_support(firmware)
    assert support['status'] == 'untested' and support['model'] is None
    assert support['message'].startswith('Cisco IOS 15.0(2)SE11 fc3 (C2960-LANBASEK9-M) is not among')


def test_crlf_and_prompt_lines():
    assert ad.verify_identity(IOSV.replace('\n', '\r\n'))[0] == TESTED_RECORD
    assert ad.verify_identity('host#show version\r\n' + IOSV + '\r\nhost#')[0] == TESTED_RECORD


@pytest.mark.parametrize('old,new,record', [
    ('15.9(3)M12', '15.9(3)M11', ('IOSv', '15.9(3)M11', 'fc1', 'VIOS-ADVENTERPRISEK9-M')),
    ('(fc1)', '(fc2)', ('IOSv', '15.9(3)M12', 'fc2', 'VIOS-ADVENTERPRISEK9-M')),
    ('VIOS-ADVENTERPRISEK9-M', 'VIOS-OTHER-M', ('IOSv', '15.9(3)M12', 'fc1', 'VIOS-OTHER-M')),
    ('15.9(3)M12', '15.9(3)T1', ('IOSv', '15.9(3)T1', 'fc1', 'VIOS-ADVENTERPRISEK9-M'))])
def test_derived_foreign_wellformed_is_untested(old, new, record):
    firmware = ad.verify_identity(IOSV.replace(old, new))[0]
    assert firmware == record
    support = ad.firmware_support(firmware)
    assert support['status'] == 'untested' and support['tested_versions'] == [
        'IOSv 15.9(3)M12 fc1 (VIOS-ADVENTERPRISEK9-M)']


@pytest.mark.parametrize('record', [
    ('IOSv', '15.9(3)M12', 'fc1'), ['IOSv', '15.9(3)M12', 'fc1', 'VIOS-ADVENTERPRISEK9-M'],
    ('IOSv', None, 'fc1', 'VIOS-ADVENTERPRISEK9-M'), ('IOSv', '15.9(3)M12', 'fc1', None),
    ('IOSv', '', 'fc1', 'VIOS-ADVENTERPRISEK9-M'), ('IOSv', '15.9(3)M12', 1, 'VIOS-ADVENTERPRISEK9-M'), None])
def test_firmware_record_shape(record):
    assert not ad.firmware_record(record)


@pytest.mark.parametrize('make', [
    lambda t: t.replace(HW, ''),                                  # missing model
    lambda t: t.replace(HEADER, ''),                              # missing version
    lambda t: t + HW + '\n',                                      # duplicate model
    lambda t: t + HEADER + '\n',                                  # duplicate version
    lambda t: t.replace('Cisco IOSv (rev', 'Cisco IOSvL2 (rev'),  # conflicting model
    lambda t: t.replace('IOSv Software', 'IOSv'),                 # malformed header
    lambda t: '',
    lambda t: '   \n',
    lambda t: 'host#',
    lambda t: t + '\x07',
    lambda t: t + '\x00',
    lambda t: t + 'x' * 70000,
    lambda t: None,
    lambda t: t.encode(),
])
def test_unverifiable_identity(make):
    with pytest.raises(ValueError, match=BAD) as info:
        ad.verify_identity(make(IOSV))
    assert type(info.value) is ValueError


def test_read_command():
    assert ad.read_command('all', True, False) == 'show running-config'
    for args in [('all', False, False), ('all', True, True), ('all', True, False, 'none'),
                 ('interfaces', True, False), ('all', True, False, 'full', 'startup'),
                 (None, True, False), ('all', 1, False), ('all', True, 0)]:
        with pytest.raises(ValueError, match='config_platform_not_supported'):
            ad.read_command(*args)


def test_profile_fingerprint():
    desc = ('cisco_ios', 'config_cisco_ios.StreamRedactor', 'ios-lines-menu-reject-1', MARKER,
            'show running-config', ('show version',), 'VIOS-ADVENTERPRISEK9-M',
            ('IOSv', '15.9(3)M12', 'fc1'))
    assert ad.POLICY_DESCRIPTOR == desc
    digest = hashlib.sha256(json.dumps(desc, separators=(',', ':')).encode('ascii')).hexdigest()
    assert ad.PROFILE == 'cisco_ios-full-1:' + digest
    changed = desc[:2] + ('ios-lines-menu-reject-2',) + desc[3:]
    assert hashlib.sha256(json.dumps(changed, separators=(',', ':')).encode('ascii')).hexdigest() != digest


def test_assess_does_not_mutate_and_keeps_honesty():
    meta = ad.metadata()
    before = copy.deepcopy(meta)
    summary = {'credential_redactions': 0, 'unverified_count': 3, 'unsupported_format_count': 1,
               'unverified_fields': ['a'], 'unverified_truncated': False}
    sbefore = copy.deepcopy(summary)
    out = ad.assess(meta, summary)
    assert meta == before and summary == sbefore
    assert out['visibility_limitations'].count('formats-not-verified') == 1
    assert 'schema-fields-unverified' in out['visibility_limitations']
    assert out['unverified_count'] == 3 and out['configuration_complete'] is False
    assert out['visibility_limitations'] is not meta['visibility_limitations']
    clean = ad.assess(meta, dict(summary, unverified_count=0, unsupported_format_count=0))
    assert clean['visibility_limitations'] == ['account-rights-not-verified', 'formats-not-verified']
    assert ad.assess(out, summary)['visibility_limitations'].count('formats-not-verified') == 1


def test_real_consumer_summary_feeds_assess():
    redactor = StreamRedactor((), 'all')
    try:
        redactor.feed(b'hostname r1\n!\nbanner motd ^C hi ^C\nend\n')
        redactor.finish()
        summary = redactor.summary()
    finally:
        redactor.close()
    out = ad.assess(ad.metadata(), summary)
    assert out['configuration_complete'] is False
    assert out['visibility_limitations'].count('formats-not-verified') == 1
    assert out['unverified_count'] == summary['unverified_count']
