"""Task 140: Cisco IOS XE identity/profile adapter (single profile IOL-XE 17.18.2 fc3).

Identity: ``show version`` is the immutable REAL capture
``fixtures/real/cisco_xe/iolxe_17.18.2/version.txt``; every other identity text is DERIVED by editing it
(or, for the classic IOS case, the REAL ``fixtures/real/cisco_ios/iosv_15.9.3M12/version.txt``).
The running-config fed to the consumer below is SYNTHETIC.
"""

import copy
import hashlib
import json
import pathlib

import pytest

from netops_helper import config_cisco_xe_adapter as ad
from netops_helper import config_cisco_ios_adapter as ios_ad
from netops_helper.config_cisco_ios import MARKER, StreamRedactor

FIXTURES = pathlib.Path(__file__).parent / 'fixtures' / 'real'
IOLXE = (FIXTURES / 'cisco_xe' / 'iolxe_17.18.2' / 'version.txt').read_text()
IOSV = (FIXTURES / 'cisco_ios' / 'iosv_15.9.3M12' / 'version.txt').read_text()
BAD = 'configuration identity could not be verified'
HEADER = ('Cisco IOS Software [IOSXE], Linux Software (X86_64BI_LINUX-ADVENTERPRISEK9-M), Version 17.18.2, '
          'RELEASE SOFTWARE (fc3)')
HW = 'Linux Unix (i686) processor with 536518K bytes of memory.'


def test_fixture_shape_is_what_the_adapter_reads():
    lines = IOLXE.splitlines()
    assert lines.count(HEADER) >= 1 and lines.count(HW) == 1


def test_real_iolxe_admitted():
    firmware, meta = ad.verify_identity(IOLXE)
    assert firmware == ('Linux', '17.18.2', 'fc3') == ad.SUPPORTED
    assert meta['config_scope'] == 'device-account-visible'
    assert meta['configuration_complete'] is False and meta['identity_scope_verified'] is False
    assert meta['visibility_limitations'] == ['account-rights-not-verified', 'formats-not-verified']
    assert ad.version_identity(IOLXE) == ('Linux', '17.18.2', 'fc3', ad.IMAGE_FAMILY)


def test_repeated_identical_header_admitted():
    # The same header line repeated verbatim further down is one identity, not a conflict.
    text = IOLXE.replace(HW, HEADER + '\n' + HW)
    assert text.count(HEADER) == IOLXE.count(HEADER) + 1
    assert ad.verify_identity(text)[0] == ad.SUPPORTED


def test_crlf_and_prompt_lines():
    assert ad.verify_identity(IOLXE.replace('\n', '\r\n'))[0] == ad.SUPPORTED
    assert ad.verify_identity('host07#show version\r\n' + IOLXE + '\r\nhost07#')[0] == ad.SUPPORTED


@pytest.mark.parametrize('old,new', [
    ('Version 17.18.2,', 'Version 17.18.1,'),                  # other release
    ('Version 17.18.2,', 'Version 17.9.4a,'),                  # other release train number
    ('(fc3)', '(fc4)'),                                        # other build
    ('X86_64BI_LINUX-ADVENTERPRISEK9-M', 'X86_64BI_LINUX-IPBASEK9-M'),  # other image family
    ('[IOSXE]', '[Dublin]'),                                   # other release train
], ids=['release', 'release-a', 'build', 'image-family', 'train'])
def test_derived_foreign_wellformed_refused(old, new):
    assert old in IOLXE
    with pytest.raises(ad.UnsupportedXeFirmware, match='configuration firmware-not-supported'):
        ad.verify_identity(IOLXE.replace(old, new))


def test_real_classic_ios_refused_as_unsupported():
    with pytest.raises(ad.UnsupportedXeFirmware):
        ad.verify_identity(IOSV)
    # And the frozen IOS adapter does not admit the IOS XE capture.
    with pytest.raises(ValueError):
        ios_ad.verify_identity(IOLXE)


@pytest.mark.parametrize('make', [
    lambda t: t.replace(HW, ''),                                                    # missing hardware line
    lambda t: t.replace(HEADER, ''),                                                # missing header
    lambda t: t + HEADER.replace('17.18.2', '17.18.1') + '\n',                      # two different headers
    lambda t: t + HEADER.replace('(fc3)', '(fc4)') + '\n',                          # two different headers
    lambda t: t.replace(HEADER, HEADER.replace('17.18.2', '17.9.4a') + '\n' + HEADER),  # different first
    lambda t: t + HW + '\n',                                                        # duplicate hardware line
    lambda t: t + HW.replace('536518K', '1048576K') + '\n',                         # conflicting hardware line
    lambda t: t.replace('Linux Unix (i686)', 'Solaris Unix (i686)'),                # conflicting model
    lambda t: t.replace(HW, 'Linux Unix (i686) processor with 536518K bytes of'),   # truncated hardware line
    lambda t: t.replace('Linux Software (', 'Linux ('),                             # malformed header
    lambda t: t.replace(', RELEASE SOFTWARE (fc3)', ''),                            # header without build
    lambda t: '',
    lambda t: '   \n',
    lambda t: 'host07#',
    lambda t: t + '\x07',
    lambda t: t + '\x00',
    lambda t: t + ' ',
    lambda t: t + 'x' * 70000,
    lambda t: None,
    lambda t: t.encode(),
], ids=['no-hw', 'no-header', 'two-headers-release', 'two-headers-build', 'two-headers-first',
        'dup-hw', 'conflicting-hw', 'model-mismatch', 'truncated-hw', 'malformed-header', 'no-build',
        'empty', 'blank', 'prompt-only', 'bel', 'nul', 'line-separator', 'oversize', 'none', 'bytes'])
def test_unverifiable_identity(make):
    with pytest.raises(ValueError, match=BAD) as info:
        ad.verify_identity(make(IOLXE))
    assert not isinstance(info.value, ad.UnsupportedXeFirmware)


def test_identity_ignores_image_file_serial_and_hostname():
    # The model and release come only from the header and hardware line.
    text = (IOLXE.replace('Cisco-IOL-XE-17.18.02.bin', 'Cisco-IOL-XE-17.15.01.bin')
            .replace('Processor board ID 0000006', 'Processor board ID C9300X')
            .replace('host07 uptime', 'cat9k-17-9 uptime'))
    assert text != IOLXE
    assert ad.version_identity(text) == ('Linux', '17.18.2', 'fc3', ad.IMAGE_FAMILY)


def test_read_command():
    assert ad.read_command('all', True, False) == 'show running-config'
    assert ad.read_command('all', True, False, 'full', 'running') == 'show running-config'
    for args in [('all', False, False), ('all', True, True), ('all', True, False, 'none'),
                 ('all', True, False, 'minimal'), ('interfaces', True, False),
                 ('all', True, False, 'full', 'startup'), (None, True, False), ('all', 1, False),
                 ('all', True, 0), ('ALL', True, False)]:
        with pytest.raises(ValueError, match='config_platform_not_supported: cisco_xe'):
            ad.read_command(*args)


def test_constants_and_profile_fingerprint():
    assert ad.PLATFORM == 'cisco_xe' and ad.COMMAND == 'show running-config'
    assert ad.IDENTITY_COMMANDS == ('show version',) and ad.IDENTITY_MAX_BYTES == 65536
    assert ad.IMAGE_FAMILY == 'X86_64BI_LINUX-ADVENTERPRISEK9-M'
    assert ad.VISIBILITY == ('account-rights-not-verified', 'formats-not-verified')
    desc = ('cisco_xe', 'config_cisco_ios.StreamRedactor', 'ios-lines-menu-reject-1', MARKER,
            'show running-config', ('show version',), 'X86_64BI_LINUX-ADVENTERPRISEK9-M',
            ('Linux', '17.18.2', 'fc3'))
    assert ad.POLICY_DESCRIPTOR == desc
    digest = hashlib.sha256(json.dumps(desc, separators=(',', ':')).encode('ascii')).hexdigest()
    assert ad.PROFILE == 'cisco_xe-full-1:' + digest
    assert ad.PROFILE != ios_ad.PROFILE


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
    assert out['identity_scope_verified'] is False
    clean = ad.assess(meta, dict(summary, unverified_count=0, unsupported_format_count=0))
    assert clean['visibility_limitations'] == ['account-rights-not-verified', 'formats-not-verified']
    forged = ad.assess(dict(meta, configuration_complete=True, identity_scope_verified=True,
                            visibility_limitations=[]), summary)
    assert forged['configuration_complete'] is False and forged['identity_scope_verified'] is False
    assert {'account-rights-not-verified', 'formats-not-verified'} <= set(forged['visibility_limitations'])


def test_real_consumer_summary_feeds_assess():
    # SYNTHETIC IOS XE style running-config through the unchanged IOS consumer.
    redactor = StreamRedactor((), 'all')
    try:
        redactor.feed(b'version 17.18\nhostname r1\n!\nbanner motd ^C hi ^C\nend\n')
        redactor.finish()
        summary = redactor.summary()
    finally:
        redactor.close()
    out = ad.assess(ad.metadata(), summary)
    assert out['configuration_complete'] is False
    assert out['visibility_limitations'].count('formats-not-verified') == 1
    assert out['unverified_count'] == summary['unverified_count']
