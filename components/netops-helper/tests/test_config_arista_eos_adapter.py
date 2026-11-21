"""Tasks 143/153: Arista EOS identity/profile adapter (single profile cEOSLab 4.36.1F).

Identity: ``show version`` is the immutable REAL capture
``fixtures/real/arista_eos/ceos_4.36.1F/version.txt``; every other identity text is DERIVED by editing it
(or, for the foreign-vendor case, the REAL ``fixtures/real/cisco_xe/iolxe_17.18.2/version.txt``).
The running-config fed to the consumer below is SYNTHETIC.  Task 153: the redaction profile is the
indentation-based ``config_indented.EosStreamRedactor`` (no longer the IOS line consumer).
"""

import copy
import hashlib
import json
import pathlib

import pytest

from netops_helper import config_arista_eos_adapter as ad
from netops_helper import config_cisco_ios_adapter as ios_ad
from netops_helper import config_cisco_xe_adapter as xe_ad
from netops_helper import config_cisco_ios
from netops_helper.config_indented import EOS_MARKER, EosStreamRedactor

FIXTURES = pathlib.Path(__file__).parent / 'fixtures' / 'real'
CEOS = (FIXTURES / 'arista_eos' / 'ceos_4.36.1F' / 'version.txt').read_text()
IOLXE = (FIXTURES / 'cisco_xe' / 'iolxe_17.18.2' / 'version.txt').read_text()
BAD = 'configuration identity could not be verified'
MODEL = 'Arista cEOSLab'
IMAGE = 'Software image version: 4.36.1F-48405728.4361F (engineering build)'
BUILD = '4.36.1F-48405728.4361F (engineering build)'
FIRMWARE = ('cEOSLab', '4.36.1F', BUILD)


def test_fixture_shape_is_what_the_adapter_reads():
    lines = CEOS.splitlines()
    assert lines.count(MODEL) == 1 and lines.count(IMAGE) == 1
    assert sum(line.startswith('Arista') for line in lines) == 1
    assert sum(line.startswith('Software image version') for line in lines) == 1


def test_real_ceos_tested_and_build_kept():
    firmware, meta = ad.verify_identity(CEOS)
    assert firmware == FIRMWARE and firmware[:2] == ad.TESTED
    assert ad.firmware_record(firmware)
    assert ad.firmware_support(firmware) == {
        'status': 'tested', 'platform': 'Arista EOS', 'device_version': '4.36.1F', 'model': 'cEOSLab',
        'tested_versions': ['cEOSLab 4.36.1F'], 'message': None}
    assert meta['config_scope'] == 'device-account-visible'
    assert meta['configuration_complete'] is False and meta['identity_scope_verified'] is False
    assert meta['visibility_limitations'] == ['account-rights-not-verified', 'formats-not-verified']
    assert ad.version_identity(CEOS) == FIRMWARE


@pytest.mark.parametrize('image, build', [
    ('4.36.1F', '4.36.1F'),
    ('4.36.1F-48405728.4361F', '4.36.1F-48405728.4361F'),
    ('4.36.1F (engineering build)', '4.36.1F (engineering build)'),
], ids=['plain', 'suffix-only', 'note-only'])
def test_same_release_with_other_build_text_is_tested_and_recorded(image, build):
    text = CEOS.replace(IMAGE, 'Software image version: ' + image)
    firmware = ad.verify_identity(text)[0]
    assert firmware == ('cEOSLab', '4.36.1F', build) and ad.firmware_record(firmware)
    assert ad.firmware_support(firmware)['status'] == 'tested'


def test_crlf_and_prompt_lines():
    assert ad.verify_identity(CEOS.replace('\n', '\r\n'))[0] == FIRMWARE
    assert ad.verify_identity('ceos1#show version\r\n' + CEOS + '\r\nceos1#')[0] == FIRMWARE


@pytest.mark.parametrize('old,new,model,release', [
    (MODEL, 'Arista vEOS-lab', 'vEOS-lab', '4.36.1F'),                                       # other model
    (MODEL, 'Arista DCS-7050TX-64-R', 'DCS-7050TX-64-R', '4.36.1F'),                        # hardware model
    (IMAGE, IMAGE.replace('4.36.1F-', '4.36.0F-'), 'cEOSLab', '4.36.0F'),                   # other release
    (IMAGE, IMAGE.replace('4.36.1F-', '4.35.1F-'), 'cEOSLab', '4.35.1F'),                   # other train
    (IMAGE, IMAGE.replace('4.36.1F-', '4.36.1M-'), 'cEOSLab', '4.36.1M'),                   # other release type
    (IMAGE, IMAGE.replace('4.36.1F-', '4.36.1.1F-'), 'cEOSLab', '4.36.1.1F'),               # four-part release
], ids=['model-veos', 'model-hw', 'release', 'train', 'release-type', 'four-part'])
def test_derived_foreign_wellformed_is_untested(old, new, model, release):
    """G00: another model or release is read; firmware_support says untested."""
    assert old in CEOS
    firmware, meta = ad.verify_identity(CEOS.replace(old, new))
    assert firmware[:2] == (model, release) and meta == ad.metadata() and ad.firmware_record(firmware)
    support = ad.firmware_support(firmware)
    assert support['status'] == 'untested' and support['model'] == model and support['device_version'] == release
    assert support['message'] == (
        'Arista EOS %s on %s is not among the versions config_read was tested on (cEOSLab 4.36.1F). '
        'It may or may not work as designed and tested; check the result.' % (release, model))


def test_real_foreign_vendor_and_frozen_adapters():
    # The real IOS XE capture has no Arista identity lines: inconclusive, never admitted.
    with pytest.raises(ValueError, match=BAD) as info:
        ad.verify_identity(IOLXE)
    assert type(info.value) is ValueError
    # And the IOS / IOS XE adapters do not admit the EOS capture.
    for other in (ios_ad, xe_ad):
        with pytest.raises(ValueError):
            other.verify_identity(CEOS)


@pytest.mark.parametrize('make', [
    lambda t: t.replace(MODEL + '\n', ''),                                          # missing model line
    lambda t: t.replace(IMAGE + '\n', ''),                                          # missing image line
    lambda t: t + MODEL + '\n',                                                     # model repeated
    lambda t: t + IMAGE + '\n',                                                     # image line repeated
    lambda t: t + 'Arista vEOS-lab\n',                                              # two different models
    lambda t: t + IMAGE.replace('4.36.1F-', '4.35.1F-') + '\n',                     # two different releases
    lambda t: t.replace(MODEL, 'Arista'),                                           # model missing value
    lambda t: t.replace(MODEL, 'Arista cEOS Lab'),                                  # malformed model
    lambda t: t.replace(IMAGE, 'Software image version: '),                         # empty image version
    lambda t: t.replace(IMAGE, 'Software image version: 4.36'),                     # truncated release
    lambda t: t.replace(IMAGE, 'Software image version 4.36.1F'),                   # no colon
    lambda t: t.replace(IMAGE, IMAGE + ' trailing'),                                # trailing text
    lambda t: t.replace(IMAGE, 'Software image version: 4.36.1F_48405728'),         # bad separator
    lambda t: t.replace(MODEL, 'Arista cEOSLab\x07'),
    lambda t: '',
    lambda t: '   \n',
    lambda t: 'ceos1#',
    lambda t: t + '\x00',
    lambda t: t + ' ',
    lambda t: t + 'x' * 70000,
    lambda t: None,
    lambda t: t.encode(),
], ids=['no-model', 'no-image', 'dup-model', 'dup-image', 'two-models', 'two-releases', 'model-empty',
        'model-malformed', 'image-empty', 'image-truncated', 'image-no-colon', 'image-trailing',
        'image-separator', 'bel', 'empty', 'blank', 'prompt-only', 'nul', 'line-separator', 'oversize',
        'none', 'bytes'])
def test_unverifiable_identity(make):
    with pytest.raises(ValueError, match=BAD) as info:
        ad.verify_identity(make(CEOS))
    assert type(info.value) is ValueError


def test_identity_ignores_image_file_internal_build_serial_and_hostname():
    # The model and release come only from the 'Arista' and 'Software image version' lines.
    text = (CEOS.replace('Internal build version: 4.36.1F-48405728.4361F',
                         'Internal build version: 4.30.0F-1.4300F')
            .replace('Serial number: S000S0000SS0SSS0SSS0S0S000S00S04', 'Serial number: vEOS-4.30.0F')
            .replace('Hardware version: ', 'Hardware version: DCS-7050TX'))
    text = 'Image file: flash:/vEOS-lab-4.30.0F.swi\nHostname: veos-4-30\n' + text
    assert text != CEOS
    assert ad.version_identity(text) == FIRMWARE


def test_firmware_record_only_for_the_record_shape():
    # G00: any consistent record is a record (tested or not); the release must be the image's release.
    for firmware in (FIRMWARE, ('vEOS-lab', '4.36.1F', '4.36.1F'), ('cEOSLab', '4.35.1F', '4.35.1F')):
        assert ad.firmware_record(firmware), firmware
    for firmware in (ad.TESTED, ('cEOSLab', '4.36.1F', ''), ('cEOSLab', '4.36.1F', '4.35.1F'),
                     ('cEOSLab', '4.36.1F', '4.36.1F trailing'), ('', '4.36.1F', '4.36.1F'),
                     ('c EOS', '4.36.1F', '4.36.1F'), list(FIRMWARE), ('cEOSLab', '4.36.1F', None),
                     FIRMWARE + ('x',), xe_ad.TESTED, None):
        assert not ad.firmware_record(firmware), firmware


def test_read_command():
    assert ad.read_command('all', True, False) == 'show running-config'
    assert ad.read_command('all', True, False, 'full', 'running') == 'show running-config'
    for args in [('all', False, False), ('all', True, True), ('all', True, False, 'none'),
                 ('all', True, False, 'minimal'), ('interfaces', True, False),
                 ('all', True, False, 'full', 'startup'), (None, True, False), ('all', 1, False),
                 ('all', True, 0), ('ALL', True, False)]:
        with pytest.raises(ValueError, match='config_platform_not_supported: arista_eos'):
            ad.read_command(*args)


def test_constants_and_profile_fingerprint():
    assert ad.PLATFORM == 'arista_eos' and ad.COMMAND == 'show running-config'
    assert ad.IDENTITY_COMMANDS == ('show version',) and ad.IDENTITY_MAX_BYTES == 65536
    assert ad.TESTED == ('cEOSLab', '4.36.1F') and ad.TESTED_NAME == 'Arista EOS'
    assert not hasattr(ad, 'IMAGE_FAMILY')
    assert ad.VISIBILITY == ('account-rights-not-verified', 'formats-not-verified')
    desc = ('arista_eos', 'config_indented.EosStreamRedactor', 'eos-indent-allowlist-2', EOS_MARKER,
            'show running-config', ('show version',), ('cEOSLab', '4.36.1F'))
    assert ad.POLICY_DESCRIPTOR == desc
    digest = hashlib.sha256(json.dumps(desc, separators=(',', ':')).encode('ascii')).hexdigest()
    assert ad.PROFILE == 'arista_eos-full-1:' + digest
    assert ad.PROFILE not in (ios_ad.PROFILE, xe_ad.PROFILE)
    # The task 143 profile (IOS line consumer) is not this profile.
    old = ('arista_eos', 'config_cisco_ios.StreamRedactor', 'ios-lines-menu-reject-1', config_cisco_ios.MARKER,
           'show running-config', ('show version',), ('cEOSLab', '4.36.1F'))
    assert ad.PROFILE != 'arista_eos-full-1:' + hashlib.sha256(
        json.dumps(old, separators=(',', ':')).encode('ascii')).hexdigest()


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
    # SYNTHETIC EOS style running-config through the EOS indentation consumer of the profile.
    redactor = EosStreamRedactor((), 'all')
    try:
        redactor.feed(b'! Command: show running-config\n!\nhostname ceos1\n!\ninterface Ethernet1\n'
                      b'   description uplink\n   ip ospf authentication-key 7 0207165218120E\n!\nend\n')
        content = redactor.finish()[0]
        text = content.page(0, content.total)[0]
        summary = redactor.summary()
    finally:
        redactor.close()
    out = ad.assess(ad.metadata(), summary)
    assert out['configuration_complete'] is False
    assert out['visibility_limitations'] == ['account-rights-not-verified', 'formats-not-verified',
                                             'schema-fields-unverified']
    assert out['unverified_count'] == summary['unverified_count'] == 2
    assert text == (EOS_MARKER + '\n!\nhostname ceos1\n!\ninterface Ethernet1\n   description uplink\n' +
                    EOS_MARKER + '\n!\nend\n')
