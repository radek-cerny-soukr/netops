"""Task 153: Cisco NX-OS identity/profile adapter (single profile Nexus9000 C9300v, NX-OS 9.3(12)).

Identity: ``show version`` is the immutable REAL capture
``fixtures/real/cisco_nxos/nexus9300v_9.3.12/version.txt``; every other identity text is DERIVED by
editing it (or, for the foreign-vendor cases, the REAL ``fixtures/real/cisco_xe/iolxe_17.18.2/version.txt``
and ``fixtures/real/arista_eos/ceos_4.36.1F/version.txt``).  The running-config fed to the consumer
below is SYNTHETIC.
"""

import copy
import hashlib
import json
import pathlib

import pytest

from netops_helper import config_arista_eos_adapter as eos_ad
from netops_helper import config_cisco_ios_adapter as ios_ad
from netops_helper import config_cisco_nxos_adapter as ad
from netops_helper import config_cisco_xe_adapter as xe_ad
from netops_helper.config_indented import NXOS_MARKER, NxosStreamRedactor

FIXTURES = pathlib.Path(__file__).parent / 'fixtures' / 'real'
NXOS = (FIXTURES / 'cisco_nxos' / 'nexus9300v_9.3.12' / 'version.txt').read_text()
IOLXE = (FIXTURES / 'cisco_xe' / 'iolxe_17.18.2' / 'version.txt').read_text()
CEOS = (FIXTURES / 'arista_eos' / 'ceos_4.36.1F' / 'version.txt').read_text()
BAD = 'configuration identity could not be verified'
HEADER = 'Cisco Nexus Operating System (NX-OS) Software'
RELEASE = ' NXOS: version 9.3(12)'
CHASSIS = '  cisco Nexus9000 C9300v Chassis '
FIRMWARE = ('Nexus9000 C9300v', '9.3(12)')


def test_fixture_shape_is_what_the_adapter_reads():
    lines = NXOS.splitlines()
    assert lines.count(HEADER) == 1 and lines.count(RELEASE) == 1 and lines.count(CHASSIS) == 1
    assert sum(line.strip().startswith('Cisco Nexus Operating System') for line in lines) == 1
    assert sum(line.strip().startswith('NXOS: version') for line in lines) == 1
    assert sum(line.strip().startswith('cisco ') and 'hassis' in line for line in lines) == 1


def test_real_nxos_admitted():
    firmware, meta = ad.verify_identity(NXOS)
    assert firmware == FIRMWARE == ad.SUPPORTED
    assert meta['config_scope'] == 'device-account-visible'
    assert meta['configuration_complete'] is False and meta['identity_scope_verified'] is False
    assert meta['visibility_limitations'] == ['account-rights-not-verified', 'formats-not-verified']
    assert ad.version_identity(NXOS) == FIRMWARE


def test_crlf_and_prompt_lines():
    assert ad.verify_identity(NXOS.replace('\n', '\r\n'))[0] == FIRMWARE
    assert ad.verify_identity('host01# show version\r\n' + NXOS + '\r\nhost01# ')[0] == FIRMWARE


@pytest.mark.parametrize('old,new', [
    (CHASSIS, '  cisco Nexus9000 C9500v Chassis'),                                  # other virtual model
    (CHASSIS, '  cisco Nexus9000 C93180YC-EX chassis'),                             # hardware model
    (RELEASE, ' NXOS: version 9.3(11)'),                                            # other maintenance
    (RELEASE, ' NXOS: version 10.3(4a)'),                                           # other train
    (RELEASE, ' NXOS: version 7.0(3)I7(9)'),                                        # old train
], ids=['model-c9500v', 'model-hw', 'release', 'train', 'old-train'])
def test_derived_foreign_wellformed_refused(old, new):
    assert old in NXOS
    with pytest.raises(ad.UnsupportedNxosFirmware, match='configuration firmware-not-supported'):
        ad.verify_identity(NXOS.replace(old, new))


def test_real_foreign_vendors_and_other_adapters():
    # The real IOS XE and EOS captures have no NX-OS identity lines: inconclusive, never admitted.
    for text in (IOLXE, CEOS):
        with pytest.raises(ValueError, match=BAD) as info:
            ad.verify_identity(text)
        assert not isinstance(info.value, ad.UnsupportedNxosFirmware)
    # And the IOS / IOS XE / EOS adapters do not admit the NX-OS capture.
    for other in (ios_ad, xe_ad, eos_ad):
        with pytest.raises(ValueError):
            other.verify_identity(NXOS)


@pytest.mark.parametrize('make', [
    lambda t: t.replace(HEADER + '\n', ''),                                          # missing header
    lambda t: t.replace(RELEASE + '\n', ''),                                         # missing release line
    lambda t: t.replace(CHASSIS + '\n', ''),                                         # missing hardware line
    lambda t: t + HEADER + '\n',                                                     # header repeated
    lambda t: t + RELEASE + '\n',                                                    # release repeated
    lambda t: t + CHASSIS + '\n',                                                    # hardware repeated
    lambda t: t + ' NXOS: version 9.3(11)\n',                                        # two different releases
    lambda t: t + '  cisco Nexus9000 C9500v Chassis\n',                              # two different models
    lambda t: t.replace(HEADER, 'Cisco Nexus Operating System (NX-OS) Software x'),  # malformed header
    lambda t: t.replace(RELEASE, ' NXOS: version '),                                 # empty release
    lambda t: t.replace(RELEASE, ' NXOS: version 9.3'),                              # truncated release
    lambda t: t.replace(RELEASE, ' NXOS: version 9.3(12) trailing'),                 # trailing text
    lambda t: t.replace(RELEASE, ' NXOS: version 9.3[12]'),                          # bad brackets
    lambda t: t.replace(CHASSIS, '  cisco Chassis'),                                 # model missing
    lambda t: t.replace(CHASSIS, '  cisco Nexus9000 C9300v Chassis trailing'),       # trailing text
    lambda t: t.replace(CHASSIS, '  cisco Catalyst 9300 Chassis'),                   # not a Nexus line
    lambda t: t.replace(HEADER, HEADER + '\x07'),
    lambda t: '',
    lambda t: '   \n',
    lambda t: 'host01#',
    lambda t: t + '\x00',
    lambda t: t + ' ',
    lambda t: t + 'x' * 70000,
    lambda t: None,
    lambda t: t.encode(),
], ids=['no-header', 'no-release', 'no-hardware', 'dup-header', 'dup-release', 'dup-hardware', 'two-releases',
        'two-models', 'header-malformed', 'release-empty', 'release-truncated', 'release-trailing',
        'release-brackets', 'hardware-no-model', 'hardware-trailing', 'hardware-not-nexus', 'bel', 'empty',
        'blank', 'prompt-only', 'nul', 'line-separator', 'oversize', 'none', 'bytes'])
def test_unverifiable_identity(make):
    with pytest.raises(ValueError, match=BAD) as info:
        ad.verify_identity(make(NXOS))
    assert not isinstance(info.value, ad.UnsupportedNxosFirmware)


def test_identity_ignores_image_file_packages_serial_and_hostname():
    # The model and release come only from the header, 'NXOS: version' and 'cisco ... Chassis' lines.
    text = (NXOS.replace('bootflash:///nxos.9.3.12.bin', 'bootflash:///nxos.10.3.4a.M.bin')
            .replace('Processor Board ID 0SSSSS0001S', 'Processor Board ID N9K-C93180YC-EX')
            .replace('Device name: host01', 'Device name: n9k-10-3-4a')
            .replace('nexus9300v_9.3.12_pty', 'nexus9500v_10.3.4a_pty')
            .replace('Nexus 9000v is a demo version', 'Nexus 9500v 10.3(4a) is a demo version'))
    assert text != NXOS
    assert ad.version_identity(text) == FIRMWARE


def test_read_command():
    assert ad.read_command('all', True, False) == 'show running-config'
    assert ad.read_command('all', True, False, 'full', 'running') == 'show running-config'
    for args in [('all', False, False), ('all', True, True), ('all', True, False, 'none'),
                 ('all', True, False, 'minimal'), ('interfaces', True, False),
                 ('all', True, False, 'full', 'startup'), (None, True, False), ('all', 1, False),
                 ('all', True, 0), ('ALL', True, False)]:
        with pytest.raises(ValueError, match='config_platform_not_supported: cisco_nxos'):
            ad.read_command(*args)


def test_constants_and_profile_fingerprint():
    assert ad.PLATFORM == 'cisco_nxos' and ad.COMMAND == 'show running-config'
    assert ad.IDENTITY_COMMANDS == ('show version',) and ad.IDENTITY_MAX_BYTES == 65536
    assert ad.SUPPORTED == ('Nexus9000 C9300v', '9.3(12)')
    assert not hasattr(ad, 'IMAGE_FAMILY') and not hasattr(ad, 'firmware_admitted')
    assert ad.VISIBILITY == ('account-rights-not-verified', 'formats-not-verified')
    desc = ('cisco_nxos', 'config_indented.NxosStreamRedactor', 'nxos-indent-allowlist-1', NXOS_MARKER,
            'show running-config', ('show version',), ('Nexus9000 C9300v', '9.3(12)'))
    assert ad.POLICY_DESCRIPTOR == desc
    digest = hashlib.sha256(json.dumps(desc, separators=(',', ':')).encode('ascii')).hexdigest()
    assert ad.PROFILE == 'cisco_nxos-full-1:' + digest
    assert ad.PROFILE not in (ios_ad.PROFILE, xe_ad.PROFILE, eos_ad.PROFILE)


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
    # SYNTHETIC NX-OS style running-config through the NX-OS indentation consumer of the profile.
    redactor = NxosStreamRedactor((), 'all')
    try:
        redactor.feed(b'!Command: show running-config\n!Time: Sat Nov 14 10:05:31 2026\n\nhostname host01\n'
                      b'interface Ethernet1/1\n  description uplink\n  ip ospf authentication-key 3 0x0FAKE\n')
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
    assert text == ('!Command: show running-config\n' + NXOS_MARKER + '\n\nhostname host01\n'
                    'interface Ethernet1/1\n  description uplink\n' + NXOS_MARKER + '\n')
