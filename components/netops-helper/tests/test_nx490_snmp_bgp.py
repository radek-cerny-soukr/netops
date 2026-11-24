"""verification (1.0.12 NX-OS): fail-closed SNMP community block and wrapped IPv6 BGP neighbors.

Only the SSH transport is replaced; the outputs are nexus9300v (NX-OS 9.3(12)) captures or declared derivations
of them, see fixtures/real/cisco_nxos/nx490_9.3.12/PROVENANCE.md.
"""
from dataclasses import replace
import json
from pathlib import Path
import re

import pytest

from conftest import EXEC_CLIENT, _target, _write_client, wire as ssh_wire
from netops_helper import engine, sanitize, tables
from netops_helper.sanitize import redact_response

FIX = Path(__file__).parent / 'fixtures/real/cisco_nxos/nx490_9.3.12'
VERSION = Path(__file__).parent / 'fixtures/real/cisco_nxos/nxos_routing_9.3.12/raw/version.out'
PROFILE = 'cisco_nxos'
INVENTORY = {'vrfs': ('default', 'management')}
WARNING = 'snmp_community_table_unrecognized'


def redact_nxos_snmp_communities(text):
    # Looked up per test so that the old code fails test by test (RED), not at collection.
    return sanitize.redact_nxos_snmp_communities(text)


def note():
    return sanitize.NXOS_SNMP_COMMUNITY_NOTE


def fixture(name):
    return (FIX / name).read_text()


@pytest.fixture
def wire(monkeypatch):
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    calls = []

    def install(query, command, output, rc=0):
        auth = replace(_target(PROFILE, query), read_inventory=INVENTORY)

        def read(target, profile, actual):
            calls.append(actual)
            if actual == 'show version':
                return 0, VERSION.read_text()
            assert actual == command
            return rc, output
        monkeypatch.setattr(engine, 'read_from_device', read)
        return auth, calls
    return install


def read_all_pages(auth, max_bytes=16000):
    pages, offset, sha = [], 0, None
    while True:
        result = engine.ssh_read(auth, PROFILE, 'snmp_statistics', {}, offset, max_bytes, sha)
        pages.append(result)
        if not result.get('ok') or result['next_offset'] is None:
            return pages
        offset, sha = result['next_offset'], result['content_sha256']


# --- (a) SNMP community block ------------------------------------------------------------------------------

@pytest.mark.parametrize('path', ['raw/snmp_statistics_admin.out', 'raw/snmp_statistics_ro.out',
                                  'derived/snmp_statistics_known_canary.out'])
def test_known_show_snmp_shapes_keep_the_previous_behaviour(wire, path):
    body = fixture(path)
    auth, calls = wire('snmp_statistics', 'show snmp', body)
    result = engine.ssh_read(auth, PROFILE, 'snmp_statistics', {}, 0, 16000)
    assert result['ok'], result
    assert 'SNMP packets input' in result['untrusted_device_output']
    assert 'SNMP protocol : Enabled' in result['untrusted_device_output']
    assert '[redacted]' in result['untrusted_device_output']
    assert note() not in result['untrusted_device_output']
    assert WARNING not in result['normalized']['warnings']
    assert 'nx490' not in json.dumps(result) and 'canary' not in json.dumps(result)
    assert calls == ['show version', 'show snmp']
    assert redact_nxos_snmp_communities(body) == (body, False)


def test_unknown_community_table_never_reaches_any_page_and_is_marked(wire):
    body = fixture('derived/snmp_statistics_unknown_header.out')
    auth, calls = wire('snmp_statistics', 'show snmp', body)
    for max_bytes in (16000, 1024):
        pages = read_all_pages(auth, max_bytes)
        text = ''.join(page['untrusted_device_output'] for page in pages)
        for page in pages:
            assert page['ok'], page
            dumped = json.dumps(page)
            assert 'nx490' not in dumped and 'canary' not in dumped
            assert WARNING in page['normalized']['warnings']
        assert '[redacted]' in text
        # Counters and agent state stay readable after all credential-bearing sections are masked.
        assert 'SNMP packets input' in text and 'SNMP protocol : Enabled' in text
        assert 'Max packetsize: 1500' in text
    assert calls[:2] == ['show version', 'show snmp']


def test_unknown_table_is_masked_line_by_line_inside_its_block():
    body = fixture('derived/snmp_statistics_unknown_header.out')
    masked, changed = redact_nxos_snmp_communities(body)
    assert changed
    lines = masked.split('\n')
    start = lines.index(note())
    assert lines[start - 1].startswith('Max packetsize:')
    end = next(i for i in range(start, len(lines)) if len(lines[i].strip()) >= 20 and set(lines[i].strip()) == {'_'})
    block = lines[start + 1:end]
    assert [line for line in block if line.strip()] == ['<REDACTED>'] * 4
    assert masked.split('\n')[:start] == body.split('\n')[:start]


@pytest.mark.parametrize('path,changed', [('raw/snmp_community.out', False), ('derived/snmp_community_known_canary.out', False),
                                          ('derived/snmp_community_unknown_header.out', True)])
def test_show_snmp_community_alone_is_the_whole_block(path, changed):
    body = fixture(path)
    masked, flagged = redact_nxos_snmp_communities(body)
    assert flagged is changed
    cleaned = redact_response(masked)
    assert 'nx490' not in cleaned and 'canary' not in cleaned
    if not changed:
        assert masked == body


def test_public_engine_refuses_unsanitized_standalone_community_query(wire):
    auth, calls = wire('snmp_community', 'show snmp community',
                       fixture('derived/snmp_community_unknown_header.out'))
    with pytest.raises(ValueError, match='query'):
        engine.ssh_read(auth, PROFILE, 'snmp_community', {}, 0, 16000)
    assert calls == []


@pytest.mark.parametrize('mutate', [
    # rows after the blank line that ends the known table
    lambda body: body.replace('_______    __________                 \n', '_______    __________                 \n\nnx490-late network-operator\n'),
    # a community table printed before the "Max packetsize" block
    lambda body: 'Community  Access\nnx490-early ro\n\n' + body,
    # no closing rule: the block runs to the end
    lambda body: re.sub(r'(?m)^_{20,}$', 'nx490-tail', body),
    # Windows line ends with an unknown header
    lambda body: body.replace('Group / Access', 'Access / Group').replace(
        '_______    __________                 \n', '_______    __________                 \nnx490-crlf ro\n').replace('\n', '\r\n'),
])
def test_other_unknown_shapes_fail_closed(mutate):
    body = mutate(fixture('raw/snmp_statistics_admin.out'))
    masked, flagged = redact_nxos_snmp_communities(body)
    assert flagged
    assert 'nx490' not in redact_response(masked)


def test_json_wrapped_capture_is_one_unknown_block(wire):
    body = fixture('derived/snmp_statistics_unknown_header.out')
    auth, _ = wire('snmp_statistics', 'show snmp', json.dumps({'output': body}))
    result = engine.ssh_read(auth, PROFILE, 'snmp_statistics', {}, 0, 16000)
    assert 'nx490' not in json.dumps(result)


# --- (b) wrapped IPv6 BGP neighbors ------------------------------------------------------------------------

IDLE = {'neighbor': '2001:db8:1::10', 'remote_as': '65046', 'state': 'Idle', 'prefixes': None, 'vrf': 'default'}


@pytest.mark.parametrize('kwargs,query,command,path', [
    ({}, 'bgp_ipv6_summary', 'show bgp ipv6 unicast summary', 'raw/bgp_ipv6_summary.out'),
    ({'vrf': 'default'}, 'bgp_ipv6_summary_vrf', 'show bgp ipv6 unicast summary vrf default', 'raw/bgp_ipv6_summary_vrf.out'),
])
def test_real_wrapped_ipv6_neighbor_is_a_record(wire, kwargs, query, command, path):
    auth, calls = wire(query, command, fixture(path))
    result = engine.switch_read(auth, 'bgp_peer', address_family='ipv6', **kwargs)
    assert result['ok'], result
    assert result['records'] == [IDLE]
    assert result['unparsed'] == []
    assert result['coverage']['complete']
    assert calls == ['show version', command]


def test_long_documentation_address_as_printed_by_the_device():
    result = tables.parse(PROFILE, 'bgp_peer', 'bgp_ipv6_summary', fixture('derived/bgp_ipv6_summary_long_address.out'))
    assert result['ok'] and not result['unparsed']
    assert [(r['neighbor'], r['remote_as'], r['state']) for r in result['records']] == [('2001:db8:4590::1234:5678', '65046', 'Idle')]


def test_several_wrapped_and_single_line_neighbors_keep_their_values():
    result = tables.parse(PROFILE, 'bgp_peer', 'bgp_ipv6_summary', fixture('derived/bgp_ipv6_summary_multi.out'))
    assert result['ok'] and not result['unparsed'], result
    assert [(r['neighbor'], r['remote_as'], r['state'], r['prefixes']) for r in result['records']] == [
        ('2001:db8:1::10', '65046', 'Idle', None),
        ('2001:db8:1::11', '65047', 'Established', 3),
        ('192.0.2.9', '65048', 'Active', None),
    ]


@pytest.mark.parametrize('mutate,line', [
    # address without its counter line
    (lambda body: body.replace('                4 65046       0       0        0    0    0 00:00:07 Idle     \n', ''), 9),
    # counter line without an address
    (lambda body: body.replace('2001:db8:1::10\n', ''), 9),
    # a non-adjacent continuation (blank line between) is not joined
    (lambda body: body.replace('2001:db8:1::10\n', '2001:db8:1::10\n\n'), 9),
    # an unknown state on the joined row
    (lambda body: body.replace('Idle     \n', 'Wobbly   \n'), 9),
])
def test_broken_or_unknown_wrapped_rows_stay_unparsed(mutate, line):
    result = tables.parse(PROFILE, 'bgp_peer', 'bgp_ipv6_summary', mutate(fixture('raw/bgp_ipv6_summary.out')))
    assert not result['ok']
    assert result['records'] == []
    assert result['unparsed'] and result['unparsed'][0]['line'] == line


def test_unparsed_line_numbers_are_those_of_the_capture():
    body = fixture('derived/bgp_ipv6_summary_multi.out').replace('Active   \n', 'Wobbly   \n')
    result = tables.parse(PROFILE, 'bgp_peer', 'bgp_ipv6_summary', body)
    assert [row['line'] for row in result['unparsed']] == [13]
    assert [r['neighbor'] for r in result['records']] == ['2001:db8:1::10', '2001:db8:1::11']


def test_vendor_glued_html_sample_is_still_not_guessed():
    body = (Path(__file__).parent / 'fixtures/real/cisco_nxos/nxos_routing_9.3.12/vendor/bgp_ipv6_summary.out').read_text()
    result = tables.parse(PROFILE, 'bgp_peer', 'bgp_ipv6_summary', body)
    assert not result['ok'] and result['unparsed']


@pytest.mark.parametrize('body,status', [
    ('% Permission denied for the role\n\nCmd exec error.\n', 'permission_denied'),
    ("Syntax error while parsing 'show snmp'\n\nCmd exec error.\n", 'unsupported'),
])
def test_refusal_of_show_snmp_is_still_a_refusal(wire, body, status):
    assert redact_nxos_snmp_communities(body) == (body, False)
    auth, _ = wire('snmp_statistics', 'show snmp', body, rc=16)
    result = engine.ssh_read(auth, PROFILE, 'snmp_statistics', {}, 0, 16000)
    assert not result['ok'] and result['status'] == status, result


def test_pager_stop_inside_an_unknown_block_is_still_truncated(wire):
    body = fixture('derived/snmp_statistics_unknown_header.out')
    body = body[:body.index('"nx490 second canary"')] + '--More--\n'
    auth, _ = wire('snmp_statistics', 'show snmp', body)
    result = engine.ssh_read(auth, PROFILE, 'snmp_statistics', {}, 0, 16000)
    assert result['status'] == 'truncated'
    assert 'nx490' not in json.dumps(result) and result['untrusted_device_output'].rstrip().endswith('--More--')


@pytest.mark.parametrize('refused', [False, True], ids=['success', 'refusal'])
def test_solid_table_underline_does_not_end_the_community_block(ssh_wire, refused):
    body = fixture('derived/snmp_statistics_unknown_header.out')
    body = re.sub(r'(?m)^-{14}[^\n]*$', '_' * 62, body, count=1)
    if refused:
        body += '\n% Permission denied for the role\n'
    _write_client(ssh_wire['binaries'], 'ssh', EXEC_CLIENT.format(log=str(ssh_wire['log']), output=body, code=0))
    auth = _target(PROFILE, 'snmp_statistics')

    result = engine.ssh_read(auth, PROFILE, 'snmp_statistics', {}, 0, 16000)

    assert result['ok'] is not refused
    if refused:
        assert result['error_code'] == 'device_cli_error'
    else:
        assert WARNING in result['normalized']['warnings']
    output = result['untrusted_device_output']
    assert 'SNMP packets input' in output
    leaked = 'nx490' in json.dumps(result)
    assert not leaked


@pytest.mark.parametrize('shape', ['unknown_header', 'known_canary'])
def test_pager_appended_to_a_masked_row_is_still_truncated(ssh_wire, shape):
    body = fixture(f'derived/snmp_statistics_{shape}.out')
    lines = body.splitlines()
    first_row = next(i for i, line in enumerate(lines) if 'nx490' in line)
    body = '\n'.join(lines[:first_row + 1]).rstrip() + '--More--'
    _write_client(ssh_wire['binaries'], 'ssh', EXEC_CLIENT.format(log=str(ssh_wire['log']), output=body, code=0))
    auth = _target(PROFILE, 'snmp_statistics')

    result = engine.ssh_read(auth, PROFILE, 'snmp_statistics', {}, 0, 16000)

    assert result['status'] == 'truncated'
    assert result['untrusted_device_output'].rstrip().endswith('[redacted]--More--')
    leaked = 'nx490' in json.dumps(result)
    assert not leaked


# --- (c) labelled community shape of a configured community (verification) -----------------------------------
# raw/*_populated.out are the live nexus9300v captures of verification with the canary `nx490-populated-canary1`.

POPULATED_CANARY = 'nx490-populated-canary1'
LABELLED = ['Community name: <REDACTED>', 'Community groupname: network-operator', 'Context mapped: ']


def _ssh_read_through_client(ssh_wire, body):
    _write_client(ssh_wire['binaries'], 'ssh', EXEC_CLIENT.format(log=str(ssh_wire['log']), output=body, code=0))
    return engine.ssh_read(_target(PROFILE, 'snmp_statistics'), PROFILE, 'snmp_statistics', {}, 0, 16000)


def test_real_populated_show_snmp_is_read_like_the_known_table(ssh_wire):
    body = fixture('raw/snmp_statistics_populated.out')
    assert POPULATED_CANARY in body

    result = _ssh_read_through_client(ssh_wire, body)
    known = _ssh_read_through_client(ssh_wire, fixture('raw/snmp_statistics_admin.out'))

    assert result['ok'], result
    assert WARNING not in result['normalized']['warnings']
    output = result['untrusted_device_output']
    assert note() not in output
    assert 'nx490' not in json.dumps(result) and 'canary' not in json.dumps(result)
    assert 'Community groupname' not in output
    assert 'SNMP packets input' in output and 'SNMP protocol : Enabled' in output
    # The same state as the known (empty) table on the same path: no fail-closed marking, no truncation.
    assert result['status'] == known['status'] and result['normalized']['warnings'] == known['normalized']['warnings']


def test_snmp_community_counter_labels_remain_readable(ssh_wire):
    result = _ssh_read_through_client(ssh_wire, fixture('raw/snmp_statistics_populated.out'))
    assert result['ok'] and result['complete']
    lines = result['untrusted_device_output'].splitlines()
    assert '0 Unknown community-name' in lines
    assert '0 Illegal operation for community-name supplied' in lines
    assert POPULATED_CANARY not in json.dumps(result)


@pytest.mark.parametrize('collision', ['own_group', 'other_triple', 'context', 'outside_block'])
def test_populated_community_names_are_redacted_throughout_response(ssh_wire, collision):
    body = fixture('raw/snmp_statistics_populated.out')
    other = 'nx490-other-canary'
    if collision == 'own_group':
        body = body.replace('Community groupname: network-operator', f'Community groupname: {POPULATED_CANARY}')
    elif collision == 'other_triple':
        body = body.replace('Community groupname: network-operator', f'Community groupname: {other}')
        body = body.replace('Context mapped: \n', 'Context mapped: \n'
                            f'Community name: {other}\nCommunity groupname: {POPULATED_CANARY}\nContext mapped: \n')
    elif collision == 'context':
        body = body.replace('Context mapped: \n', f'Context mapped: {POPULATED_CANARY}\n')
    else:
        body = body.replace('sys contact: \n', f'sys contact: {POPULATED_CANARY}\n')
        body = body.replace('sys location: \n', 'sys location: test lab\n')
        body = body.replace('user01', POPULATED_CANARY, 1)
    assert body.count(POPULATED_CANARY) >= 2

    result = _ssh_read_through_client(ssh_wire, body)

    assert result['ok']
    assert WARNING not in result['normalized']['warnings']
    output = result['untrusted_device_output']
    assert note() not in output and 'SNMP packets input' in output
    serialized = json.dumps(result)
    assert all(canary not in serialized for canary in (POPULATED_CANARY, other))
    assert 'Community groupname' not in output and 'sys contact:' not in output



@pytest.mark.parametrize('path', ['raw/snmp_statistics_populated.out', 'raw/snmp_community_populated.out'])
@pytest.mark.parametrize('newline', ['\n', '\r\n'], ids=['lf', 'crlf'])
def test_labelled_block_masks_only_the_community_name(path, newline):
    body = fixture(path).replace('\n', newline)
    masked, flagged = redact_nxos_snmp_communities(body)
    assert not flagged
    assert POPULATED_CANARY not in masked
    assert [line.rstrip('\r') for line in masked.split('\n') if line.startswith(('Community ', 'Context mapped'))] == LABELLED
    # Every other line is the capture itself.
    assert masked == body.replace(POPULATED_CANARY, '<REDACTED>')
    assert 'nx490' not in redact_response(masked)


def test_several_labelled_communities_are_all_masked():
    triple = 'Community name: {}\nCommunity groupname: network-operator\nContext mapped: \n'
    body = fixture('raw/snmp_statistics_populated.out').replace(
        triple.format(POPULATED_CANARY), triple.format('nx490 one') + triple.format('nx490-two') + '\n'
        + triple.format('nx490-three').replace('network-operator', 'network-admin'))
    masked, flagged = redact_nxos_snmp_communities(body)
    assert not flagged and 'nx490' not in masked
    assert masked.count('Community name: <REDACTED>\n') == 3 and 'Community groupname: network-admin' in masked


@pytest.mark.parametrize('mutate', [
    # an extra field in the triple
    lambda body: body.replace('Context mapped: \n', 'Context mapped: \nCommunity acl_filter: nx490-acl\n'),
    # the group line is missing
    lambda body: body.replace('Community groupname: network-operator\n', ''),
    # the lines in another order
    lambda body: body.replace('Community groupname: network-operator\n', '').replace(
        'Context mapped: \n', 'Context mapped: \nCommunity groupname: network-operator\n'),
    # a blank line inside the triple
    lambda body: body.replace('Community groupname:', '\nCommunity groupname:'),
    # a second word after the group
    lambda body: body.replace('network-operator\n', 'network-operator nx490-extra\n', 1),
    # another label case
    lambda body: body.replace('Community name:', 'community Name:'),
    # a table row next to the triple
    lambda body: body.replace('Context mapped: \n', 'Context mapped: \nnx490-row  network-operator\n'),
], ids=['extra-field', 'no-group', 'reordered', 'split', 'group-tail', 'label-case', 'table-row'])
@pytest.mark.parametrize('path', ['raw/snmp_statistics_populated.out', 'raw/snmp_community_populated.out'])
def test_other_labelled_shapes_still_fail_closed(path, mutate):
    body = mutate(fixture(path))
    assert body != fixture(path)
    masked, flagged = redact_nxos_snmp_communities(body)
    assert flagged and note() in masked
    assert 'nx490' not in redact_response(masked)


def test_pager_after_the_real_community_name_is_still_truncated(ssh_wire):
    body = fixture('raw/snmp_statistics_populated.out')
    body = body[:body.index(POPULATED_CANARY) + len(POPULATED_CANARY)] + '--More--'

    result = _ssh_read_through_client(ssh_wire, body)

    assert result['status'] == 'truncated'
    assert result['untrusted_device_output'].rstrip().endswith('[redacted]--More--')
    assert 'nx490' not in json.dumps(result)


# --- (d) community names below the general redaction floor and nested names (verification) -------------------

def _populated_with(name, *, group=None, newline='\n'):
    body = fixture('raw/snmp_statistics_populated.out').replace(POPULATED_CANARY, name)
    if group is not None:
        body = body.replace('Community groupname: network-operator', f'Community groupname: {group}')
    return body.replace('\n', newline) if newline != '\n' else body


@pytest.mark.parametrize('name', ['ro', 'rw', '1'])
@pytest.mark.parametrize('group', [None, 'same'])
def test_short_community_name_is_masked_on_its_line_and_does_not_damage_the_output(ssh_wire, name, group):
    result = _ssh_read_through_client(ssh_wire, _populated_with(name, group=name if group else None))

    assert result['ok'], result
    output = result['untrusted_device_output']
    # Words and numbers that contain the name stay intact: the name is not replaced as a substring.
    for word in ('errors', 'SNMP protocol : Enabled', 'SNMP packets input'):
        assert word in output, word
    assert '[redacted]' in output
    assert 'Community groupname' not in output
    assert WARNING not in result['normalized']['warnings']
    assert note() not in output


def test_short_community_name_in_context_is_withheld(ssh_wire):
    body = fixture('raw/snmp_statistics_populated.out').replace(POPULATED_CANARY, 'ro')
    body = body.replace('Community groupname: network-operator', 'Community groupname: rotor')
    body = body.replace('Context mapped: \n', 'Context mapped: ro\n')

    result = _ssh_read_through_client(ssh_wire, body)

    assert result['ok'], result
    output = result['untrusted_device_output']
    assert 'Context mapped' not in output and 'rotor' not in output
    assert 'SNMP protocol : Enabled' in output


def test_nested_community_names_leave_no_remainder_of_the_longer_one(ssh_wire):
    # Set order is not defined: many pairs make the unsorted order fail with certainty, not by chance.
    pairs = [(f'nx490lab{i}', f'nx490lab{i}-ro') for i in range(24)]
    block = ''.join(f'Community name: {short}\nCommunity groupname: network-operator\nContext mapped: \n'
                    f'Community name: {long}\nCommunity groupname: network-operator\nContext mapped: \n'
                    for short, long in pairs)
    body = fixture('raw/snmp_statistics_populated.out')
    body = body.replace(f'Community name: {POPULATED_CANARY}\nCommunity groupname: network-operator\n'
                        'Context mapped: \n', block)
    body = body.replace('sys contact: \n', 'sys contact: ' + ' '.join(long for _, long in pairs) + '\n')
    assert body.count('-ro') == 48

    result = _ssh_read_through_client(ssh_wire, body)

    assert result['ok'], result
    serialized = json.dumps(result)
    assert 'nx490' not in serialized and '-ro' not in serialized, result['untrusted_device_output'][:400]


def test_multi_word_community_name_is_masked_throughout(ssh_wire):
    body = fixture('raw/snmp_statistics_populated.out').replace(POPULATED_CANARY, 'nx490 two words')
    body = body.replace('sys contact: \n', 'sys contact: nx490 two words\n')

    result = _ssh_read_through_client(ssh_wire, body)

    assert result['ok'], result
    serialized = json.dumps(result)
    assert 'nx490' not in serialized and 'two words' not in serialized
    assert '[redacted]' in result['untrusted_device_output']


@pytest.mark.parametrize('name', ['ro', 'nx490-populated-canary1', 'nx490 two words'])
def test_crlf_capture_masks_the_name_and_keeps_the_rest(ssh_wire, name):
    body = _populated_with(name, newline='\r\n')
    assert 'Community name: ' + name + '\r\n' in body

    result = _ssh_read_through_client(ssh_wire, body)

    assert result['ok'], result
    output = result['untrusted_device_output']
    assert 'errors' in output and 'SNMP protocol : Enabled' in output
    assert 'nx490' not in json.dumps(result) and '[redacted]' in output
