"""1.0.12 small review fixes (verification) replay real cEOS 4.36.1F captures; only the SSH transport is replaced.

`drobne493_ceos_4.36.1F` holds live read-only captures: `show poe` of the admin account on cEOS and the triage
reads of Port-Channel128 on an MLAG peer. Cut or blanked captures are marked DERIVED.
"""
import json
from dataclasses import replace
from pathlib import Path

import pytest

from conftest import _target
from netops_helper import engine
from netops_helper.query_catalog.arista import QUERIES

FIXTURES = Path(__file__).parent / 'fixtures/real/arista_eos'
REAL = FIXTURES / 'drobne493_ceos_4.36.1F'
EOS_PORTS = FIXTURES / 'eos_ports_ceos_4.36.1F'
INDEX = json.loads((REAL / 'index.json').read_text())
EOS_PORTS_INDEX = json.loads((EOS_PORTS / 'index.json').read_text())
INVENTORY = {'interfaces': ('Ethernet2', 'Ethernet14', 'Port-Channel104', 'Port-Channel128')}


def capture(key):
    return INDEX[key]['rc'], (REAL / INDEX[key]['file']).read_text()


def transport(monkeypatch, outputs, enabled=None):
    """Answer each command with (rc, text); `show version` is the anonymized capture of the same pair."""
    outputs = dict(outputs)
    outputs.setdefault('show version', (0, (EOS_PORTS / EOS_PORTS_INDEX['pair_version_ro']['file']).read_text()))
    auth = replace(_target('arista_eos', 'version'), enabled_queries=tuple(enabled or QUERIES), read_inventory=INVENTORY)
    calls = []

    def read(auth, profile, command):
        calls.append(command)
        return outputs[command]
    monkeypatch.setattr(engine, 'read_from_device', read)
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    return auth, calls


# 1. `% Unavailable command (not supported on this hardware platform)` is a device refusal, not a transport error.

@pytest.mark.parametrize('key,query,parameters', [
    ('unavailable_poe_admin', 'poe', {}),
    ('unavailable_interface_poe_admin', 'interface_poe', {'interface': 'Ethernet2'}),
])
def test_eos_unavailable_command_is_a_device_refusal(monkeypatch, key, query, parameters):
    rc, text = capture(key)
    assert rc == 1 and '% Unavailable command (not supported on this hardware platform) at line 1' in text
    auth, _ = transport(monkeypatch, {INDEX[key]['command']: (rc, text)})
    result = engine.ssh_read(auth, 'arista_eos', query, parameters, 0, 16000)
    assert result['ok'] is False and result['error_code'] == 'device_cli_error', result
    assert result['normalized']['status'] == 'unsupported' and result['status'] == 'unsupported'
    assert 'Unavailable command' in result['untrusted_device_output']


def test_eos_unavailable_command_is_unsupported_state():
    from netops_helper import normalization
    text = capture('unavailable_poe_admin')[1]
    assert normalization.output_status(text, rc=1, profile='arista_eos') == 'unsupported'
    # An exit status of 1 without a recognised device line stays a transport error.
    assert normalization.output_status('Something unexpected\n', rc=1, profile='arista_eos') == 'transport_error'


@pytest.mark.parametrize('query,limit,short_error', [
    ('poe', 4096, True), ('poe', 1000, False), ('radius', 4096, False),
])
def test_eos_unavailable_status_survives_projection_and_page_limit(monkeypatch, query, limit, short_error):
    rc, text = capture('unavailable_poe_admin')
    if query == 'radius':
        text = text.replace('show poe', 'show radius')
    if short_error:
        # Derived from the live PoE answer, without the hardware-specific explanation and line number.
        text = text.split(' (not supported', 1)[0] + '\n'
    if limit == 1000:
        text = 'diagnostic context\n' * 80 + text
    command = QUERIES[query].command
    auth, _ = transport(monkeypatch, {command: (rc, text)})
    result = engine.ssh_read(auth, 'arista_eos', query, {}, 0, limit)
    assert not result['ok'] and result['error_code'] == 'device_cli_error'
    assert result['status'] == result['normalized']['status'] == 'unsupported'
    assert result.get('next_offset') is None


def test_eos_unavailable_command_text_keeps_cisco_xe_transport_error(monkeypatch):
    from netops_helper.query_catalog import READ_QUERIES

    command = READ_QUERIES['cisco_xe']['interfaces'].command
    identity = FIXTURES.parents[1] / 'identity/cisco_xe.txt'
    _, calls = transport(monkeypatch, {command: capture('unavailable_poe_admin'), 'show version': (0, identity.read_text())})
    auth = _target('cisco_xe', 'interfaces')
    result = engine.ssh_read(auth, 'cisco_xe', 'interfaces', {}, 0, 16000)
    assert calls[-1] == command and result['rc'] == 1
    assert result.get('error_code') != 'device_cli_error'
    assert result['normalized']['status'] == result['status'] == 'transport_error'


# 2b. An incomplete read of the selected MLAG member is missing evidence.

def pair_outputs(mlag_text=None):
    outputs = {INDEX[key]['command']: capture(key) for key in INDEX if key.startswith('pair_')}
    if mlag_text is not None:
        outputs['show mlag interfaces'] = (0, mlag_text)
    return outputs


def triage(monkeypatch, mlag_text=None, enabled=None):
    auth, calls = transport(monkeypatch, pair_outputs(mlag_text), enabled=enabled)
    return engine.triage_port(auth, 'Port-Channel128'), calls


def real_mlag():
    return capture('pair_mlag_interfaces_ro')[1]


def doc_layout(*rows):
    """DERIVED: the member rows in the documented column layout the MLAG parser models (test_switch_mlag_eos_interfaces)."""
    from test_switch_mlag_eos_interfaces import _row, _table
    return _table(*(_row(*row) for row in rows))


MEMBER = ('128', 'DUO-MLAG-to-vPC', 'active-full', 'Po128', 'Po128', 'up/up')


def test_eos_triage_real_pair_capture_reads_the_member_state(monkeypatch):
    result, calls = triage(monkeypatch)
    assert 'show mlag interfaces' in calls
    members = result['evidence']['mlag_interfaces']['mlag_members']
    row, = members['members']
    assert members['state'] == 'measured' and row['state'] == 'active-full'
    assert row['description'] == 'DUO-MLAG-to-vPC'
    assert row['local_status'] == row['remote_status'] == 'up'
    assert result['missing'] == [] and result['verdict'] == 'no_fault_observed' and result['ok'] is True


def test_eos_triage_complete_member_row_is_observed_without_fault(monkeypatch):
    result, _ = triage(monkeypatch, doc_layout(MEMBER))
    members = result['evidence']['mlag_interfaces']['mlag_members']
    assert members['state'] == 'measured' and members['members'][0]['state'] == 'active-full'
    assert result['missing'] == [] and result['verdict'] == 'no_fault_observed', result['missing']


def derived_header_only():
    return doc_layout()                                             # header and separator without a member row


def derived_blank_state():
    return doc_layout(('128', 'DUO-MLAG-to-vPC', '', 'Po128', 'Po128', 'up/up'))


def derived_blank_live_state():
    return real_mlag().replace('active-full', ' ' * len('active-full'))


def derived_unknown_link():
    return doc_layout(('128', 'DUO-MLAG-to-vPC', 'active-full', 'Po128', 'Po128', '-/up'))


@pytest.mark.parametrize('make', [derived_header_only, derived_blank_state, derived_blank_live_state, derived_unknown_link])
def test_eos_triage_partial_mlag_evidence_is_missing(monkeypatch, make):
    result, _ = triage(monkeypatch, make())
    assert 'mlag_interfaces' in result['missing'], result['evidence']['mlag_interfaces'].get('mlag_members')
    assert result['verdict'] == 'incomplete' and result['ok'] is False
    assert not any(item['source'] == 'mlag_interfaces' for item in result['findings'])


@pytest.mark.parametrize('state,links', [('active-full', 'up/up'), ('active-full', '-/up'), ('', 'up/up')])
def test_eos_triage_another_members_gaps_do_not_hide_the_selected_row(monkeypatch, state, links):
    result, _ = triage(monkeypatch, doc_layout(MEMBER, ('129', 'Other', state, 'Po129', 'Po129', links)))
    summary = result['evidence']['mlag_interfaces']['mlag_members']
    assert summary['state'] == ('measured' if state and links == 'up/up' else 'partial')
    assert result['missing'] == [] and result['verdict'] == 'no_fault_observed' and result['ok'] is True


@pytest.mark.parametrize('role', ['ro', 'admin'])
def test_eos_eos_ports_no_mlag_ports_capture_is_still_a_complete_empty_table(monkeypatch, role):
    from test_eos_ports_ports import transport as eos_ports_transport

    auth, calls = eos_ports_transport(monkeypatch, ['mlag_interfaces'], role=role)
    result = engine.ssh_read(auth, 'arista_eos', 'mlag_interfaces', {}, 0, 16000)
    assert calls[-1] == 'show mlag interfaces' and result['ok'] is True
    assert result['mlag_members'] == {'state': 'measured', 'members': [], 'missing_fields': []}


# 2c. A refused MAC read names every query the administrator can enable, including the backward compatible `mac_table`.

MAC = EOS_PORTS_INDEX['mac_table_address_ro']['parameters']['mac']
REFUSED = [
    ({'mac': MAC}, ['mac_table_address', 'mac_table']),
    ({'vlan_id': '10'}, ['mac_table_vlan', 'mac_table']),
    ({'mac': MAC, 'vlan_id': '10'}, ['mac_table_address', 'mac_table_vlan', 'mac_table']),
    ({'interface': 'Ethernet2'}, ['mac_table_interface']),
    ({}, ['mac_table']),
]


@pytest.mark.parametrize('arguments,names', REFUSED)
def test_eos_mac_read_without_an_enabled_query_names_the_candidates(monkeypatch, arguments, names):
    from netops_helper.auth import PolicyScopeError
    auth, calls = transport(monkeypatch, {}, enabled=['version'])
    with pytest.raises(PolicyScopeError) as caught:
        engine.switch_read(auth, 'mac_entry', **arguments)
    assert str(caught.value).endswith(', '.join(names)), str(caught.value)
    assert calls == []


@pytest.mark.parametrize('arguments,names', REFUSED)
def test_public_eos_mac_refusal_names_the_candidates(tmp_path, arguments, names):
    import test_proxy_contracts as contracts
    auth = replace(_target('arista_eos', 'version'), enabled_queries=('version',), read_inventory=INVENTORY)
    proxy = contracts._load_proxy()
    inventory, _, _, _ = contracts._configure(proxy, tmp_path)
    section = dict(contracts._section(), ssh_platform='arista_eos', device_types=['switch'],
                   enabled_queries=list(auth.enabled_queries), read_inventory=INVENTORY)
    section['egress']['tcp_ports'].append(22)
    contracts._write(inventory, contracts._inventory(contracts._device(section, 'arista_eos')))
    gateway = proxy.Proxy()
    errors = []
    gateway._emit = errors.append
    assert gateway.request(contracts._request(1, 'switch_read', {'target': 'device-a', 'table': 'mac_entry', **arguments})) is None
    assert errors[0]['error']['code'] == -32009
    assert errors[0]['error']['data'] == {'category': 'policy_scope', 'field': 'enabled_queries', 'queries': names}


def test_eos_mac_read_with_the_targeted_query_enabled_is_unchanged(monkeypatch):
    from test_eos_ports_ports import transport as eos_ports_transport
    auth, calls = eos_ports_transport(monkeypatch, ['mac_table_address'], enabled=['version', 'mac_table_address'])
    result = engine.switch_read(auth, 'mac_entry', mac=MAC)
    assert result['status'] == 'ok' and calls[-1] == 'show mac address-table address ' + MAC
