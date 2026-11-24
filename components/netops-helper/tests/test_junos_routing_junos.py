"""JUNOS-ROUTING Junos probes, routing-instance context and BGP/OSPF detail.

Public reads replay real anonymized vJunos-switch 26.2R1.7 captures (GNS3 lab, accounts netops-ro and
netops-admin, 2026-11-17) over a fake physical SSH transport.
"""
import json
from subprocess import CompletedProcess
from pathlib import Path

import pytest

from netops_helper import engine, tables
from netops_helper.auth import EgressPolicy, TargetAuth
from netops_helper.query_catalog.junos import ELS_QUERIES
from netops_helper.read_policy import _validate_query_command, render_read_query

REAL = Path(__file__).parent / 'fixtures/real/juniper_junos_els/junos_routing_vjunosswitch_26.2R1.7'
INDEX = json.loads((REAL / 'index.json').read_text())
PLATFORM = 'juniper_junos_els'
ADDRESSES = tuple(sorted({value for row in INDEX.values() for name, value in row['parameters'].items()
                          if name in ('address', 'source')}))
INVENTORY = {'routing_instances': ('junos-routing', 'nonexist'), 'addresses': ADDRESSES, 'interfaces': ('irb.10', 'irb.20')}
REFUSED = ('error: unknown command:', 'error: No routing tables matching specification.', 'error: Named Route table not found.')
ABSENT = ('BGP is not running', 'OSPF instance is not running')


def auth():
    return TargetAuth(alias='vjunos', host='192.0.2.10', port=2256, login='netops-ro', secret='fixture-password',
                      host_key_fingerprint='SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                      ssh_platform=PLATFORM, enabled_queries=tuple(ELS_QUERIES), read_inventory=INVENTORY,
                      egress=EgressPolicy(addresses=('192.0.2.10',)))


def current_command(row):
    # The original lab capture used a 15-hop limit. The recorded payload is still valid.
    return row['command'].replace(' ttl 15 wait 1 ', ' ttl 30 wait 1 ')


def replay(monkeypatch, row, body):
    expected_command = current_command(row)
    calls = []
    def physical(target, profile, command, **kwargs):
        calls.append(command)
        if command == INDEX['version_ro']['command']:
            return 0, (REAL / 'version_ro.out').read_text()
        assert command == expected_command
        return row['rc'], body
    monkeypatch.setattr(engine, '_exec_read', physical)
    monkeypatch.setattr(engine, 'record', lambda *a, **kw: None)
    result = engine.ssh_read(auth(), PLATFORM, row['query'], row['parameters'], 0, 48000)
    assert expected_command in calls
    return result


def replay_traceroute(monkeypatch, key, stdout, stderr, rc=0):
    row = INDEX[key]
    calls = []

    def run_command(address, port, login, credential, known_hosts, command, *, timeout_seconds, **options):
        if command == INDEX['version_ro']['command']:
            return engine.core_ssh.Result(0, (REAL / 'version_ro.out').read_bytes(), '', '', '')
        calls.append((command, timeout_seconds))
        return engine.core_ssh.Result(rc, stdout, '', '', '', stderr=stderr)

    monkeypatch.setattr(engine, 'host_key_line', lambda *args: 'fixture-host-key')
    monkeypatch.setattr(engine.core_ssh, 'run_command', run_command)
    monkeypatch.setattr(engine, 'record', lambda *args, **kwargs: None)
    result = engine.ssh_read(auth(), PLATFORM, row['query'], row['parameters'], 0, 48000)
    assert len(calls) == 1
    return result, calls[0]


@pytest.mark.parametrize('key', ['traceroute_admin', 'traceroute_instance_admin'])
@pytest.mark.parametrize('last_hop,reached', [(16, True), (30, False), (30, True)])
def test_traceroute_reports_destination_or_hop_limit(monkeypatch, key, last_hop, reached):
    row = INDEX[key]
    # Preserve the real terminal-hop format. Extend the capture with unanswered hops to model a longer path.
    terminal = (REAL / row['file']).read_bytes().lstrip().replace(b'1 ', str(last_hop).encode() + b' ', 1)
    hops = b''.join(f'{hop:2}  * * *\n'.encode() for hop in range(1, last_hop))
    stdout = hops + (terminal if reached else b'30  * * *\n')
    result, (command, timeout) = replay_traceroute(monkeypatch, key, stdout, b'')
    assert result['ok'] is True
    assert ' ttl 30 wait 1 ' in command
    assert timeout >= 150
    assert result['traceroute'] == {
        'destination_reached': reached, 'hop_limit_reached': not reached,
        'last_hop': last_hop, 'max_hops': 30,
    }


def test_traceroute_preserves_stderr_header(monkeypatch):
    stdout = (REAL / 'traceroute_admin.out').read_bytes()
    header = b'traceroute to 192.0.2.1 (192.0.2.1), 30 hops max, 52 byte packets\n'
    result, _ = replay_traceroute(monkeypatch, 'traceroute_admin', stdout, header)
    assert result['ok'] is True
    assert result['untrusted_device_output'] == (header + stdout).decode()


def test_traceroute_to_own_routed_interface_is_parsed(monkeypatch):
    fixture = REAL.parent / 'souhrn_junos_followup/traceroute_interface.out'
    header, hop = fixture.read_bytes().splitlines(keepends=True)
    result, _ = replay_traceroute(monkeypatch, 'traceroute_admin', hop, header)
    assert result['ok'] and result['complete']
    assert result['traceroute']['destination_reached'] is True
    assert result['traceroute']['last_hop'] == 1
    assert result['status'] == result['normalized']['status'] == 'ok'


@pytest.mark.parametrize('tail', [b'', b'\n 2  unrecognized hop\n'])
def test_traceroute_does_not_confirm_a_partial_capture(monkeypatch, tail):
    fixture = REAL.parent / 'souhrn_junos_followup/traceroute_interface.out'
    header, hop = fixture.read_bytes().splitlines(keepends=True)
    partial = hop.rsplit(b'  ', 1)[0] + tail
    result, _ = replay_traceroute(monkeypatch, 'traceroute_admin', partial, header)
    assert result['status'] == 'unparsed'
    assert not result['complete']


def test_traceroute_stderr_only_diagnostic_is_redacted(monkeypatch):
    # Replay the captured Junos refusal on stderr, with an enrolled secret to verify redaction.
    diagnostic = (REAL / 'traceroute_ro.out').read_bytes() + b'traceroute: fixture-password: No route to host\n'
    result, _ = replay_traceroute(monkeypatch, 'traceroute_ro', b'', diagnostic)
    assert result['ok'] is False
    assert result['error_code'] == 'device_cli_error'
    assert 'No route to host' in result['untrusted_device_output']
    assert 'fixture-password' not in json.dumps(result)


def test_traceroute_stderr_only_missing_instance(monkeypatch):
    # Captured on vJunos-switch with junos-routing absent. The command can emit its header before failing.
    diagnostic = (b'traceroute to 198.51.100.132 (198.51.100.132), 30 hops max, 52 byte packets\n'
                  b'traceroute: setting routing instance junos-routing: No such file or directory\n')
    result, _ = replay_traceroute(monkeypatch, 'traceroute_instance_admin', b'', diagnostic)
    assert result['ok'] is False
    assert result['error_code'] == 'device_cli_error'
    assert result['untrusted_device_output'] == diagnostic.decode()


def test_index_covers_every_junos_routing_query_with_both_accounts():
    junos_routing = {'ping', 'ping_instance', 'traceroute', 'traceroute_instance', 'bgp_peer', 'bgp_peer_received_routes',
            'bgp_peer_advertised_routes', 'ospf_neighbors_detail', 'ospf_interface_detail', 'ospf_database',
            'ospfv3_neighbors_detail', 'ospfv3_interface_detail', 'ospfv3_database', 'route_lookup_instance',
            'arp_table_instance', 'ipv6_neighbors_instance', 'bgp_summary_instance'}
    assert junos_routing <= set(ELS_QUERIES)
    for role in ('RO', 'ADMIN'):
        assert junos_routing <= {row['query'] for row in INDEX.values() if row['role'] == role}
    for row in INDEX.values():
        assert render_read_query(PLATFORM, row['query'], row['parameters'], INVENTORY) == (PLATFORM, current_command(row))


@pytest.mark.parametrize('key', [key for key in INDEX if not key.startswith('version')])
def test_real_query_via_fake_physical_transport(key, monkeypatch):
    row = INDEX[key]
    body = (REAL / row['file']).read_text()
    result = replay(monkeypatch, row, body)
    if any(line.strip().startswith(REFUSED) for line in body.splitlines()):
        # RO account without the network permission, or an unknown routing instance: a refusal, never data.
        assert result['ok'] is False and result['error_code'] == 'device_cli_error'
        assert result['normalized']['status'] != 'ok'
        return
    assert result['ok'] is True and result['complete'] is True
    assert result['untrusted_device_output'] == body
    if any(line.strip() in ABSENT for line in body.splitlines()):
        assert result['normalized']['status'] == 'not_applicable'
    elif not body.strip():
        assert ELS_QUERIES[row['query']].empty_allowed
        assert result['normalized']['status'] == 'empty'
    elif row['query'] in {'traceroute', 'traceroute_instance'}:
        assert result['normalized']['status'] == 'ok'
    else:
        assert result['normalized']['status'] == 'unparsed'


def test_read_only_account_cannot_probe_but_admin_can(monkeypatch):
    for name in ('ping', 'ping_instance', 'traceroute', 'traceroute_instance'):
        assert (REAL / INDEX[name + '_ro']['file']).read_text().strip() == f'error: unknown command: {name.split("_")[0]}'
    ping = (REAL / INDEX['ping_instance_admin']['file']).read_text()
    assert '5 packets transmitted, 5 packets received, 0% packet loss' in ping
    loss = (REAL / INDEX['ping_instance_loss_admin']['file']).read_text()
    assert '5 packets transmitted, 0 packets received, 100% packet loss' in loss
    result = replay(monkeypatch, INDEX['ping_instance_loss_admin'], loss)
    assert result['ok'] is True and result['untrusted_device_output'] == loss


@pytest.mark.parametrize('name,parameters', [
    ('ping', {'address': '192.0.2.1', 'source': '192.0.2.99'}),
    ('ping', {'address': '2001:db8::1', 'source': '192.0.2.6'}),
    ('ping', {'address': '192.0.2.1', 'source': '192.0.2.6', 'count': '500'}),
    ('ping_instance', {'address': '198.51.100.132', 'source': '198.51.100.132', 'instance': 'junos-routing;restart'}),
    ('ping_instance', {'address': '198.51.100.132', 'source': '198.51.100.132', 'instance': 'unlisted'}),
    ('traceroute_instance', {'address': '198.51.100.132', 'instance': '__juniper_private1__'}),
    ('route_lookup_instance', {'instance': 'junos-routing detail', 'address': '198.51.100.132'}),
    ('arp_table_instance', {'instance': 'master'}),
    ('bgp_peer', {'address': '192.0.2.99'}),
    ('ospf_interface_detail', {'interface': 'irb.30'}),
])
def test_parameters_must_be_typed_and_enrolled(name, parameters):
    with pytest.raises(ValueError):
        render_read_query(PLATFORM, name, parameters, INVENTORY)


@pytest.mark.parametrize('command', [
    'ping {address} | no-more', 'ping {address} count 5 source {source}',
    'ping {address} rapid count 500 source {source} | no-more', 'traceroute {address} | no-more',
    'traceroute {address} no-resolve ttl 64 wait 5 | no-more',
    'ping {address} count 5 source {source} | no-more | no-more',
])
def test_probe_exception_is_exact_and_junos_only(command):
    with pytest.raises(RuntimeError):
        _validate_query_command(PLATFORM, command)
    with pytest.raises(RuntimeError):
        _validate_query_command('cisco_ios', 'ping {address} count 5 source {source} | no-more')


def test_real_instance_route_lookup_keeps_the_instance():
    for key, protocol in (('route_lookup_instance_ro', 'connected'), ('route_lookup_instance_static_ro', 'static')):
        text = (REAL / INDEX[key]['file']).read_text()
        result = tables.parse(PLATFORM, 'route', 'route_lookup_instance', text)
        assert result['ok'] and result['coverage']['complete'], result
        assert [row['vrf'] for row in result['records']] == ['junos-routing']
        assert result['records'][0]['protocol'] == protocol


def test_incomplete_capture_is_reported(monkeypatch):
    row = INDEX['ospf_neighbors_detail_ro']
    # DERIVED: cut a real output at an existing line boundary and append the Junos pager marker.
    body = (REAL / row['file']).read_text().split('  Area')[0] + '---(more)---'
    result = replay(monkeypatch, row, body)
    assert result['normalized']['status'] == 'truncated'


def test_traceroute_separates_openssh_logging_from_remote_stderr(monkeypatch):
    row = INDEX['traceroute_admin']
    body = (REAL / row['file']).read_bytes()
    header = b'traceroute to 192.0.2.1 (192.0.2.1), 30 hops max, 52 byte packets\n'
    warning = (b'** WARNING: connection is not using a post-quantum key exchange algorithm.\n'
               b'** See https://openssh.com/pq.html\n')

    def run(argv, **kwargs):
        if argv[-1] == INDEX['version_ro']['command']:
            return CompletedProcess(argv, 0, (REAL / 'version_ro.out').read_bytes(), b'')
        assert argv[-1] == current_command(row)
        if '-E' in argv:
            Path(argv[argv.index('-E') + 1]).write_bytes(warning)
            stderr = header
        else:
            stderr = warning + header
        return CompletedProcess(argv, 0, body, stderr)

    monkeypatch.setattr(engine, 'host_key_line', lambda *args: 'fixture-host-key')
    monkeypatch.setattr(engine.core_ssh.hostkey, 'known_hosts_file', lambda *args: '/fixture/known_hosts')
    monkeypatch.setattr(engine.core_ssh, '_capped_runner', lambda *args: run)
    monkeypatch.setattr(engine, 'record', lambda *args, **kwargs: None)
    result = engine.ssh_read(auth(), PLATFORM, row['query'], row['parameters'], 0, 48000)
    assert result['ok']
    assert result['untrusted_device_output'] == (header + body).decode()
