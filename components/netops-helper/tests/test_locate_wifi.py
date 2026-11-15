"""locate_endpoint for a tunnelled Wi-Fi client: station -> AP/radio -> wired AP port.

DERIVED REPLAY SCENARIO, not a new measurement of any network. It reuses the
anonymised FortiOS 8.0.2 REST captures (monitor/wifi/client, managed_ap,
user/device/query), the anonymised FortiOS `get system arp` capture and the
IOS lab table captures unchanged on disk. Because each capture was anonymised
on its own (client.ip and AP.local_addr are both 192.0.2.1 there), this module
remaps a few identities, addresses and ports in memory so that one coherent
scenario results:

* client 00:00:5e:00:53:81 / 192.0.2.1  ->  00:00:5e:00:53:32 / 192.0.2.19
  (the address/MAC the ARP capture shows on the tunnel interface ssid-17);
* AP name-1 local_addr 192.0.2.1 -> 192.0.2.10 (ap-mgmt row of the ARP capture,
  Ethernet MAC 00:00:5e:00:53:01), board_mac -> 00:00:5e:00:53:a1;
* IOS MAC row 0000.5e00.5301 Gi0/1 -> Gi0/3, Gi0/3 status -> connected/10, plus
  one LLDP detail block in the existing IOS layout for a FortiAP on Gi0/3,
  appended as the tenth entry.

Only the transport is faked (REST socket/TLS/HTTP document, SSH stdout).
Auth decode, REST parsing, the station/AP join and the wired correlator are real.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from conftest import FORTIOS_STATUS
from netops_helper import endpoint_worker, engine, locate, wifi_rest as r
from netops_helper.query_catalog import READ_QUERIES
from test_engine_contracts import _context

FIXTURES = Path(__file__).parent / 'fixtures'
TOKEN = 'synthetic-rest-token-canary-04049'
CERT = b'synthetic DER certificate 109-04'
PIN = hashlib.sha256(CERT).hexdigest()
FGT_HOST, SW_HOST = '198.51.100.1', '198.51.100.2'

CLIENT_MAC, CLIENT_IP = '00:00:5e:00:53:32', '192.0.2.19'
OTHER_MAC = '00:00:5e:00:53:36'
AP_IP, AP_MAC = '192.0.2.10', '00:00:5e:00:53:01'
CLIENT = r.MONITOR + 'client'
MANAGED_AP = r.MONITOR + 'managed_ap'

AP_LLDP_BLOCK = """------------------------------------------------
Local Intf: Gi0/3
Chassis id: 0000.5e00.5301
Port id: lan1
Port Description: lan1
System Name: FAP-231G-derived

System Description:
FortiAP-231G derived replay identity

Time remaining: 110 seconds
System Capabilities: B,W,R
Enabled Capabilities: W
Management Addresses:
    IP: 192.0.2.10
Auto Negotiation - not supported
Physical media capabilities - not advertised
Media Attachment Unit type - not advertised
Vlan ID: - not advertised

"""


def rest_fixture(name):
    return json.loads((FIXTURES / ('fortios_80f_802_wifi_rest_' + name + '.json')).read_text())


def documents(radio=2, ap_known=True, second_station_ip=None):
    """Derived replay of the three REST captures (see module docstring)."""
    clients = rest_fixture('monitor_wifi_client')
    station = clients['results'][0]
    station.update(mac=CLIENT_MAC, ip=CLIENT_IP, wtp_radio=radio)
    if second_station_ip is not None:
        clients['results'][1]['ip'] = second_station_ip
    aps = rest_fixture('monitor_wifi_managed_ap')
    aps['results'][0].update(local_addr=AP_IP, board_mac='00:00:5e:00:53:a1')
    if not ap_known:
        del aps['results'][0]
    devices = rest_fixture('device_query')
    devices['results'][0]['mac'] = CLIENT_MAC
    return {CLIENT: clients, MANAGED_AP: aps, r.DEVICES: devices}


def ios_outputs(ap_on_edge=True):
    data = json.loads((FIXTURES / 'tables/cisco_ios.json').read_text())
    mac, lldp, interfaces = data['mac_entry'], data['lldp_neighbor'], data['interface']
    if ap_on_edge:
        row = '  10    0000.5e00.5301    DYNAMIC     Gi0/1'
        assert mac.count(row) == 1
        mac = mac.replace(row, '  10    0000.5e00.5301    DYNAMIC     Gi0/3')
        anchor = '\n\nTotal entries displayed: 9\n'
        assert lldp.count(anchor) == 1 and lldp.endswith(anchor)
        lldp = lldp.replace(anchor, '\n' + AP_LLDP_BLOCK + '\nTotal entries displayed: 10\n')
        status = 'Gi0/3                        notconnect   trunk      a-full   auto RJ45'
        assert interfaces.count(status) == 1
        interfaces = interfaces.replace(status, 'Gi0/3                        connected    10         a-full   auto RJ45')
    commands = READ_QUERIES['cisco_ios']
    return {commands['version'].command: (FIXTURES / 'identity/cisco_ios.txt').read_text(),
            commands['mac_table'].command: mac, commands['lldp_neighbors'].command: lldp,
            commands['interfaces'].command: interfaces, commands['vlans'].command: data['vlan']}


def fgt_outputs():
    commands = READ_QUERIES['fortinet']
    return {commands['system_status'].command: FORTIOS_STATUS,
            commands['arp_table'].command: (FIXTURES / 'fortios_80f_802_wifi_system_arp.txt').read_text()}


def contexts(rest=True, fgt_limit=40):
    """Synthetic enrolment contexts in the exact injected form, decoded by the real worker decode."""
    fgt = dict(alias='fgt', host=FGT_HOST, ssh_platform='fortinet', enabled_queries=['arp_table'],
               device_types=['firewall'], fortios_output_standard_verified=True, locate_read_limit=fgt_limit,
               egress={'addresses': [FGT_HOST], 'tcp_ports': [22, 443], 'udp_ports': [], 'tcp_port_ranges': [],
                       'udp_port_ranges': [], 'allow_icmp': False, 'allow_dns': False, 'tls_server_names': []})
    if rest:
        fgt.update(fortios_rest_token=TOKEN, fortios_rest_certificate_sha256=PIN, fortios_rest_port=443)
    sw = dict(alias='sw1', host=SW_HOST, ssh_platform='cisco_ios',
              enabled_queries=['mac_table', 'lldp_neighbors', 'interfaces', 'vlans'], device_types=['switch'],
              egress={'addresses': [SW_HOST], 'tcp_ports': [22], 'udp_ports': [], 'tcp_port_ranges': [],
                      'udp_port_ranges': [], 'allow_icmp': False, 'allow_dns': False, 'tls_server_names': []})
    return json.dumps({'fgt': _context(**fgt), 'sw1': _context(**sw)})


def decoded(**kwargs):
    return endpoint_worker.decode(['fgt', 'sw1'], contexts(**kwargs))


class Rest:
    """Fake FortiOS HTTPS peer: the real wifi_rest.get runs over it."""

    def __init__(self, docs, *, status=None, clock=None, cost=None):
        self.docs, self.status = docs, status or {}
        self.clock, self.cost = clock, cost or {}
        self.paths, self.timeouts, self.peers, self.headers = [], [], [], []

    def install(self, monkeypatch):
        peer = MagicMock()
        peer.getpeercert.return_value = CERT
        context = MagicMock()
        context.wrap_socket.return_value = peer
        monkeypatch.setattr(r.ssl, 'SSLContext', lambda *a: context)

        def connect(address, timeout=None):
            self.peers.append(address)
            self.timeouts.append(timeout)
            return MagicMock()
        monkeypatch.setattr(r.socket, 'create_connection', connect)
        monkeypatch.setattr(r.http.client, 'HTTPSConnection', lambda *a, **k: Connection(self))
        if self.clock is not None:
            monkeypatch.setattr(r, 'time', SimpleNamespace(monotonic=self.clock.monotonic))
        return self


class Connection:
    def __init__(self, rest):
        self.rest, self.sock, self.path = rest, None, None

    def request(self, method, path, headers):
        assert method == 'GET'
        self.path = path
        self.rest.paths.append(path)
        self.rest.headers.append(headers)

    def getresponse(self):
        rest = self.rest
        if rest.clock is not None and self.path in rest.cost:
            rest.clock.advance(rest.cost[self.path])
        body = json.dumps(rest.docs[self.path]).encode()
        chunks = [body, b'']
        return SimpleNamespace(status=rest.status.get(self.path, 200),
                               getheader=lambda key, default=None: default,
                               read1=lambda size: chunks.pop(0))

    def close(self):
        pass


@pytest.fixture
def audit(monkeypatch):
    events = []
    monkeypatch.setattr(engine, 'record', lambda event, **fields: events.append((event, fields)))
    r._rates.clear()
    return events


@pytest.fixture
def ssh(monkeypatch):
    outputs = {'fgt': fgt_outputs(), 'sw1': ios_outputs()}
    calls = []

    def device(auth, profile, command):
        calls.append((auth.alias, command))
        return 0, outputs[auth.alias][command]
    monkeypatch.setattr(engine, 'read_from_device', device)
    return SimpleNamespace(outputs=outputs, calls=calls)


def no_rest(monkeypatch):
    monkeypatch.setattr(r.socket, 'create_connection', lambda *a, **k: pytest.fail('REST contacted'))


def finish(result):
    """What the worker would send: JSON-serialisable, a known verdict, no credential."""
    text = json.dumps(result, allow_nan=False)
    assert result['verdict'] in endpoint_worker.VERDICTS
    assert TOKEN not in text and 'Bearer' not in text
    return result


def test_unparsed_station_row_keeps_a_found_client_incomplete(monkeypatch, audit, ssh):
    docs = documents()
    # Derived replay: another AP binding for the same IP cannot be parsed without a MAC.
    docs[CLIENT]['results'].append({'ip': CLIENT_IP, 'mac': None, 'wtp_id': 'name-10'})
    rest = Rest(docs).install(monkeypatch)
    result = finish(engine._locate_endpoint_run(decoded(), CLIENT_IP))
    assert rest.paths == [CLIENT, MANAGED_AP, r.DEVICES]
    assert result['missing'] == [{'vantage': 'fgt', 'table': 'wifi_station', 'reason': 'unparsed_rows'}]
    assert result['coverage']['complete'] is False
    assert 'fgt' in result['coverage']['unfinished_targets']
    assert 'fgt' not in result['coverage']['completed_targets']
    assert result['verdict'] == 'incomplete'
    controller = [v for v in result['vantage'] if v['target'] == 'fgt' and v['table'] == 'wifi_station']
    assert len(controller) == 1 and controller[0]['status'] == 'partial'
    wireless = result['wireless']
    assert wireless['client'] == {'mac': CLIENT_MAC, 'ip': CLIENT_IP, 'ssid': 'vap-name-2'}
    assert wireless['ap']['id'] == 'name-1' and wireless['ap']['management_ip'] == AP_IP
    assert wireless['radio'] == 2
    assert wireless['ap_location']['verdict'] == 'located'
    assert wireless['ap_port'] == {'vantage': 'sw1', 'port': 'GigabitEthernet0/3', 'vlan_id': 10,
                                   'role': 'edge_behind_ap'}


def test_real_decode_keeps_the_rest_material_the_new_branch_needs():
    fgt, sw = decoded()
    assert (fgt.fortios_rest_token, fgt.fortios_rest_certificate_sha256, fgt.fortios_rest_port) == (TOKEN, PIN, 443)
    assert sw.fortios_rest_token is None
    from netops_helper import locate_wifi
    assert [a.alias for a in locate_wifi.controllers([fgt, sw])] == ['fgt']
    assert locate_wifi.controllers(decoded(rest=False)) == []


@pytest.mark.parametrize('radio', [2, 0])
@pytest.mark.parametrize('endpoint', [CLIENT_MAC, CLIENT_IP])
def test_tunnelled_client_is_located_through_its_ap_backhaul(monkeypatch, audit, ssh, endpoint, radio):
    rest = Rest(documents(radio=radio)).install(monkeypatch)
    result = finish(engine._locate_endpoint_run(decoded(), endpoint))
    # The client is the endpoint; the switch FDB never shows it (tunnelled).
    assert result['endpoint'] == ({'mac': CLIENT_MAC} if endpoint == CLIENT_MAC else {'ip': CLIENT_IP})
    assert '0000.5e00.5332' not in ssh.outputs['sw1'][READ_QUERIES['cisco_ios']['mac_table'].command]
    assert result['verdict'] == 'located', result
    assert result['coverage']['complete'] is True and result['missing'] == []
    # No AP record is presented as a direct wired observation of the client.
    assert result['findings'] == [] and result['own_interfaces'] == [] and result['neighbors_l3'] == []
    wireless = result['wireless']
    assert wireless['status'] == 'associated' and wireless['controller'] == 'fgt'
    assert wireless['client'] == {'mac': CLIENT_MAC, 'ip': CLIENT_IP, 'ssid': 'vap-name-2'}
    assert wireless['ap'] == {'id': 'name-1', 'serial': 'name-1', 'name': 'name-1', 'management_ip': AP_IP}
    assert wireless['radio'] == radio and wireless['band'] == '5ghz'
    assert set(wireless) >= {'sources', 'ap_location', 'ap_port'}
    assert 'radio' not in wireless['ap'] and 'lldp' not in wireless['ap']       # no RF/AP tables copied
    location = wireless['ap_location']
    assert location['endpoint'] == {'ip': AP_IP} and location['verdict'] == 'located'
    assert [(f['vantage'], f['mac'], f['port'], f['vlan_id'], f['role']) for f in location['findings']] == [
        ('sw1', AP_MAC, 'GigabitEthernet0/3', 10, 'edge_behind_ap')]
    assert wireless['ap_port'] == {'vantage': 'sw1', 'port': 'GigabitEthernet0/3', 'vlan_id': 10, 'role': 'edge_behind_ap'}
    assert all(f['mac'] != CLIENT_MAC for f in location['findings'])
    # Every transport read on one shared budget: 3 REST GETs, FortiGate identity+ARP, switch identity+MAC+LLDP+ports.
    assert rest.paths == [CLIENT, MANAGED_AP, r.DEVICES]
    assert len(ssh.calls) == 6 and result['reads'] == location['reads'] == 9
    assert set(rest.peers) == {(FGT_HOST, 443)}
    # Learned AP/client addresses are only search literals, never a connection or command slot.
    assert not any(AP_IP in c or CLIENT_IP in c or CLIENT_MAC in c for _, c in ssh.calls)
    rest_events = [f for e, f in audit if e == 'fortios_wifi_get']
    assert [f['request'] for f in rest_events if f['status'] == 'started'] == ['GET ' + p for p in rest.paths]
    assert TOKEN not in json.dumps(audit, default=str)


def test_original_wired_flow_without_rest_credential_is_unchanged(monkeypatch, audit, ssh):
    no_rest(monkeypatch)
    plain = finish(engine._locate_endpoint_run(decoded(rest=False), AP_IP))
    assert 'wireless' not in plain and plain['verdict'] == 'located'
    assert set(plain) == {'ok', 'endpoint', 'verdict', 'findings', 'missing', 'vantage', 'reads', 'coverage',
                          'limits', 'own_interfaces', 'neighbors_l3', 'elapsed_seconds'}
    plain_calls = list(ssh.calls)
    # The tunnelled client without REST: the wired flow cannot see it (the original symptom).
    ssh.calls.clear()
    blind = finish(engine._locate_endpoint_run(decoded(rest=False), CLIENT_MAC))
    assert 'wireless' not in blind and blind['verdict'] == 'not_found_in_checked_data'

    # With a credential, an endpoint absent from the station table keeps the same wired decision.
    ssh.calls.clear()
    rest = Rest(documents()).install(monkeypatch)
    with_rest = finish(engine._locate_endpoint_run(decoded(), AP_IP))
    assert ssh.calls == plain_calls and rest.paths == [CLIENT, MANAGED_AP, r.DEVICES]
    for key in ('endpoint', 'verdict', 'findings', 'missing', 'own_interfaces', 'neighbors_l3', 'coverage'):
        assert with_rest[key] == plain[key], key
    assert with_rest['reads'] == plain['reads'] + 3
    assert with_rest['wireless']['status'] == 'not_in_station_table'


def test_ipv6_endpoint_keeps_the_wired_flow_without_rest(monkeypatch, audit, ssh):
    no_rest(monkeypatch)
    result = finish(engine._locate_endpoint_run(decoded(), '2001:db8::10'))
    assert 'wireless' not in result


def test_station_on_an_unjoined_ap_is_incomplete_without_guessing(monkeypatch, audit, ssh):
    Rest(documents(ap_known=False)).install(monkeypatch)
    result = finish(engine._locate_endpoint_run(decoded(), CLIENT_MAC))
    assert result['verdict'] == 'incomplete' and result['coverage']['complete'] is False
    assert {(m['table'], m['reason']) for m in result['missing']} >= {('wifi_ap', 'ap_not_joined'),
                                                                     ('wifi_ap_backhaul', 'ap_management_ip_unavailable')}
    wireless = result['wireless']
    assert wireless['ap'] == {'id': 'name-1', 'serial': None, 'name': None, 'management_ip': None}
    assert wireless['ap_location'] is None and ssh.calls == []
    assert result['findings'] == []


def test_ap_without_a_proven_edge_port_is_incomplete(monkeypatch, audit, ssh):
    # Original IOS capture: the AP MAC sits behind an LLDP bridge/router on Gi0/1 (transit).
    ssh.outputs['sw1'] = ios_outputs(ap_on_edge=False)
    Rest(documents()).install(monkeypatch)
    result = finish(engine._locate_endpoint_run(decoded(), CLIENT_MAC))
    wireless = result['wireless']
    assert wireless['ap_location']['verdict'] == 'incomplete'
    assert wireless['ap_location']['findings'][0]['role'] == 'transit'
    assert wireless['ap_port'] is None
    assert result['verdict'] == 'incomplete' and result['findings'] == []
    assert {'vantage': None, 'table': 'wifi_ap_backhaul', 'reason': 'ap_location_incomplete'} in result['missing']


def test_distinct_station_candidates_are_ambiguous_and_visible(monkeypatch, audit, ssh):
    Rest(documents(second_station_ip=CLIENT_IP)).install(monkeypatch)
    result = finish(engine._locate_endpoint_run(decoded(), CLIENT_IP))
    assert result['verdict'] == 'ambiguous'
    candidates = result['wireless']['candidates']
    assert sorted((c['client']['mac'], c['ap']['id'], c['radio']) for c in candidates) == [
        (CLIENT_MAC, 'name-1', 2), ('00:00:5e:00:53:82', 'name-1', 1)]
    assert result['wireless']['ap_location'] is None and ssh.calls == [] and result['findings'] == []


@pytest.mark.parametrize('failing,status,code', [
    (CLIENT, 403, 'authorization_failed'),        # REST denied
    (MANAGED_AP, 503, 'http_server_error'),       # partial: stations without their AP join
])
def test_rest_failure_never_becomes_absence(monkeypatch, audit, ssh, failing, status, code):
    rest = Rest(documents(), status={failing: status}).install(monkeypatch)
    result = finish(engine._locate_endpoint_run(decoded(), CLIENT_MAC))
    assert result['verdict'] == 'incomplete' and result['coverage']['complete'] is False
    assert {'vantage': 'fgt', 'table': 'wifi_station', 'reason': 'rest_unavailable', 'error_code': code,
            'failed_step': failing} in result['missing']
    assert result['wireless']['status'] == 'not_verified' and 'fgt' in result['coverage']['unfinished_targets']
    assert rest.paths[-1] == failing and r.DEVICES not in rest.paths


def test_rest_failure_does_not_cancel_a_proven_wired_location(monkeypatch, audit, ssh):
    Rest(documents(), status={CLIENT: 403}).install(monkeypatch)
    result = finish(engine._locate_endpoint_run(decoded(), AP_IP))
    assert result['verdict'] == 'located' and result['findings'][0]['port'] == 'GigabitEthernet0/3'
    assert any(m['table'] == 'wifi_station' and m['error_code'] == 'authorization_failed' for m in result['missing'])


def test_per_target_limit_counts_every_actual_rest_get(monkeypatch, audit, ssh):
    rest = Rest(documents()).install(monkeypatch)
    result = finish(engine._locate_endpoint_run(decoded(fgt_limit=2), CLIENT_MAC))
    # client + managed_ap fit; the supplementary device read is the third GET on fgt.
    assert rest.paths == [CLIENT, MANAGED_AP]
    assert {'vantage': 'fgt', 'table': 'budget', 'reason': 'target_read_limit'} in result['missing']
    assert result['verdict'] == 'incomplete'
    assert not any(alias == 'fgt' for alias, _ in ssh.calls)


def test_shared_read_cap_counts_every_actual_rest_get(monkeypatch, audit, ssh):
    monkeypatch.setattr(locate, 'MAX_READS', 2)
    rest = Rest(documents()).install(monkeypatch)
    result = finish(engine._locate_endpoint_run(decoded(), CLIENT_MAC))
    assert rest.paths == [CLIENT, MANAGED_AP] and result['reads'] == 2
    assert {'vantage': 'fgt', 'table': 'budget', 'reason': 'read_limit'} in result['missing']
    assert result['verdict'] == 'incomplete' and ssh.calls == []


def test_one_fake_clock_bounds_rest_timeouts_by_the_shared_deadline(monkeypatch, audit, ssh):
    from support.virtual_clock import Clock, install
    clock = Clock(1000.0)
    install(monkeypatch, clock)
    # First GET costs 1 s; the second outlives the remaining shared deadline.
    rest = Rest(documents(), clock=clock, cost={CLIENT: 1.0, MANAGED_AP: 3.5}).install(monkeypatch)
    result = finish(engine._locate_endpoint_run(decoded(), CLIENT_MAC, deadline=1004.0))
    # Each REST timeout is the remaining locate deadline, below the 10 s REST TIMEOUT.
    assert rest.timeouts == [pytest.approx(4.0), pytest.approx(3.0)]
    assert rest.paths == [CLIENT, MANAGED_AP]
    assert any(m.get('error_code') == 'timeout' for m in result['missing'])
    assert any(m['table'] == 'budget' and m['reason'] == 'timeout' for m in result['missing'])
    assert result['verdict'] == 'incomplete' and ssh.calls == []
    assert result['elapsed_seconds'] == pytest.approx(4.5)


def test_worker_checkpoints_keep_the_client_endpoint(monkeypatch, audit, ssh):
    Rest(documents()).install(monkeypatch)
    seen = []
    engine._locate_endpoint_run(decoded(), CLIENT_MAC, lambda result: seen.append(copy.deepcopy(result)))
    assert seen and all(item['endpoint'] == {'mac': CLIENT_MAC} for item in seen)
    assert all(item['verdict'] == 'incomplete' and item['findings'] == [] for item in seen)
    assert any(item.get('wireless', {}).get('ap_location') for item in seen)


class TestProxyWifiLocate:
    """Public path, no hand-made context: the real Proxy.request over a synthetic test
    inventory/vault/policy, the real endpoint_worker.decode of the arguments it forwards,
    then the real engine._locate_endpoint_run over the same derived replay transports.
    Only synthetic test values; nothing here is a live measurement."""

    INVALID = 'synthetic invalid token canary'

    @staticmethod
    def _proxy(tmp_path, monkeypatch, *, rest=True, token=TOKEN, fgt_requests=30, extra=()):
        import test_proxy_contracts as c
        from netops_helper import proxy as p
        inventory, vault, _, _ = c._configure(p, tmp_path)

        def section(platform, queries, types, host, ports, requests=30):
            s = c._section()
            s.update(ssh_platform=platform, enabled_queries=list(queries), device_types=list(types),
                     rate_limit={'requests': requests, 'window_seconds': 60})
            s['egress'].update(addresses=[host], tcp_ports=list(ports))
            return s

        fgt = section('fortios', ['arp_table'], ['firewall'], FGT_HOST, [22, 443], fgt_requests)
        if rest:
            fgt.update(fortios_rest_credential='api-ro', fortios_rest_certificate_sha256=PIN)
        sw = section('cisco_ios', ['mac_table', 'lldp_neighbors', 'interfaces', 'vlans'], ['switch'], SW_HOST, [22])
        devices = [{**c._device(fgt), 'name': 'fgt', 'address': FGT_HOST},
                   {**c._device(sw, 'cisco_ios'), 'name': 'sw1', 'address': SW_HOST}]
        for name in extra:              # a FortiOS target with the same REST enrolment but no reader query
            other = section('fortios', ['system_status'], ['firewall'], FGT_HOST, [22, 443])
            other.update(fortios_rest_credential='api-ro', fortios_rest_certificate_sha256=PIN)
            devices.append({**c._device(other), 'name': name, 'address': FGT_HOST})
        c._write(inventory, c._inventory(*devices))
        document = json.loads(vault.read_text())
        document['credentials']['api-ro'] = {'kind': 'api-token', 'login': None, 'value': token}
        c._write(vault, document, 0o600)
        proxy = p.Proxy()
        emitted, looked_up = [], []
        monkeypatch.setattr(proxy, '_emit', emitted.append)
        original = proxy._credential

        def recorded(vault, name):          # pass-through spy: which credentials the call reads
            looked_up.append(name)
            return original(vault, name)
        monkeypatch.setattr(proxy, '_credential', recorded)
        return SimpleNamespace(proxy=proxy, emitted=emitted, looked_up=looked_up, module=p, c=c)

    @staticmethod
    def _call(env, identifier, endpoint, targets=('fgt', 'sw1')):
        return env.proxy.request(env.c._request(identifier, 'locate_endpoint',
                                                {'targets': list(targets), 'endpoint': endpoint}))

    @staticmethod
    def _forwarded(forward):
        args = json.loads(forward)['params']['arguments']
        return args, endpoint_worker.decode(args['targets'], args['auth_context'])

    @pytest.mark.parametrize('endpoint', [CLIENT_MAC, CLIENT_IP])
    def test_configured_credential_reaches_the_worker_and_locates_the_client(
            self, tmp_path, monkeypatch, audit, ssh, capsys, endpoint):
        (tmp_path / 'plain').mkdir()
        plain = self._proxy(tmp_path / 'plain', monkeypatch, rest=False)
        assert self._call(plain, 1, endpoint) is not None
        original = dict(plain.proxy.rate_history)            # the original wired plan without a credential
        env = self._proxy(tmp_path, monkeypatch)
        forward = self._call(env, 1, endpoint)
        assert forward is not None, env.emitted
        args, (fgt, sw) = self._forwarded(forward)
        # The configured credential, pin and port arrive through the public request.
        assert (fgt.fortios_rest_token, fgt.fortios_rest_certificate_sha256, fgt.fortios_rest_port) == (TOKEN, PIN, 443)
        assert sw.fortios_rest_token is None and env.looked_up.count('api-ro') == 1
        # One plan: what the worker enforces per target is what was reserved, +3 GETs on the controller only.
        assert fgt.locate_read_limit == len(env.proxy.rate_history['fgt']) == len(original['fgt']) + 3
        assert sw.locate_read_limit == len(env.proxy.rate_history['sw1']) == len(original['sw1'])
        # The token travels only in the private auth context, never in another argument or the process arguments.
        visible = {k: v for k, v in args.items() if k not in (env.module.AUTH_FIELD, env.module.REDACTION_FIELD)}
        assert TOKEN not in json.dumps(visible) and TOKEN not in ' '.join(endpoint_worker.command())

        rest = Rest(documents()).install(monkeypatch)
        result = finish(engine._locate_endpoint_run([fgt, sw], args['endpoint']))
        assert result['verdict'] == 'located', result
        assert result['findings'] == [] and result['missing'] == []
        assert result['wireless']['client']['mac'] == CLIENT_MAC
        assert result['wireless']['ap_port'] == {'vantage': 'sw1', 'port': 'GigabitEthernet0/3', 'vlan_id': 10,
                                                 'role': 'edge_behind_ap'}
        assert rest.paths == [CLIENT, MANAGED_AP, r.DEVICES] and set(rest.peers) == {(FGT_HOST, 443)}
        assert all(h['Authorization'] == 'Bearer ' + TOKEN for h in rest.headers)
        fgt_reads = len(rest.paths) + sum(alias == 'fgt' for alias, _ in ssh.calls)
        assert fgt_reads <= fgt.locate_read_limit and result['limits']['target_reads']['fgt'] == fgt.locate_read_limit
        assert TOKEN not in json.dumps(audit, default=str)
        assert TOKEN not in json.dumps(env.emitted) and TOKEN not in str(capsys.readouterr())

    @pytest.mark.parametrize('rest,endpoint', [(False, CLIENT_MAC), (False, CLIENT_IP), (True, '2001:db8::10')])
    def test_unusable_rest_step_keeps_the_original_wired_path_and_cost(
            self, tmp_path, monkeypatch, audit, ssh, rest, endpoint):
        (tmp_path / 'plain').mkdir()
        plain = self._proxy(tmp_path / 'plain', monkeypatch, rest=False)
        assert self._call(plain, 1, endpoint) is not None
        env = self._proxy(tmp_path, monkeypatch, rest=rest)
        forward = self._call(env, 1, endpoint)
        assert forward is not None, env.emitted
        args, auths = self._forwarded(forward)
        # Nothing is read from the vault for a REST step that cannot run, and no token is injected.
        assert 'api-ro' not in env.looked_up
        assert all(a.fortios_rest_token is None for a in auths)
        charged = {alias: len(history) for alias, history in env.proxy.rate_history.items()}
        assert charged == {alias: len(history) for alias, history in plain.proxy.rate_history.items()}
        assert [a.locate_read_limit for a in auths] == [len(env.proxy.rate_history[a.alias]) for a in auths]
        no_rest(monkeypatch)
        result = finish(engine._locate_endpoint_run(auths, args['endpoint']))
        assert 'wireless' not in result

    def test_invalid_saved_token_fails_closed_without_forward_or_leak(self, tmp_path, monkeypatch, capsys):
        env = self._proxy(tmp_path, monkeypatch, token=self.INVALID)
        assert self._call(env, 7, CLIENT_MAC) is None
        error = env.emitted[-1]['error']
        assert error['code'] == -32006 and error['data']['category'] == 'auth_material'
        assert 'api-token' in error['data']['hint']
        assert self.INVALID not in json.dumps(env.emitted) and self.INVALID not in str(capsys.readouterr())
        assert not env.proxy.rate_history.get('fgt') and not env.proxy.rate_history.get('sw1')
        assert not env.proxy.pending
        # The unusable token is not read at all for IPv6, so that call proceeds on the wired plan.
        assert self._call(env, 8, '2001:db8::10') is not None

    def test_unauthorized_or_unknown_targets_and_client_contexts_are_refused(self, tmp_path, monkeypatch):
        env = self._proxy(tmp_path, monkeypatch, extra=('fw2',))
        assert self._call(env, 1, CLIENT_MAC, targets=('fw2',)) is None
        assert env.emitted[-1]['error']['data'] == {'category': 'policy_scope', 'target': 'fw2'}
        assert 'api-ro' not in env.looked_up              # refused before any REST credential is read
        assert self._call(env, 2, CLIENT_MAC, targets=('fgt', 'unknown')) is None
        assert self._call(env, 3, CLIENT_MAC, targets=('fgt', 'fw2')) is None
        assert not env.proxy.rate_history.get('fgt')
        forward = self._call(env, 4, CLIENT_MAC)
        args, _ = self._forwarded(forward)
        for injected in ('injected', args['auth_context']):
            assert env.proxy.request(env.c._request(5, 'locate_endpoint', {**args, 'auth_context': injected})) is None
        assert TOKEN not in json.dumps(env.emitted)

    def test_backend_echo_of_the_token_or_context_never_reaches_the_user(self, tmp_path, monkeypatch, audit, ssh):
        env = self._proxy(tmp_path, monkeypatch)
        forward = self._call(env, 11, CLIENT_MAC)
        args, auths = self._forwarded(forward)
        Rest(documents()).install(monkeypatch)
        result = engine._locate_endpoint_run(auths, args['endpoint'])
        context = json.loads(args['auth_context'])['fgt']
        echo = dict(result, note=TOKEN, echoed_context=context, echoed_targets=args['auth_context'])
        echo['wireless'] = dict(echo['wireless'], client=dict(echo['wireless']['client'], ssid=TOKEN))
        raw = json.dumps({'jsonrpc': '2.0', 'id': 11, 'result': {
            'content': [{'type': 'text', 'text': json.dumps(echo)}], 'structuredContent': echo}}).encode()
        out = env.proxy.response(raw)
        assert out and json.loads(out)['id'] == 11
        assert TOKEN.encode() not in out and context.encode() not in out
        assert args['auth_context'].encode() not in out
        assert b'"verdict"' in out                     # a real answer, sanitised rather than refused

    def test_reservation_is_all_or_nothing_and_the_token_never_bypasses_caps(
            self, tmp_path, monkeypatch, audit, ssh):
        import collections
        import time
        (tmp_path / 'plain').mkdir()
        plain = self._proxy(tmp_path / 'plain', monkeypatch, rest=False)
        assert self._call(plain, 1, CLIENT_MAC) is not None
        base = len(plain.proxy.rate_history['fgt'])
        env = self._proxy(tmp_path, monkeypatch)
        # sw1 has 2 of 30 requests left, fewer than its plan: neither target is charged.
        env.proxy.rate_history['sw1'] = collections.deque([time.monotonic()] * 28)
        assert self._call(env, 1, CLIENT_MAC) is None
        assert env.emitted[-1]['error']['data']['category'] == 'rate_limit'
        assert not env.proxy.rate_history.get('fgt') and len(env.proxy.rate_history['sw1']) == 28
        # The enrolled request limit caps the REST plan as well.
        (tmp_path / 'capped').mkdir()
        capped = self._proxy(tmp_path / 'capped', monkeypatch, fgt_requests=base + 1)
        args, (fgt, _) = self._forwarded(self._call(capped, 1, CLIENT_MAC))
        assert fgt.fortios_rest_token == TOKEN
        assert fgt.locate_read_limit == len(capped.proxy.rate_history['fgt']) == base + 1
        # The shared LOCATE_MAX_READS cap too; the worker then stops at that cap with the token.
        (tmp_path / 'small').mkdir()
        small = self._proxy(tmp_path / 'small', monkeypatch)
        monkeypatch.setattr(small.module, 'LOCATE_MAX_READS', 4)
        args, (fgt, sw) = self._forwarded(self._call(small, 1, CLIENT_MAC))
        assert fgt.fortios_rest_token == TOKEN
        assert fgt.locate_read_limit == len(small.proxy.rate_history['fgt']) == 4
        rest = Rest(documents()).install(monkeypatch)
        result = finish(engine._locate_endpoint_run([fgt, sw], args['endpoint']))
        assert len(rest.paths) + sum(alias == 'fgt' for alias, _ in ssh.calls) <= 4
        assert result['verdict'] != 'located'


class TestLocateWifiReview50:
    """Review50 N1/N2 regressions. Same public path as TestProxyWifiLocate (reused by
    composition, not inheritance): real Proxy.request -> endpoint_worker.decode ->
    engine._locate_endpoint_run over the derived replay transports above. The changes
    below (an HTTP status on the third GET, AP identities in the managed_ap document)
    are explicitly derived replay, not a new live measurement."""

    @staticmethod
    def _public(tmp_path, monkeypatch, endpoint):
        public = TestProxyWifiLocate
        env = public._proxy(tmp_path, monkeypatch)
        forward = public._call(env, 1, endpoint)
        assert forward is not None, env.emitted
        args, auths = public._forwarded(forward)
        assert auths[0].fortios_rest_token == TOKEN and args['endpoint'] == endpoint
        return args, auths

    @staticmethod
    def _identity_gap(status, code):
        return {'vantage': 'fgt', 'table': 'wifi_device_identity', 'reason': 'rest_unavailable',
                'error_code': code, 'http_status': status, 'failed_step': r.DEVICES}

    @pytest.mark.parametrize('status,code', [(403, 'authorization_failed'), (503, 'http_server_error')])
    def test_failed_device_identity_read_is_visible_and_not_complete(
            self, tmp_path, monkeypatch, audit, ssh, status, code):
        args, auths = self._public(tmp_path, monkeypatch, CLIENT_MAC)
        rest = Rest(documents(), status={r.DEVICES: status}).install(monkeypatch)
        result = finish(engine._locate_endpoint_run(auths, args['endpoint']))
        assert rest.paths == [CLIENT, MANAGED_AP, r.DEVICES]
        # The failed planned read is reported with its controller, endpoint and HTTP diagnosis.
        assert result['missing'] == [self._identity_gap(status, code)], result['missing']
        assert result['verdict'] == 'incomplete' and result['coverage']['complete'] is False
        assert 'fgt' in result['coverage']['unfinished_targets']
        controller = [v for v in result['vantage'] if v['target'] == 'fgt' and v['table'] == 'wifi_station']
        assert len(controller) == 1 and controller[0]['status'] == 'partial'
        # The valid station/AP/radio facts and the AP backhaul stay readable, separately from the client.
        wireless = result['wireless']
        assert wireless['status'] == 'associated' and wireless['controller'] == 'fgt'
        assert wireless['client'] == {'mac': CLIENT_MAC, 'ip': CLIENT_IP, 'ssid': 'vap-name-2'}
        assert wireless['ap'] == {'id': 'name-1', 'serial': 'name-1', 'name': 'name-1', 'management_ip': AP_IP}
        assert wireless['radio'] == 2
        assert wireless['ap_location']['verdict'] == 'located'
        assert wireless['ap_port'] == {'vantage': 'sw1', 'port': 'GigabitEthernet0/3', 'vlan_id': 10,
                                       'role': 'edge_behind_ap'}
        assert result['findings'] == [] and result['own_interfaces'] == [] and result['neighbors_l3'] == []
        assert TOKEN not in json.dumps(result['missing']) and TOKEN not in json.dumps(audit, default=str)

    def test_failed_device_identity_read_keeps_a_proven_wired_location(self, tmp_path, monkeypatch, audit, ssh):
        args, auths = self._public(tmp_path, monkeypatch, AP_IP)
        rest = Rest(documents(), status={r.DEVICES: 403}).install(monkeypatch)
        result = finish(engine._locate_endpoint_run(auths, args['endpoint']))
        assert rest.paths == [CLIENT, MANAGED_AP, r.DEVICES]
        # No Wi-Fi station for this endpoint: the wired verdict stands, the failed read is admitted.
        assert result['verdict'] == 'located' and result['findings'][0]['port'] == 'GigabitEthernet0/3'
        assert self._identity_gap(403, 'authorization_failed') in result['missing']
        assert result['coverage']['complete'] is False
        assert result['wireless']['status'] == 'not_in_station_table'

    def test_one_station_with_two_matching_aps_is_ambiguous_not_unjoined(self, tmp_path, monkeypatch, audit, ssh):
        args, auths = self._public(tmp_path, monkeypatch, CLIENT_MAC)
        docs = documents()
        first, second = docs[MANAGED_AP]['results'][:2]
        # station ap_id 'name-1': AP1 matches by serial/wtp_id, AP2 by name, with another serial and IP.
        first['name'] = 'derived-ap-by-serial'
        assert (first['serial'], first['wtp_id']) == ('name-1', 'name-1')
        second.update(name='name-1', local_addr='192.0.2.11')
        assert (second['serial'], second['wtp_id']) == ('name-10', 'name-10')
        assert sum(s.get('wtp_id') == 'name-1' and s['mac'] == CLIENT_MAC for s in docs[CLIENT]['results']) == 1
        rest = Rest(docs).install(monkeypatch)
        result = finish(engine._locate_endpoint_run(auths, args['endpoint']))
        assert rest.paths == [CLIENT, MANAGED_AP, r.DEVICES]
        assert result['verdict'] == 'ambiguous', result
        wireless = result['wireless']
        assert wireless['status'] == 'ambiguous'
        assert sorted((c['ap']['serial'], c['ap']['name'], c['ap']['management_ip']) for c in wireless['candidates']) == [
            ('name-1', 'derived-ap-by-serial', AP_IP), ('name-10', 'name-1', '192.0.2.11')]
        assert all(c['client']['mac'] == CLIENT_MAC and c['radio'] == 2 and c['joined'] for c in wireless['candidates'])
        reasons = {(m['table'], m['reason']) for m in result['missing']}
        assert ('wifi_ap', 'multiple_ap_matches') in reasons
        assert ('wifi_ap', 'ap_not_joined') not in reasons
        assert ('wifi_station', 'multiple_station_candidates') not in reasons
        # No wired lookup over an arbitrarily chosen AP, and no AP port presented as the client's.
        assert ssh.calls == [] and wireless['ap_location'] is None and wireless['ap_port'] is None
        assert result['findings'] == [] and result['coverage']['complete'] is False
