"""G52 public proxy/engine tests over measured IOSv output; only SSH is faked."""
import json
from pathlib import Path
import pytest
from netops_helper import engine
from netops_helper.auth import TargetAuth
from netops_helper.read_policy import render_read_query, _validate_query_command

HERE = Path(__file__).parent
FIXTURES = HERE / 'fixtures/real/cisco_ios/iosv_15.9.3M12_g52'
VERSION = HERE / 'fixtures/real/cisco_ios/iosv_15.9.3M12_g51/version.out'
CASES = [
    ('ping', {'address':'192.0.2.1'}, 'ping 192.0.2.1 repeat 5 timeout 1'),
    ('ping_source', {'address':'192.0.2.1','source':'Loopback0'}, 'ping 192.0.2.1 source Loopback0 repeat 5 timeout 1'),
    ('ping_vrf', {'address':'192.0.2.1','vrf':'blue'}, 'ping vrf blue 192.0.2.1 repeat 5 timeout 1'),
    ('ping_vrf_source', {'address':'192.0.2.1','vrf':'blue','source':'Loopback52'}, 'ping vrf blue 192.0.2.1 source Loopback52 repeat 5 timeout 1'),
    ('ping_ipv6', {'address':'2001:db8:1::1'}, 'ping ipv6 2001:db8:1::1 repeat 5 timeout 1'),
    ('ping_ipv6_source', {'address':'2001:db8:1::1','source':'Loopback53'}, 'ping ipv6 2001:db8:1::1 source Loopback53 repeat 5 timeout 1'),
    ('traceroute', {'address':'192.0.2.1'}, 'traceroute 192.0.2.1 numeric timeout 1 probe 1 ttl 1 5'),
    ('traceroute_source', {'address':'192.0.2.1','source':'Loopback0'}, 'traceroute 192.0.2.1 source Loopback0 numeric timeout 1 probe 1 ttl 1 5'),
    ('traceroute_vrf', {'address':'192.0.2.1','vrf':'blue'}, 'traceroute vrf blue 192.0.2.1 numeric timeout 1 probe 1 ttl 1 5'),
    ('traceroute_vrf_source', {'address':'192.0.2.1','vrf':'blue','source':'Loopback52'}, 'traceroute vrf blue 192.0.2.1 source Loopback52 numeric timeout 1 probe 1 ttl 1 5'),
]
# 464-r2: d-iosv now has VRF blue (Loopback52) and global IPv6 (Loopback53); measured loss/hop-limit
# captures target an unused address in the same prefix.
LOSS_CASES = [
    ('ping_vrf', 'ping_vrf_loss', {'address':'192.0.2.2','vrf':'blue'}),
    ('ping_vrf_source', 'ping_vrf_source_loss', {'address':'192.0.2.2','vrf':'blue','source':'Loopback52'}),
    ('ping_ipv6', 'ping_ipv6_loss', {'address':'2001:db8:1::2'}),
    ('ping_ipv6_source', 'ping_ipv6_source_loss', {'address':'2001:db8:1::2','source':'Loopback53'}),
    ('traceroute_vrf', 'traceroute_vrf_timeout', {'address':'192.0.2.2','vrf':'blue'}),
    ('traceroute_vrf_source', 'traceroute_vrf_source_timeout', {'address':'192.0.2.2','vrf':'blue','source':'Loopback52'}),
]
# Real refusals captured before the lab had any VRF/IPv6 (464): kept as unconfigured-device evidence.
UNCONFIGURED_CASES = [
    ('ping_vrf', {'address':'192.0.2.1','vrf':'G52-MISSING'}),
    ('ping_vrf_source', {'address':'192.0.2.1','vrf':'G52-MISSING','source':'Loopback0'}),
    ('ping_ipv6', {'address':'::1'}),
    ('ping_ipv6_source', {'address':'::1','source':'Loopback0'}),
    ('traceroute_vrf', {'address':'192.0.2.1','vrf':'G52-MISSING'}),
    ('traceroute_vrf_source', {'address':'192.0.2.1','vrf':'G52-MISSING','source':'Loopback0'}),
]
INVENTORY = {'addresses':['192.0.2.1','192.0.2.2','192.0.2.254','::1','2001:db8:1::1','2001:db8:1::2'],
             'interfaces':['Loopback0','Loopback52','Loopback53'], 'vrfs':['G52-MISSING','blue']}


def gateway(tmp_path, monkeypatch, body):
    import test_proxy_contracts as contracts
    module = contracts._load_proxy()
    inventory, _, _, _ = contracts._configure(module, tmp_path)
    section = contracts._section()
    section.update(ssh_platform='cisco_ios', device_types=['router'], enabled_queries=[c[0] for c in CASES], read_inventory=INVENTORY)
    section['egress']['tcp_ports'].append(22)
    contracts._write(inventory, contracts._inventory(contracts._device(section, 'cisco_ios')))
    calls = []
    def exec_read(auth, platform, command):
        assert command == 'show version'
        return 0, VERSION.read_text()
    def prompt_read(auth, command):
        calls.append(command)
        return None, body
    monkeypatch.setattr(engine, '_exec_read', exec_read)
    monkeypatch.setattr(engine, '_ios_probe_prompt', prompt_read)
    monkeypatch.setattr(engine, 'record', lambda *a, **k: None)
    engine._SSH_PAGE_CACHE.clear()
    return contracts, module.Proxy(), calls


def read(ctx, query, params):
    contracts, proxy, calls = ctx
    forwarded = proxy.request(contracts._request(1, 'ssh_read', {'target':'device-a','platform':'cisco_ios','query':query,'parameters':params}))
    assert forwarded is not None
    args = json.loads(forwarded)['params']['arguments']
    auth = TargetAuth.decode(args['target'], args['auth_context'])
    return engine.ssh_read(auth, 'cisco_ios', query, params, 0, 48000)


@pytest.mark.parametrize('name,params,command', CASES)
def test_real_admin_output(tmp_path, monkeypatch, name, params, command):
    body = (FIXTURES/(name+'.out')).read_text()
    ctx = gateway(tmp_path, monkeypatch, body)
    result = read(ctx, name, params)
    assert ctx[2] == [command]
    assert result['untrusted_device_output'].strip() == body.strip()
    assert result['normalized']['coverage']['complete']
    if name.startswith('ping'):
        assert result['status'] == 'ok'
        assert result['probe']['sent'] == result['probe']['received'] == 5
        assert result['probe']['reachable']
        assert result['probe']['loss_percent'] == 0
    else:
        assert result['status'] == 'ok'
        assert result['probe']['reached_destination']
        assert result['probe']['max_hops'] == 5


@pytest.mark.parametrize('name,fixture,params', LOSS_CASES)
def test_real_vrf_ipv6_loss_and_hop_limit(tmp_path, monkeypatch, name, fixture, params):
    body = (FIXTURES/(fixture+'.out')).read_text()
    ctx = gateway(tmp_path, monkeypatch, body)
    result = read(ctx, name, params)
    assert ctx[2] == [render_read_query('cisco_ios', name, params, INVENTORY)[1]]
    assert result['status'] == 'ok'
    assert result['normalized']['coverage']['complete']
    if name.startswith('ping'):
        assert result['probe']['sent'] == 5 and result['probe']['received'] == 0
        assert result['probe']['loss_percent'] == 100 and not result['probe']['reachable']
    else:
        assert [hop['hop'] for hop in result['probe']['hops']] == [1, 2, 3, 4, 5]
        assert [hop['result'] for hop in result['probe']['hops'][1:]] == ['*'] * 4
        assert not result['probe']['reached_destination']


@pytest.mark.parametrize('name,params', UNCONFIGURED_CASES)
def test_real_unconfigured_vrf_ipv6_refusal(tmp_path, monkeypatch, name, params):
    body = (FIXTURES/'unconfigured'/(name+'.out')).read_text()
    result = read(gateway(tmp_path, monkeypatch, body), name, params)
    assert result['status'] in {'permission_denied','not_configured','unsupported'}
    assert not result['normalized']['coverage']['complete']


@pytest.mark.parametrize('name,params,command', CASES)
def test_real_ro_refusal(tmp_path, monkeypatch, name, params, command):
    body = (FIXTURES/'ro'/(name+'.out')).read_text()
    result = read(gateway(tmp_path, monkeypatch, body), name, params)
    assert result['status'] == 'permission_denied'
    assert not result['ok']


@pytest.mark.parametrize('name,params,command', [CASES[i] for i in (0, 1, 2, 4, 6, 7, 8)])
@pytest.mark.parametrize('kind', ['header','pager','refusal'])
def test_incomplete_and_refused(tmp_path, monkeypatch, name, params, command, kind):
    real = (FIXTURES/(name+'.out')).read_text()
    body = real.split('Sending')[0] if name.startswith('ping') else real.split('  1 ')[0]
    if kind == 'pager': body = real+'\n--More--'
    if kind == 'refusal': body = '% Authorization failed.\n'  # explicit derived negative
    result = read(gateway(tmp_path, monkeypatch, body), name, params)
    assert result['status'] == {'header':'unparsed','pager':'truncated','refusal':'permission_denied'}[kind]
    assert not result['normalized']['coverage']['complete']


def test_measured_packet_loss_is_completed_probe(tmp_path, monkeypatch):
    result = read(gateway(tmp_path, monkeypatch, (FIXTURES/'ping_loss.out').read_text()), 'ping_source', {'address':'192.0.2.254','source':'Loopback0'})
    assert result['status'] == 'ok'
    assert result['normalized']['coverage']['complete']
    assert result['probe']['sent'] == 5 and result['probe']['received'] == 0
    assert result['probe']['loss_percent'] == 100 and not result['probe']['reachable']


def test_measured_trace_hop_limit(tmp_path, monkeypatch):
    result = read(gateway(tmp_path, monkeypatch, (FIXTURES/'traceroute_timeout.out').read_text()), 'traceroute_source', {'address':'192.0.2.254','source':'Loopback0'})
    assert result['status'] == 'ok'
    assert len(result['probe']['hops']) == 5
    assert not result['probe']['reached_destination']


@pytest.mark.parametrize('name,params,command', CASES)
def test_inventory_bound_and_no_extra_options(name, params, command):
    assert render_read_query('cisco_ios',name,params,INVENTORY)[1] == command
    for field in params:
        for value in ('not-enrolled','Loopback0;reload','x\nshow version'):
            with pytest.raises(ValueError):
                render_read_query('cisco_ios',name,{**params,field:value},INVENTORY)
    with pytest.raises(ValueError):
        render_read_query('cisco_ios',name,{**params,'repeat':'999'},INVENTORY)


@pytest.mark.parametrize('command', ['ping {address} repeat 500 timeout 1', 'traceroute {address}', 'ping {address} repeat 5 timeout 0', 'ping {address}; reload'])
def test_no_unreviewed_probe_template(command):
    with pytest.raises(RuntimeError): _validate_query_command('cisco_ios',command)
