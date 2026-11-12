"""Shared real proxy/engine/worker replay setup for A19/A20 regressions."""
import json
from pathlib import Path

from netops_helper import engine, endpoint_worker, proxy as p
import test_proxy_contracts as c
from conftest import KNOWN_HOSTS_LINE


def device(alias, profile, queries, **inventory):
    section = c._section()
    section.update(ssh_platform={'fortinet': 'fortios', 'extreme_exos': 'exos'}.get(profile, profile), device_types=['switch', 'router'] if profile != 'fortinet' else ['firewall'],
                   enabled_queries=queries)
    section['read_inventory'].update(inventory)
    return {**c._device(section, 'fortios' if profile == 'fortinet' else profile), 'name': alias}


def configure(tmp_path, monkeypatch, devices, outputs, *, virtual=False, late=False,
              clock_start=0.0, capture_seconds=5.6):
    inventory, _, _, _ = c._configure(p, tmp_path)
    # Distinct enrolled hosts give independent connection lanes.
    for index, item in enumerate(devices):
        item['address'] = '192.0.2.' + str(10 + index)
        item['helper']['egress']['addresses'] = [item['address']]
    c._write(inventory, c._inventory(*devices))
    audit, wire = tmp_path / 'audit.jsonl', tmp_path / 'wire.jsonl'
    monkeypatch.setenv('NETOPS_HELPER_AUDIT_PATH', str(audit))
    from netops_helper import audit as audit_module
    from netops_core.audit import Recorder
    monkeypatch.setattr(audit_module, '_RECORDER', Recorder(audit, 'helper'))
    if virtual:
        # The request deadline and child Budget must use the same clock domain.
        # Replace only this module's clock, never the process-wide time module:
        # selectors still provide the real subprocess watchdog.
        from types import SimpleNamespace
        monkeypatch.setattr(endpoint_worker, 'time', SimpleNamespace(monotonic=lambda: clock_start))
    code = '''
import json, threading, time
from pathlib import Path
from types import SimpleNamespace
from netops_helper import engine, locate
outputs, wire = %r, %r
engine.host_key_line = lambda *args: %r
engine._lane_directory = lambda: Path(%r)
clock = [%r]
capture_seconds = %r
clock_trace = Path(wire).with_suffix(".clock.jsonl")
if %r:
    engine._now = lambda: clock[0]
    def pause(seconds):
        with clock_trace.open('a') as handle:
            handle.write(json.dumps({'started': clock[0], 'seconds': seconds}) + '\\n')
        clock[0] += seconds
    engine._sleep = pause
    original_budget = locate.Budget
    locate.Budget = lambda: original_budget(lambda: clock[0])
mac_seen = threading.Event()
correlated = threading.Event()
if %r:
    original_run = locate.run
    def run(auths, endpoint, read, budget, progress, identify):
        def report(result):
            if result.get('findings'):
                correlated.set()
            progress(result)
        return original_run(auths, endpoint, read, budget, report, identify)
    locate.run = run
def transport(address, port, login, credential, hostkey, command, **kwargs):
    if %r and command == 'show ip arp' and address == '192.0.2.11':
        assert mac_seen.wait(5), 'MAC pipeline did not start'
        assert correlated.wait(10), 'first MAC was not correlated before the late ARP'
    started = engine._now()
    text = outputs[address][command]
    spent = min(capture_seconds, engine._read_timeout(capture_seconds)) if %r else 0
    clock[0] += spent
    with open(wire, 'a') as handle:
        handle.write(json.dumps({'host': address, 'command': command, 'started': started, 'capture_seconds': spent}) + '\\n')
    if command == 'show mac address-table':
        mac_seen.set()
    if %r and spent < capture_seconds:
        raise TimeoutError('fixture capture reached the shared deadline')
    if text is None:
        raise TimeoutError('fixture SSH timeout')
    return SimpleNamespace(rc=0, stdout=text.encode())
engine.core_ssh.run_command = transport
''' % ({item['address']: outputs[item['name']] for item in devices}, str(wire), KNOWN_HOSTS_LINE,
       str(tmp_path / 'lanes'), clock_start, capture_seconds, virtual, late, late, virtual, virtual)
    bootstrap = endpoint_worker.command()
    roots = bootstrap[-1].split('; from netops_helper.endpoint_worker import main; main()')[0]
    monkeypatch.setattr(endpoint_worker, 'command', lambda: bootstrap[:-1] + [
        roots + '\n' + code + '\nfrom netops_helper.endpoint_worker import main\nmain()'])
    return p.Proxy(), code, wire


def locate(proxy, endpoint, aliases):
    forwarded = proxy.request(c._request(1, 'locate_endpoint', {'targets': aliases, 'endpoint': endpoint}))
    assert forwarded is not None
    return engine.locate_endpoint(**json.loads(forwarded)['params']['arguments'])


def switch(proxy, code, monkeypatch, arguments):
    # switch_read runs in the engine process; it has no endpoint subprocess.
    namespace = {}
    exec(code, namespace)
    forwarded = proxy.request(c._request(1, 'switch_read', {'target': 'gate', **arguments}))
    assert forwarded is not None
    from netops_helper.auth import TargetAuth
    args = json.loads(forwarded)['params']['arguments']
    auth = TargetAuth.decode(args.pop('target'), args.pop('auth_context'))
    return engine.switch_read(auth, **args)
