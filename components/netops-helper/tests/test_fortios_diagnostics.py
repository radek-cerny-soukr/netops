import threading
from types import SimpleNamespace

import pytest

from netops_helper import fortios_diagnostics as d

IP = "192.0.2.183"
INTERFACE = "port2"


class Auth:
    fortios_output_standard_verified = True
    read_inventory = {"diagnostic_recipes": ["ping"], "addresses": [IP], "interfaces": [INTERFACE]}
    def require_ssh_query(self, platform, query):
        assert (platform, query) == ("fortinet", "system_status")


class Shell:
    def __init__(self, recipe):
        self.recipe = recipe
        self.commands = []
        self.interrupted = threading.Event()
        self.options = {"Repeat Count":"5","Timeout":"2","Interval":"1","Data Size":"56",
                        "Adaptive Ping":"disable","Interface":"auto","Source Address":"auto","Use SD-WAN":"no"}
        self.mapping = dict(zip(("repeat-count","timeout","interval","data-size","adaptive-ping","interface","source","use-sdwan"), self.options))
        self.filter = "any"
        self.enabled = False
        self.fail = None
        self.current_vdom = "VD1"
        self.vdom_inventory = 'config system vdom-property\n edit "root"\n next\n edit "VD1"\n next\nend'
    def navigate(self, command):
        self.commands.append(command)
        if command.startswith('edit "'):
            self.current_vdom=command.split('"')[1]
        return ""
    def interrupt(self):
        self.interrupted.set()
    def listen(self, timeout):
        assert self.interrupted.wait(timeout)
        return "bounded flow data"
    def command(self, command, timeout=10):
        self.commands.append(command)
        if command == self.fail:
            raise RuntimeError("injected transport failure")
        if command == "get system status":
            return 'Version: FortiGate-VM64-KVM v7.6.7,build3704,240101\nCurrent virtual domain: '+self.current_vdom
        if command == "show full-configuration system vdom-property":
            return self.vdom_inventory
        if command.startswith('show full-configuration system interface "'):
            return 'config system interface\n edit "port2"\n set vdom "VD1"\n next\nend'
        if command.startswith("diagnose netlink interface list "):
            return "if=port2 family=00 type=1 index=4"
        if command == "execute ping-options view-settings":
            return "\n".join(k+": "+v for k,v in self.options.items())
        if command.startswith("execute ping-options "):
            option, value = command.split()[2:]
            self.options[self.mapping[option]] = value
        if command == "diagnose sys session filter":
            return "session filter:\n"+"\n".join(k+": "+(self.filter if k=="dest ip" else "any") for k in sorted(d.SESSION_FIELDS))
        if command == "diagnose debug flow filter":
            return "\n".join(k+": "+(self.filter if k=="Host addr" else "any") for k in sorted(d.FLOW_FIELDS))
        if command.endswith("filter clear"):
            self.filter = "any"
        if "filter dst " in command or "filter addr " in command:
            self.filter = IP
        if command == "diagnose debug enable":
            self.enabled = True
        if command == "diagnose debug disable":
            self.enabled = False
        if command == "diagnose debug info":
            return "debug output: "+("enable" if self.enabled else "disable")
        return "untrusted device output"


class Library:
    identity = ("FortiGate-VM64-KVM","7.6.7","3704")
    def require_identity(self, *identity):
        if identity != self.identity:
            raise ValueError("identity mismatch")


@pytest.mark.parametrize("kwargs", [
    {"recipe":"reset"},{"address":"192.0.2.183;reboot"},{"address":"224.0.0.1"},
    {"address":"0.0.0.0"},{"address":"255.255.255.255"},{"address":"::1"},
    {"interface":"any"},{"interface":"port2\nend"},{"interface":"port2;reset"},
    {"count":0},{"count":9},{"count":True},{"timeout":0},{"timeout":11},
    {"timeout":1.5},{"max_bytes":999},{"max_bytes":16001},
    {"recipe":"traceroute","count":4},
])
def test_invalid_request(kwargs):
    values = dict(recipe="ping",address=IP,interface=INTERFACE,count=3,timeout=1,max_bytes=16000)
    values.update(kwargs)
    with pytest.raises(ValueError):
        d.validate(**values)


@pytest.mark.parametrize("category", ["diagnostic_recipes","addresses","interfaces"])
def test_missing_grant(category):
    auth = Auth()
    auth.read_inventory = {k:v for k,v in Auth.read_inventory.items() if k!=category}
    with pytest.raises(ValueError):
        d.authorize(auth,"ping",IP,INTERFACE)


def test_ping_restores_every_changed_option():
    shell = Shell("ping")
    before = dict(shell.options)
    result, timeout = d.run(shell,Library(),"ping",IP,INTERFACE,2,1)
    assert result == "untrusted device output" and not timeout
    assert shell.options == before


def test_ping_transport_failure_restores_options():
    shell = Shell("ping")
    before = dict(shell.options)
    shell.fail = "execute ping "+IP
    with pytest.raises(RuntimeError):
        d.run(shell,Library(),"ping",IP,INTERFACE,2,1)
    assert shell.options == before


def test_keyboard_interrupt_restores_options():
    shell = Shell("ping")
    before = dict(shell.options)
    original = shell.command
    def command(value, timeout=10):
        if value == "execute ping "+IP:
            raise KeyboardInterrupt()
        return original(value,timeout)
    shell.command = command
    with pytest.raises(KeyboardInterrupt):
        d.run(shell,Library(),"ping",IP,INTERFACE,2,1)
    assert shell.options == before


def test_filtered_sessions_restore():
    shell = Shell("sessions")
    d.run(shell,Library(),"sessions",IP,INTERFACE,2,1)
    assert shell.filter == "any"
    assert "diagnose sys session filter dst "+IP in shell.commands
    assert "diagnose sys session filter proto 1" in shell.commands


@pytest.mark.parametrize("recipe", ["sessions","flow"])
def test_foreign_filter_is_not_replaced(recipe):
    shell = Shell(recipe)
    shell.filter = "192.0.2.99"
    with pytest.raises(ValueError):
        d.run(shell,Library(),recipe,IP,INTERFACE,2,1)
    assert shell.filter == "192.0.2.99"
    assert not any(command.endswith(" clear") for command in shell.commands)


def test_flow_deadline_and_cleanup():
    shell = Shell("flow")
    result, timed_out = d.run(shell,Library(),"flow",IP,INTERFACE,2,1)
    assert result == "bounded flow data" and timed_out
    assert shell.filter == "any" and not shell.enabled
    assert not any(command.startswith("diagnose debug duration") for command in shell.commands)
    assert "diagnose debug flow trace start 2" in shell.commands


def test_existing_debug_is_not_disabled():
    shell = Shell("flow")
    shell.enabled = True
    with pytest.raises(ValueError):
        d.run(shell,Library(),"flow",IP,INTERFACE,2,1)
    assert shell.enabled
    assert "diagnose debug disable" not in shell.commands


def test_unmeasured_identity_never_sets_options():
    shell = Shell("ping")
    library = Library()
    library.identity = ("FortiGate-60F","7.6.7","3704")
    with pytest.raises(ValueError):
        d.run(shell,library,"ping",IP,INTERFACE,2,1)
    assert shell.commands == ["get system status"]


def test_missing_live_interface_never_sets_options():
    shell = Shell("ping")
    with pytest.raises(ValueError):
        d.run(shell,Library(),"ping",IP,"port3",2,1)
    assert not any("ping-options" in command for command in shell.commands)


def test_failed_cleanup_still_attempts_every_other_step():
    shell = Shell("flow")
    shell.fail = "diagnose debug disable"
    with pytest.raises(ValueError):
        d.run(shell,Library(),"flow",IP,INTERFACE,2,1)
    assert "diagnose debug flow trace stop" in shell.commands
    assert "diagnose debug flow filter clear" in shell.commands
    assert shell.filter == "any"


def test_diagnostic_audit_fields_are_accepted_by_core(tmp_path):
    from netops_core.audit import Recorder
    from netops_helper.engine import _audit_fields
    recorder = Recorder(tmp_path/"audit.jsonl","helper")
    values = _audit_fields({"recipe":"flow","count":2,"timeout":5,"max_bytes":1000}, {})
    recorder.record("fortios_diagnostics", **values)
    import json
    event = json.loads(recorder.path().read_text())
    assert event["recipe"] == "flow" and event["timeout"] == 5


@pytest.mark.parametrize("vdom", ["VD1\nend", 'VD1" next', "x"*32, 3])
def test_invalid_vdom(vdom):
    with pytest.raises(ValueError):
        d.validate("ping",IP,INTERFACE,1,1,1000,vdom)


def test_vdom_requires_an_independent_grant():
    with pytest.raises(ValueError):
        d.authorize(Auth(),"ping",IP,INTERFACE,"VD1")


def test_existing_vdom_is_verified_before_edit():
    shell=Shell("ping")
    shell.current_vdom="root"
    d.run(shell,Library(),"ping",IP,INTERFACE,1,1,"VD1")
    assert shell.commands.index("show full-configuration system vdom-property") < shell.commands.index('edit "VD1"')


def test_nonexistent_vdom_is_never_edited():
    shell=Shell("ping")
    with pytest.raises(ValueError):
        d.run(shell,Library(),"ping",IP,INTERFACE,1,1,"MISSING")
    assert not any(command.startswith("edit ") for command in shell.commands)


def test_incomplete_vdom_inventory_is_never_edited():
    shell=Shell("ping")
    shell.vdom_inventory='config system vdom-property\n edit "VD1"'
    with pytest.raises(ValueError):
        d.run(shell,Library(),"ping",IP,INTERFACE,1,1,"VD1")
    assert not any(command.startswith("edit ") for command in shell.commands)


def test_interface_in_another_vdom_is_refused_before_options():
    shell=Shell("ping")
    shell.current_vdom="root"
    with pytest.raises(ValueError):
        d.run(shell,Library(),"ping",IP,INTERFACE,1,1)
    assert not any("ping-options" in command for command in shell.commands)
    assert not any(command.startswith("edit ") for command in shell.commands)


def load_gate():
    import importlib.util
    root=__import__("pathlib").Path(__file__).resolve().parents[1]
    path=root/"scripts/check_public_release.py"
    spec=importlib.util.spec_from_file_location("diagnostic_gate",path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return root,module


@pytest.mark.parametrize("old,new", [
    ("diagnostics.authorize(auth, recipe, address, interface, vdom)", "diagnostics.authorize(auth, recipe, address, interface, None)"),
    ("reader.binding(auth)", "reader.binding(None)"),
    ("@_audit_device_call\ndef fortios_diagnostics", "def fortios_diagnostics"),
])
def test_release_gate_rejects_diagnostic_boundary_mutations(old,new):
    import ast
    root,gate=load_gate()
    text=(root/"src/netops_helper/engine.py").read_text()
    assert gate._diagnostic_wrapper_allowed(ast.parse(text))
    assert old in text
    assert not gate._diagnostic_wrapper_allowed(ast.parse(text.replace(old,new,1)))


@pytest.mark.parametrize("old,new", [
    ("table is None or domain not in table.entries", "table is None"),
    ("show full-configuration system vdom-property", "show full-configuration"),
    ("domain not in table.entries", "False"),
])
def test_release_gate_rejects_unverified_vdom_mutations(old,new):
    import ast
    root,gate=load_gate()
    text=(root/"src/netops_helper/fortios_diagnostics.py").read_text()
    assert gate._diagnostic_vdom_allowed(ast.parse(text))
    assert old in text
    assert not gate._diagnostic_vdom_allowed(ast.parse(text.replace(old,new,1)))
