from contextlib import contextmanager
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
        self.flow_values = {field: "any" for field in d.FLOW_FIELDS}
        self.filter_values = {field: "any" for field in d.SESSION_FIELDS}
        self.enabled = False
        self.timestamp = None
        self.fail = None
        self.status_line = "Version: FortiGate-VM64-KVM v7.6.7,build3704,240101"
        self.current_vdom = "root"
        self.mode = "disable"
        self.interface_vdom = "root"
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
            return self.status_line+"\nVirtual domain configuration: "+self.mode+"\nCurrent virtual domain: "+self.current_vdom
        if command == "show full-configuration system vdom-property":
            return self.vdom_inventory
        if command.startswith('show full-configuration system interface "'):
            return 'config system interface\n edit "port2"\n set vdom "'+self.interface_vdom+'"\n next\nend'
        if command.startswith("diagnose netlink interface list "):
            return "if=port2 family=00 type=1 index=4"
        if command == "execute ping-options view-settings":
            return "\n".join(k+": "+v for k,v in self.options.items())
        if command.startswith("execute ping-options "):
            option, value = command.split()[2:]
            self.options[self.mapping[option]] = value
        if command == "diagnose sys session filter":
            return "session filter:\n"+"\n".join(k+": "+(self.filter if k=="dest ip" and self.filter!="any" else self.filter_values[k]) for k in sorted(d.SESSION_FIELDS))
        if command == "diagnose debug flow filter":
            return "\n".join(k+": "+(self.filter if k=="Host addr" else self.flow_values[k]) for k in sorted(d.FLOW_FIELDS))
        if command.endswith("filter clear"):
            self.filter = "any"
            if command == "diagnose debug flow filter clear":
                self.flow_values = {field: "any" for field in d.FLOW_FIELDS}
            if command == "diagnose sys session filter clear":
                self.filter_values = {field: "any" for field in d.SESSION_FIELDS}
        if "filter dst " in command or "filter addr " in command:
            self.filter = command.rsplit(" ", 1)[-1]
            self.filter_values["dest ip"] = self.filter
        for suffix, field in ((" src ","source ip"),(" sport ","source port"),
                              (" dport ","dest port"),(" proto ","proto")):
            if suffix in command:
                self.filter_values[field] = command.rsplit(" ", 1)[-1]
        for selector, field in (("saddr", "Host saddr"), ("daddr", "Host daddr"),
                                ("sport", "sport"), ("dport", "dport"), ("proto", "proto")):
            if command.startswith("diagnose debug flow filter "+selector+" "):
                self.flow_values[field] = command.rsplit(" ", 1)[-1]
        if command == "diagnose debug enable":
            self.enabled = True
        if command == "diagnose debug disable":
            self.enabled = False
        if command == "diagnose debug info":
            return ("debug output:\t\t"+("enable" if self.enabled else "disable")+
                    ("\nconsole timestamp:\t"+self.timestamp if self.timestamp else ""))
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
    result, timeout, identity, domain = d.run(shell,"ping",IP,INTERFACE,2,1)
    assert result == "untrusted device output" and not timeout
    assert shell.options == before


def test_ping_transport_failure_restores_options():
    shell = Shell("ping")
    before = dict(shell.options)
    shell.fail = "execute ping "+IP
    with pytest.raises(RuntimeError):
        d.run(shell,"ping",IP,INTERFACE,2,1)
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
        d.run(shell,"ping",IP,INTERFACE,2,1)
    assert shell.options == before


@pytest.mark.parametrize("protocol", [6, 17])
def test_filtered_sessions_restore(protocol):
    source = "192.0.2.184"
    for status_line, range_bounds in (
        ("Version: FortiGate-VM64 v8.0.2,build0251,240101", False),
        ("Version: FortiGate-80F v8.0.2,build0251,260928 (GA.F)", False),
        ("Version: FortiGate-60F v7.6.8,build3744,240101", True),
    ):
        shell = Shell("sessions")
        shell.status_line = status_line
        d.run(shell,"sessions",IP,INTERFACE,2,1,
              source_address=source,source_port=49152,destination_port=443,protocol=protocol)
        assert shell.filter == "any"
        expected = []
        for selector, value in (("src", source), ("dst", IP), ("sport", "49152"),
                                ("dport", "443"), ("proto", str(protocol))):
            expected.append("diagnose sys session filter " + selector + " " +
                            (value + " " + value if range_bounds else value))
        setters = [command for command in shell.commands
                   if command.startswith("diagnose sys session filter ") and not command.endswith(" clear")]
        assert setters == expected
        assert "diagnose sys session list" in shell.commands


@pytest.mark.parametrize("recipe", ["sessions","flow"])
def test_foreign_filter_is_not_replaced(recipe):
    shell = Shell(recipe)
    shell.filter = "192.0.2.99"
    with pytest.raises(ValueError):
        d.run(shell,recipe,IP,INTERFACE,2,1)
    assert shell.filter == "192.0.2.99"
    assert not any(command.endswith(" clear") for command in shell.commands)


@pytest.mark.parametrize("protocol", [6, 17])
def test_flow_deadline_and_cleanup(protocol):
    from netops_helper import proxy
    source = "192.0.2.184"
    values = dict(source_address=source, source_port=49152,
                  destination_port=443, protocol=protocol)
    d.validate("flow", IP, INTERFACE, 2, 1, 1000, **values)
    args = proxy.Proxy()._validate_tool_arguments("fortios_diagnostics", {
        "target": "fixture", "recipe": "flow", "address": IP,
        "interface": INTERFACE, "count": 2, "timeout": 1,
        "max_bytes": 1000, **values})
    assert args["protocol"] == protocol
    for status_line, range_bounds in (
        ("Version: FortiGate-VM64 v8.0.2,build0251,240101", False),
        ("Version: FortiGate-80F v8.0.2,build0251,260928 (GA.F)", False),
        ("Version: FortiGate-60F v7.6.8,build3744,240101", True),
    ):
        shell = Shell("flow")
        shell.status_line = status_line
        result, timed_out, identity, domain = d.run(shell,"flow",IP,INTERFACE,2,1, **values)
        assert result == "bounded flow data" and timed_out
        assert shell.filter == "any" and not shell.enabled
        assert all(value == "any" for value in shell.flow_values.values())
        expected = []
        for selector, value in (("saddr", source), ("daddr", IP),
                                ("sport", "49152"), ("dport", "443"),
                                ("proto", str(protocol))):
            rendered = value + " " + value if range_bounds and selector != "proto" else value
            expected.append("diagnose debug flow filter " + selector + " " + rendered)
        setters = [command for command in shell.commands
                   if command.startswith("diagnose debug flow filter ") and
                   command != "diagnose debug flow filter clear"]
        assert setters == expected
        assert shell.commands.index("diagnose debug info") < shell.commands.index(expected[0])
        assert not any(command.startswith("diagnose debug duration") for command in shell.commands)
        assert "diagnose debug flow trace start 2" in shell.commands
        assert shell.commands[-4:] == ["diagnose debug flow trace stop",
                                      "diagnose debug flow filter clear",
                                      "diagnose debug flow filter", "diagnose debug info"]


def test_existing_debug_is_not_disabled():
    shell = Shell("flow")
    shell.enabled = True
    with pytest.raises(ValueError):
        d.run(shell,"flow",IP,INTERFACE,2,1)
    assert shell.enabled
    assert not any(command.startswith(("diagnose debug flow filter ",
                                       "diagnose debug flow trace ",
                                       "diagnose debug enable",
                                       "diagnose debug disable"))
                   for command in shell.commands)


def test_unmeasured_identity_never_sets_options():
    shell = Shell("ping")
    original = shell.command
    shell.command = lambda command, timeout=10: original(command, timeout).replace("build3704", "build9999")
    with pytest.raises(ValueError):
        d.run(shell,"ping",IP,INTERFACE,2,1)
    assert shell.commands == ["get system status"]

    tuple_shell = Shell("sessions")
    with pytest.raises(ValueError, match="TCP or UDP diagnostic tuples are not qualified"):
        d.run(tuple_shell,"sessions",IP,INTERFACE,2,1,
              source_address="192.0.2.184",source_port=49152,
              destination_port=443,protocol=6)
    assert tuple_shell.commands == ["get system status"]


def test_missing_live_interface_never_sets_options():
    shell = Shell("ping")
    with pytest.raises(ValueError):
        d.run(shell,"ping",IP,"port3",2,1)
    assert not any("ping-options" in command for command in shell.commands)


def test_failed_cleanup_still_attempts_every_other_step():
    shell = Shell("flow")
    shell.fail = "diagnose debug disable"
    with pytest.raises(ValueError):
        d.run(shell,"flow",IP,INTERFACE,2,1)
    assert "diagnose debug flow trace stop" in shell.commands
    assert "diagnose debug flow filter clear" in shell.commands
    assert shell.filter == "any"


TRACE = ('id=65308 trace_id=9 func=print_pkt_detail line=6340 msg="vd-root:0 received a packet(proto=17, '
         '192.0.2.184:40641->' + IP + ':33434) tun_id=0.0.0.0 from port2. "\n'
         'id=65308 trace_id=9 func=init_ip_session_common line=6552 msg="allocate a new session-0001b3f8"\n'
         'id=65308 trace_id=10 func=print_pkt_detail line=6340 msg="vd-root:0 received a packet(proto=17, '
         '192.0.2.184:40641->' + IP + ':33434) tun_id=0.0.0.0 from port2. "\n')


class SilentFlowShell(Shell):
    def listen(self, timeout):
        assert self.interrupted.wait(timeout)
        return ""


class TraceFlowShell(Shell):
    def listen(self, timeout):
        assert self.interrupted.wait(timeout)
        return TRACE


class OverflowFlowShell(Shell):
    def listen(self, timeout):
        from netops_core.session import SessionError
        raise SessionError("the session produced more than 131072 bytes without matching any of the "
                           "1 awaited pattern(s) and was stopped", 131073)


class DeadFlowShell(OverflowFlowShell):
    def command(self, command, timeout=10):
        if "diagnose debug enable" in self.commands:
            self.commands.append(command)
            raise RuntimeError("injected closed session")
        return super().command(command, timeout)


class FlowAuth:
    alias, secrets, host_key_fingerprint, port, login, legacy_ssh = "fgt60f", (), "SHA256:" + "A" * 43, 22, "rw", False
    ssh_platform = "fortinet"
    fortios_output_standard_verified = True
    read_inventory = {"diagnostic_recipes": ["flow"], "addresses": [IP, "192.0.2.184"], "interfaces": [INTERFACE]}
    def require_ssh_query(self, platform, query):
        assert (platform, query) == ("fortinet", "system_status")


class FlowSession:
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def close(self):
        pass


EMPTY_REASONS = ("An empty trace shows neither that the traffic passes nor that it is blocked. Check that the "
                 "filter matches the real connection (addresses, ports, protocol), that this traffic passes "
                 "through this FortiGate while the call runs, and that a new connection with exactly this tuple "
                 "starts during the call: flow debug shows only packets that the CPU processes, not those of a "
                 "session offloaded to the network processor, and a client usually opens a new connection from a "
                 "new source port, so send it from the filtered source port. ICMP is not offloaded, so a flow call "
                 "without a tuple for ICMP to this address can check the path.")


def _flow_call(adc_engine, monkeypatch, shell_type):
    from netops_helper import engine
    use, _ = adc_engine
    shell = shell_type("flow")
    shell.status_line = "Version: FortiGate-60F v7.6.8,build3744,240101"
    monkeypatch.setattr(engine, "_FortiosDiagnosticShell", lambda session: shell)
    call = lambda: use(FlowSession()).fortios_diagnostics(
        FlowAuth(), "flow", IP, INTERFACE, 8, 1, 16000,
        source_address="192.0.2.184", source_port=40641, destination_port=33434, protocol=17)
    return shell, call


def _cleaned_up(shell):
    assert not shell.enabled and all(value == "any" for value in shell.flow_values.values())
    assert shell.commands[-5:] == ["diagnose debug disable", "diagnose debug flow trace stop",
                                   "diagnose debug flow filter clear", "diagnose debug flow filter",
                                   "diagnose debug info"]


FILTER = "saddr 192.0.2.184 sport 40641 daddr " + IP + " dport 33434 proto 17"


@pytest.mark.parametrize("shell_type,state,summary", [
    (SilentFlowShell, "empty", "no packet was traced for the flow filter " + FILTER + " during the 1 s window. "
                               + EMPTY_REASONS),
    (Shell, "empty", "no packet was traced for the flow filter " + FILTER + " during the 1 s window; the device "
                     "returned 17 bytes without a packet trace line. " + EMPTY_REASONS),
    (TraceFlowShell, "captured", "the device traced 2 packets (3 trace lines) for the flow filter " + FILTER +
                                 " within the 1 s window"),
])
def test_engine_flow_states_the_trace_and_still_cleans_up(adc_engine, monkeypatch, shell_type, state, summary):
    shell, call = _flow_call(adc_engine, monkeypatch, shell_type)
    result = call()
    assert result["ok"] is True and result["cleanup"] == "verified" and result["deadline_reached"]
    _cleaned_up(shell)
    assert result["trace_state"] == state
    assert result["trace_summary"] == summary


def test_engine_icmp_flow_empty_trace_names_icmp(adc_engine, monkeypatch):
    from netops_helper import engine
    use, _ = adc_engine
    shell = SilentFlowShell("flow")
    shell.status_line = "Version: FortiGate-80F v8.0.2,build0251,260928 (GA.F)"
    monkeypatch.setattr(engine, "_FortiosDiagnosticShell", lambda session: shell)
    result = use(FlowSession()).fortios_diagnostics(FlowAuth(), "flow", IP, INTERFACE, 8, 1, 16000)
    assert result["trace_state"] == "empty" and result["cleanup"] == "verified"
    assert result["trace_summary"].startswith("no packet was traced for the flow filter addr " + IP +
                                              " proto 1 during the 1 s window. ")
    assert result["trace_summary"].endswith("and that ICMP to or from this address is sent while the call runs.")


def test_engine_flow_overflow_fails_closed_after_verified_cleanup(adc_engine, monkeypatch):
    shell, call = _flow_call(adc_engine, monkeypatch, OverflowFlowShell)
    with pytest.raises(ValueError) as failed:
        call()
    assert str(failed.value) == "bounded FortiOS diagnostic failed; the session was closed"
    _cleaned_up(shell)


def test_engine_flow_unverified_cleanup_tells_the_administrator(adc_engine, monkeypatch):
    shell, call = _flow_call(adc_engine, monkeypatch, DeadFlowShell)
    with pytest.raises(ValueError) as failed:
        call()
    assert str(failed.value) == (
        "bounded FortiOS diagnostic failed; the session was closed and the diagnostic state restoration could "
        "not be verified: check 'diagnose debug info' and 'diagnose debug flow filter' on the device; if debug "
        "output is enabled or a filter is set, run 'diagnose debug disable', 'diagnose debug flow trace stop' and "
        "'diagnose debug flow filter clear'")
    assert "diagnose debug disable" in shell.commands[shell.commands.index("diagnose debug enable"):]


@pytest.mark.parametrize("output,counted", [
    ('id=20085 trace_id=1 msg="allocate a new session-00001cd3"\n'
     'id=20085 trace_id=2 msg="Find an existing session, id-00001cd3, original direction"\n', (2, 2)),
    ('session note: id=7 trace_id=3 func=f line=1 msg="x"\n', (0, 0)),
    ('trace_id=4\nproto=17 trace_id=5 msg="x"\n', (0, 0)),
])
def test_flow_trace_counts_only_packet_trace_lines(output, counted):
    assert d.flow_trace(output) == counted


TS_TRACE_60F_768 = (
    '2026-11-02 11:13:35 id=65308 trace_id=19 func=print_pkt_detail line=6340 msg="vd-root:0 received a packet'
    '(proto=1, 192.0.2.2:39608->192.0.2.1:2048) tun_id=0.0.0.0 from PVE-MGMT. type=8, code=0, id=39608, '
    'seq=16."\n'
    '2026-11-02 11:13:35 id=65308 trace_id=19 func=resolve_ip_tuple_fast line=6448 msg="Find an existing session, '
    'id-0001b970, original direction"\n'
    '2026-11-02 11:13:35 id=65308 trace_id=20 func=print_pkt_detail line=6340 msg="vd-root:0 received a packet'
    '(proto=1, 192.0.2.1:39608->192.0.2.2:0) tun_id=0.0.0.0 from local. type=0, code=0, id=39608, seq=16."\n'
    '2026-11-02 11:13:35 id=65308 trace_id=20 func=resolve_ip_tuple_fast line=6448 msg="Find an existing session, '
    'id-0001b970, reply direction"')
TS_TRACE_VM64_802 = (
    '2026-11-02 11:15:38 id=65308 trace_id=3 func=print_pkt_detail line=6491 msg="vd-root:0 received a packet'
    '(proto=1, 198.51.100.38:2928->198.51.100.31:2048) len=84 tun_id=0.0.0.0 from port1. type=8, code=0, id=2928, '
    'seq=14."\n'
    '2026-11-02 11:15:38 id=65308 trace_id=3 func=resolve_ip_tuple_fast line=6600 msg="Find an existing session, '
    'id-0000004a, original direction"\n'
    '2026-11-02 11:15:38 id=65308 trace_id=4 func=print_pkt_detail line=6491 msg="vd-root:0 received a packet'
    '(proto=1, 198.51.100.31:2928->198.51.100.38:0) len=84 tun_id=0.0.0.0 from local. type=0, code=0, id=2928, '
    'seq=14."\n'
    '2026-11-02 11:15:38 id=65308 trace_id=4 func=resolve_ip_tuple_fast line=6600 msg="Find an existing session, '
    'id-0000004a, reply direction"')


@pytest.mark.parametrize("output", [TS_TRACE_60F_768, TS_TRACE_VM64_802])
def test_flow_trace_counts_measured_console_timestamp_lines(output):
    assert d.flow_trace(output) == (2, 4)


@pytest.mark.parametrize("line", [
    'note 2026-11-02 11:13:35 id=65308 trace_id=19 func=f line=1 msg="x"',
    '2026-11-02T11:13:35 id=65308 trace_id=19 func=f line=1 msg="x"',
    '2026-11-02 11:13:35.123 id=65308 trace_id=19 func=f line=1 msg="x"',
    'Nov 02 11:13:35 id=65308 trace_id=19 func=f line=1 msg="x"',
])
def test_flow_trace_ignores_unmeasured_timestamp_shapes(line):
    assert d.flow_trace(line + "\n") == (0, 0)


class TimestampFlowShell(Shell):
    trace = TS_TRACE_60F_768
    def listen(self, timeout):
        assert self.interrupted.wait(timeout)
        return self.trace


@pytest.mark.parametrize("status_line,tuple_call,trace", [
    ("Version: FortiGate-60F v7.6.8,build3744,240101", True, TS_TRACE_60F_768),
    ("Version: FortiGate-VM64 v8.0.2,build0251,260928 (GA.F)", False, TS_TRACE_VM64_802),
    ("Version: FortiGate-80F v8.0.2,build0251,260928 (GA.F)", False, TS_TRACE_VM64_802),
])
def test_flow_with_measured_console_timestamp_counts_the_trace(adc_engine, monkeypatch, status_line, tuple_call,
                                                               trace):
    from netops_helper import engine
    use, _ = adc_engine
    shell = TimestampFlowShell("flow")
    shell.status_line = status_line
    shell.timestamp = "enable"
    shell.trace = trace
    monkeypatch.setattr(engine, "_FortiosDiagnosticShell", lambda session: shell)
    tuple_args = ({"source_address": "192.0.2.184", "source_port": 40641, "destination_port": 33434,
                   "protocol": 17} if tuple_call else {})
    result = use(FlowSession()).fortios_diagnostics(FlowAuth(), "flow", IP, INTERFACE, 8, 1, 16000, **tuple_args)
    assert result["ok"] is True and result["cleanup"] == "verified" and result["trace_state"] == "captured"
    assert result["trace_summary"].startswith("the device traced 2 packets (4 trace lines) for the flow filter ")
    _cleaned_up(shell)
    assert not any(command.startswith("diagnose debug console") for command in shell.commands)


@pytest.mark.parametrize("timestamp", [None, "disable"])
def test_flow_runs_when_console_timestamp_is_not_enabled(timestamp):
    shell = Shell("flow")
    shell.timestamp = timestamp
    result, timed_out, identity, domain = d.run(shell, "flow", IP, INTERFACE, 2, 1)
    assert result == "bounded flow data" and "diagnose debug enable" in shell.commands
    assert not shell.enabled and shell.filter == "any"


@pytest.mark.parametrize("status_line", [
    "Version: FortiGate-VM64-KVM v7.6.7,build3704,240101",
    "Version: FortiGate-VM64-KVM v8.0.0,build0167,250101",
])
def test_flow_with_unmeasured_console_timestamp_is_refused_before_any_change(adc_engine, monkeypatch, status_line):
    from netops_helper import engine
    use, _ = adc_engine
    shell = Shell("flow")
    shell.status_line = status_line
    shell.timestamp = "enable"
    monkeypatch.setattr(engine, "_FortiosDiagnosticShell", lambda session: shell)
    with pytest.raises(d.OptionRefused) as refused:
        use(FlowSession()).fortios_diagnostics(FlowAuth(), "flow", IP, INTERFACE, 8, 1, 16000)
    assert str(refused.value) == (
        "FortiOS reports 'console timestamp: enable' in 'diagnose debug info', and the shape of timestamped flow "
        "trace lines is not measured for this hardware and build; flow was not run and nothing was changed. Run "
        "'diagnose debug console timestamp disable' if that console setting is not needed, or run the trace on the "
        "device.")
    assert shell.commands[-1] == "diagnose debug info"
    assert not any(command.startswith(("diagnose debug flow", "diagnose debug enable", "diagnose debug disable"))
                   for command in shell.commands)


def test_diagnostic_audit_fields_are_accepted_by_core(tmp_path):
    from netops_core.audit import Recorder
    from netops_helper.engine import _audit_fields
    recorder = Recorder(tmp_path/"audit.jsonl","helper")
    values = _audit_fields({
        "recipe":"sessions","address":IP,"source_address":"192.0.2.184",
        "source_port":49152,"destination_port":443,"protocol":6,
        "count":2,"timeout":5,"max_bytes":1000,
    }, {})
    recorder.record("fortios_diagnostics", **values)
    import json
    event = json.loads(recorder.path().read_text())
    assert event["recipe"] == "sessions" and event["timeout"] == 5
    assert event["destination_address"] == IP and event["source_address"] == "192.0.2.184"
    assert (event["source_port"],event["destination_port"],event["protocol"]) == (49152,443,6)


@pytest.mark.parametrize("vdom", ["VD1\nend", 'VD1" next', "x"*32, 3])
def test_invalid_vdom(vdom):
    with pytest.raises(ValueError):
        d.validate("ping",IP,INTERFACE,1,1,1000,vdom)


def test_vdom_requires_an_independent_grant():
    with pytest.raises(ValueError):
        d.authorize(Auth(),"ping",IP,INTERFACE,"VD1")


def multi(current="VD1", interface="VD1"):
    shell = Shell("ping")
    shell.mode, shell.current_vdom, shell.interface_vdom = "multiple", current, interface
    return shell


def test_valid_vdom_passes_validation():
    d.validate("ping",IP,INTERFACE,1,1,1000,"VD1")


def test_vdom_scoped_session_runs_without_switching():
    shell = multi()
    before = dict(shell.options)
    result, timed_out, identity, domain = d.run(shell,"ping",IP,INTERFACE,1,1,"VD1")
    assert result == "untrusted device output" and domain == "VD1"
    assert shell.options == before
    assert not any(c.startswith(("config ","edit ","end","next")) for c in shell.commands)


@pytest.mark.parametrize("mode,current,interface,vdom", [
    ("multiple","VD1","VD1",None),
    ("multiple","root","root",None),
    ("multiple","root","VD1","VD1"),
    ("multiple","VD1","VD1","root"),
    ("disable","root","root","VD1"),
    ("disable","VD1","VD1","VD1"),
    ("enable","VD1","VD1","VD1"),
    ("","root","root",None),
    ("multiple","VD1 x","VD1","VD1"),
])
def test_unscoped_vdom_session_is_refused_after_status_only(mode,current,interface,vdom):
    shell = Shell("ping")
    shell.mode, shell.current_vdom, shell.interface_vdom = mode, current, interface
    with pytest.raises(d.UnsupportedPlatform, match="config_platform_not_supported"):
        d.run(shell,"ping",IP,INTERFACE,1,1,vdom)
    assert shell.commands == ["get system status"]


def test_explicit_root_on_single_vdom_device_is_accepted():
    shell = Shell("ping")
    assert d.run(shell,"ping",IP,INTERFACE,1,1,"root")[3] == "root"


@pytest.mark.parametrize("text", [
    "Version: FortiGate-VM64-KVM v7.6.7,build3704,240101\nVirtual domain configuration: multiple\nVirtual domain configuration: multiple\nCurrent virtual domain: VD1",
    "Version: FortiGate-VM64-KVM v7.6.7,build3704,240101\nVirtual domain configuration: multiple\nCurrent virtual domain: VD1\nCurrent virtual domain: VD1",
])
def test_duplicate_vdom_markers_are_refused(text):
    with pytest.raises(ValueError):
        d.status_identity(text)


def test_multi_vdom_interface_of_another_vdom_is_refused_before_options():
    shell = multi(interface="root")
    with pytest.raises(d.ScopeRefused, match="^the enrolled interface belongs to another VDOM$"):
        d.run(shell,"ping",IP,INTERFACE,1,1,"VD1")
    assert not any("ping-options" in command for command in shell.commands)


def test_interface_in_another_vdom_is_refused_before_options():
    shell=Shell("ping")
    shell.interface_vdom="VD1"
    with pytest.raises(d.ScopeRefused, match="^the enrolled interface belongs to another VDOM$"):
        d.run(shell,"ping",IP,INTERFACE,1,1)
    assert not any("ping-options" in command for command in shell.commands)
    assert not any(command.startswith("edit ") for command in shell.commands)


def test_interface_without_a_reported_owner_is_unverified_not_another_vdom():
    shell=multi()
    device=shell.command
    shell.command=lambda command, timeout=10: ('config system interface\n edit "port2"\n next\nend'
        if command.startswith('show full-configuration system interface "') else device(command, timeout))
    with pytest.raises(ValueError, match="^the interface owner cannot be verified$") as refused:
        d.run(shell,"ping",IP,INTERFACE,1,1,"VD1")
    assert not isinstance(refused.value, d.ScopeRefused)
    assert not any("ping-options" in command for command in shell.commands)


def load_gate():
    import importlib.util
    root=__import__("pathlib").Path(__file__).resolve().parents[1]
    path=root/"tests/support/check_public_release.py"
    spec=importlib.util.spec_from_file_location("diagnostic_gate",path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return root,module


@pytest.mark.parametrize("old,new", [
    ("diagnostics.authorize(auth, recipe, address, interface, vdom, source_address=source_address)",
     "diagnostics.authorize(auth, recipe, address, interface, None, source_address=source_address)"),
    ("diagnostics.run(\n                        shell, recipe, address, interface, count, timeout, vdom, reconnect=reconnect,\n                        source_address=source_address, source_port=source_port,\n                        destination_port=destination_port, protocol=protocol, window=window)",
     "diagnostics.run(\n                        shell, recipe, address, interface, count, timeout, None, reconnect=reconnect,\n                        source_address=source_address, source_port=source_port,\n                        destination_port=destination_port, protocol=protocol, window=window)"),
    ("@_audit_device_call\ndef fortios_diagnostics", "def fortios_diagnostics"),
    ("    diagnostics.adc_authorize(auth, recipe, address, health_check)\n", ""),
    ("diagnostics.adc_run(shell, recipe, address, timeout, count, health_check)", "diagnostics.adc_run(shell, recipe, address, 60, count, health_check)"),
    ("diagnostics.adc_authorize(auth, recipe, address, health_check)", "diagnostics.adc_authorize(auth, recipe, address, None)"),
])
def test_release_gate_rejects_diagnostic_boundary_mutations(old,new):
    import ast
    root,gate=load_gate()
    text=(root/"src/netops_helper/engine.py").read_text()
    assert gate._diagnostic_wrapper_allowed(ast.parse(text))
    assert old in text
    assert not gate._diagnostic_wrapper_allowed(ast.parse(text.replace(old,new,1)))


@pytest.mark.parametrize("old,new", [
    ('len(domains) != 1 or not VDOM_NAME.fullmatch(domains[0])', 'False'),
    ('len(markers) != 1 or markers[0] not in VDOM_MODES', 'False'),
    ('mode == "disable" and domains != ["root"]', 'False'),
    ('vdom is None and mode != "disable"', 'False'),
    ('vdom is not None and vdom != domain', 'False'),
    ('identity, domain, mode = status_identity(shell.command("get system status"))',
     'identity, domain, mode = (("FortiGate-VM64-KVM", "7.6.7", "3704"), "root", "disable")'),
    ('    if identity not in IDENTITIES:', '    if False:'),
])
def test_release_gate_rejects_unverified_vdom_mutations(old,new):
    import ast
    root,gate=load_gate()
    text=(root/"src/netops_helper/fortios_diagnostics.py").read_text()
    assert gate._diagnostic_vdom_allowed(ast.parse(text))
    assert old in text
    assert not gate._diagnostic_vdom_allowed(ast.parse(text.replace(old,new,1)))



class DisconnectAfterPing(Shell):
    def __init__(self):
        super().__init__("ping")
        self.disconnected = False

    def command(self, command, timeout=10):
        if self.disconnected:
            self.commands.append(command)
            raise RuntimeError("transport lost")
        if command == "execute ping " + IP:
            self.commands.append(command)
            self.disconnected = True
            raise RuntimeError("transport lost")
        return super().command(command, timeout)


def _reconnect_to(shell):
    @contextmanager
    def reconnect():
        yield shell
    return reconnect


def test_disconnect_after_set_reconnects_to_restore_only_recorded_state():
    primary = DisconnectAfterPing()
    before = dict(primary.options)
    recovery = Shell("ping")
    recovery.options = primary.options
    with pytest.raises(RuntimeError, match="transport lost"):
        d.run(primary, "ping", IP, INTERFACE, 2, 1, reconnect=_reconnect_to(recovery))
    expected_restore = [
        "execute ping-options use-sdwan no",
        "execute ping-options source auto",
        "execute ping-options interface auto",
        "execute ping-options adaptive-ping disable",
        "execute ping-options data-size 56",
        "execute ping-options interval 1",
        "execute ping-options timeout 2",
        "execute ping-options repeat-count 5",
    ]
    assert primary.options == before
    assert recovery.commands[0] == "get system status"
    assert recovery.commands[1:-1] == expected_restore
    assert recovery.commands[-1] == "execute ping-options view-settings"
    assert primary.commands.count("execute ping " + IP) == 1
    assert "execute ping " + IP not in recovery.commands


def test_reconnect_identity_mismatch_never_runs_restore_commands():
    primary = DisconnectAfterPing()
    recovery = Shell("ping")
    recovery.options = primary.options
    original = recovery.command

    def mismatched_status(command, timeout=10):
        result = original(command, timeout)
        if command == "get system status":
            return result.replace("build3704", "build3705")
        return result

    recovery.command = mismatched_status
    with pytest.raises(ValueError, match="restoration could not be verified"):
        d.run(primary, "ping", IP, INTERFACE, 2, 1, reconnect=_reconnect_to(recovery))
    assert recovery.commands == ["get system status"]
    assert primary.options != dict(Shell("ping").options)


def test_reconnect_restore_refusal_remains_unverified():
    primary = DisconnectAfterPing()
    recovery = Shell("ping")
    recovery.options = primary.options
    recovery.fail = "execute ping-options repeat-count 5"
    with pytest.raises(ValueError, match="restoration could not be verified"):
        d.run(primary, "ping", IP, INTERFACE, 2, 1, reconnect=_reconnect_to(recovery))
    assert recovery.commands[0] == "get system status"
    assert recovery.commands[-2] == "execute ping-options repeat-count 5"
    assert recovery.options["Repeat Count"] != "5"


@pytest.mark.parametrize("protocol", [6, 17])
def test_tcp_udp_sniffer_is_scoped_bidirectional_and_header_only(protocol):
    source = "192.0.2.184"
    values = dict(source_address=source, source_port=49152,
                  destination_port=443, protocol=protocol)
    d.validate("sniffer", IP, INTERFACE, 2, 1, 1000, **values)
    auth = Auth()
    auth.read_inventory = {"diagnostic_recipes": ["sniffer"],
                           "addresses": [source, IP], "interfaces": [INTERFACE]}
    d.authorize(auth, "sniffer", IP, INTERFACE, source_address=source)
    auth.read_inventory = {**auth.read_inventory, "addresses": [IP]}
    with pytest.raises(ValueError):
        d.authorize(auth, "sniffer", IP, INTERFACE, source_address=source)
    for status_line in (
        "Version: FortiGate-VM64 v8.0.2,build0251,240101",
        "Version: FortiGate-80F v8.0.2,build0251,260928 (GA.F)",
        "Version: FortiGate-60F v7.6.8,build3744,240101",
    ):
        shell = Shell("sniffer")
        shell.status_line = status_line
        output, timed_out, identity, domain = d.run(
            shell, "sniffer", IP, INTERFACE, 2, 1, **values)
        transport = "tcp" if protocol == 6 else "udp"
        selector = (transport + " and ((src host " + source +
                    " and src port 49152 and dst host " + IP + " and dst port 443) or " +
                    "(src host " + IP + " and src port 443 and dst host " + source +
                    " and dst port 49152))")
        assert shell.commands[-1] == (
            'diagnose sniffer packet ' + INTERFACE + ' "' + selector + '" 1 2 l')
        assert output == "untrusted device output" and not timed_out
        assert not any("filter clear" in command or "debug enable" in command
                       for command in shell.commands)
ADC_NAME = "update.fortiguard.net"
ADC_URL = "http://" + IP + "/health"
ADC_HC = "HC_HTTP_APP"
ADC_VIEW = "execute curl-option view-settings"
ADC_CURL_OPTIONS = ("Curl Options:\n Interface: auto\n Header: {}\n Http version: 1.1\n Raw: disable\n Raw data: {}\n Timeout: 10\n"
                    "Default Curl Options:\n Interface: auto\n Header: auto\n Http version: 1.1\n Raw: disable\n Raw data: auto\n Timeout: 10")


class AdcAuth:
    alias = "adc"
    port = 22
    login = "admin"
    legacy_ssh = None
    secrets = ()
    ssh_platform = "fortiadc"
    host_key_fingerprint = "SHA256:" + "A" * 43
    def __init__(self, icmp=True, dns=True):
        self.read_inventory = {"diagnostic_recipes": ["ping", "traceroute", "nslookup", "http_probe", "health_check_verify"],
                               "addresses": [IP], "diagnostic_names": [ADC_NAME],
                               "diagnostic_http_endpoints": [ADC_URL], "adc_health_checks": [ADC_HC]}
        self.checked = []
        self.icmp, self.dns = icmp, dns
    def require_ssh_query(self, platform, query):
        assert (platform, query) == ("fortiadc", "system_status")
    def require_icmp(self):
        self.checked.append("icmp")
        if not self.icmp:
            raise ValueError("ICMP is not enabled for this target")
    def require_dns(self):
        self.checked.append("dns")
        if not self.dns:
            raise ValueError("DNS is not enabled for this target")


class AdcShell:
    def __init__(self, header="auto", raw_data="auto"):
        self.commands = []
        self.interrupted = threading.Event()
        self.curl_options = ADC_CURL_OPTIONS.format(header, raw_data)
    def interrupt(self):
        self.interrupted.set()
    def command(self, command, timeout=10):
        self.commands.append(command)
        if command == "get system status":
            return "Version: FortiADC-KVM v7.6.7,build0676,260522 (GA.M)\n"
        if command == ADC_VIEW:
            return self.curl_options
        if command.startswith("execute traceroute "):
            assert self.interrupted.wait(timeout)
            return "traceroute to "+IP+" ("+IP+"), 30 hops max, 46 byte packets\n 1  *  *  *\n^C"
        return "untrusted device output"


@pytest.mark.parametrize("recipe,address", [("ping", IP), ("traceroute", IP), ("nslookup", ADC_NAME)])
def test_adc_runs_only_the_fixed_command_after_identity(recipe, address):
    auth = AdcAuth()
    d.adc_validate(recipe, address, "", 3, 1, 16000)
    d.adc_authorize(auth, recipe, address)
    shell = AdcShell()
    d.adc_run(shell, recipe, address, 1)
    assert shell.commands == ["get system status", d.ADC_RECIPES[recipe] + address]
    assert auth.checked == {"ping": ["icmp"], "traceroute": [], "nslookup": ["dns"]}[recipe]


@pytest.mark.parametrize("recipe,address,interface", [
    ("nslookup", IP, ""), ("ping", ADC_NAME, ""), ("ping", IP, INTERFACE),
    ("nslookup", "Update.FortiGuard.net", ""), ("sniffer", IP, ""),
])
def test_adc_refuses_untyped_requests(recipe, address, interface):
    with pytest.raises(ValueError):
        d.adc_validate(recipe, address, interface, 3, 1, 16000)


@pytest.mark.parametrize("recipe,count,timeout,accepted", [
    ("traceroute", 3, 60, True), ("traceroute", 3, 61, False), ("ping", 3, 10, True),
    ("ping", 3, 11, False), ("nslookup", 3, 11, False), ("ping", 5, 5, False), ("ping", 1, 5, False),
])
def test_adc_limits_traceroute_deadline_and_fixed_ping_count(recipe, count, timeout, accepted):
    address = ADC_NAME if recipe == "nslookup" else IP
    if accepted:
        d.adc_validate(recipe, address, "", count, timeout, 16000)
    else:
        with pytest.raises(ValueError):
            d.adc_validate(recipe, address, "", count, timeout, 16000)


@pytest.mark.parametrize("recipe,address,auth", [
    ("nslookup", "fds1.fortinet.com", AdcAuth()), ("ping", "192.0.2.9", AdcAuth()),
    ("ping", IP, AdcAuth(icmp=False)), ("nslookup", ADC_NAME, AdcAuth(dns=False)),
])
def test_adc_requires_enrolled_target_and_permission(recipe, address, auth):
    with pytest.raises(ValueError):
        d.adc_authorize(auth, recipe, address)


def test_adc_traceroute_grant_needs_no_host_egress_flag():
    auth = AdcAuth(icmp=False, dns=False)
    d.adc_authorize(auth, "traceroute", IP)
    assert auth.checked == []


@pytest.mark.parametrize("platform,recipes,accepted", [
    ("fortiadc", ("ping", "traceroute", "nslookup", "http_probe", "health_check_verify"), True),
    ("fortiadc", ("sniffer",), False), ("fortios", ("ping", "flow"), True), ("fortios", ("nslookup",), False),
    ("fortios", ("http_probe",), False), ("fortios", ("health_check_verify",), False),
])
def test_inventory_refuses_recipes_the_platform_lacks(platform, recipes, accepted):
    from netops_helper.read_policy import validate_query_inventory
    if accepted:
        validate_query_inventory(platform, (), {"diagnostic_recipes": recipes})
    else:
        with pytest.raises(ValueError):
            validate_query_inventory(platform, (), {"diagnostic_recipes": recipes})


@pytest.mark.parametrize("platform,accepted", [("fortiadc", True), ("fortios", False)])
def test_inventory_refuses_dns_names_outside_fortiadc(platform, accepted):
    from netops_helper.read_policy import validate_query_inventory
    inventory = {"diagnostic_recipes": ("ping",), "diagnostic_names": (ADC_NAME,)}
    if accepted:
        validate_query_inventory(platform, (), inventory)
    else:
        with pytest.raises(ValueError):
            validate_query_inventory(platform, (), inventory)


@pytest.mark.parametrize("category,value", [("diagnostic_http_endpoints", ADC_URL), ("adc_health_checks", ADC_HC)])
@pytest.mark.parametrize("platform,accepted", [("fortiadc", True), ("fortios", False)])
def test_inventory_refuses_http_endpoints_and_health_checks_outside_fortiadc(platform, accepted, category, value):
    from netops_helper.read_policy import validate_query_inventory
    inventory = {"diagnostic_recipes": ("ping",), category: (value,)}
    if accepted:
        validate_query_inventory(platform, (), inventory)
    else:
        with pytest.raises(ValueError):
            validate_query_inventory(platform, (), inventory)


ADC_PROMPT = b"FortiADC-KVM # "


class AdcSession:
    def __init__(self, version="v7.6.7,build0676", tail=""):
        self.queue = [b"login\r\n" + ADC_PROMPT]
        self.version, self.tail, self.pending = version, tail, b""
        self.sent = []
        self.interrupted = threading.Event()
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def expect(self, patterns, timeout):
        if self.queue:
            return 0, self.queue.pop(0)
        self.interrupted.wait(timeout)
        return 0, self.pending + ADC_PROMPT
    def discard(self, data):
        return len(data)
    def send(self, command):
        self.sent.append(command)
        if command == "get system status":
            self.queue.append(("get system status\r\nVersion: FortiADC-KVM " + self.version + ",260522 (GA.M)\r\n").encode() + ADC_PROMPT)
        else:
            self.pending = (command + "\r\ntraceroute to " + IP + " (" + IP + "), 30 hops max, 46 byte packets\r\n"
                            " 1  *  *  *\r\n^C\r\n" + self.tail).encode()
    def interrupt(self):
        self.interrupted.set()


@pytest.fixture
def adc_engine(tmp_path, monkeypatch):
    from contextlib import nullcontext
    from netops_core.audit import Recorder
    import tempfile
    from netops_helper import audit, engine
    monkeypatch.setattr(audit, "_RECORDER", Recorder(tmp_path/"audit.jsonl", "helper"))
    monkeypatch.delenv("NETOPS_TARGET_LOCK_DIR", raising=False)
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    monkeypatch.setattr(engine, "record", audit.record)
    monkeypatch.setattr(engine, "_resolve_target_ipv4", lambda auth: ("198.51.100.7",))
    monkeypatch.setattr(engine, "host_key_line", lambda *args: "pinned")
    monkeypatch.setattr(engine, "_paced_connection", lambda *args: nullcontext())
    monkeypatch.setattr(engine, "DeviceCredential", lambda auth: None)
    opened = []
    def use(session):
        monkeypatch.setattr(engine.core_session, "Session", lambda *args, **kwargs: opened.append(args) or session)
        return engine
    use.opened = opened
    return use, tmp_path/"audit.jsonl"


@pytest.mark.parametrize("recipe,address,auth,count,health_check", [
    ("ping", "192.0.2.9", AdcAuth(), 3, None), ("ping", IP, AdcAuth(icmp=False), 3, None),
    ("nslookup", "fds1.fortinet.com", AdcAuth(), 3, None), ("nslookup", ADC_NAME, AdcAuth(dns=False), 3, None),
    ("http_probe", "http://" + IP + "/", AdcAuth(), 3, None), ("health_check_verify", IP, AdcAuth(), 2, "HC_TCP_APP"),
])
def test_adc_engine_refuses_ungranted_requests_before_a_session(adc_engine, recipe, address, auth, count, health_check):
    use, _ = adc_engine
    engine = use(None)
    with pytest.raises(ValueError):
        engine.fortios_diagnostics(auth, recipe, address, "", count, 1, 16000, None, health_check)
    assert use.opened == []


def test_adc_traceroute_deadline_returns_partial_not_complete(adc_engine):
    import json
    use, log = adc_engine
    session = AdcSession()
    result = use(session).fortios_diagnostics(AdcAuth(icmp=False, dns=False), "traceroute", IP, "", 3, 1, 16000)
    assert session.sent == ["get system status", "execute traceroute " + IP]
    assert result["ok"] and result["deadline_reached"] and result["complete"] is False
    assert " 1  *  *  *" in result["untrusted_device_output"]
    assert result["cleanup"] == "not_required" and result["identity"] == ("FortiADC-KVM", "7.6.7", "0676")
    assert "fixed_ping_packets" not in result
    finished = [json.loads(line) for line in log.read_text().splitlines()][-1]
    assert finished["status"] == "ok" and finished["detail"] == "deadline_reached"


def test_adc_device_refusal_uses_the_fortiadc_pattern(adc_engine):
    use, _ = adc_engine
    session = AdcSession(tail="Command fail. Return code is -284 (CLI parsing error.)\r\n")
    with pytest.raises(ValueError, match="bounded FortiADC diagnostic failed"):
        use(session).fortios_diagnostics(AdcAuth(), "traceroute", IP, "", 3, 1, 16000)


def test_adc_log_session_failure_is_withheld_and_closed(adc_engine):
    class BrokenSession:
        def __enter__(self):
            raise RuntimeError("synthetic transport failure")
        def __exit__(self, *exc):
            return False
    use, _ = adc_engine
    auth = AdcAuth()
    auth.read_inventory["diagnostic_recipes"].append("system_event_logs")
    with pytest.raises(ValueError, match="^bounded FortiADC system_event_logs read failed; the session was closed$") as caught:
        use(BrokenSession()).fortios_diagnostics(auth, "system_event_logs", "", "", 1, 20, 16384)
    assert caught.value.__cause__ is None and "synthetic" not in str(caught.value)
    assert len(use.opened) == 1


def test_adc_unmeasured_firmware_is_not_supported(adc_engine):
    use, _ = adc_engine
    session = AdcSession(version="v7.6.8,build0700")
    with pytest.raises(d.UnsupportedPlatform, match="config_platform_not_supported"):
        use(session).fortios_diagnostics(AdcAuth(), "traceroute", IP, "", 3, 1, 16000)
    assert session.sent == ["get system status"]


def test_adc_ping_result_states_the_fixed_packet_count(adc_engine):
    use, _ = adc_engine
    session = AdcSession()
    result = use(session).fortios_diagnostics(AdcAuth(), "ping", IP, "", 3, 1, 16000)
    assert result["count_applied"] is False and result["fixed_ping_packets"] == 5


@pytest.mark.parametrize("result,detail", [
    ({"complete": False, "deadline_reached": True}, "deadline_reached"),
    ({"complete": False, "deadline_reached": False}, None),
    ({"complete": True}, None),
    ({"ok": True, "complete": False, "offset": 0, "returned_bytes": 1000, "next_offset": 1000}, None),
])
def test_audit_detail_marks_only_a_reached_deadline(result, detail):
    from netops_helper import engine
    assert engine._audit_fields({}, result).get("detail") == detail


@pytest.mark.parametrize("recipe,address,health_check,count,commands", [
    ("http_probe", ADC_URL, None, 3, [ADC_VIEW, "execute curl " + ADC_URL]),
    ("health_check_verify", IP, ADC_HC, 2,
     ["execute health-check-verify health-check " + ADC_HC + " dest-address " + IP + " count 2"]),
])
def test_adc_http_probe_and_health_check_send_the_exact_granted_command(recipe, address, health_check, count, commands):
    auth = AdcAuth(icmp=False, dns=False)
    d.adc_validate(recipe, address, "", count, 1, 16000, None, health_check)
    d.adc_authorize(auth, recipe, address, health_check)
    shell = AdcShell()
    d.adc_run(shell, recipe, address, 1, count, health_check)
    assert shell.commands == ["get system status"] + commands
    assert auth.checked == []


@pytest.mark.parametrize("header,raw_data", [("Authorization: Bearer x", "auto"), ("auto", "{}")])
def test_adc_http_probe_refuses_a_curl_header_or_body_before_curl(header, raw_data):
    shell = AdcShell(header, raw_data)
    with pytest.raises(ValueError, match="Header and Raw data auto") as error:
        d.adc_run(shell, "http_probe", ADC_URL, 1)
    assert shell.commands == ["get system status", ADC_VIEW]
    assert "Bearer" not in str(error.value)


@pytest.mark.parametrize("recipe,timeout,accepted", [
    ("health_check_verify", 60, True), ("health_check_verify", 61, False), ("http_probe", 11, False),
])
def test_adc_health_check_timeout_reaches_60_seconds(recipe, timeout, accepted):
    address, health_check = (IP, ADC_HC) if recipe == "health_check_verify" else (ADC_URL, None)
    count = 5 if health_check else 3
    if accepted:
        d.adc_validate(recipe, address, "", count, timeout, 16000, None, health_check)
    else:
        with pytest.raises(ValueError):
            d.adc_validate(recipe, address, "", count, timeout, 16000, None, health_check)


@pytest.mark.parametrize("recipe,address,health_check,count", [
    ("http_probe", IP, None, 3), ("http_probe", "https://" + IP + "/health", None, 3),
    ("http_probe", "http://" + IP + ":80/health", None, 3), ("http_probe", ADC_URL + "?x=1", None, 3),
    ("http_probe", ADC_URL + " -X POST", None, 3), ("http_probe", ADC_URL, None, 1),
    ("http_probe", ADC_URL, ADC_HC, 3), ("health_check_verify", IP, ADC_HC, 0),
    ("health_check_verify", IP, ADC_HC, 6), ("health_check_verify", IP, None, 2),
    ("health_check_verify", IP, ADC_HC + " port 80", 2), ("health_check_verify", ADC_URL, ADC_HC, 2),
    ("ping", IP, ADC_HC, 3),
])
def test_adc_http_probe_and_health_check_refuse_untyped_requests(recipe, address, health_check, count):
    with pytest.raises(ValueError):
        d.adc_validate(recipe, address, "", count, 1, 16000, None, health_check)


@pytest.mark.parametrize("recipe,address,health_check,inventory", [
    ("http_probe", "http://" + IP + "/", None, {}),
    ("http_probe", ADC_URL, None, {"diagnostic_recipes": ["health_check_verify"]}),
    ("health_check_verify", IP, "HC_TCP_APP", {}),
    ("health_check_verify", "192.0.2.9", ADC_HC, {}),
    ("health_check_verify", IP, ADC_HC, {"diagnostic_recipes": ["http_probe"]}),
])
def test_adc_http_probe_and_health_check_require_their_exact_grant(recipe, address, health_check, inventory):
    auth = AdcAuth()
    auth.read_inventory.update(inventory)
    with pytest.raises(ValueError):
        d.adc_authorize(auth, recipe, address, health_check)


class AdcAnswerSession(AdcSession):
    def __init__(self, answer):
        super().__init__()
        self.answer = answer
    def send(self, command):
        if command == "get system status":
            return super().send(command)
        self.sent.append(command)
        answer = ADC_CURL_OPTIONS.format("auto", "auto").replace("\n", "\r\n") + "\r\n" if command == ADC_VIEW else self.answer
        self.queue.append((command + "\r\r\n" + answer).encode() + ADC_PROMPT)


@pytest.mark.parametrize("status", ["200 OK", "404 Not Found"])
def test_adc_http_probe_returns_status_and_body_whatever_the_status(adc_engine, status):
    use, _ = adc_engine
    session = AdcAnswerSession("> GET /health HTTP/1.1\r\r\n< HTTP/1.1 " + status + "\r\r\n\r\r\n< \r\r\nok backend-a\r\n")
    result = use(session).fortios_diagnostics(AdcAuth(icmp=False, dns=False), "http_probe", ADC_URL, "", 3, 1, 16000)
    assert session.sent == ["get system status", ADC_VIEW, "execute curl " + ADC_URL]
    assert result["ok"] and result["complete"] and not result["deadline_reached"]
    assert "< HTTP/1.1 " + status in result["untrusted_device_output"]
    assert "ok backend-a" in result["untrusted_device_output"]
    assert result["count_applied"] is False and result["http_requests"] == 1


def test_adc_health_check_returns_the_device_verdict_and_applied_count(adc_engine):
    use, _ = adc_engine
    session = AdcAnswerSession("recv hc state is UP(check service successfully, status code 200), rtt = 0.5 ms\r\n"
                               "recv hc state is UP(check service successfully, status code 200), rtt = 0.6 ms\r\n\r\n"
                               "2 checks completed, 2 checks success, Success rate: 100.0%\r\n")
    result = use(session).fortios_diagnostics(AdcAuth(icmp=False, dns=False), "health_check_verify", IP, "", 2, 1, 16000,
                                              None, ADC_HC)
    assert session.sent == ["get system status",
                            "execute health-check-verify health-check " + ADC_HC + " dest-address " + IP + " count 2"]
    assert result["ok"] and result["complete"] and result["health_check"] == ADC_HC and result["count_applied"] is True
    assert "2 checks success" in result["untrusted_device_output"]


def test_a_fortios_target_refuses_a_health_check_argument(adc_engine):
    use, _ = adc_engine
    auth = AdcAuth()
    auth.ssh_platform = "fortinet"
    with pytest.raises(ValueError, match="health_check applies only"):
        use(None).fortios_diagnostics(auth, "ping", IP, INTERFACE, 3, 1, 16000, None, ADC_HC)
    assert use.opened == []


@pytest.mark.parametrize("name", ["source_address", "source_port", "destination_port", "protocol"])
def test_a_fortiadc_target_refuses_a_tcp_udp_tuple_argument(adc_engine, name):
    use, _ = adc_engine
    value = "192.0.2.184" if name == "source_address" else 6 if name == "protocol" else 443
    with pytest.raises(ValueError, match="tuple applies only to a FortiOS target"):
        use(None).fortios_diagnostics(AdcAuth(), "ping", IP, "", 3, 1, 16000, **{name: value})
    assert use.opened == []


SESSION_BLOCK = """session info: proto=6 proto_state=01 duration=477 expire=3599 timeout=3600 refresh_dir=both flags=00000000 socktype=0 sockport=0 av_idx=0 use=3
origin-shaper=
reply-shaper=
per_ip_shaper=
class_id=0 ha_id=0 policy_dir=0 tunnel=/ vlan_cos=0/255
state=log may_dirty f00
statistic(bytes/packets/allow_err): org=38568/624/1 reply=32404/623/1 tuples=2
tx speed(Bps/kbps): 80/0 rx speed(Bps/kbps): 67/0
orgin->sink: org pre->post, reply pre->post dev=13->3/3->13 gwy=198.51.100.1/192.0.2.184
hook=post dir=org act=snat 192.0.2.184:40640->198.51.100.20:443(198.51.100.2:40640)
hook=pre dir=reply act=dnat 198.51.100.20:443->198.51.100.2:40640(192.0.2.184:40640)
pos/(before,after) 0/(0,0), 0/(0,0)
src_mac=00:00:5e:00:53:01  dst_mac=00:00:5e:00:53:02
misc=0 policy_id=5 pol_uuid_idx=26053 auth_info=0 chk_client_info=0 vd=0
serial=0001a2b3 tos=ff/ff app_list=0 app=0 url_cat=0
rpdb_link_id=00000000 ngfw_id=n/a duplicaton_id=0
npu_state=0x000100
no_ofld_reason:  npu-flag-off
hrx info: valid=0/0, qid=0/0, npuid=0/0, sublink=0/0
"""

SESSION_PROJECTED = """session proto=6 proto_state=01 duration=477 expire=3599 policy_id=5 dev=13->3/3->13 org=38568/624/1 reply=32404/623/1
hook=post dir=org act=snat 192.0.2.184:40640->198.51.100.20:443(198.51.100.2:40640)
hook=pre dir=reply act=dnat 198.51.100.20:443->198.51.100.2:40640(192.0.2.184:40640)
"""


def test_session_projection_returns_only_contract_fields():
    text, complete, omitted = d.session_projection(SESSION_BLOCK + "total session: 1\n", 8)
    assert text == SESSION_PROJECTED + "total session: 1\n"
    assert complete is True and omitted == 0
    for foreign in ("gwy=", "src_mac", "00:00:5e", "serial=", "pol_uuid_idx", "npu", "shaper", "speed", "tuples=", "flags="):
        assert foreign not in text


def test_session_projection_limits_count_and_reports_omitted():
    text, complete, omitted = d.session_projection(SESSION_BLOCK * 3 + "total session: 3\n", 2)
    assert text == SESSION_PROJECTED * 2 + "total session: 3\n"
    assert complete is True and omitted == 1


@pytest.mark.parametrize(("removed", "missing"), [
    ("misc=0 policy_id=5 ", "policy_id"),
    ("statistic(bytes/packets/allow_err): org=38568/624/1 reply=32404/623/1 tuples=2\n", "statistic"),
    (" dev=13->3/3->13", "dev"),
    ("hook=post dir=org act=snat 192.0.2.184:40640->198.51.100.20:443(198.51.100.2:40640)\n", "hook"),
    (" proto_state=01", "proto_state"),
])
def test_session_projection_marks_missing_field_incomplete(removed, missing):
    block = SESSION_BLOCK.replace(removed, "", 1)
    assert block != SESSION_BLOCK
    text, complete, omitted = d.session_projection(block + "total session: 1\n", 8)
    assert complete is False and omitted == 0
    assert "incomplete=" + missing + "\n" in text
    assert "gwy=" not in text and "serial=" not in text


def test_session_projection_without_total_is_incomplete():
    text, complete, omitted = d.session_projection(SESSION_BLOCK, 8)
    assert complete is False
    assert text == SESSION_PROJECTED + "incomplete=total\n"


def test_session_projection_without_sessions():
    assert d.session_projection("total session: 0\n", 8) == ("total session: 0\n", True, 0)


def test_engine_sessions_output_is_projected(monkeypatch):
    from contextlib import nullcontext
    import netops_core.target_lock
    from netops_helper import engine
    raw = "header noise\n" + SESSION_BLOCK + SESSION_BLOCK + "total session: 2\n"
    monkeypatch.setattr(d, "validate", lambda *a, **k: None)
    monkeypatch.setattr(d, "authorize", lambda *a, **k: None)
    monkeypatch.setattr(d, "run", lambda *a, **k: (raw, False, ("FortiGate-60F", "7.6.8", "3744"), "root"))
    monkeypatch.setattr(netops_core.target_lock, "target_lock", lambda fingerprint: nullcontext())
    monkeypatch.setattr(engine, "_resolve_target_ipv4", lambda auth: ["192.0.2.10"])
    monkeypatch.setattr(engine, "host_key_line", lambda *a: "pinned")
    monkeypatch.setattr(engine, "_paced_connection", lambda *a: nullcontext())
    monkeypatch.setattr(engine, "DeviceCredential", lambda auth: None)
    monkeypatch.setattr(engine, "_FortiosDiagnosticShell", lambda session: session)
    monkeypatch.setattr(engine.core_session, "Session", lambda *a, **k: nullcontext(SimpleNamespace(close=lambda: None)))
    auth = SimpleNamespace(alias="fgt", secrets=(), host_key_fingerprint="pin", port=22, login="ro", legacy_ssh=False,
                           ssh_platform="fortinet")
    result = engine.fortios_diagnostics.__wrapped__(auth, "sessions", IP, INTERFACE, 1, 5, 16000)
    assert result["untrusted_device_output"] == SESSION_PROJECTED + "total session: 2\n"
    assert result["complete"] is True and result["sessions_omitted"] == 1 and result["truncated"] is True
    assert "header noise" not in result["untrusted_device_output"]
    projected = result["untrusted_device_output"].encode("utf-8")
    assert result["total_bytes"] == result["returned_bytes"] == len(projected) < len(raw.encode("utf-8"))
    monkeypatch.setattr(d, "run", lambda *a, **k: ("total session: 0", False, ("FortiGate-60F", "7.6.8", "3744"), "root"))
    result = engine.fortios_diagnostics.__wrapped__(auth, "sessions", IP, INTERFACE, 8, 5, 16000)
    assert result["untrusted_device_output"] == "total session: 0\n"
    assert result["total_bytes"] == result["returned_bytes"] == 17 and result["truncated"] is False
    result = engine.fortios_diagnostics.__wrapped__(auth, "sessions", IP, INTERFACE, 8, 5, 10)
    assert (result["total_bytes"], result["returned_bytes"], result["truncated"]) == (17, 10, True)
    broken = raw.replace("misc=0 policy_id=5 ", "")
    monkeypatch.setattr(d, "run", lambda *a, **k: (broken, False, ("FortiGate-60F", "7.6.8", "3744"), "root"))
    result = engine.fortios_diagnostics.__wrapped__(auth, "sessions", IP, INTERFACE, 2, 5, 16000)
    assert result["complete"] is False and result["untrusted_device_output"].count("incomplete=policy_id\n") == 2


LOG_DUMP = ("category: traffic\ndevice: disk\nstart-line: 1\nview-lines: 10\nmax-checklines: 0\n"
            "HA member: \nlog search mode: on-demand\npre-fetch-pages: 2\nOftp search string: ")


def _record(number, source, destination):
    return (str(number) + ": date=2026-01-0" + str(number) + " time=10:00:0" + str(number) +
            ' type="traffic" subtype="forward" srcip=' + source + " dstip=" + destination + "\n\n")


LOG_DISPLAY = ("4 logs found.\n3 logs returned.\n50.0% of logs has been searched.\n\n" +
               _record(1, IP, "198.51.100.1") + _record(2, "198.51.100.2", "198.51.100.3") +
               _record(3, "198.51.100.4", IP))


class LogShell(Shell):
    def __init__(self, dump=LOG_DUMP, changes=False, display="untrusted log output"):
        super().__init__("logs")
        self.dump = dump
        self.changes = changes
        self.display = display

    def command(self, command, timeout=10):
        if command == "execute log filter dump":
            self.commands.append(command)
            return self.dump
        if command == "execute log display":
            self.commands.append(command)
            if self.changes:
                self.dump = self.dump.replace("start-line: 1", "start-line: 2")
            return self.display
        return super().command(command, timeout)


def _log_commands(shell):
    return [command for command in shell.commands if command.startswith("execute log")]


def test_logs_display_between_equal_filter_dumps_without_setting_a_filter():
    shell = LogShell(display=LOG_DISPLAY)
    result, timed_out, identity, domain = d.run(shell, "logs", IP, INTERFACE, 1, 1)
    assert not timed_out
    assert _log_commands(shell) == ["execute log filter dump", "execute log display", "execute log filter dump"]
    assert result["state"] == "ok" and result["filter"]["category"] == "traffic"
    assert (result["found"], result["loaded"], result["matched"], result["returned"]) == (4, 3, 2, 1)
    assert result["truncated"] and result["time_range"] == ["2026-01-01 10:00:01", "2026-01-03 10:00:03"]
    assert result["output"].startswith("1: date=") and "198.51.100.2" not in result["output"]
    windowed = d.run(LogShell(display=LOG_DISPLAY), "logs", IP, INTERFACE, 3, 1, window=("2026-01-02 00:00:00", "2026-01-03 23:59:59"))[0]
    assert windowed["matched"] == 1 and windowed["output"].startswith("3: date=")
    assert d.log_window("logs", "2026-01-02 00:00:00", None) == ("2026-01-02 00:00:00", None)
    for bad in (("sessions", "2026-01-02 00:00:00", None), ("logs", "2026-01-02", None),
                ("logs", "2026-02-30 00:00:00", None),
                ("logs", "2026-01-03 00:00:00", "2026-01-02 00:00:00")):
        with pytest.raises(ValueError):
            d.log_window(*bad)
    for display, state in (("0 logs found.\n0 logs returned.\n", "empty"),
                           ("Command fail. Return code -1\n", "device_refused"),
                           ("untrusted log output", "unsupported")):
        other = d.run(LogShell(display=display), "logs", IP, INTERFACE, 3, 1)[0]
        assert other["state"] == state and other["output"] == ""
    mismatch = LOG_DISPLAY.replace("3 logs returned.", "4 logs returned.")
    assert d.run(LogShell(display=mismatch), "logs", IP, INTERFACE, 3, 1)[0]["state"] == "incomplete"
    missing_date = LOG_DISPLAY.replace("date=2026-01-01 time=10:00:01", "timestamp=missing")
    assert d.run(LogShell(display=missing_date), "logs", IP, INTERFACE, 3, 1)[0]["state"] == "incomplete"
    assert d.log_read(LOG_DISPLAY, LOG_DUMP, IP, 3, timed_out=True)["state"] == "incomplete"


def test_logs_filter_changed_in_session_is_verified_from_a_new_session():
    primary = LogShell(changes=True)
    recovery = LogShell()
    result, _, _, _ = d.run(primary, "logs", IP, INTERFACE, 3, 1, reconnect=_reconnect_to(recovery))
    assert result["state"] == "unsupported"
    assert recovery.commands == ["get system status", "execute log filter dump"]


def test_unmeasured_log_filter_is_never_displayed():
    shell = LogShell(dump=LOG_DUMP.replace("\nOftp search string: ", ""))
    with pytest.raises(ValueError):
        d.run(shell, "logs", IP, INTERFACE, 3, 1)
    assert set(_log_commands(shell)) == {"execute log filter dump"}


def test_logs_recipe_is_accepted_and_audited(tmp_path):
    d.validate("logs", IP, INTERFACE, 3, 1, 16000)
    from netops_core.audit import Recorder
    from netops_helper.engine import _audit_fields
    from netops_helper.read_policy import _validate_slot
    recorder = Recorder(tmp_path/"audit.jsonl", "helper")
    window = {"recipe": "logs", "since": "2026-01-02 00:00:00", "until": "2026-01-03 23:59:59"}
    recorder.record("fortios_diagnostics", **_audit_fields(window, {}))
    import json
    event = json.loads(recorder.path().read_text())
    assert event["recipe"] == "logs" and event["since"] == window["since"] and event["until"] == window["until"]
    assert _audit_fields({"since": "2026-02-30 00:00:00"}, {})["since"] == "<invalid>"
    assert _validate_slot("logs", "fortios_diagnostic_recipe") == "logs"
    adc_recipe = {"recipe": "system_event_logs", "count": 20, "timeout": 20, "max_bytes": 16384}
    adc_recorder = Recorder(tmp_path/"adc-audit.jsonl", "helper")
    adc_recorder.record("fortios_diagnostics", **_audit_fields(adc_recipe, {}, "fortiadc"))
    adc_event = json.loads(adc_recorder.path().read_text())
    assert adc_event["recipe"] == "system_event_logs" and adc_event["count"] == 20
    assert _audit_fields(adc_recipe, {}, "fortinet")["recipe"] == "<invalid>"
    assert _audit_fields({"recipe": "waf_attack_logs"}, {}, "fortiadc")["recipe"] == "waf_attack_logs"
    assert _validate_slot("waf_attack_logs", "fortios_diagnostic_recipe") == "waf_attack_logs"


from netops_helper import fortiadc_diagnostics as adc

ADC_STATUS = "Version: FortiADC-KVM v7.6.7,build0676,260522 (GA.M)\n"
ADC_DATA = ('begin to search logs\n'
            'date=2026-10-30 time=16:23:46 type="event" subtype="system" msg=System event\n'
            'display 20 lines log messages one time at most,you can tune the starline if you want to see more logs\n')


class ADCEventShell:
    def __init__(self, filter_show=""):
        self.filter_show = filter_show
        self.selected = False
        self.commands = []

    def command(self, command, timeout=10):
        self.commands.append(command)
        if command == "get system status":
            return ADC_STATUS
        if command == "execute log filter show":
            return self.filter_show
        if command == "execute log display 0":
            return ADC_DATA if self.selected else adc.DISPLAY_REFUSAL
        if command in ("execute log filter type event", "execute log filter subtype system",
                       "execute log filter type attack", "execute log filter subtype waf"):
            self.selected = True
            return ""
        if command == "execute log filter clear":
            self.selected = False
            self.filter_show = ""
            return ""
        raise AssertionError(command)

    def interrupt(self):
        return None


class ADCEventAuth:
    ssh_platform = "fortiadc"
    enabled_queries = ("system_status",)
    read_inventory = {"diagnostic_recipes": ("system_event_logs",)}
    def require_ssh_query(self, platform, query):
        assert (platform, query) == ("fortiadc", "system_status")


def test_fortiadc_system_event_recipe_uses_fixed_selectors_and_restores_empty_filter():
    auth = ADCEventAuth()
    adc.authorize(auth, "system_event_logs")
    adc.validate("system_event_logs", "", "", 1, 20, 16384)
    shell = ADCEventShell()
    result = adc.run(shell, 1, 20)
    assert not result["timed_out"] and result["ok"] and result["state"] == "data"
    assert result["line_count"] == 1 and result["cleanup"] == "verified"
    assert "System event" in result["output"]
    assert result["identity"] == ("FortiADC-KVM", "7.6.7", "0676")
    assert shell.commands == [
        "get system status",
        "execute log filter show",
        "execute log display 0",
        "execute log filter type event",
        "execute log filter subtype system",
        "execute log display 0",
        "execute log filter clear",
        "execute log filter show",
        "execute log display 0",
    ]


def test_fortiadc_waf_attack_recipe_uses_fixed_selectors_and_restores_empty_filter():
    auth = ADCEventAuth()
    auth.read_inventory = {"diagnostic_recipes": ("waf_attack_logs",)}
    adc.authorize(auth, "waf_attack_logs")
    adc.validate("waf_attack_logs", "", "", 1, 20, 16384)
    shell = ADCEventShell()
    result = adc.run(shell, 1, 20, recipe="waf_attack_logs")
    assert result["ok"] and result["state"] == "data" and result["cleanup"] == "verified"
    assert shell.commands == [
        "get system status",
        "execute log filter show",
        "execute log display 0",
        "execute log filter type attack",
        "execute log filter subtype waf",
        "execute log display 0",
        "execute log filter clear",
        "execute log filter show",
        "execute log display 0",
    ]
    with pytest.raises(ValueError):
        adc.authorize(ADCEventAuth(), "waf_attack_logs")


def test_fortiadc_system_event_recipe_refuses_nonempty_baseline_before_mutation():
    shell = ADCEventShell("type: traffic")
    with pytest.raises(ValueError):
        adc.run(shell, 1, 20)
    assert shell.commands == ["get system status", "execute log filter show"]
    assert not shell.selected


ADC_VS = "VS_APP_HTTP"


def adc_state_show(family, flag="0", virtual_server="any"):
    fields = list(adc.STATE_FIELDS[family])
    values = {key: "any" for key in fields}
    values["virtual server"] = virtual_server
    lines = ["filter flag:" + flag] if family == "persistence" else ["filter flag: " + flag]
    return "\n".join(lines + [f"{key}: {values[key]}" for key in fields]) + "\n"


class ADCStateShell:
    def __init__(self, family, baseline=None, rows=(), selected_vs=ADC_VS, restore=True, header=None):
        self.family = family
        self.prefix = "diagnose server-load-balance " + family
        self.baseline = adc_state_show(family) if baseline is None else baseline
        self.current = self.baseline
        self.rows = rows
        self.selected_vs = selected_vs
        self.restore = restore
        self.header = adc.LIST_HEADERS[family] if header is None else header
        self.commands = []

    def command(self, command, timeout=10):
        self.commands.append(command)
        if command == "get system status":
            return ADC_STATUS
        if command == self.prefix + " filter show":
            return self.current
        if command == self.prefix + " filter 'vs-name " + ADC_VS + "'":
            self.current = adc_state_show(self.family, "1000", self.selected_vs)
            return ""
        if command == self.prefix + " list":
            return "\n".join([self.header] + list(self.rows)) + "\n"
        if command == self.prefix + " filter clear":
            self.current = self.baseline if self.restore else adc_state_show(self.family, "1000", ADC_VS)
            return ""
        raise AssertionError(command)

    def interrupt(self):
        return None


def adc_state_sequence(family):
    prefix = "diagnose server-load-balance " + family
    return ["get system status", prefix + " filter show", prefix + " filter 'vs-name " + ADC_VS + "'",
            prefix + " filter show", prefix + " list", prefix + " filter clear", prefix + " filter show"]


@pytest.mark.parametrize("recipe,family", [("session_list", "session"), ("persistence_list", "persistence")])
def test_fortiadc_state_list_selects_enrolled_virtual_server_and_restores_empty_filter(recipe, family):
    auth = ADCEventAuth()
    auth.read_inventory = {"diagnostic_recipes": (recipe,), "diagnostic_virtual_servers": (ADC_VS,)}
    adc.authorize(auth, recipe, ADC_VS)
    adc.validate(recipe, ADC_VS, "", 50, 10, 16384)
    shell = ADCStateShell(family)
    result = adc.run_state_list(shell, recipe, ADC_VS, 3, 10)
    assert result["ok"] and result["state"] == "data" and result["cleanup"] == "verified"
    assert result["header_only"] and result["returned_records"] == 0 and result["virtual_server"] == ADC_VS
    assert shell.commands == adc_state_sequence(family)
    assert not any(command.endswith((" session clear", " persistence clear")) for command in shell.commands)
    rows = ADCStateShell(family, rows=("row 1", "row 2"))
    listed = adc.run_state_list(rows, recipe, ADC_VS, 1, 10)
    assert listed["ok"] and not listed["header_only"] and listed["count_truncated"]
    assert listed["loaded_records"] == 2 and listed["returned_records"] == 1
    assert listed["output"] == adc.LIST_HEADERS[family] + "\nrow 1"
    unknown = adc.run_state_list(ADCStateShell(family, header="other header"), recipe, ADC_VS, 3, 10)
    assert not unknown["ok"] and unknown["state"] == "incomplete" and unknown["unrecognized_body"]
    assert unknown["cleanup"] == "verified"


def test_fortiadc_state_list_refuses_existing_filter_before_mutation():
    shell = ADCStateShell("session", baseline=adc_state_show("session", "1000", "OTHER_VS"))
    with pytest.raises(ValueError, match="not replaced"):
        adc.run_state_list(shell, "session_list", ADC_VS, 3, 10)
    assert shell.commands == adc_state_sequence("session")[:2]


def test_fortiadc_state_list_clears_after_unexpected_filter_readback():
    shell = ADCStateShell("persistence", selected_vs="OTHER_VS")
    result = adc.run_state_list(shell, "persistence_list", ADC_VS, 3, 10)
    assert not result["ok"] and result["state"] == "incomplete" and result["cleanup"] == "verified"
    sequence = adc_state_sequence("persistence")
    assert shell.commands == sequence[:4] + sequence[5:]


def test_fortiadc_state_list_reports_unverified_restore():
    shell = ADCStateShell("session", restore=False)
    result = adc.run_state_list(shell, "session_list", ADC_VS, 3, 10)
    assert not result["ok"] and result["state"] == "incomplete" and result["cleanup"] == "unverified"


def test_fortiadc_state_list_requires_enrolled_valid_virtual_server(tmp_path):
    auth = ADCEventAuth()
    auth.read_inventory = {"diagnostic_recipes": ("session_list",), "diagnostic_virtual_servers": (ADC_VS,)}
    with pytest.raises(ValueError, match="not enrolled"):
        adc.authorize(auth, "session_list", "OTHER_VS")
    with pytest.raises(ValueError):
        adc.validate("session_list", "VS' ; x", "", 3, 10, 16000)
    from netops_helper.engine import _audit_fields
    from netops_helper.read_policy import _validate_slot
    assert _validate_slot(ADC_VS, "fortiadc_virtual_server") == ADC_VS
    with pytest.raises(ValueError):
        _validate_slot("VS'x", "fortiadc_virtual_server")
    from netops_core.audit import Recorder
    import json
    for recipe in ("session_list", "persistence_list"):
        recorder = Recorder(tmp_path/(recipe + ".jsonl"), "helper")
        recorder.record("fortios_diagnostics", status="ok",
                        **_audit_fields({"recipe": recipe}, {"virtual_server": ADC_VS}, "fortiadc"))
        event = json.loads(recorder.path().read_text())
        assert event["recipe"] == recipe and event["virtual_server"] == ADC_VS
