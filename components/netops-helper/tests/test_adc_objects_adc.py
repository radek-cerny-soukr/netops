"""ADC-OBJECTS (ADC-C12, ADC-FIREWALL-ROUTING) with anonymized FortiADC-KVM 7.6.7 build0676 captures (fortiadc-kvm, 2026-11-17, verification).

The captures are REAL terminal reads (see the fixture PROVENANCE.md): the echoed command, the device answer and the
next prompt. Only the SSH boundary is faked; read policy, framing, refusal handling and the capture parser run as built.
Lines marked DERIVED change a real capture in one stated way.
"""
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import json
import threading

import pytest

from conftest import _calls, _fortinet_wire, _target
from netops_helper import engine, fortiadc_diagnostics as adc, proxy, read_policy
from netops_helper.query_catalog import READ_QUERIES

FIXTURES = Path(__file__).parent / "fixtures/real/fortiadc/fortiadc-kvm_7.6.7_adc_objects_20261117"
PROMPTS = ("FortiADC-KVM #", "FortiADC-KVM $")
STATUS = "Version: FortiADC-KVM v7.6.7,build0676,260522 (GA.M)\n"
CLIENT, VS, UNUSED = "198.51.100.100", "198.51.100.10", "198.51.100.99"
APPLIANCE, BACKEND = "192.0.2.1", "192.0.2.11"


def raw(name):
    with open(FIXTURES / name, encoding="utf-8", newline="") as handle:
        return handle.read()


def command_of(name):
    return raw(name).split("\n", 1)[0]


def body(name):
    lines = raw(name).split("\n")[1:]
    return "\n".join(line for line in lines if line.strip() not in PROMPTS).strip("\n") + "\n"


def packet_lines(name):
    return [line.rstrip() for line in body(name).splitlines() if " -- " in line]


# --- ADC-C12: every interface in one read ------------------------------------------------------------------------
# The exec captures are the measured body, replayed on the held terminal.

def _terminal_body(text):
    body = text.removeprefix("FortiADC-KVM # ").removesuffix("FortiADC-KVM # ")
    return body + "\n" if body and not body.endswith("\n") else body


def exec_read(wire, query, name, *, disconnect=False, stderr=""):
    command = READ_QUERIES["fortiadc"][query].command
    body = _terminal_body(raw(name)) + stderr
    _fortinet_wire(wire, {"get system status": STATUS, command: None if disconnect else body})
    auth = replace(_target("fortiadc", query), enabled_queries=("system_status", query))
    answer = engine.ssh_read(auth, "fortiadc", query, {}, 0, 48000)
    return answer, wire["transcript"].read_text().splitlines()


def exec_body(name):
    return _terminal_body(raw(name))


@pytest.mark.parametrize("query,name,expected", [
    ("interface_list", "exec-system-interface-all.out", ["== [ port%d ]" % number for number in range(1, 6)]),
    ("interface_state_all", "exec-netlink-interface-list-all.out",
     ["if=port%d family=00 type=1" % number for number in range(1, 6)] + ["if=haport0 ", "if=vsport-"]),
    ("nic_detail_all", "exec-nic-detail-all.out",
     ["Settings for port%d:" % number for number in range(1, 6)] + ["Interface: port%d" % number for number in
                                                                     range(1, 6)]),
])
def test_all_interfaces_in_one_read_match_the_device(wire, query, name, expected):
    answer, commands = exec_read(wire, query, name)
    assert answer["ok"] and answer["complete"], answer
    text = answer["untrusted_device_output"]
    assert text.strip() == exec_body(name).strip()
    assert all(item in text for item in expected)
    assert commands[-1] == READ_QUERIES["fortiadc"][query].command
    assert set(commands) <= {"get system status", READ_QUERIES["fortiadc"][query].command, "127.0.0.1"}


@pytest.mark.parametrize("scenario", ["full", "missing_rows", "second_read_failed", "paged"])
def test_interface_summary_joins_the_two_exec_reads(wire, scenario):
    interfaces = raw("exec-system-interface-all.out")
    nic = raw("exec-nic-detail-all.out")
    missing_rows = scenario == "missing_rows"
    if missing_rows:
        # DERIVED: one interface only in NIC detail, one only in the configuration.
        interfaces = interfaces[:interfaces.index("== [ port5 ]")] + "FortiADC-KVM # "
        nic = nic.replace("Settings for port4:", "Settings for port6:").replace("Interface: port4", "Interface: port6")
    if scenario == "paged":
        # DERIVED: reproduce the five measured interface blocks with five new names to exceed one page.
        interfaces = interfaces.removesuffix("FortiADC-KVM # ") + exec_body("exec-system-interface-all.out").replace(
            "port", "extra") + "FortiADC-KVM # "
        nic = nic.removesuffix("FortiADC-KVM # ") + exec_body("exec-nic-detail-all.out").replace(
            "port", "extra") + "FortiADC-KVM # "
    commands = ("get system interface", "diagnose hardware get deviceinfo nic-detail")
    _fortinet_wire(wire, {"get system status": STATUS, commands[0]: _terminal_body(interfaces),
                          commands[1]: None if scenario == "second_read_failed" else _terminal_body(nic)})
    query = "interface_summary"
    args = {"target": "adc", "platform": "fortiadc", "query": query}
    proxy.Proxy._validate_tool_arguments("ssh_read", args)
    auth = replace(_target("fortiadc", query), enabled_queries=("system_status", query))
    answer = engine.ssh_read(auth, "fortiadc", query, {}, 0, 1000 if scenario == "paged" else 48000)
    sent = wire["transcript"].read_text().splitlines()
    assert len(_calls(wire)) == 1
    assert [command for command in sent if command in commands] == list(commands)
    if scenario == "second_read_failed":
        assert not answer["ok"] and not answer["complete"] and answer["error_code"] == "disconnected", answer
        assert "interfaces" not in answer
        return
    if scenario == "paged":
        assert answer["ok"] and not answer["complete"] and answer["next_offset"]
        continuation = engine.ssh_read(auth, "fortiadc", query, {}, answer["next_offset"], 1000,
                                       answer["content_sha256"])
        assert continuation["ok"] and continuation["complete"] and continuation["pagination_source"] == "cached"
        assert len(answer["interfaces"] + continuation["interfaces"]) == 10
        assert len(_calls(wire)) == 1
        return
    assert answer["ok"] and answer["complete"] == (not missing_rows), answer
    rows = {row["name"]: row for row in answer["interfaces"]}
    assert rows["port2"] == {"name": "port2", "ipv4": "198.51.100.1/24", "ipv6": "::/0",
                             "admin_status": "up", "link_up": True, "speed_mbps": 10000, "complete": True}
    if missing_rows:
        assert set(rows) == {"port1", "port2", "port3", "port4", "port5", "port6"}
        assert rows["port4"]["link_up"] is None and rows["port4"]["speed_mbps"] is None
        assert rows["port4"]["missing_sources"] == ["nic_detail_all"] and not rows["port4"]["complete"]
        assert all(rows["port5"][field] is None for field in ("ipv4", "ipv6", "admin_status"))
        assert rows["port5"]["missing_sources"] == ["interface_list"] and not rows["port5"]["complete"]
    else:
        assert set(rows) == {"port1", "port2", "port3", "port4", "port5"}
        assert all(row["admin_status"] == "up" and row["link_up"] and row["speed_mbps"] == 10000
                   for row in rows.values())


@pytest.mark.parametrize("query,name", [
    ("interface_list", "exec-system-interface-all.out"),
    ("interface_state_all", "exec-netlink-interface-list-all.out"),
    ("nic_detail_all", "exec-nic-detail-all.out"),
])
def test_disconnected_interface_read_is_unsuccessful(wire, query, name):
    answer, _ = exec_read(wire, query, name, disconnect=True)
    assert not answer["ok"] and not answer["complete"] and answer["error_code"] == "disconnected", answer


def test_interface_queries_take_no_parameter_and_the_named_variant_still_needs_one():
    inventory = {"interfaces": ("port1",)}
    for query, command in (("interface_list", "get system interface"),
                           ("interface_state_all", "diagnose netlink interface list"),
                           ("nic_detail_all", "diagnose hardware get deviceinfo nic-detail")):
        assert read_policy.render_read_query("fortiadc", query, {}, inventory) == ("fortiadc", command)
        with pytest.raises(ValueError):
            read_policy.render_read_query("fortiadc", query, {"interface": "port1"}, inventory)
    with pytest.raises(ValueError):
        read_policy.render_read_query("fortiadc", "interface_state", {}, inventory)
    assert proxy.READ_QUERY_NAMES["fortiadc"] >= {"interface_list", "interface_state_all", "nic_detail_all"}


@pytest.mark.parametrize("query,word", [("interface_list", "interface"), ("interface_state_all", "netlink"),
                                       ("nic_detail_all", "hardware")])
def test_read_only_profile_exec_refusal_is_permission_denied(wire, query, word):
    # Replay both parts of the measured exec refusal on the terminal.
    answer, _ = exec_read(wire, query, "exec-ro-refused.out",
                          stderr="Parsing error at '%s'. err=1\n" % word)
    assert not answer["ok"] and answer["error_code"] == "permission_denied", answer


# --- ADC-FIREWALL-ROUTING: bounded packet capture ------------------------------------------------------------------------------

class CaptureTransport:
    """Interactive transport answering with the real captures; an interrupted capture answers only after Ctrl-C."""

    def __init__(self, answers, interrupted=()):
        self.answers = answers
        self.interrupted = set(interrupted)
        self.commands = []
        self.interrupts = 0
        self.ctrl_c = threading.Event()
        self.prompt = b"FortiADC-KVM # "

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        pass

    def send(self, command):
        self.commands.append(command)

    def discard(self, _):
        pass

    def interrupt(self):
        self.interrupts += 1
        self.ctrl_c.set()

    def expect(self, _patterns, _timeout):
        if not self.commands:
            return self.prompt, self.prompt
        command = self.commands[-1]
        if command == "get system status":
            response = STATUS
        else:
            if command in self.interrupted:
                assert self.ctrl_c.wait(10), "the capture was not interrupted at the deadline"
            response = self.answers[command]
        return self.prompt, command.encode() + b"\r\n" + response.encode() + self.prompt


INVENTORY = {"diagnostic_recipes": ("packet_capture",), "interfaces": ("port2", "port3", "port9"),
             "addresses": (CLIENT, VS, UNUSED, APPLIANCE, BACKEND)}


def capture(monkeypatch, name, *, interrupted=False, inventory=INVENTORY, answer=None, **arguments):
    command = command_of(name)
    transport = CaptureTransport({command: body(name) if answer is None else answer},
                                 (command,) if interrupted else ())
    monkeypatch.setattr(engine.core_session, "fortinet_session", lambda *a, **kw: transport)
    monkeypatch.setattr(engine, "host_key_line", lambda *_: "pin checked by transport")
    monkeypatch.setattr(engine, "_paced_connection", lambda *_: nullcontext())
    monkeypatch.setattr(engine, "record", lambda *a, **kw: None)
    auth = replace(_target("fortiadc", "system_status"), read_inventory=inventory)
    result = engine.fortios_diagnostics(auth, "packet_capture", **arguments)
    assert transport.commands == ["get system status", command], transport.commands
    return result, transport


def test_client_and_virtual_server_capture_matches_the_cli(monkeypatch):
    result, transport = capture(monkeypatch, "capture-client-vs.out", address=VS, interface="port2", count=6,
                                source_address=CLIENT, destination_port=80)
    assert result["ok"] and result["complete"] and result["state"] == "count_reached", result
    assert result["filter"] == "host %s and host %s and port 80" % (CLIENT, VS)
    assert result["untrusted_device_output"].splitlines() == packet_lines("capture-client-vs.out")
    assert result["packets_returned"] == 6 and result["device_received"] is None and transport.interrupts == 0
    assert result["records"][0] == {"time_utc": "2026-11-17 22:00:17.568769", "interface": "port2",
                                    "source": CLIENT, "source_port": 45978, "destination": VS,
                                    "destination_port": 80, "detail": "syn 2762684402"}
    assert [row["detail"].split()[0] for row in result["records"]] == ["syn", "syn", "ack", "psh", "psh", "ack"]
    assert result["cleanup"] == "not_required" and not result["deadline_reached"]
    assert "warnings" not in result, result["firmware_support"]


def test_appliance_and_backend_capture_matches_the_cli(monkeypatch):
    result, _ = capture(monkeypatch, "capture-backend-pair.out", address=BACKEND, interface="port3", count=4,
                        source_address=APPLIANCE, destination_port=80)
    assert result["state"] == "count_reached" and result["packets_returned"] == 4, result
    assert {(row["source"], row["destination"]) for row in result["records"]} == {(APPLIANCE, BACKEND),
                                                                                  (BACKEND, APPLIANCE)}
    assert result["untrusted_device_output"].splitlines() == packet_lines("capture-backend-pair.out")


def test_fifty_packets_is_the_bound_and_is_returned_whole(monkeypatch):
    result, _ = capture(monkeypatch, "capture-count-50.out", address=CLIENT, interface="port2", count=50,
                        destination_port=80)
    assert result["state"] == "count_reached" and result["packets_returned"] == 50 and not result["truncated"]


def test_deadline_interrupts_and_returns_the_packets_seen(monkeypatch):
    result, transport = capture(monkeypatch, "capture-deadline-50.out", interrupted=True, address=CLIENT,
                                interface="port2", count=50, timeout=1, destination_port=80)
    assert transport.interrupts == 1
    assert result["ok"] and result["state"] == "deadline_reached" and result["deadline_reached"], result
    assert result["packets_returned"] == 27 == result["device_received"] and result["device_dropped"] == 0
    assert result["untrusted_device_output"].splitlines() == packet_lines("capture-deadline-50.out")
    assert "capture_summary" not in result


def test_no_matching_packet_is_an_empty_capture_not_a_verdict(monkeypatch):
    result, _ = capture(monkeypatch, "capture-no-match-interrupted.out", interrupted=True, address=UNUSED,
                        interface="port2", count=3, timeout=1)
    assert result["ok"] and result["state"] == "deadline_reached" and result["packets_returned"] == 0, result
    assert result["device_received"] == 0 and result["records"] == [] and result["untrusted_device_output"] == ""
    assert "neither that the traffic passes nor that it is blocked" in result["capture_summary"]


def test_unknown_interface_is_a_device_refusal(monkeypatch):
    result, _ = capture(monkeypatch, "capture-unknown-interface.out", address=CLIENT, interface="port9", count=3)
    assert not result["ok"] and result["state"] == "device_refused", result
    assert result["untrusted_device_output"].startswith("interfaces=[port9]")
    assert "pcap_open_live: port9: No such device exists" in result["untrusted_device_output"]


def test_invalid_filter_refusal_is_recognized():
    # The fixed filter never sends this; the measured refusal is still recognized as one.
    assert adc.CAPTURE_DEVICE_REFUSAL.search(body("capture-invalid-filter.out"))


def test_read_only_profile_is_permission_denied_with_advice(monkeypatch):
    result, _ = capture(monkeypatch, "ro-capture.out", address=CLIENT, interface="port2", count=3)
    assert not result["ok"] and result["state"] == "permission_denied", result
    assert result["error_code"] == "permission_denied" and result["reason"] == "diagnose_not_permitted"
    assert "system administrator" in result["error"]


def test_truncated_capture_is_incomplete(monkeypatch):
    # DERIVED: the real count-6 capture with its last packet line removed (the count was not reached).
    lines = body("capture-client-vs.out").splitlines()
    short = "\n".join(lines[:-1]) + "\n"
    result, _ = capture(monkeypatch, "capture-client-vs.out", answer=short, address=VS, interface="port2", count=6,
                        source_address=CLIENT, destination_port=80)
    assert not result["ok"] and result["state"] == "incomplete" and result["records"] == []


@pytest.mark.parametrize("original,replacement", [
    (CLIENT + ".45978 -> ", "198.51.100.101.45978 -> "),
    ("port2 -- ", "port3 -- "),
    (VS + ".80: ", VS + ".8080: "),
    (".45978 -> " + VS + ".80:", " -> " + VS + ":"),
])
def test_packet_outside_the_filter_is_withheld(monkeypatch, original, replacement):
    # DERIVED: replace one of the measured packet fields, keeping the original capture header.
    changed = body("capture-client-vs.out").replace(original, replacement, 1)
    result, _ = capture(monkeypatch, "capture-client-vs.out", answer=changed, address=VS, interface="port2", count=6,
                        source_address=CLIENT, destination_port=80)
    assert result["state"] == "incomplete" and not result["ok"]
    assert result["discarded_lines"] == 1 and replacement not in json.dumps(result)
    assert result["untrusted_device_output"].splitlines() == packet_lines("capture-client-vs.out")[1:]


def test_packets_past_requested_count_are_withheld(monkeypatch):
    # DERIVED: the real count-six response followed by one extra matching packet.
    extra = packet_lines("capture-client-vs.out")[-1].replace("45978", "54321")
    changed = body("capture-client-vs.out") + extra + "\n"
    result, _ = capture(monkeypatch, "capture-client-vs.out", answer=changed, address=VS, interface="port2", count=6,
                        source_address=CLIENT, destination_port=80)
    assert result["state"] == "incomplete" and not result["ok"]
    assert result["discarded_lines"] == 1 and "54321" not in json.dumps(result)
    assert result["untrusted_device_output"].splitlines() == packet_lines("capture-client-vs.out")


@pytest.mark.parametrize("missing", ["received by filter", "dropped by kernel"])
def test_deadline_needs_both_counters(monkeypatch, missing):
    changed = "\n".join(line for line in body("capture-deadline-50.out").splitlines() if missing not in line)
    result, _ = capture(monkeypatch, "capture-deadline-50.out", answer=changed, interrupted=True,
                        address=CLIENT, interface="port2", count=50, timeout=1, destination_port=80)
    assert result["deadline_reached"] and result["state"] == "incomplete" and not result["complete"], result


def test_deadline_with_positive_counter_and_no_rows_is_incomplete(monkeypatch):
    changed = "\n".join(line for line in body("capture-deadline-50.out").splitlines() if " -- " not in line)
    result, _ = capture(monkeypatch, "capture-deadline-50.out", answer=changed, interrupted=True,
                        address=CLIENT, interface="port2", count=50, timeout=1, destination_port=80)
    assert result["state"] == "incomplete" and not result["complete"], result
    assert result["device_received"] == 27 and result["packets_returned"] == 0
    assert "reported 27" in result["capture_summary"] and "no packet matched" not in result["capture_summary"]


@pytest.mark.parametrize("arguments,match", [
    ({"count": 51}, "count"),
    ({"timeout": 31}, "timeout"),
    ({"address": "198.51.100.200"}, "not enrolled"),
    ({"interface": "port4"}, "not enrolled"),
    ({"source_address": VS}, "differ"),
    ({"destination_port": 0}, "destination_port"),
    ({"address": "198.51.100.0/24"}, "unicast IPv4"),
    ({"source_port": 1000}, "packet_capture takes only"),
    ({"protocol": 6}, "packet_capture takes only"),
    ({"vdom": "root"}, "packet_capture takes only"),
])
def test_out_of_bound_or_unenrolled_capture_is_refused_before_any_command(monkeypatch, arguments, match):
    transport = CaptureTransport({})
    monkeypatch.setattr(engine.core_session, "fortinet_session", lambda *a, **kw: transport)
    monkeypatch.setattr(engine, "record", lambda *a, **kw: None)
    auth = replace(_target("fortiadc", "system_status"), read_inventory=INVENTORY)
    call = dict({"address": VS, "interface": "port2", "count": 3, "timeout": 10}, **arguments)
    with pytest.raises(ValueError, match=match):
        engine.fortios_diagnostics(auth, "packet_capture", **call)
    assert transport.commands == []


def test_recipe_enrollment_is_fortiadc_only():
    read_policy.validate_query_inventory("fortiadc", ("system_status",),
                                         {"diagnostic_recipes": ("packet_capture",)})
    with pytest.raises(ValueError):
        read_policy.validate_query_inventory("fortinet", ("system_status",),
                                             {"diagnostic_recipes": ("packet_capture",)})


def test_proxy_validates_and_authorizes_the_capture():
    validate = proxy.Proxy._validate_tool_arguments
    arguments = {"target": "adc", "recipe": "packet_capture", "address": VS, "interface": "port2",
                 "source_address": CLIENT, "destination_port": 80, "count": 6}
    assert validate("fortios_diagnostics", dict(arguments))["destination_port"] == 80
    for change in ({"count": 51}, {"timeout": 31}, {"interface": ""}, {"source_port": 1}, {"protocol": 6},
                   {"address": "198.51.100.0/24"}, {"destination_port": 70000}):
        with pytest.raises(proxy.ToolArgumentsError):
            validate("fortios_diagnostics", dict(arguments, **change))
    section = SimpleNamespace(catalog_platform=lambda: "fortiadc", enabled_queries=("system_status",), egress={},
                              read_inventory={"diagnostic_recipes": ("packet_capture",), "interfaces": ("port2",),
                                              "addresses": (CLIENT, VS)})
    args = {key: value for key, value in arguments.items() if key != "target"}
    proxy.Proxy._authorize_tool("fortios_diagnostics", args, None, section)
    for change in ({"interface": "port3"}, {"address": "198.51.100.200"}, {"source_address": "198.51.100.200"}):
        with pytest.raises(proxy.PolicyScopeError):
            proxy.Proxy._authorize_tool("fortios_diagnostics", dict(args, **change), None, section)
    fortios = SimpleNamespace(catalog_platform=lambda: "fortinet", enabled_queries=("system_status",), egress={},
                              read_inventory=section.read_inventory)
    with pytest.raises(proxy.PolicyScopeError):
        proxy.Proxy._authorize_tool("fortios_diagnostics", args, None, fortios)


def test_interface_summary_withholds_rows_if_redaction_changes_json_syntax(wire):
    _fortinet_wire(wire, {
        "get system status": STATUS,
        "get system interface": exec_body("exec-system-interface-all.out"),
        "diagnose hardware get deviceinfo nic-detail": exec_body("exec-nic-detail-all.out"),
    })
    query = "interface_summary"
    # A credential can coincide with a non-string token in the JSON Lines projection.
    auth = replace(_target("fortiadc", query, secret="true"), enabled_queries=("system_status", query))
    answer = engine.ssh_read(auth, "fortiadc", query, {}, 0, 48000)
    assert not answer["ok"] and not answer["complete"]
    assert answer["error_code"] == "incomplete_output"
    assert "interfaces" not in answer and "untrusted_device_output" not in answer
    assert _calls(wire)[0]["argv"].count("-tt") == 1
