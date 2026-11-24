"""Junos overview through the real bridge, with transport captures."""

from collections import Counter
from pathlib import Path

import pytest

from netops_core import ssh
from netops_helper import engine
from test_network_overview import setup  # noqa: F401
from test_network_overview_eos import enrolled, overview

FIXTURES = Path(__file__).parent / "fixtures"
BASE = FIXTURES / "real/juniper_junos_els/vjunosswitch_26.2R1.7"
ELS = "juniper_junos_els"
CLASSIC = "juniper_junos"
PORT = "ge-0/0/0"
PORT_COMMAND = f"show interfaces {PORT} extensive | no-more"
JUNOS_QUERIES = {
    "show version | no-more": "version",
    "show chassis routing-engine | no-more": "routing_engine",
    "show interfaces terse | no-more": "interfaces",
    "show chassis environment | no-more": "environment",
    "show poe controller | no-more": "poe_controller",
    "show system license | no-more": "licenses",
    "show system uptime | no-more": "uptime",
    "show virtual-chassis status | no-more": "virtual_chassis",
    "show virtual-chassis vc-port | no-more": "virtual_chassis_ports",
    PORT_COMMAND: "interface_details",
}


def junos_output(command):
    return (BASE / (JUNOS_QUERIES[command] + ".txt")).read_text()


def test_junos_els_enrolled_physical_scope_and_explicit_absence(setup):
    setup.configure(enrolled("switch", 11, ELS, JUNOS_QUERIES.values(), interfaces=(PORT, PORT + ".0")))
    setup.handlers["192.0.2.11"] = lambda cmd, _: junos_output(cmd)
    row, = overview(setup)
    assert (row["model"], row["version"], row["uptime_seconds"]) == ("ex9214", "26.2R1.7", 10034)
    assert row["cpu"] == {"used_pct": 100, "sample_seconds": 300}
    assert row["memory"] == {"used_pct": 29, "used_bytes": None, "total_bytes": None}
    assert row["licenses"] == []
    assert row["poe"] is None
    assert {"field": "poe", "reason": "not_applicable", "read_id": "poe_controller"} in row["missing"]
    interfaces = row["interfaces"]
    assert interfaces["scope"] == "enrolled_interfaces"
    assert [item["name"] for item in interfaces["admin_up_down"]] == [f"ge-0/0/{n}" for n in range(1, 10)]
    assert all(finding["code"] != "interface_errors_present" for finding in row["findings"])
    assert interfaces["with_errors"] == []
    assert setup.calls.count(("192.0.2.11", PORT_COMMAND)) == 1
    assert all("show interfaces extensive" not in command for _, command in setup.calls)


def test_vjunos_identity_and_reads_with_real_answers_are_complete(setup):
    """vJunos-switch 26.2R1.7 as read live: a stopped VC control process and an empty chassis environment are the
    device's valid answers on this standalone virtual switch, so no field is unparsed."""
    setup.configure(enrolled("switch", 11, ELS, JUNOS_QUERIES.values(), interfaces=(PORT,)))
    setup.handlers["192.0.2.11"] = lambda cmd, _: junos_output(cmd)
    row, = overview(setup)
    states = {item["id"]: item["status"] for item in row["reads"]}
    assert states["version"] == "ok" and row["version"] == "26.2R1.7"
    assert states["virtual_chassis"] == states["environment"] == "empty"
    assert states["virtual_chassis_ports"] == "not_run"
    # Junos reads error counters of enrolled interfaces only: the scope limit is the one remaining gap.
    assert [(entry["field"], entry["reason"]) for entry in row["missing"] if entry["reason"] != "not_applicable"] == [
        ("interfaces.with_errors", "source_limit")]
    assert {"field": "redundancy", "reason": "not_applicable", "read_id": "virtual_chassis_ports"} in row["missing"]
    for field in ("temperatures", "fans", "power"):
        assert {"field": field, "reason": "not_applicable", "read_id": "environment"} in row["missing"]


def test_vjunos_virtual_chassis_with_unexpected_exit_code_stays_unparsed(setup):
    setup.configure(enrolled("switch", 11, ELS, JUNOS_QUERIES.values(), interfaces=(PORT,)))

    def with_failed_virtual_chassis(command, _):
        return (1 if JUNOS_QUERIES[command] == "virtual_chassis" else 0), junos_output(command)

    setup.handlers["192.0.2.11"] = with_failed_virtual_chassis
    row, = overview(setup)
    states = {item["id"]: item["status"] for item in row["reads"]}
    assert states["virtual_chassis"] == "incomplete"
    assert states["virtual_chassis_ports"] == "not_run"
    for read_id in ("virtual_chassis", "virtual_chassis_ports"):
        assert {"field": "redundancy", "reason": "unparsed", "read_id": read_id} in row["missing"]
    assert row["status"] == "partial"


def test_empty_environment_of_a_physical_identity_stays_unparsed(setup):
    setup.configure(enrolled("switch", 11, ELS, JUNOS_QUERIES.values(), interfaces=(PORT,)))
    physical = "\n".join(line for line in junos_output("show version | no-more").splitlines()
                         if not line.startswith("JUNOS Simulation"))
    setup.handlers["192.0.2.11"] = lambda cmd, _: physical if cmd == "show version | no-more" else (
        "error: the virtual-chassis-control subsystem is busy\n" if cmd == "show virtual-chassis status | no-more"
        else junos_output(cmd))
    row, = overview(setup)
    reasons = {(entry["field"], entry["reason"], entry.get("read_id")) for entry in row["missing"]}
    assert ("temperatures", "unparsed", "environment") in reasons
    assert ("redundancy", "unparsed", "virtual_chassis") in reasons
    assert row["status"] == "partial"


def test_stopped_vc_process_of_a_physical_identity_stays_unparsed(setup):
    """Review finding 3: the vJunos answer (real capture) on a physical identity can be a stopped VC
    process of a configured stack; neither the stack nor its ports become `not_applicable`."""
    setup.configure(enrolled("switch", 11, ELS, JUNOS_QUERIES.values(), interfaces=(PORT,)))
    physical = "\n".join(line for line in junos_output("show version | no-more").splitlines()
                         if not line.startswith("JUNOS Simulation"))
    stopped = junos_output("show virtual-chassis status | no-more")
    assert stopped.strip() == "error: the virtual-chassis-control subsystem is not running"
    setup.handlers["192.0.2.11"] = lambda cmd, _: physical if cmd == "show version | no-more" else junos_output(cmd)
    row, = overview(setup)
    states = {item["id"]: item["status"] for item in row["reads"]}
    assert states["version"] == "ok" and states["virtual_chassis"] == "incomplete"
    redundancy = {(entry["reason"], entry.get("read_id")) for entry in row["missing"] if entry["field"] == "redundancy"}
    assert ("unparsed", "virtual_chassis") in redundancy
    assert all(reason != "not_applicable" for reason, _ in redundancy)
    assert row["status"] == "partial"


def test_vjunos_failed_environment_read_with_empty_stdout_stays_unparsed(setup, monkeypatch):
    """Review finding 4: only the measured exit 0 with empty output is the vJunos environment answer. A
    refused read (exit 1, empty stdout, refusal on stderr) is not a confirmed absence of sensors."""
    setup.configure(enrolled("switch", 11, ELS, JUNOS_QUERIES.values(), interfaces=(PORT,)))
    setup.handlers["192.0.2.11"] = lambda cmd, _: junos_output(cmd)
    transport = engine.core_ssh.run_command

    def refusing(host, port, login, credential, pin, command, **options):
        if command == "show chassis environment | no-more":
            return ssh.Result(1, b"", "", "", "", stderr=b"error: permission denied\n")
        return transport(host, port, login, credential, pin, command, **options)

    monkeypatch.setattr(engine.core_ssh, "run_command", refusing)
    row, = overview(setup)
    states = {item["id"]: item["status"] for item in row["reads"]}
    assert states["version"] == "ok" and states["virtual_chassis"] == "empty"
    assert states["environment"] == "incomplete"
    for field in ("temperatures", "fans", "power"):
        assert {"field": field, "reason": "unparsed", "read_id": "environment"} in row["missing"]
        assert {"field": field, "reason": "not_applicable", "read_id": "environment"} not in row["missing"]
    assert row["status"] == "partial"


@pytest.mark.parametrize("rx_errors", [0, 2])
def test_junos_els_drops_are_excluded_from_interface_errors(setup, rx_errors):
    setup.configure(enrolled("switch", 11, ELS, JUNOS_QUERIES.values(), interfaces=(PORT,)))
    details = junos_output(PORT_COMMAND).replace(
        "Errors: 0, Drops: 0, Framing errors:", f"Errors: {rx_errors}, Drops: 7, Framing errors:",
    ).replace("Errors: 0, Drops: 0, Collisions:", "Errors: 0, Drops: 11, Collisions:")
    setup.handlers["192.0.2.11"] = lambda cmd, _: details if cmd == PORT_COMMAND else junos_output(cmd)

    row, = overview(setup)
    error_findings = [finding for finding in row["findings"] if finding["code"] == "interface_errors_present"]
    assert len(error_findings) == int(bool(rx_errors))
    assert row["interfaces"]["with_errors"] == ([{
        "name": PORT,
        "counters": {"rx_errors": rx_errors, "tx_errors": 0, "crc": 0},
        "counter_kind": "cumulative",
        "read_ids": ["interface_details:1"],
    }] if rx_errors else [])


def test_junos_active_member_is_explicit_and_ambiguity_keeps_other_fields(setup):
    setup.configure(enrolled("ambiguous", 11, ELS, JUNOS_QUERIES.values()),
                    enrolled("master-known", 12, ELS, JUNOS_QUERIES.values()))
    version = (FIXTURES / "identity/synthetic_juniper_junos_vc_mixed.txt").read_text()
    active = junos_output("show chassis routing-engine | no-more")
    standby = active.replace("Current state                  Master", "Current state                  Backup")
    for host, engines in (("192.0.2.11", active), ("192.0.2.12", standby)):
        responses = {"version": version, "routing_engine": f"fpc0:\n{engines}\nfpc1:\n{active}"}
        setup.handlers[host] = lambda cmd, _, responses=responses: (
            responses[JUNOS_QUERIES[cmd]] if JUNOS_QUERIES[cmd] in responses else junos_output(cmd)
        )
    ambiguous, known = overview(setup)
    assert ambiguous["model"] is None and ambiguous["cpu"] is None
    assert ambiguous["licenses"] == []
    assert known["model"] == "ex4300-48t"
    assert known["cpu"]["sample_seconds"] == 300


def test_junos_refusal_truncation_budget_and_srx_group(setup, monkeypatch):
    capture_max_bytes = 8192
    monkeypatch.setattr(engine, "_SSH_CAPTURE_MAX_BYTES", capture_max_bytes)
    srx = (FIXTURES / "docs/juniper_junos/junos-security/chassis_cluster_status.out").read_text()
    setup.configure(enrolled("bounded", 11, ELS, JUNOS_QUERIES.values(), requests=3, interfaces=(PORT,)),
                    enrolled("firewall", 12, CLASSIC, (*set(JUNOS_QUERIES.values()) - {
                        "poe_controller", "virtual_chassis", "virtual_chassis_ports"}, "chassis_cluster_status"),
                             types=("firewall",)),
                    enrolled("limit", 13, ELS, JUNOS_QUERIES.values(), interfaces=(PORT,)))
    setup.handlers["192.0.2.11"] = lambda cmd, _: junos_output(cmd)
    setup.handlers["192.0.2.12"] = lambda cmd, _: {
        "show version | no-more": junos_output("show version | no-more").replace("ex9214", "srx345"),
        "show chassis cluster status | no-more": srx.replace("secondary      no      no       None",
                                                              "secondary      no      no       IF", 1),
    }.get(cmd) or junos_output(cmd)
    setup.handlers["192.0.2.13"] = lambda cmd, _: (
        "error: permission denied: requires permission\n" if cmd == "show poe controller | no-more" else
        junos_output(cmd).ljust(capture_max_bytes + 1) if cmd == PORT_COMMAND else junos_output(cmd)
    )
    bounded, firewall, limit = overview(setup)
    assert any(entry["reason"] == "read_limit" for entry in bounded["missing"])
    assert [group["state"] for group in firewall["redundancy"]] == ["degraded", "ok"]
    assert [group["group"] for group in firewall["redundancy"]] == [0, 1]
    assert limit["interfaces"]["with_errors"] is None
    assert {(entry.get("read_id"), entry["reason"]) for entry in limit["missing"]} >= {
        ("poe_controller", "permission_denied"), ("interface_details:1", "truncated"),
    }
    assert limit["licenses"] == []
    assert Counter(host for host, _ in setup.calls)["192.0.2.11"] == 3
