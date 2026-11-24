"""EXOS network overview through the public Helper path with real captures at the SSH boundary.

The fake replaces only `core_ssh.run_command`, the host-key scan and the audit store. Negative
samples are marked copies of the listed real captures (see fixtures/overview_h2/PROVENANCE.md).
"""

import asyncio
import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from netops.worker import HelperBridge
from netops_core import ssh
from netops_core.audit import Recorder
from netops_helper import audit, engine, proxy, server
from netops_helper.overview import model, runner
from netops_helper.query_catalog.extreme import QUERIES
from test_proxy_contracts import _device, _egress, _egress_policy, _inventory, _write

FIXTURES = Path(__file__).parent / "fixtures"
X435 = FIXTURES / "real/exos/x435-8p-4s_33.7.1.6"
X440 = FIXTURES / "real/exos/x440g2-12p-10g4_33.7.1.6"
VM = FIXTURES / "real/exos/exosvm_33.6.1.14"
DOM = FIXTURES / "real/exos/dom_33.7.1.6_20261114"
HEALTH = FIXTURES / "real/exos/switch-health"
CAPTURES = json.loads((FIXTURES / "overview_h2/captures.json").read_text())
PRIORITY = ["version", "switch", "ports", "ports_rx_errors", "ports_tx_errors", "temperature", "fans", "power",
            "inline_power"]
BASE = [*PRIORITY, "cpu_monitoring", "memory", "stacking", "stacking_support", "mlag_peer", "mlag_ports", "licenses"]
SECRET = "exos-fixture-credential"
PAGER = "Press <SPACE> to continue or <Q> to quit:"
REFUSED = "This user does not have permissions for this command.\n"


def capture(key):
    item = CAPTURES[key]
    return item["rc"], item["output"]


def answers(directory):
    """Command -> (rc, output) from a real capture directory and its index."""
    index = json.loads((directory / "index.json").read_text())
    result = {}
    for query in BASE:
        result[QUERIES[query].command] = index[query]["rc"], (directory / f"{query}.txt").read_text()
    return result


def command(query, **parameters):
    return QUERIES[query].command.format(**parameters)


def edit(table, query, old, new, count=1):
    rc, text = table[command(query)]
    assert text.count(old) >= count, (query, old)
    table[command(query)] = rc, text.replace(old, new, count)


def device(alias, number, *, interfaces=(), optical_ports=(), optics=False, standalone=False, requests=60):
    address = f"192.0.2.{number}"
    egress = dict(_egress(), addresses=[address], tcp_ports=[22])
    enabled = [*dict.fromkeys(BASE), *(["interface_transceiver"] if optics else [])]
    switch_facts = [f"optical-port:{port}" for port in optical_ports]
    if standalone:
        switch_facts.append("redundancy-disabled")
    section = {"ssh_platform": "exos", "account_role": "read-only", "enabled_queries": enabled,
               "device_types": ["switch"], "read_inventory": {"interfaces": list(interfaces), "switches": switch_facts},
               "rate_limit": {"requests": requests, "window_seconds": 60}, "egress": egress}
    return dict(_device(section, "exos"), name=alias, address=address, credential=f"reader-{number}")


@pytest.fixture
def setup(tmp_path, monkeypatch):
    bridge = HelperBridge()
    calls, handlers = [], {}

    def configure(*devices):
        inv = _write(tmp_path / "inventory.json", _inventory(*devices))
        credentials = {entry["credential"]: {"kind": "password", "login": "reader", "value": SECRET}
                       for entry in devices}
        vault = _write(tmp_path / "vault.json", {"version": 2, "credentials": credentials}, 0o600)
        policy = _write(tmp_path / "egress.json", _egress_policy())
        monkeypatch.setattr(proxy, "INVENTORY", inv)
        monkeypatch.setattr(proxy, "VAULT", vault)
        monkeypatch.setattr(proxy, "EGRESS_POLICY", policy)
        monkeypatch.setattr(bridge.proxy, "_vault", lambda names=None: proxy.Proxy._vault(bridge.proxy, names))
        monkeypatch.setattr(bridge.proxy, "_load_egress_policy", lambda: proxy.Proxy._load_egress_policy(bridge.proxy))

    def transport(host, port, login, credential, pin, command, *, timeout_seconds, **options):
        # Subtracting the simulated monotonic timestamps can round past the cap.
        assert 0 < timeout_seconds <= model.READ_SECONDS + 1e-9
        calls.append((host, command))
        table = handlers[host]
        if callable(table):
            rc, text = table(command, timeout_seconds)
        else:
            rc, text = table[command]
        return ssh.Result(rc, text.encode(), "", "", "")

    monkeypatch.setattr(engine.core_hostkey, "scan", lambda *args, **kwargs: "test-pinned-key")
    monkeypatch.setattr(engine.core_ssh, "run_command", transport)
    monkeypatch.setattr(audit, "_RECORDER", Recorder(tmp_path / "operations.jsonl", "helper"))

    def call(args=None):
        result = asyncio.run(bridge.call(server.mcp, "network_overview", args or {}))
        assert not result["isError"], result
        assert json.loads(result["content"][0]["text"]) == result["structuredContent"]
        assert SECRET not in json.dumps(result)
        return result["structuredContent"]

    return SimpleNamespace(configure=configure, calls=calls, handlers=handlers, call=call, bridge=bridge)


def one(setup, table, *, interfaces=(), optical_ports=(), optics=False, standalone=False, requests=60):
    setup.configure(device("switch-a", 10, interfaces=interfaces, optical_ports=optical_ports,
                           optics=optics, standalone=standalone, requests=requests))
    setup.handlers["192.0.2.10"] = table
    return setup.call()["devices"][0]


def reasons(row, field):
    return {(item["reason"], item.get("read_id")) for item in row["missing"] if item["field"] == field}


def read(row, read_id):
    return next(item for item in row["reads"] if item["id"] == read_id)


def test_physical_switch_reports_every_field_from_real_captures(setup):
    table = answers(X440)
    table[command("interface_transceiver", interface="13")] = 0, (DOM / "sample_a-port13.txt").read_text()
    table[command("interface_transceiver", interface="14")] = 0, (DOM / "sample_b-port14.txt").read_text()
    row = one(setup, table, interfaces=("1", "13", "14"), optical_ports=("13", "14"), optics=True)

    assert row["status"] == "complete", row["missing"]
    assert row["reachability"] == "reachable"
    assert [item["status"] for item in row["reads"]] == ["ok"] * 18
    assert [command for _, command in setup.calls] == [*table]  # One SSH exec per planned catalogue read.
    assert (row["version"], row["model"], row["uptime_seconds"]) == (
        "33.7.1.6", "X440G2-12p-10G4", 20 * 86400 + 7 * 3600 + 39 * 60 + 3)
    assert row["firmware_support"]["device_version"] == "33.7.1.6-patch1-11"
    assert row["cpu"] == {"used_pct": 0.6, "sample_seconds": 5}
    assert row["memory"] == {"used_pct": 31.02, "total_bytes": 1048576 * 1024,
                             "used_bytes": (1048576 - 723324) * 1024}
    down = [item["name"] for item in row["interfaces"]["admin_up_down"]]
    assert down == ["2", "4", "6", "8", "10", "13", "14", "15", "16"]
    assert row["interfaces"]["with_errors"] == [] and row["interfaces"]["scope"] == "device"
    assert row["redundancy"] == [{"kind": "stack", "state": "standalone",
                                  "read_ids": ["stacking", "stacking_support"]}]
    assert row["temperatures"] == [
        {"name": "Switch : X440G2-12p-10G4", "state": "ok", "celsius": 80.0, "kind": "system",
         "read_ids": ["temperature"]},
        {"name": "port 13 transceiver", "state": "ok", "kind": "optic", "port": "13",
         "read_ids": ["interface_transceiver:1"], "celsius": 53.58},
    ]
    assert row["fans"] == [
        {"name": "Slot-1 FanTray", "state": "ok", "read_ids": ["fans"]},
        {"name": "Slot-1 FanTray Fan-1", "state": "ok", "read_ids": ["fans"], "rpm": 0},
        {"name": "Slot-1 FanTray Fan-2", "state": "ok", "read_ids": ["fans"], "rpm": 0},
    ]
    assert row["power"] == [{"name": "PowerSupply 1", "state": "ok", "read_ids": ["power"]}]
    assert row["poe"] == {"budget_w": 200.0, "used_w": 0.0, "available_w": 200.0}
    assert [item["name"] for item in row["licenses"]] == ["Advanced Edge", "AVB", "Quad 10G Uplink"]
    assert {item["state"] for item in row["licenses"]} == {"valid"}
    assert row["fortiguard"] is None and row["managed"] is None
    assert {item["reason"] for item in row["missing"]} == {"not_applicable"}
    assert [item["code"] for item in row["findings"]] == ["admin_up_link_down"] * 9
    assert read(row, "interface_transceiver:1")["source"] == {
        "transport": "ssh", "platform": "extreme_exos", "query": "interface_transceiver"}


def test_virtual_switch_has_no_hardware_poe_or_stacking_and_is_complete(setup):
    row = one(setup, answers(VM))
    assert (row["version"], row["model"]) == ("33.6.1.14", "EXOS-VM")
    for field, read_id in (("temperatures", "temperature"), ("fans", "fans"), ("power", "power"),
                           ("poe", "inline_power")):
        assert row[field] is None
        assert reasons(row, field) == {("not_applicable", read_id)}
    # Real answers (exit 250 and 254): the virtual switch states that stacking is not implemented and has no
    # stacking-support command. Both are valid answers that stacking does not apply, not unreadable output.
    assert read(row, "stacking")["status"] == read(row, "stacking_support")["status"] == "empty"
    assert reasons(row, "redundancy") == {("not_applicable", "stacking"), ("not_applicable", "stacking_support")}
    assert row["redundancy"] == []  # No MLAG peer and an explicit zero group count.
    assert row["status"] == "complete"
    assert row["cpu"]["sample_seconds"] == 5 and row["memory"]["total_bytes"] == 1048576 * 1024


@pytest.mark.parametrize("read_id", ["stacking", "stacking_support"])
def test_virtual_stacking_with_unexpected_exit_code_stays_unparsed(setup, read_id):
    table = answers(VM)
    _, output = table[command(read_id)]
    table[command(read_id)] = 1, output

    row = one(setup, table)
    assert read(row, read_id)["status"] == "incomplete"
    assert ("unparsed", read_id) in reasons(row, "redundancy")
    assert row["status"] == "partial"


def test_unrecognized_stacking_answers_stay_unparsed(setup):
    """Only the measured statements are recognized: a physical switch without the support command and a
    changed refusal text keep `unparsed`."""
    table = answers(X440)
    table[command("stacking_support")] = answers(VM)[command("stacking_support")]
    physical = one(setup, table)
    assert physical["model"] == "X440G2-12p-10G4"
    assert read(physical, "stacking_support")["status"] == "incomplete"
    assert ("unparsed", "stacking_support") in reasons(physical, "redundancy")
    vm = answers(VM)
    vm[command("stacking")] = 250, "Method is not implemented on this platform yet.\n"
    virtual = one(setup, vm)
    assert read(virtual, "stacking")["status"] == "incomplete"
    # Without the recognized stacking statement the support refusal is not interpreted either.
    assert reasons(virtual, "redundancy") == {("unparsed", "stacking"), ("unparsed", "stacking_support")}
    assert virtual["status"] == "partial"


def test_virtual_stacking_answer_on_a_physical_switch_stays_unparsed(setup):
    """Review finding 2: the EXOS-VM statement (real capture, exit 250) is not a stacking answer of a
    physical switch. Derived: the X440 support listing reports current stacking support Enabled."""
    table = answers(X440)
    edit(table, "stacking_support", "stacking-support:          Disabled           Disabled",
         "stacking-support:          Disabled           Enabled ")
    table[command("stacking")] = answers(VM)[command("stacking")]
    rc, answer = table[command("stacking")]
    assert (rc, answer.strip()) == (250, "Method is not implemented on this platform.")
    row = one(setup, table)
    assert row["model"] == "X440G2-12p-10G4"
    assert read(row, "stacking")["status"] == "incomplete"
    assert ("unparsed", "stacking") in reasons(row, "redundancy")
    assert ("not_applicable", "stacking") not in reasons(row, "redundancy")
    assert row["status"] == "partial"


def test_live_mlag_member_is_healthy_only_with_its_port_view(setup):
    table = answers(VM)
    table[command("mlag_peer")] = capture("extreme_exos/mlag_peer/vm-pair-member")
    table[command("mlag_ports")] = capture("extreme_exos/mlag_ports/vm-pair-member")
    table[command("ports")] = capture("extreme_exos/ports/vm-pair-member")
    row = one(setup, table)
    assert row["redundancy"] == [{"kind": "mlag", "state": "ok", "members": 1,
                                  "read_ids": ["mlag_peer", "mlag_ports"]}]
    assert [item["name"] for item in row["interfaces"]["admin_up_down"]] == ["8", "9", "10", "11", "12"]


def test_mlag_remote_link_down_degrades_an_up_checkpoint(setup):
    table = answers(VM)
    table[command("mlag_peer")] = capture("extreme_exos/mlag_peer/vm-pair-member")
    table[command("mlag_ports")] = capture("extreme_exos/mlag_ports/vm-pair-member")
    # Marked copy: change only Remote Link for the real MLAG group 104.
    edit(table, "mlag_ports", "104     5       A        Up", "104     5       A        Down")
    row = one(setup, table)
    assert row["redundancy"] == [{"kind": "mlag", "state": "degraded", "members": 1,
                                  "read_ids": ["mlag_peer", "mlag_ports"]}]
    assert {item["code"] for item in row["findings"]} >= {"redundancy_degraded"}


def test_mlag_peer_without_port_source_or_checkpoint_is_not_a_healthy_peer(setup):
    table = answers(VM)
    table[command("mlag_peer")] = capture("extreme_exos/mlag_peer/vm-pair-member")
    table[command("mlag_ports")] = 0, REFUSED
    row = one(setup, table)
    assert row["redundancy"] == [{"kind": "mlag", "state": "unknown", "read_ids": ["mlag_peer"]}]
    assert ("permission_denied", "mlag_ports") in reasons(row, "redundancy")
    assert not any(item["code"] == "redundancy_degraded" for item in row["findings"])


def test_mlag_without_checkpoint_or_with_contradicting_count_is_incomplete(setup):
    table = answers(VM)
    rc, text = capture("extreme_exos/mlag_peer/vm-pair-member")
    table[command("mlag_peer")] = rc, re.sub(r"(?m)^Checkpoint Status : Up", "Checkpoint Stat   : Up", text)
    table[command("mlag_ports")] = capture("extreme_exos/mlag_ports/vm-pair-member")
    row = one(setup, table)
    assert row["redundancy"][0]["state"] == "unknown"
    assert read(row, "mlag_peer")["status"] == "incomplete"

    setup.calls.clear()
    table = answers(VM)
    table[command("mlag_peer")] = 0, (HEALTH / "vm-mlag_peer.out").read_text()  # one group, zero in the port view
    row = one(setup, table)
    assert row["redundancy"][0]["state"] == "unknown" and row["redundancy"][0]["members"] == 0
    assert read(row, "mlag_peer")["status"] == read(row, "mlag_ports")["status"] == "incomplete"


def test_header_only_peer_without_group_count_is_not_an_absent_mlag(setup):
    table = answers(X440)
    table[command("mlag_ports")] = 0, REFUSED
    row = one(setup, table)
    assert row["redundancy"] == [{"kind": "stack", "state": "standalone",
                                  "read_ids": ["stacking", "stacking_support"]}]
    assert read(row, "mlag_peer")["status"] == "incomplete"
    assert row["status"] == "partial"


def test_disabled_and_enabled_ports_with_the_same_down_link(setup):
    table = answers(X440)
    # Marked copy: port 2 administratively disabled with the same Ready link as port 4.
    edit(table, "ports", "2                             Default             E     R",
         "2                             Default             D     R")
    row = one(setup, table)
    names = [item["name"] for item in row["interfaces"]["admin_up_down"]]
    assert "2" not in names and "4" in names
    assert row["status"] == "complete"


def test_ambiguous_port_row_keeps_read_rows_and_marks_the_read_incomplete(setup):
    table = answers(X440)
    edit(table, "ports", "3                             Default             E     A      100    FULL",
         "3                             Default             E     ?      100    FULL")
    row = one(setup, table)
    assert read(row, "ports")["status"] == "incomplete"
    assert reasons(row, "interfaces.admin_up_down") == {("unparsed", "ports")}
    assert "4" in [item["name"] for item in row["interfaces"]["admin_up_down"]]
    assert row["poe"]["budget_w"] == 200.0 and row["status"] == "partial"


def test_permission_refusal_keeps_other_fields(setup):
    table = answers(X440)
    table[command("licenses")] = 0, REFUSED
    row = one(setup, table)
    assert read(row, "licenses")["status"] == "failed"
    assert reasons(row, "licenses") == {("permission_denied", "licenses")}
    assert row["licenses"] is None
    assert row["version"] == "33.7.1.6" and row["poe"]["used_w"] == 0.0


def test_paged_error_table_is_not_counted_and_the_other_direction_stays(setup):
    table = answers(X440)
    rc, text = table[command("ports_rx_errors")]
    table[command("ports_rx_errors")] = rc, "\n".join(text.splitlines()[:8]) + "\n" + PAGER
    edit(table, "ports_tx_errors", "3         A         0            0           0         0",
         "3         A         0            0           0         4")
    row = one(setup, table)
    assert read(row, "ports_rx_errors")["status"] == "incomplete"
    assert reasons(row, "interfaces.with_errors") == {("truncated", "ports_rx_errors")}
    assert row["interfaces"]["with_errors"] == [{
        "name": "3", "counters": {"tx_late_collisions": 0, "tx_errors": 4, "tx_lost": 0, "tx_parity": 0},
        "counter_kind": "cumulative", "read_ids": ["ports_tx_errors"]}]


def test_error_table_missing_a_port_contradicts_the_port_summary(setup):
    table = answers(X440)
    rc, text = table[command("ports_rx_errors")]
    table[command("ports_rx_errors")] = rc, re.sub(r"(?m)^16 .*\n", "", text)
    row = one(setup, table)
    assert read(row, "ports_rx_errors")["status"] == "incomplete"
    assert read(row, "ports_tx_errors")["status"] == "incomplete"
    assert row["status"] == "partial"


def test_both_direction_tables_report_typed_cumulative_errors(setup):
    table = answers(X440)
    edit(table, "ports_rx_errors", "3         A        0       0", "3         A        7       0")
    edit(table, "ports_tx_errors", "3         A         0            0           0         0",
         "3         A         0            0           0         2")
    edit(table, "ports_tx_errors", "5         A         0", "5         A         9")  # collisions only
    row = one(setup, table)
    assert row["interfaces"]["with_errors"] == [{
        "name": "3", "counters": {"rx_crc": 7, "rx_over": 0, "rx_under": 0, "rx_frag": 0, "rx_jabber": 0,
                                  "rx_align": 0, "rx_lost": 0, "tx_late_collisions": 0, "tx_errors": 2,
                                  "tx_lost": 0, "tx_parity": 0},
        "counter_kind": "cumulative", "read_ids": ["ports_rx_errors", "ports_tx_errors"]}]
    assert {item["subject"] for item in row["findings"] if item["code"] == "interface_errors_present"} == {"3"}
    assert row["status"] == "complete"


def test_poe_budget_from_a_second_physical_capture(setup):
    table = answers(X440)
    table[command("inline_power")] = 0, (FIXTURES / "real/exos/x440g2-12p-10g4_33.7.1.6_2/inline_power.txt").read_text()
    row = one(setup, table)
    assert row["poe"] == {"budget_w": 200.0, "used_w": 17.0, "available_w": 183.0}
    table[command("inline_power")] = 0, (VM / "inline_power.txt").read_text()
    row = one(setup, table)
    assert row["poe"] is None and read(row, "inline_power")["status"] == "incomplete"


def test_failed_fan_and_power_are_hardware_findings(setup):
    table = answers(X440)
    edit(table, "fans", " Fan-2:                  Operational", " Fan-2:                  Failed     ")
    edit(table, "power", " State             : Powered On", " State             : Powered Off")
    row = one(setup, table)
    assert {(item["field"], item["subject"], item["severity"]) for item in row["findings"]
            if item["code"] == "hardware_degraded"} == {("fans", "Slot-1 FanTray Fan-2", "critical"),
                                                          ("power", "PowerSupply 1", "critical")}
    assert row["status"] == "complete"


def test_x435_reports_priority_fields_and_marks_fans_not_applicable(setup):
    row = one(setup, answers(X435))
    assert row["model"] == "X435-8P-4S"
    assert {query: read(row, query)["status"] for query in PRIORITY} == dict.fromkeys(PRIORITY, "ok")
    assert row["poe"]["budget_w"] == 124.0
    assert row["fans"] is None and read(row, "fans")["status"] == "ok"
    assert reasons(row, "fans") == {("not_applicable", "fans")}


def test_budget_shortage_keeps_the_prefix_and_names_the_rest(setup):
    row = one(setup, answers(X440), requests=5)
    assert [item["status"] for item in row["reads"][:5]] == ["ok"] * 5
    assert {item["status"] for item in row["reads"][5:]} == {"not_run"}
    assert reasons(row, "licenses") == {("read_limit", "licenses")}
    assert row["interfaces"]["with_errors"] == [] and row["licenses"] is None
    assert len(setup.calls) == 5 and row["status"] == "partial"


@pytest.mark.parametrize("license_seconds", [1.5, 3.5])
def test_x440_deadline_preserves_priority_reads(setup, monkeypatch, license_seconds):
    table = answers(X440)
    # The completed SSH times (seconds) from the earlier X440 live row. The
    # previously unfinished commands use a conservative typical 1.5 s.
    timing = {"version": 2.555, "switch": 1.495, "cpu_monitoring": 3.466, "memory": 3.356, "ports": 2.137,
              "stacking": 1.468, "stacking_support": 1.439, "mlag_peer": 1.440, "mlag_ports": 1.432,
              "licenses": license_seconds}
    durations = {command(query): timing.get(query, 1.5) for query in BASE}
    now = 100.0
    monkeypatch.setattr(runner, "time", SimpleNamespace(monotonic=lambda: now))

    def delayed(cmd, allowed):
        nonlocal now
        delay = durations[cmd]
        now += min(allowed, delay)
        if delay >= allowed:
            raise TimeoutError()
        return table[cmd]

    row = one(setup, delayed)
    assert {query: read(row, query)["status"] for query in PRIORITY} == dict.fromkeys(PRIORITY, "ok")
    assert [item["id"] for item in row["reads"][:len(PRIORITY)]] == PRIORITY
    assert row["interfaces"]["with_errors"] == [] and row["poe"]["budget_w"] == 200.0
    if license_seconds == 1.5:
        assert read(row, "licenses")["status"] == "ok"
        assert now - 100.0 == pytest.approx(sum(durations.values()))
    else:
        assert row["status"] == "partial" and reasons(row, "licenses") == {("timeout", "licenses")}
        assert now - 100.0 == pytest.approx(30)


def test_configured_standalone_switch_omits_redundancy_reads(setup):
    # The X440 captures show current stacking support Disabled and zero MLAG groups with no peer.
    row = one(setup, answers(X440), standalone=True)
    read_ids = [item["id"] for item in row["reads"]]
    assert {"stacking", "stacking_support", "mlag_peer", "mlag_ports"}.isdisjoint(read_ids)
    assert read_ids == [*BASE[:11], "licenses"]
    assert len(setup.calls) == 12 and row["status"] == "complete"
    assert row["redundancy"] is None and reasons(row, "redundancy") == {("not_applicable", None)}


@pytest.mark.parametrize("copper", [False, True], ids=["optical-only", "mixed-media"])
def test_optics_skip_copper_and_report_ninth_optical_port(setup, copper):
    table = answers(X440)
    optical = tuple(str(port) for port in range(13, 22))
    # Marked copies of the real DOM sample, with the port ID varied to exercise
    # the bound independently of the X440 capture's physical port count.
    sample = (DOM / "sample_a-port13.txt").read_text()
    table[command("interface_transceiver", interface="1")] = 0, (X440 / "interface_transceiver.txt").read_text()
    for port in optical:
        table[command("interface_transceiver", interface=port)] = 0, re.sub(r"(Port :  )13\b", rf"\g<1>{port}", sample)
    interfaces = ("1", *optical) if copper else optical
    row = one(setup, table, interfaces=interfaces, optical_ports=(*optical, "22"), optics=True)
    dom_commands = [cmd for _, cmd in setup.calls if "transceiver information detail" in cmd]
    assert dom_commands == [command("interface_transceiver", interface=port) for port in optical[:8]]
    assert [item["port"] for item in row["temperatures"] if item["kind"] == "optic"] == list(optical[:8])
    assert {"field": "temperatures", "reason": "source_limit", "omitted_count": 1} in row["missing"]
    assert row["status"] == "partial"


def test_optics_without_media_enrollment_reports_limited_coverage(setup):
    row = one(setup, answers(X440), interfaces=("1", "13"), optics=True)
    assert all(item["source"]["query"] != "interface_transceiver" for item in row["reads"])
    assert {"field": "temperatures", "reason": "source_limit", "omitted_count": 2} in row["missing"]


def test_unreachable_switch_leaves_the_other_result_complete(setup):
    setup.configure(device("switch-a", 10), device("switch-b", 11))
    setup.handlers["192.0.2.10"] = answers(X440)

    def refused(command, allowed):
        raise ConnectionRefusedError()

    setup.handlers["192.0.2.11"] = refused
    first, second = setup.call()["devices"]
    assert first["status"] == "complete"
    assert second["reachability"] == "unreachable" and second["status"] == "partial"
    assert all(host != "192.0.2.11" or command == "show version" for host, command in setup.calls)


def test_plan_follows_the_budget_order_and_bounds_optics():
    from netops_helper.overview import exos
    ports = tuple(str(number) for number in range(1, 20))
    scope = model.Scope("extreme_exos", ("interface_transceiver",),
                        {"interfaces": ports, "switches": tuple(f"optical-port:{port}" for port in ports[1:])})
    plan = exos.plan(scope)
    assert [spec.query for spec in plan[:16]] == BASE
    assert len(plan) == 16 + exos.MAX_OPTICS
    assert plan[16].parameters == {"interface": "2"}
    assert model.with_identity(scope, plan) == plan
    assert exos.plan(model.Scope("extreme_exos", (), {"interfaces": ("1",)})) == plan[:16]


@pytest.mark.parametrize(("text", "seconds"), [
    ("1 day 5 hours 19 minutes 56 seconds", 105596), ("34 days 6 hours 38 minutes 51 seconds", 2961531),
    ("3 minutes", 180), ("5 hours and 2 minutes", None), ("1 day 1 day", None), ("", None),
])
def test_uptime_conversion(text, seconds):
    from netops_helper.overview import exos
    assert exos.uptime_seconds(text) == seconds


@pytest.mark.parametrize("requests", [30, 20])
def test_triage_health_during_an_overview_shares_the_real_rate_window(setup, monkeypatch, requests):
    """triage_health and network_overview on one target through the real bridge, proxy and engine.

    The overview holds its identity read open while triage_health arrives on the same HelperBridge
    (from a second client thread). Both reservations land in one window: with 30 requests both plans
    fit and both read plans run; with 20 the in-flight
    overview prefix leaves fewer than the 10 reads of triage_health, which is refused as a whole
    before any of its device reads.
    """
    import threading
    setup.configure(device("switch-a", 10, requests=requests))
    table = answers(X440)
    started, release = threading.Event(), threading.Event()
    held, triage = [], {}

    def respond(command, timeout):
        if not held:
            held.append(command)
            started.set()
            assert release.wait(4)
        return table.get(command, (0, ""))

    def transport(host, port, login, credential, pin, command, *, timeout_seconds, **options):
        # Same SSH boundary as the fixture, without its overview-only read timeout check.
        setup.calls.append((host, command))
        rc, text = respond(command, timeout_seconds)
        return ssh.Result(rc, text.encode(), "", "", "")

    monkeypatch.setattr(engine.core_ssh, "run_command", transport)
    owner = setup.bridge

    def second_client():
        triage["result"] = asyncio.run(owner.call(server.mcp, "triage_health", {"target": "switch-a"}))

    async def exercise():
        overview = asyncio.create_task(owner.call(server.mcp, "network_overview", {}))
        client = threading.Thread(target=second_client, daemon=True)
        try:
            assert await asyncio.to_thread(started.wait, 4)
            charged = len(owner.proxy.rate_history["switch-a"])
            client.start()
            # Release the held read once the triage was charged or refused by the proxy.
            for _ in range(200):
                if "result" in triage or len(owner.proxy.rate_history["switch-a"]) > charged:
                    break
                await asyncio.sleep(0.01)
            during = len(setup.calls)
        finally:
            release.set()
        page = await overview
        await asyncio.to_thread(client.join, 20)
        return page, charged, during

    page, charged, during = asyncio.run(exercise())
    assert not page["isError"], page
    row = page["structuredContent"]["devices"][0]
    total = owner.proxy.rate_history["switch-a"]
    window = owner.proxy.triage_history["switch-a"]
    assert len(total) == len(window) <= requests
    # The overview prefix was charged before its first read and covers every planned read.
    assert 10 < charged <= 20
    assert charged == len(row["reads"]) and all(item["status"] != "not_run" for item in row["reads"]), row["reads"]
    result = triage["result"]
    if requests == 30:
        assert not result["isError"], result
        assert len(total) == charged + proxy.TRIAGE_HEALTH_READS
        assert len(setup.calls) > len(row["reads"]), result
        assert result["structuredContent"]["identity"] is not None, result
    else:
        assert result["isError"]
        error = json.loads(result["content"][0]["text"])
        assert error["data"]["category"] == "rate_limit" and error["data"]["retry_after_seconds"] > 0
        # Nothing but the held overview identity read reached the device; the triage never did.
        assert during == 1 and len(total) == charged and len(setup.calls) == len(row["reads"])


# Per-connection times of every X440 read measured live on 2026-11-23 (one SSH exec per read, rsa-sha1 handshake
# and login on the switch CPU make each about 1.4-3.5 s; no single command dominates).
X440_LIVE_SECONDS = {"version": 1.421, "switch": 1.498, "ports": 2.145, "ports_rx_errors": 1.582,
                     "ports_tx_errors": 1.579, "temperature": 1.440, "fans": 1.439, "power": 1.438,
                     "inline_power": 1.816, "cpu_monitoring": 3.484, "memory": 3.377, "stacking": 1.474,
                     "stacking_support": 1.470, "mlag_peer": 1.449, "mlag_ports": 1.486, "licenses": 1.455}


def test_default_call_does_not_queue_the_x440_behind_other_targets(setup, monkeypatch):
    """The 1.0.13 integration call queued the X440 as the tenth target; its reads started 28 s into the 45 s budget
    and every read after the sixth timed out. A default page now holds one parallel round, and on its own page the
    X440 completes all 16 reads within its 30-second target budget."""
    setup.configure(*(device(f"vm-{index}", 10 + index) for index in range(4)), device("x440", 20))
    for index in range(4):
        setup.handlers[f"192.0.2.{10 + index}"] = answers(VM)
    table = answers(X440)
    durations = {command(query): X440_LIVE_SECONDS[query] for query in BASE}
    first = setup.call()
    assert [row["target"] for row in first["devices"]] == [f"vm-{index}" for index in range(4)]
    assert first["selection"]["next_after"] == "vm-3" and first["selection"]["remaining"] == 1
    now = 100.0
    monkeypatch.setattr(runner, "time", SimpleNamespace(monotonic=lambda: now))

    def delayed(cmd, allowed):
        nonlocal now
        delay = durations[cmd]
        now += min(allowed, delay)
        if delay >= allowed:
            raise TimeoutError()
        return table[cmd]
    setup.handlers["192.0.2.20"] = delayed
    row, = setup.call({"after": "vm-3"})["devices"]
    assert [item["status"] for item in row["reads"]] == ["ok"] * len(BASE)
    assert row["status"] == "complete"
    assert now - 100.0 == pytest.approx(sum(X440_LIVE_SECONDS.values())) and now - 100.0 < model.TARGET_SECONDS
