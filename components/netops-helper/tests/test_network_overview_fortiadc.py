"""FortiADC overview from captured output through the held-terminal read path."""

from contextlib import contextmanager
import re

import pytest

from netops_helper import engine

from test_network_overview_linux import CAPTURES, FIXTURES, h5, overview_device

ADC = FIXTURES / "real/fortiadc"
OBJECTS = next(ADC.glob("*_adc_objects_*"))
ROUTING = next(ADC.glob("*_adc_content_routing_*"))
STATISTICS = next(ADC.glob("*_adc_statistics_*"))
HA = FIXTURES.parents[2] / "netops-admin/tests/fixtures/fortiadc_adc_ha_state"
QUERIES = ("system_status", "system_performance", "interface_summary", "interface_state_all",
           "ha_status", "interface_counters", "vm_license", "autoupdate_contract")


def body(text):
    return "\n".join(line for line in text.splitlines() if not re.fullmatch(r"FortiADC-KVM\s+[#$]\s*", line)
                     ).replace("FortiADC-KVM # Version:", "Version:").replace(
                         "FortiADC-KVM $ diagnose netlink interface list", "diagnose netlink interface list")


def adc(monkeypatch):
    answers = {
        "get system status": body((STATISTICS / "status.out").read_text()),
        "get system performance": body((ROUTING / "ro-performance.out").read_text()),
        "get system interface": body((OBJECTS / "system-interface-all.out").read_text()),
        "diagnose hardware get deviceinfo nic-detail": (OBJECTS / "nic-detail-all.out").read_text(),
        "diagnose netlink interface list": body((OBJECTS / "netlink-interface-list-all.out").read_text()),
        "get system ha-status": (HA / "standalone.txt").read_text(),
        "diagnose netlink device": CAPTURES["fortiadc/interface_counters/vendor"],
        "diagnose system vm": CAPTURES["fortiadc/vm_license/vendor"],
        "execute autoupdate contract": "Command fail. Return code is -284 (CLI parsing error.)\n",
    }
    calls = []

    @contextmanager
    def connect(*args, **kwargs):
        calls.append(("open", args))
        try:
            yield Terminal()
        finally:
            calls.append(("close", args))

    class Terminal:
        _closed = False
        _last_prompt = b"sample # "

        def send(self, command):
            calls.append((command, ()))
            self.command = command

        def expect(self, prompts, timeout):
            return 0, (self.command + "\n" + answers[self.command]).encode() + self._last_prompt

        def close(self):
            self._closed = True

        def run(self, command, **options):
            calls.append((command, ()))
            data = answers[command]
            # The real terminal discards the body on a device refusal in run().
            if engine._cli_refused("fortiadc", data, command=command):
                return engine.core_session.FortinetResult(1, b"", "", "", "", refusal="device_cli_error")
            return engine.core_session.FortinetResult(0, data.encode(), "", "", "")

    monkeypatch.setattr(engine.core_session, "fortinet_session", connect)
    return answers, calls


def test_fortiadc_summary_pair_and_cumulative_counters(h5, monkeypatch):
    _, calls = adc(monkeypatch)
    row, = h5(overview_device("fortiadc", QUERIES))
    assert row["model"] == "FortiADC-KVM" and row["version"] == "7.6.7 build 0676", row
    assert row["uptime_seconds"] == (5 * 1440 + 20 * 60 + 13) * 60, [(item["field"], item["reason"]) for item in row["missing"] if item.get("read_id") == "system_performance"]
    assert row["memory"] == {"used_pct": 37, "total_bytes": None, "used_bytes": None}
    assert row["cpu"] == {"used_pct": 3, "sample_seconds": None}
    assert row["redundancy"][0]["state"] == "standalone"
    assert row["licenses"][0]["state"] == "valid"
    assert row["interfaces"]["admin_up_down"] == []
    assert row["interfaces"]["with_errors"] == [{
        "name": "port3", "counter_kind": "cumulative", "read_ids": ["interface_counters"],
        "counters": {"rx_errors": 0, "rx_drops": 168, "tx_errors": 0, "tx_drops": 0},
    }]
    commands = [command for command, _ in calls]
    assert commands.count("open") == commands.count("close") == 1
    assert commands.count("get system interface") == 1
    assert commands[3:5] == ["get system interface", "diagnose hardware get deviceinfo nic-detail"]


def test_fortiadc_denied_diagnose_and_prompt_preserve_irrelevant_reads(h5, monkeypatch):
    answers, calls = adc(monkeypatch)
    # The denied read-only transcript gives the parser error at the verb after diagnose and code -284.
    answers["diagnose netlink device"] = "Parsing error at 'netlink'. err=1\nCommand fail. Return code is -284 (CLI parsing error.)\n"
    answers["get system ha-status"] = "Mode: standalone\n--More--\n"
    row, = h5(overview_device("fortiadc", QUERIES))
    assert row["interfaces"]["admin_up_down"] == []
    assert row["interfaces"]["with_errors"] is None and row["redundancy"] is None
    assert any(item["reason"] == "permission_denied" and item.get("read_id") == "interface_counters"
               for item in row["missing"])
    assert next(item for item in row["reads"] if item["id"] == "interface_counters")["status"] == "failed"
    assert next(item for item in row["reads"] if item["id"] == "ha_status")["status"] == "incomplete"
    assert row["cpu"]["used_pct"] == 3 and row["version"] == "7.6.7 build 0676"
    assert row["licenses"][0]["state"] == "valid"
    assert [command for command, _ in calls].count("open") == 1


def test_fortiadc_denied_interface_list_keeps_other_reads(h5, monkeypatch):
    answers, _ = adc(monkeypatch)
    refusal = (OBJECTS / "exec-ro-refused.out").read_text().splitlines()[0].split("$ ", 1)[1]
    answers["get system interface"] = f"Parsing error at 'interface'. err=1\n{refusal}\n"
    row, = h5(overview_device("fortiadc", ("system_status", "interface_list", "ha_status", "interface_counters")))
    assert row["interfaces"]["admin_up_down"] is None
    assert {item["reason"] for item in row["missing"] if item.get("read_id") == "interface_list"} == {
        "permission_denied",
    }
    assert next(item for item in row["reads"] if item["id"] == "interface_list")["status"] == "failed"
    assert row["interfaces"]["with_errors"][0]["name"] == "port3"
    assert row["redundancy"][0]["state"] == "standalone"


def test_fortiadc_peer_count_and_duplicate_counter_rows(h5, monkeypatch):
    answers, _ = adc(monkeypatch)
    answers["get system ha-status"] = (HA / "secondary.txt").read_text().replace("Peer Count: 1", "Peer Count: 2")
    answers["diagnose netlink device"] += answers["diagnose netlink device"].splitlines()[2] + "\n"
    row, = h5(overview_device("fortiadc", QUERIES))
    assert row["redundancy"] == [{"kind": "ha", "role": "secondary", "state": "unknown", "read_ids": ["ha_status"]}]
    assert {item["id"] for item in row["reads"] if item["status"] == "incomplete"} >= {"ha_status", "interface_counters"}
    assert row["cpu"]["used_pct"] == 3
    assert row["interfaces"]["with_errors"][0]["name"] == "port3"


@pytest.mark.parametrize(("fixture", "sync", "role", "state"), [
    ("primary-not-sync.txt", "not sync", "primary", "degraded"),
    ("primary-not-sync.txt", "In sync", "primary", "ok"),
    ("secondary.txt", "IN SYNC", "secondary", "ok"),
])
def test_fortiadc_ha_sync_ignores_case(h5, monkeypatch, fixture, sync, role, state):
    answers, _ = adc(monkeypatch)
    answers["get system ha-status"] = (HA / fixture).read_text().replace("Config-Sync: Not Sync", f"Config-Sync: {sync}")
    row, = h5(overview_device("fortiadc", ("system_status", "ha_status")))
    assert row["redundancy"] == [{"kind": "ha", "role": role, "state": state, "read_ids": ["ha_status"]}]
    assert next(item for item in row["reads"] if item["id"] == "ha_status")["status"] == "ok"


@pytest.mark.parametrize(("model", "reason"), [
    ("FortiADC-ALI", "not_applicable"),
    ("FortiADC-ALI_ONDEMAND", "not_applicable"),
    ("FortiADC-AZURE", "not_applicable"),
    ("FortiADC-AZURE_ONDEMAND", "not_applicable"),
    ("FortiADC-GCP", "not_applicable"),
    ("FortiADC-GCP_ONDEMAND", "not_applicable"),
    ("FortiADC-IBM", "not_applicable"),
    ("FortiADC-OCI", "not_applicable"),
    ("FortiADC-XENAWS", "not_applicable"),
    ("FortiADC-XENAWS_ONDEMAND", "not_applicable"),
    ("FortiADC-200F", "source_limit"),
])
def test_fortiadc_hardware_coverage_by_model(h5, monkeypatch, model, reason):
    answers, _ = adc(monkeypatch)
    command = "get system status"
    answers[command] = re.sub(r"(?m)^(Version:\s+)FortiADC-KVM\b", rf"\g<1>{model}", answers[command])
    row, = h5(overview_device("fortiadc", ("system_status",)))
    assert row["model"] == model
    hardware_fields = {"temperatures", "fans", "power", "poe"}
    assert {item["field"]: item["reason"] for item in row["missing"] if item["field"] in hardware_fields} == {
        field: reason for field in hardware_fields
    }


def test_fortiadc_zero_counters_confirm_an_empty_error_list(h5, monkeypatch):
    answers, _ = adc(monkeypatch)
    command = "diagnose netlink device"
    header, labels, *rows = answers[command].splitlines()
    clean = []
    for row in rows:
        port, values = row.split(":", 1)
        counts = values.split()
        for index in (2, 3, 10, 11):
            counts[index] = "0"
        clean.append(f"{port}: {' '.join(counts)}")
    answers[command] = "\n".join([header, labels, *clean])
    row, = h5(overview_device("fortiadc", QUERIES))
    assert row["interfaces"]["with_errors"] == []
    assert next(item for item in row["reads"] if item["id"] == "interface_counters")["status"] == "ok"


def test_fortiadc_sequence_is_reserved_as_a_pair_and_other_item_survives(h5, monkeypatch):
    _, calls = adc(monkeypatch)
    limited, peer = h5(overview_device("fortiadc", QUERIES, name="a-budget", requests=3),
                       overview_device("fortiadc", QUERIES, name="b-peer", number=11))
    assert limited["version"] and limited["cpu"] and limited["interfaces"]["admin_up_down"] is None
    assert any(item["reason"] == "read_limit" and item.get("read_id") == "interface_summary" for item in limited["missing"])
    assert peer["interfaces"]["admin_up_down"] == []
    assert [command for command, _ in calls].count("get system interface") == 1


def test_fortiadc_ambiguous_cpu_keeps_memory_and_uptime(h5, monkeypatch):
    answers, _ = adc(monkeypatch)
    command = "get system performance"
    answers[command] += "\nCPU usage: 10% used, 90% idle\n"
    row, = h5(overview_device("fortiadc", QUERIES))
    assert row["cpu"] is None and row["memory"]["used_pct"] == 37 and row["uptime_seconds"] > 0
    assert any(item["field"] == "cpu" and item["reason"] == "unparsed" for item in row["missing"])


CONTRACT = (FIXTURES / "real/fortiadc/fortiadc-kvm_7.6.7_overview_20261123/autoupdate_contract.txt").read_text()


def test_fortiadc_contracts_give_licence_and_fortiguard_expiry(h5, monkeypatch):
    """FortiADC-KVM 7.6.7 `execute autoupdate contract` as measured: every service with its expiry date."""
    answers, _ = adc(monkeypatch)
    answers["execute autoupdate contract"] = CONTRACT
    row, = h5(overview_device("fortiadc", QUERIES))
    assert next(item for item in row["reads"] if item["id"] == "autoupdate_contract")["status"] == "ok"
    assert not [item for item in row["missing"] if item.get("read_id") == "autoupdate_contract"]
    names = {item["name"]: item for item in row["fortiguard"]}
    assert len(names) == 15
    assert names["NIDS FortiGuard IPS Service"]["expires_on"] == "2027-01-03"
    assert names["SPRT"]["read_ids"] == ["autoupdate_contract"]
    assert {item["expires_on"] for item in row["fortiguard"]} == {"2027-01-03"}
    licence = [item for item in row["licenses"] if item["read_ids"] == ["autoupdate_contract"]]
    assert [(item["name"], item["expires_on"]) for item in licence] == [("VMLS VM license", "2027-01-03")]
    assert row["licenses"][0]["name"] == "vm_license"  # The VM licence state of `diagnose system vm` stays first.


@pytest.mark.parametrize("damage", [
    lambda text: text.replace("NIDS-1-06-20270103:0:0:0:0", "NIDS-1-06-2027013:0:0:0:0"),
    lambda text: text.replace("|Contract=", "|Contracts="),
    lambda text: text + "Unexpected line\n",
    lambda text: text.replace("AVDB-1-06-20270103", "AVDB-1-06-20270231"),
], ids=["short-date", "no-contract-field", "unknown-line", "impossible-date"])
def test_fortiadc_unknown_contract_shape_is_unparsed(h5, monkeypatch, damage):
    answers, _ = adc(monkeypatch)
    answers["execute autoupdate contract"] = damage(CONTRACT)  # derived negative copies of the real answer
    row, = h5(overview_device("fortiadc", QUERIES))
    reasons = {(item["field"], item["reason"]) for item in row["missing"] if item.get("read_id") == "autoupdate_contract"}
    assert reasons == {("licenses", "unparsed"), ("fortiguard", "unparsed")}
    assert row["fortiguard"] is None
