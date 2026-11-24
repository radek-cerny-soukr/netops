"""Linux overview through HelperBridge, with SSH replaced below the actual policy."""

import asyncio
import json
from pathlib import Path

import pytest

from conftest import HOST_KEY_BLOB, HOST_KEY_PIN
from netops.worker import HelperBridge
from netops_core import ssh
from netops_core.audit import Recorder
from netops_helper import audit, auth, engine, inventory, proxy, query_catalog, read_policy, server
from netops_helper.query_catalog.overview_linux import QUERIES
from test_proxy_contracts import _device, _egress, _egress_policy, _inventory, _write

FIXTURES = Path(__file__).parent / "fixtures"
CAPTURES = json.loads((FIXTURES / "overview_h5/captures.json").read_text())
BASE_QUERIES = ("kernel", "memory", "links", "uptime")


def capture(query, scenario="debian"):
    return CAPTURES[f"linux/{query}/{scenario}"]


def overview_device(platform, enabled, *, name="unit-a", requests=30, number=10, role="read-only"):
    address = f"192.0.2.{number}"
    section = {
        "ssh_platform": platform, "account_role": role, "enabled_queries": list(enabled),
        "rate_limit": {"requests": requests, "window_seconds": 60},
        "egress": dict(_egress(), addresses=[address], tcp_ports=[22]),
    }
    if role == "admin-bounded":
        section["role_boundary"] = "catalogue"
    return dict(_device(section, platform), name=name, address=address, credential=f"test-reader-{number}",
                host_key_fingerprint=HOST_KEY_PIN, host_key="ssh-ed25519 " + HOST_KEY_BLOB)


@pytest.fixture
def h5(tmp_path, monkeypatch):
    bridge = HelperBridge()
    monkeypatch.setattr(engine.core_hostkey, "scan", lambda *args, **kwargs: "test-pinned-key")
    monkeypatch.setattr(engine, "_lane_directory", lambda: tmp_path / "ssh-lanes")
    monkeypatch.setattr(audit, "_RECORDER", Recorder(tmp_path / "audit.jsonl", "helper"))

    def run(*devices):
        monkeypatch.setattr(proxy, "INVENTORY", _write(tmp_path / "inventory.json", _inventory(*devices)))
        materials = {entry["credential"]: {"kind": "password", "login": "reader", "value": "synthetic-login-key"}
                     for entry in devices}
        monkeypatch.setattr(proxy, "VAULT", _write(tmp_path / "vault.json", {"version": 2, "credentials": materials}, 0o600))
        monkeypatch.setattr(proxy, "EGRESS_POLICY", _write(tmp_path / "egress.json", _egress_policy()))
        monkeypatch.setattr(bridge.proxy, "_vault", lambda names=None: proxy.Proxy._vault(bridge.proxy, names))
        monkeypatch.setattr(bridge.proxy, "_load_egress_policy", lambda: proxy.Proxy._load_egress_policy(bridge.proxy))
        result = asyncio.run(bridge.call(server.mcp, "network_overview", {}))
        assert not result["isError"], result
        assert json.loads(result["content"][0]["text"]) == result["structuredContent"]
        return result["structuredContent"]["devices"]

    return run


@pytest.fixture
def active_linux(monkeypatch):
    base = query_catalog.READ_QUERIES
    assert set(QUERIES).isdisjoint(base["linux"])
    commands = frozenset(query.command for query in QUERIES.values())
    # Mirror integration's four explicit approvals in the test catalogue. The real validators still run.
    monkeypatch.setattr(read_policy, "_LINUX_COMMANDS", read_policy._LINUX_COMMANDS | commands)
    merged = query_catalog.compose({"linux": QUERIES})
    assert merged["linux"]["version"] is base["linux"]["kernel"]
    read_policy._validate_query_catalogs(merged)
    for module in (query_catalog, read_policy, auth, engine, inventory):
        monkeypatch.setattr(module, "READ_QUERIES", merged)
    monkeypatch.setitem(proxy.READ_QUERY_NAMES, "linux", frozenset(merged["linux"]))
    return (*BASE_QUERIES, *QUERIES)


@pytest.fixture
def linux_ssh(monkeypatch):
    answers = {
        query_catalog.READ_QUERIES["linux"][query].command: capture(query) for query in BASE_QUERIES
    }
    answers.update({definition.command: capture(query) for query, definition in QUERIES.items()})
    calls = []

    def send(host, port, login, credential, pin, command, *, timeout_seconds, **options):
        calls.append((host, command))
        body = answers[command]
        if callable(body):
            body = body()
        if isinstance(body, tuple):
            rc, body = body
        else:
            rc = 0
        return ssh.Result(rc, body.encode(), "", "", "")

    monkeypatch.setattr(engine.core_ssh, "run_command", send)
    return answers, calls


def test_base_reads_preserve_admin_flag_semantics(h5, linux_ssh):
    answers, calls = linux_ssh
    answers["ip -brief link"] = capture("links").replace("ens18            UP", "ens18            DOWN")
    row, = h5(overview_device("linux", BASE_QUERIES))
    assert row["memory"] and row["memory"]["total_bytes"] == 3921 * 2**20, row
    assert row["version"] == capture("kernel").split()[2]
    assert row["uptime_seconds"] == 180
    assert row["interfaces"]["admin_up_down"] == [{"name": "ens18", "read_ids": ["links"]}]
    assert row["interfaces"]["with_errors"] is None
    assert all("proc" not in command for _, command in calls)


def test_active_catalog_uses_two_samples_and_json_errors(h5, active_linux, linux_ssh):
    answers, calls = linux_ssh
    samples = iter((capture("overview_proc_stat"), capture("overview_proc_stat", "second")))
    answers["cat /proc/stat"] = lambda: next(samples)
    row, = h5(overview_device("linux", active_linux))
    assert row["cpu"] == {"used_pct": 37.22, "sample_seconds": None}, row["missing"]
    assert row["model"] == capture("overview_dmi_model").strip()
    assert row["uptime_seconds"] == int(float(capture("overview_proc_uptime").split()[0]))
    assert row["interfaces"]["admin_up_down"] == []
    assert row["interfaces"]["with_errors"] == []
    assert [command for _, command in calls].count("cat /proc/stat") == 2


def test_second_cpu_failure_and_budget_keep_other_devices(h5, active_linux, linux_ssh):
    answers, calls = linux_ssh
    samples = iter((capture("overview_proc_stat"), (1, "cat: /proc/stat: Permission denied\n")))
    answers["cat /proc/stat"] = lambda: next(samples)
    low, peer = h5(overview_device("linux", active_linux, name="a-budget", requests=1),
                   overview_device("linux", active_linux, name="b-peer", number=11))
    assert low["version"] and low["cpu"] is None
    assert any(item["reason"] == "read_limit" for item in low["missing"])
    assert peer["memory"] and peer["cpu"] is None
    assert next(item for item in peer["reads"] if item["id"] == "cpu:2")["status"] == "incomplete"
    assert any(item["reason"] == "unparsed" and item.get("read_id") == "cpu:2" for item in peer["missing"])
    assert [command for host, command in calls if host == "192.0.2.10"] == ["uname -a"]


def test_conflicting_table_counts_and_duplicate_rows_keep_supported_facts(h5, active_linux, linux_ssh):
    answers, _ = linux_ssh
    rows = json.loads(capture("overview_link_statistics"))
    rows.append(rows[0])
    answers["ip -s -j link show"] = json.dumps(rows)
    row, = h5(overview_device("linux", active_linux))
    assert next(item for item in row["reads"] if item["id"] == "link_statistics")["status"] == "incomplete"
    assert row["interfaces"]["with_errors"] == []
    assert row["cpu"] is None
    assert any(item["field"] == "cpu" and item["reason"] == "unparsed" for item in row["missing"])


def test_pager_uses_brief_fallback_and_valid_empty_list(h5, active_linux, linux_ssh):
    answers, _ = linux_ssh
    answers["ip -s -j link show"] = capture("overview_link_statistics")[:120] + "\n--More--\n"
    answers["ip -brief link"] = "\n".join(line for line in capture("links").splitlines() if "docker0" not in line)
    row, = h5(overview_device("linux", active_linux))
    assert row["interfaces"]["admin_up_down"] == []
    assert row["interfaces"]["with_errors"] is None
    assert any(item["reason"] in {"truncated", "unparsed"} and item.get("read_id") == "link_statistics"
               for item in row["missing"])


def test_json_missing_port_uses_brief_without_claiming_full_counter_coverage(h5, active_linux, linux_ssh):
    answers, _ = linux_ssh
    samples = iter((capture("overview_proc_stat"), capture("overview_proc_stat", "second")))
    answers["cat /proc/stat"] = lambda: next(samples)
    rows = json.loads(capture("overview_link_statistics"))
    answers["ip -s -j link show"] = json.dumps([row for row in rows if row["ifname"] != "docker0"])
    row, = h5(overview_device("linux", active_linux))
    assert row["interfaces"]["admin_up_down"] == []
    assert row["interfaces"]["with_errors"] == []
    assert next(item for item in row["reads"] if item["id"] == "link_statistics")["status"] == "incomplete"
    assert {item["field"] for item in row["missing"] if item.get("read_id") == "link_statistics"} == {
        "interfaces.admin_up_down", "interfaces.with_errors",
    }
    assert row["cpu"]["used_pct"] == 37.22 and row["uptime_seconds"] > 0


def test_unattached_virtual_links_are_ignored_and_packet_errors_still_report(h5, active_linux, linux_ssh):
    answers, _ = linux_ssh
    rows = json.loads(capture("overview_link_statistics"))
    physical, bridge = rows[1:]
    physical["stats64"]["rx"]["errors"] = 1
    physical["master"] = "docker0"
    for name in ("br-empty", "veth123", "gre0", "imq0"):
        rows.append(dict(bridge, ifname=name, stats64=physical["stats64"]))
    answers["ip -s -j link show"] = json.dumps(rows)
    answers["ip -brief link"] = capture("links") + "".join(
        f"{row['ifname']} DOWN 00:00:5e:00:53:02 <NO-CARRIER,UP>\n" for row in rows[3:]
    )
    row, = h5(overview_device("linux", active_linux))
    assert row["interfaces"]["admin_up_down"] == [{"name": "docker0", "read_ids": ["link_statistics"]}]
    assert row["interfaces"]["with_errors"] == [{
        "name": "ens18", "read_ids": ["link_statistics"], "counter_kind": "cumulative",
        "counters": {"rx_errors": 1, "rx_drops": 59, "tx_errors": 0, "tx_drops": 0},
    }]


def test_duplicate_memory_row_keeps_valid_kernel_and_uptime(h5, linux_ssh):
    answers, _ = linux_ssh
    memory = capture("memory")
    answers["free -m"] = memory + "\n" + next(line for line in memory.splitlines() if line.startswith("Mem:"))
    row, = h5(overview_device("linux", BASE_QUERIES))
    assert row["memory"] is None
    assert next(item for item in row["reads"] if item["id"] == "memory")["status"] == "incomplete"
    assert row["version"] == capture("kernel").split()[2] and row["uptime_seconds"] == 180


def test_existing_debian_link_capture_has_no_confirmed_admin_up_down(h5, linux_ssh):
    answers, _ = linux_ssh
    scenario = json.loads((FIXTURES / "real/scenarios/linux_debian13_batch_b.json").read_text())
    answers["ip -brief link"] = next(item["stdout"] for item in scenario["captures"] if item["query"] == "links")
    row, = h5(overview_device("linux", BASE_QUERIES))
    assert row["interfaces"]["admin_up_down"] == []
