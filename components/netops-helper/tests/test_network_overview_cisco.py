"""Cisco IOS, IOS XE and NX-OS network overview through the public Helper path.

Only the SSH transport, host key scan and audit store are replaced. Inputs are the
archived anonymized captures of the GNS3 lab images and the documented Catalyst
outputs in fixtures/overview_h3 (see its PROVENANCE.md). Negative variants derived
from them are named `derived_*` there or built inline below with a comment.
"""

import asyncio
import json
from pathlib import Path
import sys

import pytest

from netops.worker import HelperBridge
from netops_core import ssh
from netops_core.audit import Recorder
from netops_helper import audit, engine, proxy, server
from netops_helper.overview import model
from test_proxy_contracts import _device, _egress, _egress_policy, _inventory, _write

FIXTURES = Path(__file__).parent / "fixtures"
REAL = FIXTURES / "real"
CAPTURES = json.loads((FIXTURES / "overview_h3/captures.json").read_text())
SECRET = "fixture-cisco-overview-secret"


class _Adapter:
    """Imported on use, so a tree without the adapter fails each test instead of collection."""

    def __getattr__(self, name):
        from netops_helper.overview import cisco as module

        return getattr(module, name)


cisco = _Adapter()


def text(path):
    return (REAL / path).read_text()


IOSV = {
    "show version": text("cisco_ios/router-health/iosv-ro-version.out"),
    "show processes cpu": text("cisco_ios/router-health/iosv-ro-cpu.out"),
    "show processes memory": text("cisco_ios/router-health/iosv-ro-memory.out"),
    "show interfaces": text("cisco_ios/iosv_15.9.3M12/interfaces_details.txt"),
    "show env all": text("cisco_ios/router-health/iosv-ro-environment.out"),
}
IOSVL2 = {
    "show version": text("cisco_ios/router-health/iosvl2-ro-version.out"),
    "show processes cpu": text("cisco_ios/router-health/iosvl2-ro-cpu.out"),
    "show processes memory": text("cisco_ios/router-health/iosvl2-ro-memory.out"),
    "show interfaces": text("cisco_ios/iosvl2_15.2.20200924/interfaces_details.txt"),
    "show env all": text("cisco_ios/iosvl2_15.2.20200924/environment.txt"),
    "show switch": text("cisco_ios/iosvl2_15.2.20200924/stack_members.txt"),
    "show power inline": text("cisco_ios/iosvl2_15.2.20200924/power_inline.txt"),
}
IOLXE = {
    "show version": text("cisco_xe/iolxe_17.18.2_xe_health/iol-xe-switch-ro-version.out"),
    "show processes cpu": text("cisco_xe/iolxe_17.18.2_xe_health/iol-xe-switch-ro-cpu.out"),
    "show processes memory": text("cisco_xe/iolxe_17.18.2_xe_health/iol-xe-switch-ro-memory.out"),
    "show interfaces": text("cisco_xe/iolxe_17.18.2/interfaces_details.txt"),
    "show environment all": text("cisco_xe/iolxe_17.18.2/environment.txt"),
    "show switch": CAPTURES["cisco_xe/stack_members/doc_c9300_stackwise"],
    "show switch stack-ports summary": CAPTURES["cisco_xe/stack_ports/doc_c9300_stackwise"],
    "show power inline": CAPTURES["cisco_xe/power_inline/doc_c9200_poe_troubleshooting"],
}
NXOS = {
    "show version": text("cisco_nxos/nxos_health_9.3.12/version.txt"),
    "show system resources": text("cisco_nxos/nxos_health_9.3.12/system_resources.txt"),
    "show interface status": text("cisco_nxos/nexus9300v_9.3.12/interfaces.txt"),
    "show vpc brief": text("cisco_nxos/nexus9300v_9.3.12/vpc_status.txt"),
    "show redundancy status": text("cisco_nxos/nexus9300v_9.3.12/redundancy_status.txt"),
    "show interface counters errors": text("cisco_nxos/nexus9300v_9.3.12/interfaces_counters_errors.txt"),
    "show environment": text("cisco_nxos/nxos_health_9.3.12/environment.txt"),
    "show license usage": text("cisco_nxos/nexus9300v_9.3.12/license_usage.txt"),
}
NXOS_ENABLED = ("version", "system_resources", "interfaces", "vpc_status", "redundancy_status",
                "interfaces_counters_errors", "environment", "license_usage")
IOS_ENABLED = ("version", "cpu", "memory", "interfaces_details", "stack_members", "stack_ports", "environment",
               "power_inline")


def device(alias, number, platform, *, types=("switch",), enabled=IOS_ENABLED, requests=30):
    address = f"192.0.2.{number}"
    section = {"ssh_platform": platform, "account_role": "read-only", "enabled_queries": list(enabled),
               "device_types": list(types), "rate_limit": {"requests": requests, "window_seconds": 60},
               "egress": dict(_egress(), addresses=[address], tcp_ports=[22], allow_dns=False)}
    return dict(_device(section, platform), name=alias, address=address, credential=f"reader-{number}")


@pytest.fixture
def lab(tmp_path, monkeypatch):
    bridge = HelperBridge()
    answers, calls = {}, []

    def configure(*devices):
        credentials = {entry["credential"]: {"kind": "password", "login": "reader", "value": SECRET}
                       for entry in devices}
        monkeypatch.setattr(proxy, "INVENTORY", _write(tmp_path / "inventory.json", _inventory(*devices)))
        monkeypatch.setattr(proxy, "VAULT", _write(tmp_path / "vault.json",
                                                   {"version": 2, "credentials": credentials}, 0o600))
        monkeypatch.setattr(proxy, "EGRESS_POLICY", _write(tmp_path / "egress.json", _egress_policy()))
        monkeypatch.setattr(bridge.proxy, "_vault", lambda names=None: proxy.Proxy._vault(bridge.proxy, names))
        monkeypatch.setattr(bridge.proxy, "_load_egress_policy",
                            lambda: proxy.Proxy._load_egress_policy(bridge.proxy))

    def transport(host, port, login, credential, pin, command, *, timeout_seconds, **options):
        calls.append((host, command))
        assert 0 < timeout_seconds <= model.READ_SECONDS
        output = answers[host].get(command)
        if output is None:
            raise AssertionError(f"unexpected read {command!r}")
        rc, output = output if isinstance(output, tuple) else (0, output)  # (exit status, output) when recorded
        return ssh.Result(rc, output.encode(), "", "", "")

    monkeypatch.setattr(engine.core_hostkey, "scan", lambda *args, **kwargs: "test-pinned-key")
    monkeypatch.setattr(engine.core_ssh, "run_command", transport)
    monkeypatch.setattr(audit, "_RECORDER", Recorder(tmp_path / "operations.jsonl", "helper"))

    def call(args=None):
        result = asyncio.run(bridge.call(server.mcp, "network_overview", args or {}))
        assert not result["isError"], result
        assert json.loads(result["content"][0]["text"]) == result["structuredContent"]
        return result["structuredContent"]

    return type("Lab", (), {"configure": staticmethod(configure), "answers": answers, "calls": calls,
                            "call": staticmethod(call)})


def reasons(row, field):
    return {item["reason"] for item in row["missing"] if item["field"] == field}


def reads(row):
    return {item["id"]: item["status"] for item in row["reads"]}


def test_ios_router_identity_resources_and_admin_state(lab):
    lab.configure(device("r1", 10, "cisco_ios", types=("router",)))
    lab.answers["192.0.2.10"] = IOSV
    row = lab.call()["devices"][0]
    assert row["platform"] == "cisco_ios" and row["reachability"] == "reachable"
    assert (row["version"], row["model"]) == ("15.9(3)M12", "IOSv")
    assert row["uptime_seconds"] == 604800 + 4 * 86400 + 5 * 3600 + 39 * 60
    assert row["firmware_support"]["status"] == "tested"
    assert row["cpu"] == {"used_pct": 13, "sample_seconds": 60}
    assert row["memory"] == {"used_pct": 22.66, "total_bytes": 316551532, "used_bytes": 71717168}
    # Gi0/2 and Gi0/3 are administratively down: not an admin-up/link-down finding.
    assert row["interfaces"]["admin_up_down"] == []
    assert row["interfaces"]["with_errors"] == []
    # The RO account is refused the environment read on the virtual router; identity stays verified.
    assert reads(row)["environment"] == "failed"
    assert reasons(row, "temperatures") == {"permission_denied"}
    assert row["status"] == "partial"
    # A router has no planned stack or PoE read and says why.
    assert {"stack_members", "power_inline"}.isdisjoint(reads(row))
    assert reasons(row, "poe") == {"source_limit"} and reasons(row, "redundancy") == {"source_limit"}
    assert reasons(row, "fortiguard") == {"not_applicable"} and reasons(row, "licenses") == {"source_limit"}
    assert [command for _, command in lab.calls] == [
        "show version", "show processes cpu", "show processes memory", "show interfaces", "show env all"]
    for field in model.FACT_FIELDS:
        if row[field] is None and field not in {"managed", "firmware_support"}:
            assert reasons(row, field), field


def test_ios_switch_admin_up_link_down_and_refused_switch_reads(lab):
    lab.configure(device("s1", 11, "cisco_ios"))
    lab.answers["192.0.2.11"] = IOSVL2
    row = lab.call()["devices"][0]
    assert row["interfaces"]["admin_up_down"] == [{"name": "GigabitEthernet0/3", "read_ids": ["interfaces_details"]}]
    assert [item["code"] for item in row["findings"]] == ["admin_up_link_down"]
    assert reasons(row, "poe") == {"permission_denied"}
    assert reasons(row, "redundancy") == {"permission_denied"}
    # stack_ports depends on a usable member table.
    assert reads(row)["stack_ports"] == "not_run"
    assert ("192.0.2.11", "show switch stack-ports summary") not in lab.calls


def test_xe_signature_on_ios_enrollment_stops_further_reads(lab):
    lab.configure(device("wrong", 12, "cisco_ios"), device("xe", 13, "cisco_xe"))
    lab.answers["192.0.2.12"] = IOLXE
    lab.answers["192.0.2.13"] = IOLXE
    wrong, xe = lab.call()["devices"]
    assert reasons(wrong, "version") == {"identity_unverified"}
    assert [command for host, command in lab.calls if host == "192.0.2.12"] == ["show version"]
    assert xe["version"] == "17.18.2" and xe["model"] is None
    assert reasons(xe, "model") == {"source_limit"}
    assert xe["uptime_seconds"] == 2 * 86400 + 600


def test_xe_documented_stack_and_poe_budget(lab):
    lab.configure(device("xe", 13, "cisco_xe"))
    lab.answers["192.0.2.13"] = IOLXE
    row = lab.call()["devices"][0]
    assert row["poe"] == {"budget_w": 857.0, "used_w": 8.9, "available_w": 848.1}
    assert row["redundancy"] == [{"kind": "stack", "state": "ok", "members": 3, "role": "active",
                                  "read_ids": ["stack_members", "stack_ports"]}]
    assert reads(row)["stack_ports"] == "ok"
    # Ethernet0/2 and later are administratively down on the IOL capture.
    assert row["interfaces"]["admin_up_down"] == []


@pytest.mark.parametrize(("key", "capture", "field"), [
    ("show power inline", "cisco_xe/power_inline/derived_summary_mismatch", "poe"),
    ("show switch", "cisco_xe/stack_members/derived_member_removed", None),
    ("show switch stack-ports summary", "cisco_xe/stack_ports/derived_port_down", None),
])
def test_contradicting_summary_and_degraded_stack(lab, key, capture, field):
    lab.configure(device("xe", 13, "cisco_xe"))
    lab.answers["192.0.2.13"] = dict(IOLXE, **{key: CAPTURES[capture]})
    row = lab.call()["devices"][0]
    if field == "poe":
        assert row["poe"] is None and reasons(row, "poe") == {"unparsed"}
        assert reads(row)["power_inline"] == "incomplete"
    else:
        assert row["redundancy"][0]["state"] == "degraded"
        assert {"code": "redundancy_degraded", "severity": "critical", "field": "redundancy",
                "subject": "stack", "read_ids": row["redundancy"][0]["read_ids"]} in row["findings"]


def test_nxos_counters_virtual_environment_vpc_and_empty_licenses(lab):
    lab.configure(device("nx", 14, "cisco_nxos", enabled=NXOS_ENABLED))
    lab.answers["192.0.2.14"] = NXOS
    row = lab.call()["devices"][0]
    assert (row["version"], row["model"]) == ("9.3(12)", "C9300v")
    assert row["uptime_seconds"] == 4 * 86400 + 9 * 3600 + 47 * 60 + 56
    assert row["cpu"] == {"used_pct": 11.98, "sample_seconds": None}
    assert row["memory"]["total_bytes"] == 8158300 * 1024
    errors = {item["name"]: item for item in row["interfaces"]["with_errors"]}
    assert list(errors) == ["Ethernet1/9"]
    assert errors["Ethernet1/9"]["counters"]["tx_errors"] == 10133210864287744
    assert errors["Ethernet1/9"]["counter_kind"] == "cumulative"
    assert "crc" in errors["Ethernet1/9"]["counters"] and errors["Ethernet1/9"]["counters"]["crc"] == 0
    names = {item["name"] for item in row["interfaces"]["admin_up_down"]}
    assert "Ethernet1/10" in names and "Ethernet1/3" not in names and "Ethernet1/1" not in names
    # The virtual Nexus prints the environment headers without hardware rows.
    assert row["fans"] is None and reasons(row, "fans") == {"not_applicable"}
    assert reasons(row, "power") == {"not_applicable"} and reasons(row, "poe") == {"not_applicable"}
    # A configured vPC domain without a peer link is not redundant; the supervisor is standalone.
    assert row["redundancy"] == [{"kind": "vpc", "state": "degraded", "read_ids": ["vpc_status"]},
                                 {"kind": "ha", "state": "standalone", "role": "active",
                                  "read_ids": ["redundancy_status"]}]
    # The only feature in use runs under the honor model without an installed license.
    assert row["licenses"] == [{"name": "LAN_ENTERPRISE_SERVICES_PKG", "state": "unlicensed", "expires_on": None,
                                "read_ids": ["license_usage"]}]
    assert not reasons(row, "licenses")
    assert row["status"] == "complete"
    codes = {item["code"] for item in row["findings"]}
    assert codes == {"admin_up_link_down", "interface_errors_present", "redundancy_degraded"}


def test_nxos_formed_vpc_pair_is_ok(lab):
    lab.configure(device("nx", 14, "cisco_nxos", enabled=NXOS_ENABLED))
    lab.answers["192.0.2.14"] = dict(NXOS, **{
        "show vpc brief": text("cisco_nxos/nxos_ports_nexus9300v_9.3.12/peer-a-vpc-brief.out")})
    row = lab.call()["devices"][0]
    assert row["redundancy"][0] == {"kind": "vpc", "state": "ok", "role": "primary", "read_ids": ["vpc_status"]}


def test_ambiguous_rows_mark_reads_incomplete_and_keep_other_fields(lab):
    lab.configure(device("nx", 14, "cisco_nxos", enabled=NXOS_ENABLED), device("r1", 10, "cisco_ios",
                                                                              types=("router",)))
    # Derived: one status cell outside the documented values and an unknown detail line.
    status = NXOS["show interface status"].replace(
        "Eth1/3        --                 suspended", "Eth1/3        --                 mystery  ")
    details = IOSV["show interfaces"].replace("  Hardware is iGbE", "  Hardware is iGbE\n  mystery counter 5", 1)
    lab.answers["192.0.2.14"] = dict(NXOS, **{"show interface status": status})
    lab.answers["192.0.2.10"] = dict(IOSV, **{"show interfaces": details})
    nx, router = lab.call()["devices"]
    assert reads(nx)["interfaces"] == "incomplete" and nx["status"] == "partial"
    assert reasons(nx, "interfaces.admin_up_down") == {"unparsed"}
    assert nx["interfaces"]["with_errors"] is not None and nx["cpu"] is not None
    assert reads(router)["interfaces_details"] == "incomplete"
    assert reasons(router, "interfaces.with_errors") == {"unparsed"}
    assert router["cpu"] == {"used_pct": 13, "sample_seconds": 60}


def test_paged_or_interrupted_output_is_not_complete(lab):
    lab.configure(device("r1", 10, "cisco_ios", types=("router",)))
    # Derived: the capture stops at a pager prompt.
    cut = IOSV["show interfaces"].split("GigabitEthernet0/2")[0] + " --More-- "
    lab.answers["192.0.2.10"] = dict(IOSV, **{"show interfaces": cut})
    row = lab.call()["devices"][0]
    assert reasons(row, "interfaces.admin_up_down") == {"truncated"}
    assert row["interfaces"]["admin_up_down"] is None
    assert row["version"] == "15.9(3)M12" and row["memory"] is not None


def test_contradicting_memory_totals(lab):
    lab.configure(device("nx", 14, "cisco_nxos", enabled=NXOS_ENABLED))
    # Derived: used + free no longer equals total.
    resources = NXOS["show system resources"].replace("3989048K used", "3989049K used")
    lab.answers["192.0.2.14"] = dict(NXOS, **{"show system resources": resources})
    row = lab.call()["devices"][0]
    assert row["memory"] is None and reasons(row, "memory") == {"unparsed"}
    assert row["cpu"] == {"used_pct": 11.98, "sample_seconds": None}


def test_budget_shortage_keeps_priority_reads_and_other_targets(lab):
    lab.configure(device("nx", 14, "cisco_nxos", enabled=NXOS_ENABLED, requests=3),
                  device("r1", 10, "cisco_ios", types=("router",)))
    lab.answers["192.0.2.14"] = NXOS
    lab.answers["192.0.2.10"] = IOSV
    nx, router = lab.call()["devices"]
    assert [read["status"] for read in nx["reads"]][:3] == ["ok", "ok", "ok"]
    assert {read["status"] for read in nx["reads"][3:]} == {"not_run"}
    assert reasons(nx, "licenses") == {"read_limit"} and nx["status"] == "partial"
    assert nx["cpu"] is not None and nx["interfaces"]["admin_up_down"]
    assert len([call for call in lab.calls if call[0] == "192.0.2.14"]) == 3
    assert router["version"] == "15.9(3)M12" and reads(router)["interfaces_details"] == "ok"


def test_plan_declares_catalog_queries_in_priority_order():
    from netops_helper.query_catalog import READ_QUERIES

    for platform, types in (("cisco_ios", ("router",)), ("cisco_xe", ("switch",)), ("cisco_nxos", ())):
        scope = model.Scope(platform, tuple(READ_QUERIES[platform]), {}, types)
        specs = model.with_identity(scope, cisco.plan(scope))
        assert specs[0].query == "version" and specs[0].id == "version"
        assert all(spec.query in READ_QUERIES[platform] for spec in specs)
    xe = model.Scope("cisco_xe", tuple(READ_QUERIES["cisco_xe"]), {}, ("router",))
    ids = [spec.id for spec in cisco.plan(xe)]
    # The preferred control-plane summary comes before its fallback; the controller pair comes last.
    assert ids[:4] == ["version", "platform_resources", "cpu", "memory"]
    assert ids[-3:] == ["environment", "c9800_redundancy", "c9800_chassis_rmi"]


@pytest.mark.parametrize(("value", "seconds"), [
    ("1 week, 4 days, 5 hours, 39 minutes", 970740), ("2 days, 10 minutes", 173400),
    ("4 day(s), 9 hour(s), 47 minute(s), 56 second(s)", 380876), ("1 year, 1 minute", 31536060),
    ("5 minutes, 5 minutes", None), ("about a day", None), ("", None),
])
def test_uptime_conversion(value, seconds):
    assert cisco.uptime_seconds(value) == seconds


def test_documented_tables_and_refusals():
    assert cisco.poe_summary(CAPTURES["cisco_xe/power_inline/doc_c9200_poe_troubleshooting"])[1] is True
    assert cisco.poe_summary(IOSVL2["show power inline"]) == (None, False)
    members, complete = cisco.stack_members(CAPTURES["cisco_xe/stack_members/doc_c9300_stackwise"])
    assert complete and [item["role"] for item in members] == ["active", "standby", "member"]
    ports, complete = cisco.stack_ports(CAPTURES["cisco_xe/stack_ports/doc_c9300_stackwise"])
    assert complete and len(ports) == 6
    # Derived: without the honor-mode row nothing is installed or used, a measured empty list.
    unused = NXOS["show license usage"].replace(
        "LAN_ENTERPRISE_SERVICES_PKG   No    -   In use             Honor Start 2H 33M\n", "")
    assert cisco.nxos_licenses(unused) == ([], True)
    used = unused.replace("SECURITY_PKG                  No    0   Unused",
                                              "SECURITY_PKG                  Yes   1   In use")
    assert cisco.nxos_licenses(used) == ([{"name": "SECURITY_PKG", "state": "valid", "expires_on": None}], True)
    assert "netops_helper.overview.cisco" in sys.modules


@pytest.mark.parametrize(("platform", "image", "deleted"), [
    ("cisco_ios", "live_iosv_15.9.3M12", ("GigabitEthernet0/3.900", "GigabitEthernet0/3.901")),
    ("cisco_xe", "live_iolxe_17.18.2", ("Ethernet0/2.80", "Ethernet0/3.164")),
])
def test_live_deleted_subinterfaces_are_not_counted(lab, platform, image, deleted):
    lab.configure(device("r", 15, platform, types=("router",)))
    base = IOSV if platform == "cisco_ios" else IOLXE
    lab.answers["192.0.2.15"] = dict(base, **{
        "show version": CAPTURES[f"{platform}/version/{image}"],
        "show interfaces": CAPTURES[f"{platform}/interfaces_details/{image}"]})
    row = lab.call()["devices"][0]
    assert reads(row)["interfaces_details"] == "ok"
    assert row["interfaces"]["admin_up_down"] == [] and row["interfaces"]["with_errors"] == []
    assert not reasons(row, "interfaces.admin_up_down") and not reasons(row, "interfaces.with_errors")
    text = cisco.without_deleted(CAPTURES[f"{platform}/interfaces_details/{image}"])
    assert all(name not in text for name in deleted)
    # Without the filter the shared detail parser cannot account for the deleted headers.
    assert port_errors_unknown(CAPTURES[f"{platform}/interfaces_details/{image}"]) == len(deleted)


def port_errors_unknown(value):
    from netops_helper import port_errors

    return len(port_errors.ios_details(value)[1])


def test_live_nxos_without_vpc_feature_keeps_supervisor_state(lab):
    lab.configure(device("nx", 14, "cisco_nxos", enabled=NXOS_ENABLED))
    lab.answers["192.0.2.14"] = dict(NXOS, **{
        "show vpc brief": (16, CAPTURES["cisco_nxos/vpc_status/live_nexus9300v_9.3.12_feature_off"])})
    row = lab.call()["devices"][0]
    # Live NX-OS 9.3(12) without `feature vpc` has no vPC commands: the measured syntax error states that
    # vPC does not apply to this switch. It is a valid answer, not unreadable output.
    assert reads(row)["vpc_status"] == "empty" and reasons(row, "redundancy") == {"not_applicable"}
    assert row["redundancy"] == [{"kind": "ha", "state": "standalone", "role": "active",
                                  "read_ids": ["redundancy_status"]}]
    assert row["cpu"] is not None and row["licenses"] is not None


@pytest.mark.parametrize(("version", "rc"), [
    # Derived physical identity: the same Nexus capture without the demo image line.
    ("\n".join(line for line in NXOS["show version"].splitlines()
               if "Nexus 9000v is a demo version" not in line) + "\n", 16),
    (NXOS["show version"], 1),  # the virtual Nexus, but not the measured exit status 16
], ids=["physical-identity-rc16", "virtual-identity-rc1"])
def test_nxos_vpc_syntax_error_outside_the_measured_virtual_answer_stays_unparsed(lab, version, rc):
    """Review finding 1: the measured syntax error is a vPC answer only of the virtual Nexus with exit 16."""
    assert "Nexus 9000v is a demo version" in NXOS["show version"]
    lab.configure(device("nx", 14, "cisco_nxos", enabled=NXOS_ENABLED))
    lab.answers["192.0.2.14"] = dict(NXOS, **{
        "show version": version,
        "show vpc brief": (rc, CAPTURES["cisco_nxos/vpc_status/live_nexus9300v_9.3.12_feature_off"])})
    row = lab.call()["devices"][0]
    assert reads(row)["version"] == "ok"
    assert reads(row)["vpc_status"] == "incomplete" and reasons(row, "redundancy") == {"unparsed"}
    assert row["redundancy"] == [{"kind": "ha", "state": "standalone", "role": "active",
                                  "read_ids": ["redundancy_status"]}]
    assert row["status"] == "partial"


def test_other_nxos_vpc_refusal_stays_unparsed(lab):
    lab.configure(device("nx", 14, "cisco_nxos", enabled=NXOS_ENABLED))
    lab.answers["192.0.2.14"] = dict(NXOS, **{
        "show vpc brief": (16, CAPTURES["cisco_nxos/vpc_status/live_nexus9300v_9.3.12_feature_off"].replace(
            "'show vpc brief'", "'show vpc'"))})
    row = lab.call()["devices"][0]
    assert reads(row)["vpc_status"] == "incomplete" and reasons(row, "redundancy") == {"unparsed"}


# --- regressions of the review findings ----------------------------------------------------------------------------

def test_nxos_vpc_member_down_after_mtu_mismatch_is_degraded(lab):
    """Finding 1: adjacency, keep-alive and global consistency are fine, the local vPC 128 is down*/failed."""
    from netops_helper import switch_vpc

    capture = text("cisco_nxos/nxos_ports_nexus9300v_9.3.12/peer-b-vpc-brief-mtu.out")
    summary = switch_vpc.summarize(capture)
    assert summary["state"] == "measured" and summary["consistency_status"] == "success"
    assert [(row["status"], row["consistency"]) for row in summary["members"]] == [("down*", "failed")]
    lab.configure(device("nx", 14, "cisco_nxos", enabled=NXOS_ENABLED))
    lab.answers["192.0.2.14"] = dict(NXOS, **{"show vpc brief": capture})
    row = lab.call()["devices"][0]
    assert row["redundancy"][0] == {"kind": "vpc", "state": "degraded", "role": "secondary",
                                    "read_ids": ["vpc_status"]}
    assert {"code": "redundancy_degraded", "severity": "critical", "field": "redundancy", "subject": "vpc",
            "read_ids": ["vpc_status"]} in row["findings"]
    assert reads(row)["vpc_status"] == "ok"


def _stack_ports(transform):
    lines = CAPTURES["cisco_xe/stack_ports/doc_c9300_stackwise"].split("\n")
    return "\n".join(transform(lines))


def test_stack_port_with_inactive_link_is_degraded(lab):
    """Finding 2a. Derived: port 2/2 of the documented stack keeps everything but `Link Active` = No."""
    def inactive(lines):
        return [line.replace("50cm         Yes     Yes         Yes", "50cm         Yes     No          Yes")
                if line.startswith("2/2 ") else line for line in lines]

    ports = _stack_ports(inactive)
    assert ports.count("No          Yes") == 1
    lab.configure(device("xe", 13, "cisco_xe"))
    lab.answers["192.0.2.13"] = dict(IOLXE, **{"show switch stack-ports summary": ports})
    row = lab.call()["devices"][0]
    assert row["redundancy"][0]["state"] == "degraded" and reads(row)["stack_ports"] == "ok"
    assert {"code": "redundancy_degraded", "severity": "critical", "field": "redundancy", "subject": "stack",
            "read_ids": ["stack_members", "stack_ports"]} in row["findings"]


def test_stack_ports_without_rows_of_a_member_are_partial(lab):
    """Finding 2b. Derived: both rows of member 3 are left out, `show switch` still lists member 3."""
    ports = _stack_ports(lambda lines: [line for line in lines if not line.startswith(("3/1 ", "3/2 "))])
    assert "3/1" not in ports and "2/2" in ports
    lab.configure(device("xe", 13, "cisco_xe"))
    lab.answers["192.0.2.13"] = dict(IOLXE, **{"show switch stack-ports summary": ports})
    row = lab.call()["devices"][0]
    assert row["redundancy"][0]["state"] == "unknown"
    assert reads(row)["stack_ports"] == "incomplete" and reasons(row, "redundancy") == {"unparsed"}
    assert row["status"] == "partial"
    assert "redundancy_degraded" not in {item["code"] for item in row["findings"]}


def test_xe_power_supply_without_input_power_is_hardware_degraded(lab):
    """Finding 3: the documented `No Input Power` supply 1A, the same sample triage_health reports as a fault."""
    capture = (FIXTURES / "docs/cisco_xe/xe-health/environment.out").read_text()
    lab.configure(device("xe", 13, "cisco_xe", types=("router",)))
    lab.answers["192.0.2.13"] = dict(IOLXE, **{"show environment all": capture})
    row = lab.call()["devices"][0]
    assert reads(row)["environment"] == "ok" and not reasons(row, "power")
    assert row["power"] == [{"name": "1A", "state": "failed", "read_ids": ["environment"]},
                            {"name": "1B", "state": "ok", "read_ids": ["environment"]}]
    # The absent PS-1 fan slot is not a failed fan.
    assert [item["state"] for item in row["fans"]] == ["ok"] * 4
    assert {"code": "hardware_degraded", "severity": "critical", "field": "power", "subject": "1A",
            "read_ids": ["environment"]} in row["findings"]


def test_xe_unknown_printed_environment_state_is_not_healthy(lab):
    capture = (FIXTURES / "docs/cisco_xe/xe-health/environment.out").read_text()
    # Derived: an undocumented supply state.
    capture = capture.replace("No Input Power", "Mystery State ")
    lab.configure(device("xe", 13, "cisco_xe", types=("router",)))
    lab.answers["192.0.2.13"] = dict(IOLXE, **{"show environment all": capture})
    row = lab.call()["devices"][0]
    assert row["power"][0]["state"] == "unknown"
    assert reads(row)["environment"] == "incomplete" and reasons(row, "power") == {"unparsed"}


def test_c9800_reads_never_take_the_budget_of_approved_reads(lab):
    """Finding 4: IOL XE router, budget 6, the controller pair enrolled next to the approved environment."""
    enabled = ("version", "cpu", "memory", "interfaces_details", "environment", "c9800_redundancy",
               "c9800_chassis_rmi")
    lab.configure(device("xe", 13, "cisco_xe", types=("router",), enabled=enabled, requests=6))
    lab.answers["192.0.2.13"] = dict(IOLXE, **{
        "show environment all": (FIXTURES / "docs/cisco_xe/xe-health/environment.out").read_text(),
        "show redundancy": 'Line has invalid autocommand "show redundancy"'})
    row = lab.call()["devices"][0]
    statuses = reads(row)
    assert statuses["environment"] == "ok" and row["power"] is not None
    assert statuses["c9800_chassis_rmi"] == "not_run" and reasons(row, "temperatures") == set()
    commands = [command for _, command in lab.calls]
    assert commands.index("show environment all") < commands.index("show redundancy")
    assert "show chassis rmi" not in commands
    # The image is not a controller: no HA state is derived from the controller reads.
    assert row["redundancy"] is None and "not_applicable" in reasons(row, "redundancy")


def test_xe_platform_resources_is_preferred_for_cpu_and_memory(lab):
    """Finding 5: only `platform_resources` enrolled next to identity, the documented control-plane summary."""
    enabled = ("version", "platform_resources", "interfaces_details")
    lab.configure(device("xe", 13, "cisco_xe", types=("router",), enabled=enabled))
    lab.answers["192.0.2.13"] = dict(IOLXE, **{
        "show platform resources": (FIXTURES / "docs/cisco_xe/xe-health/platform_resources.out").read_text()})
    row = lab.call()["devices"][0]
    assert row["cpu"] == {"used_pct": 7.2, "sample_seconds": None}
    assert row["memory"] == {"used_pct": 69.56, "total_bytes": 3883 * 1024 * 1024, "used_bytes": 2701 * 1024 * 1024}
    assert not reasons(row, "cpu") and not reasons(row, "memory")
    assert reads(row)["platform_resources"] == "ok"
    assert [command for _, command in lab.calls][:2] == ["show version", "show platform resources"]
    assert {"show processes cpu", "show processes memory"}.isdisjoint(command for _, command in lab.calls)


def test_xe_refused_platform_resources_falls_back_to_cpu_and_memory(lab):
    enabled = ("version", "platform_resources", "cpu", "memory", "interfaces_details")
    lab.configure(device("xe", 13, "cisco_xe", types=("router",), enabled=enabled))
    lab.answers["192.0.2.13"] = dict(IOLXE, **{
        "show platform resources": text("cisco_xe/iolxe_17.18.2/platform_resources.txt")})
    row = lab.call()["devices"][0]
    assert reads(row)["platform_resources"] == "failed"
    assert row["cpu"]["sample_seconds"] == 60 and row["memory"]["total_bytes"] > 0
    assert reads(row)["cpu"] == reads(row)["memory"] == "ok"
    # The refusal of the preferred source stays visible.
    assert reasons(row, "cpu") == {"permission_denied"}


def test_platform_resources_parser_rejects_contradicting_dram():
    sample = (FIXTURES / "docs/cisco_xe/xe-health/platform_resources.out").read_text()
    assert cisco.platform_resources(sample)[1] is True
    # Derived: the printed DRAM percent no longer matches used / max.
    metrics, complete = cisco.platform_resources(sample.replace("2701MB(69%)", "2701MB(19%)"))
    assert "memory" not in metrics and metrics["cpu"]["used_pct"] == 7.2 and not complete


def test_optional_null_values_follow_the_documented_contract(lab):
    """Finding 6: an optional value the source does not print is null without a missing entry."""
    lab.configure(device("nx", 14, "cisco_nxos", enabled=NXOS_ENABLED))
    lab.answers["192.0.2.14"] = NXOS
    row = lab.call()["devices"][0]
    assert row["cpu"]["sample_seconds"] is None and row["managed"] is None
    assert not reasons(row, "cpu") and not reasons(row, "cpu.sample_seconds") and not reasons(row, "managed")
    docs = (Path(__file__).parents[1] / "docs/network-overview-cisco.md").read_text()
    assert "Each null field has a `missing` entry" not in docs
    contract = next(line for line in docs.splitlines() if line.startswith("A null field"))
    assert "`cpu.sample_seconds`" in contract and "`managed`" in contract and "without a `missing` entry" in contract
