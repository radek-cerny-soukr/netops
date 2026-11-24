"""Ruckus controller overview through real auth, catalogue and PTY dialogue."""

from netops_helper.overview import ruckus, runner
from netops_helper.overview.model import ReadResult

from test_network_overview_linux import FIXTURES, h5, overview_device
from test_wireless_path_ruckus import unleashed

QUERIES = ("system_info", "ethernet_info", "access_points")


def setup(monkeypatch):
    commands = ("show sysinfo", "show ethinfo", "show ap all")
    replies = {command: (FIXTURES / "ruckus_wireless_path" /
                         ("ruckus-" + command.replace(" ", "_") + ".out")).read_text() for command in commands}
    sent = []
    unleashed(monkeypatch, replies, sent)
    return replies, sent


def device(**options):
    return overview_device("ruckus_unleashed", QUERIES, role="admin-bounded", **options)


def test_ruckus_memory_role_and_admin_state(h5, monkeypatch):
    _, sent = setup(monkeypatch)
    row, = h5(device())
    assert row["version"] == "200.15.6.212 build 27", row
    assert row["model"] == "r610"
    assert row["uptime_seconds"] == (41 * 1440 + 63) * 60
    assert row["memory"]["used_bytes"] == 235000 * 1024
    assert row["memory"]["total_bytes"] == (235000 + 235956) * 1024
    assert row["redundancy"] == [{"kind": "ha", "state": "unknown", "role": "master", "read_ids": ["access_points"]}]
    assert row["interfaces"]["admin_up_down"] is None
    assert sent == ["show sysinfo", "show ethinfo", "show ap all"]


def test_ruckus_empty_when_every_link_is_up(h5, monkeypatch):
    replies, _ = setup(monkeypatch)
    replies["show ethinfo"] = replies["show ethinfo"].replace("Physical Link= down", "Physical Link= up")
    replies["show ap all"] = replies["show ap all"].replace("PhysicalLink= Down", "PhysicalLink= Up 1000Mbps full")
    row, = h5(device())
    assert row["interfaces"]["admin_up_down"] == []
    assert row["interfaces"]["with_errors"] is None


def test_ruckus_normalizes_version_spacing(h5, monkeypatch):
    replies, _ = setup(monkeypatch)
    command = "show sysinfo"
    replies[command] = replies[command].replace("200.15.6.212 build 27", "200.15.6.212  build   27")
    row, = h5(device())
    assert row["version"] == "200.15.6.212 build 27"
    assert row["firmware_support"]
    assert row["redundancy"][0]["role"] == "master"


def test_ruckus_failed_system_info_does_not_mark_parsed_access_points_incomplete(h5, monkeypatch):
    replies, _ = setup(monkeypatch)
    system, ethernet, aps = ruckus.plan(None)
    # Supply completed AP and Ethernet reads at the adapter boundary.
    # The runner normally skips later SSH reads when the identity read fails.
    reads = {
        system.id: ReadResult(system, "failed", reason="permission_denied"),
        ethernet.id: ReadResult(ethernet, "ok", text=replies["show ethinfo"]),
        aps.id: ReadResult(aps, "ok", text=replies["show ap all"]),
    }
    monkeypatch.setattr(runner, "_run_reads", lambda *args: reads)
    row, = h5(device())
    assert row["redundancy"] is None
    assert {read["id"]: read["status"] for read in row["reads"]} == {
        "system_info": "failed", "ethernet_info": "ok", "access_points": "ok",
    }
    assert [(item.get("read_id"), item["reason"]) for item in row["missing"]
            if item["field"] == "redundancy"] == [("system_info", "permission_denied")]


def test_ruckus_summary_count_and_ambiguous_memory(h5, monkeypatch):
    replies, _ = setup(monkeypatch)
    replies["show sysinfo"] = replies["show sysinfo"].replace("Number of APs= 1", "Number of APs= 2")
    replies["show sysinfo"] += "  Used Bytes= 135000(kB)\n"
    row, = h5(device())
    assert row["model"] == "r610" and row["memory"] is None
    assert row["reads"][0]["status"] == row["reads"][2]["status"] == "incomplete"
    assert row["redundancy"][0]["role"] == "master"


def test_ruckus_conflicting_ethernet_line_keeps_unrelated_facts(h5, monkeypatch):
    replies, _ = setup(monkeypatch)
    replies["show ethinfo"] = replies["show ethinfo"].replace(
        "Physical Link= down", "Physical Link= down\n    Physical Link= up")
    replies["show ap all"] = replies["show ap all"].replace("PhysicalLink= Down", "PhysicalLink= Up 1000Mbps full")
    row, = h5(device())
    assert row["interfaces"]["admin_up_down"] is None
    assert next(item for item in row["reads"] if item["id"] == "ethernet_info")["status"] == "incomplete"
    assert any(item.get("read_id") == "ethernet_info" and item["reason"] == "unparsed" for item in row["missing"])
    assert row["memory"]["used_bytes"] == 235000 * 1024
    assert row["redundancy"][0]["role"] == "master"


def test_ruckus_refusal_pager_and_budget_keep_peer_identity(h5, monkeypatch):
    replies, sent = setup(monkeypatch)
    replies["show ethinfo"] = "Error: Permission denied\n"
    replies["show ap all"] += "\n--More--\n"
    full, low = h5(device(name="a-full"), device(name="b-budget", number=11, requests=1))
    assert full["model"] == low["model"] == "r610"
    assert full["interfaces"]["admin_up_down"] is None and full["redundancy"] is None
    assert any(item.get("read_id") == "ethernet_info" and item["reason"] == "permission_denied" for item in full["missing"])
    assert any(item.get("read_id") == "access_points" and item["reason"] in {"unparsed", "truncated"} for item in full["missing"])
    assert {item["reason"] for item in low["missing"] if item.get("read_id") == "ethernet_info"} == {"read_limit"}
    assert sent.count("show ethinfo") == sent.count("show ap all") == 1
