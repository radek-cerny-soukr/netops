"""EOS overview through the real Helper bridge and read policy."""

from pathlib import Path

from test_network_overview import device, setup  # noqa: F401

FIXTURES = Path(__file__).parent / "fixtures" / "real" / "arista_eos"
BASE = FIXTURES / "ceos_4.36.1F"
PAIR = FIXTURES / "network_overview_ceos_4.36.1F"
PROFILE = "arista_eos"
EOS_COMMANDS = {
    "show version": "version",
    "show processes top once": "cpu",
    "show interfaces status": "interfaces",
    "show mlag detail": "mlag_detail",
    "show interfaces counters errors": "interfaces_counters_errors",
    "show system environment all": "environment",
    "show poe": "poe",
}


def enrolled(alias, number, profile, queries, *, requests=30, interfaces=(), types=("switch",)):
    result = device(alias, number, types=types, enabled=queries, requests=requests)
    result["platform"] = result["helper"]["ssh_platform"] = profile
    result["helper"]["read_inventory"] = {"interfaces": list(interfaces)}
    return result


def eos_output(command, *, pair=False):
    if pair and command in {"show mlag detail", "show mlag interfaces"}:
        return (PAIR / (command.replace("show ", "").replace(" ", "_") + ".out")).read_text()
    if command == "show poe":
        return "% Invalid input at line 1\n"
    return (BASE / (EOS_COMMANDS[command] + ".txt")).read_text()


def overview(setup):
    result = setup.call({})
    assert not result["isError"], result
    return result["structuredContent"]["devices"]


def test_eos_reports_standalone_and_local_peer_state(setup):
    setup.configure(enrolled("pair", 11, PROFILE, (*EOS_COMMANDS.values(), "mlag_interfaces")),
                    enrolled("standalone", 12, PROFILE, EOS_COMMANDS.values()))
    setup.handlers["192.0.2.11"] = lambda cmd, _: eos_output(cmd, pair=True)
    setup.handlers["192.0.2.12"] = lambda cmd, _: eos_output(cmd)
    pair, standalone = overview(setup)
    assert pair["model"] == "cEOSLab"
    assert pair["version"].startswith("4.36.1F")
    assert pair["uptime_seconds"] == 53 * 60
    assert pair["cpu"] == {"used_pct": 87.7, "sample_seconds": None}
    assert pair["memory"]["total_bytes"] > pair["memory"]["used_bytes"] > 0
    assert pair["interfaces"] == {"scope": "device", "admin_up_down": [], "with_errors": []}
    assert pair["redundancy"][0]["role"] == "secondary"
    assert pair["redundancy"][0]["state"] == "ok"
    assert pair["redundancy"][0]["members"][0]["name"] == "Port-channel128"
    assert standalone["redundancy"] == [{"kind": "mlag", "state": "standalone", "members": [],
                                          "read_ids": ["mlag_detail"]}]
    assert standalone["power"] == []
    assert standalone["licenses"] is None
    assert len([cmd for host, cmd in setup.calls if host == "192.0.2.11"]) == 8
    assert len([cmd for host, cmd in setup.calls if host == "192.0.2.12"]) == 7


def test_eos_partial_evidence_preserves_other_fields_and_devices(setup):
    setup.configure(enrolled("partial", 11, PROFILE, (*EOS_COMMANDS.values(), "mlag_interfaces")),
                    enrolled("small-budget", 12, PROFILE, EOS_COMMANDS.values(), requests=2))
    rows = eos_output("show interfaces status").splitlines()
    start = rows[0].index("Status")
    end = rows[0].index("Vlan")
    states = ("disabled", "notconnect", "errdisabled", "inactive", "undocumented")
    for index, state in enumerate(states, 1):
        rows[index] = rows[index][:start] + state.ljust(end - start) + rows[index][end:]
    partial = {
        "show interfaces status": "\n".join(rows),
        "show interfaces counters errors": eos_output("show interfaces counters errors") + "--More--",
        "show system environment all": "Error: Permission denied\n",
        "show processes top once": "\n".join(eos_output("show processes top once").splitlines()[:4]),
        "show mlag detail": eos_output("show mlag detail", pair=True).replace(
            "Active-full                        :                   1",
            "Active-full                        :                   2",
        ),
    }
    setup.handlers["192.0.2.11"] = lambda cmd, _: partial[cmd] if cmd in partial else eos_output(cmd, pair=True)
    setup.handlers["192.0.2.12"] = lambda cmd, _: eos_output(cmd)
    row, limited = overview(setup)
    assert row["status"] == limited["status"] == "partial"
    assert {(entry.get("read_id"), entry["reason"]) for entry in row["missing"]} >= {
        ("environment", "permission_denied"), ("interfaces_counters_errors", "truncated"),
        ("interfaces", "unparsed"), ("cpu", "unparsed"), ("mlag_interfaces", "unparsed"),
    }
    assert [entry["name"] for entry in row["interfaces"]["admin_up_down"]] == ["Ethernet2", "Ethernet3"]
    assert row["interfaces"]["with_errors"] is None
    assert row["cpu"]["used_pct"] == 87.7
    assert row["memory"]["total_bytes"] > 0
    assert row["redundancy"][0]["members"][0]["name"] == "Port-channel128"
    assert limited["model"] == "cEOSLab"
    assert [cmd for host, cmd in setup.calls if host == "192.0.2.12"] == [
        "show version", "show processes top once",
    ]
    assert any(entry["reason"] == "read_limit" for entry in limited["missing"])


MEASURED = FIXTURES / "ceos_4.36.1F_overview_20261123"


def live_exit_status(command):
    """The container's own exit status: `show system environment all` and `show poe` exit 1 on cEOSLab."""
    if command == "show poe":
        return 1, (MEASURED / "poe.txt").read_text()
    if command == "show system environment all":
        return 1, eos_output(command)
    return eos_output(command)


def test_ceos_lab_has_no_sensors_supplies_or_pse_and_says_so(setup):
    setup.configure(enrolled("lab", 11, PROFILE, EOS_COMMANDS.values()))
    setup.handlers["192.0.2.11"] = lambda cmd, _: live_exit_status(cmd)
    row, = overview(setup)
    assert row["model"] == "cEOSLab"
    states = {item["id"]: item["status"] for item in row["reads"]}
    assert states["environment"] == states["poe"] == "empty"
    for field, read_id in (("temperatures", "environment"), ("fans", "environment"), ("power", "environment"),
                           ("poe", "poe")):
        assert {"field": field, "reason": "not_applicable", "read_id": read_id} in row["missing"]
        assert not [entry for entry in row["missing"] if entry["field"] == field and entry["reason"] == "unparsed"]
    # The image has no licence read in the catalogue: the remaining gap is a source limit, not a parse failure.
    assert {entry["reason"] for entry in row["missing"] if entry["reason"] != "not_applicable"} == {"source_limit"}


def test_same_refusals_of_a_hardware_model_stay_unparsed(setup):
    setup.configure(enrolled("hardware", 11, PROFILE, EOS_COMMANDS.values()))
    setup.handlers["192.0.2.11"] = lambda cmd, _: (
        eos_output(cmd).replace("Arista cEOSLab", "Arista DCS-7050SX3-48YC8") if cmd == "show version"
        else live_exit_status(cmd))
    row, = overview(setup)
    assert row["model"] != "cEOSLab"
    reasons = {(entry["field"], entry["reason"]) for entry in row["missing"]}
    assert {("temperatures", "unparsed"), ("poe", "unparsed")} <= reasons
