"""FortiOS network overview adapter through the real HelperBridge, proxy, FastMCP, TargetAuth and engine.

Fakes replace only the transport boundary: the held Fortinet terminal and the pinned HTTPS GET of the
monitor document. Inputs are the anonymised real captures in fixtures/overview_h1 (FortiGate-80F 8.0.2),
the 60F 7.6.8 autoupdate and multi-VDOM captures, and negative copies derived from them (marked derived()).
"""

import copy
from contextlib import contextmanager
import json
from pathlib import Path

import pytest

from netops_helper import engine, wifi_rest
from netops_helper.overview import model
from conftest import HOST_KEY_BLOB, HOST_KEY_PIN
from test_network_overview import device, setup  # noqa: F401  (pytest fixture)
from test_switch_mclag import A as MCLAG_SWITCH, ICL, trunk, trunk_output

FIXTURES = Path(__file__).parent / "fixtures"
CAPTURES = json.loads((FIXTURES / "overview_h1/captures.json").read_text())
AUTOUPDATE_60F = (FIXTURES / "real/fortinet/fortigate60f_7.6.8_autoupdate_204/autoupdate_versions.txt").read_text()
MULTIVDOM = json.loads((FIXTURES / "real/fortinet/fortigate60f_7.6.8_multivdom/status-197.json").read_text())
TRANSCRIPTS_60F = json.loads((FIXTURES / "real/fortinet/fortigate60f_7.6.8_multivdom/transcripts.json").read_text())
ROUTING_60F = json.loads((FIXTURES / "real/fortinet/firewall_routing_20261118/captures.json").read_text())["60f"]
SWITCHES = ("S000SSSS00000003", "S000SSSS00000004")
QUERIES = ("system_status", "performance", "system_interfaces", "interface_list", "ha_status", "hardware_sensors",
           "autoupdate_versions", "managed_switch_port_stats", "interface_details")
PATHS = {wifi_rest.SWITCH_STATUS: "switch_status", wifi_rest.SWITCH_HEALTH: "switch_health",
         wifi_rest.MONITOR + "managed_ap": "managed_ap", wifi_rest.MONITOR + "ap_status": "ap_status"}


def capture(query, scenario):
    return CAPTURES[f"fortinet/{query}/{scenario}"]


def derived(value):
    """A negative copy of a real capture; every test mutates only the copy."""
    return copy.deepcopy(value)


def commands():
    answers = {
        "get system status": capture("system_status", "80f_ha_primary"),
        "get system performance status": capture("performance", "80f"),
        "get system interface": capture("system_interfaces", "80f"),
        "diagnose netlink interface list": capture("interface_list", "80f"),
        "get system ha status": capture("ha_status", "80f_active_passive"),
        "execute sensor detail": capture("hardware_sensors", "80f_psu1_absent"),
        "diagnose autoupdate versions": capture("autoupdate_versions", "80f"),
        "diagnose netlink interface list wan1": capture("interface_details", "80f_wan1"),
        f"diagnose switch-controller switch-info port-stats {SWITCHES[0]}": capture("managed_switch_port_stats", "switch1_full"),
        f"diagnose switch-controller switch-info port-stats {SWITCHES[1]}": capture("managed_switch_port_stats", "switch2_full"),
    }
    return answers


def documents():
    return {name: capture(name, "80f_live") for name in PATHS.values()}


def controller(*, enabled=QUERIES, rest=True, requests=60, read_inventory=None):
    # The per-call plan stays capped at 30 reads; the wider window (inventory maximum) allows a second call.
    entry = device("controller", 21, enabled=enabled, types=("firewall",), requests=requests)
    entry.update(platform="fortios", host_key_fingerprint=HOST_KEY_PIN, host_key="ssh-ed25519 " + HOST_KEY_BLOB)
    section = entry["helper"]
    section.update(ssh_platform="fortios", fortios_output_standard_verified=True, account_role="admin-bounded",
                   role_boundary="catalogue",
                   read_inventory=read_inventory or {"managed_switches": list(SWITCHES), "interfaces": ["wan1"]})
    if rest:
        section.update(fortios_rest_credential="controller-monitor", fortios_rest_certificate_sha256="c" * 64)
        section["egress"]["tcp_ports"].append(443)
    return entry


class Device:
    """The held terminal and the HTTPS monitor of one FortiGate; records every connection, command and GET."""

    def __init__(self, monkeypatch, answers=None, monitors=None, *, lose_after=None, rest_error=None):
        self.answers = commands() if answers is None else answers
        self.monitors = documents() if monitors is None else monitors
        self.events = []
        self.lose_after = lose_after
        self.rest_error = rest_error
        test = self

        class Terminal:
            _closed = False
            # The verified prompt of the held session; the diagnostic shell (MCLAG reads) sends and expects.
            _last_prompt = b"FortiGate-80F #"

            def answer(self, command):
                command = " ".join(command.split())
                test.events.append(command)
                if test.lose_after is not None and len(test.commands) > test.lose_after:
                    self._closed = True
                    raise engine.core_session.SessionError("terminal lost", code="disconnected")
                if command not in test.answers:
                    raise AssertionError(f"unexpected command {command!r}")
                return test.answers[command]

            def run(self, command, **options):
                assert 0 < options["timeout_seconds"] <= model.READ_SECONDS
                return engine.core_session.FortinetResult(0, self.answer(command).encode(), "", "", "")

            def send(self, command):
                self.pending = command

            def expect(self, patterns, timeout):
                assert 0 < timeout <= model.READ_SECONDS and patterns == [self._last_prompt + b" "]
                text = self.answer(self.pending)
                return 0, f"{self.pending}\n{text}".encode() + patterns[0]

            def close(self):
                self._closed = True

        @contextmanager
        def session(*args, **kwargs):
            self.events.append("connect")
            try:
                yield Terminal()
            finally:
                self.events.append("close")

        def get(auth, path, *, budget_seconds):
            assert 0 < budget_seconds <= model.READ_SECONDS
            self.events.append("GET " + PATHS[path])
            error = self.rest_error.get(PATHS[path]) if isinstance(self.rest_error, dict) else self.rest_error
            if error is not None:
                raise error
            return copy.deepcopy(self.monitors[PATHS[path]])

        monkeypatch.setattr(engine.core_session, "fortinet_session", session)
        monkeypatch.setattr(wifi_rest, "get", get)

    @property
    def commands(self):
        return [event for event in self.events if event not in ("connect", "close") and not event.startswith("GET")]

    @property
    def gets(self):
        return [event for event in self.events if event.startswith("GET")]


def overview(setup, monkeypatch, *, entry=None, peers=(), rest=True, **options):
    credentials = {"controller-monitor": {"kind": "api-token", "value": "synthetic-monitor-material"}} if rest else {}
    setup.configure(entry or controller(rest=rest), *peers, extra_credentials=credentials)
    fake = Device(monkeypatch, **options)
    result = setup.call({})
    assert not result["isError"], result
    structured = result["structuredContent"]
    assert json.loads(result["content"][0]["text"]) == structured
    rows = {row["target"]: row for row in structured["devices"]}
    return rows, fake, structured


def missing(row, field):
    return {entry["reason"] for entry in row["missing"] if entry["field"] == field}


def read(row, read_id):
    return next(item for item in row["reads"] if item["id"] == read_id)


def test_controller_switches_and_access_points_from_real_captures(setup, monkeypatch):
    rows, fake, _ = overview(setup, monkeypatch)
    row = rows["controller"]
    assert fake.events.count("connect") == 1 and fake.events[-1] == "close"
    assert fake.gets == ["GET switch_status", "GET switch_health", "GET managed_ap", "GET ap_status"]
    assert len(fake.commands) == 10
    assert row["reachability"] == "reachable"
    assert (row["model"], row["version"]) == ("FortiGate-80F", "8.0.2 build0251")
    assert row["firmware_support"]["status"] == "tested"
    assert row["uptime_seconds"] == ((2 * 24 + 11) * 60 + 13) * 60
    assert row["cpu"] == {"used_pct": 4, "sample_seconds": None}
    assert row["memory"] == {"used_pct": 62.7, "total_bytes": 3843548 * 1024, "used_bytes": 2408420 * 1024}
    assert row["redundancy"] == [{"kind": "ha", "state": "ok", "role": "primary", "members": 2,
                                  "read_ids": ["system_status", "ha_status"]}]
    assert row["power"] == [{"name": "PSU [2]", "state": "ok", "read_ids": ["hardware_sensors"]}]
    assert [(item["name"], item["state"], item["celsius"]) for item in row["temperatures"]] == [
        ("CPU ON-DIE Temperature", "ok", 68.6), ("MV1548 Temperature", "ok", 87.0), ("MV1680 Temperature", "ok", 65.0)]
    dated = [item for item in row["fortiguard"] if item["expires_on"]]
    assert len(dated) == 36 and {item["expires_on"] for item in dated} == {"2027-09-25"}
    assert {item["state"] for item in dated} == {model.expiry_state("2027-09-25")}
    assert [item["state"] for item in row["fortiguard"] if not item["expires_on"]] == ["unknown"] * 3
    assert [item["name"] for item in row["interfaces"]["admin_up_down"]] == ["internal", "internal1", "internal2", "internal3"]
    assert row["interfaces"]["scope"] == "enrolled_interfaces" and row["interfaces"]["with_errors"] == []
    assert missing(row, "interfaces.with_errors") == {"source_limit"}
    switches = [child for child in row["managed"] if child["kind"] == "fortiswitch"]
    aps = [child for child in row["managed"] if child["kind"] == "fortiap"]
    assert [child["id"] for child in switches] == list(SWITCHES)
    # The health document is joined by serial; every value survives the redaction of the monitor document.
    assert [(child["model"], child["version"], child["uptime_seconds"], child["reported_state"]) for child in switches] == [
        ("S224EP", "8.0.1 build0069", 213120, "connected"), ("S224EP", "8.0.1 build0069", 213060, "connected")]
    assert switches[1]["poe"] == {"budget_w": 180.0, "used_w": 8.1, "available_w": 171.9}
    assert switches[0]["fans"] == [{"name": "fan1", "state": "ok", "read_ids": ["switch_health"]}]
    assert switches[0]["power"] == [{"name": "PSU1", "state": "ok", "read_ids": ["switch_health"]}]
    assert switches[0]["interfaces"]["admin_up_down"] and switches[0]["interfaces"]["with_errors"] == []
    assert [child["id"] for child in aps] == sorted(child["id"] for child in aps)
    assert sorted((child["model"], child["reported_state"]) for child in aps) == [
        ("FP231K", "connected"), ("FP23JK", "disconnected"), ("FP244K", "disconnected")]
    online, = [child for child in aps if child["reported_state"] == "connected"]
    offline = next(child for child in aps if child["reported_state"] == "disconnected")
    assert online["cpu"] == {"used_pct": 8, "sample_seconds": None} and online["uptime_seconds"] > 0
    assert online["memory"]["used_pct"] == round(100 * (1937472 - 1569956) / 1937472, 1)
    assert online["temperatures"] == [{"name": "sensor1", "state": "unknown", "celsius": 50, "read_ids": ["managed_ap"]}]
    index = row["managed"].index(offline)
    assert missing(row, f"managed[{index}].cpu") == {"unreachable"} and offline["cpu"] is None
    assert row["status"] == "partial"
    assert {item["code"] for item in row["findings"]} >= {"admin_up_link_down"}
    assert "synthetic-monitor-material" not in json.dumps(row)


def test_standalone_contract_dates_and_not_applicable_capabilities(setup, monkeypatch):
    answers = commands()
    # derived(): the 80F status with the standalone HA line of the measured 60F status.
    answers["get system status"] = derived(answers["get system status"]).replace(
        "Current HA mode: a-p, primary", "Current HA mode: standalone")
    answers["diagnose autoupdate versions"] = AUTOUPDATE_60F
    rows, fake, _ = overview(setup, monkeypatch, answers=answers)
    row = rows["controller"]
    assert row["redundancy"] == [{"kind": "ha", "state": "standalone", "read_ids": ["system_status"]}]
    assert row["fans"] is None and missing(row, "fans") == {"not_applicable"}
    assert row["licenses"] is None and missing(row, "licenses") == {"not_applicable"}
    assert row["poe"] is None and missing(row, "poe") == {"not_applicable"}
    contracts = {item["name"]: item for item in row["fortiguard"]}
    assert len(contracts) == 29 and "Modem List" not in contracts and "FDS Address" not in contracts
    assert contracts["AV Engine"]["expires_on"] == "2026-11-11"
    assert contracts["AV Engine"]["state"] == model.expiry_state("2026-11-11")
    assert contracts["IoT Detect Definitions"] == {"name": "IoT Detect Definitions", "state": "unknown",
                                                   "expires_on": None, "read_ids": ["autoupdate_versions"]}
    expired = [item for item in row["findings"] if item["code"] == "fortiguard_expired"]
    assert all(item["severity"] == "critical" and item["read_ids"] == ["autoupdate_versions"] for item in expired)
    assert len(expired) == (20 if model.expiry_state("2026-11-11") == "expired" else 0)


def test_ambiguous_health_row_is_not_joined(setup, monkeypatch):
    monitors = documents()
    health = derived(monitors["switch_health"])
    health["results"].append(derived(health["results"][0]))
    monitors["switch_health"] = health
    rows, _, _ = overview(setup, monkeypatch, monitors=monitors)
    row = rows["controller"]
    first = row["managed"][0]
    assert first["id"] == SWITCHES[0] and first["uptime_seconds"] is None and first["cpu"] is None
    assert missing(row, "managed[0].cpu") == {"unparsed"}
    assert read(row, "switch_health")["status"] == "incomplete"
    assert row["managed"][1]["uptime_seconds"] == 213060  # the unambiguous row is still joined


def test_rest_permission_denied_keeps_ssh_facts_and_enrolled_switches(setup, monkeypatch):
    answers = commands()
    answers["get system ha status"] = "command parse error before 'ha'\nCommand fail. Return code -61\n"
    error = wifi_rest.RestError("authorization_failed", "HTTP 403", http_status=403)
    rows, fake, _ = overview(setup, monkeypatch, answers=answers, rest_error=error)
    row = rows["controller"]
    assert len(fake.gets) == 4 and fake.events.count("connect") == 1
    assert missing(row, "managed") == {"permission_denied"}
    assert read(row, "ha_status")["status"] == "incomplete" and row["redundancy"] is None
    assert row["version"] == "8.0.2 build0251" and row["cpu"]["used_pct"] == 4
    assert [child["id"] for child in row["managed"]] == list(SWITCHES)
    assert all(child["interfaces"]["admin_up_down"] is not None for child in row["managed"])
    assert row["status"] == "partial"


def test_lost_terminal_ends_the_plan_without_reconnect(setup, monkeypatch):
    rows, fake, _ = overview(setup, monkeypatch, lose_after=2)
    row = rows["controller"]
    assert fake.events.count("connect") == 1
    assert fake.commands == ["get system status", "get system performance status", "get system interface"]
    assert row["version"] == "8.0.2 build0251" and row["cpu"]["used_pct"] == 4
    later = [item for item in row["reads"] if item["id"] not in ("system_status", "performance", "system_interfaces")
             and item["source"]["transport"] == "ssh"]
    assert later and {item["status"] for item in later} == {"not_run"}
    assert row["status"] == "partial"


def test_interrupted_port_listing_is_unparsed(setup, monkeypatch):
    answers = commands()
    key = f"diagnose switch-controller switch-info port-stats {SWITCHES[0]}"
    text = answers[key]
    cut = text.index("input  :", text.index("Port(port2)"))
    answers[key] = derived(text)[:cut]  # derived(): output ends inside the port2 block
    rows, _, _ = overview(setup, monkeypatch, answers=answers)
    row = rows["controller"]
    assert read(row, f"managed_switch_port_stats:{SWITCHES[0]}")["status"] == "incomplete"
    assert row["managed"][0]["interfaces"]["admin_up_down"] is None
    assert missing(row, "managed[0].interfaces") == {"unparsed"}
    assert row["managed"][1]["interfaces"]["admin_up_down"] is not None


def test_access_point_summary_disagreement_is_incomplete(setup, monkeypatch):
    monitors = documents()
    summary = derived(monitors["ap_status"])
    summary["results"]["wtp_active"] += 1
    monitors["ap_status"] = summary
    rows, _, _ = overview(setup, monkeypatch, monitors=monitors)
    row = rows["controller"]
    assert read(row, "managed_ap")["status"] == "incomplete" and read(row, "ap_status")["status"] == "incomplete"
    assert "unparsed" in missing(row, "managed")
    assert row["status"] == "partial"


def test_budget_shortage_keeps_the_priority_prefix(setup, monkeypatch):
    rows, fake, _ = overview(setup, monkeypatch, entry=controller(requests=4))
    row = rows["controller"]
    assert fake.commands == ["get system status", "get system performance status", "get system interface",
                             "diagnose netlink interface list"]
    assert fake.gets == []
    skipped = [item for item in row["reads"] if item["status"] == "not_run"]
    assert {entry["reason"] for entry in row["missing"] if entry.get("read_id") in {item["id"] for item in skipped}} \
        == {"read_limit"}
    assert row["cpu"]["used_pct"] == 4 and row["interfaces"]["admin_up_down"]


def test_refused_envelope_and_refused_vdom_keep_other_targets(setup, monkeypatch):
    monitors = documents()
    envelope = derived(monitors["switch_status"])
    envelope["vdom"] = "vd1"
    monitors["switch_status"] = envelope
    rows, _, _ = overview(setup, monkeypatch, monitors=monitors, peers=(device("peer", 22),))
    assert missing(rows["controller"], "managed") >= {"unparsed"}
    assert rows["controller"]["managed"][0]["reported_state"] is None
    assert rows["peer"]["status"] == "complete"

    transcript = MULTIVDOM["197-21-A-noctx-status-one-vdom"]
    status = transcript.split("# get system status\n", 1)[1].rsplit("\n\nFortiGate-60F # ", 1)[0] + "\n"
    answers = commands()
    answers["get system status"] = status
    rows, fake, _ = overview(setup, monkeypatch, answers=answers, peers=(device("peer", 22),))
    refused = rows["controller"]
    assert fake.commands == ["get system status"]
    assert {entry["reason"] for entry in refused["missing"] if entry.get("read_id") not in (None, "system_status")
            and entry["read_id"].split(":")[0] in QUERIES} == {"policy_scope"}
    assert rows["peer"]["status"] == "complete"


def test_without_rest_the_enrolled_children_come_from_permitted_cli_reads(setup, monkeypatch):
    answers = commands()
    status, poe = capture("managed_switch_status", "switch1"), capture("managed_switch_poe", "switch1")
    for serial in SWITCHES:
        # derived(): the second switch answers with the first switch's capture under its own serial.
        answers[f"diagnose switch-controller switch-info status {serial}"] = derived(status).replace(SWITCHES[0], serial)
        answers[f"diagnose switch-controller switch-info poe summary {serial}"] = derived(poe).replace(SWITCHES[0], serial)
    answers["get wireless-controller wtp-status"] = capture("wifi_ap_status", "80f_three_aps")
    entry = controller(rest=False, enabled=(*QUERIES, "managed_switch_status", "managed_switch_poe", "wifi_ap_status"))
    rows, fake, _ = overview(setup, monkeypatch, entry=entry, rest=False, answers=answers)
    row = rows["controller"]
    assert fake.gets == [] and fake.events.count("connect") == 1
    assert missing(row, "managed") == {"rest_unavailable"}
    switches = [child for child in row["managed"] if child["kind"] == "fortiswitch"]
    aps = [child for child in row["managed"] if child["kind"] == "fortiap"]
    assert [(child["id"], child["model"], child["version"]) for child in switches] == [
        (serial, "FortiSwitch-224E-POE", "8.0.1 build0069") for serial in SWITCHES]
    assert switches[0]["poe"] == {"budget_w": 180.0, "used_w": 0.0, "available_w": 180.0}
    assert switches[0]["reported_state"] is None and missing(row, "managed[0].reported_state") == {"source_limit"}
    assert switches[0]["interfaces"]["admin_up_down"] is not None
    assert sorted((child["model"], child["version"], child["reported_state"]) for child in aps) == [
        ("FP231K", "8.0.1 build0085", "connected"), ("FP23JK", "8.0.1 build0085", "disconnected"),
        ("FP244K", "8.0.1 build0085", "disconnected")]
    assert row["version"] == "8.0.2 build0251" and row["status"] == "partial"


def transcript_answer(text, command):
    """One command's answer from a recorded 60F session transcript (prompt lines removed)."""
    start = text.index(f"# {command}\n") + len(f"# {command}\n")
    return text[start:text.index("\n\nFortiGate-60F", start)] + "\n"


def test_admin_up_interface_missing_from_the_link_listing_is_reduced_coverage(setup, monkeypatch):
    # 60F 7.6.8: `get system interface` lists the hard switch `internal`, the aggregate `fortilink` and the
    # NPU links; `get system interface physical` has no row for them.
    answers = commands()
    answers["get system interface"] = transcript_answer(TRANSCRIPTS_60F["94-A-extra"], "get system interface")
    answers["get system interface physical"] = ROUTING_60F["physical_interfaces"]
    enabled = tuple(query for query in QUERIES if query != "interface_list") + ("physical_interfaces",)
    rows, fake, _ = overview(setup, monkeypatch, entry=controller(enabled=enabled), answers=answers)
    row = rows["controller"]
    assert "get system interface physical" in fake.commands
    assert [item["name"] for item in row["interfaces"]["admin_up_down"]] == [
        "b", "dmz", "internal1", "internal2", "internal3", "internal4", "internal5"]
    uncovered = [entry for entry in row["missing"] if entry["field"] == "interfaces.admin_up_down"]
    assert uncovered == [{"field": "interfaces.admin_up_down", "reason": "source_limit", "read_id": "link_state",
                          "omitted_count": 4}]
    assert row["status"] == "partial"

    # derived(): the 80F netlink listing without the block of the admin-up hard switch `internal`.
    answers = commands()
    listing = derived(answers["diagnose netlink interface list"])
    start = listing.index("if=internal ")
    end = listing.index("\nif=", start) + 1
    answers["diagnose netlink interface list"] = listing[:start] + listing[end:]
    rows, _, _ = overview(setup, monkeypatch, answers=answers)
    row = rows["controller"]
    assert "internal" not in [item["name"] for item in row["interfaces"]["admin_up_down"]]
    assert [entry.get("omitted_count") for entry in row["missing"]
            if entry["field"] == "interfaces.admin_up_down"] == [1]

    rows, _, _ = overview(setup, monkeypatch)  # the complete 80F listing covers every admin-up interface
    assert not [entry for entry in rows["controller"]["missing"] if entry["field"] == "interfaces.admin_up_down"]


def cli_children(answers):
    status, poe = capture("managed_switch_status", "switch1"), capture("managed_switch_poe", "switch1")
    for serial in SWITCHES:
        # derived(): the second switch answers with the first switch's capture under its own serial.
        answers[f"diagnose switch-controller switch-info status {serial}"] = derived(status).replace(SWITCHES[0], serial)
        answers[f"diagnose switch-controller switch-info poe summary {serial}"] = derived(poe).replace(SWITCHES[0], serial)
    answers["get wireless-controller wtp-status"] = capture("wifi_ap_status", "80f_three_aps")
    return answers


CLI_CHILD_QUERIES = ("managed_switch_status", "managed_switch_poe", "wifi_ap_status")


def test_refused_monitors_keep_what_the_permitted_cli_reads_show(setup, monkeypatch):
    error = wifi_rest.RestError("authorization_failed", "HTTP 403", http_status=403)
    entry = controller(enabled=(*QUERIES, *CLI_CHILD_QUERIES))
    rows, fake, _ = overview(setup, monkeypatch, entry=entry, answers=cli_children(commands()), rest_error=error)
    row = rows["controller"]
    assert len(fake.gets) == 4 and fake.events.count("connect") == 1
    assert "get wireless-controller wtp-status" in fake.commands
    assert missing(row, "managed") == {"permission_denied"}
    switches = [child for child in row["managed"] if child["kind"] == "fortiswitch"]
    aps = [child for child in row["managed"] if child["kind"] == "fortiap"]
    assert [(child["id"], child["model"], child["version"]) for child in switches] == [
        (serial, "FortiSwitch-224E-POE", "8.0.1 build0069") for serial in SWITCHES]
    assert all(child["poe"] == {"budget_w": 180.0, "used_w": 0.0, "available_w": 180.0} for child in switches)
    assert missing(row, "managed[0].reported_state") == {"permission_denied"}
    assert sorted((child["model"], child["reported_state"]) for child in aps) == [
        ("FP231K", "connected"), ("FP23JK", "disconnected"), ("FP244K", "disconnected")]


def test_one_refused_monitor_is_replaced_by_its_permitted_cli_read(setup, monkeypatch):
    error = wifi_rest.RestError("authorization_failed", "HTTP 403", http_status=403)
    # Only the health monitor refused: the switch rows stay REST, the PoE budget comes from the CLI read.
    rows, _, _ = overview(setup, monkeypatch, entry=controller(enabled=(*QUERIES, *CLI_CHILD_QUERIES)),
                          answers=cli_children(commands()), rest_error={"switch_health": error})
    row = rows["controller"]
    first = row["managed"][0]
    assert (first["id"], first["model"], first["reported_state"]) == (SWITCHES[0], "S224EP", "connected")
    assert first["poe"] == {"budget_w": 180.0, "used_w": 0.0, "available_w": 180.0}
    assert missing(row, "managed[0].poe") == set() and missing(row, "managed[0].cpu") == {"permission_denied"}

    # Only the access point list refused: the access points come from `wifi_ap_status`.
    rows, _, _ = overview(setup, monkeypatch, entry=controller(enabled=(*QUERIES, *CLI_CHILD_QUERIES)),
                          answers=cli_children(commands()), rest_error={"managed_ap": error})
    aps = [child for child in rows["controller"]["managed"] if child["kind"] == "fortiap"]
    assert sorted((child["model"], child["version"], child["reported_state"]) for child in aps) == [
        ("FP231K", "8.0.1 build0085", "connected"), ("FP23JK", "8.0.1 build0085", "disconnected"),
        ("FP244K", "8.0.1 build0085", "disconnected")]


ICL_TRUNK = "_FlInK1_ICL0_"
MCLAG_QUERIES = ("managed_switch_stacking", "switch_mclag_icl", "switch_trunk_status")


def mclag_answers(trunk_state, members):
    answers = commands()
    serial = SWITCHES[0]
    answers[f"diagnose switch-controller switch-info stacking status {serial}"] = capture(
        "managed_switch_stacking", "switch1_refused")
    answers[f"diagnose switch-controller switch-info mclag icl {serial}"] = ICL.replace(MCLAG_SWITCH, serial)
    answers[f"diagnose switch-controller switch-info trunk status {serial} {ICL_TRUNK}"] = trunk_output(
        trunk(ICL_TRUNK, "auto-isl,mclag-icl", trunk_state, members)).replace(MCLAG_SWITCH, serial)
    return answers


def test_switch_mclag_state_from_the_enrolled_icl_trunk(setup, monkeypatch):
    inventory = {"managed_switches": [SWITCHES[0]], "interfaces": ["wan1"], "managed_switch_trunks": [ICL_TRUNK]}
    entry = controller(enabled=(*QUERIES, *MCLAG_QUERIES), read_inventory=inventory)
    answers = mclag_answers("down", [("port23", "down"), ("port24", "down")])
    rows, fake, _ = overview(setup, monkeypatch, entry=entry, answers=answers)
    row = rows["controller"]
    serial = SWITCHES[0]
    assert fake.commands[-3:] == [f"diagnose switch-controller switch-info stacking status {serial}",
                                  f"diagnose switch-controller switch-info mclag icl {serial}",
                                  f"diagnose switch-controller switch-info trunk status {serial} {ICL_TRUNK}"]
    child = row["managed"][0]
    trunk_read = f"switch_trunk_status:{serial}:{ICL_TRUNK}"
    assert child["redundancy"] == [{"kind": "mlag", "state": "degraded",
                                    "read_ids": [f"switch_mclag_icl:{serial}", trunk_read]}]
    degraded = [item for item in row["findings"] if item["code"] == "redundancy_degraded"]
    assert degraded == [{"code": "redundancy_degraded", "severity": "critical", "field": "managed[0].redundancy",
                         "read_ids": [f"switch_mclag_icl:{serial}", trunk_read], "subject": "mlag"}]
    # The refused stacking read is reported with its own read and reason, not as an unread source_limit.
    stacking = f"managed_switch_stacking:{serial}"
    assert read(row, stacking)["status"] == "incomplete"
    assert {(entry["reason"], entry.get("read_id")) for entry in row["missing"]
            if entry["field"] == "managed[0].redundancy"} == {("unparsed", stacking)}

    answers = mclag_answers("up", [("port24", "up"), ("port23", "up")])
    rows, _, _ = overview(setup, monkeypatch, entry=entry, answers=answers)
    row = rows["controller"]
    assert row["managed"][0]["redundancy"][0]["state"] == "ok"
    assert not [item for item in row["findings"] if item["code"] == "redundancy_degraded"]


NINE_INTERFACES = ("wan1", "wan2", "internal1", "internal2", "internal3", "internal4", "internal5", "a", "b")


def test_enrolled_objects_beyond_the_detail_cap_are_counted(setup, monkeypatch):
    answers = commands()
    for name in NINE_INTERFACES[:8]:
        # derived(): the zero-error 80F wan1 detail under each enrolled name.
        answers[f"diagnose netlink interface list {name}"] = derived(capture("interface_details", "80f_wan1"))
    # derived(): the 60F 7.6.8 wan1 detail with a non-zero receive error counter, for the ninth interface only.
    answers["diagnose netlink interface list b"] = derived(ROUTING_60F["interface_details_wan1"]).replace(
        "rxe=0 ", "rxe=7 ").replace("if=wan1 ", "if=b ")
    inventory = {"managed_switches": list(SWITCHES), "interfaces": list(NINE_INTERFACES)}
    rows, fake, _ = overview(setup, monkeypatch, entry=controller(read_inventory=inventory), answers=answers)
    row = rows["controller"]
    assert row["interfaces"]["scope"] == "enrolled_interfaces"
    assert {entry.get("omitted_count") for entry in row["missing"] if entry["field"] == "interfaces.with_errors"} \
        == {None, 1}
    assert "diagnose netlink interface list b" not in fake.commands

    rows, _, _ = overview(setup, monkeypatch, entry=controller(read_inventory={**inventory, "interfaces":
                                                                                list(NINE_INTERFACES[:8])}),
                          answers=answers)
    assert {entry.get("omitted_count") for entry in rows["controller"]["missing"]
            if entry["field"] == "interfaces.with_errors"} == {None}


def test_enrolled_switch_beyond_the_detail_cap_is_counted(setup, monkeypatch):
    # Nine enrolled switches without REST: the ninth has no read of its own and is counted.
    serials = [f"S000SSSS0000001{index}" for index in range(9)]
    answers = commands()
    for serial in serials[:8]:
        answers[f"diagnose switch-controller switch-info port-stats {serial}"] = derived(
            capture("managed_switch_port_stats", "switch1_full"))
    entry = controller(rest=False, read_inventory={"managed_switches": serials, "interfaces": ["wan1"]})
    rows, fake, _ = overview(setup, monkeypatch, entry=entry, rest=False, answers=answers)
    row = rows["controller"]
    assert [entry["omitted_count"] for entry in row["missing"]
            if entry["field"] == "managed" and entry["reason"] == "source_limit"] == [1]
    assert [child["id"] for child in row["managed"] if child["kind"] == "fortiswitch"] == serials[:8]


def test_duplicate_switch_status_serial_is_not_joined_in_either_order(setup, monkeypatch):
    results = []
    for order in (slice(None), slice(None, None, -1)):
        monitors = documents()
        status = derived(monitors["switch_status"])
        twin = derived(status["results"][0])
        twin["status"] = "Disconnected"
        rows_in = [status["results"][0], twin][order]
        status["results"] = [*rows_in, *status["results"][1:]]
        monitors["switch_status"] = status
        rows, _, _ = overview(setup, monkeypatch, monitors=monitors)
        row = rows["controller"]
        first = row["managed"][0]
        assert first["id"] == SWITCHES[0]
        assert (first["reported_state"], first["uptime_seconds"], first["cpu"], first["model"]) == (None, None, None, None)
        assert missing(row, "managed[0].reported_state") == {"unparsed"}
        assert read(row, "switch_status")["status"] == "incomplete"
        assert row["managed"][1]["uptime_seconds"] == 213060  # the unambiguous switch is still joined
        results.append(first)
    assert results[0] == results[1]


REAL_REST_GET = wifi_rest.get
MONITOR_TOKEN = "synthetic-monitor-material"


class MonitorEndpoint:
    """Fake HTTPS transport: a loopback TLS listener serving the real 80F monitor captures.

    `wifi_rest.get` runs unchanged (DNS-free IPv4, egress, limiter, TLS handshake, certificate pin,
    bearer header, body bounds and JSON checks); only the TCP connect to the enrolled address is
    redirected to this listener.
    """

    def __init__(self, monkeypatch, directory, documents, *, close_after_response=False):
        import socket
        import ssl
        import threading
        from datetime import datetime, timedelta, timezone
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "FGT80F fixture")])
        now = datetime.now(timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                       .public_key(key.public_key()).serial_number(x509.random_serial_number())
                       .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=10))
                       .sign(key, hashes.SHA256()))
        der = certificate.public_bytes(serialization.Encoding.DER)
        self.pin = __import__("hashlib").sha256(der).hexdigest()
        (directory / "monitor.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        (directory / "monitor.key").write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(directory / "monitor.pem"), str(directory / "monitor.key"))
        self.documents = documents
        self.requests = []
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        port = self.listener.getsockname()[1]
        connect = socket.create_connection

        def redirected(address, *args, **kwargs):
            if address == ("192.0.2.21", 443):
                return connect(("127.0.0.1", port), *args, **kwargs)
            return connect(address, *args, **kwargs)

        def serve():
            while True:
                try:
                    raw, _ = self.listener.accept()
                except OSError:
                    return
                raw.settimeout(5)
                try:
                    with context.wrap_socket(raw, server_side=True) as peer:
                        head = b""
                        while b"\r\n\r\n" not in head:
                            chunk = peer.recv(4096)
                            if not chunk:
                                break
                            head += chunk
                        if not head:
                            continue
                        lines = head.decode("latin-1").split("\r\n")
                        method, path, _ = lines[0].split(" ")
                        headers = dict(line.split(": ", 1) for line in lines[1:] if ": " in line)
                        self.requests.append((method, PATHS[path], headers.get("Authorization")))
                        body = json.dumps(self.documents[PATHS[path]]).encode()
                        connection_header = b"Connection: close\r\n" if close_after_response else b""
                        peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                                     + str(len(body)).encode() + b"\r\n" + connection_header + b"\r\n" + body)
                        if not close_after_response:
                            # For a persistent HTTP/1.1 answer, the client closes first.
                            while peer.recv(4096):
                                pass
                except (OSError, ssl.SSLError, ValueError, KeyError):
                    pass

        threading.Thread(target=serve, daemon=True).start()
        monkeypatch.setattr(wifi_rest.socket, "create_connection", redirected)
        monkeypatch.setattr(wifi_rest, "_rates", {})

    def close(self):
        self.listener.close()


@pytest.mark.parametrize("scenario", ["verified", "connection_close", "pin_mismatch", "limiter", "envelope"])
def test_monitor_documents_through_the_real_pinned_rest_client(setup, monkeypatch, tmp_path, scenario):
    """The overview drives the real wifi_rest client against a fake HTTPS peer."""
    monitors = documents()
    if scenario == "envelope":
        monitors["switch_health"] = dict(derived(monitors["switch_health"]), vdom="vdom1")
    endpoint = MonitorEndpoint(monkeypatch, tmp_path, monitors, close_after_response=scenario == "connection_close")
    try:
        entry = controller()
        entry["helper"]["fortios_rest_certificate_sha256"] = "0" * 64 if scenario == "pin_mismatch" else endpoint.pin
        setup.configure(entry, extra_credentials={
            "controller-monitor": {"kind": "api-token", "value": MONITOR_TOKEN}})
        fake = Device(monkeypatch)
        monkeypatch.setattr(wifi_rest, "get", REAL_REST_GET)
        if scenario == "limiter":
            # Earlier REST tool calls on this target leave two requests in the REST window.
            import time as clock
            from collections import deque
            wifi_rest._rates[("controller", "192.0.2.21")] = deque([clock.monotonic()] * 58)
        answer = setup.call({})
    finally:
        endpoint.close()
    assert not answer["isError"], answer
    row = answer["structuredContent"]["devices"][0]
    assert fake.gets == [] and fake.events.count("connect") == 1
    assert row["model"] == "FortiGate-80F" and row["reachability"] == "reachable"
    statuses = {name: read(row, name)["status"] for name in PATHS.values()}
    rest_missing = [entry for entry in row["missing"] if entry.get("read_id") in PATHS.values()]
    sent = [path for _, path, _ in endpoint.requests]
    assert all(method == "GET" and bearer == "Bearer " + MONITOR_TOKEN for method, _, bearer in endpoint.requests)
    if scenario in {"verified", "connection_close"}:
        assert sent == ["switch_status", "switch_health", "managed_ap", "ap_status"]
        assert set(statuses.values()) == {"ok"}, rest_missing
        switches = [child for child in row["managed"] if child["kind"] == "fortiswitch"]
        assert [(child["id"], child["model"], child["uptime_seconds"]) for child in switches] == [
            (SWITCHES[0], "S224EP", 213120), (SWITCHES[1], "S224EP", 213060)]
        assert sorted(child["model"] for child in row["managed"] if child["kind"] == "fortiap") == [
            "FP231K", "FP23JK", "FP244K"]
    elif scenario == "pin_mismatch":
        # The TLS handshake happens, but no HTTP byte (and so no bearer) follows a wrong pin.
        assert sent == []
        assert set(statuses.values()) == {"failed"}
        assert {entry["reason"] for entry in row["missing"] if entry.get("read_id") in PATHS.values()} == {
            "host_key_failed"}
    elif scenario == "limiter":
        assert sent == ["switch_status", "switch_health"]
        assert statuses == {"switch_status": "ok", "switch_health": "ok",
                            "managed_ap": "failed", "ap_status": "failed"}, rest_missing
        assert {entry["reason"] for entry in row["missing"]
                if entry.get("read_id") in ("managed_ap", "ap_status")} == {"rate_limited"}
    else:
        assert sent == ["switch_status", "switch_health", "managed_ap", "ap_status"]
        assert statuses["switch_health"] == "incomplete", rest_missing
        assert {entry["reason"] for entry in row["missing"] if entry.get("read_id") == "switch_health"} == {"unparsed"}
    assert MONITOR_TOKEN not in json.dumps(answer)


MEASURED_60F = FIXTURES / "real/fortinet/fortigate60f_7.6.8_overview_20261123"
SWITCH_60F = "S108ENTQ00000001"


def test_switch_without_pse_and_controller_without_aps_are_valid_answers(setup, monkeypatch):
    """FortiGate-60F 7.6.8 answers as measured: the FortiSwitch-108E is not PoE capable, no FortiAP is managed and
    the SFP/internal ports print their address line without `None loopback`. None of it is unparsed."""
    answers = commands()
    # derived(): the switch status of the 80F capture under the 60F switch serial (only version/model are read).
    answers[f"diagnose switch-controller switch-info status {SWITCH_60F}"] = derived(
        capture("managed_switch_status", "switch1")).replace(SWITCHES[0], SWITCH_60F)
    answers[f"diagnose switch-controller switch-info poe summary {SWITCH_60F}"] = (
        MEASURED_60F / "managed_switch_poe.txt").read_text()
    answers["get wireless-controller wtp-status"] = (MEASURED_60F / "wifi_ap_status.txt").read_text()
    answers[f"diagnose switch-controller switch-info port-stats {SWITCH_60F}"] = (
        MEASURED_60F / "managed_switch_port_stats.txt").read_text()
    entry = controller(rest=False, enabled=(*QUERIES, "managed_switch_status", "managed_switch_poe", "wifi_ap_status"),
                       read_inventory={"managed_switches": [SWITCH_60F], "interfaces": ["wan1"]})
    rows, fake, _ = overview(setup, monkeypatch, entry=entry, rest=False, answers=answers)
    row = rows["controller"]
    assert fake.events.count("connect") == 1
    assert read(row, f"managed_switch_poe:{SWITCH_60F}")["status"] == "empty"
    assert read(row, "wifi_ap_status")["status"] == "empty"
    assert read(row, f"managed_switch_port_stats:{SWITCH_60F}")["status"] == "ok"
    child, = row["managed"]
    assert child["kind"] == "fortiswitch" and child["poe"] is None
    assert missing(row, "managed[0].poe") == {"not_applicable"}
    assert len(child["interfaces"]["admin_up_down"]) == 7  # port2, 3, 5, 7-10: admin up, link down
    assert child["interfaces"]["with_errors"] == []
    assert missing(row, "managed[0].interfaces") == set()
    # Only the deliberately missing HTTPS monitors remain: the CLI does not publish the switch's own state.
    assert {entry["reason"] for entry in row["missing"] if entry["field"] == "managed"} <= {
        "rest_unavailable", "not_applicable"}
    assert not [entry for entry in row["missing"] if entry["reason"] == "unparsed"]


def test_other_poe_refusal_and_unknown_address_line_stay_unparsed(setup, monkeypatch):
    answers = commands()
    answers[f"diagnose switch-controller switch-info status {SWITCH_60F}"] = derived(
        capture("managed_switch_status", "switch1")).replace(SWITCHES[0], SWITCH_60F)
    answers[f"diagnose switch-controller switch-info poe summary {SWITCH_60F}"] = (
        "Vdom: root\nswitch:S108ENTQ00000002 is not PoE capable\nCommand fail. Return code -7622\n")
    answers["get wireless-controller wtp-status"] = "WTP: unexpected\n"
    answers[f"diagnose switch-controller switch-info port-stats {SWITCH_60F}"] = derived(
        (MEASURED_60F / "managed_switch_port_stats.txt").read_text()).replace(
        "Address is 00:00:5E:00:53:0B, \n", "Address is 00:00:5E:00:53:0B, remote loopback\n")
    entry = controller(rest=False, enabled=(*QUERIES, "managed_switch_status", "managed_switch_poe", "wifi_ap_status"),
                       read_inventory={"managed_switches": [SWITCH_60F], "interfaces": ["wan1"]})
    rows, _, _ = overview(setup, monkeypatch, entry=entry, rest=False, answers=answers)
    row = rows["controller"]
    assert read(row, f"managed_switch_poe:{SWITCH_60F}")["status"] == "incomplete"
    assert missing(row, "managed[0].poe") == {"unparsed"}
    assert read(row, f"managed_switch_port_stats:{SWITCH_60F}")["status"] == "incomplete"
    assert read(row, "wifi_ap_status")["status"] == "incomplete"
