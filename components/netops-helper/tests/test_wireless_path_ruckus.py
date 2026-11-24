"""WIRELESS-PATH: Ruckus Unleashed Wi-Fi triage (RP02), AP/LAN/VLAN relations (RP09), bounded ping (R02) and the AP's
switch port through locate_endpoint, on real output of R610 on Ruckus Unleashed 200.15.6.212.27 and of home
EXOS 33.7.1.6.

Only the transport is faked: Ruckus reads go through a scripted PTY terminal that answers the Unleashed login
dialogue and then the captured output of the command it was sent; EXOS reads replace `_exec_read` with the
captured output of the command. Parsers, redaction, the triage rules, the wired correlator and the
wireless join are the product code. Fixtures: `fixtures/ruckus_wireless_inventory` (client/AP/WLAN/performance, verification/475)
and `fixtures/ruckus_wireless_path` (one coherent capture of an R610 and two X440G2 switches of 2026-11-18, see PROVENANCE.md).
"""

import dataclasses
from pathlib import Path

import pytest

from conftest import HOST_KEY_PIN, _target
import netops_helper.engine as engine
from netops_helper import wifi_parse
from netops_helper.query_catalog import READ_QUERIES

WIRELESS_INVENTORY = Path(__file__).parent / "fixtures" / "ruckus_wireless_inventory"
WIRELESS_PATH = Path(__file__).parent / "fixtures" / "ruckus_wireless_path"
AP_MAC = "00:00:5e:00:53:02"            # wireless-inventory mapping
CLIENT_MAC = "00:00:5e:00:53:04"
HOME_AP = "00:00:5e:00:53:01"           # wireless-path mapping
HOME_CLIENT, HOME_CLIENT_IP = "00:00:5e:00:53:02", "203.0.113.6"
R610_RELEASE, R610_BUILD = "200.15.6.212.27".rsplit(".", 1)     # firmware of both fixture sets


def unleashed_version(dotted):
    """The `show sysinfo` spelling (`<release> build <build>`) of a five-part Unleashed firmware such as 200.15.6.212.27."""
    release, build = dotted.rsplit(".", 1)
    return f"{release} build {build}"


def text(path):
    """The capture with its echo line (wireless-inventory files keep the blank-line artefact of verification; parsers skip blank lines)."""
    return path.read_text(encoding="utf-8")


def body(path):
    return path.read_text(encoding="utf-8").split("\n", 1)[1]


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch):
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    engine._WTP_SEEN.clear()
    engine._SSH_PAGE_CACHE.clear()
    yield
    engine._WTP_SEEN.clear()
    engine._SSH_PAGE_CACHE.clear()


def unleashed(monkeypatch, answers, sent):
    """Scripted Unleashed PTY: login prompts, `enable`, then the capture of the command sent (KeyError if unknown)."""

    class Terminal:
        def __init__(self, *args, **options):
            self.buffer = [b"Welcome to the Ruckus Unleashed Network Command Line Interface\r\nPlease login: "]
            self.answered = 0

        def expect(self, patterns, timeout):
            return 0, self.buffer.pop(0)

        def discard(self, seen):
            pass

        def send(self, line):
            self.answered += 1
            if self.answered == 1:
                self.buffer.append(b"Password: ")
            elif self.answered == 2:
                self.buffer.append(b"Login success\r\nruckus> ")
            elif self.answered == 3:
                self.buffer.append(b"enable\r\nruckus#")
            else:
                command = line.strip()
                sent.append(command)
                answer = answers[command]
                if isinstance(answer, Exception):
                    raise answer
                self.buffer.append(answer.replace("\n", "\r\n").encode() + b"\r\nruckus#")

        def close(self):
            pass

    monkeypatch.setattr(engine.core_session, "Session", Terminal)


TRIAGE_QUERIES = ("system_info", "client_detail", "clients", "access_point", "wlans", "client_performance",
                  "radio_performance_24", "radio_performance_5", "ethernet_info")


def ruckus_target(*queries, inventory=None, alias="wire-test", host=None):
    auth = _target("ruckus_unleashed", queries[0], legacy_ssh="rsa-sha1", **({"host": host} if host else {}))
    return dataclasses.replace(auth, alias=alias, enabled_queries=tuple(queries), read_inventory=inventory or {})


def triage_answers(**override):
    answers = {
        "show sysinfo": text(WIRELESS_INVENTORY / "show_sysinfo.out"),
        "show current-active-clients mac " + CLIENT_MAC: text(WIRELESS_INVENTORY / "show_current_active_clients_mac_CLIENT.out"),
        "show current-active-clients all": text(WIRELESS_INVENTORY / "show_current_active_clients_all.out"),
        "show ap mac " + AP_MAC: text(WIRELESS_INVENTORY / "show_ap_mac_AP.out"),
        "show wlan all": text(WIRELESS_INVENTORY / "show_wlan_all.out"),
        "show performance station mac " + CLIENT_MAC: text(WIRELESS_INVENTORY / "show_performance_station_mac_CLIENT.out"),
        "show performance ap-radio2-4 mac " + AP_MAC: text(WIRELESS_INVENTORY / "show_performance_ap_radio2_4_mac_AP.out"),
        "show ethinfo": (WIRELESS_PATH / "ruckus-show_ethinfo.out").read_text(),
    }
    answers.update(override)
    return answers


# --- parsers on real output ---------------------------------------------------------------------------------------

def test_ping_reachable_and_unanswered_are_read_from_the_device_totals():
    reachable = wifi_parse.summarize_ruckus("ping", body(WIRELESS_PATH / "ruckus-ping_reachable.out"))
    assert reachable["unparsed"] == [] and reachable["incomplete"] is False and reachable["reachable"] is True
    record = reachable["records"][0]
    assert (record["target"], record["transmitted"], record["received"], record["loss_percent"]) == ("198.51.100.1", 3, 3, 0)
    assert [reply["seq"] for reply in record["replies"]] == [0, 1, 2] and record["rtt_max_ms"] >= record["rtt_min_ms"]
    lost = wifi_parse.summarize_ruckus("ping", body(WIRELESS_PATH / "ruckus-ping_unanswered.out"))
    assert lost["incomplete"] is False and lost["reachable"] is False
    assert (lost["records"][0]["transmitted"], lost["records"][0]["received"], lost["records"][0]["loss_percent"]) == (3, 0, 100)
    assert "not a client data path" in lost["vantage"]


def test_ping_without_the_totals_line_is_incomplete_not_loss():
    cut = body(WIRELESS_PATH / "ruckus-ping_unanswered.out").split("--- ")[0]
    parsed = wifi_parse.summarize_ruckus("ping", cut)
    assert parsed["incomplete"] is True and parsed["reachable"] is None
    noise = wifi_parse.summarize_ruckus("ping", "ping: bad address 'x'\n")
    assert noise["records"] == [] and noise["unparsed_count"] == 1 and noise["incomplete"] is True


def test_ethinfo_ports_and_ap_management_fields_rp09():
    eth = wifi_parse.summarize_ruckus("ethernet_info", body(WIRELESS_PATH / "ruckus-show_ethinfo.out"))
    assert eth["unparsed"] == [] and eth["port_count"] == 2
    assert [(p["port"], p["interface"], p["physical_link"], p["speed"]) for p in eth["records"]] == [
        (0, "eth0", "up", "1000Mbps"), (1, "eth1", "down", "1000Mbps")]
    aps = wifi_parse.summarize_ruckus("access_points", body(WIRELESS_PATH / "ruckus-show_ap_all.out"))
    assert aps["unparsed"] == []
    ap = aps["records"][0]
    assert (ap["mac"], ap["ip"], ap["netmask"], ap["gateway"], ap["ip_mode"], ap["protocol_mode"], ap["lldp_status"]) == (
        HOME_AP, "198.51.100.5", "255.255.255.0", "198.51.100.1", "Manual", "IPv4-Only", "Use Parent Setting")
    assert [(p["interface"], p["label"], p["dot1x"], p["logical_link"]) for p in ap["lan_ports"]] == [
        ("eth0", "10/100/1000 PoE Port1", "None", "Up"), ("eth1", "10/100/1000 Port2", "None", "Down")]


# --- R02: the bounded ping through the engine ----------------------------------------------------------------------

def test_ping_renders_only_an_enrolled_ipv4_and_returns_the_parsed_totals(wire, monkeypatch):
    sent = []
    unleashed(monkeypatch, {"ping 198.51.100.1": (WIRELESS_PATH / "ruckus-ping_reachable.out").read_text()}, sent)
    auth = ruckus_target("ping", "system_info", inventory={"addresses": ("198.51.100.1",)})
    result = engine.ssh_read(auth, "ruckus_unleashed", "ping", {"address": "198.51.100.1"}, 0, 48_000)
    assert result["ok"] is True, result
    assert sent == ["ping 198.51.100.1", "show sysinfo"]
    assert result["wifi"]["reachable"] is True and result["wifi"]["complete"] is True
    for bad in ("198.51.100.2", "ruckuswireless.com", "198.51.100.1 -s 65000", "2001:db8::1"):
        with pytest.raises(Exception):
            engine.ssh_read(auth, "ruckus_unleashed", "ping", {"address": bad}, 0, 48_000)
    assert sent == ["ping 198.51.100.1", "show sysinfo"]


# --- RP02 / RP09: wifi_triage on Ruckus ----------------------------------------------------------------------------

def test_triage_by_mac_follows_client_ap_wlan_rf_and_relations(wire, monkeypatch):
    sent = []
    unleashed(monkeypatch, triage_answers(), sent)
    result = engine.triage_wifi(ruckus_target(*TRIAGE_QUERIES), mac=CLIENT_MAC)
    assert result["ok"] is True, result
    assert sent == ["show sysinfo", "show current-active-clients mac " + CLIENT_MAC, "show ap mac " + AP_MAC,
                    "show wlan all", "show performance station mac " + CLIENT_MAC,
                    "show performance ap-radio2-4 mac " + AP_MAC, "show ethinfo"]
    assert result["identity"] == {"product": "r610", "version": R610_RELEASE, "build": R610_BUILD}
    assert result["firmware_support"]["status"] == "tested" and "warnings" not in result
    assert result["verdict"] == "no_fault_observed" and result["findings"] == []
    assert [m["step"] for m in result["missing"]] == ["ap_switch_port"]
    assert (result["client"]["status"], result["client"]["ip"], result["client"]["auth_method"]) == (
        "Authorized", "198.51.100.6", "Open")
    chain = result["chain"]
    assert chain["association"]["status"] == "associated"
    assert (chain["observation"]["wlan"], chain["observation"]["vlan_id"], chain["observation"]["channel"],
            chain["observation"]["signal"]) == ("ssid01", 20, 11, 67)
    assert chain["observation"]["radio_performance"]["counters_reported"] is True
    relations = chain["relations"]
    assert relations["access_point"]["management"] == {"ip": "192.0.2.5", "netmask": "255.255.255.0",
                                                      "gateway": "192.0.2.1", "ip_mode": "Manual",
                                                      "protocol_mode": "IPv4-Only"}
    assert relations["uplink_ports"] == ["eth0"]
    assert relations["lan_ports"][0]["speed"] == "1000Mbps" and relations["lan_ports"][0]["source"] == "access_point + ethernet_info"
    assert {(b["relation"], b["to"]) for b in relations["bindings"]} >= {
        ("associated_to", "ap:" + AP_MAC), ("on_wlan", "wlan:ssid01"), ("bridged_to_vlan", "vlan:20"),
        ("wired_uplink", "ap_port:eth0"), ("connected_to", None)}
    assert "access point LAN port VLAN and tagging" in relations["not_reported"]
    assert result["next_steps"][0] == {"tool": "locate_endpoint", "arguments": {"targets": ["wire-test"], "endpoint": AP_MAC},
                                       "why": result["next_steps"][0]["why"]}
    summary = engine.triage_wifi(ruckus_target(*TRIAGE_QUERIES), mac=CLIENT_MAC, summary=True)
    assert summary["view"] == "summary" and summary["verdict"] == "no_fault_observed"
    assert summary["chain"]["relations"]["uplink_ports"] == ["eth0"]


def test_triage_by_ip_selects_the_client_from_the_active_list(wire, monkeypatch):
    sent = []
    unleashed(monkeypatch, triage_answers(), sent)
    result = engine.triage_wifi(ruckus_target(*TRIAGE_QUERIES), ip="198.51.100.6")
    assert result["ok"] is True and result["client"]["mac"] == CLIENT_MAC, result
    assert sent[1] == "show current-active-clients all"
    assert result["verdict"] == "no_fault_observed"


def test_absent_client_is_not_associated_and_nothing_else_is_read(wire, monkeypatch):
    sent = []
    absent = text(WIRELESS_INVENTORY / "client_mac_absent.out")
    mac = absent.split("\n", 1)[0].rsplit(" ", 1)[1]
    unleashed(monkeypatch, triage_answers(**{"show current-active-clients mac " + mac: absent}), sent)
    result = engine.triage_wifi(ruckus_target(*TRIAGE_QUERIES), mac=mac)
    assert result["ok"] is True and result["verdict"] == "client_not_associated", result
    assert sent == ["show sysinfo", "show current-active-clients mac " + mac]
    assert result["chain"]["association"]["status"] == "not_associated" and result["client"] is None


def test_unauthorized_client_without_address_is_a_fault(wire, monkeypatch):
    sent = []
    record = text(WIRELESS_INVENTORY / "show_current_active_clients_mac_CLIENT.out")
    record = record.replace("Status= Authorized", "Status= Unauthorized").replace("User/IP= 198.51.100.6", "User/IP= 0.0.0.0")
    unleashed(monkeypatch, triage_answers(**{"show current-active-clients mac " + CLIENT_MAC: record}), sent)
    result = engine.triage_wifi(ruckus_target(*TRIAGE_QUERIES), mac=CLIENT_MAC)
    assert result["verdict"] == "fault_found", result
    assert {f["id"]: f["severity"] for f in result["findings"]} == {
        "F-WIFI-CLIENT-NOT-AUTHORIZED": "fault", "F-WIFI-CLIENT-NO-IPV4": "warning"}


def test_radio_answer_without_counters_and_a_refused_read_keep_the_triage_incomplete(wire, monkeypatch):
    sent = []
    header = text(WIRELESS_INVENTORY / "performance_radio24_header_only.out")
    unleashed(monkeypatch, triage_answers(**{"show performance ap-radio2-4 mac " + AP_MAC: header}), sent)
    result = engine.triage_wifi(ruckus_target(*TRIAGE_QUERIES), mac=CLIENT_MAC)
    assert result["verdict"] == "incomplete"
    assert {"step": "radio_performance_24", "reason": "incomplete",
            "detail": "the radio performance answer has no counters; repeat the read"} in result["missing"]
    # a query the target does not enable is named as such, never read
    sent.clear()
    narrow = [q for q in TRIAGE_QUERIES if q != "wlans"]
    result = engine.triage_wifi(ruckus_target(*narrow), mac=CLIENT_MAC)
    assert "show wlan all" not in sent and {"step": "wlans", "reason": "not_enabled"} in result["missing"]
    assert result["verdict"] == "incomplete" and result["chain"]["relations"]["wlan"] is None


def test_wrong_product_identity_is_refused_and_name_selection_is_rejected(wire, monkeypatch):
    sent = []
    unleashed(monkeypatch, triage_answers(**{"show sysinfo": "show sysinfo\nSystem Overview:\n  Name= x\n"}), sent)
    result = engine.triage_wifi(ruckus_target(*TRIAGE_QUERIES), mac=CLIENT_MAC)
    assert result["ok"] is False and result["error_code"] == "config_platform_not_supported"
    assert sent == ["show sysinfo"]
    with pytest.raises(ValueError, match="mac or ip"):
        engine.triage_wifi(ruckus_target(*TRIAGE_QUERIES), name="host-01")


def test_untested_build_warns_and_still_runs(wire, monkeypatch):
    sent = []
    sysinfo = text(WIRELESS_INVENTORY / "show_sysinfo.out").replace(unleashed_version("200.15.6.212.27"), unleashed_version("200.16.7.101.3"))
    unleashed(monkeypatch, triage_answers(**{"show sysinfo": sysinfo}), sent)
    result = engine.triage_wifi(ruckus_target(*TRIAGE_QUERIES), mac=CLIENT_MAC)
    assert result["ok"] is True and result["verdict"] == "no_fault_observed"
    assert result["firmware_support"]["status"] != "tested" and result["warnings"][0]["code"] == "firmware_untested"


# --- RP02: client -> AP -> switch port (two-switch replay) --------------------------------------------------------

EXOS = {"show version": "version", "show switch": "switch", "show fdb": "fdb", "show lldp neighbors detailed":
        "lldp_neighbors_detailed", "show ports no-refresh": "ports_no-refresh", "show vlan detail": "vlan_detail",
        "show sharing": "sharing"}
EXOS_RC = {"show vlan detail": 250, "show sharing": 250}
SWITCH_QUERIES = ("version", "switch", "mac_table", "lldp_neighbors_detail", "ports", "vlan_detail", "lag_summary")


def home(monkeypatch, wire, *, ruckus_answers=None, exos_answers=None):
    sent, exos = [], []
    answers = {"show current-active-clients all": (WIRELESS_PATH / "ruckus-show_current_active_clients_all.out").read_text(),
               "show ap all": (WIRELESS_PATH / "ruckus-show_ap_all.out").read_text()}
    answers.update(ruckus_answers or {})
    unleashed(monkeypatch, answers, sent)

    def transport(auth, profile, command, **kwargs):
        request = (auth.alias, command)
        exos.append(request)
        if exos_answers and request in exos_answers:
            return exos_answers[request]
        path = WIRELESS_PATH / ("%s-show_%s.out" % (auth.alias, EXOS[command]))
        return EXOS_RC.get(command, 0), path.read_text()
    monkeypatch.setattr(engine, "_exec_read", transport)
    queries = ("version", "switch", "mac_table", "lldp_neighbors_detail", "ports", "vlan_detail", "lag_summary")
    switches = [dataclasses.replace(_target("extreme_exos", "mac_table"), alias=alias, host=host,
                                    device_types=("switch",), enabled_queries=queries)
                for alias, host in (("switch-a", "198.51.100.2"), ("switch-b", "198.51.100.3"))]
    controller = ruckus_target("clients", "access_points", alias="r610", host="198.51.100.5")
    return [controller, *switches], sent, exos


def test_locate_client_follows_the_ruckus_ap_to_its_lldp_edge_port(wire, monkeypatch):
    targets, sent, exos = home(monkeypatch, wire)
    result = engine._locate_endpoint_run(targets, HOME_CLIENT)
    assert sent == ["show current-active-clients all", "show ap all"]
    assert result["verdict"] == "located", result["missing"]
    wireless = result["wireless"]
    assert wireless["status"] == "associated" and wireless["controller"] == "r610"
    assert (wireless["client"]["mac"], wireless["client"]["ip"], wireless["client"]["wlan"], wireless["client"]["vlan_id"]) == (
        HOME_CLIENT, HOME_CLIENT_IP, "ssid01", 20)
    assert (wireless["ap"]["mac"], wireless["ap"]["name"], wireless["ap"]["uplink_ports"]) == (HOME_AP, "host01", ["eth0"])
    assert wireless["ap_port"] == {"vantage": "switch-a", "port": "3", "vlan_id": 10, "role": "edge_behind_ap",
                                   "lldp_neighbor": "host01"}
    roles = {(f["vantage"], f["port"], f["role"]) for f in wireless["ap_location"]["findings"]}
    assert roles == {("switch-a", "3", "edge_behind_ap"), ("switch-b", "13", "transit")}
    assert wireless["ap_location"]["client_mac_observations"] == [
        {"vantage": "switch-a", "mac": HOME_CLIENT, "port": "3", "vlan_id": 20, "source": "mac_table"},
    ]
    assert wireless["ssid_binding"]["client_vlan_id"] == 20 and wireless["ssid_binding"]["ap_uplink_ports"] == ["eth0"]
    assert result["reads"] <= 40 and all(command.startswith("show ") for _, command in exos)


def test_locate_by_client_ip_and_an_unknown_client_falls_back_to_the_wired_flow(wire, monkeypatch):
    targets, sent, _ = home(monkeypatch, wire)
    result = engine._locate_endpoint_run(targets, HOME_CLIENT_IP)
    assert result["verdict"] == "located" and result["wireless"]["ap_port"]["port"] == "3"
    targets, sent, _ = home(monkeypatch, wire)
    result = engine._locate_endpoint_run(targets, "00:00:5e:00:53:fe")
    assert sent == ["show current-active-clients all"]
    assert result["wireless"]["status"] == "not_in_station_table"
    assert result["verdict"] in ("not_found_in_checked_data", "incomplete")
    assert not any(m.get("reason") == "device_type_not_declared" for m in result["missing"])


def test_locate_with_a_refused_ap_listing_stays_incomplete(wire, monkeypatch):
    refused = "show ap all\nThe entry 'all' could not be found. Please check the spelling, and then try again."
    targets, sent, _ = home(monkeypatch, wire, ruckus_answers={"show ap all": refused})
    result = engine._locate_endpoint_run(targets, HOME_CLIENT)
    # No AP is joined: the wired flow alone sees the client MAC behind the AP's LLDP edge port, the wireless
    # side stays unverified and its gap is reported; no ap_port is claimed.
    assert result["wireless"]["status"] == "not_verified" and "ap_port" not in result["wireless"]
    assert any(m["vantage"] == "r610" and m["reason"] == "device_cli_error" for m in result["missing"])
    assert result["verdict"] == "incomplete"
    assert not any(f["edge"] for f in result["findings"])
    assert any(f["vantage"] == "switch-a" and f["port"] == "3" and f["role"] == "behind_ap" for f in result["findings"])


# The production Helper bridge validates the MCP request, runs the real proxy and
# dispatches the registered server tool. Run the locate worker in-process so the
# same fixture transport is available across all three tools.
@pytest.fixture
def public(tmp_path, monkeypatch):
    import asyncio
    import json

    from netops import worker
    from netops_helper import endpoint_worker, proxy, server
    from test_locate_wifi import PIN, TOKEN
    from test_proxy_contracts import _device, _inventory, _section, _vault_document, _write

    state = tmp_path / "state"
    helper = state / "helper"
    helper.mkdir(parents=True, mode=0o700)
    inventory = helper / "inventory.json"
    monkeypatch.setattr(proxy, "INVENTORY", inventory)
    monkeypatch.setattr(worker, "STATE", state)
    vault = _vault_document()
    vault["credentials"]["api-ro"] = {"kind": "api-token", "login": None, "value": TOKEN}
    _write(helper / "vault.json", vault, 0o600)

    def run_worker(targets, endpoint, auth_context):
        return engine._locate_endpoint_run(endpoint_worker.decode(targets, auth_context), endpoint)

    monkeypatch.setattr(endpoint_worker, "call", run_worker)

    def device(alias, platform, queries, host, types=(), *, ports=(22, 443), **options):
        section = _section()
        section.pop("snmp_credential")
        section.update(ssh_platform=platform, enabled_queries=list(queries), device_types=list(types), **options)
        section["egress"].update(addresses=[host], tcp_ports=list(ports))
        result = dict(_device(section, platform), name=alias, address=host, host_key_fingerprint=HOST_KEY_PIN)
        if platform == "ruckus_unleashed":
            result["legacy_ssh"] = "rsa-sha1"
            section.update(account_role="admin-bounded", role_boundary="catalogue")
            section["egress"]["tcp_ports"] = []
            section["read_inventory"] = {"addresses": ["198.51.100.1"]}
        return result

    def configure(*, queries=(*TRIAGE_QUERIES, "access_points", "ping"), fortios=False, switch_queries=SWITCH_QUERIES):
        devices = [device("r610", "ruckus_unleashed", queries, "198.51.100.5"),
                   device("switch-a", "exos", switch_queries, "198.51.100.2", ("switch",)),
                   device("switch-b", "exos", switch_queries, "198.51.100.3", ("switch",))]
        if fortios:
            from test_locate_wifi import FGT_HOST
            devices.append(device("fgt", "fortios", ("arp_table",), FGT_HOST, ("firewall",),
                                  fortios_rest_credential="api-ro", fortios_rest_certificate_sha256=PIN))
        _write(inventory, _inventory(*devices))
        bridge = worker.HelperBridge()

        def call(tool, *, refused=False, **arguments):
            result = asyncio.run(bridge.call(server.mcp, tool, arguments))
            if refused:
                assert result["isError"] is True, result
                return json.loads(result["content"][0]["text"])
            assert result["isError"] is False, result
            return result["structuredContent"]

        return call

    return configure


@pytest.mark.parametrize(("selector", "query", "command"), [
    ({"mac": CLIENT_MAC}, "client_detail", "show current-active-clients mac " + CLIENT_MAC),
    ({"ip": "198.51.100.6"}, "clients", "show current-active-clients all"),
])
def test_public_ruckus_triage_requires_the_selected_client_query(public, wire, monkeypatch, selector, query, command):
    sent = []
    unleashed(monkeypatch, triage_answers(), sent)
    call = public()
    result = call("wifi_triage", target="r610", **selector)
    assert result["verdict"] == "no_fault_observed"
    assert sent[:2] == ["show sysinfo", command]

    sent.clear()
    for excluded in ("system_info", query):
        call = public(queries=tuple(item for item in TRIAGE_QUERIES if item != excluded))
        error = call("wifi_triage", target="r610", **selector, refused=True)
        assert (error["data"]["category"], error["data"]["field"]) == ("policy_scope", "enabled_queries")
    assert not sent


def test_public_ruckus_triage_rejects_name(public, wire, monkeypatch):
    sent = []
    unleashed(monkeypatch, triage_answers(), sent)
    error = public()("wifi_triage", target="r610", name="host01", refused=True)
    assert error["data"]["field"] == "name"
    assert not sent


def test_public_locate_accepts_only_an_enrolled_ruckus_reader(public, wire, monkeypatch):
    _, sent, _ = home(monkeypatch, wire)
    targets = ["r610", "switch-a", "switch-b"]
    result = public()("locate_endpoint", targets=targets, endpoint=HOME_CLIENT)
    assert result["verdict"] == "located"
    assert result["wireless"]["controllers_checked"] == ["r610"]
    assert sent == ["show current-active-clients all", "show ap all"]
    sent.clear()
    error = public(queries=("clients",))("locate_endpoint", targets=targets, endpoint=HOME_CLIENT, refused=True)
    assert error["data"]["target"] == "r610"
    assert not sent


@pytest.mark.parametrize("fortios_match", [False, True])
def test_public_mixed_locate_reads_both_controllers(public, wire, monkeypatch, fortios_match):
    from test_locate_wifi import CLIENT, Rest, documents, fgt_outputs

    _, sent, _ = home(monkeypatch, wire)
    switch_transport = engine._exec_read
    def replay(auth, profile, command, **kwargs):
        if auth.alias == "fgt":
            return 0, fgt_outputs()[command]
        return switch_transport(auth, profile, command, **kwargs)
    monkeypatch.setattr(engine, "_exec_read", replay)
    docs = documents()
    if fortios_match:
        docs[CLIENT]["results"][0]["mac"] = HOME_CLIENT
    else:
        docs[CLIENT]["results"] = []
    rest = Rest(docs).install(monkeypatch)

    call = public(fortios=True)
    result = call("locate_endpoint", targets=["fgt", "r610", "switch-a", "switch-b"], endpoint=HOME_CLIENT)
    assert CLIENT in rest.paths
    assert sent == ["show current-active-clients all", "show ap all"]
    wireless = result["wireless"]
    assert set(wireless["controllers_checked"]) == {"fgt", "r610"}
    if fortios_match:
        assert result["verdict"] == wireless["status"] == "ambiguous"
        assert {item["controller"] for item in wireless["candidates"]} == {"fgt", "r610"}
    else:
        assert result["verdict"] == "located"
        assert wireless["controller"] == "r610"


def test_public_locate_reports_client_vlan_at_the_ap_edge(public, wire, monkeypatch):
    _, _, exos = home(monkeypatch, wire)
    result = public()("locate_endpoint", targets=["r610", "switch-a", "switch-b"], endpoint=HOME_CLIENT)
    assert result["verdict"] == "located"
    wireless = result["wireless"]
    assert (wireless["ap_port"]["vantage"], wireless["ap_port"]["port"], wireless["ap_port"]["vlan_id"]) == ("switch-a", "3", 10)
    assert wireless["ssid_binding"]["client_vlan_id"] == 20
    assert wireless["ssid_binding"]["switch_port_vlan_membership"] == {"carries_vlan": True, "tagging": "tagged"}
    assert exos.count(("switch-a", "show vlan detail")) == 1


@pytest.mark.parametrize(("query", "command", "fixture", "keep"), [
    ("client_performance", "show performance station mac " + CLIENT_MAC,
     WIRELESS_INVENTORY / "show_performance_station_mac_CLIENT.out", 3),
    ("ethernet_info", "show ethinfo", WIRELESS_PATH / "ruckus-show_ethinfo.out", 2),
])
def test_public_triage_lists_missing_station_and_ethernet_data(public, wire, monkeypatch, query, command, fixture, keep):
    lines = [line for line in text(fixture).splitlines() if line.strip()]
    unleashed(monkeypatch, triage_answers(**{command: "\n".join(lines[:keep])}), [])
    result = public()("wifi_triage", target="r610", mac=CLIENT_MAC)
    assert result["verdict"] == "incomplete"
    assert any(item["step"] == query and item["reason"] == "incomplete" for item in result["missing"])
    assert query not in result["checked"]


@pytest.mark.parametrize(("body_lines", "status"), [(1, "not_verified"), (2, "not_in_station_table"),
                                                    (3, "not_verified")])
def test_public_locate_distinguishes_echo_empty_table_and_partial_row(public, wire, monkeypatch, body_lines, status):
    command = "show current-active-clients all"
    fixture = text(WIRELESS_PATH / "ruckus-show_current_active_clients_all.out").splitlines()
    _, sent, _ = home(monkeypatch, wire, ruckus_answers={command: "\n".join(fixture[:body_lines])})
    result = public()("locate_endpoint", targets=["r610", "switch-a", "switch-b"], endpoint="00:00:5e:00:53:fe")
    assert sent == [command]
    wireless = result["wireless"]
    assert wireless["status"] == status
    if status == "not_verified":
        assert wireless["controllers_checked"] == []
        assert wireless["controllers_failed"] == ["r610"]
        assert result["coverage"]["complete"] is False and "r610" in result["coverage"]["unfinished_targets"]
        assert result["verdict"] == "incomplete"
    else:
        assert wireless["controllers_checked"] == ["r610"]


@pytest.mark.parametrize("mutation", ["short", "loss"])
def test_public_ping_requires_three_packets_and_consistent_totals(public, wire, monkeypatch, mutation):
    fixture = text(WIRELESS_PATH / "ruckus-ping_reachable.out")
    command = "ping 198.51.100.1"
    answer = {command: fixture}
    sent = []
    unleashed(monkeypatch, answer, sent)
    call = public()
    args = {"target": "r610", "platform": "ruckus_unleashed", "query": "ping", "parameters": {"address": "198.51.100.1"}}
    result = call("ssh_read", **args)["wifi"]
    assert result["complete"] is True and result["reachable"] is True

    if mutation == "short":
        lines = fixture.splitlines()
        answer[command] = "\n".join(lines[:3] + [lines[6], "1 packets transmitted, 1 packets received, 0% packet loss"])
    else:
        answer[command] = fixture.replace("0% packet loss", "100% packet loss")
    result = call("ssh_read", **args)["wifi"]
    assert sent == [command, "show sysinfo"] * 2
    assert result["complete"] is False and result["reachable"] is None


def test_public_ip_triage_cites_clients_for_client_bindings(public, wire, monkeypatch):
    unleashed(monkeypatch, triage_answers(), [])
    result = public()("wifi_triage", target="r610", ip="198.51.100.6")
    bindings = result["chain"]["relations"]["bindings"]
    assert {item["relation"]: item["source"] for item in bindings if item["from"].startswith("client:")} == {
        "associated_to": "clients", "on_wlan": "clients"}


def test_public_ruckus_identity_failure_names_ruckus_system_info(public, wire, monkeypatch):
    sent = []
    fixture = text(WIRELESS_PATH / "ruckus-show_sysinfo.out").replace("Model= r610", "Model=", 1)
    unleashed(monkeypatch, triage_answers(**{"show sysinfo": fixture}), sent)
    result = public()("wifi_triage", target="r610", mac=CLIENT_MAC)
    assert result["ok"] is False and result["error_code"] == "config_platform_not_supported"
    assert result["failed_step"] == result["missing"][0]["step"] == "system_info"
    assert "Ruckus Unleashed" in result["vantage"]["sees"] and "FortiGate" not in result["vantage"]["sees"]
    assert sent == ["show sysinfo"]


@pytest.mark.parametrize("tool", ["wifi_triage", "locate_endpoint"])
def test_public_ruckus_redacts_secret_fields_before_parsing_and_hashing(public, wire, monkeypatch, tool):
    canaries = text(WIRELESS_PATH / "ruckus-secret-fields.out")
    if tool == "wifi_triage":
        command = "show wlan all"
        anchor = "      Ignore unauthorized client statistic = Disabled"
        fixture = text(WIRELESS_INVENTORY / "show_wlan_all.out")
        args = {"target": "r610", "mac": CLIENT_MAC}
        query = "wlans"
    else:
        command = "show current-active-clients all"
        anchor = "    Status= Authorized"
        fixture = text(WIRELESS_PATH / "ruckus-show_current_active_clients_all.out")
        args = {"targets": ["r610", "switch-a", "switch-b"], "endpoint": HOME_CLIENT}
        query = "clients"

    from netops_helper import triage_wifi

    original = wifi_parse.summarize_ruckus
    original_source = triage_wifi._source
    parser_inputs, triage_sources = [], []

    def observe_source(name, answer, moment):
        source = original_source(name, answer, moment)
        if name == query:
            triage_sources.append(source)
        return source

    monkeypatch.setattr(triage_wifi, "_source", observe_source)

    def observe(name, content):
        if name == query:
            parser_inputs.append(content)
        return original(name, content)
    monkeypatch.setattr(wifi_parse, "summarize_ruckus", observe)

    def run(fields):
        capture = fixture.replace(anchor, anchor + "\n" + fields.rstrip(), 1)
        if tool == "wifi_triage":
            unleashed(monkeypatch, triage_answers(**{command: capture}), [])
        else:
            home(monkeypatch, wire, ruckus_answers={command: capture})
        result = public()(tool, **args)
        assert result["ok"] and result["verdict"] in ("no_fault_observed", "located")
        sources = triage_sources[-1:] if tool == "wifi_triage" else result["wireless"]["sources"]
        return result, next(item["content_sha256"] for item in sources if item["query"] == query)

    redacted = "".join(line.partition("=")[0] + "= <REDACTED>\n" for line in canaries.splitlines())
    outcome, digest = run(canaries)
    _, expected = run(redacted)
    assert digest == expected
    assert len(parser_inputs) == 2 and parser_inputs[0] == parser_inputs[1]
    for line in canaries.splitlines():
        value = line.partition("=")[2].strip()
        assert value not in repr(outcome) and value not in parser_inputs[0]


# --- review non-blocking findings, through the public bridge -> proxy -> engine path -------------

def test_public_locate_reports_an_unread_client_vlan_membership(public, wire, monkeypatch):
    # Finding 1a: switch-a is enrolled without `vlan_detail`, so the AP edge port's membership in the client VLAN is
    # unknown (`tagging: missing`); that gap is a named `missing` item and makes coverage incomplete.
    _, sent, exos = home(monkeypatch, wire)
    call = public(switch_queries=tuple(query for query in SWITCH_QUERIES if query != "vlan_detail"))
    result = call("locate_endpoint", targets=["r610", "switch-a", "switch-b"], endpoint=HOME_CLIENT)
    assert sent == ["show current-active-clients all", "show ap all"]
    assert not any(command == "show vlan detail" for _, command in exos)
    wireless = result["wireless"]
    assert (wireless["ap_port"]["vantage"], wireless["ap_port"]["port"]) == ("switch-a", "3")
    assert wireless["ssid_binding"]["client_vlan_id"] == 20
    assert wireless["ssid_binding"]["switch_port_vlan_membership"] == {"carries_vlan": None, "tagging": "missing"}
    gaps = [item for item in result["missing"] if item["reason"] == "client_vlan_membership_missing"]
    assert len(gaps) == 1 and gaps[0]["detail"], result["missing"]
    assert {key: gaps[0][key] for key in ("vantage", "table", "port", "vlan_id")} == {
        "vantage": "switch-a", "table": "port_vlan", "port": "3", "vlan_id": 20}
    assert result["verdict"] == "incomplete"
    assert result["coverage"]["complete"] is False and "switch-a" in result["coverage"]["unfinished_targets"]


def test_public_locate_preserves_the_ap_port_when_switch_refuses_vlan_detail(public, wire, monkeypatch):
    request = ("switch-a", "show vlan detail")
    _, sent, exos = home(monkeypatch, wire, exos_answers={
        request: (250, "This user does not have permissions for this command.\n"),
    })
    result = public()("locate_endpoint", targets=["r610", "switch-a", "switch-b"], endpoint=HOME_CLIENT)
    assert sent == ["show current-active-clients all", "show ap all"]
    assert exos.count(request) == 1
    wireless = result["wireless"]
    nested = wireless["ap_location"]
    assert nested["verdict"] == "incomplete"
    assert [(edge["vantage"], edge["port"]) for edge in nested["findings"] if edge["edge"]] == [("switch-a", "3")]
    assert wireless["ap_port"] == {"vantage": "switch-a", "port": "3", "vlan_id": 10, "role": "edge_behind_ap",
                                   "lldp_neighbor": "host01"}
    binding = wireless["ssid_binding"]
    assert binding["client_vlan_id"] == 20
    assert binding["switch_port_vlan_membership"] == {"carries_vlan": None, "tagging": "missing"}
    gap, = result["missing"]
    assert {key: gap[key] for key in ("vantage", "table", "reason", "port", "vlan_id")} == {
        "vantage": "switch-a", "table": "port_vlan", "reason": "client_vlan_membership_missing", "port": "3", "vlan_id": 20}
    assert gap["read_status"] == "permission_denied"
    assert result["verdict"] == "incomplete"
    assert result["coverage"]["complete"] is False and "switch-a" in result["coverage"]["unfinished_targets"]


@pytest.mark.parametrize(("shape", "reason"), [("empty", "incomplete"), ("before_mac", "incomplete"),
                                              ("absent", "not_listed")])
def test_public_triage_distinguishes_incomplete_ap_data_from_explicit_absence(public, wire, monkeypatch, shape, reason):
    command = "show ap mac " + AP_MAC
    capture = text(WIRELESS_PATH / "ruckus-show_ap_all.out").replace("show ap all", command, 1)
    if shape == "absent":
        capture = text(WIRELESS_INVENTORY / "ap_mac_absent.out").replace(HOME_AP, AP_MAC)
    elif shape == "empty":
        capture = capture.split("\n", 1)[0]
    else:
        capture = capture.partition("      MAC Address=")[0]

    sent = []
    unleashed(monkeypatch, triage_answers(**{command: capture}), sent)
    result = public()("wifi_triage", target="r610", mac=CLIENT_MAC)
    assert command in sent and "show ethinfo" not in sent
    assert result["chain"]["association"]["status"] == "associated"
    assert result["chain"]["relations"]["access_point"] is None
    assert result["verdict"] == "incomplete"
    assert ("access_point" in result["checked"]) == (shape == "absent")
    assert [item["reason"] for item in result["missing"] if item["step"] == "access_point"] == [reason]


def test_public_locate_reports_a_client_vlan_the_controller_did_not_print(public, wire, monkeypatch):
    # Finding 1b: the controller prints `VLAN=` without a value for the client; the AP port is still found, the
    # client VLAN check is reported as a named gap instead of a silently missing field.
    command = "show current-active-clients all"
    capture = text(WIRELESS_PATH / "ruckus-show_current_active_clients_all.out")
    assert capture.count("    VLAN= 20\n") > 1
    capture = capture.replace("    VLAN= 20\n", "    VLAN=\n", 1)
    home(monkeypatch, wire, ruckus_answers={command: capture})
    result = public()("locate_endpoint", targets=["r610", "switch-a", "switch-b"], endpoint=HOME_CLIENT)
    wireless = result["wireless"]
    assert wireless["client"]["vlan_id"] is None
    assert (wireless["ap_port"]["vantage"], wireless["ap_port"]["port"]) == ("switch-a", "3")
    assert wireless["ssid_binding"]["client_vlan_id"] is None
    assert wireless["ssid_binding"]["switch_port_vlan_membership"] is None
    gaps = [item for item in result["missing"] if item["reason"] == "client_vlan_not_reported"]
    assert len(gaps) == 1 and gaps[0]["detail"], result["missing"]
    assert {key: gaps[0][key] for key in ("vantage", "table", "controller")} == {
        "vantage": None, "table": "ssid_binding", "controller": "r610"}
    assert result["verdict"] == "incomplete" and result["coverage"]["complete"] is False


@pytest.mark.parametrize(("removed", "uplink_gap"), [
    ("    Physical Link= down\n", False),     # unused eth1 prints no link state
    ("    Interface= eth1\n", False),         # unused eth1 prints no interface name
    ("    Physical Link= up\n", True),        # the uplink eth0 prints no link state
])
def test_public_triage_judges_ethernet_by_the_ap_uplink_port(public, wire, monkeypatch, removed, uplink_gap):
    # Finding 2: an unused LAN port without link data does not drop the whole Ethernet step; only missing data for
    # the port the AP is connected by (its logically up uplink, eth0) does.
    capture = (WIRELESS_PATH / "ruckus-show_ethinfo.out").read_text()
    assert capture.count(removed) == 1
    unleashed(monkeypatch, triage_answers(**{"show ethinfo": capture.replace(removed, "")}), [])
    result = public()("wifi_triage", target="r610", mac=CLIENT_MAC)
    gaps = [item for item in result["missing"] if item["step"] == "ethernet_info"]
    assert result["chain"]["relations"]["uplink_ports"] == ["eth0"]
    if uplink_gap:
        assert result["verdict"] == "incomplete" and "ethernet_info" not in result["checked"]
        assert len(gaps) == 1 and gaps[0]["reason"] == "incomplete" and gaps[0]["ports"] == ["eth0"]
        assert "eth0" in gaps[0]["detail"]
    else:
        assert result["verdict"] == "no_fault_observed", result["missing"]
        assert gaps == [] and "ethernet_info" in result["checked"]
        assert [m["step"] for m in result["missing"]] == ["ap_switch_port"]
        eth0 = next(port for port in result["chain"]["relations"]["lan_ports"] if port["interface"] == "eth0")
        assert eth0["speed"] == "1000Mbps" and eth0["source"] == "access_point + ethernet_info"


@pytest.mark.parametrize("mutation", ["five_packets", "sequence_from_one", "iputils", "iputils_loss"])
def test_public_ping_reads_alternate_count_numbering_and_format(public, wire, monkeypatch, mutation):
    # Derived from R610 capture; see PROVENANCE.md for the iputils field grammar.
    fixture = text(WIRELESS_PATH / "ruckus-ping_reachable.out")
    lines = fixture.splitlines()
    replies = lines[2:5]
    if mutation == "five_packets":
        extra = [replies[-1].replace("seq=2", "seq=%d" % seq) for seq in (3, 4)]
        capture = "\n".join(lines[:5] + extra + lines[5:]).replace(
            "3 packets transmitted, 3 packets received", "5 packets transmitted, 5 packets received")
    else:
        capture = fixture
        for seq in (2, 1, 0):
            capture = capture.replace("seq=%d " % seq, "seq=%d " % (seq + 1))
    if mutation.startswith("iputils"):
        capture = (capture.replace("): 56 data bytes", ") 56(84) bytes of data.")
                   .replace("seq=", "icmp_seq=").replace("packets received,", "received,")
                   .replace("0% packet loss", "0% packet loss, time 2002ms")
                   .replace("round-trip min/avg/max", "rtt min/avg/max/mdev")
                   .replace("/0.712 ms", "/0.712/0.152 ms"))
    if mutation == "iputils_loss":
        capture = "\n".join(line for line in capture.splitlines() if "icmp_seq=3 " not in line)
        capture = capture.replace("3 received, 0%", "2 received, 33.3333%")
    command = "ping 198.51.100.1"
    sent = []
    unleashed(monkeypatch, {command: capture}, sent)
    result = public()("ssh_read", target="r610", platform="ruckus_unleashed", query="ping",
                      parameters={"address": "198.51.100.1"})["wifi"]
    assert sent == [command, "show sysinfo"]
    assert result["complete"] and result["reachable"]
    assert result["unparsed_count"] == 0 and result["warnings"] == []
    record, = result["records"]
    assert record["transmitted"] == (5 if mutation == "five_packets" else 3)
    assert record["received"] == (2 if mutation == "iputils_loss" else record["transmitted"])
    assert record["loss_percent"] == (33.3333 if mutation == "iputils_loss" else 0)
    assert record["rtt_max_ms"] == 0.712


def test_public_ping_of_build_27_carries_no_warning(public, wire, monkeypatch):
    unleashed(monkeypatch, {"ping 198.51.100.1": text(WIRELESS_PATH / "ruckus-ping_reachable.out")}, [])
    result = public()("ssh_read", target="r610", platform="ruckus_unleashed", query="ping",
                      parameters={"address": "198.51.100.1"})["wifi"]
    assert result["complete"] is True and result["warnings"] == []


@pytest.mark.parametrize("case, warning", [
    ("complete", None),
    ("missing_errors", "ping_totals_inconsistent"),
    ("foreign_sequence", "ping_sequence_untested"),
    ("missing_totals", "ping_totals_missing"),
])
def test_public_iputils_ping_with_icmp_errors(public, wire, monkeypatch, case, warning):
    capture = text(WIRELESS_PATH / "ruckus-ping_unanswered.out").replace("192.0.2.1", "198.51.100.1")
    command, header, _, statistics, totals = capture.splitlines()
    header = header.replace("): 56 data bytes", ") 56(84) bytes of data.")
    totals = totals.replace("0 packets received,", "0 received, +3 errors,") + ", time 2002ms"
    seqs = (1, 2) if case == "missing_errors" else (1, 2, 4) if case == "foreign_sequence" else (1, 2, 3)
    errors = [f"From 198.51.100.254 icmp_seq={seq} Destination Host Unreachable" for seq in seqs]
    lines = [command, header, *errors, "", statistics]
    if case != "missing_totals":
        lines.append(totals)
    sent = []
    unleashed(monkeypatch, {command: "\n".join(lines)}, sent)
    result = public()("ssh_read", target="r610", platform="ruckus_unleashed", query="ping",
                      parameters={"address": "198.51.100.1"})["wifi"]
    assert sent == [command, "show sysinfo"]
    assert result["unparsed_count"] == 0
    assert result["complete"] is (warning is None)
    assert result["reachable"] is (False if warning is None else None)
    assert [item["code"] for item in result["warnings"]] == ([] if warning is None else [warning])
    if warning is None:
        record, = result["records"]
        assert (record["transmitted"], record["received"], record["loss_percent"], record["replies"]) == (3, 0, 100, [])


@pytest.mark.parametrize("answer", ["", "show ap all\n", "show ap all\nAP:\n  ID:\n"])
def test_public_empty_ap_listing_is_valid_for_read_and_wireless_locate(public, wire, monkeypatch, answer):
    _, sent, _ = home(monkeypatch, wire, ruckus_answers={"show ap all": answer})
    call = public()
    listing = call("ssh_read", target="r610", platform="ruckus_unleashed", query="access_points")
    assert listing["ok"]
    assert listing["wifi"]["complete"] and listing["wifi"]["records"] == []
    result = call("locate_endpoint", targets=["r610", "switch-a", "switch-b"], endpoint=HOME_CLIENT)
    assert sent == ["show ap all", "show sysinfo", "show current-active-clients all", "show ap all"]
    wireless = result["wireless"]
    assert {"vantage": "r610", "table": "wifi_ap", "reason": "ap_not_joined"} in result["missing"]
    assert wireless["controllers_checked"] == ["r610"] and wireless["ap_port"] is None
    assert not result["coverage"]["complete"]


def test_summary_public_ping_preserves_all_inconsistent_totals_details(public, wire, monkeypatch):
    capture = text(WIRELESS_PATH / "ruckus-ping_unanswered.out").replace("192.0.2.1", "198.51.100.1")
    capture = capture.replace("0 packets received,", "0 packets received, +3 errors,")
    capture = capture.replace("100% packet loss", "0% packet loss")
    unleashed(monkeypatch, {"ping 198.51.100.1": capture}, [])
    result = public()("ssh_read", target="r610", platform="ruckus_unleashed", query="ping",
                      parameters={"address": "198.51.100.1"})["wifi"]
    assert result["complete"] is False and result["reachable"] is None
    warning, = result["warnings"]
    assert warning["code"] == "ping_totals_inconsistent"
    assert "0% loss" in warning["detail"] and "3 ICMP errors" in warning["detail"]


def test_public_partial_ap_listing_is_incomplete(public, wire, monkeypatch):
    capture = text(WIRELESS_PATH / "ruckus-show_ap_all.out")
    answer = capture[:capture.index("MAC Address=")]
    home(monkeypatch, wire, ruckus_answers={"show ap all": answer})
    result = public()("locate_endpoint", targets=["r610", "switch-a", "switch-b"], endpoint=HOME_CLIENT)
    assert {"vantage": "r610", "table": "access_points", "reason": "incomplete"} in result["missing"]
    assert result["wireless"]["status"] == "not_verified"


def test_wifi_triage_refuses_unenrolled_ruckus_identity_before_ssh(wire, monkeypatch):
    sent = []
    unleashed(monkeypatch, triage_answers(), sent)
    result = engine.triage_wifi(ruckus_target("client_detail"), mac=CLIENT_MAC)
    assert not result["ok"] and result["verdict"] == "incomplete"
    assert result["failed_step"] == "system_info"
    assert result["missing"] == [{"step": "system_info", "reason": "permission_denied",
                                  "error_code": "permission_denied"}]
    assert sent == []


@pytest.mark.parametrize("failure, reason", [("budget", "target_read_limit"), ("transport", "disconnected")])
def test_locate_ruckus_cannot_confirm_association_without_ap_read(wire, monkeypatch, failure, reason):
    disconnect = engine.core_session.SessionError("fixture private detail", code="disconnected")
    targets, sent, _ = home(monkeypatch, wire, ruckus_answers={"show ap all": disconnect})
    controller = dataclasses.replace(targets[0], locate_read_limit=1 if failure == "budget" else 40)
    result = engine._locate_endpoint_run([controller], HOME_CLIENT)
    assert result["verdict"] == "incomplete" and result["wireless"]["status"] == "not_verified"
    assert any(item["vantage"] == "r610" and item["reason"] == reason for item in result["missing"]), result
    assert sent == ["show current-active-clients all"] + (["show ap all"] if failure == "transport" else [])
    assert result["reads"] == len(sent)
    assert "fixture private detail" not in str(result)
