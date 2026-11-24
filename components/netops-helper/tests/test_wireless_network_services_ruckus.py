"""WIRELESS-NETWORK-SERVICES: Ruckus Unleashed ACL, AAA, DHCP relay, static route and allowlisted settings reads (R10-R13, RP08, RP10).

The live captures in `fixtures/ruckus_wireless_network_services` are from an R610 running Ruckus Unleashed 200.15.6.212.27 (anonymised)
and show empty management ACL, DHCP relay, static route and L3 ACL listings. Tests also parse populated examples
derived from the CLI guides and check that unknown layouts are reported as unparsed. Engine reads go through the scripted Unleashed PTY (login, enable, captured
output), so the real PTY body handling, redaction, the config allowlist and the `wifi` payload are what is tested.
"""

import dataclasses
import re
from pathlib import Path

import pytest

from conftest import _target
import netops_helper.engine as engine
from netops_helper import proxy, wifi_parse
from netops_helper.query_catalog import READ_QUERIES

FIXTURES = Path(__file__).parent / "fixtures" / "ruckus_wireless_network_services"


def unleashed_version(dotted):
    """The `show sysinfo` spelling (`<release> build <build>`) of a five-part Unleashed firmware such as 200.15.6.212.27."""
    release, build = dotted.rsplit(".", 1)
    return f"{release} build {build}"


LISTS = {  # query -> (command, fixture)
    "l2_acls": ("show l2acl all", "show_l2acl_all.out"),
    "mgmt_acls": ("show mgmt-acl all", "show_mgmt_acl_all.out"),
    "l3_acls": ("show l3acl all", "show_l3acl_all.out"),
    "aaa_servers": ("show aaa all", "show_aaa_all.out"),
    "dhcp_relays": ("show dhcp all", "show_dhcp_all.out"),
    "static_routes": ("show static-route all", "show_static_route_all.out"),
}


def fixture(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch, wire):
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    engine._WTP_SEEN.clear()
    engine._SSH_PAGE_CACHE.clear()
    yield
    engine._WTP_SEEN.clear()
    engine._SSH_PAGE_CACHE.clear()


def unleashed(monkeypatch, outputs, sent):
    script = iter(outputs)

    class Terminal:
        def __init__(self, *args, **options):
            self.buffer = [b"Welcome to the Ruckus Unleashed Network Command Line Interface\r\nPlease login: "]
            self.answered = 0

        def expect(self, patterns, timeout):
            return 0, self.buffer.pop(0)

        def discard(self, seen):
            pass

        def send(self, text):
            sent.append(text)
            self.answered += 1
            if self.answered == 1:
                self.buffer.append(b"Password: ")
            elif self.answered == 2:
                self.buffer.append(b"Login success\r\nruckus> ")
            elif self.answered == 3:
                self.buffer.append(b"enable\r\nruckus#")
            else:
                self.buffer.append(next(script).replace("\n", "\r\n").encode() + b"\r\nruckus#")

        def close(self):
            pass

    monkeypatch.setattr(engine.core_session, "Session", Terminal)


def target(query, *additional_queries):
    return dataclasses.replace(_target("ruckus_unleashed", query, legacy_ssh="rsa-sha1"),
                               enabled_queries=(query, *additional_queries))


def read(auth, query, offset=0, limit=48_000, sha=None):
    return engine.ssh_read(auth, "ruckus_unleashed", query, {}, offset, limit, sha)


def read_all(auth, query, limit=48_000):
    pages = [read(auth, query, limit=limit)]
    assert pages[0]["ok"] is True, (pages[0].get("error_code"), pages[0].get("error"), pages[0].get("reason"))
    while pages[-1]["next_offset"] is not None:
        pages.append(read(auth, query, pages[-1]["next_offset"], limit, pages[0]["content_sha256"]))
        assert pages[-1]["ok"] is True, pages[-1]
    return pages


# --- registration ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("query", [*LISTS, "config_settings"])
def test_new_queries_are_in_catalogue_and_proxy(query):
    assert query in READ_QUERIES["ruckus_unleashed"]
    assert query in proxy.READ_QUERY_NAMES["ruckus_unleashed"]


@pytest.mark.parametrize("query, expected", [(q, c) for q, (c, _) in LISTS.items()] + [("config_settings", "show config")])
def test_commands_are_the_ones_verified_on_the_device(query, expected):
    assert READ_QUERIES["ruckus_unleashed"][query].command == expected


def test_bare_l3acl_is_not_a_command_and_never_used():
    assert "unrecognized or incomplete" in fixture("show_l3acl_bare_unrecognized.out")
    assert all(READ_QUERIES["ruckus_unleashed"][q].command != "show l3acl" for q in READ_QUERIES["ruckus_unleashed"])


# --- parsers on real output ---------------------------------------------------------------------------------

def test_l2_acls_are_read_with_restriction_and_stations():
    parsed = wifi_parse.summarize_ruckus("l2_acls", fixture("show_l2acl_all.out"))
    assert parsed["unparsed"] == [] and parsed["incomplete"] is False and parsed["count"] == 3
    names = {record["name"]: record for record in parsed["records"]}
    assert list(names) == ["System", "blacklist", "allow"]
    assert names["System"]["lists"]["Stations"] == []
    assert names["blacklist"]["settings"]["Restriction"] == "Deny only the stations listed below"
    assert names["allow"]["settings"]["Restriction"] == "Allow only the stations listed below"
    stations = names["allow"]["lists"]["Stations"]
    assert len(stations) == 36 and all(re.fullmatch(r"00:00:5e:00:53:[0-9a-f]{2}", mac) for mac in stations)


def test_aaa_servers_are_read_by_name_and_type():
    parsed = wifi_parse.summarize_ruckus("aaa_servers", fixture("show_aaa_all.out"))
    assert parsed["unparsed"] == [] and parsed["incomplete"] is False
    assert [(r["name"], r["settings"]["Type"]) for r in parsed["records"]] == [("Local Database", "Local"),
                                                                              ("Guest Accounts", "Guest")]


@pytest.mark.parametrize("query", ["mgmt_acls", "l3_acls", "dhcp_relays", "static_routes"])
def test_empty_listing_is_nothing_configured_not_an_error(query):
    parsed = wifi_parse.summarize_ruckus(query, fixture(LISTS[query][1]))
    assert parsed["records"] == [] and parsed["unparsed"] == [] and parsed["incomplete"] is False


@pytest.mark.parametrize("query", ["mgmt_acls", "dhcp_relays", "static_routes"])
def test_unknown_layout_is_unparsed_not_dropped(query):
    root = {"mgmt_acls": "Management ACL", "dhcp_relays": "DHCP servers for DHCP relay agent",
            "static_routes": "Static Route"}[query]
    parsed = wifi_parse.summarize_ruckus(query, f"show x\n{root}:\n  198.51.100.0/24 via 192.0.2.1\n")
    assert parsed["unparsed_count"] == 1 and parsed["records"] == []


def test_unrecognized_command_text_is_not_an_empty_listing():
    parsed = wifi_parse.summarize_ruckus("l3_acls", fixture("show_l3acl_bare_unrecognized.out"))
    assert parsed["unparsed_count"] >= 1 or parsed["incomplete"] is True


def test_nameless_acl_record_is_incomplete():
    parsed = wifi_parse.summarize_ruckus(
        "l2_acls", "show l2acl all\nL2/MAC ACL:\n  ID:\n    1:\n      Restriction= Deny only the stations listed below\n")
    assert parsed["incomplete"] is True


# --- engine reads over the scripted PTY ---------------------------------------------------------------------

@pytest.mark.parametrize("query", list(LISTS))
def test_list_reads_run_the_verified_command_and_report_complete(monkeypatch, query):
    sent = []
    unleashed(monkeypatch, [fixture(LISTS[query][1])], sent)
    result = read(target(query), query)
    assert result["ok"] is True, (result.get("error_code"), result.get("error"), result.get("reason"))
    assert sent[3::4] == [LISTS[query][0]]
    assert result["wifi"]["complete"] is True and result["wifi"]["unparsed"] == []


def test_aaa_secrets_are_redacted_in_every_shape(monkeypatch):
    captured = fixture("show_aaa_all.out").replace(
        "      Type= Guest\n",
        "      Type= Guest\n    3:\n      Name= radius1\n      Type= RADIUS\n      Shared Secret= s3cr3t Value 77\n"
        "      Backup Secret= zz\n      Admin Password= hunter2x\n")
    sent = []
    unleashed(monkeypatch, [captured], sent)
    result = read(target("aaa_servers"), "aaa_servers")
    dump = repr(result)
    assert result["ok"] is True
    for word in ("s3cr3t", "Value 77", "hunter2x"):
        assert word not in dump
    assert any(r["name"] == "radius1" for r in result["wifi"]["records"])


# --- RP08: allowlisted settings -----------------------------------------------------------------------------

SECTIONS_KEPT = ("Identity:", "NTP:", "Log:", "SNMP Agent:", "AAA:", "L2/MAC ACL:", "Device IP Address:")


def test_config_settings_pass_only_allowlisted_sections_and_no_secret(monkeypatch):
    sent = []
    unleashed(monkeypatch, [fixture("show_config.out")], sent)
    auth = target("config_settings")
    pages = read_all(auth, "config_settings", limit=2_000)
    text = "".join(page["untrusted_device_output"] for page in pages)
    assert sent[3::4] == ["show config"]
    for heading in SECTIONS_KEPT:
        assert heading in text
    assert "Address= tik.cesnet.cz" in text and "Status= Enabled" in text
    # everything outside the allowlist is withheld, including the WLAN definitions and the admin and token blocks
    for withheld in ("WLAN Service", "Passphrase", "Administrator Name", "Unleashed Network", "SSID", "Token"):
        assert withheld not in text.replace("[section withheld] " + withheld, "") or withheld in ("WLAN Service",)
    assert "ssid01" not in text and "FAKE-SECRET" not in text
    assert "[section withheld] AP" in text
    assert "FAKE-SECRET" not in repr(engine._SSH_PAGE_CACHE)
    assert "FAKE-SECRET" not in repr(pages)
    wifi = pages[0]["wifi"]
    assert wifi["missing_sections"] == [] and wifi["incomplete"] is False and wifi["withheld_sections"] > 5


def test_config_settings_hide_snmp_communities_and_phrases_even_in_kept_sections(monkeypatch):
    sent = []
    unleashed(monkeypatch, [fixture("show_config.out")], sent)
    text = read_all(target("config_settings"), "config_settings")[0]["untrusted_device_output"]
    shown = [line for line in text.split("\n") if "Community" in line or "Phrase" in line]
    # a community line is either redacted whole or dropped by the general SNMP rule; its value never survives
    assert not [line for line in shown if "Community" in line and "FAKE" in line]
    assert "FAKE-SECRET" not in text
    assert re.search(r"Authentication Pass Phrase\s*[=:]\s*(<REDACTED>|\[REDACTED\])", text)
    assert re.search(r"Privacy Phrase\s*[=:]\s*(<REDACTED>|\[REDACTED\])", text)
    assert "Authentication Type= MD5" in text


def test_config_settings_unknown_section_is_withheld_not_passed(monkeypatch):
    captured = fixture("show_config.out") + "Future Feature:\n  Shared Thing= hello-world-1\n"
    sent = []
    unleashed(monkeypatch, [captured], sent)
    text = read_all(target("config_settings"), "config_settings")[0]["untrusted_device_output"]
    assert "hello-world-1" not in text and "[section withheld] Future Feature" in text


def test_config_settings_cut_capture_is_incomplete(monkeypatch):
    cut = "\n".join(fixture("show_config.out").split("\n")[:12]) + "\n"
    sent = []
    unleashed(monkeypatch, [cut], sent)
    result = read(target("config_settings"), "config_settings")
    assert result["ok"] is True
    assert result["wifi"]["incomplete"] is True and result["wifi"]["complete"] is False
    assert "NTP" in result["wifi"]["missing_sections"]


def test_two_captures_show_the_changed_setting(monkeypatch):
    before = wifi_parse.summarize_ruckus("config_settings", engine_text(monkeypatch, fixture("show_config.out")))
    changed = fixture("show_config.out").replace("Address= tik.cesnet.cz", "Address= ntp.example.net")
    after = wifi_parse.summarize_ruckus("config_settings", engine_text(monkeypatch, changed))
    flat = lambda parsed: {(r["section"], k): v for r in parsed["records"] for k, v in r["settings"].items()}
    differing = {key for key in flat(before).keys() | flat(after).keys() if flat(before).get(key) != flat(after).get(key)}
    assert differing == {("NTP", "Address")}


def engine_text(monkeypatch, captured):
    sent = []
    unleashed(monkeypatch, [captured], sent)
    return read_all(target("config_settings"), "config_settings")[0]["untrusted_device_output"]


# --- RP10: another Unleashed version is read with a warning, never refused ----------------------------------------

SYSINFO = Path(__file__).parent / "fixtures" / "ruckus_wireless_inventory" / "show_sysinfo.out"


def test_tested_unleashed_build_has_no_warning(monkeypatch):
    unleashed(monkeypatch, [SYSINFO.read_text()], [])
    result = read(target("system_info"), "system_info")
    assert result["ok"] is True and result["firmware_support"]["status"] == "tested"
    assert "warnings" not in result


@pytest.mark.parametrize("old, new", [(unleashed_version("200.15.6.212.27"), unleashed_version("200.13.2.99.12")), ("= r610", "= r750")])
def test_other_unleashed_version_or_model_warns_but_is_read(monkeypatch, old, new):
    unleashed(monkeypatch, [SYSINFO.read_text().replace(old, new)], [])
    result = read(target("system_info"), "system_info")
    assert result["ok"] is True and result["firmware_support"]["status"] == "untested"
    assert result["warnings"][0]["code"] == "firmware_untested"
    assert "Uptime" in result["untrusted_device_output"]


def test_unreadable_unleashed_identity_is_unknown_not_refused(monkeypatch):
    unleashed(monkeypatch, ["show sysinfo\n\nSystem Overview:\n\n  Name= x\n"], [])
    result = read(target("system_info"), "system_info")
    assert result["ok"] is True and result["firmware_support"]["status"] == "unknown" and result["warnings"]


# --- Review regressions --------------------------------------------------------------------------------

def wlan_fixture():
    return (FIXTURES.parent / "ruckus_wireless_inventory" / "show_wlan_all.out").read_text(encoding="utf-8")


@pytest.fixture
def public_ruckus(tmp_path, monkeypatch):
    import asyncio
    import json

    from netops import worker
    from netops_helper import server
    from test_wireless_path_ruckus import HOST_KEY_PIN
    from test_proxy_contracts import _device, _inventory, _section, _vault_document, _write

    state = tmp_path / "state"
    helper = state / "helper"
    helper.mkdir(parents=True, mode=0o700)
    inventory = helper / "inventory.json"
    monkeypatch.setattr(proxy, "INVENTORY", inventory)
    monkeypatch.setattr(worker, "STATE", state)
    _write(helper / "vault.json", _vault_document(), 0o600)
    section = _section()
    section.pop("snmp_credential")
    section.update(ssh_platform="ruckus_unleashed", enabled_queries=[], account_role="admin-bounded",
                   role_boundary="catalogue", read_inventory={"config_access": ["read", "compare"]})
    section["egress"].update(addresses=["198.51.100.5"], tcp_ports=[22])
    device = dict(_device(section, "ruckus_unleashed"), name="r610", address="198.51.100.5",
                  host_key_fingerprint=HOST_KEY_PIN, legacy_ssh="rsa-sha1")
    def configure(*queries, requests=30):
        section.update(enabled_queries=list(queries), rate_limit={"requests": requests, "window_seconds": 60})
        _write(inventory, _inventory(device))
        bridge = worker.HelperBridge()

        def call(tool, *, error=False, **options):
            result = asyncio.run(bridge.call(server.mcp, tool, {
                "target": "r610", "platform": "ruckus_unleashed", **options,
            }))
            if error:
                assert result["isError"] is True, result
                return json.loads(result["content"][0]["text"])
            assert result["isError"] is False, result
            return result["structuredContent"]

        return call

    return configure


@pytest.fixture
def public_capture(public_ruckus):
    return public_ruckus()


CAPTURE_OPTIONS = {"section": "all", "include_all": True, "redaction": "full"}


def assert_firmware_query_disabled(result):
    support = result["firmware_support"]
    assert support["status"] == "unknown"
    assert support["model"] is None and support["device_version"] is None
    assert "system_info is not enabled" in support["message"]
    assert result["warnings"] == [{"code": "firmware_untested", "message": support["message"]}]


def test_r3_engine_skips_disabled_firmware_query(monkeypatch):
    sent = []
    unleashed(monkeypatch, [wlan_fixture(), SYSINFO.read_text()], sent)
    result = read(target("wlans"), "wlans")
    assert result["ok"] and result["wifi"]["records"]
    assert sent[3::4] == ["show wlan all"]
    assert_firmware_query_disabled(result)


def test_r3_public_snapshot_skips_disabled_firmware_query(monkeypatch, public_capture):
    sent = []
    unleashed(monkeypatch, [fixture("show_config.out"), SYSINFO.read_text()], sent)
    first = public_capture("config_read", **CAPTURE_OPTIONS, limit=300)
    page = public_capture("config_read", **CAPTURE_OPTIONS, snapshot_id=first["snapshot_id"],
                          offset=first["next_offset"], content_sha256=first["content_sha256"])
    assert first["complete"] and page["complete"]
    assert sent[3::4] == ["show config"]
    assert_firmware_query_disabled(first)
    assert_firmware_query_disabled(page)


@pytest.mark.parametrize(("tool", "options", "command", "capture"), [
    ("ssh_read", {"query": "wlans"}, "show wlan all", wlan_fixture()),
    ("config_read", CAPTURE_OPTIONS, "show config", fixture("show_config.out")),
], ids=["wlans", "snapshot"])
@pytest.mark.parametrize("system_info", [False, True], ids=["one-slot-disabled", "two-slots-enabled"])
def test_r3_public_rate_cost_follows_firmware_query_permission(
        monkeypatch, public_ruckus, tool, options, command, capture, system_info):
    sent = []
    unleashed(monkeypatch, [capture, SYSINFO.read_text()], sent)
    queries = ("wlans", "system_info") if system_info else ("wlans",)
    call = public_ruckus(*queries, requests=2 if system_info else 1)
    result = call(tool, **options)
    assert result["ok"]
    if system_info:
        assert sent[3::4] == [command, "show sysinfo"]
        assert result["firmware_support"]["status"] == "tested"
        assert "warnings" not in result
    else:
        assert sent[3::4] == [command]
        assert_firmware_query_disabled(result)
    before = len(sent)
    error = call("ssh_read", query="wlans", error=True)
    assert error["data"]["category"] == "rate_limit"
    assert len(sent) == before


def test_review_1_public_snapshot_and_line_diff(monkeypatch, public_ruckus):
    public_capture = public_ruckus("system_info")
    original = fixture("show_config.out")
    changed = original.replace("Address= tik.cesnet.cz", "Address= ntp.example.net")
    sent = []
    unleashed(monkeypatch, [original, SYSINFO.read_text(), changed, SYSINFO.read_text()], sent)
    first = public_capture("config_read", **CAPTURE_OPTIONS, limit=300)
    page = public_capture("config_read", **CAPTURE_OPTIONS, snapshot_id=first["snapshot_id"],
                          offset=first["next_offset"], content_sha256=first["content_sha256"])
    second = public_capture("config_read", **CAPTURE_OPTIONS)
    assert first["complete"] and page["complete"] and second["complete"]
    assert first["snapshot_id"] != second["snapshot_id"]
    assert first["content_sha256"] == page["content_sha256"] != second["content_sha256"]
    assert "FAKE-SECRET" not in repr((first, page, second))
    assert "[section withheld] WLAN Service" in page["untrusted_device_output"]
    diff = public_capture("config_diff", base_snapshot=first["snapshot_id"], other_snapshot=second["snapshot_id"])
    lines = diff["untrusted_device_output"].splitlines()[2:]
    assert len(lines) == 2
    assert lines[0].startswith("-") and "tik.cesnet.cz" in lines[0]
    assert lines[1].startswith("+") and "ntp.example.net" in lines[1]
    assert not diff["identical"] and not diff["hidden_lines_compared"] and not diff["secrets_changed"]
    assert sent[3::4] == ["show config", "show sysinfo"] * 2


@pytest.mark.parametrize("backup", ["", "192.0.2.2"])
def test_review_2_dhcp_keeps_all_nonempty_addresses(monkeypatch, backup):
    captured = fixture("vendor_dhcp.out").removesuffix("IP Address=\n") + f"IP Address= {backup}\n"
    unleashed(monkeypatch, [captured, SYSINFO.read_text()], [])
    wifi = read(target("dhcp_relays"), "dhcp_relays")["wifi"]
    assert wifi["complete"] and wifi["count"] == 1
    assert wifi["records"][0]["settings"]["IP Address"] == ["192.0.2.1"] + ([backup] if backup else [])


def test_review_3_radius_preserves_primary_and_secondary(monkeypatch):
    unleashed(monkeypatch, [fixture("vendor_aaa.out"), SYSINFO.read_text()], [])
    result = read(target("aaa_servers"), "aaa_servers")
    wifi = result["wifi"]
    assert wifi["complete"] and wifi["count"] == 5
    accounting, radius = wifi["records"][2:4]
    assert accounting["lists"]["Primary RADIUS Accounting"]["Port"] == "1813"
    assert accounting["lists"]["Secondary RADIUS Accounting"] == {"Status": "Disabled"}
    assert radius["lists"]["Primary RADIUS"]["IP Address"] == "192.0.2.99"
    assert "<REDACTED>" in radius["lists"]["Primary RADIUS"].values()
    assert radius["lists"]["Secondary RADIUS"] == {"Status": "Disabled"}
    assert "FAKE-SECRET" not in repr(result)


@pytest.mark.parametrize(("captured", "acl", "relay"), [
    (wlan_fixture(), "No ACLS", None),
    (wlan_fixture().replace("L2/MAC = No ACLS", "L2/MAC = allow", 1), "allow", None),
    (fixture("vendor_wlan.out"), "No ACLS", False),
    (fixture("vendor_wlan.out").replace("relay = Disabled", "relay = Enabled"), "No ACLS", True),
], ids=["r610", "assigned", "disabled", "enabled"])
def test_review_4_wlan_acl_assignment_and_relay_state(monkeypatch, captured, acl, relay):
    unleashed(monkeypatch, [captured, SYSINFO.read_text()], [])
    wlan = read(target("wlans"), "wlans")["wifi"]["records"][0]
    assert wlan["l2_mac_acl"] == acl
    assert wlan["dhcp_relay_enabled"] is relay


def test_review_5_config_cut_after_aaa_is_incomplete(monkeypatch):
    cut = fixture("show_config.out").split("\nDHCP servers for DHCP relay agent:", 1)[0]
    unleashed(monkeypatch, [cut, SYSINFO.read_text()], [])
    wifi = read(target("config_settings"), "config_settings")["wifi"]
    assert not wifi["complete"] and "SNMP Agent" in wifi["missing_sections"]


def test_review_5_unadorned_cli_refusal_is_an_error(monkeypatch):
    refusal = fixture("show_l3acl_bare_unrecognized.out").splitlines()[-1]
    unleashed(monkeypatch, [refusal, SYSINFO.read_text()], [])
    result = read(target("config_settings"), "config_settings")
    assert result["ok"] is False and result["error_code"] == "device_cli_error"


@pytest.mark.parametrize(("query", "name", "expected"), [
    ("mgmt_acls", "vendor_mgmt_acl.out", {"Restriction Type": "range", "IP range": "192.0.2.1-192.0.2.253"}),
    ("static_routes", "vendor_static_route.out", {"IP subnet": "192.0.2.1/24", "IP gateway": "198.51.100.1"}),
    ("l3_acls", "vendor_l3_acl.out", {"Destination Port": "53", "Protocol": "Any"}),
])
def test_review_6_documented_nonempty_layouts(monkeypatch, query, name, expected):
    unleashed(monkeypatch, [fixture(name), SYSINFO.read_text()], [])
    wifi = read(target(query), query)["wifi"]
    assert wifi["complete"] and not wifi["unparsed"] and wifi["count"]
    first = wifi["records"][0]
    fields = first["lists"]["Rules"][0] if query == "l3_acls" else first["settings"]
    assert {key: fields[key] for key in expected} == expected
    if query == "l3_acls":
        assert [rule["Order"] for rule in first["lists"]["Rules"]] == ["1", "2"]


@pytest.mark.parametrize(("query", "capture"), [
    ("wlans", wlan_fixture()), ("dhcp_relays", fixture("show_dhcp_all.out")),
    ("config_settings", fixture("show_config.out")),
], ids=["wlans", "dhcp", "config"])
def test_review_8_firmware_warning_on_individual_read(monkeypatch, query, capture):
    sent = []
    version = SYSINFO.read_text().replace(unleashed_version("200.15.6.212.27"), unleashed_version("200.13.2.99.12"))
    unleashed(monkeypatch, [capture, version], sent)
    result = read(target(query, "system_info"), query)
    assert result["ok"] and result["firmware_support"]["status"] == "untested"
    assert result["warnings"][0]["code"] == "firmware_untested"
    assert sent[-1] == "show sysinfo"


def test_review_9_config_fixture_uses_site_placeholders(monkeypatch):
    captured = fixture("show_config.out")
    unleashed(monkeypatch, [captured, SYSINFO.read_text()], [])
    wifi = read(target("config_settings"), "config_settings")["wifi"]
    assert wifi["complete"]
    # The AP block is withheld in the product, so also scan the input fixture.
    block = captured.split("\nAP:\n", 1)[1].split("\nSmart Redundancy:", 1)[0]
    for label, expected in (("Device Name", "ap01"), ("Description", "ap-description01"), ("Location", "site-location01")):
        assert re.findall(r"(?m)^\s*" + label + r"\s*=\s*([^\n]*)", block) == [expected]
    assert re.findall(r"(?m)^\s+NAME\s*=\s*([^\n]+)", captured)
    assert all(re.fullmatch(r"ssid\d+", name.strip())
               for name in re.findall(r"(?m)^\s+NAME\s*=\s*([^\n]+)", captured))


def test_review_1_public_incomplete_read_has_no_comparable_snapshot(monkeypatch, public_capture):
    cut = fixture("show_config.out").split("\nSNMP Agent:", 1)[0]
    unleashed(monkeypatch, [cut, SYSINFO.read_text()], [])
    result = public_capture("config_read", **CAPTURE_OPTIONS)
    assert result["ok"] is False and result["complete"] is False
    assert "SNMP Agent" in result["missing_sections"] and "snapshot_id" not in result


@pytest.mark.parametrize("tail", ["", "  Format= Version3\n"])
def test_summary_public_cut_snmp_trap_has_no_snapshot(monkeypatch, public_capture, tail):
    # Cut the measured R610 capture inside its last allowlisted SNMP Trap block.
    cut = fixture("show_config.out").rsplit("\nSNMP Trap:\n", 1)[0] + "\nSNMP Trap:\n" + tail
    unleashed(monkeypatch, [cut], [])
    result = public_capture("config_read", **CAPTURE_OPTIONS)
    assert result["ok"] is False and result["complete"] is False
    assert "SNMP Trap" in result["missing_sections"] and "snapshot_id" not in result


def test_summary_public_l2_acl_reads_documented_colon_restriction(monkeypatch, public_ruckus):
    # Measured R610 listing with the Restriction delimiter from the 200.15 guide, pp. 77–78.
    capture = fixture("show_l2acl_all.out").replace("Restriction=", "Restriction:")
    unleashed(monkeypatch, [capture], [])
    result = public_ruckus("l2_acls")("ssh_read", query="l2_acls")["wifi"]
    assert result["complete"] and result["unparsed"] == []
    acl = next(record for record in result["records"] if record["name"] == "allow")
    assert acl["settings"]["Restriction"] == "Allow only the stations listed below"
    assert len(acl["lists"]["Stations"]) == 36


def test_review_1_public_config_rejects_unsupported_options_without_ssh(monkeypatch, public_capture):
    sent = []
    unleashed(monkeypatch, [], sent)
    for options, field in [
        ({"include_all": False}, "include_all"),
        ({"include_defaults": True}, "include_defaults"),
        ({"redaction": "minimal"}, "redaction"),
        ({"section": "system interface"}, "section"),
    ]:
        error = public_capture("config_read", error=True, **(CAPTURE_OPTIONS | options))
        assert error["data"]["field"] == field
    error = public_capture("config_diff", error=True, base_snapshot="baseline", other_snapshot="cfg_" + "a" * 32)
    assert error["data"]["field"] == "base_snapshot"
    assert sent == []


def test_review_8_failed_firmware_probe_keeps_main_read(monkeypatch):
    sent = []
    refusal = fixture("show_l3acl_bare_unrecognized.out").splitlines()[-1]
    unleashed(monkeypatch, [fixture("show_dhcp_all.out"), refusal], sent)
    result = read(target("dhcp_relays", "system_info"), "dhcp_relays")
    assert result["ok"] and result["wifi"]["count"] == 0
    assert result["firmware_support"]["status"] == "unknown" and result["warnings"]
    assert sent[3::4] == ["show dhcp all", "show sysinfo"]
    assert "could not be read" in result["warnings"][0]["message"]


def _read_config(auth, **options):
    return engine.config_read(auth, "ruckus_unleashed", "all", True, redaction="full", **options)


@pytest.fixture
def snapshot_target(monkeypatch):
    from collections import OrderedDict
    from netops_helper import configuration
    from netops_helper.auth import EgressPolicy

    monkeypatch.setattr(configuration, "_SNAPSHOTS", OrderedDict())
    auth = target("config_settings")
    return dataclasses.replace(auth, read_inventory={"config_access": ("read",)},
                               egress=EgressPolicy(addresses=(auth.host,), tcp_ports=(auth.port,)))


def test_ruckus_snapshot_transport_failure_keeps_no_configuration(snapshot_target, monkeypatch):
    from netops_helper import configuration

    closed = []

    class Disconnected:
        def __init__(self, *args, **kwargs):
            self.session = base_session(*args, **kwargs)

        def __getattr__(self, name):
            return getattr(self.session, name)

        def send(self, command):
            if command == "show config":
                raise engine.core_session.SessionError("fixture private detail", code="disconnected")
            self.session.send(command)

        def close(self):
            closed.append(True)
            self.session.close()

    unleashed(monkeypatch, [], [])
    base_session = engine.core_session.Session
    monkeypatch.setattr(engine.core_session, "Session", Disconnected)
    result = _read_config(snapshot_target)
    assert not result["ok"] and not result["complete"] and result["error_code"] == "disconnected"
    assert "untrusted_device_output" not in result and "fixture private detail" not in str(result)
    assert closed == [True] and not configuration._SNAPSHOTS


def test_ruckus_snapshot_checks_byte_limit_after_ascii_escaping(snapshot_target, monkeypatch):
    from netops_helper import configuration
    from netops_helper.config_limits import ConfigurationLimits

    capture = fixture("show_config.out").replace("tik.cesnet.cz", "é" * 9000)
    limit = len(capture.encode()) + 64
    auth = dataclasses.replace(snapshot_target, configuration_limits=ConfigurationLimits(
        section_bytes=4096, all_bytes=limit, physical_line_bytes=1024, logical_record_bytes=4096))
    unleashed(monkeypatch, [capture], [])
    result = _read_config(auth)
    assert not result["ok"] and result["error_code"] == "incomplete_output"
    assert result["error"] == "The redacted configuration exceeds its capture limit"
    assert "untrusted_device_output" not in result and not configuration._SNAPSHOTS


def test_ruckus_snapshot_is_discarded_when_filtered_view_cannot_be_read(snapshot_target, monkeypatch):
    from netops_helper import configuration
    from netops_helper.config_buffers import Content

    def unavailable(self):
        assert len(configuration._SNAPSHOTS) == 1
        raise OSError("fixture backing storage unavailable")

    capture = fixture("show_config.out")
    sent = []
    unleashed(monkeypatch, [capture, capture], sent)
    with monkeypatch.context() as fault:
        fault.setattr(Content, "lines", unavailable)
        with pytest.raises(OSError, match="fixture backing storage unavailable"):
            _read_config(snapshot_target, contains="Address")
    assert not configuration._SNAPSHOTS
    result = _read_config(snapshot_target, contains="Address")
    assert result["ok"] and result["snapshot_id"] in configuration._SNAPSHOTS
    assert "Address= tik.cesnet.cz" in result["untrusted_device_output"]
    assert sent[3::4] == ["show config", "show config"]
