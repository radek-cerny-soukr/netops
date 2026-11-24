"""IPSEC-STATUS (1.0.12, FP-09): FortiOS IPsec tunnel detail (phase 1/2, selectors, counters, DPD) with key redaction.

Device text comes from tests/fixtures/real/fortios/fg60f_7.6.8_ipsec_ipsec_status_20261118 (PROVENANCE.md): the exec output a
read-only account received from the lab FortiGate-60F 7.6.8 build 3744 for the permanent test tunnel `netops-ipsec`
(up, peer strongSwan) and `netops-ipsec-dn` (peer never answers). The device printed live IKE/ESP keys; at capture
every key VALUE was replaced by synthetic hex of the same shape (DERIVED positions), everything else is the real
text, anonymised with tests/support/anonymize_fixture.py. Cases marked DERIVED change that text.

The public cases drive the real Proxy.request -> auth_context -> TargetAuth.decode -> engine.ssh_read /
engine.triage_vpn chain; only the SSH edge (engine._exec_command) and the keyscan (engine.host_key_line) are
replaced, so prompt cleaning, redaction, hashing, paging, parsing and audit run unmodified.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import itertools
import json
from pathlib import Path
import re

import pytest

from netops_core import prompt as core_prompt
from netops_core import ssh as core_ssh
from netops_core.audit import Recorder

import netops_helper.audit as audit
import netops_helper.engine as engine
from netops_helper import proxy as proxy_module
from netops_helper import triage_vpn as t
from netops_helper.auth import TargetAuth
from netops_helper.sanitize import redact_fortios_ipsec_keys
import test_proxy_contracts as c

FIXTURES = Path(__file__).parent / "fixtures" / "real" / "fortios" / "fg60f_7.6.8_ipsec_ipsec_status_20261118"
UP, DOWN = "netops-ipsec", "netops-ipsec-dn"
PORT = 2222


def real(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


OUTPUTS = {
    "get system status": "01-system-status.out",
    "get vpn ipsec tunnel summary": "02-ipsec-summary.out",
    "get router info routing-table all": "03-routing-table.out",
    "diagnose vpn ike errors": "04-ike-errors.out",
    f"diagnose vpn ike gateway list name {UP}": "05-ike-gateway-up.out",
    f"diagnose vpn tunnel list name {UP}": "06-tunnel-list-up.out",
    f"diagnose vpn ike gateway list name {DOWN}": "07-ike-gateway-down.out",
    f"diagnose vpn tunnel list name {DOWN}": "08-tunnel-list-down.out",
}
KEYED = ("05-ike-gateway-up.out", "06-tunnel-list-up.out", "11-tunnel-details.out")


def key_values(text: str) -> set[str]:
    """The key values of a capture (SK_*, key=<n> <hex>, enc/auth <alg> <hex>) as bare hex digits."""
    found = (re.findall(r"(?m)^\s*SK_\w+:\s*(\S+)", text) + re.findall(r"key=\d+ ([0-9a-f]+)", text)
             + re.findall(r"(?m)^\s*(?:enc|auth):\s+\S+\s+([0-9a-f]{8,})", text))
    return {value.replace("-", "") for value in found}


ALL_KEYS = set().union(*(key_values(real(name)) for name in KEYED))


def leaked(text: str) -> list[str]:
    """Any 12-digit piece of a key value, also across the `-` separators of the IKE keys."""
    bare = re.sub(r"[^0-9a-f]", "", text.lower())
    return sorted(value for value in ALL_KEYS if any(value[i:i + 12] in bare for i in range(len(value) - 11)))


def cleaned(name: str) -> str:
    """What the exec transport hands on: CRLF normalized, first prompt and trailing prompts removed."""
    return core_prompt.cleaned(real(name).replace("\r\n", "\n"), "fortinet")


# ---- provenance and the measured shapes --------------------------------------------------------------------------
def test_fixtures_are_the_documented_capture():
    provenance = (FIXTURES / "PROVENANCE.md").read_text(encoding="utf-8")
    files = sorted(path.name for path in FIXTURES.glob("*.out"))
    assert len(files) == 11
    for name in files:
        digest = hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest()
        assert f"{name} {digest}" in provenance, name


def test_the_device_prints_ike_and_esp_keys_even_to_a_read_only_account():
    # Measured: both IKE SAs of the gateway list carry SK_ei/er/ai/ar, both SAs of the proxyid carry two ESP and
    # two auth keys, and `get vpn ipsec tunnel details` prints enc/auth keys too (reason for the exclusion below).
    assert len(key_values(real("05-ike-gateway-up.out"))) == 8
    assert len(key_values(real("06-tunnel-list-up.out"))) == 8
    assert len(key_values(real("11-tunnel-details.out"))) == 8
    assert all(len(value) >= 64 for value in ALL_KEYS)


# ---- redaction ---------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("name", KEYED)
def test_redaction_withholds_every_key_value_and_keeps_every_other_line(name):
    text = real(name)
    redacted = redact_fortios_ipsec_keys(text)
    assert leaked(text) and not leaked(redacted)
    before, after = text.splitlines(), redacted.splitlines()
    assert len(before) == len(after)
    changed = [(old, new) for old, new in zip(before, after) if old != new]
    assert len(changed) == {"05-ike-gateway-up.out": 8, "06-tunnel-list-up.out": 8, "11-tunnel-details.out": 8}[name]
    for old, new in changed:
        assert new.endswith("<REDACTED>") and new[:new.index("<REDACTED>")] == old[:new.index("<REDACTED>")]
    # SPIs and IKE cookies are not keys; the parser and the operator need them.
    assert re.findall(r"spi[=:] ?([0-9a-f]{8})", text) == re.findall(r"spi[=:] ?([0-9a-f]{8})", redacted)


@pytest.mark.parametrize("line,expected", [
    # DERIVED forms: short values, another SK label, an unknown label holding a long key, a split key.
    ("  dec: spi=0a0b0c0d esp=aes key=16 0123", "  dec: spi=0a0b0c0d esp=aes key=16 <REDACTED>"),
    ("  SK_d: 00ff", "  SK_d: <REDACTED>"),
    ("  PPK-secret: " + "ab" * 32, "  PPK-secret: <REDACTED>"),
    ("  material " + " ".join(["a1b2"] * 16), "  material <REDACTED>"),
    ("        enc:  aes-cb  " + "9f" * 8, "        enc:  aes-cb  <REDACTED>"),
    # not keys: an IKE cookie pair, an SPI, counters and a selector stay
    ("  id/spi: 8 0123456789abcdef/fedcba9876543210", "  id/spi: 8 0123456789abcdef/fedcba9876543210"),
    ("  dec:pkts/bytes=1/84, enc:pkts/bytes=4/336", "  dec:pkts/bytes=1/84, enc:pkts/bytes=4/336"),
    ("       seqno=5 esn=0 replaywin_lastseq=00000001 qat=0 rekey=0 hash_search_len=1",
     "       seqno=5 esn=0 replaywin_lastseq=00000001 qat=0 rekey=0 hash_search_len=1"),
])
def test_redaction_of_derived_short_unknown_and_harmless_forms(line, expected):
    assert redact_fortios_ipsec_keys(line + "\n") == expected + "\n"


# ---- parsers on the real text ------------------------------------------------------------------------------------
def test_ike_gateway_of_the_up_tunnel():
    (gateway,) = t.ike_gateway_detail(redact_fortios_ipsec_keys(cleaned("05-ike-gateway-up.out")))
    assert {key: gateway[key] for key in ("name", "version", "interface", "local", "peer", "created")} == {
        "name": UP, "version": "2", "interface": "PVE-MGMT", "local": "192.0.2.1:4500", "peer": "192.0.2.20:4500",
        "created": "298s ago"}
    assert gateway["ike_sa"] == {"created": [2, 2], "established": [2, 2]}
    assert gateway["ipsec_sa"] == {"created": [2, 2], "established": [2, 2]}
    assert [(sa["direction"], sa["status"].split()[0], sa["proposal"]) for sa in gateway["sas"]] == [
        ("responder", "established", "aes256-sha256"), ("initiator", "established", "aes256-sha256")]
    assert gateway["sas"][0]["dpd_sent_recv"] == "00000000/00000000"
    assert not leaked(json.dumps(gateway))


@pytest.mark.parametrize("name", ["07-ike-gateway-down.out", "10-ike-gateway-unknown.out"])
def test_no_ike_sa_prints_nothing(name):
    assert cleaned(name).strip() == ""
    assert t.ike_gateway_detail(cleaned(name)) == []


def test_tunnel_list_of_the_up_tunnel_sums_both_sas_of_the_selector():
    (tunnel,) = t.ipsec_tunnel_detail(redact_fortios_ipsec_keys(cleaned("06-tunnel-list-up.out")))
    assert tunnel == {
        "name": UP, "status": "up", "local": "192.0.2.1:0", "peer": "192.0.2.20:0", "proxyid_num": 1,
        "rx_packets": 1, "tx_packets": 4, "rx_bytes": 84, "tx_bytes": 336, "dpd_status": "ok",
        "nat_traversal": "none",
        "selectors": [{"name": UP, "sa": 2, "src": "0:203.0.113.253-203.0.113.253:0",
                       "dst": "0:203.0.113.252-203.0.113.252:0", "dec_packets": 1, "dec_bytes": 84,
                       "enc_packets": 4, "enc_bytes": 336}]}


def test_tunnel_list_of_the_down_tunnel_and_of_an_unknown_name():
    (tunnel,) = t.ipsec_tunnel_detail(cleaned("08-tunnel-list-down.out"))
    assert (tunnel["status"], tunnel["dpd_status"], tunnel["peer"], tunnel["tx_packets"]) == (
        "down", "fail", "192.0.2.251:0", 0)
    assert tunnel["selectors"] == [{"name": DOWN, "sa": 0, "src": "0:203.0.113.253-203.0.113.253:0",
                                    "dst": "0:203.0.113.244-203.0.113.244:0", "dec_packets": 0, "dec_bytes": 0,
                                    "enc_packets": 0, "enc_bytes": 0}]
    # Measured: an unknown name gives the header line only.
    assert cleaned("09-tunnel-list-unknown.out").strip() == "list ipsec tunnel by names in vd 0"
    assert t.ipsec_tunnel_detail(cleaned("09-tunnel-list-unknown.out")) == []


@pytest.mark.parametrize("parser,text", [
    # DERIVED: missing header, an unknown line, a proxyid count that does not match, a gateway SA without status,
    # a free-text gateway line, SA lines before any gateway.
    (t.ipsec_tunnel_detail, cleaned("06-tunnel-list-up.out").replace("list ipsec tunnel by names in vd 0", "")),
    (t.ipsec_tunnel_detail, cleaned("06-tunnel-list-up.out") + "some free text\n"),
    (t.ipsec_tunnel_detail, cleaned("06-tunnel-list-up.out").replace("proxyid_num=1", "proxyid_num=2")),
    (t.ipsec_tunnel_detail, cleaned("06-tunnel-list-up.out").replace("stat: rxp=1", "stat: rx=1")),
    (t.ike_gateway_detail, re.sub(r"(?m)^  status: .*\n", "", cleaned("05-ike-gateway-up.out"))),
    (t.ike_gateway_detail, cleaned("05-ike-gateway-up.out") + "unexpected words\n"),
    (t.ike_gateway_detail, "  direction: initiator\n"),
])
def test_unknown_or_incomplete_shapes_are_unparsed(parser, text):
    with pytest.raises(t.Unparsed):
        parser(text)


# ---- the public paths --------------------------------------------------------------------------------------------
ALL_ENABLED = ["system_status", "ipsec_summary", "routing_table", "ike_errors", "ike_gateway_detail",
               "ipsec_tunnel_detail"]


@pytest.fixture()
def wire(tmp_path, monkeypatch, request):
    """The real proxy with one enrolled FortiGate; only the SSH exec and keyscan are replaced."""
    inventory, _, _, _ = c._configure(proxy_module, tmp_path)
    section = c._section()
    options = getattr(request, "param", {})
    if isinstance(options, list):
        options = {"queries": options}
    section.update(ssh_platform="fortios", device_types=["firewall"],
                   enabled_queries=options.get("queries", ALL_ENABLED),
                   rate_limit={"requests": options.get("requests", 60), "window_seconds": 60})
    section["read_inventory"].update(ipsec_tunnels=options.get("tunnels", [UP, DOWN]))
    device = c._device(section, "fortios")
    device["port"] = PORT
    c._write(inventory, c._inventory(device))
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "_RECORDER", Recorder(audit_path, "helper"))
    monkeypatch.setattr(engine, "record", audit.record)
    sent, overrides = [], {}

    def edge(auth, address, known_hosts_line, credential, command, platform, stdout_consumer=None):
        assert stdout_consumer is None and known_hosts_line == "pinned-host-key"
        sent.append(command)
        if command not in OUTPUTS:
            pytest.fail("unexpected device command " + command)
        return core_ssh.Result(rc=0, stdout=overrides.get(command, real(OUTPUTS[command])).encode("utf-8"),
                               said="", started_at="",
                               finished_at="")

    monkeypatch.setattr(engine, "_exec_command", edge)
    monkeypatch.setattr(engine, "host_key_line", lambda auth, address=None, platform=None: "pinned-host-key")
    proxy = proxy_module.Proxy()
    emitted = []
    proxy._emit = emitted.append
    identifiers = itertools.count(1)

    def call(tool, arguments):
        forwarded = proxy.request(c._request(next(identifiers), tool, {"target": "device-a", **arguments}))
        if forwarded is None:
            return None
        args = json.loads(forwarded)["params"]["arguments"]
        context = args.pop("auth_context")
        auth = TargetAuth.decode(args.pop("target"), context)
        values = args.pop("redaction_context", None)
        if values is not None:
            auth = replace(auth, output_secrets=tuple(dict.fromkeys((context, *values))))
        if options.get("output_secrets"):
            auth = replace(auth, output_secrets=(*auth.output_secrets, *options["output_secrets"]))
        if tool == "ssh_read":
            return engine.ssh_read(auth, args["platform"], args["query"], args.get("parameters"),
                                   args.get("offset", 0), args.get("max_bytes", 16_000), args.get("content_sha256"))
        return engine.triage_vpn(auth, args["tunnel"])

    call.sent, call.emitted, call.audit, call.overrides = sent, emitted, audit_path, overrides
    return call


def _read(wire, query, tunnel, **extra):
    return wire("ssh_read", {"platform": "fortios", "query": query, "parameters": {"tunnel": tunnel}, **extra})


@pytest.mark.parametrize("query,expected", [("ike_gateway_detail", 8), ("ipsec_tunnel_detail", 8)])
def test_ssh_read_returns_the_detail_without_any_key(wire, query, expected):
    result = _read(wire, query, UP)
    assert result["ok"] is True and result["complete"] is True
    assert result["firmware_support"]["status"] == "tested"
    assert wire.sent[-1] == {"ike_gateway_detail": "diagnose vpn ike gateway list name ",
                             "ipsec_tunnel_detail": "diagnose vpn tunnel list name "}[query] + UP
    output = result["untrusted_device_output"]
    assert output.count("<REDACTED>") == expected and "spi" in output
    assert result["content_sha256"] == hashlib.sha256(output.encode("utf-8")).hexdigest()
    assert not leaked(json.dumps(result)) and not leaked(wire.audit.read_text())


def test_every_page_of_a_paged_detail_is_without_keys(wire):
    first = _read(wire, "ipsec_tunnel_detail", UP, max_bytes=1000)
    pages, result = [first["untrusted_device_output"]], first
    while result["next_offset"] is not None:
        result = _read(wire, "ipsec_tunnel_detail", UP, max_bytes=1000, offset=result["next_offset"],
                       content_sha256=first["content_sha256"])
        pages.append(result["untrusted_device_output"])
    assert len(pages) >= 2 and not any(leaked(page) for page in pages)
    assert not leaked("".join(pages)) and "".join(pages).count("<REDACTED>") == 8


def test_a_tunnel_that_is_not_enrolled_is_refused_before_the_device(wire):
    assert _read(wire, "ike_gateway_detail", "other-tunnel") is None
    assert wire.emitted and wire.sent == []


def test_triage_vpn_reads_phase_1_and_2_of_the_up_tunnel(wire):
    result = wire("triage_vpn", {"tunnel": UP})
    assert wire.sent[1:] == ["get vpn ipsec tunnel summary", "get router info routing-table all",
                             "diagnose vpn ike errors", "diagnose vpn ike gateway list name " + UP,
                             "diagnose vpn tunnel list name " + UP]
    assert result["verdict"] == "no_fault_in_checked_data" and result["findings"] == []
    detail = result["chain"]["detail"]
    assert detail["status"] == "read" and detail["phase1"][0]["ike_sa"]["established"] == [2, 2]
    assert detail["phase2"][0]["selectors"][0]["sa"] == 2 and detail["phase2"][0]["dpd_status"] == "ok"
    assert result["checked"][-2:] == ["ike_gateway_detail", "ipsec_tunnel_detail"]
    assert result["identity"] == {"product": "FortiGate-60F", "version": "7.6.8", "build": "3744"}
    assert not leaked(json.dumps(result)) and not leaked(wire.audit.read_text())


def test_triage_vpn_names_the_missing_phase_1_of_the_down_tunnel(wire):
    result = wire("triage_vpn", {"tunnel": DOWN})
    assert [item["id"] for item in result["findings"]] == ["F-VPN-DOWN", "F-VPN-ERRORS", "F-VPN-NO-ROUTE",
                                                          "F-VPN-IKE-DOWN"]
    ike = result["findings"][-1]
    assert ike["fact"] == ("no established IKE SA (phase 1) for netops-ipsec-dn; tunnel status=down, dpd status=fail, "
                           "selectors with SA 0/1")
    assert [source["query"] for source in ike["sources"]] == ["ike_gateway_detail", "ipsec_tunnel_detail"]
    assert result["chain"]["detail"]["phase1"] == [] and result["verdict"] == "fault_found"


@pytest.mark.parametrize("wire", [ALL_ENABLED[:4]], indirect=True)
def test_triage_vpn_without_the_detail_queries_keeps_the_summary_verdict(wire):
    result = wire("triage_vpn", {"tunnel": UP})
    assert result["chain"]["detail"] == {
        "status": "not_enrolled", "phase1": None, "phase2": None,
        "last_error": {"status": "unavailable", "reason": "detail_not_enrolled"},
    }
    assert result["verdict"] == "no_fault_in_checked_data" and result["missing"] == []
    assert not any("diagnose vpn ike gateway" in command or "tunnel list" in command for command in wire.sent)


def test_triage_vpn_detail_failure_is_incomplete_not_clean(wire, monkeypatch):
    original = engine._exec_command

    def refuse(auth, address, known_hosts_line, credential, command, platform, stdout_consumer=None):
        if command.startswith("diagnose vpn tunnel list"):
            return core_ssh.Result(rc=0, stdout=b"Command fail. Return code -37\n", said="", started_at="",
                                   finished_at="")
        return original(auth, address, known_hosts_line, credential, command, platform, stdout_consumer)

    monkeypatch.setattr(engine, "_exec_command", refuse)
    result = wire("triage_vpn", {"tunnel": UP})
    assert {"step": "ipsec_tunnel_detail", "reason": "device_cli_error"} in result["missing"]
    assert result["verdict"] == "incomplete" and result["chain"]["detail"]["phase2"] is None


# R2 regressions. DERIVED variants below change only the indicated lines of the measured captures.
def test_r2_redacts_labeled_keys_before_hash_paging_and_parsing(wire):
    query = "ike_gateway_detail"
    command = f"diagnose vpn ike gateway list name {UP}"
    original = real(OUTPUTS[command])
    lines = [
        ("  enc key: ", "0123456789abcdef"),
        ("  auth key=", "b"),
        ("  enc key = ", "c" * 120),
        ("  auth key:", "two words"),
        ("  PSK: ", "synthetic PSK with spaces"),
        ("  psksecret = ", '"synthetic quoted passphrase" synthetic-suffix'),
        ("  psksecret ", "ENC synthetic cipher"),
    ]
    anchor = "  id/spi:"

    def insert(values):
        return original.replace(anchor, values + anchor, 1)

    wire.overrides[command] = insert("".join(f"{label}{value}\n" for label, value in lines))
    first = _read(wire, query, UP, max_bytes=1000)
    pages, result = [first["untrusted_device_output"]], first
    while result["next_offset"] is not None:
        result = _read(wire, query, UP, max_bytes=1000, offset=result["next_offset"],
                       content_sha256=first["content_sha256"])
        assert result["pagination_source"] == "cached"
        pages.append(result["untrusted_device_output"])
    output = "".join(pages)
    assert len(pages) > 1
    for label, _ in lines:
        # The existing general response floor also masks the suffix of an assignment label psksecret.
        expected = "  psk[REDACTED]" if label == "  psksecret = " else f"{label}<REDACTED>"
        assert expected in output.splitlines(), label
    assert wire.sent.count(command) == 1
    assert first["content_sha256"] == hashlib.sha256(output.encode("utf-8")).hexdigest()
    triage = wire("triage_vpn", {"tunnel": UP})
    assert triage["chain"]["detail"]["status"] == "read" and query in triage["checked"]


@pytest.mark.parametrize("wire", [{"tunnels": [UP]}], indirect=True)
def test_r2_vpn_triage_enforces_the_same_tunnel_scope_as_ssh_read(wire):
    assert _read(wire, "ike_gateway_detail", DOWN) is None
    direct_error = wire.emitted[-1]["error"]
    assert wire("triage_vpn", {"tunnel": DOWN}) is None
    assert wire.emitted[-1]["error"] == direct_error
    assert wire.sent == []


@pytest.mark.parametrize("query,command,phase,keep", [
    ("ike_gateway_detail", f"diagnose vpn ike gateway list name {UP}", "phase1",
     lambda line: not line.startswith("  ")),
    ("ipsec_tunnel_detail", f"diagnose vpn tunnel list name {UP}", "phase2",
     lambda line: "dec:pkts/bytes=" not in line),
    ("ipsec_tunnel_detail", f"diagnose vpn tunnel list name {UP}", "phase2",
     lambda line: "dec:pkts/bytes=0/0" not in line),
])
def test_r2_tunnel_detail_flags_truncated_sa_blocks(wire, query, command, phase, keep):
    wire.overrides[command] = "".join(line for line in real(OUTPUTS[command]).splitlines(keepends=True) if keep(line))
    result = wire("triage_vpn", {"tunnel": UP})
    assert {"step": query, "reason": "unparsed"} in result["missing"]
    assert result["chain"]["detail"]["status"] == result["verdict"] == "incomplete"
    assert result["chain"]["detail"][phase] is None
    other_phase = "phase2" if phase == "phase1" else "phase1"
    assert result["chain"]["detail"][other_phase]
    assert not result["findings"]


def test_r2_triage_distinguishes_missing_last_error_from_global_ike_counters(wire):
    result = wire("triage_vpn", {"tunnel": DOWN})
    assert result["chain"]["ike_errors"]["nonzero"]
    assert result["chain"]["detail"]["last_error"] == {
        "status": "unavailable", "reason": "not_reported_by_fortios",
    }


@pytest.mark.parametrize("wire", [
    {"queries": ALL_ENABLED[:4], "requests": 4},
    {"queries": ALL_ENABLED[:5], "requests": 5},
    {"queries": [ALL_ENABLED[0], ALL_ENABLED[1], ALL_ENABLED[4]], "requests": 3},
], indirect=True)
def test_r2_triage_reserves_only_enabled_vpn_reads(wire):
    result = wire("triage_vpn", {"tunnel": UP})
    assert result is not None and result["ok"]
    assert result["checked"] == [query for query, command in zip(ALL_ENABLED, list(OUTPUTS)[:6])
                                 if command in wire.sent]
    assert wire("triage_vpn", {"tunnel": UP}) is None
    assert wire.emitted[-1]["error"]["data"]["category"] == "rate_limit"


@pytest.mark.parametrize("wire", [{
    "queries": [query for query in ALL_ENABLED if query != "ipsec_summary"], "requests": 3,
}], indirect=True)
def test_triage_without_summary_does_not_reserve_detail_reads(wire):
    result = wire("triage_vpn", {"tunnel": UP})
    assert result is not None and result["verdict"] == "incomplete"
    assert len(wire.sent) == 3
    assert all(" list name " not in command for command in wire.sent)


@pytest.mark.parametrize("wire", [{"output_secrets": ("v7.6.8",)}], indirect=True)
def test_detail_firmware_uses_verified_identity_before_output_redaction(wire):
    result = _read(wire, "ike_gateway_detail", UP)
    assert result["ok"] and result["firmware_support"]["status"] == "tested"
    assert "v7.6.8" not in json.dumps(result)


@pytest.mark.parametrize("query", ALL_ENABLED[4:])
def test_r2_detail_firmware_is_untested_and_survives_paging(wire, query):
    wire.overrides["get system status"] = real("01-system-status.out").replace(
        "FortiGate-60F v7.6.8,build3744", "FortiGate-80F v8.0.2,build0251")
    first = _read(wire, query, UP, max_bytes=1000)
    follow = _read(wire, query, UP, max_bytes=1000, offset=first["next_offset"],
                   content_sha256=first["content_sha256"])
    assert first["firmware_support"]["status"] == "untested"
    assert follow["firmware_support"] == first["firmware_support"]
    assert follow["warnings"] == first["warnings"]
    assert first["warnings"][0]["code"] == "firmware_untested"


def test_r2_triage_firmware_for_details_is_distinct_from_summary(wire):
    wire.overrides["get system status"] = real("01-system-status.out").replace(
        "FortiGate-60F v7.6.8,build3744", "FortiGate-80F v8.0.2,build0251")
    result = wire("triage_vpn", {"tunnel": UP})
    assert result["chain"]["detail"]["status"] == "read"
    assert result["firmware_support"]["status"] == "untested"
    assert result["warnings"][0]["code"] == "firmware_untested"


@pytest.mark.parametrize("wire", [ALL_ENABLED[:4]], indirect=True)
def test_r2_previously_tested_summary_identity_remains_tested(wire):
    wire.overrides["get system status"] = real("01-system-status.out").replace(
        "FortiGate-60F v7.6.8,build3744", "FortiGate-80F v8.0.2,build0251")
    assert wire("triage_vpn", {"tunnel": UP})["firmware_support"]["status"] == "tested"
