"""FortiOS IPv6 route lookup `ipv6_route_lookup` and its route records (verification-09-83).

Device text comes only from the real, anonymised FortiGate-60F 7.6.8 build 3744 capture in
tests/fixtures/real/fortios/fg60f_7.6.8_ipv6_20261114 (VDOM disabled/root, IPv6 VRF 0):
03 is the connected loopback ::1/128 (not a forwarding route), 04 the explicit "% Network not in table".
Every case that changes that text, or replays it for another command, is marked DERIVED below; derived
cases are parser/contract checks, not a new live measurement or hardware qualification.

The public cases drive the real Proxy.request -> auth_context -> TargetAuth.decode -> engine.ssh_read /
engine.switch_read chain. Only the SSH edge is replaced: engine._exec_command (the OpenSSH exec) and
engine.host_key_line (the keyscan). Tables, parser, rendering, policy and redaction run unmodified.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import itertools
import json
from pathlib import Path
import re

import pytest

from netops_core import ssh as core_ssh
from netops_core.audit import Recorder

import netops_helper.audit as audit
import netops_helper.engine as engine
from netops_helper import proxy as proxy_module
from netops_helper import read_policy, route_ipv6, switch_managed, tables
from netops_helper.auth import TargetAuth
from netops_helper.query_catalog import READ_QUERIES
from netops_helper.query_catalog.model import Slot
import test_proxy_contracts as c

FIXTURES = Path(__file__).parent / "fixtures" / "real" / "fortios" / "fg60f_7.6.8_ipv6_20261114"
FILES = ("01-version.txt", "02-ipv6-routing-table.txt", "03-lookup-loopback.txt",
         "04-lookup-documentation-address.txt")
LOOPBACK = "::1"
NO_ROUTE_ADDRESS = "2001:db8:ffff:ffff::dead"
ENROLLED_PREFIX = "2001:db8:ffff:ffff::/64"
COMMAND = "get router info6 routing-table {}"
CONNECTED = {"prefix": "::1/128", "next_hop": None, "interface": "root", "protocol": "connected", "vrf": "default"}
PORT = 2222


def real(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


LOOKUP_03 = real("03-lookup-loopback.txt")
LOOKUP_04 = real("04-lookup-documentation-address.txt")


def parse(text: str, **options) -> dict:
    return tables.parse("fortinet", "route", "ipv6_route_lookup", text, **options)


# ---- provenance and identity of the sample ---------------------------------------------------------------------------
def test_fixtures_are_the_unchanged_provenance_capture():
    provenance = real("PROVENANCE.md")
    for name in FILES:
        digest = hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest()
        assert re.search(r"(?m)^" + re.escape(name) + " " + digest + "$", provenance), name
    version = real("01-version.txt")
    assert "Version: FortiGate-60F v7.6.8,build3744,260929 (GA.M)" in version
    assert "Virtual domain configuration: disable" in version and "Current virtual domain: root" in version
    # The only IPv6 route of the sampled table is the connected loopback; no forwarding route was measured.
    table = real("02-ipv6-routing-table.txt")
    assert "Routing table for VRF=0" in table
    assert re.findall(r"(?m)^[A-Z]\S*\s+\S+/\d+ via", table) == ["C       ::1/128 via"]


# ---- catalogue, policy and binding ------------------------------------------------------------------------------------
def test_query_is_one_typed_ipv6_lookup_not_the_ipv4_details_command():
    query = READ_QUERIES["fortinet"]["ipv6_route_lookup"]
    assert query.command == "get router info6 routing-table {address}"
    assert "details" not in query.command and "info routing-table" not in query.command
    assert dict(query.slots) == {"address": Slot("addresses", "ipv6_lookup")}
    assert query.high_volume is False and query.group is None and query.pty is False
    assert query.command in read_policy._FORTINET_COMMANDS
    assert "ipv6_route_lookup" in proxy_module.READ_QUERY_NAMES["fortinet"]
    assert proxy_module.READ_QUERY_SLOTS["fortinet"]["ipv6_route_lookup"] == {
        "address": {"inventory": "addresses", "kind": "ipv6_lookup"}}
    # The IPv4 lookup is unchanged.
    ipv4 = READ_QUERIES["fortinet"]["route_lookup"]
    assert ipv4.command == "get router info routing-table details {address}"
    assert dict(ipv4.slots) == {"address": Slot("addresses", "ipv4_lookup")}


def test_render_uses_the_existing_ipv6_lookup_contract():
    inventory = {"addresses": (LOOPBACK, "192.0.2.20"), "lookup_prefixes": (ENROLLED_PREFIX,)}
    render = lambda value: read_policy.render_read_query("fortinet", "ipv6_route_lookup", {"address": value}, inventory)
    assert render(LOOPBACK) == ("fortinet", COMMAND.format(LOOPBACK))
    # A prefix inside the enrolled lookup prefix stands for its network address.
    assert render(ENROLLED_PREFIX) == ("fortinet", COMMAND.format("2001:db8:ffff:ffff::"))
    assert render(NO_ROUTE_ADDRESS + "/128") == ("fortinet", COMMAND.format(NO_ROUTE_ADDRESS))
    for value in ("192.0.2.20", "2001:db8::2", "2001:db8:fffe::/64", "::/0", "::1/128", "0:0::1", "::1 detail",
                  "::1;get system status", "::1\nget system status", "fe80::1%port1", "::ffff:192.0.2.20", ""):
        with pytest.raises(ValueError):
            render(value)


def test_route_v6_binding_and_unchanged_ipv4_route_requests():
    assert tables.BINDINGS["fortinet"]["route_v6"] == "ipv6_route_lookup"
    assert tables.BINDINGS["fortinet"]["route"] == "route_lookup"
    assert tables.BINDINGS["fortinet"]["route_all"] == "routing_table"
    assert tables.request("fortinet", "route", ip=LOOPBACK) == ("ipv6_route_lookup", {"address": LOOPBACK}, {})
    assert tables.request("fortinet", "route", ip="192.0.2.20") == ("route_lookup", {"address": "192.0.2.20"}, {})
    # Without an ip the existing IPv4 table stays; no whole IPv6 RIB is offered.
    assert tables.request("fortinet", "route") == ("routing_table", {}, {})
    assert "route_v6" not in switch_managed.supported_tables()
    assert tables.QUERY_PARSERS[("fortinet", "route", "ipv6_route_lookup")] is route_ipv6.routes
    assert tables.QUERY_PARSERS[("fortinet", "route", "route_lookup")] is not route_ipv6.routes


def test_ipv4_lookup_records_are_unchanged():
    # Existing FG-80F 8.0.2 IPv4 lookup fixture, through the IPv4 binding only.
    text = (Path(__file__).parent / "fixtures" / "fortios_80f_802_routing_route_bgp_connected.txt").read_text()
    assert tables.parse("fortinet", "route", "route_lookup", text)["records"] == switch_managed.routes(
        "route", text, lookup=True)[0]


# ---- the two real answers -------------------------------------------------------------------------------------------
def test_real_connected_loopback_is_one_route_record():
    result = parse(LOOKUP_03)
    assert result["status"] == "ok" and result["ok"] is True
    assert result["records"] == [CONNECTED]
    assert result["unparsed"] == [] and result["coverage"]["complete"] is True
    assert result["sources"][0]["query"] == "ipv6_route_lookup"
    assert result["sources"][0]["content_sha256"] == hashlib.sha256(LOOKUP_03.encode()).hexdigest()
    assert set(result["records"][0]) == set(tables.FIELDS["route"])


def test_real_network_not_in_table_is_recognized_no_route():
    # In 04 the marker follows the prompt on the same line; the existing prompt strip removes it.
    assert LOOKUP_04.startswith("FortiGate-60F # % Network not in table\n")
    result = parse(LOOKUP_04)
    assert result["status"] == "empty" and result["ok"] is True
    assert result["records"] == [] and result["unparsed"] == []
    assert result["coverage"] == {"complete": True, "parsed_records": 0, "unparsed_lines": 0, "missing_fields": []}


# ---- DERIVED: mutated text is never a route and never a healthy empty table ------------------------------------------
DERIVED_UNRECOGNIZED = {
    "gateway_next_hop": LOOKUP_03.replace("* directly connected, root", "* fe80::1, via port1"),
    "two_next_hops": LOOKUP_03.replace("* directly connected, root", "* directly connected, root\n  * directly connected, port1"),
    "next_hop_without_fib_mark": LOOKUP_03.replace("* directly connected, root", "directly connected, root"),
    "trailing_hop_text": LOOKUP_03.replace("* directly connected, root", "* directly connected, root, inactive"),
    "ipv4_prefix": LOOKUP_03.replace("::1/128", "192.0.2.0/24"),
    "ipv4_mixed_prefix": LOOKUP_03.replace("::1/128", "::ffff:192.0.2.1/128"),
    "invalid_ipv6": LOOKUP_03.replace("::1/128", "2001:db8:::1/128"),
    "host_bits": LOOKUP_03.replace("::1/128", "2001:db8::1/64"),
    "prefix_length": LOOKUP_03.replace("::1/128", "::1/129"),
    "non_canonical_prefix": LOOKUP_03.replace("::1/128", "0::1/128"),
    "not_best": LOOKUP_03.replace(", best", ""),
    "other_protocol": LOOKUP_03.replace('"connected"', '"static"'),
    "other_vrf": LOOKUP_03.replace("VRF=0", "VRF=1"),
    "two_entries": LOOKUP_03 + LOOKUP_03.split("\n", 1)[1],
    "unknown_line": LOOKUP_03.replace("  Last update", "  Unexpected detail\n  Last update"),
    "header_only": "FortiGate-60F # \nRouting table for VRF=0\n",
    "entry_without_next_hop": "Routing table for VRF=0\nRouting entry for ::1/128\n  Known via \"connected\", distance 0, metric 0, best\n",
    "no_route_with_extra_line": LOOKUP_04.replace("% Network not in table", "% Network not in table\nextra"),
    "no_route_other_case": LOOKUP_04.replace("% Network not in table", "% network not in table"),
    "no_route_after_vrf_header": "Routing table for VRF=0\n% Network not in table\n",
    "other_text": "something else\n",
}


@pytest.mark.parametrize("name", sorted(DERIVED_UNRECOGNIZED))
def test_derived_unrecognized_shapes_are_unparsed_not_empty(name):
    text = DERIVED_UNRECOGNIZED[name]
    result = parse(text)
    assert result["status"] == "unparsed" and result["ok"] is False, name
    assert result["records"] == [] and result["unparsed"], name
    assert result["coverage"]["complete"] is False
    assert "unrecognized_output_lines" in result["warnings"]
    # Every non-blank line except a bare prompt is kept (with its number); none is silently dropped.
    kept = [line for line in text.splitlines() if line.strip() and line.strip() != "FortiGate-60F #"]
    assert len(result["unparsed"]) == len(kept)


def test_derived_blank_refused_failed_and_paged_output_is_not_no_route():
    blank = parse("")
    assert blank["status"] == "unparsed" and blank["ok"] is False and blank["records"] == []
    assert "blank_output_not_a_route_answer" in blank["warnings"] and blank["coverage"]["complete"] is False
    assert parse(" \n\n")["status"] == "unparsed"
    refused = parse("Command fail. Return code -61\n", status="permission_denied", refused=True)
    assert refused["status"] == "permission_denied" and refused["ok"] is False and refused["records"] == []
    for text in (LOOKUP_03, LOOKUP_04):
        failed = parse(text, rc=1)
        assert failed["status"] == "transport_error" and failed["ok"] is False and failed["records"] == []
    paged = parse(LOOKUP_03.rstrip().removesuffix("FortiGate-60F #") + "--More--")
    assert paged["status"] == "truncated" and paged["records"] == []


# ---- the public paths ---------------------------------------------------------------------------------------------
@pytest.fixture()
def wire(tmp_path, monkeypatch):
    """The real proxy with one enrolled FortiGate; only the SSH exec and keyscan are replaced."""
    inventory, _, _, _ = c._configure(proxy_module, tmp_path)
    section = c._section()
    section.update(ssh_platform="fortios", device_types=["firewall"],
                   enabled_queries=["system_status", "route_lookup", "ipv6_route_lookup"],
                   rate_limit={"requests": 30, "window_seconds": 60})
    section["read_inventory"].update(addresses=["192.0.2.20", LOOPBACK, NO_ROUTE_ADDRESS],
                                     lookup_prefixes=[ENROLLED_PREFIX])
    device = c._device(section, "fortios")
    device["port"] = PORT
    c._write(inventory, c._inventory(device))
    monkeypatch.setattr(audit, "_RECORDER", Recorder(tmp_path / "audit.jsonl", "helper"))
    monkeypatch.setattr(engine, "record", audit.record)
    sent = []
    outputs = {
        "get system status": real("01-version.txt"),
        COMMAND.format(LOOPBACK): LOOKUP_03,
        COMMAND.format(NO_ROUTE_ADDRESS): LOOKUP_04,
        # DERIVED replay: the real 04 answer reused for the network address of the enrolled /64.
        COMMAND.format("2001:db8:ffff:ffff::"): LOOKUP_04,
    }
    state = {"override": {}, "rc": 0}

    def edge(auth, address, known_hosts_line, credential, command, platform, stdout_consumer=None):
        assert stdout_consumer is None and known_hosts_line == "pinned-host-key"
        sent.append({"command": command, "platform": platform, "address": address, "alias": auth.alias,
                     "port": auth.port, "login": auth.login, "pin": auth.host_key_fingerprint,
                     "credential_from_vault": credential.use() == c.DEVICE_SECRET,
                     "enabled_queries": auth.enabled_queries, "read_inventory": dict(auth.read_inventory),
                     "verified": auth.fortios_output_standard_verified})
        if command not in outputs:
            pytest.fail("unexpected device command " + command)
        text = state["override"].get(command, outputs[command])
        rc = 0 if command == "get system status" else state["rc"]
        return core_ssh.Result(rc=rc, stdout=text.encode("utf-8"), said="", started_at="", finished_at="")

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
        if values is not None:  # the server's paged-tool handoff (server._paged_auth)
            auth = replace(auth, output_secrets=tuple(dict.fromkeys((context, *values))))
        if tool == "ssh_read":
            return engine.ssh_read(auth, args["platform"], args["query"], args.get("parameters"),
                                   args.get("offset", 0), args.get("max_bytes", 16_000), args.get("content_sha256"))
        return engine.switch_read(auth, **args)

    call.sent, call.state, call.emitted, call.proxy = sent, state, emitted, proxy
    return call


def _device_commands(wire):
    return [item["command"] for item in wire.sent if item["command"] != "get system status"]


def test_switch_read_real_connected_lookup_through_the_proxy(wire):
    result = wire("switch_read", {"table": "route", "ip": LOOPBACK})
    assert _device_commands(wire) == [COMMAND.format(LOOPBACK)]
    sent = wire.sent[-1]
    assert sent == {
        "command": "get router info6 routing-table ::1", "platform": "fortinet", "address": "192.0.2.10",
        "alias": "device-a", "port": PORT, "login": "reader", "pin": c.DEVICE_PIN, "credential_from_vault": True,
        "enabled_queries": ("system_status", "route_lookup", "ipv6_route_lookup"),
        "read_inventory": {"interfaces": (), "services": (), "switches": ("sw-example",),
                           "addresses": ("192.0.2.20", LOOPBACK, NO_ROUTE_ADDRESS),
                           "lookup_prefixes": (ENROLLED_PREFIX,)},
        "verified": True,
    }
    assert result["target"] == "device-a" and result["table"] == "route"
    assert result["status"] == "ok" and result["ok"] is True
    assert result["records"] == [CONNECTED] and result["unparsed"] == []
    assert result["coverage"]["complete"] is True
    assert [source["query"] for source in result["sources"]] == ["ipv6_route_lookup"]
    assert result["sources"][0]["status"] == "ok"


def test_switch_read_real_no_route_through_the_proxy(wire):
    result = wire("switch_read", {"table": "route", "ip": NO_ROUTE_ADDRESS})
    assert _device_commands(wire) == [COMMAND.format(NO_ROUTE_ADDRESS)]
    assert result["status"] == "empty" and result["ok"] is True
    assert result["records"] == [] and result["unparsed"] == [] and result["coverage"]["complete"] is True


def test_ssh_read_real_outputs_through_the_proxy(wire):
    answer = wire("ssh_read", {"platform": "fortinet", "query": "ipv6_route_lookup", "parameters": {"address": LOOPBACK}})
    assert answer["ok"] is True and answer["query"] == "ipv6_route_lookup" and answer["rc"] == 0
    raw = answer["untrusted_device_output"]
    assert "Routing entry for ::1/128" in raw and "* directly connected, root" in raw
    assert "FortiGate-60F #" not in raw  # the existing prompt strip ran
    assert answer["next_offset"] is None and answer["pagination_source"] == "fresh"
    assert tables.parse("fortinet", "route", "ipv6_route_lookup", raw)["records"] == [CONNECTED]
    # An enrolled /128 inside the lookup prefix renders exactly the captured no-route command.
    answer = wire("ssh_read", {"platform": "fortinet", "query": "ipv6_route_lookup",
                               "parameters": {"address": NO_ROUTE_ADDRESS + "/128"}})
    assert answer["ok"] is True and answer["untrusted_device_output"].strip() == "% Network not in table"
    # DERIVED replay: an enrolled-prefix network address (no reachability claim for the /64).
    answer = wire("ssh_read", {"platform": "fortinet", "query": "ipv6_route_lookup",
                               "parameters": {"address": ENROLLED_PREFIX}})
    assert answer["ok"] is True
    assert _device_commands(wire) == [COMMAND.format(LOOPBACK), COMMAND.format(NO_ROUTE_ADDRESS),
                                      COMMAND.format("2001:db8:ffff:ffff::")]


REFUSED_SSH = (
    ({"address": "2001:db8::2"}, "addresses"),                 # not enrolled
    ({"address": "192.0.2.20"}, "addresses"),                  # enrolled, but IPv4
    ({"address": "2001:db8:fffe::/64"}, "lookup_prefixes"),    # outside the enrolled prefix
    ({"address": "::/0"}, "lookup_prefixes"),
    ({"address": "2001:db8:ffff::/48"}, "lookup_prefixes"),    # wider than the enrolled prefix
    ({"address": "0:0::1"}, "addresses"),                      # not canonical
    ({"address": "::1 detail"}, "addresses"),
    ({"address": "::1;get system status"}, "addresses"),
    ({"address": "::1\nget system status"}, "addresses"),
    ({"address": "fe80::1%port1"}, "addresses"),
    ({"address": "::ffff:192.0.2.20"}, "addresses"),
    ({"address": "::1", "vdom": "root"}, "parameters"),
)


@pytest.mark.parametrize("parameters,field", REFUSED_SSH)
def test_ssh_read_refuses_out_of_scope_and_unsafe_values_before_ssh(wire, parameters, field):
    before = {key: len(value) for key, value in wire.proxy.rate_history.items()}
    assert wire("ssh_read", {"platform": "fortinet", "query": "ipv6_route_lookup", "parameters": parameters}) is None
    error = wire.emitted[-1]["error"]
    assert error["data"]["category"] in ("policy_scope", "invalid_params"), error
    if error["data"]["category"] == "policy_scope":
        assert error["data"].get("field") == field
    assert wire.sent == []
    assert {key: len(value) for key, value in wire.proxy.rate_history.items()} == before


def test_query_must_be_enabled_and_known(wire, tmp_path):
    for query in ("ipv6_route_lookup_all", "ipv6_routing_table"):
        assert wire("ssh_read", {"platform": "fortinet", "query": query, "parameters": {"address": LOOPBACK}}) is None
    document = json.loads(Path(proxy_module.INVENTORY).read_text())
    document["devices"][0]["helper"]["enabled_queries"] = ["system_status", "route_lookup"]
    c._write(Path(proxy_module.INVENTORY), document)
    assert wire("ssh_read", {"platform": "fortinet", "query": "ipv6_route_lookup",
                             "parameters": {"address": LOOPBACK}}) is None
    assert wire.emitted[-1]["error"]["data"].get("field") == "enabled_queries"
    assert wire("switch_read", {"table": "route", "ip": LOOPBACK}) is None
    assert wire.emitted[-1]["error"]["data"].get("field") == "enabled_queries"
    assert wire.sent == []


@pytest.mark.parametrize("ip", ["2001:db8::2", "2001:db8:ffff:ffff::beef", "::1/128", "::1;show", "::ffff:192.0.2.20"])
def test_switch_read_refuses_out_of_scope_ipv6_before_ssh(wire, ip):
    assert wire("switch_read", {"table": "route", "ip": ip}) is None
    assert wire.emitted[-1]["error"]["data"]["category"] in ("policy_scope", "invalid_params")
    assert wire.sent == []


def test_rate_limit_scopes_the_target(wire):
    document = json.loads(Path(proxy_module.INVENTORY).read_text())
    document["devices"][0]["helper"]["rate_limit"] = {"requests": 2, "window_seconds": 60}
    c._write(Path(proxy_module.INVENTORY), document)
    assert wire("switch_read", {"table": "route", "ip": LOOPBACK})["status"] == "ok"
    assert wire("ssh_read", {"platform": "fortinet", "query": "ipv6_route_lookup",
                             "parameters": {"address": LOOPBACK}})["ok"] is True
    sent = len(wire.sent)
    assert wire("switch_read", {"table": "route", "ip": LOOPBACK}) is None
    assert wire.emitted[-1]["error"]["data"]["category"] == "rate_limit"
    assert len(wire.sent) == sent


def test_derived_secret_in_device_output_is_redacted_through_the_proxy(wire):
    command = COMMAND.format(LOOPBACK)
    wire.state["override"][command] = LOOKUP_03.replace("  Last update", "  " + c.DEVICE_SECRET + "\n  Last update")
    answer = wire("ssh_read", {"platform": "fortinet", "query": "ipv6_route_lookup", "parameters": {"address": LOOPBACK}})
    assert c.DEVICE_SECRET not in json.dumps(answer) and "<REDACTED>" in answer["untrusted_device_output"]
    result = wire("switch_read", {"table": "route", "ip": LOOPBACK})
    assert c.DEVICE_SECRET not in json.dumps(result)
    assert result["status"] == "unparsed" and result["ok"] is False and result["records"] == []
    assert any("<REDACTED>" in line["text"] for line in result["unparsed"])


def test_derived_refusal_failure_and_blank_are_not_no_route_on_the_public_paths(wire):
    command = COMMAND.format(NO_ROUTE_ADDRESS)
    wire.state["override"][command] = "Command fail. Return code -61\n"
    answer = wire("ssh_read", {"platform": "fortinet", "query": "ipv6_route_lookup",
                               "parameters": {"address": NO_ROUTE_ADDRESS}})
    assert answer["ok"] is False and answer["error_code"] == "device_cli_error"
    result = wire("switch_read", {"table": "route", "ip": NO_ROUTE_ADDRESS})
    assert result["status"] == "permission_denied" and result["ok"] is False and result["records"] == []

    wire.state["override"][command] = ""
    answer = wire("ssh_read", {"platform": "fortinet", "query": "ipv6_route_lookup",
                               "parameters": {"address": NO_ROUTE_ADDRESS}})
    assert answer["ok"] is False and answer["error_code"] == "empty"
    result = wire("switch_read", {"table": "route", "ip": NO_ROUTE_ADDRESS})
    assert result["status"] == "unparsed" and result["ok"] is False and result["records"] == []

    wire.state["override"].pop(command)
    wire.state["rc"] = 1
    result = wire("switch_read", {"table": "route", "ip": NO_ROUTE_ADDRESS})
    assert result["status"] == "transport_error" and result["ok"] is False and result["records"] == []


def test_fortios_output_standard_flag_is_carried_and_required(wire):
    document = json.loads(Path(proxy_module.INVENTORY).read_text())
    document["devices"][0]["helper"]["fortios_output_standard_verified"] = False
    c._write(Path(proxy_module.INVENTORY), document)
    result = wire("switch_read", {"table": "route", "ip": LOOPBACK})
    if result is not None:  # the proxy may already refuse; the engine must never read
        assert result["ok"] is False and result["records"] == []
    assert wire.sent == []
