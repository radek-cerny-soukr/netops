"""G28 r2 (ADC-C04, ADC-C08, ADC-C13) with anonymized FortiADC-KVM 7.6.7 build0676 captures (VM220, 2026-11-17).

The captures are REAL terminal reads (see the fixture PROVENANCE.md). A capture holds the echoed command, the device
answer and the next prompt; `body()` removes the echo and the prompt lines, which is what the PTY transport returns.
`exec_stream()` is DERIVED for the configuration stream: the answer prefixed by the exec-channel prompt, the frame of
the real exec captures of the schedule fixtures.
"""
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from conftest import _target
from netops_helper import engine, fortiadc_diagnostics as adc, proxy, triage_slb as rules
from netops_helper.query_catalog import READ_QUERIES

FIXTURES = Path(__file__).parent / "fixtures/real/fortiadc/fortiadc-kvm_7.6.7_g28r2_20261117"
PROMPTS = ("FortiADC-KVM #", "FortiADC-KVM $")
STATUS = "Version: FortiADC-KVM v7.6.7,build0676,260522 (GA.M)\n"
CLIENT = "203.0.113.100"
CR_VS = "LAB_VS_HTTPS"


def raw(name):
    with open(FIXTURES / name, encoding="utf-8", newline="") as handle:
        return handle.read()


def body(name):
    lines = raw(name).split("\n")[1:]
    return "\n".join(line for line in lines if line.strip() not in PROMPTS).strip("\n") + "\n"


def exec_stream(name):
    """DERIVED: the configuration answer as the exec channel frames it (prompt before the first line)."""
    return "FortiADC-KVM # " + body(name) + "\nFortiADC-KVM # "


# --- ADC-C08: session/persistence list with a client filter -------------------------------------------------

def test_real_rows_parse_into_columns():
    session = adc.parse_rows("session", body("session-list-http.out").splitlines()[1:])
    assert len(session) == 4
    assert session[0] == {
        "client_ip": CLIENT, "client_port": 59220, "virtual_server_ip": "203.0.113.10", "virtual_server_port": 80,
        "local_ip": "203.0.113.253", "local_port": 27678, "real_server_ip": "203.0.113.254", "real_server_port": 80,
        "protocol": 6, "service": "http", "state": "ESTABLISHED", "in_bytes": 0, "out_bytes": 0, "expire": 100,
        "virtual_server": "VS_APP_HTTP", "real_server": "RS_A"}
    assert [row["real_server"] for row in session] == ["RS_A", "RS_B", "RS_A", "RS_B"]
    udp = adc.parse_rows("session", body("session-list-udp.out").splitlines()[1:])
    assert {(row["protocol"], row["service"], row["state"]) for row in udp} == {(17, "udp", "UDP")}
    persistence = adc.parse_rows("persistence", body("persistence-list.out").splitlines()[1:])
    assert persistence[0] == {
        "client_ip": CLIENT, "client_port": 0, "virtual_server_ip": "203.0.113.10", "virtual_server_port": 443,
        "local_ip": "0.0.0.0", "local_port": 0, "real_server_ip": "203.0.113.254", "real_server_port": 80,
        "protocol": 6, "service": "https", "expire": 300, "virtual_server": CR_VS, "real_server": "RS_A"}
    # A row of the other family or a shifted column is never guessed.
    assert adc.parse_rows("persistence", body("session-list-http.out").splitlines()[1:]) is None
    assert adc.parse_rows("session", ["%s x 203.0.113.10 80" % CLIENT]) is None


def test_measured_filter_flags_and_refusals():
    values = adc._filter_values(body("session-filter-vs-source.out"))
    assert values == adc._state_filter("session", "1010", "VS_APP_HTTP", (CLIENT, CLIENT))
    assert adc._filter_values(body("persistence-filter-vs-source.out")) == adc._state_filter(
        "persistence", "1010", CR_VS, (CLIENT, CLIENT))
    assert adc._filter_values(body("persistence-filter-vs.out")) == adc._state_filter("persistence", "1000", CR_VS)
    assert adc._filter_values(body("session-filter-range.out"))["source ip range"] == CLIENT + " - 203.0.113.110"
    assert adc._filter_values(body("session-filter-vs-rs.out"))["filter flag"] == "3000"
    # Two quoted arguments: the device applied only the first (vs-name); the readback shows it.
    assert adc._filter_values(body("session-filter-two-args.out")) == adc._state_filter("session", "1000", "VS_APP_HTTP")
    for name in ("persistence-filter-rs-refused.out", "session-filter-invalid-ip.out"):
        assert adc.FILTER_REFUSAL.search(body(name)) and not adc._is_refusal(body(name))
    for name in ("session-filter-cleared.out", "persistence-filter-cleared.out"):
        family = name.split("-")[0]
        assert adc._filter_values(body(name)) == adc._state_filter(family, "0")
    # The anonymiser also mapped the example addresses of the help text.
    assert "'source-ip " in body("persistence-filter-help.out") and "'vs-name vs1 vs2'" in body("persistence-filter-help.out")
    assert "rs-name" not in body("persistence-filter-help.out") and "rs-name" in body("session-filter-help.out")


class StateShell:
    """Answers with the real captures; the filter state follows the commands like the device did."""

    def __init__(self, family, select_answers, listing, cleared=None):
        self.family = family
        self.prefix = "diagnose server-load-balance " + family
        self.cleared = body(cleared or "%s-filter-cleared.out" % family)
        self.current = self.cleared
        self.select_answers = select_answers
        self.listing = listing
        self.commands = []

    def command(self, command, timeout=10):
        self.commands.append(command)
        if command == "get system status":
            return STATUS
        if command == self.prefix + " filter show":
            return self.current
        if command == self.prefix + " filter clear":
            self.current = self.cleared
            return ""
        if command == self.prefix + " list":
            return self.listing
        answer, readback = self.select_answers[command]
        if readback is not None:
            self.current = readback
        return answer

    def interrupt(self):
        return None


@pytest.mark.parametrize("recipe,family,vs,readback,listing", [
    ("session_list", "session", "VS_APP_HTTP", "session-filter-vs-source.out", "session-list-vs-source.out"),
    ("persistence_list", "persistence", CR_VS, "persistence-filter-vs-source.out", "persistence-list-vs-source.out"),
])
def test_client_filter_is_one_quoted_argument_read_back_and_cleared(recipe, family, vs, readback, listing):
    select = "diagnose server-load-balance %s filter 'vs-name %s source-ip %s'" % (family, vs, CLIENT)
    shell = StateShell(family, {select: ("", body(readback))}, body(listing))
    result = adc.run_state_list(shell, recipe, vs, 50, 10, source_address=CLIENT)
    assert result["ok"] and result["state"] == "data" and result["cleanup"] == "verified", result
    assert shell.commands == ["get system status", shell.prefix + " filter show", select, shell.prefix + " filter show",
                              shell.prefix + " list", shell.prefix + " filter clear", shell.prefix + " filter show"]
    assert result["records"] and all(row["client_ip"] == CLIENT and row["virtual_server"] == vs
                                     for row in result["records"])
    assert result["source_address"] == CLIENT and not result["filter_mismatch"]
    assert result["loaded_records"] == len(result["records"]) == result["returned_records"]


def test_client_filter_answers_where_the_client_goes():
    select = "diagnose server-load-balance persistence filter 'vs-name %s source-ip %s'" % (CR_VS, CLIENT)
    shell = StateShell("persistence", {select: ("", body("persistence-filter-vs-source.out"))},
                       body("persistence-list-vs-source.out"))
    result = adc.run_state_list(shell, "persistence_list", CR_VS, 1, 10, source_address=CLIENT)
    assert result["records"] == [dict(result["records"][0], real_server="RS_A", real_server_ip="203.0.113.254")]
    assert result["count_truncated"] and result["returned_records"] == 1


def test_client_without_rows_is_header_only_data():
    select = "diagnose server-load-balance session filter 'vs-name VS_APP_HTTP source-ip %s'" % CLIENT
    shell = StateShell("session", {select: ("", body("session-filter-vs-source.out"))},
                       body("session-list-other-client.out"))
    result = adc.run_state_list(shell, "session_list", "VS_APP_HTTP", 3, 10, source_address=CLIENT)
    assert result["ok"] and result["header_only"] and result["records"] == []


def test_vs_only_filter_keeps_the_released_contract():
    select = "diagnose server-load-balance persistence filter 'vs-name %s'" % CR_VS
    shell = StateShell("persistence", {select: ("", body("persistence-filter-vs.out"))}, body("persistence-list.out"))
    result = adc.run_state_list(shell, "persistence_list", CR_VS, 3, 10)
    assert result["ok"] and result["source_address"] is None and len(result["records"]) == 2


def test_readback_of_another_filter_is_incomplete_and_cleared():
    # The measured trap: a second quoted argument was ignored, the readback names only the virtual server.
    select = "diagnose server-load-balance session filter 'vs-name VS_APP_HTTP source-ip %s'" % CLIENT
    shell = StateShell("session", {select: ("", body("session-filter-two-args.out"))}, body("session-list-http.out"))
    result = adc.run_state_list(shell, "session_list", "VS_APP_HTTP", 3, 10, source_address=CLIENT)
    assert not result["ok"] and result["state"] == "incomplete" and result["cleanup"] == "verified"
    assert shell.prefix + " list" not in shell.commands and result["records"] == []


def test_device_refused_filter_value_is_reported_and_cleared():
    select = "diagnose server-load-balance session filter 'vs-name VS_APP_HTTP source-ip %s'" % CLIENT
    # REAL refusal text of an invalid source-ip value; the filter stays empty.
    shell = StateShell("session", {select: (body("session-filter-invalid-ip.out"), None)}, "")
    result = adc.run_state_list(shell, "session_list", "VS_APP_HTTP", 3, 10, source_address=CLIENT)
    assert result["state"] == "device_refused" and not result["ok"] and result["cleanup"] == "verified"


def test_row_outside_the_filter_is_not_returned():
    # DERIVED: the real HTTP rows of VS_APP_HTTP returned for a filter that selected LAB_VS_HTTPS.
    select = "diagnose server-load-balance session filter 'vs-name %s source-ip %s'" % (CR_VS, CLIENT)
    readback = body("session-filter-vs-source.out").replace("virtual server: VS_APP_HTTP", "virtual server: " + CR_VS)
    shell = StateShell("session", {select: ("", readback)}, body("session-list-http.out"))
    result = adc.run_state_list(shell, "session_list", CR_VS, 3, 10, source_address=CLIENT)
    assert result["filter_mismatch"] and result["state"] == "incomplete" and result["records"] == []


@pytest.mark.parametrize("value,expected", [
    (CLIENT, (CLIENT, CLIENT)), ("198.51.100.0/24", ("198.51.100.1", "198.51.100.254")),
    ("198.51.100.8/31", ("198.51.100.8", "198.51.100.9")),
])
def test_client_range(value, expected):
    assert adc.client_range(value) == expected


@pytest.mark.parametrize("value", ["203.0.113.300", "198.51.100.1/24", "192.0.0.0/8", "224.0.0.5", "0.0.0.0",
                                   "2001:db8::1", " 203.0.113.1", 1])
def test_client_range_refuses(value):
    with pytest.raises(ValueError):
        adc.client_range(value)


def test_client_filter_needs_enrolled_address_and_state_recipe():
    auth = SimpleNamespace(read_inventory={"diagnostic_recipes": ("session_list", "system_event_logs"),
                                           "diagnostic_virtual_servers": ("VS_APP_HTTP",),
                                           "addresses": (CLIENT,), "lookup_prefixes": ("198.51.100.0/24",)},
                           require_ssh_query=lambda *a: None)
    adc.authorize(auth, "session_list", "VS_APP_HTTP", source_address=CLIENT)
    adc.authorize(auth, "session_list", "VS_APP_HTTP", source_address="198.51.100.0/25")
    with pytest.raises(ValueError, match="not enrolled"):
        adc.authorize(auth, "session_list", "VS_APP_HTTP", source_address="203.0.113.101")
    with pytest.raises(ValueError, match="client source_address"):
        adc.validate("system_event_logs", "", "", 3, 10, 16000, source_address=CLIENT)
    adc.validate("persistence_list", CR_VS, "", 3, 10, 16000, source_address=CLIENT)


def test_engine_refuses_client_filter_outside_state_recipes(tmp_path, monkeypatch):
    from netops_core.audit import Recorder
    from netops_helper import audit
    monkeypatch.setattr(audit, "_RECORDER", Recorder(tmp_path / "audit.jsonl", "helper"))
    monkeypatch.setattr(engine, "record", audit.record)
    auth = replace(_target("fortiadc", "system_status"))
    with pytest.raises(ValueError, match="does not take a client source_address"):
        engine.fortios_diagnostics(auth, "system_event_logs", "", "", source_address=CLIENT)
    with pytest.raises(ValueError, match="TCP or UDP tuple"):
        engine.fortios_diagnostics(auth, "session_list", "VS_APP_HTTP", "", source_address=CLIENT, source_port=1)


def test_proxy_normalizes_and_authorizes_the_client_filter():
    validate = proxy.Proxy._validate_tool_arguments
    ok = validate("fortios_diagnostics", {"target": "adc", "recipe": "session_list", "address": "VS_APP_HTTP",
                                          "interface": "", "source_address": CLIENT})
    assert ok["source_address"] == CLIENT
    with pytest.raises(proxy.ToolArgumentsError):
        validate("fortios_diagnostics", {"target": "adc", "recipe": "session_list", "address": "VS_APP_HTTP",
                                         "interface": "", "source_address": "203.0.113.300"})
    with pytest.raises(proxy.ToolArgumentsError):
        validate("fortios_diagnostics", {"target": "adc", "recipe": "session_list", "address": "VS_APP_HTTP",
                                         "interface": "", "source_address": CLIENT, "source_port": 1})
    section = SimpleNamespace(catalog_platform=lambda: "fortiadc", enabled_queries=("system_status",),
                              egress={}, read_inventory={"diagnostic_recipes": ("session_list",),
                                                         "diagnostic_virtual_servers": ("VS_APP_HTTP",),
                                                         "addresses": (CLIENT,)})
    args = {"recipe": "session_list", "address": "VS_APP_HTTP", "interface": "", "source_address": CLIENT}
    proxy.Proxy._authorize_tool("fortios_diagnostics", args, None, section)
    with pytest.raises(proxy.PolicyScopeError):
        proxy.Proxy._authorize_tool("fortios_diagnostics", dict(args, source_address="203.0.113.101"), None, section)


# --- ADC-C04: triage_slb follows content routing ------------------------------------------------------------

def test_real_content_routing_entries_parse():
    first = rules.content_routing_config(raw("cr1-full.out").split("\n", 1)[1], "NETOPS_TEST_CR1")
    assert first == {"type": "l7-content-routing", "pool": "POOL_APP", "schedule_list": "disable",
                     "persistence_inherit": "enable", "method_inherit": "enable",
                     "conditions": [{"id": 1, "content": "app.lab.test", "ignore_case": "enable",
                                     "object": "http-host-header", "reverse": "disable", "type": "string"}]}
    second = rules.content_routing_config(raw("cr2-full.out").split("\n", 1)[1], "NETOPS_TEST_CR2")
    assert second["conditions"][0]["object"] == "http-request-url" and second["conditions"][0]["content"] == "/"
    with pytest.raises(rules.TriageParseError):
        rules.content_routing_config(raw("cr1-full.out").split("\n", 1)[1], "NETOPS_TEST_CR2")
    vs = rules.virtual_server_config(raw("vs-cr-full.out").split("\n", 1)[1], CR_VS)
    assert vs["content_routing"] == "enable" and vs["pool"] is None
    assert vs["content_routing_list"] == ["NETOPS_TEST_CR1", "NETOPS_TEST_CR2"]
    assert vs["persistence"] == "LB_PERSIS_SRC_ADDR"
    # Measured: the CLI hides the stored pool, vs_stat still prints it.
    assert "load-balance-pool" not in raw("vs-cr-show.out") and "real-server-pool: POOL_APP" in raw("vs-stat-cr.out")
    assert "is not found" in raw("cr-missing.out")


def test_content_routing_plan_fits_the_reserved_budget():
    assert rules.CONTENT_ROUTING_PLAN == 17 + rules.MAX_CONTENT_ROUTES <= rules.RATE_COST


VS_STAT_CR = "diagnose server-load-balance vs_stat vdom root vs " + CR_VS
SLB_LOAD = "diagnose server-load-balance slb_load"
POOL_VIEW = """FortiADC-KVM # config load-balance pool
  edit "POOL_APP"
    set health-check-ctrl enable
    set health-check-list HC_HTTP_APP
    config  pool_member
      edit 1
        set status enable
        set real-server RS_A
      next
      edit 2
        set status enable
        set real-server RS_B
      next
    end
  next
end

FortiADC-KVM # """
HC_VIEW = """FortiADC-KVM # config system health-check
  edit "HC_HTTP_APP"
    set type http
  next
end

FortiADC-KVM # """


@pytest.fixture
def cr_wire(monkeypatch):
    from netops_helper import configuration
    configuration._SNAPSHOTS.clear()
    state = SimpleNamespace(calls=[], views={
        "load-balance virtual-server " + CR_VS: exec_stream("vs-cr-full.out"),
        "load-balance content-routing NETOPS_TEST_CR1": exec_stream("cr1-full.out"),
        "load-balance content-routing NETOPS_TEST_CR2": exec_stream("cr2-full.out"),
        # SYNTHETIC: pool and health-check views (not under test here; the pool shape of test_triage_slb).
        "load-balance pool POOL_APP": POOL_VIEW,
        "system health-check HC_HTTP_APP": HC_VIEW,
        "load-balance client-ssl-profile LB_CLIENT_SSL_PROF_DEFAULT": exec_stream("cr2-full.out"),
    }, runtime={VS_STAT_CR: body("vs-stat-cr.out"), SLB_LOAD: body("slb-load-cr.out"),
                "get system performance": body("ro-performance.out")})

    def exec_read(auth, platform, command, stdout_consumer=None):
        state.calls.append(command)
        if command == "get system status":
            text = STATUS
        elif command.startswith("get load-balance client-ssl-profile"):
            text = "FortiADC-KVM # \n"
        else:
            assert command.startswith("show full-configuration "), command
            text = state.views[command[len("show full-configuration "):]]
        if stdout_consumer:
            stdout_consumer(text.encode())
            return 0, ""
        return 0, text

    def prompt_read(auth, platform, command):
        state.calls.append(command)
        return None, state.runtime[command]

    monkeypatch.setattr(engine, "_exec_read", exec_read)
    monkeypatch.setattr(engine, "_prompt_read", prompt_read)
    monkeypatch.setattr(engine, "record", lambda *a, **k: None)
    engine._SSH_PAGE_CACHE.clear()
    yield state
    engine._SSH_PAGE_CACHE.clear()
    configuration._SNAPSHOTS.clear()


def cr_auth():
    from netops_helper.auth import EgressPolicy
    return replace(_target("fortiadc", "system_status"), enabled_queries=tuple(READ_QUERIES["fortiadc"]),
                   egress=EgressPolicy(addresses=("127.0.0.1",), tcp_ports=(2222,), allow_icmp=True),
                   read_inventory={"adc_vdoms": ("root",), "adc_virtual_servers": (CR_VS,), "config_access": ("read",),
                                   "adc_health_checks": ("HC_HTTP_APP",)})


def test_triage_follows_content_routing_to_its_single_candidate_pool(cr_wire):
    result = engine.triage_slb(cr_auth(), CR_VS)
    assert result["ok"], result
    chain = result["chain"]
    assert chain["pool"]["selection"] == "content_routing" and chain["pool"]["candidates_complete"]
    assert [(item["entry"], item["pool"]) for item in chain["content_routing"]] == [
        ("NETOPS_TEST_CR1", "POOL_APP"), ("NETOPS_TEST_CR2", "POOL_APP")]
    assert chain["content_routing"][0]["conditions"][0]["object"] == "http-host-header"
    refs = chain["pool"]["references"]
    assert refs[0]["name"] == "POOL_APP" and refs[0]["relation"] == "configured_candidate"
    assert refs[0]["entries"] == ["NETOPS_TEST_CR1", "NETOPS_TEST_CR2"]
    assert chain["pool"]["name"] == "POOL_APP" and chain["pool"]["config"]["members"]
    assert [m["runtime"]["hc_state"] for m in chain["members"]] == ["UP", "UP"]
    ids = [finding["id"] for finding in result["findings"]]
    assert "F-POOL-BY-CONTENT" in ids and "F-POOL-NOT-CANDIDATE" not in ids and "F-MISMATCH" not in ids
    assert {"content_routing:NETOPS_TEST_CR1", "content_routing:NETOPS_TEST_CR2", "pool_config"} <= set(result["checked"])
    assert not any(item["step"] == "pool_config" for item in result["missing"]), result["missing"]
    assert not any(call.startswith("show full-configuration load-balance real-server") for call in cr_wire.calls)
    reads = [call for call in cr_wire.calls if call != "get system status"]
    assert len(reads) + 1 <= rules.RATE_COST


# SYNTHETIC: another existing pool with other real servers and the same member ids 1/2 (ids belong to their pool).
POOL_OTHER_VIEW = POOL_VIEW.replace('"POOL_APP"', '"POOL_OTHER"').replace("RS_A", "RS_C").replace("RS_B", "RS_D")


def route_to_other_pool(cr_wire, vs_stat_states=None):
    """Review 445-r2-rv repro: both real entries point to POOL_OTHER, vs_stat/slb_load still print hidden POOL_APP."""
    for name in ("NETOPS_TEST_CR1", "NETOPS_TEST_CR2"):
        key = "load-balance content-routing " + name
        cr_wire.views[key] = cr_wire.views[key].replace("set load-balance-pool POOL_APP", "set load-balance-pool POOL_OTHER")
    cr_wire.views["load-balance pool POOL_OTHER"] = POOL_OTHER_VIEW
    if vs_stat_states:
        # DERIVED: the real vs_stat with its member states substituted.
        cr_wire.runtime[VS_STAT_CR] = cr_wire.runtime[VS_STAT_CR].replace("hc_state: UP", "hc_state: " + vs_stat_states)


def test_content_routing_candidate_never_takes_member_state_of_the_hidden_pool(cr_wire):
    route_to_other_pool(cr_wire)
    result = engine.triage_slb(cr_auth(), CR_VS)
    chain = result["chain"]
    assert chain["pool"]["name"] == "POOL_OTHER" and chain["pool"]["candidates_complete"]
    assert [(m["id"], m["real_server"], m["runtime"]) for m in chain["members"]] == [
        (1, "RS_C", None), (2, "RS_D", None)]
    findings = {finding["id"]: finding for finding in result["findings"]}
    assert "F-MEMBER-DOWN" not in findings and "F-POOL-ALL-DOWN" not in findings
    assert findings["F-POOL-NOT-CANDIDATE"]["object"] == "POOL_APP"
    mismatch = [f["fact"] for f in result["findings"] if f["id"] == "F-MISMATCH"]
    assert "config member ids [1, 2], vs_stat member ids [], vs_stat pools ['POOL_APP']" in mismatch
    assert "slb_load present True, member ids [], config member ids [1, 2]" in mismatch


def test_down_hidden_pool_is_no_fault_of_the_content_routing_candidate(cr_wire):
    route_to_other_pool(cr_wire, vs_stat_states="DOWN")
    result = engine.triage_slb(cr_auth(), CR_VS)
    assert [m["runtime"] for m in result["chain"]["members"]] == [None, None]
    ids = [finding["id"] for finding in result["findings"]]
    assert "F-MEMBER-DOWN" not in ids and "F-POOL-ALL-DOWN" not in ids
    assert not any("RS_C" in step["why"] or "RS_D" in step["why"] for step in result["next_steps"])
    assert not any(call.startswith("show full-configuration load-balance real-server") for call in cr_wire.calls)


def test_down_candidate_printed_by_vs_stat_is_still_reported(cr_wire):
    # DERIVED: the real vs_stat with its member states substituted; the printed pool is the candidate POOL_APP.
    cr_wire.runtime[VS_STAT_CR] = cr_wire.runtime[VS_STAT_CR].replace("hc_state: UP", "hc_state: DOWN")
    result = engine.triage_slb(cr_auth(), CR_VS)
    assert [m["runtime"]["hc_state"] for m in result["chain"]["members"]] == ["DOWN", "DOWN"]
    ids = [finding["id"] for finding in result["findings"]]
    assert ids.count("F-MEMBER-DOWN") == 2 and "F-POOL-ALL-DOWN" in ids


def test_unread_content_routing_entry_keeps_candidates_incomplete(cr_wire):
    cr_wire.views["load-balance content-routing NETOPS_TEST_CR2"] = exec_stream("cr-missing.out")
    result = engine.triage_slb(cr_auth(), CR_VS)
    assert result["chain"]["pool"]["candidates_complete"] is False
    assert result["chain"]["pool"]["name"] is None and result["chain"]["pool"]["config"] is None
    assert any(item["step"] == "content_routing:NETOPS_TEST_CR2" for item in result["missing"])
    assert result["verdict"] == "incomplete"


def test_content_routing_list_beyond_the_limit_is_truncated(cr_wire):
    view = exec_stream("vs-cr-full.out")
    # DERIVED: the real view with three more (unread) entries in the list.
    cr_wire.views["load-balance virtual-server " + CR_VS] = view.replace(
        "NETOPS_TEST_CR1 NETOPS_TEST_CR2 ", "NETOPS_TEST_CR1 NETOPS_TEST_CR2 X3 X4 X5 ")
    for name in ("X3", "X4"):
        cr_wire.views["load-balance content-routing " + name] = exec_stream("cr2-full.out").replace(
            "NETOPS_TEST_CR2", name)
    result = engine.triage_slb(cr_auth(), CR_VS)
    assert {"step": "content_routing:X5", "reason": "truncated"} in result["missing"]
    assert not any(call.endswith("content-routing X5") for call in cr_wire.calls)
    assert result["verdict"] == "incomplete"


# --- ADC-C13: what the read profile may do -------------------------------------------------------------------

@pytest.mark.parametrize("name,command", [
    ("ro-vs-overview-refused.out", "diagnose server-load-balance vs_stat vdom root"),
    ("ro-rs-stat-refused.out", "diagnose server-load-balance vs_stat vdom root vs VS_APP_HTTP rs 1"),
    ("ro-slb-load-refused.out", "diagnose server-load-balance slb_load"),
    ("ro-session-refused.out", "diagnose server-load-balance session list"),
])
def test_read_profile_rejects_the_diagnose_subtree(name, command):
    assert adc.diagnose_refused(command, body(name))
    assert body("ro-diagnose-help.out").strip().splitlines()[-1] == "<Enter>"


def test_admin_argument_error_is_not_a_permission_refusal():
    admin = (Path(__file__).parent / "fixtures/real/fortiadc/fortiadc-kvm_7.6.7_g28_20261117/refusal.out").read_text()
    assert not adc.diagnose_refused("diagnose server-load-balance slb_load extra", admin)
    assert not adc.diagnose_refused("get system performance", body("ro-vs-overview-refused.out"))


@pytest.fixture
def ro_wire(monkeypatch):
    calls = []
    output = {}

    def execute(auth, platform, command, **kwargs):
        calls.append(command)
        assert command == "get system status"
        return 0, STATUS

    def terminal(auth, platform, command):
        calls.append(command)
        return None, output[command]

    monkeypatch.setattr(engine, "_exec_read", execute)
    monkeypatch.setattr(engine, "_prompt_read", terminal)
    monkeypatch.setattr(engine, "record", lambda *a, **k: None)
    engine._SSH_PAGE_CACHE.clear()
    yield calls, output
    engine._SSH_PAGE_CACHE.clear()


def ro_auth():
    return replace(_target("fortiadc", "system_status"), enabled_queries=tuple(READ_QUERIES["fortiadc"]),
                   read_inventory={"adc_vdoms": ("root",), "adc_virtual_servers": ("VS_APP_HTTP",)})


@pytest.mark.parametrize("query,parameters,name", [
    ("slb_vs_overview", {"vdom": "root"}, "ro-vs-overview-refused.out"),
    ("slb_rs_stat", {"vdom": "root", "virtual_server": "VS_APP_HTTP", "real_server": "1"}, "ro-rs-stat-refused.out"),
    ("slb_load", None, "ro-slb-load-refused.out"),
])
def test_read_only_diagnose_is_permission_denied_with_advice(ro_wire, query, parameters, name):
    calls, output = ro_wire
    command = READ_QUERIES["fortiadc"][query].command.format_map(parameters or {})
    output[command] = body(name)
    result = engine.ssh_read(ro_auth(), "fortiadc", query, parameters, 0, 48000)
    assert not result["ok"] and result["error_code"] == "permission_denied", result
    assert result["reason"] == "diagnose_not_permitted" and "admin-bounded" in result["error"]


def test_admin_argument_error_stays_device_cli_error(ro_wire):
    calls, output = ro_wire
    # DERIVED: the real admin refusal (parsing error at an argument) as the answer of slb_load.
    admin = (Path(__file__).parent / "fixtures/real/fortiadc/fortiadc-kvm_7.6.7_g28_20261117/refusal.out").read_text()
    output[SLB_LOAD] = "\n".join(line for line in admin.split("\n")[1:] if line.strip() not in PROMPTS)
    result = engine.ssh_read(ro_auth(), "fortiadc", "slb_load", None, 0, 48000)
    assert not result["ok"] and result["error_code"] == "device_cli_error"
