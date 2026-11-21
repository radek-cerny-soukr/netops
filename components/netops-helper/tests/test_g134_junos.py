"""G134 MCP reads through HelperBridge, the production proxy and a fake SSH transport."""
import asyncio
import json
from pathlib import Path

import pytest

from netops import worker
from netops_helper import engine, proxy, server
from netops_helper.query_catalog import READ_QUERIES

from test_proxy_contracts import DEVICE_PIN, _device, _egress, _inventory, _section, _write

PROFILE = "juniper_junos_els"
SUFFIX = " | no-more"
FIXTURES = Path(__file__).parent / "fixtures/real/juniper_junos_els"
LAB = FIXTURES / "g134_vjunosswitch_26.2R1.7"
OLD = FIXTURES / "vjunosswitch_26.2R1.7"
VENDOR = Path(__file__).parent / "fixtures/docs/juniper_junos/g134"
IDENTITY = (FIXTURES / "g132_vjunosswitch_26.2R1.7/version_ro.out").read_text()
WINDOW = {"start": "2026-11-09T01:09:00", "end": "2026-11-09T01:27:42"}
LOG = "show log messages | last 2000"
UPTIME = "show system uptime"
COUNT = ' | match "[[:graph:]]" | count'


@pytest.fixture
def public(tmp_path, monkeypatch):
    responses = {"show version": IDENTITY}
    sent = []
    private = tmp_path / "helper"
    private.mkdir()
    _write(private / "vault.json", {"version": 2, "credentials": {
        "device-a-account": {"kind": "password", "login": "reader", "value": "fixture-password"},
    }}, 0o600)
    inventory_path = tmp_path / "inventory.json"
    monkeypatch.setattr(worker, "STATE", tmp_path)
    monkeypatch.setattr(proxy, "INVENTORY", inventory_path)
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)

    def fake(auth, platform, command, **kwargs):
        assert platform == PROFILE and command.endswith(SUFFIX)
        command = command.removesuffix(SUFFIX)
        sent.append(command)
        response = responses[command]
        return 0, response() if callable(response) else response

    monkeypatch.setattr(engine, "_exec_read", fake)

    bridge = worker.HelperBridge()

    def call(name, args, *, config_access=True, omit=()):
        section = _section()
        section.pop("snmp_credential")
        section.pop("fortios_output_standard_verified")
        section.update(
            ssh_platform=PROFILE, enabled_queries=sorted(set(READ_QUERIES[PROFILE]) - set(omit)),
            device_types=["switch"], egress={**_egress(), "tcp_ports": [22]},
            read_inventory={
                "interfaces": ["ge-0/0/3", "ge-0/0/30"],
                "addresses": ["203.0.113.128"], "diagnostic_names": ["example.org", "device.example.net"],
                "config_access": ["read"] if config_access else [],
            },
        )
        device = _device(section, PROFILE)
        device["host_key_fingerprint"] = DEVICE_PIN
        _write(inventory_path, _inventory(device))
        result = asyncio.run(bridge.call(server.mcp, name, {"target": "device-a", **args}))
        if "structuredContent" in result:
            return result["structuredContent"]
        return json.loads(result["content"][0]["text"])

    return responses, sent, call


def read(public, query, *, parameters=None, **options):
    return public[2]("ssh_read", {"platform": PROFILE, "query": query, "parameters": parameters or {}}, **options)


@pytest.mark.parametrize("query", (
    "dhcp_server_bindings", "dhcp_relay_bindings", "dhcp_server_statistics", "dhcp_relay_statistics", "snmp_statistics",
))
def test_operational_reads(public, query):
    body = (LAB / f"{query}_ro.out").read_text()
    command = READ_QUERIES[PROFILE][query].command.removesuffix(SUFFIX)
    public[0][command] = body
    answer = read(public, query)
    assert answer["ok"] and answer["complete"]
    assert answer["status"] == ("ok" if body else "empty")
    if query == "snmp_statistics":
        incoming = json.loads(answer["untrusted_device_output"].splitlines()[0])["counters"]
        assert incoming["bad_community_names"] == incoming["bad_community_uses"] == 0
        assert "<REDACTED>" not in answer["untrusted_device_output"]
    else:
        assert answer["untrusted_device_output"] == body
    assert public[1] == ["show version", command]


@pytest.mark.parametrize("query", ("dhcp_server_statistics", "dhcp_relay_statistics", "snmp_statistics"))
def test_counter_capture_with_last_section_removed(public, query):
    body = (LAB / f"{query}_ro.out").read_text().split("Output:" if query == "snmp_statistics" else "Messages sent:")[0]
    public[0][READ_QUERIES[PROFILE][query].command.removesuffix(SUFFIX)] = body
    answer = read(public, query)
    assert not answer["ok"] and answer["error_code"] == "incomplete_output"
    assert not answer["complete"]


@pytest.mark.parametrize(("query", "lines"), (
    ("dhcp_server_statistics", 24),
    ("dhcp_relay_statistics", 21),
    ("snmp_statistics", 22),
))
def test_counter_capture_cut_at_the_review_boundary(public, query, lines):
    body = (LAB / f"{query}_ro.out").read_text()
    command = READ_QUERIES[PROFILE][query].command.removesuffix(SUFFIX)
    public[0][command + COUNT] = f"Count: {sum(bool(line.strip()) for line in body.splitlines())} lines"
    for cut in (lines, len(body.splitlines()) - 1, 0):
        public[0][command] = "".join(body.splitlines(keepends=True)[:cut])
        answer = read(public, query)
        assert not answer["complete"], (query, cut, answer)
        assert answer["error_code"] == "incomplete_output"


@pytest.mark.parametrize(("query", "fixture"), (
    ("dhcp_relay_statistics", "dhcp_relay_statistics_ex.out"),
    ("snmp_statistics", "snmp_statistics_output_traps.out"),
))
def test_documented_short_counter_output(public, query, fixture):
    body = (VENDOR / fixture).read_text()
    command = READ_QUERIES[PROFILE][query].command.removesuffix(SUFFIX)
    public[0][command] = body
    public[0][command + COUNT] = f"Count: {sum(bool(line.strip()) for line in body.splitlines())} lines"
    result = read(public, query)
    assert result["ok"] and result["complete"], result
    assert public[1] == ["show version", command, command + COUNT]
    if query == "dhcp_relay_statistics":
        assert result["untrusted_device_output"] == body
    else:
        incoming, v3, outgoing = map(json.loads, result["untrusted_device_output"].splitlines())
        assert incoming["counters"]["bad_community_names"] == 12
        assert incoming["counters"]["asn_parse_errors"] == 96
        assert v3["section"] == "V3 Input"
        assert outgoing["section"] == "Output" and outgoing["counters"]["traps"] == 0

    public[0][command + COUNT] = "error: permission denied: count"
    assert read(public, query)["error_code"] == "incomplete_output"


def test_server_details_include_the_pool_of_a_bound_lease(public):
    command = "show dhcp server binding detail"
    body = (VENDOR / "dhcp_server_details.out").read_text()
    public[0][command] = body
    assert read(public, "dhcp_server_bindings")["untrusted_device_output"] == body
    public[0][command] = body.split("Client Pool Name:")[0]
    assert read(public, "dhcp_server_bindings")["error_code"] == "incomplete_output"


def test_sessions_count_and_truncation(public):
    body = (LAB / "system_users_ro.out").read_text()
    command = "show system users"
    public[0][command] = body
    answer = read(public, "system_users")
    assert answer["session_count"] == 1
    assert json.loads(answer["untrusted_device_output"])["user"] == "user02"
    public[0][command] = "\n".join(body.splitlines()[:2])
    assert read(public, "system_users")["error_code"] == "incomplete_output"


@pytest.mark.parametrize("query", ("dns_lookup", "dns_resolvers", "syslog_status", "authentication_order",
                                   "radius_servers", "tacacs_servers"))
def test_ro_device_denials(public, query):
    command = READ_QUERIES[PROFILE][query].command.removesuffix(SUFFIX).replace("{name}", "example.org")
    public[0][command] = (LAB / f"{query}_ro.out").read_text()
    answer = read(public, query, parameters={"name": "example.org"} if query == "dns_lookup" else {})
    assert not answer["ok"] and answer["error_code"] == "permission_denied"


def test_junos_dns_is_bound_to_enrolled_name(public):
    denied = read(public, "dns_lookup", parameters={"name": "non-enrolled.example"})
    assert denied["data"]["field"] == "diagnostic_names"
    assert public[1] == []


def test_junos_dns_failure_is_not_an_ssh_timeout(public):
    public[0]["show host example.org"] = (LAB / "dns_lookup_admin.out").read_text()
    answer = read(public, "dns_lookup", parameters={"name": "example.org"})
    assert not answer["ok"] and answer["error_code"] == "dns_timeout" and answer["status"] == "timeout"


def test_junos_dns_returns_a_device_answer(public):
    text = (VENDOR / "dns_answer.out").read_text()
    public[0]["show host device.example.net"] = text
    result = read(public, "dns_lookup", parameters={"name": "device.example.net"})
    assert result["ok"] and result["untrusted_device_output"] == text


def test_syslog_xml_projection_and_authorization(public):
    command = "show configuration system syslog | display xml"
    public[0][command] = (LAB / "syslog_status_admin.out").read_text()
    denied = read(public, "syslog_status", config_access=False)
    assert denied["data"]["field"] == "config_access"
    assert public[1] == []
    answer = read(public, "syslog_status")
    rows = [json.loads(line) for line in answer["untrusted_device_output"].splitlines()]
    assert [row["name"] for row in rows] == ["interactive-commands", "messages"]
    assert rows[1]["selectors"] == [{"facility": "any", "severity": "notice"},
                                    {"facility": "authorization", "severity": "info"}]


def test_absent_config_and_malformed_with_short_canary(public):
    command = "show configuration system authentication-order | display xml"
    absent = (LAB / "authentication_order_admin.out").read_text()
    public[0][command] = absent
    assert read(public, "authentication_order")["status"] == "empty"
    # Derived from the real XML envelope. The credential canary must not escape even
    # when a response is clipped or the field has never been seen by the generic redactor.
    command = "show configuration system radius-server | display xml"
    xml = absent.replace("<cli>", "<configuration><system><radius-server><name>192.0.2.3</name>"
                         "<secret>q!</secret><unknown>q!</unknown></radius-server></system></configuration><cli>")
    public[0][command] = xml
    answer = read(public, "radius_servers")
    assert json.loads(answer["untrusted_device_output"]) == {"address": "192.0.2.3", "inactive": False}
    assert "q!" not in json.dumps(answer)
    public[0][command] = xml[:xml.index("</unknown>")]
    answer = read(public, "radius_servers")
    assert answer["error_code"] == "incomplete_output" and "q!" not in json.dumps(answer)


def test_health_retains_alarm_and_ntp_data_without_environment(public):
    public[0].update({
        READ_QUERIES[PROFILE][query].command.removesuffix(SUFFIX): (OLD / f"{query}.txt").read_text()
        for query in ("routing_engine", "environment", "system_alarms", "chassis_alarms", "ntp_status")
    })
    result = public[2]("triage_health", {})
    assert result["verdict"] == "incomplete"
    assert result["missing"] == [{"step": "environment", "reason": "empty"}]
    assert {item["rule"] for item in result["findings"]} >= {"active_alarm", "ntp_not_synchronized"}
    partial = public[2]("triage_health", {}, omit=("system_alarms",))
    assert {"step": "system_alarms", "reason": "permission_denied"} in partial["missing"]


def test_routing_checks_active_path_and_keeps_other_facts(public):
    public[0].update({
        "show route 203.0.113.128 detail": (OLD / "route_lookup_default.txt").read_text(),
        "show ospf neighbor": (OLD / "ospf_neighbors.txt").read_text(),
        "show bgp summary": (OLD / "bgp_summary.txt").read_text(),
    })
    result = public[2]("triage_routing", {"address": "203.0.113.128"})
    assert result["verdict"] == "no_fault_in_checked_data", result
    assert result["chain"]["route_lookup"][0]["next_hop"] == "203.0.113.129"
    assert len(result["chain"]["ospf_neighbors"]) == 4
    partial = public[2]("triage_routing", {"address": "203.0.113.128"}, omit=("bgp_summary",))
    assert partial["verdict"] == "incomplete"
    assert partial["missing"] == [{"step": "bgp_summary", "reason": "permission_denied"}]


@pytest.mark.parametrize("hop_type", ("Discard", "Reject"))
def test_routing_reports_active_discarding_route(public, hop_type):
    body = (FIXTURES / "g132_vjunosswitch_26.2R1.7/route_lookup_instance_static_ro.out").read_text()
    public[0].update({
        # Reject is derived from the captured Discard entry, changing only the next-hop type.
        "show route 203.0.113.128 detail": body.replace("Next hop type: Discard", f"Next hop type: {hop_type}"),
        "show ospf neighbor": (OLD / "ospf_neighbors.txt").read_text(),
        "show bgp summary": (OLD / "bgp_summary.txt").read_text(),
    })
    result = public[2]("triage_routing", {"address": "203.0.113.128"})
    assert result["verdict"] == "fault_found", result
    route, = result["chain"]["route_lookup"]
    assert route["next_hop_type"] == hop_type
    assert result["findings"] == [
        {"rule": "discarding_route", "fact": route, "sources": [result["sources"]["route_lookup"]]},
    ]


def test_log_history_uses_clock_from_before_capture(public):
    uptime = (OLD / "uptime.txt").read_text()
    # Retimestamp two real messages. The device clock crosses the end of the requested
    # window after the messages snapshot has already been collected.
    messages = (OLD / "log_messages.admin.txt").read_text().splitlines()
    public[0][LOG] = "\n".join([
        messages[27].replace("01:09:00", "13:59:54"),
        messages[29].replace("01:09:02", "14:00:03"),
    ])
    public[0][UPTIME] = lambda: uptime.replace("01:06:21", "14:00:12" if LOG in public[1] else "14:00:05")
    window = {"start": "2026-11-09T14:00:00", "end": "2026-11-09T14:00:10"}
    answer = read(public, "log_history", parameters=window)
    assert answer["ok"] and answer["log_history"]["matched"] == 1
    assert not answer["complete"] and not answer["log_history"]["complete"]
    assert public[1].index(UPTIME) < public[1].index(LOG)

    public[1].clear()
    public[0][LOG] += "\n" + messages[30].replace("01:09:02", "14:00:07")
    answer = read(public, "log_history", parameters={**window, "end": "2026-11-09T14:00:04"})
    assert answer["complete"] and answer["log_history"]["complete"]
    assert answer["log_history"]["last_time"] == "2026-11-09T14:00:07"


def test_log_history_distinguishes_ssh_events_at_the_same_time(public):
    public[0][LOG] = (OLD / "log_messages.admin.txt").read_text()
    public[0][UPTIME] = (OLD / "uptime.txt").read_text().replace("01:06:21", "01:30:00")
    window = {"start": "2026-11-09T01:09:02", "end": "2026-11-09T01:09:03"}
    result = read(public, "log_history", parameters=window)
    records = [json.loads(line) for line in result["untrusted_device_output"].splitlines()]
    assert [row["event"] for row in records if row["process"] == "sshd"] == [
        "sshd_authentication_accepted", "sshd_disconnect_received", "sshd_session_disconnected",
    ]
    assert "user02" not in result["untrusted_device_output"]


def test_log_history_distinguishes_untagged_authentication_errors(public):
    messages = (OLD / "log_messages.admin.txt").read_text().splitlines()
    # Preserve the real prefix and replace the same-second messages with the review's cases.
    public[0][LOG] = "\n".join([
        *messages[:29],
        "Nov  9 01:09:02  host05 sshd[32061]: error: PAM: Authentication error for fixture-user",
        "Nov  9 01:09:02  host05 sshd[32064]: Connection closed by authenticating user fixture-user"
        " 192.0.2.99 port 42220 [preauth]",
        "Nov  9 01:09:02  host05 sshd[32065]: unrecognized event token=fixture-password",
    ])
    public[0][UPTIME] = (OLD / "uptime.txt").read_text().replace("01:06:21", "01:30:00")
    window = {"start": "2026-11-09T01:09:02", "end": "2026-11-09T01:09:03"}
    result = read(public, "log_history", parameters=window)
    body = result["untrusted_device_output"]
    assert [json.loads(line)["event"] for line in body.splitlines()] == [
        "sshd_pam_authentication_error", "sshd_connection_closed_preauth", "untagged",
    ]
    assert "fixture-user" not in body
    assert "fixture-password" not in body
    assert "192.0.2.99" not in body


def test_log_refusal_and_filters_use_only_fixed_commands(public):
    public[0][LOG] = (OLD / "log_messages.txt").read_text()
    public[0][UPTIME] = (OLD / "uptime.txt").read_text()
    denied = read(public, "log_history", parameters=WINDOW)
    assert denied["error_code"] == "permission_denied"
    assert denied["archive_correlation"] == "external_archive_unavailable"
    assert public[1] == ["show version", UPTIME, LOG]

    public[0][LOG] = (OLD / "log_messages.admin.txt").read_text()
    # Derived uptime changes only the timestamp, to bracket the older messages capture.
    public[0][UPTIME] = (OLD / "uptime.txt").read_text().replace("01:06:21", "01:30:00")
    answer = read(public, "log_history", parameters=WINDOW)
    assert answer["ok"] and answer["log_history"]["matched"] > 0
    assert public[1][-3:] == ["show version", UPTIME, LOG]
    assert "Accepted keyboard-interactive" not in answer["untrusted_device_output"]
    severity = read(public, "log_history", parameters={**WINDOW, "severity": "6"})
    assert severity["log_history"]["matched"] == 0 and not severity["complete"]
    assert severity["log_history"]["missing_severity"] > 0
    assert read(public, "log_history", parameters={**WINDOW, "end": WINDOW["start"]})["code"] == -32602


def test_log_history_pages_a_large_lab_capture(public):
    public[0][LOG] = (LAB / "log_history_admin.out").read_text()
    # Derived clock for the Nov 18 capture, with the original Junos uptime format.
    public[0][UPTIME] = (OLD / "uptime.txt").read_text().replace("2026-11-09 01:06:21", "2026-11-18 13:31:00")
    window = {"start": "2026-11-18T13:04:00", "end": "2026-11-18T13:30:00"}
    request = {"platform": PROFILE, "query": "log_history", "parameters": window, "max_bytes": 1000}
    page = public[2]("ssh_read", request)
    assert page["ok"] and page["log_history"]["scanned_lines"] > 200
    sent = list(public[1])
    second = public[2]("ssh_read", {**request, "offset": page["next_offset"], "content_sha256": page["content_sha256"]})
    assert second["pagination_source"] == "cached" and second["log_history"] == page["log_history"]
    assert second["untrusted_device_output"] != page["untrusted_device_output"] and public[1] == sent


def test_log_history_severity_and_port_require_both_selectors(public):
    public[0][UPTIME] = (OLD / "uptime.txt").read_text().replace("01:06:21", "01:30:00")
    # Derived from the documented Junos explicit-priority and millisecond.year forms.
    public[0][LOG] = "\n".join([
        "Nov 9 01:08:42.404.2026 host05 chassisd[522]: %DAEMON-6-CHASSISD_PARSE_COMPLETE: ge-0/0/3",
        "Nov 9 01:10:00.401.2026 host05 chassisd[522]: %DAEMON-6-CHASSISD_PARSE_COMPLETE: ge-0/0/3.0",
        "Nov 9 01:10:00.402.2026 host05 chassisd[522]: %DAEMON-5-CHASSISD_PARSE_COMPLETE: ge-0/0/3",
        "Nov 9 01:10:00.403.2026 host05 chassisd[522]: %DAEMON-6-CHASSISD_PARSE_COMPLETE: ge-0/0/30",
    ])
    result = read(public, "log_history", parameters={**WINDOW, "severity": "6", "interface": "ge-0/0/3"})
    assert result["log_history"]["matched"] == 1 and result["complete"]
    assert json.loads(result["untrusted_device_output"])["interfaces"] == ["ge-0/0/3.0"]


def test_log_history_recognizes_forwarding_node_headers(public):
    text = (LAB / "log_forwarding_node_admin.out").read_text()
    public[0][LOG] = text
    public[0][UPTIME] = (OLD / "uptime.txt").read_text().replace("2026-11-09 01:06:21", "2026-11-18 14:16:00")
    result = read(public, "log_history", parameters={"start": "2026-11-18T14:15:06", "end": "2026-11-18T14:16:00"})
    assert result["ok"] and result["log_history"]["unparsed_lines"] == 0
    assert result["log_history"]["matched"] == len(text.splitlines())
    assert all(json.loads(line)["process"] == "fpc0" for line in result["untrusted_device_output"].splitlines())


def test_short_snmp_reply_cannot_end_inside_a_counter(public):
    command = "show snmp statistics"
    # Derived from Juniper's short SNMP statistics example by clipping the last line.
    body = (VENDOR / "snmp_statistics_output_traps.out").read_text().rstrip("\n")
    public[0][command] = body
    public[0][command + COUNT] = f"Count: {sum(bool(line.strip()) for line in body.splitlines())} lines"
    answer = read(public, "snmp_statistics")
    assert not answer["complete"] and answer["error_code"] == "incomplete_output"


@pytest.mark.parametrize("sd", ["-", r'[exampleSDID@32473 eventSource="ge-0/0/3\]"][meta sequenceId="1"]'])
def test_structured_log_uses_only_the_message_for_ssh_event_and_ports(public, sd):
    # RFC 5424 section 6, with the message taken from the real Junos sshd capture.
    ssh = (OLD / "log_messages.admin.txt").read_text().splitlines()[29].split("]: ", 1)[1]
    public[0][LOG] = f"<38>1 2026-11-09T01:09:02Z host05 sshd 32064 - {sd} {ssh}\n"
    public[0][UPTIME] = (OLD / "uptime.txt").read_text().replace("01:06:21", "01:30:00")
    result = read(public, "log_history", parameters=WINDOW)
    row = json.loads(result["untrusted_device_output"])
    assert row["event"] == "sshd_authentication_accepted"
    assert row["interfaces"] == []


@pytest.mark.parametrize(("before", "after", "day"), [
    ("2026-11-09", "2026-11-10", "Nov 10"),
    ("2026-12-31", "2027-01-01", "Jan  1"),
])
def test_log_year_for_records_written_after_midnight(public, before, after, day):
    # Real Junos messages with their timestamps moved to a midnight boundary.
    messages = (OLD / "log_messages.admin.txt").read_text().splitlines()
    prior_day = "Dec 31" if day.startswith("Jan") else "Nov  9"
    public[0][LOG] = "\n".join([
        prior_day + " 23:59:58" + messages[27][15:],
        day + " 00:00:01" + messages[29][15:],
    ])
    public[0][UPTIME] = lambda: (OLD / "uptime.txt").read_text().replace(
        "2026-11-09 01:06:21", after + " 00:00:03" if LOG in public[1] else before + " 23:59:59")
    answer = read(public, "log_history", parameters={"start": before + "T23:59:59", "end": after + "T00:00:02"})
    assert answer["log_history"]["matched"] == 1
    assert json.loads(answer["untrusted_device_output"])["time"] == after + "T00:00:01"
    assert not answer["complete"]


@pytest.mark.parametrize(("inverted", "complete"), [("01:09:01", True), ("01:08:54", False)])
def test_log_coverage_tolerates_only_small_reordering(public, inverted, complete):
    messages = (OLD / "log_messages.admin.txt").read_text().splitlines()
    public[0][LOG] = "\n".join([messages[27].replace("01:09:00", "01:08:50"), messages[29],
                                messages[30].replace("01:09:02", inverted), messages[31]])
    public[0][UPTIME] = (OLD / "uptime.txt").read_text().replace("01:06:21", "01:30:00")
    answer = read(public, "log_history", parameters=WINDOW)
    assert not answer["log_history"]["chronological"]
    assert answer["log_history"]["complete"] is complete
    assert answer["complete"] is complete


@pytest.mark.parametrize(("first", "omitted_time", "complete"), [
    ("13:59:59", "14:00:01", False), ("13:59:55", "14:00:00", False), ("13:59:54", "13:59:59", True),
])
def test_log_coverage_accounts_for_reordering_before_capture(public, first, omitted_time, complete):
    # Real messages with times adjusted to reproduce the omitted 14:00:01 row at the tail boundary.
    messages = (OLD / "log_messages.admin.txt").read_text().splitlines()
    omitted = "Nov  9 " + omitted_time + messages[26][15:]
    device_log = [omitted, "Nov  9 " + first + messages[27][15:],
                  "Nov  9 14:00:04" + messages[29][15:], "Nov  9 14:00:02" + messages[30][15:]]
    device_log.extend(["Nov  9 14:00:05" + messages[31][15:]] * 1997)
    public[0][LOG] = "\n".join(device_log[-2000:]) + "\n"
    public[0][UPTIME] = (OLD / "uptime.txt").read_text().replace("01:06:21", "14:00:10")

    answer = read(public, "log_history", parameters={"start": "2026-11-09T14:00:00", "end": "2026-11-09T14:00:02"})
    coverage = answer["log_history"]
    assert answer["ok"] and coverage["scanned_lines"] == 2000
    assert coverage["unparsed_lines"] == coverage["matched"] == 0
    assert not coverage["chronological"]
    assert coverage["complete"] is complete
    assert answer["complete"] is complete


@pytest.mark.parametrize("suffix", ["", " fixture-password ge-0/0/3"])
def test_log_history_recognizes_only_whole_syslog_repeat_message(public, suffix):
    repeated = (FIXTURES / "souhrn_junos_698_r2/log_repeated.out").read_text().rstrip("\n")
    previous = (OLD / "log_messages.admin.txt").read_text().splitlines()[27]
    public[0][LOG] = "Nov 20 20:19:30" + previous[15:] + "\n" + repeated + suffix + "\n"
    public[0][UPTIME] = (OLD / "uptime.txt").read_text().replace("2026-11-09 01:06:21", "2026-11-20 20:25:00")
    window = {"start": "2026-11-20T20:19:50", "end": "2026-11-20T20:21:00"}

    answer = read(public, "log_history", parameters=window)
    assert answer["ok"]
    assert answer["log_history"]["unparsed_lines"] == int(bool(suffix))
    assert answer["complete"] is (not suffix)
    if suffix:
        assert answer["untrusted_device_output"] == ""
    else:
        row = json.loads(answer["untrusted_device_output"])
        assert row["event"] == "syslog_message_repeated"
        assert row["severity"] is None and row["interfaces"] == []


def test_junos_counter_transport_failure_withholds_unverified_counters(public):
    from netops_core.ssh import SshError

    def disconnect():
        raise SshError("fixture transport details")

    query = "snmp_statistics"
    command = READ_QUERIES[PROFILE][query].command.removesuffix(SUFFIX)
    public[0][command] = (VENDOR / "snmp_statistics_output_traps.out").read_text()
    public[0][command + COUNT] = disconnect
    answer = read(public, query)
    assert not answer["ok"] and not answer["complete"]
    assert answer["error_code"] == "incomplete_output"
    assert "counters" not in answer.get("untrusted_device_output", "")
    assert "fixture transport details" not in str(answer)
    assert public[1] == ["show version", command, command + COUNT]


def test_junos_log_without_initial_clock_withholds_raw_messages(public):
    public[0][LOG] = (OLD / "log_messages.admin.txt").read_text() + "\nfixture-password"
    public[0][UPTIME] = (OLD / "uptime.txt").read_text().replace("2026-11-09 01:06:21", "unavailable")
    answer = read(public, "log_history", parameters=WINDOW)
    assert not answer["ok"] and not answer["complete"]
    assert answer["error_code"] == "incomplete_output"
    assert not answer.get("untrusted_device_output")
    assert "fixture-password" not in str(answer)
    assert public[1] == ["show version", UPTIME, LOG]


def test_junos_log_without_second_midnight_clock_stays_incomplete(public):
    uptime = (OLD / "uptime.txt").read_text()
    public[0][UPTIME] = lambda: uptime.replace(
        "01:06:21", "unavailable" if LOG in public[1] else "23:59:59")
    public[0][LOG] = (OLD / "log_messages.admin.txt").read_text()
    answer = read(public, "log_history", parameters={
        "start": "2026-11-09T23:50:00", "end": "2026-11-09T23:59:58",
    })
    assert not answer["complete"] and not answer["log_history"]["complete"]
    assert public[1] == ["show version", UPTIME, LOG, UPTIME]


def test_proxy_rejects_invalid_junos_severity_before_ssh(public):
    answer = read(public, "log_history", parameters={**WINDOW, "severity": "8"})
    assert answer["code"] == -32602 or answer["data"]["category"] == "policy_scope"
    assert public[1] == []
