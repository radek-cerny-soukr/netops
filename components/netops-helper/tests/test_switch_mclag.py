from dataclasses import replace
import json

from conftest import FORTIOS_STATUS, PASSWORD, _target
import netops_helper.engine as engine
from netops_helper.query_catalog.fortinet import QUERIES
from netops_helper.read_policy import render_read_query
from netops_helper.switch_mclag import summarize

A = "S224EPTF00000001"
B = "S224EPTF00000002"
MAC = "00:00:5e:00:53:01"

ICL = f"""Vdom: root
Managed Switch : {A}\t0
_FlInK1_ICL0_
    icl-ports            23-24
    egress-block-ports   2
    interface-mac        {MAC}
    local-serial-number  {A}
    peer-mac             {MAC}
    peer-serial-number   {B}
    Local uptime         1 days  2h:36m: 0s
    Peer uptime          0 days  0h:46m: 0s
    MCLAG-STP-mac        {MAC}
    keepalive interval   1
    keepalive timeout    60
    dormant candidate    Peer
    split-brain          Disabled
Counters
    received keepalive packets          567
"""

ICL_EMPTY = f"Vdom: root\nManaged Switch : {A}\t0\n"
UNSUPPORTED = "Vdom: root\nswitch:S108ENTQ00000001 does not support MCLAG feature!\nCommand fail. Return code -7622\n"
NOT_FOUND_SWITCH = "Vdom: root\nswitch:S224EPTF00000009 not found!\nCommand fail. Return code -7622\n"


def trunk(name, mode, status, slaves):
    body = "".join(
        f"slave: {port}\n  status: {state}\n  link failure count: 0\n  permanent MAC addr: {MAC}\n"
        f"  actor state: ASAIEE\n  partner state: ASAIEE\n  aggregator ID: 1\n"
        for port, state in slaves
    )
    return (
        f"  Trunk Name:  {name}\n  Mode:  lacp-active ({mode})\n  Port Selection Algorithm: src-dst-ip\n"
        f"  Trunk MAC: {MAC} \n  Trunk ID:  1\n  Active Port  Up  Time\n  ___________  _____\n"
        f"  Non-Active Port  Status\n  _______________  ______\nLACP flags: (A|P)(S|F)(A|I)(I|O)(E|D)(E|D)\n"
        f"status: {status}\nports: {len(slaves)}\nLACP mode: active\nactor MAC address: {MAC}\n{body}"
    )


def trunk_output(*blocks):
    return f"Vdom: root\n{A}:\nSwitch Trunk Information, primary-Channel\n" + "".join(blocks)


def consistency(peer_inactive="none", local_inactive="none", lag="UP", trunk_check="OK",
                local_lag="port1", local_stp="FORWARDING", remote_lag="port2", remote_stp="FORWARDING", drop=()):
    marker = "    <--" if peer_inactive != "none" else ""
    local_marker = "    <--" if local_inactive != "none" else ""
    rows = [
        f"Vdom: root\nManaged Switch : {A}     0\n",
        f"    ** Comparing \"switch.trunk\" config             ....{trunk_check}\n",
        "    ** Comparing \"switch.interface\" config         ....OK\n",
        "    ** Comparing \"switch.physical-port\" config     ....OK\n",
        "    ** Comparing \"switch.stp.instance\" config      ....OK\n",
        "    Comparing \"LAG state\"\n    -------------------\n",
        "    local ports                                       port1\n",
        f"    local inactive ports                              {local_inactive}{local_marker}\n",
        "    Peer ports                                        port2\n",
        f"    Peer inactive ports                               {peer_inactive}{marker}\n",
        f"    LAG state                                         {lag}\n",
        "    Comparing \"STP state\"\n    -------------------\n",
        f"    Local active-LAG ports                            {local_lag}\n",
        f"    Local active ports                                {local_stp}\n",
        f"    Remote active-LAG ports                           {remote_lag}\n",
        f"    Remote active ports                               {remote_stp}\n",
    ]
    return "".join(row for row in rows if not any(row.lstrip().startswith(prefix) for prefix in drop))


def test_icl_reports_peer_and_ports_without_macs():
    result = summarize("switch_mclag_icl", ICL, {"managed_switch": A})
    assert result == {
        "state": "configured", "icl_trunk": "_FlInK1_ICL0_", "icl_ports": "23-24",
        "local_serial": A, "peer_serial": B, "split_brain": "Disabled",
    }
    assert MAC not in json.dumps(result)


def test_icl_absent_is_not_configured_and_unsupported_switch_is_explicit():
    assert summarize("switch_mclag_icl", ICL_EMPTY + "\n\n", {"managed_switch": A})["state"] == "not_configured"
    for query in ("switch_mclag_icl", "switch_trunk_status", "switch_mclag_consistency"):
        assert summarize(query, UNSUPPORTED, {})["state"] == "not_supported"


def test_trunk_states_name_missing_member():
    up = trunk_output(trunk("_FlInK1_ICL0_", "auto-isl,mclag-icl", "up", [("port24", "up"), ("port23", "up")]))
    result = summarize("switch_trunk_status", up, {"mclag_trunk": "_FlInK1_ICL0_"})
    assert result["state"] == "ok" and result["role"] == "icl" and result["missing_members"] == []
    assert result["members"] == [{"port": "port24", "status": "up"}, {"port": "port23", "status": "up"}]
    partial = trunk_output(trunk("SRV1", "auto-isl,mclag", "up", [("port5", "up"), ("port6", "suspended")]))
    result = summarize("switch_trunk_status", partial, {"mclag_trunk": "SRV1"})
    assert result["state"] == "degraded" and result["role"] == "mclag"
    assert result["missing_members"] == ["port6"]
    down = trunk_output(trunk("SRV1", "auto-isl,mclag", "down", [("port5", "suspended")]))
    result = summarize("switch_trunk_status", down, {"mclag_trunk": "SRV1"})
    assert result["state"] == "down" and result["missing_members"] == ["port5"]
    lag = trunk_output(trunk("LAG1", "auto-isl", "up", [("port1", "up")]))
    assert summarize("switch_trunk_status", lag, {"mclag_trunk": "LAG1"})["role"] == "lag"


def test_trunk_selects_requested_block_or_reports_not_found():
    both = trunk_output(
        trunk("OTHER", "auto-isl,mclag", "down", [("port1", "suspended")]),
        trunk("SRV1", "auto-isl,mclag", "up", [("port2", "up")]),
    )
    assert summarize("switch_trunk_status", both, {"mclag_trunk": "SRV1"})["state"] == "ok"
    other = trunk_output(trunk("OTHER", "auto-isl,mclag", "up", [("port1", "up")])) + "\n\n\n"
    assert summarize("switch_trunk_status", other, {"mclag_trunk": "SRV1"}) == {"state": "not_found", "trunk": "SRV1"}


def test_consistency_states_and_missing_peer_member():
    result = summarize("switch_mclag_consistency", consistency(), {})
    assert result["state"] == "ok"
    assert result["config_checks"] == {"switch.trunk": "OK", "switch.interface": "OK", "switch.physical-port": "OK", "switch.stp.instance": "OK"}
    assert result["local_ports"] == ["port1"] and result["peer_ports"] == ["port2"] and result["lag_state"] == "UP"
    result = summarize("switch_mclag_consistency", consistency(peer_inactive="port2"), {})
    assert result["state"] == "degraded"
    assert result["missing_members"] == [{"side": "peer", "port": "port2"}]
    result = summarize("switch_mclag_consistency", consistency(local_inactive="port1"), {})
    assert result["missing_members"] == [{"side": "local", "port": "port1"}]
    assert summarize("switch_mclag_consistency", consistency(lag="DOWN", peer_inactive="port2"), {})["state"] == "down"
    assert summarize("switch_mclag_consistency", consistency(trunk_check="FAIL"), {})["state"] == "inconsistent"
    missing = f"Vdom: root\nManaged Switch : {A}     0\n    >>>>SRV9 TRUNK NOT FOUND ON LOCAL SWITCH<<<<\n"
    assert summarize("switch_mclag_consistency", missing, {})["state"] == "not_found"
    assert summarize("switch_mclag_consistency", "garbage\n", {})["state"] == "incomplete"


def test_untrusted_values_outside_grammar_are_dropped():
    hostile = consistency().replace("port2\n", "port2;exec\n").replace("....OK\n", "....<script>\n", 1)
    result = summarize("switch_mclag_consistency", hostile, {})
    assert "<script>" not in json.dumps(result) and "exec" not in json.dumps(result)
    assert result["state"] == "inconsistent"


def _mclag_target(query):
    return replace(_target("fortinet", query), read_inventory={
        "managed_switches": (A,), "managed_switch_trunks": ("SRV1",),
    })


def _fake(monkeypatch, body):
    sent = []

    def fake_read(auth, platform, command):
        sent.append(command)
        return 0, FORTIOS_STATUS if command == engine._IDENTITY_COMMAND else body

    monkeypatch.setattr(engine, "read_from_device", fake_read)
    monkeypatch.setattr(engine, "record", lambda event, **fields: None)
    return sent


def test_ssh_read_attaches_mclag_summary(monkeypatch):
    sent = _fake(monkeypatch, consistency(peer_inactive="port2") + PASSWORD)
    answer = engine.ssh_read(_mclag_target("switch_mclag_consistency"), "fortinet", "switch_mclag_consistency",
                             {"managed_switch": A, "mclag_trunk": "SRV1"}, 0, 16000)
    assert answer["ok"] is True
    assert sent[-1] == f"diagnose switch-controller switch-info mclag peer-consistency-check {A} SRV1"
    assert answer["mclag"]["state"] == "degraded"
    assert answer["mclag"]["missing_members"] == [{"side": "peer", "port": "port2"}]
    assert PASSWORD not in json.dumps(answer)


def test_ssh_read_unsupported_switch_is_explicit_not_a_failure(monkeypatch):
    _fake(monkeypatch, UNSUPPORTED)
    answer = engine.ssh_read(_mclag_target("switch_mclag_icl"), "fortinet", "switch_mclag_icl", {"managed_switch": A}, 0, 16000)
    assert answer["ok"] is True and answer["mclag"] == {"state": "not_supported"}


def test_ssh_read_other_refusal_stays_device_cli_error(monkeypatch):
    _fake(monkeypatch, NOT_FOUND_SWITCH)
    answer = engine.ssh_read(_mclag_target("switch_mclag_icl"), "fortinet", "switch_mclag_icl", {"managed_switch": A}, 0, 16000)
    assert answer["ok"] is False and answer["error_code"] == "device_cli_error" and "mclag" not in answer


def test_other_queries_get_no_mclag_field(monkeypatch):
    _fake(monkeypatch, "fan ok\n")
    target = replace(_target("fortinet", "switch_fan_health"), read_inventory={"managed_switches": (A,)})
    answer = engine.ssh_read(target, "fortinet", "switch_fan_health", {"managed_switch": A}, 0, 16000)
    assert answer["ok"] is True and "mclag" not in answer


def test_mclag_trunk_must_be_enrolled_and_cannot_be_an_option():
    inventory = {"managed_switches": (A,), "managed_switch_trunks": ("SRV1",)}
    for query in ("switch_trunk_status", "switch_mclag_consistency"):
        parameters = {"managed_switch": A, "mclag_trunk": "SRV1"}
        assert render_read_query("fortinet", query, parameters, inventory)[1] == QUERIES[query].command.format_map(parameters)
        for bad, enrolled in (("SRV2", ("SRV1",)), ("-x", ("-x",)), ("a b", ("a b",)), ("x" * 36, ("x" * 36,))):
            try:
                render_read_query("fortinet", query, {**parameters, "mclag_trunk": bad}, {**inventory, "managed_switch_trunks": enrolled})
            except ValueError:
                continue
            raise AssertionError(f"trunk {bad!r} accepted")


def _state(query, text, trunk="SRV1"):
    return summarize(query, text, {"managed_switch": A, "mclag_trunk": trunk})


def test_unknown_inactive_port_token_is_incomplete_not_ok():
    result = _state("switch_mclag_consistency", consistency(local_inactive="port1 port49.1"))
    assert result["state"] == "incomplete" and "local inactive ports" in result["unreadable_fields"]
    result = _state("switch_mclag_consistency", consistency(peer_inactive="port2 ae1"))
    assert result["state"] == "incomplete" and "peer inactive ports" in result["unreadable_fields"]


def test_missing_or_truncated_inactive_rows_are_incomplete():
    for row in ("local inactive ports", "Peer inactive ports", "LAG state", "Local active ports", "Remote active-LAG ports"):
        result = _state("switch_mclag_consistency", consistency(drop=(row,)))
        assert result["state"] == "incomplete" and row.lower() in result["unreadable_fields"], row
    full = consistency(peer_inactive="port2")
    truncated = full[:full.index("    Peer inactive ports")]
    assert _state("switch_mclag_consistency", truncated)["state"] == "incomplete"


def test_inactive_rows_are_read_in_any_letter_case():
    text = consistency(local_inactive="port1").replace("    local inactive ports", "    Local Inactive Ports")
    result = _state("switch_mclag_consistency", text)
    assert result["state"] == "degraded" and result["missing_members"] == [{"side": "local", "port": "port1"}]


def test_stp_discarding_on_active_lag_port_is_a_finding():
    result = _state("switch_mclag_consistency", consistency(local_stp="DISCARDING"))
    assert result["state"] == "degraded" and result["stp_blocked"] == [{"side": "local", "port": "port1"}]
    assert result["stp_state"] == {"local": "DISCARDING", "peer": "FORWARDING"}
    result = _state("switch_mclag_consistency", consistency(remote_stp="DISCARDING"))
    assert result["state"] == "degraded" and result["stp_blocked"] == [{"side": "peer", "port": "port2"}]


def test_stp_discarding_on_inactive_side_is_degraded_without_stp_block():
    result = _state("switch_mclag_consistency", consistency(peer_inactive="port2", remote_lag="none", remote_stp="DISCARDING"))
    assert result["state"] == "degraded" and result["stp_blocked"] == []
    assert result["missing_members"] == [{"side": "peer", "port": "port2"}]
    result = _state("switch_mclag_consistency", consistency(remote_lag="none", remote_stp="DISCARDING"))
    assert result["state"] == "degraded" and result["stp_blocked"] == []


def test_missing_stp_section_is_incomplete():
    text = consistency()
    text = text[:text.index("    Comparing \"STP state\"")]
    assert _state("switch_mclag_consistency", text)["state"] == "incomplete"


def test_lag_state_other_than_up_is_down():
    assert _state("switch_mclag_consistency", consistency(lag="INACTIVE"))["state"] == "down"


def test_lag_rows_without_config_checks_are_incomplete():
    text = consistency(drop=("** Comparing",))
    assert _state("switch_mclag_consistency", text)["state"] == "incomplete"


def test_trunk_without_members_is_incomplete():
    text = trunk_output(trunk("SRV1", "auto-isl,mclag", "up", []))
    assert _state("switch_trunk_status", text)["state"] == "incomplete"


def test_trunk_without_status_line_is_incomplete():
    text = trunk_output(trunk("SRV1", "auto-isl,mclag", "up", [("port1", "up")])).replace("status: up\nports:", "ports:")
    result = _state("switch_trunk_status", text)
    assert result["state"] == "incomplete" and result["trunk_status"] is None


def test_trunk_member_count_mismatch_is_incomplete():
    text = trunk_output(trunk("SRV1", "auto-isl,mclag", "up", [("port1", "up"), ("port2", "down")]))
    text = text.replace("slave: port2", "member: port2")
    assert _state("switch_trunk_status", text)["state"] == "incomplete"
    no_count = trunk_output(trunk("SRV1", "auto-isl,mclag", "up", [("port1", "up")])).replace("ports: 1\n", "")
    assert _state("switch_trunk_status", no_count)["state"] == "incomplete"


def test_empty_or_unreadable_output_is_incomplete_for_all_three():
    for query in ("switch_mclag_icl", "switch_trunk_status", "switch_mclag_consistency"):
        assert _state(query, "")["state"] == "incomplete", query
        assert _state(query, "Vdom: root\n")["state"] == "incomplete", query
    unreadable_peer = ICL.replace(f"peer-serial-number   {B}", "peer-serial-number   unknown")
    assert _state("switch_mclag_icl", unreadable_peer)["state"] == "incomplete"


def test_live_shaped_ha_ap_outputs_keep_expected_states():
    primary = consistency(local_lag="port2", remote_lag="port1").replace("local ports                                       port1", "local ports                                       port2").replace("Peer ports                                        port2", "Peer ports                                        port1")
    assert _state("switch_mclag_consistency", primary)["state"] == "ok"
    secondary = consistency(local_inactive="port2", local_lag="none", local_stp="DISCARDING", remote_lag="port1")
    result = _state("switch_mclag_consistency", secondary)
    assert result["state"] == "degraded" and result["stp_blocked"] == []
    assert result["stp_state"] == {"local": "DISCARDING", "peer": "FORWARDING"}


def test_helper_docs_explain_mclag_states_and_limits():
    from pathlib import Path
    text = Path(__file__).resolve().parents[1].joinpath("docs/tools.md").read_text(encoding="utf-8")
    section = text[text.index("## FortiSwitch MCLAG state"):]
    for word in ("`configured`", "`not_configured`", "`not_supported`", "`incomplete`", "`ok`", "`degraded`",
                 "`down`", "`inconsistent`", "`not_found`", "`stp_blocked`", "`unreadable_fields`"):
        assert word in section, word
    assert "configuration only" in section and "switch_trunk_status" in section
    assert "does not show link state" in section
    for word in ("`LEARNING`", "`LISTENING`", "`BLOCKING`", "`DISCARDING`", "ends with an empty line"):
        assert word in section, word
    assert "only configuration" in QUERIES["switch_mclag_icl"].description
    assert "switch_trunk_status" in QUERIES["switch_mclag_icl"].description


def test_icl_header_without_answer_end_is_incomplete():
    assert _state("switch_mclag_icl", ICL_EMPTY)["state"] == "incomplete"
    cut = ICL_EMPTY + "Counters\n    received keepalive packets 5\n"
    assert _state("switch_mclag_icl", cut)["state"] == "incomplete"
    assert _state("switch_mclag_icl", ICL_EMPTY + "\n\n\n")["state"] == "not_configured"
    assert _state("switch_mclag_icl", "Vdom: root\n\n\n")["state"] == "incomplete"


def test_trunk_not_found_needs_a_complete_listing():
    assert _state("switch_trunk_status", trunk_output())["state"] == "incomplete"
    assert _state("switch_trunk_status", trunk_output() + "\n\n\n")["state"] == "incomplete"
    other = trunk_output(trunk("OTHER", "auto-isl,mclag", "up", [("port1", "up")]))
    assert _state("switch_trunk_status", other)["state"] == "incomplete"
    assert _state("switch_trunk_status", other + "\n\n\n") == {"state": "not_found", "trunk": "SRV1"}
    cut = trunk_output(trunk("OTHER", "auto-isl,mclag", "up", [("port1", "up"), ("port2", "up")])).replace("slave: port2", "member: port2")
    assert _state("switch_trunk_status", cut + "\n\n\n")["state"] == "incomplete"


def test_requested_trunk_before_another_block_reads_only_its_own_members():
    text = trunk_output(
        trunk("SRV1", "auto-isl,mclag", "up", [("port2", "up")]),
        trunk("OTHER", "auto-isl", "down", [("port1", "suspended")]),
    ) + "\n\n\n"
    result = _state("switch_trunk_status", text)
    assert result["state"] == "ok" and result["role"] == "mclag"
    assert result["members"] == [{"port": "port2", "status": "up"}] and result["missing_members"] == []


def test_missing_member_list_rows_are_incomplete():
    for row in ("local ports", "Peer ports"):
        result = _state("switch_mclag_consistency", consistency(drop=(row,)))
        assert result["state"] == "incomplete" and result["unreadable_fields"] == [row.lower()], row


def test_every_stp_state_other_than_forwarding_is_a_finding():
    for word in ("LEARNING", "LISTENING", "BLOCKING", "DISCARDING"):
        result = _state("switch_mclag_consistency", consistency(local_stp=word))
        assert result["state"] == "degraded" and result["stp_blocked"] == [{"side": "local", "port": "port1"}], word
        result = _state("switch_mclag_consistency", consistency(remote_stp=word))
        assert result["state"] == "degraded" and result["stp_blocked"] == [{"side": "peer", "port": "port2"}], word


def test_unknown_stp_state_is_incomplete():
    for word in ("DISABLED", "forwarding", "UNKNOWN"):
        result = _state("switch_mclag_consistency", consistency(remote_stp=word))
        assert result["state"] == "incomplete" and result["unreadable_fields"] == ["remote active ports"], word
        assert result["stp_state"]["peer"] is None


def test_lag_up_without_any_usable_member_is_down():
    no_active = _state("switch_mclag_consistency", consistency(local_lag="none", remote_lag="none"))
    assert no_active["state"] == "down" and no_active["lag_state"] == "UP"
    all_inactive = _state("switch_mclag_consistency", consistency(local_inactive="port1", peer_inactive="port2"))
    assert all_inactive["state"] == "down"
    text = consistency().replace("local ports                                       port1", "local ports                                       none")
    text = text.replace("Peer ports                                        port2", "Peer ports                                        none")
    assert _state("switch_mclag_consistency", text)["state"] == "down"


def test_trunk_block_without_trunk_information_header_is_incomplete():
    text = f"Vdom: root\n{A}:\n" + trunk("SRV1", "auto-isl,mclag", "up", [("port1", "up")]) + "\n\n\n"
    assert _state("switch_trunk_status", text) == {"state": "incomplete", "trunk": "SRV1"}
