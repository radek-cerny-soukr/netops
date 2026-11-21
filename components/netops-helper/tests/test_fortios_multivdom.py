"""Multi-VDOM FortiOS reads on the measured FortiGate-60F 7.6.8 (task 175, 1.0.9 item 11).

The fixtures in fixtures/real/fortinet/fortigate60f_7.6.8_multivdom/transcripts.json are anonymised interactive transcripts of
the 60F in multi-VDOM mode (measurement task 172): `A` is a super_admin session (prompt `#`), `G` a
super_admin_readonly session (prompt `$`); `root` / `vd1` / `noctx` name the VDOM context the commands ran in.
The 514/523 `show system interface` captures were filtered on the device side to the `edit` and `set vdom` lines.

The transport is faked, never the read under test: the identity (`get system status`) comes from a fake exec
read (`read_from_device`) and every VDOM context read from a fake interactive SSH session that answers each
command with the recorded answer for the prompt (VDOM context) it was sent in. The real engine, the real
diagnostic shell, the real parsers and the real redaction run unchanged.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re

import pytest

from conftest import KNOWN_HOSTS_LINE, _target
import netops_helper.engine as engine
from netops_helper import fortios_diagnostics as diagnostics
from netops_helper import fortios_vdom as vdom
from netops_helper import triage_health, triage_routing, triage_vpn

FIXTURES = Path(__file__).parent / "fixtures/real/fortinet/fortigate60f_7.6.8_multivdom"
TRANSCRIPTS = json.loads((FIXTURES / "transcripts.json").read_text())
# Excerpts of the task 197 CLI evidence (`config global`, `edit root` refusing a global command), see README.
TRANSCRIPTS.update(json.loads((FIXTURES / "context-197.json").read_text()))
# The per-VDOM administrator of task 197 (`44-vd1acct-exec-run2`, one exec call per capture), see README (task 206).
TRANSCRIPTS.update(json.loads((FIXTURES / "vdom-admin-197.json").read_text()))
PROMPT = re.compile(r"^(FortiGate-60F(?: \([A-Za-z0-9_.+-]+\))? [#$] )(.*)$")
VD1 = "nops172-vd1"
# The no-VDOM status of the same 60F (task 158 capture), between its two `FortiGate-60F # ` prompts.
DISABLE_STATUS = (Path(__file__).parent / "fixtures/real/fortios/fg60f_7.6.8_ipv6_20261114/01-version.txt").read_text(
).split("FortiGate-60F # ")[1]


def transcript(name):
    """[(prompt, command, answer)] of one recorded session; the last step is the closing prompt."""
    lines = TRANSCRIPTS[name].split("\n")
    assert lines[0] == "[login]"
    steps = []
    for line in lines[1:]:
        found = PROMPT.match(line)
        if found:
            steps.append([found[1], found[2], []])
        elif steps:
            steps[-1][2].append(line)
    return [(prompt, command, "\n".join(answer).strip("\n")) for prompt, command, answer in steps]


def answer(name, command):
    (text,) = [text for _, sent, text in transcript(name) if sent == command]
    return text


ROOT_STATUS = answer("511-A-noctx-status", "get system status")
VD1_STATUS = answer("529-A-vd1-status", "get system status")
# Task 197 `21-status-multivdom` (see README): multi-VDOM right after `set vdom-mode multi-vdom`, only `root` exists.
TRANSCRIPTS.update(json.loads((FIXTURES / "status-197.json").read_text()))
ONE_VDOM_STATUS = answer("197-21-A-noctx-status-one-vdom", "get system status")
MISSING = "nops197-xx"


class Device:
    """A FortiGate replayed from transcripts: an answer per (prompt, command); the first recording wins."""

    def __init__(self, *names, override=None):
        self.answers = {}
        self.login = None
        for name in names:
            steps = transcript(name)
            self.login = self.login or steps[0][0]
            for (prompt, command, text), (following, _, _) in zip(steps, steps[1:]):
                self.answers.setdefault((prompt, command), (text, following))
        self.answers.update(override or {})
        self.sent = []
        self.unexpected = []
        self.sessions = 0

    def session(self, *args, **kwargs):
        return _Session(self)


class _Session:
    def __init__(self, device):
        device.sessions += 1
        self.device = device
        self.prompt = device.login
        self._last_prompt = device.login.encode()
        self.pending = []

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def close(self):
        pass

    def discard(self, seen):
        pass

    def interrupt(self):
        pass

    def expect(self, patterns, timeout):
        buffer = self.pending.pop(0)
        (index,) = [number for number, pattern in enumerate(patterns) if buffer.endswith(pattern)][:1]
        return index, buffer

    def send(self, command):
        self.device.sent.append(command)
        key = (self.prompt, command)
        if key not in self.device.answers:
            self.device.unexpected.append(key)
            text, following = "command parse error before '%s'\nCommand fail. Return code -61" % command, self.prompt
        else:
            text, following = self.device.answers[key]
        self.prompt = following
        self._last_prompt = following.encode()
        self.pending.append((command + "\r\n" + text.replace("\n", "\r\n") + "\r\n\r\n" + following).encode())


@pytest.fixture()
def device(wire, monkeypatch):
    state = {"status": ROOT_STATUS, "exec": []}

    def install(*names, status=ROOT_STATUS, override=None):
        replay = Device(*names, override=override)
        state["status"] = status
        monkeypatch.setattr(engine.core_session, "fortinet_session", replay.session)
        monkeypatch.setattr(engine, "host_key_line", lambda *args, **kwargs: KNOWN_HOSTS_LINE)
        return replay

    def exec_read(auth, platform, command, **options):
        state["exec"].append(command)
        if command == "get system status":
            return 0, state["status"]
        raise AssertionError("a per-VDOM command was sent outside a VDOM context: " + command)

    monkeypatch.setattr(engine, "read_from_device", exec_read)
    install.state = state
    return install


def fortigate(*queries, vdoms=("root",), **inventory):
    target = _target("fortinet", queries[0])
    return replace(target, enabled_queries=tuple(queries), device_types=("firewall",),
                   read_inventory={"diagnostic_vdoms": tuple(vdoms), **inventory})


# --- the scope parser on the measured status, marker and configuration texts --------------------------------


def test_the_measured_status_names_the_mode_and_the_session_vdom():
    assert vdom.scope(ROOT_STATUS) == {"vdom_mode": "multiple", "vdom": "root"}
    assert vdom.scope(VD1_STATUS) == {"vdom_mode": "multiple", "vdom": VD1}
    assert vdom.scope(DISABLE_STATUS) == {"vdom_mode": "disable", "vdom": "root"}


# Review 175-rv finding 1: an accepted product status without the VDOM mode line (the measured status with the
# `Virtual domain configuration` line removed, or only the version line) is unverified, never no-VDOM.
WITHOUT_MODE = re.sub(r"(?m)^Virtual domain configuration: multiple\n", "", ROOT_STATUS)
VERSION_ONLY = "Version: FortiGate-60F v7.6.8,build3744,260929 (GA.M)\n"


@pytest.mark.parametrize("status", [VERSION_ONLY, VERSION_ONLY + "Current virtual domain: root\n", WITHOUT_MODE,
                                    re.sub(r"(?m)^Virtual domain configuration: disable\n", "", DISABLE_STATUS)])
def test_a_status_without_the_vdom_mode_line_is_unverified_not_no_vdom(status):
    assert "Version: FortiGate-60F v7.6.8,build3744" in status and "Virtual domain configuration" not in status
    with pytest.raises(vdom.VdomRefused) as refused:
        vdom.scope(status)
    assert refused.value.code == "vdom_unverified"
    with pytest.raises(vdom.VdomRefused) as refused:
        vdom.require(None, {"diagnostic_vdoms": ("root",)})
    assert refused.value.code == "vdom_unverified"


@pytest.mark.parametrize("change", [
    lambda text: text + "\nVirtual domain configuration: multiple\n",
    lambda text: text + "\nCurrent virtual domain: root\n",
    lambda text: text.replace("Current virtual domain: root", "Current virtual domain: root x"),
    lambda text: re.sub(r"(?m)^Current virtual domain: root\n", "", text),
    lambda text: text.replace("configuration: multiple", "configuration: enable"),
])
def test_an_ambiguous_or_incomplete_vdom_status_is_refused(change):
    with pytest.raises(vdom.VdomRefused) as refused:
        vdom.scope(change(ROOT_STATUS))
    assert refused.value.code == "vdom_unverified"


def test_a_multi_vdom_session_reads_only_an_enrolled_vdom():
    found = vdom.scope(ROOT_STATUS)
    assert vdom.require(found, {"diagnostic_vdoms": ("root",)}) == found
    with pytest.raises(vdom.VdomRefused) as refused:
        vdom.require(found, {"diagnostic_vdoms": (VD1,)})
    assert refused.value.code == "vdom_scope_required" and refused.value.scope == found
    assert vdom.require(vdom.scope(DISABLE_STATUS), {}) == {"vdom_mode": "disable", "vdom": "root"}


# Task 212 (live check 197 S5): a VDOM that the device provably does not have gets its own code.


def test_the_vdom_count_of_the_status_proves_only_a_device_with_one_vdom():
    assert "Virtual domains status: 1 in NAT mode, 0 in TP mode" in ONE_VDOM_STATUS
    assert vdom.scope(ONE_VDOM_STATUS) == {"vdom_mode": "multiple", "vdom": "root"}
    assert vdom.only_session_vdom(ONE_VDOM_STATUS)
    # The measured two-VDOM status (global and VDOM account alike) names no other VDOM: nothing is inferred.
    assert not vdom.only_session_vdom(ROOT_STATUS) and not vdom.only_session_vdom(VD1_STATUS)
    without = re.sub(r"(?m)^Virtual domains status:.*\n", "", ONE_VDOM_STATUS)
    twice = ONE_VDOM_STATUS + "\nVirtual domains status: 1 in NAT mode, 0 in TP mode\n"
    tp_only = ONE_VDOM_STATUS.replace("1 in NAT mode, 0 in TP mode", "0 in NAT mode, 1 in TP mode")
    garbled = ONE_VDOM_STATUS.replace("1 in NAT mode, 0 in TP mode", "1 in NAT mode")
    assert not any(map(vdom.only_session_vdom, (without, twice, garbled, "")))
    assert vdom.only_session_vdom(tp_only)


def test_an_enrolled_vdom_that_cannot_exist_is_vdom_not_found_otherwise_scope_required():
    found = vdom.scope(ONE_VDOM_STATUS)
    with pytest.raises(vdom.VdomRefused) as refused:
        vdom.require(found, {"diagnostic_vdoms": (MISSING,)}, ONE_VDOM_STATUS)
    assert refused.value.code == "vdom_not_found" and refused.value.scope == found
    assert "exactly one VDOM" in str(refused.value)
    for status, inventory in ((ROOT_STATUS, {"diagnostic_vdoms": (MISSING,)}), (None, {"diagnostic_vdoms": (MISSING,)}),
                              (ONE_VDOM_STATUS, {}), (ONE_VDOM_STATUS, {"diagnostic_vdoms": ()})):
        with pytest.raises(vdom.VdomRefused) as refused:
            vdom.require(vdom.scope(status or ROOT_STATUS), inventory, status)
        assert refused.value.code == "vdom_scope_required"
    # The session VDOM itself enrolled: read as before; no-VDOM is never refused for its scope.
    assert vdom.require(found, {"diagnostic_vdoms": ("root", MISSING)}, ONE_VDOM_STATUS) == found
    assert vdom.require(vdom.scope(DISABLE_STATUS), {"diagnostic_vdoms": (MISSING,)}, DISABLE_STATUS)["vdom"] == "root"


def test_the_context_marker_names_the_vdom_and_its_index():
    assert vdom.context_index(answer("512-A-root-arp", "edit root"), "root") == 0
    assert vdom.context_index(answer("521-A-vd1-arp", "edit " + VD1), VD1) == 3
    for text, name in ((answer("521-A-vd1-arp", "edit " + VD1), "root"), ("", "root"),
                       ("current vf=root:0\ncurrent vf=root:0", "root")):
        with pytest.raises(vdom.VdomRefused):
            vdom.context_index(text, name)


def test_interface_membership_comes_from_set_vdom_of_show_system_interface():
    owners = vdom.memberships(answer("523-A-vd1-intfshow", "show system interface"))
    assert owners["dmz"] == VD1 and owners["wan1"] == "root" and owners["netops-172-p1"] == VD1
    assert len(owners) == 33
    assert vdom.memberships(answer("514-A-root-intfshow", "show system interface")) == owners
    nested = ('config system interface\n    edit "port1"\n        set vdom "root"\n        config ipv6\n'
              '            set vdom "other"\n        end\n    next\nend')
    assert vdom.memberships(nested) == {"port1": "root"}
    for text in ('    edit "a"\n        set vdom "root"\n    edit "a"\n        set vdom "root"',
                 '    edit "a"\n    edit "b"\n        set vdom "root"', ""):
        with pytest.raises(vdom.VdomRefused):
            vdom.memberships(text)


def test_sessions_of_another_vdom_are_detected_by_their_vd_field():
    unfiltered = answer("528-A-vd1-session", "diagnose sys session list")
    assert "vd=0" in unfiltered and not vdom.sessions_in_vdom(unfiltered, 3)
    extra = transcript("94-A-extra")
    filtered_root = [text for prompt, command, text in extra
                     if prompt.startswith("FortiGate-60F (root)") and command == "diagnose sys session list"][0]
    assert "session info:" in filtered_root and vdom.sessions_in_vdom(filtered_root, 0)
    filtered_vd1 = [text for prompt, command, text in extra
                    if prompt.startswith("FortiGate-60F (" + VD1) and command == "diagnose sys session list"][0]
    assert filtered_vd1 == "total session: 0" and vdom.sessions_in_vdom(filtered_vd1, 3)


def test_a_read_only_profile_refuses_diagnose_with_unknown_action_only():
    assert vdom.diagnose_refused("diagnose ip arp list", answer("542-G-root-diagarp", "diagnose ip arp list"))
    # Without a VDOM context the super_admin gets a numbered refusal and a return code: not a profile refusal.
    assert not vdom.diagnose_refused("diagnose sys session list", answer("510-A-noctx-session", "diagnose sys session list"))
    assert not vdom.diagnose_refused("get system arp", "Unknown action 0")


# --- ssh_read ---------------------------------------------------------------------------------------------


def test_a_multi_vdom_read_runs_inside_the_verified_context_and_names_its_vdom(device):
    replay = device("512-A-root-arp")
    result = engine.ssh_read(fortigate("arp_table"), "fortinet", "arp_table", None, 0, 16000)
    assert result["ok"] is True, result
    assert (result["vdom_mode"], result["vdom"], result["vdom_index"], result["data_scope"]) == (
        "multiple", "root", 0, "vdom")
    assert "fortilink" in result["untrusted_device_output"] and "current vf" not in result["untrusted_device_output"]
    assert replay.sent == ["config vdom", "edit root", "get system arp", "end"] and replay.unexpected == []
    assert device.state["exec"] == ["get system status"]


def test_the_vd1_session_reads_its_own_empty_arp_table(device):
    replay = device("521-A-vd1-arp", status=VD1_STATUS)
    result = engine.ssh_read(fortigate("arp_table", vdoms=(VD1,)), "fortinet", "arp_table", None, 0, 16000)
    assert result["ok"] is True and (result["vdom"], result["vdom_index"]) == (VD1, 3)
    assert result["untrusted_device_output"].split() == ["Address", "Age(min)", "Hardware", "Addr", "Interface"]
    assert replay.sent[:2] == ["config vdom", "edit " + VD1]


def test_a_vdom_that_is_not_enrolled_is_refused_before_any_per_vdom_command(device):
    replay = device("512-A-root-arp")
    result = engine.ssh_read(fortigate("arp_table", vdoms=(VD1,)), "fortinet", "arp_table", None, 0, 16000)
    assert result["ok"] is False and result["error_code"] == "vdom_scope_required"
    assert (result["vdom_mode"], result["vdom"]) == ("multiple", "root")
    assert "untrusted_device_output" not in result
    assert replay.sessions == 0 and device.state["exec"] == ["get system status"]


def test_a_vdom_the_device_does_not_have_is_refused_as_not_found_before_any_per_vdom_command(device):
    replay = device("512-A-root-arp", status=ONE_VDOM_STATUS)
    result = engine.ssh_read(fortigate("arp_table", vdoms=(MISSING,)), "fortinet", "arp_table", None, 0, 16000)
    assert result["ok"] is False and result["error_code"] == "vdom_not_found"
    assert result["error"] == vdom.ADVICE["vdom_not_found"]
    assert (result["vdom_mode"], result["vdom"]) == ("multiple", "root")
    assert "untrusted_device_output" not in result
    assert replay.sessions == 0 and device.state["exec"] == ["get system status"]


def test_a_missing_vdom_on_a_device_with_more_vdoms_stays_scope_required(device):
    # Live check 197 S5: `nops197-xx` on the 60F with `root` and `nops172-vd1`; the status cannot prove it absent.
    replay = device("512-A-root-arp")
    result = engine.ssh_read(fortigate("arp_table", vdoms=(MISSING,)), "fortinet", "arp_table", None, 0, 16000)
    assert result["ok"] is False and result["error_code"] == "vdom_scope_required"
    assert replay.sessions == 0 and device.state["exec"] == ["get system status"]


def test_the_status_itself_is_read_and_labelled_without_an_enrolled_vdom(device):
    device("512-A-root-arp")
    result = engine.ssh_read(fortigate("system_status", vdoms=()), "fortinet", "system_status", None, 0, 16000)
    assert result["ok"] is True and "Virtual domain configuration: multiple" in result["untrusted_device_output"]
    assert (result["vdom_mode"], result["vdom"], result["data_scope"]) == ("multiple", "root", "device")


def test_a_context_without_the_marker_of_the_vdom_returns_no_data(device):
    replay = device("512-A-root-arp", override={
        ("FortiGate-60F (vdom) # ", "edit root"): ("current vf=" + VD1 + ":3", "FortiGate-60F (root) # ")})
    result = engine.ssh_read(fortigate("arp_table"), "fortinet", "arp_table", None, 0, 16000)
    assert result["ok"] is False and result["error_code"] == "vdom_context_unverified"
    assert "get system arp" not in replay.sent and "untrusted_device_output" not in result


def test_without_a_vdom_context_the_measured_refusal_stays_a_cli_error(device):
    # What the helper read before this change: the plain read answers -61 in multi-VDOM (503-A-noctx-arp).
    text = answer("503-A-noctx-arp", "get system arp")
    assert engine._cli_refused("fortinet", text)


def test_session_statistics_are_labelled_as_device_wide(device):
    stat = [text for prompt, command, text in transcript("94-A-extra")
            if prompt.startswith("FortiGate-60F (" + VD1) and command == "diagnose sys session stat"][0]
    device("521-A-vd1-arp", status=VD1_STATUS, override={
        ("FortiGate-60F (" + VD1 + ") # ", "diagnose sys session stat"): (stat, "FortiGate-60F (" + VD1 + ") # ")})
    result = engine.ssh_read(fortigate("session_stats", vdoms=(VD1,)), "fortinet", "session_stats", None, 0, 16000)
    assert result["ok"] is True and "session_count=17" in result["untrusted_device_output"]
    assert (result["vdom"], result["data_scope"]) == (VD1, "device")


def test_a_read_only_profile_without_diagnose_is_a_permission_refusal_not_an_empty_result(device):
    refusal = answer("542-G-root-diagarp", "diagnose ip arp list")
    replay = device("541-G-root-arp", override={
        ("FortiGate-60F (root) $ ", "diagnose sys session stat"): (refusal, "FortiGate-60F (root) $ ")})
    result = engine.ssh_read(fortigate("session_stats"), "fortinet", "session_stats", None, 0, 16000)
    assert result["ok"] is False and result["error_code"] == "permission_denied"
    assert result["reason"] == "diagnose_not_permitted" and result["vdom"] == "root"
    assert replay.sent[:2] == ["config vdom", "edit root"]


def test_the_read_only_session_reads_get_commands_in_its_context(device):
    replay = device("541-G-root-arp")
    result = engine.ssh_read(fortigate("arp_table"), "fortinet", "arp_table", None, 0, 16000)
    assert result["ok"] is True and result["vdom"] == "root" and replay.unexpected == []


def test_a_no_vdom_device_keeps_the_plain_read_and_is_labelled_root(wire, monkeypatch):
    sent = []

    def exec_read(auth, platform, command, **options):
        sent.append(command)
        return 0, DISABLE_STATUS if command == "get system status" else answer("512-A-root-arp", "get system arp")

    monkeypatch.setattr(engine, "read_from_device", exec_read)
    monkeypatch.setattr(engine.core_session, "fortinet_session", lambda *a, **k: pytest.fail("no interactive session"))
    result = engine.ssh_read(fortigate("arp_table", vdoms=()), "fortinet", "arp_table", None, 0, 16000)
    assert result["ok"] is True and (result["vdom_mode"], result["vdom"]) == ("disable", "root")
    assert "vdom_index" not in result and "data_scope" not in result
    assert sent == ["get system status", "get system arp"]


def test_a_read_after_a_status_without_the_vdom_mode_line_is_refused_before_any_per_vdom_command(device):
    replay = device("512-A-root-arp", status=WITHOUT_MODE)
    result = engine.ssh_read(fortigate("arp_table"), "fortinet", "arp_table", None, 0, 16000)
    assert result["ok"] is False and result["error_code"] == "vdom_unverified"
    assert "untrusted_device_output" not in result and "vdom_mode" not in result
    assert replay.sessions == 0 and device.state["exec"] == ["get system status"]
    table = engine.switch_read(fortigate("arp_table"), "neighbor_l3")
    assert table["ok"] is False and table["error_code"] == "vdom_unverified" and table["records"] == []
    assert replay.sessions == 0


def test_the_status_without_the_vdom_mode_line_is_still_answered_unlabelled(device):
    device("512-A-root-arp", status=WITHOUT_MODE)
    result = engine.ssh_read(fortigate("system_status"), "fortinet", "system_status", None, 0, 16000)
    assert result["ok"] is True and "vdom_mode" not in result and "data_scope" not in result


@pytest.mark.parametrize("tool", ["triage_routing", "triage_health", "triage_vpn"])
def test_a_triage_after_a_status_without_the_vdom_mode_line_stops_unverified(device, tool):
    replay = device("512-A-root-arp", "517-A-root-physical", "514-A-root-intfshow", status=WITHOUT_MODE)
    target = fortigate("system_status", "route_lookup", "policy_routes_ipv4", "sdwan_health", "arp_table",
                       "ipsec_summary", "routing_table", "ike_errors", "session_stats", "physical_interfaces",
                       "interface_vlan_ids", addresses=("192.0.2.10",))
    result = {"triage_routing": lambda: engine.triage_routing(target, "192.0.2.10"),
              "triage_health": lambda: engine.triage_health(target),
              "triage_vpn": lambda: engine.triage_vpn(target, "netops-172-p1")}[tool]()
    assert result["ok"] is False and result["error_code"] == "vdom_unverified"
    assert result["verdict"] == "incomplete" and result["failed_step"] == "system_status"
    assert result["vdom_mode"] is None and result["current_vdom"] is None
    assert replay.sessions == 0 and device.state["exec"] == ["get system status"]


def test_the_triage_parsers_give_no_verdict_from_a_status_without_the_vdom_mode_line():
    texts = {"system_status": WITHOUT_MODE,
             "route_lookup": "Routing table for VRF=0\n% Network not in table\n",
             "policy_routes_ipv4": "list route policy info(vf=root):\n\n", "sdwan_health": "",
             "arp_table": answer("512-A-root-arp", "get system arp")}
    result = triage_routing.run(lambda query, parameters: _answer(texts[query], "root"), _clock(), "192.0.2.10", "fw")
    assert result["verdict"] == "incomplete" and result["vdom"] is None
    assert {item["reason"] for item in result["missing"]} == {"vdom_unverified"}
    health = triage_health.run(lambda query: _answer(WITHOUT_MODE if query == "system_status" else "x", "root"), _clock())
    assert health["verdict"] == "incomplete" and health["vdom"] is None
    assert {item["reason"] for item in health["missing"] if item["reason"] != "not_applicable"} == {"vdom_unverified"}


# --- switch_read: interface tables and VDOM membership ------------------------------------------------------


def _full_interface_configuration(name, *entries):
    """`show system interface` in configuration form from the measured `edit` / `set vdom` lines of `name`.

    The 514/523 captures were filtered on the device to the `edit` and `set vdom` lines; the `config`, `next`
    and `end` lines are restored here and `entries` are appended (synthetic VLAN interfaces, documentation
    addresses).
    """
    output = ["config system interface"]
    for line in answer(name, "show system interface").split("\n"):
        if line.startswith("    edit ") and len(output) > 1:
            output.append("    next")
        output.append(line)
    output.append("    next")
    for entry in entries:
        output.extend(entry.strip("\n").split("\n") + ["    next"])
    return "\n".join(output + ["end"])


ROOT_VLAN = ('    edit "root-vlan10"\n        set vdom "root"\n        set ip 192.0.2.1 255.255.255.0\n'
             '        set interface "internal"\n        set vlanid 10')
VD1_VLAN = '    edit "vd1-vlan"\n        set vdom "nops172-vd1"\n        set interface "dmz"\n        set vlanid 100'


def _vlan_device(device, configuration, status=ROOT_STATUS, context="root"):
    prompt = "FortiGate-60F (" + context + ") # "
    return device("512-A-root-arp", "521-A-vd1-arp", status=status,
                  override={(prompt, "show system interface"): (configuration, prompt)})


def test_the_vlan_table_keeps_only_vlans_whose_own_set_vdom_names_the_session_vdom(device):
    # Review 175-rv finding 2: 514 (root context) lists the interfaces of every VDOM.
    replay = _vlan_device(device, _full_interface_configuration("514-A-root-intfshow", ROOT_VLAN, VD1_VLAN))
    result = engine.switch_read(fortigate("interface_vlan_ids"), "vlan")
    assert result["ok"] is True, result
    assert [(row["name"], row["vlan_id"], row["vdom"]) for row in result["records"]] == [("root-vlan10", 10, "root")]
    assert (result["vdom"], result["data_scope"], result["other_vdom_records"]) == ("root", "vdom", 1)
    assert replay.sent == ["config vdom", "edit root", "show system interface", "end"]


def test_the_vd1_session_gets_only_its_own_vlan(device):
    configuration = _full_interface_configuration("523-A-vd1-intfshow", ROOT_VLAN, VD1_VLAN)
    _vlan_device(device, configuration, status=VD1_STATUS, context=VD1)
    result = engine.switch_read(fortigate("interface_vlan_ids", vdoms=(VD1,)), "vlan")
    assert [(row["name"], row["interface"], row["vdom"]) for row in result["records"]] == [("vd1-vlan", "dmz", VD1)]
    assert result["other_vdom_records"] == 1


def test_ssh_read_projects_only_the_vlans_of_the_session_vdom(device):
    _vlan_device(device, _full_interface_configuration("514-A-root-intfshow", ROOT_VLAN, VD1_VLAN))
    result = engine.ssh_read(fortigate("interface_vlan_ids"), "fortinet", "interface_vlan_ids", None, 0, 16000)
    assert result["ok"] is True, result
    text = result["untrusted_device_output"]
    assert '"root-vlan10"' in text and "vd1-vlan" not in text and "set vdom" not in text
    assert (result["vdom"], result["data_scope"], result["other_vdom_records"]) == ("root", "vdom", 1)


def test_a_vlan_without_its_own_set_vdom_is_not_labelled_as_a_vlan_of_the_session_vdom(device):
    orphan = '    edit "orphan-vlan"\n        set interface "dmz"\n        set vlanid 200'
    _vlan_device(device, _full_interface_configuration("514-A-root-intfshow", ROOT_VLAN, orphan))
    result = engine.switch_read(fortigate("interface_vlan_ids"), "vlan")
    assert result["ok"] is False and result["error_code"] == "vdom_membership_unverified" and result["records"] == []
    raw = engine.ssh_read(fortigate("interface_vlan_ids"), "fortinet", "interface_vlan_ids", None, 0, 16000)
    assert raw["ok"] is False and raw["error_code"] == "vdom_membership_unverified"
    assert "untrusted_device_output" not in raw


def test_a_no_vdom_vlan_projection_is_unchanged(wire, monkeypatch):
    configuration = ('config system interface\n    edit "wan1"\n        set vdom "root"\n    next\n' + ROOT_VLAN
                     + '\n    next\nend')

    def exec_read(auth, platform, command, **options):
        return 0, DISABLE_STATUS if command == "get system status" else configuration

    monkeypatch.setattr(engine, "read_from_device", exec_read)
    result = engine.switch_read(fortigate("interface_vlan_ids", vdoms=()), "vlan")
    assert [(row["name"], row["vlan_id"]) for row in result["records"]] == [("root-vlan10", 10)]
    assert "vdom" not in result["records"][0] and "other_vdom_records" not in result
    assert (result["vdom_mode"], result["vdom"]) == ("disable", "root")


LLDP_DMZ = "1 port 'dmz' 1 mac 00:00:5e:00:53:01 chassis 00:00:5e:00:53:01 port 'port1' system 'sw1'"
LLDP_WAN1 = "2 port 'wan1' 1 mac 00:00:5e:00:53:02 chassis 00:00:5e:00:53:02 port 'port2' system 'sw2'"


def test_lldp_rows_are_assigned_to_the_vdom_of_their_local_port(device):
    prompt = "FortiGate-60F (" + VD1 + ") # "
    replay = device("521-A-vd1-arp", "523-A-vd1-intfshow", status=VD1_STATUS, override={
        (prompt, "diagnose lldp rx neighbor summary"): (LLDP_DMZ + "\n" + LLDP_WAN1, prompt)})
    result = engine.switch_read(fortigate("lldp_summary", "interface_vlan_ids", vdoms=(VD1,)), "lldp_neighbor")
    assert result["ok"] is True, result
    assert [(row["local_port"], row["vdom"]) for row in result["records"]] == [("dmz", VD1)]
    assert (result["other_vdom_records"], result["data_scope"]) == (1, "vdom")
    assert replay.sent[-2:] == ["show system interface", "end"]
    refused = engine.switch_read(fortigate("lldp_summary", vdoms=(VD1,)), "lldp_neighbor")
    assert refused["ok"] is False and refused["error_code"] == "vdom_membership_unverified"
    assert refused["records"] == []


def test_every_read_that_lists_interfaces_of_any_vdom_is_joined_or_labelled():
    assert vdom.MEMBERSHIP_READS == {"physical_interfaces", "system_interfaces", "lldp_summary"}
    assert vdom.DATA_SCOPES["interface_vlan_ids"] == "all_vdoms"
    assert {vdom.DATA_SCOPES[query] for query in ("performance", "ha_status", "ntp_status", "conserve_state",
                                                    "autoupdate_versions", "session_stats")} == {"device"}


def _interfaces_device(device):
    extra = transcript("94-A-extra")
    listing = [text for prompt, command, text in extra
               if prompt.startswith("FortiGate-60F (" + VD1) and command == "get system interface"][0]
    prompt = "FortiGate-60F (" + VD1 + ") # "
    return device("521-A-vd1-arp", "523-A-vd1-intfshow", "526-A-vd1-physical", status=VD1_STATUS,
                  override={(prompt, "get system interface"): (listing, prompt)})


def test_ip_interface_keeps_only_the_interfaces_of_the_session_vdom(device):
    replay = _interfaces_device(device)
    target = fortigate("system_interfaces", "interface_vlan_ids", vdoms=(VD1,))
    result = engine.switch_read(target, "ip_interface")
    assert result["ok"] is True, result
    assert [(row["interface"], row["vdom"]) for row in result["records"]] == [("dmz", VD1)]
    assert result["other_vdom_records"] >= 2 and (result["vdom"], result["data_scope"]) == (VD1, "vdom")
    assert replay.sent == ["config vdom", "edit " + VD1, "get system interface", "show system interface", "end"]
    assert [source["query"] for source in result["sources"]] == ["system_interfaces", "interface_vlan_ids"]


def test_physical_ports_of_other_vdoms_are_not_listed_as_ports_of_this_vdom(device):
    _interfaces_device(device)
    target = fortigate("physical_interfaces", "interface_vlan_ids", vdoms=(VD1,))
    result = engine.switch_read(target, "interface")
    assert result["ok"] is True, result
    assert [(row["name"], row["vdom"]) for row in result["records"]] == [("dmz", VD1)]
    assert result["other_vdom_records"] == 12


def test_without_the_membership_query_the_interface_table_is_not_mixed(device):
    replay = _interfaces_device(device)
    result = engine.switch_read(fortigate("system_interfaces", vdoms=(VD1,)), "ip_interface")
    assert result["ok"] is False and result["error_code"] == "vdom_membership_unverified"
    assert result["records"] == [] and "interface_vlan_ids_join_not_enabled" in result["warnings"]
    assert "show system interface" not in replay.sent


def test_a_neighbor_table_in_multi_vdom_names_the_vdom_of_each_row(device):
    device("512-A-root-arp")
    result = engine.switch_read(fortigate("arp_table"), "neighbor_l3")
    assert result["ok"] is True and result["records"]
    assert {row["vdom"] for row in result["records"]} == {"root"} and result["vdom_mode"] == "multiple"


def test_a_table_read_of_a_vdom_that_is_not_enrolled_is_refused(device):
    replay = device("512-A-root-arp")
    result = engine.switch_read(fortigate("arp_table", vdoms=()), "neighbor_l3")
    assert result["ok"] is False and result["error_code"] == "vdom_scope_required" and result["records"] == []
    assert replay.sessions == 0


def test_a_table_read_of_a_vdom_the_device_does_not_have_is_refused_as_not_found(device):
    replay = device("512-A-root-arp", status=ONE_VDOM_STATUS)
    result = engine.switch_read(fortigate("arp_table", vdoms=(MISSING,)), "neighbor_l3")
    assert result["ok"] is False and result["error_code"] == "vdom_not_found" and result["records"] == []
    assert result["status"] == "permission_denied" and "vdom_not_found" in result["warnings"]
    assert replay.sessions == 0


# --- triage_health: scope of every part, physical ports assigned to their VDOM (review 175-rv finding 3) -----


def _health_device(device, physical, intfshow, status=ROOT_STATUS, context="root"):
    stat = [text for prompt, command, text in transcript("94-A-extra")
            if prompt.startswith("FortiGate-60F (" + VD1) and command == "diagnose sys session stat"][0]
    prompt = "FortiGate-60F (" + context + ") # "
    return device(physical, intfshow, "512-A-root-arp", "521-A-vd1-arp", status=status,
                  override={(prompt, "diagnose sys session stat"): (stat, prompt)})


def _health_target(*extra, vdoms=("root",)):
    return fortigate("system_status", "session_stats", "physical_interfaces", *extra, vdoms=vdoms)


def test_triage_health_lists_only_the_root_ports_and_keeps_the_device_scope_of_sessions(device):
    replay = _health_device(device, "517-A-root-physical", "514-A-root-intfshow")
    result = engine.triage_health(_health_target("interface_vlan_ids"))
    assert (result["vdom_mode"], result["vdom"]) == ("multiple", "root")
    names = [port["name"] for port in result["chain"]["links"]["physical"]]
    assert "dmz" not in names and "wan1" in names and len(names) == 12
    assert result["chain"]["links"]["other_vdom_ports"] == 1
    assert result["chain"]["sessions"]["session_count"] == 17 and result["chain"]["sessions"]["data_scope"] == "device"
    assert result["data_scopes"] == {"system_status": "device", "session_stats": "device",
                                     "physical_interfaces": "vdom"}
    assert result["verdict"] == "incomplete"
    assert "show system interface" in replay.sent and replay.unexpected == []


def test_triage_health_in_vd1_lists_only_the_vd1_port(device):
    _health_device(device, "526-A-vd1-physical", "523-A-vd1-intfshow", status=VD1_STATUS, context=VD1)
    result = engine.triage_health(_health_target("interface_vlan_ids", vdoms=(VD1,)))
    assert [port["name"] for port in result["chain"]["links"]["physical"]] == ["dmz"]
    assert result["chain"]["links"]["other_vdom_ports"] == 12 and result["vdom"] == VD1


def test_triage_health_without_the_membership_query_does_not_present_ports_of_other_vdoms(device):
    replay = _health_device(device, "517-A-root-physical", "514-A-root-intfshow")
    result = engine.triage_health(_health_target())
    assert result["chain"]["links"]["physical"] is None and "other_vdom_ports" not in result["chain"]["links"]
    assert {"step": "physical_interfaces", "reason": "vdom_membership_unverified"} in result["missing"]
    assert "physical_interfaces" not in result["checked"] and result["verdict"] == "incomplete"
    assert "show system interface" not in replay.sent


def test_triage_health_refuses_ports_the_membership_does_not_name():
    texts = {"system_status": ROOT_STATUS, "physical_interfaces": answer("517-A-root-physical",
                                                                         "get system interface physical")}
    owners = vdom.memberships(answer("514-A-root-intfshow", "show system interface"))
    del owners["wan2"]

    def read(query):
        if query not in texts:
            return {"ok": False, "reason": "permission_denied"}
        return {**_answer(texts[query], "root"), "data_scope": "all_vdoms", "interface_vdoms": owners}

    result = triage_health.run(read, _clock())
    assert result["chain"]["links"]["physical"] is None
    assert {"step": "physical_interfaces", "reason": "vdom_membership_unverified"} in result["missing"]


# --- triage_health: the global system state is read in `config global` (task 202, finding N2 of task 197) -----

GLOBAL_STEPS = {"conserve_state": "diagnose hardware sysinfo conserve", "performance": "get system performance status",
                "ha_status": "get system ha status", "ha_checksum": "diagnose sys ha checksum cluster",
                "ntp_status": "diagnose sys ntp status", "autoupdate_versions": "diagnose autoupdate versions"}


def _global_answers(prompt):
    """The global reads answered at the `(global)` prompt (payloads of the triage_health tests)."""
    from test_triage_health import HA_AP, outputs
    values = outputs(ha_status=HA_AP)
    return {(prompt, command): (values[query], prompt) for query, command in GLOBAL_STEPS.items()}


def test_the_measured_global_context_has_no_marker_but_its_prompt_and_vdom_context_refuses_global_reads():
    # 34: `config global` answers nothing and the prompt names `(global)`; 35: `edit root` -> `-61` (finding N2).
    ((prompt, command, text), (following, _, _)) = transcript("197-34-gdiag-global")[:2]
    assert (prompt, command, text, following) == ("FortiGate-60F # ", "config global", "", "FortiGate-60F (global) # ")
    assert vdom.global_prompt(following.encode()) and not vdom.global_prompt(b"FortiGate-60F (root) # ")
    assert vdom.global_prompt(b"FortiGate-60F (global) $ ") and not vdom.global_prompt(b"FortiGate-60F # ")
    refusal = answer("197-35-diag-root", "get system performance status")
    assert "Return code -61" in refusal and engine._cli_refused("fortinet", refusal)
    assert vdom.GLOBAL_QUERIES == set(GLOBAL_STEPS)
    assert all(vdom.DATA_SCOPES[query] == "device" for query in vdom.GLOBAL_QUERIES)


def test_multi_vdom_triage_health_reads_the_global_parts_in_config_global_with_device_scope(device):
    stat = [text for prompt, command, text in transcript("94-A-extra")
            if prompt.startswith("FortiGate-60F (root") and command == "diagnose sys session stat"][0]
    replay = device("197-34-gdiag-global", "517-A-root-physical", "514-A-root-intfshow", "512-A-root-arp",
                    override={("FortiGate-60F (root) # ", "diagnose sys session stat"): (stat, "FortiGate-60F (root) # "),
                              **_global_answers("FortiGate-60F (global) # ")})
    result = engine.triage_health(_health_target("interface_vlan_ids", *GLOBAL_STEPS))
    assert replay.unexpected == [], replay.unexpected
    assert (result["vdom_mode"], result["vdom"]) == ("multiple", "root")
    missing = {item["step"] for item in result["missing"]}
    assert missing == {"sdwan_health"}, result["missing"]
    assert set(GLOBAL_STEPS) <= set(result["checked"])
    assert result["data_scopes"] == {"system_status": "device", "session_stats": "device",
                                     "physical_interfaces": "vdom", **dict.fromkeys(GLOBAL_STEPS, "device")}
    assert result["chain"]["resources"]["performance"] is not None and result["chain"]["ha"]["mode"] == "HA A-P"
    assert result["chain"]["ntp"] is not None and result["chain"]["updates"] is not None
    assert result["chain"]["ha"]["checksum"] is not None and result["chain"]["sessions"]["data_scope"] == "device"
    for command in GLOBAL_STEPS.values():
        position = replay.sent.index(command)
        assert replay.sent[position - 1:position + 2] == ["config global", command, "end"]
    assert replay.sent.count("config global") == len(GLOBAL_STEPS)
    assert "edit root" in replay.sent  # the per-VDOM parts still run in the verified VDOM context


def test_a_read_only_diag_session_reads_global_parts_in_global_and_sessions_in_its_vdom(device):
    # The task 197 diag account (prompt `$`): 35 for the VDOM context, `(global) $` for the global context.
    login, context = "FortiGate-60F $ ", "FortiGate-60F (global) $ "
    replay = device("197-35-diag-root", override={(login, "config global"): ("", context),
                                                  (context, "end"): ("", login),
                                                  ("FortiGate-60F (root) $ ", "end"): ("", login),
                                                  **_global_answers(context)})
    result = engine.triage_health(fortigate("system_status", "session_stats", *GLOBAL_STEPS))
    assert replay.unexpected == [], replay.unexpected
    assert result["chain"]["sessions"]["session_count"] == 37
    assert {item["step"]: item["reason"] for item in result["missing"]} == {
        "physical_interfaces": "permission_denied", "sdwan_health": "permission_denied"}
    assert all(result["data_scopes"][query] == "device" for query in GLOBAL_STEPS)
    assert "get system performance status" in replay.sent and replay.sent.count("edit root") == 1


def test_an_account_without_config_global_gets_the_global_parts_refused_not_a_crash(device):
    # 33: the account without cli-config is refused `config vdom` (`Unknown action 0`, `-1`); `config global` is
    # answered with the same measured refusal here. Nothing global is read or guessed.
    refusal = answer("197-33-diag-noconfig", "config vdom")
    replay = device("197-33-diag-noconfig", override={("FortiGate-60F $ ", "config global"): (refusal, "FortiGate-60F $ ")})
    result = engine.triage_health(fortigate("system_status", "session_stats", *GLOBAL_STEPS))
    assert result["ok"] is True and result["verdict"] == "incomplete" and result["vdom"] == "root"
    reasons = {item["step"]: item["reason"] for item in result["missing"]}
    assert all(reasons[query] == "permission_denied" for query in GLOBAL_STEPS if query != "ha_checksum")
    assert reasons["ha_checksum"] == "permission_denied"  # follows the refused ha_status
    assert reasons["session_stats"] == "vdom_unverified"
    assert result["chain"]["resources"] == {"conserve": None, "performance": None}
    assert result["checked"] == ["system_status"] and result["data_scopes"] == {"system_status": "device"}
    assert not any(command in replay.sent for command in GLOBAL_STEPS.values())


def test_the_global_read_refusal_names_the_global_context(device):
    refusal = answer("197-33-diag-noconfig", "config vdom")
    device("197-33-diag-noconfig", override={("FortiGate-60F $ ", "config global"): (refusal, "FortiGate-60F $ ")})
    holder = {"scope": {"vdom_mode": "multiple", "vdom": "root"}}
    token = engine._TRIAGE_SCOPE.set(holder)
    try:
        result = engine.triage_health_read(fortigate("system_status", "performance"), "fortinet", "performance")
    finally:
        engine._TRIAGE_SCOPE.reset(token)
    assert result["ok"] is False and (result["reason"], result["error_code"]) == ("permission_denied", "permission_denied")
    assert (result["detail"], result["context"], result["data_scope"]) == ("global_context_not_permitted", "global", "device")
    assert "text" not in result


def test_a_global_context_without_the_global_prompt_returns_no_data(device):
    replay = device("197-34-gdiag-global", override={
        ("FortiGate-60F # ", "config global"): ("", "FortiGate-60F (root) # ")})
    holder = {"scope": {"vdom_mode": "multiple", "vdom": "root"}}
    token = engine._TRIAGE_SCOPE.set(holder)
    try:
        result = engine.triage_health_read(fortigate("system_status", "performance"), "fortinet", "performance")
    finally:
        engine._TRIAGE_SCOPE.reset(token)
    assert result["ok"] is False and result["error_code"] == "global_context_unverified"
    assert result["reason"] == "vdom_unverified" and "get system performance status" not in replay.sent


def test_no_vdom_triage_health_keeps_the_plain_reads_without_config_global(wire, monkeypatch):
    from test_triage_health import COMMANDS, outputs
    values = outputs(system_status=DISABLE_STATUS)
    sent = []

    def exec_read(auth, platform, command, **options):
        sent.append(command)
        return 0, values[COMMANDS[command]]

    monkeypatch.setattr(engine, "read_from_device", exec_read)
    monkeypatch.setattr(engine.core_session, "fortinet_session", lambda *a, **k: pytest.fail("no interactive session"))
    result = engine.triage_health(fortigate(*COMMANDS.values(), vdoms=()))
    assert (result["vdom_mode"], result["vdom"]) == ("disable", "root") and "data_scopes" not in result
    assert "config global" not in sent and sent[0] == "get system status"
    assert {GLOBAL_STEPS[query] for query in GLOBAL_STEPS if query != "ha_checksum"} <= set(sent)


# --- triage_routing / triage_vpn ----------------------------------------------------------------------------

NOW = datetime(2026, 11, 14, 18, 0, 0, tzinfo=timezone.utc)


def _clock():
    ticks = iter(NOW + timedelta(seconds=n) for n in range(100))
    return lambda: next(ticks)


def _answer(text, vdom_name=None):
    return {"ok": True, "text": text, "content_sha256": hashlib.sha256(text.encode()).hexdigest(),
            **({"vdom": vdom_name} if vdom_name else {})}


def test_triage_vpn_reports_a_vd1_tunnel_only_from_reads_in_that_vdom():
    summary = answer("525-A-vd1-ipsec", "get vpn ipsec tunnel summary")
    texts = {"system_status": VD1_STATUS, "ipsec_summary": summary,
             "routing_table": answer("527-A-vd1-rt", "get router info routing-table all"),
             "ike_errors": "no ike errors\n"}
    # G14 detail reads: DERIVED minimal answers (no IKE SA, header only), not a VDOM measurement
    texts.update(ike_gateway_detail="", ipsec_tunnel_detail="list ipsec tunnel by names in vd 1\n")
    result = triage_vpn.run(lambda query, parameters=None: _answer(texts[query], VD1), _clock(), "netops-172-p1")
    assert (result["vdom_mode"], result["vdom"], result["current_vdom"]) == ("multiple", VD1, VD1)
    assert result["chain"]["tunnel"]["instances"][0]["name"] == "netops-172-p1"
    unlabelled = triage_vpn.run(lambda query, parameters=None: _answer(texts[query]), _clock(), "netops-172-p1")
    assert unlabelled["verdict"] == "incomplete" and unlabelled["chain"]["tunnel"]["instances"] is None
    assert {"step": "ipsec_summary", "reason": "vdom_unverified"} in unlabelled["missing"]


def test_a_missing_tunnel_names_the_vdom_it_was_looked_for_in():
    texts = {"system_status": VD1_STATUS, "ipsec_summary": answer("525-A-vd1-ipsec", "get vpn ipsec tunnel summary"),
             "routing_table": "Routing table for VRF=0\n", "ike_errors": ""}
    result = triage_vpn.run(lambda query, parameters=None: _answer(texts[query], VD1), _clock(), "other-tunnel")
    (finding,) = [item for item in result["findings"] if item["id"] == "F-VPN-NOT-FOUND"]
    assert finding["fact"] == "tunnel not in get vpn ipsec tunnel summary in VDOM " + VD1


def test_triage_routing_gives_no_verdict_from_reads_outside_the_session_vdom():
    texts = {"system_status": ROOT_STATUS,
             "route_lookup": "Routing table for VRF=0\n% Network not in table\n",
             "policy_routes_ipv4": "list route policy info(vf=root):\n\n", "sdwan_health": "",
             "arp_table": answer("512-A-root-arp", "get system arp")}
    result = triage_routing.run(lambda query, parameters: _answer(texts[query]), _clock(), "192.0.2.10", "fw")
    assert result["verdict"] == "incomplete" and result["current_vdom"] == "root"
    assert all(item["reason"] == "vdom_unverified" for item in result["missing"])
    scoped = triage_routing.run(lambda query, parameters: _answer(texts[query], "root"), _clock(), "192.0.2.10", "fw")
    assert scoped["verdict"] == "fault_found" and scoped["vdom"] == "root"


def test_engine_triage_routing_refuses_a_multi_vdom_session_without_an_enrolled_vdom(device):
    replay = device("512-A-root-arp")
    target = fortigate("system_status", "route_lookup", "policy_routes_ipv4", "sdwan_health", "arp_table",
                       vdoms=(), addresses=("192.0.2.10",))
    result = engine.triage_routing(target, "192.0.2.10")
    assert result["ok"] is False and result["error_code"] == "vdom_scope_required"
    assert result["verdict"] == "incomplete" and (result["vdom_mode"], result["current_vdom"]) == ("multiple", "root")
    assert replay.sessions == 0 and device.state["exec"] == ["get system status"]


def test_engine_triage_routing_stops_with_vdom_not_found_for_a_vdom_the_device_does_not_have(device):
    replay = device("512-A-root-arp", status=ONE_VDOM_STATUS)
    target = fortigate("system_status", "route_lookup", "policy_routes_ipv4", "sdwan_health", "arp_table",
                       vdoms=(MISSING,), addresses=("192.0.2.10",))
    result = engine.triage_routing(target, "192.0.2.10")
    assert result["ok"] is False and result["error_code"] == "vdom_not_found"
    assert result["verdict"] == "incomplete" and (result["vdom_mode"], result["current_vdom"]) == ("multiple", "root")
    assert replay.sessions == 0 and device.state["exec"] == ["get system status"]


def test_engine_triage_vpn_reads_every_step_inside_the_enrolled_vdom(device):
    replay = device("525-A-vd1-ipsec", "527-A-vd1-rt", status=VD1_STATUS)
    target = fortigate("system_status", "ipsec_summary", "routing_table", "ike_errors", vdoms=(VD1,))
    result = engine.triage_vpn(target, "netops-172-p1")
    assert (result["vdom_mode"], result["current_vdom"]) == ("multiple", VD1)
    assert result["chain"]["tunnel"]["instances"][0]["name"] == "netops-172-p1"
    # `diagnose vpn ike errors` was not recorded: the replay refuses it, so the verdict stays incomplete.
    assert result["verdict"] == "incomplete" and {"step": "ike_errors", "reason": "device_cli_error"} in result["missing"]
    assert replay.sent.count("edit " + VD1) == 3 and replay.sessions == 1
    assert device.state["exec"] == ["get system status"]


# --- fortios_diagnostics sessions recipe ----------------------------------------------------------------------


class _RecipeShell:
    """The measured answers of a super_admin (or read-only) root session for the sessions recipe.

    Derived: the empty filter display is the measured `vd: 3` display with `vd: any`, the interface owner is the
    measured `set vdom` line in configuration form, and the netlink line is synthetic.
    """

    def __init__(self, listing, readonly=False, marker="current vf=root:0"):
        self.commands = []
        self.prompt = b"FortiGate-60F (root) " + (b"$ " if readonly else b"# ")
        self.readonly = readonly
        self.listing = listing
        self.marker = marker
        extra = transcript("94-A-extra")
        shown = [text for _, command, text in extra if command == "diagnose sys session filter"][0]
        self.empty = shown.replace("vd: 3", "vd: any")
        self.filter = self.empty

    def navigate(self, command):
        self.commands.append(command)
        return self.marker if command.startswith("edit ") else ""

    def command(self, command, timeout=10):
        self.commands.append(command)
        if command == "get system status":
            return ROOT_STATUS
        if self.readonly and command.startswith("diagnose "):
            raise diagnostics.StepRefused(answer("548-G-root-session", "diagnose sys session list"))
        if command.startswith('show full-configuration system interface "wan1"'):
            return 'config system interface\n    edit "wan1"\n        set vdom "root"\n    next\nend'
        if command.startswith("diagnose netlink interface list "):
            return "if=wan1 family=00 type=1 index=5 mtu=1500 link=0 master=0"
        if command == "diagnose sys session filter":
            return self.filter
        if command == "diagnose sys session filter clear":
            self.filter = self.empty
        if command == "diagnose sys session list":
            return self.listing
        return ""

    def listen(self, timeout):
        return self.listing


def _sessions(shell):
    return diagnostics.run(shell, "sessions", "203.0.113.2", "wan1", 3, 5, "root",
                           source_address="192.0.2.36", source_port=46582, destination_port=22, protocol=6)


def _root_listing():
    return [text for prompt, command, text in transcript("94-A-extra")
            if prompt.startswith("FortiGate-60F (root)") and command == "diagnose sys session list"][0]


def test_the_sessions_recipe_filters_by_the_verified_vdom_index():
    shell = _RecipeShell(_root_listing())
    output, timed_out, identity, domain = _sessions(shell)
    assert domain == "root" and "vd=0" in output and identity == ("FortiGate-60F", "7.6.8", "3744")
    assert shell.commands[1:3] == ["config vdom", "edit root"]
    assert "diagnose sys session filter vd 0" in shell.commands
    assert shell.commands.index("diagnose sys session filter vd 0") < shell.commands.index("diagnose sys session list")
    assert shell.commands[-1] == "end" and shell.filter == shell.empty


def test_a_listing_with_sessions_of_another_vdom_is_refused_and_the_filter_restored():
    shell = _RecipeShell(answer("528-A-vd1-session", "diagnose sys session list"), marker="current vf=root:3")
    with pytest.raises(diagnostics.ScopeRefused, match="does not belong to the requested VDOM"):
        _sessions(shell)
    assert "diagnose sys session filter clear" in shell.commands and shell.filter == shell.empty


def test_a_read_only_profile_gets_a_clear_refusal_for_the_sessions_recipe():
    shell = _RecipeShell("", readonly=True)
    with pytest.raises(diagnostics.PermissionRefused, match="no diagnose commands"):
        _sessions(shell)
    assert "diagnose sys session list" not in shell.commands


def test_a_session_that_cannot_enter_the_vdom_context_is_refused():
    shell = _RecipeShell(_root_listing(), marker="")
    with pytest.raises(diagnostics.ScopeRefused, match="verified context"):
        _sessions(shell)
    assert not any(command.startswith("diagnose") for command in shell.commands)


# --- release gate: the one VDOM context of the diagnostics stays the measured, verified one ----------------


def _gate():
    import importlib.util
    path = Path(__file__).resolve().parents[1] / "tests/support/check_public_release.py"
    spec = importlib.util.spec_from_file_location("multivdom_gate", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("old,new", [
    ('if mode == "multiple" and recipe == "sessions" else None', 'if mode == "multiple" else None'),
    ('return context_index(shell.navigate("edit " + vdom), vdom)', 'return 0'),
    ('    if context is not None and restored:\n            leave_vdom(shell)',
     '    if context is not None and restored:\n            shell.navigate("end")'),
])
def test_the_release_gate_admits_only_the_verified_sessions_context(old, new):
    import ast
    gate = _gate()
    text = (Path(__file__).resolve().parents[1] / "src/netops_helper/fortios_diagnostics.py").read_text()
    assert gate._diagnostic_vdom_allowed(ast.parse(text))
    assert text.count(old) == 1
    assert not gate._diagnostic_vdom_allowed(ast.parse(text.replace(old, new, 1)))


# --- per-VDOM administrator (task 206, finding N1 of task 197) -----------------------------------------------
# The account `set vdom "nops172-vd1"` logged in through an interface of its VDOM: `config vdom` answers
# `Unknown action 0`, the status names its VDOM and `get system arp` answers right after the login (44-run2).

VDOM_ADMIN = ("197-44-vd1acct-config-vdom", "197-44-vd1acct-status", "197-44-vd1acct-arp",
              "197-44-vd1acct-intfshow", "197-44-vd1acct-physical")
VDOM_ADMIN_STATUS = answer("197-44-vd1acct-status", "get system status")
LOGIN = "FortiGate-60F $ "


def _vdom_admin(device, override=None):
    return device(*VDOM_ADMIN, status=VDOM_ADMIN_STATUS, override=override)


def test_the_measured_per_vdom_administrator_signals():
    assert vdom.scope(VDOM_ADMIN_STATUS) == {"vdom_mode": "multiple", "vdom": VD1}
    refusal = answer("197-44-vd1acct-config-vdom", "config vdom")
    assert refusal == "Unknown action 0" and engine._cli_refused("fortinet", refusal)
    probe = answer("197-44-vd1acct-arp", "get system arp")
    assert vdom.login_probe_answered(probe) and vdom.login_context(VDOM_ADMIN_STATUS, probe, VD1)
    # The same probe in a global session outside a VDOM context is refused (503), the root table is a table (512).
    assert not vdom.login_probe_answered(answer("503-A-noctx-arp", "get system arp"))
    assert vdom.login_probe_answered(answer("512-A-root-arp", "get system arp"))
    assert not vdom.login_context(VDOM_ADMIN_STATUS, probe, "root")
    assert not vdom.login_context(ROOT_STATUS, probe, VD1)
    assert not vdom.login_context(DISABLE_STATUS, probe, "root")
    assert not vdom.login_probe_answered("") and not vdom.login_probe_answered("Unknown action 0")
    assert vdom.LOGIN_CONTEXT_PROBE == engine.READ_QUERIES["fortinet"]["arp_table"].command


def test_the_reads_refused_to_a_per_vdom_administrator_are_the_device_and_all_vdom_reads():
    assert vdom.VDOM_ADMIN_REFUSED_QUERIES == {query for query, scope in vdom.DATA_SCOPES.items()
                                               if scope in ("device", "all_vdoms")} - {"system_status"}
    assert {"physical_interfaces", "system_interfaces", "interface_vlan_ids", "session_stats"} <= \
        vdom.VDOM_ADMIN_REFUSED_QUERIES and set(vdom.GLOBAL_QUERIES) <= vdom.VDOM_ADMIN_REFUSED_QUERIES
    catalogue = engine.READ_QUERIES["fortinet"]
    assert engine._VDOM_ADMIN_REFUSED_COMMANDS == {catalogue[query].command for query in vdom.VDOM_ADMIN_REFUSED_QUERIES}
    # No read of the VDOM shares a command with a refused read.
    assert not {query for query, entry in catalogue.items() if entry.command in engine._VDOM_ADMIN_REFUSED_COMMANDS} \
        - vdom.VDOM_ADMIN_REFUSED_QUERIES
    assert vdom.VDOM_ADMIN_GLOBAL in vdom.ADVICE and "global account" in vdom.ADVICE[vdom.VDOM_ADMIN_GLOBAL]


def test_a_per_vdom_administrator_reads_its_own_vdom_without_config_vdom(device):
    replay = _vdom_admin(device)
    result = engine.ssh_read(fortigate("arp_table", vdoms=(VD1,)), "fortinet", "arp_table", None, 0, 16000)
    assert result["ok"] is True, result
    assert (result["vdom_mode"], result["vdom"], result["data_scope"]) == ("multiple", VD1, "vdom")
    assert "vdom_index" not in result
    assert result["untrusted_device_output"].split() == ["Address", "Age(min)", "Hardware", "Addr", "Interface"]
    assert replay.sent == ["config vdom", "get system status", "get system arp", "get system arp"]
    assert "edit " + VD1 not in replay.sent and "end" not in replay.sent and replay.unexpected == []
    assert device.state["exec"] == ["get system status"]


def test_a_per_vdom_administrator_gets_its_table_labelled_with_its_vdom(device):
    # The measured table of the VD1 account was empty; two rows in the measured column layout (512) are added.
    table = answer("197-44-vd1acct-arp", "get system arp") + (
        "\n192.0.2.20        0          00:00:5e:00:53:20 dmz"
        "\n198.51.100.30     1          00:00:5e:00:53:30 nops197-v197")
    replay = _vdom_admin(device, override={(LOGIN, "get system arp"): (table, LOGIN)})
    result = engine.switch_read(fortigate("arp_table", vdoms=(VD1,)), "neighbor_l3")
    assert result["ok"] is True, result
    assert [(row["ip"], row["vdom"]) for row in result["records"]] == [("192.0.2.20", VD1), ("198.51.100.30", VD1)]
    assert (result["vdom"], result["data_scope"]) == (VD1, "vdom") and "vdom_index" not in result
    assert "edit " + VD1 not in replay.sent and replay.unexpected == []


def test_a_per_vdom_administrator_reading_another_vdom_is_refused_before_any_session(device):
    replay = _vdom_admin(device)
    result = engine.ssh_read(fortigate("arp_table", vdoms=("root",)), "fortinet", "arp_table", None, 0, 16000)
    assert result["ok"] is False and result["error_code"] == "vdom_scope_required"
    assert (result["vdom_mode"], result["vdom"]) == ("multiple", VD1) and "untrusted_device_output" not in result
    assert replay.sessions == 0 and device.state["exec"] == ["get system status"]


@pytest.mark.parametrize("query,command", [
    ("physical_interfaces", "get system interface physical"), ("system_interfaces", "get system interface"),
    ("interface_vlan_ids", "show system interface"), ("session_stats", "diagnose sys session stat"),
    ("performance", "get system performance status"), ("ha_status", "get system ha status"),
])
def test_a_global_read_of_a_per_vdom_administrator_gets_the_new_code_and_no_data(device, query, command):
    # 44-run2: the physical listing of the VDOM account shows the ports and addresses of root too.
    assert "203.0.113.254" in answer("197-44-vd1acct-physical", "get system interface physical")
    replay = _vdom_admin(device)
    result = engine.ssh_read(fortigate(query, vdoms=(VD1,)), "fortinet", query, None, 0, 16000)
    assert result["ok"] is False and result["error_code"] == "vdom_admin_global_scope_unavailable", result
    assert result["error"] == vdom.ADVICE["vdom_admin_global_scope_unavailable"]
    assert (result["vdom_mode"], result["vdom"]) == ("multiple", VD1) and "untrusted_device_output" not in result
    assert command not in replay.sent and replay.sent == ["config vdom", "get system status", "get system arp"]


@pytest.mark.parametrize("table,queries", [("interface", ("physical_interfaces", "interface_vlan_ids")),
                                           ("ip_interface", ("system_interfaces", "interface_vlan_ids")),
                                           ("vlan", ("interface_vlan_ids",))])
def test_an_interface_table_of_a_per_vdom_administrator_is_refused_with_the_new_code(device, table, queries):
    replay = _vdom_admin(device)
    result = engine.switch_read(fortigate(*queries, vdoms=(VD1,)), table)
    assert result["ok"] is False and result["error_code"] == "vdom_admin_global_scope_unavailable"
    assert result["status"] == "permission_denied" and result["records"] == []
    assert "vdom_admin_global_scope_unavailable" in result["warnings"]
    assert not {"get system interface physical", "get system interface", "show system interface"} & set(replay.sent)


def test_a_per_vdom_administrator_lldp_read_with_the_all_vdom_join_is_refused_before_any_command(device):
    # Review 206-rv finding 1: the membership join `show system interface` (extra) lists every VDOM; the whole
    # read is refused with the new code before the LLDP command or the join is sent.
    replay = _vdom_admin(device, override={(LOGIN, "diagnose lldp rx neighbor summary"): (
        LLDP_DMZ + "\n" + LLDP_WAN1, LOGIN)})
    result = engine.switch_read(fortigate("lldp_summary", "interface_vlan_ids", vdoms=(VD1,)), "lldp_neighbor")
    assert result["ok"] is False and result["error_code"] == "vdom_admin_global_scope_unavailable", result
    assert result["error"] == vdom.ADVICE["vdom_admin_global_scope_unavailable"]
    assert result["status"] == "permission_denied" and result["records"] == []
    assert (result["vdom_mode"], result["vdom"]) == ("multiple", VD1)
    assert replay.sent == ["config vdom", "get system status", "get system arp"] and replay.unexpected == []
    assert not (engine._VDOM_ADMIN_REFUSED_COMMANDS | {"diagnose lldp rx neighbor summary"}) & set(replay.sent)


def test_a_per_vdom_administrator_lldp_read_without_the_join_sends_no_all_vdom_command(device):
    # Without the membership query nothing beyond the VDOM is sent; the rows cannot be assigned: refused, no rows.
    replay = _vdom_admin(device, override={(LOGIN, "diagnose lldp rx neighbor summary"): (
        LLDP_DMZ + "\n" + LLDP_WAN1, LOGIN)})
    result = engine.switch_read(fortigate("lldp_summary", vdoms=(VD1,)), "lldp_neighbor")
    assert result["ok"] is False and result["error_code"] == "vdom_membership_unverified" and result["records"] == []
    assert replay.sent == ["config vdom", "get system status", "get system arp", "diagnose lldp rx neighbor summary"]
    assert not engine._VDOM_ADMIN_REFUSED_COMMANDS & set(replay.sent)


def test_a_vdom_context_read_checks_its_extra_commands_too(device):
    # The engine read itself: a refused command only in `extra` refuses the whole read before anything is sent.
    replay = _vdom_admin(device)
    with pytest.raises(vdom.VdomRefused) as refused:
        engine._vdom_context_read(fortigate("arp_table", vdoms=(VD1,)), "fortinet", VD1, ("get system arp",),
                                  extra=("show system interface",))
    assert refused.value.code == "vdom_admin_global_scope_unavailable"
    assert replay.sent == ["config vdom", "get system status", "get system arp"]
    assert replay.sent.count("get system arp") == 1 and "show system interface" not in replay.sent


def test_a_status_of_another_vdom_in_the_read_session_fails_closed(device):
    # The identity read named VD1, the session itself names root: nothing more is sent, nothing answered.
    replay = _vdom_admin(device, override={(LOGIN, "get system status"): (ROOT_STATUS, LOGIN)})
    result = engine.ssh_read(fortigate("arp_table", vdoms=(VD1,)), "fortinet", "arp_table", None, 0, 16000)
    assert result["ok"] is False and result["error_code"] == "vdom_context_unverified"
    assert "untrusted_device_output" not in result
    assert replay.sent == ["config vdom", "get system status"]


@pytest.mark.parametrize("probe", [answer("503-A-noctx-arp", "get system arp"), "Unknown action 0", "",
                                   "Address           Age(min)   Hardware Addr      Interface\nCommand fail. Return code -1"])
def test_a_session_without_the_login_context_of_the_vdom_fails_closed(device, probe):
    replay = _vdom_admin(device, override={(LOGIN, "get system arp"): (probe, LOGIN)})
    result = engine.ssh_read(fortigate("routing_table", vdoms=(VD1,)), "fortinet", "routing_table", None, 0, 16000)
    assert result["ok"] is False and result["error_code"] == "vdom_context_unverified"
    assert "untrusted_device_output" not in result
    assert replay.sent == ["config vdom", "get system status", "get system arp"]


def test_a_global_account_without_config_vdom_stays_unverified(device):
    # 33: a global profile without cli-config is refused `config vdom` too; its session is root and outside a VDOM
    # context the probe answers -61 (503): not a per-VDOM login, so the result is unchanged (no data).
    replay = device("197-33-diag-noconfig", override={
        (LOGIN, "get system status"): (ROOT_STATUS, LOGIN),
        (LOGIN, "get system arp"): (answer("503-A-noctx-arp", "get system arp"), LOGIN)})
    result = engine.ssh_read(fortigate("routing_table"), "fortinet", "routing_table", None, 0, 16000)
    assert result["ok"] is False and result["error_code"] == "vdom_context_unverified"
    assert replay.sent == ["config vdom", "get system status", "get system arp"]
    physical = engine.ssh_read(fortigate("physical_interfaces"), "fortinet", "physical_interfaces", None, 0, 16000)
    assert physical["error_code"] == "vdom_context_unverified"


def test_a_global_account_with_config_vdom_never_sends_the_login_probe(device):
    replay = device("512-A-root-arp")
    result = engine.ssh_read(fortigate("arp_table"), "fortinet", "arp_table", None, 0, 16000)
    assert result["ok"] is True and result["vdom_index"] == 0
    assert replay.sent == ["config vdom", "edit root", "get system arp", "end"]


def test_triage_health_of_a_per_vdom_administrator_names_the_new_code_for_every_global_part(device):
    # `config global` of the VDOM account was not measured; it is answered with the measured `config vdom` refusal.
    # The SD-WAN health of the VDOM was not measured for this account; the measured "not running" reply is used.
    refusal = answer("197-44-vd1acct-config-vdom", "config vdom")
    replay = _vdom_admin(device, override={(LOGIN, "config global"): (refusal, LOGIN),
                                           (LOGIN, "diagnose sys sdwan health-check"): (
                                               "SD-WAN health monitor is not running.", LOGIN)})
    target = fortigate("system_status", "session_stats", "physical_interfaces", "interface_vlan_ids", "sdwan_health",
                       *GLOBAL_STEPS, vdoms=(VD1,))
    result = engine.triage_health(target)
    assert (result["vdom_mode"], result["vdom"]) == ("multiple", VD1)
    reasons = {item["step"]: item for item in result["missing"]}
    for step in (*GLOBAL_STEPS, "session_stats", "physical_interfaces"):
        assert reasons[step]["reason"] == "vdom_admin_global_scope_unavailable", reasons[step]
    assert reasons["performance"]["error_code"] == "vdom_admin_global_scope_unavailable"
    assert reasons["performance"]["error"] == vdom.ADVICE["vdom_admin_global_scope_unavailable"]
    # ha_checksum follows the refused ha_status with its code and advice (review 206-rv note).
    assert {key: reasons["ha_checksum"].get(key) for key in ("reason", "error_code", "error")} == {
        key: reasons["ha_status"].get(key) for key in ("reason", "error_code", "error")}
    assert reasons["ha_checksum"]["error_code"] == "vdom_admin_global_scope_unavailable"
    assert not any(item["reason"] == "device_cli_error" for item in result["missing"])
    assert result["verdict"] == "incomplete" and result["checked"] == ["system_status"]
    assert result["chain"]["resources"] == {"conserve": None, "performance": None}
    # One `config global` proves the per-VDOM login; the other global parts are refused without a session.
    assert replay.sent.count("config global") == 1
    assert not any(command in replay.sent for command in GLOBAL_STEPS.values())
    assert not {"get system interface physical", "show system interface", "diagnose sys session stat"} & set(replay.sent)
    # The VDOM part (SD-WAN health) is read in the login context of the VDOM.
    assert "edit " + VD1 not in replay.sent and "diagnose sys sdwan health-check" in replay.sent
    assert reasons["sdwan_health"]["reason"] == "not_applicable" and replay.unexpected == []


def test_the_global_triage_parts_of_a_global_account_without_config_global_stay_permission_denied(device):
    refusal = answer("197-33-diag-noconfig", "config vdom")
    device("197-33-diag-noconfig", override={(LOGIN, "config global"): (refusal, LOGIN),
                                             (LOGIN, "get system status"): (ROOT_STATUS, LOGIN),
                                             (LOGIN, "get system arp"): (answer("503-A-noctx-arp", "get system arp"),
                                                                         LOGIN)})
    result = engine.triage_health(fortigate("system_status", *GLOBAL_STEPS))
    reasons = {item["step"]: item["reason"] for item in result["missing"]}
    assert all(reasons[query] == "permission_denied" for query in GLOBAL_STEPS)
