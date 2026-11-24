"""NXOS-CHANNEL-ADMIN Admin operations with NX-OS output captured on nexus9300v and SWITCH-PAIR."""
import json
import re
from pathlib import Path

import pytest

from fake_nxos import FakeNxos, fixture as baseline
from netops_admin import exec_nxos, execute, mcp_server, nxos
from netops_admin.access import AccessError
from netops_admin.errors import Rejected
from test_nxos import KEY, make_runtime, request, steps

FIXTURES = Path(__file__).parent / "fixtures" / "nxos_nxos_channel_admin"
CHANNEL = "port-channel140"
BOUNCE = "port-bounce"
CHANNEL_SUMMARY = "show port-channel summary | json"
VPC_SUMMARY = "show vpc brief | json"
KEEPALIVE = "show vpc peer-keepalive | json"


def capture(name):
    return (FIXTURES / name).read_text()


def captured_block(kind, header):
    lines = capture(kind).splitlines()
    start = lines.index(header)
    end = next((index for index in range(start + 1, len(lines)) if not lines[index].startswith(" ")), len(lines))
    return lines[start:end]


class G101Device(FakeNxos):
    def __init__(self):
        super().__init__()
        self.lacp = True
        self.vpc = False
        self.failed_off_read = False
        self.shorten_channel = False
        self.shorten_vpc = False
        self.port_writes = []

    def add_channel(self, name=CHANNEL, children=()):
        idx = self.body.index("interface Ethernet1/1")
        self.body[idx:idx] = [f"interface {name}", *("  " + line for line in children)]

    def add_pair(self):
        self.vpc = True
        for number, source in ((128, "vpc-channel-config.txt"), (200, "peerlink-config.txt")):
            channel = f"port-channel{number}"
            self.add_channel(channel, [line.strip() for line in captured_block(source, "interface " + channel)[1:]])
        pos = self.body.index("interface Vlan1")
        self.body[pos:pos] = captured_block("vpc-domain-config.txt", "vpc domain 128")

    def _line(self, line, mode):
        if mode[0] == "domain" and line.startswith("peer-keepalive destination "):
            index = next(i for i, child in enumerate(self.body) if child.startswith("vpc domain "))
            _, end = self._block(self.body[index])
            self.body[index + 1:end] = ["  " + line]
            return ""
        return super()._line(line, mode)

    def _config_line(self, words, mode):
        header = " ".join(words)
        if len(words) == 2 and words[0] == "interface" and words[1].startswith("port-channel"):
            if header not in self.body:
                self.add_channel(words[1])
        elif header.startswith(("no interface port-channel", "no vpc domain ")):
            header = header.removeprefix("no ")
            first, end = self._block(header)
            del self.body[first:end]
            return ""
        elif header.startswith("vpc domain "):
            if header not in self.body:
                index = self.body.index("interface Vlan1")
                self.body.insert(index, header)
            mode[0] = "domain"
            return ""
        return super()._config_line(words, mode)

    def _interface_line(self, name, words, line):
        if name == KEY and line in ("shutdown", "no shutdown"):
            self.port_writes.append((line, self.uptime))
        if words[0] == "channel-group" or words[:2] == ["no", "channel-group"]:
            self._set(name, re.compile("^channel-group "), line if words[0] == "channel-group" else None)
            return ""
        if words[:3] == ["spanning-tree", "port", "type"]:
            self._stp_port_type(name, " ".join(words[3:]))
            return ""
        if words[0] == "vpc" or words[:2] == ["no", "vpc"]:
            self._set(name, re.compile("^vpc "), line if words[0] == "vpc" else None)
            # peer-link-stp-port-type.txt: the peer-link forces the network port type and its removal drops the line
            if line in ("vpc peer-link", "no vpc peer-link"):
                self._stp_port_type(name, "network" if words[0] == "vpc" else None)
            return ""
        if line == "switchport mode trunk":
            self._set(name, re.compile("^switchport mode "), line)
            return ""
        return super()._interface_line(name, words, line)

    def _stp_port_type(self, name, value):
        start, end = self._block("interface %s" % name)
        children = [line for line in self.body[start + 1:end]
                    if not line.strip().startswith("spanning-tree port type ")]
        if value:
            index = next((i for i, line in enumerate(children) if line.strip().startswith("vpc ")), len(children))
            children.insert(index, "  spanning-tree port type " + value)
        self.body[start + 1:end] = children

    def _channels(self):
        if self.shorten_channel:
            return '{"TABLE_channel":'
        measured_rows = json.loads(capture("channels.json"))["TABLE_channel"]["ROW_channel"]
        rows = []
        for line in self.body:
            if not line.startswith("interface port-channel"):
                continue
            name = line.split()[1]
            group = name.removeprefix("port-channel")
            if name in ("port-channel128", "port-channel200"):
                row = next(row for row in measured_rows if row["port-channel"] == name)
            else:
                row = json.loads(capture("channel-empty.json"))["TABLE_channel"]["ROW_channel"]
                row.update(group=group, **{"port-channel": name})
                if any(line.startswith(f"channel-group {group} ") for line in self.interface(KEY)):
                    row["prtcl"] = "LACP"
                    member = measured_rows[0]["TABLE_member"]["ROW_member"][0]
                    row["TABLE_member"] = {"ROW_member": {**member, "port": KEY, "port-status": "D"}}
            rows.append(row)
        if not rows:
            return capture("empty-channels.json")
        return json.dumps({"TABLE_channel": {"ROW_channel": rows[0] if len(rows) == 1 else rows}})

    def _vpc(self):
        data = json.loads(capture("vpc.json"))
        base = data.pop("TABLE_vpc")["ROW_vpc"]
        peer = data.pop("TABLE_peerlink")["ROW_peerlink"]
        domain = next((line.split()[-1] for line in self.body if line.startswith("vpc domain ")), "0")
        data["vpc-domain-id"] = domain
        rows = []
        for line in self.body:
            if not line.startswith("interface port-channel"):
                continue
            name = line.split()[1]
            for child in self.interface(name):
                if child == "vpc peer-link":
                    link = "Po" + name.removeprefix("port-channel")
                    data["TABLE_peerlink"] = {"ROW_peerlink": {
                        **peer, "peerlink-ifindex": link, "peer-link-port-state": "1" if link == "Po200" else "0"}}
                elif child.startswith("vpc "):
                    ident = child.split()[-1]
                    rows.append({**base, "vpc-id": ident, "vpc-ifindex": "Po" + name.removeprefix("port-channel"),
                                 "vpc-port-state": "1" if ident == "128" else "0"})
        data["num-of-vpcs"] = str(len(rows) + self.shorten_vpc)
        if rows:
            data["TABLE_vpc"] = {"ROW_vpc": rows if len(rows) > 1 else rows[0]}
        else:
            # vpc-peer-link-only.json and vpc-unpaired-domain.json: without vPC rows there is no vPC table header
            # and at most one vpc-end string (only with a peer-link)
            for field in ("vpc-hdr", "vpc-not-es"):
                data.pop(field)
            if "TABLE_peerlink" in data:
                data["vpc-end"] = "End of table"
            else:
                del data["vpc-peer-link-hdr"], data["vpc-end"]
        return json.dumps(data)

    def query(self, command):
        if command == "show cdp neighbors":
            return (Path(__file__).parent / "fixtures" / "nxos_nxos_switchport_admin" / "nexus9300v__cdp.txt").read_text()
        if command == "show feature | include lacp":
            return capture("lacp-on.txt" if self.lacp else "lacp-off.txt")
        if command == "show feature | include vpc":
            return capture("vpc-off.txt").replace("disabled", "enabled") if self.vpc else capture("vpc-off.txt")
        if command == CHANNEL_SUMMARY:
            return self._channels()
        if command == VPC_SUMMARY:
            return self._vpc()
        if command == "show vpc brief":
            assert not any(line.startswith("vpc domain ") for line in self.body)
            return capture("vpc-unconfigured-vendor.txt")
        if command == KEEPALIVE:
            data = json.loads(capture("keepalive.json"))
            line = next(line.split() for line in self.body if line.strip().startswith("peer-keepalive destination "))
            data["vpc-keepalive-dest"] = [line[2], line[2]]
            return json.dumps(data)
        if command == f"show interface {KEY} | json":
            if "shutdown" in self.interface(KEY):
                if self.failed_off_read:
                    raise AccessError("check account timed out")
                return capture("bounce-down.json")
            return capture("ethernet-up-admin.json")
        if command.startswith("show interface port-channel") and command.endswith(("status", "switchport")):
            channel, kind = command.split()[2:]
            if kind == "status":
                return capture("channel-status.txt").replace("Po140", "Po" + channel.removeprefix("port-channel"))
            text = capture("channel-switchport.txt").replace("Name: " + CHANNEL, "Name: " + channel)
            if "switchport mode trunk" in self.interface(channel):
                text = text.replace("Operational Mode: access", "Operational Mode: trunk")
            return text
        if command.startswith("show mac address-table interface port-channel"):
            return baseline("show-mac-address-table-interface-Eth1-48__empty.txt")
        return super().query(command)

    def check_query(self, command):
        if (command == "show vpc brief"
                or command.endswith("| json") or command.startswith("show interface port-channel")):
            self.check_queries.append(command)
            return self.query(command)
        return super().check_query(command)


@pytest.fixture
def device(monkeypatch):
    switch = G101Device()
    monkeypatch.setattr(exec_nxos, "PAUSE", switch.advance)
    return switch


def configured(device, tmp_path):
    device.saved = device._config()
    return make_runtime(tmp_path, device, safeguard=300)


@pytest.mark.parametrize("peer", ("nexus-peer-a", "nexus-peer-b"))
def test_full_switch_pair_feature_list_passes_scheduler_preflight(peer, device, tmp_path, monkeypatch):
    device.add_pair()
    runtime = configured(device, tmp_path)
    text = "".join(json.loads(capture(f"{peer}__show-feature.json")))
    query = device.query
    monkeypatch.setattr(device, "query", lambda command: text if command == exec_nxos.QUERY_FEATURE else query(command))

    result = execute.preview(runtime, "lab-nxos", changes("port-channel", {}, key=CHANNEL, op="create"))

    assert result["result"] == "ready", result["reason_codes"]
    assert {name: nxos.feature_state(text, name) for name in ("rise", "scheduler", "lacp", "vpc", "dhcp")} == {
        "rise": "disabled", "scheduler": "enabled", "lacp": "enabled", "vpc": "enabled", "dhcp": "disabled",
    }


def changes(table, values, *, key=KEY, op="update", ident=None):
    return request(table=table, changes=values, key=key, op=op, request_id=ident or "nxos-channel-admin-" + table + "-" + op)


def applied(runtime, req):
    preview = execute.preview(runtime, "lab-nxos", req)
    assert preview["result"] == "ready", preview
    result = execute.apply(runtime, "lab-nxos", req, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "confirmed" and result["reason"] is None, steps(result)
    assert {"postcheck_passed", "check_identity_passed", "configuration_saved"} <= set(steps(result))
    return result


def undo(runtime, result):
    preview = execute.preview_undo(runtime, result["change_id"], "test exact restoration", issue=True)
    assert preview["result"] == "ready", preview
    result = execute.undo(runtime, result["change_id"], "test exact restoration",
                          expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "confirmed", steps(result)


def test_bounce_through_mcp_returns_and_verifies_port(device, tmp_path, monkeypatch):
    runtime = configured(device, tmp_path)
    monkeypatch.setattr(mcp_server, "configured_runtime", lambda: runtime)
    state = device._config()
    args = dict(device="lab-nxos", table=BOUNCE, op="update", key=KEY, changes={"admin-state": "disabled"},
                reason="verify a bounce", user_request="bounce the test port", request_id="nxos-channel-admin-bounce")
    preview = mcp_server.admin_preview(**args)
    assert preview["result"] == "ready"
    assert preview["hold_seconds"] == 5
    assert preview["cycle_state"]["link"] == "down"
    assert not device.applied_blocks
    rejected = mcp_server.admin_apply(**args)
    assert rejected["reason_codes"] == ["plan_changed"] and not device.applied_blocks
    applied_record = mcp_server.admin_apply(**args, expected_plan_sha256=preview["plan_sha256"])
    assert applied_record["result"] == "confirmed"
    result = runtime.store.operation(applied_record["change_id"])
    assert result["cycle"] == {"before": {"admin": "up", "link": "down"}, "off": {"admin": "down", "link": "down"},
                               "after": {"admin": "up", "link": "down"}}
    assert [command for command, _ in device.port_writes] == ["shutdown", "no shutdown"]
    assert device.port_writes[1][1] - device.port_writes[0][1] >= 5
    assert device._config() == state and device.clean()
    with pytest.raises(Rejected) as refusal:
        execute.undo_request(result, "bounce already restored itself")
    assert refusal.value.reason_codes == ["undo_not_applicable"]


def test_bounce_attempts_an_inverse_even_when_off_readback_times_out(device, tmp_path):
    runtime = configured(device, tmp_path)
    state = device._config()
    req = changes(BOUNCE, {"admin-state": "disabled"})
    with pytest.raises(Rejected) as refused:
        execute.preview(runtime, "lab-nxos", req)
    assert refused.value.reason_codes == ["action_only_table"]
    preview = exec_nxos.preview(runtime, "lab-nxos", BOUNCE, req)
    assert preview["result"] == "ready"
    device.failed_off_read = True
    result = exec_nxos.apply(runtime, "lab-nxos", BOUNCE, req, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "reverted"
    assert [command for command, _ in device.port_writes] == ["shutdown", "no shutdown"]
    assert device._config() == state and device.clean()


def test_wave6_bounce_with_no_operational_return_is_not_confirmed(device, tmp_path, monkeypatch):
    runtime = configured(device, tmp_path)
    query = device.query

    def read(command):
        if command == f"show interface {KEY} status":
            return (FIXTURES.parent / "nxos_nxos_switchport_admin" / "nexus9300v__occupied-status.txt").read_text().replace("Eth1/2", "Eth1/48")
        if command == f"show mac address-table interface {KEY}":
            return (FIXTURES.parent / "nxos_nxos_targeted_clear" / "nexus9300v__mac-interface-hit.txt").read_text().replace(
                "Eth1/2", "Eth1/48")
        if command == f"show interface {KEY} | json" and not device.port_writes:
            captured = json.loads(capture("ethernet-up-admin.json"))
            captured["TABLE_interface"]["ROW_interface"]["state"] = "up"
            return json.dumps(captured)
        return query(command)

    monkeypatch.setattr(device, "query", read)
    req = exec_nxos.request(BOUNCE, "lab-nxos", KEY, "verify the lab bounce", "bounce test port",
                            "wave6-link-down", KEY)
    preview = exec_nxos.preview(runtime, "lab-nxos", BOUNCE, req)
    assert preview["result"] == "ready", preview
    result = exec_nxos.apply(runtime, "lab-nxos", BOUNCE, req, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] in ("unknown", "reverted"), result
    assert result["reason"] == "link not up after the bounce"
    assert result["cycle"]["after"] == {"admin": "up", "link": "down"}
    assert [command for command, _ in device.port_writes] == ["shutdown", "no shutdown"]


def test_port_channel_lifecycle_and_member_undo_keep_an_empty_channel(device, tmp_path):
    runtime = configured(device, tmp_path)
    original = device.running()
    req = changes("port-channel", {}, key=CHANNEL, op="create")
    created = applied(runtime, req)
    empty = device.running()
    assert device.interface(CHANNEL) == []
    joined = applied(runtime, changes("port-channel-member", {"group": 140, "mode": "active"}))
    assert device.interface(KEY) == ["channel-group 140 mode active"]
    undo(runtime, joined)
    assert device.running() == empty and device.interface(CHANNEL) == []
    undo(runtime, created)
    assert device.running() == original and device.interface(CHANNEL) is None and device.clean()


def test_batch_creates_channel_attaches_idle_member_and_undoes_both(device, tmp_path):
    runtime = configured(device, tmp_path)
    original = device.running()
    req = request(table="batch", key="batch", changes=[
        {"table": "port-channel", "op": "create", "key": CHANNEL, "changes": {}},
        {"table": "port-channel-member", "op": "update", "key": KEY, "changes": {"group": 140, "mode": "active"}},
    ])
    preview = execute.preview(runtime, "lab-nxos", req)
    assert preview["result"] == "ready", preview
    assert not device.applied_blocks
    record = execute.apply(runtime, "lab-nxos", req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", [
        (step["result"], step.get("failure"), step.get("reason_codes")) for step in record["batch_results"]
    ]
    assert device.interface(CHANNEL) == []
    assert device.interface(KEY) == ["channel-group 140 mode active"]

    reverse = execute.preview_undo(runtime, record["change_id"], "restore", issue=True)
    assert reverse["result"] == "ready", reverse
    undone = execute.undo(runtime, record["change_id"], "restore", expected_plan_sha256=reverse["plan_sha256"])
    assert undone["result"] == "confirmed", undone
    assert device.running() == original and device.clean()


@pytest.mark.parametrize("kind,code", [
    ("protected", "port_protected"), ("disabled", "nxos_link_feature_disabled"),
    ("truncated", "port_usage_unreadable"), ("missing", "nxos_channel_dependency"),
])
def test_member_refuses_unsafe_or_incomplete_scope(device, tmp_path, kind, code):
    if kind != "missing":
        device.add_channel()
    device.lacp = kind != "disabled"
    device.shorten_channel = kind == "truncated"
    runtime = configured(device, tmp_path)
    if kind == "protected":
        runtime.config.devices["lab-nxos"].protected["interface"] = ["Po140"]
    req = changes("port-channel-member", {"group": 140, "mode": "active"})
    assert execute.preview(runtime, "lab-nxos", req)["reason_codes"] == [code]
    assert not device.applied_blocks


def test_vpc_assigns_and_undoes_only_the_selected_channel(device, tmp_path):
    device.add_pair()
    device.add_channel()
    runtime = configured(device, tmp_path)
    original = device.running()
    result = applied(runtime, changes("vpc-port", {"vpc-id": 140}, key=CHANNEL))
    assert device.interface(CHANNEL) == ["vpc 140"]
    undo(runtime, result)
    assert device.running() == original and device.clean()


def test_vpc_and_channel_undo_allow_a_memberless_channel_with_lldp_disabled(device, tmp_path, monkeypatch):
    device.add_pair()
    runtime = configured(device, tmp_path)
    original = device.running()
    features = "".join(json.loads(capture("nexus-peer-a__show-feature.json")))
    query = device.query

    def switch_pair_query(command):
        if command == exec_nxos.QUERY_LLDP:
            raise AccessError("query ended with exit status 16")
        if command == exec_nxos.QUERY_FEATURE:
            return features
        return query(command)

    monkeypatch.setattr(device, "query", switch_pair_query)
    created = applied(runtime, changes("port-channel", {}, key=CHANNEL, op="create"))
    physical = changes("port-channel-member", {"group": 140, "mode": "active"})
    assert execute.preview(runtime, "lab-nxos", physical)["reason_codes"] == ["port_usage_unreadable"]
    assigned = applied(runtime, changes("vpc-port", {"vpc-id": 140}, key=CHANNEL))
    undo(runtime, assigned)
    undo(runtime, created)
    assert device.running() == original and device.clean()


def test_vpc_refuses_existing_pair_changes_and_truncated_output(device, tmp_path):
    device.add_pair()
    device.add_channel()
    runtime = configured(device, tmp_path)
    for table, key, attrs in (("vpc-domain", "128", {"destination": "198.51.100.82"}),
                              ("vpc-peer-link", "port-channel200", {"peer-link": None})):
        preview = execute.preview(runtime, "lab-nxos", changes(table, attrs, key=key))
        assert preview["result"] == "rejected"
    device.shorten_vpc = True
    preview = execute.preview(runtime, "lab-nxos", changes("vpc-port", {"vpc-id": 140}, key=CHANNEL))
    assert preview["reason_codes"] == ["port_usage_unreadable"]
    assert not device.applied_blocks


def test_vpc_domain_and_keepalive_create_update_and_undo(device, tmp_path):
    device.vpc = True
    runtime = configured(device, tmp_path)
    original = device.running()
    req = changes("vpc-domain", {"destination": "198.51.100.56", "source": "198.51.100.55", "vrf": "management"},
                  key="140", op="create")
    created = applied(runtime, req)
    initial_domain = device.running()
    updated = applied(runtime, changes("vpc-domain", {"destination": "198.51.100.57"}, key="140"))
    undo(runtime, updated)
    assert device.running() == initial_domain
    undo(runtime, created)
    assert device.running() == original and device.clean()


def test_vpc_peer_link_create_and_undo_preserve_trunk(device, tmp_path):
    device.vpc = True
    idx = device.body.index("interface Vlan1")
    device.body[idx:idx] = ["vpc domain 140", "  peer-keepalive destination 198.51.100.56 source 198.51.100.55"]
    device.add_channel(children=("switchport mode trunk", "switchport trunk allowed vlan 1",
                                 "spanning-tree port type network"))
    runtime = configured(device, tmp_path)
    before = device.running()
    result = applied(runtime, changes("vpc-peer-link", {"peer-link": "enabled"}, key=CHANNEL))
    assert "vpc peer-link" in device.interface(CHANNEL)
    undo(runtime, result)
    assert device.running() == before and device.clean()


def _peer_link_candidate(device, stp=("spanning-tree port type network",), *, assigned=False):
    device.vpc = True
    idx = device.body.index("interface Vlan1")
    device.body[idx:idx] = ["vpc domain 140", "  peer-keepalive destination 198.51.100.56 source 198.51.100.55"]
    device.add_channel(children=("switchport mode trunk", "switchport trunk allowed vlan 1", *stp,
                                 *(("vpc peer-link",) if assigned else ())))


@pytest.mark.parametrize("stp", ((), ("spanning-tree port type edge trunk",)))
def test_vpc_peer_link_refuses_a_channel_whose_port_type_nxos_would_change(device, tmp_path, stp):
    _peer_link_candidate(device, stp)
    runtime = configured(device, tmp_path)
    preview = execute.preview(runtime, "lab-nxos", changes("vpc-peer-link", {"peer-link": "enabled"}, key=CHANNEL))
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["nxos_vpc_dependency"], preview
    assert any("already has spanning-tree port type network" in reason for reason in preview["reasons"]), preview
    assert not device.applied_blocks


def test_vpc_peer_link_removal_keeps_the_network_port_type_and_undo_restores(device, tmp_path):
    _peer_link_candidate(device, assigned=True)
    runtime = configured(device, tmp_path)
    before = device.running()
    req = changes("vpc-peer-link", {"peer-link": None}, key=CHANNEL)
    preview = execute.preview(runtime, "lab-nxos", req)
    assert preview["result"] == "ready", preview
    assert preview["commands"] == ["configure terminal", "interface " + CHANNEL, "no vpc peer-link",
                                   "spanning-tree port type network", "end"]
    result = applied(runtime, req)
    assert device.interface(CHANNEL) == ["switchport mode trunk", "switchport trunk allowed vlan 1",
                                         "spanning-tree port type network"]
    undo(runtime, result)
    assert device.running() == before and device.clean()


class _CheckReads:
    def __init__(self, answers):
        self.answers = answers

    def check_query(self, command):
        return self.answers[command]


@pytest.mark.parametrize("name, domain, link, assignments", (
    ("vpc-feature-without-domain.json", None, None, {}),
    ("vpc-unpaired-domain.json", "967", None, {}),
    ("vpc-without-peer-link.json", "128", None, {}),
    ("vpc-peer-link-only.json", "128", "Po201", {}),
    ("vpc.json", "128", "Po200", {"Po128": "128"}),
))
def test_measured_vpc_summaries_are_read(name, domain, link, assignments):
    reads = _CheckReads({VPC_SUMMARY: capture(name), "show vpc brief": capture("vpc-unconfigured-vendor.txt")})
    topology = exec_nxos._vpc_summary(reads)
    assert (topology["domain"], topology["peer_link"], topology["assignments"]) == (domain, link, assignments)


def test_vpc_summary_with_a_table_but_without_its_end_is_refused():
    data = json.loads(capture("vpc-peer-link-only.json"))
    del data["vpc-end"]
    with pytest.raises(Rejected):
        exec_nxos._vpc_summary(_CheckReads({VPC_SUMMARY: json.dumps(data)}))


def test_measured_keepalive_of_an_unpaired_domain():
    reads = _CheckReads({KEEPALIVE: capture("keepalive-unpaired-domain.json")})
    assert exec_nxos._keepalive(reads) == {"destination": "198.51.100.56", "vrf": "management"}
