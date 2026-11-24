"""ADC-VIRTUAL-SERVERS operational clears through the Admin runtime and the measured FortiADC CLI frames."""
from pathlib import Path

import pytest

from netops_admin import engine, execute, mcp_server
from netops_admin.errors import Rejected
from test_fortiadc_admin_runtime import make_runtime, request
from test_fortiadc_adc_pool_members import Wire

FIXTURES = Path(__file__).with_name("fixtures") / "fortiadc_adc_virtual_servers"
CLIENT = "192.0.2.100"
SMTP = "LAB_VS_SMTP"
HTTPS = "LAB_VS_HTTPS"
SOURCE = {"source-ip": CLIENT}
WAF_CLIENT = "192.0.2.249"
WAF_RELEASE = f"execute waf block-ip release vs-name {HTTPS} ip {WAF_CLIENT}"


def measured(name):
    return (FIXTURES / (name + ".out")).read_text()


class ClearWire(Wire):
    def __init__(self, family, *, truncate_session=None, wrong_selection=False, changed=False):
        super().__init__()
        self.family = family
        self.prefix = "diagnose server-load-balance " + family
        self.select = f"{self.prefix} filter 'vs-name {SMTP} source-ip {CLIENT}'"
        self.clear = self.prefix + " clear l4"
        self.reset = self.prefix + " filter clear"
        self.selected = self.cleared = False
        self.truncate_session = truncate_session
        self.wrong_selection = wrong_selection
        self.changed = changed
        self.sessions = 0

    def with_interactive_reader(self, spec, inspect):
        self.sessions += 1
        # DeviceAccess consumes the response through the hostname anchor, before the terminal "# ".
        return inspect(lambda command: self.command(command) + spec.anchor.decode("ascii"))

    def command(self, command):
        if command == self.prefix + " filter show":
            return measured(self.family + "-filter-" + ("selected" if self.selected else "default"))
        if command == self.prefix + " list":
            if self.sessions == self.truncate_session:
                # Derived from the measured frame, cut after the first columns of the last row.
                return measured(self.family + "-list-before").rsplit(" ", 4)[0]
            if self.selected and not self.wrong_selection:
                name = "selected-after" if self.cleared else "selected-before"
            else:
                name = "list-after" if self.cleared or (self.changed and self.sessions >= 3) else "list-before"
            return measured(self.family + "-" + name)
        self.writes.append(command)
        if command == self.select:
            self.selected = True
            return measured(self.family + "-select")
        if command == self.clear:
            self.cleared = True
            return measured(self.family + "-clear")
        assert command == self.reset
        self.selected = False
        return measured(self.family + "-filter-clear")


class WafWire(Wire):
    def __init__(self, blocked, *, remains=False, pending_reads=0):
        super().__init__()
        self.blocked = blocked
        self.remains = remains
        self.pending_reads = pending_reads
        self.released = False

    def with_interactive_reader(self, spec, inspect):
        def read(command):
            if command == "execute waf block-ip filter show":
                answer = "waf-filter-default"
            elif command == "execute waf block-ip list":
                if self.released and self.pending_reads:
                    self.pending_reads -= 1
                    answer = "waf-list-release-pending"
                else:
                    answer = "waf-list-blocked" if self.blocked else "waf-list-empty"
            else:
                assert command == WAF_RELEASE
                self.writes.append(command)
                self.blocked = self.remains
                self.released = True
                answer = "waf-release"
            return measured(answer) + spec.anchor.decode("ascii")

        return inspect(read)


@pytest.mark.parametrize("family", ["session", "persistence"])
def test_scoped_clear_requires_preview_then_confirms_and_restores_filter(tmp_path, family):
    wire = ClearWire(family)
    runtime = make_runtime(tmp_path, wire)
    req = request(table="slb-" + family, key=SMTP, op="clear", changes=SOURCE)
    preview = execute.preview(runtime, "adc", req)
    assert preview["result"] == "ready", preview
    assert preview["return_mechanism"] == "irreversible"
    assert preview["firmware_support"]["status"] == "tested"
    assert preview["commands"] == [wire.select, wire.clear, wire.reset]
    assert len(preview["predicted"]["before"]["entries"]) == 1
    assert preview["predicted"]["after"] == {"virtual_server": SMTP, "source_ip": CLIENT, "entries": []}
    assert not wire.writes
    with pytest.raises(Rejected) as err:
        execute.apply(runtime, "adc", req)
    assert err.value.reason_codes == ["clear_preview_required"]
    assert not wire.writes

    record = execute.apply(runtime, "adc", req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", record
    assert wire.writes == preview["commands"]
    assert not wire.selected
    assert engine._read_plan(record["plan"]) == record["plan"]
    assert record["readback"] == preview["predicted"]["after"]
    assert mcp_server.summary(record)["return_mechanism"] == "irreversible"
    replay = execute.apply(runtime, "adc", req, expected_plan_sha256=preview["plan_sha256"])
    assert (replay["change_id"], replay["result"]) == (record["change_id"], "confirmed")
    assert len(wire.writes) == 3
    with pytest.raises(Rejected) as err:
        execute.undo(runtime, record["change_id"], "restore the filter if required")
    assert err.value.reason_codes == ["undo_not_applicable"]
    assert wire.sessions == 4  # preview, fresh preparation, write, independent readback


@pytest.mark.parametrize("case, code", [
    ("unreadable", "clear_readback_unreadable"),
    ("active-filter", "clear_scope_unverified"),
    ("protected", "clear_protected_target"),
    ("empty", "clear_no_entry"),
    ("l7", "clear_invalid_target"),
    ("range", "clear_invalid_target"),
])
def test_clear_refuses_unverified_or_unsupported_preview_without_writes(tmp_path, case, code):
    wire = ClearWire("session", truncate_session=1 if case == "unreadable" else None)
    wire.selected = case == "active-filter"
    wire.cleared = case == "empty"
    protected = {"load-balance virtual-server": [SMTP.lower()]} if case == "protected" else {}
    runtime = make_runtime(tmp_path, wire, protected=protected)
    key = HTTPS if case == "l7" else SMTP
    changes = {"source-ip": CLIENT + "/24"} if case == "range" else SOURCE
    result = execute.preview(runtime, "adc", request(table="slb-session", op="clear", key=key, changes=changes))
    assert result["result"] == "rejected", result
    assert result["reason_codes"] == [code]
    assert not wire.writes


@pytest.mark.parametrize("changes", [{}, SOURCE], ids=["whole-vs", "explicit-source"])
def test_clear_refuses_protected_source_in_plan(tmp_path, changes):
    wire = ClearWire("session")
    runtime = make_runtime(tmp_path, wire, protected={"slb-session": [CLIENT]})
    req = request(table="slb-session", op="clear", key=SMTP, changes=changes)
    result = execute.preview(runtime, "adc", req)
    assert result["result"] == "rejected", result
    assert result["reason_codes"] == ["clear_protected_target"]
    assert not wire.writes


def test_clear_refuses_truncated_final_prewrite_listing(tmp_path):
    wire = ClearWire("session", truncate_session=3)
    runtime = make_runtime(tmp_path, wire)
    req = request(table="slb-session", op="clear", key=SMTP, changes=SOURCE)
    preview = execute.preview(runtime, "adc", req)
    assert preview["result"] == "ready", preview

    record = execute.apply(runtime, "adc", req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "rejected", record
    assert record["reason_codes"] == ["clear_readback_unreadable"]
    assert wire.sessions == 3
    assert not wire.writes


@pytest.mark.parametrize("changed", [False, True])
def test_apply_rechecks_rows_before_clear_and_restores_only_its_filter(tmp_path, changed):
    wire = ClearWire("session", wrong_selection=not changed, changed=changed)
    runtime = make_runtime(tmp_path, wire)
    req = request(table="slb-session", key=SMTP, op="clear", changes=SOURCE)
    preview = execute.preview(runtime, "adc", req)
    assert preview["result"] == "ready", preview
    record = execute.apply(runtime, "adc", req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "rejected", record
    assert record["reason_codes"] == ["clear_scope_unverified"]
    assert wire.writes == ([] if changed else [wire.select, wire.reset])
    assert not wire.selected


def test_firmware_warning_preserves_a_ready_preview(tmp_path):
    wire = ClearWire("session")
    wire.answers["get system status"] = wire.answers["get system status"].replace("v7.6.7", "v7.6.8")
    runtime = make_runtime(tmp_path, wire)
    result = execute.preview(runtime, "adc", request(table="slb-session", op="clear", key=SMTP, changes=SOURCE))
    assert result["result"] == "ready", result
    assert result["firmware_support"]["status"] == "untested"


def test_clear_aborted_on_snapshot_transport_error(tmp_path):
    class Offline(Wire):
        unavailable = False

        def snapshot(self):
            if self.unavailable:
                raise OSError("test transport lost")
            return super().snapshot()

    wire = Offline()
    runtime = make_runtime(tmp_path, wire)
    wire.unavailable = True
    req = request(table="slb-session", op="clear", key=SMTP, changes=SOURCE)
    result = execute.preview(runtime, "adc", req)
    assert result["reason_codes"] == ["clear_readback_unreadable"]
    assert not wire.writes


def test_waf_empty_reply_refuses_with_no_entry(tmp_path):
    wire = WafWire(blocked=False)
    runtime = make_runtime(tmp_path, wire)
    req = request(table="waf-block-ip", op="clear", key=HTTPS, changes={"source-ip": WAF_CLIENT})
    result = execute.preview(runtime, "adc", req)
    assert result["reason_codes"] == ["clear_no_entry"], result
    assert not wire.writes


@pytest.mark.parametrize("remains, expected", [(False, "confirmed"), (True, "unknown")])
def test_waf_clear_checks_the_actual_block_list_after_the_approved_command(tmp_path, remains, expected):
    wire = WafWire(blocked=True, remains=remains)
    runtime = make_runtime(tmp_path, wire)
    req = request(table="waf-block-ip", op="clear", key=HTTPS, changes={"source-ip": WAF_CLIENT})
    preview = execute.preview(runtime, "adc", req)
    assert preview["result"] == "ready", preview
    assert preview["predicted"]["before"]["entries"] == [[WAF_CLIENT, HTTPS]]
    assert preview["commands"] == [WAF_RELEASE]
    assert not wire.writes
    with pytest.raises(Rejected) as err:
        execute.apply(runtime, "adc", req)
    assert err.value.reason_codes == ["clear_preview_required"]
    assert not wire.writes
    record = execute.apply(runtime, "adc", req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == expected, record
    assert wire.writes == [WAF_RELEASE]
    assert record["readback"] == preview["predicted"]["before" if remains else "after"]
    with pytest.raises(Rejected) as err:
        execute.undo(runtime, record["change_id"], "restore")
    assert err.value.reason_codes == ["undo_not_applicable"]


def test_waf_clear_confirms_after_the_reported_block_disappears(tmp_path):
    wire = WafWire(blocked=True, pending_reads=4)
    runtime = make_runtime(tmp_path, wire)
    delays = []
    runtime.sleep = delays.append
    req = request(table="waf-block-ip", op="clear", key=HTTPS, changes={"source-ip": WAF_CLIENT})
    preview = execute.preview(runtime, "adc", req)
    assert preview["result"] == "ready", preview

    record = execute.apply(runtime, "adc", req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", record
    assert record["readback"] == preview["predicted"]["after"]
    assert wire.writes == [WAF_RELEASE]
    assert sum(delays) == 40
