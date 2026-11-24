"""FortiOS IPsec Admin operations with independently replayed lab readbacks."""
from dataclasses import replace
from pathlib import Path

import pytest

from fake_fortios import FakeFortiOS
from test_execute import make_runtime, request

from netops_admin import engine, execute, fortios
from netops_admin.errors import Rejected
from netops_core.fortios import tokenize

IPSEC_STATUS = "netops-ipsec"
NEW = "netops-fw-copy"
DIRECT = "netops-fw-direct"
CREATED = {NEW: "phase2-created", DIRECT: "phase2-direct"}
PHASE2 = fortios.PHASE2_TABLE
FIXTURES = Path(__file__).parent / "fixtures" / "fortios_7_6_8_firewall_cleanup"


def fixture(name):
    return (FIXTURES / (name + ".txt")).read_text()


class FortiOSG26(FakeFortiOS):
    firmware = ("7.6.8", "3744")

    def __init__(self):
        super().__init__()
        self.phase2 = {}
        self.up = True
        self.ignore_down = False
        self.auto_negotiate = False
        self.echo_wrapped = False
        self.status_refusal = None
        self.config_refusal = None
        self.runtime_writes = []
        self.selectors = fixture("selectors-expiry-before")
        self.snapshot_extra = [
            'config vpn ipsec phase1-interface', '    edit "netops-ipsec"',
            '        set psksecret ENC SYNTHETIC-CANARY', '    next', 'end',
        ]

    def snapshot(self):
        baseline = super().snapshot().replace('    edit "wan1"\n    next',
            '    edit "wan1"\n    next\n    edit "netops-ipsec"\n        set type tunnel\n    next')
        added = "".join(self.show_phase2(name).split("\n", 1)[1].removesuffix("end\n") for name in self.phase2)
        return baseline + fixture("phase2-source").removesuffix("end\n") + added + "end\n"

    def show_phase2(self, name):
        if name == IPSEC_STATUS:
            return fixture("phase2-source")
        if name not in self.phase2:
            return fixture("phase2-absent")
        lines = [f"config {PHASE2}", f'    edit "{name}"']
        for field, value in self.phase2[name].items():
            if field == "phase1name":
                value = '"' + value + '"'
            lines.append(f"        set {field} {value}")
        return "\n".join([*lines, "    next", "end", ""])

    def _run(self, lines, automatic=False):
        if lines[0] == f"config {PHASE2}":
            op, name = tokenize(lines[1].strip())
            if op == "delete":
                del self.phase2[name]
            else:
                settings = {}
                for line in lines[2:-2]:
                    op, field, *value = tokenize(line.strip())
                    assert op == "set"
                    text = " ".join(value)
                    if (field, text) != ("auto-negotiate", "disable"):
                        settings[field] = text
                self.phase2[name] = settings
            return len(lines)
        if lines[0].startswith(("diagnose vpn tunnel down ", "diagnose vpn tunnel up ")):
            prefix, verb, phase2, phase1 = lines[0].rsplit(" ", 3)
            assert prefix == "diagnose vpn tunnel"
            assert (phase2, phase1) == (IPSEC_STATUS, IPSEC_STATUS)
            self.runtime_writes.append(verb)
            if verb == "down" and self.auto_negotiate:
                self.selectors = fixture("selectors-expiry-after")
            elif verb == "up" or not self.ignore_down:
                self.up = verb == "up"
            return 1
        return super()._run(lines, automatic)

    def check_query_status(self, command):
        if command.startswith(("diagnose vpn tunnel list name ", "diag vpn tunnel list name ")):
            if self.status_refusal is not None:
                return self.status_refusal
            if self.up:
                if self.echo_wrapped:
                    echo = command.replace("SA:", " \bSA:")
                    return 0, echo + "\n" + self.selectors
                return 0, self.selectors
            return 0, fixture("selectors-down")
        assert command.startswith(f"show {PHASE2} ")
        name = tokenize(command)[-1]
        if name == NEW and self.config_refusal is not None:
            return self.config_refusal
        text = self.show_phase2(name)
        if name in CREATED and name in self.phase2:
            measured = fixture(CREATED[name])
            if fortios.shown_object(measured, PHASE2, name) == fortios.shown_object(text, PHASE2, name):
                return 0, measured
        return 0, text


def runtime(tmp_path, target, **kwargs):
    return make_runtime(tmp_path, target, protected=kwargs.pop("protected", {"interface": ["wan1"]}),
                        opt_in=(PHASE2, fortios.IPSEC_TUNNEL), **kwargs)


def create(key=NEW):
    raw = fortios.shown_object(fixture(CREATED[key]), PHASE2, key)
    changes = raw if key == DIRECT else {
        "copy-from": IPSEC_STATUS, "src-subnet": raw["src-subnet"], "auto-negotiate": "disable",
    }
    return request(table=PHASE2, op="create", key=key, endpoint_impact=key,
                   changes=changes, request_id="firewall-cleanup-create-selector")


def recover():
    return request(table=fortios.IPSEC_TUNNEL, op="clear", key=IPSEC_STATUS, endpoint_impact=IPSEC_STATUS,
                   changes={"phase1name": IPSEC_STATUS}, request_id="firewall-cleanup-cycle-tunnel")


@pytest.mark.parametrize("key", [DIRECT, NEW])
def test_phase2_preview_apply_readback_and_undo(tmp_path, key):
    target = FortiOSG26()
    rt = runtime(tmp_path, target)
    baseline = target.snapshot()
    req = create(key)
    preview = execute.preview(rt, "lab", req)
    assert preview["result"] == "ready", preview
    assert not target.applied_blocks and target.snapshot() == baseline
    assert "SYNTHETIC-CANARY" not in repr(preview)
    assert "set proposal aes256-sha256" in [line.strip() for line in preview["commands"]]
    with pytest.raises(Rejected) as exc:
        execute.apply(rt, "lab", req)
    assert exc.value.reason_codes == ["fortios_ipsec_preview_required"]
    assert not target.applied_blocks
    result = execute.apply(rt, "lab", req, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "confirmed", result
    status, answer = target.check_query_status(f'show {PHASE2} "{key}"')
    assert status == 0 and answer == fixture(CREATED[key])
    assert engine.verify(result["plan"], target.snapshot().encode())["result"] == "match"
    undo = execute.preview_undo(rt, result["change_id"], "Restore baseline", issue=True)
    assert undo["result"] == "ready", undo
    result = execute.undo(rt, result["change_id"], "Restore baseline", undo["plan_sha256"])
    assert result["result"] == "confirmed", result
    assert target.snapshot() == baseline and not target.stitches


def test_phase2_incomplete_readback_never_proves_absence(tmp_path):
    target = FortiOSG26()
    target.config_refusal = (1, fixture("phase2-absent") + "permission denied\n")
    rt = runtime(tmp_path, target)
    assert execute.preview(rt, "lab", create())["reason_codes"] == ["clear_readback_unreadable"]
    assert not target.applied_blocks


def test_phase2_copy_fields_and_preflight_scope_are_bound_to_the_hash(tmp_path):
    target = FortiOSG26()
    rt = runtime(tmp_path, target)
    preview = execute.preview(rt, "lab", create())
    assert preview["result"] == "ready"
    target.snapshot_extra.insert(-2, "        set dpd on-idle")
    with pytest.raises(Rejected) as exc:
        execute.apply(rt, "lab", create(), expected_plan_sha256=preview["plan_sha256"])
    assert exc.value.reason_codes == ["plan_changed"]
    assert not target.applied_blocks


@pytest.mark.parametrize("up", [True, False])
def test_recovery_checks_observed_transitions_and_preserves_config(tmp_path, up):
    target = FortiOSG26()
    target.up = up
    rt = runtime(tmp_path, target)
    baseline = target.snapshot()
    req = recover()
    preview = execute.preview(rt, "lab", req)
    assert preview["result"] == "ready", preview
    assert preview["predicted"]["before"]["up"] is up
    assert not target.runtime_writes and not target.applied_blocks
    with pytest.raises(Rejected) as exc:
        execute.apply(rt, "lab", req)
    assert exc.value.reason_codes == ["clear_preview_required"]
    result = execute.apply(rt, "lab", req, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "confirmed", result
    assert result["readback"]["after"]["up"] is True
    assert result["readback"]["down_observed"] is (True if up else None)
    assert target.runtime_writes == (["down", "up"] if up else ["up"])
    assert target.snapshot() == baseline
    with pytest.raises(Rejected) as exc:
        execute.preview_undo(rt, result["change_id"], "Runtime operation")
    assert exc.value.reason_codes == ["undo_not_applicable"]


def test_recovery_protects_management_and_checks_explicit_impact(tmp_path):
    target = FortiOSG26()
    rt = runtime(tmp_path, target, protected={"interface": ["wan1", IPSEC_STATUS]})
    denied = execute.preview(rt, "lab", recover())
    assert denied["reason_codes"] == ["fortios_ipsec_protected"]
    unapproved = execute.preview(rt, "lab", replace(recover(), endpoint_impact=None))
    assert unapproved["reason_codes"] == ["fortios_ipsec_impact_required"]
    assert not target.applied_blocks


def test_recovery_refuses_truncated_or_denied_readback(tmp_path):
    target = FortiOSG26()
    rt = runtime(tmp_path, target)
    for response in ((0, fixture("selectors-up").splitlines()[0]), (1, fixture("selectors-up"))):
        target.status_refusal = response
        denied = execute.preview(rt, "lab", recover())
        assert denied["reason_codes"] == ["clear_readback_unreadable"]
    assert not target.applied_blocks


def test_accepted_down_without_effect_is_never_confirmed(tmp_path):
    target = FortiOSG26()
    target.ignore_down = True
    rt = runtime(tmp_path, target)
    preview = execute.preview(rt, "lab", recover())
    result = execute.apply(rt, "lab", recover(), expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "unknown"
    assert result["readback"]["down_observed"] is False
    assert result["readback"]["sas_replaced"] is False
    assert target.runtime_writes == ["down", "up"]


def test_recovery_without_final_snapshot_blocks_without_repeating_tunnel_commands(tmp_path):
    class TunnelWire(FortiOSG26):
        def snapshot(self):
            if self.runtime_writes:
                raise OSError("synthetic private IPsec diagnostic")
            return super().snapshot()

    target = TunnelWire()
    rt = runtime(tmp_path, target)
    wanted = recover()
    preview = execute.preview(rt, "lab", wanted)
    assert preview["result"] == "ready"

    record = execute.apply(rt, "lab", wanted, expected_plan_sha256=preview["plan_sha256"])

    assert (record["result"], record["reason"]) == ("unknown", "IPsec recovery readback unavailable")
    assert record["readback"]["down_observed"] is True
    assert rt.store.blocked("lab")["change_id"] == record["change_id"]
    assert execute.recover(rt, "lab") == []
    assert target.runtime_writes == ["down", "up"] and target.up and not target.stitches
    assert "synthetic private IPsec diagnostic" not in repr(rt.store.records())


def test_recovery_confirms_measured_sa_replacement_before_up(tmp_path):
    target = FortiOSG26()
    target.auto_negotiate = True
    target.echo_wrapped = True
    rt = runtime(tmp_path, target)
    preview = execute.preview(rt, "lab", recover())
    assert preview["result"] == "ready", preview
    result = execute.apply(rt, "lab", recover(), expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "confirmed", result
    assert result["readback"]["down_observed"] is False
    assert result["readback"]["sas_replaced"] is True
    assert result["readback"]["after"]["up"] is True


def test_other_firmware_warns_and_does_not_block(tmp_path):
    target = FortiOSG26()
    target.firmware = ("7.6.9", "3745")
    rt = runtime(tmp_path, target)
    for req in (create(), recover()):
        preview = execute.preview(rt, "lab", req)
        assert preview["result"] == "ready", preview
        assert preview["firmware_support"]["status"] == "untested"
