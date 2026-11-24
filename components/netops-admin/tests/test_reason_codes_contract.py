import re
import unittest
from pathlib import Path

import pytest
from test_issue5_admin import delivery_bench

from netops_admin import execute
from netops_admin.errors import Rejected, BudgetExhausted, StateUnreadable
from approved_apply import approved_apply


class ReasonCodesTest(unittest.TestCase):
    def test_codes_are_explicit_and_independent_of_text(self):
        for message in ('blocked', 'odmítnuto'):
            self.assertEqual(Rejected([message], reason_codes=['device_blocked']).reason_codes, ['device_blocked'])
        self.assertEqual(Rejected(['other']).reason_codes, ['unspecified_refusal'])
        self.assertEqual(BudgetExhausted(['limit']).reason_codes, ['budget_exhausted'])
        self.assertEqual(StateUnreadable(['bad']).reason_codes, ['state_unreadable'])

    def test_state_unreadable_code_does_not_make_the_class_state_unreadable(self):
        coded = Rejected(['lock'], reason_codes=['state_unreadable'])
        self.assertEqual(coded.reason_codes, ['state_unreadable'])
        self.assertNotIsInstance(coded, StateUnreadable)
        self.assertIs(type(coded), Rejected)
        self.assertTrue(issubclass(StateUnreadable, Rejected))


def test_unusable_device_lock_is_a_plain_rejection_with_the_code(tmp_path):
    runtime, change = delivery_bench(tmp_path)
    lock = runtime.store.locks / 'lab.lock'
    lock.unlink(missing_ok=True)
    lock.symlink_to(tmp_path / 'elsewhere')
    with pytest.raises(Rejected) as caught:
        with runtime.store.lock('lab'):
            pass
    assert type(caught.value) is Rejected
    assert caught.value.reason_codes == ['state_unreadable']


def test_refresh_delivery_returns_the_record_when_the_lock_is_unusable(tmp_path):
    runtime, change = delivery_bench(tmp_path)
    record = runtime.store.operation(change)
    assert record['audit_delivery'] == 'pending'
    lock = runtime.store.locks / 'lab.lock'
    lock.unlink(missing_ok=True)
    lock.symlink_to(tmp_path / 'elsewhere')
    assert execute.refresh_delivery(runtime, record) == record
    assert runtime.store.operation(change)['audit_delivery'] == 'pending'


def test_plan_changed_carries_its_code_and_both_hashes(tmp_path):
    from fake_fortios import FakeFortiOS
    from test_execute import make_runtime, request

    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    approved = request(op='update', key='spare-host', changes={'comment': 'approved'}, request_id='req-code-0001')
    expected = execute.preview(runtime, 'lab', approved)['plan_sha256']
    device.addresses['spare-host']['comment'] = 'changed meanwhile'
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, 'lab', approved, expected_plan_sha256=expected)
    assert type(caught.value) is Rejected
    assert caught.value.reason_codes == ['plan_changed']
    assert [set(detail) for detail in caught.value.reason_details] == [{'code', 'expected', 'actual'}]
    assert caught.value.reason_details[0]['expected'] == expected


def test_schema_transaction_is_bound_to_its_preview_like_every_apply():
    from types import SimpleNamespace
    from netops_admin.schema_request import Transaction

    transaction = Transaction('lab', [], 'reason', 'request', 'req-code-0002')
    assert execute._expected_plan(transaction, 'a' * 64) == 'a' * 64
    with pytest.raises(Rejected) as caught:
        execute._expected_plan(transaction, 'A' * 64)
    assert '64 lowercase hexadecimal' in caught.value.reasons[0]
    device = SimpleNamespace(platform='fortios', name='lab')
    with pytest.raises(Rejected) as caught:
        execute._plan_required(device, transaction, None)
    assert caught.value.reason_codes == ['plan_changed']
    assert 'schema transaction' in caught.value.reasons[0]
    execute._plan_required(device, transaction, 'a' * 64)
    execute._plan_required(device, transaction, None, undo=True)


def test_undo_preview_after_an_undo_is_undo_already_done(tmp_path):
    from fake_fortios import FakeFortiOS
    from test_execute import make_runtime, request

    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    first = approved_apply(runtime, 'lab', request(op='update', key='spare-host', changes={'comment': 'mine'}))
    assert execute.undo(runtime, first['change_id'], 'investigated')['result'] == 'confirmed'
    for reason in ('investigated', 'another reason'):
        with pytest.raises(Rejected) as caught:
            execute.preview_undo(runtime, first['change_id'], reason)
        assert caught.value.reason_codes == ['undo_already_done']
        assert caught.value.reasons == [execute.UNDO_DONE]


PORT_AND_POE_CODES = {
    "port_protected", "port_management_vlan", "port_uplink", "port_lag_member", "port_lldp_neighbor",
    "port_learned_mac", "port_usage_unreadable", "poe_not_capable", "poe_unsupported",
    "poe_disabled", "poe_device_not_powered", "poe_state_unreadable", "action_only_table", "action_unsupported", "undo_not_applicable",
}
CODE_PATTERNS = (
    re.compile(r'reason_codes=\["([a-z_]+)"'),
    re.compile(r'reason_code="([a-z_]+)"'),
    re.compile(r'"code": "([a-z_]+)"'),
    re.compile(r'default_code = "([a-z_]+)"'),
    re.compile(r'\["reason_codes"\] = \["([a-z_]+)"\]'),
    re.compile(r'_reject\("(backup_[a-z_]+)"'),
)


def _source_codes() -> set:
    source = Path(execute.__file__).parent
    codes = set()
    for path in sorted(source.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        for pattern in CODE_PATTERNS:
            codes.update(pattern.findall(text))
    return codes


def test_port_and_poe_refusals_carry_named_codes():
    assert PORT_AND_POE_CODES <= _source_codes()


def test_the_version_gate_codes_are_gone_and_t1_has_its_technical_code():
    # STARTUP-1: no refusal names an untested firmware; the technical limit T1 has its own code
    codes = _source_codes()
    assert "port_action_not_measured" not in codes
    assert "safeguard_no_rest_inverse" in codes


# Every reason code of the source has its row in docs/admin-configuration.md; a new code needs its row
# in the same change. Keep this set empty.
DOCUMENTATION_PENDING = set()


def test_every_reason_code_of_the_source_is_documented():
    docs = Path(__file__).resolve().parents[3] / "docs" / "admin-configuration.md"
    if not docs.is_file():
        pytest.skip("the monorepo documentation is not part of this tree")
    documented = set()
    for row in re.findall(r"^\| (`[a-z_]+`(?:, `[a-z_]+`)*) \|", docs.read_text(encoding="utf-8"), re.MULTILINE):
        documented.update(re.findall(r"`([a-z_]+)`", row))
    assert _source_codes() - documented <= DOCUMENTATION_PENDING
