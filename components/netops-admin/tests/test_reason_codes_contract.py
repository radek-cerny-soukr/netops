import unittest

import pytest
from test_issue5_admin import delivery_bench

from netops_admin import execute
from netops_admin.errors import Rejected, BudgetExhausted, StateUnreadable


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
