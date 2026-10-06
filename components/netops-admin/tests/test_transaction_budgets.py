from types import SimpleNamespace
import pytest
from netops_admin import execute,state
from netops_admin.errors import Rejected,BudgetExhausted

def runtime(records,hour=12,day=75):
    store=SimpleNamespace(rejections_since=lambda _:0,records=lambda:records)
    limits={"rejections_per_hour":30,"journal_records":20000,"changes_per_device_per_hour":hour,"changes_per_day":day}
    return SimpleNamespace(store=store,config=SimpleNamespace(limits=limits))

def record(device="a",weight=1,at=10000):
    return {"device":device,"budget_changes":weight,"created_at_epoch":at,"safeguard":{}}

def test_multi_operation_request_consumes_each_change(monkeypatch):
    monkeypatch.setattr(execute.time,"time",lambda:10000)
    with pytest.raises(BudgetExhausted):
        execute._budgets(runtime([record(weight=2)],hour=4),SimpleNamespace(name="a"),changes=3)
    execute._budgets(runtime([record(weight=2)],hour=4),SimpleNamespace(name="a"),changes=2)

def test_daily_budget_counts_transactions_from_all_devices(monkeypatch):
    monkeypatch.setattr(execute.time,"time",lambda:10000)
    with pytest.raises(BudgetExhausted):
        execute._budgets(runtime([record("other",weight=3)],day=4),SimpleNamespace(name="a"),changes=2)
    execute._budgets(runtime([record("other",weight=3)],day=4),SimpleNamespace(name="a"),changes=1)

def test_old_records_count_as_one_change_and_old_hours_do_not_count(monkeypatch):
    monkeypatch.setattr(execute.time,"time",lambda:10000)
    legacy=record();legacy.pop("budget_changes")
    execute._budgets(runtime([legacy,record(weight=4,at=6000)],hour=3,day=7),SimpleNamespace(name="a"),changes=2)
    with pytest.raises(BudgetExhausted):
        execute._budgets(runtime([legacy,record(weight=4,at=6000)],hour=3,day=6),SimpleNamespace(name="a"),changes=2)

@pytest.mark.parametrize("changes",[True,0,-1,33,1.5,"2"])
def test_invalid_transaction_weights_are_refused(changes):
    with pytest.raises(Rejected):
        execute._budgets(runtime([]),SimpleNamespace(name="a"),changes=changes)

@pytest.mark.parametrize("weight",[True,0,-1,33,1.5,"2",None])
def test_journal_does_not_accept_malformed_transaction_weights(weight):
    change="a"*32
    document={"change_id":change,"request_id":"request-123","device":"a","status":"finished","budget_changes":weight}
    assert not state._operation_valid(document,change)

def test_legacy_journal_weight_is_compatible():
    change="a"*32
    document={"change_id":change,"request_id":"request-123","device":"a","status":"finished"}
    assert state._operation_valid(document,change)
    document["budget_changes"]=32
    assert state._operation_valid(document,change)
