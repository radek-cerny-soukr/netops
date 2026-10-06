import copy
import datetime
import hashlib
import json
import pytest
from fake_fortios import FakeFortiOS
from test_schema_runtime import setup, request, render
from test_schema_plan import TEXT, op
from netops_core import fortios
from netops_admin import execute, schema_runtime, exec_schema_fortios, enrollment
from netops_admin.config import Config, DEFAULT_LIMITS
from netops_admin.errors import Rejected

class Lab(FakeFortiOS):
    def __init__(self,lib):
        super().__init__(hostname="fixture")
        self.lib=lib
        self.addresses={"source":{"subnet":"192.0.2.0 255.255.255.0","comment":"source text","uuid":self._uuid()}}
        self.foreign=False

    def snapshot(self):
        self._fire()
        if self.unreadable:raise RuntimeError("snapshot unavailable")
        tree=fortios.parse(TEXT)
        root=tree.section("vdom").entries["root"]
        table=root.section("firewall address")
        table.entries={}
        for name,values in self.addresses.items():
            node=fortios.Node(("address",name),0)
            for attr,value in values.items():
                node.attrs[attr]=fortios.Attr(tuple(value.split()) if attr=="subnet" else (value,),0)
            table.entries[name]=node
        if self.foreign:root.section("router bgp").attrs["as"]=fortios.Attr(("64599",),0)
        global_node=tree.section("global")
        for path,items in [("system automation-action",self.actions),("system automation-trigger",self.triggers),
                           ("system automation-stitch",self.stitches)]:
            if not items:continue
            table=fortios.Node((path,),0)
            for name in items:table.entries[name]=fortios.Node((path,name),0)
            global_node.sub[path]=table
        return render(tree)

    def query(self,command):
        tables={"show system automation-action":self.actions,
                "show system automation-trigger":self.triggers,
                "show system automation-stitch":self.stitches}
        if command in tables:
            path=command.removeprefix("show ")
            return "config "+path+"\n"+"".join("    edit "+schema_runtime.schema.quoted(name)+"\n    next\n" for name in tables[command])+"end\n"
        return super().query(command)

    def observe(self,plan):
        if self.check_unreadable:raise RuntimeError("check unavailable")
        tree=fortios.parse(self.snapshot())
        schema_runtime._generated(tree,plan,"after")
        objects=[]
        for step in schema_runtime.targets(plan["schema_plan"]):
            _,_,node=schema_runtime.schema_plan._locate(tree,self.lib,step["operation"])
            objects.append(schema_runtime.schema_plan._digest(schema_runtime.schema_plan._state(node) if node is not None else None))
        return {"objects":objects}

def runtime(tmp_path,monkeypatch):
    lib,device=setup(tmp_path,True)
    fake=Lab(lib)
    cfg=Config(str(tmp_path/"state"),str(tmp_path/"audit.jsonl"),None,None,dict(DEFAULT_LIMITS),{"lab":device})
    value=execute.Runtime(cfg,lambda _:fake,sleep=fake.advance)
    value.store.save_enrollment("lab",{"protocol":enrollment.PROTOCOL,
        "binding":enrollment.binding(device,"fp",device.firmware,cfg)})
    monkeypatch.setattr(schema_runtime,"Access",lambda base,_device:base)
    monkeypatch.setattr(exec_schema_fortios,"accounts_check",lambda *_:"fp")
    monkeypatch.setattr(schema_runtime,"audit_snapshot",lambda *_:({},{"fixture":True}))
    monkeypatch.setattr(schema_runtime,"after_audit",lambda *_:([],{"fixture":True}))
    return value,fake

def test_generic_batch_apply_and_undo_use_journal_safeguards_and_weighted_budget(tmp_path,monkeypatch):
    value,fake=runtime(tmp_path,monkeypatch)
    req=request([op(changes={"comment":"intermediate"}),op(changes={"comment":"final"})])
    result=execute.apply(value,"lab",req)
    assert result["result"]=="confirmed" and result["budget_changes"]==2
    assert fake.addresses["source"]["comment"]=="final"
    assert not fake.actions and not fake.triggers and not fake.stitches
    count=len(fake.applied_blocks)
    assert execute.apply(value,"lab",req)["change_id"]==result["change_id"]
    assert len(fake.applied_blocks)==count
    undone=execute.undo(value,result["change_id"],"operator undo")
    assert undone["result"]=="confirmed" and undone["budget_changes"]==2
    assert fake.addresses["source"]["comment"]=="source text"
    assert value.store.operation(result["change_id"])["budget_changes"]==2

def test_generic_partial_batch_failure_returns_all_steps_in_reverse_order(tmp_path,monkeypatch):
    value,fake=runtime(tmp_path,monkeypatch)
    def fail_second_change(device,lines):
        if len(device.applied_blocks)==2:device.fail_at_line=14
        else:device.fail_at_line=None
    fake.on_apply=fail_second_change
    result=execute.apply(value,"lab",request([op(changes={"comment":"first"}),op(changes={"subnet":"192.0.2.32/27"})]))
    assert result["result"]=="reverted"
    assert fake.addresses["source"]["comment"]=="source text"
    assert fake.addresses["source"]["subnet"]=="192.0.2.0 255.255.255.0"

def test_missing_independent_read_before_mutation_refuses_transaction(tmp_path,monkeypatch):
    value,fake=runtime(tmp_path,monkeypatch)
    fake.check_unreadable=True
    with pytest.raises(Rejected):execute.apply(value,"lab",request([op()]))
    assert fake.applied_blocks==[]

def test_missing_independent_read_after_mutation_fires_safeguard(tmp_path,monkeypatch):
    value,fake=runtime(tmp_path,monkeypatch)
    calls=0
    observed=fake.observe
    def check(plan):
        nonlocal calls
        calls+=1
        if calls>=2:raise RuntimeError("check unavailable")
        return observed(plan)
    fake.observe=check
    result=execute.apply(value,"lab",request([op()]))
    assert result["result"]=="reverted" and result["reason"]=="check identity unavailable"
    assert fake.addresses["source"]["comment"]=="source text"

def test_postchange_audit_failure_returns_configuration(tmp_path,monkeypatch):
    value,fake=runtime(tmp_path,monkeypatch)
    calls=0
    def audit(*_):
        nonlocal calls
        calls+=1
        if calls==2:raise RuntimeError("audit unavailable")
        return [],{"fixture":True}
    monkeypatch.setattr(schema_runtime,"after_audit",audit)
    result=execute.apply(value,"lab",request([op()]))
    assert result["result"]=="reverted" and result["reason"]=="audit unavailable"
    assert fake.addresses["source"]["comment"]=="source text"

def test_interrupted_generic_operation_recovers_through_same_journal(tmp_path,monkeypatch):
    value,fake=runtime(tmp_path,monkeypatch)
    def interrupt(device,lines):
        if len(device.applied_blocks)==2:raise KeyboardInterrupt()
    fake.on_apply=interrupt
    with pytest.raises(KeyboardInterrupt):execute.apply(value,"lab",request([op()]))
    assert value.store.running("lab")
    fake.on_apply=None
    settled=execute.recover(value,"lab")
    assert len(settled)==1 and settled[0]["result"]=="reverted"
    assert not value.store.running("lab")
    assert fake.addresses["source"]["comment"]=="source text"

def test_foreign_change_during_confirmation_is_not_reported_as_success(tmp_path,monkeypatch):
    value,fake=runtime(tmp_path,monkeypatch)
    def foreign_after_remove(device,lines):
        if len(device.applied_blocks)==3:device.foreign=True
    fake.on_apply=foreign_after_remove
    result=execute.apply(value,"lab",request([op()]))
    assert result["result"]=="unknown" and value.store.blocked("lab")


def test_generic_doctor_checks_bound_schema_independent_reader_and_enrollment(tmp_path,monkeypatch):
    import dataclasses,time
    from netops_admin import readiness
    from netops_admin.config import Notify
    value,fake=runtime(tmp_path,monkeypatch)
    status=tmp_path/"export.json"
    status.write_text(json.dumps({"updated_at":time.time(),"pending":0,"audit_file":value.config.audit_file}))
    value.config=dataclasses.replace(value.config,export_status_file=str(status),
                                    notify=Notify("https://example.invalid",str(tmp_path/"topic"),10,True))
    device=value.config.devices["lab"]
    value.store.save_enrollment("lab",{"protocol":enrollment.PROTOCOL,
        "binding":enrollment.binding(device,"fp",device.firmware,value.config)})
    report=readiness.doctor(value,"lab")
    assert report["ready"],report["checks"]
    assert report["operations"]["firewall address"]["vdom"]==["create","delete","update"]
    fake.check_unreadable=True
    report=readiness.doctor(value,"lab")
    assert not report["ready"]
    assert any(x["check"]=="check account" and x["status"]=="refused" for x in report["checks"])

def test_generic_transaction_consumes_budget_for_each_step_before_any_write(tmp_path,monkeypatch):
    value,fake=runtime(tmp_path,monkeypatch)
    value.config.limits["changes_per_device_per_hour"]=1
    with pytest.raises(Rejected,match="budget"):
        execute.apply(value,"lab",request([op(changes={"comment":"first"}),op(changes={"comment":"final"})]))
    assert fake.applied_blocks==[]


@pytest.mark.parametrize("mode",["empty","other","own","missing-table","malformed","unreadable"])
def test_schema_guard_cleanup_requires_three_complete_table_reads(mode):
    from types import SimpleNamespace
    change="a"*32
    names=exec_schema_fortios.fortios.safeguard_names(change)
    calls=[]
    def query(command):
        calls.append(command)
        table=command.removeprefix("show ")
        kind=next(kind for kind,path in schema_runtime.GUARD_TABLES.items() if path==table)
        if mode=="unreadable":raise RuntimeError("not readable")
        if mode=="missing-table":return "Command fail. Return code -3\n"
        if mode=="malformed":return "config "+table+"\n"
        owner=names[kind] if mode=="own" else "another-automation"
        entries="    edit "+schema_runtime.schema.quoted(owner)+"\n    next\n" if mode in ("own","other") else ""
        return "config "+table+"\n"+entries+"end\n"
    assert exec_schema_fortios.safeguard_absent(SimpleNamespace(query=query),{"change_id":change}) is (mode in ("empty","other"))
    if mode in ("empty","other"):
        assert set(calls)=={"show "+table for table in schema_runtime.GUARD_TABLES.values()}


@pytest.mark.parametrize("owners",[
    ["source","other"],
    ["source","other","source"],
    ["source","other","third","source"],
])
def test_generic_undo_matches_final_objects_in_reverse_operation_order(tmp_path,monkeypatch,owners):
    value,fake=runtime(tmp_path,monkeypatch)
    value.config.limits["plan_commands"]=512
    value.config.limits["changes_per_device_per_hour"]=16
    for name in dict.fromkeys(owners):
        if name not in fake.addresses:
            fake.addresses[name]={"subnet":"192.0.2.64 255.255.255.192","comment":name+" original","uuid":fake._uuid()}
    before=copy.deepcopy(fake.addresses)
    req=request([op(owners=[name],changes={"comment":"step "+str(index)}) for index,name in enumerate(owners)])
    result=execute.apply(value,"lab",req)
    assert result["result"]=="confirmed"
    undone=execute.undo(value,result["change_id"],"operator undo")
    assert undone["result"]=="confirmed"
    assert undone["budget_changes"]==len(owners)
    assert fake.addresses==before


def test_generic_undo_still_refuses_changed_target_before_any_write(tmp_path,monkeypatch):
    value,fake=runtime(tmp_path,monkeypatch)
    fake.addresses["other"]={"subnet":"192.0.2.64 255.255.255.192","comment":"other original","uuid":fake._uuid()}
    result=execute.apply(value,"lab",request([op(changes={"comment":"first"}),op(owners=["other"],changes={"comment":"second"})]))
    assert result["result"]=="confirmed"
    fake.addresses["other"]["comment"]="outside change"
    writes=len(fake.applied_blocks)
    with pytest.raises(Rejected,match="differs from the state"):
        execute.undo(value,result["change_id"],"operator undo")
    assert len(fake.applied_blocks)==writes
    assert fake.addresses["other"]["comment"]=="outside change"
