import copy
import dataclasses
import hashlib
import json
from pathlib import Path

import pytest
from netops_core import schema, fortios
from netops_admin import engine, schema_runtime, schema_policy, schema_request
from netops_admin.config import Device
from netops_admin.errors import Rejected
from netops_admin.prediction import fortios_text
from netops_admin.request import parse_request
from test_schema_plan import fixture, TEXT, op

def setup(tmp_path,generated=False):
    original,grants=fixture()
    document=copy.deepcopy(original._document)
    if generated:document["config"]["firewall address"]["attrs"]["uuid"]={"type":"string","max_length":36}
    library_file=tmp_path/"library.json"
    library_file.write_text(json.dumps(document))
    lib=schema.load(library_file)
    objects=copy.deepcopy(grants.objects)
    if generated:objects["firewall address"]["vdom"]["generated_on_create"]=["uuid"]
    calibration={"format":schema_policy.FORMAT,"schema_sha256":lib.sha256,"identity":list(lib.identity),"objects":objects}
    cal_file=tmp_path/"calibration.json";cal_file.write_text(json.dumps(calibration))
    binding={"library":str(library_file),"schema_sha256":lib.sha256,"calibration":str(cal_file),
             "calibration_sha256":hashlib.sha256(cal_file.read_bytes()).hexdigest(),"vdoms":["root","VD1"]}
    device=Device("lab","fortios","192.0.2.1",22,"SHA256:"+"A"*43,"/nonexistent/vault.json","rw",
                  "8.0.0 build0167",180,45,{},check_credential="ro",schema=binding)
    return lib,device

def request(operations):
    return parse_request(json.dumps({"device":"lab","operations":operations,"reason":"operator request",
                                    "user_request":"perform the transaction","request_id":"schema-req-12345"}).encode())

def render(tree):
    return "\n".join(fortios_text(tree))+"\n"

def test_live_plan_roundtrip_uses_same_verifier_and_prediction(tmp_path):
    _,device=setup(tmp_path)
    plan=schema_runtime.build(device,request([op()]),TEXT)
    plan=json.loads(json.dumps(plan))
    after=schema_runtime.snapshot_after(TEXT,plan)
    assert engine.verify(plan,TEXT.encode(),"before")["result"]=="match"
    assert engine.verify(plan,after.encode())["result"]=="match"
    assert engine.verify(plan,after.replace("64512","64513").encode())["result"]=="mismatch"
    assert schema_runtime.read_plan(plan) is plan
    assert plan["budget_changes"]==1

def test_only_current_safeguard_is_excluded_from_comparison(tmp_path):
    _,device=setup(tmp_path)
    plan=schema_runtime.build(device,request([op()]),TEXT)
    plan["safeguard_id"]="a"*32
    after=schema_runtime.snapshot_after(TEXT,plan)
    tree=fortios.parse(after);global_node=tree.section("global")
    table=fortios.Node(("global","system automation-action"),0)
    table.entries["netops-sg-"+("a"*12)+"-a"]=fortios.Node(("guard",),0)
    global_node.sub["system automation-action"]=table
    assert engine.verify(plan,render(tree).encode())["result"]=="match"
    table.entries["netops-sg-"+("b"*12)+"-a"]=fortios.Node(("foreign",),0)
    assert engine.verify(plan,render(tree).encode())["result"]=="mismatch"

def test_calibrated_generated_uuid_is_checked_and_bound_to_original_object(tmp_path):
    _,device=setup(tmp_path,True)
    operation=op(owners=["new"],mode="create",changes={"subnet":"192.0.2.183/32","comment":"calibration"})
    plan=schema_runtime.build(device,request([operation]),TEXT)
    after=schema_runtime.snapshot_after(TEXT,plan);tree=fortios.parse(after)
    entry=tree.section("vdom").entries["root"].section("firewall address").entries["new"]
    entry.attrs["uuid"]=fortios.Attr(("b049e8b8-779a-4682-bc73-ce6d54051235",),0)
    verdict=engine.verify(plan,render(tree).encode())
    assert verdict["result"]=="match"
    schema_runtime.bind_generated(plan,verdict["generated_bindings"])
    serialized=json.loads(json.dumps(plan))
    assert engine.verify(serialized,render(tree).encode())["result"]=="match"
    entry.attrs["uuid"]=fortios.Attr(("a049e8b8-779a-4682-bc73-ce6d54051235",),0)
    with pytest.raises(Rejected,match="identity changed"):engine.verify(serialized,render(tree).encode())
    with pytest.raises(Rejected):schema_runtime.bind_generated(plan,{"0":{"uuid":"a"*36}})
    assert engine.verify(plan,TEXT.encode(),"before")["result"]=="match"

def test_unmeasured_generated_uuid_cannot_be_ignored(tmp_path):
    _,device=setup(tmp_path,False)
    plan=schema_runtime.build(device,request([op(owners=["new"],mode="create",changes={"comment":"new"})]),TEXT)
    tree=fortios.parse(schema_runtime.snapshot_after(TEXT,plan))
    tree.section("vdom").entries["root"].section("firewall address").entries["new"].attrs["uuid"]=fortios.Attr(("b049e8b8-779a-4682-bc73-ce6d54051235",),0)
    assert engine.verify(plan,render(tree).encode())["result"]=="mismatch"

@pytest.mark.parametrize("field,value",[("commands",["execute reboot"]),("budget_changes",2),("schema_binding",{}),("generated_bindings",{"0":None})])
def test_journal_tampering_and_malformed_fields_are_rejected(tmp_path,field,value):
    _,device=setup(tmp_path)
    plan=schema_runtime.build(device,request([op()]),TEXT)
    plan[field]=value
    with pytest.raises(Rejected):engine.verify(plan,TEXT.encode(),"before")

def test_calibration_and_library_must_still_match_operator_pins(tmp_path):
    _,device=setup(tmp_path)
    Path(device.schema["calibration"]).write_text("{}")
    with pytest.raises(Rejected):schema_runtime.build(device,request([op()]),TEXT)

def test_preview_audit_refuses_missing_catalog_coverage(tmp_path):
    _,device=setup(tmp_path)
    plan=schema_runtime.build(device,request([op()]),TEXT)
    with pytest.raises(Rejected):schema_runtime.audit_snapshot(plan,TEXT,None)

def test_schema_undo_is_new_reverse_transaction_with_exact_original_prediction(tmp_path):
    _,device=setup(tmp_path)
    plan=schema_runtime.build(device,request([op(),op("router bgp",[],changes={"as":64513})]),TEXT)
    record={"plan":plan,"device":"lab","change_id":"a"*32}
    reverse,expected=schema_runtime.undo_request(record,"operator undo")
    assert isinstance(reverse,schema_request.Transaction)
    assert reverse.operations[0]["path"]=="router bgp"
    assert reverse.operations[0]["changes"]=={"as":"64512"}
    assert reverse.operations[1]["changes"]=={"comment":"source text"}
    after=schema_runtime.snapshot_after(TEXT,plan)
    undo_plan=schema_runtime.build(device,reverse,after)
    assert undo_plan["predicted"]["before"]==expected
    restored=schema_runtime.snapshot_after(after,undo_plan)
    assert engine.verify(plan,restored.encode(),"before")["result"]=="match"

@pytest.mark.parametrize("operation",[
    {"path":None,"scope":"root","owners":[],"op":"update","changes":{}},
    {"path":"firewall address","scope":[],"owners":[],"op":"create","changes":{}},
    {"path":"firewall address","scope":"root","owners":[{}],"op":"create","changes":{}},
    {"path":"firewall address","scope":"root","owners":["new"],"op":"create","changes":{"comment":{}}},
    {"path":"firewall address","scope":"root","owners":["new"],"op":"create","changes":{"comment":[True]}},
])
def test_malformed_transaction_inputs_fail_without_traceback(operation):
    with pytest.raises(Rejected):request([operation])


def test_multiple_steps_on_same_object_have_one_final_readback_and_two_budget_units(tmp_path):
    _,device=setup(tmp_path)
    plan=schema_runtime.build(device,request([op(changes={"comment":"intermediate"}),op(changes={"comment":"final"})]),TEXT)
    assert plan["budget_changes"]==2
    assert len(plan["predicted"]["before"]["objects"])==1
    assert len(plan["predicted"]["after"]["objects"])==1
    after=schema_runtime.snapshot_after(TEXT,plan)
    assert engine.verify(plan,after.encode())["result"]=="match"
    assert engine.verify(plan,TEXT.encode(),"before")["result"]=="match"
    assert "final" in after and "intermediate" not in after

def test_vdom_calibration_cannot_authorize_another_domain(tmp_path):
    _,device=setup(tmp_path)
    cal=Path(device.schema["calibration"]);document=json.loads(cal.read_text())
    document["objects"]["firewall address"]["vdom"]["vdom_names"]=["VD1"]
    cal.write_text(json.dumps(document))
    device.schema["calibration_sha256"]=hashlib.sha256(cal.read_bytes()).hexdigest()
    with pytest.raises(Rejected,match="VDOM"):schema_runtime.build(device,request([op()]),TEXT)


def test_builtin_administrator_profiles_are_read_completely_and_fingerprinted(tmp_path):
    from types import SimpleNamespace
    from netops_admin import exec_schema_fortios
    _,device=setup(tmp_path)
    device=dataclasses.replace(device,accounts=("auditor","operator"))
    queries=[]
    admin='config system admin\n edit "operator"\n set accprofile "super_admin"\n next\n edit "auditor"\n set accprofile "mutable-profile"\n next\nend\n'
    profiles='config system accprofile\n edit "mutable-profile"\n set cli-show enable\n next\nend\n'
    class Access:
        def query(self,command):
            queries.append(command)
            return admin if command=="show system admin" else profiles
    access=Access()
    before=exec_schema_fortios.accounts_check(access,device,TEXT)
    assert queries==["show system admin","show full-configuration system accprofile"]
    profiles=profiles.replace("enable","disable")
    assert exec_schema_fortios.accounts_check(access,device,TEXT)!=before
    profiles='config system accprofile\nend\n'
    with pytest.raises(Rejected):exec_schema_fortios.accounts_check(access,device,TEXT)


@pytest.mark.parametrize("field,value",[("generated_on_create",None),("generated_on_create",["password"]),
                                       ("generated_on_create",{}),("vdom_names",[]),("vdom_names",[{}]),
                                       ("vdom_names",["VD1","VD1"]),("vdom_names","VD1")])
def test_malformed_calibration_context_and_generated_claims_are_rejected(tmp_path,field,value):
    _,device=setup(tmp_path,True)
    cal=Path(device.schema["calibration"]);document=json.loads(cal.read_text())
    document["objects"]["firewall address"]["vdom"][field]=value
    cal.write_text(json.dumps(document))
    device.schema["calibration_sha256"]=hashlib.sha256(cal.read_bytes()).hexdigest()
    with pytest.raises(Rejected):schema_runtime.policy(device)


def test_unknown_and_similarly_named_admin_profiles_cannot_use_builtin_exception():
    from netops_admin import fortios as admin
    snapshot='config system accprofile\nend\n'
    for name in ("custom-profile","super_admin_extra","super_admin_readonly"):
        text='config system admin\n edit "operator"\n set accprofile "'+name+'"\n next\nend\n'
        with pytest.raises(Rejected):admin.admin_fingerprint(text,snapshot,immutable_profiles=("super_admin",))
    with pytest.raises(Rejected):admin.admin_fingerprint("config system admin\nend\n",snapshot,immutable_profiles=("custom-profile",))


def test_generic_request_cannot_enter_legacy_offline_plan_without_operator_binding():
    with pytest.raises(Rejected,match="schema-plan"):
        engine.build_plan("fortios",TEXT.encode(),request([op()]))


@pytest.mark.parametrize("value",[None,"not-a-uuid","b049e8b8-779a-4682-bc73-ce6d54051235 extra"])
def test_generated_identity_must_be_present_and_well_formed(tmp_path,value):
    _,device=setup(tmp_path,True)
    operation=op(owners=["new"],mode="create",changes={"comment":"calibration"})
    plan=schema_runtime.build(device,request([operation]),TEXT)
    tree=fortios.parse(schema_runtime.snapshot_after(TEXT,plan))
    entry=tree.section("vdom").entries["root"].section("firewall address").entries["new"]
    if value is not None:
        entry.attrs["uuid"]=fortios.Attr((value,),0)
    with pytest.raises(Rejected,match="generated attribute"):
        engine.verify(plan,render(tree).encode())

def test_normal_apply_cannot_use_operator_enrollment_namespace(tmp_path):
    _,device=setup(tmp_path)
    operation=op(owners=["netops-enroll-1234"],mode="create",changes={"comment":"calibration"})
    with pytest.raises(Rejected,match="namespace is reserved"):
        schema_runtime.build(device,request([operation]),TEXT)

@pytest.mark.parametrize("file",["library","calibration"])
def test_valid_but_modified_operator_document_is_refused(tmp_path,file):
    _,device=setup(tmp_path)
    path=Path(device.schema[file])
    document=json.loads(path.read_text())
    if file=="library":
        document["config"]["firewall address"]["attrs"]["comment"]["max_length"]=128
    else:
        document["objects"]["firewall address"]["vdom"]["evidence_sha256"]="f"*64
    path.write_text(json.dumps(document))
    with pytest.raises(Rejected):
        schema_runtime.build(device,request([op()]),TEXT)
