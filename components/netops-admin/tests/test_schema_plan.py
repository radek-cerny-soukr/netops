import copy
import pytest
from netops_core.schema import Library
from netops_admin import schema_plan, schema_policy
from netops_admin.errors import Rejected

def fixture():
 document={"format":1,"platform":"fortios","hardware":"FortiGate-VM64-KVM","os_version":"8.0.0","build":"0167","config":{
 "firewall address":{"kind":"table","key":"name","scope":"vdom","available":True,"attrs":{
 "name":{"type":"string","max_length":79},"comment":{"type":"string","max_length":100},
 "type":{"type":"option","options":["ipmask","fqdn"],"default":"ipmask"},
 "subnet":{"type":"ipv4-classnet"},
 "fqdn":{"type":"string","conditions":{"any_of":[{"when":"type","equals":"fqdn"}]}}}},
 "firewall addrgrp":{"kind":"table","key":"name","scope":"vdom","available":True,"attrs":{
 "name":{"type":"string"},"member":{"type":"string","multi":True,"ref":{"tables":["firewall address"]}}}},
 "router bgp":{"kind":"section","scope":"vdom","available":True,"attrs":{"as":{"type":"integer","min":1,"max":4294967295}}},
 "router bgp neighbor-group":{"kind":"table","key":"name","scope":"vdom","available":True,"attrs":{"name":{"type":"string"}}},
 "router bgp neighbor-group child":{"kind":"table","key":"id","scope":"vdom","available":True,"attrs":{
 "id":{"type":"integer","min":1,"max":99},"comment":{"type":"string"}}},
 "system global":{"kind":"section","scope":"global","available":True,"attrs":{"hostname":{"type":"string"}}}}}
 lib=Library(document)
 objects={}
 for path,node in document["config"].items():
  ops={"update":[x for x in node["attrs"] if x!=node.get("key")]}
  if node["kind"]=="table":ops.update(create=ops["update"],delete=ops["update"])
  objects[path]={node["scope"]:{"operations":ops,"config_bytes_restored":True,"evidence_sha256":"e"*64}}
 policy=schema_policy.Policy(lib,{"format":schema_policy.FORMAT,"identity":list(lib.identity),
  "schema_sha256":lib.sha256,"objects":objects},"c"*64)
 return lib,policy

TEXT="""config global
 config system global
  set hostname "fixture"
 end
end
config vdom
 edit "root"
  config firewall address
   edit "source"
    set subnet 192.0.2.0 255.255.255.0
    set comment "source text"
   next
  end
  config firewall addrgrp
  end
  config router bgp
   set as 64512
   config neighbor-group
    edit "parent"
     config child
      edit 1
       set comment "before"
      next
     end
    next
   end
  end
 next
 edit "VD1"
  config firewall address
  end
  config firewall addrgrp
  end
 next
end
"""

def op(path="firewall address",owners=None,mode="update",changes=None,scope="root"):
 return {"path":path,"owners":["source"] if owners is None else owners,"op":mode,
         "changes":{"comment":"after"} if changes is None else changes,"scope":scope}

def build(operations,text=TEXT,protected=None):
 lib,policy=fixture()
 return schema_plan.build(lib,policy,text,operations,protected)

def test_batch_resolves_created_references_and_reverses_dependency_order():
 plan=build([op(owners=["new"],mode="create",changes={"subnet":"192.0.2.128/25"}),
             op("firewall addrgrp",["group"],"create",{"member":["new"]})])
 assert plan["inverse"].index('delete "group"')<plan["inverse"].index('delete "new"')
 assert "set subnet 192.0.2.128 255.255.255.128" in plan["commands"]
 assert not plan["execution_ready"]
 assert len(plan["operations"])==2
 assert plan["schema_sha256"]==fixture()[0].sha256

def test_network_delete_restores_both_tokens_and_full_original_object():
 plan=build([op(mode="delete",changes={})])
 assert "set subnet 192.0.2.0 255.255.255.0" in plan["inverse"]
 assert 'set comment "source text"' in plan["inverse"]
 assert 'edit "source"' in plan["inverse"]

def test_nested_owner_context_closes_each_level_and_protects_parent():
 operation=op("router bgp neighbor-group child",["parent","1"],changes={"comment":"nested"})
 plan=build([operation])
 assert plan["commands"]==["config vdom",'edit "root"',"config router bgp","config neighbor-group",
  'edit "parent"',"config child",'edit "1"','set comment "nested"',"next","end","next","end","end","next","end"]
 with pytest.raises(Rejected):build([operation],protected={"router bgp neighbor-group":["parent"]})

def test_global_section_update_uses_global_wrapper():
 plan=build([op("system global",[],changes={"hostname":"example"},scope=None)])
 assert plan["commands"]==["config global","config system global",'set hostname "example"',"end","end"]
 assert plan["operations"][0]["risk"]=="C"

def test_condition_trigger_is_ordered_before_dependent_attribute():
 plan=build([op(owners=["fqdn"],mode="create",changes={"fqdn":"example.invalid","type":"fqdn"})])
 assert plan["commands"].index('set type "fqdn"')<plan["commands"].index('set fqdn "example.invalid"')

def test_condition_transition_cannot_silently_drop_existing_attribute():
 text=TEXT.replace('set subnet 192.0.2.0 255.255.255.0','set type "fqdn"\n    set fqdn "example.invalid"')
 with pytest.raises(Rejected):build([op(changes={"type":"ipmask"})],text)

def test_inverse_keeps_quotes_backslashes_and_single_quote_as_literal():
 value="text's \\ path"
 plan=build([op(changes={"comment":value})])
 assert plan["operations"][0]["after_sha256"]==schema_plan._digest({"subnet":("192.0.2.0","255.255.255.0"),"comment":(value,)})

@pytest.mark.parametrize("operation",[
 op(owners=["Source"],mode="create",changes={}),
 op(owners=["missing"]),
 op(owners=["source\nnext"]),
 op(scope="missing"),
 op("router bgp neighbor-group child",["parent"]),
 op(changes={"name":"renamed"}),
 op(changes={"unknown":"value"}),
 op(changes={"comment":"x"*101}),
 op(changes={"comment":"source text"}),
 op("firewall addrgrp",["group"],"create",{"member":["missing"]}),
 op(mode="delete",changes={"comment":"value"}),
])
def test_invalid_identity_context_values_and_references_fail_closed(operation):
 with pytest.raises(Rejected):build([operation])

def test_reference_scope_does_not_cross_vdoms():
 with pytest.raises(Rejected):
  build([op("firewall addrgrp",["group"],"create",{"member":["source"]},scope="VD1")])

def test_delete_refuses_incoming_reference_even_without_metadata():
 text=TEXT.replace('set hostname "fixture"','set hostname "source"')
 with pytest.raises(Rejected):build([op(mode="delete",changes={})],text)

def test_delete_requires_order_restoration_calibration_for_non_tail_entry():
 text=TEXT.replace('set comment "source text"\n   next','set comment "source text"\n   next\n   edit "last"\n   next')
 with pytest.raises(Rejected):build([op(mode="delete",changes={})],text)

def test_protected_reference_blocks_any_change_to_referencing_object():
 with pytest.raises(Rejected):build([op()],protected={"other table":["192.0.2.0"]})

def test_plan_does_not_modify_caller_operations_or_policy():
 lib,policy=fixture();operations=[op()];original=copy.deepcopy(operations)
 schema_plan.build(lib,policy,TEXT,operations)
 assert operations==original

def test_truncated_snapshot_and_command_budget_are_refused():
 with pytest.raises(Rejected):build([op()],TEXT[:-8])
 with pytest.raises(Rejected):build([op()]*33)

def test_inverse_unsets_attribute_that_was_absent():
 text=TEXT.replace('    set comment "source text"\n','')
 assert "unset comment" in build([op()],text)["inverse"]

def test_verification_detects_foreign_change_anywhere_in_snapshot():
 lib,policy=fixture();plan=schema_plan.build(lib,policy,TEXT,[op()])
 assert schema_plan.verify(lib,plan,TEXT,"before")["result"]=="match"
 after=TEXT.replace('set comment "source text"','set comment "after"')
 assert schema_plan.verify(lib,plan,after)["result"]=="match"
 foreign=after.replace('set as 64512','set as 64513')
 assert schema_plan.verify(lib,plan,foreign)["result"]=="mismatch"
 plan["commands"].append("execute reboot")
 with pytest.raises(Rejected):schema_plan.verify(lib,plan,after)

def test_offline_cli_requires_exact_pins_and_reports_verification(tmp_path,capsys):
 import hashlib,json
 from netops_admin.cli import main,EXIT_REJECTED
 lib,policy=fixture()
 schema_file=tmp_path/"schema.json"
 schema_file.write_text(json.dumps(lib._document))
 actual=hashlib.sha256(schema_file.read_bytes()).hexdigest()
 calibration={"format":schema_policy.FORMAT,"identity":list(lib.identity),"schema_sha256":actual,
              "objects":policy.objects}
 cal_file=tmp_path/"calibration.json";cal_file.write_text(json.dumps(calibration))
 cal_sha=hashlib.sha256(cal_file.read_bytes()).hexdigest()
 snapshot=tmp_path/"snapshot.conf";snapshot.write_text(TEXT)
 operations=tmp_path/"operations.json";operations.write_text(json.dumps([op()]))
 args=["schema-plan","--library",str(schema_file),"--schema-sha256",actual,
       "--calibration",str(cal_file),"--calibration-sha256",cal_sha,
       "--snapshot",str(snapshot),"--operations",str(operations)]
 assert main(args)==0
 plan=json.loads(capsys.readouterr().out);assert plan["execution_ready"] is False
 plan_file=tmp_path/"plan.json";plan_file.write_text(json.dumps(plan))
 assert main(["schema-verify","--library",str(schema_file),"--schema-sha256",actual,
              "--snapshot",str(snapshot),"--plan",str(plan_file),"--expect","before"])==0
 assert json.loads(capsys.readouterr().out)["result"]=="match"
 args[args.index("--calibration-sha256")+1]="a"*64
 assert main(args)==EXIT_REJECTED
 assert json.loads(capsys.readouterr().out)["result"]=="rejected"

@pytest.mark.parametrize("case",["new-value","old-value","owner"])
def test_automation_expansions_cannot_change_the_timed_inverse(case):
 text=TEXT
 operation=op()
 if case=="new-value":operation["changes"]["comment"]="%%date%%"
 elif case=="old-value":text=text.replace("source text","%%date%%")
 else:operation=op(owners=["%%date%%"],mode="create")
 with pytest.raises(Rejected):build([operation],text)

def test_vdom_names_cannot_expand_inside_the_timed_inverse():
 with pytest.raises(Rejected):build([op(scope="%%date%%")],TEXT.replace('edit "root"','edit "%%date%%"'))
