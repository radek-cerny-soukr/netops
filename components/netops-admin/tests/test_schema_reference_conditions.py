import copy
import hashlib
import json
import pytest
from netops_core.schema import Library
from netops_admin import schema_plan, schema_policy
from netops_admin.errors import Rejected

EVIDENCE={"kubernetes":"c9b7df4e6734ed7dd33a0a9af3a8c3c0e945e2cfd51276570ae4d2aac85fac10",
 "vmware":"eaf827c915a84aae3fd95c8d3c50cb8034a5ab7ef53061cd284a93162385ba62",
 "aws":"c43a6ef7ceb8b7528d2675711a64c351ce860c5cefe8ba92e132c6f03b5c1bdf",
 "azure":"c43a6ef7ceb8b7528d2675711a64c351ce860c5cefe8ba92e132c6f03b5c1bdf"}
MEASURED={"kubernetes":("filter","node-ip-only","sdn-addr-type"),"vmware":("filter",),
 "aws":("filter","sdn-addr-type"),"azure":("filter","sdn-addr-type")}
CONNECTORS={"kubernetes":"k8s","vmware":"vcenter","aws":"aws1","azure":"azure1"}
VALUES={"filter":"Name=example","node-ip-only":"enable","sdn-addr-type":"public"}
TYPES=["aci","alicloud","aws","azure","gcp","nsx","nuage","oci","openstack","kubernetes","vmware","sepm","aci-direct","ibm","nutanix","sap"]
ROOT_TO_GLOBAL=[{"source":"vdom:root","target":"global"}]
ROOT_TO_ROOT=[{"source":"vdom:root","target":"vdom:root"}]
ADDRESS=["type","sub-type","sdn","filter","node-ip-only","sdn-addr-type","comment","subnet"]
UNKNOWN="cannot be evaluated"

def clause(kind,contexts=None):
 return {"reference":{"attribute":"sdn","table":"system sdn-connector","target_attribute":"type","equals":kind,
  "contexts":copy.deepcopy(contexts or ROOT_TO_GLOBAL),"evidence_sha256":EVIDENCE[kind]}}

def visible(attribute,contexts=None):
 return {"measured_on":"FortiGate-60F 8.0.0 build0167 lab measurement 2026-10-08","any_of":[
  {"all_of":[{"when":"type","equals":"dynamic"},{"when":"sub-type","equals":"sdn"},clause(kind,contexts)]}
  for kind in ("kubernetes","vmware","aws","azure") if attribute in MEASURED[kind]]}

def document(contexts=None,connector_scope="global",hardware="FortiGate-60F"):
 return {"format":1,"platform":"fortios","hardware":hardware,"os_version":"8.0.0","build":"0167","config":{
  "firewall address":{"kind":"table","key":"name","scope":"vdom","available":True,"attrs":{
   "name":{"type":"string","max_length":79},
   "type":{"type":"option","options":["ipmask","iprange","fqdn","dynamic"],"default":"ipmask"},
   "sub-type":{"type":"option","options":["sdn","fsso"],"default":"sdn","conditions":{"any_of":[{"when":"type","equals":"dynamic"}]}},
   "sdn":{"type":"string","max_length":35,"ref":{"tables":["system sdn-connector"]},
    "conditions":{"any_of":[{"all_of":[{"when":"type","equals":"dynamic"},{"when":"sub-type","equals":"sdn"}]}]}},
   "filter":{"type":"var-string","conditions":visible("filter",contexts)},
   "node-ip-only":{"type":"option","options":["enable","disable"],"default":"disable","conditions":visible("node-ip-only",contexts)},
   "sdn-addr-type":{"type":"option","options":["private","public","all"],"default":"private","conditions":visible("sdn-addr-type",contexts)},
   "subnet":{"type":"ipv4-classnet"},"comment":{"type":"var-string","max_length":255}}},
  "system sdn-connector":{"kind":"table","key":"name","scope":connector_scope,"available":True,"attrs":{
   "name":{"type":"string","max_length":35},"type":{"type":"option","options":TYPES,"default":"aws"},
   "status":{"type":"option","options":["disable","enable"],"default":"enable"}}}}}

def calibration(lib,address=ADDRESS,connector_scope="global"):
 grant=lambda names:{"operations":{"create":list(names),"update":list(names),"delete":list(names)},"config_bytes_restored":True,"evidence_sha256":"e"*64}
 return {"format":schema_policy.FORMAT,"identity":list(lib.identity),"schema_sha256":lib.sha256,"objects":{
  "firewall address":{"vdom":grant(address)},"system sdn-connector":{connector_scope:grant(["type","status"])}}}

def fixture(contexts=None,connector_scope="global",address=ADDRESS,hardware="FortiGate-60F"):
 lib=Library(document(contexts,connector_scope,hardware))
 return lib,schema_policy.Policy(lib,calibration(lib,address,connector_scope),"c"*64)

TEXT="""config global
 config system sdn-connector
  edit "k8s"
   set type kubernetes
   set status disable
  next
  edit "vcenter"
   set type vmware
   set status disable
  next
  edit "aws1"
   set type aws
   set status disable
  next
  edit "azure1"
   set type azure
   set status disable
  next
  edit "gcp1"
   set type gcp
   set status disable
  next
 end
end
config vdom
 edit "root"
  config firewall address
   edit "plain"
    set subnet 192.0.2.0 255.255.255.0
   next
   edit "dyn"
    set type dynamic
    set sub-type sdn
    set sdn "k8s"
    set filter "Name=example"
    set node-ip-only disable
    set sdn-addr-type private
   next
  end
 next
 edit "VD1"
  config firewall address
   edit "dyn"
    set type dynamic
    set sub-type sdn
    set sdn "k8s"
   next
  end
 next
end
"""

CONNECTOR_IN_VDOM="""config global
end
config vdom
 edit "root"
  config system sdn-connector
   edit "%s"
    set type kubernetes
    set status disable
   next
  end
  config firewall address
  end
 next
 edit "VD1"
  config system sdn-connector
   edit "%s"
    set type kubernetes
    set status disable
   next
  end
  config firewall address
  end
 next
end
"""

def build(operations,snapshot=TEXT,**options):
 lib,policy=fixture(**options)
 return schema_plan.build(lib,policy,snapshot,operations)

def sdn(connector,attribute=None,value=None,name="new",mode="create",scope="root"):
 changes={"type":"dynamic","sub-type":"sdn","sdn":connector}
 if attribute:changes[attribute]=value
 return {"path":"firewall address","scope":scope,"owners":[name],"op":mode,"changes":changes}

def update(changes,name="dyn",scope="root"):
 return {"path":"firewall address","scope":scope,"owners":[name],"op":"update","changes":changes}

def connector(name,mode="update",**changes):
 return {"path":"system sdn-connector","scope":None,"owners":[name],"op":mode,"changes":changes}

def planned(connector_name="k8s",attribute="node-ip-only",value="enable"):
 changes={"type":"dynamic","sub-type":"sdn","sdn":connector_name,attribute:value}
 return changes,{name:(text,) for name,text in changes.items()}

@pytest.mark.parametrize("kind",sorted(MEASURED))
@pytest.mark.parametrize("attribute",sorted(VALUES))
def test_measured_connector_type_reveals_only_its_measured_attributes(kind,attribute):
 operation=sdn(CONNECTORS[kind],attribute,VALUES[attribute])
 if attribute in MEASURED[kind]:
  commands=build([operation])["commands"]
  assert commands.index('set sdn "%s"'%CONNECTORS[kind])<commands.index('set %s "%s"'%(attribute,VALUES[attribute]))
  assert commands.index('set type "dynamic"')<commands.index('set sdn "%s"'%CONNECTORS[kind])
 else:
  with pytest.raises(Rejected):build([operation])

@pytest.mark.parametrize("attribute",sorted(VALUES))
def test_without_a_reference_or_after_unset_no_target_attribute_is_allowed(attribute):
 operation=sdn("k8s",attribute,VALUES[attribute]);del operation["changes"]["sdn"]
 with pytest.raises(Rejected):build([operation])
 with pytest.raises(Rejected):build([update({"sdn":None})])
 with pytest.raises(Rejected):build([update({"sdn":""})])
 lib,policy=fixture();refs=schema_policy.References(lib,TEXT);meta=lib.node("firewall address")["attrs"]
 state={"type":("dynamic",),"sub-type":("sdn",)}
 assert schema_policy.condition_state(meta[attribute],meta,state,"root",refs,"firewall address") is False
 assert schema_policy.condition_state(meta[attribute],meta,dict(state,sdn=("",)),"root",refs,"firewall address") is False

def test_dynamic_type_or_an_unmeasured_connector_is_not_generalised():
 with pytest.raises(Rejected):build([sdn("gcp1","filter","Name=example")])
 operation=sdn("k8s","filter","Name=example");operation["changes"]["sub-type"]="fsso";del operation["changes"]["sdn"]
 with pytest.raises(Rejected):build([operation])
 operation=sdn("k8s","node-ip-only","enable");del operation["changes"]["sub-type"];operation["changes"]["type"]="fqdn"
 with pytest.raises(Rejected):build([operation])

def test_target_type_is_read_from_the_snapshot_and_follows_its_change():
 assert build([update({"node-ip-only":"enable"})])["commands"].count('set node-ip-only "enable"')==1
 vmware=TEXT.replace("set type kubernetes","set type vmware").replace("    set node-ip-only disable\n    set sdn-addr-type private\n","")
 with pytest.raises(Rejected):build([update({"node-ip-only":"enable"})],vmware)
 assert build([update({"filter":"Name=other"})],vmware)["commands"].count('set filter "Name=other"')==1
 aws=TEXT.replace("set type kubernetes","set type aws").replace("    set node-ip-only disable\n","")
 assert build([update({"sdn-addr-type":"public"})],aws)["commands"].count('set sdn-addr-type "public"')==1
 with pytest.raises(Rejected):build([update({"node-ip-only":"enable"})],aws)
 with pytest.raises(Rejected):build([update({"comment":"kept"})],TEXT.replace("set type kubernetes","set type vmware"))

def test_transaction_cannot_change_the_type_behind_a_referencing_object():
 with pytest.raises(Rejected):build([connector("k8s",type="vmware")])
 with pytest.raises(Rejected):build([connector("k8s",type="vmware")],TEXT.replace('    set sdn "k8s"\n   next\n  end\n next\nend','   next\n  end\n next\nend'))
 assert len(build([connector("k8s",status="enable")])["operations"])==1
 assert len(build([connector("gcp1",type="kubernetes")])["operations"])==1
 plan=build([connector("k8s2","create",type="kubernetes"),sdn("k8s2","node-ip-only","enable")])
 assert plan["inverse"].index('delete "new"')<plan["inverse"].index('delete "k8s2"')
 with pytest.raises(Rejected):build([connector("k8s2","create",type="vmware"),sdn("k8s2","node-ip-only","enable")])

def test_reference_context_is_explicit_without_a_vdom_or_global_fallback():
 with pytest.raises(Rejected) as refused:build([sdn("k8s","filter","Name=example",scope="VD1")])
 assert UNKNOWN in refused.value.reasons[0]
 with pytest.raises(ValueError):build([sdn("k8s","filter","Name=example")],contexts=ROOT_TO_ROOT)
 lib,policy=fixture(ROOT_TO_ROOT,"vdom")
 only_vd1=CONNECTOR_IN_VDOM%("other","k8s")
 refs=schema_policy.References(lib,only_vd1);changes,state=planned()
 with pytest.raises(Rejected):policy.require("firewall address","root","create",changes,state,refs,refs.snapshot_sha256)
 refs=schema_policy.References(lib,CONNECTOR_IN_VDOM%("k8s","other"))
 assert policy.require("firewall address","root","create",changes,state,refs,refs.snapshot_sha256)["risk"]=="A"
 with pytest.raises(Rejected):policy.require("firewall address","VD1","create",changes,state,refs,refs.snapshot_sha256)
 assert build([sdn("k8s","node-ip-only","enable")],CONNECTOR_IN_VDOM%("k8s","other"),contexts=ROOT_TO_ROOT,connector_scope="vdom")["operations"]

def test_library_identity_schema_digest_and_snapshot_digest_stay_bound():
 lib,policy=fixture();refs=schema_policy.References(lib,TEXT);changes,state=planned()
 assert refs.snapshot_sha256==hashlib.sha256(TEXT.encode()).hexdigest()
 assert policy.require("firewall address","root","create",changes,state,refs,refs.snapshot_sha256)["risk"]=="A"
 for other in (Library(document(hardware="FortiGate-80F")),Library(dict(document(),build="0168")),
               Library({**document(),"config":{**document()["config"],"firewall addrgrp":{"kind":"table","attrs":{}}}})):
  foreign=schema_policy.References(other,TEXT)
  with pytest.raises(Rejected):policy.require("firewall address","root","create",changes,state,foreign,foreign.snapshot_sha256)
 for digest in (hashlib.sha256(b"another snapshot").hexdigest(),None,"not-a-digest"):
  with pytest.raises(Rejected):policy.require("firewall address","root","create",changes,state,refs,digest)
 with pytest.raises(Rejected):policy.require("firewall address","root","create",changes,state)
 assert policy.require("firewall address","root","update",{"comment":"plain"},{"comment":("plain",)})["risk"]=="A"
 plan=build([sdn("k8s","node-ip-only","enable")])
 assert plan["snapshot_sha256"]==refs.snapshot_sha256 and plan["schema_sha256"]==lib.sha256 and plan["identity"]==lib.identity

UNEVALUATED=[
 ("missing",'set sdn "k8s"','set sdn "ghost"'),
 ("type-unmeasured","set type kubernetes","set type unmeasured"),
 ("type-two-values","set type kubernetes","set type kubernetes vmware"),
 ("case-duplicate",'  edit "vcenter"','  edit "K8S"\n   set type kubernetes\n  next\n  edit "vcenter"'),
 ("case-mismatch",'set sdn "k8s"','set sdn "K8s"'),
 ("two-references",'set sdn "k8s"','set sdn "k8s" "vcenter"'),
 ("table-absent"," config system sdn-connector\n",' config system sdn-connector-absent\n'),
]

@pytest.mark.parametrize("case,old,new",UNEVALUATED,ids=[x[0] for x in UNEVALUATED])
def test_missing_unknown_incomplete_or_duplicate_targets_are_not_evaluated(case,old,new):
 text=TEXT.replace(old,new);assert text!=TEXT
 with pytest.raises(Rejected) as refused:build([update({"node-ip-only":"enable"})],text)
 assert UNKNOWN in refused.value.reasons[0]
 lib,_=fixture();refs=schema_policy.References(lib,text);meta=lib.node("firewall address")["attrs"]
 node=refs.tree.section("vdom").entries["root"].section("firewall address").entries["dyn"]
 state=schema_plan._state(node)
 assert schema_policy.condition_state(meta["node-ip-only"],meta,state,"root",refs,"firewall address") is None
 assert not schema_policy.condition_allowed(meta["node-ip-only"],meta,state,"root",refs,"firewall address")

def test_absent_target_attribute_takes_only_an_unconditional_measured_default():
 lib,_=fixture();meta=lib.node("firewall address")["attrs"]
 for text in (TEXT.replace("   set type kubernetes\n",""),TEXT.replace("set type kubernetes","unset type")):
  refs=schema_policy.References(lib,text);_,state=planned("k8s")
  assert [schema_policy.condition_state(meta[x],meta,state,"root",refs,"firewall address") for x in ("filter","node-ip-only","sdn-addr-type")]==[True,False,True]
 shown=TEXT.replace("   set type aws\n","").replace("    set sub-type sdn\n","").replace("    set node-ip-only disable\n","").replace("    set sdn-addr-type private\n","")
 assert build([sdn("aws1","sdn-addr-type","public")],shown)["operations"]
 assert build([update({"sdn-addr-type":"public"})],shown.replace("set type kubernetes","set type azure"))["operations"]
 with pytest.raises(Rejected):build([sdn("aws1","node-ip-only","enable")],shown)
 for changes in ({"default_model_dependent":True},{"conditions":{"any_of":[{"when":"status","equals":"enable"}]}},{"default":None}):
  data=document();attr=data["config"]["system sdn-connector"]["attrs"]["type"];attr.update(changes)
  if attr.get("default") is None:attr.pop("default")
  other=Library(data);refs=schema_policy.References(other,TEXT.replace("   set type kubernetes\n",""))
  meta=other.node("firewall address")["attrs"]
  assert schema_policy.condition_state(meta["filter"],meta,planned("k8s")[1],"root",refs,"firewall address") is None

def test_reference_attribute_default_is_not_taken_as_an_absent_reference():
 for changes,expected in (({"default":"k8s"},None),({"default":""},False),({"default_model_dependent":True},None)):
  data=document();data["config"]["firewall address"]["attrs"]["sdn"].update(changes)
  lib=Library(data);refs=schema_policy.References(lib,TEXT);meta=lib.node("firewall address")["attrs"]
  assert schema_policy.condition_state(meta["filter"],meta,{"type":("dynamic",)},"root",refs,"firewall address") is expected

def test_definite_mismatch_is_false_and_unmeasured_context_is_unknown():
 lib,_=fixture();refs=schema_policy.References(lib,TEXT);meta=lib.node("firewall address")["attrs"]
 _,state=planned("vcenter")
 assert schema_policy.condition_state(meta["node-ip-only"],meta,state,"root",refs,"firewall address") is False
 assert schema_policy.condition_state(meta["filter"],meta,state,"root",refs,"firewall address") is True
 assert schema_policy.condition_state(meta["filter"],meta,state,"VD1",refs,"firewall address") is None
 assert schema_policy.condition_state(meta["filter"],meta,state,None,refs,"firewall address") is None
 assert schema_policy.condition_state(meta["filter"],meta,state,"root",None,"firewall address") is None
 assert schema_policy.condition_state(meta["filter"],meta,state,"root",refs,None) is None

def spec_of(attribute):
 return attribute["conditions"]["any_of"][0]["all_of"][2]["reference"]

def wrap(attribute,levels):
 terms=attribute["conditions"]["any_of"][0]
 for _ in range(levels):terms={"all_of":[terms]}
 attribute["conditions"]["any_of"][0]=terms

MALFORMED=[
 ("evidence-absent",lambda a:spec_of(a).pop("evidence_sha256")),
 ("extra-field",lambda a:spec_of(a).update(fallback=True)),
 ("attribute-absent",lambda a:spec_of(a).update(attribute="missing")),
 ("attribute-without-reference",lambda a:spec_of(a).update(attribute="type")),
 ("table-outside-reference",lambda a:spec_of(a).update(table="firewall address")),
 ("target-attribute-absent",lambda a:spec_of(a).update(target_attribute="missing")),
 ("equals-type",lambda a:spec_of(a).update(equals=5)),
 ("contexts-empty",lambda a:spec_of(a).update(contexts=[])),
 ("context-incomplete",lambda a:spec_of(a).update(contexts=[{"source":"vdom:root"}])),
 ("context-unqualified",lambda a:spec_of(a).update(contexts=[{"source":"root","target":"global"}])),
 ("context-ambiguous",lambda a:spec_of(a).update(contexts=ROOT_TO_GLOBAL+ROOT_TO_ROOT)),
 ("evidence-claimed",lambda a:spec_of(a).update(evidence_sha256="claimed")),
 ("mixed-clause",lambda a:a["conditions"]["any_of"][0]["all_of"][2].update(when="type",equals="dynamic")),
 ("unknown-clause",lambda a:a["conditions"]["any_of"][0]["all_of"].__setitem__(2,{"references":spec_of(a)})),
 ("duplicate-clause",lambda a:a["conditions"]["any_of"][0]["all_of"].append(copy.deepcopy(a["conditions"]["any_of"][0]["all_of"][2]))),
 ("unknown-condition-field",lambda a:a["conditions"].update(fallback="global")),
 ("too-deep",lambda a:wrap(a,9)),
 ("too-many-alternatives",lambda a:a["conditions"]["any_of"].extend({"when":"type","equals":"x%d"%i} for i in range(64))),
 ("too-many-terms",lambda a:a["conditions"]["any_of"].extend({"all_of":[{"when":"type","equals":"%d-%d"%(i,j)} for j in range(16)]} for i in range(16))),
 ("malformed-alternative",lambda a:a["conditions"]["any_of"].append({"reference":{"attribute":"sdn"}})),
]

@pytest.mark.parametrize("case,mutate",MALFORMED,ids=[x[0] for x in MALFORMED])
def test_malformed_reference_metadata_never_allows_a_write(case,mutate):
 lib,_=fixture();refs=schema_policy.References(lib,TEXT);meta=lib.node("firewall address")["attrs"]
 _,state=planned()
 attribute=copy.deepcopy(meta["node-ip-only"])
 assert schema_policy.condition_state(attribute,meta,state,"root",refs,"firewall address") is True
 mutate(attribute)
 assert schema_policy.condition_state(attribute,meta,state,"root",refs,"firewall address") is None
 assert not schema_policy.condition_allowed(attribute,meta,state,"root",refs,"firewall address")

def test_self_referencing_target_table_is_refused_as_a_cycle():
 lib,_=fixture();refs=schema_policy.References(lib,TEXT);meta=lib.node("firewall address")["attrs"]
 meta["sdn"]["ref"]["tables"].append("firewall address")
 attribute=copy.deepcopy(meta["node-ip-only"])
 spec_of(attribute).update(table="firewall address",target_attribute="type",equals="dynamic",contexts=ROOT_TO_ROOT)
 state=dict(planned("dyn")[1])
 assert schema_policy.condition_state(attribute,meta,state,"root",refs,"firewall address") is None
 assert schema_policy.condition_state(attribute,meta,state,"root",refs,"firewall addrgrp") is True

def test_a_satisfied_reference_condition_is_not_a_write_grant():
 with pytest.raises(Rejected) as refused:build([update({"node-ip-only":"enable"})],address=[x for x in ADDRESS if x!="node-ip-only"])
 assert "calibration" in refused.value.reasons[0]
 old=document()
 for name in ("filter","node-ip-only","sdn-addr-type"):old["config"]["firewall address"]["attrs"][name].pop("conditions")
 previous=Library(old);current=Library(document())
 with pytest.raises(Rejected):schema_policy.Policy(current,calibration(previous),"c"*64)

LOCAL=[
 ({"any_of":[{"when":"type","equals":"fqdn","baseline":"ipmask"}]},{"type":("fqdn",)},None,True),
 ({"any_of":[{"when":"type","equals":"fqdn","baseline":"ipmask"}]},{},None,False),
 ({"any_of":[{"when":"mode","equals":"a","baseline":"a","hidden_by":"b"}]},{"mode":("a",)},None,True),
 ({"any_of":[{"when":"mode","equals":"a","baseline":"a","hidden_by":"b"}]},{"mode":("b",)},None,False),
 ({"any_of":[{"when":"model","equals":"x"}]},{},None,False),
 ({"any_of":[{"when":"absent","equals":"x"}]},{},None,False),
 ({"any_of":[{"when":"type","equals":"fqdn"},{"all_of":[{"when":"mode","equals":"a"},{"when":"type","equals":"ipmask"}]}]},{"mode":("a",)},None,True),
 ({"measured_contexts":["vdom:VD1"],"evidence_sha256":"e"*64,"measured_on":"lab","any_of":[{"when":"type","equals":"ipmask"}]},{},"VD1",True),
 ({"measured_contexts":["vdom:VD1"],"any_of":[{"when":"type","equals":"ipmask"}]},{},"root",False),
]

@pytest.mark.parametrize("conditions,state,scope,expected",LOCAL)
def test_local_conditions_keep_their_previous_results(conditions,state,scope,expected):
 metadata={"type":{"type":"option","default":"ipmask"},"mode":{"type":"option"},"model":{"type":"option","default_model_dependent":True}}
 assert schema_policy.condition_allowed({"conditions":conditions},metadata,state,scope) is expected

def test_vdom_measured_local_condition_orders_changes_in_its_own_vdom():
 data={"format":1,"platform":"fortios","hardware":"FortiGate-VM64-KVM","os_version":"8.0.0","build":"0167","config":{
  "firewall address":{"kind":"table","key":"name","scope":"vdom","available":True,"attrs":{
   "name":{"type":"string"},"type":{"type":"option","options":["ipmask","fqdn"],"default":"ipmask"},
   "fqdn":{"type":"string","conditions":{"measured_contexts":["vdom:VD1"],"any_of":[{"when":"type","equals":"fqdn"}]}}}}}}
 lib=Library(data)
 policy=schema_policy.Policy(lib,{"format":schema_policy.FORMAT,"identity":list(lib.identity),"schema_sha256":lib.sha256,"objects":{
  "firewall address":{"vdom":{"operations":{"create":["type","fqdn"]},"config_bytes_restored":True,"evidence_sha256":"e"*64}}}},"c"*64)
 text='config global\nend\nconfig vdom\n edit "root"\n  config firewall address\n  end\n next\n edit "VD1"\n  config firewall address\n  end\n next\nend\n'
 operation={"path":"firewall address","scope":"VD1","owners":["host"],"op":"create","changes":{"fqdn":"example.invalid","type":"fqdn"}}
 commands=schema_plan.build(lib,policy,text,[operation])["commands"]
 assert commands.index('set type "fqdn"')<commands.index('set fqdn "example.invalid"')
 with pytest.raises(Rejected):schema_plan.build(lib,policy,text,[dict(operation,scope="root")])

def test_plan_order_and_digest_are_deterministic():
 first=build([sdn("k8s","node-ip-only","enable")])
 operation=sdn("k8s","node-ip-only","enable");operation["changes"]=dict(reversed(list(operation["changes"].items())))
 second=build([operation])
 assert first["commands"]==second["commands"] and first["plan_sha256"]==second["plan_sha256"]
 assert first["commands"][4:8]==['set type "dynamic"','set sdn "k8s"','set node-ip-only "enable"','set sub-type "sdn"']

def test_offline_plan_reports_an_unevaluated_reference_separately(tmp_path,capsys):
 from netops_admin.cli import main,EXIT_REJECTED
 lib=Library(document())
 library=tmp_path/"schema.json";library.write_text(json.dumps(document()))
 schema_sha=hashlib.sha256(library.read_bytes()).hexdigest()
 data=calibration(lib);data["schema_sha256"]=schema_sha
 cal=tmp_path/"calibration.json";cal.write_text(json.dumps(data))
 snapshot=tmp_path/"snapshot.conf";snapshot.write_text(TEXT)
 def run(operation):
  operations=tmp_path/"operations.json";operations.write_text(json.dumps([operation]))
  code=main(["schema-plan","--library",str(library),"--schema-sha256",schema_sha,"--calibration",str(cal),
             "--calibration-sha256",hashlib.sha256(cal.read_bytes()).hexdigest(),"--snapshot",str(snapshot),"--operations",str(operations)])
  return code,json.loads(capsys.readouterr().out)
 code,plan=run(sdn("k8s","node-ip-only","enable"))
 assert code==0 and plan["snapshot_sha256"]==hashlib.sha256(TEXT.encode()).hexdigest()
 code,result=run(sdn("k8s","node-ip-only","enable",scope="VD1"))
 assert code==EXIT_REJECTED and UNKNOWN in result["reasons"][0]
 code,result=run(sdn("vcenter","node-ip-only","enable"))
 assert code==EXIT_REJECTED and UNKNOWN not in result["reasons"][0]

def live_device(tmp_path):
 from netops_core import schema
 from netops_admin.config import Device
 library=tmp_path/"library.json";library.write_text(json.dumps(document()))
 lib=schema.load(library)
 cal=tmp_path/"calibration.json";cal.write_text(json.dumps(calibration(lib)))
 binding={"library":str(library),"schema_sha256":lib.sha256,"calibration":str(cal),
          "calibration_sha256":hashlib.sha256(cal.read_bytes()).hexdigest(),"vdoms":["root","VD1"]}
 return Device("lab","fortios","192.0.2.1",22,"SHA256:"+"A"*43,"/nonexistent/vault.json","rw",
               "8.0.0 build0167",180,45,{},check_credential="ro",schema=binding)

def live_request(operations):
 from netops_admin.request import parse_request
 return parse_request(json.dumps({"device":"lab","operations":operations,"reason":"operator request",
  "user_request":"perform the transaction","request_id":"schema-req-12345"}).encode())

def test_live_runtime_plan_uses_the_same_pinned_reference_evaluation(tmp_path):
 from netops_admin import engine,schema_runtime
 device=live_device(tmp_path)
 plan=json.loads(json.dumps(schema_runtime.build(device,live_request([update({"node-ip-only":"enable"})]),TEXT)))
 assert plan["snapshot_sha256"]==hashlib.sha256(TEXT.encode()).hexdigest()
 assert engine.verify(plan,TEXT.encode(),"before")["result"]=="match"
 assert engine.verify(plan,schema_runtime.snapshot_after(TEXT,plan).encode())["result"]=="match"
 for text in (TEXT.replace("set type kubernetes","set type vmware"),TEXT.replace('set sdn "k8s"','set sdn "ghost"')):
  with pytest.raises(Rejected):schema_runtime.build(device,live_request([update({"node-ip-only":"enable"})]),text)
 with pytest.raises(Rejected) as refused:schema_runtime.build(device,live_request([sdn("k8s","filter","Name=example",scope="VD1")]),TEXT)
 assert UNKNOWN in refused.value.reasons[0]

@pytest.mark.parametrize("context,scope",[
 (ROOT_TO_GLOBAL,"vdom"),
 (ROOT_TO_ROOT,"global"),
])
def test_reference_target_context_must_match_the_measured_table_scope(context,scope):
 with pytest.raises(ValueError):
  Library(document(contexts=context,connector_scope=scope))

def test_reference_source_context_must_match_the_measured_table_scope():
 data=document()
 data["config"]["firewall address"]["scope"]="global"
 with pytest.raises(ValueError):
  Library(data)

@pytest.mark.parametrize("duplicate",[
 "set type vmware\n   set type kubernetes",
 "set type kubernetes\n   set type kubernetes",
 "unset type\n   set type kubernetes",
])
def test_duplicate_target_type_in_pinned_snapshot_does_not_allow_a_write(duplicate):
 text=TEXT.replace("set type kubernetes",duplicate)
 with pytest.raises(Rejected):
  build([update({"node-ip-only":"enable"})],text)

def test_duplicate_source_reference_in_pinned_snapshot_does_not_allow_a_write():
 text=TEXT.replace('set sdn "k8s"','set sdn "vcenter"\n    set sdn "k8s"')
 with pytest.raises(Rejected):
  build([update({"node-ip-only":"enable"})],text)

def test_repeated_target_entry_without_repeated_attributes_does_not_allow_a_write():
 text=TEXT.replace('  edit "vcenter"','  edit "k8s"\n   set comment "duplicate entry"\n  next\n  edit "vcenter"')
 with pytest.raises(Rejected):
  build([update({"node-ip-only":"enable"})],text)

def test_invalid_empty_snapshot_entry_is_rejected_without_a_traceback():
 text=TEXT.replace('  edit "vcenter"','  edit')
 with pytest.raises(Rejected):
  build([update({"node-ip-only":"enable"})],text)
