import hashlib
import json
import pytest
from netops_core.schema import Library
from netops_admin.errors import Rejected
from netops_admin import schema_policy

def library():
 return Library({"format":1,"platform":"fortios","hardware":"FortiGate-VM64-KVM","os_version":"8.0.0","build":"0167","config":{
 "firewall address":{"kind":"table","scope":"vdom","available":True,"attrs":{
 "name":{"type":"string","max_length":79},"type":{"type":"option","options":["ipmask","fqdn"],"default":"ipmask"},
 "fqdn":{"type":"string","conditions":{"any_of":[{"when":"type","equals":"fqdn"}]}}}},
 "system global":{"kind":"section","scope":"global","available":True,"attrs":{"hostname":{"type":"string"}}}}})

def fixture(tmp_path):
 lib=library();data={"format":schema_policy.FORMAT,"identity":list(lib.identity),"schema_sha256":lib.sha256,
 "objects":{"firewall address":{"vdom":{"operations":{"create":["type","fqdn"]},"config_bytes_restored":True,"evidence_sha256":"a"*64}}}}
 p=tmp_path/"calibration.json";p.write_text(json.dumps(data))
 return lib,p,data

def load(lib,p):
 return schema_policy.load(lib,p,hashlib.sha256(p.read_bytes()).hexdigest())

def test_exact_calibration_requires_visible_attributes_and_every_class_keeps_safeguard(tmp_path):
 lib,p,_=fixture(tmp_path);policy=load(lib,p)
 verdict=policy.require("firewall address","root","create",{"fqdn":"example.invalid"},{"type":("fqdn",)})
 assert verdict["risk"]=="A" and verdict["safeguard_required"] and verdict["independent_readback_required"]
 with pytest.raises(Rejected):policy.require("firewall address","root","create",{"fqdn":"example.invalid"},{})
 with pytest.raises(Rejected):policy.require("firewall address",None,"create",{"type":"fqdn"},{})
 with pytest.raises(Rejected):policy.require("firewall address","root","delete",{},{})

@pytest.mark.parametrize("mutation",["digest","schema","identity","restored","evidence","attribute","scope","section-create"])
def test_unmeasured_calibration_is_refused(tmp_path,mutation):
 lib,p,data=fixture(tmp_path)
 if mutation=="digest":
  with pytest.raises(Rejected):schema_policy.load(lib,p,"b"*64)
  return
 grant=data["objects"]["firewall address"]["vdom"]
 if mutation=="schema":data["schema_sha256"]="b"*64
 elif mutation=="identity":data["identity"][1]="7.6.7"
 elif mutation=="restored":grant["config_bytes_restored"]=False
 elif mutation=="evidence":grant["evidence_sha256"]="claimed"
 elif mutation=="attribute":grant["operations"]["create"]=["unknown"]
 elif mutation=="scope":data["objects"]["firewall address"]={"global":grant}
 elif mutation=="section-create":data["objects"]={"system global":{"global":grant}}
 p.write_text(json.dumps(data))
 with pytest.raises(Rejected):load(lib,p)

def test_risk_classes_do_not_make_unknown_paths_less_restricted():
 assert schema_policy.risk("firewall service custom")=="A"
 assert schema_policy.risk("router static")=="B"
 assert schema_policy.risk("system interface",["ip"])=="B"
 for path,attrs in (("system interface",["allowaccess"]),("system admin",["accprofile"]),("unknown subsystem",[])):
  assert schema_policy.risk(path,attrs)=="C"

def test_multilevel_visibility_requires_all_triggers_and_rejects_unknown_defaults():
 metadata={"first":{"type":"option","default":"enable"},"second":{"type":"option","default_model_dependent":True}}
 attr={"conditions":{"any_of":[{"all_of":[{"when":"first","equals":"enable"},{"when":"second","equals":"on"}]}]}}
 assert not schema_policy.condition_allowed(attr,metadata,{})
 assert schema_policy.condition_allowed(attr,metadata,{"second":("on",)})
 assert not schema_policy.condition_allowed(attr,metadata,{"first":("disable",),"second":("on",)})

def test_calibration_and_value_validation_do_not_mutate_operator_data(tmp_path):
 lib,p,data=fixture(tmp_path)
 policy=schema_policy.Policy(lib,data,"a"*64)
 data["objects"]["firewall address"]["vdom"]["operations"]["create"].append("name")
 with pytest.raises(Rejected):policy.require("firewall address","root","create",{"name":"added-after-validation"},{})
 with pytest.raises(Rejected):policy.require("firewall address","root","create",{"type":"not-an-option"},{})
 with pytest.raises(Rejected):policy.require("firewall address",True,"create",{"type":"fqdn"},{})
 assert policy.require("firewall address","root","create",{"fqdn":"example.invalid"},{"type":("fqdn",)})["canonical_changes"]=={"fqdn":('"example.invalid"',)}


def test_visibility_conditions_measured_in_one_vdom_do_not_authorize_another_context():
    from netops_admin.schema_policy import condition_allowed
    metadata={"system-dns":{"type":"option","default":"disable"},"protocol":{"type":"option","default":"ftp"}}
    attribute={"conditions":{"measured_contexts":["vdom:VD1"],"any_of":[{"all_of":[{"when":"system-dns","equals":"disable"},{"when":"protocol","equals":"ftp"}]}]}}
    assert condition_allowed(attribute,metadata,{}, "VD1")
    assert not condition_allowed(attribute,metadata,{}, "root")
    assert not condition_allowed(attribute,metadata,{}, None)
    assert not condition_allowed(attribute,metadata,{"protocol":("ping",)}, "VD1")
    attribute["conditions"]["measured_contexts"]=["global"]
    assert condition_allowed(attribute,metadata,{},None)
    assert not condition_allowed(attribute,metadata,{},"VD1")


def test_unknown_or_invalid_visibility_measurement_context_does_not_allow_a_write():
    from netops_admin.schema_policy import condition_allowed
    for contexts in (None,False,"vdom:VD1",[],[None]):
        attribute={"conditions":{"measured_contexts":contexts,"any_of":[{"when":"mode","equals":"enable"}]}}
        assert not condition_allowed(attribute,{"mode":{"default":"enable"}},{},"VD1")
