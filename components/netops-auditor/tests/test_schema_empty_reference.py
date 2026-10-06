import pytest
from netops_core import fortios,schema
from netops_auditor import schema_checks

@pytest.mark.parametrize("tokens",["''",'""'])
def test_empty_reference_is_not_a_missing_object_or_evaluated_reference(tokens):
 lib=schema.Library({"format":1,"platform":"fortios","hardware":"FortiGate-VM64-KVM","os_version":"8.0.0","build":"0167",
 "config":{"firewall address":{"kind":"table","scope":"vdom","available":True,"attrs":{
 "associated-interface":{"type":"string","ref":{"tables":["system interface"]}}}},
 "system interface":{"kind":"table","scope":"global","available":True,"attrs":{"vdom":{"type":"string"}}}}})
 text="config global\n config system interface\n end\nend\nconfig vdom\n edit root\n config firewall address\n edit example\n set associated-interface "+tokens+"\n next\n end\n next\nend\n"
 hits,coverage=schema_checks.references(lib,fortios.parse(text),True)
 assert hits==[]
 assert coverage["fields"]["firewall address::associated-interface"]["status"]=="not-present"
 text=text.replace(tokens,'"missing"')
 hits,coverage=schema_checks.references(lib,fortios.parse(text),True)
 assert len(hits)==1
 assert coverage["fields"]["firewall address::associated-interface"]["checked_values"]==1

def test_reference_measured_in_one_vdom_is_unknown_in_another_vdom():
 doc={"format":1,"platform":"fortios","hardware":"FortiGate-VM64-KVM","os_version":"8.0.0","build":"0167",
 "config":{"firewall address":{"kind":"table","scope":"vdom","available":True,"attrs":{
 "associated-interface":{"type":"string","ref":{"tables":["system interface"],"measured_contexts":["vdom:root"]}}}},
 "system interface":{"kind":"table","scope":"global","available":True,"attrs":{"vdom":{"type":"string"}}}}}
 text="config global\n config system interface\n end\nend\nconfig vdom\n edit VD1\n config firewall address\n edit example\n set associated-interface missing\n next\n end\n next\nend\n"
 hits,coverage=schema_checks.references(schema.Library(doc),fortios.parse(text),True)
 assert hits==[]
 field=coverage["fields"]["firewall address::associated-interface"]
 assert field["status"]=="not-evaluated" and field["reason"]=="reference context was not measured"
 doc["config"]["firewall address"]["attrs"]["associated-interface"]["ref"]["measured_contexts"].append("vdom:VD1")
 assert len(schema_checks.references(schema.Library(doc),fortios.parse(text),True)[0])==1

@pytest.mark.parametrize("contexts",[None,[],[""],["root"],["vdom:"],["global","global"],["vdom:bad\nname"],[None]])
def test_invalid_measured_reference_context_metadata_is_refused(contexts):
 document={"format":1,"platform":"fortios","hardware":"FortiGate-VM64-KVM","os_version":"8.0.0","build":"0167",
 "config":{"source":{"kind":"table","scope":"vdom","available":True,"attrs":{
 "ref":{"type":"string","ref":{"tables":["target"],"measured_contexts":contexts}}}}}}
 with pytest.raises(schema.SchemaError):schema.Library(document)
