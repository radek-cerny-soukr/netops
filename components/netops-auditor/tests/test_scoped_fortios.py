import json
import pytest
from netops_core import fortios,schema
from netops_auditor import checks_fortios,management,scoped_fortios
from netops_auditor.engine import CheckError,NOT_EVALUATED

def library(default="root"):
 nodes={path:{"kind":"table","scope":"vdom","available":True,"attrs":{}} for path in set(scoped_fortios.PRIMARY_PATHS.values())}
 for path in ("system interface","system global","system admin","system auto-install"):
  nodes[path]["scope"]="global"
 nodes["system interface"]["scope"]="global+vdom"
 nodes["system interface"]["attrs"]={"vdom":{"type":"string"}}
 if default is not None:nodes["system interface"]["attrs"]["vdom"]["default"]=default
 return schema.Library({"format":1,"platform":"fortios","hardware":"FortiGate-VM64-KVM","os_version":"8.0.0","build":"0167","config":nodes})

TEXT="""config global
 config system global
  set strong-crypto enable
 end
 config system interface
  edit root-port
   set vdom root
   set allowaccess ping
  next
  edit other-port
   set vdom VD1
   set allowaccess ping
  next
 end
end
config vdom
 edit root
  config firewall policy
   edit 1
    set srcintf other-port
    set dstintf root-port
    set srcaddr all
    set dstaddr all
    set service HTTPS
    set schedule always
   next
  end
 next
 edit VD1
  config firewall policy
   edit 1
    set srcintf other-port
    set dstintf other-port
    set srcaddr all
    set dstaddr all
    set service HTTPS
    set schedule always
   next
  end
 next
end
"""

def test_views_filter_interfaces_and_preserve_source_tree():
 tree=fortios.parse(TEXT);view,unknown=scoped_fortios.views(library(),tree)
 assert set(view["root"].section("system interface").entries)=={"root-port"}
 assert set(view["VD1"].section("system interface").entries)=={"other-port"}
 assert set(tree.section("global").section("system interface").entries)=={"root-port","other-port"}
 assert view["root"].section("system global").path==("system global",)
 assert not any(unknown.values())

def test_actual_policy_references_do_not_resolve_interfaces_from_another_vdom():
 hits,states=scoped_fortios.run(library(),fortios.parse(TEXT),"tenant","device")
 references=[hit for hit in hits if hit.rule_id=="fortios.ref.dangling"]
 assert len(references)==1
 assert json.loads(references[0].object_key)[0]=="root"
 assert json.loads(references[0].object_key)[1].startswith("firewall policy/1/")
 assert "fortios.scope.vdom-unsupported" not in {hit.rule_id for hit in hits}
 assert states[json.dumps(["root","fortios.ref.dangling"],separators=(",",":"))][0]=="evaluated"

def test_unknown_interface_owner_does_not_produce_false_dangling_findings():
 text=TEXT.replace("   set vdom VD1\n","")
 hits,states=scoped_fortios.run(library(None),fortios.parse(text),"tenant","device")
 assert not any(hit.rule_id=="fortios.ref.dangling" for hit in hits)
 assert states['["root","fortios.ref.dangling"]'][0]==NOT_EVALUATED
 assert states['["VD1","fortios.ref.dangling"]'][0]==NOT_EVALUATED

def test_identical_keys_in_vdoms_have_distinct_fingerprints():
 text=TEXT.replace("set srcintf other-port","set srcintf missing")
 hits,_=scoped_fortios.run(library(),fortios.parse(text),"tenant","device")
 references=[hit for hit in hits if hit.rule_id=="fortios.ref.dangling"]
 assert len(references)==2 and len({hit.fingerprint() for hit in references})==2

@pytest.mark.parametrize("text",[
 "config firewall address\nend\n",
 "config global\nend\nconfig vdom\nend\n",
 TEXT+"config firewall address\nend\n",
 "config global\nend\nconfig vdom\n"+"".join(" edit v"+str(i)+"\n next\n" for i in range(65))+"end\n",
])
def test_missing_or_mixed_snapshots_are_refused(text):
 with pytest.raises(CheckError):scoped_fortios.run(library(),fortios.parse(text),"tenant","device")

def test_global_node_cannot_override_vdom_node():
 text=TEXT.replace(" edit root\n"," edit root\n  config system global\n  end\n",1)
 with pytest.raises(CheckError):scoped_fortios.views(library(),fortios.parse(text))

def test_cli_scoped_catalog_keeps_vdoms_and_reports_findings(tmp_path,capsys):
 from netops_auditor.cli import main
 lib=library();source=tmp_path/"schema.json";source.write_text(json.dumps(lib._document))
 snapshot=tmp_path/"snapshot.conf";snapshot.write_text(TEXT)
 code=main(["schema-check","--library",str(source),"--hardware",lib.identity[0],
  "--os-version",lib.identity[1],"--build",lib.identity[2],"--config",str(snapshot),
  "--tenant","tenant","--device","device","--full-snapshot","--catalog-vdoms"])
 report=json.loads(capsys.readouterr().out)
 assert code==1
 assert report["catalog_coverage"]['["root","fortios.ref.dangling"]']["status"]=="evaluated"
 assert all(value["status"]=="evaluated" for value in report["catalog_coverage"].values() if value["required"])
 assert any(finding["rule_id"]=="fortios.ref.dangling" for finding in report["findings"])


def test_cli_mandatory_unknown_owner_is_incomplete(tmp_path,capsys):
 from netops_auditor.cli import main
 lib=library(None);source=tmp_path/"schema.json";source.write_text(json.dumps(lib._document))
 snapshot=tmp_path/"snapshot.conf";snapshot.write_text(TEXT.replace("   set vdom VD1\n",""))
 code=main(["schema-check","--library",str(source),"--hardware",lib.identity[0],
  "--os-version",lib.identity[1],"--build",lib.identity[2],"--config",str(snapshot),
  "--tenant","tenant","--device","device","--full-snapshot","--catalog-vdoms"])
 report=json.loads(capsys.readouterr().out)
 assert code==3
 assert report["catalog_coverage"]['["root","fortios.ref.dangling"]']["required"]
 assert report["catalog_coverage"]['["root","fortios.ref.dangling"]']["status"]=="not-evaluated"

def test_scoped_view_limit_is_checked_before_copying(monkeypatch):
 lib=library();tree=fortios.parse(TEXT)
 monkeypatch.setattr(scoped_fortios,"MAX_VIEW_ITEMS",30)
 def copy_was_not_allowed(value):
  raise AssertionError("deepcopy ran before the view size limit")
 monkeypatch.setattr(scoped_fortios.copy,"deepcopy",copy_was_not_allowed)
 with pytest.raises(CheckError,match="view size"):
  scoped_fortios.views(lib,tree)
