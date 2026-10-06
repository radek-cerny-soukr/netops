from __future__ import annotations

import copy
import json

import pytest

from netops_core import fortios
from netops_core.schema import Library, SchemaError
from netops_auditor import schema_checks


def document(version="7.6.7", build="3704"):
    return {"format":1,"platform":"fortios","hardware":"FortiGate-VM64-KVM","os_version":version,"build":build,
        "config":{
            "firewall address":{"kind":"table","scope":"vdom","available":True,"attrs":{"comment":{"type":"string","max_length":40}}},
            "firewall addrgrp":{"kind":"table","scope":"vdom","available":True,"attrs":{
                "member":{"type":"string","multi":True,"ref":{"tables":["firewall address"],"builtin":["all"],"special":["any"]}},
                "mode":{"type":"option","options":["a","b"]},"count":{"type":"integer","min":0,"max":100},
                "description":{"type":"string","max_length":40}}},
            "system interface":{"kind":"table","scope":"global","available":True,"attrs":{"vdom":{"type":"string","ref":{"tables":["vdom"]}}}},
            "router static":{"kind":"table","scope":"vdom","available":True,"attrs":{"device":{"type":"string","ref":{"tables":["system interface"]}}}},
            "system sdwan":{"kind":"section","scope":"vdom","available":True,"attrs":{}},
            "system sdwan members":{"kind":"table","attrs":{}},
            "system sdwan health-check":{"kind":"table","attrs":{"members":{"type":"integer","multi":True,"ref":{"tables":["system sdwan members"],"special":["0"]}}}},
            "system sdwan health-check sla":{"kind":"table","attrs":{}},
            "system sdwan health-check rules":{"kind":"table","attrs":{"sla":{"type":"string","ref":{"tables":["system sdwan health-check sla"]}}}}
        }}


def audit(text, data=None, complete=True):
    return schema_checks.references(Library(data or document()),fortios.parse(text),complete)


def test_all_configured_reference_values_and_builtin_values_are_checked():
    hits, coverage=audit("""config firewall address
 edit "present"
 next
end
config firewall addrgrp
 edit "group"
  set member "present" "all" "any" "missing"
 next
end
""")
    assert len(hits)==1 and hits[0]["evidence"]["value"]=="missing"
    assert hits[0]["line"]==7 and hits[0]["class"]=="fakt"
    field=coverage["fields"]["firewall addrgrp::member"]
    assert field=={"status":"evaluated","checked_values":4}
    assert coverage["fields"]["router static::device"]["status"]=="not-present"


def test_empty_target_table_is_not_silently_skipped():
    hits, coverage=audit('config firewall addrgrp\n edit "g"\n set member "missing"\n next\nend\n')
    assert len(hits)==1
    assert coverage["configured_instances"]["firewall addrgrp::member"]==1


def test_partial_snapshot_and_unresolved_metadata_do_not_claim_missing_targets():
    text='config firewall addrgrp\n edit "g"\n set member "missing"\n next\nend\n'
    hits, coverage=audit(text,complete=False)
    assert hits==[] and coverage["fields"]["firewall addrgrp::member"]["status"]=="not-evaluated"
    for mutation in ("unknown-target","unresolved","unmeasured-builtin","no-target"):
        data=document()
        ref=data["config"]["firewall addrgrp"]["attrs"]["member"]["ref"]
        if mutation=="unknown-target":ref["tables"]=["firewall unknown"]
        elif mutation=="unresolved":ref["unresolved"]=True
        elif mutation=="unmeasured-builtin":ref["builtin_values_not_captured"]=True
        else:ref["tables"]=[]
        hits, coverage=audit(text,data)
        assert hits==[] and coverage["fields"]["firewall addrgrp::member"]["status"]=="not-evaluated"


def test_targets_in_another_vdom_cannot_satisfy_a_reference():
    hits, coverage=audit("""config vdom
 edit "VD1"
  config firewall address
   edit "same-name"
   next
  end
 next
 edit "VD2"
  config firewall addrgrp
   edit "group"
    set member "same-name"
   next
  end
 next
end
""")
    assert len(hits)==1 and hits[0]["evidence"]["vdom"]=="VD2"
    assert json.loads(hits[0]["object_key"])[0]=="VD2"


def test_global_interface_binding_and_vdom_list_are_respected():
    hits, _=audit("""config global
 config system interface
  edit "port1"
   set vdom "VD1"
  next
  edit "port2"
   set vdom "missing-vdom"
  next
 end
end
config vdom
 edit "VD1"
 next
 edit "VD2"
  config router static
   edit 1
    set device "port1"
   next
  end
 next
end
""")
    assert {(h["section"],h["evidence"]["value"]) for h in hits}=={
        ("system interface","missing-vdom"),("router static","port1")}


def test_nested_references_preserve_the_parent_table_key():
    hits, _=audit("""config system sdwan
 config members
  edit 1
  next
 end
 config health-check
  edit "first"
   set members 1 0
   config sla
    edit 1
    next
   end
  next
  edit "second"
   config rules
    edit 1
     set sla 1
    next
   end
  next
 end
end
""")
    assert len(hits)==1 and hits[0]["section"]=="system sdwan health-check rules"
    owners=json.loads(hits[0]["object_key"])[2]
    assert owners[0]==["system sdwan health-check","second"]


def test_unknown_target_scope_in_multivdom_snapshot_is_not_evaluated():
    data=document();data["config"]["firewall address"]["scope"]=None
    hits, coverage=audit('config vdom\n edit "VD1"\n config firewall addrgrp\n edit "g"\n set member "x"\n next\n end\n next\nend\n',data)
    assert hits==[] and coverage["fields"]["firewall addrgrp::member"]["status"]=="not-evaluated"


def compare(change, text=None):
    old=document()
    new=copy.deepcopy(old);new.update(os_version="8.0.0",build="0167")
    change(new)
    tree=fortios.parse(text or 'config firewall addrgrp\n edit "g"\n set mode "b"\n set count 50\n set description "abcdefgh"\n next\nend\n')
    return schema_checks.upgrade(Library(old),Library(new),tree)


@pytest.mark.parametrize("change,rule",[
    (lambda d:d["config"].pop("firewall addrgrp"),"fortios.schema.upgrade-path"),
    (lambda d:d["config"]["firewall addrgrp"].update(available=False),"fortios.schema.upgrade-availability"),
    (lambda d:d["config"]["firewall addrgrp"].update(scope="global"),"fortios.schema.upgrade-scope"),
    (lambda d:d["config"]["firewall addrgrp"]["attrs"].pop("mode"),"fortios.schema.upgrade-attribute"),
    (lambda d:d["config"]["firewall addrgrp"]["attrs"]["mode"].update(options=["a"]),"fortios.schema.upgrade-value"),
    (lambda d:d["config"]["firewall addrgrp"]["attrs"]["count"].update(max=10),"fortios.schema.upgrade-value"),
    (lambda d:d["config"]["firewall addrgrp"]["attrs"]["description"].update(max_length=3),"fortios.schema.upgrade-value"),
    (lambda d:d["config"]["firewall addrgrp"]["attrs"]["mode"].update(type="string"),"fortios.schema.upgrade-value")
])
def test_upgrade_detects_configured_incompatible_schema_changes(change,rule):
    hits, coverage=compare(change)
    assert any(h["rule_id"]==rule for h in hits)
    assert coverage["source"][1]=="7.6.7" and coverage["target"][1]=="8.0.0"
    assert "do not simulate" in coverage["assurance"]


def test_upgrade_does_not_report_unused_schema_changes_or_default_sentinels():
    hits, _=compare(lambda d:d["config"]["firewall addrgrp"]["attrs"]["count"].update(max=10,default="50"))
    assert hits==[]
    hits, _=compare(lambda d:d["config"]["router static"]["attrs"].clear())
    assert hits==[]


def test_upgrade_unknown_metadata_is_explicit_and_unset_attributes_are_not_values():
    hits, coverage=compare(lambda d:d["config"]["firewall addrgrp"].update(available=None),
        'config firewall addrgrp\n edit "g"\n unset mode\n set unknown "x"\n next\nend\nconfig unmeasured table\n edit "x"\n next\nend\n')
    assert hits==[]
    assert {x["reason"] for x in coverage["not_evaluated"]}=={
        "target availability is not measured","configured source attribute is not measured","configured source path is not measured"}


def test_upgrade_refuses_another_model_or_an_older_version():
    for data in [document("7.6.6"),dict(document("8.0.0"),hardware="FortiGate-80F")]:
        with pytest.raises(SchemaError):
            schema_checks.upgrade(Library(document()),Library(data),fortios.parse(""))


def test_findings_limit_is_enforced(monkeypatch):
    monkeypatch.setattr(schema_checks,"MAX_FINDINGS",1)
    with pytest.raises(SchemaError):
        audit('config firewall addrgrp\n edit "g"\n set member "a" "b"\n next\nend\n')


def invoke(tmp_path,capsys,extra=(),text=None):
    from netops_auditor import cli
    schema=tmp_path/"library.json";schema.write_text(json.dumps(document()))
    snapshot=tmp_path/"snapshot.conf"
    snapshot.write_text(text or 'config firewall addrgrp\n edit "g"\n set member "missing"\n next\nend\n')
    args=["schema-check","--library",str(schema),"--hardware","FortiGate-VM64-KVM",
          "--os-version","7.6.7","--build","3704","--config",str(snapshot),
          "--tenant","example","--device","example-device",*extra]
    code=cli.main(args)
    out=capsys.readouterr()
    return code,out


def test_schema_cli_requires_explicit_complete_snapshot_and_reports_assurance(tmp_path,capsys):
    from netops_auditor import cli
    code,out=invoke(tmp_path,capsys)
    assert code==cli.EXIT_INCOMPLETE
    report=json.loads(out.out)
    assert report["findings"]==[] and report["identity_assurance"]=="operator-declared"
    code,out=invoke(tmp_path,capsys,["--full-snapshot"])
    assert code==cli.EXIT_STALE and json.loads(out.out)["findings"]


def test_schema_cli_refuses_identity_mismatch_without_traceback(tmp_path,capsys):
    from netops_auditor import cli
    code,out=invoke(tmp_path,capsys,["--build","0167"])
    assert code==cli.EXIT_ERROR and out.out==""
    assert "does not match" in out.err and "Traceback" not in out.err


def test_schema_cli_handles_malformed_snapshot_without_traceback(tmp_path,capsys):
    from netops_auditor import cli
    code,out=invoke(tmp_path,capsys,text="config firewall address\n")
    assert code==cli.EXIT_ERROR and out.out=="" and "Traceback" not in out.err


def test_schema_cli_outputs_upgrade_coverage_and_target_hash(tmp_path,capsys):
    from netops_auditor import cli
    target=tmp_path/"target.json";data=document("8.0.0","0167")
    data["config"]["firewall addrgrp"]["attrs"]["mode"]["options"]=["a"]
    target.write_text(json.dumps(data))
    code,out=invoke(tmp_path,capsys,["--full-snapshot","--upgrade-library",str(target)],
                    'config firewall addrgrp\n edit "g"\n set mode "b"\n next\nend\n')
    assert code==cli.EXIT_STALE
    report=json.loads(out.out)
    assert report["upgrade_coverage"]["target"][1]=="8.0.0"
    import hashlib
    assert report["target_schema_sha256"]==hashlib.sha256(target.read_bytes()).hexdigest()
    assert report["findings"][0]["rule_id"]=="fortios.schema.upgrade-value"


def test_upgrade_unknown_target_scope_is_not_reported_as_complete():
    hits, coverage=compare(lambda d:d["config"]["firewall addrgrp"].update(scope=None))
    assert hits==[]
    assert any(x["reason"]=="target scope is not measured" for x in coverage["not_evaluated"])


@pytest.mark.parametrize("name,kind,prefix",[("password","password",""),("psksecret","string",""),("ciphertext","string","ENC ")])
def test_secret_bearing_reference_is_not_copied_to_findings_or_coverage(name,kind,prefix):
    data=document()
    data["config"]["firewall addrgrp"]["attrs"][name]={"type":kind,"ref":{"tables":["firewall address"]}}
    text="\n".join(["config firewall addrgrp",' edit "g"',' set '+name+' '+prefix+'"never-copy-this-secret"'," next","end",""])
    hits, coverage=audit(text,data)
    assert hits==[]
    assert coverage["fields"]["firewall addrgrp::"+name]["status"]=="not-evaluated"
    assert "never-copy-this-secret" not in json.dumps(coverage)


def test_reference_to_a_child_table_cannot_use_another_parent_objects_child():
    data=document()
    data["config"]["system sdwan health-check"]["attrs"]["sla"]={"type":"string","ref":{"tables":["system sdwan health-check sla"]}}
    hits,_=audit("""config system sdwan
 config health-check
  edit "first"
   config sla
    edit 1
    next
   end
  next
  edit "second"
   set sla 1
  next
 end
end
""",data)
    assert len(hits)==1 and hits[0]["section"]=="system sdwan health-check"
    assert json.loads(hits[0]["object_key"])[2]==[["system sdwan health-check","second"]]


def test_many_references_reuse_a_target_index_without_rescanning_objects(monkeypatch):
    import netops_auditor.schema_checks as checks
    original=checks._target_sets;builds=[]
    def observe(targets,table,ancestors,source,cache):
        before=len(cache);result=original(targets,table,ancestors,source,cache)
        if len(cache)>before:builds.append(table)
        return result
    monkeypatch.setattr(checks,"_target_sets",observe)
    addresses="config firewall address\n"+''.join(' edit "a'+str(i)+'"\n next\n' for i in range(1000))+"end\n"
    groups="config firewall addrgrp\n"+''.join(' edit "g'+str(i)+'"\n set member "a'+str(i)+'"\n next\n' for i in range(1000))+"end\n"
    hits,coverage=audit(addresses+groups)
    assert hits==[] and builds==["firewall address"]
    assert coverage["fields"]["firewall addrgrp::member"]["checked_values"]==1000

@pytest.mark.parametrize("values,maximum,hits,unknown",[
    ("1 2 3",10,0,0),("1 20",10,1,0),("1 bad",10,0,1),
    ("1 0",10,0,0),('""',10,0,0),("1 +2",10,0,1),
])
def test_upgrade_integer_lists_are_validated_item_by_item(values,maximum,hits,unknown):
    old=document();new=copy.deepcopy(old);new.update(os_version="8.0.0",build="0167")
    for data in (old,new):data["config"]["firewall addrgrp"]["attrs"]["count"].update(multi=True,default="0",min=1)
    new["config"]["firewall addrgrp"]["attrs"]["count"]["max"]=maximum
    found,coverage=schema_checks.upgrade(Library(old),Library(new),fortios.parse("config firewall addrgrp\n edit g\n set count "+values+"\n next\nend\n"))
    assert len(found)==hits and len(coverage["not_evaluated"])==unknown

def test_upgrade_inline_table_attributes_are_compared():
    old=document();new=copy.deepcopy(old);new.update(os_version="8.0.0",build="0167")
    for data in (old,new):
        data["config"]["firewall addrgrp"]["key"]="name"
        data["config"]["firewall addrgrp"]["attrs"]["name"]={"type":"string","max_length":35}
    new["config"]["firewall addrgrp"]["attrs"].pop("mode")
    hits,coverage=schema_checks.upgrade(Library(old),Library(new),fortios.parse("config firewall addrgrp g\n set mode b\nend\n"))
    assert len(hits)==1 and hits[0]["rule_id"]=="fortios.schema.upgrade-attribute"
    assert not coverage["not_evaluated"]


@pytest.mark.parametrize("side", ["source","target"])
def test_upgrade_missing_type_is_unknown_instead_of_a_type_change(side):
    old=document();new=copy.deepcopy(old);new.update(os_version="8.0.0",build="0167")
    (old if side=="source" else new)["config"]["firewall addrgrp"]["attrs"]["mode"]["type"]=None
    hits,coverage=schema_checks.upgrade(Library(old),Library(new),fortios.parse('config firewall addrgrp\n edit g\n set mode b\n next\nend\n'))
    assert hits==[]
    assert coverage["not_evaluated"]==[{"path":"firewall addrgrp","attribute":"mode","reason":"source or target attribute type is not measured"}]


@pytest.mark.parametrize("options",[None,[]])
def test_upgrade_unmeasured_option_choices_do_not_claim_removed_values(options):
    def change(data):
        attribute=data["config"]["firewall addrgrp"]["attrs"]["mode"]
        if options is None:attribute.pop("options")
        else:attribute["options"]=options
    hits,coverage=compare(change,'config firewall addrgrp\n edit g\n set mode b\n next\nend\n')
    assert hits==[]
    assert coverage["not_evaluated"]==[{"path":"firewall addrgrp","attribute":"mode","reason":"target option values are not measured"}]


def test_upgrade_unmeasured_integer_bounds_are_unknown():
    def change(data):
        attribute=data["config"]["firewall addrgrp"]["attrs"]["count"]
        attribute.pop("min");attribute.pop("max")
    hits,coverage=compare(change,'config firewall addrgrp\n edit g\n set count 50\n next\nend\n')
    assert hits==[]
    assert coverage["not_evaluated"]==[{"path":"firewall addrgrp","attribute":"count","reason":"target integer bounds are not measured"}]
