from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from netops_core.schema import Library, SchemaError, load


def document():
    return {"format":1,"platform":"fortios","hardware":"FortiGate-VM64-KVM","os_version":"8.0.0","build":"0167",
        "config":{"system sdwan":{"kind":"section","available":True,"scope":"vdom","attrs":{}},
                  "system sdwan health-check":{"kind":"table","attrs":{}},
                  "system sdwan health-check sla":{"kind":"table","available":True,"scope":"vdom","attrs":{
                    "id":{"type":"integer","min":1,"max":32,"default":"0"},
                    "server":{"type":"string","max_length":40},
                    "protocol":{"type":"option","options":["ping","http"]},
                    "members":{"type":"string","multi":True,"ref":{"tables":["system sdwan members"],"special":["0"]}},
                    "network":{"type":"ipv4-classnet"},
                    "password":{"type":"password"}}}}}


def test_nested_read_has_no_config_edit_or_free_cli_text():
    library=Library(document())
    path="system sdwan health-check sla"
    assert library.chain(path)==("system sdwan","system sdwan health-check",path)
    assert library.read_command(path)=="show full-configuration system sdwan"
    with pytest.raises(SchemaError):
        library.read_command("system sdwan; reboot")


def test_exact_identity_and_content_digest_are_required(tmp_path):
    file=tmp_path/"schema.json"
    raw=json.dumps(document()).encode();file.write_bytes(raw)
    library=load(file,hashlib.sha256(raw).hexdigest())
    library.require_identity("FortiGate-VM64-KVM","8.0.0","0167")
    for identity in [("FortiGate-80F","8.0.0","0167"),("FortiGate-VM64-KVM","8.0.1","0167"),("FortiGate-VM64-KVM","8.0.0","0168")]:
        with pytest.raises(SchemaError):
            library.require_identity(*identity)
    with pytest.raises(SchemaError):
        load(file,"0"*64)


def test_valid_typed_values_preserve_quoting_and_sentinels():
    library=Library(document())
    result=library.validate("system sdwan health-check sla",{
        "id":0,"server":'name with "quotes" and \\ slash',"protocol":"http",
        "members":["0","name"],"network":"192.0.2.45/24"})
    assert result["id"]==("0",)
    assert result["server"]==('"name with \\"quotes\\" and \\\\ slash"',)
    assert result["network"]==("192.0.2.0","255.255.255.0")
    assert result["members"]==('"0"','"name"')


@pytest.mark.parametrize("changes",[
    {"id":True},{"id":33},{"id":"1; reboot"},{"id":1.0},{"server":"x\nreboot"},
    {"server":"x\x1b[31m"},{"protocol":"ftp"},{"protocol":["http"]},{"members":[]},
    {"unknown":"x"},{"network":"example.invalid"},{"password":"replace-me"},{"password":None},
    {"server":"x"*41}])
def test_rejects_injection_unsupported_types_and_wrong_ranges(changes):
    with pytest.raises(SchemaError):
        Library(document()).validate("system sdwan health-check sla",changes)


def test_unknown_availability_or_scope_never_allows_writes():
    for field,value in [("available",None),("available",False),("scope",None)]:
        data=document();data["config"]["system sdwan health-check sla"][field]=value
        with pytest.raises(SchemaError):
            Library(data).validate("system sdwan health-check sla",{"id":1})


@pytest.mark.parametrize("mutate",[
    lambda d:d.update(format=True),
    lambda d:d.update(hardware="x\nreboot"),
    lambda d:d["config"]["system sdwan"].update(scope=[]),
    lambda d:d["config"]["system sdwan"].update(available=1),
    lambda d:d["config"]["system sdwan health-check sla"]["attrs"]["id"].update(min=40),
    lambda d:d["config"]["system sdwan health-check sla"]["attrs"]["server"].update(max_length=-1)])
def test_rejects_malformed_library_metadata(mutate):
    data=document();mutate(data)
    with pytest.raises(SchemaError):
        Library(data)


def test_duplicate_fields_nonfinite_values_and_fifo_are_bounded(tmp_path):
    for raw in [b'{"format":1,"format":1}',b'{"format":NaN}',b'\xff',b'[]']:
        file=tmp_path/"bad.json";file.write_bytes(raw)
        with pytest.raises(SchemaError):
            load(file)
    import os
    file=tmp_path/"fifo";os.mkfifo(file)
    with pytest.raises(SchemaError):
        load(file)


def test_caller_mutation_does_not_change_validated_schema():
    data=document();library=Library(data)
    data["config"].clear()
    node=library.node("system sdwan health-check sla");node["attrs"].clear()
    assert library.validate("system sdwan health-check sla",{"id":1})["id"]==("1",)


def test_nested_scope_inherits_and_cannot_override_an_unavailable_parent():
    path="system sdwan health-check sla"
    data=document();node=data["config"][path]
    del node["scope"];del node["available"]
    library=Library(data)
    assert library.scope(path)=="vdom"
    assert library.validate(path,{"id":1})["id"]==("1",)
    data["config"]["system sdwan"]["available"]=False
    data["config"][path]["available"]=True
    with pytest.raises(SchemaError):
        Library(data).validate(path,{"id":1})


def test_real_cli_names_keep_case_and_empty_strings_can_be_cleared():
    data=document()
    data["config"]["system sdwan health-check sla"]["attrs"]["FDS-update-logs"]={"type":"option","options":["enable","disable"]}
    library=Library(data)
    result=library.validate("system sdwan health-check sla",{"FDS-update-logs":"enable","server":""})
    assert result["FDS-update-logs"]==('"enable"',)
    assert result["server"]==('""',)

def inline_library():
    return Library({"format":1,"platform":"fortios","hardware":"FortiGate-VM64-KVM","os_version":"8.0.0","build":"0167",
        "config":{"router bgp":{"kind":"section","scope":"vdom","available":True,"attrs":{}},
            "router bgp redistribute":{"kind":"table","key":"name","attrs":{"name":{"type":"string","max_length":35},"status":{"type":"option","options":["enable","disable"]}}},
            "router bgp redistribute filters":{"kind":"table","key":"id","attrs":{"id":{"type":"integer","min":1,"max":10}}},
            "system replacemsg auth":{"kind":"table","scope":"global","available":True,"key":"msg-type","attrs":{"msg-type":{"type":"string","max_length":28}}},
            "waf profile signature main-class":{"kind":"table","scope":"vdom","available":True,"key":"id","attrs":{"id":{"type":"integer","min":1,"max":99}}}}})

def test_inline_config_keys_are_bound_to_measured_tables_and_parent_owners():
    from netops_core import fortios
    from netops_core.schema import config_instances
    text='config vdom\n edit VD1\n config router bgp\n config redistribute "connected route"\n set status enable\n config filters\n edit 1\n next\n end\n end\n end\n next\nend\n'
    tree=fortios.parse(text)
    instances=list(config_instances(inline_library(),tree))
    parent=next(i for i in instances if i.path=="router bgp redistribute")
    child=next(i for i in instances if i.path.endswith("filters"))
    assert parent.key=="connected route" and parent.scope=="VD1"
    assert child.owners==(("router bgp redistribute","connected route"),("router bgp redistribute filters","1"))
    assert "redistribute connected route" in tree.section("vdom").entries["VD1"].section("router bgp").sub

def test_inline_global_and_integer_key_tables():
    from netops_core import fortios
    from netops_core.schema import config_instances
    tree=fortios.parse('config global\n config system replacemsg auth "auth-login-page"\n end\nend\nconfig vdom\n edit VD1\n config waf profile signature main-class 12\n end\n next\nend\n')
    instances=list(config_instances(inline_library(),tree))
    assert [(i.path,i.key,i.scope) for i in instances]==[("system replacemsg auth","auth-login-page",None),("waf profile signature main-class","12","VD1")]

@pytest.mark.parametrize("name",["100","no-number","12 extra"])
def test_inline_key_syntax_must_match_the_measured_key_type(name):
    from netops_core import fortios
    from netops_core.schema import config_instances
    text="config waf profile signature main-class "+name+"\nend\n"
    instances=list(config_instances(inline_library(),fortios.parse(text),include_unknown=True))
    assert all(i.path!="waf profile signature main-class" for i in instances)

def test_exact_schema_path_takes_precedence_over_inline_key_guess():
    from netops_core import fortios
    from netops_core.schema import config_instances
    library=inline_library()
    instances=list(config_instances(library,fortios.parse("config router bgp\n config redistribute\n edit connected\n next\n end\nend\n")))
    assert next(i for i in instances if i.path=="router bgp redistribute").key=="connected"


@pytest.mark.parametrize("value",[0,1,None,"false",[],{}])
def test_builtin_reference_coverage_requires_a_boolean(value):
    data=document()
    data["config"]["system sdwan health-check sla"]["attrs"]["members"]["ref"]["builtin_values_not_captured"]=value
    with pytest.raises(SchemaError):
        Library(data)


@pytest.mark.parametrize("value",[0,1,None,"false",{},[None],[""],["bad\nname"]])
def test_unresolved_reference_metadata_requires_explicit_known_shape(value):
    data=document()
    data["config"]["system sdwan health-check sla"]["attrs"]["members"]["ref"]["unresolved"]=value
    with pytest.raises(SchemaError):
        Library(data)


@pytest.mark.parametrize("value",[False,True,[],["unmeasured-table"]])
def test_valid_unresolved_reference_metadata_is_preserved(value):
    data=document()
    ref=data["config"]["system sdwan health-check sla"]["attrs"]["members"]["ref"]
    ref["unresolved"]=value;ref["builtin_values_not_captured"]=False
    assert Library(data).node("system sdwan health-check sla")["attrs"]["members"]["ref"]==ref
