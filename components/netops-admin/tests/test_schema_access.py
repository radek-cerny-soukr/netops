from types import SimpleNamespace

import pytest

from netops_admin import access as access_module
from netops_admin.access import SchemaAccess
from netops_admin.errors import Rejected


def context(monkeypatch,inventory="known",current="root"):
    value=object.__new__(SchemaAccess)
    value.device=SimpleNamespace(address="192.0.2.1",check_address=None,port=22,
        legacy_ssh=None,schema={"vdoms":["root","VD1","missing"]})
    value.credential=object()
    value.check_credential=object()
    value.spec=SimpleNamespace(anchor=b"fixture",ends=(b"#",b">"))
    value.base=SimpleNamespace(_host_key=lambda _address:"fixture pin",
        _login=lambda *_:None,check_query=lambda _command:"Current virtual domain: "+current+"\n")
    domains={"root","VD1"}
    sent=[]
    created=[]

    class Shell:
        def __init__(self,*_args,**_kwargs):
            self.last=""
        def __enter__(self):return self
        def __exit__(self,*_args):return False
        def send(self,line):
            sent.append(line)
            self.last=line
            if line.startswith("edit "):
                name=line.removeprefix("edit ").strip('"')
                if name not in domains:
                    domains.add(name)
                    created.append(name)
        def expect(self,patterns,_timeout):
            if len(patterns)==2 and patterns[1]==b"--More--":
                if self.last=="show full-configuration system vdom-property":
                    if inventory=="unreadable":
                        return 0,b"Command fail. Return code -3\n"
                    if inventory=="malformed":
                        return 0,b"config system vdom-property\n"
                    if inventory=="wrong-table":
                        return 0,b"config system global\nend\n"
                    names=sorted(domains) if inventory=="known" else []
                    body="config system vdom-property\n"+"".join('    edit "'+name+'"\n    next\n' for name in names)+"end\n"
                    return 0,body.encode()
                if self.last=="show":
                    return 0,b"config firewall address\nend\n"
                return 0,b""
            return 0,b"#"

    monkeypatch.setattr(access_module.session,"Session",Shell)
    return value,sent,created


def test_missing_declared_vdom_is_refused_before_any_edit(monkeypatch):
    value,sent,created=context(monkeypatch)
    with pytest.raises(Rejected):
        value._context("missing","show")
    assert created==[]
    assert not any(line.startswith("edit ") for line in sent)


@pytest.mark.parametrize("inventory",["empty","malformed","wrong-table","unreadable"])
def test_vdom_navigation_requires_complete_readable_inventory(monkeypatch,inventory):
    value,sent,created=context(monkeypatch,inventory)
    with pytest.raises(Rejected):
        value._context("VD1","show")
    assert created==[]
    assert not any(line.startswith("edit ") for line in sent)


def test_vdom_outside_binding_is_refused_before_transport(monkeypatch):
    value,sent,created=context(monkeypatch)
    with pytest.raises(Rejected):
        value._context("outside","show")
    assert sent==[] and created==[]


def test_existing_vdom_is_verified_before_context_navigation(monkeypatch):
    value,sent,created=context(monkeypatch)
    assert "config firewall address" in value._context("VD1","show")
    assert sent==["config global","show full-configuration system vdom-property",
        "config vdom",'edit "VD1"',"show"]
    assert created==[]


def test_independent_reader_in_current_vdom_avoids_edit_but_checks_inventory(monkeypatch):
    value,sent,created=context(monkeypatch,current="VD1")
    assert "config firewall address" in value._context("VD1","show",True)
    assert sent==["config global","show full-configuration system vdom-property","show"]
    assert created==[]


def test_global_read_does_not_select_any_vdom(monkeypatch):
    value,sent,created=context(monkeypatch)
    value._context(None,"show")
    assert sent==["config global","show"] and created==[]
