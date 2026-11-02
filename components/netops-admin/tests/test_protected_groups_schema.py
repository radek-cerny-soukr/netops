import pytest
from netops_core.schema import Library
from netops_admin import schema_plan, schema_policy
from netops_admin.errors import Rejected

LINKED = "schema transaction changes an object linked to a protected name"


def fixture():
    def group(refs):
        return {"kind": "table", "key": "name", "scope": "vdom", "available": True, "attrs": {
            "name": {"type": "string"},
            "member": {"type": "string", "multi": True, "ref": {"tables": refs}},
            "exclude": {"type": "option", "options": ["enable", "disable"], "default": "disable"},
            "exclude-member": {"type": "string", "multi": True, "ref": {"tables": refs}}}}
    def address():
        return {"kind": "table", "key": "name", "scope": "vdom", "available": True, "attrs": {
            "name": {"type": "string"}, "subnet": {"type": "string"},
            "comment": {"type": "string", "max_length": 100}}}
    document = {"format": 1, "platform": "fortios", "hardware": "FortiGate-VM64-KVM", "os_version": "8.0.0",
                "build": "0167", "config": {
                    "firewall address": address(), "firewall address6": address(),
                    "firewall addrgrp": group(["firewall address", "firewall addrgrp"]),
                    "firewall addrgrp6": group(["firewall address6", "firewall addrgrp6"])}}
    library = Library(document)
    objects = {}
    for path, node in document["config"].items():
        names = [name for name in node["attrs"] if name != node["key"]]
        objects[path] = {node["scope"]: {"operations": {"update": names, "create": names, "delete": names},
                                         "config_bytes_restored": True, "evidence_sha256": "e" * 64}}
    policy = schema_policy.Policy(library, {"format": schema_policy.FORMAT, "identity": list(library.identity),
                                            "schema_sha256": library.sha256, "objects": objects}, "c" * 64)
    return library, policy


def snapshot(suffix, outer):
    return """config vdom
 edit "root"
  config firewall address%(s)s
   edit "a1"
   next
   edit "a2"
   next
  end
  config firewall addrgrp%(s)s
   edit "servers"
    set member "a1"
   next
   edit "middle"
    set member "a2"
   next
%(outer)s  end
 next
end
""" % {"s": suffix, "outer": outer}


def build(path, outer, protected):
    library, policy = fixture()
    operation = {"path": path, "owners": ["servers"], "op": "update", "changes": {"member": ["a1", "a2"]},
                 "scope": "root"}
    text = snapshot("6" if path.endswith("6") else "", outer)
    return schema_plan.build(library, policy, text, [operation], {path: protected})


NESTED = '   edit "admin-hosts"\n    set member "outer"\n   next\n   edit "outer"\n    set member "servers"\n   next\n'
EXCLUDED = '   edit "admin-hosts"\n    set member "a2"\n    set exclude enable\n    set exclude-member "servers"\n   next\n'


@pytest.mark.parametrize("path", ["firewall addrgrp", "firewall addrgrp6"])
@pytest.mark.parametrize("outer", [NESTED, EXCLUDED], ids=["nested", "excluded"])
def test_schema_change_of_a_group_inside_a_protected_group_is_refused(path, outer):
    with pytest.raises(Rejected) as caught:
        build(path, outer, ["Admin-Hosts"])
    assert caught.value.reasons == [LINKED]


@pytest.mark.parametrize("path", ["firewall addrgrp", "firewall addrgrp6"])
def test_schema_change_of_a_group_outside_a_protected_group_is_planned(path):
    plan = build(path, NESTED, ["middle"])
    assert 'set member "a1" "a2"' in plan["commands"]


def run(path, outer, operation, protected):
    library, policy = fixture()
    operation = dict({"op": "update", "scope": "root", "path": path}, **operation)
    return schema_plan.build(library, policy, snapshot("6" if path.endswith("6") else "", outer), [operation], protected)


TOP = '   edit "top"\n    set member "middle" "a1"\n   next\n'


@pytest.mark.parametrize("suffix", ["", "6"])
@pytest.mark.parametrize("members", [["a1"], ["middle", "servers"]], ids=["removed", "kept"])
def test_schema_change_of_a_group_holding_a_protected_address_through_a_subgroup_is_refused(suffix, members):
    with pytest.raises(Rejected) as caught:
        run("firewall addrgrp" + suffix, TOP, {"owners": ["top"], "changes": {"member": members}},
            {"firewall address" + suffix: ["A2"]})
    assert caught.value.reasons == [LINKED]


@pytest.mark.parametrize("suffix", ["", "6"])
def test_schema_change_of_a_group_whose_subgroups_hold_no_protected_address_is_planned(suffix):
    outer = '   edit "top"\n    set member "servers"\n   next\n'
    plan = run("firewall addrgrp" + suffix, outer, {"owners": ["top"], "changes": {"member": ["servers", "a1"]}},
               {"firewall address" + suffix: ["a2"]})
    assert 'set member "servers" "a1"' in plan["commands"]


@pytest.mark.parametrize("suffix", ["", "6"])
@pytest.mark.parametrize("outer,protected", [("", "servers"), (NESTED, "admin-hosts")], ids=["direct", "nested"])
def test_schema_content_change_of_an_address_in_a_protected_group_is_refused(suffix, outer, protected):
    with pytest.raises(Rejected) as caught:
        run("firewall address" + suffix, outer, {"owners": ["a1"], "changes": {"subnet": "192.0.2.1/32"}},
            {"firewall addrgrp" + suffix: [protected.upper()]})
    assert caught.value.reasons == [LINKED]


@pytest.mark.parametrize("suffix", ["", "6"])
def test_schema_comment_of_an_address_in_a_protected_group_and_content_outside_it_are_planned(suffix):
    protected = {"firewall addrgrp" + suffix: ["admin-hosts"]}
    plan = run("firewall address" + suffix, NESTED, {"owners": ["a1"], "changes": {"comment": "member"}}, protected)
    assert 'set comment "member"' in plan["commands"]
    plan = run("firewall address" + suffix, NESTED, {"owners": ["a2"], "changes": {"subnet": "192.0.2.2/32"}},
               protected)
    assert any("set subnet" in line for line in plan["commands"])
