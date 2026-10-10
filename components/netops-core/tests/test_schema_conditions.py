from __future__ import annotations

import copy
import hashlib
import json

import pytest

from netops_core.schema import Library, SchemaError, load

EVIDENCE = "c9b7df4e6734ed7dd33a0a9af3a8c3c0e945e2cfd51276570ae4d2aac85fac10"


def reference(**changes):
    spec = {"attribute": "sdn", "table": "system sdn-connector", "target_attribute": "type", "equals": "kubernetes",
            "contexts": [{"source": "vdom:root", "target": "global"}], "evidence_sha256": EVIDENCE}
    spec.update(changes)
    return {"reference": spec}


def document():
    return {"format": 1, "platform": "fortios", "hardware": "FortiGate-60F", "os_version": "8.0.0", "build": "0167",
        "config": {
            "firewall address": {"kind": "table", "key": "name", "scope": "vdom", "available": True, "attrs": {
                "name": {"type": "string"},
                "type": {"type": "option", "options": ["ipmask", "dynamic"], "default": "ipmask"},
                "sub-type": {"type": "option", "options": ["sdn", "fsso"], "default": "sdn",
                             "conditions": {"any_of": [{"when": "type", "equals": "dynamic", "baseline": "ipmask"}]}},
                "sdn": {"type": "string", "ref": {"tables": ["system sdn-connector"]},
                        "conditions": {"measured_on": "lab", "any_of": [{"all_of": [
                            {"when": "type", "equals": "dynamic"}, {"when": "sub-type", "equals": "sdn"}]}]}},
                "node-ip-only": {"type": "option", "options": ["enable", "disable"],
                                 "conditions": {"measured_on": "lab", "any_of": [{"all_of": [
                                     {"when": "type", "equals": "dynamic"}, {"when": "sub-type", "equals": "sdn"},
                                     reference()]}]}},
                "comment": {"type": "string", "conditions": {"measured_contexts": ["vdom:VD1"], "evidence_sha256": "e" * 64,
                            "any_of": [{"when": "type", "equals": "ipmask", "baseline": "ipmask", "hidden_by": "dynamic"}]}}}},
            "system sdn-connector": {"kind": "table", "key": "name", "scope": "global", "available": True, "attrs": {
                "name": {"type": "string"},
                "type": {"type": "option", "options": ["aws", "azure", "kubernetes", "vmware"]},
                "server": {"type": "string"}}},
            "router bgp": {"kind": "section", "scope": "vdom", "available": True, "attrs": {}},
            "router bgp neighbor": {"kind": "table", "key": "ip", "scope": "vdom", "available": True, "attrs": {
                "ip": {"type": "string"}, "kind": {"type": "option", "options": ["a", "b"]}}}}}


def condition(data):
    return data["config"]["firewall address"]["attrs"]["node-ip-only"]["conditions"]


def terms(data):
    return condition(data)["any_of"][0]["all_of"]


def spec(data):
    return terms(data)[2]["reference"]


def test_reference_condition_and_existing_local_shapes_load_with_a_pinned_digest(tmp_path):
    library = Library(document())
    assert library.node("firewall address")["attrs"]["node-ip-only"]["conditions"] == condition(document())
    file = tmp_path / "schema.json"
    raw = json.dumps(document()).encode()
    file.write_bytes(raw)
    assert load(file, hashlib.sha256(raw).hexdigest()).sha256 == hashlib.sha256(raw).hexdigest()


def wrap(data, levels):
    clause = condition(data)["any_of"][0]
    for _ in range(levels):
        clause = {"all_of": [clause]}
    condition(data)["any_of"][0] = clause


def chain(data):
    data["config"]["system sdn-connector"]["attrs"]["type"]["conditions"] = {"any_of": [reference(
        table="firewall address", target_attribute="type", equals="dynamic", attribute="server")]}
    data["config"]["system sdn-connector"]["attrs"]["server"]["ref"] = {"tables": ["firewall address"]}


def cycle(data):
    attrs = data["config"]["firewall address"]["attrs"]
    attrs["sdn"]["conditions"]["any_of"][0]["all_of"].append({"when": "node-ip-only", "equals": "enable"})


MALFORMED = [
    ("conditions-not-object", lambda d: d["config"]["firewall address"]["attrs"]["comment"].update(conditions=["x"])),
    ("unknown-condition-field", lambda d: condition(d).update(fallback="global")),
    ("any-of-absent", lambda d: condition(d).pop("any_of")),
    ("any-of-empty", lambda d: condition(d).update(any_of=[])),
    ("measured-on-control", lambda d: condition(d).update(measured_on="lab\nnext")),
    ("evidence-invalid", lambda d: condition(d).update(evidence_sha256="claimed")),
    ("contexts-invalid", lambda d: condition(d).update(measured_contexts=["root"])),
    ("contexts-repeated", lambda d: condition(d).update(measured_contexts=["global", "global"])),
    ("local-unknown-field", lambda d: terms(d)[0].update(fallback="yes")),
    ("local-mixed-reference", lambda d: terms(d)[2].update(when="type", equals="dynamic")),
    ("local-invalid-name", lambda d: terms(d)[0].update(when="type; reboot")),
    ("local-equals-type", lambda d: terms(d)[0].update(equals=1)),
    ("clause-unknown", lambda d: terms(d).__setitem__(2, {"references": spec(d)})),
    ("clause-repeated", lambda d: terms(d).append(copy.deepcopy(terms(d)[0]))),
    ("too-deep", lambda d: wrap(d, 9)),
    ("too-many-alternatives", lambda d: condition(d)["any_of"].extend(
        {"when": "type", "equals": "x%d" % i} for i in range(64))),
    ("too-many-terms", lambda d: terms(d).extend({"when": "type", "equals": "x%d" % i} for i in range(14))),
    ("too-many-nodes", lambda d: condition(d)["any_of"].extend(
        {"all_of": [{"when": "type", "equals": "%d-%d" % (i, j)} for j in range(16)]} for i in range(16))),
    ("reference-field-absent", lambda d: spec(d).pop("evidence_sha256")),
    ("reference-field-unknown", lambda d: spec(d).update(fallback="global")),
    ("reference-evidence-claimed", lambda d: spec(d).update(evidence_sha256="replace-me")),
    ("reference-equals-type", lambda d: spec(d).update(equals=["kubernetes"])),
    ("reference-attribute-absent", lambda d: spec(d).update(attribute="missing")),
    ("reference-attribute-self", lambda d: spec(d).update(attribute="node-ip-only")),
    ("reference-attribute-plain", lambda d: spec(d).update(attribute="comment")),
    ("reference-attribute-multi", lambda d: d["config"]["firewall address"]["attrs"]["sdn"].update(multi=True)),
    ("reference-table-not-referenced", lambda d: spec(d).update(table="router bgp neighbor")),
    ("reference-table-absent", lambda d: d["config"]["firewall address"]["attrs"]["sdn"].update(
        ref={"tables": ["system sdn-connector", "system missing"]}) or spec(d).update(table="system missing")),
    ("reference-table-self", lambda d: d["config"]["firewall address"]["attrs"]["sdn"].update(
        ref={"tables": ["firewall address"]}) or spec(d).update(table="firewall address", target_attribute="type", equals="dynamic")),
    ("reference-table-section", lambda d: d["config"]["firewall address"]["attrs"]["sdn"].update(
        ref={"tables": ["router bgp"]}) or spec(d).update(table="router bgp")),
    ("reference-table-nested", lambda d: d["config"]["firewall address"]["attrs"]["sdn"].update(
        ref={"tables": ["router bgp neighbor"]}) or spec(d).update(table="router bgp neighbor", target_attribute="kind", equals="a")),
    ("target-attribute-absent", lambda d: spec(d).update(target_attribute="missing")),
    ("target-attribute-key", lambda d: spec(d).update(target_attribute="name", equals="x")),
    ("target-attribute-not-option", lambda d: spec(d).update(target_attribute="server", equals="x")),
    ("target-value-unmeasured", lambda d: spec(d).update(equals="gcp")),
    ("target-attribute-chained", chain),
    ("dependency-cycle", cycle),
    ("contexts-empty", lambda d: spec(d).update(contexts=[])),
    ("contexts-not-pairs", lambda d: spec(d).update(contexts=["vdom:root"])),
    ("contexts-pair-incomplete", lambda d: spec(d).update(contexts=[{"source": "vdom:root"}])),
    ("contexts-pair-extra", lambda d: spec(d).update(contexts=[{"source": "vdom:root", "target": "global", "fallback": "any"}])),
    ("contexts-unqualified", lambda d: spec(d).update(contexts=[{"source": "root", "target": "global"}])),
    ("contexts-ambiguous-source", lambda d: spec(d).update(contexts=[{"source": "vdom:root", "target": "global"},
                                                                     {"source": "vdom:root", "target": "vdom:root"}])),
    ("contexts-too-many", lambda d: spec(d).update(contexts=[{"source": "vdom:v%d" % i, "target": "global"} for i in range(65)])),
]


@pytest.mark.parametrize("case,mutate", MALFORMED, ids=[item[0] for item in MALFORMED])
def test_malformed_conditions_are_refused_when_the_library_is_loaded(case, mutate, tmp_path):
    data = document()
    mutate(data)
    with pytest.raises(SchemaError):
        Library(data)
    file = tmp_path / "schema.json"
    raw = json.dumps(data).encode()
    file.write_bytes(raw)
    with pytest.raises(SchemaError):
        load(file, hashlib.sha256(raw).hexdigest())


def test_limits_accept_the_largest_bounded_shapes():
    data = document()
    wrap(data, 7)
    condition(data)["any_of"].extend({"when": "type", "equals": "x%d" % i} for i in range(63))
    Library(data)
    data = document()
    terms(data).extend({"when": "type", "equals": "x%d" % i} for i in range(13))
    Library(data)
