from __future__ import annotations

import copy
import json

from netops_core import fortios
from netops_core.schema import Library
from netops_auditor import cli, schema_checks

REASON = "target attribute visibility depends on a referenced object and is not evaluated"
REFERENCE = {"any_of": [{"all_of": [{"when": "type", "equals": "dynamic"}, {"reference": {
    "attribute": "sdn", "table": "system sdn-connector", "target_attribute": "type", "equals": "kubernetes",
    "contexts": [{"source": "vdom:root", "target": "global"}],
    "evidence_sha256": "c9b7df4e6734ed7dd33a0a9af3a8c3c0e945e2cfd51276570ae4d2aac85fac10"}}]}]}
LOCAL = {"any_of": [{"when": "type", "equals": "dynamic", "baseline": "ipmask"}]}
TEXT = """config global
 config system sdn-connector
  edit "k8s"
   set type kubernetes
  next
 end
end
config vdom
 edit "root"
  config firewall address
   edit "dyn"
    set type dynamic
    set sub-type sdn
    set sdn "k8s"
    set node-ip-only enable
   next
  end
 next
end
"""


def document(version="7.6.7", build="3704", conditions=None):
    attrs = {"name": {"type": "string"},
             "type": {"type": "option", "options": ["ipmask", "dynamic"], "default": "ipmask"},
             "sub-type": {"type": "option", "options": ["sdn", "fsso"]},
             "sdn": {"type": "string", "ref": {"tables": ["system sdn-connector"]}},
             "node-ip-only": {"type": "option", "options": ["enable", "disable"]}}
    for name, value in (conditions or {}).items():
        attrs[name]["conditions"] = copy.deepcopy(value)
    return {"format": 1, "platform": "fortios", "hardware": "FortiGate-60F", "os_version": version, "build": build,
        "config": {"firewall address": {"kind": "table", "key": "name", "scope": "vdom", "available": True, "attrs": attrs},
                   "system sdn-connector": {"kind": "table", "key": "name", "scope": "global", "available": True, "attrs": {
                       "name": {"type": "string"}, "type": {"type": "option", "options": ["kubernetes", "vmware"]}}}}}


def upgrade(target):
    return schema_checks.upgrade(Library(document()), target, fortios.parse(TEXT))


def test_upgrade_marks_a_reference_dependent_target_attribute_as_not_evaluated():
    hits, coverage = upgrade(Library(document("8.0.0", "0167", {"node-ip-only": REFERENCE, "sub-type": LOCAL})))
    assert hits == []
    assert coverage["not_evaluated"] == [{"path": "firewall address", "attribute": "node-ip-only", "reason": REASON}]


def test_upgrade_keeps_local_visibility_conditions_unchanged():
    hits, coverage = upgrade(Library(document("8.0.0", "0167", {"node-ip-only": LOCAL, "sub-type": LOCAL})))
    assert hits == [] and coverage["not_evaluated"] == []


def test_upgrade_does_not_trust_an_unvalidated_visibility_shape():
    for shape in ({"any_of": [{"when": "type", "equals": "dynamic", "reference": {}}]}, {"any_of": "dynamic"},
                  ["dynamic"], {"any_of": [{"all_of": [{"when": "type"}]}]}, {"any_of": [{"when": "type", "equals": 1}]}):
        target = Library(document("8.0.0", "0167"))
        target._document["config"]["firewall address"]["attrs"]["node-ip-only"]["conditions"] = shape
        hits, coverage = upgrade(target)
        assert {"path": "firewall address", "attribute": "node-ip-only", "reason": REASON} in coverage["not_evaluated"]


def test_schema_check_reports_incomplete_coverage_for_reference_dependent_visibility(tmp_path, capsys):
    library = tmp_path / "library.json"
    library.write_text(json.dumps(document()))
    target = tmp_path / "target.json"
    target.write_text(json.dumps(document("8.0.0", "0167", {"node-ip-only": REFERENCE})))
    snapshot = tmp_path / "snapshot.conf"
    snapshot.write_text(TEXT)
    args = ["schema-check", "--library", str(library), "--hardware", "FortiGate-60F", "--os-version", "7.6.7",
            "--build", "3704", "--config", str(snapshot), "--tenant", "example", "--device", "example-device",
            "--full-snapshot", "--upgrade-library", str(target)]
    assert cli.main(args) == cli.EXIT_INCOMPLETE
    report = json.loads(capsys.readouterr().out)
    assert report["findings"] == []
    assert report["upgrade_coverage"]["not_evaluated"] == [
        {"path": "firewall address", "attribute": "node-ip-only", "reason": REASON}]
    malformed = document("8.0.0", "0167", {"node-ip-only": REFERENCE})
    malformed["config"]["firewall address"]["attrs"]["node-ip-only"]["conditions"]["any_of"][0]["all_of"][1]["reference"]["contexts"] = []
    target.write_text(json.dumps(malformed))
    assert cli.main(args) == cli.EXIT_ERROR
    output = capsys.readouterr()
    assert output.out == "" and "schema audit cannot be evaluated" in output.err and "Traceback" not in output.err
