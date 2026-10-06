import hashlib
import json
import pytest
from netops_auditor import schema_reports

def fixture(tmp_path):
 report={"tenant":"tenant-a","device":"device-a","platform":"fortios","snapshot_sha256":"a"*64,"schema_sha256":"b"*64,
 "target_schema_sha256":None,"identity":["FortiGate-VM64-KVM","7.6.7","3704"],"identity_assurance":"operator-declared",
 "findings":[{"rule":"fortios.schema.reference","evidence":{"value":"data"}}],
 "reference_coverage":{"fields":{"firewall addrgrp::member":{"status":"not-evaluated","checked_values":0}}},"upgrade_coverage":None}
 path=tmp_path/"report.json";path.write_text(json.dumps(report))
 manifest=tmp_path/"manifest.json";manifest.write_text(json.dumps({"format":1,"tenant":"tenant-a","reports":{"device-a":{"file":path.name,"sha256":hashlib.sha256(path.read_bytes()).hexdigest()}}}))
 return manifest,path,report

def test_report_preserves_assurance_coverage_and_bytes(tmp_path):
 manifest,path,_=fixture(tmp_path);before=path.read_bytes()
 result=schema_reports.read(manifest,"tenant-a","device-a","reference")
 assert result["items"]==[{"field":"firewall addrgrp::member","status":"not-evaluated","checked_values":0}]
 assert result["identity_assurance"]=="operator-declared"
 assert result["findings_count"]==1 and path.read_bytes()==before
 assert schema_reports.read(manifest,"tenant-a","device-a",offset=1)["items"]==[]

@pytest.mark.parametrize("mutation",["digest","tenant","device","traversal","duplicate","malformed-report"])
def test_report_binding_rejects_untrusted_changes(tmp_path,mutation):
 manifest,path,report=fixture(tmp_path)
 data=json.loads(manifest.read_text())
 if mutation=="digest":path.write_text("{}")
 elif mutation=="tenant":data["tenant"]="other"
 elif mutation=="device":data["reports"]={"other":data["reports"]["device-a"]}
 elif mutation=="traversal":data["reports"]["device-a"]["file"]="../report.json"
 elif mutation=="duplicate":manifest.write_text('{"format":1,"format":1}');data=None
 elif mutation=="malformed-report":
  report["reference_coverage"]["fields"]["firewall addrgrp::member"]["status"]="clean"
  path.write_text(json.dumps(report));data["reports"]["device-a"]["sha256"]=hashlib.sha256(path.read_bytes()).hexdigest()
 if data is not None:manifest.write_text(json.dumps(data))
 with pytest.raises(ValueError,match="cannot be verified"):schema_reports.read(manifest,"tenant-a","device-a")

@pytest.mark.parametrize("offset,limit",[(True,10),(0,True),(-1,10),(0,101)])
def test_report_pagination_is_bounded(tmp_path,offset,limit):
 manifest,_,_=fixture(tmp_path)
 with pytest.raises(ValueError):schema_reports.read(manifest,"tenant-a","device-a",offset=offset,limit=limit)

def save_report(manifest,path,report):
 path.write_text(json.dumps(report))
 data=json.loads(manifest.read_text())
 data["reports"]["device-a"]["sha256"]=hashlib.sha256(path.read_bytes()).hexdigest()
 manifest.write_text(json.dumps(data))

def test_pinned_catalog_view_keeps_unknown_required_rule_state(tmp_path):
 manifest,path,report=fixture(tmp_path)
 report["catalog_coverage"]={'["root","fortios.ref.dangling"]':{"status":"not-evaluated","reason":"interface ownership unknown","required":True}}
 save_report(manifest,path,report)
 result=schema_reports.read(manifest,"tenant-a","device-a","catalog")
 assert result["catalog_coverage_available"]
 assert result["catalog_coverage_states"]["not-evaluated"]==1
 assert result["items"][0]["required"] is True
 assert schema_reports.read(manifest,"tenant-a","device-a")["catalog_coverage_available"]

def test_old_report_does_not_claim_that_the_catalog_was_evaluated(tmp_path):
 manifest,_,_=fixture(tmp_path)
 result=schema_reports.read(manifest,"tenant-a","device-a","catalog")
 assert result["items"]==[] and result["catalog_coverage_available"] is False

@pytest.mark.parametrize("mutation",["state","required","key","oversize"])
def test_malformed_catalog_coverage_is_refused(tmp_path,mutation):
 manifest,path,report=fixture(tmp_path)
 value={"status":"evaluated","reason":"","required":True};key='["root","fortios.ref.dangling"]'
 if mutation=="state":value["status"]="clean"
 elif mutation=="required":value["required"]=1
 elif mutation=="key":key='[[], "fortios.ref.dangling"]'
 elif mutation=="oversize":value["reason"]="x"*257
 report["catalog_coverage"]={key:value};save_report(manifest,path,report)
 with pytest.raises(ValueError):schema_reports.read(manifest,"tenant-a","device-a","catalog")
