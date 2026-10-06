from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from netops_core.inputs import read_regular

MAX_REPORT_BYTES=4*1024*1024
SHA256=re.compile(r"^[a-f0-9]{64}$")

def unique(pairs):
 result={}
 for key,value in pairs:
  if key in result:raise ValueError("duplicate report field")
  result[key]=value
 return result

def document(path,limit):
 return json.loads(read_regular(path,limit).decode("utf-8"),object_pairs_hook=unique,
                   parse_constant=lambda value:(_ for _ in ()).throw(ValueError("invalid number")))

def read(manifest_path,tenant,device,view="findings",offset=0,limit=100):
 if not isinstance(device,str) or not device or len(device)>128:
  raise ValueError("schema report device is invalid")
 if view not in ("findings","reference","upgrade","catalog"):
  raise ValueError("schema report view is invalid")
 if type(offset) is not int or not 0<=offset<=100000 or type(limit) is not int or not 1<=limit<=100:
  raise ValueError("schema report pagination is invalid")
 try:
  manifest=document(manifest_path,262144)
  if not isinstance(manifest,dict) or set(manifest)!={"format","tenant","reports"} or type(manifest["format"]) is not int or manifest["format"]!=1 or manifest["tenant"]!=tenant:
   raise ValueError()
  reports=manifest["reports"]
  if not isinstance(reports,dict) or len(reports)>4096:raise ValueError()
  entry=reports[device]
  if not isinstance(entry,dict) or set(entry)!={"file","sha256"}:raise ValueError()
  name=entry["file"]
  if not isinstance(name,str) or not name or Path(name).is_absolute() or ".." in Path(name).parts:raise ValueError()
  if not isinstance(entry["sha256"],str) or not SHA256.fullmatch(entry["sha256"]):raise ValueError()
  raw=read_regular(Path(manifest_path).parent/name,MAX_REPORT_BYTES)
  if hashlib.sha256(raw).hexdigest()!=entry["sha256"]:raise ValueError()
  report=json.loads(raw.decode("utf-8"),object_pairs_hook=unique,
                   parse_constant=lambda value:(_ for _ in ()).throw(ValueError("invalid number")))
  required={"tenant","device","platform","snapshot_sha256","schema_sha256","target_schema_sha256","identity","identity_assurance","findings","reference_coverage","upgrade_coverage"}
  if not isinstance(report,dict) or set(report)-required not in (set(),{"catalog_coverage"}) or not required <= set(report) or report["tenant"]!=tenant or report["device"]!=device or report["platform"]!="fortios":raise ValueError()
  for field in ("snapshot_sha256","schema_sha256"):
   if not isinstance(report[field],str) or not SHA256.fullmatch(report[field]):raise ValueError()
  if report["target_schema_sha256"] is not None and (not isinstance(report["target_schema_sha256"],str) or not SHA256.fullmatch(report["target_schema_sha256"])):raise ValueError()
  if not isinstance(report["identity"],list) or len(report["identity"])!=3 or not all(isinstance(x,str) and x.isprintable() and len(x)<=96 for x in report["identity"]):raise ValueError()
  if report["identity_assurance"] not in ("operator-declared","live-status-verified"):raise ValueError()
  findings=report["findings"];reference=report["reference_coverage"];upgrade=report["upgrade_coverage"]
  if not isinstance(findings,list) or len(findings)>10000 or not all(isinstance(x,dict) for x in findings):raise ValueError()
  if not isinstance(reference,dict) or not isinstance(reference.get("fields"),dict) or len(reference["fields"])>100000:raise ValueError()
  for value in reference["fields"].values():
   if not isinstance(value,dict) or value.get("status") not in ("evaluated","not-evaluated","not-present") or type(value.get("checked_values")) is not int or value["checked_values"]<0:raise ValueError()
  if upgrade is not None and (not isinstance(upgrade,dict) or not isinstance(upgrade.get("not_evaluated"),list)):raise ValueError()
  catalog=report.get("catalog_coverage")
  if "catalog_coverage" in report:
   if not isinstance(catalog,dict) or not catalog or len(catalog)>1600:raise ValueError()
   for key,item in catalog.items():
    context=json.loads(key)
    if not isinstance(context,list) or len(context)!=2 or context[0] is not None and (not isinstance(context[0],str) or not context[0].isprintable() or not 1<=len(context[0].encode())<=128):raise ValueError()
    if not isinstance(context[1],str) or not re.fullmatch(r"fortios\.[a-z0-9.-]{1,128}",context[1]):raise ValueError()
    if not isinstance(item,dict) or set(item)!={"status","reason","required"} or item["status"] not in ("evaluated","not-evaluated","unsupported") or type(item["required"]) is not bool or not isinstance(item["reason"],str) or not item["reason"].isprintable() and item["reason"]!="" or len(item["reason"])>256:raise ValueError()

 except (OSError,ValueError,TypeError,KeyError,RecursionError):
  raise ValueError("the configured schema report cannot be verified for this tenant and device") from None
 items=findings if view=="findings" else [{"field":key,**value} for key,value in sorted(reference["fields"].items())] if view=="reference" else [{"context_rule":key,**value} for key,value in sorted(catalog.items())] if view=="catalog" and catalog is not None else upgrade["not_evaluated"] if view=="upgrade" and upgrade else []
 states={state:sum(x["status"]==state for x in reference["fields"].values()) for state in ("evaluated","not-evaluated","not-present")}
 page=items[offset:offset+limit]
 result={"tenant":tenant,"device":device,"view":view,"identity":report["identity"],
         "identity_assurance":report["identity_assurance"],"snapshot_sha256":report["snapshot_sha256"],
         "schema_sha256":report["schema_sha256"],"target_schema_sha256":report["target_schema_sha256"],
         "report_sha256":entry["sha256"],"findings_count":len(findings),"reference_coverage_states":states,
         "upgrade_not_evaluated_count":len(upgrade["not_evaluated"]) if upgrade else 0,
         "offset":offset,"total":len(items),"next_offset":offset+len(page) if offset+len(page)<len(items) else None,
         "items":page,"untrusted_configuration_data":True,"assurance":"finished pinned report; no device access or collection"}
 if view=="catalog" or catalog is not None:
  result["catalog_coverage_available"]=catalog is not None
  result["catalog_coverage_states"]={state:sum(x["status"]==state for x in (catalog or {}).values()) for state in ("evaluated","not-evaluated","unsupported")}
 return result
