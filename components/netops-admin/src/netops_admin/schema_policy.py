from __future__ import annotations

import copy
import hashlib
import json
import re

from netops_core.inputs import read_regular
from netops_admin.errors import Rejected
from netops_auditor.schema_checks import SECRET_ATTRIBUTE

FORMAT="netops-schema-calibration/1"
SHA256=re.compile(r"^[a-f0-9]{64}$")
A_PATHS=frozenset(("firewall address","firewall address6","firewall addrgrp","firewall addrgrp6",
 "firewall service custom","firewall service group","firewall schedule recurring","firewall schedule onetime"))
C_PATHS=("system admin","system accprofile","system api-user","system global","system ha","system vdom")
OPS=("create","update","delete")

def risk(path,attributes=()):
 if any(path==prefix or path.startswith(prefix+" ") for prefix in C_PATHS):
  return "C"
 if path=="system interface" and "allowaccess" in attributes:
  return "C"
 if path in A_PATHS:return "A"
 if path.startswith(("router ","vpn ","firewall policy","firewall policy6","system sdwan","system interface")):
  return "B"
 return "C"

def _unique(pairs):
 result={}
 for key,value in pairs:
  if key in result:raise ValueError("duplicate calibration field")
  result[key]=value
 return result

def _condition(clause,metadata,state,depth=0):
 if depth>8 or not isinstance(clause,dict):return False
 if "all_of" in clause:
  entries=clause["all_of"]
  return isinstance(entries,list) and 1<=len(entries)<=16 and all(_condition(x,metadata,state,depth+1) for x in entries)
 name=clause.get("when");expected=clause.get("equals")
 if not isinstance(name,str) or name not in metadata or not isinstance(expected,str):return False
 value=state.get(name)
 if value is None:
  attr=metadata[name]
  if attr.get("default_model_dependent"):return False
  default=attr.get("default")
  value=(str(default),) if default is not None else None
 return value==(expected,)

def condition_allowed(attribute,metadata,state,scope=None):
 conditions=attribute.get("conditions")
 if conditions is None:return True
 if not isinstance(conditions,dict):return False
 contexts=conditions.get("measured_contexts")
 if "measured_contexts" in conditions:
  context="global" if scope is None else "vdom:"+scope
  if not isinstance(contexts,list) or not contexts or any(not isinstance(value,str) for value in contexts) or context not in contexts:return False
 clauses=conditions.get("any_of")
 return isinstance(clauses,list) and 1<=len(clauses)<=64 and any(_condition(x,metadata,state) for x in clauses)

class Policy:
 def __init__(self,library,document,digest):
  try:
   if not isinstance(digest,str) or not SHA256.fullmatch(digest):raise ValueError()
   if not isinstance(document,dict) or set(document)!={"format","schema_sha256","identity","objects"}:
    raise ValueError()
   if document["format"]!=FORMAT or document["schema_sha256"]!=library.sha256 or document["identity"]!=list(library.identity):
    raise ValueError()
   objects=document["objects"]
   if not isinstance(objects,dict) or len(objects)>5000:raise ValueError()
   for path,scopes in objects.items():
    node=library.node(path)
    if not isinstance(scopes,dict) or not scopes or set(scopes)-{"global","vdom"}:raise ValueError()
    for scope,grant in scopes.items():
     if library.scope(path) not in (scope,"global+vdom") or library.availability(path) is not True:raise ValueError()
     if not isinstance(grant,dict) or set(grant)-{"generated_on_create","vdom_names"}!={"operations","config_bytes_restored","evidence_sha256"}:raise ValueError()
     if grant["config_bytes_restored"] is not True or not isinstance(grant["evidence_sha256"],str) or not SHA256.fullmatch(grant["evidence_sha256"]):raise ValueError()
     domains=grant.get("vdom_names")
     if domains is not None and (scope!="vdom" or not isinstance(domains,list) or not domains or len(domains)>64 or any(not isinstance(x,str) or not x or not x.isprintable() or len(x.encode())>128 for x in domains) or len(set(domains))!=len(domains)):raise ValueError()
     generated=grant.get("generated_on_create",[])
     if not isinstance(generated,list) or generated not in ([],["uuid"]) or any(x not in node["attrs"] for x in generated):raise ValueError()
     if generated and "create" not in grant["operations"]:raise ValueError()
     operations=grant["operations"]
     if not isinstance(operations,dict) or not operations or set(operations)-set(OPS):raise ValueError()
     if node["kind"]=="section" and set(operations)!={"update"}:raise ValueError()
     for names in operations.values():
      if not isinstance(names,list) or len(names)>64 or len(names)!=len(set(names)) or not all(isinstance(x,str) and x in node["attrs"] for x in names):raise ValueError()
  except (ValueError,TypeError,KeyError):
   raise Rejected(["schema calibration is invalid or is not bound to this exact measured library"]) from None
  self.library=library;self.objects=copy.deepcopy(objects);self.sha256=digest

 def require(self,path,scope,operation,changes,state):
  if scope is not None and (not isinstance(scope,str) or not scope or not scope.isprintable() or len(scope.encode("utf-8"))>128):
   raise Rejected(["schema VDOM scope is invalid"])
  if not isinstance(state,dict):raise Rejected(["schema object state is invalid"])
  domain="global" if scope is None else "vdom"
  try:grant=self.objects[path][domain];allowed=grant["operations"][operation]
  except (KeyError,TypeError):raise Rejected(["the schema object and operation have no byte-exact rollback calibration"]) from None
  if grant.get("vdom_names") is not None and scope not in grant["vdom_names"]:
   raise Rejected(["the requested VDOM has no rollback calibration"])
  if operation not in OPS or not isinstance(changes,dict) or set(changes)-set(allowed):
   raise Rejected(["the requested attributes are outside the rollback calibration"])
  if any(SECRET_ATTRIBUTE.search(name) for name in changes):
   raise Rejected(["secret-bearing attributes are not accepted by this schema write policy"])
  try:canonical=self.library.validate(path,changes) if changes else {}
  except ValueError:raise Rejected(["the schema change values cannot be validated"]) from None
  if any("%%" in token for tokens in canonical.values() if tokens for token in tokens):
   raise Rejected(["automation placeholders cannot be restored as literal values by the timed safeguard"])
  metadata=self.library.node(path)["attrs"]
  if any(not condition_allowed(metadata[name],metadata,state,scope) for name in changes):
   raise Rejected(["a measured attribute visibility condition is not satisfied"])
  return {"risk":risk(path,changes),"calibration_sha256":self.sha256,"evidence_sha256":grant["evidence_sha256"],
          "safeguard_required":True,"independent_readback_required":True,"canonical_changes":canonical,"generated_on_create":grant.get("generated_on_create",[]) if operation=="create" else []}

def load(library,path,expected_sha256):
 try:
  if not isinstance(expected_sha256,str) or not SHA256.fullmatch(expected_sha256):raise ValueError()
  raw=read_regular(path,16*1024*1024)
  digest=hashlib.sha256(raw).hexdigest()
  if digest!=expected_sha256:raise ValueError()
  document=json.loads(raw.decode("utf-8"),object_pairs_hook=_unique,
                      parse_constant=lambda value:(_ for _ in ()).throw(ValueError("invalid number")))
 except (OSError,ValueError,TypeError,RecursionError):
  raise Rejected(["the operator schema calibration cannot be read or its digest does not match"]) from None
 return Policy(library,document,digest)
