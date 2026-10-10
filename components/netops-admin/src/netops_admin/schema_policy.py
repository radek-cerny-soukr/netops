from __future__ import annotations

import copy
import hashlib
import json
import re

from netops_core import fortios
from netops_core.inputs import read_regular
from netops_admin.errors import Rejected
from netops_auditor.schema_checks import SECRET_ATTRIBUTE

FORMAT="netops-schema-calibration/1"
SHA256=re.compile(r"^[a-f0-9]{64}$")
A_PATHS=frozenset(("firewall address","firewall address6","firewall addrgrp","firewall addrgrp6",
 "firewall service custom","firewall service group","firewall schedule recurring","firewall schedule onetime"))
C_PATHS=("system admin","system accprofile","system api-user","system global","system ha","system vdom")
OPS=("create","update","delete")
CONDITION_FIELDS=frozenset(("any_of","measured_on","measured_contexts","evidence_sha256"))
LOCAL_FIELDS=frozenset(("when","equals","baseline","hidden_by"))
REFERENCE_FIELDS=frozenset(("attribute","table","target_attribute","equals","contexts","evidence_sha256"))
UNKNOWN_VISIBILITY="a measured attribute visibility condition cannot be evaluated from the pinned snapshot"

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

def _unique_snapshot_attributes(text):
 frames=[];seen=set();entries=set()
 for _,raw in fortios.logical_lines(text):
  line=raw.strip()
  if not line or line.startswith("#"):continue
  words=fortios.tokenize(line);command=words[0]
  if command=="config":frames.append(("config"," ".join(words[1:])))
  elif command=="edit":
   if len(words)!=2 or not words[1]:raise ValueError("reference snapshot contains an invalid entry")
   key=(tuple(frames),words[1])
   if key in entries:raise ValueError("reference snapshot contains repeated entries")
   entries.add(key);frames.append(("edit",words[1]))
  elif command=="next":
   if frames and frames[-1][0]=="edit":frames.pop()
  elif command=="end":
   if frames and frames[-1][0]=="edit":frames.pop()
   if frames:frames.pop()
  elif command in ("set","unset"):
   key=(tuple(frames),words[1])
   if key in seen:raise ValueError("reference snapshot contains repeated attributes")
   seen.add(key)

class References:
 def __init__(self,library,text):
  if not isinstance(text,str) or len(text.encode("utf-8"))>16*1024*1024:raise ValueError("reference snapshot exceeds its limit")
  try:
   self.tree=fortios.parse(text)
   _unique_snapshot_attributes(text)
  except fortios.ParseError:raise ValueError("reference snapshot is incomplete or malformed") from None
  self.library=library;self.identity=tuple(library.identity);self.schema_sha256=library.sha256
  self.snapshot_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest()

 def value(self,table,context,key,attribute):
  if context=="global":space=self.tree.section("global")
  else:
   wrapper=self.tree.section("vdom")
   space=wrapper.entries.get(context[5:]) if wrapper is not None and context.startswith("vdom:") else None
  container=space.section(table) if space is not None else None
  if container is None or [name for name in container.entries if name.casefold()==key.casefold()]!=[key]:return None
  item=container.entries[key].attrs.get(attribute)
  try:measured=self.library.node(table)["attrs"][attribute];options=measured["options"]
  except (ValueError,KeyError,TypeError):return None
  if item is None or item.unset:
   if measured.get("default_model_dependent") or measured.get("conditions") is not None or measured.get("default") is None:return None
   values=(str(measured["default"]),)
  else:values=item.values
  if len(values)!=1 or not isinstance(options,list) or values[0] not in options:return None
  return values[0]

def bound(references,library,snapshot_sha256=None):
 return (isinstance(references,References) and references.schema_sha256==library.sha256 and
         references.identity==tuple(library.identity) and (snapshot_sha256 is None or references.snapshot_sha256==snapshot_sha256))

def _text(value):
 return isinstance(value,str) and value.isprintable() and len(value.encode("utf-8"))<=4096

def _context(value):
 return isinstance(value,str) and value.isprintable() and (value=="global" or value.startswith("vdom:") and 1<=len(value[5:].encode("utf-8"))<=128)

def _spec(spec):
 if not isinstance(spec,dict) or set(spec)!=REFERENCE_FIELDS or not all(_text(spec[x]) for x in ("attribute","table","target_attribute","equals")):return False
 contexts=spec["contexts"]
 if not isinstance(spec["evidence_sha256"],str) or not SHA256.fullmatch(spec["evidence_sha256"]) or not isinstance(contexts,list) or not 1<=len(contexts)<=64:return False
 if any(not isinstance(x,dict) or set(x)!={"source","target"} or not _context(x["source"]) or not _context(x["target"]) for x in contexts):return False
 return len({x["source"] for x in contexts})==len(contexts)

def _shape(entries,limit,depth,budget):
 if depth>8 or not isinstance(entries,list) or not 1<=len(entries)<=limit:return False
 for clause in entries:
  budget[0]+=1
  if budget[0]>256 or not isinstance(clause,dict):return False
  if set(clause)=={"all_of"}:
   if not _shape(clause["all_of"],16,depth+1,budget):return False
  elif set(clause)=={"reference"}:
   if not _spec(clause["reference"]):return False
  elif not {"when","equals"}<=set(clause)<=LOCAL_FIELDS or not all(_text(x) for x in clause.values()):return False
 return len({json.dumps(x,sort_keys=True) for x in entries})==len(entries)

def _valid(conditions):
 if not isinstance(conditions,dict) or "any_of" not in conditions or not set(conditions)<=CONDITION_FIELDS:return False
 if "measured_on" in conditions and not _text(conditions["measured_on"]):return False
 if "evidence_sha256" in conditions and not (isinstance(conditions["evidence_sha256"],str) and SHA256.fullmatch(conditions["evidence_sha256"])):return False
 contexts=conditions.get("measured_contexts")
 if "measured_contexts" in conditions and (not isinstance(contexts,list) or not 1<=len(contexts)<=256 or not all(_context(x) for x in contexts) or len(set(contexts))!=len(contexts)):return False
 return _shape(conditions["any_of"],64,0,[0])

def reference_specs(attribute):
 conditions=attribute.get("conditions") if isinstance(attribute,dict) else None
 if conditions is None or not _valid(conditions):return []
 found=[];pending=list(conditions["any_of"])
 while pending:
  clause=pending.pop(0)
  if "all_of" in clause:pending.extend(clause["all_of"])
  elif "reference" in clause:found.append(clause["reference"])
 return found

def _reference(spec,metadata,state,context,references,path):
 if not isinstance(references,References) or not isinstance(path,str) or spec["table"]==path:return None
 targets=[x["target"] for x in spec["contexts"] if x["source"]==context]
 source=metadata.get(spec["attribute"]) if isinstance(metadata,dict) else None
 ref=source.get("ref") if isinstance(source,dict) else None
 if len(targets)!=1 or not isinstance(ref,dict) or not isinstance(ref.get("tables"),list) or spec["table"] not in ref["tables"] or source.get("multi"):return None
 value=state.get(spec["attribute"])
 if value is None:
  if source.get("default_model_dependent") or source.get("default") not in (None,""):return None
  return False
 if value==("",):return False
 if not isinstance(value,tuple) or len(value)!=1 or not isinstance(value[0],str) or not value[0]:return None
 found=references.value(spec["table"],targets[0],value[0],spec["target_attribute"])
 return None if found is None else found==spec["equals"]

def _local(clause,metadata,state):
 attr=metadata.get(clause["when"]) if isinstance(metadata,dict) else None
 if not isinstance(attr,dict):return None
 value=state.get(clause["when"])
 if value is None:
  if attr.get("default_model_dependent"):return None
  default=attr.get("default")
  value=(str(default),) if default is not None else None
 return value==(clause["equals"],)

def _term(clause,metadata,state,context,references,path):
 if "all_of" in clause:
  results=[_term(x,metadata,state,context,references,path) for x in clause["all_of"]]
  return False if False in results else None if None in results else True
 if "reference" in clause:return _reference(clause["reference"],metadata,state,context,references,path)
 return _local(clause,metadata,state)

def condition_state(attribute,metadata,state,scope=None,references=None,path=None):
 conditions=attribute.get("conditions")
 if conditions is None:return True
 if not _valid(conditions) or not isinstance(state,dict) or scope is not None and not isinstance(scope,str):return None
 context="global" if scope is None else "vdom:"+scope
 if "measured_contexts" in conditions and context not in conditions["measured_contexts"]:return None
 results=[_term(x,metadata,state,context,references,path) for x in conditions["any_of"]]
 return True if True in results else None if None in results else False

def condition_allowed(attribute,metadata,state,scope=None,references=None,path=None):
 return condition_state(attribute,metadata,state,scope,references,path) is True

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

 def require(self,path,scope,operation,changes,state,references=None,snapshot_sha256=None):
  if scope is not None and (not isinstance(scope,str) or not scope or not scope.isprintable() or len(scope.encode("utf-8"))>128):
   raise Rejected(["schema VDOM scope is invalid"])
  if not isinstance(state,dict):raise Rejected(["schema object state is invalid"])
  if references is not None and (snapshot_sha256 is None or not bound(references,self.library,snapshot_sha256)):
   raise Rejected(["the reference snapshot is not bound to this exact library and snapshot"])
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
  verdicts=[condition_state(metadata[name],metadata,state,scope,references,path) for name in changes]
  if False in verdicts:raise Rejected(["a measured attribute visibility condition is not satisfied"])
  if None in verdicts:raise Rejected([UNKNOWN_VISIBILITY])
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
