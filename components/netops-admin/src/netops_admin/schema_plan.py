from __future__ import annotations

import copy
import hashlib
import ipaddress
import json

from netops_core import fortios, schema
from netops_admin.errors import Rejected
from netops_admin import schema_policy
from netops_auditor import schema_checks

FORMAT="netops-schema-plan/1"
MAX_OPERATIONS=32
MAX_COMMANDS=512

def _reject(message):
 raise Rejected([message])

def _digest(value):
 return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()).hexdigest()

def _operation(data,library):
 if not isinstance(data,dict) or set(data)!={"path","scope","owners","op","changes"}:
  _reject("schema operation fields are invalid")
 path=data["path"];owners=data["owners"];scope=data["scope"]
 try:node=library.node(path)
 except ValueError:_reject("schema operation path is not measured")
 if data["op"] not in ("create","update","delete"):_reject("schema operation is invalid")
 if not isinstance(owners,list) or len(owners)>16 or any(not isinstance(x,str) or not x or not x.isprintable() or len(x.encode())>128 or "%%" in x for x in owners):
  _reject("schema operation owner keys are invalid")
 if scope is not None and (not isinstance(scope,str) or not scope or not scope.isprintable() or len(scope.encode())>128 or "%%" in scope):
  _reject("schema operation VDOM is invalid")
 if library.scope(path) not in ("global" if scope is None else "vdom","global+vdom") or library.availability(path) is not True:
  _reject("schema operation scope or availability is not measured")
 tables=[p for p in library.chain(path) if library.node(p)["kind"]=="table"]
 if len(owners)!=len(tables):_reject("schema operation requires every table owner key")
 for level,key in zip(tables,owners):
  name=library.node(level).get("key")
  if not name:_reject("schema table key validation is not measured")
  try:library.validate(level,{name:key})
  except ValueError:_reject("schema table key cannot be validated")
 if node["kind"]=="section" and data["op"]!="update":_reject("schema sections allow update only")
 if not isinstance(data["changes"],dict) or len(data["changes"])>64:_reject("schema operation attribute changes are invalid")
 if data["op"]=="delete" and data["changes"]:_reject("schema delete accepts no attribute changes")
 if data["op"]=="update" and not data["changes"]:_reject("schema update must change an attribute")
 if node.get("key") in data["changes"]:_reject("table identity is selected through owner keys")
 return copy.deepcopy(data)

def _locate(tree,library,operation):
 domain=tree.section("global") if operation["scope"] is None else tree.section("vdom")
 if domain is None:_reject("schema snapshot lacks the required global or VDOM wrapper")
 if operation["scope"] is not None:
  domain=domain.entries.get(operation["scope"])
  if domain is None:_reject("schema snapshot lacks the selected VDOM")
 current=domain;keys=iter(operation["owners"]);previous=None
 chain=library.chain(operation["path"])
 for level in chain:
  name=level if previous is None else level[len(previous)+1:]
  container=current.section(name)
  if container is None:_reject("schema snapshot lacks a required configuration container")
  item=library.node(level)
  if item["kind"]=="table":
   key=next(keys)
   entry=container.entries.get(key)
   if level==chain[-1]:return container,key,entry
   if entry is None:_reject("schema snapshot lacks a required parent table entry")
   current=entry
  else:
   if level==chain[-1]:return container,None,container
   current=container
  previous=level
 _reject("schema operation context is incomplete")

def _state(node):
 return {name:tuple(attr.values) for name,attr in node.attrs.items() if not attr.unset} if node else {}

def _source_values(library,path,values):
 metadata=library.node(path)["attrs"];result={}
 for name,tokens in values.items():
  item=metadata.get(name)
  if not item or schema_checks.SECRET_ATTRIBUTE.search(name) or "ENC" in tokens or any("%%" in token for token in tokens):
   _reject("a snapshot attribute cannot be safely restored")
  if item.get("multi"):value=list(tokens)
  elif item.get("type") in schema.NETWORK_TYPES and len(tokens)==2:
   try:value=str(ipaddress.IPv4Interface(tokens[0]+"/"+tokens[1]))
   except ValueError:_reject("a snapshot network attribute cannot be safely restored")
  elif len(tokens)==1:value=tokens[0]
  else:_reject("a snapshot attribute has an unmeasured value shape")
  result[name]=value
 return result

def _restore(library,path,values):
 try:
  native=_source_values(library,path,values)
  return library.validate(path,native) if native else {}
 except ValueError:_reject("a snapshot attribute cannot be safely restored")

def _assignments(library,path,values,state,scope=None,references=None):
 if references is not None and not schema_policy.bound(references,library):_reject("the reference snapshot is not bound to this exact library")
 metadata=library.node(path)["attrs"];pending=dict(values);ordered={};current=dict(state)
 def visible(name):
  return schema_policy.condition_state(metadata.get(name,{}),metadata,current,scope,references,path)
 while pending:
  for name,tokens in sorted(pending.items()):
   if visible(name) is True:
    ordered[name]=tokens;pending.pop(name)
    if tokens is None:current.pop(name,None)
    else:current[name]=tuple(fortios.tokenize(" ".join(tokens)))
    break
  else:
   if any(visible(name) is None for name in sorted(pending)):_reject(schema_policy.UNKNOWN_VISIBILITY)
   _reject("schema attributes cannot be ordered under their measured visibility conditions")
 for name in current:
  verdict=visible(name)
  if verdict is None:_reject(schema_policy.UNKNOWN_VISIBILITY)
  if verdict is False:_reject("schema change would hide an existing attribute and its restoration is not calibrated")
 return ordered,current

def _linked(library):
 result={}
 for path in library.paths:
  for name,attribute in library.node(path)["attrs"].items():
   for spec in schema_policy.reference_specs(attribute):
    link=result.setdefault(spec["table"],{"targets":set(),"paths":{}})
    link["targets"].add(spec["target_attribute"])
    link["paths"].setdefault(path,{}).setdefault(name,set()).add(spec["attribute"])
 return result

def _dependents(library,tree,references,link,key):
 result={};metadata={}
 for instance in schema.config_instances(library,tree):
  attributes=link["paths"].get(instance.path)
  if not attributes:continue
  if instance.path not in metadata:metadata[instance.path]=library.node(instance.path)["attrs"]
  attrs=metadata[instance.path];state=_state(instance.node)
  for name,sources in sorted(attributes.items()):
   if any(value.casefold()==key.casefold() for source in sorted(sources) for value in state.get(source,())):
    result[json.dumps([instance.scope,instance.path,instance.owners,name])]=schema_policy.condition_state(attrs[name],attrs,state,instance.scope,references,instance.path)
 return result

def _render(library,operation,mode,values):
 scope=operation["scope"]
 lines=["config global"] if scope is None else ["config vdom","edit "+schema.quoted(scope)]
 close=["end"] if scope is None else ["next","end"]
 keys=iter(operation["owners"]);previous=None;tail=[]
 chain=library.chain(operation["path"])
 for level in chain:
  item=library.node(level);name=level if previous is None else level[len(previous)+1:]
  lines.append("config "+name);tail=["end"]+tail
  if item["kind"]=="table":
   key=next(keys)
   if level==chain[-1] and mode=="delete":
    lines.append("delete "+schema.quoted(key))
   else:
    lines.append("edit "+schema.quoted(key));tail=["next"]+tail
  previous=level
 if mode!="delete":
  for name,tokens in values.items():
   lines.append("unset "+name if tokens is None else "set "+name+" "+" ".join(tokens))
 return lines+tail+close

def _tree_state(node):
 return {"attributes":{name:[list(attr.values),attr.unset] for name,attr in sorted(node.attrs.items())},
         "sections":{name:_tree_state(child) for name,child in sorted(node.sub.items())},
         "entries":[[name,_tree_state(child)] for name,child in node.entries.items()]}

def build(library,policy,text,operations,protected=None):
 if policy.library.sha256!=library.sha256:_reject("schema policy is bound to another library")
 if not isinstance(text,str) or len(text.encode())>16*1024*1024:_reject("schema snapshot exceeds its limit")
 if not isinstance(operations,list) or not 1<=len(operations)<=MAX_OPERATIONS:_reject("schema transaction operation count is invalid")
 try:tree=fortios.parse(text);references=schema_policy.References(library,text)
 except (fortios.ParseError,fortios.TruncatedError,ValueError):_reject("schema snapshot is incomplete or malformed")
 snapshot_sha256=hashlib.sha256(text.encode()).hexdigest();links=_linked(library)
 before_findings,_=schema_checks.references(library,tree,True)
 known={_digest(x) for x in before_findings};working=references.tree
 steps=[];commands=[];inverse=[]
 for data in operations:
  operation=_operation(data,library);path=operation["path"];mode=operation["op"]
  tables=[p for p in library.chain(path) if library.node(p)["kind"]=="table"]
  for level,key in zip(tables,operation["owners"]):
   if key.casefold() in {x.casefold() for x in (protected or {}).get(level,())}:
    _reject("schema transaction touches a protected object or parent")
  container,key,node=_locate(working,library,operation)
  if mode=="create" and any(x.casefold()==key.casefold() for x in container.entries):_reject("schema create requires an unused key")
  if mode!="create" and node is None:_reject("schema operation requires an existing object")
  original_present=node is not None
  before=_state(node)
  if mode=="delete" and (node.sub or node.entries):_reject("schema deletion of a populated nested object requires separate child operations")
  changes=operation["changes"]
  restored=_restore(library,path,before if mode=="delete" else {name:before[name] for name in changes if name in before})
  native=changes if mode!="delete" else _source_values(library,path,before)
  try:canonical=library.validate(path,changes) if changes else {}
  except ValueError:_reject("schema change values cannot be validated")
  canonical,planned_state=_assignments(library,path,canonical,before,operation["scope"],references)
  verdict=policy.require(path,operation["scope"],mode,native,planned_state if mode!="delete" else before,references,snapshot_sha256)
  guarded={x.casefold() for names in (protected or {}).values() for x in names}
  referenced=set(value.casefold() for tokens in before.values() for value in tokens)
  referenced.update(value.casefold() for tokens in canonical.values() if tokens for value in fortios.tokenize(" ".join(tokens)))
  if guarded & referenced:_reject("schema transaction changes an object linked to a protected name")
  if mode=="delete":
   for instance in schema.config_instances(library,working,include_unknown=True):
    if instance.node is node:continue
    if any(key.casefold() in {v.casefold() for v in a.values} for a in instance.node.attrs.values() if not a.unset):
     _reject("schema deletion has a configured incoming reference or an unclassified matching value")
  link=links.get(path)
  if link is not None and (key is None or mode=="update" and not link["targets"]&set(changes)):link=None
  exposed=_dependents(library,working,references,link,key) if link is not None else None
  if mode=="create":
   node=fortios.Node(container.path+(key,),0);container.entries[key]=node
  if mode=="delete":
   if key!=next(reversed(container.entries)):_reject("schema delete requires a tail entry until order restoration is calibrated")
   container.entries.pop(key)
  else:
   for name,tokens in canonical.items():
    if tokens is None:node.attrs.pop(name,None)
    else:node.attrs[name]=fortios.Attr(tuple(fortios.tokenize(" ".join(tokens))),0)
  if link is not None:
   now=_dependents(library,working,references,link,key)
   if None in exposed.values() or None in now.values():_reject(schema_policy.UNKNOWN_VISIBILITY)
   if now!=exposed:_reject("schema change would change the visibility of an attribute of a referencing object")
  after=None if mode=="delete" else _state(node)
  if mode=="update" and after==before:_reject("schema update changes nothing")
  findings,coverage=schema_checks.references(library,working,True)
  if any(_digest(x) not in known for x in findings):_reject("schema transaction introduces an unresolved reference")
  for name in changes:
   field=coverage["fields"].get(path+"::"+name)
   if field and field["status"]=="not-evaluated":_reject("schema transaction reference coverage is incomplete")
  forward=_render(library,operation,mode,canonical)
  reverse_mode="delete" if mode=="create" else "create" if mode=="delete" else "update"
  reverse_values={} if mode=="create" else restored if mode=="delete" else {name:restored.get(name) for name in changes}
  reverse_values,_=_assignments(library,path,reverse_values,{} if mode=="delete" else after or {},operation["scope"],references)
  reverse=_render(library,operation,reverse_mode,reverse_values)
  commands+=forward;inverse=reverse+inverse
  steps.append({"operation":operation,"risk":verdict["risk"],"evidence_sha256":verdict["evidence_sha256"],"generated_on_create":verdict["generated_on_create"],
                "before_sha256":_digest(before if original_present else None),"after_sha256":_digest(after),"before_state":before if original_present else None,"after_state":after,"commands":forward,"inverse":reverse})
 if len(commands)>MAX_COMMANDS or len(inverse)>MAX_COMMANDS:_reject("schema transaction command count exceeds its limit")
 result={"format":FORMAT,"identity":library.identity,"schema_sha256":library.sha256,"calibration_sha256":policy.sha256,
         "snapshot_sha256":snapshot_sha256,"before_tree_sha256":_digest(_tree_state(tree)),"predicted_tree_sha256":_digest(_tree_state(working)),
         "operations":steps,"commands":commands,"inverse":inverse,
         "execution_ready":False,"assurance":"schema plan only; live execution requires the existing journal, enrollment, audit and on-device safeguard pipeline"}
 result["plan_sha256"]=_digest(result)
 return result

def verify(library,plan,text,expect="after"):
 if expect not in ("before","after"):_reject("schema verification expectation is invalid")
 if not isinstance(plan,dict) or plan.get("format")!=FORMAT or plan.get("schema_sha256")!=library.sha256:
  _reject("schema verification requires a plan bound to the exact measured library")
 unsigned={k:v for k,v in plan.items() if k!="plan_sha256"}
 if plan.get("plan_sha256")!=_digest(unsigned):_reject("schema plan digest is invalid")
 if not isinstance(text,str) or len(text.encode())>16*1024*1024:_reject("schema snapshot exceeds its limit")
 try:tree=fortios.parse(text)
 except fortios.ParseError:_reject("schema snapshot is incomplete or malformed")
 wanted=plan.get("before_tree_sha256" if expect=="before" else "predicted_tree_sha256")
 observed=_digest(_tree_state(tree))
 return {"result":"match" if observed==wanted else "mismatch","expect":expect,
         "expected_tree_sha256":wanted,"observed_tree_sha256":observed}
