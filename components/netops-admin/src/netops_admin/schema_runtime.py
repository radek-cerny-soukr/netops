from __future__ import annotations

import copy
import hashlib
import json
import re

from netops_core import fortios as core_fortios, schema
from netops_admin import __version__, exec_fortios, fortios, schema_plan, schema_policy, prediction
from netops_admin.errors import Rejected
from netops_auditor import schema_checks, scoped_fortios, checks_fortios
from netops_auditor.engine import EVALUATED
from netops_auditor.state import evaluation_complete

FORMAT = "netops-admin-schema-live/1"
MAX_BYTES = 16 * 1024 * 1024
GUARD_TABLES = {"action":"system automation-action","trigger":"system automation-trigger","stitch":"system automation-stitch"}

def is_plan(plan):
    return isinstance(plan,dict) and plan.get("format")==FORMAT

def library(plan):
    try:
        return schema.load(plan["schema_binding"]["library"],plan["schema_binding"]["schema_sha256"])
    except (ValueError,OSError,KeyError,TypeError):
        raise Rejected(["the exact schema library for this transaction is unavailable"]) from None

def policy(device):
    binding=device.schema
    if device.platform!="fortios" or not isinstance(binding,dict):
        raise Rejected(["schema transactions require a configured operator binding"])
    try:
        lib=schema.load(binding["library"],binding["schema_sha256"])
        cal=schema_policy.load(lib,binding["calibration"],binding["calibration_sha256"])
    except (ValueError,OSError,KeyError,TypeError):
        raise Rejected(["the pinned schema transaction policy is unavailable"]) from None
    firmware="%s build%s" % (lib.identity[1],lib.identity[2])
    if device.firmware!=firmware:
        raise Rejected(["the configured firmware does not match the exact schema build"])
    return lib,cal

def _parse(text):
    if not isinstance(text,str) or len(text.encode())>MAX_BYTES:
        raise Rejected(["schema transaction snapshot exceeds its limit"])
    try:
        return core_fortios.parse(text)
    except core_fortios.ParseError:
        raise Rejected(["schema transaction snapshot is incomplete or malformed"]) from None

def _text(tree):
    return "\n".join(prediction.fortios_text(tree))+"\n"

def _clean(tree,plan):
    tree=copy.deepcopy(tree)
    global_node=tree.section("global")
    if global_node is None:
        raise Rejected(["schema transaction snapshot lacks a global wrapper"])
    change=plan.get("safeguard_id")
    if change:
        for kind,name in fortios.safeguard_names(change).items():
            path=GUARD_TABLES[kind]
            table=global_node.section(path)
            if table is not None:
                table.entries.pop(name,None)
                if not table.entries and not table.attrs and not table.sub and path not in plan["guard_tables_before"]:
                    global_node.sub.pop(path,None)
    return tree

def _valid_inner(inner):
    if not isinstance(inner,dict) or inner.get("format")!=schema_plan.FORMAT:
        return False
    unsigned={k:v for k,v in inner.items() if k!="plan_sha256"}
    return inner.get("plan_sha256")==schema_plan._digest(unsigned)

def _target_key(operation):
    return json.dumps([operation["path"],operation["scope"],operation["owners"]],separators=(",",":"))

def targets(inner):
    result={}
    for step in inner["operations"]:
        operation=step["operation"]
        key=_target_key(operation)
        if key not in result:
            result[key]={"operation":operation,"before_state":step["before_state"],"before_sha256":step["before_sha256"]}
        result[key].update(after_state=step["after_state"],after_sha256=step["after_sha256"])
    return list(result.values())

def predictions(inner):
    return {side:{"objects":[step[side+"_sha256"] for step in targets(inner)]} for side in ("before","after")}

def read_plan(plan):
    fields={"format","admin_version","platform","firmware","table","op","key","device","request_id",
            "request_sha256","reason_characters","user_request_characters","snapshot_sha256",
            "prechecks","commands","inverse","predicted","rollback_evidence","plan_sha256","safeguard_id",
            "schema_binding","schema_plan","guard_tables_before","budget_changes","generated_bindings"}
    if not isinstance(plan,dict) or set(plan)!=fields or plan.get("format")!=FORMAT:
        raise Rejected(["schema live transaction plan fields are invalid"])
    if plan["platform"]!="fortios" or plan["table"]!="schema" or plan["op"]!="update":
        raise Rejected(["schema live transaction plan identity is invalid"])
    if any(not isinstance(plan[x],str) for x in ("admin_version","firmware","key","device","request_id","request_sha256","snapshot_sha256","rollback_evidence","plan_sha256")):
        raise Rejected(["schema live transaction plan text fields are invalid"])
    if any(type(plan[x]) is not int or plan[x]<0 for x in ("reason_characters","user_request_characters")):
        raise Rejected(["schema live transaction plan counts are invalid"])
    if plan["safeguard_id"] is not None and (not isinstance(plan["safeguard_id"],str) or not re.fullmatch("[0-9a-f]{32}",plan["safeguard_id"])):
        raise Rejected(["schema live safeguard identifier is invalid"])
    if not isinstance(plan["generated_bindings"],dict) or len(plan["generated_bindings"])>32 or any(not isinstance(k,str) or not isinstance(v,dict) or set(v)!={"uuid"} or not isinstance(v["uuid"],str) or not re.fullmatch(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}",v["uuid"]) for k,v in plan["generated_bindings"].items()):
        raise Rejected(["schema generated attribute bindings are invalid"])
    inner=plan["schema_plan"]
    if not _valid_inner(inner) or not isinstance(inner.get("operations"),list) or not 1<=len(inner["operations"])<=32:
        raise Rejected(["schema live transaction inner plan is invalid"])
    if type(plan["budget_changes"]) is not int or plan["budget_changes"]!=len(inner["operations"]):
        raise Rejected(["schema live transaction budget count is invalid"])
    if not isinstance(plan["guard_tables_before"],list) or set(plan["guard_tables_before"])-set(GUARD_TABLES.values()):
        raise Rejected(["schema live transaction safeguard table list is invalid"])
    for field in ("commands","inverse"):
        if plan[field]!=inner.get(field) or not isinstance(plan[field],list) or not 1<=len(plan[field])<=512 or any(not isinstance(x,str) or "\r" in x or "\n" in x or "%%" in x for x in plan[field]):
            raise Rejected(["schema live transaction commands are invalid"])
    expected=predictions(inner)
    if plan["predicted"]!=expected:
        raise Rejected(["schema live transaction prediction is invalid"])
    unsigned={k:v for k,v in plan.items() if k not in ("plan_sha256","safeguard_id")}
    if plan["plan_sha256"]!=schema_plan._digest(unsigned):
        raise Rejected(["schema live transaction digest is invalid"])
    return plan

def build(device,request,text,enrolling=False):
    if not enrolling and any(key.startswith("netops-enroll-") for operation in request.operations for key in operation["owners"]):
        raise Rejected(["the enrollment object namespace is reserved"])
    lib,cal=policy(device)
    inner=schema_plan.build(lib,cal,text,request.operations,device.protected)
    global_node=_parse(text).section("global")
    result={"format":FORMAT,"admin_version":__version__,"platform":"fortios","firmware":device.firmware,
            "table":"schema","op":"update","key":"transaction","device":device.name,"request_id":request.request_id,
            "request_sha256":request.fingerprint(),"reason_characters":len(request.reason),
            "user_request_characters":len(request.user_request),"snapshot_sha256":inner["snapshot_sha256"],
            "prechecks":["exact schema identity, pinned calibration, typed references, protected owners and inverse verified"],
            "commands":inner["commands"],"inverse":inner["inverse"],
            "predicted":predictions(inner),
            "rollback_evidence":cal.sha256,"safeguard_id":None,"schema_binding":copy.deepcopy(device.schema),
            "schema_plan":inner,"guard_tables_before":[p for p in GUARD_TABLES.values() if global_node.section(p) is not None],
            "budget_changes":len(request.operations),"generated_bindings":{}}
    result["plan_sha256"]=schema_plan._digest({k:v for k,v in result.items() if k!="safeguard_id"})
    return result

def snapshot_after(text,plan):
    lib=library(plan);tree=_parse(text)
    for step in plan["schema_plan"]["operations"]:
        operation=step["operation"]
        container,key,node=schema_plan._locate(tree,lib,operation)
        if operation["op"]=="delete":
            container.entries.pop(key)
        else:
            if node is None:
                node=core_fortios.Node(container.path+(key,),0);container.entries[key]=node
            node.attrs={name:core_fortios.Attr(tuple(values),0) for name,values in step["after_state"].items()}
    return _text(tree)

def _generated(tree,plan,expect):
    bindings={}
    lib=library(plan)
    for index,step in enumerate(plan["schema_plan"]["operations"]):
        if not step.get("generated_on_create"):continue
        _,_,node=schema_plan._locate(tree,lib,step["operation"])
        if node is None:continue
        values={}
        for name in step["generated_on_create"]:
            value=node.value(name)
            if name!="uuid" or not isinstance(value,str) or not re.fullmatch(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}",value):
                raise Rejected(["the calibrated generated attribute has an invalid value"])
            values[name]=value
            node.attrs.pop(name,None)
        key=str(index)
        if expect=="after" and plan["generated_bindings"] and plan["generated_bindings"].get(key)!=values:
            raise Rejected(["the created object identity changed after its first readback"])
        bindings[key]=values
    return bindings

def observe_tree(text,plan,expect="after"):
    tree=_clean(_parse(text),plan)
    _generated(tree,plan,expect)
    return {"tree_sha256":schema_plan._digest(schema_plan._tree_state(tree))}

def bind_generated(plan,values):
    if plan["generated_bindings"] and plan["generated_bindings"]!=values:
        raise Rejected(["generated attribute bindings cannot change"])
    plan["generated_bindings"]=copy.deepcopy(values)
    plan["plan_sha256"]=schema_plan._digest({k:v for k,v in plan.items() if k not in ("plan_sha256","safeguard_id")})

def verify(plan,raw,expect):
    read_plan(plan)
    if expect not in ("before","after") or not isinstance(raw,bytes) or len(raw)>MAX_BYTES:
        raise Rejected(["schema transaction verification input is invalid"])
    try:text=raw.decode("utf-8")
    except UnicodeError:raise Rejected(["schema transaction snapshot is not UTF-8"]) from None
    tree=_clean(_parse(text),plan)
    generated=_generated(tree,plan,expect)
    actual={"tree_sha256":schema_plan._digest(schema_plan._tree_state(tree))}
    matches=actual["tree_sha256"]==plan["schema_plan"]["before_tree_sha256" if expect=="before" else "predicted_tree_sha256"]
    lib=library(plan);objects=True
    for step in targets(plan["schema_plan"]):
        _,_,node=schema_plan._locate(tree,lib,step["operation"])
        if schema_plan._digest(schema_plan._state(node))!=schema_plan._digest(step[expect+"_state"] or {}) or ((node is None)!=(step[expect+"_state"] is None)):
            objects=False
    return {"result":"match" if matches else "mismatch","expect":expect,"object_matches":objects,
            "rest_matches":matches,"generated_bindings":generated,
            "differences":[] if matches else ["configuration differs from the calibrated transaction prediction"]}

def audit_snapshot(plan,text,policy,required_table=None):
    lib=library(plan);tree=_clean(_parse(text),plan)
    found,states=scoped_fortios.run(lib,tree,"netops-admin",plan["device"],policy)
    required=set((policy or {}).get("required_rules",[]))
    from netops_admin.audit_gate import TABLE_RULES
    for step in plan["schema_plan"]["operations"]:
        required|=TABLE_RULES.get(step["operation"]["path"],set())
    statuses={}
    for key,(state,reason) in states.items():
        _,rule=json.loads(key)
        name=rule.removeprefix("fortios.management.") if rule.startswith("fortios.management.") else None
        statuses[key]={"status":state,"reason":reason,"required":name is None or name in required}
    if not evaluation_complete(found,statuses):
        from netops_admin.audit_gate import Incomplete
        codes={key:item["reason"] or item["status"] for key,item in statuses.items() if item["required"] and item["status"]!=EVALUATED}
        raise Incomplete(["schema transaction mandatory catalog coverage is incomplete"],codes)
    refs,coverage=schema_checks.references(lib,tree,True)
    for step in plan["schema_plan"]["operations"]:
        for name in step["operation"]["changes"]:
            field=coverage["fields"].get(step["operation"]["path"]+"::"+name)
            if field and field["status"] not in ("evaluated","absent"):
                raise Rejected(["schema transaction reference evaluation is incomplete"])
    result={}
    for finding in found:
        signature=hashlib.sha256(json.dumps(dict(finding.evidence),sort_keys=True).encode()).hexdigest()
        result[finding.fingerprint()]=(finding.rule_id,finding.severity,signature)
    for finding in refs:
        signature=schema_plan._digest(finding)
        result["reference:"+signature]=("schema.reference","high",signature)
    return result,{"catalog":statuses,"references":coverage}

def after_audit(plan,before,text,policy):
    after,coverage=audit_snapshot(plan,text,policy)
    blocking=sorted({value[0] for key,value in after.items() if value[1] in ("high","medium") and (key not in before or tuple(before[key])!=tuple(value))})
    return blocking,coverage

def undo_request(record,reason):
    from netops_admin.schema_request import Transaction
    plan=read_plan(record["plan"]);lib=library(plan);operations=[]
    for step in reversed(plan["schema_plan"]["operations"]):
        operation=copy.deepcopy(step["operation"])
        operation["op"]={"create":"delete","delete":"create","update":"update"}[operation["op"]]
        if operation["op"]=="delete":operation["changes"]={}
        else:
            before=step["before_state"] or {}
            selected=before if operation["op"]=="create" else {name:before[name] for name in operation["changes"] if name in before}
            operation["changes"]=schema_plan._source_values(lib,operation["path"],selected)
            if operation["op"]=="update":
                operation["changes"].update({name:None for name in step["operation"]["changes"] if name not in before})
        operations.append(operation)
    final_states={_target_key(step["operation"]):step["after_sha256"] for step in targets(plan["schema_plan"])}
    undo_targets=dict.fromkeys(_target_key(operation) for operation in operations)
    expected={"objects":[final_states[key] for key in undo_targets]}
    return Transaction(record["device"],operations,reason,"undo of operation "+record["change_id"],"undo-"+record["change_id"]),expected

def Access(base,device):
    from netops_admin.access import SchemaAccess
    return SchemaAccess(base,device)


def doctor(runtime,device,report):
    from netops_admin import enrollment, exec_schema_fortios
    reached,context=report.attempt("schema identity and write account",
        lambda:Access(runtime.access_factory(device),device))
    if not reached:
        report.skip("schema snapshot","administrator accounts","calibration","check account","audit policy","enrollment")
        return None,{}
    reached,text=report.attempt("schema snapshot",context.snapshot)
    if not reached:
        report.skip("administrator accounts","calibration","check account","audit policy","enrollment")
        return None,{}
    reached,fingerprint=report.attempt("administrator accounts",
        lambda:exec_schema_fortios.accounts_check(context,device,text))
    loaded,bound=report.attempt("calibration",lambda:policy(device))
    operations={}
    if loaded:
        lib,cal=bound
        operations={path:{domain:sorted(grant["operations"]) for domain,grant in scopes.items()}
                    for path,scopes in cal.objects.items()}
        steps=[]
        for path,scopes in sorted(cal.objects.items()):
            for domain,grant in scopes.items():
                actual_scopes=[None] if domain=="global" else grant.get("vdom_names",device.schema["vdoms"])
                for scope in actual_scopes:
                    for instance in schema.config_instances(lib,_parse(text),include_unknown=False):
                        if instance.path!=path or instance.scope!=scope:continue
                        tables=[x for x in lib.chain(path) if lib.node(x)["kind"]=="table"]
                        owners=dict(instance.owners)
                        if any(x not in owners for x in tables):continue
                        operation={"path":path,"scope":scope,"owners":[owners[x] for x in tables],"op":"update","changes":{}}
                        state=schema_plan._state(instance.node)
                        steps.append({"operation":operation,"before_state":state,"after_state":state,
                                      "before_sha256":schema_plan._digest(state),"after_sha256":schema_plan._digest(state),
                                      "generated_on_create":[]})
                        break
                    if steps:break
                if steps:break
            if steps:break
        if steps:
            plan={"schema_binding":device.schema,"schema_plan":{"operations":steps},"device":device.name,
                  "generated_bindings":{},"guard_tables_before":[],"safeguard_id":None}
            expected={"objects":[step["before_sha256"] for step in steps]}
            def check():
                if context.observe(plan)!=expected:
                    raise Rejected(["the independent account sees another object state"])
            report.attempt("check account",check)
            report.attempt("audit policy",lambda:audit_snapshot(plan,text,device.audit_policy))
        else:
            report.add("check account","missing","no calibrated existing object is available for a read-only probe")
            report.skip("audit policy")
    else:
        report.skip("check account","audit policy")
    report.attempt("leftover safeguards",lambda:_no_guards(context))
    if reached:
        report.attempt("enrollment",lambda:enrollment.require(runtime,device,fingerprint,device.firmware))
    else:
        report.skip("enrollment")
    return device.firmware,operations

def _no_guards(access):
    if exec_fortios.leftovers(access):
        raise Rejected(["an unfinished schema safeguard remains"])
