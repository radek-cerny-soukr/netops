from __future__ import annotations

import json
import os
from pathlib import Path
import re

from netops_core import fortios, schema
from netops_core.inputs import InputError, read_regular

from .inventory import unique_object
from .sanitize import redact

MAX_SNAPSHOT = 2_000_000
STATUS = re.compile(r"(?m)^Version:\s+([A-Za-z0-9_.+-]+)\s+v(\d+\.\d+\.\d+),\s*build(\d{4,6})(?:,|\s|$)")
CURRENT_VDOM = re.compile(r"(?m)^Current virtual domain:[ \t]*([^\r\n]+?)[ \t]*$")
SECRET_ATTRIBUTE = re.compile(r"(?:^|[-_])(?:password|passwd|passphrase|pwd|psk|psksecret|secret|token|private.key|community|api.key)(?:$|[-_])",re.I)


def binding(auth, registry_path=None):
    auth.require_ssh_query("fortinet","system_status")
    path = registry_path or os.environ.get("NETOPS_SCHEMA_REGISTRY")
    if not path:
        raise schema.SchemaError("a server-side schema registry is required")
    try:
        document=json.loads(read_regular(path,262144).decode("utf-8"),object_pairs_hook=unique_object)
        if not isinstance(document,dict) or set(document)!={"format","targets"} or type(document["format"]) is not int or document["format"]!=1:
            raise ValueError()
        targets=document["targets"]
        if not isinstance(targets,dict) or len(targets)>4096:
            raise ValueError()
        entry=targets[auth.alias]
        if not isinstance(entry,dict) or set(entry)!={"schema","sha256","host_key_fingerprint"}:
            raise ValueError()
        filename=entry["schema"]
        if not isinstance(filename,str) or not filename or Path(filename).is_absolute() or ".." in Path(filename).parts:
            raise ValueError()
        if not isinstance(entry["sha256"],str) or not re.fullmatch(r"[a-f0-9]{64}",entry["sha256"]):
            raise ValueError()
        if entry["host_key_fingerprint"]!=auth.host_key_fingerprint:
            raise ValueError()
        library=schema.load(Path(path).parent/filename,entry["sha256"])
    except (OSError,InputError,UnicodeError,ValueError,TypeError,KeyError,RecursionError):
        raise schema.SchemaError("the target schema registry binding cannot be verified") from None
    return library


def verify_status(library,text):
    if not isinstance(text,str) or len(text.encode("utf-8"))>65536:
        raise schema.SchemaError("the device identity response exceeds its limit")
    matches=STATUS.findall(text)
    if len(matches)!=1:
        raise schema.SchemaError("the device did not return one exact FortiOS identity")
    library.require_identity(*matches[0])
    domains=[value.strip() for value in CURRENT_VDOM.findall(text)]
    if len(domains)!=1 or not domains[0] or not domains[0].isprintable() or len(domains[0].encode("utf-8"))>128:
        raise schema.SchemaError("the device did not return one verified current VDOM")
    return domains[0]


def selectors(auth,library,path,view,vdom,owners):
    library.node(path)
    if path not in auth.read_inventory.get("schema_paths",()):
        raise schema.SchemaError("the configuration path is not enrolled for this target")
    if view not in ("show","get"):
        raise schema.SchemaError("schema view must be show or get")
    if vdom is not None and (not isinstance(vdom,str) or not vdom or len(vdom.encode("utf-8"))>128 or not vdom.isprintable()):
        raise schema.SchemaError("VDOM selector is invalid")
    if not isinstance(owners,list) or len(owners)>64 or any(not isinstance(k,str) or not k or len(k.encode("utf-8"))>128 or not k.isprintable() for k in owners):
        raise schema.SchemaError("table key selectors are invalid")


def snapshot(library,text,path,view,vdom,owners,secrets=(),current_vdom=None):
    if len(text.encode("utf-8"))>MAX_SNAPSHOT:
        raise schema.SchemaError("the schema snapshot exceeds its safety cap")
    try:
        tree=fortios.parse(text)
    except (fortios.ParseError,fortios.TruncatedError):
        raise schema.SchemaError("the device schema snapshot is incomplete or malformed") from None
    wrapped=tree.section("vdom") is not None
    if not wrapped and (not isinstance(current_vdom,str) or not current_vdom or not current_vdom.isprintable()):
        raise schema.SchemaError("an unwrapped snapshot requires a verified current VDOM")
    if not wrapped and vdom is not None and vdom!=current_vdom:
        raise schema.SchemaError("the selected VDOM is outside the verified snapshot")
    metadata=library.node(path)["attrs"]
    objects=[]
    for instance in schema.config_instances(library,tree):
        scope=instance.scope if wrapped or instance.scope is None else current_vdom
        if instance.path!=path or vdom is not None and scope!=vdom:
            continue
        if owners and tuple(k for _,k in instance.owners)!=tuple(owners):
            continue
        attributes={}
        for name,value in instance.node.attrs.items():
            if value.unset:
                continue
            sensitive=(name not in metadata or SECRET_ATTRIBUTE.search(name) or metadata[name].get("type")=="password"
                       or "ENC" in value.values)
            attributes[redact(name,secrets)]=["<REDACTED>"] if sensitive else [redact(v,secrets) for v in value.values]
        item={"vdom":redact(scope or "global",secrets),"owners":[[p,redact(k,secrets)] for p,k in instance.owners],
              "attributes":attributes}
        if view=="show":
            item["show"]="\n".join("set "+name+" "+" ".join(json.dumps(v,ensure_ascii=False) for v in values)
                                     for name,values in sorted(attributes.items()))
        objects.append(item)
    return {"path":path,"view":view,"objects":objects,
            "value_source":"live full-configuration; no defaults inferred",
            "snapshot_scope":"wrapped-vdoms" if wrapped else "current-vdom",
            "schema_sha256":library.sha256,"identity":library.identity,"identity_assurance":"live-status-verified"}
