from __future__ import annotations

from collections import defaultdict
import json
import re

from netops_core.schema import SchemaError, config_instances

MAX_FINDINGS = 10000
SECRET_ATTRIBUTE = re.compile(r"(?:^|[-_])(?:password|passwd|passphrase|pwd|psk|psksecret|secret|token|private.key|community|api.key)(?:$|[-_])",re.I)


def _key(instance, attribute="", value=""):
    return json.dumps([instance.scope, instance.path, instance.owners, attribute, value],
                      ensure_ascii=False, separators=(",", ":"))


def _hit(instance, rule, attribute, reason, value=""):
    return {"rule_id":rule, "class":"fakt", "severity":"high", "object_key":_key(instance,attribute,value),
            "section":instance.path, "line":instance.node.line_of(attribute) or instance.node.line,
            "evidence":{"attribute":attribute,"reason":reason,"vdom":instance.scope or "global","value":value}}


def _bounded(hits, hit):
    if len(hits) >= MAX_FINDINGS:
        raise SchemaError("schema finding limit is exceeded")
    hits.append(hit)


def _target_sets(targets,table,ancestor_paths,source,cache):
    source_owners=dict(source.owners)
    common=tuple(sorted(source_owners.keys() & ancestor_paths[table]))
    cache_key=(table,common)
    if cache_key not in cache:
        groups=defaultdict(set)
        for target in targets[table]:
            parents={p:k for p,k in target.owners if p!=target.path}
            context=tuple(parents.get(p) for p in common)
            if target.scope is None:
                groups[(context,"global-all",None)].add(target.key)
                bound=target.node.value("vdom") if table=="system interface" else None
                groups[(context,"global",bound or None)].add(target.key)
            else:
                groups[(context,"vdom",target.scope)].add(target.key)
        cache[cache_key]={k:frozenset(v) for k,v in groups.items()}
    groups=cache[cache_key]
    context=tuple(source_owners[p] for p in common)
    empty=frozenset()
    if source.scope is None:
        return (groups.get((context,"global-all",None),empty),)
    return (groups.get((context,"global",None),empty),
            groups.get((context,"global",source.scope),empty),
            groups.get((context,"vdom",source.scope),empty))


def references(library, tree, complete=True):
    metadata_by_path = {p:library.node(p) for p in library.paths}
    scopes = {p:library.scope(p) for p in library.paths}
    ancestor_paths = {p:set(library.chain(p)[:-1]) for p in library.paths}
    indexes = {}
    instances = list(config_instances(library, tree))
    targets = defaultdict(list)
    for instance in instances:
        targets[instance.path].append(instance)
    vdom = tree.section("vdom")
    vdom_names = set(vdom.entries) if vdom is not None else {"root"}
    configured = defaultdict(int)
    coverage, hits = {}, []
    for path in library.paths:
        for attribute, metadata in metadata_by_path[path]["attrs"].items():
            if "ref" in metadata:
                coverage[path+"::"+attribute] = {"status":"not-present","checked_values":0}
    for instance in instances:
        for attribute, metadata in metadata_by_path[instance.path]["attrs"].items():
            ref = metadata.get("ref")
            values = tuple(value for value in instance.node.values(attribute) if value != "")
            if ref is None or not values:
                continue
            field = instance.path+"::"+attribute
            configured[field] += 1
            tables = ref["tables"]
            secret = metadata.get("type") == "password" or bool(SECRET_ATTRIBUTE.search(attribute)) or "ENC" in values
            context = "global" if instance.scope is None else "vdom:" + instance.scope
            context_unknown = "measured_contexts" in ref and context not in ref["measured_contexts"]
            unknown = secret or context_unknown or ref.get("unresolved") or ref.get("builtin_values_not_captured") or not tables or any(
                p != "vdom" and p not in metadata_by_path for p in tables)
            if vdom is not None and any(p != "vdom" and p in metadata_by_path and scopes[p] is None for p in tables):
                unknown = True
            if unknown or not complete:
                coverage[field] = {"status":"not-evaluated","checked_values":0,
                    "reason":"secret-bearing reference is not reported" if secret else "reference context was not measured" if context_unknown else "reference metadata or VDOM scope is unresolved" if unknown else "a complete snapshot is not declared"}
                continue
            names = [frozenset(ref.get("special", [])) | frozenset(ref.get("builtin", []))]
            for path in tables:
                if path == "vdom":
                    names.append(vdom_names)
                else:
                    names.extend(_target_sets(targets,path,ancestor_paths,instance,indexes))
            status = coverage[field]
            if status["status"] != "not-evaluated":
                status["status"]="evaluated"
                status["checked_values"] += len(values)
            for value in values:
                if value and not any(value in group for group in names):
                    _bounded(hits,_hit(instance,"fortios.schema.reference",attribute,
                                      "configured reference is absent from its measured target tables",value))
    return hits, {"fields":coverage,"configured_instances":dict(configured),
                  "snapshot_complete":complete}


def upgrade(current, target, tree):
    if current.identity[0] != target.identity[0]:
        raise SchemaError("upgrade comparison requires the same hardware model")
    if tuple(map(int,target.identity[1].split("."))) < tuple(map(int,current.identity[1].split("."))):
        raise SchemaError("upgrade comparison cannot select an older firmware version")
    hits, unknown = [], []
    target_nodes = {p:target.node(p) for p in target.paths}
    current_nodes = {p:current.node(p) for p in current.paths}
    target_paths = set(target_nodes)
    current_paths = set(current_nodes)
    target_scopes = {p:target.scope(p) for p in target.paths}
    target_availability = {p:target.availability(p) for p in target.paths}
    for instance in config_instances(current,tree,include_unknown=True):
        if instance.path not in current_paths:
            if instance.node.attrs or instance.owners:
                unknown.append({"path":instance.path,"reason":"configured source path is not measured"})
            continue
        if instance.path not in target_paths:
            if instance.node.attrs or instance.owners:
                _bounded(hits,_hit(instance,"fortios.schema.upgrade-path","","configured path is absent from the target schema"))
            continue
        old, new = current_nodes[instance.path], target_nodes[instance.path]
        if target_scopes[instance.path] is None:
            unknown.append({"path":instance.path,"reason":"target scope is not measured"})
        if instance.scope is not None and target_scopes[instance.path] == "global":
            _bounded(hits,_hit(instance,"fortios.schema.upgrade-scope","","configured VDOM object has global scope in the target schema"))
        if target_availability[instance.path] is False:
            _bounded(hits,_hit(instance,"fortios.schema.upgrade-availability","","configured path is unavailable in the measured target build"))
        elif target_availability[instance.path] is None:
            unknown.append({"path":instance.path,"reason":"target availability is not measured"})
        for attribute, value in instance.node.attrs.items():
            if value.unset:
                continue
            if attribute not in old["attrs"]:
                unknown.append({"path":instance.path,"attribute":attribute,"reason":"configured source attribute is not measured"})
                continue
            if attribute not in new["attrs"]:
                _bounded(hits,_hit(instance,"fortios.schema.upgrade-attribute",attribute,
                                  "configured attribute is absent from the target schema"))
                continue
            before, after = old["attrs"][attribute], new["attrs"][attribute]
            if before.get("type") is None or after.get("type") is None:
                unknown.append({"path":instance.path,"attribute":attribute,"reason":"source or target attribute type is not measured"})
                continue
            if after.get("type") == "option" and not after.get("options"):
                unknown.append({"path":instance.path,"attribute":attribute,"reason":"target option values are not measured"})
                continue
            if after.get("type") == "integer" and "min" not in after and "max" not in after:
                unknown.append({"path":instance.path,"attribute":attribute,"reason":"target integer bounds are not measured"})
                continue
            reason = None
            if before.get("type") != after.get("type"):
                reason = "configured attribute type changes in the target schema"
            elif after.get("type") == "option" and any(v not in after.get("options",[]) for v in value.values):
                reason = "configured option is absent from the target schema"
            elif after.get("type") == "integer":
                numbers = tuple(v for v in value.values if v != "") if after.get("multi") else value.values
                if (not after.get("multi") and len(numbers) != 1) or any(not re.fullmatch(r"-?[0-9]{1,20}", v) for v in numbers):
                    unknown.append({"path":instance.path,"attribute":attribute,"reason":"configured integer syntax cannot be evaluated"})
                elif any(str(int(v)) != str(after.get("default")) and (
                        "min" in after and int(v) < after["min"] or "max" in after and int(v) > after["max"]) for v in numbers):
                    reason = "configured integer is outside the target range"
            elif "max_length" in after and any(len(v.encode("utf-8")) > after["max_length"] for v in value.values):
                reason = "configured text exceeds the target length"
            if reason:
                _bounded(hits,_hit(instance,"fortios.schema.upgrade-value",attribute,reason))
    return hits, {"not_evaluated":unknown,"source":current.identity,"target":target.identity,
                  "assurance":"schema differences require vendor upgrade guidance; they do not simulate firmware migration"}
