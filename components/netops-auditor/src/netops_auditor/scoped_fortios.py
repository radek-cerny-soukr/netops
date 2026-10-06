from __future__ import annotations

import copy
import json
from dataclasses import replace

from .engine import CheckError, NOT_EVALUATED, UNSUPPORTED, evaluate, load_catalog

MAX_VDOMS = 64
MAX_FINDINGS = 10000
MAX_VIEW_ITEMS = 250000
PRIMARY_PATHS = {
 "dangling_reference":"firewall policy",
 "admin_access_on_untrusted_interface":"system interface",
 "utm_without_ssl_profile":"firewall policy",
 "no_syslog_target":"log syslogd setting",
 "no_ntp_sync":"system ntp",
 "usb_auto_install":"system auto-install",
 "static_key_ciphers":"system global",
 "strong_crypto_disabled":"system global",
 "admin_gui_legacy_tls":"system global",
 "admin_idle_timeout":"system global",
 "admin_lockout_threshold":"system global",
 "default_admin_account":"system admin",
 "plaintext_admin_access":"system interface",
 "snmp_community":"system snmp community",
 "policy_service_all":"firewall policy",
 "policy_logging_disabled":"firewall policy",
 "ldap_without_tls":"user ldap",
 "management_fortios_address_unused":"firewall address",
 "management_fortios_address_policy":"firewall address",
 "management_fortios_group_empty":"firewall addrgrp",
 "management_fortios_group_dangling":"firewall addrgrp",
 "management_fortios_group_cycle":"firewall addrgrp",
 "management_fortios_dhcp_conflict":"system dhcp server",
 "management_fortios_dhcp_subnet":"system dhcp server",
}
INTERFACE_DEPENDENT = frozenset(("dangling_reference","management_fortios_dhcp_subnet"))

def _rebase(node,path):
 node.path=path
 for name,section in node.sub.items():_rebase(section,path+(name,))
 for name,entry in node.entries.items():_rebase(entry,path+(name,))
 return node

def _items(node):
 return 1+len(node.attrs)+sum(len(attr.values) for attr in node.attrs.values())+sum(_items(child) for child in node.sub.values())+sum(_items(child) for child in node.entries.values())

def views(library,tree):
 global_node=tree.section("global");vdom_node=tree.section("vdom")
 if global_node is None or vdom_node is None or not vdom_node.entries or len(vdom_node.entries)>MAX_VDOMS:
  raise CheckError("scoped audit requires explicit global and 1 to 64 VDOM snapshots")
 if set(tree.sub)!={"global","vdom"} or tree.attrs or tree.entries:
  raise CheckError("scoped audit refuses mixed wrapped and unwrapped configuration")
 if _items(global_node)*(1+len(vdom_node.entries))+sum(_items(domain) for domain in vdom_node.entries.values())>MAX_VIEW_ITEMS:
  raise CheckError("scoped audit view size exceeds its limit")
 result={None:_rebase(copy.deepcopy(global_node),())};unknown_interfaces={}
 interface_meta=library.node("system interface") if "system interface" in library.paths else None
 for scope,domain in vdom_node.entries.items():
  if not scope or not scope.isprintable() or len(scope.encode())>128:raise CheckError("invalid VDOM name")
  view=_rebase(copy.deepcopy(domain),())
  for path,node in global_node.sub.items():
   if path in library.paths and (library.scope(path)=="global" or path=="system interface" and library.scope(path)=="global+vdom"):
    if path in view.sub:raise CheckError("global configuration collides with the VDOM snapshot")
    view.sub[path]=_rebase(copy.deepcopy(node),(path,))
  interface=view.section("system interface");unknown=False
  if interface is not None:
   selected={}
   for name,entry in interface.entries.items():
    owner=entry.value("vdom")
    if owner is None and interface_meta is not None:
     attr=interface_meta["attrs"].get("vdom",{})
     owner=None if attr.get("default_model_dependent") else attr.get("default")
    if not isinstance(owner,str) or not owner:
     unknown=True
    elif owner==scope:selected[name]=entry
   interface.entries=selected
  unknown_interfaces[scope]=unknown;result[scope]=view
 return result,unknown_interfaces

def run(library,tree,tenant,device,policy=None):
 scoped,unknown_interfaces=views(library,tree)
 rules=load_catalog("fortios")
 ordinary=[rule for rule in rules if not rule.scope_gate]
 if set(rule.check for rule in ordinary)!=set(PRIMARY_PATHS):
  raise CheckError("scoped audit requires a reviewed primary schema path for every catalog check")
 findings=[];states={}
 for scope,view in scoped.items():
  selected=[]
  for rule in ordinary:
   path=PRIMARY_PATHS[rule.check]
   state_key=json.dumps([scope,rule.id],ensure_ascii=True,separators=(",",":"))
   measured_scope=library.scope(path) if path in library.paths else None
   if measured_scope is None:
    states[state_key]=(NOT_EVALUATED,"primary rule scope is not measured");continue
   if measured_scope not in ("global" if scope is None else "vdom","global+vdom"):continue
   if library.availability(path) is not True:
    states[state_key]=(UNSUPPORTED if library.availability(path) is False else NOT_EVALUATED,"primary rule availability is not measured as enabled")
    continue
   if scope is not None and unknown_interfaces[scope] and rule.check in INTERFACE_DEPENDENT:
    states[state_key]=(NOT_EVALUATED,"interface VDOM ownership is not measured");continue
   selected.append(rule)
  hits,statuses=evaluate(view,tenant,device,selected,policy)
  for rule in selected:
   states[json.dumps([scope,rule.id],ensure_ascii=True,separators=(",",":"))]=statuses[rule.id]
  for finding in hits:
   findings.append(replace(finding,object_key=json.dumps([scope,finding.object_key],ensure_ascii=True,separators=(",",":"))))
   if len(findings)>MAX_FINDINGS:raise CheckError("scoped audit finding count exceeds its limit")
 return tuple(sorted(findings,key=lambda f:(f.rule_id,f.object_key))),states
