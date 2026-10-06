from __future__ import annotations

from netops_admin import exec_fortios, fortios, schema_runtime
from netops_core import fortios as core_fortios

prompt_spec=exec_fortios.prompt_spec
safeguard_label=exec_fortios.safeguard_label
clock=exec_fortios.clock
leftovers=exec_fortios.leftovers
foreign_sessions=exec_fortios.foreign_sessions
persist=exec_fortios.persist
ports=exec_fortios.ports
prechecks=exec_fortios.prechecks

def hostname(access,text):
    return access.hostname

def accounts_check(access,device,text):
    table=access.query(fortios.QUERY_ADMINS)
    visible=fortios.visible_admins(table)
    from netops_admin.errors import Rejected
    if visible!=sorted(device.accounts):
        raise Rejected(["schema write account sees an unexpected administrator inventory"])
    tree=core_fortios.parse(text).section("global")
    profiles=core_fortios.parse(access.query("show full-configuration system accprofile")).section("system accprofile")
    if profiles is None:
        raise Rejected(["the complete administrator profiles are not visible"])
    tree.sub["system accprofile"]=profiles
    return fortios.admin_fingerprint(table,schema_runtime._text(tree),immutable_profiles=("super_admin",))

def install_safeguard(access,record,plan,device,spec):
    access.apply(["config global"]+fortios.render_safeguard(record["change_id"],plan["inverse"],record["safeguard"]["fire_at"])+["end"],spec)
    return fortios.safeguard_state(record["change_id"],exec_fortios._answers(access,record["change_id"]),plan["inverse"],record["safeguard"]["fire_at"])

def remove_safeguard(access,record,spec):
    try:
        access.apply(["config global"]+fortios.render_safeguard_removal(record["change_id"])+["end"],spec)
    except Exception:
        pass
    return safeguard_absent(access,record)

def safeguard_absent(access,record):
    try:
        names=fortios.safeguard_names(record["change_id"])
        for kind,table in schema_runtime.GUARD_TABLES.items():
            node=core_fortios.parse(access.query("show "+table)).section(table)
            if node is None or names[kind] in node.entries:
                return False
        return True
    except Exception:
        return False

def observe(access,plan):
    return access.observe(plan)
