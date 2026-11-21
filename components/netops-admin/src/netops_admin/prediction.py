from __future__ import annotations

from netops_auditor import l1_fortios

from . import engine, eos, exos, exos_acl, exos_g44, exos_services, fortios, ios, junos, membership, nxos
from .profiles import find_profile
from .request import list_items


def fortios_text(node, indent=""):
    lines = []
    for name, attr in node.attrs.items():
        if attr.unset:
            lines.append(indent + "unset " + name)
        else:
            values = " ".join('"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
                              for value in attr.values)
            lines.append(indent + "set " + name + (" " + values if values else ""))
    for name, section in node.sub.items():
        lines += [indent + "config " + name] + fortios_text(section, indent + "    ") + [indent + "end"]
    for name, entry in node.entries.items():
        lines += [indent + 'edit "' + name.replace("\\", "\\\\").replace('"', '\\"') + '"']
        lines += fortios_text(entry, indent + "    ") + [indent + "next"]
    return lines


def audited(text, plan):
    if "ports" not in plan:
        return text
    states = plan.get("predicted", {})
    grouped = plan["table"] == "vlan" and exos.plan_kind(states.get("before"), states.get("after")) == "ports"
    if not grouped and plan["table"] not in ("vlan-membership", "ports"):
        return text
    snapshot = exos.load(text, plan["firmware"])
    snapshot.inventory = frozenset(plan["ports"])
    implied = sorted(membership.implicit_default(snapshot), key=exos.port_order)
    lines = "".join("configure vlan %s add ports %s untagged\n" % (membership.DEFAULT_VLAN, port) for port in implied)
    return (text if text.endswith("\n") else text + "\n") + lines


def snapshot_after(text, plan):
    from netops_admin import schema_runtime
    if schema_runtime.is_plan(plan):
        return schema_runtime.snapshot_after(text, plan)
    state = plan["predicted"]["after"]
    key, table = plan["key"], plan["table"]
    if plan["platform"] == "eos":
        return eos.snapshot_after(text, plan)
    if plan["platform"] == "nxos":
        return nxos.snapshot_after(text, plan)
    if plan["platform"] in ios.PLATFORMS:
        return ios.snapshot_after(text, plan)
    if plan["platform"] == "junos":
        return junos.snapshot_after(text, plan)
    if plan["platform"] == "fortios":
        snapshot = fortios.load(text, plan["firmware"])
        tree = snapshot.root
        if table in fortios.NESTED:
            parent_table, child_table = fortios.NESTED[table]
            parent_key, key = fortios.split_nested(table, key)
            parent = tree.section(parent_table).entries[parent_key]
            section = parent.sub.setdefault(child_table, l1_fortios.Node((parent_table, parent_key, child_table), 0))
        elif table in fortios.SWITCH_PORT_TABLES:
            serial, key = key.split(":")
            section = tree.section(fortios.MANAGED_SWITCH).entries[serial].section("ports")
        elif table in (fortios.GROUP_TABLE, fortios.POLICY_TABLE, fortios.PHASE2_TABLE, *fortios.NAT_TABLES):
            section = tree.sub.setdefault(table, l1_fortios.Node((table,), 0))
        else:
            section = tree.section(table)
        if state is None:
            section.entries.pop(key, None)
            if table in (fortios.GROUP_TABLE, *fortios.NAT_TABLES) and not (section.entries or section.attrs or section.sub):
                tree.sub.pop(table)
            elif table in fortios.NESTED and not (section.entries or section.attrs or section.sub):
                parent.sub.pop(fortios.NESTED[table][1], None)
        elif plan["op"] != "move":
            entry = section.entries.setdefault(key, l1_fortios.Node((table, key), 0))
            profile = find_profile("fortios", table, plan["firmware"])
            for name in profile.attributes:
                entry.attrs.pop(name, None)
            for name, value in state.items():
                if table == fortios.POLICY_TABLE and name == "uuid":
                    entry.attrs[name] = l1_fortios.Attr((value,), 0)
                    continue
                if name not in profile.attributes:
                    continue
                attribute = profile.attributes[name]
                tokens = (value,) if attribute.type == "text" else tuple(list_items(attribute, value, profile.platform))
                entry.attrs[name] = l1_fortios.Attr(tokens, 0)
        if "policy_order" in plan:
            section.entries = {item: section.entries[item] for item in plan["policy_order"]["after"]}
        return text.splitlines()[0] + "\n" + "\n".join(fortios_text(tree)) + "\n"
    snapshot = exos.load(text, plan["firmware"])
    if "ports" in plan:
        snapshot.inventory = frozenset(plan["ports"])
    if table == "vlan-membership":
        return membership.prediction(snapshot, key, state)
    if table == exos_acl.POLICY:
        return text
    if table == exos_acl.BINDING:
        kept = [command for command in snapshot.commands if not exos_acl.owns_binding(command, key)]
        added = exos_acl.render_binding(key, state) if state else []
        return "\n".join(membership.modular(snapshot, kept, added, module="acl")) + "\n"
    if table == "vlan" and exos.plan_kind(plan["predicted"]["before"], state) is not None:
        return exos.predicted_text(snapshot, plan, text)
    if table in exos_services.TABLES:
        return exos_services.prediction(snapshot, table, key, state)
    if table in exos_g44.TABLES:
        return exos_g44.prediction(snapshot, table, key, state, plan["predicted"]["before"])
    if table in exos.DHCP_TABLES:
        return exos.dhcp_prediction(snapshot, table, key, state)
    if table in exos.exos_g46.TABLES:
        return exos.exos_g46.prediction(snapshot, table, key, state)
    if table in exos.STATE_TABLES:
        return exos.state_prediction(snapshot, table, key, state)
    owns_l3 = snapshot.owns_vlan_l3(key)
    kept = []
    for command in snapshot.commands:
        own = (exos.port_owned(command, table, key) if table in exos.PORT_TABLES
               else snapshot._is_own(command, key, l3=owns_l3))
        if not own:
            kept.append(command)
    lines = []
    if table == "inline-power":
        added = ["disable inline-power ports %s" % key] if (state or {}).get("admin-state") == "disabled" else []
        return "\n".join(membership.modular(snapshot, kept, added, module="poe")) + "\n"
    if state is not None:
        if table in ("ports", exos.BOUNCE_TABLE):
            if state.get("admin-state") == "disabled":
                lines += ["disable port %s" % key]
            if "display-string" in state:
                lines += ["configure ports %s display-string %s" % (key, state["display-string"])]
            if "description-string" in state:
                lines += ['configure ports %s description-string "%s"' % (key, state["description-string"])]
        else:
            lines += ["create vlan %s" % key]
            if "tag" in state:
                lines += ["configure vlan %s tag %s" % (key, state["tag"])]
            if "description" in state:
                lines += ['configure vlan %s description "%s"' % (key, state["description"])]
            lines += exos.l3_config_lines(key, state)
    return "\n".join(membership.modular(snapshot, kept, lines)) + "\n"
