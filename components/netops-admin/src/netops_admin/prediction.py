from __future__ import annotations

from netops_auditor import l1_fortios

from . import engine, exos, fortios, membership
from .profiles import find_profile


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


def snapshot_after(text, plan):
    state = plan["predicted"]["after"]
    key, table = plan["key"], plan["table"]
    if plan["platform"] == "fortios":
        snapshot = fortios.load(text, plan["firmware"])
        tree = snapshot.root
        if table == "system dhcp server/reserved-address":
            sid, rid = key.split(":")
            server = tree.section("system dhcp server").entries[sid]
            section = server.sub.setdefault("reserved-address", l1_fortios.Node(("system dhcp server", sid, "reserved-address"), 0))
            key = rid
        else:
            section = tree.section(table)
        if state is None:
            section.entries.pop(key, None)
        else:
            entry = section.entries.setdefault(key, l1_fortios.Node((table, key), 0))
            profile = find_profile("fortios", table, plan["firmware"])
            for name in profile.attributes:
                entry.attrs.pop(name, None)
            for name, value in state.items():
                tokens = (value,) if profile.attributes[name].type == "text" else tuple(value.split())
                entry.attrs[name] = l1_fortios.Attr(tokens, 0)
        return text.splitlines()[0] + "\n" + "\n".join(fortios_text(tree)) + "\n"
    snapshot = exos.load(text, plan["firmware"])
    if table == "vlan-membership":
        return membership.prediction(snapshot, key, state)
    kept = []
    for command in snapshot.commands:
        own = (exos._is_display_string(command) and command.tokens[2] == key) if table == "ports" else snapshot._is_own(command, key)
        if not own:
            kept.append(command.text)
    lines = ["# Module vlan configuration."] + kept
    if state is not None:
        if table == "ports":
            if "display-string" in state:
                lines += ["configure ports %s display-string %s" % (key, state["display-string"])]
        else:
            lines += ["create vlan %s" % key]
            if "tag" in state:
                lines += ["configure vlan %s tag %s" % (key, state["tag"])]
            if "description" in state:
                lines += ['configure vlan %s description "%s"' % (key, state["description"])]
    return "\n".join(lines) + "\n"
