"""1.0.13 A3 FortiOS tables (firewall address6, firewall addrgrp6, router static6).

Registered in fortios_tables.MODULES as TABLES = {table: TableHooks(...)}. The shared code (fortios_tables, engine,
execute, exec_fortios) plans, renders, reads back and returns these tables; this module adds what is specific to IPv6:

- ``firewall address6`` (an IPv6 prefix, an IPv6 range or an FQDN) and ``firewall addrgrp6`` (members only
  ``firewall address6`` or ``firewall addrgrp6`` objects, no cycle, never empty) follow the rules of their IPv4
  counterparts. A change of an object a firewall policy uses through ``srcaddr6``/``dstaddr6`` (directly or through an
  address group) needs ``endpoint_impact`` naming the object when the policy is active and is refused when the policy is
  protected; a change of an object referenced elsewhere (other than by a policy or an address group), directly or
  through an address group that holds it (nested groups included, for example a firewall local-in-policy6 naming the
  group), is refused, a referenced object is never deleted (``fortios_object_referenced``, the shared delete check).
- A create is checked with the values it writes (``explicit_create``): an IPv6 prefix needs ip6. FortiOS 7.6.8 asks
  for an interactive confirmation when an IPv6 prefix at ::/0 (all IPv6 addresses) is saved, so a create or an update
  that leaves an address6 at ::/0 is refused before any write. show omits type ipprefix and ip6 ::/0; the undo of a
  delete names them (``restore``), so the A2 check of the undo plan refuses the delete of an object at ::/0 before any
  write instead of a delete that could not be undone.
- ``router static6`` follows the rules of ``router static`` (design A 3, rule a-f, ``fortios_route6_protected``). As
  for IPv4, a default route through the management path stays protected by itself (its device and its ::/0
  destination refuse any change of it); every destination overlaps ::/0, so that route does not refuse the others.
- On FortiOS 8.0.1 and later no operation of these tables is verified with the webhook safeguard, so every change is
  refused there before any write with ``safeguard_no_rest_inverse`` (rest_verified is empty).
"""
from __future__ import annotations

import ipaddress

from netops_auditor import l1_fortios

from netops_admin import fortios
from netops_admin.errors import Rejected
from netops_admin.fortios_tables import TableHooks

ADDRESS6 = "firewall address6"
GROUP6 = "firewall addrgrp6"
ROUTE6 = fortios.ROUTE6_TABLE
POLICY_ATTRIBUTES = ("srcaddr6", "dstaddr6")
# the attributes of each address6 type (with no explicit type FortiOS uses ipprefix and omits it in show)
ADDRESS6_FIELDS = {"ipprefix": ("ip6",), "iprange": ("start-ip", "end-ip"), "fqdn": ("fqdn",)}
TYPED_FIELDS = frozenset(name for names in ADDRESS6_FIELDS.values() for name in names)
UNMANAGED_CHANGE = frozenset(("comment",))


def _changed(before, after) -> set:
    return {name for name in set(before or {}) | set(after or {})
            if (before or {}).get(name) != (after or {}).get(name)} - UNMANAGED_CHANGE


ALL_IPV6_REFUSAL = ("firewall address6 %s would be an IPv6 prefix at ::/0 (all IPv6 addresses): FortiOS 7.6.8 asks for an"
                    " interactive confirmation when such an entry is saved, which Admin and its safeguard cannot give;"
                    " Admin does not write it")


def _all_ipv6(state) -> bool:
    """An IPv6 prefix at ::/0 (ip6 named as ::/0 or omitted at its default, as show prints it)."""
    if state.get("type", "ipprefix") != "ipprefix":
        return False
    network = fortios._network6(state.get("ip6", "::/0"))
    return network is not None and network.prefixlen == 0


def _address6_fields(state, creating=False) -> list:
    kind = state.get("type", "ipprefix")
    if kind not in ADDRESS6_FIELDS:
        return ["firewall address6 type %s is not managed" % kind]
    wanted = ADDRESS6_FIELDS[kind]
    foreign = sorted(name for name in TYPED_FIELDS - set(wanted) if name in state)
    if foreign:
        return ["firewall address6 of type %s does not take %s" % (kind, ", ".join(foreign))]
    if creating:
        missing = [name for name in wanted if name not in state]
        if missing:
            return ["creating a firewall address6 of type %s needs %s" % (kind, ", ".join(missing))]
    if kind == "iprange" and "start-ip" in state and "end-ip" in state:
        try:
            if ipaddress.IPv6Address(state["start-ip"]) > ipaddress.IPv6Address(state["end-ip"]):
                return ["start-ip must be less than or equal to end-ip"]
        except ValueError:
            return ["the IPv6 range bounds are not IPv6 addresses"]
    return []


def _policy_use(snapshot, key, op, before, after, protected, impact, undo) -> None:
    """A change of an address6 object or address group an IPv6 policy matches (directly or through an addrgrp6 that
    holds it): refused for a protected policy, only with endpoint_impact for an active one."""
    if op not in ("update", "delete"):
        return
    if not _changed(before, after) and op != "delete":
        return
    names = {key} | fortios.containing_groups(snapshot.entries(GROUP6), key)
    guarded, active = fortios.policy_use(snapshot, names, POLICY_ATTRIBUTES, protected)
    if guarded:
        raise Rejected(["%s is used by the protected firewall policies %s" % (key, ", ".join(guarded))])
    if active and impact is None and not undo:
        raise Rejected(["%s is used by the active firewall policies %s: the change alters the traffic they match;"
                        " endpoint_impact naming the object is required" % (key, ", ".join(active))],
                       reason_codes=["fortios_policy_impact_required"])


def _foreign_references(snapshot, table, key) -> list:
    """References of the object, and of every addrgrp6 that holds it directly or through nested groups, other than an
    IPv6 policy match (firewall policy srcaddr6/dstaddr6, judged by _policy_use) or an IPv6 address group member
    (followed here): for example a firewall local-in-policy6, a VIP or another policy table, which Admin does not
    evaluate (1.0.13 A3-r2: a group member reaches the local-in policy of its group as well)."""
    def handled(item):
        path, _, name = item.rpartition(": ")
        return ((path.startswith(fortios.POLICY_TABLE + " / ") and name in POLICY_ATTRIBUTES)
                or (path.startswith(GROUP6 + " / ") and name == "member"))
    found = [item for item in snapshot.references(table, key) if not handled(item)]
    for group in sorted(fortios.containing_groups(snapshot.entries(GROUP6) or {}, key)):
        found.extend("%s through %s %s" % (item, GROUP6, group)
                     for item in snapshot.references(GROUP6, group) if not handled(item))
    return found


def _foreign_refusal(table, key, references) -> list:
    return ["%s %s is referenced outside IPv6 policies and address groups (%s); Admin does not change it"
            % (table, key, "; ".join(references))]


def address6_prechecks(snapshot, profile, op, key, before, after, protected, impact, undo) -> list:
    if op == "create":
        reasons = _address6_fields(after or {}, creating=True)
    else:
        reasons = _address6_fields(before or {}) or (_address6_fields(after) if after is not None else [])
    if reasons:
        return reasons
    if op in ("create", "update") and _all_ipv6(after or {}):
        # 1.0.13 A3-r2 (measured on FortiGate-60F 7.6.8): "The IPv6 address is set to ::/0 which means all IPv6
        # addresses." and no prompt after next; the undo of a delete of such an object is refused the same way
        # (the restoration names ip6 ::/0, the A2 check of the undo plan refuses the delete before any write)
        return [ALL_IPV6_REFUSAL % key]
    foreign = _foreign_references(snapshot, ADDRESS6, key) if op == "update" and _changed(before, after) else []
    if foreign:
        return _foreign_refusal(ADDRESS6, key, foreign)
    _policy_use(snapshot, key, op, before, after, protected, impact, undo)
    return []


def addrgrp6_prechecks(snapshot, profile, op, key, before, after, protected, impact, undo) -> list:
    state = before if op == "delete" else after
    members = set(l1_fortios.tokenize((state or {}).get("member", "")))
    if not members or (before is not None and not before.get("member")):
        return ["an IPv6 address group must retain at least one member"]
    groups = snapshot.entries(GROUP6) or {}
    known = {name.casefold() for name in (snapshot.entries(ADDRESS6) or {})} | {name.casefold() for name in groups}
    folded = {name.casefold() for name in members}
    if key.casefold() in folded or key.casefold() in fortios.member_closure(groups, members):
        return ["the group cannot include itself directly or through another group"]
    if folded - known:
        return ["the group names a member that is no firewall address6 or addrgrp6 object in the visible snapshot"]
    foreign = _foreign_references(snapshot, GROUP6, key) if op == "update" and _changed(before, after) else []
    if foreign:
        return _foreign_refusal(GROUP6, key, foreign)
    _policy_use(snapshot, key, op, before, after, protected, impact, undo)
    return []


def route6_prechecks(snapshot, profile, op, key, before, after, protected, impact, undo) -> list:
    """Design A 3 rules a-e for the state before and after the change (rule f, management over IPv4 literals, runs in
    exec_fortios.plan_prechecks where the device address is known). Like router static, a default route through the
    management path does not refuse the other routes (every destination overlaps ::/0); it stays protected itself."""
    if op == "create" and int(key) > fortios.SEQ_NUM_MAX:
        raise Rejected(["the route sequence number exceeds %d" % fortios.SEQ_NUM_MAX],
                       reason_codes=["fortios_route6_protected"])
    routes = snapshot.entries(ROUTE6) or {}
    defaults = {seq for seq, entry in routes.items()
                if seq != key and (network := fortios._network6(entry.value("dst", "::/0"))) is not None
                and network.prefixlen == 0}
    view = _RoutesWithout(snapshot, defaults) if defaults else snapshot
    fortios.route6_prechecks(view, key, before, after, protected)
    return []


class _RoutesWithout:
    """The snapshot as route6_prechecks reads it, without the other default routes in router static6 (the IPv4 rule
    of router static, design A 3: router static6 has the rules of router static)."""

    def __init__(self, snapshot, hidden):
        self._snapshot = snapshot
        self._hidden = frozenset(hidden)

    def entries(self, table):
        entries = self._snapshot.entries(table)
        if table != ROUTE6 or entries is None:
            return entries
        return {seq: entry for seq, entry in entries.items() if seq not in self._hidden}

    def __getattr__(self, name):
        return getattr(self._snapshot, name)


def restore_address6(profile, state) -> dict:
    """The create that recreates a deleted address6 from its stored state: show omits type ipprefix and ip6 ::/0 (and
    the default :: of a range bound), so the stored state of an object at those defaults lacks them; the recreation
    names the type and the measured default of each attribute of the type the state omits (1.0.13 A3-r2), and the hook
    judges the real values (an IPv6 prefix at ::/0 is refused, and with it the delete). An FQDN has no default and
    stays missing (the hook refuses it, and with it the delete)."""
    kind = state.get("type", "ipprefix")
    if kind not in ADDRESS6_FIELDS:
        return state
    restored = dict(state, type=kind)
    for name in ADDRESS6_FIELDS[kind]:
        default = profile.attributes[name].default if name in profile.attributes else None
        if restored.get(name) is None and default is not None:
            restored[name] = default
    return restored


def render_address6(profile, op, key, assign, remove):
    """Create establishes the type before its fields (an IPv6 range takes start-ip and end-ip only once its type is
    iprange); update and delete use the shared rendering."""
    if op != "create" or "type" not in assign:
        return None
    values = dict(assign)
    lines = ["config " + ADDRESS6, "    edit " + fortios._quoted(key),
             "        set type " + values.pop("type")]
    for name in ("start-ip", "end-ip"):
        if name in values:
            lines.append("        set %s %s" % (name, fortios._value(profile, name, values.pop(name))))
    lines += ["        set %s %s" % (name, fortios._value(profile, name, values[name])) for name in sorted(values)]
    return lines + ["    next", "end"]


TABLES = {
    ADDRESS6: TableHooks(ADDRESS6, rest_path="firewall/address6", rest_key="name", rest_permission="fwgrp",
                         impact=True, prechecks=address6_prechecks, render=render_address6,
                         restore=restore_address6, explicit_create=True),
    GROUP6: TableHooks(GROUP6, rest_path="firewall/addrgrp6", rest_key="name", rest_permission="fwgrp",
                       impact=True, prechecks=addrgrp6_prechecks),
    ROUTE6: TableHooks(ROUTE6, rest_permission="netgrp", prechecks=route6_prechecks),
}
