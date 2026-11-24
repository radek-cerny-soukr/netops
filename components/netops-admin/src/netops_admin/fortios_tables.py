"""1.0.13 A1-R: the registry of the FortiOS tables added in 1.0.13.

The tables of the 1.0.13 profiles (services, policy objects, IPv6) are no longer if-branches of engine.py,
execute.py, fortios.py and exec_fortios.py. Each group registers its tables in its own flat module (MODULES) as
``TABLES = {table: TableHooks(...)}``; the shared code asks ``hooks(table)`` and treats every registered table the
same way:

- the table kind (``object``, ``singleton`` with key ``-``, ``nested`` below a parent as ``<parent>:<child>``)
  decides how the snapshot, the rest digest, the prediction, the rendering and the readback address it;
- ``excluded`` names attributes Admin never manages (attributes that can hold secrets or key material, out-of-scope
  options); an object read by the plan that carries one is refused by name before any state is built, and a readback
  that shows one is a mismatch (the values never reach a plan, a preview or an inverse);
- apply needs the approved preview's plan_sha256 (``preview_code``), checked once in execute.py for every table here;
- on FortiOS 8.0.1 and later an operation is allowed only when it and its opposite operation are in
  ``rest_verified`` (create needs a verified delete and the reverse) and the REST inverse of both renders within the
  1023-byte body limit; otherwise ``safeguard_no_rest_inverse`` before any write;
- ``impact`` tables take ``endpoint_impact`` naming the key (``-`` for a singleton);
- a profile of a registered table cannot use ``isolated_update``.

The registry refuses a table registered twice and a table fortios.py already handles itself.
"""
from __future__ import annotations

from dataclasses import dataclass

from netops_admin.errors import Rejected

MODULES = ("fortios_tab_services", "fortios_tab_policy", "fortios_tab_ipv6")
KINDS = ("object", "singleton", "nested")
SINGLETON_KEY = "-"
# the tables of the 1.0.13 profiles (design A, section 4); integration of wave A turns the subset check into equality
PLANNED_TABLES = frozenset((
    "system dhcp server", "system dhcp server/ip-range", "system dns", "log syslogd setting",
    "firewall service group", "firewall schedule recurring", "firewall schedule onetime",
    "firewall address6", "firewall addrgrp6", "router static6",
))
PREVIEW_CODES = ("fortios_service_preview_required", "fortios_object_preview_required")
READBACK_CODES = (None, "fortios_service_readback_unreadable")
SCOPE_CODE = "fortios_service_scope"
OPPOSITE = {"create": "delete", "delete": "create", "update": "update"}
REST_GROUPS = ("fwgrp", "sysgrp", "netgrp", "loggrp", "vpngrp", "utmgrp", "wifi", "authgrp", "secfabgrp", "ftviewgrp")


class RegistryError(Exception):
    pass


@dataclass(frozen=True)
class TableHooks:
    """How the shared FortiOS code handles one registered table.

    Hooks (all optional):
    entries(snapshot) -> dict | None: the objects of the table (None = the section is missing/unreadable);
    excluded_check(snapshot, profile, op, key, changes) -> list of excluded attribute names on further objects the
        plan reads (for example every DHCP server on the same interface); runs with the generic check of the target;
    prechecks(snapshot, profile, op, key, before, after, protected, impact, undo) -> list of refusals
        (a Rejected raised by the hook keeps its reason codes);
    predict(tree, plan) -> None: changes the parsed predicted tree in place instead of the generic prediction;
    render(profile, op, key, assign, remove) -> list of CLI lines, instead of the generic rendering;
    readback_command(plan) -> str and readback_parse(text, plan) -> dict | None: the check account read;
    restore(profile, state) -> dict: the values of the create that recreates a deleted object from its stored state
        (1.0.13 A3-r2: the stored state omits measured defaults as show does; the restoration names the ones the
        create needs, for example ip6 ::/0 of an IPv6 prefix), used by the undo request and its validation alike.
    explicit_create: the prechecks of a create see the values the create writes (a measured default named in the
        request included), not the predicted state, which omits defaults as show does (1.0.13 A3-r2).
    """

    table: str
    kind: str = "object"
    rest_path: str | None = None
    rest_key: str | None = None
    rest_permission: str = "fwgrp"
    rest_verified: frozenset = frozenset()
    child_sections: tuple = ()
    entries: object = None
    prechecks: object = None
    impact: bool = False
    predict: object = None
    render: object = None
    readback_command: object = None
    readback_parse: object = None
    policy_attributes: tuple = ()
    excluded: tuple = ()
    excluded_check: object = None
    preview_code: str = "fortios_object_preview_required"
    readback_code: str | None = None  # A1: fortios_service_readback_unreadable
    parent: tuple | None = None  # nested: (parent table, child section)
    restore: object = None
    explicit_create: bool = False


_registry = None


def _fortios_tables() -> frozenset:
    """The tables fortios.py handles itself (1.0.12 and earlier); a group cannot take one over."""
    from netops_admin import fortios, fortios_lease
    return frozenset((
        *fortios.ORIGINAL_NESTED, *fortios.ORIGINAL_REST, *fortios.NETWORK_TABLES, *fortios.ADDRESS_TABLES,
        *fortios.NAT_TABLES, *fortios.SWITCH_PORT_TABLES, fortios.POLICY_TABLE, fortios.SERVICE_TABLE,
        fortios.PHASE1_TABLE, fortios.PHASE2_TABLE, fortios.IPSEC_TUNNEL, fortios.SESSION_TABLE,
        fortios.VIP_GROUP_TABLE, fortios.ISDB_TABLE, fortios_lease.TABLE,
    ))


def validate(hooks: TableHooks, known: frozenset) -> None:
    if not isinstance(hooks, TableHooks):
        raise RegistryError("a registered table needs TableHooks")
    if hooks.table in known:
        raise RegistryError("table %s is handled by fortios.py and cannot be registered" % hooks.table)
    if hooks.kind not in KINDS:
        raise RegistryError("table %s: kind must be one of %s" % (hooks.table, ", ".join(KINDS)))
    if hooks.kind == "nested" and (not isinstance(hooks.parent, tuple) or len(hooks.parent) != 2):
        raise RegistryError("nested table %s needs parent (parent table, child section)" % hooks.table)
    if hooks.kind != "nested" and hooks.parent is not None:
        raise RegistryError("table %s: only a nested table has a parent" % hooks.table)
    if hooks.kind == "singleton" and (hooks.rest_verified or hooks.child_sections):
        raise RegistryError("singleton %s has no REST inverse and no child sections" % hooks.table)
    if not set(hooks.rest_verified) <= set(OPPOSITE):
        raise RegistryError("table %s: rest_verified names an unknown operation" % hooks.table)
    if hooks.rest_verified and not (hooks.rest_path and hooks.rest_key):
        raise RegistryError("table %s: rest_verified needs rest_path and rest_key" % hooks.table)
    if hooks.rest_permission not in REST_GROUPS:
        raise RegistryError("table %s: unknown REST permission group %s" % (hooks.table, hooks.rest_permission))
    if hooks.preview_code not in PREVIEW_CODES or hooks.readback_code not in READBACK_CODES:
        raise RegistryError("table %s: unknown preview or readback reason code" % hooks.table)


def build(modules: dict) -> dict:
    """modules: name -> TABLES mapping; returns the validated registry."""
    known = _fortios_tables()
    registry, owners = {}, {}
    for module, tables in modules.items():
        if not isinstance(tables, dict):
            raise RegistryError("module %s: TABLES must be a dict" % module)
        for table, hooks in tables.items():
            validate(hooks, known)
            if hooks.table != table:
                raise RegistryError("module %s: TABLES key %s differs from its hooks table %s"
                                    % (module, table, hooks.table))
            if table in registry:
                raise RegistryError("table %s is registered twice (%s, %s)" % (table, owners[table], module))
            registry[table], owners[table] = hooks, module
    return registry


def registry() -> dict:
    global _registry
    if _registry is None:
        from netops_admin import fortios_tab_ipv6, fortios_tab_policy, fortios_tab_services
        modules = {"fortios_tab_services": fortios_tab_services, "fortios_tab_policy": fortios_tab_policy,
                   "fortios_tab_ipv6": fortios_tab_ipv6}
        _registry = build({name: modules[name].TABLES for name in MODULES})
    return _registry


def reset() -> None:
    """Forget the loaded registry (tests that replace the TABLES of a module)."""
    global _registry
    _registry = None


def hooks(table) -> TableHooks | None:
    return registry().get(table) if isinstance(table, str) else None


def all_tables() -> tuple:
    return tuple(sorted(registry()))


def impact_tables() -> tuple:
    return tuple(sorted(table for table, item in registry().items() if item.impact))


def nested_tables() -> dict:
    return {table: item.parent for table, item in registry().items() if item.kind == "nested"}


def check_profile(profile) -> None:
    """A profile of a registered table never uses isolated_update: the whole state is checked (design A, 1.3)."""
    if profile.platform == "fortios" and hooks(profile.table) is not None and profile.isolated_update:
        raise Rejected(["profile fortios %r uses isolated_update, which the 1.0.13 FortiOS tables do not support"
                        % profile.table])


def explicit_default(attribute) -> bool:
    """Design A 1.5b: an attribute whose measured default is not restored by unset (undo_to_default false) returns to
    its default by an explicit set, in the inverse of a plan and in the undo request alike."""
    return attribute is not None and attribute.default is not None and not attribute.undo_to_default


def _matches(name: str, pattern: str) -> bool:
    return name.startswith(pattern[:-1]) if pattern.endswith("*") else name == pattern


def excluded_names(item: TableHooks, names) -> list:
    return sorted({name for name in names for pattern in item.excluded if _matches(name, pattern)})


def scope_refusal(item: TableHooks, names) -> Rejected:
    return Rejected(["the configuration read by the plan holds attributes Admin does not manage: %s"
                     % ", ".join(names)], reason_codes=[SCOPE_CODE])


def state_names(profile, before, after) -> frozenset:
    """The attributes of a singleton that belong to the plan state; the rest digest leaves out only these."""
    return frozenset(set(before or {}) | set(after or {}) | set(profile.attributes)
                     | set(profile.fixed) | set(profile.volatile))


def webhook_allowed(item: TableHooks, op) -> bool:
    """On FortiOS 8.0.1+: an operation of a registered table only with its opposite operation verified."""
    if item.kind == "singleton" or not item.rest_verified or not (item.rest_path and item.rest_key):
        return False
    if op is None:
        return True
    return op in item.rest_verified and OPPOSITE.get(op) in item.rest_verified


def allowed_operations(item: TableHooks, ops) -> tuple:
    return tuple(op for op in ops if webhook_allowed(item, op))


def _read_nodes(snapshot, item: TableHooks, key: str, entry) -> list:
    """The configuration a plan of the table reads: the target and, for a nested table, its parent object."""
    nodes = [] if entry is None else [entry]
    if item.kind == "nested":
        parent_table, _child = item.parent
        parent_key = key.rpartition(":")[0]
        parents = snapshot.root.section(parent_table)
        parent = None if parents is None else parents.entries.get(parent_key)
        if parent is not None:
            nodes.append(parent)
    return nodes


def plan_scope(snapshot, item: TableHooks, profile, op: str, key: str, entry, changes) -> None:
    """Design A 1.3a: before any state of the plan is built, refuse every operation (a change of status only included)
    when an object the plan reads carries an excluded attribute; the refusal names the attributes, never a value."""
    names = set()
    for node in _read_nodes(snapshot, item, key, entry):
        names.update(excluded_names(item, [*node.attrs, *node.sub]))
    if item.excluded_check is not None:
        names.update(item.excluded_check(snapshot, profile, op, key, changes) or ())
    if names:
        raise scope_refusal(item, sorted(names))


def observed_scope(item: TableHooks, attributes) -> None:
    """Design A 1.3a: an excluded attribute the check account sees after the write is a mismatch, before normalize."""
    names = excluded_names(item, attributes or {})
    if names:
        raise Rejected(["the check account sees attributes Admin does not manage: %s" % ", ".join(names)],
                       reason_codes=[item.readback_code] if item.readback_code else None)


def plan_prechecks(item: TableHooks, snapshot, profile, op: str, key: str, before, after, protected, impact,
                   undo) -> list:
    """The prechecks of the group (hook) and the policy use of the object (TableHooks.policy_attributes): an object a
    protected firewall policy uses is never changed, one an active policy uses changes only with endpoint_impact."""
    from netops_admin import fortios
    reasons = []
    if item.policy_attributes and op in ("update", "delete"):
        changed = {name for name in set(before or {}) | set(after or {})
                   if (before or {}).get(name) != (after or {}).get(name)} - {"comment", "comments"}
        guarded, active = fortios.policy_use(snapshot, {key}, item.policy_attributes, protected)
        if guarded and (changed or op == "delete"):
            raise Rejected(["%s %s is used by the protected firewall policies %s" % (profile.table, key,
                                                                                  ", ".join(guarded))])
        if active and (changed or op == "delete") and impact is None and not undo:
            raise Rejected(["%s %s is used by the active firewall policies %s: the change alters the traffic they"
                            " match; endpoint_impact naming the object is required"
                            % (profile.table, key, ", ".join(active))],
                           reason_codes=["fortios_policy_impact_required"])
    if item.prechecks is not None:
        reasons.extend(item.prechecks(snapshot, profile, op, key, before, after, protected, impact, undo) or ())
    return reasons
