"""FortiADC execution adapter of the common Admin engine (execute.ADAPTERS["fortiadc"]).

FortiADC-KVM 7.6.7 build0676 offers Admin no on-device timed return (verification: no automation-stitch, scheduler or
cron in the CLI; the documented alert policy of type schedule with a CLI script action is not measured). The adapter
is therefore COMPENSATING: execute installs nothing on the device and returns an unverified change itself in the same
run by writing the inverse of the plan and verifying the snapshot before (``execute._compensate``); recover does
the same after an interruption. Nothing returns a change on the device when the Admin process or its management path
is lost after the write until recover runs; this is a property of the platform, not a safeguard.
"""
from __future__ import annotations

import hashlib
import json

from netops_admin import fortiadc, fortiadc_certificate_import, fortiadc_plan
from netops_admin.access import AccessError
from netops_admin.errors import Rejected, SnapshotRejected, SNAPSHOT_UNREADABLE

COMPENSATING = True
AUDIT_RULES = False
FIRING_OBSERVED = True
RETURN_MECHANISM = "compensating write of the inverse in the same run (no on-device timer)"
SNAPSHOT_QUERIES = ("show load-balance pool", "show load-balance virtual-server", "show load-balance real-server",
                    "show system admin")
STATUS_QUERY = "get system status"
CERT_GROUP_QUERY = "show full-configuration " + fortiadc.CERT_GROUP
CERT_NAMES_QUERY = "get " + fortiadc.CERT_TABLE
AUDIT_NOT_RUN = ("fortiadc.auditor", "not-evaluated",
                 "Admin runs no auditor rules on FortiADC: the rules need the exported full configuration and its"
                 " snapshot context (auditor run --platform fortiadc)")


class NotRead(Exception):
    """A value Admin does not read on FortiADC."""


def prompt_spec(hostname: str):
    return fortiadc.prompt_spec(hostname)


def safeguard_label(change_id: str) -> str:
    return "compensation-%s" % change_id[:12]


def snapshot(access) -> str:
    firmware = fortiadc_plan.firmware_of(access.query(STATUS_QUERY))
    parts = [fortiadc_plan.HEADER + firmware]
    for command in SNAPSHOT_QUERIES:
        parts.append(fortiadc_plan.listing(access.query(command), command))
    return "\n".join(parts) + "\n"


def with_certificates(access, text: str, table: str) -> str:
    if not getattr(getattr(access, "device", None), "fortiadc_https_sha256", None):
        return text
    try:
        if table in (fortiadc.CERT_GROUP, fortiadc.CERT_MEMBER):
            cert_groups, _ = _certificate_groups(access.query(CERT_GROUP_QUERY))
            text += cert_groups + "\n"
        if table in (fortiadc.CERT_TABLE, fortiadc.CERT_MEMBER):
            names = fortiadc.certificate_names(access.query(CERT_NAMES_QUERY))
            text += "\n".join(["config " + fortiadc.CERT_TABLE,
                               *(f'  edit "{name}"\n  next' for name in sorted(names)
                                 if fortiadc.CERT_NAME.fullmatch(name)), "end", ""])
    except (ValueError, OSError, AccessError, Rejected) as exc:
        code = "fortiadc_certificate_read_timeout" if _timeout(exc) else "fortiadc_certificate_unreadable"
        failure = SnapshotRejected(["could not verify the certificate configuration"], SNAPSHOT_UNREADABLE)
        failure.reason_codes = [code]
        raise failure from None
    return text


def _timeout(error):
    return isinstance(error, TimeoutError) or "timed out" in str(error).lower()


def _certificate_groups(raw):
    from netops_core import prompt

    raw = fortiadc.PAGER.sub("", raw)
    if "--More--" in raw or "\ufffd" in raw or fortiadc.cli_error(raw):
        raise ValueError("incomplete certificate groups")
    cleaned = prompt.cleaned(raw.replace("\r\n", "\n"), prompt.PLATFORM_FORTIADC).strip()
    if cleaned.startswith(CERT_GROUP_QUERY + "\n"):
        cleaned = cleaned.removeprefix(CERT_GROUP_QUERY + "\n").strip()
    parsed = fortiadc_plan.parse_listing(cleaned)
    if parsed.sections != [fortiadc.CERT_GROUP]:
        raise ValueError("certificate group section does not match")
    return cleaned, parsed


def _certificate_prechecks(access, device, plan, snapshot):
    group, _ = fortiadc_plan.split_key(plan["key"])
    before = plan["predicted"]["before"]
    after = plan["predicted"]["after"]
    if group.casefold() in {"local_cert_group", "http2_cert_group"}:
        raise Rejected(["the built-in certificate group is protected"],
                       reason_codes=["fortiadc_certificate_protected"])
    _refuse_protected(device, "certificate group member", plan["key"],
                      [group, before["local-cert"], after["local-cert"]],
                      reason_codes=["fortiadc_certificate_protected"])
    if observe(access, plan) != before:
        raise Rejected(["the check account did not confirm the current certificate reference"],
                       reason_codes=["fortiadc_certificate_unreadable"])

    protected = getattr(device, "protected", None) or {}
    profiles = protected.get("load-balance client-ssl-profile", ())
    virtual_servers = protected.get("load-balance virtual-server", ())
    if profiles or virtual_servers:
        clients = {name.casefold() for name in profiles}
        servers = [attributes for name, attributes in snapshot.virtual_servers().items()
                   if name.casefold() in {server.casefold() for server in virtual_servers}]
        if virtual_servers and len(servers) != len(set(virtual_servers)):
            raise Rejected(["the affected protected virtual servers cannot be verified"],
                           reason_codes=["fortiadc_certificate_unreadable"])
        clients.update(attributes.get("client-ssl-profile", "LB_CLIENT_SSL_PROF_DEFAULT").casefold()
                       for attributes in servers)
        try:
            with fortiadc_certificate_import.certificate_https(device, access.credential) as session:
                payload = session.read("load_balance_client_ssl_profile", vdom="global")
            if not isinstance(payload, list) or not all(
                    isinstance(entry, dict) and isinstance(entry.get("mkey"), str)
                    and isinstance(entry.get("local_certificate_group"), str) for entry in payload):
                raise ValueError("client SSL profiles are incomplete")
            related = {entry["mkey"].casefold() for entry in payload
                       if entry["local_certificate_group"].casefold() == group.casefold()}
            known = {entry["mkey"].casefold() for entry in payload}
            if not clients - {"none"} <= known:
                raise ValueError("protected client SSL profiles are incomplete")
        except (OSError, ValueError) as exc:
            code = "fortiadc_certificate_read_timeout" if _timeout(exc) or getattr(exc, "code", None) == "timeout" else "fortiadc_certificate_unreadable"
            raise Rejected(["the protected client SSL profile references cannot be read"],
                           reason_codes=[code]) from None
        if related & clients:
            raise Rejected(["a protected SSL profile or virtual server uses this certificate group"],
                           reason_codes=["fortiadc_certificate_protected"])
    plan["prechecks"].append("the independent check account verified the existing certificate reference")


def hostname(access, snapshot_text: str) -> str:
    return fortiadc._hostname(access)


def accounts_check(access, device, snapshot_text) -> str:
    admins = fortiadc_plan.load(snapshot_text, None).admins()
    visible = sorted(admins)
    expected = sorted(device.accounts) if device.accounts else sorted(
        {access.credential.login, access.check_credential.login})
    if visible != expected:
        parts = [label + ": " + ", ".join(names) for label, names in
                 (("not configured", sorted(set(visible) - set(expected))),
                  ("not visible", sorted(set(expected) - set(visible)))) if names]
        raise Rejected(["the write account sees other administrators than the configured ones: " + "; ".join(parts)])
    kept = {name: {field: value for field, value in fields.items() if field in fortiadc_plan.ADMIN_FIELDS}
            for name, fields in admins.items()}
    return hashlib.sha256(json.dumps(kept, sort_keys=True).encode("utf-8")).hexdigest()


def prechecks(access, device, snapshot_text, spec) -> list:
    return []


verify_ha_sync = fortiadc.verify_ha_sync


def ports(access, table):
    return None


def leftovers(access) -> list:
    return []


def _require_clear_unprotected(protected, keys):
    if any(key.casefold() in protected for key in keys):
        raise Rejected(["clear affects a protected FortiADC target"], reason_codes=["clear_protected_target"])


def clear_prechecks(access, device, spec, target, snapshot_text):
    snapshot = fortiadc_plan.load(snapshot_text, None)
    servers = snapshot.virtual_servers()
    if target.key not in servers:
        raise Rejected(["the FortiADC virtual server does not exist"], reason_codes=["clear_invalid_target"])
    protected = {key.casefold() for keys in device.protected.values() for key in keys}
    _require_clear_unprotected(protected, (target.key, target.source_ip or ""))
    if (target.table != fortiadc.WAF_BLOCK_IP
            and servers[target.key].get("type", "l4-load-balance") != "l4-load-balance"):
        raise Rejected(["FortiADC session and persistence clear requires a Layer 4 virtual server"],
                       reason_codes=["clear_invalid_target"])
    observed = observe_clear(access, spec, target)
    if target.source_ip is None:
        _require_clear_unprotected(protected, (entry[0] for entry in observed["entries"]))
    return snapshot.firmware, observed


def _clear_filter_is(read, target, *, selected=False):
    return fortiadc.clear_filter(read(target.show), target.show) == target.filter_fields(selected=selected)


def _clear_scope_unverified():
    return Rejected(["the FortiADC runtime filter or entries do not match the requested clear scope"],
                    reason_codes=["clear_scope_unverified"])


def _clear_readback_unreadable():
    return Rejected(["the FortiADC runtime table or filter could not be read completely"],
                    reason_codes=["clear_readback_unreadable"])


def _read_clear(read, target):
    try:
        if not _clear_filter_is(read, target):
            raise _clear_scope_unverified()
        rows = fortiadc.clear_entries(target, read(target.listing))
        idle = _clear_filter_is(read, target)
    except Rejected:
        raise
    except Exception:
        raise _clear_readback_unreadable() from None
    if not idle:
        raise _clear_scope_unverified()
    return fortiadc.clear_scope(target, rows)


def _with_clear_cli(access, spec, operation):
    anchor = spec.anchor.decode("ascii")
    return access.with_interactive_reader(spec, lambda read: operation(
        lambda command: read(command).removesuffix(anchor)))


def observe_clear(access, spec, target):
    # FortiADC 7.6.7 restricts SLB diagnostics to the write account.
    # The held CLI must prove the runtime filter is idle on every read.
    try:
        return _with_clear_cli(access, spec, lambda read: _read_clear(read, target))
    except Rejected:
        raise
    except Exception:
        raise _clear_readback_unreadable() from None


def readback_clear(access, spec, target, expected, sleep):
    observed = observe_clear(access, spec, target)
    if target.table == fortiadc.WAF_BLOCK_IP:
        # FortiADC-KVM 7.6.7 still listed the released block at 23 s and dropped the row by 38 s.
        # Allow up to 60 s of refresh time and require a complete listing without the target.
        for _ in range(6):
            if observed == expected:
                break
            sleep(10)
            observed = observe_clear(access, spec, target)
    return observed


def write_clear(access, spec, target, plan):
    def run(read):
        if _read_clear(read, target) != plan["predicted"]["before"]:
            raise _clear_scope_unverified()
        if target.table == fortiadc.WAF_BLOCK_IP:
            command, = plan["commands"]
            fortiadc.clear_body(read(command), command)
            return
        select, clear, reset = plan["commands"]
        # SLB diagnostic filters are shared between logins. Require an idle filter, verify the entire
        # selection immediately before clearing, and reset only the selection this operation installed.
        try:
            fortiadc.clear_body(read(select), select)
            if not _clear_filter_is(read, target, selected=True):
                raise _clear_scope_unverified()
            rows = fortiadc.clear_entries(target, read(target.listing))
            selected = fortiadc.clear_scope(target, rows)
            if (len(rows) != len(selected["entries"]) or selected != plan["predicted"]["before"]
                    or not _clear_filter_is(read, target, selected=True)):
                raise _clear_scope_unverified()
            fortiadc.clear_body(read(clear), clear)
        finally:
            if _clear_filter_is(read, target, selected=True):
                fortiadc.clear_body(read(reset), reset)
            if not _clear_filter_is(read, target):
                raise ValueError("FortiADC clear filter cleanup could not be verified")

    _with_clear_cli(access, spec, run)


def _dynamic_pool(attributes) -> bool:
    return bool(attributes.get("content-routing", "disable") != "disable" or attributes.get("schedule-pool-list"))


def _status(attributes):
    status = attributes.get("status", fortiadc.DEFAULT_STATUS)
    if status not in fortiadc.STATUSES:
        raise Rejected(["a server or pool member reports an unknown status"])
    return status


def _enabled_members(snapshot, pool, excluded=None) -> set:
    servers = snapshot.real_servers()
    candidates = set()
    for number, entry in snapshot.pool_members(pool).items():
        real = entry.attributes.get("real-server")
        if number == excluded or _status(entry.attributes) != "enable":
            continue
        if real not in servers or fortiadc.MEMBER.fullmatch(number) is None:
            raise Rejected(["pool %s lists an invalid member or a missing real server" % pool])
        if _status(servers[real]) == "enable":
            candidates.add(int(number))
    return candidates


def _require_health(access, vs, pool, candidates):
    health = fortiadc.read_health(access, vs, pool)
    if candidates - health.keys():
        raise Rejected(["vs_stat did not report all enabled candidates for virtual server %s" % vs])
    if not any(health[number] for number in candidates):
        raise _outage(vs)


def _outage(vs) -> Rejected:
    # 1.0.12 adc pool members r2 (review finding 1): losing the last healthy member is a service outage of the virtual server
    return Rejected(["the change would leave virtual server %s without a healthy enabled member (service outage:"
                     " the virtual server would not serve its clients)" % vs], reason_codes=["no_healthy_member"],
                    reason_details=[{"code": "no_healthy_member", "virtual_server": vs, "service_outage": True}])


def _refuse_protected(device, kind, key, names, *, reason_codes=None):
    # 1.0.12 adc pool members r2 (review finding 2): engine.build_plan checks only the key of the changed object. A status or
    # address of a real server, a pool member or a virtual server also changes the pools, members and virtual servers
    # it serves; a protected name of any table among them refuses the change (as engine._protected_references).
    guarded = {name.casefold() for names in (getattr(device, "protected", None) or {}).values() for name in names}
    hits = [name for name in names if name.casefold() in guarded]
    if hits:
        raise Rejected(["the change of %s %s affects protected object %s" % (kind, key, ", ".join(hits))],
                       reason_codes=reason_codes)


# 1.0.12 adc pool members r2: a virtual server with content routing or schedule names its pools in these entries; vs_stat names the
# stored load-balance-pool, which show hides when schedule-list is enabled (measured 7.6.7 build0676, verification)
CONTENT_ROUTING = "load-balance content-routing"
SCHEDULE_POOL = "load-balance schedule-pool"
DYNAMIC_ENTRIES = (("content-routing-list", CONTENT_ROUTING), ("schedule-pool-list", SCHEDULE_POOL))
POOL_FIELDS = {"load-balance-pool", "schedule-list", "schedule-pool-list"}


def _entry_pools(access, section, name) -> set | None:
    """Pools selected by one content-routing or schedule-pool entry, None when they cannot be read."""
    if fortiadc.POOL.fullmatch(name) is None:
        return None
    command = "show full-configuration %s %s" % (section, name)
    try:
        lines = fortiadc_plan.listing(access.query(command), command).split("\n")
        stack, fields, entries = [], {}, []
        for raw in lines:
            words = fortiadc._words(raw)
            if not words:
                continue
            if words[0] == "config" and len(words) > 1:
                block = " ".join(words[1:])
                if (not stack and (block != section or entries)) or (stack and stack[-1] != "edit"):
                    return None
                stack.append("config")
            elif words[0] == "edit" and len(words) == 2 and stack and stack[-1] == "config":
                stack.append("edit")
                if len(stack) == 2:
                    entries.append(words[1])
            elif words[0] in ("next", "end") and len(words) == 1:
                if not stack or stack.pop() != ("edit" if words[0] == "next" else "config"):
                    return None
            elif (words[0] == "set" and len(words) > 2 or words[0] == "unset" and len(words) == 2
                  ) and stack and stack[-1] == "edit":
                if len(stack) == 2 and words[1] in POOL_FIELDS:
                    if words[1] in fields:
                        return None
                    fields[words[1]] = words[2:]
            else:
                return None
    except Exception:
        return None
    if stack or entries != [name]:
        return None
    schedule = fields.get("schedule-list", ["disable"])
    if section == CONTENT_ROUTING and schedule == ["enable"]:
        names = fields.get("schedule-pool-list")
        if not names:
            return None
        pools = set()
        for entry in names:
            selected = _entry_pools(access, SCHEDULE_POOL, entry)
            if selected is None:
                return None
            pools.update(selected)
        return pools
    pool = fields.get("load-balance-pool", [])
    if schedule != ["disable"] or len(pool) != 1 or fortiadc.POOL.fullmatch(pool[0]) is None:
        return None
    return {pool[0]}


def _stored_pools(access, vs) -> set | None:
    if fortiadc.POOL.fullmatch(vs) is None:
        return None
    try:
        text = access.diagnose_query(fortiadc.vs_stat_command(vs))
    except Exception:
        return None
    text = text.replace("\r", "")
    headers = list(fortiadc.RUNTIME_VS.finditer(text))
    if fortiadc.HEALTH_REFUSALS.search(text) or len(headers) != 1 or headers[0].group(1) != vs:
        return None
    body = text[headers[0].end():]
    lines = [bare for line in body.splitlines() if (bare := fortiadc_plan.PROMPTS.sub("", line).strip())]
    pools = fortiadc.RUNTIME_POOL.findall(body)
    pool_rows = sum(line.startswith("real-server-pool:") for line in lines)
    empty = "no rs for this vs"
    if pools and len(pools) == pool_rows and empty not in lines and all(fortiadc.POOL.fullmatch(pool) for pool in pools):
        return set(pools)
    if not pool_rows and lines and lines[-1] == empty and lines.count(empty) == 1 and not fortiadc.MEMBER_ID.search(body):
        return set()
    return None


def _dynamic_pools(access, vs, attributes) -> set:
    """Every pool a content-routing or schedule virtual server may select; refused when one cannot be read."""
    def refuse(why):
        return Rejected(["the virtual server %s selects pools by content routing or schedule; %s" % (vs, why)])
    names = {field: attributes.get(field, "").split() for field, _section in DYNAMIC_ENTRIES}
    if attributes.get("content-routing", "disable") != "disable" and not names["content-routing-list"]:
        raise refuse("it names no content-routing entry")
    pools = _stored_pools(access, vs)
    if pools is None:
        raise refuse("its stored pool cannot be read from vs_stat")
    for field, section in DYNAMIC_ENTRIES:
        for name in names[field]:
            selected = _entry_pools(access, section, name)
            if selected is None:
                raise refuse("the pool of %s %s cannot be read" % (section, name))
            pools.update(selected)
    return pools


def _virtual_server_precheck(access, device, snapshot, plan):
    name = plan["key"]
    attributes = snapshot.virtual_servers()[name]
    pool = attributes.get("load-balance-pool")
    if _dynamic_pool(attributes) or pool not in snapshot.pools or not snapshot.pool_members(pool):
        raise Rejected(["virtual server %s has no statically verifiable pool with members" % name])
    _refuse_protected(device, "virtual server", name,
                      [pool] + sorted("%s:%s" % (pool, number) for number in snapshot.pool_members(pool)))
    before, after = plan["predicted"]["before"], plan["predicted"]["after"]
    if _status(before) == "enable":
        fortiadc.read_health(access, name, pool)
        plan["prechecks"].append("current runtime of virtual server %s verified (vs_stat, pool %s)" % (name, pool))
    if _status(after) == "enable" and not _enabled_members(snapshot, pool):
        raise Rejected(["virtual server %s has no enabled backend in pool %s" % (name, pool)],
                       reason_codes=["no_healthy_member"])
    # 1.0.12 adc pool members r2 (review finding 1): maintain or disable of a serving virtual server stops the service
    outage = _status(before) == "enable" and _status(after) in fortiadc_plan.INACTIVE
    plan["service_outage"] = [name] if outage else []
    if outage:
        plan["prechecks"].append("SERVICE OUTAGE: virtual server %s stops serving its clients while its status is %s;"
                                 " the service is unavailable until the status is enable again (undo)"
                                 % (name, _status(after)))
    plan["prechecks"].append("virtual server %s uses configured pool %s" % (name, pool))


def _real_server_precheck(access, device, snapshot, plan, undo=False):
    if plan["op"] != "update":
        return
    name = plan["key"]
    members = snapshot.references(fortiadc_plan.REAL_SERVERS, name)
    pools = {fortiadc_plan.split_key(member)[0] for member in members}
    servers = sorted(snapshot.virtual_servers().items())
    _refuse_protected(device, "real server", name, members + sorted(pools) + [
        vs for vs, attributes in servers if attributes.get("load-balance-pool") in pools])
    users = []
    before, after = plan["predicted"]["before"], plan["predicted"]["after"]
    address_changed = any(before.get(field) != after.get(field) for field in ("ip", "fqdn"))
    # An address undo can preserve the backend's status or restore it to service without another healthy member.
    restores_address = undo and address_changed and (_status(before) == _status(after) or _status(after) == "enable")
    if pools:
        for vs, attributes in servers:
            if _dynamic_pool(attributes):
                # 1.0.12 adc pool members r2: refused only when the virtual server may select a pool of this real server
                selected = _dynamic_pools(access, vs, attributes)
                if selected & pools:
                    raise Rejected(["the virtual server %s selects pools by content routing or schedule; "
                                    "the real server use cannot be evaluated" % vs])
                plan["prechecks"].append("virtual server %s selects pools %s (content routing or schedule, vs_stat);"
                                         " real server %s is not in them" % (vs, ", ".join(sorted(selected)), name))
                continue
            pool = attributes.get("load-balance-pool")
            if pool not in pools:
                continue
            users.append(vs)
            if _status(attributes) != "enable":
                plan["prechecks"].append("virtual server %s is administratively inactive" % vs)
                continue
            if restores_address:
                plan["prechecks"].append("undo restores the previous address of real server %s in %s; no member"
                                         " health is required" % (name, pool))
                continue
            candidates = _enabled_members(snapshot, pool)
            # A change of address invalidates health measured for the previous endpoint.
            if address_changed or _status(after) != "enable":
                candidates -= {int(number) for number, entry in snapshot.pool_members(pool).items()
                               if entry.attributes.get("real-server") == name and fortiadc.MEMBER.fullmatch(number)}
            _require_health(access, vs, pool, candidates)
            plan["prechecks"].append("virtual server %s keeps a healthy enabled member in %s (vs_stat)" % (vs, pool))
    plan["prechecks"].append("virtual servers using real server %s: %s" % (name, ", ".join(users) or "none"))


def plan_prechecks(access, device, plan, snapshot_text="", undo=False) -> list:
    snapshot = fortiadc_plan.load(snapshot_text, None)
    if plan["table"] == fortiadc.CERT_MEMBER:
        _certificate_prechecks(access, device, plan, snapshot)
        return []
    if plan["table"] == fortiadc_plan.VIRTUAL_SERVERS:
        _virtual_server_precheck(access, device, snapshot, plan)
        return []
    if plan["table"] == fortiadc_plan.REAL_SERVERS:
        _real_server_precheck(access, device, snapshot, plan, undo)
        return []
    pool, member = fortiadc_plan.split_key(plan["key"])
    before_state, after_state = plan["predicted"]["before"], plan["predicted"]["after"]
    before = _status(before_state) if before_state is not None else None
    after = _status(after_state) if after_state is not None else None
    port_changed = fortiadc_plan._port(before_state) != fortiadc_plan._port(after_state)
    needs_health = plan["op"] == "update" and (before != after or port_changed and after == "enable")
    servers = sorted(snapshot.virtual_servers().items())
    users = [name for name, attributes in servers if attributes.get("load-balance-pool") == pool]
    _refuse_protected(device, "pool member", plan["key"], [pool] + users)
    guarded = {name.casefold() for names in (getattr(device, "protected", None) or {}).values() for name in names}
    for name, attributes in servers:
        if not _dynamic_pool(attributes) or not (needs_health or name.casefold() in guarded):
            continue
        if pool not in _dynamic_pools(access, name, attributes):
            continue
        _refuse_protected(device, "pool member", plan["key"], [name])
        if needs_health:
            raise Rejected(["the virtual server %s selects pools by content routing or schedule; "
                            "the pool use cannot be evaluated" % name])
    plan["prechecks"].append("virtual servers using pool %s: %s" % (pool, ", ".join(users) or "none"))
    if not needs_health:
        return []
    if not users:
        raise Rejected(["no virtual server uses the pool; the effect of the change cannot be evaluated"])
    statuses = {number: entry.attributes.get("status", "enable")
                for number, entry in snapshot.pool_members(pool).items()}
    statuses[member] = after
    for vs in users:
        if port_changed:
            candidates = _enabled_members(snapshot, pool, excluded=member)
            _require_health(access, vs, pool, candidates)
            continue
        health = fortiadc.read_health(access, vs)
        if not any(state == "enable" and health.get(int(number), False) for number, state in statuses.items()):
            raise _outage(vs)
    plan["prechecks"].append("every virtual server using the pool keeps a healthy enabled member (vs_stat)")
    return []


def install_safeguard(access, record, plan, device, spec) -> list:
    return []


def remove_safeguard(access, record, spec) -> bool:
    return True


def safeguard_absent(access, record) -> bool:
    return True


def remove_remaining(access, record, spec) -> bool:
    return True


def safeguard_disarmed(access, record) -> bool:
    return False


def safeguard_fired(access, record) -> bool:
    return False


def persist(access, spec) -> bool:
    # FortiADC keeps a CLI change once its block ends; there is no separate save
    return False


def observe(access, plan):
    if plan["table"] == "system status":
        found = fortiadc.HOSTNAME_LINE.findall(access.check_query(STATUS_QUERY).replace("\r", ""))
        return {"hostname": found[0]} if len(found) == 1 else None
    table, key = plan["table"], plan["key"]
    if table == fortiadc.CERT_MEMBER:
        try:
            _, parsed = _certificate_groups(access.check_query(CERT_GROUP_QUERY))
            entry = parsed.entries(table).get(key)
            if entry is None or entry.unsupported:
                raise ValueError("certificate group member is not verifiable")
        except (ValueError, OSError, AccessError, Rejected) as exc:
            code = "fortiadc_certificate_read_timeout" if _timeout(exc) else "fortiadc_certificate_unreadable"
            raise Rejected(["the check account could not read the certificate reference"],
                           reason_codes=[code]) from None
    elif table in fortiadc_plan.SERVER_TABLES:
        command = "show " + table
        text = fortiadc_plan.listing(access.check_query(command), command)
        entries = fortiadc_plan.parse_listing(text).entries(table)
        if entries is None:
            raise Rejected(["the check account does not see %s" % table])
        entry = entries.get(key)
    else:
        pool, member = fortiadc_plan.split_key(key)
        command = fortiadc.show_command(pool)
        text = fortiadc_plan.listing(access.check_query(command), command)
        entry = _members(text, pool).get(member)
    if entry is None:
        return None
    if entry.unsupported:
        raise Rejected(["the check account sees configuration outside the profile: %s"
                        % ", ".join(sorted(entry.unsupported))])
    return dict(entry.attributes)


def _members(text: str, pool: str) -> dict:
    parsed = fortiadc_plan.parse_listing(text)
    if pool not in parsed.pools:
        raise Rejected(["the check account does not see pool %s" % pool])
    return parsed.pool_members(pool)


def foreign_sessions(access, device) -> int:
    raise NotRead("FortiADC administrator sessions are not read by Admin")
