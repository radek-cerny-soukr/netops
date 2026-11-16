"""FortiADC execution adapter of the common Admin engine (execute.ADAPTERS["fortiadc"]).

FortiADC-KVM 7.6.7 build0676 offers Admin no on-device timed return (task 306: no automation-stitch, scheduler or
cron in the CLI; the documented alert policy of type schedule with a CLI script action is not measured). The adapter
is therefore COMPENSATING: execute installs nothing on the device and returns an unverified change itself in the same
run by writing the inverse of the plan and verifying the snapshot before (``execute._compensate``); recover does
the same after an interruption. Nothing returns a change on the device when the Admin process or its management path
is lost after the write until recover runs; this is a property of the platform, not a safeguard.
"""
from __future__ import annotations

import hashlib
import json

from netops_admin import fortiadc, fortiadc_plan
from netops_admin.errors import Rejected

COMPENSATING = True
AUDIT_RULES = False
FIRING_OBSERVED = True
RETURN_MECHANISM = "compensating write of the inverse in the same run (no on-device timer)"
SNAPSHOT_QUERIES = ("show load-balance pool", "show load-balance virtual-server", "show load-balance real-server",
                    "show system admin")
STATUS_QUERY = "get system status"
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


def ports(access, table):
    return None


def leftovers(access) -> list:
    return []


def plan_prechecks(access, device, plan, snapshot_text="") -> list:
    pool, member = fortiadc_plan.split_key(plan["key"])
    snapshot = fortiadc_plan.load(snapshot_text, None)
    users = []
    for name, attributes in sorted(snapshot.virtual_servers().items()):
        selects = attributes.get("content-routing", "disable") != "disable" or attributes.get("schedule-pool-list")
        if attributes.get("load-balance-pool") == pool:
            users.append(name)
        if selects and plan["op"] == "update":
            raise Rejected(["the virtual server %s selects pools by content routing or schedule; "
                            "the pool use cannot be evaluated" % name])
    before = (plan["predicted"]["before"] or {}).get("status", "enable") if plan["predicted"]["before"] is not None else None
    after = (plan["predicted"]["after"] or {}).get("status", "enable") if plan["predicted"]["after"] is not None else None
    plan["prechecks"].append("virtual servers using pool %s: %s" % (pool, ", ".join(users) or "none"))
    if plan["op"] != "update" or before == after:
        return []
    if not users:
        raise Rejected(["no virtual server uses the pool; the effect of the change cannot be evaluated"])
    statuses = {number: entry.attributes.get("status", "enable")
                for number, entry in snapshot.pool_members(pool).items()}
    statuses[member] = after
    for vs in users:
        health = fortiadc.read_health(access, vs)
        if not any(state == "enable" and health.get(int(number), False) for number, state in statuses.items()):
            raise Rejected(["the change would leave virtual server %s without a healthy enabled member" % vs],
                           reason_codes=["no_healthy_member"])
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
    pool, member = fortiadc_plan.split_key(plan["key"])
    command = fortiadc.show_command(pool)
    text = fortiadc_plan.listing(access.check_query(command), command)
    members = _members(text, pool)
    entry = members.get(member)
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
