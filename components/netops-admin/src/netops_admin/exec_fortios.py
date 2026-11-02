from __future__ import annotations

import datetime
from dataclasses import dataclass

from netops_admin import fortios
from netops_admin.errors import Rejected
from netops_admin.profiles import find_profile


@dataclass(frozen=True)
class PromptSpec:
    anchor: bytes
    ends: tuple
    continuation: bytes | None
    error: object
    typed: object = None


def prompt_spec(hostname: str) -> PromptSpec:
    return PromptSpec(anchor=("\n%s" % hostname).encode("ascii"), ends=(b"$ ", b"# "),
                      continuation=b"\n> ", error=fortios.cli_error, typed=fortios.typed)


def safeguard_label(change_id: str) -> str:
    return fortios.safeguard_names(change_id)["stitch"]


def hostname(access, snapshot_text: str) -> str:
    node = fortios.Snapshot(snapshot_text).root.sub.get("system global")
    name = None if node is None else node.value("hostname")
    if not name:
        raise Rejected(["the snapshot does not name the device hostname"])
    return name


def clock(access) -> datetime.datetime:
    return datetime.datetime.strptime(fortios.clock_text(access.query(fortios.QUERY_CLOCK)), fortios.CLOCK_FORMAT)


def accounts_check(access, device, snapshot_text) -> str:
    table = access.query(fortios.QUERY_ADMINS)
    visible = fortios.visible_admins(table)
    expected = sorted(device.accounts) if device.accounts else [access.credential.login]
    if visible != expected:
        parts = [label + ": " + ", ".join(names) for label, names in
                 (("not configured", sorted(set(visible) - set(expected))),
                  ("not visible", sorted(set(expected) - set(visible)))) if names]
        raise Rejected(["the write account sees other administrators than the configured ones: " + "; ".join(parts)])
    return fortios.admin_fingerprint(table, snapshot_text, immutable_profiles=("super_admin",))


def prechecks(access, device, snapshot_text, spec) -> list:
    return []


def _webhook(plan) -> bool:
    return fortios.webhook_firmware((plan or {}).get("firmware"))


def _request(plan, device) -> dict:
    profile = find_profile("fortios", plan["table"], plan["firmware"])
    return fortios.rest_inverse(profile, plan["op"], plan["key"], plan["inverse"], device.address)


def _webhook_preflight(access, device, snapshot_text) -> tuple:
    snapshot = fortios.Snapshot(snapshot_text)
    reasons = fortios.webhook_prechecks(snapshot, device.address, getattr(access.credential, "kind", None))
    login = getattr(access.credential, "login", None)
    reasons.extend(fortios.write_permission(login, fortios.write_account_profile(snapshot, login)))
    port = None
    try:
        port = fortios.admin_sport(access.query(fortios.QUERY_GLOBAL))
    except Rejected as exc:
        reasons.extend(exc.reasons)
    holder = next((name for name, entry in (snapshot.entries("system interface") or {}).items()
                   if list(entry.values("ip"))[:1] == [device.address]), None)
    return reasons, port, holder


def plan_prechecks(access, device, plan, snapshot_text="") -> list:
    if not _webhook(plan):
        return []
    reasons = _webhook_preflight(access, device, snapshot_text)[0]
    try:
        _request(plan, device)
    except Rejected as exc:
        reasons.extend(exc.reasons)
    return reasons


def safeguard_preflight(access, device, snapshot_text, firmware) -> str:
    if not fortios.webhook_firmware(firmware):
        return "not used: firmware %s keeps the cli-script safeguard" % firmware
    reasons, port, holder = _webhook_preflight(access, device, snapshot_text)
    if reasons:
        raise Rejected(reasons)
    return ("the safeguard webhook can call %s on HTTPS port %s through interface %s; preview and apply check"
            " the table and the request" % (device.address, port, holder))


def ports(access, table: str):
    return None


def leftovers(access) -> list:
    return fortios.leftover_safeguards(access.query(fortios.QUERY_STITCHES))


def _answers(access, change_id: str) -> dict:
    return {kind: access.query(command) for kind, command in fortios.safeguard_queries(change_id).items()}


def _webhook_answers(access, change_id: str, parts=fortios.WEBHOOK_PARTS) -> dict:
    queries = fortios.webhook_queries(change_id)
    return {part: access.query(queries[part]) for part in parts}


def _install_webhook(access, record, plan, device, spec) -> list:
    change_id, fire_at = record["change_id"], record["safeguard"]["fire_at"]
    request = _request(plan, device)
    port = fortios.admin_sport(access.query(fortios.QUERY_GLOBAL))
    access.apply(fortios.render_webhook_identity(change_id, device.address), spec)
    token = fortios.api_key(access.generate_api_key(fortios.render_key_request(change_id), spec))
    try:
        access.apply(fortios.render_webhook_safeguard(change_id, request, port, token, fire_at), spec)
    except Exception as exc:
        from netops_admin.access import AccessError

        if isinstance(exc, AccessError) and token in str(exc):
            raise AccessError(str(exc).replace(token, "<token>"), exc.accepted_lines) from None
        raise
    return fortios.webhook_state(change_id, _webhook_answers(access, change_id), request, port, token, fire_at,
                                 device.address)


def install_safeguard(access, record, plan, device, spec) -> list:
    if _webhook(plan):
        return _install_webhook(access, record, plan, device, spec)
    access.apply(fortios.render_safeguard(record["change_id"], plan["inverse"], record["safeguard"]["fire_at"]), spec)
    return fortios.safeguard_state(record["change_id"], _answers(access, record["change_id"]), plan["inverse"],
                                   record["safeguard"]["fire_at"])


def remove_safeguard(access, record, spec) -> bool:
    if _webhook(record.get("plan")):
        return remove_remaining(access, record, spec)
    try:
        access.apply(fortios.render_safeguard_removal(record["change_id"]), spec)
    except Exception:
        pass
    return safeguard_absent(access, record)


def safeguard_absent(access, record) -> bool:
    if _webhook(record.get("plan")):
        try:
            return fortios.webhook_absent(record["change_id"], _webhook_answers(access, record["change_id"]))
        except Exception:
            return False
    try:
        return fortios.safeguard_absent(record["change_id"], _answers(access, record["change_id"]))
    except Exception:
        return False


def _remove_webhook_parts(access, record, spec, parts) -> bool:
    change_id = record["change_id"]
    try:
        answers = _webhook_answers(access, change_id, parts)
        present = [part for part in parts if not fortios.webhook_absent(change_id, answers, (part,))]
        if present:
            access.apply(fortios.render_webhook_removal(change_id, present), spec)
    except Exception:
        pass
    try:
        return fortios.webhook_absent(change_id, _webhook_answers(access, change_id, parts), parts)
    except Exception:
        return False


def revoke_token(access, record, spec):
    if not _webhook(record.get("plan")):
        return None
    return _remove_webhook_parts(access, record, spec, ("user", "profile"))


def remove_remaining(access, record, spec) -> bool:
    if _webhook(record.get("plan")):
        return _remove_webhook_parts(access, record, spec, fortios.WEBHOOK_PARTS)
    names = fortios.safeguard_names(record["change_id"])
    try:
        answers = _answers(access, record["change_id"])
        parts = [part for part in fortios.SAFEGUARD_PARTS
                 if not fortios._entry_absent(answers[part], "system automation-" + part, names[part])]
        if parts:
            access.apply(fortios.render_safeguard_removal(record["change_id"], parts), spec)
    except Exception:
        pass
    return safeguard_absent(access, record)


def safeguard_disarmed(access, record) -> bool:
    names = fortios.safeguard_names(record["change_id"])
    try:
        answer = access.query(fortios.safeguard_queries(record["change_id"])["stitch"])
        return fortios._entry_absent(answer, "system automation-stitch", names["stitch"])
    except Exception:
        return False


FIRING_OBSERVED = False


def safeguard_fired(access, record) -> bool:
    return True


def persist(access, spec) -> bool:
    return False


def observe(access, plan):
    if plan["table"] == "system dhcp server/reserved-address":
        command = "show system dhcp server " + plan["key"].split(":")[0]
    else:
        command = 'show %s "%s"' % (plan["table"], plan["key"])
    answer = access.check_query(command)
    return fortios.shown_object(answer, plan["table"], plan["key"])


def foreign_sessions(access, device) -> int:
    own = {access.credential.login, access.check_credential.login}
    return fortios.foreign_sessions(access.query(fortios.QUERY_SESSIONS), own)
