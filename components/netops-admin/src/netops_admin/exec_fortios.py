from __future__ import annotations

import datetime
from dataclasses import dataclass

from netops_admin import fortios
from netops_admin.errors import Rejected


@dataclass(frozen=True)
class PromptSpec:
    anchor: bytes
    ends: tuple
    continuation: bytes | None
    error: object


def prompt_spec(hostname: str) -> PromptSpec:
    return PromptSpec(anchor=("\n%s" % hostname).encode("ascii"), ends=(b"$ ", b"# "),
                      continuation=b"\n> ", error=fortios.cli_error)


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
        raise Rejected(["the write account sees other administrators than the configured ones (%d accounts)"
                        % len(visible)])
    return fortios.admin_fingerprint(table, snapshot_text)


def prechecks(access, device, snapshot_text, spec) -> list:
    return []


def leftovers(access) -> list:
    return fortios.leftover_safeguards(access.query(fortios.QUERY_STITCHES))


def _answers(access, change_id: str) -> dict:
    return {kind: access.query(command) for kind, command in fortios.safeguard_queries(change_id).items()}


def install_safeguard(access, record, plan, device, spec) -> list:
    access.apply(fortios.render_safeguard(record["change_id"], plan["inverse"], record["safeguard"]["fire_at"]), spec)
    return fortios.safeguard_state(record["change_id"], _answers(access, record["change_id"]), plan["inverse"],
                                   record["safeguard"]["fire_at"])


def remove_safeguard(access, record, spec) -> bool:
    try:
        access.apply(fortios.render_safeguard_removal(record["change_id"]), spec)
    except Exception:
        pass
    return safeguard_absent(access, record)


def safeguard_absent(access, record) -> bool:
    try:
        return fortios.safeguard_absent(record["change_id"], _answers(access, record["change_id"]))
    except Exception:
        return False


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
