"""Plan and verify a separate, explicitly approved ExtremeXOS configuration save."""

import hashlib
import re

from netops_admin import exos
from netops_admin.errors import Rejected
from netops_core import tested

TABLE = "startup-config"
KIND = "exos-save"
COMMAND = "save configuration"
VERSIONS = ("33.6.1.14", "33.7.1.6")
EVIDENCE = ("ExtremeXOS overwrites the selected startup configuration with the entire running configuration. "
            "The previous saved configuration cannot be restored by Admin undo.")
SELECTED = re.compile(r"^Config Selected:[^\S\n]+([A-Za-z0-9][A-Za-z0-9_.-]{0,63})\.cfg\s*$", re.MULTILINE)
PREVIEW_LIMIT = 100
RUNNING_HEADER = re.compile(r"^\+\+\+ Running Configuration\s+\w{3} \w{3} +\d{1,2} \d\d:\d\d:\d\d \d{4}\s*$")
# Match credential-bearing syntax, leaving ordinary commands and key references visible.
# Patterns operate on the stripped CLI line but do not normalize its internal spacing.
SECRET_LINES = tuple((kind, re.compile(pattern, re.IGNORECASE)) for kind, pattern in (
    ("snmp community", r"^configure\s+snmp(?:v3)?\s+(?:add|delete)\s+"
                       r"(?:community\s+\S|trapreceiver\s+\S+\s+community\s+\S)"),
    ("snmpv3 key", r"^configure\s+snmpv3\s+add\s+user\s+.+?\s+authentication\s+(?:md5|sha\d*)\s+\S"),
    ("radius secret", r"^configure\s+radius(?:-accounting)?\s+(?:.+?\s+)?shared-secret\s+\S"),
    ("tacacs secret", r"^configure\s+tacacs(?:-accounting)?\s+(?:.+?\s+)?shared-secret\s+\S"),
    ("password", r"^(?:create\s+account\s+(?:admin|user|lawful-intercept)\s+\S+\s+\S"
                 r"|create\s+netlogin\s+local-user\s+\S+\s+\S"
                 r"|configure\s+account\s+\S+\s+encrypted\s+\S)"),
    ("password", r"^configure\s+(?:bgp|isis)\s+.+?\s+(?:password|(?:area|domain)-password)\s+(?!none\s*$)\S"),
    ("key", r"^(?:create\s+ntp\s+key\s+\S+\s+(?:md5|sha256)\s+\S"
            r"|(?:create|configure)\s+macsec\s+connectivity-association\s+.+?\s+cak\s+\S"
            r"|configure\s+ospf\s+.+?\s+authentication\s+(?:encrypted\s+)?(?:md5\s+\S+|simple-password)\s+\S)"),
    ("credential", r"^(?:create|configure)\s+\S+\s+(?:[^\"\s]+\s+|\"[^\"]*\"\s+)*?"
                   r"(?:shared-secret|pre-shared-key|passphrase|private-key|localized-key|encrypted)\s+\S"),
))


def _reject(code, message):
    return Rejected([message], reason_codes=[code])


def validate(platform, request):
    if (platform != "exos" or request.table != TABLE or request.key != TABLE
            or request.endpoint_impact is not None or request.changes):
        raise _reject("action_unsupported", "ExtremeXOS save requires startup-config for both table and key, with empty changes")


def _digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def _read(access, command, *, check=False):
    from netops_admin.access import AccessError

    reader = access.check_query_status if check else access.query_status
    try:
        status, text = reader(command)
    except AccessError as exc:
        if "timeout" in str(exc).casefold() or "timed out" in str(exc).casefold():
            raise _reject("exos_save_read_timeout", "ExtremeXOS save read timed out") from None
        code = "exos_save_check_denied" if check else "exos_save_diff_unreadable"
        raise _reject(code, "ExtremeXOS save state could not be read") from None
    if status or "\ufffd" in text or exos.cli_error(text) is not None:
        code = "exos_save_check_denied" if check else "exos_save_diff_unreadable"
        raise _reject(code, "ExtremeXOS save state could not be read")
    return text


def _selected(access, *, check=False):
    fields = SELECTED.findall(_read(access, "show switch", check=check))
    if len(fields) != 1:
        code = "exos_save_check_denied" if check else "exos_save_diff_unreadable"
        raise _reject(code, "The selected ExtremeXOS startup configuration is unclear")
    return fields[0]


def _diff(access, selected, *, check=False):
    text = _read(access, "show configuration difference " + selected, check=check).strip("\r\n")
    # Each SSH query timestamps the running-file header independently. Keep all configuration and hunk lines.
    return "\n".join("+++ Running Configuration" if RUNNING_HEADER.fullmatch(line) else line
                     for line in text.splitlines())


def _preview_lines(diff):
    lines = []
    for line in diff.splitlines():
        if line[:1] not in ("+", "-") or line.startswith(("--- ", "+++ ")):
            continue
        value = line[1:].strip()
        kind = next((kind for kind, pattern in SECRET_LINES if pattern.search(value)), None)
        lines.append(line[0] + " " + (f"[redacted: {kind}]" if kind else value))
    if diff.strip() and not lines:
        raise _reject("exos_save_diff_unreadable", "The selected ExtremeXOS configuration diff is unrecognized")
    return lines[:PREVIEW_LIMIT], len(lines)


def _read_pending(access, spec):
    from netops_admin.access import AccessError

    selected = _selected(access)
    diff = _diff(access, selected)
    lines, count = _preview_lines(diff)
    try:
        dirty = b"*" in access.login_prefix(spec)
    except AccessError as exc:
        code = ("exos_save_read_timeout" if "timed out" in str(exc).casefold() or "timeout" in str(exc).casefold()
                else "exos_save_diff_unreadable")
        raise _reject(code, "The ExtremeXOS unsaved indicator could not be read") from None
    before = {"selected": selected + ".cfg", "prompt_dirty": dirty, "unsaved_changes": bool(diff.strip()),
              "changed_lines": count, "diff": lines}
    return selected, diff, before


def _independent(access, selected, diff):
    if _selected(access, check=True) != selected or _diff(access, selected, check=True) != diff:
        raise _reject("exos_save_check_denied", "The check account could not independently confirm the selected file and its diff")


def prepare(access, device, request, snapshot, spec):
    from netops_admin import engine

    selected, diff, before = _read_pending(access, spec)
    support = tested.support("exos", device.firmware, VERSIONS, function="standalone save")
    plan = {
        "format": engine.PLAN_FORMAT, "admin_version": engine.__version__, "platform": "exos",
        "device": device.name, "firmware": device.firmware, "firmware_support": support,
        "table": TABLE, "op": "save", "key": TABLE, "request_id": request.request_id,
        "request_sha256": request.fingerprint(), "reason_characters": len(request.reason),
        "user_request_characters": len(request.user_request), "snapshot_sha256": _digest(snapshot),
        "rest_sha256": _digest(diff), "prechecks": [EVIDENCE], "commands": [COMMAND], "inverse": [],
        "predicted": {"before": before, "after": {"selected": selected + ".cfg", "unsaved_changes": False}},
        "ignored_attributes": [], "inverse_identity_changes": [], "rollback_evidence": EVIDENCE,
        "safeguard_id": None,
    }
    if warning := tested.warning(support):
        plan["prechecks"].append(warning["message"])
    plan["plan_sha256"] = engine.plan_digest(plan)
    try:
        _independent(access, selected, diff)
    except Rejected as exc:
        return plan, exc
    return plan, None


def prewrite(access, spec, plan):
    selected, diff, before = _read_pending(access, spec)
    if (before != plan["predicted"]["before"] or _digest(diff) != plan["rest_sha256"]
            or _digest(access.snapshot()) != plan["snapshot_sha256"]):
        raise _reject("plan_changed", "The ExtremeXOS running or saved configuration changed since the approved preview")
    _independent(access, selected, diff)


def readback(access, spec, plan):
    selected = plan["predicted"]["after"]["selected"].removesuffix(".cfg")
    _independent(access, selected, "")
    if (b"*" in access.login_prefix(spec) or _selected(access) != selected
            or _diff(access, selected).strip() or _digest(access.snapshot()) != plan["snapshot_sha256"]):
        raise _reject("exos_save_diff_mismatch", "ExtremeXOS save did not produce the expected clean state")
    return plan["predicted"]["after"]
