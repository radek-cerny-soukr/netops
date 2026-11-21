"""Preview and verify an irreversible EOS copy from running-config to startup-config."""
from __future__ import annotations

import hashlib
import re

from netops_admin import eos_services
from netops_admin.errors import Rejected

TABLE = "startup-config"
KIND = "eos-save"
COMMAND = "copy running-config startup-config"
DIFF_COMMAND = "show running-config diffs"
DIFF_HEADERS = ("--- flash:/startup-config", "+++ system:/running-config")
HUNK = re.compile(r"@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@")
HASH = re.compile(r"[0-9a-f]{64}")
NO_UNDO = "Saving overwrites startup-config. Admin has no undo for this operation."
# A diff can contain credentials anywhere, including context and free-form values. Expose only recognized
# credential-free statements. For all other lines the sign, line position and a fixed command label suffice.
SAFE_SWITCH_LINE = re.compile(
    r"(?:!|end|shutdown|no shutdown|interface (?:Ethernet|Management|Vlan|Loopback|Port-Channel)[0-9./]+"
    r"|vlan [0-9,\-]+|switchport (?:mode (?:access|trunk)|access vlan [0-9]+)"
    r"|(?:no )?(?:ip routing|ipv6 unicast-routing))"
)
SENSITIVE_LABELS = ("username", "enable", "snmp-server", "tacacs-server", "radius-server", "ntp authentication-key")


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _public_line(line):
    body = line[1:]
    statement = " ".join(body.split())
    if SAFE_SWITCH_LINE.fullmatch(statement):
        return line
    for table, pattern in eos_services.SERVER_LINES.items():
        match = pattern.fullmatch(statement)
        if match and eos_services.address(match[2]) and eos_services._server_options(table, match[3]) is not None:
            return line
    setting = eos_services._system(statement)
    if setting and setting[1] is not None:
        return line
    label = next((prefix for prefix in SENSITIVE_LABELS
                  if statement.startswith(prefix + " ")), None)
    return line[:1] + (label + " " if label else "") + "[redacted]"


def parse_diff(text):
    """Validate the full EOS diff before deriving its digest and a display-safe unified diff."""
    normalized = text.replace("\r\n", "\n").strip("\n")
    if not normalized:
        return {"diff_sha256": _sha(""), "diff": []}
    if re.search(r"[\x00-\x08\x0b-\x1f\x7f\ufffd]", normalized):
        raise unreadable()
    lines = normalized.split("\n")
    if tuple(lines[:2]) != DIFF_HEADERS:
        raise unreadable()
    public = list(DIFF_HEADERS)
    old = new = changes = 0
    saw_hunk = False
    for line in lines[2:]:
        hunk = HUNK.fullmatch(line)
        if hunk:
            if old != 0 or new != 0:
                raise unreadable()
            old, new = (int(count) if count is not None else 1 for count in hunk.groups())
            saw_hunk = True
            public.append(line)
        elif saw_hunk and line.startswith((" ", "-", "+")):
            sign = line[0]
            old -= sign != "+"
            new -= sign != "-"
            changes += sign != " "
            if old < 0 or new < 0:
                raise unreadable()
            public.append(_public_line(line))
        else:
            raise unreadable()
    if old != 0 or new != 0 or not changes:
        raise unreadable()
    return {"diff_sha256": _sha(normalized), "diff": public}


def unreadable():
    return Rejected(["EOS did not return a complete running/startup diff"],
                    reason_codes=["eos_save_diff_unreadable"])


def read_diff(access, *, check=False):
    from netops_admin.access import AccessError

    try:
        status, text = (access.check_query_status if check else access.query_status)(DIFF_COMMAND)
    except AccessError as exc:
        message = str(exc).lower()
        if any(marker in message for marker in ("timeout", "timed out", "did not finish within")):
            raise Rejected(["the EOS running/startup diff read timed out"],
                           reason_codes=["eos_save_read_timeout"]) from None
        raise unreadable() from None
    if check and "(privileged mode required)" in text:
        raise Rejected(["the independent check account must be permitted to run show running-config diffs"],
                       reason_codes=["eos_save_check_denied"])
    if status != 0:
        raise unreadable()
    return parse_diff(text)


def compare_check(access, expected):
    if read_diff(access, check=True) != expected:
        raise Rejected(["the independent running/startup diff differs from the write account's view"],
                       reason_codes=["eos_save_diff_mismatch"])


def _valid_state(state):
    return (isinstance(state, dict) and set(state) == {"diff_sha256", "diff"}
            and isinstance(state["diff_sha256"], str) and HASH.fullmatch(state["diff_sha256"])
            and isinstance(state["diff"], list) and all(isinstance(line, str) for line in state["diff"])
            and (bool(state["diff"]) or state["diff_sha256"] == _sha("")))


def valid_plan(plan):
    return (plan["platform"] in ("eos", "nxos") and plan["table"] == plan["key"] == TABLE
            and plan["commands"] == [COMMAND] and not plan["inverse"]
            and plan["safeguard_id"] is None and "endpoint_impact" not in plan
            and _valid_state(plan["predicted"]["before"]) and plan["predicted"]["after"] == parse_diff(""))
