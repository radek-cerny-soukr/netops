"""Approval and readback for IOS running-config to startup-config saves."""
from __future__ import annotations

from difflib import SequenceMatcher
import hashlib
import re

from netops_admin import ios, ios_acl
from netops_admin.errors import Rejected

TABLE = "startup-config"
KIND = "ios-save"
COMMAND = "write memory"
STARTUP = "show startup-config"
NO_UNDO = "Saving overwrites startup-config. Admin has no undo for this operation."
UNREADABLE = "ios_save_diff_unreadable"
TIMEOUT = "ios_save_read_timeout"
STARTUP_HEADER = re.compile(r"Using [0-9]+ out of [0-9]+ bytes")
STARTUP_COMPRESSED = re.compile(r"Uncompressed configuration from [0-9]+ bytes to [0-9]+ bytes")
HASH = re.compile(r"[0-9a-f]{64}")
CONTROL = re.compile(r"[^\S \n\r\t]|[\x00-\x08\x0e-\x1f\x7f\ufffd]")
SECRET = re.compile(
    r"\b(?:password|secret|key-string|authentication-key|message-digest-key|pre-shared-key|"
    r"preshared-key|pre-share|passphrase|pass-phrase|private-key|keyring|shared-secret|auth-key|priv-key|"
    r"community|community-string|psk|wep-key|sae-password|encrypted-password|token|idtoken)\b"
    r"|^(?:(?:no )?snmp-server (?:host|user)|ntp authentication-key|crypto (?:isakmp|ikev2) key|"
    r"enable (?:password|secret)|(?:key|server-key)\s+\S+|(?:tacacs-server|radius-server) (?:key|host)|"
    r"standby\s+(?:\d+\s+)?authentication|vrrp\s+\d+\s+authentication|"
    r"isdn spid[12]|ip ftp username|ip http client username)(?: |$)",
    re.IGNORECASE,
)
OPAQUE = re.compile(r"^(?:crypto pki certificate chain |(?:ip ssh|crypto key) pubkey-chain\b|"
                    r"crypto key (?:generate|import)\b|event manager applet )")
RADIUS_COA_KEY = re.compile(r"(?:^|\s)(?:server-key|key)(?:\s|$)", re.IGNORECASE)
AAA_GROUP = re.compile(r"aaa group server (?:radius|tacacs\+) \S+", re.IGNORECASE)
SERVER_PRIVATE_KEY = re.compile(r"^server-private[ \t]+\S+.*?[ \t]key(?:[ \t]|$)", re.IGNORECASE)
SAFE_PASSWORD_COMMAND = re.compile(r"(?:no )?service password-encryption|security passwords min-length [0-9]+")


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _unreadable():
    return Rejected(["IOS did not return complete running and startup configurations"],
                    reason_codes=[UNREADABLE])


def _lines(text, firmware, *, startup=False):
    text = text.replace("\r\n", "\n")
    if CONTROL.search(text) or "\r" in text or "--More--" in text or ios.refused(text):
        raise _unreadable()
    lines = text.strip("\n").split("\n")
    if startup:
        if not STARTUP_HEADER.fullmatch(lines[0].strip()):
            raise _unreadable()
        lines = lines[1:]
        while lines and not lines[0].strip():
            lines.pop(0)
        if lines and STARTUP_COMPRESSED.fullmatch(lines[0].strip()):
            lines = lines[1:]
        framed = [ios.BUILDING, "Current configuration : 0 bytes", *lines]
    else:
        framed = lines
    try:
        snapshot = ios.load("\n".join(framed), firmware)
    except Rejected:
        raise _unreadable() from None
    private, public = [], []
    opaque, radius_coa, aaa_group = False, False, False
    delimiter, macro = None, False
    for line in snapshot.source_lines:
        if delimiter is not None or macro:
            private.append(line)
            public.append("[redacted multiline content]")
            if delimiter is not None and delimiter in line:
                delimiter = None
            if macro and line.strip() == "@":
                macro = False
            continue
        if (not line.strip() or line.strip() == "!" or line.startswith(ios.VOLATILE_HEADER)
                or (not startup and (line == ios.VLAN_DATABASE or line.startswith(
                    ("! netops-vlan ", ios_acl.LISTING_MARK, ios_acl.MARK))))):
            continue
        stripped = line.lstrip()
        if stripped == line:
            opaque = bool(OPAQUE.match(line))
            radius_coa = line == "aaa server radius dynamic-author"
            aaa_group = AAA_GROUP.fullmatch(line.rstrip(" \t")) is not None
        banner = ios.BANNER.match(line)
        if banner:
            marker = banner.group(1)
            if marker not in line[banner.end():]:
                delimiter = marker
            safe = " ".join(line.split()[:2]) + " [redacted banner]"
        elif line.startswith("macro name "):
            macro = True
            safe = "macro name [redacted]"
        elif (opaque or (radius_coa and RADIUS_COA_KEY.search(stripped))
              or (aaa_group and SERVER_PRIVATE_KEY.search(stripped))
              or (SECRET.search(stripped) and not SAFE_PASSWORD_COMMAND.fullmatch(stripped))):
            safe = line[:len(line) - len(stripped)] + "[redacted]"
        else:
            safe = line
        private.append(line)
        public.append(safe)
    if delimiter is not None or macro:
        raise _unreadable()
    return private, public


def _diff(old, new):
    old_lines, old_public = old
    new_lines, new_public = new
    result = []
    groups = SequenceMatcher(None, old_lines, new_lines, autojunk=False).get_grouped_opcodes(2)
    for group in groups:
        _, start_old, _, start_new, _ = group[0]
        _, _, end_old, _, end_new = group[-1]
        result.append(f"@@ -{start_old + 1},{end_old - start_old} +{start_new + 1},{end_new - start_new} @@")
        for tag, i, j, k, m in group:
            if tag == "equal":
                result.extend(" " + line for line in old_public[i:j])
            if tag in ("delete", "replace"):
                result.extend("-" + line for line in old_public[i:j])
            if tag in ("insert", "replace"):
                result.extend("+" + line for line in new_public[k:m])
    if result:
        result[:0] = ["--- startup-config", "+++ running-config"]
    return result


def read(access, firmware, running=None):
    from netops_admin.access import AccessError

    try:
        status, startup = access.query_status(STARTUP)
        running = access.snapshot() if running is None else running
    except AccessError as exc:
        if re.search(r"timeout|timed out|within", str(exc), re.I):
            raise Rejected(["the IOS save read timed out"], reason_codes=[TIMEOUT]) from None
        raise _unreadable() from None
    if status != 0:
        raise _unreadable()
    old, new = _lines(startup, firmware, startup=True), _lines(running, firmware)
    return {"startup_sha256": _sha("\n".join(old[0])), "running_sha256": _sha("\n".join(new[0])),
            "diff": _diff(old, new)}


def after(before):
    digest = before["running_sha256"]
    return {"startup_sha256": digest, "running_sha256": digest, "diff": []}


def valid_plan(plan):
    before = plan["predicted"]["before"]
    return (plan["platform"] in ios.PLATFORMS and plan["table"] == plan["key"] == TABLE
            and plan["commands"] == [COMMAND] and not plan["inverse"] and plan["safeguard_id"] is None
            and "endpoint_impact" not in plan and isinstance(before, dict)
            and set(before) == {"startup_sha256", "running_sha256", "diff"}
            and all(isinstance(before[key], str) and HASH.fullmatch(before[key])
                    for key in ("startup_sha256", "running_sha256"))
            and isinstance(before["diff"], list) and all(isinstance(line, str) for line in before["diff"])
            and bool(before["diff"]) == (before["startup_sha256"] != before["running_sha256"])
            and plan["predicted"]["after"] == after(before))
