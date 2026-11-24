"""Ruckus Unleashed execution adapter of the common Admin engine (execute.ADAPTERS["ruckus"]), 1.0.12 wireless wlans and wireless dhcp.

Unleashed 200.15.6.212 build 27 has no on-device timed return (the CLI offers no scheduler, no commit timer and no
rollback; measured, private measurement record). The adapter is therefore COMPENSATING like FortiADC: execute installs nothing
on the device and returns an unverified change itself in the same run by writing the inverse of the plan and reading
the WLAN listing back. Nothing returns a change when the Admin process or the management path is lost after the write
until recover runs; this is a property of the platform, not a safeguard.

The CLI is an interactive login on a pty (no exec channel): "Please login:", the password, the prompt ``ruckus>``,
``enable``, then ``ruckus# ``. A change is typed in ``config`` and ``wlan <name>`` and saved by ``end``/``exit``.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass

from netops_admin import ruckus
from netops_admin.errors import Rejected

COMPENSATING = True
AUDIT_RULES = False
FIRING_OBSERVED = True
RETURN_MECHANISM = "compensating write of the inverse in the same run (no on-device timer)"
AUDIT_NOT_RUN = ("ruckus.auditor", "not-evaluated",
                 "Admin runs no auditor rules on Ruckus Unleashed: the CLI has no full configuration export")
SNAPSHOT_QUERIES = ("show sysinfo", "show wlan all")
GROUP_QUERY = "show config"
DHCP_QUERY = "show dhcp all"
HOSTNAME = "ruckus"
LOGIN_PROMPT = b"Please login:"
PASSWORD_PROMPT = b"assword"
USER_PROMPT = b"ruckus>"
ENABLE_COMMAND = "enable"
ENABLE_PROMPT = b"ruckus# "
# the answers of the device to a line that worked; every other answer line is a refusal (fail closed)
ACCEPTED = re.compile(
    r"^(?:You have all rights in this mode\.|The command was executed successfully\..*"
    r"|The WLAN service '[^']*' has been (?:created|loaded)\..*"
    r"|The WLAN service '[^']*' has been (?:updated and saved|deleted)\.|Your changes have been saved\."
    r"|The DHCP server '[^']*' has been (?:created|loaded)\..*|The DHCP server '[^']*' has been (?:updated and saved|deleted)\."
    r"|No changes have been saved\.)$")
PROMPT_LINE = re.compile(r"^ruckus(?:\([a-z-]+\))?[#>] ?$")
PASSPHRASE_CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
PASSPHRASE_LENGTH = 32
REFERENCE = re.compile(re.escape(ruckus.PASSPHRASE_REF_PREFIX) + r"(WLAN_PSK_[A-Z0-9_]{1,48})>")
PASSPHRASE_VALUE = re.compile(r"^(?:[!-~]{8,63}|[0-9A-Fa-f]{64})$")
PASSPHRASE_COMMAND = re.compile(
    r'(?i)^\s*(?:open\s+)?wpa(?:2|3|23-mixed)\s+passphrase\s+'
    r'(?:"([^"]*)"|(.+?))(?:\s+algorithm(?:\s+.*)?)?\s*$'
)


class NotRead(Exception):
    """A value Admin does not read on Unleashed."""


def _generated() -> str:
    return "".join(secrets.choice(PASSPHRASE_CHARACTERS) for _ in range(PASSPHRASE_LENGTH))


def refusal(text: str):
    """The first line of an answer the device did not accept; None when every line is a known acceptance. The first
    row is the echo of the typed command and is not judged."""
    rows = text.replace("\r", "").split("\n")[1:]
    for row in rows:
        bare = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", row).strip()
        if not bare or PROMPT_LINE.fullmatch(bare) or ACCEPTED.fullmatch(bare):
            continue
        return bare
    return None


@dataclass(frozen=True)
class PromptSpec:
    anchor: bytes
    ends: tuple
    continuation: bytes | None
    error: object
    typed: object = None
    seconds: object = None
    anchors: tuple = ()
    # performs the interactive login of the pty session (access.DeviceAccess._login calls it); None: the anchor logic
    login: object = None
    answer_secrets: object = None
    # 1.0.12 wireless dhcp: replaces a vault reference in a line by the secret just before the line is typed (access.apply)
    resolve: object = None


def check_passphrase(value: str) -> None:
    """A passphrase typed unquoted into the CLI: 8..63 printable ASCII characters without a space, or 64 hex."""
    if not isinstance(value, str) or PASSPHRASE_VALUE.fullmatch(value) is None:
        raise Rejected(["the vault entry is not a usable WLAN passphrase (8 to 63 printable characters without a space,"
                        " or 64 hexadecimal characters)"])


def resolve(text: str, access) -> str:
    """The vault reference of a passphrase line is resolved here, in the privileged transport, and nowhere else: the
    plan, the journal and the audit record hold the reference only."""
    from netops_admin.access import AccessError

    found = REFERENCE.search(text)
    if found is None:
        return text
    try:
        secret = access.secret_value(found.group(1))
        check_passphrase(secret)
    except Rejected as exc:
        raise AccessError(exc.reasons[0]) from None
    return text.replace(found.group(0), secret, 1)


def _typed(text: str) -> str:
    # a passphrase is generated for every write line that carries the token; it is never stored or shown
    if ruckus.PASSPHRASE_TOKEN in text and _passphrases(text) == (ruckus.PASSPHRASE_TOKEN,):
        return text.replace(ruckus.PASSPHRASE_TOKEN, _generated(), 1)
    return text


def _passphrases(command: str) -> tuple[str, ...]:
    found = PASSPHRASE_COMMAND.fullmatch(command)
    return tuple(value for value in found.groups() if value) if found else ()


def login(shell, credential, timeout) -> bytes:
    """Log in like the Helper (wireless inventory): the user name and the password at their prompts, then enable; returns what the
    device printed up to the privileged prompt (to be discarded)."""
    seen = b""
    for prompt, answer in ((LOGIN_PROMPT, credential.login), (PASSWORD_PROMPT, credential.use()),
                           (USER_PROMPT, ENABLE_COMMAND)):
        _index, data = shell.expect([prompt], timeout)
        shell.discard(data)
        seen += data
        shell.send(answer)
    _index, data = shell.expect([ENABLE_PROMPT], timeout)
    return seen + data


def prompt_spec(hostname: str = HOSTNAME) -> PromptSpec:
    return PromptSpec(anchor=b"\nruckus", ends=(b"# ",), continuation=None, error=refusal, typed=_typed, login=login,
                      answer_secrets=_passphrases, resolve=resolve)


def safeguard_label(change_id: str) -> str:
    return "compensation-%s" % change_id[:12]


def _body(text: str, command: str) -> str:
    """The answer of a read: the echo of the command and the prompts around it removed."""
    rows = text.replace("\r", "").split("\n")
    while rows and not rows[0].strip():
        rows.pop(0)
    if rows and rows[0].strip().endswith(command):
        rows.pop(0)
    while rows and (not rows[-1].strip() or PROMPT_LINE.fullmatch(rows[-1].strip())):
        rows.pop()
    return "\n".join(rows)


def read(query, command: str) -> str:
    answer = query(command)
    tail = [row for row in answer.replace("\r", "").split("\n") if row.strip()][-1:]
    if not tail or PROMPT_LINE.fullmatch(tail[0].strip()) is None:
        # an answer that does not end with the prompt was cut (timeout, closed session): never a listing
        raise Rejected(["the answer to %s ends without the prompt of the device; it is incomplete" % command])
    text = _body(answer, command)
    if "--More--" in text or "The command is either unrecognized or incomplete" in text:
        raise Rejected(["the answer to %s is not a complete listing" % command])
    return text


def group_memberships(access) -> dict | None:
    from netops_admin.access import AccessError

    # Only the parsed membership data leaves this read. An unreadable group section blocks delete planning.
    try:
        return ruckus.read_group_memberships(read(access.query, GROUP_QUERY))
    except (AccessError, Rejected):
        return None


def snapshot(access) -> str:
    identity = read(access.query, SNAPSHOT_QUERIES[0])
    firmware = ruckus.sysinfo_firmware(identity)
    listing = ruckus.redact(read(access.query, SNAPSHOT_QUERIES[1]))
    text = "%s%s\n%s\n" % (ruckus.HEADER, firmware, listing)
    memberships = group_memberships(access)
    if memberships is not None:
        text = text.rstrip("\n") + ruckus.GROUPS_HEADER + json.dumps(memberships, sort_keys=True) + "\n"
    return text


def relay_listing(access) -> str:
    """`show dhcp all` in the privileged mode (a read of the DHCP relay server entries)."""
    return read(access.query, DHCP_QUERY)


def with_dhcp(access, text: str) -> str:
    """1.0.12 wireless dhcp R23: the snapshot of a DHCP relay plan holds the relay listing too. The relay section sits before
    the group section, which stays last."""
    listing = relay_listing(access)
    head, marker, groups = text.partition(ruckus.GROUPS_HEADER)
    return head.rstrip("\n") + ruckus.DHCP_HEADER + listing + "\n" + (marker + groups if marker else "")


def hostname(access, snapshot_text: str) -> str:
    return HOSTNAME


def accounts_check(access, device, snapshot_text) -> str:
    # Unleashed has one administrator account in the lab and the CLI shows no account table to Admin; the identity
    # bound to the enrollment is the pair of logins Admin uses
    logins = sorted({access.credential.login, access.check_credential.login})
    return hashlib.sha256("\n".join(logins).encode("utf-8")).hexdigest()


def prechecks(access, device, snapshot_text, spec) -> list:
    return []


def ports(access, table):
    return None


def leftovers(access) -> list:
    return []


def selected(device) -> set:
    return {name.casefold() for name in getattr(device, "wlans", ())}


def _require_selected(device, key):
    if key.casefold() not in selected(device):
        raise Rejected(["WLAN %r is not selected for Admin: only %s may be changed (device entry wlans)"
                        % (key, ", ".join(sorted(getattr(device, "wlans", ()))) or "no WLAN")],
                       reason_codes=["wlan_not_selected"])


def request_prechecks(device, request) -> None:
    """Admin writes only the WLANs the device entry selects (wlans); every other WLAN is refused before the device is
    contacted."""
    _require_selected(device, request.key)


def plan_prechecks(access, device, plan, snapshot_text="", undo=False) -> list:
    """The same selection again on the plan (an undo plans from a stored record)."""
    key = plan["key"]
    _require_selected(device, key)
    plan["prechecks"].append("WLAN %s is selected for Admin (device entry wlans)" % key)
    if plan["table"] == ruckus.TABLE:
        for command in plan["commands"] + plan["inverse"]:
            found = REFERENCE.search(command)
            if found is not None:
                try:
                    check_passphrase(access.secret_value(found.group(1)))
                except Rejected as exc:
                    raise Rejected(exc.reasons, reason_codes=["wlan_passphrase_reference"]) from None
                plan["prechecks"].append("the passphrase reference %s resolves in the vault; its value is not shown"
                                         % found.group(1))
        if any(ruckus.PASSPHRASE_TOKEN in command for command in plan["inverse"]):
            plan["prechecks"].append("the inverse types a newly generated passphrase; set the real one in the Unleashed"
                                     " web interface after an undo")
    if plan["op"] == "create" and plan["table"] == ruckus.TABLE:
        plan["prechecks"].append("the passphrase is generated at the write and not recorded; set the real passphrase"
                                 " in the Unleashed web interface before enabling the WLAN")
    if plan["op"] == "delete" and plan["table"] == ruckus.TABLE:
        plan["prechecks"].append("the WLAN matches settings Admin can recreate; a restoration will use a new"
                                 " passphrase that the administrator must set in the Unleashed web interface")
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
    # Unleashed saves a change when its context ends (end/exit); there is no separate save
    return False


def observe(access, plan, *, after=False):
    """The WLAN as the check account reads it (an independent session), or None when it is not listed."""
    if plan["table"] == ruckus.RELAY_TABLE:
        relays = ruckus.parse_relays(read(access.check_query, DHCP_QUERY))
        if relays is None:
            raise Rejected(["the check account does not read a complete DHCP relay listing"])
        relay = relays.get(plan["key"])
        if relay is None:
            return None
        state = {"first": relay["first"]}
        state.update({name: relay[name] for name in ("second", "description") if relay[name]})
        return state
    text = read(access.check_query, SNAPSHOT_QUERIES[1])
    listing = ruckus.parse_listing(ruckus.redact(text))
    if plan["key"] == "*":
        return {}  # the doctor probe: the check account reads the complete WLAN listing
    entry = (listing.entries(ruckus.TABLE) or {}).get(plan["key"])
    if entry is None:
        return None
    if entry.unsupported:
        raise Rejected(["the check account sees configuration outside the profile: %s"
                        % ", ".join(sorted(entry.unsupported))])
    if after and ruckus.passphrase_only(plan):
        ref = next((match[1] for command in plan["commands"] if (match := REFERENCE.search(command))), None)
        # Compare in memory only. All ordinary observations, including the returned state, use the redacted listing.
        value = ruckus.parse_listing(text).wlans[plan["key"]]["values"].get("Passphrase", "")
        if (ref is None or PASSPHRASE_VALUE.fullmatch(value) is None or value in (ruckus.REDACTED, "[redacted]")
                or set(value) == {"*"} or not secrets.compare_digest(value, access.secret_value(ref))):
            raise Rejected(["the stored WLAN passphrase does not verify against the vault reference"])
    return dict(entry.attributes)


def foreign_sessions(access, device) -> int:
    raise NotRead("Unleashed administrator sessions are not read by Admin")
