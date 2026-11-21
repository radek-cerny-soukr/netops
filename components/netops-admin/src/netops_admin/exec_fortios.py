from __future__ import annotations

import datetime
import hashlib
import json
import re
from dataclasses import dataclass

from netops_admin import fortios, fortios_lease
from netops_admin.errors import Rejected, StateUnreadable
from netops_admin.profiles import find_profile
from netops_admin.request import parse_request


@dataclass(frozen=True)
class PromptSpec:
    anchor: bytes
    ends: tuple
    continuation: bytes | None
    error: object
    typed: object = None
    # seconds a line may take before its prompt returns (None: access.LINE_TIMEOUT_SECONDS); Junos commits take
    # minutes
    seconds: object = None
    # alternative anchors (1.0.12 G145: the old and the new Junos host name of a host-name change)
    anchors: tuple = ()


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


def manual_policy_uuid(access) -> bool:
    state = access.query("diagnose sys uuid allow-manual-set").strip()
    if state not in ("allow-manual-set is enabled", "allow-manual-set is disabled"):
        raise Rejected(["the write account could not read whether FortiOS allows manual policy UUIDs"])
    return state == "allow-manual-set is enabled"


def clear_query(access, command, *, check=False):
    from netops_admin.access import AccessError

    query = access.check_query_status if check else access.query_status
    try:
        status, text = query(command)
    except (AccessError, OSError) as exc:
        if isinstance(exc, TimeoutError) or any(term in str(exc).lower() for term in ("timed out", "timeout")):
            raise Rejected(["the scoped FortiOS read timed out"],
                           reason_codes=["fortios_clear_read_timeout"]) from None
        raise Rejected(["the scoped FortiOS read could not complete"],
                       reason_codes=["clear_readback_unreadable"]) from None
    if status or "\ufffd" in text or fortios.cli_error("\n" + text):
        raise Rejected(["the scoped FortiOS command was refused or returned unreadable output"],
                       reason_codes=["clear_readback_unreadable"])
    return text


def clear_identity(access, *, check=False):
    from netops_admin.access import fortios_version_record

    status = clear_query(access, fortios.QUERY_CLOCK, check=check)
    identity = fortios_version_record(status)
    if identity is None:
        raise Rejected(["could not verify the FortiOS session table identity"],
                       reason_codes=["clear_readback_unreadable"])
    model, version, build = identity
    hostname = re.findall(r"(?m)^Hostname:[ \t]+([A-Za-z0-9_.-]{1,63})[ \t]*$", status)
    mode = re.findall(r"(?m)^Virtual domain configuration:[ \t]+([^\n]+)$", status)
    vdom = re.findall(r"(?m)^Current virtual domain:[ \t]+([^\n]+)$", status)
    if len(hostname) != 1 or [item.strip() for item in mode] != ["disable"] or vdom != ["root"]:
        raise Rejected(["FortiOS session clear requires a verified single-VDOM root session"],
                       reason_codes=["clear_scope_unverified"])
    return model, f"{version} build{build}", hostname[0]


def clear_checksum(access, *, check=False):
    text = clear_query(access, fortios.SESSION_CHECKSUM, check=check)
    sections = re.split(r"(?m)^checksum[ \t]*$", text)
    digest = re.findall(r"(?m)^all:[ \t]+([0-9a-fA-F]{2}(?: [0-9a-fA-F]{2}){15})[ \t]*$",
                        sections[1]) if len(sections) == 2 else []
    if len(digest) != 1:
        raise Rejected(["the FortiOS configuration checksum could not be read"],
                       reason_codes=["clear_readback_unreadable"])
    return hashlib.sha256(bytes.fromhex(digest[0])).hexdigest()


def with_clear_filter(access, target, firmware, action, *, check=False):
    """Install, read and remove a filter in one held SSH session."""
    def query(command):
        return clear_query(access, command, check=check)

    prefix = fortios.SESSION_FILTER
    if not fortios.clear_filter_matches(query(prefix)):
        raise Rejected(["the initial FortiOS session filter is not empty or is unreadable"],
                       reason_codes=["clear_scope_unverified"])
    failure = None
    try:
        for command in target.commands(firmware):
            query(command)
        return action(query)
    except Rejected as exc:
        failure = exc
        raise
    finally:
        try:
            query(prefix + " clear")
            if not fortios.clear_filter_matches(query(prefix)):
                raise ValueError
        except (Rejected, ValueError):
            if failure is not None:
                raise Rejected([*failure.reasons, "the FortiOS session filter reset could not be verified"],
                               reason_codes=[*failure.reason_codes, "fortios_clear_cleanup_unverified"]) from None
            raise Rejected(["the FortiOS session filter reset could not be verified"],
                           reason_codes=["fortios_clear_cleanup_unverified"]) from None


def clear_protected(query, entries, protected):
    policies = set(protected.get(fortios.POLICY_TABLE, ()))
    if any(str(entry["policy_id"]) in policies for entry in entries):
        raise Rejected(["the FortiOS session crosses a protected firewall policy"],
                       reason_codes=["clear_protected_target"])
    interfaces = {name.casefold() for table in (fortios.INTERFACE_TABLE, "interface")
                  for name in protected.get(table, ())}
    if not interfaces:
        return
    for index in sorted({index for entry in entries for index in entry["interface_indices"]}):
        rows = query(f'diagnose netlink interface list | grep "index={index} "')
        names = re.findall(rf"(?m)^if=(\S+)[ \t]+[^\n]*\bindex={index}(?=[ \t]|$)", rows)
        if len(names) != 1:
            raise Rejected(["a FortiOS session interface could not be verified"],
                           reason_codes=["clear_scope_unverified"])
        if names[0].casefold() in interfaces:
            raise Rejected(["the FortiOS session crosses a protected interface"],
                           reason_codes=["clear_protected_target"])


def clear_observe(query, target, *, protected=None):
    def verify_filter():
        if not fortios.clear_filter_matches(query(fortios.SESSION_FILTER), target):
            raise Rejected(["the FortiOS session filter does not match the requested scope"],
                           reason_codes=["clear_scope_unverified"])

    verify_filter()
    observed = fortios.clear_observation(target, query(fortios.SESSION_LIST))
    if query(fortios.SESSION_LIST + " expectation").strip() not in ("", "total session: 0", "total session 0"):
        raise Rejected(["the scoped FortiOS expectation table is not verifiably empty"],
                       reason_codes=["clear_scope_unverified"])
    clear_protected(query, observed["entries"], protected or {})
    verify_filter()
    return observed


def clear_checked_observation(access, target, firmware, *, protected=None):
    return with_clear_filter(access, target, firmware,
                             lambda query: clear_observe(query, target, protected=protected), check=True)


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
    if plan["table"] in fortios.SWITCH_PORT_TABLES:
        if snapshot_text:
            snapshot = fortios.load(snapshot_text, plan["firmware"])
            name = fortios.write_account_profile(snapshot, access.credential.login)
            profile = (snapshot.entries("system accprofile") or {}).get(name)
            if profile is not None and profile.value("wifi", "none") in ("none", "read"):
                raise Rejected(["the write account needs Read/Write access to WiFi & Switch Controller"],
                               reason_codes=["fortiswitch_write_permission_required"])
        plan["cycle_state"] = switch_port_preflight(access, plan)
    reasons = []
    fields = plan.get("predicted", {}).get("after") or {}
    if plan["table"] == fortios.POLICY_TABLE and plan["op"] != "move":
        for name in fortios.l1_fortios.tokenize(fields.get("internet-service-name", "")):
            command = 'show %s "%s"' % (fortios.ISDB_TABLE, name)
            if _nat_read(access, command, fortios.ISDB_TABLE, name) is None:
                raise Rejected(["the named Internet Service does not exist"],
                               reason_codes=["fortios_policy_internet_service_missing"])
    if _webhook(plan):
        reasons.extend(_webhook_preflight(access, device, snapshot_text)[0])
        try:
            _request(plan, device)
        except Rejected as exc:
            reasons.extend(exc.reasons)
    return reasons


WRITE_BUDGET_SECONDS = 20


def batch_read_error(exc):
    if re.search(r"timed out|timeout", str(exc), re.IGNORECASE):
        return Rejected(["the FortiOS profile batch preflight read timed out"],
                        reason_codes=["fortios_batch_read_timeout"])
    return Rejected(["the FortiOS profile batch preflight read could not complete"],
                    reason_codes=["fortios_batch_read_unreadable"])


def batch_prechecks(access, device, plan, snapshot_text, earlier, *, undo=False):
    """Check the step against the current device: the plan prechecks and the starting state seen by the check account."""
    from netops_admin import engine
    from netops_admin.access import AccessError

    try:
        reasons = plan_prechecks(access, device, plan, snapshot_text)
        if reasons:
            raise Rejected(reasons)
        observed = observe(access, plan, before=True)
    except AccessError as exc:
        raise batch_read_error(exc) from None
    except Rejected:
        raise
    except Exception as exc:
        raise batch_read_error(exc) from None
    if engine.observed_state(plan, observed) != engine.check_view(plan, plan["predicted"]["before"]):
        raise Rejected(["the check account sees the object in another state than the planned starting state"])


def before_write(access, record, left, device):
    """None when a batch step may be written: the own safeguard is still installed and enough of its time is left
    for the write, the readback and the confirmation margin; else the reason (nothing is written then)."""
    needed = WRITE_BUDGET_SECONDS + device.confirm_margin_seconds
    if left < needed:
        return "%d s of the safeguard left, %d s needed to write, read back and confirm" % (max(left, 0), needed)
    if safeguard_disarmed(access, record):
        return "the own safeguard is no longer installed"
    return None


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
    access.apply(fortios.render_webhook_identity(change_id, device.address, plan["table"]), spec)
    token = fortios.api_key(access.generate_api_key(fortios.render_key_request(change_id), spec))
    try:
        access.apply(fortios.render_webhook_safeguard(change_id, request, port, token, fire_at), spec)
    except Exception as exc:
        from netops_admin.access import AccessError

        if isinstance(exc, AccessError) and token in str(exc):
            raise AccessError(str(exc).replace(token, "<token>"), exc.accepted_lines) from None
        raise
    return fortios.webhook_state(change_id, _webhook_answers(access, change_id), request, port, token, fire_at,
                                 device.address, plan["table"])


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


def observe(access, plan, *, before=False):
    if plan["table"] in fortios.SWITCH_PORT_TABLES:
        serial, _port = plan["key"].split(":")
        text = _switch_query(access, f"show {fortios.MANAGED_SWITCH} {serial}")
        return fortios.shown_switch_port(text, plan["key"])
    if "policy_order" in plan:
        try:
            text = access.check_query("show firewall policy")
            root = fortios.parse_snapshot(text)
            if set(root.sub) != {fortios.POLICY_TABLE} or fortios.cli_error("\n" + text):
                raise Rejected(["the answer does not contain one complete firewall policy table"])
            section = root.section(fortios.POLICY_TABLE)
            order = fortios.policy_order(section, text)
        except Exception as exc:
            if isinstance(exc, TimeoutError) or any(marker in str(exc).lower()
                                                     for marker in ("timed out", "idle timeout")):
                raise Rejected(["the check account firewall policy read timed out"],
                               reason_codes=["fortios_policy_read_timeout"]) from None
            raise Rejected(["the check account could not read the complete firewall policy order"],
                           reason_codes=["fortios_policy_order_unreadable"]) from None
        if order != plan["policy_order"]["before" if before else "after"]:
            raise Rejected(["the check account sees a different firewall policy order"],
                           reason_codes=["fortios_policy_order_changed"])
        if "policy_move_sha256" in plan:
            entry = section.entries[plan["key"]]
            if fortios.policy_move_digest(entry) != plan["policy_move_sha256"]:
                raise Rejected(["the check account sees different firewall policy configuration"],
                               reason_codes=["fortios_policy_order_changed"])
            return fortios._shown_attributes(entry)
    if plan["table"] in fortios.NESTED:
        command = "show %s %s" % (fortios.NESTED[plan["table"]][0], fortios.split_nested(plan["table"], plan["key"])[0])
    else:
        command = 'show %s "%s"' % (plan["table"], plan["key"])
    if plan["table"] in fortios.NAT_TABLES:
        return _nat_read(access, command, plan["table"], plan["key"])
    if plan["table"] == fortios.PHASE2_TABLE:
        status, answer = _ipsec_check(access, command)
        try:
            state = fortios.shown_object(answer, plan["table"], plan["key"])
        except Rejected:
            raise fortios.ipsec_refused("the check account returned incomplete Phase 2 configuration",
                                        "clear_readback_unreadable") from None
        if status != 0 and state is not None:
            raise fortios.ipsec_refused("the check account refused the Phase 2 read", "clear_readback_unreadable")
        return state
    answer = access.check_query(command)
    return fortios.shown_object(answer, plan["table"], plan["key"])


def _nat_read(access, command, table, key):
    try:
        status, answer = access.check_query_status(command)
    except Exception as exc:
        timed_out = isinstance(exc, TimeoutError) or "timeout" in str(exc).lower() or "timed out" in str(exc).lower()
        code = "fortios_nat_read_timeout" if timed_out else "fortios_nat_read_unreadable"
        raise Rejected(["the check account could not read the FortiOS NAT configuration"],
                       reason_codes=[code]) from None
    try:
        state = fortios.shown_object(answer, table, key)
        if status not in (0, 1) or status and state is not None:
            raise Rejected(["the check account returned a CLI failure"])
    except Rejected:
        raise Rejected(["the check account returned incomplete or refused FortiOS NAT configuration"],
                       reason_codes=["fortios_nat_read_unreadable"]) from None
    return state


def _ipsec_check(access, command):
    try:
        return access.check_query_status(command)
    except Exception as exc:
        timed_out = isinstance(exc, TimeoutError) or "timed out" in str(exc).lower()
        code = "fortios_ipsec_read_timeout" if timed_out else "clear_readback_unreadable"
        raise fortios.ipsec_refused("the check account could not read the scoped IPsec output", code) from None


def observe_ipsec(access, target):
    # Ask FortiOS for the selector status rows only.
    command = "diag vpn tunnel list name " + target[1] + r" | grep '^proxyid\|^ *SA:'"
    status, answer = _ipsec_check(access, command)
    if status != 0:
        raise fortios.ipsec_refused("the check account refused the scoped IPsec read", "clear_readback_unreadable")
    # FortiOS may add a space and backspace where the echoed input wraps at the terminal edge.
    echo, _, body = answer.partition("\n")
    if echo.replace(" \b", "").rstrip("\r") == command:
        answer = body
    observed = fortios.ipsec_observation(answer, target, lifetimes=True)
    expiry = observed.pop("sa_expiry_seconds")
    return observed, expiry


def prepare_ipsec(access, device, snapshot_text, target):
    snapshot = fortios.load(snapshot_text, device.firmware)
    fortios.ipsec_target_prechecks(snapshot, target, device.protected)
    config = observe(access, {"table": fortios.PHASE2_TABLE, "key": target[0]})
    if config is None or config["phase1name"] != target[1]:
        raise fortios.ipsec_refused("the check account did not confirm the Phase 2 parent", "clear_readback_unreadable")
    return observe_ipsec(access, target)[0]


def recover_ipsec(access, spec, target, plan, sleep):
    before = plan["predicted"]["before"]
    commands = plan["commands"]
    readback = {"down_observed": None, "sas_replaced": None, "after": None}
    fresh, expiry_before = observe_ipsec(access, target)
    if fresh != before:
        return readback
    if before["up"]:
        try:
            if access.apply(commands[:1], spec) == 1:
                readback["down_observed"] = False
                readback["sas_replaced"] = False
                for attempt in range(4):
                    if attempt:
                        sleep(0.25)
                    observed, expiry = observe_ipsec(access, target)
                    if observed == dict(before, up=False):
                        readback["down_observed"] = True
                        break
                    # A peer may negotiate before the first probe. The remaining lifetime of every
                    # replacement SA must exceed that of every original SA, allowing for rounding.
                    if observed == before and expiry and min(expiry) > max(expiry_before) + 2:
                        readback["sas_replaced"] = True
                        break
        except Exception:
            # Try bring-up even if acceptance or the intermediate read could not be determined.
            readback["down_observed"] = False
    if access.apply(commands[-1:], spec) != 1:
        return readback
    for attempt in range(10):
        if attempt:
            sleep(1)
        observed, _expiry = observe_ipsec(access, target)
        readback["after"] = observed
        if observed == plan["predicted"]["after"]:
            break
    return readback


def foreign_sessions(access, device) -> int:
    own = {access.credential.login, access.check_credential.login}
    return fortios.foreign_sessions(access.query(fortios.QUERY_SESSIONS), own)


def observe_clear(access, target):
    """Every DHCP lease of the device, read with the check account (1.0.12 G20 FG-37)."""
    return fortios_lease.observation(access.check_query(target.read))


TABLES = {"port-bounce": fortios.SWITCH_BOUNCE, "poe-cycle": fortios.SWITCH_POE_CYCLE}
ACTION_CHANGES = {"port-bounce": {"status": "down"}, "poe-cycle": {"poe-status": "disable"}}
SWITCH_INFO = "diagnose switch-controller switch-info"
PORT_HEADER = re.compile(
    r"Port\(([^()\s]+)\) is HW Admin (up|down), SW Admin (up|down), line protocol is (up|down)"
)
MAC_ROW = re.compile(r"MAC: (?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\s+VLAN: \d+ (?:Port|Trunk): ([^ (]+)\(")


@dataclass(frozen=True)
class SwitchPoeSample:
    status: str
    watts: str
    current_ma: int

    def draws_power(self):
        # The parser accepts digits and an optional decimal point. Test for exact zero at any precision.
        return bool(self.watts.strip("0."))

    def delivering(self):
        return self.status == "Delivering Power" and self.draws_power() and self.current_ma > 0

    def readback(self):
        return {"poe": self.status, "watts": self.watts, "current_ma": self.current_ma}


def _switch_query(access, command, *, poe_key=None):
    from netops_admin.access import AccessError

    try:
        text = access.check_query(command)
    except (AccessError, TimeoutError) as exc:
        if isinstance(exc, TimeoutError) or re.search(r"timed out|timeout", str(exc), re.I):
            raise Rejected(["the managed switch diagnostic timed out"], reason_codes=["fortiswitch_read_timeout"]) from None
        raise StateUnreadable(["the managed switch diagnostic could not be read"]) from None
    if poe_key is not None:
        serial, _port = poe_key.split(":")
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if (len(lines) == 3 and lines[0].casefold() == "vdom: root"
                and lines[1:] == [f"switch:{serial} is not PoE capable", "Command fail. Return code -7622"]):
            raise Rejected(["the managed switch does not support PoE"], reason_codes=["poe_not_capable"])
    if (not text.strip() or "--More--" in text
            or re.search(r"(?im)^(?:command (?:parse error|fail)|permission denied)", text)):
        raise StateUnreadable(["the managed switch diagnostic is refused or incomplete"])
    return text


def switch_poe_status(access, key):
    serial, port = key.split(":")
    text = _switch_query(access, f"{SWITCH_INFO} poe detail {serial} {port}", poe_key=key)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if lines and lines[0].casefold() == "vdom: root":
        lines.pop(0)
    if not lines or not re.fullmatch(r"Managed Switch\s*:\s*" + re.escape(serial) + r"\s+\d+", lines[0]):
        raise StateUnreadable(["the PoE diagnostic does not identify the target switch"])
    match = re.fullmatch(r"Port\(" + port[4:] + r"\)\s+Power:\s*([0-9]+(?:\.[0-9]+)?)W,\s*Power-Status:\s*(.+)",
                         lines[1]) if len(lines) > 1 else None
    current = re.fullmatch(r"Current:\s*([0-9]+)\s*mA", lines[-1])
    if (not match or sum(line.startswith("Port(") for line in lines) != 1
            or not current or sum(line.startswith("Current:") for line in lines) != 1
            or not any(line.startswith("Defined Max Power:") for line in lines)):
        raise StateUnreadable(["the PoE diagnostic does not identify one complete port"])
    return SwitchPoeSample(match[2], match[1], int(current[1]))


def switch_port_status(access, key):
    serial, port = key.split(":")
    text = _switch_query(access, f"{SWITCH_INFO} port-stats {serial} {port}")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    head = PORT_HEADER.fullmatch(lines[2]) if len(lines) > 2 else None
    if (not head or lines[:2] != ["Vdom: root", f"{serial}:"] or head[1] != port
            or sum(line.startswith("Port(") for line in lines) != 1
            or sum(line.startswith("input") for line in lines) != 1
            or sum(line.startswith("output") for line in lines) != 1
            or not re.fullmatch(r"\d+ fragments, \d+ undersizes, \d+ collisions, \d+ jabbers", lines[-1])):
        raise StateUnreadable(["the port-stats answer does not identify one complete port"])
    return {"admin": head[3], "link": head[4]}


def switch_trunk_ports(access, serial):
    text = _switch_query(access, f"{SWITCH_INFO} trunk status {serial}")
    if (not re.search(r"(?m)^" + re.escape(serial) + r":\s*$", text)
            or "Switch Trunk Information," not in text):
        raise StateUnreadable(["the managed switch trunk listing is incomplete"])
    members = set(re.findall(r"(?m)^\s*(?:slave:\s*)?(port[1-9][0-9]*)[ \t]+\S", text))
    members.update(re.findall(r"(?m)^slave:[ \t]*(port[1-9][0-9]*)[ \t]*$", text))
    counts = [int(count) for count in re.findall(r"(?m)^ports:[ \t]*(\d+)[ \t]*$", text)]
    if not members or sum(counts) > len(members):
        raise StateUnreadable(["the managed switch trunk members are incomplete"])
    return members


def switch_client_ports(access, serial):
    text = _switch_query(access, f"{SWITCH_INFO} mac-table {serial}")
    rows = [MAC_ROW.match(line.strip()) for line in text.splitlines() if line.strip().startswith("MAC:")]
    total = re.search(r"(?m)^Total Displayed:[ \t]*(\d+)[ \t]*\Z", text.rstrip())
    if (not total or int(total[1]) != len(rows) or not all(rows)
            or not re.search(r"(?m)^Managed Switch\s*:[ \t]*" + re.escape(serial) + r"[ \t]+\d+[ \t]*$", text)):
        raise StateUnreadable(["the managed switch MAC table is incomplete"])
    return {row[1] for row in rows}


def switch_port_preflight(access, plan):
    serial, port = plan["key"].split(":")
    state = switch_port_status(access, plan["key"])
    if state["admin"] != plan["predicted"]["before"].get("status", "up"):
        raise StateUnreadable(["managed switch configuration and software admin state disagree"])
    if port in switch_trunk_ports(access, serial):
        raise Rejected(["the port is a managed switch trunk member"], reason_codes=["port_protected"])
    cycle = plan["table"] == fortios.SWITCH_POE_CYCLE
    before, after = (plan["predicted"][side] for side in ("before", "after"))
    sample = switch_poe_status(access, plan["key"]) if cycle or before.get("poe-status") != after.get("poe-status") else None
    power = sample.status if sample is not None else None
    if cycle:
        if not sample.delivering():
            raise Rejected(["the managed switch port is not delivering power"], reason_codes=["poe_device_not_powered"])
        state["poe"] = power
    active = power == "Delivering Power" or state["link"] == "up" or port in switch_client_ports(access, serial)
    if active and plan.get("endpoint_impact") != plan["key"]:
        raise Rejected(["changing an active managed switch port requires endpoint_impact naming the port key"],
                       reason_codes=["endpoint_impact_required"])
    if state["link"] == "up":
        text = _switch_query(access, f"{SWITCH_INFO} lldp neighbors-summary {serial}")
        rows = [re.split(r"\s{2,}", line.strip()) for line in text.splitlines()
                if line.strip().split(maxsplit=1)[:1] == [port]]
        if (len(rows) != 1 or len(rows[0]) != 7 or rows[0][1] != "Up"
                or not re.fullmatch(r"\d+|-", rows[0][3])
                or not re.fullmatch(r"[RBTCWPSO]+|-", rows[0][4])
                or not re.search(r"(?m)^Managed Switch\s*:[ \t]*" + re.escape(serial) + r"[ \t]+\d+[ \t]*$", text)):
            raise StateUnreadable(["managed switch LLDP does not identify the active port"])
        # Device names may contain spaces. The last four columns are TTL, capability, MED type and port ID.
        if "B" in rows[0][4] or rows[0][5] == "Network":
            raise Rejected(["the port has a bridge or network infrastructure neighbor"], reason_codes=["port_protected"])
    return state


def request(action, device, port, reason, user_request, request_id, endpoint_impact=None):
    body = {"device": device, "table": TABLES[action], "key": port, "op": "update",
            "changes": ACTION_CHANGES[action], "reason": reason, "user_request": user_request, "request_id": request_id}
    if endpoint_impact is not None:
        body["endpoint_impact"] = endpoint_impact
    return parse_request(json.dumps(body).encode("utf-8"))


def preview(runtime, device, action, cycle_request):
    from netops_admin import execute
    return execute._preview(runtime, device, cycle_request, action=action)[0]


def apply(runtime, device, action, cycle_request, *, expected_plan_sha256=None):
    from netops_admin import execute
    try:
        expected = execute._expected_plan(cycle_request, expected_plan_sha256)
    except Rejected:
        execute._count_rejection(runtime)
        raise
    return execute._apply_counted(runtime, device, cycle_request, execute.ANY_STATE,
                                  action=action, expected_plan=expected)


def wait_switch_state(runtime, access, key, accept, deadline, *, read=switch_port_status):
    while runtime.monotonic() < deadline:
        saved_limit = getattr(access, "read_seconds", None)
        access.read_seconds = max(1, min(5, deadline - runtime.monotonic()))
        try:
            state = read(access, key)
        finally:
            access.read_seconds = saved_limit
        if accept(state):
            return state
        if runtime.monotonic() + 1 < deadline:
            runtime.sleep(1)
        else:
            break
    raise StateUnreadable(["the managed switch did not reach the requested port state"])


def run_switch_cycle(runtime, adapter, access, record, plan, device, due):
    from netops_admin import engine, execute
    spec = execute._spec(record)
    key = plan["key"]
    poe = plan["table"] == fortios.SWITCH_POE_CYCLE
    settle = execute._settle_after_expiry
    started = runtime.monotonic()
    try:
        device_remaining = (execute._fire_at(record) - adapter.clock(access)).total_seconds()
    except Exception as exc:
        execute._step(runtime, record, "clock_unreadable", type(exc).__name__)
        return settle(runtime, access, record, plan, "device clock", due)
    due = min(due, started + device_remaining)
    deadline = due - device.confirm_margin_seconds
    try:
        current = switch_port_preflight(access, plan)
        baseline = switch_poe_status(access, key) if poe else None
        if baseline is not None and not baseline.delivering():
            raise StateUnreadable(["the managed switch port is no longer delivering measurable power"])
        if current != plan["cycle_state"] or runtime.monotonic() + 10 >= deadline:
            raise StateUnreadable(["the port state or safeguard window changed after preflight"])
    except Rejected:
        return settle(runtime, access, record, plan, "cycle port state changed after preflight", due)
    record["cycle"] = {"before": plan["cycle_state"]}
    if baseline is not None:
        record["cycle"]["before"] = {**current, **baseline.readback()}
    execute._step(runtime, record, "change_start")
    off = None
    try:
        access.apply(plan["commands"], spec)
        if poe:
            depleted = wait_switch_state(
                runtime, access, key,
                lambda sample: not sample.draws_power() and (sample.current_ma == 0 or (
                    sample.status == "Searching" and sample.current_ma < baseline.current_ma)),
                min(deadline - 2, runtime.monotonic() + 10), read=switch_poe_status,
            )
            off = depleted.readback()
        else:
            off = wait_switch_state(runtime, access, key, lambda state: state == {"admin": "down", "link": "down"},
                                    min(deadline - 2, runtime.monotonic() + 10))
        record["cycle"]["down"] = off
        execute._step(runtime, record, "port_down_observed")
        if not poe:
            runtime.sleep(2)
    except Exception as exc:
        execute._step(runtime, record, "cycle_down_unverified", type(exc).__name__)
    if runtime.monotonic() >= deadline:
        return settle(runtime, access, record, plan, "too close to the safeguard", due)
    try:
        restore_by = min(deadline, runtime.monotonic() + 30)
        if poe:
            restored = wait_switch_state(runtime, access, key, SwitchPoeSample.delivering,
                                         restore_by, read=switch_poe_status)
            after = restored.readback()
        else:
            access.apply(plan["inverse"], spec)
            after = wait_switch_state(runtime, access, key, lambda state: state == current, restore_by)
        record["cycle"]["after"] = after
        snapshot = access.snapshot()
        unchanged = engine.verify(plan, snapshot.encode("utf-8"), expect="before")["result"] == "match"
        independent = engine.observed_state(plan, observe(access, plan)) == plan["predicted"]["before"]
        accounts = accounts_check(access, device, snapshot)
        if not unchanged or not independent or accounts != record["accounts"]:
            raise StateUnreadable(["the managed switch configuration did not return exactly"])
    except Exception as exc:
        execute._step(runtime, record, "cycle_return_unverified", type(exc).__name__)
        return settle(runtime, access, record, plan, "cycle return unverified", due)
    if runtime.monotonic() >= deadline:
        return settle(runtime, access, record, plan, "no time left to confirm", due)
    if off is not None:
        execute._step(runtime, record, "confirm_start")
    if not adapter.remove_safeguard(access, record, spec):
        return settle(runtime, access, record, plan, "confirmation unverified", due)
    result = "confirmed" if off is not None else "reverted"
    reason = None if off is not None else "cycle effect unverified"
    if not execute._persist(runtime, adapter, access, record):
        reason = "not persisted"
    return execute._finish(runtime, record, result, reason)
