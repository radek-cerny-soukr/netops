from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re
from time import sleep

from netops_admin.errors import Rejected
from netops_admin.exec_fortios import PromptSpec

STATUSES = ("enable", "disable", "maintain")
DEFAULT_STATUS = "enable"
POOL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}")
CERT_GROUP = "system certificate local_cert_group"
CERT_MEMBER = CERT_GROUP + "/group_member"
CERT_TABLE = "system certificate local"
CERT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,34}")
CERT_NAMES = re.compile(r"== \[ ([^\[\]\r\n]+) \]")
MEMBER = re.compile(r"[1-9][0-9]{0,8}")
HOSTNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
HOSTNAME_LINE = re.compile(r"(?m)^Hostname:[ \t]+(\S+)[ \t]*$")
PAGER = re.compile(r"--More-- \r {1,256}\r")
TOKEN = re.compile(r'"((?:[^"\\]|\\.)*)"(?=[ \t]|$)|([^\s"\\]+)(?=[ \t]|$)')
EXIT = {"ready": 0, "confirmed": 0, "unchanged": 0, "rolled_back": 4, "unknown": 7}
REFUSALS = (
    (re.compile(r"command fail", re.IGNORECASE), "command failed"),
    (re.compile(r"command parse error", re.IGNORECASE), "command parse error"),
    (re.compile(r"unknown action", re.IGNORECASE), "unknown action"),
    (re.compile(r"value parse error", re.IGNORECASE), "value parse error"),
)
HA_STATUS = "get system ha-status"
HA_MODES = {"active-active", "active-active-vrrp", "active-passive"}
HA_SECONDARY = {"secondary", "secondary(working)", "slave", "slave(working)"}


def read_ha(access):
    """Return the local role and whether FortiADC reports a synchronized pair."""
    try:
        text = access.query(HA_STATUS)
    except Exception as exc:
        if isinstance(exc, TimeoutError) or "timed out" in str(exc).lower():
            raise Rejected(["FortiADC HA status read timed out"],
                           reason_codes=["fortiadc_ha_read_timeout"]) from None
        raise _ha_unreadable() from None
    if "--More--" in text or "\ufffd" in text or cli_error(text) or CLEAR_REFUSAL.search(text):
        raise _ha_unreadable()
    fields = re.findall(r"(?im)^[ \t]*(mode|state|config-sync(?: source)?|init done|peer count|serial-number|ip address)"
                        r"[ \t]*:[ \t]*([^\r\n]+)", text)
    local = {}
    peer = {}
    for name, value in fields:
        name, value = name.lower(), value.strip().lower()
        if "peer count" in local:
            if name in {"state", "serial-number", "ip address"}:
                if name in peer:
                    raise _ha_unreadable()
                peer[name] = value
            elif name in {"mode", "peer count", "init done"}:
                raise _ha_unreadable()
        elif name in local:
            raise _ha_unreadable()
        else:
            local[name] = value
    mode, state, peers = (local.get(key) for key in ("mode", "state", "peer count"))
    if mode == "standalone" and state == "standalone" and peers == "0" and not peer:
        return "standalone", False
    if mode in HA_MODES and state in HA_SECONDARY:
        return "secondary", False
    if mode in HA_MODES and state in {"primary", "master"}:
        synced = (peers == "1" and peer.get("state") in HA_SECONDARY
                  and all(local.get(key) and peer.get(key) and local[key] != peer[key]
                          for key in ("serial-number", "ip address"))
                  and local.get("config-sync") == "in sync"
                  and local.get("config-sync source") == "y"
                  and local.get("init done") == "yes")
        return "primary", synced
    raise _ha_unreadable()


def _ha_unreadable():
    return Rejected(["could not establish the FortiADC local HA role"],
                    reason_codes=["fortiadc_ha_unreadable"])


def require_ha_write(access, expected_role=None):
    role, synchronized = read_ha(access)
    if role == "secondary":
        raise Rejected(["FortiADC is secondary; target the synchronized primary"],
                       reason_codes=["fortiadc_ha_secondary"])
    if expected_role is not None and role != expected_role:
        raise Rejected(["FortiADC HA role changed during the operation"],
                       reason_codes=["fortiadc_ha_role_changed"])
    if role == "primary" and not synchronized:
        raise Rejected(["FortiADC primary has no verified synchronized secondary"],
                       reason_codes=["fortiadc_ha_not_synchronized"])
    return role


def verify_ha_sync(access, wait):
    # Incremental sync can still be running after the CLI returns to its prompt.
    for attempt in range(6):
        try:
            require_ha_write(access, "primary")
            return
        except Rejected as exc:
            if exc.reason_codes != ["fortiadc_ha_not_synchronized"] or attempt == 5:
                raise
        wait(1)


def member_outcome(access, role, pool, result, parse, expected):
    if role == "primary":
        try:
            verify_ha_sync(access, sleep)
        except Rejected as exc:
            return {"result": "unknown", "reason": exc.reasons[0]}
        if result == "unknown":
            return {"result": result}
        try:
            observed = parse(access.check_query(show_command(pool)))
        except Exception:
            return {"result": "unknown", "reason": "the check account could not read the FortiADC pool member state"}
        if observed != expected:
            return {"result": "unknown", "reason": "the check account sees a different FortiADC pool member state"}
    return {"result": result}

CLEAR_FIRMWARE = ("7.6.7 build0676",)
WAF_BLOCK_IP = "waf-block-ip"
CLEAR_FAMILIES = {"slb-session": "session", "slb-persistence": "persistence"}
CLEAR_TABLES = frozenset((WAF_BLOCK_IP, *CLEAR_FAMILIES))
SLB_COLUMNS = "client-ip/port virtual-server-ip/port local-ip/port real-server-ip/port protocol service "
CLEAR_HEADERS = {
    "slb-session": SLB_COLUMNS + "state in-bytes out-bytes expire virtual-server-name real-server-name",
    "slb-persistence": SLB_COLUMNS + "expire virtual-server-name real-server-name",
    WAF_BLOCK_IP: "ip vs-name expire",
}
CLEAR_FILTER_FIELDS = ("source ip range", "source port range", "dest ip range", "dest port range", "virtual server")
SESSION_FILTER_FIELDS = ("type", "protocol", "trans source ip range", "trans source port range",
                         "trans dest ip range", "trans dest port range", "real server")
CLEAR_REFUSAL = re.compile(r"(?im)^\s*(?:Parsing error|invalid (?:command|or incomplete command)|"
                           r"incomplete command|no permission|permission denied|.* is invalid filter option)\b")


@dataclass(frozen=True)
class ClearTarget:
    table: str
    key: str
    source_ip: str | None

    @property
    def listing(self):
        prefix = "execute waf block-ip" if self.table == WAF_BLOCK_IP else self.prefix
        return prefix + " list"

    @property
    def show(self):
        prefix = "execute waf block-ip" if self.table == WAF_BLOCK_IP else self.prefix
        return prefix + " filter show"

    @property
    def prefix(self):
        return "diagnose server-load-balance " + CLEAR_FAMILIES[self.table]

    @property
    def commands(self):
        if self.table == WAF_BLOCK_IP:
            return [f"execute waf block-ip release vs-name {self.key} ip {self.source_ip}"]
        selector = f"vs-name {self.key}"
        if self.source_ip:
            selector += f" source-ip {self.source_ip}"
        return [f"{self.prefix} filter '{selector}'", self.prefix + " clear l4", self.prefix + " filter clear"]

    def filter_fields(self, selected=False):
        if self.table == WAF_BLOCK_IP:
            return {"ip range": "any", "virtual server": "any"}
        fields = CLEAR_FILTER_FIELDS + (SESSION_FILTER_FIELDS if self.table == "slb-session" else ())
        result = dict.fromkeys(fields, "any")
        result["filter flag"] = "0"
        if selected:
            result["virtual server"] = self.key
            result["filter flag"] = "1000"
            if self.source_ip:
                result["filter flag"] = "1010"
                result["source ip range"] = f"{self.source_ip} - {self.source_ip}"
        return result


def clear_target(table, key, changes):
    source = None
    if set(changes) == {"source-ip"} and isinstance(changes["source-ip"], str):
        try:
            source = str(ipaddress.IPv4Address(changes["source-ip"]))
        except ValueError:
            pass
    if (table not in CLEAR_TABLES or POOL.fullmatch(key) is None
            or (source is None and (changes or table == WAF_BLOCK_IP))):
        raise Rejected(["clear needs one FortiADC virtual server name as key and a single IPv4 address in source-ip"
                        " (optional only for the Layer 4 tables)"], reason_codes=["clear_invalid_target"])
    return ClearTarget(table, key, source)


def clear_body(output, command):
    """Return the answer of a completed CLI frame, dropping only its exact echo."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if lines and lines[0] == command:
        lines.pop(0)
    text = "\n".join(lines)
    if cli_error(text) or CLEAR_REFUSAL.search(text) or "--More--" in text or "\ufffd" in text:
        raise ValueError("FortiADC clear command or readback was refused or incomplete")
    return lines


def clear_filter(output, command):
    fields = {}
    for line in clear_body(output, command):
        field, separator, value = line.partition(":")
        if not separator or field in fields:
            raise ValueError("unrecognized FortiADC clear filter")
        fields[field] = value.strip()
    return fields


def clear_entries(target, output):
    """Identify rows without their changing expiry, byte counts or TCP state."""
    lines = clear_body(output, target.listing)
    if not lines or " ".join(lines[0].split()) != CLEAR_HEADERS[target.table]:
        raise ValueError("FortiADC clear listing has no recognized heading")
    rows = []
    for line in lines[1:]:
        fields = line.split()
        if target.table == WAF_BLOCK_IP:
            if len(fields) != 3 or not fields[2].isdigit():
                raise ValueError("unrecognized FortiADC WAF block")
            address, server = str(ipaddress.ip_address(fields[0])), fields[1]
            entry = [address, server]
        else:
            session = target.table == "slb-session"
            if (len(fields) != (16 if session else 13)
                    or any(not fields[i].isdigit() for i in (1, 3, 5, 7, 8, len(fields) - 3))
                    or (session and any(not fields[i].isdigit() for i in (11, 12)))):
                raise ValueError("unrecognized FortiADC SLB entry")
            for i in (0, 2, 4, 6):
                fields[i] = str(ipaddress.ip_address(fields[i]))
            address, server = fields[0], fields[-2]
            entry = fields[:10] + fields[-2:]
        if POOL.fullmatch(server) is None:
            raise ValueError("unrecognized FortiADC virtual server")
        rows.append((address, server, entry))
    return rows


def clear_scope(target, rows):
    entries = sorted(entry for address, server, entry in rows
                     if server == target.key and (target.source_ip is None or address == target.source_ip))
    return {"virtual_server": target.key, "source_ip": target.source_ip, "entries": entries}


def clear_snapshot_digest(snapshot_text):
    # FortiADC can re-encrypt a stored secret when it prints it.
    masked = re.sub(r"(?m)(\bENC[ \t]+)\S+", r"\1[redacted]", snapshot_text)
    return hashlib.sha256(masked.encode("utf-8")).hexdigest()


def cli_error(text: str):
    for pattern, label in REFUSALS:
        if pattern.search(text):
            return label
    return None


def prompt_spec(hostname: str) -> PromptSpec:
    return PromptSpec(anchor=("\n%s" % hostname).encode("ascii"), ends=(b"# ",), continuation=None, error=cli_error)


def exit_code(record: dict) -> int:
    return EXIT[record["result"]]


def show_command(pool: str) -> str:
    return "show load-balance pool %s" % pool


def render(pool: str, member: str, status: str) -> list:
    return ["config load-balance pool", 'edit "%s"' % pool, "config pool_member", "edit %s" % member,
            "set status %s" % status, "next", "end", "next", "end"]


def _unreadable(why: str) -> Rejected:
    return Rejected(["the pool listing cannot be read (%s)" % why])


def _lines(text: str) -> list:
    return PAGER.sub("", text).replace("\r", "").splitlines()


def _words(raw: str) -> list:
    words, at = [], 0
    while True:
        while at < len(raw) and raw[at] in " \t":
            at += 1
        if at == len(raw):
            return words
        match = TOKEN.match(raw, at)
        if match is None:
            raise _unreadable("malformed quoting")
        words.append(match.group(2) if match.group(1) is None else match.group(1))
        at = match.end()


def parse_status(text: str, pool: str, member: str) -> str:
    target = (("config", "load-balance pool"), ("edit", pool), ("config", "pool_member"), ("edit", member))
    stack, seen, status = [], set(), None
    for raw in _lines(text):
        words = _words(raw)
        if not words:
            continue
        head = words[0]
        if head == "config" and len(words) > 1:
            stack.append(("config", " ".join(words[1:])))
        elif head == "edit" and len(words) == 2:
            stack.append(("edit", words[1]))
            if tuple(stack) in seen:
                raise _unreadable("duplicate entry")
            seen.add(tuple(stack))
        elif head in ("next", "end") and len(words) == 1:
            kind = "edit" if head == "next" else "config"
            if not stack or stack[-1][0] != kind:
                raise _unreadable("unbalanced block")
            stack.pop()
        elif head == "set" and len(words) > 2 and stack and stack[-1][0] == "edit":
            if tuple(stack) == target and words[1] == "status":
                if status is not None:
                    raise _unreadable("duplicate status")
                status = " ".join(words[2:])
        else:
            raise _unreadable("unexpected line")
    if stack:
        raise _unreadable("unbalanced block")
    if target not in seen:
        raise Rejected(["the pool or the member is not listed by the device"])
    status = DEFAULT_STATUS if status is None else status
    if status not in STATUSES:
        raise _unreadable("unknown status")
    return status


HEALTH_STATES = ("UP", "DOWN")
VS_COMMAND = "show load-balance virtual-server"
HEALTH_REFUSALS = re.compile(r"parsing error|command fail|permission|not authorized|unknown action|invalid", re.IGNORECASE)
AVAILABILITY = re.compile(r"\bavailability:[ \t]*([A-Za-z]+)")
RUNTIME_VS = re.compile(r"(?m)^[ \t]*virtual-server:[ \t]*(\S+),[ \t]*availability:[ \t]*[A-Za-z]+[ \t]*$")
RUNTIME_POOL = re.compile(r"(?m)^[ \t]*real-server-pool:[ \t]*(\S+)[ \t]*\n")
MEMBER_ID = re.compile(r"\bid:[ \t]*([0-9]+)\b")
HC_STATE = re.compile(r"\bhc_state:[ \t]*([A-Za-z]+)")


def vs_stat_command(vs: str) -> str:
    return "diagnose server-load-balance vs_stat vdom root vs %s" % vs


def _health_unreadable(why: str) -> Rejected:
    return Rejected(["the health of the pool members cannot be read (%s); the change is refused" % why])


def parse_vs_stat(text: str, vs: str | None = None, pool: str | None = None) -> dict:
    if HEALTH_REFUSALS.search(text):
        raise _health_unreadable("vs_stat was refused")
    text = text.replace("\r", "")
    lines = text.splitlines()
    if len([1 for line in lines if AVAILABILITY.search(line)]) != 1:
        raise _health_unreadable("vs_stat output is not recognised")
    if vs is not None and (RUNTIME_VS.findall(text) != [vs] or RUNTIME_POOL.findall(text) != [pool]):
        raise _health_unreadable("vs_stat does not identify the expected virtual server and pool")
    states, current = {}, None
    for line in lines:
        found = MEMBER_ID.search(line)
        if found:
            if current is not None and current not in states:
                raise _health_unreadable("vs_stat omitted a member health state")
            current = int(found.group(1))
        state = HC_STATE.search(line)
        if state is None:
            continue
        if current is None or current in states or state.group(1).upper() not in HEALTH_STATES:
            raise _health_unreadable("vs_stat member list is not recognised")
        states[current] = state.group(1).upper()
    if current is not None and current not in states:
        raise _health_unreadable("vs_stat omitted a member health state")
    if not states:
        raise _health_unreadable("vs_stat lists no members")
    return states


def read_health(access, vs: str, pool: str | None = None) -> dict:
    if POOL.fullmatch(vs) is None:
        raise _health_unreadable("the virtual server name is not valid")
    try:
        text = access.diagnose_query(vs_stat_command(vs))
    except Exception:
        raise _health_unreadable("vs_stat query failed") from None
    return {number: state == "UP" for number, state in
            parse_vs_stat(text, vs if pool is not None else None, pool).items()}


def _blocks(text: str, section: str) -> dict:
    stack, blocks, current = [], {}, None
    for raw in _lines(text):
        words = _words(raw)
        if not words:
            continue
        head = words[0]
        if head == "config" and len(words) > 1:
            stack.append(("config", " ".join(words[1:])))
        elif head == "edit" and len(words) == 2:
            stack.append(("edit", words[1]))
            if tuple(stack) == (("config", section), ("edit", words[1])):
                if words[1] in blocks:
                    raise _unreadable("duplicate entry")
                current = blocks[words[1]] = {}
        elif head in ("next", "end") and len(words) == 1:
            kind = "edit" if head == "next" else "config"
            if not stack or stack[-1][0] != kind:
                raise _unreadable("unbalanced block")
            stack.pop()
        elif head == "set" and len(words) > 2 and stack and stack[-1][0] == "edit":
            if len(stack) == 2 and stack[0] == ("config", section):
                current[words[1]] = " ".join(words[2:])
        else:
            raise _unreadable("unexpected line")
    if stack:
        raise _unreadable("unbalanced block")
    return blocks


def _member_numbers(text: str, pool: str) -> list:
    numbers, stack = [], []
    for raw in _lines(text):
        words = _words(raw)
        if not words:
            continue
        if words[0] == "config" and len(words) > 1:
            stack.append(("config", " ".join(words[1:])))
        elif words[0] == "edit" and len(words) == 2:
            stack.append(("edit", words[1]))
            if len(stack) == 4 and stack[2] == ("config", "pool_member"):
                numbers.append(words[1])
        elif words[0] in ("next", "end") and stack:
            stack.pop()
    return numbers


def prechecks(access, pool: str, member: str, status: str, listing: str) -> None:
    try:
        servers = _blocks(access.query(VS_COMMAND), "load-balance virtual-server")
    except Rejected:
        raise
    except Exception:
        raise Rejected(["the virtual servers cannot be read"]) from None
    users = []
    for name, attributes in servers.items():
        if attributes.get("content-routing", "disable") != "disable" or attributes.get("schedule-pool-list"):
            raise Rejected(["the virtual server %s selects pools by content routing or schedule; "
                            "the pool use cannot be evaluated" % name])
        if attributes.get("load-balance-pool") == pool:
            users.append(name)
    if not users:
        raise Rejected(["no virtual server uses the pool; the effect of the change cannot be evaluated"])
    numbers = _member_numbers(listing, pool)
    statuses = {number: parse_status(listing, pool, number) for number in numbers}
    statuses[member] = status
    for vs in users:
        health = read_health(access, vs)
        if not any(state == "enable" and health.get(int(number), False) for number, state in statuses.items()):
            raise Rejected(["the change would leave virtual server %s without a healthy enabled member" % vs])


def _hostname(access) -> str:
    try:
        found = HOSTNAME_LINE.findall(access.query("get system status").replace("\r", ""))
    except Exception:
        raise Rejected(["the device state cannot be read"]) from None
    if len(found) != 1 or HOSTNAME.fullmatch(found[0]) is None:
        raise Rejected(["the device hostname cannot be established"])
    return found[0]


def _listing(access, pool: str) -> str:
    try:
        return access.query(show_command(pool))
    except Exception:
        raise Rejected(["the device state cannot be read"]) from None


def _read(access, pool: str, member: str) -> str:
    return parse_status(_listing(access, pool), pool, member)


def _readback(access, pool: str, member: str):
    try:
        return _read(access, pool, member)
    except Rejected:
        return None


def _write(access, spec, pool: str, member: str, status: str, role: str):
    try:
        require_ha_write(access, role)
        access.apply(render(pool, member, status), spec)
    except Exception as exc:
        return "write failed (%s)" % type(exc).__name__
    return None


# The deprecated direct pool member commands (pool-member, pool-member-add, pool-member-remove) write, like every
# Admin apply, only with the plan_sha256 of their own approved preview of the same command and device state.
MEMBER_PLAN_SHA256 = re.compile(r"[0-9a-f]{64}")
MEMBER_PLAN_CHANGED = ("the fresh plan differs from the previewed plan (another device, or the pool changed since the"
                       " preview); run the command with --preview again and approve its plan_sha256")


def member_plan_required(command: str, expected_plan_sha256) -> None:
    """Refuse a write of `command` without a well-formed approved hash, before the device is contacted."""
    if expected_plan_sha256 is None:
        raise Rejected(["%s writes only with the plan_sha256 of its approved --preview, passed as"
                        " --expect-plan-sha256" % command], reason_codes=["plan_changed"])
    if not isinstance(expected_plan_sha256, str) or MEMBER_PLAN_SHA256.fullmatch(expected_plan_sha256) is None:
        raise Rejected(["expected_plan_sha256 must be 64 lowercase hexadecimal characters"])


def member_target(device) -> dict:
    """The configured identity of the target a plan_sha256 binds: alias, address, port and pinned SSH host key."""
    return {"device": device.name, "address": device.address, "port": device.port,
            "host_key_fingerprint": device.host_key_fingerprint}


def member_plan_digest(plan: dict) -> str:
    text = json.dumps(plan, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def member_approved(plan: dict, preview: bool, expected_plan_sha256) -> str:
    """The plan_sha256 of `plan`; outside a preview it must equal the approved hash, else nothing is written."""
    digest = member_plan_digest(plan)
    if not preview and digest != expected_plan_sha256:
        raise Rejected([MEMBER_PLAN_CHANGED], reason_codes=["plan_changed"],
                       reason_details=[{"code": "plan_changed", "expected": expected_plan_sha256, "actual": digest}])
    return digest


def run(access, pool: str, member: str, status: str, *, target: dict, preview: bool = False,
        expected_plan_sha256=None) -> dict:
    if not isinstance(pool, str) or POOL.fullmatch(pool) is None:
        raise Rejected(["the pool name is not valid"])
    if not isinstance(member, str) or MEMBER.fullmatch(member) is None:
        raise Rejected(["the member must be a pool member number"])
    if status not in STATUSES:
        raise Rejected(["the status must be one of: %s" % ", ".join(STATUSES)])
    if not preview:
        member_plan_required("pool-member", expected_plan_sha256)
    from netops_admin.fortiadc_member import parse_members

    hostname = _hostname(access)
    spec = prompt_spec(hostname)
    listing = _listing(access, pool)
    before = parse_status(listing, pool, member)
    record = {"pool": pool, "member": member, "requested": status, "before": before}
    changed = before != status
    commands = render(pool, member, status) if changed else []
    # The plan binds the configured target and every member of the pool as read (the backend of the member too).
    plan = {"operation": "pool-member", "target": target, "hostname": hostname, "pool": pool, "member": member,
            "before": before, "members_before": parse_members("\n".join(_lines(listing)), pool), "requested": status,
            "commands": commands, "inverse": render(pool, member, before) if changed else []}
    role = None
    if changed:
        prechecks(access, pool, member, status, listing)
        role = require_ha_write(access)
    record["plan_sha256"] = member_approved(plan, preview, expected_plan_sha256)
    if preview:
        return dict(record, result="ready" if changed else "unchanged",
                    preview={"commands": plan["commands"], "inverse": plan["inverse"]})
    if not changed:
        return dict(record, result="unchanged", after=before)
    failure = _write(access, spec, pool, member, status, role)
    after = _readback(access, pool, member)
    if failure is None and after == status:
        result = "confirmed"
    else:
        record["reason"] = failure or ("read-back differs" if after is not None else "read-back unreadable")
        if after != before:
            _write(access, spec, pool, member, before, role)
            after = _readback(access, pool, member)
        result = "rolled_back" if after == before else "unknown"
    return dict(record, after=after) | member_outcome(
        access, role, pool, result, lambda text: parse_status(text, pool, member), after)


def certificate_names(text):
    """Project a complete FortiADC local certificate GET to object names."""
    from netops_core import prompt

    names, current, has_status = set(), None, False
    if "--More--" in text or "\ufffd" in text or not text.strip():
        raise ValueError("certificate listing is incomplete")
    for line in prompt.cleaned(text.replace("\r\n", "\n"), prompt.PLATFORM_FORTIADC).splitlines():
        if not line.strip():
            continue
        match = CERT_NAMES.fullmatch(line.strip())
        if match:
            if current is not None and not has_status or match[1].strip() in names:
                raise ValueError("certificate listing is incomplete")
            current, has_status = match[1].strip(), False
            names.add(current)
        elif current is None or not re.fullmatch(r"[ \t]+[A-Za-z0-9_-]+:[^\r\n]*", line):
            raise ValueError("certificate listing is incomplete")
        elif line.lstrip().startswith("acme-status:"):
            has_status = bool(line.partition(":")[2].strip())
    if not names or not has_status:
        raise ValueError("certificate listing is incomplete")
    return names
