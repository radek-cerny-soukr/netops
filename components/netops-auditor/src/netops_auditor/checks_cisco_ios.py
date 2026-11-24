"""Evidence-based IOS and IOS XE configuration checks."""
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from ipaddress import ip_address, ip_network
import re

from . import l1_cli
from .engine import EVALUATED, NOT_EVALUATED, check
from .management import SYSLOG_LEVELS
from .platforms import VISIBLE


@dataclass
class Result:
    hits: list = field(default_factory=list)
    reason: str = ""

    def need(self, condition, section):
        if not condition and not self.reason:
            self.reason = "unproven: " + section
        return condition

    def hit(self, key, section, command=None, **evidence):
        self.hits.append(dict(object_key=key, section=section,
                              line=command.line if command else 1, evidence=evidence))


def last(commands, *words):
    return next((item for item in reversed(commands) if item.starts_with(*words)), None)


def toggle(command):
    return None if command is None or command.mode == "default" else command.mode == "set"


def active(commands, prefix, identity, *, reset_all=True):
    """Apply repeated keyed declarations and their no/default forms in input order."""
    values = {}
    for item in commands:
        if item.starts_with(*prefix):
            key = identity(item.tokens[len(prefix):])
            if item.mode == "set" and key is not None:
                values[key] = item
            elif key is not None:
                values.pop(key, None)
            elif item.mode != "set" and reset_all:
                values.clear()
    return values


class IOS:
    def __init__(self, tree, context):
        self.context = context
        self.intent = context.intent
        self.top = tuple(item for item in tree.commands if not item.parents)
        self.children = {}
        header = None
        for item in tree.commands:
            if not item.parents:
                header = item.line
            elif len(item.parents) == 1:
                self.children.setdefault(header, []).append(item)
        self.aux = context.snapshot.auxiliary if context.snapshot else {}
        view = self.aux.get("cli view", "")
        privileged = (self.has_aux("privilege") and self.has_aux("cli view")
                      and re.search(r"(?m)^Current privilege level is 15[ \t]*$", self.aux["privilege"]))
        unrestricted = re.search(r"(?mi)^Current view is ['\"]?root['\"]?[ \t]*$|^No view is active[ \t]*!", view)
        self.verified = bool(context.snapshot and context.snapshot.complete and (
            any(value.reason == "verified-profile" for value in context.snapshot.sections.values())
            or privileged and unrestricted
        ))
        version = last(self.top, "version")
        self.known_version = bool(version and len(version.tokens) == 2
                                  and re.fullmatch(r"(?:15|16|17)\.\d+", version.tokens[1]))

    def full(self, section):
        if self.verified:
            visibility = self.context.snapshot.sections.get(section)
            return visibility.state == VISIBLE if visibility else section in l1_cli.SECTIONS
        return False

    def has_aux(self, section):
        return self.context.visibility(section).reason == "auxiliary-output" and section in self.aux

    def get(self, *words):
        return last(self.top, *words)

    def body(self, item):
        return self.children.get(item.line, ())

    def blocks(self, *words):
        return {item.tokens: item for item in active(self.top, words, lambda args: args or None).values()}

    def vty(self):
        lines = {}
        # Associate each block with its own occurrence, including repeated identical headers.
        for item in self.top:
            if not item.starts_with("line", "vty"):
                continue
            bounds = item.tokens[2:]
            if len(bounds) not in (1, 2) or not all(re.fullmatch(r"\d{1,4}", x) for x in bounds):
                continue
            first, last_line = int(bounds[0]), int(bounds[-1])
            commands = self.body(item)
            for number in range(first, last_line + 1):
                if item.mode == "set":
                    lines.setdefault(number, []).extend(commands)
                else:
                    lines.pop(number, None)
        return lines


def rule(name, section, *, applies=None, scope=None):
    def register(evaluate):
        def outcome(tree, context):
            result = Result()
            evaluate(IOS(tree, context), result)
            return result

        def status(tree, context):
            result = outcome(tree, context)
            if result.reason and not (result.hits and context.snapshot is None):
                return NOT_EVALUATED, result.reason
            return EVALUATED, ""

        @check("ios_" + name.replace("-", "_"), audit_context=True, status=status,
               partial=True, applies=applies,
               offline_scope=scope or (lambda tree: bool(tree.section(section))))
        def findings(tree, context):
            return outcome(tree, context).hits

        return evaluate
    return register


def transports(commands):
    cmd = last(commands, "transport", "input")
    if not cmd or cmd.mode != "set" or len(cmd.tokens) < 3:
        return None, cmd
    modes = set(cmd.tokens[2:])
    if modes == {"all"}:
        return {"ssh", "telnet"}, cmd
    if modes == {"none"}:
        return set(), cmd
    if modes <= {"ssh", "telnet", "rlogin", "lat", "pad", "udptn", "nasi", "mop"}:
        return modes, cmd
    return None, cmd


def vty_scope(ios, result):
    lines = ios.vty()
    result.need(lines and ios.full("line vty"), "effective VTY ranges")
    return lines


@rule("telnet-enabled", "line vty")
def telnet(ios, result):
    for number, commands in vty_scope(ios, result).items():
        modes, cmd = transports(commands)
        if result.need(modes is not None, "VTY transport") and "telnet" in modes:
            result.hit(f"vty:{number}", "line vty", cmd, state="telnet-enabled")


@rule("http-enabled", "global", scope=lambda tree: bool(tree.matching("ip", "http", "server")
                                                           or tree.matching("ip", "http", "secure-server")))
def http(ios, result):
    # HTTP defaults are platform dependent. A verified configuration can still omit the setting.
    cmd = ios.get("ip", "http", "server")
    value = toggle(cmd)
    result.need(value is not None, "HTTP listener/default")
    if value:
        result.hit("global", "global", cmd, state="enabled")


@rule("source-routing", "global", scope=lambda tree: bool(tree.matching("ip", "source-route")))
def source_route(ios, result):
    cmd = ios.get("ip", "source-route")
    enabled = toggle(cmd)
    result.need(enabled is not None or ios.full("global"), "ip source-route")
    if enabled:
        result.hit("global", "global", cmd, state="enabled")


@rule("ssh-v2", "line vty")
def ssh_version(ios, result):
    cmd = ios.get("ip", "ssh", "version")
    version = cmd.tokens[3] if cmd and cmd.mode == "set" and len(cmd.tokens) == 4 else None
    enabled = True
    if ios.has_aux("ip ssh"):
        answer = ios.aux["ip ssh"]
        enabled = not bool(re.search(r"(?mi)^SSH (?:is )?disabled\b", answer))
        match = re.search(r"(?mi)^SSH enabled\s*-\s*version (1\.99|[12](?:\.0)?)\b", answer)
        if match:
            version = match[1]
    if not enabled:
        return
    for number, commands in vty_scope(ios, result).items():
        modes, transport = transports(commands)
        if result.need(modes is not None, "SSH transport") and "ssh" in modes:
            if result.need(version in {"1", "1.0", "1.99", "2", "2.0"}, "SSH protocol version"):
                if version in {"1", "1.0", "1.99"}:
                    result.hit(f"vty:{number}", "line vty", cmd or transport, version=version)


@rule("idle-timeout", "line vty")
def idle_timeout(ios, result):
    for number, commands in vty_scope(ios, result).items():
        modes, _ = transports(commands)
        if modes == set() or toggle(last(commands, "exec")) is False:
            continue
        cmd = last(commands, "exec-timeout")
        values = cmd.tokens[1:] if cmd and cmd.mode == "set" else ()
        seconds = None
        if len(values) in (1, 2) and all(re.fullmatch(r"\d{1,6}", word) for word in values):
            if len(values) == 1 or int(values[1]) < 60:
                seconds = 60 * int(values[0]) + (int(values[1]) if len(values) == 2 else 0)
        elif not values and ios.full("line vty") and ios.known_version:
            seconds = 600
        if result.need(seconds is not None, "VTY exec-timeout") and (seconds == 0 or seconds > 600):
            result.hit(f"vty:{number}", "line vty", cmd, seconds=seconds)


@rule("lockout", "global", scope=lambda tree: bool(tree.matching("login", "block-for")
                                                      or tree.matching("ip", "ssh", "authentication-retries")))
def lockout(ios, result):
    cmd = ios.get("login", "block-for")
    words = cmd.tokens if cmd else ()
    if toggle(cmd) is True:
        result.need(len(words) == 7 and words[3] == "attempts" and words[5] == "within"
                    and all(re.fullmatch(r"[1-9]\d{0,8}", words[i]) for i in (2, 4, 6)), "login block-for format")
        return
    lines = vty_scope(ios, result)
    if lines and all(transports(commands)[0] == set() for commands in lines.values()):
        return
    for commands in lines.values():
        modes, transport = transports(commands)
        if not modes:
            result.need(modes is not None, "VTY transport")
            continue
        method, _ = aaa_method(ios, commands)
        if method == "external":
            result.need(False, "external AAA lockout enforcement")
        elif method == "local" and (toggle(cmd) is False or (ios.full("global") and ios.known_version)):
            if not result.hits:
                result.hit("global", "global", cmd or transport, state="missing")
        else:
            result.need(False, "login block-for and effective AAA")


def aaa_method(ios, commands):
    enabled = toggle(ios.get("aaa", "new-model"))
    binding = last(commands, "login", "authentication")
    if enabled is False or (enabled is None and ios.full("aaa")):
        return "local", binding
    if enabled is None:
        return "unknown", binding
    name = binding.tokens[2] if binding and binding.mode == "set" and len(binding.tokens) == 3 else "default"
    method = ios.get("aaa", "authentication", "login", name)
    if toggle(method) is not True:
        if ios.full("aaa"):
            return ("local" if name == "default" else "missing"), method
        return "unknown", method
    words = method.tokens[4:]
    if not words:
        return "unknown", method
    local = {"local", "local-case", "line", "enable", "none"}
    # Even a later external method can be used if preceding methods return an error.
    groups = [words[i + 1] for i, word in enumerate(words[:-1]) if word == "group"]
    if groups:
        states = [aaa_group(ios, name) for name in groups]
        if True in states:
            return "external", method
        return ("unknown" if None in states else "missing"), method
    return ("local" if set(words) <= local else "unknown"), method


def aaa_group(ios, name):
    def endpoint(protocol, server):
        block = ios.get(protocol, "server", server)
        address = last(ios.body(block), "address") if toggle(block) is True else None
        return toggle(address) is True and len(address.tokens) >= 3 and address.tokens[1] in ("ipv4", "ipv6")

    def legacy(protocol):
        return active(ios.top, (protocol + "-server", "host"), lambda args: args[0] if args else None)

    named = [item for item in ios.blocks("aaa", "group", "server").values()
             if len(item.tokens) == 5 and item.tokens[4] == name and item.tokens[3] in ("tacacs+", "radius")]
    if name in ("tacacs+", "radius"):
        protocol = name.rstrip("+")
        found = bool(legacy(protocol)) or any(endpoint(protocol, item.tokens[2])
            for item in ios.blocks(protocol, "server").values() if len(item.tokens) == 3)
    elif named:
        found = False
        for item in named:
            protocol = item.tokens[3].rstrip("+")
            children = ios.body(item)
            names = active(children, ("server", "name"), lambda args: args[0] if args else None)
            inline = active(children, ("server-private",), lambda args: args[0] if args else None)
            hosts = active(children, ("server",), lambda args: args[0] if args and args[0] != "name" else None, reset_all=False)
            found |= bool(inline or hosts.keys() & legacy(protocol).keys()
                          or any(endpoint(protocol, server) for server in names))
    else:
        found = False
    return True if found else False if ios.full("aaa") else None


@rule("external-login", "aaa", applies=lambda intent: intent.get("external_aaa_required"))
def external_login(ios, result):
    for number, commands in vty_scope(ios, result).items():
        modes, transport = transports(commands)
        if not result.need(modes is not None, "VTY transport") or not modes:
            continue
        method, cmd = aaa_method(ios, commands)
        if result.need(method != "unknown", "AAA method, group or server") and method != "external":
            result.hit(f"vty:{number}", "aaa", cmd or transport, state="external-login-missing")


def first_word(args):
    return args[0] if args else None


@rule("local-password-storage", "aaa", scope=lambda tree: bool(tree.matching("username") or tree.matching("enable")))
def local_password(ios, result):
    result.need(ios.full("aaa"), "local account visibility")
    accounts = active(ios.top, ("username",), first_word)
    enables = active(ios.top, ("enable", "password"),
                     lambda args: int(args[1]) if len(args) >= 2 and args[0] == "level" and args[1].isdigit() else 15)
    weak = {}
    for cmd in (*accounts.values(), *enables.values()):
        words = cmd.tokens
        if words[0] == "enable":
            value = words[4:] if words[2:3] == ("level",) else words[2:]
            field_name = "password"
        else:
            kind = next((index for index in range(2, len(words)) if words[index] in ("password", "secret")), None)
            if kind is None:
                result.need("nopassword" in words[2:], "account credential type")
                continue
            field_name = words[kind]
            value = words[kind + 1:]
        if not value or value == ("ACCESS-DENIED",):
            result.need(False, "account credential type")
            continue
        storage = value[0] if len(value) > 1 and value[0].isdigit() else None
        if field_name == "secret" and storage in {"5", "8", "9"}:
            continue
        if field_name == "password" and (storage in {"0", "7"} or (storage is None and value[0] != "SECRET-DATA")):
            weak.setdefault((words[0], storage or "0"), []).append(cmd)
        else:
            result.need(False, "account credential type")
    for (kind, storage), commands in weak.items():
        result.hit(f"{kind}:type-{storage}", "aaa", commands[0], storage_type=int(storage), count=len(commands))


@rule("v1v2c-community", "snmp")
def snmp_community(ios, result):
    communities = active(ios.top, ("snmp-server", "community"), first_word)
    result.need(ios.full("snmp"), "SNMP community visibility")
    visible = [item for key, item in communities.items() if key != "ACCESS-DENIED"]
    result.need(len(visible) == len(communities), "SNMP community visibility")
    if visible and not any(item.tokens == ("snmp-server",) and item.mode == "no" for item in ios.top):
        result.hit("communities", "snmp", visible[0], count=len(visible))


def snmp_users(answer):
    rows = []
    for entry in re.split(r"(?mi)^\s*User name\s*:", answer)[1:]:
        fields = dict((name.lower(), value.strip()) for name, value in re.findall(
            r"(?mi)^\s*(Group[ -]name|Authentication protocol|Privacy protocol|Row\s*status)\s*:\s*([^\r\n]+)", entry))
        state = fields.get("rowstatus", fields.get("row status", "")).lower()
        if not state and re.search(r"(?mi)^\s*storage-type:.*\bactive(?:\s|$)", entry):
            state = "active"
        rows.append((fields.get("group name", fields.get("group-name")), state,
                     fields.get("authentication protocol", "").lower(), fields.get("privacy protocol", "").lower()))
    return rows


@rule("v3-auth-priv", "snmp", scope=lambda tree: any(item.tokens[1:2] in (("group",), ("user",))
                                                   for item in tree.matching("snmp-server")))
def snmp_v3(ios, result):
    if any(item.tokens == ("snmp-server",) and item.mode == "no" for item in ios.top):
        return
    groups = active(ios.top, ("snmp-server", "group"),
                    lambda args: args[0] if len(args) > 1 and args[1] == "v3" else None, reset_all=False)
    if not ios.has_aux("snmp users"):
        result.need(False, "show snmp user visibility")
        return
    answer = ios.aux["snmp users"]
    if re.fullmatch(r"(?i)\s*%?\s*SNMP agent (?:is )?not enabled[.!]?\s*", answer):
        return
    users = snmp_users(answer)
    if not users and answer.strip() and not re.fullmatch(r"(?i)\s*(?:%\s*)?No SNMP(?:v3)? users(?: configured| found)?[.!]?\s*", answer):
        result.need(False, "show snmp user format")
        return
    result.need(ios.full("snmp"), "SNMPv3 group visibility")
    weak = 0
    for name, state, auth, privacy in users:
        if not result.need(bool(state), "SNMP user state") or state != "active":
            continue
        group = groups.get(name)
        if not result.need(group is not None and len(group.tokens) >= 5 and group.tokens[4] in
                           {"noauth", "auth", "priv"}, "SNMPv3 user group mapping"):
            continue
        if group.tokens[4] != "priv" or "none" in (auth, privacy):
            weak += 1
        else:
            result.need(bool(auth and privacy), "SNMPv3 user auth/privacy")
    if weak:
        result.hit("active-v3-users", "snmp", count=weak, state="auth-priv-missing")


def ntp_sources(ios):
    def identity(args):
        if args[:1] == ("vrf",):
            return (args[1], args[2]) if len(args) >= 3 else None
        return ("", args[0]) if args and args[0] not in {"ACCESS-DENIED", "SECRET-DATA"} else None
    return [cmd for kind in ("server", "peer")
            for cmd in active(ios.top, ("ntp", kind), identity).values()]


@rule("no-ntp-source", "ntp")
def no_ntp(ios, result):
    sources = ntp_sources(ios)
    if not sources and result.need(ios.full("ntp"), "external NTP source visibility"):
        result.hit("ntp", "ntp", ios.get("ntp", "master"), count=0)


def number(args):
    return args[0] if args and re.fullmatch(r"\d{1,10}", args[0]) else None


@rule("ntp-auth", "ntp", applies=lambda intent: intent.get("ntp_auth_required"))
def ntp_auth(ios, result):
    sources = ntp_sources(ios)
    result.need(ios.full("ntp"), "NTP source and key visibility")
    if not sources:
        return
    enabled = toggle(ios.get("ntp", "authenticate"))
    keys = active(ios.top, ("ntp", "authentication-key"), number)
    trusted = active(ios.top, ("ntp", "trusted-key"), number)
    weak = []
    for cmd in sources:
        tail = cmd.tokens[5:] if cmd.tokens[2] == "vrf" else cmd.tokens[3:]
        key = tail[tail.index("key") + 1:][:1] if "key" in tail else ()
        definition = keys.get(key[0]) if key else None
        if enabled is False or not key and "key" not in tail or (
            ios.full("ntp") and (enabled is not True or definition is None or key[0] not in trusted)
        ):
            weak.append(cmd)
        elif definition is None or len(definition.tokens) < 5 or definition.tokens[3] == "ACCESS-DENIED":
            result.need(False, "NTP authentication-key type")
    if weak:
        result.hit("ntp-sources", "ntp", weak[0], count=len(weak), state="authentication-missing")


LOGGING_OPTIONS = frozenset({"alarm", "buffered", "buginf", "cns-events", "console", "count", "delimiter",
    "discriminator", "dmvpn", "event", "facility", "filter", "flow-export", "history", "host", "message-counter",
    "monitor", "on", "origin-id", "persistent", "queue-limit", "rate-limit", "server-arp", "source-interface",
    "synchronous", "trap", "userinfo"})


def logging_targets(ios):
    targets = {}
    for cmd in ios.top:
        if not cmd.starts_with("logging") or len(cmd.tokens) < 2:
            continue
        args = cmd.tokens[1:]
        if args[0] == "host":
            args = args[1:]
        elif args[0] in LOGGING_OPTIONS or not any(char in args[0] for char in ".:"):
            continue
        if args and args[0] not in {"ACCESS-DENIED", "SECRET-DATA"}:
            vrf = args[args.index("vrf") + 1:][:1] if "vrf" in args[1:] else ()
            key = args[0], vrf
            if cmd.mode == "set":
                targets[key] = cmd
            else:
                targets.pop(key, None)
    return targets


@rule("no-syslog-target", "logging")
def no_syslog(ios, result):
    cmd = ios.get("logging", "on")
    targets = logging_targets(ios)
    if toggle(cmd) is False or not targets and result.need(ios.full("logging"), "syslog target visibility"):
        result.hit("syslog", "logging", cmd, count=0)
    elif targets:
        result.need(toggle(cmd) is True or ios.full("logging") and ios.known_version, "syslog activation")


SYSLOG_NAMES = ("emergencies", "alerts", "critical", "errors", "warnings", "notifications", "informational", "debugging")


@rule("syslog-level", "logging", applies=lambda intent: "syslog_severity" in intent)
def syslog_level(ios, result):
    activation = ios.get("logging", "on")
    targets = logging_targets(ios)
    if not result.need(targets and toggle(activation) is not False, "effective syslog target"):
        return
    if not result.need(toggle(activation) is True or ios.full("logging") and ios.known_version, "syslog activation"):
        return
    cmd = ios.get("logging", "trap")
    value = cmd.tokens[2] if cmd and cmd.mode == "set" and len(cmd.tokens) == 3 else None
    if value in SYSLOG_NAMES:
        level = SYSLOG_NAMES.index(value)
    elif value is not None and re.fullmatch(r"[0-7]", value):
        level = int(value)
    elif cmd and cmd.mode == "no":
        level = -1
    elif value is None and ios.full("logging") and ios.known_version:
        level = 6
    else:
        result.need(False, "logging trap level")
        return
    if level < SYSLOG_LEVELS.index(ios.intent["syslog_severity"]):
        result.hit("syslog", "logging", cmd, level=level)


PHYSICAL = re.compile(r"(GigabitEthernet|TenGigabitEthernet|TwentyFiveGigE|FortyGigabitEthernet|"
                      r"HundredGigE|FastEthernet|Ethernet|Gi|Te|Twe|Fo|Hu|Fa|Eth|Et)(\d+(?:/\d+)*)", re.I)
PORT_PREFIXES = {"gigabitethernet": "gi", "tengigabitethernet": "te", "twentyfivegige": "twe",
                 "fortygigabitethernet": "fo", "hundredgige": "hu", "fastethernet": "fa",
                 "ethernet": "et", "eth": "et"}


def physical(name):
    match = PHYSICAL.fullmatch(name)
    if match:
        prefix, number = match[1].lower(), match[2]
        return PORT_PREFIXES.get(prefix, prefix) + number
    return None


def interfaces(ios):
    return {physical(words[1]): cmd for words, cmd in ios.blocks("interface").items()
            if len(words) == 2 and physical(words[1])}


def port_intent(role, field=None, value=True):
    return lambda intent: any(port["role"] == role and (field is None or port.get(field) == value)
                              for port in intent.get("ports", {}).values())


def intended_ports(ios, result, matches):
    ports = interfaces(ios)
    included = set()
    for name, flags in ios.intent.get("ports", {}).items():
        if not matches({"ports": {name: flags}}):
            continue
        key = physical(name)
        cmd = ports.get(key)
        if result.need(cmd is not None, "declared physical interface") and key not in included:
            included.add(key)
            yield cmd, ios.body(cmd), flags


def switch_mode(commands):
    mode = last(commands, "switchport", "mode")
    switch = next((item for item in reversed(commands) if item.tokens == ("switchport",)), None)
    if toggle(switch) is False or toggle(last(commands, "ip", "address")) or toggle(last(commands, "ipv6", "address")):
        return "routed"
    if toggle(mode) is True and len(mode.tokens) > 2:
        return mode.tokens[2]
    return None


def switchport(result, commands, wanted):
    mode = switch_mode(commands)
    if mode == "routed" or mode in {"access", "trunk"} and mode != wanted:
        return False
    return result.need(mode == wanted, f"effective switchport {wanted} mode")


def port_hit(result, port, command=None, **evidence):
    result.hit(port.tokens[1], "interface", command or port, **evidence)


DISCOVERY = port_intent("edge", "discovery_allowed", False)


@rule("edge-discovery", "interface", applies=DISCOVERY)
def discovery(ios, result):
    for port, commands, _ in intended_ports(ios, result, DISCOVERY):
        if toggle(last(commands, "shutdown")) is True:
            continue
        for protocol, setting, global_default in (("cdp", "enable", True), ("lldp", "transmit", False)):
            global_cmd = ios.get(protocol, "run")
            local_cmd = last(commands, protocol, setting)
            system, local = toggle(global_cmd), toggle(local_cmd)
            if system is None and ios.full("global") and ios.known_version:
                system = global_default
            if local is None and ios.full("interface") and ios.known_version:
                local = True
            if False not in (system, local):
                if result.need(system is True and local is True, f"effective {protocol.upper()} transmission"):
                    result.hit(f"{port.tokens[1]}:{protocol}", "interface", local_cmd or global_cmd or port,
                               protocol=protocol)


def stp_default(ios, *setting):
    return next((item for item in reversed(ios.top) if item.tokens in (
        ("spanning-tree", "portfast", *setting, "default"),
        ("spanning-tree", "portfast", "edge", *setting, "default"),
    )), None)


EDGE = port_intent("edge")


@rule("bpdu-guard", "interface", applies=EDGE)
def bpdu_guard(ios, result):
    for port, commands, _ in intended_ports(ios, result, EDGE):
        if not switchport(result, commands, "access") or toggle(last(commands, "shutdown")) is True:
            continue
        local = last(commands, "spanning-tree", "bpduguard")
        if toggle(local) is True and local.tokens[2:] in (("enable",), ("disable",)):
            if local.tokens[2] == "disable":
                port_hit(result, port, local, state="disabled")
            continue
        guard_command = stp_default(ios, "bpduguard")
        guard = toggle(guard_command)
        fast_command = last(commands, "spanning-tree", "portfast")
        fast = None
        if fast_command and fast_command.mode == "set":
            arguments = fast_command.tokens[2:]
            if arguments in ((), ("edge",), ("trunk",), ("edge", "trunk")):
                fast = True
            elif arguments in (("disable",), ("normal",), ("network",)):
                fast = False
        elif fast_command and fast_command.mode == "no" and fast_command.tokens[2:] in ((), ("edge",)):
            fast = False
        if fast is None:
            fast = toggle(stp_default(ios))
        if ios.full("global") and ios.full("interface") and ios.known_version:
            guard = False if guard is None else guard
            fast = False if fast is None else fast
        if result.need(guard is not None and (not guard or fast is not None), "BPDU guard and effective PortFast"):
            # A missing port override is usable only with complete interface visibility.
            if result.need(ios.full("interface"), "BPDU guard port override") and not (guard and fast):
                port_hit(result, port, fast_command or guard_command, state="disabled")


DEFAULT_VLAN = port_intent("edge", "default_vlan_allowed", False)


def port_vlan(ios, commands, words):
    cmd = last(commands, *words)
    if not cmd or cmd.mode != "set":
        return (1 if ios.full("interface") and ios.known_version else None), cmd
    value = cmd.tokens[len(words):]
    if len(value) == 1 and re.fullmatch(r"\d{1,4}", value[0]) and 1 <= int(value[0]) <= 4094:
        return int(value[0]), cmd
    return None, cmd


@rule("default-vlan", "interface", applies=DEFAULT_VLAN)
def default_vlan(ios, result):
    for port, commands, _ in intended_ports(ios, result, DEFAULT_VLAN):
        if not switchport(result, commands, "access"):
            continue
        admin = toggle(last(commands, "shutdown"))
        if admin is True:
            continue
        if not result.need(admin is False or ios.full("interface") and ios.known_version, "access port admin state"):
            continue
        vlan, cmd = port_vlan(ios, commands, ("switchport", "access", "vlan"))
        if result.need(vlan is not None, "effective access VLAN") and vlan == 1:
            port_hit(result, port, cmd, vlan=vlan)


def native_intent(intent):
    return any(port["role"] == "trunk" and "native_vlan" in port for port in intent.get("ports", {}).values())


@rule("trunk-native", "interface", applies=native_intent)
def trunk_native(ios, result):
    for port, commands, flags in intended_ports(ios, result, native_intent):
        if switchport(result, commands, "trunk"):
            vlan, cmd = port_vlan(ios, commands, ("switchport", "trunk", "native", "vlan"))
            if result.need(vlan is not None, "effective native VLAN") and vlan != flags["native_vlan"]:
                port_hit(result, port, cmd, vlan=vlan, expected=flags["native_vlan"])


def vlan_set(words):
    if not re.fullmatch(r"\d{1,4}(?:-\d{1,4})?(?:,\d{1,4}(?:-\d{1,4})?)*", words):
        return None
    values = set()
    for part in words.split(","):
        ends = part.split("-")
        first, final = int(ends[0]), int(ends[-1])
        if not 1 <= first <= final <= 4094:
            return None
        values.update(range(first, final + 1))
    return values


def dhcp_intent(intent):
    return bool(intent.get("dhcp_snooping_vlans") or "trusted_dhcp_ports" in intent)


@rule("dhcp-snooping", "global", applies=dhcp_intent)
def dhcp_snooping(ios, result):
    prefix = ("ip", "dhcp", "snooping")
    main = next((item for item in reversed(ios.top) if item.tokens == prefix), None)
    enabled = toggle(main)
    if enabled is None and ios.full("global") and ios.known_version:
        enabled = False
    required = set(ios.intent.get("dhcp_snooping_vlans", ()))
    if required and result.need(enabled is not None, "DHCP snooping activation"):
        vlans = set()
        known = enabled is False or ios.full("global")
        if enabled:
            for cmd in ios.top:
                if not cmd.starts_with(*prefix, "vlan"):
                    continue
                spec = "".join(cmd.tokens[4:])
                values = vlan_set(spec)
                if cmd.mode == "default" or cmd.mode == "no" and not spec:
                    vlans.clear()
                elif values is None:
                    known = False
                elif cmd.mode == "set":
                    vlans.update(values)
                else:
                    vlans.difference_update(values)
        if result.need(known, "DHCP snooping VLAN coverage") and required - vlans:
            result.hit("dhcp-snooping-vlans", "global", main, count=len(required - vlans))
    if "trusted_dhcp_ports" not in ios.intent:
        return
    wanted = {physical(port) for port in ios.intent["trusted_dhcp_ports"]}
    ports = interfaces(ios)
    result.need(wanted <= ports.keys() and ios.full("interface"), "DHCP trusted port scope")
    for name, port in ports.items():
        commands = ios.body(port)
        if switch_mode(commands) == "routed":
            result.need(name not in wanted, "trusted DHCP port is routed")
            continue
        cmd = last(commands, *prefix, "trust")
        actual = toggle(cmd)
        if actual is None and ios.full("interface") and ios.known_version and switch_mode(commands) in {"access", "trunk"}:
            actual = False
        if name in wanted or actual is True:
            if result.need(actual is not None, "DHCP trust state") and actual != (name in wanted):
                port_hit(result, port, cmd, state="unexpected-trust" if actual else "trust-missing")


STORM = port_intent("edge", "storm_control_required")


@rule("storm-control", "interface", applies=STORM)
def storm_control(ios, result):
    for port, commands, _ in intended_ports(ios, result, STORM):
        if not switchport(result, commands, "access") or toggle(last(commands, "shutdown")) is True:
            continue
        cmd = last(commands, "storm-control", "broadcast", "level")
        if toggle(cmd) is not True:
            if toggle(cmd) is False or ios.full("interface") and ios.known_version:
                port_hit(result, port, cmd, state="limit-missing")
            else:
                result.need(False, "broadcast storm-control visibility")
            continue
        values = cmd.tokens[3:]
        pps = values[:1] == ("pps",)
        thresholds = values[1:] if pps else values
        try:
            limit = Decimal(thresholds[0]) if len(thresholds) in (1, 2) else Decimal("NaN")
        except InvalidOperation:
            limit = Decimal("NaN")
        if not result.need(limit.is_finite() and limit >= 0 and (pps or limit <= 100), "broadcast storm-control unit"):
            continue
        if not pps and limit == 100:
            port_hit(result, port, cmd, state="unlimited")


UNUSED = port_intent("unused")


@rule("unused-up", "interface", applies=UNUSED)
def unused(ios, result):
    for port, commands, _ in intended_ports(ios, result, UNUSED):
        cmd = last(commands, "shutdown")
        down = toggle(cmd)
        if down is None and ios.full("interface") and ios.known_version:
            down = False
        if result.need(down is not None, "physical port administrative shutdown") and not down:
            port_hit(result, port, cmd, state="administratively-up")


def acl_address(words, family):
    if words and words[0] == "any":
        return ip_network("0.0.0.0/0" if family == 4 else "::/0"), words[1:]
    if words and words[0] == "host":
        return ip_network(words[1]), words[2:]
    if family == 6:
        return ip_network(words[0], strict=False), words[1:]
    address = ip_address(words[0])
    if len(words) > 1 and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", words[1]):
        wildcard = int(ip_address(words[1]))
        if wildcard & (wildcard + 1):
            raise ValueError("noncontiguous wildcard")
        return ip_network((address, 32 - wildcard.bit_length()), strict=False), words[2:]
    return ip_network(address), words[1:]


def subtract(networks, excluded):
    for item in networks:
        if not item.overlaps(excluded):
            yield item
        elif excluded.subnet_of(item):
            yield from item.address_exclude(excluded)


def acl_entry(words, family, extended, protocols):
    if words and words[0].isdigit():
        words = words[1:]
    if not words or words[0] == "remark":
        return None
    action, tail = words[0], words[1:]
    if action not in {"permit", "deny"}:
        raise ValueError("unknown ACL action")
    matched = protocols
    if extended:
        protocol, tail = tail[0], tail[1:]
        if protocol in {"icmp", "icmp6", "udp", "igmp"}:
            return None
        if protocol not in {"tcp", "ip", "ipv6"}:
            raise ValueError("unknown ACL protocol")
    network, tail = acl_address(tail, family)
    if extended:
        destination, tail = acl_address(tail, family)
        if destination.prefixlen != 0 or destination.version != family:
            raise ValueError("destination scope differs across IOS releases")
        if protocol == "tcp" and tail[:1] == ("eq",):
            port = {"22": "ssh", "23": "telnet", "513": "rlogin"}.get(tail[1], tail[1])
            matched, tail = protocols & {port}, tail[2:]
    if network.version != family or tail not in ((), ("log",), ("log-input",)):
        raise ValueError("unknown ACL qualifier")
    return action, network, matched


def acl_definition(ios, family, name):
    if family == 4:
        for mode in ("standard", "extended"):
            header = ios.get("ip", "access-list", mode, name)
            if toggle(header) is True:
                return ios.body(header), mode == "extended"
        if re.fullmatch(r"\d{1,4}", name):
            number = int(name)
            legacy = [cmd for cmd in ios.top if cmd.starts_with("access-list", name)]
            if legacy:
                return legacy, 100 <= number <= 199 or 2000 <= number <= 2699
    else:
        header = ios.get("ipv6", "access-list", name)
        if toggle(header) is True:
            return ios.body(header), True
    return None, False


def broad_acl(ios, family, name, allowed, protocols):
    commands, extended = acl_definition(ios, family, name)
    if commands is None:
        return None
    base = ("access-list", name)
    entries = {}
    sequence = 0
    for cmd in commands:
        if cmd.starts_with(*base):
            words = cmd.tokens[2:]
            key = words
        else:
            words = cmd.tokens
            if words and re.fullmatch(r"\d{1,10}", words[0]):
                key = int(words[0])
            else:
                key = sequence + 10
            sequence = max(sequence, key)
        if cmd.mode == "set":
            entries[key] = words
        elif not words:
            entries.clear()
        else:
            entries.pop(key, None)
    ordered = (values for _, values in sorted(entries.items())) if sequence else entries.values()
    remaining = {protocol: [ip_network("0.0.0.0/0" if family == 4 else "::/0")] for protocol in protocols}
    try:
        for words in ordered:
            entry = acl_entry(words, family, extended, protocols)
            if entry is None:
                continue
            action, prefix, matched = entry
            for protocol in matched:
                if action == "permit":
                    outside = [prefix]
                    for intended in allowed:
                        outside = list(subtract(outside, intended))
                    if any(item.overlaps(reachable) for item in outside for reachable in remaining[protocol]):
                        return True
                remaining[protocol] = list(subtract(remaining[protocol], prefix))
    except (IndexError, ValueError):
        return None
    return False


@rule("access-acl", "line vty", applies=lambda intent: intent.get("management_prefixes"))
def access_acl(ios, result):
    prefixes = [ip_network(value) for value in ios.intent["management_prefixes"]]
    ipv6 = (toggle(ios.get("ipv6", "unicast-routing")) is True
            or any(cmd.starts_with("ipv6", "address") and cmd.mode == "set"
                   for children in ios.children.values() for cmd in children))
    for number, commands in vty_scope(ios, result).items():
        modes, transport = transports(commands)
        if not result.need(modes is not None, "VTY transport") or not modes:
            continue
        if not result.need(ios.full("line vty"), "VTY ACL binding visibility"):
            continue
        for family, prefix in ((4, ("access-class",)), (6, ("ipv6", "access-class"))):
            cmd = next((item for item in reversed(commands) if item.starts_with(*prefix)
                        and (item.tokens[len(prefix) + 1:len(prefix) + 2] == ("in",)
                             or item.mode != "set" and item.tokens == prefix)), None)
            allowed = [network for network in prefixes if network.version == family]
            if not cmd and not allowed and family == 6 and not ipv6:
                continue
            if not result.need(bool(allowed), f"IPv{family} intended management prefixes"):
                continue
            if toggle(cmd) is not True:
                result.hit(f"vty:{number}:ipv{family}", "line vty", cmd or transport, state="filter-missing")
                continue
            section = "ip access-list" if family == 4 else "ipv6 access-list"
            qualifiers = cmd.tokens[len(prefix) + 2:]
            if not result.need(qualifiers in ((), ("vrf-also",)), f"IPv{family} VTY filter scope"):
                continue
            if not result.need(ios.full(section), f"IPv{family} ACL visibility"):
                continue
            broad = broad_acl(ios, family, cmd.tokens[len(prefix)], allowed, modes)
            if result.need(broad is not None, f"IPv{family} ordered ACL definition") and broad:
                result.hit(f"vty:{number}:ipv{family}", "line vty", cmd, state="filter-too-broad")
