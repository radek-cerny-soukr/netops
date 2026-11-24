"""FortiOS checks whose findings use only object identity and bounded evidence."""
from __future__ import annotations

from . import fortios_audit as fortios
from .engine import EVALUATED, NOT_EVALUATED, check, section_missing
from .management import SYSLOG_LEVELS
from .platforms import VISIBLE


def _entries(tree, name):
    table = tree.section(name)
    return table.entries if table is not None else {}


def _value(node, name, default=None, *, gap=""):
    value = None if node is None else node.value(name)
    return default if value is None and not gap else value


def _gap(tree, context, *names):
    for name in names:
        if context.live and context.snapshot is not None:
            visibility = context.visibility(name)
            if visibility.state != VISIBLE:
                return visibility.reason
        elif tree.section(name) is None and name not in fortios.DEFAULT_OMITTED:
            return section_missing(name)
    return ""


def _hit(section, node, attribute, **evidence):
    return {"object_key": "/".join(node.path), "section": section,
            "line": node.line_of(attribute) or node.line, "evidence": evidence}


def _status(inspect):
    def status(tree, context):
        reason, _ = inspect(tree, context)
        return (NOT_EVALUATED, reason) if reason else (EVALUATED, "")
    return status


def _enabled(value):
    return value in ("enable", "disable")


def _ssh(tree, context):
    tree = fortios.effective_tree(tree, context)
    global_gap = _gap(tree, context, fortios.GLOBAL)
    setting = _value(tree.section(fortios.GLOBAL), "admin-ssh-v1", "disable", gap=global_gap)
    if setting == "disable":
        return "", ()
    port_gap = _gap(tree, context, fortios.INTERFACE)
    entries = _entries(tree, fortios.INTERFACE)
    candidates = [(port, _value(port, "status", "up", gap=port_gap))
                  for port in entries.values() if "ssh" in port.values("allowaccess")]
    hits = tuple(_hit(fortios.INTERFACE, port, "allowaccess", ssh_version=1)
                 for port, status in candidates if status == "up" and setting == "enable")
    reason = global_gap or port_gap
    if not reason and (not _enabled(setting) or any(
            status not in ("up", "down") for _, status in candidates)):
        reason = "effective-ssh-state-unproven"
    return reason, hits


@check("ssh_v1", audit_context=True, status=_status(_ssh), partial=True,
       offline_scope=lambda tree: _value(tree.section(fortios.GLOBAL), "admin-ssh-v1") == "enable")
def ssh_v1(tree, context):
    return _ssh(tree, context)[1]


def _external(tree, context):
    tree = fortios.effective_tree(tree, context)
    reason = _gap(tree, context, fortios.ADMIN)
    admins = _entries(tree, fortios.ADMIN)
    if (not context.live or context.snapshot is None) and (not admins or not any(
            admin.value("accprofile") == "super_admin" for admin in admins.values())):
        reason = reason or "admin-visibility-unproven"
    if reason:
        return reason, ()
    remote = [admin for admin in admins.values() if _value(admin, "remote-auth", "disable") == "enable"]
    if not remote:
        if any(not _enabled(_value(admin, "remote-auth", "disable")) for admin in admins.values()):
            return "effective-remote-auth-unproven", ()
        return "", (_hit(fortios.ADMIN, tree.section(fortios.ADMIN), "remote-auth", issue="no-remote-login"),)
    hits = []
    groups = _entries(tree, fortios.GROUP)
    for admin in remote:
        name = admin.value("remote-group")
        group = groups.get(name)
        if not name:
            hits.append(_hit(fortios.ADMIN, admin, "remote-auth", issue="no-remote-group"))
            continue
        if group is None or not group.values("member"):
            gap = _gap(tree, context, fortios.GROUP)
            reason = reason or gap
            if not gap:
                hits.append(_hit(fortios.ADMIN, admin, "remote-group", issue="no-group-member"))
            continue
        if any(_value(_entries(tree, section).get(member), "server")
               for member in group.values("member") for section in fortios.AAA_SERVERS):
            continue
        gap = _gap(tree, context, *fortios.AAA_SERVERS)
        reason = reason or gap
        if not gap:
            hits.append(_hit(fortios.ADMIN, admin, "remote-group", issue="no-server-endpoint"))
    return reason, hits


@check("external_login", audit_context=True, applies=lambda intent: intent.get("external_aaa_required"),
       status=_status(_external), partial=True)
def external_login(tree, context):
    return _external(tree, context)[1]


def _snmp(tree, context):
    tree = fortios.effective_tree(tree, context)
    info_gap = _gap(tree, context, fortios.SNMP_INFO)
    active = _value(tree.section(fortios.SNMP_INFO), "status", "disable", gap=info_gap)
    if active == "disable":
        return "", ()
    user_gap = _gap(tree, context, fortios.SNMP_USERS)
    reason = info_gap or user_gap
    if active != "enable":
        return reason or "effective-snmp-state-unproven", ()
    hits = []
    for user in _entries(tree, fortios.SNMP_USERS).values():
        status = _value(user, "status", "enable", gap=user_gap)
        level = _value(user, "security-level", "no-auth-no-priv", gap=user_gap)
        if status == "disable":
            continue
        if status != "enable":
            reason = reason or "effective-snmp-user-state-unproven"
        elif level in ("no-auth-no-priv", "auth-no-priv"):
            hits.append(_hit(fortios.SNMP_USERS, user, "security-level", security_level=level))
        elif level != "auth-priv" or not (_value(user, "auth-proto", "sha", gap=user_gap)
                                          and _value(user, "priv-proto", "aes", gap=user_gap)):
            reason = reason or "effective-snmp-security-level-unproven"
    return reason, hits


def _snmp_in_scope(tree):
    return _value(tree.section(fortios.SNMP_INFO), "status") == "enable" or any(
        user.value("status") == "enable" or user.value("security-level")
        for user in _entries(tree, fortios.SNMP_USERS).values()
    )


@check("snmp_v3_auth_priv", audit_context=True, status=_status(_snmp), partial=True,
       offline_scope=_snmp_in_scope)
def snmp_v3_auth_priv(tree, context):
    return _snmp(tree, context)[1]


def _ntp(tree, context):
    tree = fortios.effective_tree(tree, context)
    node = tree.section(fortios.NTP)
    ntp_gap = reason = _gap(tree, context, fortios.NTP)
    sync = _value(node, "ntpsync", "enable", gap=ntp_gap)
    mode = _value(node, "type", "fortiguard", gap=ntp_gap)
    if sync == "disable" or (sync == "enable" and mode == "fortiguard"):
        return "", ()
    if sync != "enable" or mode != "custom":
        return reason or "effective-ntp-mode-unproven", ()
    servers = node.section("ntpserver")
    if servers is None:
        return reason or section_missing("system ntp/ntpserver"), ()
    hits = []
    for server in servers.entries.values():
        if not server.value("server"):
            continue  # No usable custom destination. The existing sync rule covers this.
        authentication = _value(server, "authentication", "disable", gap=ntp_gap)
        key_absent = not server.value("key") and (not ntp_gap or "key" in server.attrs)
        if authentication == "disable" or authentication == "enable" and key_absent:
            hits.append(_hit(fortios.NTP, server, "authentication", issue=(
                "authentication-disabled" if authentication == "disable" else "key-missing"
            )))
        elif authentication != "enable" or not server.value("key"):
            reason = reason or "effective-ntp-auth-unproven"
    return reason, hits


@check("ntp_auth", audit_context=True, applies=lambda intent: intent.get("ntp_auth_required"),
       status=_status(_ntp), partial=True)
def ntp_auth(tree, context):
    return _ntp(tree, context)[1]


_FORTIOS_LEVELS = (*SYSLOG_LEVELS[:5], "notification", "information", "debug")


def _syslog(tree, context):
    tree = fortios.effective_tree(tree, context)
    desired = context.intent["syslog_severity"]
    threshold = SYSLOG_LEVELS.index(desired)
    reason, hits = "", []
    for setting, filtering in fortios.SYSLOG:
        node = tree.section(setting)
        gap = _gap(tree, context, setting)
        active = _value(node, "status", "disable", gap=gap)
        if active == "disable":
            continue
        reason = reason or gap
        if active != "enable":
            reason = reason or "effective-syslog-status-unproven"
            continue
        if not node.value("server"):
            continue  # The existing rule handles missing destinations.
        filter_node = tree.section(filtering)
        filter_gap = _gap(tree, context, filtering)
        level = _value(filter_node, "severity", "information", gap=filter_gap)
        reason = reason or filter_gap
        if level not in _FORTIOS_LEVELS:
            reason = reason or "effective-syslog-severity-unproven"
        elif _FORTIOS_LEVELS.index(level) < threshold:
            hit = _hit(filtering, filter_node or node, "severity", severity=level, required=desired)
            hit["object_key"] = filtering
            hits.append(hit)
    return reason, hits


@check("syslog_level", audit_context=True, applies=lambda intent: "syslog_severity" in intent,
       status=_status(_syslog), partial=True)
def syslog_level(tree, context):
    return _syslog(tree, context)[1]


def _ports(tree, context):
    tree = fortios.effective_tree(tree, context)
    interfaces = _entries(tree, fortios.INTERFACE)
    interface_gap = reason = _gap(tree, context, fortios.INTERFACE)
    hits = []
    for name, declaration in context.intent["ports"].items():
        if declaration["role"] != "unused":
            continue
        port = interfaces.get(name)
        kind, status = _value(port, "type"), _value(port, "status", "up", gap=interface_gap)
        if not kind or kind == "physical" and status not in ("up", "down"):
            reason = reason or "effective-physical-port-state-unproven"
        elif kind == "physical" and status == "up":
            hits.append(_hit(fortios.INTERFACE, port, "status", status=status))
    return reason, hits


@check("unused_up", audit_context=True,
       applies=lambda intent: any(port["role"] == "unused" for port in intent.get("ports", {}).values()),
       status=_status(_ports), partial=True)
def unused_up(tree, context):
    return _ports(tree, context)[1]
