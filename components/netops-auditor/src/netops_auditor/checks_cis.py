from __future__ import annotations

import ipaddress

from .engine import EVALUATED, NOT_EVALUATED, check, section_missing

_GLOBAL = "system global"
_PASSWORD_POLICY = "system password-policy"
_ADMIN = "system admin"
_EVENTFILTER = "log eventfilter"
_FAZ_SECTIONS = ("log fortianalyzer setting", "log fortianalyzer2 setting", "log fortianalyzer3 setting")
_SSL_VPN = "vpn ssl settings"
_ANTIVIRUS = "antivirus settings"
_POLICY = "firewall policy"
_INTERFACE = "system interface"
_ZONE = "system zone"
_SETTINGS = "system settings"
_PROFILE_GROUP = "firewall profile-group"
_DNSFILTER = "dnsfilter profile"
_APPLICATION = "application list"

_GLOBAL_MISSING = section_missing(_GLOBAL)
_ADMIN_MISSING = section_missing(_ADMIN)
_ADMIN_VISIBILITY_UNPROVEN = "admin-visibility-unproven"
_SUPER_ADMIN_PROFILE = "super_admin"
_NOT_NUMERIC = "value-not-numeric"
_NOT_RECOGNIZED = "value-not-recognized"
_DEFAULT_DIFFERS = "default-differs-by-release"
_NGFW_POLICY_BASED = "ngfw-mode-policy-based"
_DSTINTF_UNRESOLVED = "dstintf-unresolved"
_GROUP_NOT_FOUND = "profile-group-not-found"
_PROFILE_NOT_IN_CONFIG = "profile-not-in-config"

_MIN_PASSWORD_LENGTH = 14
_MAX_DIGITS = 10
_PASSWORD_SCOPE = ("admin-password", "ipsec-preshared-key")
_TLS_ORDER = ("tls1-0", "tls1-1", "tls1-2", "tls1-3")
_SSL_ALGORITHMS = ("high", "medium", "default", "low")
_ROLES = ("lan", "wan", "dmz", "undefined")
_KINDS = (
    ("ips", "ips-sensor"),
    ("av", "av-profile"),
    ("dnsfilter", "dnsfilter-profile"),
    ("appctrl", "application-list"),
)


def _cis(name):
    def register(inner):
        def status(tree, policy=None):
            state, reason, _ = inner(tree)
            return state, reason

        def generate(tree):
            yield from inner(tree)[2]

        generate.__name__ = name
        check(name, status=status)(generate)
        return generate

    return register


def _result(hits):
    return EVALUATED, "", tuple(hits)


def _failed(reason):
    return NOT_EVALUATED, reason, ()


def _hit(section_name, section, key, attribute, object_key, evidence):
    line = 0 if section is None else (section.line_of(attribute) or section.line)
    return {"object_key": object_key, "section": section_name, "line": line, "evidence": evidence}


def _numeric(value) -> bool:
    return value.isascii() and value.isdigit() and len(value) <= _MAX_DIGITS


def _global_hit(section, attribute, value):
    return _hit(_GLOBAL, section, attribute, attribute, attribute, {"value": value})


def _global_flag(attribute, weak_when):
    def inner(tree):
        section = tree.section(_GLOBAL)
        if section is None:
            return _failed(_GLOBAL_MISSING)
        value = section.value(attribute)
        if value not in (None, "enable", "disable"):
            return _failed(_NOT_RECOGNIZED)
        if (value or "disable") == weak_when:
            return _result((_global_hit(section, attribute, value or "default"),))
        return _result(())

    return inner


_single_cpu_high = _global_flag("log-single-cpu-high", "disable")
_gui_display_hostname = _global_flag("gui-display-hostname", "enable")


@_cis("single_cpu_high")
def single_cpu_high(tree):
    return _single_cpu_high(tree)


@_cis("gui_display_hostname")
def gui_display_hostname(tree):
    return _gui_display_hostname(tree)


@_cis("password_policy")
def password_policy(tree):
    if tree.section(_GLOBAL) is None:
        return _failed(_GLOBAL_MISSING)
    section = tree.section(_PASSWORD_POLICY)
    status = None if section is None else section.value("status")
    if status not in (None, "enable", "disable"):
        return _failed(_NOT_RECOGNIZED)
    if status == "disable":
        return _result((_hit(_PASSWORD_POLICY, section, "status", "status", "status", {"aspect": "status", "value": "disable"}),))
    hits = []
    applied = () if section is None else section.values("apply-to")
    if any(item not in _PASSWORD_SCOPE for item in applied):
        return _failed(_NOT_RECOGNIZED)
    if not all(item in (applied or ("admin-password",)) for item in _PASSWORD_SCOPE):
        hits.append(_hit(_PASSWORD_POLICY, section, "apply-to", "apply-to", "scope", {"aspect": "scope", "value": " ".join(applied) or "default"}))
    length = None if section is None else section.value("minimum-length")
    if length is not None and not _numeric(length):
        return _failed(_NOT_NUMERIC)
    if length is None or int(length) < _MIN_PASSWORD_LENGTH:
        hits.append(_hit(_PASSWORD_POLICY, section, "minimum-length", "minimum-length", "length", {"aspect": "length", "value": length or "default"}))
    if status is None and not hits:
        return _failed(_DEFAULT_DIFFERS)
    return _result(hits)


def _network(kind, value):
    try:
        if kind == "ipv4":
            address, _, mask = value.replace("/", " ").partition(" ")
            return ipaddress.IPv4Network("%s/%s" % (address, mask.strip()), strict=False)
        return ipaddress.IPv6Network(value, strict=False)
    except ValueError:
        return None


def _restricted(account, kind):
    prefix = "trusthost" if kind == "ipv4" else "ip6-trusthost"
    restricting = 0
    for number in range(1, 11):
        value = account.value("%s%d" % (prefix, number))
        if value is None:
            continue
        network = _network(kind, value)
        if network is None:
            return None
        if network.prefixlen > 0:
            restricting += 1
    return restricting


@_cis("admin_no_trusthost")
def admin_no_trusthost(tree):
    if tree.section(_GLOBAL) is None:
        return _failed(_GLOBAL_MISSING)
    section = tree.section(_ADMIN)
    if section is None or not section.entries:
        return _failed(_ADMIN_MISSING)
    if not any(account.value("accprofile") == _SUPER_ADMIN_PROFILE for account in section.entries.values()):
        return _failed(_ADMIN_VISIBILITY_UNPROVEN)
    hits = []
    for name, account in section.entries.items():
        v4 = _restricted(account, "ipv4")
        v6 = _restricted(account, "ipv6")
        if v4 is None or v6 is None:
            return _failed(_NOT_RECOGNIZED)
        unrestricted = " ".join(kind for kind, count in (("ipv4", v4), ("ipv6", v6)) if count == 0)
        if not unrestricted:
            continue
        hits.append(
            {
                "object_key": "/".join(account.path),
                "section": _ADMIN,
                "line": account.line,
                "evidence": {
                    "admin": name,
                    "trusthost_count": v4,
                    "ip6_trusthost_count": v6,
                    "unrestricted": unrestricted,
                },
            }
        )
    return _result(hits)


@_cis("event_disabled")
def event_disabled(tree):
    if tree.section(_GLOBAL) is None:
        return _failed(_GLOBAL_MISSING)
    section = tree.section(_EVENTFILTER)
    if section is None:
        return _result(())
    hits = []
    for attribute in section.attrs:
        if section.value(attribute) == "disable":
            hits.append(_hit(_EVENTFILTER, section, attribute, attribute, attribute, {"event_type": attribute}))
    return _result(hits)


@_cis("faz_unencrypted")
def faz_unencrypted(tree):
    if tree.section(_GLOBAL) is None:
        return _failed(_GLOBAL_MISSING)
    hits = []
    for name in _FAZ_SECTIONS:
        section = tree.section(name)
        if section is None:
            continue
        status = section.value("status")
        if status not in (None, "enable", "disable"):
            return _failed(_NOT_RECOGNIZED)
        if status != "enable":
            continue
        reliable = section.value("reliable")
        algorithm = section.value("enc-algorithm")
        if reliable not in (None, "enable", "disable") or algorithm not in (None, "high", "high-medium", "low"):
            return _failed(_NOT_RECOGNIZED)
        if reliable != "enable":
            hits.append(_hit(name, section, "reliable", "reliable", "%s:reliable" % name, {"target": name, "aspect": "reliable", "value": reliable or "default"}))
        if algorithm in ("high-medium", "low"):
            hits.append(_hit(name, section, "enc-algorithm", "enc-algorithm", "%s:enc-algorithm" % name, {"target": name, "aspect": "enc-algorithm", "value": algorithm}))
    return _result(hits)


@_cis("ssl_legacy_tls")
def ssl_legacy_tls(tree):
    if tree.section(_GLOBAL) is None:
        return _failed(_GLOBAL_MISSING)
    section = tree.section(_SSL_VPN)
    if section is None:
        return _result(())
    status = section.value("status")
    if status not in (None, "enable", "disable"):
        return _failed(_NOT_RECOGNIZED)
    if status == "disable":
        return _result(())
    low = section.value("ssl-min-proto-ver")
    high = section.value("ssl-max-proto-ver")
    algorithm = section.value("algorithm")
    if low not in (None,) + _TLS_ORDER or high not in (None,) + _TLS_ORDER or algorithm not in (None,) + _SSL_ALGORITHMS:
        return _failed(_NOT_RECOGNIZED)
    hits = []
    if low is not None and _TLS_ORDER.index(low) < _TLS_ORDER.index("tls1-2"):
        hits.append(_hit(_SSL_VPN, section, "ssl-min-proto-ver", "ssl-min-proto-ver", "min-version", {"aspect": "min-version", "value": low}))
    if high is not None and _TLS_ORDER.index(high) < _TLS_ORDER.index("tls1-3"):
        hits.append(_hit(_SSL_VPN, section, "ssl-max-proto-ver", "ssl-max-proto-ver", "max-version", {"aspect": "max-version", "value": high}))
    if algorithm in ("medium", "default", "low"):
        hits.append(_hit(_SSL_VPN, section, "algorithm", "algorithm", "algorithm", {"aspect": "algorithm", "value": algorithm}))
    return _result(hits)


@_cis("av_detection_disabled")
def av_detection_disabled(tree):
    if tree.section(_GLOBAL) is None:
        return _failed(_GLOBAL_MISSING)
    section = tree.section(_ANTIVIRUS)
    grayware = None if section is None else section.value("grayware")
    learning = None if section is None else section.value("machine-learning-detection")
    if grayware not in (None, "enable", "disable") or learning not in (None, "enable", "monitor", "disable"):
        return _failed(_NOT_RECOGNIZED)
    hits = []
    if grayware != "enable":
        hits.append(_hit(_ANTIVIRUS, section, "grayware", "grayware", "grayware", {"setting": "grayware", "value": grayware or "default"}))
    if learning in ("disable", "monitor"):
        hits.append(_hit(_ANTIVIRUS, section, "machine-learning-detection", "machine-learning-detection", "machine-learning-detection", {"setting": "machine-learning-detection", "value": learning}))
    return _result(hits)


def _entries(tree, name):
    section = tree.section(name)
    return {} if section is None else section.entries


def _sdwan_zones(tree):
    sdwan = tree.section("system sdwan")
    zones = None if sdwan is None else sdwan.section("zone")
    return {} if zones is None else zones.entries


def _classify(tree, value, interfaces, zones, sdwan_zones):
    if value == "any":
        return True, "any", None
    if value == "ssl.root":
        return False, "", None
    if value in interfaces:
        role = interfaces[value].value("role")
        if role is not None and role not in _ROLES:
            return False, "", _NOT_RECOGNIZED
        return role == "wan", "role", None
    if value in zones:
        for member in zones[value].values("interface"):
            if member in interfaces:
                role = interfaces[member].value("role")
                if role is not None and role not in _ROLES:
                    return False, "", _NOT_RECOGNIZED
                if role == "wan":
                    return True, "zone", None
        return False, "", None
    if value in sdwan_zones:
        return True, "sdwan-zone", None
    return False, "", _DSTINTF_UNRESOLVED


def _wan_policies(tree):
    settings = tree.section(_SETTINGS)
    mode = None if settings is None else settings.value("ngfw-mode")
    if mode == "policy-based":
        return _NGFW_POLICY_BASED, ()
    if mode not in (None, "profile-based"):
        return _NOT_RECOGNIZED, ()
    interfaces = _entries(tree, _INTERFACE)
    zones = _entries(tree, _ZONE)
    sdwan_zones = _sdwan_zones(tree)
    found = []
    for policy in _entries(tree, _POLICY).values():
        if policy.value("action") != "accept":
            continue
        status = policy.value("status")
        if status not in (None, "enable", "disable"):
            return _NOT_RECOGNIZED, ()
        if status == "disable":
            continue
        destinations = policy.values("dstintf")
        if not destinations:
            return _DSTINTF_UNRESOLVED, ()
        via = ""
        for destination in destinations:
            wan, how, problem = _classify(tree, destination, interfaces, zones, sdwan_zones)
            if problem:
                return problem, ()
            if wan and not via:
                via = how
        if not via:
            continue
        utm = policy.value("utm-status")
        profile_type = policy.value("profile-type")
        if utm not in (None, "enable", "disable") or profile_type not in (None, "single", "group"):
            return _NOT_RECOGNIZED, ()
        found.append((policy, via, " ".join(destinations), utm == "enable", profile_type == "group"))
    return "", tuple(found)


def _profile_name(tree, policy, group, attribute):
    if not group:
        return True, policy.value(attribute)
    name = policy.value("profile-group")
    entry = _entries(tree, _PROFILE_GROUP).get(name) if name else None
    if entry is None:
        return False, None
    return True, entry.value(attribute)


@_cis("policy_wan_missing_profile")
def policy_wan_missing_profile(tree):
    reason, found = _wan_policies(tree)
    if reason:
        return _failed(reason)
    hits = []
    for policy, via, destinations, inspected, group in found:
        for kind, attribute in _KINDS:
            if inspected:
                ok, name = _profile_name(tree, policy, group, attribute)
                if not ok:
                    return _failed(_GROUP_NOT_FOUND)
                if name:
                    continue
            hits.append(
                {
                    "object_key": "%s/%s" % (policy.path[-1], kind),
                    "section": _POLICY,
                    "line": policy.line,
                    "evidence": {"policy": policy.path[-1], "kind": kind, "dstintf": destinations, "wan_via": via},
                }
            )
    return _result(hits)


def _policy_order(policy):
    return (0, int(policy), policy) if policy.isdigit() else (1, 0, policy)


def _referenced_profiles(tree, attribute):
    reason, found = _wan_policies(tree)
    if reason:
        return reason, {}
    used = {}
    for policy, _, _, inspected, group in found:
        if not inspected:
            continue
        ok, name = _profile_name(tree, policy, group, attribute)
        if not ok:
            return _GROUP_NOT_FOUND, {}
        if name:
            used.setdefault(name, []).append(policy.path[-1])
    return "", used


def _profile_rule(tree, section_name, reference, attribute):
    reason, used = _referenced_profiles(tree, reference)
    if reason:
        return _failed(reason)
    entries = _entries(tree, section_name)
    hits = []
    for name in sorted(used):
        profile = entries.get(name)
        if profile is None:
            return _failed(_PROFILE_NOT_IN_CONFIG)
        value = profile.value(attribute)
        if value not in (None, "enable", "disable"):
            return _failed(_NOT_RECOGNIZED)
        if value == "enable":
            continue
        hits.append(
            {
                "object_key": name,
                "section": section_name,
                "line": profile.line_of(attribute) or profile.line,
                "evidence": {"profile": name, "policies": " ".join(sorted(used[name], key=_policy_order))},
            }
        )
    return _result(hits)


@_cis("dnsfilter_log_all_domain")
def dnsfilter_log_all_domain(tree):
    return _profile_rule(tree, _DNSFILTER, "dnsfilter-profile", "log-all-domain")


@_cis("appctrl_default_port")
def appctrl_default_port(tree):
    return _profile_rule(tree, _APPLICATION, "application-list", "enforce-default-app-port")
