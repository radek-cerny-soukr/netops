from __future__ import annotations

from .engine import check

_BUILTIN_OBJECTS = frozenset(("all", "none", "any", "always"))

_BUILTIN_SERVICES = frozenset(
    (
        "ALL",
        "ALL_TCP",
        "ALL_UDP",
        "ALL_ICMP",
        "ALL_ICMP6",
        "HTTP",
        "HTTPS",
        "DNS",
        "PING",
        "SSH",
        "NTP",
        "DHCP",
        "IKE",
        "SMTP",
        "SMTPS",
        "POP3",
        "IMAP",
        "FTP",
        "TFTP",
        "SNMP",
        "SYSLOG",
        "TRACEROUTE",
        "WINS",
        "LDAP",
        "RADIUS",
        "SAMBA",
        "NFS",
        "RDP",
        "MS-SQL",
        "MYSQL",
    )
)

_VDOM_SECTION = "vdom"
_POLICY_SECTION = "firewall policy"
_INTERFACE_SECTION = "system interface"
_SYSLOG_SECTION = "log syslogd setting"
_NTP_SECTION = "system ntp"

_ADDRESS_SOURCES = (("firewall address",), ("firewall addrgrp",))

_SERVICE_SOURCES = (("firewall service custom",), ("firewall service group",))

_SCHEDULE_SOURCES = (
    ("firewall schedule recurring",),
    ("firewall schedule onetime",),
    ("firewall schedule group",),
)

_INTERFACE_SOURCES = (
    (_INTERFACE_SECTION,),
    ("system zone",),
    ("system sdwan", "zone"),
)

_REFERENCES = (
    ("srcaddr", _ADDRESS_SOURCES, _BUILTIN_OBJECTS),
    ("dstaddr", _ADDRESS_SOURCES, _BUILTIN_OBJECTS),
    ("service", _SERVICE_SOURCES, _BUILTIN_OBJECTS | _BUILTIN_SERVICES),
    ("schedule", _SCHEDULE_SOURCES, _BUILTIN_OBJECTS),
    ("srcintf", _INTERFACE_SOURCES, _BUILTIN_OBJECTS),
    ("dstintf", _INTERFACE_SOURCES, _BUILTIN_OBJECTS),
)

_ADMIN_SERVICES = ("http", "https", "ssh", "telnet")


def _vdom_scope(tree):
    return tree.section(_VDOM_SECTION)


def _node(tree, path):
    node = tree
    for name in path:
        if node is None:
            return None
        node = node.section(name)
    return node


def _entries(tree, *path):
    node = _node(tree, path)
    return {} if node is None else node.entries


def _defined(tree, sources):
    names = set()
    for source in sources:
        names.update(_entries(tree, *source))
    return names


def _object_key(node):
    return "/".join(node.path)


@check("vdom_unsupported")
def vdom_unsupported(tree):
    section = _vdom_scope(tree)
    if section is None:
        return
    yield {
        "object_key": _VDOM_SECTION,
        "section": _VDOM_SECTION,
        "line": section.line,
        "evidence": {"vdoms": len(section.entries)},
    }


@check("dangling_reference")
def dangling_reference(tree):
    defined = {}
    for attribute, sections, _builtins in _REFERENCES:
        defined[attribute] = _defined(tree, sections)
    for policy in _entries(tree, _POLICY_SECTION).values():
        reported = set()
        for attribute, _sections, builtins in _REFERENCES:
            line = policy.line_of(attribute)
            for value in policy.values(attribute):
                if value in builtins or value in defined[attribute]:
                    continue
                object_key = "%s/%s/%s" % (_object_key(policy), attribute, value)
                if object_key in reported:
                    continue
                reported.add(object_key)
                yield {
                    "object_key": object_key,
                    "section": _POLICY_SECTION,
                    "line": line,
                    "evidence": {
                        "policy": policy.path[-1],
                        "attribute": attribute,
                        "value": value,
                    },
                }


@check("admin_access_on_untrusted_interface")
def admin_access_on_untrusted_interface(tree):
    for interface in _entries(tree, _INTERFACE_SECTION).values():
        if interface.value("role") != "wan":
            continue
        allowed = set(interface.values("allowaccess"))
        exposed = tuple(service for service in _ADMIN_SERVICES if service in allowed)
        if not exposed:
            continue
        yield {
            "object_key": _object_key(interface),
            "section": _INTERFACE_SECTION,
            "line": interface.line_of("allowaccess"),
            "evidence": {
                "interface": interface.path[-1],
                "services": " ".join(exposed),
            },
        }


@check("utm_without_ssl_profile")
def utm_without_ssl_profile(tree):
    for policy in _entries(tree, _POLICY_SECTION).values():
        if policy.value("utm-status") != "enable":
            continue
        if policy.value("ssl-ssh-profile"):
            continue
        yield {
            "object_key": _object_key(policy),
            "section": _POLICY_SECTION,
            "line": policy.line_of("utm-status"),
            "evidence": {
                "policy": policy.path[-1],
                "name": policy.value("name", ""),
            },
        }


@check("no_syslog_target")
def no_syslog_target(tree):
    section = tree.section(_SYSLOG_SECTION)
    if section is None:
        yield {
            "object_key": _SYSLOG_SECTION,
            "section": _SYSLOG_SECTION,
            "line": 0,
            "evidence": {"reason": "section missing"},
        }
        return
    if section.value("status") != "enable":
        yield {
            "object_key": _SYSLOG_SECTION,
            "section": _SYSLOG_SECTION,
            "line": section.line_of("status") or section.line,
            "evidence": {"reason": "status not enable"},
        }
        return
    if not section.value("server"):
        yield {
            "object_key": _SYSLOG_SECTION,
            "section": _SYSLOG_SECTION,
            "line": section.line_of("server") or section.line,
            "evidence": {"reason": "server not set"},
        }


@check("no_ntp_sync")
def no_ntp_sync(tree):
    section = tree.section(_NTP_SECTION)
    if section is None:
        yield {
            "object_key": _NTP_SECTION,
            "section": _NTP_SECTION,
            "line": 0,
            "evidence": {"reason": "section missing"},
        }
        return
    if section.value("ntpsync") != "enable":
        yield {
            "object_key": _NTP_SECTION,
            "section": _NTP_SECTION,
            "line": section.line_of("ntpsync") or section.line,
            "evidence": {"reason": "ntpsync not enable"},
        }
        return
    if section.value("type") != "custom":
        return
    servers = section.section("ntpserver")
    if servers is not None:
        for entry in servers.entries.values():
            if entry.value("server"):
                return
    yield {
        "object_key": _NTP_SECTION,
        "section": _NTP_SECTION,
        "line": section.line if servers is None else servers.line,
        "evidence": {"reason": "no ntp server"},
    }

_GLOBAL_SECTION = "system global"
_AUTO_INSTALL_SECTION = "system auto-install"
_ADMIN_SECTION = "system admin"
_SNMP_COMMUNITY_SECTION = "system snmp community"
_LDAP_SECTION = "user ldap"
_AUTO_INSTALL_ATTRIBUTES = ("auto-install-config", "auto-install-image")
_PLAINTEXT_ADMIN_SERVICES = ("http", "telnet")
_LEGACY_TLS = ("tlsv1-0", "tlsv1-1")
_DEFAULT_ADMIN = "admin"
_MAX_IDLE_MINUTES = 5
_MAX_LOCKOUT_THRESHOLD = 3


def _global_hit(section, attribute, evidence):
    return {
        "object_key": _GLOBAL_SECTION,
        "section": _GLOBAL_SECTION,
        "line": section.line_of(attribute) or section.line,
        "evidence": evidence,
    }


def _global_number(section, attribute):
    value = section.value(attribute)
    if value is None or not value.isdigit():
        return None
    return int(value)


@check("usb_auto_install")
def usb_auto_install(tree):
    section = tree.section(_AUTO_INSTALL_SECTION)
    if section is None:
        return
    enabled = tuple(name for name in _AUTO_INSTALL_ATTRIBUTES if section.value(name) == "enable")
    if not enabled:
        return
    yield {
        "object_key": _AUTO_INSTALL_SECTION,
        "section": _AUTO_INSTALL_SECTION,
        "line": section.line_of(enabled[0]),
        "evidence": {"enabled": " ".join(enabled)},
    }


@check("static_key_ciphers")
def static_key_ciphers(tree):
    section = tree.section(_GLOBAL_SECTION)
    if section is None:
        return
    value = section.value("ssl-static-key-ciphers")
    if value == "disable":
        return
    yield _global_hit(section, "ssl-static-key-ciphers", {"setting": value or "unset"})


@check("strong_crypto_disabled")
def strong_crypto_disabled(tree):
    section = tree.section(_GLOBAL_SECTION)
    if section is None or section.value("strong-crypto") != "disable":
        return
    yield _global_hit(section, "strong-crypto", {"setting": "disable"})


@check("admin_gui_legacy_tls")
def admin_gui_legacy_tls(tree):
    section = tree.section(_GLOBAL_SECTION)
    if section is None:
        return
    legacy = tuple(version for version in section.values("admin-https-ssl-versions") if version in _LEGACY_TLS)
    if not legacy:
        return
    yield _global_hit(section, "admin-https-ssl-versions", {"versions": " ".join(legacy)})


@check("admin_idle_timeout")
def admin_idle_timeout(tree):
    section = tree.section(_GLOBAL_SECTION)
    if section is None:
        return
    minutes = _global_number(section, "admintimeout")
    if minutes is None or minutes <= _MAX_IDLE_MINUTES:
        return
    yield _global_hit(section, "admintimeout", {"minutes": minutes})


@check("admin_lockout_threshold")
def admin_lockout_threshold(tree):
    section = tree.section(_GLOBAL_SECTION)
    if section is None:
        return
    attempts = _global_number(section, "admin-lockout-threshold")
    if attempts is None or attempts <= _MAX_LOCKOUT_THRESHOLD:
        return
    yield _global_hit(section, "admin-lockout-threshold", {"attempts": attempts})


@check("default_admin_account")
def default_admin_account(tree):
    account = _entries(tree, _ADMIN_SECTION).get(_DEFAULT_ADMIN)
    if account is None:
        return
    yield {
        "object_key": _object_key(account),
        "section": _ADMIN_SECTION,
        "line": account.line,
        "evidence": {"account": _DEFAULT_ADMIN},
    }


@check("plaintext_admin_access")
def plaintext_admin_access(tree):
    for interface in _entries(tree, _INTERFACE_SECTION).values():
        allowed = set(interface.values("allowaccess"))
        exposed = tuple(service for service in _PLAINTEXT_ADMIN_SERVICES if service in allowed)
        if not exposed:
            continue
        yield {
            "object_key": _object_key(interface),
            "section": _INTERFACE_SECTION,
            "line": interface.line_of("allowaccess"),
            "evidence": {
                "interface": interface.path[-1],
                "services": " ".join(exposed),
            },
        }


@check("snmp_community")
def snmp_community(tree):
    for community in _entries(tree, _SNMP_COMMUNITY_SECTION).values():
        if community.value("status") == "disable":
            continue
        yield {
            "object_key": _object_key(community),
            "section": _SNMP_COMMUNITY_SECTION,
            "line": community.line,
            "evidence": {"community": community.path[-1]},
        }


@check("policy_service_all")
def policy_service_all(tree):
    for policy in _entries(tree, _POLICY_SECTION).values():
        if policy.value("action") != "accept" or "ALL" not in policy.values("service"):
            continue
        yield {
            "object_key": _object_key(policy),
            "section": _POLICY_SECTION,
            "line": policy.line_of("service"),
            "evidence": {
                "policy": policy.path[-1],
                "name": policy.value("name", ""),
            },
        }


@check("policy_logging_disabled")
def policy_logging_disabled(tree):
    for policy in _entries(tree, _POLICY_SECTION).values():
        if policy.value("logtraffic") != "disable":
            continue
        yield {
            "object_key": _object_key(policy),
            "section": _POLICY_SECTION,
            "line": policy.line_of("logtraffic"),
            "evidence": {
                "policy": policy.path[-1],
                "name": policy.value("name", ""),
            },
        }


@check("ldap_without_tls")
def ldap_without_tls(tree):
    for server in _entries(tree, _LDAP_SECTION).values():
        setting = server.value("secure")
        if setting in ("ldaps", "starttls"):
            continue
        yield {
            "object_key": _object_key(server),
            "section": _LDAP_SECTION,
            "line": server.line_of("secure") or server.line,
            "evidence": {"server": server.path[-1], "setting": setting or "unset"},
        }


from . import management

from .management import management_fortios_address_unused
from .management import management_fortios_address_policy
from .management import management_fortios_group_empty
from .management import management_fortios_group_dangling
from .management import management_fortios_group_cycle
from .management import management_fortios_dhcp_conflict
from .management import management_fortios_dhcp_subnet
