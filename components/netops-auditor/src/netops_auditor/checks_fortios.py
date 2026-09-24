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

from . import management

from .management import management_fortios_address_unused
from .management import management_fortios_address_policy
from .management import management_fortios_group_empty
from .management import management_fortios_group_dangling
from .management import management_fortios_group_cycle
from .management import management_fortios_dhcp_conflict
from .management import management_fortios_dhcp_subnet
