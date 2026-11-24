"""Auditor's fixed platform registry and interfaces for vendor rules."""
from __future__ import annotations

from dataclasses import dataclass, field
from importlib import import_module
from types import MappingProxyType

from . import l1_cli, l1_exos, l1_fortios, l1_junos

TAXONOMY = frozenset({"mgmt", "aaa", "snmp", "time", "logging", "services", "l2", "ports"})
VISIBLE = "visible"
HIDDEN = "hidden"
UNPROVEN = "unproven"
INCOMPLETE = "incomplete"
NOT_SUPPORTED = "not-supported"

REASONS = {
    VISIBLE: frozenset({"content", "verified-profile", "auxiliary-output"}),
    HIDDEN: frozenset({"access-denied", "permission-denied"}),
    UNPROVEN: frozenset({"visibility-unproven", "inheritance-unresolved", "admin-visibility-unproven"}),
    INCOMPLETE: frozenset({"pager", "timeout", "output-limit", "truncated", "invalid-utf8",
                           "authentication-failed", "transport-error"}),
    NOT_SUPPORTED: frozenset({"command-unavailable", "platform-not-supported"}),
}


@dataclass(frozen=True)
class SectionVisibility:
    state: str
    reason: str

    def __post_init__(self):
        if self.reason not in REASONS.get(self.state, ()):
            raise ValueError("invalid section visibility or reason")


@dataclass(frozen=True)
class SSHStep:
    command: str
    field: str = ""
    expect: str = ""
    known: tuple = ()
    remedy: str = ""
    snapshot: bool = False
    prompt: bool = False
    section: str = ""


@dataclass(frozen=True)
class SnapshotMetadata:
    inventory_platform: str
    sections: dict = field(default_factory=dict)
    auxiliary: dict = field(default_factory=dict, repr=False)
    complete: bool = False
    integrity_reason: str = ""
    tree: object | None = field(default=None, repr=False)

    def visibility(self, section):
        return self.sections.get(section, SectionVisibility(UNPROVEN, "visibility-unproven"))


@dataclass(frozen=True)
class AuditContext:
    intent: dict = field(default_factory=dict)
    snapshot: SnapshotMetadata | None = None
    live: bool = False
    management_policy: dict | None = None

    def visibility(self, section):
        if self.snapshot is not None:
            return self.snapshot.visibility(section)
        return SectionVisibility(UNPROVEN, "visibility-unproven")


@dataclass(frozen=True)
class Platform:
    parser: object
    checks_module: str
    channels: tuple
    aliases: tuple
    collector_module: str | None = None


PLATFORMS = MappingProxyType({
    "arista-eos": Platform(l1_cli, "checks_arista_eos", ("file", "ssh"), ("arista_eos",)),
    "cisco-ios": Platform(l1_cli, "checks_cisco_ios", ("file", "ssh"), ("cisco_ios", "cisco_xe")),
    "cisco-nxos": Platform(l1_cli, "checks_cisco_nxos", ("file", "ssh"), ("cisco_nxos",)),
    "exos": Platform(l1_exos, "checks_exos", ("file", "ssh"), ()),
    "fortiadc": Platform(l1_fortios, "checks_fortiadc", (), ()),
    "fortios": Platform(l1_fortios, "checks_fortios", ("file", "ssh", "fortios-rest"), (), "fortios_audit"),
    "juniper-junos": Platform(l1_junos, "checks_juniper_junos", ("file", "ssh"),
                             ("juniper_junos", "juniper_junos_els")),
})

INVENTORY_ALIASES = MappingProxyType({
    alias: key for key, spec in PLATFORMS.items() for alias in (key, *spec.aliases)
})


def catalog_key(inventory_platform):
    return INVENTORY_ALIASES.get(inventory_platform)


def optional_collector(platform):
    name = PLATFORMS[platform].collector_module
    if name is None:
        return None
    qualified = f"{__package__}.{name}"
    try:
        return import_module(qualified)
    except ModuleNotFoundError as error:
        if error.name != qualified:
            raise
        return None


def is_snapshot_marker(rule_id):
    if not isinstance(rule_id, str):
        return False
    platform, _, suffix = rule_id.partition(".")
    return platform in PLATFORMS and suffix == "snapshot.incomplete"
