"""Token and indentation parser shared by IOS, NX-OS and EOS."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

OPAQUE_BEGIN = re.compile(r"(?:certificate (?:ca )?[0-9A-Fa-f]+|key-string)$")
TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|\S+')
BLOCKS = (
    ("line", "vty"), ("interface",), ("vlan",), ("ip", "access-list"),
    ("ipv6", "access-list"), ("mac", "access-list"), ("management", "ssh"),
    ("management", "telnet"), ("management", "api", "http-commands"), ("vrf",),
)
FAMILIES = {
    "aaa": "aaa", "tacacs": "aaa", "tacacs-server": "aaa", "radius": "aaa",
    "radius-server": "aaa", "username": "aaa", "enable": "aaa", "snmp-server": "snmp",
    "ntp": "ntp", "logging": "logging", "feature": "feature", "nxapi": "nxapi",
}
SECTIONS = frozenset({"global", "ip ssh", *FAMILIES.values(), *(" ".join(b) for b in BLOCKS)})


class ParseError(ValueError):
    pass


@dataclass(frozen=True)
class Command:
    line: int
    tokens: tuple = field(repr=False)
    mode: str
    parents: tuple = field(repr=False)
    family: str

    def starts_with(self, *words):
        return self.tokens[:len(words)] == words


@dataclass(frozen=True)
class Configuration:
    commands: tuple
    unterminated: int | None = None

    def section(self, name):
        return tuple(item for item in self.commands if item.family == name) or None

    def matching(self, *words):
        return tuple(item for item in self.commands if item.starts_with(*words))

    @property
    def sections(self):
        return frozenset(item.family for item in self.commands)


def family(tokens):
    for prefix in (*BLOCKS, ("ip", "ssh")):
        if tokens[:len(prefix)] == prefix:
            return " ".join(prefix)
    return FAMILIES.get(tokens[0], "global")


def parse(text):
    commands, parents = [], []
    opaque = None
    for number, raw in enumerate(text.split("\n"), 1):
        line = raw.strip()
        if opaque:
            marker, start = opaque
            if (line == marker if marker in ("quit", "EOF") else marker in line):
                opaque = None
            continue
        if not line or line.startswith(("!", "#", ">")):
            continue
        if line == "end" or line.startswith(("Building configuration", "Current configuration")):
            continue
        banner = re.match(r"(?:banner\s+\S+|vacant-message)\s+(\^\S|\S)(.*)", line)
        if banner:
            if banner[1] not in banner[2]:
                opaque = (banner[1], number)
            continue
        if line.split() in (["banner", "motd"], ["banner", "login"], ["banner", "exec"]):
            opaque = ("EOF", number)
            continue
        if OPAQUE_BEGIN.fullmatch(line) and parents:
            opaque = ("quit", number)
            continue
        indent = len(raw) - len(raw.lstrip())
        while parents and parents[-1][0] >= indent:
            parents.pop()
        tokens = tuple(TOKEN.findall(line))
        mode = tokens[0] if tokens[0] in ("no", "default") and len(tokens) > 1 else "set"
        words = tokens[1:] if mode != "set" else tokens
        name = parents[0][1].family if parents else family(words)
        command = Command(number, words, mode, tuple(parent.tokens for _, parent in parents), name)
        commands.append(command)
        parents.append((indent, command))
    return Configuration(tuple(commands), None if opaque is None else opaque[1])
