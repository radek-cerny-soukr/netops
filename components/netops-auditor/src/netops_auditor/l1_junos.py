"""Junos display-set parser with exact hierarchy and explicit visibility gaps."""
from __future__ import annotations

from dataclasses import dataclass, field
import re

from .l1_cli import TOKEN, ParseError

SECTIONS = frozenset({"system", "snmp", "interfaces", "vlans", "protocols", "forwarding-options", "firewall"})
MASKS = frozenset({"SECRET-DATA", "ACCESS-DENIED"})
SCOPE = re.compile(r"\{(?:master|backup|primary|secondary):[0-9]+\}")


@dataclass(frozen=True)
class Statement:
    line: int
    tokens: tuple = field(repr=False)
    active: bool
    masked: bool = False

    def starts_with(self, *words):
        return self.tokens[:len(words)] == words


@dataclass(frozen=True)
class Configuration:
    statements: tuple
    hidden: frozenset
    inheritance: frozenset
    malformed: int | None = None
    disabled: frozenset = frozenset()
    # Any ACCESS-DENIED mark of the output, also outside the families of SECTIONS.
    denied: bool = False

    def matching(self, *words):
        return tuple(item for item in self.statements if item.active and item.starts_with(*words))

    def section(self, name):
        return self.matching(*name.split()) or None

    @property
    def sections(self):
        return frozenset(item.tokens[0] for item in self.statements if item.active)


def _value(token):
    return token[1:-1] if token.startswith('"') and token.endswith('"') else token


def parse(text):
    pending, disabled, hidden, inheritance = [], set(), set(), set()
    malformed, denied = None, False
    for number, raw in enumerate(text.split("\n"), 1):
        line = raw.strip()
        if not line or line.startswith("##") or SCOPE.fullmatch(line):
            continue
        if line in ("/* ACCESS-DENIED */", "/* ACCESS-DENIED */;"):
            hidden.update(SECTIONS)
            denied = True
            continue
        # A comment outside quotes may carry Junos's access/mask marker.
        words = tuple(TOKEN.findall(line))
        comment = words.index("##") if "##" in words else len(words)
        markers = MASKS.intersection(words[comment + 1:])
        words = words[:comment]
        if "/*" in words:
            block = words.index("/*")
            markers |= MASKS.intersection(words[block + 1:])
            words = words[:block]
        inactive = words[:1] == ("inactive:",)
        if inactive:
            words = words[1:]
        if words == ("ACCESS-DENIED",):
            hidden.update(SECTIONS)
            denied = True
            continue
        if (len(words) < 2 or words[0] not in ("set", "deactivate")
                or any(token.startswith('"') and not token.endswith('"') for token in words[1:])):
            malformed = malformed or number
            continue
        verb, path = words[0], tuple(_value(token) for token in words[1:])
        masks = MASKS.intersection(words[1:]) | markers
        if "ACCESS-DENIED" in masks:
            hidden.update(SECTIONS if path[0] == "ACCESS-DENIED" else {path[0]} & SECTIONS)
            denied = True
            continue
        if verb == "deactivate":
            disabled.add(path)
            continue
        if "SECRET-DATA" in masks and "SECRET-DATA" not in path:
            path += ("SECRET-DATA",)
        pending.append((number, path, inactive, "SECRET-DATA" in masks))
    statements = []
    for number, path, inactive, masked in pending:
        active = not inactive and not any(path[:end] in disabled for end in range(1, len(path) + 1))
        if active and path[0] != "groups" and {"apply-groups", "apply-groups-except"}.intersection(path):
            inheritance.update({path[0]} & SECTIONS or SECTIONS)
        statements.append(Statement(number, path, active, masked))
    return Configuration(tuple(statements), frozenset(hidden), frozenset(inheritance), malformed, frozenset(disabled),
                         denied)


def with_inheritance(tree, inherited):
    confirmed = inherited.sections - inherited.hidden - inherited.inheritance
    confirmed &= tree.inheritance
    known = {item.tokens for item in tree.statements}
    extra = tuple(item for item in inherited.statements
                  if item.active and item.tokens[0] in confirmed and item.tokens not in known
                  and not any(item.tokens[:end] in tree.disabled for end in range(1, len(item.tokens) + 1)))
    return Configuration(tree.statements + extra, tree.hidden | inherited.hidden,
                         tree.inheritance - confirmed, tree.malformed, tree.disabled, tree.denied or inherited.denied)
