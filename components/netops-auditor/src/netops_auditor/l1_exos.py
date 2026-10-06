from __future__ import annotations

import re
from dataclasses import dataclass

MODULE_HEADER = re.compile(r"^#\s*Module\s+(\S+)\s+configuration\.$")

NO_MODULE = ""

UPM_PROFILE = ("create", "upm", "profile")
UPM_END = "."
UPM_UNNAMED = "-"


class ParseError(Exception):
    pass


@dataclass(frozen=True)
class Command:
    line: int
    module: str
    tokens: tuple
    text: str
    upm_profile: str = ""

    def starts_with(self, *words) -> bool:
        return self.tokens[: len(words)] == tuple(words)

    def argument(self, position: int, default=None):
        if position < 0 or position >= len(self.tokens):
            return default
        return self.tokens[position]


@dataclass(frozen=True)
class Configuration:
    raw: tuple
    commands: tuple
    modules: tuple
    active: tuple = ()
    upm_bodies: tuple = ()
    unterminated_upm: bool = False

    def serialize(self) -> str:
        return "".join(self.raw)

    def matching(self, *words) -> tuple:
        return tuple(command for command in self.active if command.starts_with(*words))

    def first(self, *words):
        for command in self.active:
            if command.starts_with(*words):
                return command
        return None


def split_lines(text: str) -> list:
    parts = text.split("\n")
    lines = [part + "\n" for part in parts[:-1]]
    if parts[-1]:
        lines.append(parts[-1])
    return lines


def tokenize(text: str, line: int = 0) -> list:
    tokens, current, in_quotes, quoted = [], "", False, False
    for char in text:
        if char == '"':
            in_quotes = not in_quotes
            quoted = True
        elif char in " \t" and not in_quotes:
            if current or quoted:
                tokens.append(current)
                current, quoted = "", False
        else:
            current += char
    if in_quotes:
        raise ParseError("line %d: unterminated quoted value" % line)
    if current or quoted:
        tokens.append(current)
    return tokens


def parse(text: str) -> Configuration:
    if not isinstance(text, str):
        raise ParseError("configuration must be a string, got %r" % (text,))
    raw = split_lines(text)
    commands, modules, module = [], [], NO_MODULE
    bodies, profile, opened = [], "", 0
    for number, line in enumerate(raw, 1):
        content = line.strip()
        if not content:
            continue
        if profile and content == UPM_END:
            commands.append(Command(line=number, module=module, tokens=(UPM_END,), text=content, upm_profile=profile))
            bodies.append((opened, number))
            profile = ""
            continue
        if content.startswith("#"):
            header = None if profile else MODULE_HEADER.match(content)
            if header is not None:
                module = header.group(1)
                if module not in modules:
                    modules.append(module)
            continue
        tokens = tokenize(content, number)
        if not tokens:
            continue
        commands.append(
            Command(line=number, module=module, tokens=tuple(tokens), text=content, upm_profile=profile)
        )
        if not profile and tuple(tokens[:3]) == UPM_PROFILE:
            profile = tokens[3] if len(tokens) > 3 and tokens[3] else UPM_UNNAMED
            opened = number + 1
    if profile:
        bodies.append((opened, len(raw)))
    return Configuration(
        raw=tuple(raw),
        commands=tuple(commands),
        modules=tuple(modules),
        active=tuple(command for command in commands if not command.upm_profile),
        upm_bodies=tuple(bodies),
        unterminated_upm=bool(profile),
    )
