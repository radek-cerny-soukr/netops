from __future__ import annotations

import re
from dataclasses import dataclass

MODULE_HEADER = re.compile(r"^#\s*Module\s+(\S+)\s+configuration\.$")

NO_MODULE = ""


class ParseError(Exception):
    pass


@dataclass(frozen=True)
class Command:
    line: int
    module: str
    tokens: tuple
    text: str

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

    def serialize(self) -> str:
        return "".join(self.raw)

    def matching(self, *words) -> tuple:
        return tuple(command for command in self.commands if command.starts_with(*words))

    def first(self, *words):
        for command in self.commands:
            if command.starts_with(*words):
                return command
        return None


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
    raw = text.splitlines(keepends=True)
    commands, modules, module = [], [], NO_MODULE
    for number, line in enumerate(raw, 1):
        content = line.strip()
        if not content:
            continue
        if content.startswith("#"):
            header = MODULE_HEADER.match(content)
            if header is not None:
                module = header.group(1)
                if module not in modules:
                    modules.append(module)
            continue
        tokens = tokenize(content, number)
        if not tokens:
            continue
        commands.append(
            Command(line=number, module=module, tokens=tuple(tokens), text=content)
        )
    return Configuration(raw=tuple(raw), commands=tuple(commands), modules=tuple(modules))
