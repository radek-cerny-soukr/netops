from __future__ import annotations

from dataclasses import dataclass, field


MAX_DEPTH = 64
VDOM_SECTION = "vdom"


class ParseError(Exception):
    pass


class TruncatedError(ParseError):
    def __init__(self, message, line):
        super().__init__(message)
        self.line = line


@dataclass(frozen=True)
class Attr:
    values: tuple
    line: int
    unset: bool = False

    def value(self) -> str:
        return " ".join(self.values)


@dataclass
class Node:
    path: tuple
    line: int
    attrs: dict = field(default_factory=dict)
    sub: dict = field(default_factory=dict)
    entries: dict = field(default_factory=dict)
    config_tokens: tuple = ()

    def value(self, name, default=None):
        attr = self.attrs.get(name)
        if attr is None or attr.unset:
            return default
        return attr.value()

    def values(self, name) -> tuple:
        attr = self.attrs.get(name)
        if attr is None or attr.unset:
            return ()
        return attr.values

    def line_of(self, name):
        attr = self.attrs.get(name)
        return None if attr is None else attr.line

    def section(self, name):
        return self.sub.get(name)


def tokenize(text: str) -> list:
    tokens, current, in_quotes, escaped, quoted = [], "", False, False, False
    skip = False
    for index, char in enumerate(text):
        if skip:
            skip = False
            continue
        if escaped:
            current += char
            escaped = False
        elif char == "\\" and in_quotes:
            escaped = True
        elif not in_quotes and not current and not quoted and char == "'" and text[index:index + 2] == "''" and (
                index + 2 == len(text) or text[index + 2] in " \t"):
            quoted = True
            skip = True
        elif char == '"':
            in_quotes = not in_quotes
            quoted = True
        elif char in " \t" and not in_quotes:
            if current or quoted:
                tokens.append(current)
                current, quoted = "", False
        else:
            current += char
    if current or quoted:
        tokens.append(current)
    return tokens


def _quote_state(text: str, in_quotes: bool = False, escaped: bool = False) -> tuple:
    for char in text:
        if escaped:
            escaped = False
        elif char == "\\" and in_quotes:
            escaped = True
        elif char == '"':
            in_quotes = not in_quotes
    return in_quotes, escaped


def physical_lines(text: str) -> list:
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    return [line[:-1] if line.endswith("\r") else line for line in lines]


def logical_lines(text: str):
    buffer, start, state = None, 0, (False, False)
    for number, line in enumerate(physical_lines(text), 1):
        if buffer is None:
            buffer, start, state = line, number, _quote_state(line)
        else:
            buffer += "\n" + line
            state = _quote_state("\n" + line, *state)
        if not state[0]:
            yield start, buffer
            buffer = None
    if buffer is not None:
        raise TruncatedError("unterminated quoted value opened at line %d" % start, start)


def parse(text: str) -> Node:
    root = Node(path=(), line=0)
    stack = [root]
    for number, raw in logical_lines(text):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens = tokenize(line)
        if not tokens:
            continue
        command = tokens[0]
        if command in ("config", "edit") and len(stack) > MAX_DEPTH:
            raise ParseError("line %d: blocks nest deeper than %d levels" % (number, MAX_DEPTH))
        if command == "config":
            name = " ".join(tokens[1:])
            node = stack[-1].sub.get(name)
            if node is None:
                node = Node(path=stack[-1].path + (name,), line=number, config_tokens=tuple(tokens[1:]))
                stack[-1].sub[name] = node
            stack.append(node)
        elif command == "edit":
            key = tokens[1] if len(tokens) > 1 else ""
            node = stack[-1].entries.get(key)
            if node is None:
                node = Node(path=stack[-1].path + (key,), line=number)
                stack[-1].entries[key] = node
            stack.append(node)
        elif command == "set":
            if len(tokens) < 2:
                raise ParseError("line %d: set without an attribute" % number)
            stack[-1].attrs[tokens[1]] = Attr(values=tuple(tokens[2:]), line=number)
        elif command == "unset":
            if len(tokens) < 2:
                raise ParseError("line %d: unset without an attribute" % number)
            stack[-1].attrs[tokens[1]] = Attr(values=(), line=number, unset=True)
        elif command in ("next", "end"):
            if len(stack) == 1:
                raise ParseError("line %d: %s outside of a block" % (number, command))
            if command == "end" and len(stack) == 3 and stack[1].path == (VDOM_SECTION,):
                stack.pop()
            stack.pop()
    if len(stack) != 1:
        raise TruncatedError("unterminated block opened at line %d" % stack[-1].line, stack[-1].line)
    return root
