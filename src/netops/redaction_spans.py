"""Carry original credential ranges through the existing text substitutions.

A replacement inherits any secret range it consumes. Unchanged prefixes/suffixes
retain their exact offsets, so legacy cross-line matches keep their full effect.
Plain strings use the normal regex/string fast paths.
"""
from __future__ import annotations


class Marked(str):
    def __new__(cls, value, spans=()):
        instance = super().__new__(cls, value)
        instance.spans = tuple((*span, None) if len(span) == 2 else tuple(span) for span in spans)
        return instance


def edits(value, changes):
    if not isinstance(value, Marked):
        parts, cursor = [], 0
        for start, end, replacement in changes:
            parts.extend((value[cursor:start], replacement))
            cursor = end
        return ''.join(parts) + value[cursor:] if parts else value
    parts, spans, cursor, offset = [], [], 0, 0

    def copy(start, end):
        nonlocal offset
        parts.append(value[start:end])
        for left, right, kind in value.spans:
            a, b = max(start, left), min(end, right)
            if a < b:
                spans.append((offset + a - start, offset + b - start, kind))
        offset += end - start

    for start, end, replacement in changes:
        copy(cursor, start)
        original = value[start:end]
        prefix = 0
        while prefix < min(len(original), len(replacement)) and original[prefix] == replacement[prefix]:
            prefix += 1
        suffix = 0
        while (suffix < min(len(original), len(replacement)) - prefix
               and original[-suffix - 1] == replacement[-suffix - 1]):
            suffix += 1
        copy(start, start + prefix)
        changed = replacement[prefix:len(replacement) - suffix if suffix else len(replacement)]
        inherited = [kind for a, b, kind in value.spans if a < end and b > start]
        if changed and inherited:
            spans.append((offset, offset + len(changed), 'community' if 'community' in inherited else None))
        parts.append(changed)
        offset += len(changed)
        copy(end - suffix, end)
        cursor = end
    copy(cursor, len(value))
    return Marked(''.join(parts), spans)


def sub(pattern, replacement, value):
    if not isinstance(value, Marked):
        return pattern.sub(replacement, value)
    return edits(value, ((m.start(), m.end(), replacement(m) if callable(replacement) else m.expand(replacement))
                         for m in pattern.finditer(value)))


def replace(value, old, new):
    if not isinstance(value, Marked):
        return value.replace(old, new)
    def changes():
        cursor = 0
        while True:
            start = value.find(old, cursor)
            if start < 0:
                break
            yield start, start + len(old), new
            cursor = start + len(old)
    return edits(value, changes())


def mask(value):
    if not isinstance(value, Marked) or not value.spans:
        return str(value)
    merged = []
    for start, end, kind in sorted(value.spans, key=lambda span: span[:2]):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]),
                          'community' if 'community' in (kind, merged[-1][2]) else None)
        else:
            merged.append((start, end, kind))
    return edits(str(value), ((a, b, '<REDACTED>' if kind == 'community' else '<REDACTED:credential#%d>' % index)
                              for index, (a, b, kind) in enumerate(merged, 1)))


# JSON string offsets are translated through escaping without changing the JSON
# parser or serializer. This also preserves ranges in nested MCP text content.
import bisect
import json
import re

_JSON_STRING = re.compile(r'"(?:[^"\\]|\\.)*"', re.S)


def _boundaries(token):
    result, cursor = [1], 1
    while cursor < len(token) - 1:
        if token[cursor] == '\\':
            size = 6 if token[cursor + 1] == 'u' else 2
            if (size == 6 and 0xD800 <= int(token[cursor + 2:cursor + 6], 16) <= 0xDBFF
                    and token[cursor + 6:cursor + 8] == '\\u'
                    and 0xDC00 <= int(token[cursor + 8:cursor + 12], 16) <= 0xDFFF):
                size = 12
            cursor += size
        else:
            cursor += 1
        result.append(cursor)
    return result


def loads(text, **kwargs):
    value = json.loads(text, **kwargs)
    if not isinstance(text, Marked):
        return value
    tokens = iter(_JSON_STRING.finditer(text))

    def walk(item):
        if isinstance(item, str):
            token = next(tokens)
            bounds = _boundaries(token.group())
            spans = []
            for start, end, kind in text.spans:
                a, b = max(start, token.start() + 1), min(end, token.end() - 1)
                if a < b:
                    spans.append((max(0, bisect.bisect_right(bounds, a - token.start()) - 1),
                                  bisect.bisect_left(bounds, b - token.start()), kind))
            return Marked(item, spans) if spans else item
        if isinstance(item, dict):
            return {walk(key): walk(child) for key, child in item.items()}
        if isinstance(item, list):
            return [walk(child) for child in item]
        return item
    return walk(value)


def dumps(value, **kwargs):
    output = json.dumps(value, **kwargs)
    def strings(item):
        if isinstance(item, str):
            yield item
        elif isinstance(item, dict):
            for key, child in item.items():
                yield key
                yield from strings(child)
        elif isinstance(item, list):
            for child in item:
                yield from strings(child)
    items = list(strings(value))
    if not any(isinstance(item, Marked) and item.spans for item in items):
        return output
    spans = []
    for token, item in zip(_JSON_STRING.finditer(output), items):
        if isinstance(item, Marked):
            bounds = _boundaries(token.group())
            spans.extend((token.start() + bounds[a], token.start() + bounds[b], kind)
                         for a, b, kind in item.spans)
    return Marked(output, spans)
