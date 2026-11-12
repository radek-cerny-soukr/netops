"""Bound normalized record responses before they cross the role IPC boundary."""
from __future__ import annotations

import json

DEFAULT_LIMIT = 100
MAX_LIMIT = 500
DEFAULT_BYTES = 16_000
MAX_BYTES = 48_000
MAX_OFFSET = 8_000_000


def validate(limit=DEFAULT_LIMIT, offset=0, max_bytes=DEFAULT_BYTES):
    for field, value, low, high in (("limit", limit, 1, MAX_LIMIT),
                                    ("offset", offset, 0, MAX_OFFSET),
                                    ("max_bytes", max_bytes, 1_000, MAX_BYTES)):
        if type(value) is not int or not low <= value <= high:
            raise ValueError("%s must be an integer from %d to %d" % (field, low, high))


def page(result, fields=("records",), *, limit=DEFAULT_LIMIT, offset=0, max_bytes=DEFAULT_BYTES):
    """Page lists in field order, after capture, redaction, joins and local filters.

    Each continuation performs a fresh read, not a snapshot. The source hashes let
    callers detect table changes. A row is indivisible; an oversized row fails
    explicitly rather than making an IPC error or a nonadvancing continuation.
    has_more describes a usable continuation; status describes capture quality.
    """
    validate(limit, offset, max_bytes)
    rows = {name: result.get(name, []) for name in fields}
    total = sum(len(values) for values in rows.values())
    result = {**result, **{name: [] for name in fields}}
    result['page'] = {'offset': offset, 'limit': limit, 'max_bytes': max_bytes,
                      'total': total, 'returned': 0,
                      'counts': {name: len(values) for name, values in rows.items()}}

    def metadata(returned):
        end = min(offset, total) + returned
        more = end < total
        result.update(has_more=more, next={'offset': end, 'limit': limit, 'max_bytes': max_bytes} if more else None)
        result['page']['returned'] = returned
        if 'coverage' in result:
            result['coverage']['returned'] = len(result.get('records', []))
        for name in fields:
            if name in result.get('counts', {}):
                result['counts'][name]['returned'] = len(result[name])

    def size():
        return len(json.dumps(result, ensure_ascii=True, allow_nan=False).encode('utf-8'))

    def too_large(field):
        return {'ok': False, 'target': result.get('target'), 'error_code': 'result_too_large',
                'failed_step': field, 'has_more': False, 'next': None,
                'error': 'One record or response metadata exceeds max_bytes; increase max_bytes or narrow the read'}

    metadata(0)
    if size() > max_bytes:
        return too_large('metadata')
    position = 0
    returned = 0
    for name, values in rows.items():
        start = max(0, offset - position)
        position += len(values)
        for row in values[start:]:
            if returned == limit:
                return result
            result[name].append(row)
            metadata(returned + 1)
            if size() > max_bytes:
                result[name].pop()
                metadata(returned)
                return result if returned else too_large(name)
            returned += 1
    return result
