from __future__ import annotations

import json


class JsonError(ValueError):
    pass


def _unique(pairs) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise JsonError("duplicate key %s" % json.dumps(key)[:80])
        result[key] = value
    return result


def loads(text: str):
    try:
        document = json.loads(text, object_pairs_hook=_unique)
        json.dumps(document, ensure_ascii=False).encode("utf-8")
    except RecursionError:
        raise JsonError("nesting is too deep") from None
    except UnicodeEncodeError:
        raise JsonError("a string holds an unpaired surrogate escape") from None
    return document
