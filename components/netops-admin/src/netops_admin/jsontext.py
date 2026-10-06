from __future__ import annotations

import json

from netops_admin.errors import Rejected

DUPLICATE_KEY = "repeats a key within one JSON object"
NOT_JSON = "is not UTF-8 JSON"
TOO_DEEP = "is nested too deeply"
SURROGATE = "holds an unpaired surrogate escape"


class JsonRefused(ValueError):
    def __init__(self, why):
        super().__init__(why)
        self.why = why


def _unique(pairs) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise JsonRefused(DUPLICATE_KEY)
        result[key] = value
    return result


def parse(raw: bytes):
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
        json.dumps(document, ensure_ascii=False).encode("utf-8")
    except JsonRefused:
        raise
    except UnicodeEncodeError:
        raise JsonRefused(SURROGATE) from None
    except RecursionError:
        raise JsonRefused(TOO_DEEP) from None
    except ValueError:
        raise JsonRefused(NOT_JSON) from None
    return document


def loads(raw: bytes, label: str):
    try:
        return parse(raw)
    except JsonRefused as refused:
        raise Rejected(["%s %s" % (label, refused.why)]) from None
