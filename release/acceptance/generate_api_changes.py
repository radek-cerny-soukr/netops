"""Draft exact declarations from verify_state MCP captures with reviewed reasons.

The reasons are not part of this tool: --reasons names a reviewed file, either an earlier declaration (its
item reasons are reused per tool and kind) or a JSON object {"<tool> <kind>": "<reason>"}. A change without a
reviewed reason is an error; --draft writes a TODO(api-review) placeholder instead, which verify_state refuses.
"""
import argparse
import json
from pathlib import Path

from verify_state import (CATALOG, COMPARED, VALUE_FIELDS, catalog_payload, fingerprint,
                          pointer_diff, short_scalar, tool_definitions, tool_payload, value_at)


def expectation(value):
    result = {"sha256": fingerprint(value)}
    if short_scalar(value):
        result["value"] = value
    return result


DRAFT_REASON = "TODO(api-review): describe this change"


def load_reasons(path):
    document = json.loads(Path(path).read_text())
    if isinstance(document, dict) and isinstance(document.get("changes"), list):
        return {item["tool"] + " " + item["kind"]: item["reason"] for item in document["changes"]}
    if isinstance(document, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in document.items()):
        return dict(document)
    raise ValueError("reasons must be a declaration or an object of '<tool> <kind>' to reason")


def generate(before, after, from_version, to_version, reasons=None, draft=False):
    reasons = dict(reasons or {})
    missing = []

    def reason(tool, kind):
        found = reasons.get(tool + " " + kind)
        if found is None:
            missing.append(tool + " " + kind)
            return DRAFT_REASON
        return found

    changes = []
    old, new = tool_definitions(before), tool_definitions(after)
    if not old or not new or set(old) - set(new):
        raise ValueError("missing tools/list or removed tools; manual API review required")
    for tool in sorted(set(new) - set(old)):
        changes.append({"tool": tool, "kind": "added", "reason": reason(tool, "added")})

    def record(tool, kind, a, b):
        diff = pointer_diff(a, b)
        if not any(diff.values()):
            return
        item = {"tool": tool, "kind": kind, "reason": reason(tool, kind)}
        for field, pointers in diff.items():
            if pointers:
                item[field] = {p: expectation(value_at(b, p)) for p in pointers} if field in VALUE_FIELDS else pointers
        changes.append(item)

    for tool in sorted(set(old) & set(new)):
        record(tool, "definition", old[tool], new[tool])
    for name, tool in COMPARED:
        if tool == CATALOG:
            a, b = catalog_payload(before), catalog_payload(after)
        else:
            if any(not (m.get("calls", {}).get(name) or {}).get("reply", {}).get("result") for m in (before, after)):
                raise ValueError("missing response: " + name)
            a, b = (tool_payload((m["calls"][name])["reply"], version)
                    for m, version in ((before, from_version), (after, to_version)))
        if a is None or b is None or a["isError"] != b["isError"]:
            raise ValueError("incomplete or changed result state: " + name)
        record(tool, "response", a["content"], b["content"])
    if missing and not draft:
        raise ValueError("no reviewed reason for: " + ", ".join(missing))
    return {"from": from_version, "to": to_version, "changes": changes}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before")
    parser.add_argument("after")
    parser.add_argument("--from-version", required=True)
    parser.add_argument("--to-version", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--reasons", help="reviewed reasons: an earlier declaration or a '<tool> <kind>' object")
    parser.add_argument("--draft", action="store_true", help="write TODO(api-review) placeholders for missing reasons")
    args = parser.parse_args()
    result = generate(json.loads(Path(args.before).read_text()), json.loads(Path(args.after).read_text()),
                      args.from_version, args.to_version, load_reasons(args.reasons) if args.reasons else None, args.draft)
    Path(args.out).write_text(json.dumps(result, indent=1, ensure_ascii=False) + "\n")
