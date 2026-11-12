"""Page metadata of the paged reads, kept out of the response redaction of proxy and worker."""

from __future__ import annotations

import json
import re
from typing import Any

# Protocol metadata of a paged read (ssh_read, schema_read, config_read, config_diff). The engine
# computes these numbers, the flag and the SHA-256 over text that it has already redacted; they carry no device data, so
# they are kept out of response redaction, which would otherwise turn a byte count or a hash
# that happens to contain a known secret into a marker and break the continuation.
PAGED_TOOLS = frozenset(("ssh_read", "schema_read"))
PAGE_METADATA = ("total_bytes", "offset", "returned_bytes", "next_offset", "complete", "content_sha256")
# Configuration pages (the export an Auditor imports) carry the same numbers and hashes without
# `complete`; their snapshot and filter digests are engine-computed too.
CONFIGURATION_PAGED_TOOLS = frozenset(("config_read", "config_diff"))
CONFIGURATION_PAGE_METADATA = ("total_bytes", "offset", "returned_bytes", "next_offset", "content_sha256")
CONFIGURATION_DIGESTS = ("snapshot_sha256", "filter_sha256")
_SHA256 = re.compile(r"[0-9a-f]{64}")


def _count(value: object) -> bool:
    return type(value) is int and value >= 0


def _digest(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def page_metadata(structured: object, tool: str = "ssh_read") -> dict[str, Any] | None:
    """The typed metadata of a successful page of `tool`, or None when any field has another shape."""
    if tool in CONFIGURATION_PAGED_TOOLS:
        names = CONFIGURATION_PAGE_METADATA
    elif tool in PAGED_TOOLS:
        names = PAGE_METADATA
    else:
        return None
    if not isinstance(structured, dict) or structured.get("ok") is not True:
        return None
    if not all(name in structured for name in names):
        return None
    metadata = {name: structured[name] for name in names}
    next_offset = metadata["next_offset"]
    if not (
        _count(metadata["total_bytes"]) and _count(metadata["offset"])
        and _count(metadata["returned_bytes"])
        and (next_offset is None or (_count(next_offset) and next_offset > 0))
        and ("complete" not in metadata or type(metadata["complete"]) is bool)
        and _digest(metadata["content_sha256"])
    ):
        return None
    if tool in CONFIGURATION_PAGED_TOOLS:
        for name in CONFIGURATION_DIGESTS:
            if name in structured:
                if not _digest(structured[name]):
                    return None
                metadata[name] = structured[name]
    return metadata


def json_object(text: str) -> dict[str, Any] | None:
    """`text` decoded when it is one JSON object, else None."""
    try:
        decoded = json.loads(text)
    except (ValueError, RecursionError):
        return None
    return decoded if isinstance(decoded, dict) else None


def _text_document(item: object) -> dict[str, Any] | None:
    if not isinstance(item, dict) or item.get("type") != "text" or not isinstance(item.get("text"), str):
        return None
    return json_object(item["text"])


def _with_metadata(document: dict[str, Any], order: list[str], metadata: dict[str, Any]) -> dict[str, Any]:
    restored = {name: metadata[name] if name in metadata else document[name]
                for name in order if name in metadata or name in document}
    restored.update((name, value) for name, value in document.items() if name not in restored)
    return restored


def strip_page_metadata(result: dict[str, Any], metadata: dict[str, Any]):
    """Copy of an MCP tool result without the page metadata, and a function that puts it back.

    The metadata is removed from `structuredContent` and from every JSON text item, so no
    redaction layer sees it; `restore(result)` writes it back in place, at the original key
    positions. A text item that is no longer a JSON object after redaction stays without it.
    """
    stripped = dict(result)
    orders: dict[Any, list[str]] = {}
    structured = result.get("structuredContent")
    if isinstance(structured, dict):
        orders["structured"] = list(structured)
        stripped["structuredContent"] = {name: value for name, value in structured.items()
                                         if name not in metadata}
    content = result.get("content")
    if isinstance(content, list):
        stripped["content"] = list(content)
        for index, item in enumerate(content):
            document = _text_document(item)
            if document is None:
                continue
            orders[index] = list(document)
            text = json.dumps({name: value for name, value in document.items() if name not in metadata},
                              separators=(",", ":"), ensure_ascii=item["text"].isascii())
            stripped["content"][index] = {**item, "text": text}

    def restore(cleaned: dict[str, Any]) -> dict[str, Any]:
        structured = cleaned.get("structuredContent")
        if "structured" in orders and isinstance(structured, dict):
            cleaned["structuredContent"] = _with_metadata(structured, orders["structured"], metadata)
        content = cleaned.get("content")
        for index, order in orders.items():
            if index == "structured" or not isinstance(content, list) or index >= len(content):
                continue
            document = _text_document(content[index])
            if document is None:
                continue
            text = json.dumps(_with_metadata(document, order, metadata), separators=(",", ":"),
                              ensure_ascii=content[index]["text"].isascii())
            content[index] = {**content[index], "text": text}
        return cleaned

    return stripped, restore
