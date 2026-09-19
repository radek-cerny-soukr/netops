#!/usr/bin/env python3
"""Validate query-source traceability and render the public query catalogue."""

from __future__ import annotations

import argparse
import html
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile
from typing import Any, Mapping
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
SOURCE_REGISTRY = ROOT / "docs/query-sources.json"
OUTPUT = ROOT / "docs/query-catalog.md"
PROFILE_ORDER = (
    "linux",
    "fortinet",
    "extreme_exos",
    "cisco_ios",
    "cisco_xe",
    "cisco_nxos",
    "arista_eos",
    "juniper_junos",
    "juniper_junos_els",
    "ruckus_unleashed",
)
LOGIN_PROFILES = ("ruckus_unleashed",)
OFFICIAL_HOSTS = {
    "docs.fortinet.com",
    "documentation.extremenetworks.com",
    "www.cisco.com",
    "developer.cisco.com",
    "www.arista.com",
    "www.juniper.net",
}
SOURCE_ID_RE = re.compile(r"[A-Z][A-Z0-9-]{2,63}\Z")
VERIFIED_DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
PROJECT_NOTE = "Project contract; upstream source audit pending."
LOGIN_NOTE = (
    "Vendor guide behind a support login; syntax verified on a device 2026-09-16."
)
LOGIN_ACCESS = "login_required"


class RegistryError(ValueError):
    """Raised when the source registry is incomplete or inconsistent."""


class _DuplicateKey(ValueError):
    pass


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _fail(condition: bool, message: str) -> None:
    if not condition:
        raise RegistryError(message)


def _source_type(profile: str) -> str:
    if profile == "linux":
        return "project_contract"
    if profile in LOGIN_PROFILES:
        return "vendor_login_required"
    return "official_vendor"


def load_registry(path: Path = SOURCE_REGISTRY) -> dict[str, Any]:
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object_without_duplicates,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, _DuplicateKey) as exc:
        raise RegistryError("query source registry is unavailable or invalid") from exc
    _fail(isinstance(document, dict), "query source registry root must be an object")
    return document


def load_catalog() -> Mapping[str, Mapping[str, Any]]:
    source_root = str(ROOT / "src")
    if source_root not in sys.path:
        sys.path.insert(0, source_root)
    from netops_helper.query_catalog import READ_QUERIES

    return READ_QUERIES


def _expected_keys(catalog: Mapping[str, Mapping[str, Any]]) -> set[str]:
    return {
        f"{profile}/{query_name}"
        for profile, queries in catalog.items()
        for query_name in queries
    }


def _reference_text(relative: str) -> str:
    pure = PurePosixPath(relative)
    _fail(
        not pure.is_absolute()
        and ".." not in pure.parts
        and len(pure.parts) >= 2
        and pure.parts[0] == "docs",
        f"invalid reference document path: {relative}",
    )
    path = ROOT.joinpath(*pure.parts)
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise RegistryError(f"reference document is unavailable: {relative}") from exc


def validate_registry(
    registry: Mapping[str, Any],
    catalog: Mapping[str, Mapping[str, Any]] | None = None,
) -> None:
    catalog = load_catalog() if catalog is None else catalog
    _fail(
        set(registry) == {"schema", "profiles", "sources", "queries"},
        "registry root fields do not match schema",
    )
    _fail(registry.get("schema") == 1, "unsupported registry schema")
    profiles = registry.get("profiles")
    sources = registry.get("sources")
    queries = registry.get("queries")
    _fail(isinstance(profiles, dict), "profiles must be an object")
    _fail(isinstance(sources, dict), "sources must be an object")
    _fail(isinstance(queries, dict), "queries must be an object")
    _fail(tuple(catalog) == PROFILE_ORDER, "runtime profile order or keyset changed")
    _fail(set(profiles) == set(PROFILE_ORDER), "registry profile keyset changed")
    expected_query_keys = _expected_keys(catalog)
    _fail(set(queries) == expected_query_keys, "registry composite query keyset changed")
    _fail(list(sources) == sorted(sources), "source IDs must be sorted")
    _fail(list(queries) == sorted(queries), "composite query keys must be sorted")

    reference_texts: dict[str, str] = {}
    profile_vendors: dict[str, str | None] = {}
    for profile in PROFILE_ORDER:
        record = profiles[profile]
        _fail(isinstance(record, dict), f"profile record is not an object: {profile}")
        expected_fields = {
            "source_type", "vendor", "baseline", "reference_document"
        }
        if profile == "linux" or profile in LOGIN_PROFILES:
            expected_fields.add("source_note")
        _fail(set(record) == expected_fields, f"invalid profile fields: {profile}")
        expected_type = _source_type(profile)
        _fail(record.get("source_type") == expected_type, f"invalid source type: {profile}")
        vendor = record.get("vendor")
        _fail(
            vendor is None if profile == "linux" else isinstance(vendor, str) and bool(vendor),
            f"invalid profile vendor: {profile}",
        )
        profile_vendors[profile] = vendor
        _fail(
            isinstance(record.get("baseline"), str) and bool(record["baseline"].strip()),
            f"missing profile baseline: {profile}",
        )
        reference = record.get("reference_document")
        _fail(isinstance(reference, str), f"invalid reference document: {profile}")
        reference_texts[profile] = _reference_text(reference)
        if profile == "linux":
            _fail(record.get("source_note") == PROJECT_NOTE, "invalid Linux source marker")
        elif profile in LOGIN_PROFILES:
            _fail(record.get("source_note") == LOGIN_NOTE, f"invalid login-source marker: {profile}")

    source_urls: set[str] = set()
    source_titles: set[str] = set()
    for source_id, record in sources.items():
        _fail(isinstance(source_id, str) and SOURCE_ID_RE.fullmatch(source_id) is not None,
              f"invalid source ID: {source_id}")
        _fail(isinstance(record, dict), f"source record is not an object: {source_id}")
        behind_login = "access" in record
        expected_source_fields = (
            {"vendor", "title", "baseline", "access", "verified_on_device"}
            if behind_login
            else {"vendor", "title", "baseline", "url"}
        )
        _fail(
            set(record) == expected_source_fields,
            f"invalid source fields: {source_id}",
        )
        for field in sorted(expected_source_fields):
            _fail(
                isinstance(record.get(field), str) and bool(record[field].strip()),
                f"source {source_id} has invalid {field}",
            )
        if behind_login:
            _fail(record["access"] == LOGIN_ACCESS, f"invalid source access: {source_id}")
            _fail(
                VERIFIED_DATE_RE.fullmatch(record["verified_on_device"]) is not None,
                f"source behind a login has no measured verification date: {source_id}",
            )
            _fail(
                record["title"] not in source_titles,
                f"duplicate source title: {source_id}",
            )
            source_titles.add(record["title"])
            continue
        url = record["url"]
        parsed = urlsplit(url)
        _fail(parsed.scheme == "https", f"source URL is not HTTPS: {source_id}")
        _fail(parsed.hostname in OFFICIAL_HOSTS, f"source host is not allowlisted: {source_id}")
        _fail(parsed.username is None and parsed.password is None,
              f"source URL contains user information: {source_id}")
        _fail(parsed.port in (None, 443), f"source URL uses an invalid port: {source_id}")
        _fail(not parsed.fragment, f"source URL contains an unstable fragment: {source_id}")
        _fail(
            not any(
                character.isspace()
                or ord(character) < 32
                or character in "<>|"
                for character in url
            ),
            f"source URL contains invalid characters: {source_id}",
        )
        _fail(url not in source_urls, f"duplicate source URL: {source_id}")
        source_urls.add(url)

    referenced_sources: set[str] = set()
    for composite, record in queries.items():
        _fail(isinstance(record, dict), f"query record is not an object: {composite}")
        profile, query_name = composite.split("/", 1)
        expected_fields = {"profile", "query", "source_type", "source_ids"}
        if profile == "linux" or profile in LOGIN_PROFILES:
            expected_fields.add("source_note")
        _fail(set(record) == expected_fields, f"invalid query fields: {composite}")
        _fail(record.get("profile") == profile, f"profile mismatch: {composite}")
        _fail(record.get("query") == query_name, f"query-name mismatch: {composite}")
        _fail(query_name in catalog[profile], f"unknown runtime query: {composite}")
        expected_type = profiles[profile]["source_type"]
        _fail(record.get("source_type") == expected_type, f"source-type mismatch: {composite}")
        source_ids = record.get("source_ids")
        _fail(isinstance(source_ids, list), f"source IDs are not a list: {composite}")
        _fail(
            all(isinstance(source_id, str) for source_id in source_ids),
            f"source ID is not a string: {composite}",
        )
        _fail(len(source_ids) == len(set(source_ids)), f"duplicate source ID: {composite}")
        if profile == "linux":
            _fail(not source_ids, f"Linux query falsely claims a vendor source: {composite}")
            _fail(record.get("source_note") == PROJECT_NOTE,
                  f"Linux query lacks pending-audit marker: {composite}")
            continue
        _fail(bool(source_ids), f"vendor query has no source: {composite}")
        if profile in LOGIN_PROFILES:
            _fail(record.get("source_note") == LOGIN_NOTE,
                  f"login-source query lacks its marker: {composite}")
        for source_id in source_ids:
            _fail(source_id in sources, f"unknown source ID {source_id}: {composite}")
            source = sources[source_id]
            _fail(source["vendor"] == profile_vendors[profile],
                  f"source vendor mismatch {source_id}: {composite}")
            anchor = source["title"] if "access" in source else source["url"]
            _fail(anchor in reference_texts[profile],
                  f"source is absent from narrative {source_id}: {composite}")
            referenced_sources.add(source_id)

    _fail(set(sources) == referenced_sources, "registry contains an unreferenced source record")
    counted = {
        source_type: sum(
            1 for record in queries.values() if record["source_type"] == source_type
        )
        for source_type in ("official_vendor", "project_contract", "vendor_login_required")
    }
    _fail(counted["official_vendor"] == 258, "vendor query count is not 258")
    _fail(counted["project_contract"] == 16, "project-contract query count is not 16")
    _fail(counted["vendor_login_required"] == 4, "login-source query count is not 4")
    _fail(sum(counted.values()) == len(queries), "a query carries an unknown source type")


def _text(value: str) -> str:
    return html.escape(value, quote=False).replace("|", "&#124;")


def _code(value: str) -> str:
    return f"<code>{_text(value)}</code>"


def _slot_cell(query: Any) -> str:
    if not query.slots:
        return "none"
    return "<br>".join(
        _code(f"{parameter} -> {slot.inventory}.{slot.kind}")
        for parameter, slot in query.slots.items()
    )


def _source_cell(registry: Mapping[str, Any], composite: str) -> str:
    record = registry["queries"][composite]
    if record["source_type"] == "project_contract":
        return _text(record["source_note"])
    if record["source_type"] == "vendor_login_required":
        return "<br>".join(
            _text(
                "%s - %s (behind a vendor login; syntax verified on a device %s)"
                % (
                    source_id,
                    registry["sources"][source_id]["title"],
                    registry["sources"][source_id]["verified_on_device"],
                )
            )
            for source_id in record["source_ids"]
        )
    return "<br>".join(
        f"[{source_id}]({registry['sources'][source_id]['url']})"
        for source_id in record["source_ids"]
    )


def render_document(
    registry: Mapping[str, Any],
    catalog: Mapping[str, Mapping[str, Any]] | None = None,
) -> str:
    catalog = load_catalog() if catalog is None else catalog
    validate_registry(registry, catalog)
    total = sum(len(queries) for queries in catalog.values())
    lines = [
        "# Phase-1 query catalog",
        "",
        "This file is generated by `scripts/render_query_catalog_docs.py` from the runtime query authority and `docs/query-sources.json`. Do not edit it manually.",
        "",
        f"It records {total} exact named query templates across {len(PROFILE_ORDER)} canonical profiles. Parameters are accepted only through the listed inventory-bound type. `high-volume: yes` is a maintainer advisory that the fixed command returns a variable collection or history known or conservatively expected to require continuation pages. It does not change authorization, opt-in, rate accounting, timeout, snapshot or cache behavior, or the 2,000,000-byte capture cap. `high-volume: no` is not a promise that output is small, cheap, or bounded.",
        "",
        "The Phase-1 catalog intentionally excludes running, startup, full, backup, and exported configuration; arbitrary CLI; logs except the bounded Linux service query; debug; support bundles; packet capture; file display; shells; and every write or lifecycle action.",
        "",
        "Source links establish reviewed syntax and purpose. They do not prove support, output shape, read-only AAA behavior, or transmitted bytes on a particular target. A source named without a link is a vendor guide that is only reachable behind a vendor login; its row carries the date the syntax was run on a device instead. See the [vendor audit index](vendor-cli-references.md) for limitations and exclusions.",
        "",
    ]
    for profile in PROFILE_ORDER:
        profile_record = registry["profiles"][profile]
        lines.extend((
            f"## `{profile}`",
            "",
            f"Baseline: {profile_record['baseline']}",
            "",
            "| Profile | Query | Exact command template | Parameter -> inventory.kind | High-volume | Description | Source |",
            "|---|---|---|---|---|---|---|",
        ))
        for query_name in sorted(catalog[profile]):
            query = catalog[profile][query_name]
            composite = f"{profile}/{query_name}"
            lines.append(
                "| "
                + " | ".join((
                    _code(profile),
                    _code(query_name),
                    _code(query.command),
                    _slot_cell(query),
                    "yes" if query.high_volume else "no",
                    _text(query.description),
                    _source_cell(registry, composite),
                ))
                + " |"
            )
        lines.append("")
    return "\n".join(lines)


def validate_document(
    document: str,
    registry: Mapping[str, Any],
    catalog: Mapping[str, Mapping[str, Any]] | None = None,
) -> None:
    expected = render_document(registry, catalog)
    if document != expected:
        raise RegistryError("generated query catalog differs from runtime authority or registry")


def _write_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail unless the registry is valid and the generated document is byte-for-byte current",
    )
    args = parser.parse_args()
    try:
        registry = load_registry()
        rendered = render_document(registry)
        if args.check:
            validate_document(OUTPUT.read_text(encoding="utf-8"), registry)
            print("query_catalog_docs=passed")
            return 0
        _write_atomic(OUTPUT, rendered)
    except (OSError, UnicodeError, RegistryError) as exc:
        print(f"query_catalog_docs=failed detail={exc}", file=sys.stderr)
        return 1
    print("query_catalog_docs=rendered")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
