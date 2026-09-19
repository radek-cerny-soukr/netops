from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/render_query_catalog_docs.py"


def _load_renderer():
    specification = importlib.util.spec_from_file_location("render_query_catalog_docs", SCRIPT)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


RENDERER = _load_renderer()


def _must_reject(function, *args) -> None:
    try:
        function(*args)
    except (RENDERER.RegistryError, OSError, UnicodeError):
        return
    raise AssertionError("unsafe query-catalog mutation was accepted")


def _mutate_row(document: str, profile: str, query_name: str, mutation) -> str:
    prefix = f"| <code>{profile}</code> | <code>{query_name}</code> |"
    lines = document.splitlines(keepends=True)
    matches = [index for index, line in enumerate(lines) if line.startswith(prefix)]
    assert len(matches) == 1, (profile, query_name, matches)
    index = matches[0]
    mutated = mutation(lines[index])
    assert mutated != lines[index]
    lines[index] = mutated
    return "".join(lines)


def test_registry_has_exact_profile_and_composite_keysets() -> None:
    registry = RENDERER.load_registry()
    catalog = RENDERER.load_catalog()
    RENDERER.validate_registry(registry, catalog)
    assert tuple(catalog) == RENDERER.PROFILE_ORDER
    assert len(registry["queries"]) == 278
    assert sum(len(queries) for queries in catalog.values()) == 278
    vendor = [
        record for record in registry["queries"].values()
        if record["source_type"] == "official_vendor"
    ]
    project = [
        record for record in registry["queries"].values()
        if record["source_type"] == "project_contract"
    ]
    behind_login = [
        record for record in registry["queries"].values()
        if record["source_type"] == "vendor_login_required"
    ]
    assert len(vendor) == 258
    assert len(project) == 16
    assert len(behind_login) == 4
    assert all(record["source_ids"] for record in vendor)
    assert all(not record["source_ids"] for record in project)
    assert all(record["source_note"] == RENDERER.PROJECT_NOTE for record in project)
    assert all(record["source_ids"] for record in behind_login)
    assert all(record["source_note"] == RENDERER.LOGIN_NOTE for record in behind_login)
    assert all(
        "url" not in registry["sources"][source_id]
        for record in behind_login
        for source_id in record["source_ids"]
    )


def test_generated_document_is_byte_for_byte_current() -> None:
    registry = RENDERER.load_registry()
    catalog = RENDERER.load_catalog()
    document = (ROOT / "docs/query-catalog.md").read_text(encoding="utf-8")
    RENDERER.validate_document(document, registry, catalog)
    assert document == RENDERER.render_document(registry, catalog)
    for profile, queries in catalog.items():
        for query_name in queries:
            prefix = f"| <code>{profile}</code> | <code>{query_name}</code> |"
            assert document.count(prefix) == 1, f"{profile}/{query_name}"
    data_rows = [line for line in document.splitlines() if line.startswith("| <code>")]
    assert len(data_rows) == 278
    assert all(line.count("|") == 8 for line in data_rows)


def test_document_drift_in_command_slot_volume_and_description_is_rejected() -> None:
    registry = RENDERER.load_registry()
    catalog = RENDERER.load_catalog()
    document = RENDERER.render_document(registry, catalog)
    command = catalog["fortinet"]["system_status"].command
    command_drift = _mutate_row(
        document,
        "fortinet",
        "system_status",
        lambda line: line.replace(RENDERER._code(command), RENDERER._code(command + " altered"), 1),
    )
    _must_reject(RENDERER.validate_document, command_drift, registry, catalog)

    slot_text = RENDERER._slot_cell(catalog["fortinet"]["interface_details"])
    slot_drift = _mutate_row(
        document,
        "fortinet",
        "interface_details",
        lambda line: line.replace(slot_text, slot_text.replace("interfaces.", "wrong."), 1),
    )
    _must_reject(RENDERER.validate_document, slot_drift, registry, catalog)

    volume_drift = _mutate_row(
        document,
        "fortinet",
        "routing_table",
        lambda line: line.replace(" | yes | ", " | no | ", 1),
    )
    _must_reject(RENDERER.validate_document, volume_drift, registry, catalog)

    description = catalog["fortinet"]["system_status"].description
    description_drift = _mutate_row(
        document,
        "fortinet",
        "system_status",
        lambda line: line.replace(description, description + " Altered.", 1),
    )
    _must_reject(RENDERER.validate_document, description_drift, registry, catalog)


def test_missing_same_name_records_in_distinct_profiles_are_rejected() -> None:
    registry = RENDERER.load_registry()
    for composite in ("cisco_xe/version", "juniper_junos_els/version"):
        mutated = deepcopy(registry)
        del mutated["queries"][composite]
        _must_reject(RENDERER.validate_registry, mutated)


def test_unknown_missing_and_duplicate_source_ids_are_rejected() -> None:
    registry = RENDERER.load_registry()
    composite = "fortinet/system_status"

    unknown = deepcopy(registry)
    unknown["queries"][composite]["source_ids"][0] = "F-UNKNOWN-SOURCE"
    _must_reject(RENDERER.validate_registry, unknown)

    missing = deepcopy(registry)
    source_id = missing["queries"][composite]["source_ids"][0]
    del missing["sources"][source_id]
    _must_reject(RENDERER.validate_registry, missing)

    duplicate = deepcopy(registry)
    duplicate["queries"][composite]["source_ids"].append(
        duplicate["queries"][composite]["source_ids"][0]
    )
    _must_reject(RENDERER.validate_registry, duplicate)


def test_duplicate_json_keys_and_unofficial_urls_are_rejected() -> None:
    with tempfile.TemporaryDirectory(prefix="query-registry-negative-") as temporary:
        duplicate = Path(temporary) / "duplicate.json"
        duplicate.write_text(
            '{"schema":1,"schema":1,"profiles":{},"sources":{},"queries":{}}\n',
            encoding="utf-8",
        )
        _must_reject(RENDERER.load_registry, duplicate)

    registry = RENDERER.load_registry()
    source_id = next(iter(registry["sources"]))
    for url in (
        "http://www.cisco.com/reference",
        "https://www.cisco.com.evil.example/reference",
        "https://user:password@www.cisco.com/reference",
        "https://www.cisco.com:8443/reference",
        "https://www.cisco.com/reference#mutable-fragment",
    ):
        mutated = deepcopy(registry)
        mutated["sources"][source_id]["url"] = url
        _must_reject(RENDERER.validate_registry, mutated)


def test_manual_document_edit_is_rejected() -> None:
    registry = RENDERER.load_registry()
    document = RENDERER.render_document(registry)
    _must_reject(
        RENDERER.validate_document,
        document + "\nManual undocumented line.\n",
        registry,
    )


def main() -> int:
    test_registry_has_exact_profile_and_composite_keysets()
    test_generated_document_is_byte_for_byte_current()
    test_document_drift_in_command_slot_volume_and_description_is_rejected()
    test_missing_same_name_records_in_distinct_profiles_are_rejected()
    test_unknown_missing_and_duplicate_source_ids_are_rejected()
    test_duplicate_json_keys_and_unofficial_urls_are_rejected()
    test_manual_document_edit_is_rejected()
    print("query_catalog_docs_tests=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
