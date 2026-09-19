from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from netops_helper.query_catalog import READ_QUERIES  # noqa: E402


DOCS = ROOT / "docs"
INDEX = DOCS / "vendor-cli-references.md"
SOURCE_DIR = DOCS / "vendor-cli-references"
PROFILE_DOCUMENTS = {
    "fortinet": "fortinet-fortios.md",
    "extreme_exos": "extreme-switch-engine.md",
    "cisco_ios": "cisco.md",
    "cisco_xe": "cisco.md",
    "cisco_nxos": "cisco.md",
    "arista_eos": "arista-eos.md",
    "juniper_junos": "juniper-junos.md",
    "juniper_junos_els": "juniper-junos.md",
    "ruckus_unleashed": "ruckus-unleashed.md",
}
LOGIN_ONLY_DOCUMENTS = {"ruckus-unleashed.md"}
LOGIN_SOURCE_TITLE = "Ruckus Unleashed 200.13 CLI Reference Guide"
LOGIN_VERIFIED_ON_DEVICE = "2026-09-16"
CANONICAL_KEYS_AND_ALIASES = {
    "fortinet",
    "fortios",
    "extreme_exos",
    "extreme_switch_engine",
    "cisco_ios",
    "cisco_xe",
    "cisco_nxos",
    "arista_eos",
    "juniper_junos",
    "juniper_junos_els",
    "ruckus_unleashed",
}
ALLOWED_HOSTS = {
    "docs.fortinet.com",
    "documentation.extremenetworks.com",
    "www.cisco.com",
    "developer.cisco.com",
    "www.arista.com",
    "www.juniper.net",
}
URL_RE = re.compile(r"https?://[^\s<>()|\]]+")
INDEX_LINK_RE = re.compile(r"\[[^\]]+\]\((vendor-cli-references/[^)]+\.md)\)")
TABLE_ROW_RE = re.compile(
    r"^\|\s*`([^`]+)`\s*\|\s*`([^`]+)`\s*\|\s*"
    r"(none|`[^`]+`)\s*\|\s*(normal|high-volume)\s*\|\s*([^|\n]+)\|",
    re.MULTILINE,
)
REQUIRED_SECTION_PATTERNS = {
    "accepted": re.compile(r"^#{2,3}\s+.*accepted", re.IGNORECASE | re.MULTILINE),
    "excluded": re.compile(r"^#{2,3}\s+.*exclu", re.IGNORECASE | re.MULTILINE),
    "deferred": re.compile(r"^#{2,3}\s+.*deferred", re.IGNORECASE | re.MULTILINE),
    "limitations": re.compile(
        r"^#{2,3}\s+.*(?:limitations|limits|constraints)",
        re.IGNORECASE | re.MULTILINE,
    ),
}


def _load_renderer():
    path = ROOT / "scripts/render_query_catalog_docs.py"
    specification = importlib.util.spec_from_file_location("vendor_registry_renderer", path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


RENDERER = _load_renderer()


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _extract_urls(text: str) -> tuple[str, ...]:
    return tuple(URL_RE.findall(text))


def _validate_official_urls(text: str) -> None:
    urls = _extract_urls(text)
    assert urls, "source document has no URL"
    for url in urls:
        parsed = urlsplit(url)
        assert parsed.scheme == "https", url
        assert parsed.username is None and parsed.password is None, url
        assert parsed.port in (None, 443), url
        assert parsed.hostname in ALLOWED_HOSTS, url
        assert not any(character.isspace() or ord(character) < 32 for character in url), url


def _validate_login_only_source(text: str) -> None:
    assert not _extract_urls(text), "a source behind a login must claim no public URL"
    assert LOGIN_SOURCE_TITLE in text
    assert LOGIN_VERIFIED_ON_DEVICE in text
    assert "behind a vendor support login" in text


def _validate_source_document(
    text: str, query_names: set[str], login_only: bool = False,
) -> None:
    assert re.search(
        r"(?:Audit|Verification) date:\s*2026-09-(?:09|16)\.",
        text,
        re.IGNORECASE,
    )
    for section, pattern in REQUIRED_SECTION_PATTERNS.items():
        assert pattern.search(text), section
    assert "../query-catalog.md" in text
    for query_name in query_names:
        assert f"`{query_name}`" in text, query_name
    if login_only:
        _validate_login_only_source(text)
        return
    _validate_official_urls(text)


def _slot_label(query) -> str:
    if not query.slots:
        return "none"
    assert len(query.slots) == 1
    slot = next(iter(query.slots.values()))
    return f"{slot.inventory}.{slot.kind}"


def _parse_detailed_accepted_table(
    text: str,
) -> dict[str, tuple[str, str, str, tuple[str, ...]]]:
    rows: dict[str, tuple[str, str, str, tuple[str, ...]]] = {}
    for query_name, command, raw_slot, volume, raw_sources in TABLE_ROW_RE.findall(text):
        assert query_name not in rows, query_name
        slot = raw_slot.strip("`")
        sources = tuple(item.strip() for item in raw_sources.split(",") if item.strip())
        assert sources, query_name
        rows[query_name] = (command, slot, volume, sources)
    assert rows
    return rows


def _validate_detailed_table(text: str, profile: str, registry) -> None:
    catalogue = READ_QUERIES[profile]
    rows = _parse_detailed_accepted_table(text)
    assert set(rows) == set(catalogue)
    for query_name, query in catalogue.items():
        registry_sources = tuple(
            registry["queries"][f"{profile}/{query_name}"]["source_ids"]
        )
        expected = (
            query.command,
            _slot_label(query),
            "high-volume" if query.high_volume else "normal",
            registry_sources,
        )
        assert rows[query_name] == expected, f"{profile}/{query_name}"


def _assert_rejected(validation) -> None:
    try:
        validation()
    except (AssertionError, ValueError):
        return
    raise AssertionError("unsafe mutation was accepted")


def test_index_keys_and_vendor_links() -> None:
    text = _read(INDEX)
    for key in CANONICAL_KEYS_AND_ALIASES:
        assert f"`{key}`" in text, key
    assert "query-catalog.md" in text
    links = INDEX_LINK_RE.findall(text)
    expected = {f"vendor-cli-references/{name}" for name in set(PROFILE_DOCUMENTS.values())}
    assert set(links) == expected
    assert len(set(links)) == len(set(PROFILE_DOCUMENTS.values()))
    for link in links:
        assert (DOCS / link).is_file(), link


def test_source_documents_cover_profiles_sections_urls_and_catalog_link() -> None:
    for filename in sorted(set(PROFILE_DOCUMENTS.values())):
        profiles = {
            profile for profile, source_filename in PROFILE_DOCUMENTS.items()
            if source_filename == filename
        }
        names = {name for profile in profiles for name in READ_QUERIES[profile]}
        _validate_source_document(
            _read(SOURCE_DIR / filename), names, filename in LOGIN_ONLY_DOCUMENTS,
        )


def test_registry_resolves_every_vendor_composite_to_its_narrative() -> None:
    registry = RENDERER.load_registry()
    RENDERER.validate_registry(registry, READ_QUERIES)
    assert set(registry["profiles"]) == set(RENDERER.PROFILE_ORDER)
    assert set(registry["queries"]) == {
        f"{profile}/{query_name}"
        for profile, queries in READ_QUERIES.items()
        for query_name in queries
    }
    for profile, filename in PROFILE_DOCUMENTS.items():
        text = _read(SOURCE_DIR / filename)
        login_only = filename in LOGIN_ONLY_DOCUMENTS
        for query_name in READ_QUERIES[profile]:
            record = registry["queries"][f"{profile}/{query_name}"]
            assert record["source_type"] == (
                "vendor_login_required" if login_only else "official_vendor"
            )
            assert record["source_ids"]
            for source_id in record["source_ids"]:
                source = registry["sources"][source_id]
                assert source["vendor"] == registry["profiles"][profile]["vendor"]
                if login_only:
                    assert "url" not in source
                    assert source["access"] == "login_required"
                    assert source["verified_on_device"] == LOGIN_VERIFIED_ON_DEVICE
                    assert source["title"] in text
                    continue
                assert source["url"] in text


def test_fortinet_and_extreme_tables_match_catalogue_and_registry() -> None:
    registry = RENDERER.load_registry()
    _validate_detailed_table(
        _read(SOURCE_DIR / "fortinet-fortios.md"),
        "fortinet",
        registry,
    )
    _validate_detailed_table(
        _read(SOURCE_DIR / "extreme-switch-engine.md"),
        "extreme_exos",
        registry,
    )


def test_mutations_cannot_remove_query_tokens_or_change_source_ids() -> None:
    registry = RENDERER.load_registry()
    for profile, filename in PROFILE_DOCUMENTS.items():
        text = _read(SOURCE_DIR / filename)
        login_only = filename in LOGIN_ONLY_DOCUMENTS
        query_name = sorted(READ_QUERIES[profile])[0]
        token = f"`{query_name}`"
        assert token in text
        mutated = text.replace(token, query_name)
        names = set(READ_QUERIES[profile])
        _assert_rejected(
            lambda mutated=mutated, names=names, login_only=login_only: (
                _validate_source_document(mutated, names, login_only)
            )
        )

    text = _read(SOURCE_DIR / "fortinet-fortios.md")
    mutated = text.replace("F-CLI-76, F-CLI-80", "F-CLI-80", 1)
    _assert_rejected(
        lambda: _validate_detailed_table(mutated, "fortinet", registry)
    )


def test_mutations_cannot_introduce_foreign_or_insecure_urls() -> None:
    text = _read(SOURCE_DIR / "cisco.md")
    first_url = _extract_urls(text)[0]
    bad_urls = (
        "https://example.com/vendor-reference",
        "https://www.cisco.com.evil.example/vendor-reference",
        "http://www.cisco.com/vendor-reference",
        "https://user:password@www.cisco.com/vendor-reference",
        "https://www.cisco.com:8443/vendor-reference",
    )
    for bad_url in bad_urls:
        mutated = text.replace(first_url, bad_url, 1)
        _assert_rejected(lambda mutated=mutated: _validate_official_urls(mutated))


def test_a_login_only_source_may_not_invent_a_public_url() -> None:
    text = _read(SOURCE_DIR / "ruckus-unleashed.md")
    names = set(READ_QUERIES["ruckus_unleashed"])
    _validate_source_document(text, names, True)
    for invented in (
        "https://docs.fortinet.com/unleashed",
        "https://www.arista.com/unleashed",
    ):
        mutated = text.replace("## Limitations", f"{invented}\n\n## Limitations", 1)
        _assert_rejected(
            lambda mutated=mutated, names=names: _validate_source_document(
                mutated, names, True,
            )
        )
    stripped = text.replace(LOGIN_VERIFIED_ON_DEVICE, "sometime")
    _assert_rejected(
        lambda: _validate_source_document(stripped, names, True)
    )


def main() -> int:
    test_index_keys_and_vendor_links()
    test_source_documents_cover_profiles_sections_urls_and_catalog_link()
    test_registry_resolves_every_vendor_composite_to_its_narrative()
    test_fortinet_and_extreme_tables_match_catalogue_and_registry()
    test_mutations_cannot_remove_query_tokens_or_change_source_ids()
    test_mutations_cannot_introduce_foreign_or_insecure_urls()
    test_a_login_only_source_may_not_invent_a_public_url()
    print("vendor_reference_tests=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
