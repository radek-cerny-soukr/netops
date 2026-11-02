from __future__ import annotations

import importlib.util
from pathlib import Path
import posixpath
import re
import sys
import tomllib
from urllib.parse import unquote, urlsplit


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
    "fortiadc": "fortinet-fortiadc.md",
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
    "fortiadc",
}
ALLOWED_HOSTS = {
    "docs.fortinet.com",
    "community.fortinet.com",
    "documentation.extremenetworks.com",
    "www.cisco.com",
    "developer.cisco.com",
    "www.arista.com",
    "www.juniper.net",
}
REPOSITORY = "https://github.com/radek-cerny-soukr/netops"
COMPONENT_PATH = "components/netops-helper/"
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
    path = ROOT / "tests/support/render_query_catalog_docs.py"
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


def _repository_link_prefix() -> str:
    project = tomllib.loads(_read(ROOT.parents[1] / "pyproject.toml"))["project"]
    return REPOSITORY + "/blob/v" + project["version"] + "/"


REPOSITORY_LINK_PREFIX = _repository_link_prefix()


def _is_repository_link(url: str) -> bool:
    if not url.startswith(REPOSITORY_LINK_PREFIX):
        return False
    path = unquote(urlsplit(url).path)[len(urlsplit(REPOSITORY_LINK_PREFIX).path):]
    return (
        posixpath.normpath(path) == path
        and path != ".."
        and not path.startswith(("/", "../", "docs/archive/"))
        and (ROOT.parents[1] / path).is_file()
    )


def _vendor_urls(text: str) -> tuple[str, ...]:
    return tuple(url for url in _extract_urls(text) if not _is_repository_link(url))


def _validate_official_urls(text: str) -> None:
    urls = _vendor_urls(text)
    assert urls, "source document has no URL"
    for url in urls:
        parsed = urlsplit(url)
        assert parsed.scheme == "https", url
        assert parsed.username is None and parsed.password is None, url
        assert parsed.port in (None, 443), url
        assert parsed.hostname in ALLOWED_HOSTS, url
        assert not any(character.isspace() or ord(character) < 32 for character in url), url


def _validate_login_only_source(text: str) -> None:
    assert not _vendor_urls(text), "a source behind a login must claim no public URL"
    assert LOGIN_SOURCE_TITLE in text
    assert LOGIN_VERIFIED_ON_DEVICE in text
    assert "behind a vendor support login" in text


def _validate_source_document(
    text: str, query_names: set[str], login_only: bool = False,
) -> None:
    assert re.search(
        r"(?:Audit|Verification) date:\s*2026-(?:09-(?:09|16)|10-27)\.",
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
    if len(query.slots) == 1:
        slot = next(iter(query.slots.values()))
        return f"{slot.inventory}.{slot.kind}"
    return ", ".join(
        f"{name} -> {slot.inventory}.{slot.kind}"
        for name, slot in sorted(query.slots.items())
    )


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
    _validate_detailed_table(
        _read(SOURCE_DIR / "fortinet-fortiadc.md"),
        "fortiadc",
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


def test_only_this_release_repository_links_are_accepted_besides_vendors() -> None:
    cisco = _read(SOURCE_DIR / "cisco.md")
    ruckus = _read(SOURCE_DIR / "ruckus-unleashed.md")
    names = set(READ_QUERIES["ruckus_unleashed"])
    own = REPOSITORY_LINK_PREFIX + "docs/compatibility-boundaries.md"
    for accepted in (own, own + "#scope", REPOSITORY_LINK_PREFIX + "components/netops-core/docs/ssh.md"):
        _validate_official_urls(f"{cisco}\nSee [it]({accepted}).\n")
        _validate_source_document(f"{ruckus}\nSee [it]({accepted}).\n", names, True)
    _assert_rejected(lambda: _validate_official_urls(f"See [it]({own})."))
    version = REPOSITORY_LINK_PREFIX.split("/blob/", 1)[1]
    for rejected in (
        own.replace("radek-cerny-soukr/netops", "someone-else/netops", 1),
        own.replace("/netops/blob/", "/netops-fork/blob/", 1),
        own.replace(version, "main/", 1),
        own.replace(version, "netops-helper/v0.0.1/", 1),
        own.replace(version, "netops-core/v" + version.removeprefix("v"), 1),
        own.replace("https://", "http://", 1),
        own.replace("github.com", "github.com:8443", 1),
        own.replace("github.com", "user@github.com", 1),
        own.replace("github.com", "github.com.evil.example", 1),
        REPOSITORY_LINK_PREFIX + COMPONENT_PATH + "docs/installation.md",
        REPOSITORY_LINK_PREFIX + "../docs/compatibility-boundaries.md",
        REPOSITORY_LINK_PREFIX + "docs/../../compatibility-boundaries.md",
        REPOSITORY_LINK_PREFIX,
        REPOSITORY_LINK_PREFIX + "..",
        REPOSITORY_LINK_PREFIX + "/docs/compatibility-boundaries.md",
        "https://github.com/radek-cerny-soukr/netops",
        "https://example.com/vendor-reference",
    ):
        _assert_rejected(
            lambda rejected=rejected: _validate_official_urls(f"{cisco}\nSee [it]({rejected}).\n")
        )
        _assert_rejected(
            lambda rejected=rejected: _validate_source_document(
                f"{ruckus}\nSee [it]({rejected}).\n", names, True,
            )
        )


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


FORTIADC_BASELINE = "FortiADC 7.6.7"
FORTIADC_DOCUMENT_ROOT = "https://docs.fortinet.com/document/fortiadc/7.6.7/"
FORTIADC_PROVENANCE = {
    'F-ADC-EXECUTE-SSL-HANDSHAKE-RECORD-76': (
        'https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/606888/execute-ssl-handshake-record-statistics',
        ('4f9c962c7652e0f6b02ad5ded3d8047b334183e0dbbcb4efb04286ae12c8ba87',),
    ),
    'F-ADC-EXECUTE-SSL-CLIENT-SESSION-76': (
        'https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/617840/execute-ssl-client-side-session-statistics',
        ('f78bf910aa9c38b547585fa115efcfb9cf3c8c71e9511bdbd47cd4d3b234e939',),
    ),
    "F-ADC-EXECUTE-DOS-GET-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/705032/execute-dos-get",
        ("4f644807d5af84cef926be97c6f1b392939366e690b5c7c255575312add56472",),
    ),
    "F-ADC-CLI-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference",
        ("ea7ac3cda6140e5e98cb6a8750b4ffc2c162e351211e4e5a2b9798c421c6f7a8",),
    ),
    "F-ADC-GET-SYSTEM-STATUS-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/379949/get-system-status",
        (
            "311be651a39bcfc5db2ade9b3ca269ab1c4eb0dafa6d76faed1b61aef240fae9",
            "0573f62380b5945754ce8dcbcb3b80da333dde5451ce59a988dbf8ef023d4142",
        ),
    ),
    "F-ADC-GET-SYSTEM-PERFORMANCE-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/420036/get-system-performance",
        ("30c11b9de3bf41af1b77ef9cb0838ff85d4e0fb49a6193d6d906bab7561d4b67",),
    ),
    "F-ADC-DIAGNOSE-SYSTEM-VM-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/878940/diagnose-system-vm",
        ("607bf59689f6f3c1c200711d3797afabfb5efc672fccb16153720ce14a6243bf",),
    ),
    "F-ADC-DIAGNOSE-NETLINK-INTERFACE-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/188513/diagnose-netlink-interface",
        ("2e8600a66855e815a79c7f63c17190117ee5bf16bc076a0438419248f5b45002",),
    ),
    "F-ADC-DIAGNOSE-NETLINK-DEVICE-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/176977/diagnose-netlink-device",
        ("b9c63d029caf6879e521e133568879ca01515fb72874b39940280151b35f138e",),
    ),
    "F-ADC-GET-ROUTER-INFO-ROUTING-TABLE-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/474071/get-router-info-routing-table",
        ("9d3d431e4368bee70a3fc3d2798a5b66139d36912b03b5241188c1ea540fc318",),
    ),
    "F-ADC-DIAGNOSE-NETLINK-NEIGHBOR-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/354318/diagnose-netlink-neighbor-neighbor6",
        ("f351ad74bf99040426d6eae1f5f82c08c9045a6f2eaceec3f6ec4ef10cce61ad",),
    ),
    "F-ADC-GET-FIREWALL-GLOBAL-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/492107/get-firewall-global",
        ("98c67cc3bc735ebf8069d6ccf97abac464f4b3197c3c12efe68cb8fab90af874",),
    ),
    "F-ADC-DIAGNOSE-SERVER-LOAD-BALANCE-SLB-LOAD-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/242244/diagnose-server-load-balance-slb-load",
        ("0bc15c7a149f19ff58c381283c563b66389277619a97c4f0f388cfd284fd70cf",),
    ),
    "F-ADC-DIAGNOSE-SERVER-LOAD-BALANCE-VS-STAT-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/531193/diagnose-server-load-balance-vs-stat",
        ("84aec25fd20d656a01784138823655112c9f92b1bce076f2df569a7a520ddad5",),
    ),
    "F-ADC-GET-SECURITY-WAF-SIGNATURE-STATUS-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/165394/get-security-waf-signature-status",
        ("7111fba6e2511b68f1a5d5d2b277de3c320b248d3101312c6c090b96f2dfae3a",),
    ),
    "F-ADC-DIAGNOSE-HARDWARE-SYSINFO-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/106768/diagnose-hardware-sysinfo",
        ("1d62204b8af0306762f632f78bca87f1bccff280d25accf1dc2da03720908196",),
    ),
    "F-ADC-DIAGNOSE-SERVER-LOAD-BALANCE-SESSION-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/894949/diagnose-server-load-balance-session",
        ("bd59becb4f57ca250505e847d34acd31dfed2a95c26ad9c3421634dbcb07dc2f",),
    ),
    "F-ADC-DIAGNOSE-SERVER-LOAD-BALANCE-PERSISTENCE-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/136507/diagnose-server-load-balance-persistence",
        ("890fa8c9efdc765aea8e6d37a431ef2b5ce7295398176f4e8e750d366dd881ca",),
    ),
    "F-ADC-DIAGNOSE-HARDWARE-DEVICEINFO-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/273890/diagnose-hardware-deviceinfo",
        ("4fbee9e08b980a6640fec25888023dfc682a1fac879470166222880cfa481c3d",),
    ),
    "F-ADC-EXECUTE-WAF-BLOCK-IP-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/503984/execute-waf-block-ip",
        ("31a0ecdc97029d87485f6c00e112c09526c7f36711d25ea83ec33ff268a44843",),
    ),
    "F-ADC-EXECUTE-LOG-LIST-TYPE-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/36340/execute-log-list-type",
        ("9d8bb206a7d1596a098748bb6232aa922b52410a82c18d32a7752342daed4579",),
    ),
    "F-ADC-EXECUTE-AUTOUPDATE-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/244507/execute-autoupdate",
        ("01f2edc3e6ff0552d53aa55cc0b5d39de53d54833c09858dcbab373212a09183",),
    ),
    "F-ADC-DIAGNOSE-LLB-POLICY-LIST-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/410726/diagnose-llb-policy-list",
        ("cbdad7c1e85b08e987a7586c544214b2f3ca75724964b9916494b259b78a373c",),
    ),
    "F-ADC-DIAGNOSE-LLDPRX-NEIGHBOR-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/51527/diagnose-lldprx-neighbor",
        ("f24e9cbf19e7784319aa9cc23802416b8016fd31b88bad984a99931d061a1ef6",),
    ),
    "F-ADC-EXECUTE-DATE-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/979351/execute-date",
        ("676a07e14f028993838c1be24da17c78b065c48694e1f6d4cfd2331d3f55c486",),
    ),
    "F-ADC-GET-ROUTER-INFO-BGP-NEIGHBORS-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/756515/get-router-info-bgp-neighbors",
        ("e91b15ae59534ad93260bf8deaa6eb08a06af1e2234574667ccc04c4a48650e6",),
    ),
    "F-ADC-GET-ROUTER-INFO-BGP-SUMMARY-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/858752/get-router-info-bgp-summary",
        ("54f10576302474229be9f7c751aeb7491bbd81de2ac88c4022d999f6d1c88408",),
    ),
    "F-ADC-GET-ROUTER-INFO-OSPF-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/765439/get-router-info-ospf",
        ("75803a7c3652c15138b38ca45973c564e4c6053548b315e5b7e1beae216d1b3c",),
    ),
    "F-ADC-GET-SYSTEM-HA-STATUS-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/935095/get-system-ha-status",
        ("b27bed71a3f0bbf8b033930a7aa9ef6c1766d268c398e28bac3969efe878dbe0",),
    ),
    "F-ADC-GET-SYSTEM-TRAFFIC-GROUP-STATUS-76": (
        "https://docs.fortinet.com/document/fortiadc/7.6.7/cli-reference/593476/get-system-traffic-group-status",
        ("518e619f07ddfbd84db2e032c7c37efd8b1bdeecb1317acbec9074e97855b031",),
    ),
}


def _section(text: str, heading: str) -> str:
    start = text.index(f"\n## {heading}\n")
    end = text.find("\n## ", start + 1)
    return text[start:] if end < 0 else text[start:end]


def test_fortiadc_sources_name_one_exact_version_with_its_public_provenance() -> None:
    registry = RENDERER.load_registry()
    assert registry["profiles"]["fortiadc"]["baseline"] == FORTIADC_BASELINE
    used = {
        source_id
        for query_name in READ_QUERIES["fortiadc"]
        for source_id in registry["queries"][f"fortiadc/{query_name}"]["source_ids"]
    }
    assert used == set(FORTIADC_PROVENANCE)
    text = _read(SOURCE_DIR / "fortinet-fortiadc.md")
    assert f"- Reviewed version: {FORTIADC_BASELINE}." in text
    for url in URL_RE.findall(text):
        if "/document/fortiadc/" in url:
            assert url.startswith(FORTIADC_DOCUMENT_ROOT), url
    provenance = _section(text, "Source provenance")
    for phrase in ("Product: FortiADC", "Exact version: 7.6.7", "Compared on: 2026-10-27",
                   "FortiADC 7.6.7 CLI Reference"):
        assert phrase in provenance, phrase
    for internal in ("FortiRAG", "fortinet-docs/", "corpus"):
        assert internal not in text, internal
    for source_id, (url, digests) in FORTIADC_PROVENANCE.items():
        source = registry["sources"][source_id]
        assert source["baseline"] == FORTIADC_BASELINE
        assert source["url"] == url
        assert source["title"].startswith(FORTIADC_BASELINE + " ")
        assert source_id in provenance and url in provenance
        assert any(source_id in row and url in row and "| " + source["title"] + " |" in row
                   for row in provenance.splitlines()), source_id
        for digest in digests:
            assert digest in provenance, digest
    index_row = next(line for line in _read(INDEX).splitlines() if line.startswith("| `fortiadc` |"))
    assert f"| {FORTIADC_BASELINE} |" in index_row


FORTIADC_RETRACTED_SENTENCES = (
    "postfix",
    "server limit",
    "too many errors",
    "does not read or change session pickup",
    "does not read session pickup",
    "default `l4-load-balance`",
    "before, during",
    "role switch of an ha pair",
    "remains unmeasured",
    "recorded but not evaluated",
)


def _check_fortiadc_ha_traffic_text(text: str) -> None:
    lowered = text.lower()
    for sentence in FORTIADC_RETRACTED_SENTENCES:
        assert sentence not in lowered, sentence
    assert re.search(r"(?<!at most )1\.6 s after", text) is None
    assert "at most 1.6 s after the answer of the device recorded at 08:31:15Z" in text
    assert "`y` sent at" not in text
    assert "can resume without interruption" in text
    assert "including the `*-pickup` settings" in text and "does not change it" in text
    assert "no `type` line in the LAB_VS_SMTP configuration" in text
    assert text.count("- Traffic through the pair during the failover and the return") == 1


def test_fortiadc_ha_traffic_text_keeps_only_recorded_statements() -> None:
    _check_fortiadc_ha_traffic_text(_read(SOURCE_DIR / "fortinet-fortiadc.md"))


def main() -> int:
    test_index_keys_and_vendor_links()
    test_source_documents_cover_profiles_sections_urls_and_catalog_link()
    test_registry_resolves_every_vendor_composite_to_its_narrative()
    test_fortinet_and_extreme_tables_match_catalogue_and_registry()
    test_mutations_cannot_remove_query_tokens_or_change_source_ids()
    test_mutations_cannot_introduce_foreign_or_insecure_urls()
    test_only_this_release_repository_links_are_accepted_besides_vendors()
    test_a_login_only_source_may_not_invent_a_public_url()
    test_fortiadc_sources_name_one_exact_version_with_its_public_provenance()
    test_fortiadc_ha_traffic_text_keeps_only_recorded_statements()
    print("vendor_reference_tests=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
