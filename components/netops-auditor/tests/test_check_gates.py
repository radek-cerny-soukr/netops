import base64
import ipaddress
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

COMPONENT = Path(__file__).resolve().parents[1]
SCRIPT = COMPONENT / "scripts" / "check_gates.py"
CATALOG_DIRECTORY = COMPONENT / "src" / "netops_auditor" / "catalog"
CATALOG = CATALOG_DIRECTORY / "fortios.json"
GATE_NAMES = (
    "fixtures_per_rule",
    "fixtures_synthetic",
    "catalog",
    "core_stdlib",
    "version_metadata",
    "release_content",
)
EXACT_RELEASE_FILES = (
    "CHANGELOG.md", "LICENSE", "README.md",
    "requirements-release.in", "requirements-release.lock", "sbom.cdx.json",
)
RELEASE_TREES = ("docs", "scripts")
SYNTHETIC = (
    "config system global",
    '    set hostname "fw-example"',
    "end",
    "config system interface",
    '    edit "wan1"',
    "        set ip 192.0.2.1 255.255.255.0",
    "    next",
    "end",
)

RFC1918_TEST_ADDRESS = str(ipaddress.ip_address(0x0A000001))
PUBLIC_DNS_SAMPLE = str(ipaddress.ip_address(0x08080808))
NTP_DOMAIN_SAMPLE = "ntp." + "cesnet" + ".cz"
PEM_TEST_PAYLOAD = "MII" + base64.b64encode(bytes(range(45))).decode("ascii")
ULA_TEST_ADDRESS = str(ipaddress.ip_address((0xFD12 << 112) | 1))
DOCUMENTATION_IPV6_SAMPLE = str(ipaddress.ip_address((0x20010DB8 << 96) | 1))
MAC_TEST_ADDRESS = ":".join("%02x" % octet for octet in (0x3C, 0x2A, 0xF4, 0x11, 0x22, 0x33))
DOCUMENTATION_MAC_SAMPLE = ":".join(
    "%02x" % octet for octet in (0x00, 0x00, 0x5E, 0x00, 0x53, 0x01)
)
PRIVATE_PATH_SAMPLE = "/" + "home" + "/deploy/netops"
CREDENTIAL_SAMPLE = "gh" + "p_" + "A" * 36


def _text(lines) -> str:
    return "\n".join(lines) + "\n"


def _rule_identifiers() -> list:
    identifiers = []
    for path in sorted(CATALOG_DIRECTORY.glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        identifiers.extend(item["id"] for item in document["rules"])
    return identifiers


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "component"
    shutil.copytree(
        COMPONENT / "src", root / "src", ignore=shutil.ignore_patterns("__pycache__")
    )
    for name in RELEASE_TREES:
        shutil.copytree(
            COMPONENT / name, root / name, ignore=shutil.ignore_patterns("__pycache__")
        )
    shutil.copy2(COMPONENT / "requirements-mcp.txt", root / "requirements-mcp.txt")
    shutil.copy2(COMPONENT / "pyproject.toml", root / "pyproject.toml")
    for name in EXACT_RELEASE_FILES:
        shutil.copy2(COMPONENT / name, root / name)
    for identifier in _rule_identifiers():
        directory = root / "tests" / "fixtures" / "rules" / identifier
        directory.mkdir(parents=True)
        for name in ("positive.conf", "negative.conf"):
            (directory / name).write_text(_text(SYNTHETIC), encoding="utf-8")
    return root


def _fixture(root: Path, identifier: str, name: str) -> Path:
    return root / "tests" / "fixtures" / "rules" / identifier / name


def _catalog(root: Path) -> Path:
    return root / "src" / "netops_auditor" / "catalog" / "fortios.json"


def _patch_first_rule(root: Path, changes: dict) -> str:
    path = _catalog(root)
    document = json.loads(path.read_text(encoding="utf-8"))
    document["rules"][0].update(changes)
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return document["rules"][0]["id"]


def _run(root: Path):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(root)],
        capture_output=True,
        text=True,
        timeout=300,
    )


def _lines(result) -> list:
    return result.stdout.splitlines()


def _details(result, gate: str) -> list:
    prefix = "gate_%s=failed detail=" % gate
    return [line[len(prefix):] for line in _lines(result) if line.startswith(prefix)]


def _passed(result, gate: str) -> bool:
    return ("gate_%s=passed" % gate) in _lines(result)


def _only_gate_failed(result, *gates: str) -> None:
    assert result.returncode != 0, result.stdout + result.stderr
    assert _lines(result)[-1] == "auditor_gates=failed"
    for other in GATE_NAMES:
        if other not in gates:
            assert _passed(result, other), result.stdout
    for gate in gates:
        assert not _passed(result, gate), result.stdout


def test_synthetic_tree_passes(tmp_path):
    result = _run(_tree(tmp_path))
    assert result.returncode == 0, result.stdout + result.stderr
    for gate in GATE_NAMES:
        assert _passed(result, gate), result.stdout
    assert _lines(result)[-1] == "auditor_gates=passed"


def test_root_must_be_a_directory(tmp_path):
    result = _run(tmp_path / "nowhere")
    assert result.returncode == 2, result.stdout + result.stderr
    assert _lines(result)[-1] == "auditor_gates=failed"


def test_missing_positive_fixture_names_the_rule(tmp_path):
    root = _tree(tmp_path)
    identifier = _rule_identifiers()[0]
    _fixture(root, identifier, "positive.conf").unlink()
    result = _run(root)
    _only_gate_failed(result, "fixtures_per_rule")
    details = _details(result, "fixtures_per_rule")
    assert any(
        identifier in detail and "positive.conf" in detail for detail in details
    ), details


def test_missing_negative_fixture_names_the_rule(tmp_path):
    root = _tree(tmp_path)
    identifier = _rule_identifiers()[-1]
    _fixture(root, identifier, "negative.conf").unlink()
    result = _run(root)
    _only_gate_failed(result, "fixtures_per_rule")
    details = _details(result, "fixtures_per_rule")
    assert any(
        identifier in detail and "negative.conf" in detail for detail in details
    ), details


def test_empty_fixture_is_rejected(tmp_path):
    root = _tree(tmp_path)
    identifier = _rule_identifiers()[0]
    _fixture(root, identifier, "positive.conf").write_text("", encoding="utf-8")
    result = _run(root)
    _only_gate_failed(result, "fixtures_per_rule")
    details = _details(result, "fixtures_per_rule")
    assert any(identifier in detail and "empty" in detail for detail in details), details


def test_fixture_directory_without_a_rule_is_rejected(tmp_path):
    root = _tree(tmp_path)
    directory = root / "tests" / "fixtures" / "rules" / "fortios.gone.removed-rule"
    directory.mkdir(parents=True)
    for name in ("positive.conf", "negative.conf"):
        (directory / name).write_text(_text(SYNTHETIC), encoding="utf-8")
    result = _run(root)
    _only_gate_failed(result, "fixtures_per_rule")
    details = _details(result, "fixtures_per_rule")
    assert any("fortios.gone.removed-rule" in detail for detail in details), details


def test_real_address_in_a_fixture_is_rejected(tmp_path):
    root = _tree(tmp_path)
    identifier = _rule_identifiers()[0]
    path = _fixture(root, identifier, "negative.conf")
    path.write_text(
        _text(("config system dns", "    set primary %s" % PUBLIC_DNS_SAMPLE, "end")),
        encoding="utf-8",
    )
    result = _run(root)
    _only_gate_failed(result, "fixtures_synthetic", "release_content")
    details = _details(result, "fixtures_synthetic")
    expected = "tests/fixtures/rules/%s/negative.conf:2" % identifier
    assert any(expected in detail and PUBLIC_DNS_SAMPLE in detail for detail in details), details


def test_real_address_outside_the_rule_fixtures_is_rejected(tmp_path):
    root = _tree(tmp_path)
    path = root / "tests" / "fixtures" / "loose.conf"
    path.write_text(_text(("set gateway %s" % RFC1918_TEST_ADDRESS,)), encoding="utf-8")
    result = _run(root)
    _only_gate_failed(result, "fixtures_synthetic", "release_content")
    details = _details(result, "fixtures_synthetic")
    assert any(
        "tests/fixtures/loose.conf:1" in detail and RFC1918_TEST_ADDRESS in detail
        for detail in details
    ), details


def test_documentation_addresses_and_masks_pass(tmp_path):
    root = _tree(tmp_path)
    identifier = _rule_identifiers()[0]
    _fixture(root, identifier, "negative.conf").write_text(
        _text(
            (
                "set ip 192.0.2.1 255.255.255.0",
                "set ip 198.51.100.254 255.255.0.0",
                "set ip 203.0.113.7 255.255.255.255",
                "set gateway 0.0.0.0 0.0.0.0",
                "set wildcard 0.0.0.255",
            )
        ),
        encoding="utf-8",
    )
    result = _run(root)
    assert result.returncode == 0, result.stdout + result.stderr
    assert _passed(result, "fixtures_synthetic"), result.stdout


def test_real_domain_in_a_fixture_is_rejected(tmp_path):
    root = _tree(tmp_path)
    identifier = _rule_identifiers()[0]
    _fixture(root, identifier, "positive.conf").write_text(
        _text(("config system ntp", '    set server "%s"' % NTP_DOMAIN_SAMPLE, "end")),
        encoding="utf-8",
    )
    result = _run(root)
    _only_gate_failed(result, "fixtures_synthetic", "release_content")
    details = _details(result, "fixtures_synthetic")
    expected = "tests/fixtures/rules/%s/positive.conf:2" % identifier
    assert any(
        expected in detail and NTP_DOMAIN_SAMPLE in detail for detail in details
    ), details


def test_allowed_documentation_domains_pass(tmp_path):
    root = _tree(tmp_path)
    identifier = _rule_identifiers()[0]
    _fixture(root, identifier, "positive.conf").write_text(
        _text(
            (
                'set server "ntp.example.invalid"',
                'set fqdn "www.example.com"',
                'set fqdn "mail.example.net"',
                'set fqdn "example.org"',
            )
        ),
        encoding="utf-8",
    )
    result = _run(root)
    assert result.returncode == 0, result.stdout + result.stderr
    assert _passed(result, "fixtures_synthetic"), result.stdout


def test_rule_identifiers_are_not_read_as_domains(tmp_path):
    root = _tree(tmp_path)
    identifier = _rule_identifiers()[0]
    _fixture(root, identifier, "positive.conf").write_text(
        _text(tuple("# %s" % name for name in _rule_identifiers())), encoding="utf-8"
    )
    result = _run(root)
    assert result.returncode == 0, result.stdout + result.stderr
    assert _passed(result, "fixtures_synthetic"), result.stdout


def test_private_key_material_is_rejected(tmp_path):
    root = _tree(tmp_path)
    identifier = _rule_identifiers()[0]
    _fixture(root, identifier, "positive.conf").write_text(
        _text(
            (
                "config vpn certificate local",
                "-----BEGIN PRIVATE KEY-----",
                PEM_TEST_PAYLOAD,
                "-----END PRIVATE KEY-----",
                "end",
            )
        ),
        encoding="utf-8",
    )
    result = _run(root)
    _only_gate_failed(result, "fixtures_synthetic", "release_content")
    details = _details(result, "fixtures_synthetic")
    expected = "tests/fixtures/rules/%s/positive.conf:2" % identifier
    assert any(
        expected in detail and "private key" in detail for detail in details
    ), details


def test_placeholder_key_block_passes(tmp_path):
    root = _tree(tmp_path)
    identifier = _rule_identifiers()[0]
    _fixture(root, identifier, "positive.conf").write_text(
        _text(
            (
                "config vpn certificate local",
                '    set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----',
                "KANARCI-TAJEMSTVI-13",
                '-----END ENCRYPTED PRIVATE KEY-----"',
                "end",
            )
        ),
        encoding="utf-8",
    )
    result = _run(root)
    assert result.returncode == 0, result.stdout + result.stderr
    assert _passed(result, "fixtures_synthetic"), result.stdout


def test_empty_title_is_rejected(tmp_path):
    root = _tree(tmp_path)
    identifier = _patch_first_rule(root, {"title": "   "})
    result = _run(root)
    _only_gate_failed(result, "catalog")
    details = _details(result, "catalog")
    assert any(identifier in detail and "title" in detail for detail in details), details


def test_empty_remediation_is_rejected(tmp_path):
    root = _tree(tmp_path)
    identifier = _patch_first_rule(root, {"remediation": ""})
    result = _run(root)
    _only_gate_failed(result, "catalog")
    details = _details(result, "catalog")
    assert any(
        identifier in detail and "remediation" in detail for detail in details
    ), details


def test_empty_evidence_fields_are_rejected(tmp_path):
    root = _tree(tmp_path)
    identifier = _patch_first_rule(root, {"evidence_fields": []})
    result = _run(root)
    _only_gate_failed(result, "catalog")
    details = _details(result, "catalog")
    assert any(
        identifier in detail and "evidence_fields" in detail for detail in details
    ), details


def test_unknown_severity_is_rejected(tmp_path):
    root = _tree(tmp_path)
    identifier = _patch_first_rule(root, {"severity": "critical"})
    result = _run(root)
    _only_gate_failed(result, "catalog")
    details = _details(result, "catalog")
    assert any(
        identifier in detail and "severity" in detail for detail in details
    ), details


def test_unknown_class_is_rejected(tmp_path):
    root = _tree(tmp_path)
    identifier = _patch_first_rule(root, {"class": "dohad"})
    result = _run(root)
    _only_gate_failed(result, "catalog")
    details = _details(result, "catalog")
    assert any(identifier in detail and "class" in detail for detail in details), details


def test_judgement_rule_must_not_be_high(tmp_path):
    root = _tree(tmp_path)
    identifier = _patch_first_rule(root, {"class": "usudek", "severity": "high"})
    result = _run(root)
    _only_gate_failed(result, "catalog")
    details = _details(result, "catalog")
    assert any(
        identifier in detail and "usudek" in detail for detail in details
    ), details


def test_unimplemented_check_is_rejected(tmp_path):
    root = _tree(tmp_path)
    _patch_first_rule(root, {"check": "check_that_does_not_exist"})
    result = _run(root)
    _only_gate_failed(result, "catalog")
    details = _details(result, "catalog")
    assert any(
        "check_that_does_not_exist" in detail and "not implemented" in detail
        for detail in details
    ), details


def test_third_party_import_in_the_core_is_rejected(tmp_path):
    root = _tree(tmp_path)
    path = root / "src" / "netops_auditor" / "query.py"
    path.write_text(path.read_text(encoding="utf-8") + "import requests\n", encoding="utf-8")
    result = _run(root)
    _only_gate_failed(result, "core_stdlib")
    details = _details(result, "core_stdlib")
    assert any(
        "query.py" in detail and "requests" in detail for detail in details
    ), details


def test_the_shared_access_layer_is_not_a_third_party_import(tmp_path):
    root = _tree(tmp_path)
    path = root / "src" / "netops_auditor" / "query.py"
    path.write_text(
        path.read_text(encoding="utf-8") + "from netops_core import inventory\n", encoding="utf-8"
    )
    result = _run(root)
    assert result.returncode == 0, result.stdout + result.stderr
    assert _passed(result, "core_stdlib"), result.stdout


def test_mcp_dependency_outside_the_mcp_shell_is_rejected(tmp_path):
    root = _tree(tmp_path)
    path = root / "src" / "netops_auditor" / "cli.py"
    path.write_text(
        path.read_text(encoding="utf-8") + "from fastmcp import FastMCP\n", encoding="utf-8"
    )
    result = _run(root)
    _only_gate_failed(result, "core_stdlib")
    details = _details(result, "core_stdlib")
    assert any("cli.py" in detail and "fastmcp" in detail for detail in details), details


def test_a_stale_sbom_is_rejected(tmp_path):
    root = _tree(tmp_path)
    document = json.loads((root / "sbom.cdx.json").read_text(encoding="utf-8"))
    document["metadata"]["component"]["version"] = "0.0.0"
    (root / "sbom.cdx.json").write_text(json.dumps(document), encoding="utf-8")
    result = _run(root)
    _only_gate_failed(result, "version_metadata")
    details = _details(result, "version_metadata")
    assert any("generate_sbom.py" in detail for detail in details), details


def test_a_missing_sbom_is_rejected(tmp_path):
    root = _tree(tmp_path)
    (root / "sbom.cdx.json").unlink()
    result = _run(root)
    details = _details(result, "version_metadata")
    assert any("sbom.cdx.json is missing" in detail for detail in details), details


def test_missing_version_is_rejected(tmp_path):
    root = _tree(tmp_path)
    (root / "src" / "netops_auditor" / "__init__.py").write_text("", encoding="utf-8")
    result = _run(root)
    _only_gate_failed(result, "version_metadata")
    details = _details(result, "version_metadata")
    assert any("__version__" in detail for detail in details), details


def test_unusable_version_is_rejected(tmp_path):
    root = _tree(tmp_path)
    (root / "src" / "netops_auditor" / "__init__.py").write_text(
        '__version__ = "unknown"\n', encoding="utf-8"
    )
    result = _run(root)
    _only_gate_failed(result, "version_metadata")
    details = _details(result, "version_metadata")
    assert any("__version__" in detail and "unknown" in detail for detail in details), details


def test_unpinned_requirement_is_rejected(tmp_path):
    root = _tree(tmp_path)
    (root / "requirements-mcp.txt").write_text("fastmcp>=4.0.3\n", encoding="utf-8")
    result = _run(root)
    _only_gate_failed(result, "version_metadata")
    details = _details(result, "version_metadata")
    assert any(
        "requirements-mcp.txt:1" in detail and "fastmcp>=4.0.3" in detail
        for detail in details
    ), details


def test_missing_project_metadata_is_rejected(tmp_path):
    root = _tree(tmp_path)
    (root / "pyproject.toml").unlink()
    result = _run(root)
    _only_gate_failed(result, "version_metadata", "release_content")
    details = _details(result, "version_metadata")
    assert any("pyproject.toml" in detail and "missing" in detail for detail in details), details


def test_foreign_component_name_is_rejected(tmp_path):
    root = _tree(tmp_path)
    path = root / "pyproject.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            'name = "netops-auditor"', 'name = "netops-helper"'
        ),
        encoding="utf-8",
    )
    result = _run(root)
    _only_gate_failed(result, "version_metadata", "release_content")
    details = _details(result, "version_metadata")
    assert any("foreign component name" in detail for detail in details), details


def test_version_that_disagrees_with_the_package_is_rejected(tmp_path):
    root = _tree(tmp_path)
    path = root / "pyproject.toml"
    body = path.read_text(encoding="utf-8")
    declared = re.search(r'^version = "([^"]+)"', body, re.MULTILINE)
    assert declared is not None, body
    current = declared.group(1)
    other = "9.9.9"
    path.write_text(
        body.replace('version = "%s"' % current, 'version = "%s"' % other, 1),
        encoding="utf-8",
    )
    result = _run(root)
    _only_gate_failed(result, "version_metadata")
    details = _details(result, "version_metadata")
    assert any(
        current in detail and other in detail for detail in details
    ), details


def test_missing_requirements_file_is_rejected(tmp_path):
    root = _tree(tmp_path)
    (root / "requirements-mcp.txt").unlink()
    result = _run(root)
    _only_gate_failed(result, "version_metadata", "release_content")
    details = _details(result, "version_metadata")
    assert any(
        "requirements-mcp.txt" in detail and "missing" in detail for detail in details
    ), details


def _release_tree(tmp_path: Path) -> Path:
    root = _tree(tmp_path)
    (root / "docs" / "leak.md").write_text(_text(("# leak",)), encoding="utf-8")
    return root


def _leak(root: Path, line: str) -> None:
    path = root / "docs" / "leak.md"
    path.write_text(path.read_text(encoding="utf-8") + line + "\n", encoding="utf-8")


def _release_detail(result) -> list:
    return _details(result, "release_content")


def test_release_content_rejects_a_private_address_outside_the_fixtures(tmp_path):
    root = _release_tree(tmp_path)
    _leak(root, "Management address %s." % RFC1918_TEST_ADDRESS)
    result = _run(root)
    _only_gate_failed(result, "release_content")
    details = _release_detail(result)
    assert any(
        "docs/leak.md:2" in detail and RFC1918_TEST_ADDRESS in detail for detail in details
    ), details


def test_release_content_rejects_a_unique_local_ipv6_address(tmp_path):
    root = _release_tree(tmp_path)
    _leak(root, "Peer %s." % ULA_TEST_ADDRESS)
    result = _run(root)
    _only_gate_failed(result, "release_content")
    details = _release_detail(result)
    assert any(
        "docs/leak.md:2" in detail and ULA_TEST_ADDRESS in detail for detail in details
    ), details


def test_release_content_rejects_a_mac_address(tmp_path):
    root = _release_tree(tmp_path)
    _leak(root, "Seen from %s." % MAC_TEST_ADDRESS)
    result = _run(root)
    _only_gate_failed(result, "release_content")
    details = _release_detail(result)
    assert any(
        "docs/leak.md:2" in detail and MAC_TEST_ADDRESS in detail for detail in details
    ), details


def test_release_content_rejects_a_domain_outside_the_allowlist(tmp_path):
    root = _release_tree(tmp_path)
    _leak(root, "Mirror %s." % NTP_DOMAIN_SAMPLE)
    result = _run(root)
    _only_gate_failed(result, "release_content")
    details = _release_detail(result)
    assert any(
        "docs/leak.md:2" in detail and NTP_DOMAIN_SAMPLE in detail for detail in details
    ), details


def test_release_content_rejects_a_private_path_marker(tmp_path):
    root = _release_tree(tmp_path)
    _leak(root, "Run it from %s." % PRIVATE_PATH_SAMPLE)
    result = _run(root)
    _only_gate_failed(result, "release_content")
    details = _release_detail(result)
    assert any(
        "docs/leak.md:2" in detail and "private marker" in detail for detail in details
    ), details


def test_release_content_rejects_credential_material(tmp_path):
    root = _release_tree(tmp_path)
    _leak(root, "Token %s." % CREDENTIAL_SAMPLE)
    result = _run(root)
    _only_gate_failed(result, "release_content")
    details = _release_detail(result)
    assert any(
        "docs/leak.md:2" in detail and "credential-shaped" in detail for detail in details
    ), details


def test_release_content_rejects_a_leak_in_a_released_module(tmp_path):
    root = _release_tree(tmp_path)
    path = root / "src" / "netops_auditor" / "query.py"
    path.write_text(
        path.read_text(encoding="utf-8") + "\nDEFAULT = \"%s\"\n" % RFC1918_TEST_ADDRESS,
        encoding="utf-8",
    )
    result = _run(root)
    _only_gate_failed(result, "release_content")
    details = _release_detail(result)
    assert any(
        "src/netops_auditor/query.py" in detail and RFC1918_TEST_ADDRESS in detail
        for detail in details
    ), details


def test_release_content_accepts_documentation_values(tmp_path):
    root = _release_tree(tmp_path)
    _leak(root, "Peer 192.0.2.1, %s, %s, host ntp.example.invalid." % (
        DOCUMENTATION_IPV6_SAMPLE, DOCUMENTATION_MAC_SAMPLE,
    ))
    result = _run(root)
    assert result.returncode == 0, result.stdout + result.stderr
    assert _passed(result, "release_content"), result.stdout


def test_release_content_fails_closed_without_the_selector(tmp_path):
    root = _release_tree(tmp_path)
    (root / "scripts" / "create_release_artifacts.py").unlink()
    result = _run(root)
    _only_gate_failed(result, "release_content")
    details = _release_detail(result)
    assert any("release selector is missing" in detail for detail in details), details


def test_release_content_survives_a_selector_that_rewrites_the_gate(tmp_path):
    root = _release_tree(tmp_path)
    _leak(root, "Management address %s." % RFC1918_TEST_ADDRESS)
    path = root / "scripts" / "create_release_artifacts.py"
    anchor = "from __future__ import annotations\n"
    payload = (
        anchor
        + "\nimport re as _re\nimport sys as _sys\n"
        + "_gate = _sys.modules.get(\"__main__\")\n"
        + "if _gate is not None:\n"
        + "    _gate.PRIVATE_MARKERS = ()\n"
        + "    _gate.CREDENTIAL_MARKERS = ()\n"
        + "    _gate.IPV4_PATTERN = _re.compile(r\"(?!x)x\")\n"
    )
    source = path.read_text(encoding="utf-8")
    assert anchor in source
    path.write_text(source.replace(anchor, payload, 1), encoding="utf-8")
    result = _run(root)
    _only_gate_failed(result, "release_content")
    details = _release_detail(result)
    assert any(
        "docs/leak.md:2" in detail and RFC1918_TEST_ADDRESS in detail for detail in details
    ), details


def _export(tmp_path: Path) -> Path:
    destination = tmp_path / "dist"
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            str(COMPONENT / "scripts" / "create_release_artifacts.py"),
            "--output",
            str(destination),
        ],
        capture_output=True,
        text=True,
        timeout=900,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    exported = sorted(destination.iterdir())
    assert len(exported) == 1, exported
    return exported[0]


def _gate_in(export: Path):
    return subprocess.run(
        [sys.executable, "-B", str(export / "scripts" / "check_gates.py")],
        cwd=str(export),
        capture_output=True,
        text=True,
        timeout=900,
    )


def test_the_export_carries_no_repository_and_passes_the_gate(tmp_path):
    if not (COMPONENT / "tests" / "fixtures" / "rules").is_dir():
        pytest.skip("tests/fixtures/rules does not exist yet")
    export = _export(tmp_path)
    assert not (export / ".git").exists()
    result = _gate_in(export)
    assert result.returncode == 0, result.stdout + result.stderr
    for gate in GATE_NAMES:
        assert _passed(result, gate), result.stdout


def test_a_leak_added_to_the_export_fails_the_gate_inside_the_export(tmp_path):
    if not (COMPONENT / "tests" / "fixtures" / "rules").is_dir():
        pytest.skip("tests/fixtures/rules does not exist yet")
    export = _export(tmp_path)
    (export / "docs" / "leak.md").write_text(
        _text(("# leak", "Peer %s." % ULA_TEST_ADDRESS)), encoding="utf-8"
    )
    result = _gate_in(export)
    assert result.returncode != 0, result.stdout + result.stderr
    details = _release_detail(result)
    assert any(
        "docs/leak.md:2" in detail and ULA_TEST_ADDRESS in detail for detail in details
    ), details


def test_the_export_rejects_a_file_outside_the_release_selection(tmp_path):
    if not (COMPONENT / "tests" / "fixtures" / "rules").is_dir():
        pytest.skip("tests/fixtures/rules does not exist yet")
    export = _export(tmp_path)
    (export / "NOTES.md").write_text(_text(("# notes",)), encoding="utf-8")
    result = _gate_in(export)
    assert result.returncode != 0, result.stdout + result.stderr
    details = _release_detail(result)
    assert any(
        "NOTES.md" in detail and "outside the release selection" in detail
        for detail in details
    ), details


def test_the_export_rejects_a_released_file_that_is_gone(tmp_path):
    if not (COMPONENT / "tests" / "fixtures" / "rules").is_dir():
        pytest.skip("tests/fixtures/rules does not exist yet")
    export = _export(tmp_path)
    removed = sorted((export / "docs").glob("*.md"))[0]
    relative = removed.relative_to(export).as_posix()
    removed.unlink()
    result = _gate_in(export)
    assert result.returncode != 0, result.stdout + result.stderr
    details = _release_detail(result)
    assert any(
        relative in detail and "lacks" in detail for detail in details
    ), details


def test_the_export_rejects_a_symlink_in_the_released_tree(tmp_path):
    if not (COMPONENT / "tests" / "fixtures" / "rules").is_dir():
        pytest.skip("tests/fixtures/rules does not exist yet")
    export = _export(tmp_path)
    (export / "docs" / "link.md").symlink_to(export / "README.md")
    result = _gate_in(export)
    assert result.returncode != 0, result.stdout + result.stderr


def test_a_tree_beside_a_repository_is_not_checked_for_completeness(tmp_path):
    root = _release_tree(tmp_path)
    (root / "NOTES.md").write_text(_text(("# notes",)), encoding="utf-8")
    result = _run(root)
    _only_gate_failed(result, "release_content")
    details = _release_detail(result)
    assert any(
        "NOTES.md" in detail and "outside the release selection" in detail
        for detail in details
    ), details
    (root / ".git").mkdir()
    result = _run(root)
    assert result.returncode == 0, result.stdout + result.stderr
    assert _passed(result, "release_content"), result.stdout


def test_the_gate_leaves_no_bytecode_behind(tmp_path):
    root = _release_tree(tmp_path)
    result = _run(root)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not sorted(root.rglob("*.pyc")), sorted(root.rglob("*.pyc"))


def test_component_passes_every_gate():
    rules = COMPONENT / "tests" / "fixtures" / "rules"
    if not rules.is_dir():
        pytest.skip("tests/fixtures/rules does not exist yet")
    result = _run(COMPONENT)
    assert result.returncode == 0, result.stdout + result.stderr
    for gate in GATE_NAMES:
        assert _passed(result, gate), result.stdout
    assert _lines(result)[-1] == "auditor_gates=passed"


def test_the_export_hands_on_the_executable_bit_of_every_program(tmp_path):
    export = _export(tmp_path)
    for path in sorted(export.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(export)
        source = COMPONENT / relative
        if not source.is_file():
            continue
        assert bool(source.stat().st_mode & 0o100) == bool(
            path.stat().st_mode & 0o100
        ), relative.as_posix()
