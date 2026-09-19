import base64
import ipaddress
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

COMPONENT = Path(__file__).resolve().parents[1]
SCRIPT = COMPONENT / "scripts" / "check_gates.py"
PACKAGE = "netops_core"
GATE_NAMES = (
    "core_stdlib",
    "version_metadata",
    "release_content",
)
EXACT_RELEASE_FILES = (
    "CHANGELOG.md", "LICENSE", "README.md", "pyproject.toml",
    "requirements-release.in", "requirements-release.lock", "sbom.cdx.json",
)
RELEASE_TREES = ("docs", "scripts", "src", "tests")

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
THIRD_PARTY_IMPORT = "import " + "requests" + "\n"


def _text(lines) -> str:
    return "\n".join(lines) + "\n"


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "component"
    root.mkdir()
    for name in RELEASE_TREES:
        shutil.copytree(
            COMPONENT / name, root / name, ignore=shutil.ignore_patterns("__pycache__")
        )
    for name in EXACT_RELEASE_FILES:
        shutil.copy2(COMPONENT / name, root / name)
    return root


def _module(root: Path) -> Path:
    return root / "src" / PACKAGE / "__init__.py"


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
    assert _lines(result)[-1] == "core_gates=failed"
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
    assert _lines(result)[-1] == "core_gates=passed"


def test_root_must_be_a_directory(tmp_path):
    result = _run(tmp_path / "nowhere")
    assert result.returncode == 2, result.stdout + result.stderr
    assert _lines(result)[-1] == "core_gates=failed"


def test_third_party_import_in_the_package_is_rejected(tmp_path):
    root = _tree(tmp_path)
    path = _module(root)
    path.write_text(path.read_text(encoding="utf-8") + THIRD_PARTY_IMPORT, encoding="utf-8")
    result = _run(root)
    _only_gate_failed(result, "core_stdlib")
    details = _details(result, "core_stdlib")
    assert any(
        "__init__.py" in detail and "requests" in detail for detail in details
    ), details


def test_third_party_import_below_the_package_is_rejected(tmp_path):
    root = _tree(tmp_path)
    directory = root / "src" / PACKAGE / "channels"
    directory.mkdir()
    (directory / "__init__.py").write_text(THIRD_PARTY_IMPORT, encoding="utf-8")
    result = _run(root)
    _only_gate_failed(result, "core_stdlib")
    details = _details(result, "core_stdlib")
    assert any(
        "channels/__init__.py" in detail and "requests" in detail for detail in details
    ), details


def test_a_missing_package_directory_is_rejected(tmp_path):
    root = _tree(tmp_path)
    shutil.rmtree(root / "src" / PACKAGE)
    result = _run(root)
    assert result.returncode != 0, result.stdout + result.stderr
    details = _details(result, "core_stdlib")
    assert any("src/%s" % PACKAGE in detail for detail in details), details


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
    _only_gate_failed(result, "version_metadata", "release_content")
    details = _details(result, "version_metadata")
    assert any("sbom.cdx.json is missing" in detail for detail in details), details


def test_missing_version_is_rejected(tmp_path):
    root = _tree(tmp_path)
    _module(root).write_text("", encoding="utf-8")
    result = _run(root)
    _only_gate_failed(result, "version_metadata")
    details = _details(result, "version_metadata")
    assert any("__version__" in detail for detail in details), details


def test_unusable_version_is_rejected(tmp_path):
    root = _tree(tmp_path)
    _module(root).write_text('__version__ = "unknown"\n', encoding="utf-8")
    result = _run(root)
    _only_gate_failed(result, "version_metadata")
    details = _details(result, "version_metadata")
    assert any("__version__" in detail and "unknown" in detail for detail in details), details


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
    assert any(current in detail and other in detail for detail in details), details


def test_foreign_component_name_is_rejected(tmp_path):
    root = _tree(tmp_path)
    path = root / "pyproject.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            'name = "netops-core"', 'name = "netops-helper"'
        ),
        encoding="utf-8",
    )
    result = _run(root)
    _only_gate_failed(result, "version_metadata", "release_content")
    details = _details(result, "version_metadata")
    assert any("foreign component name" in detail for detail in details), details


def test_missing_project_metadata_is_rejected(tmp_path):
    root = _tree(tmp_path)
    (root / "pyproject.toml").unlink()
    result = _run(root)
    _only_gate_failed(result, "version_metadata", "release_content")
    details = _details(result, "version_metadata")
    assert any("pyproject.toml" in detail and "missing" in detail for detail in details), details


def _release_tree(tmp_path: Path) -> Path:
    root = _tree(tmp_path)
    (root / "docs" / "leak.md").write_text(_text(("# leak",)), encoding="utf-8")
    return root


def _leak(root: Path, line: str) -> None:
    path = root / "docs" / "leak.md"
    path.write_text(path.read_text(encoding="utf-8") + line + "\n", encoding="utf-8")


def _release_detail(result) -> list:
    return _details(result, "release_content")


def test_release_content_rejects_a_private_address(tmp_path):
    root = _release_tree(tmp_path)
    _leak(root, "Management address %s." % RFC1918_TEST_ADDRESS)
    result = _run(root)
    _only_gate_failed(result, "release_content")
    details = _release_detail(result)
    assert any(
        "docs/leak.md:2" in detail and RFC1918_TEST_ADDRESS in detail for detail in details
    ), details


def test_release_content_rejects_a_public_address(tmp_path):
    root = _release_tree(tmp_path)
    _leak(root, "Resolver %s." % PUBLIC_DNS_SAMPLE)
    result = _run(root)
    _only_gate_failed(result, "release_content")
    details = _release_detail(result)
    assert any(
        "docs/leak.md:2" in detail and PUBLIC_DNS_SAMPLE in detail for detail in details
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


def test_release_content_rejects_private_key_material(tmp_path):
    root = _release_tree(tmp_path)
    _leak(root, "-----BEGIN PRIVATE KEY-----")
    _leak(root, PEM_TEST_PAYLOAD)
    _leak(root, "-----END PRIVATE KEY-----")
    result = _run(root)
    _only_gate_failed(result, "release_content")
    details = _release_detail(result)
    assert any(
        "docs/leak.md:2" in detail and "private key" in detail for detail in details
    ), details


def test_release_content_rejects_a_leak_in_a_released_module(tmp_path):
    root = _release_tree(tmp_path)
    path = _module(root)
    path.write_text(
        path.read_text(encoding="utf-8") + '\nDEFAULT = "%s"\n' % RFC1918_TEST_ADDRESS,
        encoding="utf-8",
    )
    result = _run(root)
    _only_gate_failed(result, "release_content")
    details = _release_detail(result)
    assert any(
        "src/%s/__init__.py" % PACKAGE in detail and RFC1918_TEST_ADDRESS in detail
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
    export = _export(tmp_path)
    assert not (export / ".git").exists()
    result = _gate_in(export)
    assert result.returncode == 0, result.stdout + result.stderr
    for gate in GATE_NAMES:
        assert _passed(result, gate), result.stdout


def test_a_leak_added_to_the_export_fails_the_gate_inside_the_export(tmp_path):
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
    export = _export(tmp_path)
    removed = sorted((export / "docs").glob("*.md"))[0]
    relative = removed.relative_to(export).as_posix()
    removed.unlink()
    result = _gate_in(export)
    assert result.returncode != 0, result.stdout + result.stderr
    details = _release_detail(result)
    assert any(relative in detail and "lacks" in detail for detail in details), details


def test_the_export_rejects_a_symlink_in_the_released_tree(tmp_path):
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
    result = _run(COMPONENT)
    assert result.returncode == 0, result.stdout + result.stderr
    for gate in GATE_NAMES:
        assert _passed(result, gate), result.stdout
    assert _lines(result)[-1] == "core_gates=passed"
