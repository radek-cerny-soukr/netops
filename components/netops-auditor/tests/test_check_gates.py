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
SCRIPT = COMPONENT / "tests" / "support" / "check_gates.py"
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
    "CHANGELOG.md", "LICENSE", "README.md", "action.yml",
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

def test_root_must_be_a_directory(tmp_path):
    result = _run(tmp_path / "nowhere")
    assert result.returncode == 2, result.stdout + result.stderr
    assert _lines(result)[-1] == "auditor_gates=failed"

def _release_tree(tmp_path: Path) -> Path:
    root = _tree(tmp_path)
    (root / "docs" / "leak.md").write_text(_text(("# leak",)), encoding="utf-8")
    return root

def _leak(root: Path, line: str) -> None:
    path = root / "docs" / "leak.md"
    path.write_text(path.read_text(encoding="utf-8") + line + "\n", encoding="utf-8")

def _release_detail(result) -> list:
    return _details(result, "release_content")

def _export(tmp_path: Path) -> Path:
    destination = tmp_path / "dist"
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            str(COMPONENT / "tests" / "support" / "create_release_artifacts.py"),
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
        [sys.executable, "-B", str(export / "tests" / "support" / "check_gates.py")],
        cwd=str(export),
        capture_output=True,
        text=True,
        timeout=900,
    )
