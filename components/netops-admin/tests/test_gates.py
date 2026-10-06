from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("admin_check_gates", ROOT / "scripts" / "check_gates.py")
gates = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gates)


@pytest.fixture
def tree(tmp_path) -> Path:
    copy = tmp_path / "netops-admin"
    shutil.copytree(ROOT / "src", copy / "src")
    shutil.copy2(ROOT / "pyproject.toml", copy / "pyproject.toml")
    return copy


def test_shipped_tree_passes():
    assert gates.import_errors() == []
    assert gates.metadata_errors() == []
    assert gates.profile_errors() == []


@pytest.mark.parametrize(("line", "fragment"), [
    ("import socket\n", "imports socket"),
    ("import subprocess\n", "imports subprocess"),
    ("import importlib\n", "imports importlib"),
    ("from netops_core import transport\n", "imports transport from netops_core"),
    ("from netops_auditor import collect\n", "imports collect from netops_auditor"),
    ("from importlib import import_module\n", "imports import_module from importlib"),
    ("value = eval('1')\n", "uses eval"),
    ("value = __import__('os')\n", "uses __import__"),
    ("import re\nre.system = None\n", "calls system"),
])
def test_forbidden_capability_is_reported(tree, line, fragment):
    module = tree / "src" / "netops_admin" / "cli.py"
    module.write_text(module.read_text(encoding="utf-8") + line, encoding="utf-8")
    assert any(fragment in error for error in gates.import_errors(tree)), gates.import_errors(tree)


def test_version_drift_is_reported(tree):
    init = tree / "src" / "netops_admin" / "__init__.py"
    init.write_text('__version__ = "9.9.9"\n', encoding="utf-8")
    assert gates.metadata_errors(tree) == ["package __version__ differs from pyproject version"]


def test_dependency_drift_is_reported(tree):
    pyproject = tree / "pyproject.toml"
    pyproject.write_text(pyproject.read_text(encoding="utf-8").replace("netops-auditor==0.2.10", "netops-auditor"),
                         encoding="utf-8")
    assert gates.metadata_errors(tree) == ["dependencies must be exactly %r" % gates.DEPENDENCIES]


def test_every_gate_passes_on_the_shipped_component():
    assert gates.check(ROOT) == {name: [] for name in gates.GATE_ORDER}


@pytest.fixture
def component(tmp_path) -> Path:
    copy = tmp_path / "netops-admin"
    shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    return copy


def test_private_material_in_a_released_file_is_reported(component):
    address = ".".join(("10", "1", "2", "3"))
    document = component / "docs" / "execution.md"
    document.write_text(document.read_text(encoding="utf-8") + "\nRun it on host %s as mail.example-corp.cz.\n" % address,
                        encoding="utf-8")
    errors = gates.gate_release_content(component)
    assert any(address in error for error in errors)
    assert any("example-corp.cz" in error for error in errors)


def test_sbom_version_drift_is_reported(component):
    sbom = component / "sbom.cdx.json"
    sbom.write_text(sbom.read_text(encoding="utf-8").replace('"type": "application",\n      "version": "0.2.6"',
                                                           '"type": "application",\n      "version": "0.0.9"', 1),
                    encoding="utf-8")
    assert any("sbom.cdx.json" in error for error in gates.gate_version_metadata(component))


@pytest.mark.parametrize("change", ["first", "duplicate"])
def test_changelog_heading_drift_is_reported(component, change):
    changelog = component / "CHANGELOG.md"
    lines = changelog.read_text(encoding="utf-8").splitlines(keepends=True)
    first = next(index for index, line in enumerate(lines) if line.startswith("## "))
    if change == "first":
        lines[first] = "## 0.0.9 - unreleased\n"
    else:
        lines.append("\n" + lines[first])
    changelog.write_text("".join(lines), encoding="utf-8")
    assert any("CHANGELOG.md" in error for error in gates.gate_version_metadata(component))


def test_unpinned_mcp_requirement_is_reported(component):
    (component / "requirements-mcp.txt").write_text("fastmcp>=4\n", encoding="utf-8")
    assert any("does not pin" in error for error in gates.gate_version_metadata(component))


def test_installation_and_first_operation_use_the_package_pins():
    assert gates.gate_installation_versions(ROOT) == []


@pytest.mark.parametrize("document", ["installation.md", "operations-020.md"])
@pytest.mark.parametrize("label", ["Core", "Auditor", "Admin"])
def test_an_old_pin_in_either_installation_step_is_refused(component, document, label):
    import re
    path = component / "docs" / document
    word = "netops-" + label.lower() if document == "installation.md" else label
    changed, count = re.subn(r"(\b" + re.escape(word) + r"`?\s+)[0-9]+\.[0-9]+\.[0-9]+",
                            r"\g<1>0.0.1", path.read_text(encoding="utf-8"), count=1)
    assert count == 1
    path.write_text(changed, encoding="utf-8")
    assert any(document in error and label in error for error in gates.gate_installation_versions(component))


def test_installation_stops_on_every_unpack_or_checksum_failure():
    import hashlib
    import io
    import re
    import subprocess
    import tarfile
    import tempfile
    import textwrap
    text = (ROOT / "docs" / "installation.md").read_text(encoding="utf-8")
    blocks = re.findall(r"(?ms)^[ \t]*```sh[ \t]*\n(.*?)^[ \t]*```[ \t]*$", text)
    block = textwrap.dedent(next(value for value in blocks if "tar -xzf" in value and "sha256sum -c SHA256SUMS" in value))
    archives = re.findall(r"tar -xzf (netops-[a-z]+-[0-9.]+-source\.tar\.gz)", block)
    assert archives
    cases = [(None, None)] + [(kind, index) for kind in ("missing", "checksum") for index in range(len(archives))]
    for kind, broken in cases:
        with tempfile.TemporaryDirectory(prefix="netops-installation-") as temporary:
            directory = Path(temporary)
            for index, name in enumerate(archives):
                if kind == "missing" and index == broken:
                    continue
                root = name.removesuffix("-source.tar.gz")
                member = root + ".txt"
                payload = b"verified source data\n"
                digest = hashlib.sha256(payload).hexdigest()
                checksums = (digest + "  " + member + "\n").encode()
                actual = b"changed source data\n" if kind == "checksum" and index == broken else payload
                with tarfile.open(directory / name, "w:gz") as archive:
                    for filename, content in ((member, actual), ("SHA256SUMS", checksums)):
                        info = tarfile.TarInfo(root + "/" + filename)
                        info.size = len(content)
                        info.mode = 0o644
                        archive.addfile(info, io.BytesIO(content))
            result = subprocess.run(["sh", "-c", block + "\nprintf INSTALLATION_REACHED_NEXT_PHASE"],
                                    cwd=directory, capture_output=True, text=True)
            if kind is None:
                assert result.returncode == 0, result.stderr
                assert "INSTALLATION_REACHED_NEXT_PHASE" in result.stdout
            else:
                assert result.returncode != 0, (kind, broken, result.stdout, result.stderr)
                assert "INSTALLATION_REACHED_NEXT_PHASE" not in result.stdout


@pytest.mark.parametrize("metadata", [None, "[broken", "", '[project]\nversion="0.2.6"\n', '[project]\ndependencies=42\nversion="0.2.6"\n'])
def test_installation_version_gate_reports_unusable_metadata(tmp_path, metadata):
    if metadata is not None:
        (tmp_path / "pyproject.toml").write_text(metadata)
    assert gates.gate_installation_versions(tmp_path)
