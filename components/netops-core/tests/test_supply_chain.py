import json
import re
import tomllib
from pathlib import Path

COMPONENT = Path(__file__).resolve().parents[1]
SBOM = COMPONENT / "sbom.cdx.json"
PYPROJECT = COMPONENT / "pyproject.toml"
INIT = COMPONENT / "src" / "netops_core" / "__init__.py"
CHANGELOG = COMPONENT / "CHANGELOG.md"
LOCK = COMPONENT / "requirements-release.lock"
REQUIREMENTS = COMPONENT / "requirements-release.in"
URL = re.compile(r"[a-z][a-z0-9+.-]*://[^\s\"]*")
ABSOLUTE_PATH = re.compile(r"(?<![A-Za-z0-9_.~-])/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+")
WINDOWS_PATH = re.compile(r"[A-Za-z]:\\\\?[A-Za-z0-9_.-]")


def _canonical(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def _project():
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]


def _document():
    return json.loads(SBOM.read_text(encoding="utf-8"))


def _package_version():
    found = re.search(
        r'^__version__ = "([^"]+)"$', INIT.read_text(encoding="utf-8"), re.MULTILINE
    )
    assert found is not None, INIT.read_text(encoding="utf-8")
    return found.group(1)


def _changelog_heading():
    for line in CHANGELOG.read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            return line[3:].strip()
    raise AssertionError("the changelog names no version")


def test_sbom_root_carries_the_project_identity():
    project = _project()
    root = _document()["metadata"]["component"]
    assert root["name"] == project["name"]
    assert root["version"] == project["version"]
    assert root["type"] == "library"
    assert root["purl"] == "pkg:pypi/%s@%s" % (
        _canonical(project["name"]), project["version"],
    )
    assert [entry["license"]["id"] for entry in root["licenses"]] == ["MIT"]


def test_the_package_states_the_project_version():
    assert _package_version() == _project()["version"]


def test_the_changelog_names_the_project_version():
    heading = _changelog_heading()
    assert heading.split(" ")[0] == _project()["version"], heading


def test_sbom_is_reproducible():
    document = _document()
    assert "serialNumber" not in document
    assert "timestamp" not in document["metadata"]
    assert {"name": "cdx:reproducible", "value": "true"} in document["metadata"]["properties"]


def test_sbom_names_no_filesystem_location():
    text = URL.sub(" ", SBOM.read_text(encoding="utf-8"))
    assert ABSOLUTE_PATH.search(text) is None
    assert WINDOWS_PATH.search(text) is None


def test_sbom_states_no_dependency_at_all():
    assert _project()["dependencies"] == []
    document = _document()
    assert document.get("components", []) == []
    root = document["metadata"]["component"]["bom-ref"]
    entry = next(item for item in document["dependencies"] if item["ref"] == root)
    assert entry["dependsOn"] == []


def test_release_requirements_name_only_the_release_toolbox():
    entries = [
        line.strip() for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert entries == ["cyclonedx-bom==7.3.1", "pytest==9.1.1"]


def test_release_lock_pins_every_requirement_with_hashes():
    lines = LOCK.read_text(encoding="utf-8").splitlines()
    pinned = [line for line in lines if re.match(r"^[A-Za-z0-9]", line)]
    assert pinned
    for line in pinned:
        assert "==" in line
        assert line.rstrip().endswith("\\")
    assert any("--hash=sha256:" in line for line in lines)
