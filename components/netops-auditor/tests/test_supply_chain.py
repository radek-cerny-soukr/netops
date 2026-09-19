import json
import re
import tomllib
from pathlib import Path

COMPONENT = Path(__file__).resolve().parents[1]
SBOM = COMPONENT / "sbom.cdx.json"
PYPROJECT = COMPONENT / "pyproject.toml"
OPTIONAL_REQUIREMENTS = COMPONENT / "requirements-mcp.txt"
LOCK = COMPONENT / "requirements-release.lock"
URL = re.compile(r"[a-z][a-z0-9+.-]*://[^\s\"]*")
ABSOLUTE_PATH = re.compile(r"(?<![A-Za-z0-9_.~-])/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+")
WINDOWS_PATH = re.compile(r"[A-Za-z]:\\\\?[A-Za-z0-9_.-]")
CORE_NAME = "netops-core"
CORE_VERSION = "0.1.0"
CORE_REQUIREMENT = "%s==%s" % (CORE_NAME, CORE_VERSION)
CORE_PURL = "pkg:pypi/%s@%s" % (CORE_NAME, CORE_VERSION)


def _canonical(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def _project():
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]


def _document():
    return json.loads(SBOM.read_text(encoding="utf-8"))


def _optional_names():
    names = set()
    for line in OPTIONAL_REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        entry = line.strip()
        if entry and not entry.startswith("#"):
            names.add(_canonical(re.split(r"[<=>!~\[]", entry, maxsplit=1)[0]))
    return names


def test_sbom_root_carries_the_project_identity():
    project = _project()
    root = _document()["metadata"]["component"]
    assert root["name"] == project["name"]
    assert root["version"] == project["version"]
    assert root["purl"] == "pkg:pypi/%s@%s" % (
        _canonical(project["name"]), project["version"],
    )
    assert [entry["license"]["id"] for entry in root["licenses"]] == ["MIT"]


def test_sbom_is_reproducible():
    document = _document()
    assert "serialNumber" not in document
    assert "timestamp" not in document["metadata"]
    assert {"name": "cdx:reproducible", "value": "true"} in document["metadata"]["properties"]


def test_sbom_names_no_filesystem_location():
    text = URL.sub(" ", SBOM.read_text(encoding="utf-8"))
    assert ABSOLUTE_PATH.search(text) is None
    assert WINDOWS_PATH.search(text) is None


def test_sbom_carries_the_shared_access_layer_as_the_required_dependency():
    assert _project()["dependencies"] == [CORE_REQUIREMENT]
    document = _document()
    root = document["metadata"]["component"]["bom-ref"]
    entry = next(item for item in document["dependencies"] if item["ref"] == root)
    assert entry["dependsOn"] == [CORE_PURL]
    required = [
        item for item in document["components"] if item.get("scope") == "required"
    ]
    assert [(item["name"], item["version"], item["purl"]) for item in required] == [
        (CORE_NAME, CORE_VERSION, CORE_PURL)
    ]


def test_the_pinned_core_version_is_the_one_in_the_tree():
    document = tomllib.loads(
        (COMPONENT.parent / CORE_NAME / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]
    assert document["name"] == CORE_NAME
    assert document["version"] == CORE_VERSION


def test_sbom_carries_every_optional_requirement_as_optional():
    optional = _optional_names()
    assert optional
    marked = {
        _canonical(component["name"])
        for component in _document()["components"]
        if component.get("scope") == "optional"
    }
    assert marked == optional


def test_release_lock_pins_every_requirement_with_hashes():
    lines = LOCK.read_text(encoding="utf-8").splitlines()
    pinned = [line for line in lines if re.match(r"^[A-Za-z0-9]", line)]
    assert pinned
    for line in pinned:
        assert "==" in line
        assert line.rstrip().endswith("\\")
    assert any("--hash=sha256:" in line for line in lines)
