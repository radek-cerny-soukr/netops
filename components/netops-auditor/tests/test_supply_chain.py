import json
import re
import tomllib
from fnmatch import fnmatch
from pathlib import Path

from netops_auditor.suppressions import MIGRATE_COMMAND

COMPONENT = Path(__file__).resolve().parents[1]
SBOM = COMPONENT / "sbom.cdx.json"
PYPROJECT = COMPONENT / "pyproject.toml"
OPTIONAL_REQUIREMENTS = COMPONENT / "requirements-mcp.txt"
LOCK = COMPONENT / "requirements-release.lock"
URL = re.compile(r"[a-z][a-z0-9+.-]*://[^\s\"]*")
ABSOLUTE_PATH = re.compile(r"(?<![A-Za-z0-9_.~-])/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+")
WINDOWS_PATH = re.compile(r"[A-Za-z]:\\\\?[A-Za-z0-9_.-]")
CORE_NAME = "netops-core"
CORE_VERSION = "0.2.4"
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


def test_every_link_into_the_core_archive_names_the_pinned_version():
    tagged = re.compile(r"netops-core/v([0-9]+\.[0-9]+\.[0-9]+)")
    seen = 0
    for document in sorted((COMPONENT / "docs").glob("*.md")):
        text = document.read_text(encoding="utf-8")
        for found in tagged.finditer(text):
            seen += 1
            assert found.group(1) == CORE_VERSION, (
                "%s links into netops-core/v%s while this component pins %s"
                % (document.name, found.group(1), CORE_REQUIREMENT)
            )
    assert seen, "the documentation links into no core archive at all"


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


def _configuration():
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def test_every_file_the_package_reads_at_runtime_travels_in_the_distribution():
    package = COMPONENT / "src" / "netops_auditor"
    data = sorted(
        path.relative_to(package).as_posix()
        for path in package.rglob("*")
        if path.is_file()
        and path.suffix != ".py"
        and "__pycache__" not in path.parts
        and not path.name.endswith(".egg-info")
    )
    assert data, "the package has no data files, this test guards the wrong path"
    declared = _configuration()["tool"]["setuptools"].get("package-data", {})
    patterns = declared.get("netops_auditor", [])
    assert patterns, "pyproject declares no package data, the wheel would ship none"
    for name in data:
        assert any(fnmatch(name, pattern) for pattern in patterns), name


def test_the_documented_command_is_installed_by_the_distribution():
    scripts = _configuration()["project"].get("scripts", {})
    assert scripts.get("netops-auditor") == "netops_auditor.cli:main", scripts
    assert MIGRATE_COMMAND.startswith("netops-auditor ")


ACTION = COMPONENT / "action.yml"


def test_the_action_pins_every_action_it_uses_to_a_commit():
    uses = re.findall(r"^\s*(?:-\s*)?uses:\s*(\S+)", ACTION.read_text(encoding="utf-8"), re.MULTILINE)
    assert uses
    for value in uses:
        assert re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", value), value


def test_the_action_runs_the_sources_it_ships_with():
    text = ACTION.read_text(encoding="utf-8")
    assert 'PYTHONPATH="$NETOPS_SOURCE/src:$NETOPS_SOURCE/../netops-core/src"' in text
    assert (COMPONENT / "src" / "netops_auditor" / "__main__.py").is_file()
    assert (COMPONENT.parent / "netops-core" / "src" / "netops_core" / "__init__.py").is_file()
