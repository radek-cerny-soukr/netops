import os
import json
import re
import shutil
import tomllib
from pathlib import Path

import pytest

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




















def test_the_askpass_program_a_deployment_names_is_reachable_without_the_source_tree():
    from netops_core import ssh

    program = shutil.which("netops-askpass")
    if program is None:
        if os.environ.get("NETOPS_REQUIRE_INSTALLED_PACKAGE_TESTS") == "1":
            pytest.fail("installation acceptance requires netops-askpass on PATH")
        pytest.skip("netops-askpass is not installed in this environment")
    assert ssh._named_askpass(program) == program


def test_installation_acceptance_does_not_skip_a_missing_askpass(monkeypatch):
    monkeypatch.setenv("NETOPS_REQUIRE_INSTALLED_PACKAGE_TESTS", "1")
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(pytest.fail.Exception, match="requires netops-askpass"):
        test_the_askpass_program_a_deployment_names_is_reachable_without_the_source_tree()
