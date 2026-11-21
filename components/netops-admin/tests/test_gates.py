from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("admin_check_gates", ROOT / "tests" / "support" / "check_gates.py")
gates = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gates)

@pytest.fixture
def tree(tmp_path) -> Path:
    copy = tmp_path / "netops-admin"
    shutil.copytree(ROOT / "src", copy / "src")
    shutil.copy2(ROOT / "pyproject.toml", copy / "pyproject.toml")
    return copy

@pytest.mark.parametrize(("line", "fragment"), [
    ("import socket\n", "imports socket"),
    ("import subprocess\n", "imports subprocess"),
    ("import importlib\n", "imports importlib"),
    ("from netops_core import transport\n", "imports transport from netops_core"),
    ("from netops import gateway\n", "imports gateway from netops"),
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

def _new_import_errors(tree, name, line):
    module = tree / "src" / "netops_admin" / name
    before = set(gates.import_errors(tree))
    text = module.read_text(encoding="utf-8") if module.exists() else ""
    module.write_text(text + "\n" + line, encoding="utf-8")
    return sorted(set(gates.import_errors(tree)) - before)

def test_access_may_import_the_core_platforms_module(tree):
    assert _new_import_errors(tree, "access.py", "from netops_core import platforms\n") == []


def test_access_allows_dns_resolution_without_opening_socket_transport(tree):
    resolution = "from socket import SOCK_STREAM, getaddrinfo"
    assert _new_import_errors(tree, "access.py", resolution) == []
    assert _new_import_errors(tree, "exec_junos.py", resolution)
    assert _new_import_errors(tree, "access.py", "import socket")
    assert _new_import_errors(tree, "access.py", "from socket import socket")


OTHER_ADMIN_MODULES = sorted(
    ({path.name for path in (ROOT / "src" / "netops_admin").rglob("*.py")} | set(gates.FILE_RULES) | {"unlisted_module.py"})
    - {"access.py"}
)

def test_the_platforms_admission_check_covers_existing_listed_and_unlisted_modules():
    assert {"cli.py", "engine.py", "execute.py", "schema_runtime.py", "unlisted_module.py"} <= set(OTHER_ADMIN_MODULES)
    assert set(gates.FILE_RULES) - {"access.py"} <= set(OTHER_ADMIN_MODULES)
    assert "access.py" not in OTHER_ADMIN_MODULES

@pytest.mark.parametrize("name", OTHER_ADMIN_MODULES)
def test_the_core_platforms_module_is_admitted_only_for_access(tree, name):
    errors = _new_import_errors(tree, name, "from netops_core import platforms\n")
    assert any("imports platforms from netops_core" in error for error in errors), errors

@pytest.mark.parametrize(("line", "fragment"), [
    ("from netops_core import transport\n", "imports transport from netops_core"),
    ("from netops_core import inputs\n", "imports inputs from netops_core"),
    ("import netops_core\n", "imports netops_core"),
    ("import netops_core.platforms\n", "imports netops_core.platforms"),
    ("from netops_core.platforms import version_record\n", "imports version_record from netops_core.platforms"),
])
def test_access_stays_closed_to_the_rest_of_netops_core(tree, line, fragment):
    errors = _new_import_errors(tree, "access.py", line)
    assert any(fragment in error for error in errors), errors


def test_only_the_backup_module_can_import_the_backup_transport(tree):
    transport = "from http.client import HTTPSConnection"
    assert _new_import_errors(tree, "backup.py", transport) == []
    for name in ("cli.py", "access.py", "unlisted_module.py"):
        errors = _new_import_errors(tree, name, transport)
        assert any("imports HTTPSConnection from http.client" in error for error in errors), errors
    errors = _new_import_errors(tree, "backup.py", "from http.client import HTTPConnection")
    assert any("imports HTTPConnection from http.client" in error for error in errors), errors


def test_exos_backup_admits_only_the_pinned_sftp_download(tree):
    statement = "from netops_core.sftp import read_exos_configuration"
    assert _new_import_errors(tree, "backup_exos.py", statement) == []
    assert any("imports read_exos_configuration from netops_core.sftp" in error
               for error in _new_import_errors(tree, "cli.py", statement))
    assert any("imports sftp from netops_core" in error
               for error in _new_import_errors(tree, "backup_exos.py", "from netops_core import sftp"))


def test_eos_backup_only_admits_the_reviewed_ssh_transport(tree):
    ssh = "from netops_core import hostkey, ssh"
    assert _new_import_errors(tree, "backup_eos.py", ssh) == []
    assert len(_new_import_errors(tree, "backup.py", ssh)) == 2
    for statement, fragment in (
        ("import socket", "imports socket"),
        ("from http.client import HTTPSConnection", "imports HTTPSConnection"),
        ("from netops_core import session", "imports session"),
    ):
        errors = _new_import_errors(tree, "backup_eos.py", statement)
        assert any(fragment in error for error in errors), errors


def test_fortinet_dialog_imports_framing_only_and_config_imports_pin_validation_only(tree):
    framing = "from netops_core.session import _FortinetOutput"
    assert _new_import_errors(tree, "fortinet_cli.py", framing) == []
    assert any("imports fortinet_session" in error for error in _new_import_errors(
        tree, "fortinet_cli.py", "from netops_core.session import fortinet_session"))
    assert any("imports _FortinetOutput" in error for error in _new_import_errors(tree, "cli.py", framing))
    validation = "from netops_core.hostkey import checked_public_key"
    assert _new_import_errors(tree, "config.py", validation) == []
    assert any("imports scan" in error for error in _new_import_errors(
        tree, "config.py", "from netops_core.hostkey import scan"))


def test_same_named_eos_backup_in_subpackage_has_no_import_exception(tree):
    path = "subpackage/backup_eos.py"
    package = tree / "src" / "netops_admin" / "subpackage"
    package.mkdir()
    (package / "__init__.py").touch()
    errors = _new_import_errors(tree, path, "from netops_core import hostkey, ssh")
    assert errors == [
        f"src/netops_admin/{path}:2 imports hostkey from netops_core",
        f"src/netops_admin/{path}:2 imports ssh from netops_core",
    ]


def test_nxos_backup_only_admits_the_reviewed_imports(tree):
    statements = (
        "import fcntl",
        "import os",
        "from hmac import compare_digest",
        "from netops.files import read_private, write_private",
        "from netops_core import hostkey, nxos_config, ssh",
        "from netops_core.vault import Credential, VaultError",
    )
    assert _new_import_errors(tree, "backup_nxos.py", "\n".join(statements)) == []

    nested = tree / "src" / "netops_admin" / "subpackage"
    nested.mkdir()
    errors = _new_import_errors(tree, "subpackage/backup_nxos.py", statements[4])
    assert len(errors) == 3
    assert all(" from netops_core" in error for error in errors)

    for statement in (
        "import socket",
        "from hmac import new",
        "from netops.files import sync_directory",
        "from netops_core import session",
        "from netops_core.vault import Vault",
    ):
        assert len(_new_import_errors(tree, "backup_nxos.py", statement)) == 1


@pytest.fixture
def component(tmp_path) -> Path:
    copy = tmp_path / "netops-admin"
    shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    return copy

def test_private_material_in_a_released_file_is_reported(component):
    address = ".".join(("10", "1", "2", "3"))
    document = component / "README.md"
    document.write_text(document.read_text(encoding="utf-8") + "\nRun it on host %s as mail.example-corp.cz.\n" % address,
                        encoding="utf-8")
    errors = gates._release_text_errors("README.md", document.read_text(encoding="utf-8"), True)
    assert any(address in error for error in errors)
    assert any("example-corp.cz" in error for error in errors)

def test_current_engine_import_and_profile_boundaries():
    assert gates.import_errors(ROOT) == []
    assert gates.profile_errors(ROOT) == []
