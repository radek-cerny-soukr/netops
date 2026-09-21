from __future__ import annotations

import ast
import ipaddress
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile


ROOT = Path(__file__).parents[1]
for _SOURCE in (ROOT / "src", ROOT.parent / "netops-core" / "src"):
    if str(_SOURCE) not in sys.path:
        sys.path.insert(0, str(_SOURCE))

CGNAT_SAMPLE = str(ipaddress.ip_address(0x64400307))
LINK_LOCAL_SAMPLE = str(ipaddress.ip_address(0xFE800000000000000000000000000001))
LINK_LOCAL_LONG_SAMPLE = str(ipaddress.ip_address((0xFE80 << 112) + (0x1234 << 16) + 0xABCD))
ULA_SAMPLE = str(ipaddress.ip_address((0xFD12 << 112) + (0x3456 << 96) + 1))
MDNS_SAMPLE = "nas." + "local"
VENDOR_CONTRACT_TESTS = {
    "tests/test_query_catalog_arista.py",
    "tests/test_query_catalog_cisco.py",
    "tests/test_query_catalog_extreme.py",
    "tests/test_query_catalog_fortinet.py",
    "tests/test_query_catalog_junos.py",
    "tests/test_query_catalog_ruckus.py",
    "tests/test_query_catalog_docs.py",
    "tests/test_vendor_references.py",
}


def test_sbom_contains_all_direct_dependencies() -> None:
    document = json.loads((ROOT / "sbom.cdx.json").read_text())
    root = document["metadata"]["component"]
    dependency = next(item for item in document["dependencies"] if item["ref"] == root["bom-ref"])
    direct = {
        re.split(r"[<=>!~\[]", line.strip(), maxsplit=1)[0].replace("_", "-").lower()
        for line in (ROOT / "requirements.txt").read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    components = {
        item["bom-ref"]: item["name"].replace("_", "-").lower()
        for item in document["components"]
    }
    assert {components[reference] for reference in dependency["dependsOn"]} == direct


def test_release_license_is_mit() -> None:
    assert (ROOT / "LICENSE").read_text().startswith("MIT License\n")
    assert 'license = { text = "MIT" }' in (ROOT / "pyproject.toml").read_text()


def test_healthcheck_uses_system_trust_without_private_ca_name() -> None:
    source = (ROOT / "src/netops_helper/selftest.py").read_text()
    assert "get_default_verify_paths" in source
    assert "/usr/local/share/ca-certificates/" not in source
    assert not any(isinstance(node, ast.Assert) for node in ast.walk(ast.parse(source)))
    assert "askpass_unsafe" in source
    assert "ASKPASS_PROGRAM_ENV" in source


def test_healthcheck_fails_closed_under_python_optimize() -> None:
    program = r"""
import importlib.util
import sys
import types

for name in ("fastmcp", "httpx", "pysnmp"):
    sys.modules[name] = types.ModuleType(name)
specification = importlib.util.spec_from_file_location("optimized_selftest", sys.argv[1])
if specification is None or specification.loader is None:
    raise SystemExit(90)
module = importlib.util.module_from_spec(specification)
specification.loader.exec_module(module)
module.ssl.get_default_verify_paths = lambda: types.SimpleNamespace(
    cafile="/definitely/missing/netops-helper-ca-bundle"
)
raise SystemExit(0 if module.main() != 0 else 91)
"""
    completed = subprocess.run(
        [
            sys.executable,
            "-O",
            "-c",
            program,
            str(ROOT / "src/netops_helper/selftest.py"),
        ],
        cwd=ROOT,
        env={
            **os.environ,
            "PYTHONOPTIMIZE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": os.pathsep.join(
                (str(ROOT / "src"), str(ROOT.parent / "netops-core" / "src"))
            ),
        },
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=5,
        check=False,
    )
    assert completed.returncode == 0, (completed.stdout, completed.stderr)


def _load_selftest():
    specification = importlib.util.spec_from_file_location(
        "netops_helper_selftest_under_test",
        ROOT / "src/netops_helper/selftest.py",
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def test_the_health_check_itself_refuses_an_unsafe_askpass_program() -> None:
    tree = ast.parse((ROOT / "src/netops_helper/selftest.py").read_text())
    main = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    refusals = [
        node for node in main.body
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Call)
        and isinstance(node.test.func, ast.Name)
        and node.test.func.id == "askpass_unsafe"
        and len(node.body) == 1
        and isinstance(node.body[0], ast.Return)
        and isinstance(node.body[0].value, ast.Constant)
        and node.body[0].value.value == 1
    ]
    assert len(refusals) == 1, ast.dump(main)


def test_askpass_unsafe_is_false_when_the_variable_is_not_set() -> None:
    module = _load_selftest()
    variable = module.ssh_module.ASKPASS_PROGRAM_ENV
    previous = os.environ.pop(variable, None)
    try:
        assert module.askpass_unsafe() is False
    finally:
        if previous is not None:
            os.environ[variable] = previous


def test_askpass_unsafe_reuses_the_shared_core_validation(tmp_path: Path) -> None:
    module = _load_selftest()
    variable = module.ssh_module.ASKPASS_PROGRAM_ENV
    previous = os.environ.pop(variable, None)
    try:
        program = tmp_path / "netops-askpass"
        program.write_text("#!/bin/sh\ncat \"$NETOPS_ASKPASS_FILE\"\n", encoding="utf-8")

        program.chmod(0o755)
        os.environ[variable] = str(program)
        assert module.askpass_unsafe() is False

        program.chmod(0o644)
        assert module.askpass_unsafe() is True

        program.chmod(0o757)
        assert module.askpass_unsafe() is True

        os.environ[variable] = str(tmp_path / "missing-askpass")
        assert module.askpass_unsafe() is True

        os.environ[variable] = str(tmp_path)
        assert module.askpass_unsafe() is True
    finally:
        if previous is None:
            os.environ.pop(variable, None)
        else:
            os.environ[variable] = previous


def test_proxy_transport_guard_is_not_an_optimized_assert() -> None:
    source = (ROOT / "src/netops_helper/proxy.py").read_text(encoding="utf-8")
    assert not any(isinstance(node, ast.Assert) for node in ast.walk(ast.parse(source)))
    assert "The local SSH process pipes are unavailable." in source


def test_base_image_is_pinned_and_lock_uses_hashes() -> None:
    first = (ROOT / "Dockerfile").read_text().splitlines()[0]
    assert re.fullmatch(r"FROM python:[^@\s]+@sha256:[0-9a-f]{64}", first)
    for name in ("requirements.lock", "requirements-release.lock"):
        lock = (ROOT / name).read_text()
        active = "\n".join(
            line for line in lock.splitlines() if not line.lstrip().startswith("#")
        )
        assert "pip-compile with Python 3.14" in lock
        assert "--hash=sha256:" in active
        assert "--no-index" not in active
        assert "--trusted-host" not in active
        assert "http://" not in active
        assert "file:" not in active


def test_release_tools_are_pinned() -> None:
    lines = {
        line.strip() for line in (ROOT / "requirements-release.in").read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert lines == {"-r requirements.txt", "cyclonedx-bom==7.4.0", "pytest==9.1.1"}


def _load_module(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _load_release_module(name: str):
    return _load_module(name, ROOT / f"scripts/{name}.py")


VERSION_CONTRACT_PATHS = (
    "pyproject.toml",
    "src/netops_helper/__init__.py",
    "compose.yaml",
    "scripts/create_release_artifacts.py",
    "sbom.cdx.json",
    "CHANGELOG.md",
)


def _version_fixture(tmp_path: Path) -> Path:
    root = tmp_path / "version-contract"
    for relative in VERSION_CONTRACT_PATHS:
        source = ROOT / relative
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    return root


def _replace_exact(path: Path, before: str, after: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert text.count(before) == 1
    path.write_text(text.replace(before, after), encoding="utf-8")


def _replace_current_changelog_heading(path: Path, version: str) -> None:
    text = path.read_text(encoding="utf-8")
    pattern = re.compile(r"^## 0\.3\.2(?P<suffix> - [^\n]+)$", re.MULTILINE)
    path.write_text(
        pattern.sub(lambda match: f"## {version}{match.group('suffix')}", text),
        encoding="utf-8",
    )

def test_version_invariant_accepts_authorities_and_ignores_decoys(
    tmp_path: Path,
) -> None:
    root = _version_fixture(tmp_path)
    (root / "pyproject.toml").write_text(
        (root / "pyproject.toml").read_text(encoding="utf-8")
        + "\n[tool.release-decoy]\nversion = \"9.9.9\"\n",
        encoding="utf-8",
    )
    (root / "src/netops_helper/__init__.py").write_text(
        (root / "src/netops_helper/__init__.py").read_text(encoding="utf-8")
        + "\nDECOY_VERSION = \"9.9.9\"\n",
        encoding="utf-8",
    )
    _replace_exact(
        root / "compose.yaml",
        "\nnetworks:\n",
        "\n  unrelated:\n    image: local/netops-helper:9.9.9\n\nnetworks:\n",
    )
    (root / "scripts/create_release_artifacts.py").write_text(
        (root / "scripts/create_release_artifacts.py").read_text(encoding="utf-8")
        + "\nDECOY_VERSION = \"9.9.9\"\n",
        encoding="utf-8",
    )
    sbom_path = root / "sbom.cdx.json"
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    sbom["components"][0]["version"] = "9.9.9"
    sbom_path.write_text(json.dumps(sbom), encoding="utf-8")
    (root / "CHANGELOG.md").write_text(
        (root / "CHANGELOG.md").read_text(encoding="utf-8")
        + "\nA body-only decoy mentions versions 9.9.9 and 0.1.0.\n",
        encoding="utf-8",
    )
    gate = _load_release_module("check_public_release")
    assert gate._version_invariant_errors(root) == []


def test_version_invariant_rejects_changed_pyproject(tmp_path: Path) -> None:
    root = _version_fixture(tmp_path)
    _replace_exact(
        root / "pyproject.toml",
        "version = \"0.3.5\"",
        "version = \"not-a-release\"",
    )
    errors = _load_release_module("check_public_release")._version_invariant_errors(root)
    assert errors == [
        "pyproject project identity or version is unavailable or invalid"
    ]


def test_version_invariant_rejects_changed_package_version(tmp_path: Path) -> None:
    root = _version_fixture(tmp_path)
    _replace_exact(
        root / "src/netops_helper/__init__.py",
        "__version__ = \"0.3.5\"",
        "__version__ = \"9.9.9\"",
    )
    errors = _load_release_module("check_public_release")._version_invariant_errors(root)
    assert "package __version__ does not match project metadata" in errors


def test_version_invariant_rejects_nested_and_function_version_bindings(
    tmp_path: Path,
) -> None:
    gate = _load_release_module("check_public_release")
    cases = {
        "nested": "\nif True:\n    __version__ = \"9.9.9\"\n",
        "function": (
            "\ndef version_decoy():\n"
            "    __version__ = \"0.3.5\"\n"
            "    return __version__\n"
        ),
    }
    for label, addition in cases.items():
        root = _version_fixture(tmp_path / label)
        init_path = root / "src/netops_helper/__init__.py"
        init_path.write_text(
            init_path.read_text(encoding="utf-8") + addition,
            encoding="utf-8",
        )
        errors = gate._version_invariant_errors(root)
        assert "package __version__ does not match project metadata" in errors


def test_version_invariant_rejects_dynamic_package_namespace_writes(
    tmp_path: Path,
) -> None:
    gate = _load_release_module("check_public_release")
    cases = {
        "exec": "\nexec(\"__version__ = \\\"9.9.9\\\"\")\n",
        "globals": "\nglobals()[\"__version__\"] = \"9.9.9\"\n",
    }
    for label, addition in cases.items():
        root = _version_fixture(tmp_path / label)
        init_path = root / "src/netops_helper/__init__.py"
        init_path.write_text(
            init_path.read_text(encoding="utf-8") + addition,
            encoding="utf-8",
        )
        errors = gate._version_invariant_errors(root)
        assert "package __version__ does not match project metadata" in errors


def test_version_invariant_rejects_changed_compose_image(tmp_path: Path) -> None:
    root = _version_fixture(tmp_path)
    _replace_exact(
        root / "compose.yaml",
        "image: local/netops-helper:0.3.5",
        "image: local/netops-helper:9.9.9",
    )
    errors = _load_release_module("check_public_release")._version_invariant_errors(root)
    assert "Compose netops-helper image label does not match project metadata" in errors


def test_version_invariant_rejects_manual_exporter_version(tmp_path: Path) -> None:
    root = _version_fixture(tmp_path)
    _replace_exact(
        root / "scripts/create_release_artifacts.py",
        "VERSION = project_version()",
        "VERSION = \"0.2.3\"",
    )
    errors = _load_release_module("check_public_release")._version_invariant_errors(root)
    assert "release exporter does not derive VERSION from project metadata" in errors


def test_version_invariant_rejects_changed_sbom_root(tmp_path: Path) -> None:
    root = _version_fixture(tmp_path)
    sbom_path = root / "sbom.cdx.json"
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    sbom["metadata"]["component"]["version"] = "9.9.9"
    sbom_path.write_text(json.dumps(sbom), encoding="utf-8")
    errors = _load_release_module("check_public_release")._version_invariant_errors(root)
    assert "source SBOM root application metadata does not match project metadata" in errors


def test_version_invariant_rejects_malformed_and_duplicate_sbom(
    tmp_path: Path,
) -> None:
    gate = _load_release_module("check_public_release")
    malformed = _version_fixture(tmp_path / "malformed")
    (malformed / "sbom.cdx.json").write_text("{", encoding="utf-8")
    errors = gate._version_invariant_errors(malformed)
    assert "source SBOM root application metadata is unavailable or invalid" in errors

    duplicate = _version_fixture(tmp_path / "duplicate")
    sbom_path = duplicate / "sbom.cdx.json"
    text = sbom_path.read_text(encoding="utf-8")
    assert text.count("\"metadata\": {") == 1
    sbom_path.write_text(
        text.replace("\"metadata\": {", "\"metadata\": {}, \"metadata\": {", 1),
        encoding="utf-8",
    )
    errors = gate._version_invariant_errors(duplicate)
    assert "source SBOM root application metadata is unavailable or invalid" in errors


def test_version_invariant_ignores_backtick_fenced_heading_decoy(
    tmp_path: Path,
) -> None:
    root = _version_fixture(tmp_path)
    _replace_current_changelog_heading(root / "CHANGELOG.md", "0.3.1")
    _replace_exact(
        root / "CHANGELOG.md",
        "# Changelog\n\n",
        "# Changelog\n\n```md\n## 0.3.1 - fenced decoy\n```\n\n",
    )
    errors = _load_release_module("check_public_release")._version_invariant_errors(root)
    assert "changelog current release heading does not match project metadata" in errors


def test_version_invariant_respects_tilde_fence_closing_length(
    tmp_path: Path,
) -> None:
    root = _version_fixture(tmp_path)
    _replace_current_changelog_heading(root / "CHANGELOG.md", "0.3.1")
    _replace_exact(
        root / "CHANGELOG.md",
        "# Changelog\n\n",
        (
            "# Changelog\n\n~~~~~markdown\n"
            "## 0.3.1 - first fenced decoy\n"
            "~~~~\n"
            "## 0.3.1 - still fenced after short closer\n"
            "~~~~~~\n\n"
        ),
    )
    errors = _load_release_module("check_public_release")._version_invariant_errors(root)
    assert "changelog current release heading does not match project metadata" in errors


def test_version_invariant_rejects_wrong_or_duplicate_changelog_heading(
    tmp_path: Path,
) -> None:
    gate = _load_release_module("check_public_release")
    wrong = _version_fixture(tmp_path / "wrong")
    _replace_current_changelog_heading(wrong / "CHANGELOG.md", "0.3.1")
    errors = gate._version_invariant_errors(wrong)
    assert "changelog current release heading does not match project metadata" in errors

    duplicate = _version_fixture(tmp_path / "duplicate")
    (duplicate / "CHANGELOG.md").write_text(
        (duplicate / "CHANGELOG.md").read_text(encoding="utf-8")
        + "\n## 0.3.0 - misleading duplicate\n",
        encoding="utf-8",
    )
    errors = gate._version_invariant_errors(duplicate)
    assert "changelog current release heading does not match project metadata" in errors


def test_public_allowlist_contains_all_0_2_contracts() -> None:
    exporter = _load_release_module("create_release_artifacts")
    gate = _load_release_module("check_public_release")
    runner_tree = ast.parse((ROOT / "tests/run_tests.py").read_text())
    runner_assignment = next(
        node
        for node in runner_tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name)
            and target.id == "DEPENDENCY_FREE_TESTS"
            for target in node.targets
        )
    )
    dependency_free_tests = set(ast.literal_eval(runner_assignment.value))
    required_tests = {
        "tests/test_apply_egress_rules.py",
        "tests/test_egress_scripts.py",
        "tests/test_engine_contracts.py",
        "tests/test_ssh_wire_safety.py",
    "tests/test_connection_pacing.py",
        "tests/test_policy_parity.py",
        "tests/test_proxy_contracts.py",
        "tests/test_sanitize.py",
        "tests/test_supply_chain.py",
        *VENDOR_CONTRACT_TESTS,
    }
    dependency_free_required = {
        "tests/test_supply_chain.py",
        *VENDOR_CONTRACT_TESTS,
    }
    required_scripts = {
        "scripts/apply_egress_rules.py",
        "scripts/check_egress_rules.py",
        "scripts/generate_egress_rules.py",
        "scripts/render_query_catalog_docs.py",
    }
    required_registry_paths = {
        "docs/query-catalog.md",
        "docs/query-sources.json",
        "scripts/render_query_catalog_docs.py",
        "tests/test_query_catalog_docs.py",
    }
    selected = {
        path.relative_to(ROOT).as_posix()
        for path in exporter.selected_files(ROOT)
    }
    assert len(selected) == 97
    assert exporter.VERSION == "0.3.5"
    assert required_tests <= exporter.TESTS
    assert required_tests <= gate.REQUIRED_RELEASE_PATHS
    assert dependency_free_required <= dependency_free_tests
    assert required_scripts <= exporter.SCRIPTS
    assert required_registry_paths <= selected
    assert required_registry_paths <= gate.REQUIRED_RELEASE_PATHS


SELECTION_ERROR = "public release source selection is unavailable or invalid"
SELECTION_MARKER = "SENSITIVE_SELECTION_MARKER"


def _public_source_fixture(tmp_path: Path) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    output = tmp_path / "baseline-output"
    subprocess.run(
        [
            sys.executable,
            "-B",
            str(ROOT / "scripts/create_release_artifacts.py"),
            "--output",
            str(output),
        ],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        text=True,
    )
    exported = output / "netops-helper-0.3.5"
    manifest = json.loads(
        (exported / "release-manifest.json").read_text(encoding="utf-8")
    )
    core_modules = sorted(
        name for name in manifest["files"] if name.startswith("src/netops_core/")
    )
    assert len(manifest["files"]) == 97 + len(core_modules)
    assert "src/netops_core/audit.py" in core_modules
    (exported / "release-manifest.json").unlink()
    (exported / "SHA256SUMS").unlink()
    assert _load_release_module("check_public_release").check(exported) == []
    return exported


def _selection_variant(base: Path, tmp_path: Path, label: str) -> Path:
    root = tmp_path / label
    shutil.copytree(base, root)
    return root


def _assert_selection_rejected(root: Path) -> None:
    gate = _load_release_module("check_public_release")
    errors = gate.check(root)
    assert len(errors) == 1 and errors[0].startswith(SELECTION_ERROR), errors
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            str(root / "scripts/check_public_release.py"),
            str(root),
        ],
        cwd=root,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    combined = completed.stdout + completed.stderr
    assert completed.returncode != 0
    assert (
        f"public_release_check=failed detail={SELECTION_ERROR}"
        in completed.stdout
    )
    assert "Traceback" not in combined
    assert SELECTION_MARKER not in combined


def test_release_selection_rejects_unsafe_entries(tmp_path: Path) -> None:
    baseline = _public_source_fixture(tmp_path)
    outside = tmp_path / "outside-marker"
    outside.write_text(SELECTION_MARKER, encoding="utf-8")

    ignored_cache = _selection_variant(baseline, tmp_path, "ignored-cache")
    cache_directory = ignored_cache / "src/netops_helper/__pycache__"
    cache_directory.mkdir()
    cache_payload = cache_directory / "private.pyc"
    cache_payload.write_text(SELECTION_MARKER, encoding="utf-8")
    cache_payload.chmod(0)
    exporter = _load_release_module("create_release_artifacts")
    assert not any(
        "__pycache__" in path.parts
        for path in exporter.selected_files(ignored_cache)
    )
    assert _load_release_module("check_public_release").check(ignored_cache) == []

    security_audit = _selection_variant(baseline, tmp_path, "security-audit")
    audit_path = security_audit / "docs/security-audit.md"
    audit_path.write_text("# Security audit\n\nReviewed public notes.\n", encoding="utf-8")
    selected = {
        path.relative_to(security_audit).as_posix()
        for path in exporter.selected_files(security_audit)
    }
    assert "docs/security-audit.md" in selected
    assert _load_release_module("check_public_release").check(security_audit) == []

    exact_link = _selection_variant(baseline, tmp_path, "exact-link")
    (exact_link / "README.md").unlink()
    (exact_link / "README.md").symlink_to(outside)
    _assert_selection_rejected(exact_link)

    source_link = _selection_variant(baseline, tmp_path, "source-link")
    (source_link / "src/netops_helper/linked.py").symlink_to(outside)
    _assert_selection_rejected(source_link)

    docs_link = _selection_variant(baseline, tmp_path, "docs-link")
    (docs_link / "docs/linked.md").symlink_to(outside)
    _assert_selection_rejected(docs_link)

    outside_cache = tmp_path / "outside-cache"
    outside_cache.mkdir()
    (outside_cache / "private.pyc").write_text(
        SELECTION_MARKER,
        encoding="utf-8",
    )
    cache_link = _selection_variant(baseline, tmp_path, "cache-link")
    (cache_link / "src/netops_helper/__pycache__").symlink_to(
        outside_cache,
        target_is_directory=True,
    )
    _assert_selection_rejected(cache_link)

    unknown = _selection_variant(baseline, tmp_path, "unknown-binary")
    (unknown / "docs/unreviewed.bin").write_bytes(
        SELECTION_MARKER.encode("utf-8")
    )
    _assert_selection_rejected(unknown)

    private_config = _selection_variant(baseline, tmp_path, "private-config")
    (private_config / "config/credentials.json").write_text(
        SELECTION_MARKER,
        encoding="utf-8",
    )
    _assert_selection_rejected(private_config)

    bytecode_outside_cache = _selection_variant(
        baseline,
        tmp_path,
        "bytecode-outside-cache",
    )
    (bytecode_outside_cache / "src/netops_helper/private.pyc").write_text(
        SELECTION_MARKER,
        encoding="utf-8",
    )
    _assert_selection_rejected(bytecode_outside_cache)

    special = _selection_variant(baseline, tmp_path, "special-file")
    os.mkfifo(special / "src/netops_helper/pipe.py")
    _assert_selection_rejected(special)

    excluded_link = _selection_variant(baseline, tmp_path, "excluded-link")
    (excluded_link / "config/inventory.json").symlink_to(outside)
    _assert_selection_rejected(excluded_link)

    excluded_special = _selection_variant(
        baseline,
        tmp_path,
        "excluded-special",
    )
    os.mkfifo(excluded_special / "config/container/certs/device.crt")
    _assert_selection_rejected(excluded_special)

    destination_tree = tmp_path / "unsafe-destination-tree"
    destination_tree.mkdir()
    destination_link = destination_tree / "linked-file"
    destination_link.symlink_to(outside)
    for operation in (
        lambda: exporter.digest(destination_link),
        lambda: exporter._regular_tree_files(destination_tree),
    ):
        try:
            operation()
        except exporter.ReleaseSelectionError:
            pass
        else:
            raise AssertionError("destination symlink was dereferenced")


def test_release_export_preserves_existing_destination(tmp_path: Path) -> None:
    output = tmp_path / "existing-output"
    destination = output / "netops-helper-0.3.5"
    destination.mkdir(parents=True)
    marker = destination / "marker"
    marker_bytes = SELECTION_MARKER.encode("utf-8")
    marker.write_bytes(marker_bytes)
    before = {
        path.relative_to(destination).as_posix(): path.read_bytes()
        for path in destination.rglob("*")
        if path.is_file()
    }

    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            str(ROOT / "scripts/create_release_artifacts.py"),
            "--output",
            str(output),
        ],
        cwd=ROOT,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    after = {
        path.relative_to(destination).as_posix(): path.read_bytes()
        for path in destination.rglob("*")
        if path.is_file()
    }
    combined = completed.stdout + completed.stderr
    assert completed.returncode != 0
    assert before == after == {"marker": marker_bytes}
    assert "release_export=failed detail=destination already exists" in completed.stderr
    assert "Traceback" not in combined
    assert SELECTION_MARKER not in combined


def test_release_export_rejects_symlinked_output(tmp_path: Path) -> None:
    actual = tmp_path / "actual-output"
    actual.mkdir(parents=True)
    direct_link = tmp_path / "direct-output-link"
    direct_link.symlink_to(actual, target_is_directory=True)
    parent_link = tmp_path / "parent-output-link"
    parent_link.symlink_to(actual, target_is_directory=True)

    cases = {
        "direct": (direct_link, actual / "netops-helper-0.3.5"),
        "parent": (
            parent_link / "nested-output",
            actual / "nested-output",
        ),
    }
    for label, (output, forbidden_destination) in cases.items():
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(ROOT / "scripts/create_release_artifacts.py"),
                "--output",
                str(output),
            ],
            cwd=ROOT,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )
        combined = completed.stdout + completed.stderr
        assert completed.returncode != 0, label
        assert not forbidden_destination.exists(), label
        assert (
            "release_export=failed detail=destination is unavailable"
            in completed.stderr
        ), label
        assert "Traceback" not in combined, label


def test_release_gate_rejects_missing_vendor_contract(tmp_path: Path) -> None:
    output = tmp_path / "missing-vendor-export"
    subprocess.run(
        [
            sys.executable,
            "-B",
            str(ROOT / "scripts/create_release_artifacts.py"),
            "--output",
            str(output),
        ],
        check=True,
    )
    exported = output / "netops-helper-0.3.5"
    (exported / "release-manifest.json").unlink()
    gate = _load_release_module("check_public_release")

    victims = {
        "tests/test_query_catalog_fortinet.py": SELECTION_ERROR,
        "docs/query-sources.json": (
            "required release artifact is missing: docs/query-sources.json"
        ),
    }
    for victim, expected in victims.items():
        path = exported / victim
        original = path.read_bytes()
        path.unlink()
        errors = gate.check(exported)
        assert any(error.startswith(expected) for error in errors), errors
        path.write_bytes(original)

    generated = exported / "docs/query-catalog.md"
    original = generated.read_text(encoding="utf-8")
    generated.write_text(original + "\nmanual drift\n", encoding="utf-8")
    errors = gate.check(exported)
    assert "query-catalog registry or generated document is invalid" in errors
    generated.write_text(original, encoding="utf-8")


def test_grype_contract_counts_all_severities_and_fails_closed(
    tmp_path: Path,
) -> None:
    gate = _load_release_module("check_public_release")
    accepted = tmp_path / "accepted.json"
    accepted.write_text(json.dumps({
        "matches": [
            {"vulnerability": {"severity": "High"}},
            {"vulnerability": {"severity": "Medium"}},
        ],
        "ignoredMatches": [{
            "vulnerability": {"severity": "Critical"},
            "appliedIgnoreRules": [{"reason": "reviewed"}],
        }],
    }))
    errors, counts = gate.check_grype_report(accepted)
    assert errors == []
    assert counts["active"]["High"] == 1
    assert counts["active"]["Medium"] == 1
    assert counts["ignored"]["Critical"] == 1
    assert set(counts["active"]) == set(gate.SEVERITIES)

    active_critical = tmp_path / "active-critical.json"
    active_critical.write_text(json.dumps({
        "matches": [{"vulnerability": {"severity": "Critical"}}],
        "ignoredMatches": [],
    }))
    errors, _ = gate.check_grype_report(active_critical)
    assert any("active Critical" in error for error in errors)

    unattributed = tmp_path / "unattributed.json"
    unattributed.write_text(json.dumps({
        "matches": [],
        "ignoredMatches": [{"vulnerability": {"severity": "Critical"}}],
    }))
    errors, _ = gate.check_grype_report(unattributed)
    assert any("appliedIgnoreRules" in error for error in errors)

    incomplete = tmp_path / "incomplete.json"
    incomplete.write_text(json.dumps({"ignoredMatches": []}))
    errors, _ = gate.check_grype_report(incomplete)
    assert any("matches list" in error for error in errors)

    malformed = tmp_path / "malformed-findings.json"
    malformed.write_text(json.dumps({
        "matches": [
            {},
            {"vulnerability": []},
            {"vulnerability": {"severity": 3}},
            {"vulnerability": {"severity": "Unexpected"}},
        ],
        "ignoredMatches": [],
    }))
    errors, counts = gate.check_grype_report(malformed)
    assert len(errors) == 4
    assert sum(counts["active"].values()) == 0
    assert counts["active"]["Unknown"] == 0
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            str(ROOT / "scripts/check_public_release.py"),
            str(ROOT),
            "--grype-report",
            str(malformed),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    assert completed.returncode != 0
    assert "has an invalid severity" in completed.stdout

    legitimate_unknown = tmp_path / "legitimate-unknown.json"
    legitimate_unknown.write_text(json.dumps({
        "matches": [{"vulnerability": {"severity": "Unknown"}}],
        "ignoredMatches": [],
    }))
    errors, counts = gate.check_grype_report(legitimate_unknown)
    assert errors == []
    assert counts["active"]["Unknown"] == 1


def test_release_tree_integrity_fails_closed(tmp_path: Path) -> None:
    output = tmp_path / "export"
    subprocess.run(
        [
            sys.executable,
            "-B",
            str(ROOT / "scripts/create_release_artifacts.py"),
            "--output",
            str(output),
        ],
        check=True,
    )
    exported = output / "netops-helper-0.3.5"
    gate = _load_release_module("check_public_release")
    assert gate._release_tree_integrity_errors(exported) == []

    rogue = exported / "vault.json"
    rogue.write_text("{}\n")
    errors = gate.check(exported)
    assert any("file set does not exactly match" in error for error in errors)
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            str(exported / "scripts/check_public_release.py"),
            str(exported),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    assert completed.returncode != 0
    assert "public_release_check=failed" in completed.stdout
    rogue.unlink()

    victim = exported / "README.md"
    original = victim.read_bytes()
    victim.write_bytes(original + b"changed\n")
    errors = gate._release_tree_integrity_errors(exported)
    assert any("hash does not match manifest" in error for error in errors)
    victim.write_bytes(original)

    backup = tmp_path / "README.md.backup"
    victim.replace(backup)
    errors = gate._release_tree_integrity_errors(exported)
    assert any("file set does not exactly match" in error for error in errors)
    backup.replace(victim)

    symlink = exported / "rogue-link"
    symlink.symlink_to("README.md")
    errors = gate._release_tree_integrity_errors(exported)
    assert any("contains a symlink" in error for error in errors)
    symlink.unlink()

    sums = exported / "SHA256SUMS"
    original_sums = sums.read_text()
    sums.write_text(original_sums + original_sums.splitlines()[0] + "\n")
    errors = gate._release_tree_integrity_errors(exported)
    assert any("duplicate path" in error for error in errors)

    checksum_lines = original_sums.splitlines()
    sums.write_text("\n".join(checksum_lines[1:]) + "\n")
    errors = gate._release_tree_integrity_errors(exported)
    assert any("does not exactly cover" in error for error in errors)

    first_digest, first_name = checksum_lines[0].split("  ", 1)
    assert first_digest != "0" * 64
    sums.write_text(
        "\n".join([f"{'0' * 64}  {first_name}", *checksum_lines[1:]]) + "\n"
    )
    errors = gate._release_tree_integrity_errors(exported)
    assert any("checksum hash does not match" in error for error in errors)
    sums.write_text(original_sums)

    manifest = exported / "release-manifest.json"
    original_manifest = manifest.read_text()
    manifest_document = json.loads(original_manifest)
    relative, digest = next(iter(manifest_document["files"].items()))
    del manifest_document["files"][relative]
    manifest_document["files"]["../outside"] = digest
    manifest.write_text(json.dumps(manifest_document))
    errors = gate._release_tree_integrity_errors(exported)
    assert any("unsafe file path" in error for error in errors)

    manifest_document = json.loads(original_manifest)
    manifest_document["unexpected"] = True
    manifest.write_text(json.dumps(manifest_document))
    errors = gate._release_tree_integrity_errors(exported)
    assert any("exact schema" in error for error in errors)

    manifest.write_text(original_manifest.replace("{", '{"schema":1,', 1))
    errors = gate._release_tree_integrity_errors(exported)
    assert errors == ["release manifest is unavailable or invalid"]
    manifest.write_text(original_manifest)
    assert gate._release_tree_integrity_errors(exported) == []


def test_phase1_surface_rejects_forbidden_command_in_added_module(
    tmp_path: Path,
) -> None:
    gate = _load_release_module("check_public_release")
    root = tmp_path / "phase1-tree"
    source_root = root / "src/netops_helper"
    platform_root = source_root / "platforms"
    platform_root.mkdir(parents=True)
    (source_root / "server.py").write_text(
        "class Mcp:\n"
        "    def tool(self):\n"
        "        return lambda function: function\n"
        "mcp = Mcp()\n"
        "@mcp.tool()\n"
        "def helper_status():\n"
        "    return None\n",
        encoding="utf-8",
    )
    policy_path = source_root / "read_policy.py"
    policy_path.write_text(
        "SAFE_QUERY = \"show version\"\n",
        encoding="utf-8",
    )
    assert gate._phase1_surface_errors(root) == []

    added_module = platform_root / "vendor.py"
    added_module.write_text(
        "FORBIDDEN_QUERY = \"show full-configuration\"\n"
        "def config_mode():\n"
        "    return None\n",
        encoding="utf-8",
    )
    errors = gate._phase1_surface_errors(root)
    assert errors == [
        "phase-1 source contains configuration export pattern: "
        "src/netops_helper/platforms/vendor.py: show full-configuration",
        "phase-1 source contains a write implementation: "
        "src/netops_helper/platforms/vendor.py: config_mode",
    ]
    assert "show full-configuration" not in policy_path.read_text(
        encoding="utf-8"
    ).lower()


def test_phase1_surface_rejects_removed_body_read_symbols_and_policy(
    tmp_path: Path,
) -> None:
    gate = _load_release_module("check_public_release")
    root = tmp_path / "removed-body-read"
    source_root = root / "src/netops_helper"
    source_root.mkdir(parents=True)
    (source_root / "server.py").write_text(
        "class Mcp:\n"
        "    def tool(self):\n"
        "        return lambda function: function\n"
        "mcp = Mcp()\n"
        "@mcp.tool()\n"
        "def helper_status():\n"
        "    return None\n",
        encoding="utf-8",
    )
    assert gate._phase1_surface_errors(root) == []

    (source_root / "legacy.py").write_text(
        "from somewhere import https_get as engine_https_get\n"
        "https_endpoints = []\n"
        "def sftp_read_text():\n"
        "    return None\n",
        encoding="utf-8",
    )
    errors = gate._phase1_surface_errors(root)
    assert any(
        "removed body-read surface remains" in error
        and "https_get" in error
        and "engine_https_get" in error
        and "https_endpoints" in error
        and "sftp_read_text" in error
        for error in errors
    )

    (source_root / "legacy.py").unlink()
    config = root / "config"
    config.mkdir()
    (config / "inventory.example.json").write_text(
        json.dumps({
            "version": 2,
            "devices": [{
                "name": "device",
                "helper": {
                    "https_endpoints": [{
                        "path": "/export.conf",
                        "port": 443,
                        "use_basic_auth": False,
                    }],
                },
            }],
        }),
        encoding="utf-8",
    )
    assert "phase-1 example policy contains removed https_endpoints" in (
        gate._phase1_surface_errors(root)
    )


def test_public_gate_rejects_recursive_local_environment_markers(
    tmp_path: Path,
) -> None:
    baseline = _public_source_fixture(tmp_path)
    markers = (
        "\x72pi8-node",
        "R\x50i-12-edge",
        "/\x77orkspace/project",
        "/home/\x73ynthetic-user/project",
        "home\x2dlab project",
        "local\x20lab deployment",
        "personal\x2dlab notes",
        "private\x20lab notes",
        "\x72aspberry pi builder",
        "\x72aspberry\x5fpi builder",
        "synthetic\x2dmcp trace",
        "generic\x2dreadonly trace",
    )

    def case_variants(value: str) -> tuple[str, str, str]:
        mixed = "".join(
            character.upper() if index % 2 else character.lower()
            for index, character in enumerate(value)
        )
        return value.lower(), value.upper(), mixed

    gate = _load_release_module("check_public_release")
    content_variant = _selection_variant(
        baseline, tmp_path, "local-marker-content-cases"
    )
    nested = content_variant / "docs/content-cases"
    nested.mkdir()
    content_names = []
    for marker_index, marker in enumerate(markers):
        for case_index, candidate in enumerate(case_variants(marker)):
            name = f"environment-{marker_index}-{case_index}.md"
            content_names.append(name)
            (nested / name).write_text(candidate + "\n", encoding="utf-8")
    errors = gate.check(content_variant)
    assert all(
        any(name in error and "private marker" in error for error in errors)
        for name in content_names
    )

    path_variant = _selection_variant(
        baseline, tmp_path, "local-marker-path-cases"
    )
    nested = path_variant / "docs/path-cases"
    nested.mkdir()
    path_markers = ("\x72pi8-node", "\x72aspberry\x2dpi", "\x72aspberry\x5fpi")
    path_names = []
    for marker_index, path_marker in enumerate(path_markers):
        for case_index, candidate in enumerate(case_variants(path_marker)):
            name = f"path-{marker_index}-{case_index}-{candidate}.md"
            path_names.append(name)
            (nested / name).write_text("Environment notes.\n", encoding="utf-8")
    errors = gate.check(path_variant)
    assert all(
        any(name in error and "private marker in release path" in error for error in errors)
        for name in path_names
    )

    generic = _selection_variant(baseline, tmp_path, "generic-runner-language")
    nested = generic / "docs/nested"
    nested.mkdir()
    (nested / "deployment.md").write_text(
        "Test the generic Linux ARM64 builder and device example.\n",
        encoding="utf-8",
    )
    assert gate.check(generic) == []


def test_public_gate_privacy_scan_has_bounded_runtime(tmp_path: Path) -> None:
    baseline = _public_source_fixture(tmp_path)
    variant = _selection_variant(baseline, tmp_path, "privacy-performance")
    nested = variant / "docs/performance"
    nested.mkdir()
    (nested / "large-neutral-input.md").write_text(
        "generic Linux ARM64 builder documentation; \n" * 25000,
        encoding="utf-8",
    )
    script = (
        "import importlib.util, sys\n"
        "spec = importlib.util.spec_from_file_location(\"gate\", sys.argv[1])\n"
        "module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)\n"
        "root = __import__(\"pathlib\").Path(sys.argv[2])\n"
        "files = module._tracked_release_files(root)\n"
        "assert all(module._privacy_errors(root, files) == [] for _ in range(3))\n"
    )
    completed = subprocess.run(
        [sys.executable, "-B", "-c", script, str(ROOT / "scripts/check_public_release.py"), str(variant)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=20, check=False,
    )
    assert completed.returncode == 0, (completed.stdout, completed.stderr)

def test_public_export_contains_no_python_bytecode(tmp_path: Path) -> None:
    subprocess.run(
        [
            sys.executable,
            "-B",
            str(ROOT / "scripts/create_release_artifacts.py"),
            "--output",
            str(tmp_path),
        ],
        check=True,
    )
    exported = tmp_path / "netops-helper-0.3.5"
    assert not [path for path in exported.rglob("*") if "__pycache__" in path.parts]
    assert not list(exported.rglob("*.pyc"))
    assert not list(exported.rglob("*.pyo"))


def test_runtime_image_drops_pip_and_carries_oci_labels() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    install = dockerfile.index("--require-hashes -r requirements.lock")
    assert dockerfile.index("python -m pip uninstall -y pip") > install
    assert 'org.opencontainers.image.source="https://github.com/radek-cerny-soukr/netops"' in dockerfile
    assert 'org.opencontainers.image.licenses="MIT"' in dockerfile


def test_gate_flags_credential_shaped_and_private_network_markers() -> None:
    gate = _load_release_module("check_public_release")
    flagged = {
        "ghp_" + "A" * 36: "credential-shaped material",
        "AKIA" + "B" * 16: "credential-shaped material",
        "xoxb-" + "1" * 12: "credential-shaped material",
        "ssh-ed25519 AAAA" + "C" * 44 + " user": "credential-shaped material",
        "next hop " + LINK_LOCAL_LONG_SAMPLE: "private network marker",
        "peer " + ULA_SAMPLE: "private network marker",
        "carrier " + CGNAT_SAMPLE: "private network marker",
        "resolver " + MDNS_SAMPLE: "private network marker",
    }
    for text, detail in flagged.items():
        errors = gate._secret_and_network_marker_errors("docs/sample.md", text)
        assert errors == [f"{detail} in docs/sample.md"], (text, errors)
    assert gate._secret_and_network_marker_errors("docs/sample.md", "target 192.0.2.10 example.invalid") == []
    assert gate._secret_and_network_marker_errors("tests/fixture.py", "peer " + LINK_LOCAL_SAMPLE) == []


def test_release_export_compose_builds_from_archive_root(tmp_path: Path) -> None:
    tmp_path.mkdir(parents=True, exist_ok=True)
    output = tmp_path / "compose-build-root"
    subprocess.run(
        [
            sys.executable,
            "-B",
            str(ROOT / "scripts/create_release_artifacts.py"),
            "--output",
            str(output),
        ],
        check=True,
    )
    exported = output / "netops-helper-0.3.5"
    compose_text = (exported / "compose.yaml").read_text(encoding="utf-8")
    assert "      context: .\n" in compose_text
    assert "../.." not in compose_text
    assert "dockerfile:" not in compose_text
    assert "args:" not in compose_text


def test_release_export_keeps_askpass_executable(tmp_path: Path) -> None:
    tmp_path.mkdir(parents=True, exist_ok=True)
    output = tmp_path / "compose-build-modes"
    subprocess.run(
        [
            sys.executable,
            "-B",
            str(ROOT / "scripts/create_release_artifacts.py"),
            "--output",
            str(output),
        ],
        check=True,
    )
    exported = output / "netops-helper-0.3.5"
    askpass_mode = stat.S_IMODE(
        (exported / "src/netops_core/askpass.py").stat().st_mode
    )
    ssh_mode = stat.S_IMODE((exported / "src/netops_core/ssh.py").stat().st_mode)
    assert askpass_mode == 0o755
    assert ssh_mode == 0o644


def test_release_export_rejects_unknown_compose_build_block(tmp_path: Path) -> None:
    tmp_path.mkdir(parents=True, exist_ok=True)
    mutated = tmp_path / "netops-helper-mutated"
    shutil.copytree(ROOT, mutated)
    _replace_exact(
        mutated / "compose.yaml",
        "      context: ../..\n",
        "      context: ../../..\n",
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            str(mutated / "scripts/create_release_artifacts.py"),
            "--output",
            str(tmp_path / "mutated-output"),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    assert completed.returncode != 0
    assert (
        "release_export=failed detail=compose build block is not the known one"
        in completed.stderr
    )
    assert "Traceback" not in completed.stdout + completed.stderr


def test_compose_build_gate_rejects_missing_dockerfile(tmp_path: Path) -> None:
    tmp_path.mkdir(parents=True, exist_ok=True)
    root = tmp_path / "compose-build-gate"
    root.mkdir()
    (root / "compose.yaml").write_text(
        "services:\n"
        "  netops-helper:\n"
        "    build:\n"
        "      context: .\n"
        "    image: local/netops-helper:0.3.1\n",
        encoding="utf-8",
    )
    gate = _load_release_module("check_public_release")
    errors = gate._compose_build_target_errors(root)
    assert any(
        "dockerfile does not exist relative to its context" in error
        for error in errors
    ), errors

    (root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (root / "src/netops_core").mkdir(parents=True)
    (root / "src/netops_core/__init__.py").write_text("", encoding="utf-8")
    assert gate._compose_build_target_errors(root) == []


def test_runtime_inputs_and_install_metadata_agree() -> None:
    import tomllib
    dependencies = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["dependencies"]
    runtime = [line.strip() for line in (ROOT / "requirements.txt").read_text().splitlines() if line.strip() and not line.startswith("#")]
    assert sorted(x for x in dependencies if not x.startswith("netops-core==")) == sorted(runtime)


def test_release_gate_rejects_dependency_drift(tmp_path: Path) -> None:
    tmp_path.mkdir(parents=True, exist_ok=True)
    project = tmp_path / "pyproject.toml"
    project.write_text('[project]\ndependencies = ["netops-core==0.2.3", "httpx==0.28.1"]\n')
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("httpx==0.28.1\n")
    gate = _load_release_module("check_public_release")
    assert gate._runtime_dependency_errors(tmp_path) == []
    for bad in ("httpx==0.28.0\n", "", "httpx==0.28.1\nhttpx==0.28.1\n", "httpx==0.28.1\nmcp==2.1.1\n"):
        requirements.write_text(bad)
        assert gate._runtime_dependency_errors(tmp_path)
    requirements.write_text("httpx==0.28.1\n")
    assert gate._runtime_dependency_errors(tmp_path) == []


def main() -> int:
    test_runtime_inputs_and_install_metadata_agree()
    test_sbom_contains_all_direct_dependencies()
    test_release_license_is_mit()
    test_healthcheck_uses_system_trust_without_private_ca_name()
    test_healthcheck_fails_closed_under_python_optimize()
    test_the_health_check_itself_refuses_an_unsafe_askpass_program()
    test_askpass_unsafe_is_false_when_the_variable_is_not_set()
    with tempfile.TemporaryDirectory(prefix="netops-selftest-askpass-") as directory:
        test_askpass_unsafe_reuses_the_shared_core_validation(Path(directory))
    test_proxy_transport_guard_is_not_an_optimized_assert()
    test_base_image_is_pinned_and_lock_uses_hashes()
    test_release_tools_are_pinned()
    test_public_allowlist_contains_all_0_2_contracts()
    with tempfile.TemporaryDirectory(prefix="netops-supply-chain-contracts-") as directory:
        temporary = Path(directory)
        test_release_gate_rejects_dependency_drift(temporary / "dependency-drift")
        test_version_invariant_accepts_authorities_and_ignores_decoys(
            temporary / "version-decoys"
        )
        test_version_invariant_rejects_changed_pyproject(
            temporary / "version-pyproject"
        )
        test_version_invariant_rejects_changed_package_version(
            temporary / "version-package"
        )
        test_version_invariant_rejects_nested_and_function_version_bindings(
            temporary / "version-package-bindings"
        )
        test_version_invariant_rejects_dynamic_package_namespace_writes(
            temporary / "version-package-dynamic"
        )
        test_version_invariant_rejects_changed_compose_image(
            temporary / "version-compose"
        )
        test_version_invariant_rejects_manual_exporter_version(
            temporary / "version-exporter"
        )
        test_version_invariant_rejects_changed_sbom_root(
            temporary / "version-sbom"
        )
        test_version_invariant_rejects_malformed_and_duplicate_sbom(
            temporary / "version-sbom-invalid"
        )
        test_version_invariant_ignores_backtick_fenced_heading_decoy(
            temporary / "version-changelog-backtick-fence"
        )
        test_version_invariant_respects_tilde_fence_closing_length(
            temporary / "version-changelog-tilde-fence"
        )
        test_version_invariant_rejects_wrong_or_duplicate_changelog_heading(
            temporary / "version-changelog"
        )
        test_release_selection_rejects_unsafe_entries(
            temporary / "release-selection"
        )
        test_release_export_preserves_existing_destination(
            temporary / "existing-destination"
        )
        test_release_export_rejects_symlinked_output(
            temporary / "symlinked-output"
        )
        test_release_gate_rejects_missing_vendor_contract(temporary)
        test_grype_contract_counts_all_severities_and_fails_closed(temporary)
        test_release_tree_integrity_fails_closed(temporary)
        test_phase1_surface_rejects_forbidden_command_in_added_module(temporary)
        test_phase1_surface_rejects_removed_body_read_symbols_and_policy(temporary)
        test_public_gate_rejects_recursive_local_environment_markers(
            temporary / "local-environment-markers"
        )
        test_public_gate_privacy_scan_has_bounded_runtime(temporary / "privacy-performance")
        test_public_export_contains_no_python_bytecode(temporary)
        test_release_export_compose_builds_from_archive_root(
            temporary / "compose-build-root"
        )
        test_release_export_keeps_askpass_executable(
            temporary / "compose-build-modes"
        )
        test_release_export_rejects_unknown_compose_build_block(
            temporary / "compose-build-mutated"
        )
        test_compose_build_gate_rejects_missing_dockerfile(
            temporary / "compose-build-gate"
        )
    test_runtime_image_drops_pip_and_carries_oci_labels()
    test_gate_flags_credential_shaped_and_private_network_markers()
    print("supply_chain_contract_tests=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


def test_the_exporter_marks_exactly_the_programs_the_tree_marks() -> None:
    exporter = _load_release_module("create_release_artifacts")
    marked = set()
    for tree in ("scripts", "src"):
        for path in sorted((ROOT / tree).rglob("*")):
            if path.is_file() and path.stat().st_mode & 0o100:
                marked.add(path.relative_to(ROOT).as_posix())
    assert exporter.SCRIPTS == marked
    core = {
        path.name
        for path in sorted((ROOT.parent / "netops-core/src/netops_core").iterdir())
        if path.is_file() and path.stat().st_mode & 0o100
    }
    assert set(exporter.CORE_EXECUTABLE) == core
