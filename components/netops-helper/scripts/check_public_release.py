#!/usr/bin/env python3
"""Fail closed when a public release violates the reviewed release contract."""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile
import sys
import tomllib
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {
    "", ".cfg", ".env", ".in", ".ini", ".json", ".lock", ".md", ".py", ".sh", ".toml", ".txt",
    ".yaml", ".yml",
}
SECRET_MATERIAL_MARKERS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bssh-(?:ed25519|rsa|dss) AAAA[0-9A-Za-z+/]{40,}"),
)
PRIVATE_NETWORK_MARKERS = (
    re.compile(r"(?<![0-9])100\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}(?![0-9])"),
    re.compile(r"(?<![0-9])169\.254\.[0-9]{1,3}\.[0-9]{1,3}(?![0-9])"),
    re.compile(r"(?<![0-9a-f:])f[cd][0-9a-f]{2}:[0-9a-f:]+", re.IGNORECASE),
    re.compile(r"(?<![0-9a-f:])fe80:[0-9a-f:]+", re.IGNORECASE),
    re.compile(r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:local|lan|home\.arpa|internal|intranet)\b", re.IGNORECASE),
)
SEVERITIES = ("Critical", "High", "Medium", "Low", "Negligible", "Unknown")
RELEASE_VERSION_PATTERN = re.compile(
    r"[0-9]+\.[0-9]+\.[0-9]+(?:[.-][0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
)
RELEASE_METADATA = {"release-manifest.json", "SHA256SUMS"}
MANIFEST_FIELDS = {
    "schema",
    "name",
    "version",
    "base_image_digest",
    "image_digest",
    "files",
}
REQUIRED_RELEASE_PATHS = {
    "docs/query-catalog.md",
    "docs/query-sources.json",
    "scripts/apply_egress_rules.py",
    "scripts/check_egress_rules.py",
    "scripts/generate_egress_rules.py",
    "scripts/render_query_catalog_docs.py",
    "scripts/check_operator_config.py",
    "tests/test_apply_egress_rules.py",
    "tests/test_egress_scripts.py",
    "tests/test_check_operator_config.py",
    "tests/test_engine_contracts.py",
    "tests/test_ssh_wire_safety.py",
    "tests/test_connection_pacing.py",
    "tests/test_policy_parity.py",
    "tests/test_proxy_contracts.py",
    "tests/test_query_catalog_arista.py",
    "tests/test_query_catalog_cisco.py",
    "tests/test_query_catalog_extreme.py",
    "tests/test_query_catalog_fortinet.py",
    "tests/test_query_catalog_junos.py",
    "tests/test_query_catalog_ruckus.py",
    "tests/test_query_catalog_docs.py",
    "tests/test_vendor_references.py",
    "tests/test_sanitize.py",
    "tests/test_supply_chain.py",
}


def _load_release_exporter(root: Path) -> Any:
    path = root / "scripts/create_release_artifacts.py"
    for required in (path, root / "pyproject.toml"):
        mode = required.lstat().st_mode
        if not stat.S_ISREG(mode):
            raise RuntimeError("release exporter input is not a regular file")
    module_name = "_netops_release_exporter_" + hashlib.sha256(
        str(path).encode("utf-8")
    ).hexdigest()
    specification = importlib.util.spec_from_file_location(module_name, path)
    if specification is None or specification.loader is None:
        raise RuntimeError("release exporter is unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _tracked_release_files(root: Path) -> list[Path]:
    module = _load_release_exporter(root)
    selected_files = getattr(module, "selected_files", None)
    if not callable(selected_files):
        raise RuntimeError("release exporter has no file selector")
    return selected_files(root)


def _source_path(root: Path) -> str:
    return os.pathsep.join(
        (str(root / "src"), str(root.parent / "netops-core" / "src"))
    )


def _mcp_tool(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(
        isinstance(decorator, ast.Attribute) and decorator.attr == "tool"
        or isinstance(decorator, ast.Call)
        and isinstance(decorator.func, ast.Attribute)
        and decorator.func.attr == "tool"
        for decorator in function.decorator_list
    )


def _phase1_surface_errors(root: Path) -> list[str]:
    errors: list[str] = []
    source_root = root / "src/netops_helper"
    server_path = source_root / "server.py"
    walk_errors: list[OSError] = []
    source_paths: list[Path] = []
    contains_symlink = False
    try:
        if source_root.is_symlink() or not source_root.is_dir():
            raise OSError("phase-1 source root is not a regular directory")
        for directory, directory_names, file_names in os.walk(
            source_root, topdown=True, onerror=walk_errors.append, followlinks=False,
        ):
            directory_path = Path(directory)
            retained_directories = []
            for name in sorted(directory_names):
                candidate = directory_path / name
                mode = candidate.lstat().st_mode
                if stat.S_ISLNK(mode):
                    contains_symlink = True
                    continue
                if not stat.S_ISDIR(mode):
                    raise OSError("phase-1 source child is not a directory")
                retained_directories.append(name)
            directory_names[:] = retained_directories
            for name in sorted(file_names):
                if not name.endswith(".py"):
                    continue
                candidate = directory_path / name
                mode = candidate.lstat().st_mode
                if stat.S_ISLNK(mode):
                    contains_symlink = True
                    continue
                if not stat.S_ISREG(mode):
                    raise OSError("phase-1 Python source is not a regular file")
                source_paths.append(candidate)
    except OSError:
        return ["phase-1 surface sources are unavailable or invalid"]
    if walk_errors or server_path not in source_paths:
        return ["phase-1 surface sources are unavailable or invalid"]
    if contains_symlink:
        errors.append("phase-1 source tree contains a symlink")

    source_texts: dict[Path, str] = {}
    source_trees: dict[Path, ast.Module] = {}
    try:
        for source_path in source_paths:
            source_text = source_path.read_text(encoding="utf-8")
            source_texts[source_path] = source_text.lower()
            source_trees[source_path] = ast.parse(source_text)
    except (OSError, UnicodeError, SyntaxError):
        return ["phase-1 surface sources are unavailable or invalid"]

    forbidden_tool_names = {
        "route_trace",
        "traceroute",
        "running_config",
        "startup_config",
        "full_configuration",
        "configuration_backup",
        "configuration_export",
        "https_get",
        "sftp_read_text",
    }
    for node in source_trees[server_path].body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _mcp_tool(node):
            normalized = node.name.lower()
            if normalized in forbidden_tool_names or any(
                marker in normalized
                for marker in ("config_export", "backup_config", "raw_command")
            ):
                errors.append(f"phase-1 server registers forbidden tool: {node.name}")

    removed_body_read_identifiers = {
        "https_get",
        "sftp_read_text",
        "engine_https_get",
        "engine_sftp_read_text",
        "https_endpoints",
        "require_https_endpoint",
    }
    production_trees = dict(source_trees)
    for relative in (
        "scripts/remote_mcp_proxy.py",
        "scripts/generate_egress_rules.py",
    ):
        path = root / relative
        if not path.exists():
            continue
        try:
            mode = path.lstat().st_mode
            if not stat.S_ISREG(mode):
                raise OSError("body-read surface is not a regular file")
            production_trees[path] = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, SyntaxError):
            errors.append(f"phase-1 body-read surface is unavailable or invalid: {relative}")
    for source_path, source_tree in production_trees.items():
        found: set[str] = set()
        for node in ast.walk(source_tree):
            candidates: tuple[str | None, ...] = ()
            if isinstance(node, ast.Name):
                candidates = (node.id,)
            elif isinstance(node, ast.Attribute):
                candidates = (node.attr,)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                candidates = (node.name,)
            elif isinstance(node, ast.alias):
                candidates = (node.name.rsplit(".", 1)[-1], node.asname)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                candidates = (node.value,)
            found.update(
                candidate for candidate in candidates
                if candidate in removed_body_read_identifiers
            )
        if found:
            relative = source_path.relative_to(root).as_posix()
            errors.append(
                "phase-1 removed body-read surface remains in "
                + relative + ": " + ", ".join(sorted(found))
            )

    example_policy = root / "config/inventory.example.json"
    if example_policy.exists():
        try:
            mode = example_policy.lstat().st_mode
            if not stat.S_ISREG(mode):
                raise OSError("example policy is not a regular file")
            example_document = json.loads(example_policy.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            errors.append("phase-1 example policy is unavailable or invalid")
        else:
            pending: list[Any] = [example_document]
            legacy_field_found = False
            while pending:
                value = pending.pop()
                if isinstance(value, dict):
                    if "https_endpoints" in value:
                        legacy_field_found = True
                    pending.extend(value.values())
                elif isinstance(value, list):
                    pending.extend(value)
            if legacy_field_found:
                errors.append("phase-1 example policy contains removed https_endpoints")

    forbidden_catalog_patterns = (
        "show running-config",
        "show startup-config",
        "show full-configuration",
        "show configuration",
        "backup configuration",
        "execute backup",
        "running_config",
        "startup_config",
        "full_configuration",
        "configuration_backup",
    )
    forbidden_implementation_patterns = (
        "prepare" + "_",
        "apply" + "_",
        "cancel" + "_change",
        "sftp" + "_upload",
        "send" + "_command_timing",
        "posix" + "_rename",
        "save" + "_config",
        "config" + "_mode",
    )
    for source_path in source_paths:
        relative = source_path.relative_to(root).as_posix()
        source_text = source_texts[source_path]
        for pattern in forbidden_catalog_patterns:
            if pattern in source_text:
                errors.append(
                    "phase-1 source contains configuration export pattern: "
                    f"{relative}: {pattern}"
                )
        for pattern in forbidden_implementation_patterns:
            if pattern in source_text:
                errors.append(
                    "phase-1 source contains a write implementation: "
                    f"{relative}: {pattern}"
                )
    return errors


def _ssh_wire_errors(root: Path) -> list[str]:
    errors: list[str] = []
    engine_path = root / "src/netops_helper/engine.py"
    wire_path = root / "tests/test_ssh_wire_safety.py"
    try:
        engine_text = engine_path.read_text(encoding="utf-8")
        engine_tree = ast.parse(engine_text)
        wire_text = wire_path.read_text(encoding="utf-8")
        wire_tree = ast.parse(wire_text)
    except (OSError, UnicodeError, SyntaxError):
        return ["SSH transport or wire-safety test is unavailable or invalid"]

    imported: set[str] = set()
    for node in ast.walk(engine_tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    for retired in ("netmiko", "paramiko"):
        if retired in imported:
            errors.append(f"the read transport still imports {retired}")

    functions = {
        node.name
        for node in ast.walk(engine_tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for required in ("host_key_line", "read_from_device", "_exec_read", "_pty_read"):
        if required not in functions:
            errors.append(f"the read transport has no {required}")
    if "netmiko_connection" in functions or "ReadOnlyFortinetSSH" in {
        node.name for node in ast.walk(engine_tree) if isinstance(node, ast.ClassDef)
    }:
        errors.append("a retired Netmiko connection factory is still present")

    for token, message in (
        ("core_hostkey.scan(", "the host key pin is not verified with the shared keyscan"),
        ("core_ssh.run_command(", "the exec transport does not call the shared SSH client"),
        ("core_session.Session(", "the terminal transport does not use the shared session"),
        ("session.discard(", "the terminal transport does not discard its login phase"),
        ("_SSH_TRANSPORTS", "the transport per platform is not a table in the code"),
        ("_PLATFORM_PREAMBLE", "the platform preamble is not a table in the code"),
    ):
        if token not in engine_text:
            errors.append(message)
    transport_bodies = [
        node
        for node in ast.walk(engine_tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in {"read_from_device", "_exec_read", "_pty_read", "_pty_body"}
    ]
    literals = {
        inner.value
        for node in transport_bodies
        for inner in ast.walk(node)
        if isinstance(inner, ast.Constant) and isinstance(inner.value, str)
    }
    if literals & {"exit", "quit", "config", "configure", "end", "save"}:
        errors.append("the read transport carries a literal that leaves the read boundary")

    wire_tests = {
        node.name
        for node in ast.walk(wire_tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    }
    required_tests = {
        "test_every_exec_platform_sends_its_preamble_and_the_catalog_command",
        "test_the_password_reaches_the_client_only_through_the_askpass_file",
        "test_a_key_reaches_the_client_only_as_a_private_file",
        "test_the_legacy_options_appear_only_with_the_enrolled_profile",
        "test_the_exec_client_is_given_no_configuration_file_of_the_host",
        "test_the_access_point_is_driven_on_a_terminal_and_the_login_never_leaks",
        "test_the_login_phase_of_the_access_point_stays_out_of_error_and_audit",
    }
    missing_tests = sorted(required_tests - wire_tests)
    if missing_tests:
        errors.append("wire-safety test is missing: " + ", ".join(missing_tests))
    required_tokens = (
        "engine.ssh_read",
        "engine._SSH_TRANSPORTS",
        "\"-F\"",
        "/dev/null",
        "StrictHostKeyChecking=yes",
        "SSH_ASKPASS",
        "LEGACY_OPTIONS",
        "transcript",
        "FORBIDDEN_ON_THE_WIRE",
    )
    if any(token not in wire_text for token in required_tokens):
        errors.append("SSH wire-safety test does not inspect the real client call")
    return errors


def _run_query_catalog_docs(root: Path) -> list[str]:
    path = root / "scripts/render_query_catalog_docs.py"
    if not path.is_file():
        return ["query-catalog renderer is missing"]
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = _source_path(root)
    try:
        completed = subprocess.run(
            [sys.executable, "-B", str(path), "--check"],
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
            text=True,
        )
    except (OSError, subprocess.SubprocessError):
        return ["query-catalog validation could not run"]
    if completed.returncode:
        return ["query-catalog registry or generated document is invalid"]
    return []


def _run_policy_parity(root: Path) -> list[str]:
    path = root / "tests/test_policy_parity.py"
    if not path.is_file():
        return ["policy parity artifact is missing"]
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = _source_path(root)
    try:
        with tempfile.TemporaryDirectory(prefix="netops-policy-parity-pycache-") as cache:
            environment["PYTHONPYCACHEPREFIX"] = cache
            completed = subprocess.run(
                [sys.executable, "-B", str(path)],
                cwd=root,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=False,
                text=True,
            )
    except (OSError, subprocess.SubprocessError):
        return ["policy parity artifact could not run"]
    if completed.returncode:
        return ["policy parity artifact failed"]
    return []


class _DuplicateJsonKey(ValueError):
    pass


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(key)
        result[key] = value
    return result


def _safe_release_path(value: Any) -> bool:
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    if "\\" in value or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        return False
    try:
        if len(value.encode("utf-8")) > 4096:
            return False
        candidate = PurePosixPath(value)
        components_are_safe = all(
            part not in {"", ".", ".."} and len(part.encode("utf-8")) <= 255
            for part in candidate.parts
        )
    except UnicodeError:
        return False
    return (
        bool(candidate.parts)
        and not candidate.is_absolute()
        and candidate.as_posix() == value
        and components_are_safe
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _package_version_from_tree(tree: ast.Module) -> str | None:
    statements = list(tree.body)
    if (
        statements
        and isinstance(statements[0], ast.Expr)
        and isinstance(statements[0].value, ast.Constant)
        and type(statements[0].value.value) is str
    ):
        statements.pop(0)

    package_versions: list[str] = []
    for statement in statements:
        if isinstance(statement, ast.Assign):
            if (
                len(statement.targets) != 1
                or not isinstance(statement.targets[0], ast.Name)
                or not isinstance(statement.targets[0].ctx, ast.Store)
                or not isinstance(statement.value, ast.Constant)
            ):
                return None
            if statement.targets[0].id == "__version__":
                if type(statement.value.value) is not str:
                    return None
                package_versions.append(statement.value.value)
        elif isinstance(statement, ast.AnnAssign):
            if (
                not statement.simple
                or not isinstance(statement.target, ast.Name)
                or not isinstance(statement.target.ctx, ast.Store)
                or not isinstance(statement.annotation, ast.Name)
                or not isinstance(statement.value, ast.Constant)
                or statement.target.id == "__version__"
            ):
                return None
        else:
            return None
    if len(package_versions) != 1:
        return None
    return package_versions[0]


def _markdown_h2_headings(text: str) -> list[str]:
    headings: list[str] = []
    fence_character: str | None = None
    fence_length = 0
    for line in text.splitlines():
        if fence_character is not None:
            closing = re.fullmatch(r" {0,3}(`{3,}|~{3,})[ \t]*", line)
            if closing is not None:
                marker = closing.group(1)
                if marker[0] == fence_character and len(marker) >= fence_length:
                    fence_character = None
                    fence_length = 0
            continue

        opening = re.fullmatch(r" {0,3}(`{3,}|~{3,})(.*)", line)
        if opening is not None:
            marker = opening.group(1)
            info = opening.group(2)
            if marker[0] != "`" or "`" not in info:
                fence_character = marker[0]
                fence_length = len(marker)
                continue

        heading = re.fullmatch(r" {0,3}##(?:[ \t]+(.*?)[ \t]*)?", line)
        if heading is not None:
            headings.append(heading.group(1) or "")
    return headings


def _compose_service_lines(compose_lines: list[str], service_header: str) -> list[str] | None:
    service_roots = [
        index for index, line in enumerate(compose_lines)
        if line == "services:"
    ]
    if len(service_roots) != 1:
        return None
    section_start = service_roots[0] + 1
    section_end = len(compose_lines)
    for index in range(section_start, len(compose_lines)):
        line = compose_lines[index]
        if (
            line.strip()
            and not line.lstrip().startswith("#")
            and not line[0].isspace()
        ):
            section_end = index
            break
    service_headers = [
        index for index in range(section_start, section_end)
        if compose_lines[index] == service_header
    ]
    if len(service_headers) != 1:
        return None
    service_start = service_headers[0] + 1
    service_end = section_end
    for index in range(service_start, section_end):
        line = compose_lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indentation = len(line) - len(line.lstrip(" "))
        if indentation <= 2:
            service_end = index
            break
    return compose_lines[service_start:service_end]


def _compose_mapping_lines(lines: list[str], indent: int, key: str) -> list[str] | None:
    header = (" " * indent) + key + ":"
    headers = [index for index, line in enumerate(lines) if line == header]
    if len(headers) != 1:
        return None
    start = headers[0] + 1
    end = len(lines)
    for index in range(start, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indentation = len(line) - len(line.lstrip(" "))
        if indentation <= indent:
            end = index
            break
    return lines[start:end]


def _compose_scalar(lines: list[str], indent: int, key: str) -> str | None:
    pattern = re.compile(
        r"^" + (" " * indent) + re.escape(key) + r":[ \t]+([^#\s]+)[ \t]*(?:#.*)?$"
    )
    values = [match.group(1) for line in lines if (match := pattern.fullmatch(line))]
    return values[0] if len(values) == 1 else None


def _compose_build_target_errors(root: Path) -> list[str]:
    compose_path = root / "compose.yaml"
    try:
        compose_lines = compose_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return ["Compose netops-helper build block is unavailable or invalid"]

    service_lines = _compose_service_lines(compose_lines, "  netops-helper:")
    if service_lines is None:
        return ["Compose netops-helper build block is unavailable or invalid"]

    build_lines = _compose_mapping_lines(service_lines, 4, "build")
    if build_lines is None:
        return ["Compose netops-helper build block is unavailable or invalid"]

    context_value = _compose_scalar(build_lines, 6, "context")
    if context_value is None:
        return ["Compose netops-helper build context is unavailable or invalid"]
    context_directory = (compose_path.parent / context_value).resolve()

    dockerfile_value = _compose_scalar(build_lines, 6, "dockerfile") or "Dockerfile"
    dockerfile_path = (context_directory / dockerfile_value).resolve()

    errors: list[str] = []
    if not dockerfile_path.is_file():
        errors.append(
            "Compose netops-helper build dockerfile does not exist relative to "
            f"its context: {dockerfile_value}"
        )

    args_lines = _compose_mapping_lines(build_lines, 6, "args") or []
    core_package_value = (
        _compose_scalar(args_lines, 8, "CORE_PACKAGE_DIR") or "src/netops_core"
    )
    core_package_init = (
        context_directory / core_package_value / "__init__.py"
    ).resolve()
    if not core_package_init.is_file():
        errors.append(
            "Compose netops-helper build CORE_PACKAGE_DIR does not hold "
            f"__init__.py relative to its context: {core_package_value}"
        )
    return errors


def _version_invariant_errors(root: Path) -> list[str]:
    errors: list[str] = []
    try:
        document = tomllib.loads(
            (root / "pyproject.toml").read_text(encoding="utf-8")
        )
        project = document["project"]
        project_name = project["name"]
        project_version = project["version"]
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, KeyError, TypeError):
        return ["pyproject project identity or version is unavailable or invalid"]
    if (
        project_name != "netops-helper"
        or not isinstance(project_version, str)
        or RELEASE_VERSION_PATTERN.fullmatch(project_version) is None
    ):
        return ["pyproject project identity or version is unavailable or invalid"]

    init_path = root / "src/netops_helper/__init__.py"
    try:
        init_tree = ast.parse(init_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, SyntaxError):
        errors.append("package __version__ is unavailable or invalid")
    else:
        package_version = _package_version_from_tree(init_tree)
        if package_version != project_version:
            errors.append("package __version__ does not match project metadata")

    try:
        compose_lines = (root / "compose.yaml").read_text(
            encoding="utf-8"
        ).splitlines()
    except (OSError, UnicodeError):
        errors.append("Compose netops-helper image label is unavailable or invalid")
    else:
        service_lines = _compose_service_lines(compose_lines, "  netops-helper:")
        compose_image = (
            _compose_scalar(service_lines, 4, "image")
            if service_lines is not None else None
        )
        if compose_image != f"local/netops-helper:{project_version}":
            errors.append("Compose netops-helper image label does not match project metadata")

    exporter_path = root / "scripts/create_release_artifacts.py"
    exporter_derives_version = False
    try:
        exporter_tree = ast.parse(exporter_path.read_text(encoding="utf-8"))
        version_assignments = [
            node for node in exporter_tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "VERSION"
        ]
        if len(version_assignments) == 1:
            value = version_assignments[0].value
            exporter_derives_version = (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id == "project_version"
                and not value.args
                and not value.keywords
            )
    except (OSError, UnicodeError, SyntaxError):
        pass
    if not exporter_derives_version:
        errors.append("release exporter does not derive VERSION from project metadata")
    try:
        exporter = _load_release_exporter(root)
        derived = exporter.project_version(root)
        exported = exporter.VERSION
    except Exception:
        errors.append("release exporter version is unavailable or invalid")
    else:
        if derived != project_version or exported != project_version:
            errors.append("release exporter version does not match project metadata")

    try:
        sbom = json.loads(
            (root / "sbom.cdx.json").read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
        component = sbom["metadata"]["component"]
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        KeyError,
        TypeError,
    ):
        errors.append("source SBOM root application metadata is unavailable or invalid")
    else:
        if (
            not isinstance(component, dict)
            or component.get("type") != "application"
            or component.get("name") != "netops-helper"
            or component.get("version") != project_version
        ):
            errors.append("source SBOM root application metadata does not match project metadata")

    try:
        changelog_text = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        errors.append("changelog current release heading is unavailable or invalid")
    else:
        headings = _markdown_h2_headings(changelog_text)
        release_heading = re.compile(
            r"(" + RELEASE_VERSION_PATTERN.pattern + r")(?:[ 	]+-[ 	]+.+)?"
        )
        versions = [
            match.group(1)
            for heading in headings
            if (match := release_heading.fullmatch(heading)) is not None
        ]
        first_is_current = bool(
            headings
            and (match := release_heading.fullmatch(headings[0])) is not None
            and match.group(1) == project_version
        )
        if (
            not first_is_current
            or versions.count(project_version) != 1
            or len(versions) != len(set(versions))
        ):
            errors.append("changelog current release heading does not match project metadata")
    return errors


def _release_tree_integrity_errors(root: Path) -> list[str]:
    manifest_path = root / "release-manifest.json"
    sums_path = root / "SHA256SUMS"
    if manifest_path.is_symlink():
        return ["release manifest must not be a symlink"]
    if not manifest_path.exists():
        return []

    errors: list[str] = []
    actual_files: set[str] = set()
    try:
        for path in root.rglob("*"):
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                errors.append("release tree contains a symlink")
                continue
            mode = path.stat(follow_symlinks=False).st_mode
            if stat.S_ISREG(mode):
                actual_files.add(relative)
            elif not stat.S_ISDIR(mode):
                errors.append("release tree contains a non-regular filesystem entry")
    except OSError:
        errors.append("release tree could not be inspected safely")
    if errors:
        return errors
    if "release-manifest.json" not in actual_files:
        return ["release manifest is not a regular file"]
    if "SHA256SUMS" not in actual_files:
        return ["release checksum file is missing or is not a regular file"]

    try:
        document = json.loads(
            manifest_path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, _DuplicateJsonKey):
        return ["release manifest is unavailable or invalid"]
    if not isinstance(document, dict):
        return ["release manifest root must be an object"]
    if set(document) != MANIFEST_FIELDS:
        errors.append("release manifest fields do not match the exact schema")
    if type(document.get("schema")) is not int or document.get("schema") != 1:
        errors.append("release manifest schema must be integer 1")
    if document.get("name") != "netops-helper":
        errors.append("release manifest name is invalid")

    version = document.get("version")
    if not isinstance(version, str) or not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+(?:[A-Za-z0-9.-]+)?", version
    ):
        errors.append("release manifest version is invalid")
    else:
        try:
            project_version = tomllib.loads(
                (root / "pyproject.toml").read_text(encoding="utf-8")
            )["project"]["version"]
        except (OSError, UnicodeError, tomllib.TOMLDecodeError, KeyError, TypeError):
            errors.append("release project version is unavailable or invalid")
        else:
            if version != project_version:
                errors.append("release manifest version does not match project metadata")

    base_digest = document.get("base_image_digest")
    if not isinstance(base_digest, str) or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", base_digest
    ):
        errors.append("release manifest base image digest is invalid")
    else:
        try:
            docker_base = (
                (root / "Dockerfile")
                .read_text(encoding="utf-8")
                .splitlines()[0]
                .rsplit("@", 1)[1]
            )
        except (OSError, UnicodeError, IndexError):
            errors.append("release Dockerfile base image digest is unavailable")
        else:
            if base_digest != docker_base:
                errors.append("release manifest base image digest does not match Dockerfile")

    image_digest = document.get("image_digest")
    if image_digest is not None and (
        not isinstance(image_digest, str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest)
    ):
        errors.append("release manifest image digest is invalid")

    raw_manifest_files = document.get("files")
    manifest_files: dict[str, str] = {}
    if not isinstance(raw_manifest_files, dict) or not raw_manifest_files:
        errors.append("release manifest files must be a non-empty object")
    else:
        for index, (relative, expected_digest) in enumerate(raw_manifest_files.items()):
            if not _safe_release_path(relative) or relative in RELEASE_METADATA:
                errors.append(
                    f"release manifest contains an unsafe file path at index {index}"
                )
                continue
            if not isinstance(expected_digest, str) or not re.fullmatch(
                r"[0-9a-f]{64}", expected_digest
            ):
                errors.append(
                    f"release manifest contains an invalid SHA-256 at index {index}"
                )
                continue
            manifest_files[relative] = expected_digest

    content_files = actual_files - RELEASE_METADATA
    if set(manifest_files) != content_files:
        errors.append("release file set does not exactly match the manifest")
    for relative in sorted(set(manifest_files) & content_files):
        try:
            actual_digest = _sha256(root / relative)
        except OSError:
            errors.append(f"release file could not be hashed: {relative}")
            continue
        if actual_digest != manifest_files[relative]:
            errors.append(f"release file hash does not match manifest: {relative}")

    try:
        sums_text = sums_path.read_bytes().decode("utf-8")
    except (OSError, UnicodeError):
        errors.append("release checksum file is unavailable or invalid")
        return errors
    if not sums_text.endswith("\n"):
        errors.append("release checksum file must end with a newline")
        checksum_lines = sums_text.split("\n")
    else:
        checksum_lines = sums_text[:-1].split("\n")
    checksum_entries: dict[str, str] = {}
    for index, line in enumerate(checksum_lines):
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None or not _safe_release_path(match.group(2)):
            errors.append(f"release checksum line {index + 1} is invalid")
            continue
        relative = match.group(2)
        if relative in checksum_entries:
            errors.append(
                f"release checksum file contains a duplicate path at line {index + 1}"
            )
            continue
        checksum_entries[relative] = match.group(1)

    expected_checksum_paths = set(manifest_files) | {"release-manifest.json"}
    if set(checksum_entries) != expected_checksum_paths:
        errors.append("release checksum file does not exactly cover manifest files")
    expected_checksums = dict(manifest_files)
    try:
        expected_checksums["release-manifest.json"] = _sha256(manifest_path)
    except OSError:
        errors.append("release manifest could not be hashed")
    for relative in sorted(set(checksum_entries) & set(expected_checksums)):
        if checksum_entries[relative] != expected_checksums[relative]:
            errors.append(f"release checksum hash does not match: {relative}")
    return errors


def check(root: Path = ROOT) -> list[str]:
    integrity_errors = _release_tree_integrity_errors(root)
    if integrity_errors:
        return integrity_errors

    try:
        files = _tracked_release_files(root)
    except Exception as exc:
        return [f"public release source selection is unavailable or invalid: {exc}"]
    errors = _version_invariant_errors(root)
    relative_files = {path.relative_to(root).as_posix() for path in files}
    for relative in sorted(REQUIRED_RELEASE_PATHS):
        if not (root / relative).is_file():
            errors.append(f"required release artifact is missing: {relative}")
        elif relative not in relative_files:
            errors.append(f"required release artifact is outside allowlist: {relative}")

    forbidden_names = {
        "vault.json", "inventory.json", "egress-policy.json", "runner.json",
        "known_hosts", ".env",
    }
    private_markers = (
        re.compile(r"begin\s+private\s+key", re.IGNORECASE),
        re.compile(r"/workspace(?:/|$)", re.IGNORECASE),
        re.compile(r"/home/[a-z0-9](?:[a-z0-9._-]{0,61}[a-z0-9])?(?:/|$)", re.IGNORECASE),
    )
    topology_markers = (
        re.compile(r"\brpi(?:[-_ ]?\d+)?[-_][a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?\b", re.IGNORECASE),
        re.compile(r"\braspberry(?:\s+|[-_]+)pi\b", re.IGNORECASE),
        re.compile(r"\b(?:home|local|personal|private)[-_ ]+lab\b", re.IGNORECASE),
        re.compile(r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?-(?:mcp|readonly)\b", re.IGNORECASE),
    )
    agent_vendor_markers = (
        re.compile(r"\bcodex\b", re.IGNORECASE),
        re.compile(r"\bopenai\b", re.IGNORECASE),
        re.compile(r"\bchatgpt\b", re.IGNORECASE),
        re.compile(r"\bclaude\b", re.IGNORECASE),
        re.compile(r"\banthropic\b", re.IGNORECASE),
    )
    private_ipv4 = re.compile(
        r"(?<![0-9])(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.(?:\d{1,3}\.)\d{1,3}|"
        r"172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3})(?![0-9])"
    )
    hardcoded_trust_file = re.compile(
        r"/(?:usr/local/share/ca-certificates|etc/netops-helper/certs)/[^\s\"'`]+\.(?:crt|cer|pem)"
    )
    for path in files:
        relative = path.relative_to(root)
        if any(marker.search(relative.as_posix()) for marker in agent_vendor_markers):
            errors.append(f"agent-vendor-specific path in {relative}")
        if any(
            marker.search(relative.as_posix())
            for marker in (*private_markers, *topology_markers)
        ):
            errors.append(f"private marker in release path: {relative}")
        if path.name in forbidden_names:
            errors.append(f"private configuration included: {relative}")
        if path.suffix.lower() in {".crt", ".cer", ".key", ".p12", ".pfx", ".pem"}:
            errors.append(f"environment-specific key/certificate included: {relative}")
        if path.suffix.lower() in TEXT_SUFFIXES:
            text = path.read_text(encoding="utf-8", errors="replace")
            for marker in (*private_markers, *topology_markers, *agent_vendor_markers):
                if marker.search(text):
                    errors.append(f"private marker in {relative}")
            if private_ipv4.search(text):
                errors.append(f"private IPv4 address in {relative}")
            errors.extend(_secret_and_network_marker_errors(relative.as_posix(), text))
            if hardcoded_trust_file.search(text):
                errors.append(f"hard-coded environment trust file in {relative}")

    for trust_directory in (root / "config/container/ca", root / "config/container/certs"):
        if trust_directory.exists():
            for trust_path in trust_directory.iterdir():
                if trust_path.is_file() and trust_path.name != ".gitkeep":
                    errors.append(
                        "environment-specific trust material present: "
                        f"{trust_path.relative_to(root)}"
                    )

    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    first = dockerfile.splitlines()[0]
    if not re.fullmatch(r"FROM python:[^@\s]+@sha256:[0-9a-f]{64}", first):
        errors.append("Dockerfile base image is not digest-pinned")
    if "pip install --no-cache-dir --upgrade" in dockerfile:
        errors.append("Dockerfile contains a moving package-manager operation")
    apt_lines = [line for line in dockerfile.splitlines() if "apt-get" in line]
    if apt_lines:
        expected_apt = [
            "    && apt-get update \\",
            "    && apt-get install --yes --no-install-recommends openssh-client \\",
        ]
        if apt_lines != expected_apt or "rm -rf /var/lib/apt/lists/*" not in dockerfile:
            errors.append(
                "Dockerfile installs a distribution package outside the reviewed"
                " openssh-client step"
            )
    if "--require-hashes -r requirements.lock" not in dockerfile:
        errors.append("Dockerfile does not enforce the dependency hash lock")

    for lock_name in ("requirements.lock", "requirements-release.lock"):
        lock = (root / lock_name).read_text(encoding="utf-8")
        active = "\n".join(
            line for line in lock.splitlines() if not line.lstrip().startswith("#")
        )
        if "--hash=sha256:" not in active:
            errors.append(f"{lock_name} does not enforce hashes")
        if any(
            marker in active
            for marker in ("http://", "file:", "--no-index", "--trusted-host")
        ):
            errors.append(f"{lock_name} contains an unsafe package source")

    release_input = {
        line.strip()
        for line in (root / "requirements-release.in").read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    expected_release_input = {
        "-r requirements.txt",
        "cyclonedx-bom==7.3.1",
        "pytest==9.1.1",
    }
    if release_input != expected_release_input:
        errors.append("requirements-release.in is not the reviewed release tool set")

    if (root / "plugin").exists():
        errors.append("agent-vendor-specific plugin directory is forbidden")
    source_root = root / "src/netops_helper"
    for removed_name in ("changes.py", "policy.py"):
        if (source_root / removed_name).exists():
            errors.append(f"phase-1 release contains removed write module: {removed_name}")
    errors.extend(_phase1_surface_errors(root))
    errors.extend(_ssh_wire_errors(root))
    errors.extend(_run_query_catalog_docs(root))
    errors.extend(_run_policy_parity(root))
    errors.extend(_compose_build_target_errors(root))
    return errors


def _severity(value: Any) -> str | None:
    return value if isinstance(value, str) and value in SEVERITIES else None


def check_grype_report(path: Path) -> tuple[list[str], dict[str, dict[str, int]]]:
    errors: list[str] = []
    counts = {
        "active": {severity: 0 for severity in SEVERITIES},
        "ignored": {severity: 0 for severity in SEVERITIES},
    }
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return ["Grype report is unavailable or invalid"], counts
    if not isinstance(document, dict):
        return ["Grype report root must be an object"], counts
    for field in ("matches", "ignoredMatches"):
        if field not in document or not isinstance(document[field], list):
            errors.append(f"Grype report must contain a {field} list")
    if errors:
        return errors, counts

    for field, category in (("matches", "active"), ("ignoredMatches", "ignored")):
        for index, finding in enumerate(document[field]):
            if not isinstance(finding, dict):
                errors.append(f"Grype {field} contains a non-object finding at index {index}")
                continue
            vulnerability = finding.get("vulnerability")
            if not isinstance(vulnerability, dict):
                errors.append(
                    f"Grype {field} finding at index {index} has no vulnerability object"
                )
                continue
            severity = _severity(vulnerability.get("severity"))
            if severity is None:
                errors.append(
                    f"Grype {field} finding at index {index} has an invalid severity"
                )
                continue
            counts[category][severity] += 1
            if category == "ignored" and severity == "Critical":
                rules = finding.get("appliedIgnoreRules")
                if not isinstance(rules, list) or not rules:
                    errors.append("ignored Critical finding has no appliedIgnoreRules")

    if counts["active"]["Critical"]:
        errors.append(
            f"Grype report contains {counts['active']['Critical']} active Critical findings"
        )
    return errors, counts


def _secret_and_network_marker_errors(relative: str, text: str) -> list[str]:
    errors: list[str] = []
    if any(marker.search(text) for marker in SECRET_MATERIAL_MARKERS):
        errors.append(f"credential-shaped material in {relative}")
    if not relative.startswith("tests/") and any(
        marker.search(text) for marker in PRIVATE_NETWORK_MARKERS
    ):
        errors.append(f"private network marker in {relative}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", type=Path, default=ROOT)
    parser.add_argument("--grype-report", type=Path)
    args = parser.parse_args()

    errors = check(args.root.resolve())
    summary: dict[str, dict[str, int]] | None = None
    if args.grype_report is not None:
        report_errors, summary = check_grype_report(args.grype_report.resolve())
        errors.extend(report_errors)
        print(
            "grype_findings="
            + json.dumps(summary, separators=(",", ":"), sort_keys=True)
        )
    if errors:
        for error in errors:
            print(f"public_release_check=failed detail={error}")
        return 1
    print("public_release_check=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
