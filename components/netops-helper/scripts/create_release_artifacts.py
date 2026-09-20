#!/usr/bin/env python3
"""Export an allowlisted public tree and create deterministic release integrity metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]
_VERSION_PATTERN = re.compile(
    r"[0-9]+\.[0-9]+\.[0-9]+(?:[.-][0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
)


class ReleaseSelectionError(RuntimeError):
    pass


def _regular_file_stat(path: Path) -> os.stat_result:
    try:
        information = path.lstat()
    except OSError as exc:
        raise ReleaseSelectionError(f"public source entry is unavailable: {path.name}") from exc
    if not stat.S_ISREG(information.st_mode):
        raise ReleaseSelectionError(f"public source entry is not a regular file: {path.name}")
    return information


def _read_regular_bytes(path: Path) -> bytes:
    before = _regular_file_stat(path)
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(after.st_mode)
            or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise ReleaseSelectionError("public source entry changed during selection")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            return handle.read()
    except OSError as exc:
        raise ReleaseSelectionError("public source entry could not be opened safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def project_version(root: Path = ROOT) -> str:
    """Return the validated project version from the canonical metadata."""
    try:
        project = tomllib.loads(
            _read_regular_bytes(root / "pyproject.toml").decode("utf-8")
        )["project"]
        name = project["name"]
        version = project["version"]
    except (
        ReleaseSelectionError,
        UnicodeError,
        tomllib.TOMLDecodeError,
        KeyError,
        TypeError,
    ) as exc:
        raise RuntimeError("project metadata is unavailable or invalid") from exc
    if name != "netops-helper" or not isinstance(version, str):
        raise RuntimeError("project identity is invalid")
    if _VERSION_PATTERN.fullmatch(version) is None:
        raise RuntimeError("project version is invalid")
    return version


VERSION = project_version()
EXACT = {
    ".gitignore", "CHANGELOG.md", "Dockerfile",
    "LICENSE", "README.md", "compose.yaml", "pyproject.toml",
    "requirements.txt", "requirements.lock", "requirements-release.in",
    "requirements-release.lock", "sbom.cdx.json",
}
TESTS = {
    "tests/conftest.py", "tests/run_tests.py", "tests/test_apply_egress_rules.py",
    "tests/test_audit_rotation.py", "tests/test_egress_scripts.py",
    "tests/test_engine_contracts.py", "tests/test_engine_safety.py",
    "tests/test_ssh_wire_safety.py",
    "tests/test_connection_pacing.py",
    "tests/test_phase1_surface.py",
    "tests/test_plain_ftp_acknowledgement.py", "tests/test_policy_parity.py",
    "tests/test_proxy.py", "tests/test_proxy_contracts.py",
    "tests/test_query_catalog_arista.py", "tests/test_query_catalog_cisco.py",
    "tests/test_query_catalog_extreme.py", "tests/test_query_catalog_fortinet.py",
    "tests/test_query_catalog_junos.py", "tests/test_query_catalog_ruckus.py",
    "tests/test_query_catalog_docs.py",
    "tests/test_vendor_references.py",
    "tests/test_sanitize.py", "tests/test_security.py",
    "tests/test_sftp_safety.py", "tests/test_supply_chain.py",
    "tests/test_check_operator_config.py",
}
SCRIPTS = {
    "scripts/apply_egress_rules.py", "scripts/check_egress_rules.py",
    "scripts/check_public_release.py", "scripts/create_release_artifacts.py",
    "scripts/generate_egress_rules.py", "scripts/generate_sbom.py",
    "scripts/render_query_catalog_docs.py", "scripts/remote_mcp_proxy.py",
    "scripts/check_operator_config.py",
    "src/netops_helper/proxy.py",
}


CORE_PACKAGE = ROOT.parent / "netops-core" / "src" / "netops_core"
CORE_DESTINATION = "src/netops_core"
CORE_EXECUTABLE = frozenset({"askpass.py"})

COMPOSE_REPOSITORY_BUILD_BLOCK = (
    "    build:\n"
    "      context: ../..\n"
    "      dockerfile: components/netops-helper/Dockerfile\n"
    "      args:\n"
    "        COMPONENT_DIR: components/netops-helper\n"
    "        CORE_PACKAGE_DIR: components/netops-core/src/netops_core\n"
)
COMPOSE_EXPORT_BUILD_BLOCK = (
    "    build:\n"
    "      context: .\n"
)


PUBLIC_CONFIG_FILES = frozenset({
    "config/container/ca/.gitkeep",
    "config/container/certs/.gitkeep",
    "config/container/tls-pins.json",
    "config/egress-policy.example.json",
    "config/inventory.example.json",
    "config/runner.example.json",
    "config/vault.example.json",
})
OPERATOR_FILES = frozenset({
    "config/inventory.json",
    "config/egress-policy.json",
    "config/runner.json",
    "config/vault.json",
})
RECURSIVE_FILE_RULES = {
    "config": (frozenset(), frozenset()),
    "docs": (frozenset({".json", ".md"}), frozenset()),
    "src": (frozenset({".py"}), frozenset()),
}


def _intentionally_excluded(relative: str) -> bool:
    path = Path(relative)
    if relative in OPERATOR_FILES:
        return True
    if relative.startswith(("config/container/certs/", "config/container/ca/")):
        return path.name != ".gitkeep"
    return False


def _recursive_file_allowed(tree_name: str, path: Path, relative: str) -> bool:
    if tree_name == "config":
        return relative in PUBLIC_CONFIG_FILES
    suffixes, names = RECURSIVE_FILE_RULES[tree_name]
    return path.name in names or path.suffix.lower() in suffixes


def _require_directory(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise ReleaseSelectionError("public source directory is unavailable") from exc
    if not stat.S_ISDIR(mode):
        raise ReleaseSelectionError("public source directory is not a directory")


def selected_files(root: Path = ROOT) -> list[Path]:
    chosen: list[Path] = []
    for relative in sorted(EXACT | TESTS | SCRIPTS):
        path = root / relative
        _regular_file_stat(path)
        chosen.append(path)

    for tree_name in sorted(RECURSIVE_FILE_RULES):
        tree_root = root / tree_name
        _require_directory(tree_root)
        walk_errors: list[OSError] = []
        for directory, directory_names, file_names in os.walk(
            tree_root,
            topdown=True,
            onerror=walk_errors.append,
            followlinks=False,
        ):
            directory_path = Path(directory)
            retained_directories: list[str] = []
            for name in sorted(directory_names):
                _require_directory(directory_path / name)
                if name != "__pycache__":
                    retained_directories.append(name)
            directory_names[:] = retained_directories
            file_names.sort()
            for name in file_names:
                path = directory_path / name
                relative = path.relative_to(root).as_posix()
                _regular_file_stat(path)
                if _intentionally_excluded(relative):
                    continue
                if not _recursive_file_allowed(tree_name, path, relative):
                    raise ReleaseSelectionError(
                        "recursive public source contains an unreviewed file type"
                    )
                chosen.append(path)
        if walk_errors:
            raise ReleaseSelectionError("recursive public source could not be traversed")

    return sorted(chosen, key=lambda item: item.relative_to(root).as_posix())


def _regular_tree_files(root: Path) -> list[Path]:
    _require_directory(root)
    chosen: list[Path] = []
    walk_errors: list[OSError] = []
    for directory, directory_names, file_names in os.walk(
        root,
        topdown=True,
        onerror=walk_errors.append,
        followlinks=False,
    ):
        directory_path = Path(directory)
        retained_directories: list[str] = []
        for name in sorted(directory_names):
            child = directory_path / name
            _require_directory(child)
            retained_directories.append(name)
        directory_names[:] = retained_directories
        for name in sorted(file_names):
            path = directory_path / name
            _regular_file_stat(path)
            chosen.append(path)
    if walk_errors:
        raise ReleaseSelectionError("release destination could not be traversed")
    return sorted(chosen, key=lambda item: item.relative_to(root).as_posix())


def digest(path: Path) -> str:
    return hashlib.sha256(_read_regular_bytes(path)).hexdigest()


def _rewrite_export_compose(destination: Path) -> None:
    compose_path = destination / "compose.yaml"
    text = _read_regular_bytes(compose_path).decode("utf-8")
    if text.count(COMPOSE_REPOSITORY_BUILD_BLOCK) != 1:
        raise ReleaseSelectionError("compose build block is not the known one")
    compose_path.write_text(
        text.replace(COMPOSE_REPOSITORY_BUILD_BLOCK, COMPOSE_EXPORT_BUILD_BLOCK, 1),
        encoding="utf-8",
    )
    compose_path.chmod(0o644)


def _prepare_output_root(path: Path) -> Path:
    output_root = Path(os.path.abspath(os.fspath(path)))
    parts = output_root.parts
    if not parts or not output_root.is_absolute():
        raise ReleaseSelectionError("release output path is invalid")

    current = Path(output_root.anchor)
    _require_directory(current)
    remaining = parts[1:]
    for index, name in enumerate(remaining):
        current /= name
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            if index != len(remaining) - 1:
                raise ReleaseSelectionError(
                    "release output parent is unavailable"
                )
            try:
                current.mkdir()
            except OSError as exc:
                raise ReleaseSelectionError(
                    "release output directory could not be created"
                ) from exc
            _require_directory(current)
            return output_root
        except OSError as exc:
            raise ReleaseSelectionError(
                "release output path is unavailable"
            ) from exc
        if not stat.S_ISDIR(mode):
            raise ReleaseSelectionError(
                "release output path component is not a directory"
            )
    return output_root


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    parser.add_argument("--image-digest")
    args = parser.parse_args()
    if args.image_digest and not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image_digest):
        parser.error("--image-digest must be sha256:<64 lowercase hex digits>")

    try:
        sources = selected_files()
    except ReleaseSelectionError:
        print(
            "release_export=failed detail=public source selection rejected",
            file=sys.stderr,
        )
        return 1

    try:
        output_root = _prepare_output_root(args.output)
    except ReleaseSelectionError:
        print(
            "release_export=failed detail=destination is unavailable",
            file=sys.stderr,
        )
        return 1

    destination = output_root / f"netops-helper-{VERSION}"
    try:
        destination.mkdir()
    except FileExistsError:
        print(
            "release_export=failed detail=destination already exists",
            file=sys.stderr,
        )
        return 1
    except OSError:
        print(
            "release_export=failed detail=destination is unavailable",
            file=sys.stderr,
        )
        return 1

    try:
        for source in sources:
            relative = source.relative_to(ROOT)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(_read_regular_bytes(source))
            target.chmod(0o755 if relative.as_posix() in SCRIPTS else 0o644)
    except (OSError, ReleaseSelectionError):
        print(
            "release_export=failed detail=public source copy rejected",
            file=sys.stderr,
        )
        return 1

    try:
        for source in sorted(CORE_PACKAGE.rglob("*.py")):
            if "__pycache__" in source.parts:
                continue
            _regular_file_stat(source)
            target = destination / CORE_DESTINATION / source.relative_to(CORE_PACKAGE)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(_read_regular_bytes(source))
            target.chmod(0o755 if source.name in CORE_EXECUTABLE else 0o644)
    except (OSError, ReleaseSelectionError):
        print(
            "release_export=failed detail=shared access layer copy rejected",
            file=sys.stderr,
        )
        return 1

    try:
        _rewrite_export_compose(destination)
    except (OSError, ReleaseSelectionError, UnicodeError):
        print(
            "release_export=failed detail=compose build block is not the known one",
            file=sys.stderr,
        )
        return 1

    try:
        from_line = _read_regular_bytes(destination / "Dockerfile").decode(
            "utf-8"
        ).splitlines()[0]
        base_digest = from_line.rsplit("@", 1)[1]
        entries = {
            path.relative_to(destination).as_posix(): digest(path)
            for path in _regular_tree_files(destination)
        }
    except (ReleaseSelectionError, UnicodeError, IndexError):
        print(
            "release_export=failed detail=release destination validation rejected",
            file=sys.stderr,
        )
        return 1
    manifest = {
        "schema": 1,
        "name": "netops-helper",
        "version": VERSION,
        "base_image_digest": base_digest,
        "image_digest": args.image_digest,
        "files": entries,
    }
    manifest_path = destination / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    manifest_path.chmod(0o644)

    checksum_entries = {**entries, "release-manifest.json": digest(manifest_path)}
    sums = "".join(f"{value}  {name}\n" for name, value in sorted(checksum_entries.items()))
    (destination / "SHA256SUMS").write_text(sums)
    (destination / "SHA256SUMS").chmod(0o644)

    completed = subprocess.run(
        [sys.executable, "-B", str(destination / "scripts/check_public_release.py"), str(destination)],
        check=False,
    )
    if completed.returncode:
        return completed.returncode
    try:
        destination_files = _regular_tree_files(destination)
    except ReleaseSelectionError:
        print(
            "release_export=failed detail=release destination validation rejected",
            file=sys.stderr,
        )
        return 1
    bytecode = [
        path for path in destination_files
        if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}
    ]
    if bytecode:
        print("release_export=failed detail=python bytecode present", file=sys.stderr)
        return 1
    print(f"release_export=complete files={len(entries)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
