#!/usr/bin/env python3
"""Export an allowlisted component tree and create deterministic release integrity metadata."""

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
NAME = "netops-auditor"
_VERSION_PATTERN = re.compile(
    r"[0-9]+\.[0-9]+\.[0-9]+(?:[.-][0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
)
EXACT = {
    "CHANGELOG.md", "LICENSE", "README.md", "pyproject.toml", "requirements-mcp.txt",
    "requirements-release.in", "requirements-release.lock", "sbom.cdx.json",
}
RECURSIVE_FILE_RULES = {
    "docs": frozenset({".md"}),
    "scripts": frozenset({".py"}),
    "src": frozenset({".json", ".py"}),
    "tests": frozenset({".conf", ".py", ".json"}),
}
EXECUTABLE = {
    "scripts/check_gates.py",
    "scripts/create_release_artifacts.py",
    "scripts/generate_sbom.py",
}


class ReleaseSelectionError(RuntimeError):
    pass


def _regular_file_stat(path: Path) -> os.stat_result:
    try:
        information = path.lstat()
    except OSError as exc:
        raise ReleaseSelectionError(f"component source entry is unavailable: {path.name}") from exc
    if not stat.S_ISREG(information.st_mode):
        raise ReleaseSelectionError(f"component source entry is not a regular file: {path.name}")
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
            raise ReleaseSelectionError("component source entry changed during selection")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            return handle.read()
    except OSError as exc:
        raise ReleaseSelectionError("component source entry could not be opened safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def project_version(root: Path = ROOT) -> str:
    """Return the validated component version from the canonical metadata."""
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
        raise RuntimeError("component metadata is unavailable or invalid") from exc
    if name != NAME or not isinstance(version, str):
        raise RuntimeError("component identity is invalid")
    if _VERSION_PATTERN.fullmatch(version) is None:
        raise RuntimeError("component version is invalid")
    return version


VERSION = project_version()


def _require_directory(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise ReleaseSelectionError("component source directory is unavailable") from exc
    if not stat.S_ISDIR(mode):
        raise ReleaseSelectionError("component source directory is not a directory")


def selected_files(root: Path = ROOT) -> list[Path]:
    chosen: list[Path] = []
    for relative in sorted(EXACT):
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
            for name in sorted(file_names):
                path = directory_path / name
                _regular_file_stat(path)
                if path.suffix.lower() not in RECURSIVE_FILE_RULES[tree_name]:
                    raise ReleaseSelectionError(
                        "recursive component source contains an unreviewed file type"
                    )
                chosen.append(path)
        if walk_errors:
            raise ReleaseSelectionError("recursive component source could not be traversed")

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
        for name in sorted(directory_names):
            _require_directory(directory_path / name)
        directory_names[:] = sorted(directory_names)
        for name in sorted(file_names):
            path = directory_path / name
            _regular_file_stat(path)
            chosen.append(path)
    if walk_errors:
        raise ReleaseSelectionError("release destination could not be traversed")
    return sorted(chosen, key=lambda item: item.relative_to(root).as_posix())


def digest(path: Path) -> str:
    return hashlib.sha256(_read_regular_bytes(path)).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    arguments = parser.parse_args()

    try:
        sources = selected_files()
    except ReleaseSelectionError:
        print("release_export=failed detail=component source selection rejected", file=sys.stderr)
        return 1

    output_root = Path(os.path.abspath(os.fspath(arguments.output)))
    try:
        output_root.mkdir(parents=True, exist_ok=True)
        _require_directory(output_root)
    except (OSError, ReleaseSelectionError):
        print("release_export=failed detail=destination is unavailable", file=sys.stderr)
        return 1

    destination = output_root / f"{NAME}-{VERSION}"
    try:
        destination.mkdir()
    except FileExistsError:
        print("release_export=failed detail=destination already exists", file=sys.stderr)
        return 1
    except OSError:
        print("release_export=failed detail=destination is unavailable", file=sys.stderr)
        return 1

    try:
        for source in sources:
            relative = source.relative_to(ROOT)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(_read_regular_bytes(source))
            target.chmod(0o755 if relative.as_posix() in EXECUTABLE else 0o644)
    except (OSError, ReleaseSelectionError):
        print("release_export=failed detail=component source copy rejected", file=sys.stderr)
        return 1

    try:
        entries = {
            path.relative_to(destination).as_posix(): digest(path)
            for path in _regular_tree_files(destination)
        }
    except ReleaseSelectionError:
        print("release_export=failed detail=release destination validation rejected", file=sys.stderr)
        return 1
    manifest = {
        "schema": 1,
        "name": NAME,
        "version": VERSION,
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
        [sys.executable, "-B", str(destination / "scripts/check_gates.py")],
        cwd=str(destination),
        check=False,
    )
    if completed.returncode:
        return completed.returncode

    bytecode = [
        path for path in _regular_tree_files(destination)
        if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}
    ]
    if bytecode:
        print("release_export=failed detail=python bytecode present", file=sys.stderr)
        return 1
    print(f"release_export=complete files={len(entries)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
