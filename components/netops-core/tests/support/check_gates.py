#!/usr/bin/env python3

from __future__ import annotations

import argparse
import ast
import os
import sys
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "netops_core"

GATE_ORDER = (
    "core_stdlib",
)


def _relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _package_modules(root: Path) -> list:
    directory = root / "src"
    modules = []
    for parent, directory_names, file_names in os.walk(directory, followlinks=False):
        directory_names[:] = sorted(
            name for name in directory_names if name != "__pycache__"
        )
        for name in sorted(file_names):
            if name.endswith(".py"):
                modules.append(Path(parent) / name)
    return sorted(modules)


def gate_core_stdlib(root: Path) -> list:
    directory = root / "src" / PACKAGE
    if not directory.is_dir():
        return ["package directory is missing: src/%s" % PACKAGE]
    allowed = set(sys.stdlib_module_names) | {PACKAGE}
    errors = []
    modules = _package_modules(root)
    if not modules:
        return ["package directory holds no module: src/%s" % PACKAGE]
    for path in modules:
        relative = _relative(root, path)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, SyntaxError) as error:
            errors.append("%s is unreadable or not valid Python: %s" % (relative, error))
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    continue
                names = [(node.module or "").split(".")[0]]
            else:
                continue
            for name in names:
                if not name or name in allowed:
                    continue
                errors.append(
                    "%s:%d imports a module outside the standard library: %s"
                    % (relative, node.lineno, name)
                )
    return errors


GATES = {
    "core_stdlib": gate_core_stdlib,
}


def check(root: Path) -> dict:
    return {name: GATES[name](root) for name in GATE_ORDER}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    if not root.is_dir():
        print("gate_root=failed detail=root is not a directory: %s" % root)
        print("core_gates=failed")
        return 2
    results = check(root)
    failed = False
    for name in GATE_ORDER:
        errors = results[name]
        if not errors:
            print("gate_%s=passed" % name)
            continue
        failed = True
        for error in errors:
            print("gate_%s=failed detail=%s" % (name, error))
    print("core_gates=%s" % ("failed" if failed else "passed"))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
