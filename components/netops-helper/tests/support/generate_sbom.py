#!/usr/bin/env python3
"""Generate a reproducible CycloneDX SBOM and connect the root to direct dependencies."""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "sbom.cdx.json"
PYPROJECT = ROOT / "pyproject.toml"
REQUIRED_PATTERN = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)==([0-9][0-9A-Za-z.+-]*)")


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def direct_names() -> set[str]:
    result = set()
    for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines():
        entry = line.strip()
        if entry and not entry.startswith("#"):
            result.add(canonical(re.split(r"[<=>!~\[]", entry, maxsplit=1)[0]))
    return result


def required_components(project: dict) -> list[dict]:
    result = []
    names = set()
    for entry in project.get("dependencies", []):
        found = REQUIRED_PATTERN.fullmatch(entry.strip())
        if found is None:
            raise RuntimeError(f"required dependency is not pinned with ==: {entry}")
        name, version = canonical(found.group(1)), found.group(2)
        if name in names:
            raise RuntimeError(f"duplicate required dependency: {name}")
        names.add(name)
        if name.startswith("netops-"):
            purl = f"pkg:pypi/{name}@{version}"
            result.append({
                "bom-ref": purl, "name": name, "version": version, "purl": purl,
                "type": "library", "scope": "required",
            })
    return sorted(result, key=lambda item: item["bom-ref"])


def connect_dependencies(document: dict, project: dict) -> None:
    required = required_components(project)
    root = document["metadata"]["component"]
    if (root.get("name"), root.get("version")) != (project["name"], project["version"]):
        raise RuntimeError("SBOM root identity does not come from the project metadata")
    components = document.setdefault("components", [])
    dependencies = document.setdefault("dependencies", [])
    for component in required:
        existing = [item for item in components if canonical(item["name"]) == component["name"]]
        if existing and existing != [component]:
            raise RuntimeError(f"SBOM internal dependency identity does not match: {component['name']}")
        if not existing:
            components.append(component)
        nodes = [item for item in dependencies if item["ref"] == component["bom-ref"]]
        if nodes and nodes != [{"ref": component["bom-ref"], "dependsOn": []}]:
            raise RuntimeError(f"SBOM internal dependency graph does not match: {component['name']}")
        if not nodes:
            dependencies.append({"ref": component["bom-ref"], "dependsOn": []})
    direct = direct_names() | {item["name"] for item in required}
    pins = {
        canonical(found.group(1)): found.group(2)
        for entry in project.get("dependencies", [])
        for found in [REQUIRED_PATTERN.fullmatch(entry.strip())]
    }
    if set(pins) != direct:
        raise RuntimeError("project and requirements disagree on direct dependencies")
    matched = [item for item in components if canonical(item["name"]) in direct]
    if len(matched) != len(direct):
        raise RuntimeError("SBOM is missing or duplicates one or more direct dependencies")
    if any(item.get("version") != pins[canonical(item["name"])] for item in matched):
        raise RuntimeError("SBOM direct dependency version does not match the project pin")
    root_dependencies = [item for item in dependencies if item.get("ref") == root["bom-ref"]]
    if len(root_dependencies) != 1:
        raise RuntimeError("SBOM must have exactly one root dependency node")
    root_dependencies[0]["dependsOn"] = sorted(item["bom-ref"] for item in matched)
    document["components"] = sorted(components, key=lambda item: (canonical(item["name"]), item["bom-ref"]))
    document["dependencies"] = sorted(dependencies, key=lambda item: item["ref"])


def main() -> int:
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    required_components(project)
    subprocess.run([
        sys.executable, "-m", "cyclonedx_py", "requirements", str(ROOT / "requirements.lock"),
        "--pyproject", str(PYPROJECT), "--mc-type", "application",
        "--sv", "1.6", "--output-reproducible", "--of", "JSON", "-o", str(OUTPUT),
    ], check=True)
    document = json.loads(OUTPUT.read_text(encoding="utf-8"))
    connect_dependencies(document, project)
    OUTPUT.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"sbom_generation=complete components={len(document.get('components', []))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
