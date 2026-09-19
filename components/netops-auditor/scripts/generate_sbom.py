#!/usr/bin/env python3
"""Generate a reproducible CycloneDX SBOM carrying the required and optional dependencies."""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "sbom.cdx.json"
PYPROJECT = ROOT / "pyproject.toml"
OPTIONAL_REQUIREMENTS = ROOT / "requirements-mcp.txt"
REQUIRED_PATTERN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([0-9][0-9A-Za-z.+-]*)$")


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def optional_names() -> set[str]:
    result = set()
    for line in OPTIONAL_REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        entry = line.strip()
        if entry and not entry.startswith("#"):
            result.add(canonical(re.split(r"[<=>!~\[]", entry, maxsplit=1)[0]))
    return result


def required_components(project: dict) -> list:
    result = []
    for entry in project.get("dependencies", []):
        found = REQUIRED_PATTERN.match(entry.strip())
        if found is None:
            raise RuntimeError(f"required dependency is not pinned with ==: {entry}")
        name, version = found.group(1), found.group(2)
        purl = f"pkg:pypi/{canonical(name)}@{version}"
        result.append({
            "bom-ref": purl,
            "name": name,
            "version": version,
            "purl": purl,
            "type": "library",
            "scope": "required",
        })
    return result


def main() -> int:
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    required = required_components(project)
    subprocess.run([
        sys.executable, "-m", "cyclonedx_py", "requirements", str(OPTIONAL_REQUIREMENTS),
        "--pyproject", str(PYPROJECT), "--mc-type", "application",
        "--sv", "1.6", "--output-reproducible", "--of", "JSON", "-o", str(OUTPUT),
    ], check=True)
    document = json.loads(OUTPUT.read_text(encoding="utf-8"))
    root = document["metadata"]["component"]
    if (root.get("name"), root.get("version")) != (project["name"], project["version"]):
        raise RuntimeError("SBOM root identity does not come from the project metadata")
    root["purl"] = f"pkg:pypi/{canonical(project['name'])}@{project['version']}"
    optional = optional_names()
    marked = sorted(
        component["bom-ref"] for component in document.get("components", [])
        if canonical(component.get("name", "")) in optional
    )
    if len(marked) != len(optional):
        raise RuntimeError("SBOM is missing one or more optional dependencies")
    for component in document.get("components", []):
        if component["bom-ref"] in marked:
            component["scope"] = "optional"
    document["components"] = sorted(
        document.get("components", []) + required, key=lambda item: item["bom-ref"]
    )
    root_dependency = next(
        item for item in document.get("dependencies", []) if item.get("ref") == root["bom-ref"]
    )
    root_dependency["dependsOn"] = sorted(component["bom-ref"] for component in required)
    document["dependencies"] = sorted(
        document.get("dependencies", [])
        + [{"ref": component["bom-ref"], "dependsOn": []} for component in required],
        key=lambda item: item["ref"],
    )
    OUTPUT.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"sbom_generation=complete components={len(document.get('components', []))}"
        f" required={len(required)} optional={len(marked)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
