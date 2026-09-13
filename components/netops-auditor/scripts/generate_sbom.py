#!/usr/bin/env python3
"""Generate a reproducible CycloneDX SBOM stating the component has no required dependency."""

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


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def optional_names() -> set[str]:
    result = set()
    for line in OPTIONAL_REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        entry = line.strip()
        if entry and not entry.startswith("#"):
            result.add(canonical(re.split(r"[<=>!~\[]", entry, maxsplit=1)[0]))
    return result


def main() -> int:
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    if project.get("dependencies"):
        raise RuntimeError("component declares a required dependency the SBOM would not carry")
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
    root_dependency = next(
        item for item in document.get("dependencies", []) if item.get("ref") == root["bom-ref"]
    )
    root_dependency["dependsOn"] = []
    OUTPUT.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"sbom_generation=complete components={len(document.get('components', []))}"
        f" required=0 optional={len(marked)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
