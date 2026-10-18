#!/usr/bin/env python3
"""Generate a reproducible CycloneDX SBOM stating the library has no dependency at all."""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "sbom.cdx.json"
PYPROJECT = ROOT / "pyproject.toml"


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def main() -> int:
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    if project.get("dependencies"):
        raise RuntimeError("component declares a required dependency the SBOM would not carry")
    with tempfile.TemporaryDirectory() as directory:
        empty = Path(directory) / "requirements.txt"
        empty.write_text("", encoding="utf-8")
        subprocess.run([
            sys.executable, "-m", "cyclonedx_py", "requirements", str(empty),
            "--pyproject", str(PYPROJECT), "--mc-type", "library",
            "--sv", "1.6", "--output-reproducible", "--of", "JSON", "-o", str(OUTPUT),
        ], check=True)
    document = json.loads(OUTPUT.read_text(encoding="utf-8"))
    root = document["metadata"]["component"]
    if (root.get("name"), root.get("version")) != (project["name"], project["version"]):
        raise RuntimeError("SBOM root identity does not come from the project metadata")
    if document.get("components"):
        raise RuntimeError("SBOM carries a component the library does not depend on")
    root["purl"] = f"pkg:pypi/{canonical(project['name'])}@{project['version']}"
    root_dependency = next(
        item for item in document.get("dependencies", []) if item.get("ref") == root["bom-ref"]
    )
    root_dependency["dependsOn"] = []
    OUTPUT.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("sbom_generation=complete components=0 required=0 optional=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
