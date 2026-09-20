#!/usr/bin/env python3
"""Launcher for the stdio proxy: runs it from an unpacked archive without installing it."""

from __future__ import annotations

from pathlib import Path
import sys

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
for SOURCE_ROOT in (
    COMPONENT_ROOT / "src", COMPONENT_ROOT.parent / "netops-core" / "src",
):
    if SOURCE_ROOT.is_dir() and str(SOURCE_ROOT) not in sys.path:
        sys.path.insert(0, str(SOURCE_ROOT))

from netops_helper.proxy import main

if __name__ == "__main__":
    raise SystemExit(main())
