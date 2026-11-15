from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_gate():
    spec = importlib.util.spec_from_file_location(
        "check_public_release_phase1_source",
        ROOT / "tests" / "support" / "check_public_release.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_phase1_surface_gate_passes_on_real_helper_source() -> None:
    """Run the real phase-1 gate over the real component root (as ref/phase1_diag.py does)."""
    errors = _load_gate()._phase1_surface_errors(ROOT)
    assert errors == [], "phase-1 gate findings:\n" + "\n".join(errors)
