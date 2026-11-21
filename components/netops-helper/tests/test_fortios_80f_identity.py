"""fortios_diagnostics is tested on FortiGate-80F 8.0.2 build 0251; a neighbouring build runs with a warning (G00)."""

from __future__ import annotations

import importlib.util
import pathlib

import pytest

_spec = importlib.util.spec_from_file_location("diag_support", pathlib.Path(__file__).with_name("test_fortios_diagnostics.py"))
_support = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_support)
d = _support.d
Shell = _support.Shell

STATUS = "Version: FortiGate-80F v8.0.2,build0251,260928 (GA.F)"


def test_the_80f_identity_is_measured_for_recipes_and_tuples() -> None:
    assert ("FortiGate-80F", "8.0.2", "0251") in d.IDENTITIES
    assert ("FortiGate-80F", "8.0.2", "0251") in d.TUPLE_IDENTITIES
    assert ("FortiGate-80F", "8.0.2", "0251") not in d.RANGE_TUPLE_IDENTITIES


@pytest.mark.parametrize("recipe", ["ping", "sessions"])
def test_the_80f_runs_a_recipe(recipe) -> None:
    shell = Shell(recipe)
    shell.status_line = STATUS
    d.run(shell, recipe, _support.IP, _support.INTERFACE, 2, 1)


@pytest.mark.parametrize("status", [
    "Version: FortiGate-80F v8.0.2,build0250,260928 (GA.F)",
    "Version: FortiGate-80F v8.0.1,build0251,260928 (GA.F)",
    "Version: FortiGate-81F v8.0.2,build0251,260928 (GA.F)",
])
def test_another_80f_build_runs_untested(status) -> None:
    shell = Shell("ping")
    shell.status_line = status
    support = []
    result, _, _, _ = d.run(shell, "ping", _support.IP, _support.INTERFACE, 2, 1, support=support)
    assert result == "untrusted device output"
    assert support[0]["status"] == "untested"
    assert "FortiGate-80F 8.0.2 build0251" in support[0]["tested_versions"]


def test_the_80f_build_is_tested() -> None:
    shell = Shell("ping")
    shell.status_line = STATUS
    support = []
    d.run(shell, "ping", _support.IP, _support.INTERFACE, 2, 1, support=support)
    assert support[0]["status"] == "tested"
