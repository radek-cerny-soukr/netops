from __future__ import annotations

import json
import time
from functools import wraps
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def request_bytes(**fields) -> bytes:
    body = {
        "table": "firewall address",
        "op": "create",
        "key": "new-host",
        "changes": {"subnet": "192.0.2.30/32"},
        "reason": "operator asked for a host object",
        "user_request": "create an address object for the new host",
        "request_id": "req-0001-example",
    }
    body.update(fields)
    return json.dumps(body).encode("utf-8")


@pytest.fixture
def fortios_snapshot() -> bytes:
    return (FIXTURES / "fortios_8_0_0.conf").read_bytes()


@pytest.fixture
def exos_snapshot() -> bytes:
    return (FIXTURES / "exos_33_7_1.conf").read_bytes()


@pytest.fixture
def watch_export_status(monkeypatch):
    """Keep the simulated export status fresh before each operation on a wired device."""
    from netops_admin import execute

    exports = {}

    def with_fresh_export(operation):
        @wraps(operation)
        def run(runtime, *args, **kwargs):
            export = exports.get(runtime.config.export_status_file)
            if export is not None:
                status = json.loads(export.read_text())
                status["updated_at"] = time.time()
                export.write_text(json.dumps(status))
            return operation(runtime, *args, **kwargs)

        return run

    for name in ("preview", "apply", "preview_undo", "undo", "recover"):
        monkeypatch.setattr(execute, name, with_fresh_export(getattr(execute, name)))

    def watch(export):
        exports[str(export)] = export

    return watch


import importlib.util as _sandbox_import  # noqa: E402
import sys as _sandbox_sys  # noqa: E402
from pathlib import Path as _SandboxPath  # noqa: E402

_sandbox_spec = _sandbox_import.spec_from_file_location(
    "netops_sandbox_guard", _SandboxPath(__file__).with_name("_sandbox_guard.py")
)
_sandbox = _sandbox_import.module_from_spec(_sandbox_spec)
_sandbox_sys.modules[_sandbox_spec.name] = _sandbox
_sandbox_spec.loader.exec_module(_sandbox)
pytest_configure = _sandbox.pytest_configure
pytest_runtest_setup = _sandbox.pytest_runtest_setup
pytest_runtest_call = _sandbox.pytest_runtest_call
pytest_runtest_teardown = _sandbox.pytest_runtest_teardown
