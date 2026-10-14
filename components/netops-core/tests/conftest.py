import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


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
