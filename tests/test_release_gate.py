from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile

if not __debug__:
    raise RuntimeError("Assertions must be enabled")

ROOT = Path(__file__).resolve().parents[1]


def _load_except_coverage():
    path = ROOT / "scripts/except_branch_coverage.py"
    specification = importlib.util.spec_from_file_location("_netops_except_coverage", path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module



def _except_coverage_tools() -> str | None:
    for name in ("coverage", "pytest"):
        if importlib.util.find_spec(name) is None:
            return name
    return None



def test_except_branch_coverage_baseline_follows_the_source() -> None:
    gate = _load_except_coverage()
    baseline = json.loads(gate.BASELINE.read_text(encoding="utf-8"))
    assert sorted(baseline["components"]) == sorted(gate.MODULES)
    for component, modules in gate.MODULES.items():
        recorded = baseline["components"][component]
        assert sorted(recorded["modules"]) == sorted(modules), component
        for module in modules:
            source = (ROOT / "components" / component / "src" / module).read_text(encoding="utf-8")
            found = len(gate.branches_of(source))
            assert recorded["modules"][module]["branches_in_source"] == found, (
                "%s/%s has %d except/else branches; measure them and record the floor with "
                "scripts/except_branch_coverage.py --write-baseline" % (component, module, found)
            )



def test_except_branch_coverage_gate_refuses_a_lower_coverage() -> None:
    missing = _except_coverage_tools()
    if missing is not None:
        raise RuntimeError("except_branch_coverage=unavailable: %s is not installed" % missing)
    gate = _load_except_coverage()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        component = root / "components/demo"
        (component / "src/demo_pkg").mkdir(parents=True)
        (component / "tests").mkdir()
        (component / "src/demo_pkg/__init__.py").write_text("", encoding="utf-8")
        (component / "src/demo_pkg/state.py").write_text(
            "def load(text):\n"
            "    try:\n"
            "        value = int(text)\n"
            "    except ValueError:\n"
            "        return None\n"
            "    except TypeError:\n"
            "        return -1\n"
            "    else:\n"
            "        return value\n",
            encoding="utf-8",
        )
        (component / "tests/test_state.py").write_text(
            "import sys\n"
            "from pathlib import Path\n"
            "sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))\n"
            "from demo_pkg.state import load\n"
            "def test_load():\n"
            "    assert load('1') == 1\n"
            "    assert load('x') is None\n",
            encoding="utf-8",
        )
        baseline = root / "baseline.json"
        gate.ROOT = root
        gate.MODULES = {"demo": ("demo_pkg/state.py",)}
        assert gate.main(["demo", "--baseline", str(baseline), "--write-baseline"]) == 0
        recorded = json.loads(baseline.read_text(encoding="utf-8"))["components"]["demo"]
        assert (recorded["branches"], recorded["covered"], recorded["min_percent"]) == (3, 2, 66)
        assert gate.main(["demo", "--baseline", str(baseline)]) == 0
        assert gate.main(["demo", "--baseline", str(baseline), "--min", "67"]) == 1
        recorded["modules"]["demo_pkg/state.py"]["min_percent"] = 67
        baseline.write_text(json.dumps({"components": {"demo": recorded}}), encoding="utf-8")
        assert gate.main(["demo", "--baseline", str(baseline)]) == 1
        assert gate.main(["demo", "--baseline", str(baseline), "--report-only"]) == 0



def test_except_branch_coverage_of_the_components_keeps_its_floor() -> None:
    missing = _except_coverage_tools()
    if missing is not None:
        raise RuntimeError("except_branch_coverage=unavailable: %s is not installed" % missing)
    if os.environ.get("NETOPS_EXCEPT_COVERAGE") != "1":
        raise RuntimeError("except_branch_coverage=unavailable: set NETOPS_EXCEPT_COVERAGE=1 to measure the four test suites")
    assert _load_except_coverage().main([]) == 0



def main() -> int:
    tests = [(name, function) for name, function in sorted(globals().items())
             if name.startswith("test_") and callable(function)]
    if len(tests) != 3:
        raise RuntimeError("Exactly three coverage controls required")
    for name, function in tests:
        function()
    print("repository_gate_tests=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
