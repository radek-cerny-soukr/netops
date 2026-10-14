#!/usr/bin/env python3
"""Gate on the coverage of the except branches of the modules that keep security state.

Runs the test suite of one component under coverage.py with branch measurement and reports,
per module, every `except` handler and every `else:` of a `try` statement: how many there
are, how many the suite entered and the lines of those it never entered. A handler counts
as entered when the first statement of its body ran. The run fails when the coverage of a
module or of the component falls below the floor recorded in except_branch_coverage.json,
so a change can never lower it; --min overrides the component floor, --report-only prints
without judging and --write-baseline records the measured floors.
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass, field
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BASELINE = Path(__file__).with_suffix(".json")
MODULES = {
    "netops-auditor": ("netops_auditor/collect.py", "netops_auditor/store.py", "netops_auditor/cli.py"),
    "netops-admin": ("netops_admin/execute.py", "netops_admin/notify.py", "netops_admin/state.py", "netops_admin/audit.py"),
    "netops-helper": ("netops_helper/proxy.py", "netops_helper/engine.py"),
    "netops-core": ("netops_core/audit.py", "netops_core/ssh.py", "netops_core/session.py"),
}
PYTEST = ("-m", "pytest", "-q", "-p", "no:cacheprovider")


@dataclass
class Branch:
    kind: str
    line: int
    body: tuple[int, ...]


@dataclass
class ModuleResult:
    module: str
    branches: list[Branch]
    covered: list[Branch] = field(default_factory=list)
    missed: list[Branch] = field(default_factory=list)
    excluded: list[Branch] = field(default_factory=list)

    @property
    def counted(self) -> int:
        return len(self.covered) + len(self.missed)

    @property
    def percent(self) -> float:
        return 100.0 * len(self.covered) / self.counted if self.counted else 100.0


def _body_lines(statements: list[ast.stmt]) -> tuple[int, ...]:
    return tuple(statement.lineno for statement in statements)


def branches_of(source: str) -> list[Branch]:
    found: list[Branch] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.Try, ast.TryStar)):
            for handler in node.handlers:
                found.append(Branch("except", handler.lineno, _body_lines(handler.body)))
            if node.orelse:
                found.append(Branch("else", node.orelse[0].lineno, _body_lines(node.orelse)))
    return sorted(found, key=lambda branch: (branch.line, branch.kind))


def _coverage_config(directory: Path, source: Path, data: Path) -> Path:
    import coverage

    lines = ["[run]", "branch = True", "parallel = True", "data_file = %s" % data, "source =", "    %s" % source]
    if tuple(int(part) for part in coverage.__version__.split(".")[:2]) >= (7, 10):
        lines.append("patch = subprocess")
    rc = directory / "coveragerc"
    rc.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return rc


def measure(component: str, pytest_args: list[str], log) -> tuple[list[ModuleResult], int]:
    import coverage

    component_root = ROOT / "components" / component
    package = component_root / "src" / MODULES[component][0].split("/", 1)[0]
    with tempfile.TemporaryDirectory(prefix="except-coverage-") as directory:
        workspace = Path(directory)
        data = workspace / "coverage.data"
        rc = _coverage_config(workspace, package, data)
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", COVERAGE_RCFILE=str(rc))
        completed = subprocess.run(
            [sys.executable, "-B", "-m", "coverage", "run", "--rcfile", str(rc), *PYTEST, *pytest_args],
            cwd=component_root, env=environment, stdout=log, stderr=subprocess.STDOUT, check=False,
        )
        measured = coverage.Coverage(config_file=str(rc), data_file=str(data))
        measured.combine(data_paths=[str(workspace)], keep=False)
        measured.load()
        results = []
        for relative in MODULES[component]:
            path = component_root / "src" / relative
            result = ModuleResult(relative, branches_of(path.read_text(encoding="utf-8")))
            _, statements, _, missing, _ = measured.analysis2(str(path))
            executed = set(statements) - set(missing)
            for branch in result.branches:
                lines = [line for line in branch.body if line in statements]
                if not lines:
                    result.excluded.append(branch)
                elif lines[0] in executed:
                    result.covered.append(branch)
                else:
                    result.missed.append(branch)
            results.append(result)
    return results, completed.returncode


def _floor(value: float) -> int:
    return int(math.floor(value + 1e-9))


def _total(results: list[ModuleResult]) -> tuple[int, int]:
    return sum(len(result.covered) for result in results), sum(result.counted for result in results)


def render(component: str, results: list[ModuleResult]) -> str:
    rows = ["| component | module | except/else branches | covered | not covered | % | not covered (line:kind) |",
            "|---|---|---|---|---|---|---|"]
    for result in results:
        missed = ", ".join("%d:%s" % (branch.line, branch.kind) for branch in result.missed) or "-"
        rows.append("| %s | %s | %d | %d | %d | %.1f | %s |" % (
            component, result.module, result.counted, len(result.covered), len(result.missed), result.percent, missed))
    covered, counted = _total(results)
    rows.append("| %s | **total** | %d | %d | %d | %.1f | |" % (
        component, counted, covered, counted - covered, 100.0 * covered / counted if counted else 100.0))
    return "\n".join(rows)


def judge(component: str, results: list[ModuleResult], baseline: dict, minimum: float | None) -> list[str]:
    recorded = baseline.get("components", {}).get(component)
    if recorded is None:
        return ["no baseline recorded for %s; run with --write-baseline" % component]
    errors = []
    for result in results:
        floor = recorded["modules"].get(result.module, {}).get("min_percent")
        if floor is None:
            errors.append("no baseline recorded for %s" % result.module)
        elif result.percent + 1e-9 < floor:
            errors.append("%s: except-branch coverage %.1f%% fell below the recorded floor %d%%" % (
                result.module, result.percent, floor))
    covered, counted = _total(results)
    percent = 100.0 * covered / counted if counted else 100.0
    floor = recorded["min_percent"] if minimum is None else minimum
    if percent + 1e-9 < floor:
        errors.append("%s: except-branch coverage %.1f%% fell below the floor %s%%" % (component, percent, floor))
    return errors


def record(baseline: dict, component: str, results: list[ModuleResult]) -> None:
    covered, counted = _total(results)
    baseline.setdefault("components", {})[component] = {
        "branches": counted,
        "covered": covered,
        "min_percent": _floor(100.0 * covered / counted if counted else 100.0),
        "modules": {
            result.module: {
                "branches": result.counted,
                "branches_in_source": len(result.branches),
                "covered": len(result.covered),
                "min_percent": _floor(result.percent),
            }
            for result in results
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("components", nargs="*", default=sorted(MODULES), help="components to measure (default: all)")
    parser.add_argument("--min", type=float, default=None, help="component floor in percent (default: the recorded baseline)")
    parser.add_argument("--report-only", action="store_true", help="print the table, never fail on coverage")
    parser.add_argument("--write-baseline", action="store_true", help="record the measured floors in the baseline file")
    parser.add_argument("--baseline", type=Path, default=BASELINE, help="baseline file (default: %(default)s)")
    parser.add_argument("--json", type=Path, help="also write the measured branches to this file")
    parser.add_argument("--log-dir", type=Path, help="keep the pytest output of each component here")
    parser.add_argument("--pytest-arg", action="append", default=[], help="extra argument for pytest (repeatable)")
    arguments = parser.parse_args(argv)
    try:
        import coverage  # noqa: F401
    except ImportError:
        print("except_branch_coverage=unavailable: coverage is not installed", file=sys.stderr)
        return 2
    unknown = sorted(set(arguments.components) - set(MODULES))
    if unknown:
        parser.error("unknown component: " + ", ".join(unknown))
    baseline = json.loads(arguments.baseline.read_text(encoding="utf-8")) if arguments.baseline.exists() else {}
    errors: list[str] = []
    measured: dict[str, list[dict]] = {}
    for component in arguments.components:
        if arguments.log_dir:
            arguments.log_dir.mkdir(parents=True, exist_ok=True)
            log = open(arguments.log_dir / ("except-coverage-%s.log" % component), "w", encoding="utf-8")
        else:
            log = subprocess.DEVNULL
        try:
            results, status = measure(component, arguments.pytest_arg, log)
        finally:
            if log is not subprocess.DEVNULL:
                log.close()
        print(render(component, results))
        print()
        if status not in (0, 5) and not arguments.report_only:
            errors.append("%s: the test suite failed under coverage (pytest exit %d)" % (component, status))
        measured[component] = [
            {"module": result.module,
             "covered": [[branch.line, branch.kind] for branch in result.covered],
             "missed": [[branch.line, branch.kind] for branch in result.missed],
             "excluded": [[branch.line, branch.kind] for branch in result.excluded]}
            for result in results
        ]
        if arguments.write_baseline and status in (0, 5):
            record(baseline, component, results)
        elif not arguments.report_only:
            errors.extend(judge(component, results, baseline, arguments.min))
    if arguments.write_baseline and not errors:
        baseline["description"] = (
            "Floors of scripts/except_branch_coverage.py: per component and module the number of except/else "
            "branches of a try statement (branches_in_source counts handlers without a measurable statement too), how many "
            "the test suite entered and the measured percentage rounded down; the gate fails below these floors."
        )
        arguments.baseline.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if arguments.json:
        arguments.json.write_text(json.dumps(measured, indent=2) + "\n", encoding="utf-8")
    for error in errors:
        print("except_branch_coverage: " + error, file=sys.stderr)
    print("except_branch_coverage=%s" % ("failed" if errors else "passed"))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
