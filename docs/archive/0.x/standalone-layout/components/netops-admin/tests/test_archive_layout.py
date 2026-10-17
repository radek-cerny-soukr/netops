import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

COMPONENT = Path(__file__).resolve().parents[1]
SUBPROCESS_TEST = "tests/test_malformed_inputs.py::test_the_installed_entry_point_answers_broken_input_without_a_traceback"


def _sibling_source(name, version):
    trees = [path for path in (COMPONENT.parent / name, COMPONENT.parent / ("%s-%s" % (name, version)))
             if (path / "src").is_dir()]
    if len(trees) != 1:
        pytest.skip("needs exactly one %s source tree beside the component" % name)
    return trees[0] / "src"


def test_subprocess_tests_pass_with_the_pinned_archives_on_pythonpath(tmp_path):
    project = tomllib.loads((COMPONENT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    ignored = shutil.ignore_patterns("__pycache__")
    path = ["src"]
    for requirement in project["dependencies"]:
        name, version = requirement.split("==")
        target = tmp_path / ("%s-%s" % (name, version))
        shutil.copytree(_sibling_source(name, version), target / "src", ignore=ignored)
        path.append(os.path.join("..", target.name, "src"))
    admin = tmp_path / ("%s-%s" % (project["name"], project["version"]))
    for name in ("scripts", "src", "tests"):
        shutil.copytree(COMPONENT / name, admin / name, ignore=ignored)
    shutil.copyfile(COMPONENT / "pyproject.toml", admin / "pyproject.toml")
    done = subprocess.run(
        [sys.executable, "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider",
         "--basetemp", str(tmp_path / "basetemp"), SUBPROCESS_TEST],
        cwd=str(admin), env=dict(os.environ, PYTHONPATH=os.pathsep.join(path)), stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=600,
    )
    assert done.returncode == 0, done.stdout[-6000:] + done.stderr[-2000:]
