import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
spec = importlib.util.spec_from_file_location("unit_shards", ROOT / "release" / "unit_shards.py")
shards = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shards)

UNIT_DOCKER = ("docker run --rm --network none --read-only --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m --cap-drop ALL "
               "--security-opt no-new-privileges --user 51000:51000 --workdir /opt/netops/tests --entrypoint python \"$ref\" "
               "-B -m unittest -v \"$1\"")


def workflow_text():
    return WORKFLOW.read_text(encoding="utf-8")


def run_block(step_name, text=None):
    text = workflow_text() if text is None else text
    step = text.index("      - name: " + step_name + "\n")
    lines = text[step:].splitlines()
    start = lines.index("        run: |") + 1
    body = []
    for line in lines[start:]:
        if line and not line.startswith("          "):
            break
        body.append(line[10:] if line else "")
    if not any(line.strip() for line in body):
        raise ValueError("run block of %r is empty" % step_name)
    return "\n".join(body) + "\n"


def configured_shards(text=None):
    text = workflow_text() if text is None else text
    count = re.search(r'(?m)^  UNIT_SHARDS: "([0-9]+)"$', text)
    matrix = re.search(r"(?m)^        shard: \[([0-9, ]+)\]$", text)
    if not count or not matrix:
        raise ValueError("ci.yml must define UNIT_SHARDS and the unit shard matrix")
    return int(count.group(1)), [int(value) for value in matrix.group(1).split(",")]


class Split(unittest.TestCase):
    def fixture(self, names, packages=()):
        directory = tempfile.TemporaryDirectory(prefix="unit-shards-")
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        for name in names:
            (root / name).write_text("", encoding="utf-8")
        for package in packages:
            (root / package).mkdir()
            (root / package / "__init__.py").write_text("", encoding="utf-8")
        return root

    def test_lists_top_level_test_modules_like_unittest_discovery(self):
        root = self.fixture(["test_b.py", "test_a.py", "helper.py", "testing_c.py", "test_d.txt"])
        (root / "fixtures").mkdir()
        (root / "fixtures" / "test_ignored.py").write_text("", encoding="utf-8")
        self.assertEqual(shards.modules(root), ["test_a", "test_b", "testing_c"])

    def test_test_packages_and_empty_directories_are_refused(self):
        with self.assertRaisesRegex(shards.ShardError, "packages"):
            shards.modules(self.fixture(["test_a.py"], packages=["nested"]))
        with self.assertRaisesRegex(shards.ShardError, "no test modules"):
            shards.modules(self.fixture(["helper.py"]))

    def test_every_split_is_a_deterministic_partition(self):
        names = ["test_%02d" % index for index in range(23)]
        weights = {name: float((index * 7) % 11 + 1) for index, name in enumerate(names)}
        for count in range(1, len(names) + 1):
            with self.subTest(shards=count):
                plan, loads = shards.assign(names, count, weights)
                self.assertEqual(plan, shards.assign(list(reversed(names)), count, dict(weights))[0])
                flat = [name for members in plan for name in members]
                self.assertEqual(sorted(flat), names)
                self.assertTrue(all(plan))
                for members, load in zip(plan, loads):
                    self.assertEqual(members, sorted(members, key=lambda name: (-weights[name], name)))
                    self.assertGreaterEqual(load, weights[members[0]])
                    self.assertLessEqual(load, sum(weights[name] for name in members))
                errors, _, _ = shards.check(names, count, weights)
                self.assertEqual(errors, [])

    def test_longest_units_are_balanced_first(self):
        weights = {"a": 8.0, "b": 5.0, "c": 4.0, "d": 3.0}
        plan, loads = shards.assign(["a", "b", "c", "d"], 2, weights, parallel=1)
        self.assertEqual(plan, [["a", "d"], ["b", "c"]])
        self.assertEqual(loads, [11.0, 9.0])
        plan, loads = shards.assign(["d", "c", "b", "a"], 1, weights, parallel=2)
        self.assertEqual(plan, [["a", "b", "c", "d"]])
        self.assertEqual(loads, [11.0])

    def test_one_long_unit_does_not_take_the_other_slots_of_its_shard(self):
        weights = {"long": 100.0, **{"short%d" % index: 10.0 for index in range(8)}}
        plan, loads = shards.assign(sorted(weights), 2, weights, parallel=4)
        self.assertEqual(plan[0][0], "long")
        self.assertEqual(loads, [100.0, 20.0])
        self.assertEqual(len(plan[0]), 4)

    def test_unknown_modules_get_the_default_weight(self):
        plan, loads = shards.assign(["test_new", "test_old"], 2, {"test_old": 1.0})
        self.assertEqual(plan, [["test_new"], ["test_old"]])
        self.assertEqual(loads, [shards.DEFAULT_WEIGHT, 1.0])

    def test_stale_weights_and_impossible_splits_are_refused(self):
        errors, _, _ = shards.check(["test_a", "test_b"], 2, {"test_a": 1.0, "test_gone": 2.0})
        self.assertEqual(errors, ["weights name missing test modules: test_gone"])
        for count in (0, 3):
            with self.subTest(shards=count), self.assertRaises(shards.ShardError):
                shards.assign(["test_a", "test_b"], count, {})
        with self.assertRaises(shards.ShardError):
            shards.assign(["test_a"], 1, {}, parallel=0)


class RepositoryShards(unittest.TestCase):
    def run_tool(self, *args):
        return subprocess.run([sys.executable, "-B", str(ROOT / "release" / "unit_shards.py"), *args],
                              capture_output=True, text=True, timeout=60)

    def test_weights_name_exactly_the_test_modules(self):
        self.assertEqual(sorted(shards.WEIGHTS), shards.modules())
        self.assertTrue(all(weight > 0 for weight in shards.WEIGHTS.values()))

    def test_union_of_the_configured_shards_is_every_test_module_once(self):
        count, _ = configured_shards()
        check = self.run_tool("--shards", str(count), "--check")
        self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
        listed = self.run_tool("--list")
        self.assertEqual(listed.returncode, 0, listed.stderr)
        everything = listed.stdout.split()
        self.assertEqual(everything, shards.modules())
        union = []
        for number in range(1, count + 1):
            with self.subTest(shard=number):
                result = self.run_tool("--shards", str(count), "--shard", str(number))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(result.stdout.split())
                union += result.stdout.split()
        self.assertEqual(sorted(union), everything)
        self.assertEqual(len(union), len(set(union)))

    def test_shard_numbers_outside_the_split_are_refused(self):
        count, _ = configured_shards()
        for number in ("0", str(count + 1)):
            with self.subTest(shard=number):
                self.assertNotEqual(self.run_tool("--shards", str(count), "--shard", number).returncode, 0)


class Workflow(unittest.TestCase):
    def test_matrix_lists_every_configured_shard(self):
        count, matrix = configured_shards()
        self.assertGreater(count, 1)
        self.assertEqual(matrix, list(range(1, count + 1)))

    def test_tooling_job_checks_the_split_and_unit_jobs_use_it(self):
        text = workflow_text()
        self.assertIn('run: python3 -B release/unit_shards.py --shards "$UNIT_SHARDS" --check\n', text)
        block = run_block("Run the installed product unit tests")
        self.assertIn('python3 -B release/unit_shards.py --shards "$UNIT_SHARDS" --shard "$SHARD"', block)
        self.assertIn('test "$installed" = "$(python3 -B release/unit_shards.py --list)"', block)
        self.assertIn("-B - --tests /opt/netops/tests --list < release/unit_shards.py", block)
        self.assertIn(" ".join(UNIT_DOCKER.split()), " ".join(block.replace("\\\n", " ").split()))
        self.assertNotIn("unittest discover -s /opt/netops/tests", text)
        self.assertNotIn("--privileged", text)

    def test_every_job_has_a_timeout(self):
        jobs = re.findall(r"(?m)^  ([a-z][a-z0-9_-]*):\n((?:    .*\n|\n)*)", workflow_text().split("\njobs:\n", 1)[1])
        self.assertEqual([name for name, _ in jobs], ["tooling", "unit", "engine"])
        for name, body in jobs:
            with self.subTest(job=name):
                self.assertRegex(body, r"(?m)^    timeout-minutes: (?:[1-9][0-9]*|\$\{\{ matrix\.timeout \}\})$")
        engine = dict(jobs)["engine"]
        roles = re.search(r"(?m)^        role: \[([a-z, ]+)\]$", engine).group(1).split(", ")
        timeouts = dict(re.findall(r"(?m)^          - role: ([a-z]+)\n            timeout: ([1-9][0-9]*)$", engine))
        self.assertEqual(sorted(timeouts), sorted(roles))
        _, matrix = configured_shards()
        timeouts = re.findall(r"(?m)^          - shard: ([0-9]+)\n            timeout: ([1-9][0-9]*)$", dict(jobs)["unit"])
        self.assertEqual([int(shard) for shard, _ in timeouts], matrix)

    def check_unit_pipeline(self, failing):
        with tempfile.TemporaryDirectory(prefix="unit-pipeline-") as directory:
            root = Path(directory)
            (root / "release").mkdir()
            names = ("test_a", "test_b", "test_c")
            (root / "release" / "unit_shards.py").write_text(
                "import sys\n"
                "print('\\n'.join(%r))\n" % (names,), encoding="utf-8")
            temp = root / "runner-temp"
            temp.mkdir()
            (temp / "netops-ci-unit.iid").write_text("sha256:" + "a" * 64 + "\n", encoding="utf-8")
            tools = root / "bin"
            tools.mkdir()
            calls = root / "calls"
            calls.mkdir()
            docker = tools / "docker"
            docker.write_text(
                "#!/bin/bash\n"
                "module=\"${@: -1}\"\n"
                "if [[ \"$*\" == *\"--tests /opt/netops/tests --list\"* ]]; then printf 'test_a\\ntest_b\\ntest_c\\n'; exit 0; fi\n"
                "printf '%s\\n' \"$*\" > \"$CALLS/$module\"\n"
                "printf 'fixture output %s\\n' \"$module\"\n"
                "printf 'Ran 2 tests in 0.1s\\n' >&2\n"
                "if [ \"$module\" = test_a ]; then exit \"$FAIL_CODE\"; fi\n", encoding="utf-8")
            docker.chmod(0o700)
            if failing == 255:
                (tools / "nproc").write_text("#!/bin/sh\nprintf '1\\n'\n", encoding="utf-8")
                (tools / "nproc").chmod(0o700)
            environment = dict(os.environ, RUNNER_TEMP=str(temp), SHARD="1", UNIT_SHARDS="1", CALLS=str(calls),
                               FAIL_CODE=str(int(failing)),
                               PATH=str(tools) + os.pathsep + os.environ.get("PATH", os.defpath))
            result = subprocess.run(["bash", "-c", run_block("Run the installed product unit tests")], cwd=root,
                                    env=environment, capture_output=True, text=True, timeout=60)
            diagnostic = result.stdout + result.stderr
            self.assertEqual(result.returncode != 0, bool(failing), diagnostic)
            self.assertEqual(sorted(os.listdir(calls)), list(names), diagnostic)
            for name in names:
                with self.subTest(module=name):
                    call = (calls / name).read_text(encoding="utf-8")
                    self.assertIn("--network none --read-only", call)
                    self.assertIn("--cap-drop ALL --security-opt no-new-privileges --user 51000:51000", call)
                    log = (root / "test-logs" / "unit" / (name + ".log")).read_text(encoding="utf-8")
                    self.assertIn("fixture output " + name, log)
                    self.assertIn("[%s] exit=%d" % (name, int(failing) if name == "test_a" else 0), result.stdout)
            self.assertIn("shard 1/1: 3 modules, 6 tests", result.stdout, diagnostic)

    def test_unit_pipeline_all_modules_pass(self):
        self.check_unit_pipeline(failing=False)

    def test_unit_pipeline_failure_propagates_after_other_modules_finish(self):
        for code in (1, 125, 255):
            with self.subTest(code=code):
                self.check_unit_pipeline(failing=code)


if __name__ == "__main__":
    unittest.main()
