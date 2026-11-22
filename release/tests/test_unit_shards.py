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


def job_bodies(text=None):
    text = workflow_text() if text is None else text
    return dict(re.findall(r"(?m)^  ([a-z][a-z0-9_-]*):\n((?:    .*\n|\n)*)", text.split("\njobs:\n", 1)[1]))


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
                errors, _, _ = shards.check(names, count, weights, serial=())
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
        errors, _, _ = shards.check(["test_a", "test_b"], 2, {"test_a": 1.0, "test_gone": 2.0}, serial=())
        self.assertEqual(errors, ["weights name missing test modules: test_gone"])
        for count in (0, 3):
            with self.subTest(shards=count), self.assertRaises(shards.ShardError):
                shards.assign(["test_a", "test_b"], count, {})
        with self.assertRaises(shards.ShardError):
            shards.assign(["test_a"], 1, {}, parallel=0)

    def test_stale_weights_of_another_tree_can_be_ignored_but_coverage_is_still_proven(self):
        errors, plan, _ = shards.check(["test_a", "test_new"], 2, {"test_a": 1.0, "test_gone": 2.0}, ignore_stale=True)
        self.assertEqual(errors, [])
        self.assertEqual(sorted(name for members in plan for name in members), ["test_a", "test_new"])
        broken = lambda names, count, weights=None, **options: ([["test_a"], []], [1.0, 0.0])
        original = shards.assign
        shards.assign = broken
        try:
            errors, _, _ = shards.check(["test_a", "test_b"], 2, {}, ignore_stale=True)
        finally:
            shards.assign = original
        self.assertEqual(errors, ["shard 2 is empty", "modules in no shard: test_b"])


class SerialModules(unittest.TestCase):
    """Time-sensitive modules stay in their shard but run alone after its parallel part."""

    WEIGHTS = {"a": 8.0, "b": 5.0, "c": 4.0, "d": 3.0, "e": 2.0}

    def test_serial_modules_keep_the_split_and_go_last(self):
        names = sorted(self.WEIGHTS)
        plain, _ = shards.assign(names, 2, self.WEIGHTS, parallel=2, serial=())
        plan, loads = shards.assign(names, 2, self.WEIGHTS, parallel=2, serial=("b", "e"))
        self.assertEqual([sorted(members) for members in plan], [sorted(members) for members in plain])
        for members in plan:
            running, alone = shards.parts(members, ("b", "e"))
            self.assertEqual(members, running + alone)
            self.assertEqual(running, sorted(running, key=lambda name: (-self.WEIGHTS[name], name)))
            self.assertEqual(alone, sorted(alone, key=lambda name: (-self.WEIGHTS[name], name)))
        # slots: shard 1 [a | c], shard 2 [b | d, e]; b and e run alone after d in shard 2
        self.assertEqual(plan, [["a", "c"], ["d", "b", "e"]])
        self.assertEqual(loads, [8.0, 3.0 + 5.0 + 2.0])

    def test_check_proves_every_serial_module_is_in_one_serial_part(self):
        names = sorted(self.WEIGHTS)
        errors, plan, _ = shards.check(names, 2, self.WEIGHTS, serial=("c",))
        self.assertEqual(errors, [])
        self.assertEqual(sum(shards.parts(members, ("c",))[1] == ["c"] for members in plan), 1)
        errors, _, _ = shards.check(names, 2, self.WEIGHTS, serial=("c", "c"))
        self.assertEqual(errors, ["serial modules listed more than once: c"])
        errors, _, _ = shards.check(names, 2, self.WEIGHTS, serial=("c", "gone"))
        self.assertEqual(errors, ["serial modules name missing test modules: gone"])
        errors, _, _ = shards.check(names, 2, self.WEIGHTS, serial=("c", "gone"), ignore_stale=True)
        self.assertEqual(errors, [])
        # a split that put the serial module into no shard or into two is refused
        for broken_plan, expected in (([["a", "b"], ["d", "e"]], "serial part of 0 shards"),
                                      ([["a", "c"], ["c", "b", "d", "e"]], "serial part of 2 shards")):
            original = shards.assign
            shards.assign = lambda *args, **kwargs: (broken_plan, [1.0, 1.0])
            try:
                errors, _, _ = shards.check(names, 2, self.WEIGHTS, serial=("c",))
            finally:
                shards.assign = original
            with self.subTest(plan=broken_plan):
                self.assertTrue(any(expected in error for error in errors), errors)

    def test_the_repository_lists_the_time_sensitive_modules_once(self):
        self.assertIn("test_admin_text_limits", shards.SERIAL_MODULES)
        self.assertEqual(len(shards.SERIAL_MODULES), len(set(shards.SERIAL_MODULES)))
        self.assertTrue(set(shards.SERIAL_MODULES) <= set(shards.modules()))
        self.assertTrue(set(shards.SERIAL_MODULES) <= set(shards.WEIGHTS))


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
        alone = []
        for number in range(1, count + 1):
            with self.subTest(shard=number):
                result = self.run_tool("--shards", str(count), "--shard", str(number))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(result.stdout.split())
                union += result.stdout.split()
                running = self.run_tool("--shards", str(count), "--shard", str(number), "--part", "parallel")
                serial = self.run_tool("--shards", str(count), "--shard", str(number), "--part", "serial")
                self.assertEqual((running.returncode, serial.returncode), (0, 0), running.stderr + serial.stderr)
                self.assertTrue(running.stdout.split())
                self.assertEqual(running.stdout.split() + serial.stdout.split(), result.stdout.split())
                self.assertTrue(set(serial.stdout.split()) <= set(shards.SERIAL_MODULES))
                self.assertFalse(set(running.stdout.split()) & set(shards.SERIAL_MODULES))
                alone += serial.stdout.split()
        self.assertEqual(sorted(union), everything)
        self.assertEqual(len(union), len(set(union)))
        # every time-sensitive module runs alone in exactly one shard
        self.assertEqual(sorted(alone), sorted(shards.SERIAL_MODULES))
        self.assertIn("run alone afterwards: test_admin_text_limits", check.stdout)
        for wrong in (("--shards", str(count), "--check", "--part", "serial"), ("--shards", str(count), "--part", "parallel")):
            with self.subTest(arguments=wrong):
                self.assertNotEqual(self.run_tool(*wrong).returncode, 0)

    def test_another_tree_is_split_with_the_tools_of_this_revision(self):
        # a manual CI run tests a released tree whose modules may differ from WEIGHTS
        with tempfile.TemporaryDirectory(prefix="unit-shards-tree-") as directory:
            tree = Path(directory)
            names = shards.modules()[1:] + ["test_only_in_the_tested_tree"]
            for name in names:
                (tree / (name + ".py")).write_text("", encoding="utf-8")
            count, _ = configured_shards()
            strict = self.run_tool("--tests", str(tree), "--shards", str(count), "--check")
            self.assertNotEqual(strict.returncode, 0)
            self.assertIn("weights name missing test modules: " + shards.modules()[0], strict.stderr)
            lenient = self.run_tool("--tests", str(tree), "--shards", str(count), "--check", "--ignore-stale-weights")
            self.assertEqual(lenient.returncode, 0, lenient.stdout + lenient.stderr)
            self.assertIn("modules without a measured weight", lenient.stdout)
            self.assertIn("test_only_in_the_tested_tree", lenient.stdout)
            self.assertEqual(self.run_tool("--tests", str(tree), "--list").stdout.split(), sorted(names))
            union = []
            for number in range(1, count + 1):
                result = self.run_tool("--tests", str(tree), "--shards", str(count), "--shard", str(number))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(result.stdout.split())
                union += result.stdout.split()
            self.assertEqual(sorted(union), sorted(names))
            self.assertEqual(len(union), len(set(union)))
            # a tree without a serial module: strict --check names it, the manual run ignores it
            (tree / "test_admin_text_limits.py").unlink()
            strict = self.run_tool("--tests", str(tree), "--shards", str(count), "--check")
            self.assertIn("serial modules name missing test modules: test_admin_text_limits", strict.stderr)
            lenient = self.run_tool("--tests", str(tree), "--shards", str(count), "--check", "--ignore-stale-weights")
            self.assertEqual(lenient.returncode, 0, lenient.stdout + lenient.stderr)
            for number in range(1, count + 1):
                serial = self.run_tool("--tests", str(tree), "--shards", str(count), "--shard", str(number), "--part", "serial")
                self.assertEqual((serial.returncode, serial.stdout), (0, ""), serial.stderr)
        empty = self.run_tool("--tests", str(ROOT / "missing-tests"), "--shards", "2", "--check", "--ignore-stale-weights")
        self.assertNotEqual(empty.returncode, 0)

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
        self.assertIn("        if: ${{ github.event_name != 'workflow_dispatch' }}\n"
                      '        run: python3 -B release/unit_shards.py --shards "$UNIT_SHARDS" --check\n', text)
        self.assertIn("        if: ${{ github.event_name == 'workflow_dispatch' }}\n"
                      '        run: python3 -B "$CI_TOOLS"/release/unit_shards.py --tests tests/v1 --shards "$UNIT_SHARDS" --check'
                      ' --ignore-stale-weights\n', text)
        block = run_block("Run the installed product unit tests")
        for part in ("parallel", "serial"):
            self.assertIn('python3 -B "$CI_TOOLS"/release/unit_shards.py --tests tests/v1 --shards "$UNIT_SHARDS" --shard "$SHARD"'
                          ' --part %s > "$RUNNER_TEMP/unit-%s"' % (part, part), block)
        self.assertIn('xargs -r -a "$RUNNER_TEMP/unit-parallel" -n1 -P "$(nproc)" bash -c "$run_module" _ || status=$?', block)
        self.assertIn('bash -c "$run_module" _ "$module" || status=1\ndone 3< "$RUNNER_TEMP/unit-serial"', block)
        self.assertLess(block.index("xargs -r -a"), block.index('done 3< "$RUNNER_TEMP/unit-serial"'))
        self.assertEqual(block.count("docker run --rm"), 1)
        self.assertIn('test "$installed" = "$(python3 -B "$CI_TOOLS"/release/unit_shards.py --tests tests/v1 --list)"', block)
        self.assertIn('-B - --tests /opt/netops/tests --list < "$CI_TOOLS"/release/unit_shards.py', block)
        for job in ("tooling", "unit"):
            with self.subTest(job=job):
                self.assertIn("      CI_TOOLS: ${{ github.event_name == 'workflow_dispatch' && 'ci-tools' || '.' }}\n",
                              job_bodies(text)[job])
        self.assertIn(" ".join(UNIT_DOCKER.split()), " ".join(block.replace("\\\n", " ").split()))
        self.assertNotIn("unittest discover -s /opt/netops/tests", text)
        self.assertNotIn("--privileged", text)

    def test_every_job_has_a_timeout(self):
        jobs = re.findall(r"(?m)^  ([a-z][a-z0-9_-]*):\n((?:    .*\n|\n)*)", workflow_text().split("\njobs:\n", 1)[1])
        self.assertEqual([name for name, _ in jobs], ["tooling", "unit", "engine", "report"])
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

    def test_timeouts_are_the_measured_job_durations_with_half_again_as_reserve(self):
        # longest GitHub run of the whole job in tenths of a minute -> timeout >= x 1.5, the next whole minute;
        # admin: 64 is exactly 150 % of its longest run (42 min 40 s, shown as 42.7); shard 1: 29.0 min, the push run
        # on 27174f7c8 (29:01, job 137208180176) -> 43.5 -> 44
        jobs = job_bodies()
        engine = dict(re.findall(r"(?m)^          - role: ([a-z]+)\n            timeout: ([1-9][0-9]*)$", jobs["engine"]))
        unit = dict(re.findall(r"(?m)^          - shard: ([0-9]+)\n            timeout: ([1-9][0-9]*)$", jobs["unit"]))
        configured = {"core": engine["core"], "helper": engine["helper"], "auditor": engine["auditor"],
                      "admin": engine["admin"], "shard 1": unit["1"], "shard 2": unit["2"], "shard 3": unit["3"],
                      "tooling": re.search(r"(?m)^    timeout-minutes: ([0-9]+)$", jobs["tooling"]).group(1)}
        expected = {"core": (22, 4), "helper": (320, 48), "auditor": (67, 11), "admin": (None, 64),
                    "shard 1": (290, 44), "shard 2": (30, 5), "shard 3": (42, 7), "tooling": (54, 9)}
        for name, (tenths, timeout) in expected.items():
            with self.subTest(job=name):
                self.assertEqual(int(configured[name]), timeout)
                if tenths is not None:
                    self.assertEqual(timeout, -(-tenths * 15 // 100))

    def check_unit_pipeline(self, failing, tools_directory=".", failing_module="test_a"):
        with tempfile.TemporaryDirectory(prefix="unit-pipeline-") as directory:
            root = Path(directory)
            # a manual run keeps the shard tool of the workflow revision in ci-tools/, the tested tree has none
            (root / tools_directory / "release").mkdir(parents=True)
            names = ("test_a", "test_b", "test_c")
            # test_c is the time-sensitive module of the shard
            (root / tools_directory / "release" / "unit_shards.py").write_text(
                "import sys\n"
                "names = %r\n"
                "if '--part' in sys.argv:\n"
                "    names = names[2:] if sys.argv[sys.argv.index('--part') + 1] == 'serial' else names[:2]\n"
                "print('\\n'.join(names))\n" % (names,), encoding="utf-8")
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
                "printf 'start %s\\n' \"$module\" >> \"$EVENTS\"\n"
                "sleep 0.3\n"
                "printf 'fixture output %s\\n' \"$module\"\n"
                "printf 'Ran 2 tests in 0.1s\\n' >&2\n"
                "printf 'end %s\\n' \"$module\" >> \"$EVENTS\"\n"
                "if [ \"$module\" = \"$FAIL_MODULE\" ]; then exit \"$FAIL_CODE\"; fi\n", encoding="utf-8")
            docker.chmod(0o700)
            if failing == 255:
                (tools / "nproc").write_text("#!/bin/sh\nprintf '1\\n'\n", encoding="utf-8")
                (tools / "nproc").chmod(0o700)
            environment = dict(os.environ, RUNNER_TEMP=str(temp), SHARD="1", UNIT_SHARDS="1", CALLS=str(calls),
                               CI_TOOLS=tools_directory, EVENTS=str(root / "events"), FAIL_MODULE=failing_module,
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
                    self.assertIn("[%s] exit=%d" % (name, int(failing) if name == failing_module else 0), result.stdout)
            self.assertIn("shard 1/1: 3 modules (1 alone after the parallel part), 6 tests", result.stdout, diagnostic)
            # the serial module starts only after both parallel modules ended, and nothing runs beside it
            events = (root / "events").read_text(encoding="utf-8").splitlines()
            self.assertEqual(events[-2:], ["start test_c", "end test_c"], events)
            self.assertEqual(sorted(events[:-2]), ["end test_a", "end test_b", "start test_a", "start test_b"], events)
            self.assertIn("[test_c] serial: alone after the parallel part", result.stdout)

    def test_unit_pipeline_all_modules_pass(self):
        for tools in (".", "ci-tools"):
            with self.subTest(tools=tools):
                self.check_unit_pipeline(failing=False, tools_directory=tools)

    def test_unit_pipeline_failure_propagates_after_other_modules_finish(self):
        for tools in (".", "ci-tools"):
            for code in (1, 125, 255):
                with self.subTest(tools=tools, code=code):
                    self.check_unit_pipeline(failing=code, tools_directory=tools)

    def test_unit_pipeline_failure_of_a_serial_module_fails_the_shard(self):
        for code in (1, 255):
            with self.subTest(code=code):
                self.check_unit_pipeline(failing=code, failing_module="test_c")


CHECKOUT_SOURCE = """      - name: Check out source
        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
        with:
          ref: ${{ github.event_name == 'workflow_dispatch' && inputs.ref || '' }}
          persist-credentials: false
"""
CHECKOUT_TOOLS = """      - name: Check out the CI tools of this workflow revision
        if: ${{ github.event_name == 'workflow_dispatch' }}
        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
        with:
          ref: ${{ github.sha }}
          path: ci-tools
          persist-credentials: false
"""
HEAD = "1" * 40
TAGGED = "2" * 40
REPORT_ROLES = "core helper auditor admin"


def expected_items(shards):
    return ["tooling"] + ["unit-%d" % shard for shard in range(1, shards + 1)] + ["engine-" + role for role in REPORT_ROLES.split()]


class ManualRun(unittest.TestCase):
    """workflow_dispatch tests the code of a released ref and reports the result on its commit."""

    def test_trigger_takes_a_required_ref(self):
        text = workflow_text()
        self.assertIn("  workflow_dispatch:\n    inputs:\n      ref:\n        description: Tag or commit SHA to test\n"
                      "        required: true\n        type: string\n", text)
        self.assertIn("  push:\n    branches-ignore:\n", text)
        self.assertIn("  pull_request:\n", text)

    def test_every_job_checks_out_ref_and_the_unit_jobs_take_the_ci_tools_of_this_revision(self):
        jobs = job_bodies()
        for job in ("tooling", "unit", "engine"):
            with self.subTest(job=job):
                body = jobs[job]
                self.assertEqual(body.count("uses: actions/checkout@"), 1 if job == "engine" else 2)
                self.assertEqual(body.count(CHECKOUT_SOURCE), 1)
                self.assertEqual(body.count(CHECKOUT_TOOLS), 0 if job == "engine" else 1)
                self.assertLess(body.index(CHECKOUT_SOURCE), body.index("      - name: Identify the tested commit\n"))
                # no shared matrix output: every item reports its own tested commit as an artifact
                self.assertNotIn("    outputs:\n", body)
                self.assertIn("        id: tested\n", body)
        self.assertNotIn("actions/checkout", jobs["report"])

    def test_the_tested_commit_names_the_image_and_the_engine_reports(self):
        text = workflow_text()
        jobs = job_bodies(text)
        identity = run_block("Identify the tested commit")
        # GITHUB_SHA / github.sha only in the identity step (push, pull_request) and for the CI tools checkout
        self.assertEqual(text.count("GITHUB_SHA"), 3 * identity.count("GITHUB_SHA"))
        self.assertEqual(text.count("github.sha"), 2)
        for job in ("unit", "engine"):
            with self.subTest(job=job):
                build = run_block("Build the native product image from locked dependencies", "  " + job + ":\n" + jobs[job])
                self.assertIn('--build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"', build)
                self.assertEqual(build.count('"netops-ci-product:$TESTED_SHA"'), 2)
        engine = run_block("Run the installed engine suite")
        self.assertIn('product="netops-ci-product:$TESTED_SHA"', engine)
        self.assertIn('--candidate-commit "$TESTED_SHA"', engine)

    def run_identity(self, event):
        with tempfile.TemporaryDirectory(prefix="tested-commit-") as directory:
            root = Path(directory)
            git = lambda *args: subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True)
            git("init", "-q")
            (root / "file").write_text("tree\n", encoding="utf-8")
            git("add", "file")
            git("-c", "user.name=ci", "-c", "user.email=ci@example.invalid", "commit", "-q", "-m", "tree")
            head = git("rev-parse", "HEAD").stdout.strip()
            environment = dict(os.environ, GITHUB_EVENT_NAME=event, GITHUB_SHA=HEAD,
                               GITHUB_ENV=str(root / "env"), GITHUB_OUTPUT=str(root / "output"))
            result = subprocess.run(["bash", "-c", run_block("Identify the tested commit")], cwd=root, env=environment,
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return head, (root / "env").read_text(), (root / "output").read_text()

    def test_identity_is_github_sha_for_push_and_the_checked_out_commit_for_a_manual_run(self):
        for event in ("push", "pull_request"):
            with self.subTest(event=event):
                _, env, output = self.run_identity(event)
                self.assertEqual(env, "TESTED_SHA=%s\n" % HEAD)
                self.assertEqual(output, "sha=%s\n" % HEAD)
        head, env, output = self.run_identity("workflow_dispatch")
        self.assertNotEqual(head, HEAD)
        self.assertEqual(env, "TESTED_SHA=%s\n" % head)
        self.assertEqual(output, "sha=%s\n" % head)

    def test_only_the_report_job_may_write_checks(self):
        text = workflow_text()
        self.assertIn("\npermissions:\n  contents: read\n\n", text)
        self.assertEqual(text.count("checks: write"), 1)
        self.assertEqual(re.findall(r"(?m)^ *[a-z-]+: write$", text), ["      checks: write"])
        report = job_bodies(text)["report"]
        self.assertIn("    if: ${{ always() && github.event_name == 'workflow_dispatch' }}\n"
                      "    needs: [tooling, unit, engine]\n", report)
        self.assertIn("    permissions:\n      checks: write\n      contents: read\n", report)
        self.assertIn("          GH_TOKEN: ${{ github.token }}\n", report)
        # inputs reach the shell only through the environment
        self.assertEqual(text.count("inputs.ref"), 4)
        self.assertIn("          REF: ${{ inputs.ref }}\n", report)

    def run_report(self, results, ref="v1.0.12", shards="3", extra=()):
        """results maps an item (tooling, unit-<n>, engine-<role>) to the SHA it uploaded; absent = no artifact."""
        with tempfile.TemporaryDirectory(prefix="ci-report-") as directory:
            root = Path(directory)
            tools = root / "bin"
            tools.mkdir()
            (tools / "gh").write_text(
                "#!/bin/bash\n"
                "printf '%s\\n' \"$@\" > \"$CALLS/$(ls \"$CALLS\" | wc -l)\"\n"
                "if [ \"$1 $2\" = \"api repos/owner/repo/commits/$EXPECTED_PATH\" ] && [ \"$3 $4\" = \"--jq .sha\" ]; then\n"
                "  printf '%s\\n' \"$TAGGED\"; exit 0; fi\n"
                "if [ \"$1 $2 $3 $4\" = 'api --method POST repos/owner/repo/check-runs' ]; then printf 'https://checks.invalid/1\\n'; exit 0; fi\n"
                "exit 3\n", encoding="utf-8")
            (tools / "jq").write_text(
                "#!%s\n"
                "import sys, urllib.parse\n"
                "assert sys.argv[1:3] == ['-rn', '--arg'] and sys.argv[3] == 'ref' and sys.argv[5] == '$ref | @uri', sys.argv\n"
                "print(urllib.parse.quote(sys.argv[4], safe=''))\n" % sys.executable, encoding="utf-8")
            for tool in ("gh", "jq"):
                (tools / tool).chmod(0o700)
            calls = root / "calls"
            calls.mkdir()
            # the layout of actions/download-artifact with a pattern: one directory per artifact
            for item, sha in list(results.items()) + [(name, TAGGED) for name in extra]:
                # a stored "<sha> <attempt>"; names starting with "old:" are artifacts of an earlier attempt
                old = item.startswith("old:")
                name = "ci-result-%s-%s" % ("1" if old else "2", item[4:] if old else item)
                (root / "ci-results" / name).mkdir(parents=True)
                (root / "ci-results" / name / "sha").write_text(sha + (" 1\n" if old else " 2\n"), encoding="utf-8")
            import urllib.parse
            environment = dict(os.environ, CALLS=str(calls), TAGGED=TAGGED, EXPECTED_PATH=urllib.parse.quote(ref, safe=""),
                               GITHUB_REPOSITORY="owner/repo", GITHUB_SERVER_URL="https://server.invalid",
                               GITHUB_RUN_ID="42", ATTEMPT="2", GITHUB_STEP_SUMMARY=str(root / "summary"), REF=ref, GH_TOKEN="token",
                               UNIT_SHARDS=shards, ENGINE_ROLES=REPORT_ROLES,
                               PATH=str(tools) + os.pathsep + os.environ.get("PATH", os.defpath))
            result = subprocess.run(["bash", "-c", run_block("Record the result as the check run CI on the tested commit")],
                                    cwd=root, env=environment, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            made = [(calls / name).read_text().splitlines() for name in sorted(os.listdir(calls), key=int)]
            self.assertEqual(len(made), 2, made)
            post = made[1]
            fields = dict(post[index + 1].split("=", 1) for index, value in enumerate(post) if value == "-f")
            self.assertEqual(post[:4], ["api", "--method", "POST", "repos/owner/repo/check-runs"])
            self.assertEqual(fields["name"], "CI")
            self.assertEqual(fields["head_sha"], TAGGED)
            self.assertEqual(fields["status"], "completed")
            self.assertEqual(fields["details_url"], "https://server.invalid/owner/repo/actions/runs/42")
            self.assertEqual(fields["output[title]"], "CI %s for %s" % (fields["conclusion"], ref))
            self.assertIn("`%s`" % ref, "\n".join(post))
            self.assertIn("`%s`" % TAGGED, "\n".join(post))
            # the fake gh writes one argument per line, so the multi-line summary is taken from the step summary
            summary = (root / "summary").read_text().rsplit("\n\nconclusion: ", 1)[0]
            self.assertIn("output[summary]=" + summary, "\n".join(post))
            for item in expected_items(int(shards)):
                # an empty result file counts as missing
                state = "missing" if not results.get(item) else ("success" if results[item] == TAGGED else "other commit")
                self.assertIn("| %s | %s |" % (item, state), summary)
                if state != "success":
                    self.assertIn(item + " (" + state + ")", summary.split("missing or failed: ", 1)[1])
            self.assertIn("conclusion: " + fields["conclusion"], (root / "summary").read_text())
            return fields["conclusion"], summary

    def test_report_is_success_only_when_every_matrix_item_passed_on_the_commit_of_ref(self):
        everything = {item: TAGGED for item in expected_items(3)}
        self.assertEqual(len(everything), 8)
        conclusion, summary = self.run_report(everything)
        self.assertEqual(conclusion, "success")
        self.assertNotIn("missing or failed", summary)
        for item in everything:
            with self.subTest(item=item, artifact="missing"):
                # a failed, cancelled or never started item uploads nothing
                results = dict(everything)
                del results[item]
                conclusion, summary = self.run_report(results)
                self.assertEqual(conclusion, "failure")
                self.assertIn("missing or failed: %s (missing)" % item, summary)
            for other in (HEAD, ""):
                with self.subTest(item=item, sha=other):
                    self.assertEqual(self.run_report(dict(everything, **{item: other}))[0], "failure")
        with self.subTest(stale="artifact of an earlier attempt"):
            # shard 1 passed in attempt 1 and failed in attempt 2: its old result must not complete the set
            results = dict(everything)
            del results["unit-1"]
            results["old:unit-1"] = TAGGED
            conclusion, summary = self.run_report(results)
            self.assertEqual(conclusion, "failure")
            self.assertIn("unit-1 (missing)", summary)
        with self.subTest(artifacts="none"):
            conclusion, summary = self.run_report({})
            self.assertEqual(conclusion, "failure")
            self.assertEqual(summary.split("missing or failed: ", 1)[1].count("(missing)"), 8)

    def test_report_expects_one_result_per_configured_shard_and_no_other(self):
        # a fourth shard that never ran fails a run configured for four shards
        self.assertEqual(self.run_report({item: TAGGED for item in expected_items(3)}, shards="4")[0], "failure")
        self.assertEqual(self.run_report({item: TAGGED for item in expected_items(4)}, shards="4")[0], "success")
        conclusion, summary = self.run_report({item: TAGGED for item in expected_items(3)}, extra=("unit-4",))
        self.assertEqual(conclusion, "failure")
        self.assertIn("unit-4 (unexpected)", summary)

    def test_report_resolves_a_commit_sha_and_quotes_the_ref_in_the_api_path(self):
        everything = {item: TAGGED for item in expected_items(3)}
        self.assertEqual(self.run_report(everything, ref=TAGGED)[0], "success")
        self.assertEqual(self.run_report(everything, ref="../x?y")[0], "success")


if __name__ == "__main__":
    unittest.main()
