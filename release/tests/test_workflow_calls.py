import glob
import os
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def invocations():
    found = []
    for workflow in sorted(glob.glob(os.path.join(ROOT, ".github", "workflows", "*.yml"))):
        with open(workflow, encoding="utf-8") as stream:
            text = stream.read().replace("\\\n", " ")
        for line in text.splitlines():
            # a manual CI run calls the scripts of the workflow revision from "$CI_TOOLS"
            match = re.search(r"python3? -B (?:\"\$CI_TOOLS\"/)?(release/[\w/]+\.py)(.*)", line)
            if match:
                found.append((os.path.basename(workflow), match.group(1), re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]*)", match.group(2))))
    return found


def tooling_run_block(workflow="candidate.yml"):
    path = os.path.join(ROOT, ".github", "workflows", workflow)
    with open(path, encoding="utf-8") as stream:
        text = stream.read()
    step = text.index("      - name: Test the release and acceptance tooling\n")
    lines = text[step:].splitlines()
    start = lines.index("        run: |") + 1
    body = []
    for line in lines[start:]:
        if line and not line.startswith("          "):
            break
        body.append(line[10:] if line else "")
    if not body or not any(line.strip() for line in body):
        raise ValueError("tooling run block is empty")
    return "\n".join(body) + "\n"


class WorkflowCalls(unittest.TestCase):
    def test_workflows_call_release_scripts(self):
        self.assertGreater(len(invocations()), 5)

    def test_calls_through_the_ci_tools_directory_are_checked(self):
        calls = [(script, flags) for workflow, script, flags in invocations() if workflow == "ci.yml"]
        self.assertIn(("release/unit_shards.py", ["--tests", "--shards", "--check", "--ignore-stale-weights"]), calls)
        self.assertIn(("release/unit_shards.py", ["--tests", "--shards", "--shard"]), calls)
        self.assertIn(("release/unit_shards.py", ["--tests", "--shards", "--shard", "--part"]), calls)
        self.assertIn(("release/unit_shards.py", ["--tests", "--list"]), calls)

    def test_every_flag_is_accepted_by_the_script(self):
        helps = {}
        for workflow, script, flags in invocations():
            if script not in helps:
                proc = subprocess.run([sys.executable, "-B", os.path.join(ROOT, script), "--help"], capture_output=True, text=True, timeout=60)
                self.assertEqual(proc.returncode, 0, "%s --help failed: %s" % (script, proc.stderr))
                helps[script] = proc.stdout
            for flag in flags:
                self.assertRegex(helps[script], r"(?<![\w-])%s(?![\w-])" % re.escape(flag), "%s passes %s to %s, which does not accept it" % (workflow, flag, script))

    def check_tooling_pipeline(self, test_directory, failing):
        with tempfile.TemporaryDirectory(prefix="tooling-pipeline-") as directory:
            suite = os.path.join(directory, test_directory)
            os.makedirs(suite)
            names = ("test_a.py", "test_b.py", "test_c.py")
            for index, name in enumerate(names):
                fixture = ("from pathlib import Path\n"
                           "import sys\n"
                           "print(\"fixture stdout %s\")\n"
                           "print(\"fixture stderr %s\", file=sys.stderr)\n"
                           "Path(__file__).with_suffix(\".done\").write_text(\"complete\")\n"
                           "raise SystemExit(%d)\n" % (name, name, int(failing) if index == 0 else 0))
                with open(os.path.join(suite, name), "w", encoding="utf-8") as stream:
                    stream.write(fixture)
            environment = dict(os.environ, TEST_DIRECTORY=test_directory)
            if failing == 255:
                tools = os.path.join(directory, "bin")
                os.mkdir(tools)
                nproc = os.path.join(tools, "nproc")
                with open(nproc, "w", encoding="utf-8") as stream:
                    stream.write("#!/bin/sh\nprintf '1\\n'\n")
                os.chmod(nproc, 0o700)
                environment["PATH"] = tools + os.pathsep + environment.get("PATH", os.defpath)
            result = subprocess.run(["bash", "-c", tooling_run_block()], cwd=directory,
                                    env=environment,
                                    capture_output=True, text=True, timeout=30)
            diagnostic = result.stdout + result.stderr
            if failing:
                self.assertNotEqual(result.returncode, 0, diagnostic)
            else:
                self.assertEqual(result.returncode, 0, diagnostic)
            self.assertEqual(sorted(name for name in os.listdir(suite) if name.endswith(".done")),
                             ["test_a.done", "test_b.done", "test_c.done"], diagnostic)
            for index, name in enumerate(names):
                prefix = "[%s/%s] " % (test_directory, name)
                self.assertIn(prefix + "fixture stdout " + name, result.stdout.splitlines(), diagnostic)
                self.assertIn(prefix + "fixture stderr " + name, result.stdout.splitlines(), diagnostic)
                self.assertIn(prefix + "exit=%d" % (int(failing) if index == 0 else 0),
                              result.stdout.splitlines(), diagnostic)
                with open(os.path.join(suite, name.replace(".py", ".done")), encoding="utf-8") as stream:
                    self.assertEqual(stream.read(), "complete")

    def test_tooling_pipeline_all_files_pass(self):
        for directory in ("release/tests", "release/acceptance/tests"):
            with self.subTest(directory=directory):
                self.check_tooling_pipeline(directory, failing=False)

    def test_tooling_pipeline_failure_propagates_after_other_files_finish(self):
        for directory in ("release/tests", "release/acceptance/tests"):
            for code in (1, 255):
                with self.subTest(directory=directory, code=code):
                    self.check_tooling_pipeline(directory, failing=code)

    def check_ci_tooling_pipeline(self, failing):
        directories = ("release/tests", "release/acceptance/tests", "release/sign/tests")
        names = ("test_a.py", "test_b.py")
        with tempfile.TemporaryDirectory(prefix="ci-tooling-pipeline-") as directory:
            for test_directory in directories:
                suite = os.path.join(directory, test_directory)
                os.makedirs(suite)
                for name in names:
                    code = int(failing) if (test_directory, name) == ("release/acceptance/tests", "test_a.py") else 0
                    fixture = ("from pathlib import Path\n"
                               "import sys\n"
                               "print(\"fixture stdout %s\")\n"
                               "print(\"fixture stderr %s\", file=sys.stderr)\n"
                               "Path(__file__).with_suffix(\".done\").write_text(\"complete\")\n"
                               "raise SystemExit(%d)\n" % (name, name, code))
                    with open(os.path.join(suite, name), "w", encoding="utf-8") as stream:
                        stream.write(fixture)
            environment = dict(os.environ)
            if failing == 255:
                tools = os.path.join(directory, "bin")
                os.mkdir(tools)
                nproc = os.path.join(tools, "nproc")
                with open(nproc, "w", encoding="utf-8") as stream:
                    stream.write("#!/bin/sh\nprintf '1\\n'\n")
                os.chmod(nproc, 0o700)
                environment["PATH"] = tools + os.pathsep + environment.get("PATH", os.defpath)
            result = subprocess.run(["bash", "-c", tooling_run_block("ci.yml")], cwd=directory, env=environment,
                                    capture_output=True, text=True, timeout=60)
            diagnostic = result.stdout + result.stderr
            self.assertEqual(result.returncode != 0, bool(failing), diagnostic)
            lines = result.stdout.splitlines()
            for test_directory in directories:
                for name in names:
                    path = test_directory + "/" + name
                    code = int(failing) if path == "release/acceptance/tests/test_a.py" else 0
                    with self.subTest(test=path):
                        with open(os.path.join(directory, test_directory, name.replace(".py", ".done")), encoding="utf-8") as stream:
                            self.assertEqual(stream.read(), "complete")
                        log = os.path.join(directory, "test-logs", "tooling", path.replace("/", "_") + ".log")
                        with open(log, encoding="utf-8") as stream:
                            self.assertEqual(stream.read().splitlines(), ["fixture stdout " + name, "fixture stderr " + name])
                        self.assertTrue(any(line.startswith("[%s] exit=%d seconds=" % (path, code)) for line in lines), diagnostic)
                        self.assertIn("[%s] fixture stdout %s" % (path, name), lines, diagnostic)
                        self.assertIn("[%s] fixture stderr %s" % (path, name), lines, diagnostic)

    def test_ci_tooling_runs_every_file_in_parallel_with_a_log_per_file(self):
        self.check_ci_tooling_pipeline(failing=False)
        block = tooling_run_block("ci.yml")
        self.assertIn('xargs -0 -n1 -P "$(nproc)"', block)
        self.assertEqual(block.count("release/sign/tests/test_*.py release/acceptance/tests/test_*.py release/tests/test_*.py"), 2)

    def test_ci_tooling_failure_propagates_after_other_files_finish(self):
        for code in (1, 255):
            with self.subTest(code=code):
                self.check_ci_tooling_pipeline(failing=code)

    def test_ci_report_checks_a_result_artifact_of_every_matrix_item(self):
        with open(os.path.join(ROOT, ".github", "workflows", "ci.yml"), encoding="utf-8") as stream:
            text = stream.read()
        with open(os.path.join(ROOT, ".github", "workflows", "candidate.yml"), encoding="utf-8") as stream:
            candidate = stream.read()
        jobs = dict(re.findall(r"(?m)^  ([a-z][a-z0-9_-]*):\n((?:    .*\n|\n)*)", text.split("\njobs:\n", 1)[1]))
        steps = lambda body: re.split(r"(?m)^      - (?=name: )", body)[1:]
        upload = re.search(r"uses: (actions/upload-artifact@[0-9a-f]{40} # v[0-9.]+)\n", text).group(1)
        download = re.search(r"uses: (actions/download-artifact@[0-9a-f]{40} # v[0-9.]+)\n", candidate).group(1)
        MANUAL = "${{ success() && github.event_name == 'workflow_dispatch' }}"
        # each job and matrix item uploads its own result, only when it passed, as its last two steps
        for job, name in (("tooling", "ci-result-${{ github.run_attempt }}-tooling"),
                          ("unit", "ci-result-${{ github.run_attempt }}-unit-${{ matrix.shard }}"),
                          ("engine", "ci-result-${{ github.run_attempt }}-engine-${{ matrix.role }}")):
            with self.subTest(job=job):
                body = jobs[job]
                self.assertNotIn("    outputs:\n", body)
                record, keep = steps(body)[-2:]
                self.assertEqual(record, "name: Record that this job passed on the tested commit\n"
                                         "        if: " + MANUAL + "\n        run: |\n          set -euo pipefail\n"
                                         "          mkdir -p ci-result\n"
                                         "          printf '%s %s\\n' \"$TESTED_SHA\" \"$GITHUB_RUN_ATTEMPT\" > ci-result/sha\n\n")
                self.assertEqual(keep.rstrip("\n"), "name: Keep the result of this job for the report\n"
                                 "        if: " + MANUAL + "\n        uses: " + upload + "\n        with:\n"
                                 "          name: " + name + "\n          path: ci-result/sha\n"
                                 "          if-no-files-found: error\n          retention-days: 30")
        self.assertEqual(text.count("ci-result/sha"), 6)
        report = jobs["report"]
        collect, record = steps(report)
        self.assertEqual(collect, "name: Collect the results of every job and matrix item\n"
                                  "        continue-on-error: true\n        uses: " + download + "\n        with:\n"
                                  "          pattern: ci-result-${{ github.run_attempt }}-*\n          path: ci-results\n\n")
        self.assertTrue(record.startswith("name: Record the result as the check run CI on the tested commit\n"))
        # the report reads neither the aggregated job results nor shared matrix outputs
        self.assertIsNone(re.search(r"\$\{\{[^}]*\bneeds\.", text), "ci.yml reads needs.<job> in an expression")
        self.assertNotRegex(text, r"(?m)^    outputs:")
        # the expected list: tooling, UNIT_SHARDS unit shards and every engine role of the matrix
        roles = re.search(r"(?m)^        role: \[([a-z, ]+)\]$", jobs["engine"]).group(1).split(", ")
        self.assertIn("          ENGINE_ROLES: %s\n" % " ".join(roles), record)
        self.assertIn('expected=(tooling)\n', record)
        self.assertIn('for shard in $(seq 1 "$UNIT_SHARDS"); do expected+=("unit-$shard"); done\n', record)
        self.assertIn('for role in $ENGINE_ROLES; do expected+=("engine-$role"); done\n', record)
        self.assertEqual(record.count("conclusion=success"), 1)
        # only the artifacts of the current attempt count, and the stored attempt must match
        self.assertIn("          ATTEMPT: ${{ github.run_attempt }}\n", record)
        self.assertIn('file="ci-results/ci-result-$ATTEMPT-$item/sha"', record)
        self.assertIn('[ "${attempt:-}" = "$ATTEMPT" ] || tested=""', record)
        self.assertNotIn("ci-result-*", text)
        # no step writing or uploading a result runs for push or pull_request
        self.assertEqual(text.count(MANUAL), 6)
        self.assertEqual(len(re.findall(r"(?m)^        if: \$\{\{ success\(\) \}\}$", text)), 0)


if __name__ == "__main__":
    unittest.main()
