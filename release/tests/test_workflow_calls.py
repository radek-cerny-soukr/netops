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
            match = re.search(r"python3? -B (release/[\w/]+\.py)(.*)", line)
            if match:
                found.append((os.path.basename(workflow), match.group(1), re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]*)", match.group(2))))
    return found


def tooling_run_block():
    path = os.path.join(ROOT, ".github", "workflows", "candidate.yml")
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


if __name__ == "__main__":
    unittest.main()
