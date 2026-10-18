import glob
import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def invocations():
    found = []
    for workflow in sorted(glob.glob(os.path.join(ROOT, ".github", "workflows", "*.yml"))):
        text = open(workflow).read().replace("\\\n", " ")
        for line in text.splitlines():
            match = re.search(r"python3? -B (release/[\w/]+\.py)(.*)", line)
            if match:
                found.append((os.path.basename(workflow), match.group(1), re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]*)", match.group(2))))
    return found


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


if __name__ == "__main__":
    unittest.main()
