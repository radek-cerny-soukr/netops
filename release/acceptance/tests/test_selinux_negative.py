import json
import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "selinux_negative.sh")
MARKER = "selinux-negative-marker"

DOCKER = r'''#!/bin/sh
case "$*" in
  "rm -f "*) exit 0 ;;
  "run -d "*) echo fixture-container; exit 0 ;;
  "inspect "*) echo "$FAKE_OWNER_LABEL"; exit 0 ;;
  "exec "*) [ "$FAKE_OWNER" = read ] && { echo selinux-negative-marker; exit 0; }; echo "cat: /d/f: Permission denied"; exit 1 ;;
  "run --rm "*) [ "$FAKE_OTHER" = read ] && { echo selinux-negative-marker; exit 0; }; echo "cat: /d/f: Permission denied"; exit 1 ;;
  *"down -v"*) exit 0 ;;
  *":/d:z "*) touch "$FAKE_STATE/relabeled"; echo selinux-negative-marker; exit 0 ;;
  "compose "*) [ "$FAKE_PRODUCT" = read ] && { echo selinux-negative-marker; exit 0; }; echo "cat: /d/f: Permission denied"; exit 1 ;;
esac
exit 2
'''


class SelinuxNegative(unittest.TestCase):
    def run_case(self, **changes):
        env = {"FAKE_MODE": "Enforcing", "FAKE_OWNER": "read", "FAKE_OTHER": "denied", "FAKE_PRODUCT": "denied", "FAKE_AVC": "0",
               "FAKE_PRIVATE": "system_u:object_r:container_file_t:s0:c1,c2", "FAKE_SHARED": "system_u:object_r:container_file_t:s0",
               "FAKE_OWNER_LABEL": "system_u:system_r:container_t:s0:c1,c2"}
        env.update(changes)
        with tempfile.TemporaryDirectory() as directory:
            shims = os.path.join(directory, "bin")
            bundle = os.path.join(directory, "bundle")
            os.makedirs(shims)
            os.makedirs(bundle)
            env["FAKE_STATE"] = directory
            for name, body in (("sudo", '#!/bin/sh\nexec "$@"\n'), ("docker", DOCKER),
                               ("getenforce", '#!/bin/sh\necho "$FAKE_MODE"\n'),
                               ("ls", '#!/bin/sh\nif [ -e "$FAKE_STATE/relabeled" ]; then echo "$FAKE_SHARED $2"; else echo "$FAKE_PRIVATE $2"; fi\n'),
                               ("ausearch", '#!/bin/sh\ni=0\nwhile [ "$i" -lt "$FAKE_AVC" ]; do echo \'type=AVC avc:  denied  { read } comm="cat"\'; i=$((i+1)); done\n')):
                path = os.path.join(shims, name)
                with open(path, "w") as stream:
                    stream.write(body)
                os.chmod(path, 0o755)
            for name in ("compose.yaml", "env.example"):
                with open(os.path.join(bundle, name), "w") as stream:
                    stream.write("NETOPS_IMAGE=\nNETOPS_BIND_IP=\nNETOPS_PORT=\nNETOPS_SERVER_NAME=\n")
            output = os.path.join(directory, "report.json")
            proc = subprocess.run(["bash", SCRIPT, bundle, "fixture-image", "a" * 40, "sha256:" + "1" * 64, output],
                                  env=dict(os.environ, PATH=shims + os.pathsep + os.environ["PATH"], **env),
                                  capture_output=True, text=True, timeout=60)
            with open(output) as stream:
                report = json.load(stream)
        self.assertEqual(proc.returncode, 0 if report["checks"][0]["status"] == "PASS" else 1, proc.stderr)
        self.assertEqual(report["schema"], "netops-acceptance-selinux/1")
        self.assertEqual(report["candidate_commit"], "a" * 40)
        self.assertEqual(report["candidate_image"], "sha256:" + "1" * 64)
        self.assertEqual([check["check"] for check in report["checks"]], ["selinux-label-negative"])
        self.assertNotIn(MARKER + MARKER, report["checks"][0]["detail"])
        return report["checks"][0]["status"]

    def test_enforced_private_labels_pass(self):
        self.assertEqual(self.run_case(), "PASS")
        self.assertEqual(self.run_case(FAKE_AVC="2"), "PASS")

    def test_every_missing_refusal_fails(self):
        for changes in ({"FAKE_MODE": "Permissive"}, {"FAKE_MODE": "Disabled"}, {"FAKE_OWNER": "denied"},
                        {"FAKE_OTHER": "read"}, {"FAKE_PRODUCT": "read"},
                        {"FAKE_PRIVATE": "system_u:object_r:container_file_t:s0"},
                        {"FAKE_PRIVATE": "system_u:object_r:container_file_t:s0:c3,c4"},
                        {"FAKE_SHARED": "system_u:object_r:container_file_t:s0:c1,c2"},
                        {"FAKE_OWNER_LABEL": "system_u:system_r:container_t:s0:", "FAKE_PRIVATE": "system_u:object_r:container_file_t:s0:"}):
            with self.subTest(changes=changes):
                self.assertEqual(self.run_case(**changes), "FAIL")


if __name__ == "__main__":
    unittest.main()
