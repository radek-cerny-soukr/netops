import json
import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "nonroot_operator.sh")
GOOD = ("init=0\nup=0\nca=0 BEGINCERTIFICATE\ntoken_length=64\nconnection=0\nmcp=200\naudit_tail=0\nrestart=0\nstop=0\n"
        "container_nonroot_refused=50/50\ncontainer_nonroot_not_refused=\nstate_unchanged=yes\nmodes=600 600 \nup_again=0\ndone=1\n")

SUDO = r'''#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_STATE/trace"
case "$1" in
  useradd) [ "$FAKE_USERADD_RC" = 0 ] || exit "$FAKE_USERADD_RC"; for last; do :; done; : > "$FAKE_STATE/users/$last"; exit 0 ;;
  userdel) [ "$FAKE_USERDEL_RC" = 0 ] || exit "$FAKE_USERDEL_RC"; [ "$FAKE_USERDEL_KEEPS" = 1 ] || rm -f "$FAKE_STATE/users/$3"; exit 0 ;;
  install) shift; directory=0; files=""
    while [ $# -gt 0 ]; do case "$1" in -d) directory=1; shift ;; -o|-g|-m) shift 2 ;; *) files="$files $1"; shift ;; esac; done
    set -- $files; [ "$directory" = 1 ] && { mkdir -p "$1"; exit 0; }
    for last; do :; done; while [ $# -gt 1 ]; do cp "$1" "$last"; shift; done; exit 0 ;;
  docker) if grep -q "down -v" "$FAKE_STATE/trace"; then rc="$FAKE_DOCKER_RC"; left="$FAKE_LEFT"; else rc="$FAKE_PREFLIGHT_RC"; left="$FAKE_PREFLIGHT_LEFT"; fi
    [ "$rc" = 0 ] || exit "$rc"; [ "$2" = "$left" ] && echo leftover; exit 0 ;;
  -iu) home="$FAKE_STATE/home-$2"
    case "$2" in
      netops-ot-*) printf 'docker=denied\nenv=denied\nmcp=401\n'; exit "$FAKE_OTHER_RC" ;;
      netops-op-*) [ "$4" = -c ] && exit "$FAKE_DOWN_RC"
        if [ "$FAKE_OPERATOR" = real ]; then shift 3; HOME="$home" exec bash "$@"; fi
        cat "$FAKE_STATE/operator.out"; exit "$FAKE_OPERATOR_RC" ;;
    esac ;;
esac
exit 0
'''

GETENT = r'''#!/bin/sh
[ -n "$FAKE_GETENT_RC" ] && exit "$FAKE_GETENT_RC"
if [ "$FAKE_PREEXISTING" = 1 ] || [ -e "$FAKE_STATE/users/$2" ]; then printf '%s:x:1000:1000::%s/home-%s:/bin/bash\n' "$2" "$FAKE_STATE" "$2"; exit 0; fi
exit 2
'''

MKTEMP = r'''#!/bin/sh
if [ "$FAKE_RESULTS_UNWRITABLE" = 1 ] && [ ! -e "$FAKE_STATE/results-made" ]; then : > "$FAKE_STATE/results-made"; exec /usr/bin/mktemp -d; fi
exec /usr/bin/mktemp "$@"
'''

DOCKER = r'''#!/bin/sh
count() { n=$(cat "$FAKE_STATE/$1" 2> /dev/null || echo 0); n=$((n + 1)); echo "$n" > "$FAKE_STATE/$1"; echo "$n"; }
case "$*" in
  *"--user "*) echo "netops: Use the image default container user for this operator command; remove any --user override"; exit 2 ;;
  *"token show"*) n=$(count tokens); [ "$n" -ge "$FAKE_TOKEN_FAIL_FROM" ] && exit 1
    [ "$n" -ge "$FAKE_TOKEN_CHANGE_FROM" ] && { printf '%064d\n' 2; exit 0; }; printf '%064d\n' 1; exit 0 ;;
  *" netops ca") printf -- '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n'; exit 0 ;;
esac
exit 0
'''


class NonrootOperator(unittest.TestCase):
    def run_case(self, operator=GOOD, **fake):
        settings = {"FAKE_USERADD_RC": "0", "FAKE_USERDEL_RC": "0", "FAKE_USERDEL_KEEPS": "0", "FAKE_DOCKER_RC": "0", "FAKE_LEFT": "none",
                    "FAKE_DOWN_RC": "0", "FAKE_OPERATOR": "canned", "FAKE_PREEXISTING": "0", "FAKE_GETENT_RC": "",
                    "FAKE_TOKEN_FAIL_FROM": "99", "FAKE_TOKEN_CHANGE_FROM": "99", "FAKE_PREFLIGHT_RC": "0", "FAKE_PREFLIGHT_LEFT": "none",
                    "FAKE_OPERATOR_RC": "0", "FAKE_OTHER_RC": "0", "FAKE_RESULTS_UNWRITABLE": "0"}
        settings.update(fake)
        with tempfile.TemporaryDirectory() as directory:
            shims = os.path.join(directory, "bin")
            bundle = os.path.join(directory, "bundle")
            for path in (shims, bundle, os.path.join(directory, "users")):
                os.makedirs(path)
            with open(os.path.join(directory, "operator.out"), "w") as stream:
                stream.write(operator)
            for name in ("compose.yaml", "env.example"):
                with open(os.path.join(bundle, name), "w") as stream:
                    stream.write("NETOPS_IMAGE=\nNETOPS_BIND_IP=\nNETOPS_PORT=\nNETOPS_SERVER_NAME=\n")
            for name, body in (("sudo", SUDO), ("getent", GETENT), ("docker", DOCKER), ("mktemp", MKTEMP)):
                path = os.path.join(shims, name)
                with open(path, "w") as stream:
                    stream.write(body)
                os.chmod(path, 0o755)
            output = os.path.join(directory, "report.json")
            env = dict(os.environ, PATH=shims + os.pathsep + os.environ["PATH"], FAKE_STATE=directory, TMPDIR=directory, **settings)
            proc = subprocess.run(["bash", SCRIPT, bundle, "fixture-image", "a" * 40, "sha256:" + "1" * 64, output],
                                  env=env, capture_output=True, text=True, timeout=120)
            trace_path = os.path.join(directory, "trace")
            trace = []
            if os.path.exists(trace_path):
                with open(trace_path) as stream:
                    trace = stream.read().splitlines()
            with open(output) as stream:
                report = json.load(stream)
        self.assertEqual(report["schema"], "netops-acceptance-nonroot/1")
        self.assertEqual(report["candidate_commit"], "a" * 40)
        self.assertEqual(report["candidate_image"], "sha256:" + "1" * 64)
        created = [line.split()[-1] for line in trace if line.startswith("useradd ")]
        deleted = [line.split()[-1] for line in trace if line.startswith("userdel ")]
        checks = {check["check"]: check for check in report["checks"]}
        return proc.returncode, report, checks, created, deleted, trace

    def test_all_checks_pass_and_only_created_accounts_are_removed(self):
        rc, report, checks, created, deleted, trace = self.run_case()
        self.assertEqual(rc, 0)
        self.assertEqual(report["summary"], {"PASS": 5})
        self.assertEqual(len(created), 2)
        self.assertEqual(sorted(deleted), sorted(created))
        self.assertEqual(sum("down -v" in line for line in trace), 1)

    def test_existing_or_unreadable_account_is_refused_untouched(self):
        for fake in ({"FAKE_PREEXISTING": "1"}, {"FAKE_GETENT_RC": "1"}):
            with self.subTest(fake=fake):
                rc, report, checks, created, deleted, trace = self.run_case(**fake)
                self.assertEqual(rc, 1)
                self.assertEqual(report["summary"], {"FAIL": 1})
                self.assertEqual((created, deleted), ([], []))
                self.assertFalse([line for line in trace if "-iu" in line or line.startswith("docker")])

    def test_failed_account_creation_removes_nothing(self):
        rc, report, checks, created, deleted, trace = self.run_case(FAKE_USERADD_RC="1")
        self.assertEqual(rc, 1)
        self.assertEqual(report["summary"], {"FAIL": 1})
        self.assertEqual(deleted, [])

    def test_every_operator_failure_gives_nonzero_exit_and_cleans_up(self):
        for broken in (GOOD.replace("init=0", "init=1"), GOOD.replace("mcp=200", "mcp=ConnectionRefusedError"),
                       GOOD.replace("token_length=64", "token_length=0"), GOOD.replace("modes=600 600 ", "modes=644 600 "),
                       GOOD.replace("50/50", "49/50"), GOOD.replace("state_unchanged=yes", "state_unchanged=no"),
                       GOOD.replace("state_unchanged=yes", "state_unchanged=unreadable"), GOOD.replace("done=1\n", ""), ""):
            with self.subTest(broken=broken[-60:]):
                rc, report, checks, created, deleted, trace = self.run_case(operator=broken)
                self.assertEqual(rc, 1)
                self.assertGreaterEqual(report["summary"].get("FAIL", 0), 1)
                self.assertEqual(checks["nonroot-cleanup"]["status"], "PASS")
                self.assertEqual(sorted(deleted), sorted(created))

    def test_failed_or_unverifiable_cleanup_fails(self):
        for fake, reason in (({"FAKE_DOWN_RC": "1"}, "compose-down"), ({"FAKE_USERDEL_RC": "1"}, "userdel-netops-op-"),
                             ({"FAKE_LEFT": "ps"}, "containers-left"), ({"FAKE_LEFT": "volume"}, "volumes-left"), ({"FAKE_LEFT": "network"}, "networks-left"),
                             ({"FAKE_DOCKER_RC": "1"}, "container-inventory-failed"),
                             ({"FAKE_USERDEL_KEEPS": "1"}, "not-confirmed-removed")):
            with self.subTest(reason=reason):
                rc, report, checks, created, deleted, trace = self.run_case(**fake)
                self.assertEqual(rc, 1)
                self.assertEqual(report["summary"], {"PASS": 4, "FAIL": 1})
                self.assertEqual(checks["nonroot-cleanup"]["status"], "FAIL")
                self.assertIn(reason, checks["nonroot-cleanup"]["detail"])
                self.assertEqual(sorted(set(deleted)), sorted(created))

    def test_existing_docker_project_or_unreadable_inventory_is_refused_untouched(self):
        for fake in ({"FAKE_PREFLIGHT_LEFT": "ps"}, {"FAKE_PREFLIGHT_LEFT": "volume"}, {"FAKE_PREFLIGHT_LEFT": "network"}, {"FAKE_PREFLIGHT_RC": "1"}):
            with self.subTest(fake=fake):
                rc, report, checks, created, deleted, trace = self.run_case(**fake)
                self.assertEqual(rc, 1)
                self.assertEqual(report["summary"], {"FAIL": 1})
                self.assertEqual(list(checks), ["nonroot-setup"])
                self.assertEqual((created, deleted), ([], []))
                self.assertFalse([line for line in trace if "down -v" in line])

    def test_failed_operator_or_other_process_fails_even_with_expected_output(self):
        for fake, row in (({"FAKE_OPERATOR_RC": "1"}, "nonroot-operator-quickstart"), ({"FAKE_OTHER_RC": "1"}, "other-user-denied")):
            with self.subTest(fake=fake):
                rc, report, checks, created, deleted, trace = self.run_case(**fake)
                self.assertEqual(rc, 1)
                self.assertEqual(checks[row]["status"], "FAIL")
                self.assertIn("rc 1", checks[row]["detail"])
                self.assertEqual(sorted(deleted), sorted(created))

    def test_lost_results_are_reported_as_incomplete(self):
        rc, report, checks, created, deleted, trace = self.run_case(FAKE_RESULTS_UNWRITABLE="1")
        self.assertEqual(rc, 1)
        self.assertEqual(checks["nonroot-report-complete"]["status"], "FAIL")
        self.assertIn("result write failed True", checks["nonroot-report-complete"]["detail"])
        self.assertEqual(sorted(deleted), sorted(created))

    def test_operator_script_state_check_needs_two_successful_reads(self):
        for fake, expected in (({}, "PASS"), ({"FAKE_TOKEN_FAIL_FROM": "2"}, "FAIL"), ({"FAKE_TOKEN_FAIL_FROM": "3"}, "FAIL"),
                               ({"FAKE_TOKEN_CHANGE_FROM": "3"}, "FAIL")):
            with self.subTest(fake=fake):
                rc, report, checks, created, deleted, trace = self.run_case(FAKE_OPERATOR="real", **fake)
                refused = checks["container-nonroot-refused"]
                self.assertEqual(refused["status"], expected, refused["detail"])
                if expected == "FAIL":
                    self.assertNotIn("state unchanged: yes", refused["detail"])
                self.assertEqual(checks["nonroot-operator-file-modes"]["status"], "PASS")
                self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
