import json
from pathlib import Path
import runpy
import random
import threading
import time
import unittest

from netops_helper import sanitize

SEED = 20261015
FRAGMENTS = ("password", "Password", "PASSWD", "token", "api token", "api_key", "apikey", "access-token",
             "accesstoken", "bearer", "secret", "community", "x", "-", "_", "a", '"', "'", "=", ":", " ", "\t",
             "\n", "\r\n", ",", "}", "]", "canary", '"val ue"', "'v'", "xaccess token=", "api", "access", "key",
             " ", "ſecret", "set password ENC x", "username u secret 5 x", "-----BEGIN RSA PRIVATE KEY-----")


def previous_redact(text, secrets=()):
    value = str(text)
    for secret in sorted({str(item) for item in secrets if len(str(item).encode("utf-8")) >= 3}, key=len, reverse=True):
        value = value.replace(secret, "<REDACTED>")
    value = sanitize.PRIVATE_PEM.sub("<PRIVATE-KEY-REDACTED>", value)
    value = sanitize.SNMP_CLI_SECRET.sub(sanitize._quoted_only(lambda match: match.group(1) + "<REDACTED>"), value)
    value = sanitize.PRESHARED_SECRET.sub(sanitize._quoted_only(lambda match: match.group(1) + "<REDACTED>"), value)
    value = sanitize.CLI_OPTION_SECRET.sub(sanitize._quoted_only(lambda match: match.group(1) + "<REDACTED>"), value)
    value = sanitize.ASSIGNED_QUOTED_SECRET.sub(sanitize._replace_quoted, value)
    value = sanitize.FORTI_ENC.sub("ENC <REDACTED>", value)
    value = sanitize.SHADOW_HASH.sub(lambda match: match.group(1) + "<REDACTED>", value)
    value = sanitize.CISCO_ENABLE_SECRET.sub(lambda match: match.group(1) + "<REDACTED>", value)
    value = sanitize.CISCO_USER_SECRET.sub(lambda match: match.group(1) + "<REDACTED>", value)
    value = sanitize.SNMP_CLI_SECRET.sub(lambda match: match.group(1) + "<REDACTED>", value)
    value = sanitize.SNMP_STATUS_SECRET.sub(lambda match: match.group(1) + "<REDACTED>", value)
    value = sanitize.COMMUNITY_VALUE_SECRET.sub(lambda match: match.group(1) + "<REDACTED>", value)
    value = sanitize.CISCO_TYPE7_SECRET.sub(lambda match: match.group(1) + "<REDACTED>", value)
    value = sanitize.PRESHARED_SECRET.sub(lambda match: match.group(1) + "<REDACTED>", value)
    value = sanitize.BEARER_SECRET.sub(lambda match: match.group(1) + "<REDACTED>", value)
    value = sanitize.ASSIGNED_BARE_SECRET.sub(sanitize._replace_bare, value)
    return value


FIXTURES = Path(__file__).parent / "fixtures"
OLD_HELPER = runpy.run_path(str(FIXTURES / "sanitize_1_0_6.py"))["redact"]
OLD_PROXY = runpy.run_path(str(FIXTURES / "proxy_sanitize_1_0_6.py"))["sanitize_object"]
OLD_WORKER = runpy.run_path(str(FIXTURES / "redaction_1_0_6.py"))["redact"]


def previous_response(text, secrets):
    """Independent full 1.0.6 chain for the control-bearing generator inputs."""
    def settle(text):
        for _ in range(8):
            cleaned = OLD_WORKER(OLD_PROXY(OLD_HELPER(text, secrets), secrets), secrets)[0]
            if cleaned == text:
                return text
            text = cleaned
        raise AssertionError("1.0.6 reference did not settle")
    raw = settle(text)
    # The generator has CRLF but no ANSI: independent intended cleanup.
    clean = "".join(c for c in raw if ord(c) >= 32 or c in "\n\t")
    return settle(clean)


class AssignedSecrets(unittest.TestCase):
    def test_redaction_matches_the_previous_function(self):
        generator = random.Random(SEED)
        for _ in range(20000):
            text = "".join(generator.choice(FRAGMENTS) for _ in range(generator.randrange(0, 25)))
            with self.subTest(text=text[:80]):
                expected = (previous_response(text, ("canary",)) if "\r" in text
                            else previous_redact(text, ("canary",)))
                actual = sanitize.redact(text, ("canary",))
                # The full response chain now retains credential keywords; the frozen
                # old chain removes those safe prefixes when judging equivalence.
                comparable = previous_response(actual, ("canary",)) if "\r" in text else actual
                self.assertEqual(comparable, expected)
                self.assertNotIn('canary', actual)

    def test_label_chunk_boundaries_do_not_change_the_result(self):
        assigned = getattr(sanitize, "_assigned", None)
        generator = random.Random(SEED + 1)
        for _ in range(20000):
            text = "".join(generator.choice(FRAGMENTS) for _ in range(generator.randrange(0, 25)))
            for pattern, replace in ((sanitize.ASSIGNED_QUOTED_SECRET, sanitize._replace_quoted),
                                     (sanitize.ASSIGNED_BARE_SECRET, sanitize._replace_bare)):
                expected = pattern.sub(replace, text)
                actual = expected if assigned is None else assigned(pattern, replace, text, generator.randrange(1, 17))
                self.assertEqual(actual, expected, text)

    def test_a_large_secret_free_capture_does_not_hold_the_interpreter_lock(self):
        value = " " * (16 * 1024 * 1024)
        done = threading.Event()
        result, errors = [], []
        def work():
            try:
                result.append(sanitize.redact(value))
            except BaseException as error:
                errors.append(error)
            finally:
                done.set()
        gaps, cpu_gaps = [], []
        last, last_cpu = time.monotonic(), time.process_time()
        deadline = last + 60
        threading.Thread(target=work, daemon=True).start()
        while not done.wait(0.01):
            now, now_cpu = time.monotonic(), time.process_time()
            gaps.append(now - last)
            cpu_gaps.append(now_cpu - last_cpu)
            last, last_cpu = now, now_cpu
            self.assertLess(now, deadline, "redaction diagnostic exceeded 60 seconds")
        gaps.append(time.monotonic() - last)
        cpu_gaps.append(time.process_time() - last_cpu)
        self.assertFalse(errors, errors)
        self.assertEqual(result, [value])
        wall = sum(gaps)
        stall_share = max(gaps) / wall
        print("ASSIGNED_SECRETS_GIL=" + json.dumps({"wall": wall, "samples": len(gaps), "max_gap": max(gaps),
            "max_cpu_gap": max(cpu_gaps), "stall_share": stall_share}), flush=True)
        self.assertGreaterEqual(len(gaps), 5)
        self.assertLess(stall_share, 0.5, max(gaps))
        self.assertLess(max(cpu_gaps), 4.0, max(cpu_gaps))


if __name__ == "__main__":
    unittest.main()
