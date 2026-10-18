import hashlib
import json
import subprocess
import sys
import unittest

from netops.redaction import redact

WORKER = r"""
import hashlib,json,signal,sys,time
from netops.redaction import redact
value=json.load(sys.stdin)
class BudgetExceeded(Exception):
    pass
def exceeded(*args):
    raise BudgetExceeded()
signal.signal(signal.SIGALRM, exceeded)
print("START", flush=True)
start=time.monotonic()
signal.setitimer(signal.ITIMER_REAL, 3.0)
try:
    result,paths=redact(value)
except BudgetExceeded:
    signal.setitimer(signal.ITIMER_REAL,0)
    print(json.dumps({"budget_exceeded":True}),flush=True)
    raise SystemExit(2)
signal.setitimer(signal.ITIMER_REAL,0)
print(json.dumps({"sha256":hashlib.sha256(result.encode()).hexdigest(),
                 "paths":paths,"seconds":time.monotonic()-start}),flush=True)
"""

class PublicRedactionAdversarial(unittest.TestCase):
    def test_private_key_boundaries_and_path_contract(self):
        begin = "-----BEGIN PRIVATE KEY-----"
        end = "-----END PRIVATE KEY-----"
        rsa = "-----BEGIN RSA PRIVATE KEY-----"
        ec_end = "-----END EC PRIVATE KEY-----"
        cases = [
            ("before"+begin+"a\nb"+end+"after", "before[REDACTED]after"),
            (end+"before"+begin+"a"+end, end+"before[REDACTED]"),
            (rsa+"a"+begin+"b"+ec_end+"c"+end, "[REDACTED]c"+end),
            (rsa+"a"+ec_end, "[REDACTED]"),
            (begin+"a\r\nb"+end, "[REDACTED]"),
            (begin+"unterminated", begin+"unterminated"),
            ("-----BEGIN RSA\tPRIVATE KEY-----a"+end,
             "-----BEGIN RSA\tPRIVATE KEY-----a"+end),
            ("-----BEGIN RSA\u00a0PRIVATE KEY-----a"+end,
             "-----BEGIN RSA\u00a0PRIVATE KEY-----a"+end),
            (begin+"a"+end+" / "+begin+"b"+end, "[REDACTED] / [REDACTED]"),
        ]
        for raw, expected in cases:
            with self.subTest(case=cases.index((raw, expected))):
                actual, paths = redact({"data":raw})
                self.assertEqual(actual, {"data":expected})
                self.assertEqual(paths, [["data"]] if raw != expected else [])

    def test_embedded_json_and_known_secret_order(self):
        raw = '{"outer":[{"password":"synthetic-key","info":"synthetic-marker"}]}'
        cleaned, paths = redact({"payload":raw}, ("synthetic-marker",))
        self.assertEqual(cleaned, {"payload":
                         '{"outer":[{"password":"[REDACTED]","info":"[REDACTED]"}]}'})
        self.assertEqual(paths, [
            ["payload","$json","outer","0","password"],
            ["payload","$json","outer","0","info"], ["payload"]])
        marker = "-----BEGIN PRIVATE KEY-----"
        cleaned, paths = redact(marker+"body-----END PRIVATE KEY-----", (marker,))
        self.assertEqual(cleaned, "[REDACTED]body-----END PRIVATE KEY-----")
        self.assertEqual(paths, [[]])

    def test_untrusted_max_strings_finish_within_work_budget(self):
        size = 4 * 1024 * 1024 - 1024
        patterns = [
            ("unterminated_keys", "-----BEGIN PRIVATE KEY-----"),
            ("malformed_header", "-----BEGIN "+"A"*512+"!"),
            ("keyword_no_separator", "token"+" "*512),
            ("whitespace_no_separator", "password"+" "*size),
            ("cli_whitespace_no_password", "set "+" "*size),
            ("cli_prefix_no_password", "encrypted"+" "*512),
        ]
        for name, pattern in patterns:
            with self.subTest(shape=name):
                value = (pattern * (size // len(pattern) + 1))[:size]
                process = subprocess.run(
                    [sys.executable, "-B", "-c", WORKER],
                    input=json.dumps(value), text=True, capture_output=True, timeout=15)
                lines = process.stdout.splitlines()
                self.assertTrue(lines and lines[0] == "START",
                                "worker did not enter measured redaction phase")
                self.assertEqual(process.returncode, 0, process.stdout[:256])
                result = json.loads(lines[1])
                self.assertEqual(result["sha256"], hashlib.sha256(value.encode()).hexdigest())
                self.assertEqual(result["paths"], [])
                self.assertLess(result["seconds"], 3.0)

if __name__ == "__main__":
    unittest.main()
