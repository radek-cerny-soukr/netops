import random
import re
import time
import unittest
from netops.redaction import private_keys, redact

REFERENCE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)
FRAGMENTS = ("-----BEGIN ", "-----END ", "RSA ", "EC ", "OPENSSH ", "PRIVATE KEY-----", "PRIVATE KEY", "-----", "-", "A", " ", "\n", "\r\n", "x", "key", "BEGIN", "END")


class PrivateKeyRedaction(unittest.TestCase):
    def test_matches_the_previous_expression_on_generated_and_listed_text(self):
        listed = [
            "",
            "no key here",
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
            "a -----BEGIN RSA PRIVATE KEY-----x-----END RSA PRIVATE KEY----- b -----BEGIN EC PRIVATE KEY-----y-----END EC PRIVATE KEY----- c",
            "-----BEGIN PRIVATE KEY----- no end",
            "-----END PRIVATE KEY----- no begin -----BEGIN PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----a-----BEGIN PRIVATE KEY-----b-----END PRIVATE KEY-----c",
            "-----BEGIN PRIVATE KEY-----\r\nz\r\n-----END OPENSSH PRIVATE KEY-----tail",
            "-----BEGIN PRIVATE KEY PRIVATE KEY-----q-----END PRIVATE KEY-----",
        ]
        generator = random.Random(20261015)
        generated = ["".join(generator.choice(FRAGMENTS) for _ in range(generator.randrange(0, 40))) for _ in range(20000)]
        for text in listed + generated:
            with self.subTest(text=text[:80]):
                self.assertEqual(private_keys(text), REFERENCE.sub("[REDACTED]", text))

    def test_redact_still_marks_a_private_key_inside_a_value(self):
        payload, paths = redact({"output": "x -----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY----- y"})
        self.assertEqual(payload["output"], "x [REDACTED] y")
        self.assertEqual(paths, [["output"]])

    def test_many_unterminated_headers_scale_linearly(self):
        header = "-----BEGIN A PRIVATE KEY-----"
        def elapsed(count):
            text = header * count
            best = None
            for _ in range(3):  # the best of three is the least disturbed by a busy runner
                start = time.perf_counter()
                self.assertEqual(private_keys(text), text)
                taken = time.perf_counter() - start
                best = taken if best is None else min(best, taken)
            return best
        small, large = elapsed(20000), elapsed(80000)
        self.assertLess(large, max(small, 0.01) * 8, (small, large))
        whole = elapsed(4194304 // len(header))
        self.assertLess(whole, 60, whole)  # hard stop; quadratic handling of 4 MiB needs hours


if __name__ == "__main__":
    unittest.main()
