import asyncio
import importlib.util
import time
import unittest
from pathlib import Path

from netops import redaction

spec = importlib.util.spec_from_file_location("redaction_full_baseline", Path(__file__).parent / "fixtures" / "redaction_reference.py")
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)

WINDOW = 262144
EDGES = (16384, 32768, WINDOW, 2 * WINDOW)
LABELS = sorted({variant for field in redaction.SECRET_FIELDS for variant in (field, field.replace("_", "-"), field.upper())}
                | {"passwd", "PASSWD", "community", "Community", "-----BEGIN ", "\\"})


class WindowBoundaries(unittest.TestCase):
    def same(self, text, secrets=()):
        self.assertEqual(redaction.redact(text, secrets), baseline.redact(text, secrets), repr(text[:40]) + "..." + repr(text[-60:]))

    def test_every_label_on_every_side_of_a_window_edge_redacts_like_the_full_scan(self):
        for label in LABELS:
            value = label + "=synthetic-canary" if label not in ("\\", "-----BEGIN ") else label + "RSA PRIVATE KEY-----x-----END RSA PRIVATE KEY-----"
            for edge in EDGES:
                for shift in (-len(value), -len(label), -1, 0, 1):
                    with self.subTest(label=label, edge=edge, shift=shift):
                        start = edge + shift
                        self.same("." * start + " " + value + " " + "." * 100)

    def test_text_lengths_around_window_multiples_and_label_at_the_very_end(self):
        for length in (0, 1, 16383, 16384, 16385, 32768 + 63, 32768 + 64, WINDOW - 1, WINDOW, WINDOW + 1, 2 * WINDOW, 2 * WINDOW + 63, 2 * WINDOW + 64):
            with self.subTest(length=length):
                self.same("." * length)
                self.same("." * length + " token=synthetic-canary")
                self.same("." * length + "\\")

    def test_known_secret_across_a_window_edge_is_still_redacted(self):
        secret = "synthetic-known-value"
        self.assertIsNone(redaction.CANDIDATE.search(secret))
        for edge in EDGES:
            for shift in range(-len(secret), 2):
                with self.subTest(edge=edge, shift=shift):
                    text = "." * (edge + shift) + secret + "." * 50
                    self.same(text, (secret,))
                    self.assertNotIn(secret, str(redaction.redact(text, (secret,))))

    def test_known_secret_inside_list_items_is_redacted_like_the_full_scan(self):
        secret = "synthetic-known-value"
        for items in (["[x]", secret], [secret] * 3, ["a" * 3, "b" + secret + "c", "[x]"], [["[x]", secret]], [{"note": secret}]):
            with self.subTest(items=items):
                value = {"oids": items}
                self.assertEqual(redaction.redact(value, (secret,)), baseline.redact(value, (secret,)))
                self.assertNotIn(secret, str(redaction.redact(value, (secret,))[0]))

    def test_a_large_neutral_string_does_not_hold_the_loop(self):
        value = "." * (8 * 1024 * 1024)
        async def measure():
            gaps, last = [], time.monotonic()
            task = asyncio.create_task(asyncio.to_thread(redaction.redact, value))
            while not task.done():
                await asyncio.sleep(0.01)
                now = time.monotonic()
                gaps.append(now - last)
                last = now
            self.assertEqual(await task, (value, []))
            return max(gaps)
        largest = asyncio.run(measure())
        print("largest loop gap %.3f s" % largest, flush=True)
        self.assertLess(largest, 2.0, largest)


if __name__ == "__main__":
    unittest.main()
