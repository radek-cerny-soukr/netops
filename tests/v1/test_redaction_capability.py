import asyncio
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from netops.audit import Audit
from netops.redaction import redact

spec = importlib.util.spec_from_file_location("redaction_capability_baseline",
                                              Path(__file__).parent / "fixtures" / "redaction_1_0_6.py")
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)

CAPABILITY = "128-length passwd                 : enabled"
# Synthetic value inside a password: the review reproduction (literal backslash + n, not a line break).
INSIDE_PASSWORD = r'set password "prefix\n128-length passwd : enabled\nSYNTHETIC_TAIL"'


class WtpCapabilityLine(unittest.TestCase):
    def test_other_passwd_values_are_still_redacted(self):
        for text in ("128-length passwd : disabled", "x 128-length passwd : enabled",
                     "128-length passwd : enabledx", "passwd: enabled", "128-length passwd : en"):
            cleaned, paths = redact(text)
            self.assertIn("[REDACTED]", cleaned, text)
            self.assertEqual(paths, [[]])

    def test_capability_inside_a_password_does_not_shorten_the_redaction(self):
        for value in (INSIDE_PASSWORD, {"output": INSIDE_PASSWORD}, [INSIDE_PASSWORD],
                      "show\n" + INSIDE_PASSWORD + "\nend", json.dumps({"o": INSIDE_PASSWORD})):
            cleaned, paths = redact(value)
            self.assertEqual(baseline.redact(cleaned)[0], baseline.redact(value)[0], repr(value))
            self.assertNotIn("SYNTHETIC_TAIL", json.dumps(cleaned))
            self.assertNotIn("prefix", json.dumps(cleaned))
        self.assertEqual(redact({"output": INSIDE_PASSWORD})[0], {"output": "set password [REDACTED]"})

    def test_escaped_backslash_n_in_json_is_data_not_a_line_break(self):
        # Decoded value: a\n128-length passwd : enabled with a literal backslash, one line.
        value = json.dumps({"o": "a\\n" + CAPABILITY})
        self.assertIn('\\\\n128-length', value)
        cleaned, _ = redact(value)
        self.assertNotIn("passwd", cleaned)
        self.assertEqual(redact(value), baseline.redact(value))
        tail = json.dumps({"o": "set password \"x\\n" + CAPABILITY + "\\nSYNTHETIC_TAIL\""})
        self.assertNotIn("SYNTHETIC_TAIL", redact(tail)[0])

    def test_plain_text_backslash_n_is_not_a_line_break(self):
        for text in ("a\\n" + CAPABILITY, CAPABILITY + "\\nSYNTHETIC_TAIL", "token=x\\n" + CAPABILITY):
            self.assertEqual(redact(text), baseline.redact(text), text)
            self.assertNotIn("passwd", redact(text)[0])

    def test_capability_in_json_key_matches_1_0_6(self):
        text = '{"128-length passwd : enabled":"SYNTHETIC_TAIL"}'
        for value in (text, {"output": text}, [text], json.dumps({"output": text})):
            cleaned = redact(value)[0]
            self.assertNotIn("SYNTHETIC_TAIL", json.dumps(cleaned))
            self.assertNotIn("enabled", json.dumps(cleaned))
            self.assertEqual(redact(cleaned)[0], cleaned)

    def test_audit_redacts_capability_in_json_key(self):
        async def scenario(directory):
            audit = Audit(directory, {"mode": "local"})
            body = {"output": '{"128-length passwd : enabled":"SYNTHETIC_TAIL"}'}
            await audit.record("response", json.dumps(body).encode(), "synthetic-key", decode="response")
            records = [json.loads(line) for path in audit._files() for line in path.read_bytes().splitlines()]
            return body, records
        with tempfile.TemporaryDirectory() as directory:
            body, records = asyncio.run(scenario(directory))
        self.assertEqual(records[0]["payload"], {"output": '"[REDACTED]"'})
        self.assertNotIn("SYNTHETIC_TAIL", json.dumps(records))

    def test_audit_record_matches_1_0_6_and_hides_password_tail(self):
        async def scenario(directory):
            audit = Audit(directory, {"mode": "local"})
            body = {"untrusted_device_output": "Version: x\n" + CAPABILITY + "\n" + INSIDE_PASSWORD + "\n"
                    + "set password \"y\n" + CAPABILITY + "\nSYNTHETIC_SECOND\"\npassword: synthetic-audit\n"}
            await audit.record("response", json.dumps(body).encode(), "synthetic-correlation", decode="response")
            return body, [json.loads(line) for path in audit._files() for line in path.read_bytes().splitlines()]
        with tempfile.TemporaryDirectory() as directory:
            body, records = asyncio.run(scenario(directory))
        flat = json.dumps(records)
        self.assertEqual(len(records), 1)
        output = records[0]["payload"]["untrusted_device_output"]
        for hidden in ("SYNTHETIC_TAIL", "prefix", "synthetic-audit"):
            self.assertNotIn(hidden, flat)
        self.assertEqual(baseline.redact(output)[0], baseline.redact(body)[0]["untrusted_device_output"])
        self.assertIn(["payload", "untrusted_device_output"], records[0]["redaction"]["paths"])


if __name__ == "__main__":
    unittest.main()
