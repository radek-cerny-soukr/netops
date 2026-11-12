"""Response redaction is at least as strict as 1.0.6 (0b2ea90).

The redactors preserve credential keywords and additionally hide SNMP communities. The
`(set|encrypted) (password|passwd)` rule does not start inside `unset` when `unset password` has no
value on its line, so it no longer takes the next line (`next`/`end`). A differential fuzz compares
both chains (worker alone, proxy then worker) of 1.0.6 and this tree over plain text, a JSON object
and a JSON string; no value hidden by 1.0.6 may be visible here, except the line after a value-less
`unset password`, which is exactly what the rule change gives back.

NETOPS_REDACTION_FUZZ_CASES sets the number of random inputs (default 50000) and
NETOPS_REDACTION_FUZZ_SEED the seed (default 20261109).
"""
import json
import os
from pathlib import Path
import random
import re
import runpy
import unittest

from netops.redaction import redact
from types import SimpleNamespace
import hashlib

from netops_helper import proxy_sanitize, engine, configuration, sanitize
from netops_helper.config_buffers import Content
from netops_helper.proxy_sanitize import sanitize_object

FIXTURES = Path(__file__).parent / "fixtures"
SOURCE = Path(__file__).resolve().parents[2]
OLD_REDACT = runpy.run_path(str(FIXTURES / "redaction_1_0_6.py"))["redact"]
OLD_HELPER = runpy.run_path(str(FIXTURES / "sanitize_1_0_6.py"))["redact"]
OLD_SANITIZE = runpy.run_path(str(FIXTURES / "proxy_sanitize_1_0_6.py"))["sanitize_object"]
CASES = int(os.environ.get("NETOPS_REDACTION_FUZZ_CASES", "50000"))
SEED = int(os.environ.get("NETOPS_REDACTION_FUZZ_SEED", "20261109"))

MARKERS = ("<REDACTED>", "<REDACTED:credential#99>", "<redacted:credential#99>", "[REDACTED]",
           "<UNVERIFIED:unclassified-field>", "<UNVERIFIED:unsupported-format>", "<UNVERIFIED:x>",
           "<PRIVATE-KEY-REDACTED>", "ENC", "SH2")
SPACES = (" ", "  ", "\t", " \t", "\n", "\r\n", "\r", "\x0b", "\x0c", " \n ", "\n\n")
ENDS = ("\n", "\r\n", "\r", "", " \n", "\\n", "\\r\\n", '",', '"}', "]", ",", ";")
# The canary on the line after a value-less `unset password`, which 1.0.6 took with that line.
VALUELESS_UNSET = re.compile(r"(?i)(?<=(?<!\w)un)set(?=\s+(?:password|passwd)[^\S\r\n]*[\r\n])")


def old_chain(value, proxy):
    return OLD_REDACT(OLD_SANITIZE(value) if proxy else value)[0]


def new_chain(value, proxy):
    return redact(sanitize_object(value) if proxy else value)[0]


def representations(text):
    yield "text", text
    yield "object", {"output": text}
    yield "json", json.dumps({"output": text})


def shown(output):
    return output if isinstance(output, str) else json.dumps(output, ensure_ascii=False)



class Generator:
    def __init__(self, seed):
        self.random = random.Random(seed)
        self.serial = 0

    def canary(self):
        self.serial += 1
        return "CNRY%07dQ" % self.serial

    def pick(self, values):
        return self.random.choice(values)

    def case(self, word):
        return self.pick((word, word.upper(), word.capitalize()))

    def value(self):
        canary = self.canary()
        shape = self.random.randrange(6)
        if shape == 0:
            return canary
        if shape == 1:
            return self.pick(MARKERS) + self.pick(("", " ", "\t")) + canary
        if shape == 2:
            return self.pick(MARKERS) + self.pick(ENDS) + canary
        if shape == 3:
            return canary + self.pick(ENDS) + self.canary()
        if shape == 4:
            return '"' + canary + '"'
        return "prefix" + self.pick(MARKERS) + canary

    def line(self):
        kind = self.random.randrange(14)
        indent = self.pick(("", "    ", "\t"))
        if kind <= 2:
            return (indent + self.case(self.pick(("set", "encrypted"))) + self.pick(SPACES)
                    + self.case(self.pick(("password", "passwd"))) + self.pick(SPACES) + self.value())
        if kind <= 4:
            # A value-less `unset password`, then any line; or a value on the same line.
            tail = self.pick(("", " ", "\t", " " + self.value(), "\t" + self.value()))
            return (indent + self.case("unset") + self.pick((" ", "\t", "\n")) + self.case(self.pick(("password", "passwd")))
                    + tail + self.pick(("\n", "\r\n", "\r")) + self.line())
        if kind == 5:
            return indent + self.pick(("set ", "", "snmp ")) + "community" + self.pick((" ", "\t", ": ", "=")) + self.value()
        if kind == 6:
            return indent + self.pick(("password", "passwd", "secret", "token", "api_token", "community")) + self.pick(
                (": ", "=", " = ", ":")) + self.value()
        if kind == 7:
            return indent + '"' + self.pick(("password", "passwd", "passphrase", "secret", "token")) + '": "' + self.canary() + '"'
        if kind == 8:
            return indent + "passphrase = " + self.value()
        if kind == 9:
            return indent + "set " + self.pick(("psksecret", "priv-pwd", "comments")) + " ENC " + self.canary()
        if kind == 10:
            return indent + self.pick(("next", "end", "config system admin", 'edit "op1"', "set hostname lab"))
        if kind == 11:
            return indent + "set " + self.pick(("password-policy", "passwords", "set-community")) + " " + self.value()
        if kind == 12:
            return self.pick(("unencrypted", "xset", "un", "\\n")) + self.case("set") + " password " + self.value()
        return indent + "-----BEGIN PRIVATE KEY-----" + self.canary() + "\n-----END PRIVATE KEY-----"

    def snmp(self):
        """Communities plus legacy anchors on and after set name / EXOS lines."""
        credential, following = self.canary(), self.canary()
        attack = self.pick(("ENC\n" + following, "set password\n" + following,
                            "password:\n" + following,
                            "-----BEGIN PRIVATE KEY-----\n" + following + "\n-----END PRIVATE KEY-----",
                            '"ENC X1"\nset alias <REDACTED>\t' + following + '\nset name "N1"',
                            '"prefix\n' + following + '"', self.value()))
        platform = self.random.randrange(5)
        if platform == 0:
            text = ('config system snmp community\nedit 1\nset name ' + credential
                    + '\nnext\nedit 2\nset name ' + attack + '\nnext\nend\n')
        elif platform == 1:
            text = ('config system snmp user\nedit reader\nset auth-pwd ' + credential
                    + '\nset priv-pwd ' + attack + '\nnext\nend\n')
        elif platform == 2:
            text = ('configure snmp add community readonly ' + credential
                    + '\nconfigure snmp add community readwrite ' + attack + '\n')
        elif platform == 3:
            text = ('config system snmp community\nedit 1\nset name ' + credential
                    + '\nnext\nedit 2\nset name ' + attack + '\nnext\nend\n'
                    + 'config system health-check\nedit check\nset community ' + self.canary() + '\nnext\nend\n')
        else:
            text = ('configure snmpv3 add community ' + credential
                    + '\nconfigure snmp add community readonly ' + attack + '\n')
        if platform in (0, 1, 3):
            wrapper = self.pick(("", "global", "vdom"))
            if wrapper:
                text = 'config ' + wrapper + '\n' + text + 'end\n'
        text += 'set password ' + self.canary() + '\n'
        return text, credential

    def text(self):
        lines = [self.line() for _ in range(self.random.randint(1, 6))]
        text = "".join(line + self.pick(("\n", "\r\n", "\n", "")) for line in lines)
        return self.snmp()[0] + text if self.random.randrange(4) == 0 else text


def canaries(text):
    return set(re.findall(r"CNRY[0-9]{7}Q", text))


class RedactionFloor106(unittest.TestCase):
    def test_the_proxy_retains_every_1_0_6_rule_plus_snmp_protection(self):
        # Range tracking changes plumbing, while each legacy matching rule must
        # remain present verbatim; the independent frozen chains below test behavior.
        frozen = runpy.run_path(str(FIXTURES / "proxy_sanitize_1_0_6.py"))
        for name in ('FORTI_ENC', 'PRIVATE_PEM', 'CISCO_SECRET', 'SHADOW_HASH',
                     'LABELED_COMMUNITY', 'SENSITIVE_TEXT_FIELD'):
            with self.subTest(rule=name):
                current, old = getattr(proxy_sanitize, name), frozen[name]
                self.assertEqual((current.pattern, current.flags), (old.pattern, old.flags))
        self.assertEqual(proxy_sanitize.SENSITIVE_KEYS, frozen['SENSITIVE_KEYS'])

    def test_standalone_control_bearing_helper_uses_the_complete_raw_chain(self):
        for text in ("prompt#\r\npassword: my CNRY0000001Q CNRY0000002Q\r\n",
                     "\x1b[0m\ntoken: first CNRY0000001Q CNRY0000002Q",
                     "\x00secret: first CNRY0000001Q CNRY0000002Q"):
            with self.subTest(text=text):
                result = sanitize.redact(text)
                self.assertNotIn("CNRY", result)
                self.assertNotIn("\r", result)
                self.assertNotIn("\x1b", result)

    def test_complete_helper_paths_never_reveal_1_0_6_canaries(self):
        # Freeze all three original layers, including helper. The existing unset
        # exception has separate tests; neutralize only that exception here.
        def old_full(text):
            for _ in range(8):
                cleaned = OLD_REDACT(OLD_SANITIZE(OLD_HELPER(text)))[0]
                if cleaned == text:
                    return text
                text = cleaned
            self.fail("frozen 1.0.6 chain did not settle")

        def configuration_path(text):
            raw = text.encode("ascii")
            source = Content((raw,), len(raw), hashlib.sha256(raw).hexdigest())
            result = configuration.response_content(source, ())
            actual = result.page(0, result.total)[0]
            self.assertEqual(result.sha256, hashlib.sha256(actual.encode()).hexdigest())
            self.assertEqual(result.total, len(actual.encode()))
            return actual

        def old_proxy_full(text):
            for _ in range(8):
                cleaned = OLD_REDACT(OLD_SANITIZE(text))[0]
                if cleaned == text:
                    return text
                text = cleaned
            self.fail("frozen proxy-worker chain did not settle")

        auth = SimpleNamespace(redaction_secrets=())
        generator = Generator(SEED + 1)
        count = max(50000, CASES)
        for index in range(count):
            snmp, credential = generator.snmp()
            text = snmp + VALUELESS_UNSET.sub("seX", generator.text())
            # Every case exercises CRLF, ANSI or C0; include multiword values
            # because an early worker pass used to expose their suffix.
            tail = "password: prefix " + generator.canary() + " " + generator.canary() + "\n"
            kind = index % 4
            if kind == 0:
                text = (text + tail).replace("\n", "\r\n")
            elif kind == 1:
                text = "\x1b[0m\n" + text + tail
            elif kind == 2:
                text = "\x00\x0b\n" + text + tail
            else:
                text = "\x1b[1m\r\n" + text + tail.replace("password", "pass\x08word")
            previous = old_full(text)
            for name, actual in (("engine", engine._redact_output(text, auth)),
                                 ("configuration", configuration_path(text)),
                                 ("response", sanitize.redact_response(text)),
                                 ("proxy-worker", redact(sanitize_object(text))[0])):
                with self.subTest(index=index, path=name):
                    if name != "proxy-worker":
                        self.assertFalse(any(ord(c) < 32 and c not in "\n\t" for c in actual))
                    self.assertEqual(redact(sanitize_object(actual))[0], actual)
                    self.assertNotIn(credential, actual)
                    floor = old_proxy_full(text) if name == "proxy-worker" else previous
                    for canary in canaries(text):
                        if canary not in floor:
                            self.assertNotIn(canary, actual)
            if index and index % 5000 == 0:
                print("complete helper floor: %d/%d cases, 0 leaks" % (index, count), flush=True)
        print("complete helper floor: %d inputs, %d paths, 0 leaks" % (count, 4 * count), flush=True)

    def test_snmp_detection_requires_a_command_line_and_decodes_json(self):
        for text in ('config ' * 20000, 'comment config system snmp community', 'snmp_community'):
            self.assertFalse(proxy_sanitize._contains_snmp(text))
        for text in ('config system snmp community\nset name CNRY0000001Q',
                     '  configure snmp add community readonly CNRY0000001Q',
                     '\n\tconfig switch-controller snmp-community\nset name CNRY0000001Q'):
            self.assertTrue(proxy_sanitize._contains_snmp(text))
            self.assertTrue(proxy_sanitize._contains_snmp(json.dumps({'output': text})))

    def test_snmp_masking_handles_legacy_access_markers_and_escaped_json(self):
        self.assertEqual(sanitize_object({'snmp_community': 'CNRY0000001Q'}),
                         {'snmp_community': '<REDACTED>'})
        auth = SimpleNamespace(redaction_secrets=())
        for text in ('configure snmp add community readonly CNRY0000001Q\n',
                     'configure snmp add community readwrite CNRY0000001Q\n',
                     'configure snmpv3 add community CNRY0000001Q\n',
                     'config system snmp community\nedit 1\nset name "CNRY0000001Q"\nend\n'):
            for clean in (sanitize.redact_response, sanitize.redact, proxy_sanitize.sanitize_text,
                          lambda value: engine._redact_output(value, auth)):
                self.assertNotIn('CNRY', clean(text))
            encoded = json.dumps({'output': text}).replace('snmp', r'\u0073nmp')
            result = sanitize_object(encoded)
            self.assertNotIn('CNRY', result)
            self.assertEqual(sanitize_object(result), result)

    def test_b1_snmp_cross_line_and_quote_reproductions(self):
        prefix = "config system snmp community\nedit 1\nset name "
        cases = [prefix + anchor + "\nCANARY\n" + end + "\nnext\nend\n"
                 for anchor, end in (("ENC", ""), ("set password", ""), ("password:", ""),
                                     ("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"))]
        cases += ["configure snmp add community readonly ENC\nCANARY\n",
                  prefix + '"N0"\nset community "ENC X1"\nset alias <REDACTED>\tCANARY\nset name "N1"\nend\n']
        auth = SimpleNamespace(redaction_secrets=())
        for index, text in enumerate(cases):
            for name, actual in (("engine", engine._redact_output(text, auth)),
                                 ("response", sanitize.redact_response(text)),
                                 ("proxy-worker", redact(sanitize_object(text))[0])):
                with self.subTest(text=text, path=name):
                    # The quote reproduction was hidden by proxy+worker only;
                    # helper first already consumed its closing quote in 1.0.6.
                    if index < 5 or name == "proxy-worker":
                        self.assertNotIn("CANARY", actual)
            raw = text.encode()
            content = Content((raw,), len(raw), hashlib.sha256(raw).hexdigest())
            result = configuration.response_content(content, ())
            if index < 5:
                self.assertNotIn("CANARY", result.page(0, result.total)[0])
            for _, document in representations(text):
                old, new = shown(old_chain(document, True)), shown(new_chain(document, True))
                if "CANARY" not in old:
                    self.assertNotIn("CANARY", new)

    def test_review_reproductions_match_1_0_6(self):
        cases = [
            "set password <REDACTED:credential#99>\n", "set password <redacted:credential#99>\n",
            "set password <REDACTED>\n", "set password [REDACTED]\n", "set password <UNVERIFIED:unclassified-field>\n",
            r"set password <REDACTED>\nCANARY", r"set password <REDACTED>\r\nCANARY", 'set password <REDACTED>",CANARY',
            "set password\nCANARY\n", "set password\r\nCANARY\n", "set\rpassword\rCANARY\n", "encrypted passwd\nCANARY\n",
            "set password\x0bCANARY\n", "set password\x0cCANARY\n",
            "community <REDACTED:credential#99>\n", "community <UNVERIFIED:unclassified-field>\n", "community [REDACTED]\n",
            {"api_token": "<PRIVATE-KEY-REDACTED>"}, {"community": "[REDACTED]"},
            {"output": "community <REDACTED:credential#99>\n"}, {"output": "set password <REDACTED>\n"},
            json.dumps({"output": r"set password <REDACTED>\nCANARY"}),
        ]
        for value in cases:
            for proxy in (False, True):
                with self.subTest(value=value, proxy=proxy):
                    self.assertEqual(old_chain(new_chain(value, proxy), proxy), old_chain(value, proxy))
                    self.assertNotIn("CANARY", shown(new_chain(value, proxy)))
        # Finding 6: the JSON stays valid and equal to 1.0.6.
        document = json.dumps({"output": r"set password <REDACTED>\nCANARY"})
        self.assertEqual(json.loads(redact(document)[0]), {"output": "set password [REDACTED]"})

    def test_unset_password_keeps_the_next_line_and_hides_a_value_on_its_own_line(self):
        self.assertEqual(redact("    unset password\n    next\n")[0], "    unset password\n    next\n")
        self.assertEqual(redact("    unset passwd\r\nend\r\n")[0], "    unset passwd\r\nend\r\n")
        self.assertEqual(old_chain("    unset password\n    next\n", False), "    un[REDACTED]\n")
        for value in ("unset password CANARY\n", "UNSET Passwd\tCANARY\n", "unset password \x0bCANARY\n",
                      "unset\npassword CANARY\n", "unset password\nset password CANARY\n"):
            with self.subTest(value=value):
                self.assertNotIn("CANARY", redact(value)[0])
        # Everything else of the rule is 1.0.6, including whitespace across line ends after `set password`.
        for value in ("set password\n    CANARY\n", "unencrypted password CANARY\n", "\\nset password CANARY",
                      "Xset password CANARY"):
            with self.subTest(value=value):
                self.assertEqual(OLD_REDACT(redact(value)[0])[0], OLD_REDACT(value)[0])
                self.assertNotIn("CANARY", redact(value)[0])

    def test_the_unset_exception_is_only_for_the_standalone_word(self):
        for value in ("sunset password\nCANARY\n", "xunset passwd\rCANARY\n", "unUNSET password\nCANARY\n",
                      "sunset password\r\nCANARY\n", "xunset password\x0bCANARY\n", "sunset passwd\x0cCANARY\n",
                      "\\nsunset password\nCANARY", "_unset password\nCANARY\n"):
            for proxy in (False, True):
                with self.subTest(value=value, proxy=proxy):
                    self.assertEqual(old_chain(new_chain(value, proxy), proxy), old_chain(value, proxy))
                    self.assertNotIn("CANARY", shown(new_chain(value, proxy)))
                    # The oracle does not excuse these inputs as a value-less `unset password`.
                    self.assertIsNone(VALUELESS_UNSET.search(value))
        for value in ("unset password\nCANARY\n", "a\nUNSET passwd\r\nCANARY\n", "x unset password \n\x0cCANARY\n"):
            with self.subTest(value=value):
                self.assertIsNotNone(VALUELESS_UNSET.search(value))
                self.assertIn("CANARY", redact(value)[0])

    def test_json_key_redaction_does_not_unhide_its_associated_value(self):
        cases = ('{"set password ":"CANARY-associated-value","sibling":"CANARY-neighbor"}',
                 '{"-----BEGIN PRIVATE KEY-----":"CANARY-associated-value","end":"-----END PRIVATE KEY-----"}')
        for raw in cases:
            for _, value in representations(raw):
                for proxy in (False, True):
                    old, new = old_chain(value, proxy), new_chain(value, proxy)
                    for canary in ('CANARY-associated-value', 'CANARY-neighbor'):
                        if canary not in shown(old):
                            self.assertNotIn(canary, shown(new))
                    if raw == cases[0]:
                        self.assertNotIn('CANARY-', shown(new))
                    self.assertEqual(new_chain(new, proxy), new)
            self.assertEqual(json.loads(redact(raw)[0]), '[REDACTED]')

    def test_differential_fuzz_shows_nothing_that_1_0_6_hid(self):
        generator = Generator(SEED)
        violations, allowed, stricter, compared, inputs, unset_inputs = [], 0, 0, 0, 0, 0
        for index in range(CASES):
            if index and index % 5000 == 0:
                print("redaction fuzz: %d/%d inputs" % (index, CASES), flush=True)
            text = generator.text()
            inputs += 1
            unset_inputs += "unset" in text.lower()
            neutral = VALUELESS_UNSET.sub("seX", text)
            for name, value in representations(text):
                neutral_value = dict(representations(neutral))[name]
                for proxy in (False, True):
                    compared += 1
                    old, new = shown(old_chain(value, proxy)), shown(new_chain(value, proxy))
                    for canary in canaries(text):
                        if canary in old or canary not in new:
                            stricter += canary in old and canary not in new
                            continue
                        if canary in shown(old_chain(neutral_value, proxy)):
                            allowed += 1
                        else:
                            violations.append((name, proxy, text, canary))
        print("\nredaction fuzz: seed %d, %d inputs (%d with unset), %d comparisons, %d leaks, "
              "%d canaries after a value-less unset password, %d hidden only here"
              % (SEED, inputs, unset_inputs, compared, len(violations), allowed, stricter))
        self.assertEqual(violations[:5], [])
        self.assertGreaterEqual(inputs, min(CASES, 50000))


if __name__ == "__main__":
    unittest.main()
