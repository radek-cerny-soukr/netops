import json
import re
import subprocess
import sys
import time
import unittest
from pathlib import Path

from netops.redaction import redact as gateway_redact
from netops_helper import engine, proxy_sanitize
from netops_helper.sanitize import redact as engine_redact

RUCKUS = ("WLAN Service:\n  ID:\n    1:\n      NAME = corp\n      ESSID = corp\n"
          "      Authentication = open\n      Encryption = wpa2\n      Algorithm = aes\n"
          "      Passphrase = Synth Wifi 2026!\n      VLAN = 20\n")
PASSPHRASE = "Synth Wifi 2026!"
CLI = "ExecStart=/usr/bin/app --password synthpw123 --api-key=synthkey456 --password-file /etc/app/pw --verbose\n"
FORTIOS = "config system admin\n edit admin\n set passwd ENC SH2synthEnc789\n set accprofile super_admin\n next\nend\n"
JSON_TEXT = 'resp {"password": "synth json pw", "user": "admin"}\n'
SECRETS = (PASSPHRASE, "synthpw123", "synthkey456", "SH2synthEnc789", "synth json pw")
SAFE = ("NAME = corp", "Encryption = wpa2", "Algorithm = aes", "VLAN = 20", "--password-file /etc/app/pw",
        "--verbose", "set accprofile super_admin", '"user": "admin"')

OLD_REFUSALS = {
    "fortinet": re.compile(
        r"(?mi)^[ \t]*(?:Command fail\.(?:[ \t]+Return code[ \t]+-?[0-9]+)?"
        r"|command parse error before[^\r\n]*|Unknown action[ \t]+[0-9]+"
        r"|(?:%[ \t]+)?Inbound soft reconfiguration not enabled)[ \t]*\r?$"),
    "juniper_junos": re.compile(
        r"(?m)^[ \t]*error: (?:syntax error, expecting <command>: [^\r\n]*"
        r"|unknown command: [^\r\n]*|permission denied: [^\r\n]*"
        r"|the [a-z0-9-]+ subsystem is not running)[ \t]*\r?$"),
    "extreme_exos": re.compile(
        r"(?mi)^[ \t]*(?:This user does not have permissions for this command\."
        r"|Method is not implemented on this platform\."
        r"|%%[ \t]+(?:Invalid input detected|Unrecognized command|Incomplete command|Ambiguous command)[^\r\n]*)[ \t]*\r?$"),
}
HEADS = (("fortinet", "command parse error before"), ("juniper_junos", "error: unknown command: "),
         ("juniper_junos", "error: permission denied: "),
         ("juniper_junos", "error: syntax error, expecting <command>: "),
         ("extreme_exos", "%% Invalid input detected"))
SEARCH = "import re,sys;p=re.compile(sys.argv[1],int(sys.argv[2]));p.search(sys.stdin.read())"


def proxy_path(text):
    message = {"jsonrpc": "2.0", "id": 1, "result": {"content": [
        {"type": "text", "text": json.dumps({"ok": True, "output": text})}]}}
    cleaned = proxy_sanitize.sanitize_object(message)
    return json.loads(cleaned["result"]["content"][0]["text"])


class EngineFormats(unittest.TestCase):
    def test_ruckus_passphrase_line_is_redacted_whole(self):
        out = engine_redact(RUCKUS)
        self.assertIn("      Passphrase = <REDACTED>\n", out)
        self.assertNotIn("Synth", out)

    def test_process_arguments_are_redacted(self):
        out = engine_redact(CLI)
        self.assertIn("--password <REDACTED> --api-key=<REDACTED>", out)
        self.assertNotIn("synthpw123", out)
        self.assertNotIn("synthkey456", out)

    def test_fortios_psk_and_json_text_stay_redacted(self):
        out = engine_redact(FORTIOS + JSON_TEXT + "set psksecret synthpsk42\n")
        for secret in ("SH2synthEnc789", "synth json pw", "synthpsk42"):
            self.assertNotIn(secret, out)

    def test_safe_diagnostics_are_preserved(self):
        out = engine_redact(RUCKUS + CLI + FORTIOS + JSON_TEXT)
        for safe in SAFE:
            self.assertIn(safe, out)


    def test_only_dynamic_psk_state_stays_visible(self):
        self.assertEqual(engine_redact("      Dynamic PSK = ENABLED\n"), "      Dynamic PSK = ENABLED\n")
        for line, secret in (("      Dynamic PSK = Synth-dpsk-9\n", "Synth-dpsk-9"),
                             ("      Dynamic PSK = Disabledx\n", "Disabledx"),
                             ("      PSK = Disabled\n", "Disabled"), ("      psk = enabled\n", "enabled")):
            with self.subTest(line=line):
                out = engine_redact(line)
                self.assertNotIn(secret, out)
                self.assertIn("<REDACTED>", out)


class GatewayFormats(unittest.TestCase):
    def test_passwd_and_psksecret_fields_are_redacted(self):
        self.assertEqual(gateway_redact({"passwd": "synth-pw1"})[0], {"passwd": "[REDACTED]"})
        self.assertEqual(gateway_redact({"psksecret": "synth-psk"})[0], {"psksecret": "[REDACTED]"})

    def test_json_inside_text_is_redacted(self):
        out = gateway_redact({"t": JSON_TEXT})[0]["t"]
        self.assertNotIn("synth json pw", out)
        self.assertIn('resp {"password": "[REDACTED]"', out)
        self.assertIn('"user": "admin"', out)

    def test_ruckus_passphrase_line_is_redacted(self):
        out = gateway_redact({"t": RUCKUS})[0]["t"]
        self.assertIn("      Passphrase = [REDACTED]\n", out)
        self.assertNotIn("Synth", out)
        for safe in SAFE[:4]:
            self.assertIn(safe, out)

    def test_fortios_set_passwd_enc_is_redacted(self):
        out = gateway_redact({"t": FORTIOS})[0]["t"]
        self.assertNotIn("SH2synthEnc789", out)
        self.assertIn("set accprofile super_admin", out)

    def test_cli_keywords_survive_but_entire_values_are_hidden(self):
        for field in ('password', 'passwd', 'psksecret', 'secret', 'passphrase', 'auth-pwd', 'priv-pwd'):
            for value in ('CANARY-one CANARY-two', 'ENC CANARY-one CANARY-two',
                          '"CANARY-one CANARY-two"', "'CANARY-one CANARY-two'", 'ENC "CANARY-one CANARY-two"'):
                for eol in ('\n', '\r\n'):
                    with self.subTest(field=field, value=value, eol=repr(eol)):
                        raw = '    set ' + field + ' ' + value + eol + 'next' + eol
                        output = gateway_redact(raw)[0]
                        self.assertEqual(output, '    set ' + field + ' [REDACTED]' + eol + 'next' + eol)
                        self.assertNotIn('CANARY-', output)

    def test_changed_json_still_redacts_keys_and_known_numeric_values(self):
        raw = json.dumps({'output': 'set password CANARY-password', 'number': 735190246})
        output = gateway_redact(raw, ('735190246',))[0]
        decoded = json.loads(output)
        self.assertNotIn('CANARY', output)
        self.assertNotIn('735190246', output)
        self.assertEqual(decoded['output'], 'set password [REDACTED]')
        self.assertEqual(decoded['number'], '[REDACTED]')
        keyed = json.dumps({'set password CANARY-key': 'safe', 'neighbor': 'CANARY-neighbor'})
        hidden = gateway_redact(keyed)[0]
        self.assertEqual(json.loads(hidden), '[REDACTED]')
        self.assertNotIn('CANARY', hidden)
        self.assertEqual(output, gateway_redact(output, ('735190246',))[0])

    def test_snmp_community_and_safe_fields_stay_visible(self):
        value = {"community": "public-ro", "user": "admin", "t": "set passwd-type plain"}
        self.assertEqual(gateway_redact(value), (value, []))


class DistributedPath(unittest.TestCase):
    def test_engine_proxy_gateway_carry_no_secret_and_keep_diagnostics(self):
        raw = RUCKUS + CLI + FORTIOS + JSON_TEXT
        out = gateway_redact(proxy_path(engine_redact(raw)))[0]
        text = json.dumps(out, ensure_ascii=False)
        for secret in SECRETS:
            self.assertNotIn(secret, text)
        for safe in SAFE:
            self.assertIn(safe, out["output"])


    def test_proxy_enc_redaction_keeps_the_escaped_line_end(self):
        out = proxy_path(" set passwd ENC SH2synthEnc789\n set accprofile super_admin\n")["output"]
        self.assertEqual(out, " set passwd ENC <REDACTED>\n set accprofile super_admin\n")


class QuotedCliSecret(unittest.TestCase):
    def test_quoted_values_with_spaces_are_redacted_whole(self):
        for quote in ('"', "'"):
            for sep in (" ", "="):
                line = ("ExecStart=/usr/bin/app --password" + sep + quote + "alpha synthbeta" + quote
                        + " --password-file /etc/app/pw --verbose\n")
                with self.subTest(quote=quote, sep=sep):
                    engine_out = engine_redact(line)
                    self.assertEqual(engine_out, "ExecStart=/usr/bin/app --password" + sep
                                     + "<REDACTED> --password-file /etc/app/pw --verbose\n")
                    out = gateway_redact(proxy_path(engine_out))[0]["output"]
                    for fragment in ("alpha", "synthbeta"):
                        self.assertNotIn(fragment, out)
                    self.assertIn("--verbose", out)
                    self.assertIn("--password-file /etc/app/pw", out)


    def test_proxy_keeps_engine_markers_and_still_redacts_raw_values(self):
        self.assertEqual(proxy_sanitize.sanitize_text("--password=<REDACTED> --verbose"), "--password=<REDACTED> --verbose")
        self.assertNotIn("synthtail", proxy_sanitize.sanitize_text("password=<REDACTED>synthtail"))
        self.assertNotIn("synthraw", proxy_sanitize.sanitize_text("password=synthraw"))


class ProxyEscapedJson(unittest.TestCase):
    CASES = (
        ("bare", "ExecStart=/usr/bin/app password=synthraw9 more\n", "synthraw9"),
        ("bare-comma", "x passwd=synthcm8, y\n", "synthcm8"),
        ("json-text", 'resp {"token": "synthtok7", "user": "admin"}\n', "synthtok7"),
    )

    def test_bare_fields_inside_escaped_json_keep_it_valid(self):
        for name, text, secret in self.CASES:
            for wrap in ("object", "list"):
                payload = {"ok": True, "output": text} if wrap == "object" else [text]
                message = {"jsonrpc": "2.0", "id": 1, "result": {"content": [
                    {"type": "text", "text": json.dumps(payload)}]}}
                with self.subTest(case=name, wrap=wrap):
                    cleaned = proxy_sanitize.sanitize_object(message)["result"]["content"][0]["text"]
                    self.assertNotIn(secret, cleaned)
                    decoded = json.loads(cleaned)
                    out = decoded["output"] if wrap == "object" else decoded[0]
                    self.assertIn("<REDACTED>", out)
                    self.assertNotIn(secret, out)


    def test_duplicate_keys_do_not_hide_an_earlier_value(self):
        text = '{"output": "password=synthdup5", "output": "ok"}'
        self.assertNotIn("synthdup5", proxy_sanitize.sanitize_object({"text": text})["text"])


class RuckusGolden(unittest.TestCase):
    GOLDEN = (Path(__file__).parent / "fixtures" / "ruckus_show_wlan_all.golden.txt").read_text()
    KEPT = ("Encryption = wpa2", "Algorithm = aes", "Type = Guest Access", "      Dynamic PSK = Disabled\n",
            "Authentication Server = Guest Accounts", "SSID = netops-k01-name-1")

    def check(self, out, marker):
        self.assertNotIn("netops-k01-psk-", out)
        self.assertEqual(out.count("      Passphrase = " + marker + "\n"), 2)
        for kept in self.KEPT:
            self.assertIn(kept, out)

    def test_engine_redacts_the_device_passphrases(self):
        self.check(engine_redact(self.GOLDEN), "<REDACTED>")

    def test_gateway_redacts_the_device_passphrases(self):
        self.check(gateway_redact({"t": self.GOLDEN})[0]["t"], "[REDACTED]")

    def test_distributed_path_redacts_the_device_passphrases(self):
        self.check(gateway_redact(proxy_path(engine_redact(self.GOLDEN)))[0]["output"], "[REDACTED]")


class RefusalLinearTime(unittest.TestCase):
    def test_hundred_thousand_spaces_finish_within_the_limit(self):
        for platform, head in HEADS:
            pattern = engine._CLI_REFUSALS[platform]
            text = head + " " * 100_000 + "\rX\n"
            with self.subTest(platform=platform, head=head):
                start = time.perf_counter()
                subprocess.run([sys.executable, "-I", "-c", SEARCH, pattern.pattern, str(int(pattern.flags))],
                               input=text, text=True, check=True, timeout=5)
                self.assertLess(time.perf_counter() - start, 5)

    def test_new_expression_is_much_faster_than_the_old_one(self):
        for platform, head in HEADS[:1] + HEADS[3:]:
            text = head + " " * 8000 + "\rX\n"
            timings = []
            for pattern in (OLD_REFUSALS[platform], engine._CLI_REFUSALS[platform]):
                start = time.perf_counter()
                pattern.search(text)
                timings.append(time.perf_counter() - start)
            with self.subTest(platform=platform):
                self.assertGreater(timings[0], 10 * max(timings[1], 0.001), timings)

    def test_refusals_are_recognised_as_before(self):
        lines = ["command parse error before 'foo'", "command parse error before 'foo'   ",
                 "Command fail. Return code -61", "error: unknown command: shw", "error: permission denied: x",
                 "error: syntax error, expecting <command>: x  ", "error: the mgd subsystem is not running",
                 "%% Invalid input detected at '^' marker.", "%% Unrecognized command", "plain output",
                 "error: unknown command: x\rY", "command parse error before x\rY"]
        for platform in OLD_REFUSALS:
            for line in lines:
                for end in ("", "\n", "\r\n"):
                    text = "prefix\n" + line + end
                    with self.subTest(platform=platform, text=text):
                        self.assertEqual(engine._cli_refused(platform, text),
                                         OLD_REFUSALS[platform].search(text) is not None)


if __name__ == "__main__":
    unittest.main()
