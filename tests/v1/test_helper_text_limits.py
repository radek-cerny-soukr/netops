import hashlib
import json
import subprocess
import sys
import unittest

from netops_helper.sanitize import redact
from netops_helper.proxy_sanitize import sanitize_text

WORKER = r"""
import hashlib,json,signal,sys,time
value=json.load(sys.stdin)
kind=value["kind"]
if kind=="helper":
    from netops_helper.sanitize import redact as operation
elif kind=="proxy":
    from netops_helper.proxy_sanitize import sanitize_text as operation
else:
    from netops_helper.engine import _pty_body
    operation=lambda text:_pty_body(text.encode(),"show x",b"SSH@synthetic#")
class BudgetExceeded(Exception):
    pass
def exceeded(*args):
    raise BudgetExceeded()
signal.signal(signal.SIGALRM,exceeded)
print("START",flush=True)
start=time.monotonic()
signal.setitimer(signal.ITIMER_REAL,45 if kind=="helper" else 10)
try:
    result=operation(value["text"])
except BudgetExceeded:
    signal.setitimer(signal.ITIMER_REAL,0)
    print(json.dumps({"budget_exceeded":True}),flush=True)
    raise SystemExit(2)
signal.setitimer(signal.ITIMER_REAL,0)
print(json.dumps({"sha256":hashlib.sha256(result.encode()).hexdigest(),
                 "seconds":time.monotonic()-start}),flush=True)
"""

class HelperTextLimits(unittest.TestCase):
    def bounded(self, kind, text, expected):
        result=subprocess.run([sys.executable,"-B","-c",WORKER],
                              input=json.dumps({"kind":kind,"text":text}),
                              text=True,capture_output=True,timeout=75 if kind=="helper" else 40)
        lines=result.stdout.splitlines()
        self.assertTrue(lines and lines[0]=="START",
                        "worker did not enter the measured transformation")
        self.assertEqual(result.returncode,0,result.stdout[:200])
        measured=json.loads(lines[1])
        self.assertEqual(measured["sha256"],hashlib.sha256(expected.encode()).hexdigest())
        self.assertLess(measured["seconds"],45 if kind=="helper" else 10)

    def test_whitespace_prefix_and_line_endings_are_preserved(self):
        for prefix in ("\n\n","\r\n\r\n\t"," \n\t","\u00a0\u2003","\v\f\n"):
            with self.subTest(prefix=repr(prefix)):
                source=prefix+"username synthetic secret 9 synthetic-canary\r\n"
                self.assertEqual(redact(source),
                                 prefix+"username synthetic secret 9 <REDACTED>\r\n")
                source=prefix+"enable secret 9 synthetic-canary\r\n"
                self.assertEqual(sanitize_text(source),
                                 prefix+"enable secret 9 <REDACTED>\r\n")
        self.assertEqual(redact("\nusername synthetic\nsecret 9 synthetic-canary\n"),
                         "\nusername synthetic\nsecret 9 <REDACTED>\n")
        self.assertEqual(redact('snmp-server community "synthetic-canary" ro\n'),
                         "snmp-server community <REDACTED> ro\n")

    def test_maximum_capture_and_page_of_blank_lines_have_bounded_work(self):
        for kind,size in (("helper",16*1024*1024),("proxy",48000)):
            with self.subTest(kind=kind,size=size):
                text="\n"*size
                self.bounded(kind,text,text)

    def test_maximum_pty_capture_discards_preamble_and_echo_without_quadratic_work(self):
        tail="show x\r\npayload\r\nSSH@synthetic#"
        size=16*1024*1024
        self.bounded("pty","\n"*(size-len(tail))+tail,"payload")

if __name__=="__main__":
    unittest.main()
