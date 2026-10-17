import json
import subprocess
import sys
import unittest

from netops_admin import exos, membership
from netops_admin.errors import Rejected

WORKER = r"""
import json,signal,sys,time
value=json.load(sys.stdin)
from netops_admin import exos,membership
from netops_admin.errors import Rejected
class BudgetExceeded(Exception):
    pass
def exceeded(*args):
    raise BudgetExceeded()
signal.signal(signal.SIGALRM,exceeded)
print("START",flush=True)
start=time.monotonic()
signal.setitimer(signal.ITIMER_REAL,10)
try:
    kind,text=value["kind"],value["text"]
    try:
        if kind=="upm":
            result=exos.upm_listing_complete(text,"profiles")
        elif kind=="sessions":
            result=exos.foreign_sessions(text)
        elif kind=="vlan":
            result=exos.shown_vlan(text,"synthetic")
        else:
            result=membership.shown(text,"1")
        result={"value":result}
    except Rejected as error:
        result={"rejected":error.reasons}
except BudgetExceeded:
    signal.setitimer(signal.ITIMER_REAL,0)
    print(json.dumps({"budget_exceeded":True}),flush=True)
    raise SystemExit(2)
signal.setitimer(signal.ITIMER_REAL,0)
result["seconds"]=time.monotonic()-start
print(json.dumps(result),flush=True)
"""


class AdminTextLimits(unittest.TestCase):
    def bounded(self, kind, text, expected):
        try:
            result=subprocess.run([sys.executable,"-B","-c",WORKER],
                                  input=json.dumps({"kind":kind,"text":text}),
                                  text=True,capture_output=True,timeout=40)
        except subprocess.TimeoutExpired as error:
            output=error.stdout or b""
            if isinstance(output,bytes):
                output=output.decode("utf-8","replace")
            if not output.splitlines() or output.splitlines()[0]!="START":
                raise RuntimeError("controller expired before measured operation") from None
            self.fail("operation exceeded both budgets after START")
        lines=result.stdout.splitlines()
        self.assertTrue(lines and lines[0]=="START",
                        "worker did not enter the measured operation")
        self.assertEqual(result.returncode,0,result.stdout[:200])
        measured=json.loads(lines[1])
        self.assertLess(measured.pop("seconds"),10)
        self.assertEqual(measured,expected)

    def test_vlan_description_preserves_internal_whitespace_and_none(self):
        for ending in ("\n","\r\n"):
            for prefix in ("","\t","\u00a0\u2003"):
                with self.subTest(ending=repr(ending),prefix=repr(prefix)):
                    base=ending.join(("VLAN Interface with name synthetic created",
                                      "802.1Q Tag 123"))
                    text=base+ending+prefix+"Description: inner  whitespace \t"+ending
                    self.assertEqual(exos.shown_vlan(text,"synthetic"),
                                     {"tag":"123","description":"inner  whitespace"})
                    self.assertEqual(exos.shown_vlan(base+ending+prefix+"Description: None \t"+ending,
                                                     "synthetic"),{"tag":"123"})
        with self.assertRaises(Rejected):
            exos.shown_vlan("VLAN Interface with name other created\n","synthetic")

    def test_sessions_and_upm_counts_preserve_scope(self):
        self.assertEqual(exos.foreign_sessions("\n\u00a0*1 Thu Oct 15\n 2 Thu Oct 15\n"),1)
        with self.assertRaises(Rejected):
            exos.foreign_sessions("synthetic-no-session")
        table="===\nheader\n===\n%s===\nNumber of UPM profiles: %d\n"
        for rows,count,expected in (("",0,True),("synthetic\n",1,True),
                                    ("synthetic\n",2,False),("synthetic\n",0,False)):
            with self.subTest(rows=rows,count=count):
                self.assertEqual(exos.upm_listing_complete(table%(rows,count),"profiles"),expected)
        self.assertFalse(exos.upm_listing_complete(table%("",0),"events"))

    def test_membership_rejects_other_ports_and_preserves_continuation(self):
        for ending in ("\n","\r\n"):
            text=ending.join(("VLAN Name(s)","1 Untagged Native",
                              "\u00a0 Tagged Blue,Red","    Extra",""))
            self.assertEqual(membership.shown(text,"1"),
                             {"untagged":"Native","tagged":"Blue Extra Red"})
            with self.assertRaises(Rejected):
                membership.shown(text,"2")
        with self.assertRaises(Rejected):
            membership.shown("VLAN Name(s)\n1 Tagged Blue\n","1")
        with self.assertRaises(Rejected):
            membership.shown("VLAN Name(s)\n1 Untagged Native\n Tagged Bad!\n","1")

    def test_large_device_answers_have_bounded_work(self):
        size=16*1024*1024
        vlan_prefix="VLAN Interface with name synthetic created\n802.1Q Tag 123\n"
        membership_prefix="VLAN Name(s)\n1 Untagged a"
        for kind,text,expected in (
            ("upm","\n"*size,{"value":False}),
            ("sessions","\n"*size,
             {"rejected":["the session list is not readable"]}),
            ("vlan",vlan_prefix+"\n"*(size-len(vlan_prefix)),
             {"value":{"tag":"123"}}),
            ("membership",membership_prefix+" "*(size-len(membership_prefix)-3)+"b!\n",
             {"rejected":["unsupported VLAN name in membership answer"]}),
        ):
            with self.subTest(kind=kind):
                self.bounded(kind,text,expected)


if __name__=="__main__":
    unittest.main()
