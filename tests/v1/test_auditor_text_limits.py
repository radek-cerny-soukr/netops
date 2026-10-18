import hashlib
import json
import subprocess
import sys
import unittest

from netops_auditor import l1_exos, l1_fortios
from netops_auditor.management import hits

WORKER = r"""
import hashlib,json,signal,sys,time
value=json.load(sys.stdin)
from netops_auditor import l1_exos,l1_fortios
from netops_auditor.management import hits
class BudgetExceeded(Exception):
    pass
def exceeded(*args):
    raise BudgetExceeded()
signal.signal(signal.SIGALRM,exceeded)
print("START",flush=True)
start=time.monotonic()
signal.setitimer(signal.ITIMER_REAL,10)
try:
    if value["kind"]=="modules":
        parsed=l1_exos.parse(value["text"])
        result={"modules":len(parsed.modules),
                "last":parsed.modules[-1],
                "same_source":parsed.serialize()==value["text"]}
    else:
        parsed=l1_fortios.parse(value["text"])
        found=list(hits("fortios",value["kind"],parsed))
        result={"keys":sorted(item["object_key"] for item in found),
                "codes":sorted(item["evidence"]["code"] for item in found)}
except BudgetExceeded:
    signal.setitimer(signal.ITIMER_REAL,0)
    print(json.dumps({"budget_exceeded":True}),flush=True)
    raise SystemExit(2)
signal.setitimer(signal.ITIMER_REAL,0)
result["seconds"]=time.monotonic()-start
print(json.dumps(result),flush=True)
"""


def group_config(count, terminal):
    lines=["config firewall address", "end", "config firewall addrgrp"]
    for number in range(count):
        member="g%d"%(number+1) if number+1<count else terminal
        lines.extend(('edit "g%d"'%number,'set member "%s"'%member,"next"))
    return "\n".join(lines+["end",""])


class AuditorTextLimits(unittest.TestCase):
    def bounded(self, kind, text, expected):
        result=subprocess.run([sys.executable,"-B","-c",WORKER],
                              input=json.dumps({"kind":kind,"text":text}),
                              text=True,capture_output=True,timeout=40)
        lines=result.stdout.splitlines()
        self.assertTrue(lines and lines[0]=="START",
                        "worker did not enter the measured operation")
        self.assertEqual(result.returncode,0,result.stdout[:200])
        measured=json.loads(lines[1])
        self.assertLess(measured.pop("seconds"),10)
        self.assertEqual(measured,expected)

    def test_group_membership_scope_and_cycle_evidence(self):
        text='''config firewall address
edit "addr-ok"
next
end
config firewall addrgrp
edit "gA"
set member "addr-ok" "gB" "all" "missing"
next
edit "gB"
set member "gA"
next
edit "dynamic"
set type dynamic
set member "missing"
next
end
'''
        tree=l1_fortios.parse(text)
        for rule,keys,code in (
            ("group-dangling",["firewall addrgrp/gA/member/missing"],"missing-member"),
            ("group-cycle",["firewall addrgrp/gA/member/gB","firewall addrgrp/gB/member/gA"],
             "membership-cycle")):
            with self.subTest(rule=rule):
                found=list(hits("fortios",rule,tree))
                self.assertEqual(sorted(item["object_key"] for item in found),keys)
                self.assertTrue(all(item["evidence"]=={"code":code,"count":1} for item in found))

    def test_dhcp_conflicts_are_scoped_normalized_and_not_duplicated(self):
        reservations=(
            ("2","192.0.2.20","00:00:5e:00:53:AB",""),
            ("10","192.0.2.20","00:00:5e:00:53:CD",""),
            ("1","192.0.2.21","00-00-5E-00-53-ab",""),
            ("3","192.0.2.20","00:00:5e:00:53:AB",""),
            ("4","192.0.2.20","00:00:5e:00:53:AB","set action assign"),
            ("5","192.0.2.20","00:00:5e:00:53:AB","set type option82"),
        )
        lines=["config system dhcp server","edit 1","config reserved-address"]
        for key,ip,mac,extra in reservations:
            lines.extend(("edit "+key,"set ip "+ip,"set mac "+mac,extra,"next"))
        lines.extend(("end","next","edit 2","set status disable","config reserved-address",
                      "edit 1","set ip 192.0.2.20","set mac 00:00:5e:00:53:AB","next",
                      "edit 2","set ip 192.0.2.20","set mac 00:00:5e:00:53:AB",
                      "next","end","next","end",""))
        found=list(hits("fortios","dhcp-conflict",l1_fortios.parse("\n".join(lines))))
        prefix="system dhcp server/1/reserved-address/"
        expected=["1/conflict/2","1/conflict/3","10/conflict/2",
                  "10/conflict/3","2/conflict/3"]
        self.assertEqual(sorted(item["object_key"] for item in found),
                         sorted(prefix+key for key in expected))
        self.assertTrue(all(item["evidence"]=={"code":"reservation-conflict","count":1}
                            for item in found))

    def test_module_order_and_upm_body_preserve_source(self):
        text=('# Module vlan configuration.\r\n'
              'create upm profile synthetic\r\n'
              '# Module hidden configuration.\r\n'
              'configure vlan hidden tag 99\r\n.\r\n'
              '# Module ports configuration.\r\n'
              'configure ports 1 display-string synthetic\r\n'
              '# Module vlan configuration.\r\n'
              'create vlan visible\r\n')
        parsed=l1_exos.parse(text)
        self.assertEqual(parsed.serialize(),text)
        self.assertEqual(parsed.modules,("vlan","ports"))
        self.assertFalse(parsed.unterminated_upm)
        self.assertFalse(any(command.tokens[:3]==("configure","vlan","hidden")
                             for command in parsed.active))
        self.assertEqual(parsed.matching("create","vlan")[0].tokens,
                         ("create","vlan","visible"))

    def test_large_dangling_group_chain_has_bounded_work(self):
        self.bounded("group-dangling",group_config(60000,"missing"),{
            "keys":["firewall addrgrp/g59999/member/missing"],"codes":["missing-member"]})

    def test_large_group_cycle_chain_has_bounded_work(self):
        self.bounded("group-cycle",group_config(60000,"g59999"),{
            "keys":["firewall addrgrp/g59999/member/g59999"],"codes":["membership-cycle"]})

    def test_many_independent_dhcp_servers_have_bounded_work(self):
        lines=["config system dhcp server"]
        for server in range(1,201):
            lines.extend(("edit "+str(server),"config reserved-address"))
            for host in range(1,251):
                lines.extend(("edit "+str(host),"set ip 192.0.2."+str(host),
                              "set mac 00:00:5e:00:53:%02x"%host,"next"))
            lines.extend(("end","next"))
        self.bounded("dhcp-conflict","\n".join(lines+["end",""]),{"keys":[],"codes":[]})

    def test_unique_module_headers_have_bounded_work(self):
        text="".join("# Module m%d configuration.\n"%number for number in range(100000))
        self.bounded("modules",text,{"modules":100000,"last":"m99999","same_source":True})


if __name__=="__main__":
    unittest.main()
