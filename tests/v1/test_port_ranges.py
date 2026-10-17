import json
import subprocess
import sys
import unittest

from netops_auditor.management import PolicyError, ports

WORKER = r"""
import json,signal,sys,time
value=json.load(sys.stdin)
from netops_auditor.management import ports,exos_model
from netops_auditor import l1_exos
inventory=frozenset(value["inventory"])
class BudgetExceeded(Exception):
    pass
def exceeded(*args):
    raise BudgetExceeded()
signal.signal(signal.SIGALRM,exceeded)
print("START",flush=True)
start=time.monotonic()
signal.setitimer(signal.ITIMER_REAL,10)
try:
    if value["kind"]=="ports":
        result={"ports":sorted(ports(value["value"],inventory))}
    else:
        tree=l1_exos.parse(value["value"])
        vlans,members,descriptions=exos_model(tree,inventory)
        result={"vlans":len(vlans),"members":sorted(members),
                "tagged_counts":sorted(len(modes["tagged"]) for modes in members.values()),
                "descriptions":len(descriptions)}
except BudgetExceeded:
    signal.setitimer(signal.ITIMER_REAL,0)
    print(json.dumps({"budget_exceeded":True}),flush=True)
    raise SystemExit(2)
signal.setitimer(signal.ITIMER_REAL,0)
result["seconds"]=time.monotonic()-start
print(json.dumps(result),flush=True)
"""


class PortRanges(unittest.TestCase):
    def test_cross_slot_ranges_follow_numeric_order_and_inventory_gaps(self):
        inventory=frozenset(("1:1","1:2","1:10","2:1","2:3","10:1"))
        self.assertEqual(ports("1:2-2:1",inventory),{"1:2","1:10","2:1"})
        self.assertEqual(ports("2:1-10:1",inventory),{"2:1","2:3","10:1"})
        sparse=frozenset(("1:1","1:3","2:1"))
        self.assertEqual(ports("1:1-2:1",sparse),set(sparse))
        self.assertEqual(ports("1:1-1:3",sparse),{"1:1","1:2","1:3"})
        self.assertEqual(ports("all",inventory),set(inventory))
        self.assertEqual(ports("1:2-2:1,1:2-2:1",inventory),{"1:2","1:10","2:1"})

    def test_cross_slot_refusals_and_result_limit_are_preserved(self):
        inventory=frozenset(("1:1","1:3","2:1"))
        for value,supplied,message in (
            ("1:1-2:1",None,"unsupported port list"),
            ("1:1-2:1",frozenset(),"unsupported port list"),
            ("1:2-2:1",inventory,"port range outside the port inventory"),
            ("2:1-1:1",inventory,"port range outside the port inventory"),
        ):
            with self.subTest(value=value,inventory=supplied):
                with self.assertRaises(PolicyError) as caught:
                    ports(value,supplied)
                self.assertEqual(str(caught.exception),message)
        full=frozenset("1:"+str(number) for number in range(1,4097)) | {"2:1"}
        self.assertEqual(ports("1:2-2:1",full),set(full)-{"1:1"})
        with self.assertRaises(PolicyError) as caught:
            ports("1:1-2:1",full)
        self.assertEqual(str(caught.exception),"port list is too large")

    def bounded(self, kind, value, expected):
        inventory=["%d:%d"%(slot,number) for slot in range(1,65)
                   for number in range(1,4097)]
        result=subprocess.run([sys.executable,"-B","-c",WORKER],
                              input=json.dumps({"kind":kind,"value":value,"inventory":inventory}),
                              text=True,capture_output=True,timeout=40)
        lines=result.stdout.splitlines()
        self.assertTrue(lines and lines[0]=="START",
                        "worker did not enter the measured operation")
        self.assertEqual(result.returncode,0,result.stdout[:200])
        measured=json.loads(lines[1])
        self.assertLess(measured.pop("seconds"),10)
        self.assertEqual(measured,expected)

    def test_repeated_small_cross_slot_range_has_bounded_work(self):
        self.bounded("ports",",".join(["1:4096-2:1"]*1200),
                     {"ports":["1:4096","2:1"]})

    def test_many_model_rows_share_one_inventory_preparation(self):
        text="".join("create vlan v%d\nconfigure vlan v%d add ports 1:4096-2:1 tagged\n"%(i,i)
                     for i in range(1200))
        self.bounded("model",text,{"vlans":1200,"members":["1:4096","2:1"],
                                   "tagged_counts":[1200,1200],"descriptions":0})


if __name__=="__main__":
    unittest.main()
