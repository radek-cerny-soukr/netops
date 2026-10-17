import asyncio
import json
import time
import types
import unittest
from unittest.mock import patch

from netops_helper import engine
from netops_helper.sanitize import redact


class HelperRedactionContract(unittest.TestCase):
    def test_assignment_boundaries_quotes_overlaps_and_unicode(self):
        for text,expected in (
            ("password: canary","password: <REDACTED>"),
            ('"password": "canary"','"password": <REDACTED>'),
            ("xpassword: canary","xpassword: canary"),
            ("xaccess token=canary","xaccess token=<REDACTED>"),
            ('x"password": "canary"','x"password": <REDACTED>'),
            ('xpassword:"inner password:canary"','xpassword:"inner password:<REDACTED>'),
            ('password:"inner token:canary"',"password:<REDACTED>"),
            ("coMmun\u0130ty=canary","coMmun\u0130ty=<REDACTED>"),
            ("-password: canary","-password: canary"),
            ("api-key: canary","api-key: <REDACTED>"),
            ("api access token: canary","api access token: <REDACTED>"),
            ('token : "unclosed',"token : <REDACTED>"),
            ("passwork token:","passwork token:"),
            ("community:\n \tcanary","community:\n \t<REDACTED>"),
            ('"password": \'canary\'','"password": <REDACTED>'),
            ("'password':canary","'password':<REDACTED>"),
            ("password:one, token:two","password:<REDACTED>, token:<REDACTED>"),
        ):
            with self.subTest(text=text):
                self.assertEqual(redact(text),expected)

    def test_string_subclass_cannot_override_the_scanner(self):
        class Text(str):
            def __str__(self):
                return self
            def __getitem__(self,key):
                raise AssertionError("subclass index override used")
            def find(self,*args):
                raise AssertionError("subclass find override used")
            def startswith(self,*args):
                raise AssertionError("subclass prefix override used")
        self.assertEqual(redact(Text("password:canary")),"password:<REDACTED>")

    def test_ssh_read_applies_the_existing_size_cap_after_redaction(self):
        auth=types.SimpleNamespace(alias="synthetic",secrets=())
        pem="-----BEGIN PRIVATE KEY-----\n"+"x"*2_000_001+"\n-----END PRIVATE KEY-----"
        with patch.object(engine,"_ssh_read_state",
                          return_value=("fortinet","show system status",("synthetic",))), \
             patch.object(engine,"read_from_device",return_value=(0,pem)):
            result=engine.ssh_read.__wrapped__(auth,"fortinet","system_status",None,0,16000)
        self.assertTrue(result["ok"])
        self.assertEqual(result["untrusted_device_output"],"<PRIVATE-KEY-REDACTED>")
        with patch.object(engine,"_ssh_read_state",
                          return_value=("fortinet","show system status",("synthetic",))), \
             patch.object(engine,"read_from_device",return_value=(0,"x"*2_000_001)):
            result=engine.ssh_read.__wrapped__(auth,"fortinet","system_status",None,0,16000)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"],"SSH output exceeds the 2000000-byte safety cap")

    def test_threaded_maximum_redaction_keeps_the_loop_responsive(self):
        async def measure():
            value="\n"*(16*1024*1024)
            intervals=[]
            started=time.monotonic()
            task=asyncio.create_task(asyncio.to_thread(redact,value))
            while not task.done():
                tick=time.monotonic()
                await asyncio.sleep(0.05)
                intervals.append(time.monotonic()-tick)
            self.assertTrue(await task==value)
            self.assertTrue(intervals)
            print("HELPER_REDACTION_LOOP="+json.dumps({
                "bytes":len(value),"wall":time.monotonic()-started,
                "samples":len(intervals),"max_interval":max(intervals)}),flush=True)
            self.assertLess(max(intervals),2)
        asyncio.run(measure())


if __name__=="__main__":
    unittest.main()
