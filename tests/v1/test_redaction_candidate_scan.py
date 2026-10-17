import asyncio
import json
import time
import unittest

from netops import redaction as module
def scan(text):
    operation=getattr(module,"has_candidate",module.CANDIDATE.search)
    return bool(operation(text))

class CandidateScanContract(unittest.IsolatedAsyncioTestCase):
    def test_secret_labels_crossing_window_edges(self):
        needles=("authorization","password","passphrase","secret","token","access_token","refresh_token",
                 "auth_context","private_key","snmp_community","credentials","proxy_authorization",
                 "cookie","set_cookie","x_api_key","api_key","mcp_session_id","url_query",
                 "passwd","community","-----BEGIN ","\\","API-KEY","toKen","ſecret")
        for needle in needles:
            for edge in (16384,32768,262144):
                for offset in (edge-1,edge-len(needle)+1,edge):
                    with self.subTest(needle=needle,offset=offset):
                        self.assertTrue(scan("z"*offset+needle+"z"*64))
        self.assertFalse(scan(""))
        self.assertFalse(scan("z"*524288))
    async def test_one_long_scan_keeps_the_event_loop_responsive(self):
        text="z"*8388608
        start=previous=time.perf_counter()
        task=asyncio.create_task(asyncio.to_thread(scan,text))
        gaps=[]
        try:
            while not task.done():
                await asyncio.sleep(0.02)
                now=time.perf_counter();gaps.append(now-previous);previous=now
            self.assertFalse(await task)
        finally:
            if not task.done():await task
        worst=max(gaps)
        print("CANDIDATE_SCAN_GIL="+json.dumps({"chars":len(text),"wall_seconds":time.perf_counter()-start,
            "samples":len(gaps),"max_loop_seconds":worst,"release_go":False}),flush=True)
        self.assertLess(worst,2.0,"single candidate scan prevents the existing two-second status deadline")

