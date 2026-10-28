import hashlib
import inspect
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import unittest
from unittest import mock

from netops_core import ssh

CANARY = "SyntheticCredentialCanaryH1"
HOST_KEY = "192.0.2.10 ssh-ed25519 cmVwbGFjZS1tZS1ob3N0LWtleS1tYXRlcmlhbC1B"

class Credential:
    kind = "password"
    login = "reader"
    def use(self):
        return CANARY

class StreamingSshBlock(unittest.TestCase):
    def setUp(self):
        self.assertIn("stdout_consumer", inspect.signature(ssh.run_command).parameters,
                      "H1_STREAMING_SSH_MISSING")
        self.processes = []
        self.workspaces = []
        self.real_popen = subprocess.Popen

    def call(self, producer, consumer, **changes):
        def launch(argv, **kwargs):
            self.assertIn("StrictHostKeyChecking=yes", argv)
            self.assertIn("GlobalKnownHostsFile=/dev/null", argv)
            path = Path(kwargs["env"]["NETOPS_ASKPASS_FILE"])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.read_text(), CANARY+"\n")
            self.workspaces.append(path.parent)
            proc = self.real_popen([sys.executable, "-B", "-c", producer], **kwargs)
            self.processes.append(proc)
            return proc
        options = dict(stdout_consumer=consumer, capture_max_bytes=64*1024*1024,
                       timeout_seconds=10, idle_timeout_seconds=1)
        options.update(changes)
        with mock.patch.object(ssh.subprocess, "Popen", side_effect=launch):
            try:
                return ssh.run_command("192.0.2.10",22,"reader",Credential(),HOST_KEY,"show",**options)
            finally:
                self.assertTrue(all(not p.exists() for p in self.workspaces))
                self.assertTrue(all(p.poll() is not None for p in self.processes))

    def test_a_stream_above_legacy_budget_without_accumulating_raw(self):
        total = 17*1024*1024+123
        expected = hashlib.sha256()
        for unused in range(272):
            expected.update(b"v"*65536)
        expected.update(b"x"*123)
        actual = hashlib.sha256()
        count = 0
        def consume(chunk):
            nonlocal count
            self.assertIsInstance(chunk,bytes)
            count += len(chunk)
            actual.update(chunk)
        before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        result = self.call("import os;[(os.write(1,b'v'*65536)) for _ in range(272)];os.write(1,b'x'*123)",consume)
        growth = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss-before
        self.assertEqual(result.rc,0)
        self.assertEqual(result.stdout,b"")
        self.assertEqual(count,total)
        self.assertEqual(actual.hexdigest(),expected.hexdigest())
        self.assertLessEqual(growth,8192,"H1_RAW_STREAM_ACCUMULATED")
        print(json.dumps({"stream_bytes":total,"parent_maxrss_growth_kib":growth,"hash_match":True}))

    def test_b_failure_cap_idle_total_consumer_block(self):
        def broken(chunk):
            raise ValueError("SyntheticPrivateCallbackCanary")
        def broken_ssh(chunk):
            raise ssh.SshError("SyntheticPrivateCallbackCanary")
        variants = [
            ("import os;os.write(1,b'x'*131072)",lambda c:None,{"capture_max_bytes":1024}),
            ("import os,time;os.write(1,b'x');time.sleep(10)",lambda c:None,{"idle_timeout_seconds":0.15}),
            ("import os,time;[(os.write(1,b'x'),time.sleep(.03)) for _ in range(100)]",lambda c:None,
             {"timeout_seconds":0.25,"idle_timeout_seconds":0.15}),
            ("import os,time;os.write(1,b'x');time.sleep(10)",broken,{}),
            ("import os,time;os.write(1,b'x');time.sleep(10)",broken_ssh,{}),
        ]
        for producer, consumer, options in variants:
            with self.subTest(options=list(options)), self.assertRaises(ssh.SshError) as caught:
                self.call(producer,consumer,**options)
            self.assertNotIn(CANARY,str(caught.exception))
            self.assertNotIn("SyntheticPrivateCallbackCanary",str(caught.exception))
        with self.assertRaises(ssh.SshError):
            ssh.run_command("192.0.2.10",22,"reader",Credential(),HOST_KEY,"show",stdout_consumer=123)
        with self.assertRaises(ssh.SshError):
            ssh.run_command("192.0.2.10",22,"reader",Credential(),HOST_KEY,"show",
                            stdout_consumer=lambda c:None,run=lambda *a,**k:None)


class SshDiagnosticBlock(unittest.TestCase):
    def test_recognized_failure_after_long_warning(self):
        warning = ("** WARNING: connection is not using a post-quantum key exchange algorithm.\n"
                   "** This session may be vulnerable to store-now decrypt-later attacks.\n"
                   "** The server may need to be upgraded. See https://openssh.com/pq.html\n")
        self.assertGreater(len(warning),200)
        for error in ("Permission denied (publickey,password).",
                      "Host key verification failed.",
                      "Unable to negotiate with 192.0.2.10 port 22: no matching host key type found. Their offer: ssh-rsa"):
            with self.subTest(error=error.split()[0]):
                def runner(argv,**kwargs):
                    return subprocess.CompletedProcess(argv,255,b"",(warning+error).encode())
                with self.assertRaises(ssh.SshError) as caught:
                    ssh.run_command("192.0.2.10",22,"reader",Credential(),HOST_KEY,"show",run=runner)
                self.assertEqual(ssh.reason(caught.exception.said),ssh.reason(error),
                                 "SSH_WARNING_OBSCURED_REAL_REASON")
                self.assertNotIn(CANARY,str(caught.exception))

if __name__=="__main__":
    unittest.main()
