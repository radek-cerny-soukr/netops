import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mock_server

TOOL = os.path.join(HERE, "..", "blackbox.py")
TOKEN = "t0k-" + "a" * 40


def openssl(*args, cwd):
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


def make_pki(d, constrained, leaf_days):
    ca_ext = os.path.join(d, "ca.ext")
    with open(ca_ext, "w") as f:
        f.write("[v3]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n")
        if constrained == "noncritical":
            f.write("nameConstraints=permitted;DNS:localhost\n")
        elif constrained == "ipv4-only":
            f.write("nameConstraints=critical,permitted;DNS:localhost,excluded;IP:0.0.0.0/0.0.0.0\n")
        elif constrained == "dns-only":
            f.write("nameConstraints=critical,permitted;DNS:localhost\n")
        elif constrained:
            f.write("nameConstraints=critical,permitted;DNS:localhost,excluded;IP:0.0.0.0/0.0.0.0,excluded;IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0\n")
    cnf = os.path.join(d, "ca.cnf")
    with open(cnf, "w") as f:
        f.write("[req]\ndistinguished_name=dn\n[dn]\n")
        f.write(open(ca_ext).read())
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
            "-days", "3650", "-subj", "/CN=NetOps test CA", "-extensions", "v3", "-config", cnf, cwd=d)
    leaf_ext = os.path.join(d, "leaf.ext")
    with open(leaf_ext, "w") as f:
        f.write("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n")
    openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=localhost", cwd=d)
    openssl("x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "leaf.pem",
            "-days", str(leaf_days), "-extfile", leaf_ext, cwd=d)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Blackbox(unittest.TestCase):
    def run_against(self, constrained, leaf_days, lax):
        with tempfile.TemporaryDirectory() as d:
            make_pki(d, constrained, leaf_days)
            port = free_port()
            server = mock_server.serve(port, os.path.join(d, "leaf.pem"), os.path.join(d, "leaf.key"), TOKEN, lax)
            try:
                token_file = os.path.join(d, "token")
                with open(token_file, "w") as f:
                    f.write(TOKEN + "\n")
                out = os.path.join(d, "report.json")
                proc = subprocess.run([sys.executable, TOOL, "--url", "https://localhost:%d/mcp" % port, "--ca", os.path.join(d, "ca.pem"),
                                       "--token-file", token_file, "--expect-name", "localhost", "--expect-tool", "helper_status",
                                       "--expect-tool", "audit_status", "--output", out], capture_output=True, text=True, timeout=120)
                report = json.load(open(out))
            finally:
                server.shutdown()
        return proc.returncode, {c["check"]: c["status"] for c in report["checks"]}, proc.stdout

    def test_correct_server_passes(self):
        rc, checks, out = self.run_against(True, 30, False)
        failing = {k: v for k, v in checks.items() if v == "FAIL"}
        self.assertEqual(failing, {}, out)
        for name in ("plain-http-refused", "system-trust-rejects", "hostname-verified", "auth-no-token", "auth-wrong-token",
                     "auth-token-in-query", "ca-name-constraints", "ca-pathlen-zero", "leaf-certificate", "mcp-initialize-and-list"):
            self.assertEqual(checks[name], "PASS", out)

    def test_ipv6_left_open_fails(self):
        rc, checks, out = self.run_against("ipv4-only", 30, False)
        self.assertEqual(checks["ca-name-constraints"], "FAIL", out)

    def test_defective_server_is_caught(self):
        rc, checks, out = self.run_against(False, 365, True)
        self.assertEqual(rc, 1)
        for name in ("auth-no-token", "auth-token-in-query", "ca-name-constraints", "leaf-certificate"):
            self.assertEqual(checks[name], "FAIL", out)
        self.assertEqual(checks["auth-wrong-token"], "PASS", out)

    def test_noncritical_name_constraints_fail(self):
        rc, checks, out = self.run_against("noncritical", 30, False)
        self.assertEqual(checks["ca-name-constraints"], "FAIL", out)
        self.assertEqual(rc, 1)

    def test_single_name_type_constraints_fail(self):
        rc, checks, out = self.run_against("dns-only", 30, False)
        self.assertEqual(checks["ca-name-constraints"], "FAIL", out)
        self.assertEqual(rc, 1)

    def test_missing_tool_is_caught(self):
        with tempfile.TemporaryDirectory() as d:
            make_pki(d, True, 30)
            port = free_port()
            server = mock_server.serve(port, os.path.join(d, "leaf.pem"), os.path.join(d, "leaf.key"), TOKEN, False)
            try:
                tf = os.path.join(d, "token")
                open(tf, "w").write(TOKEN)
                out = os.path.join(d, "r.json")
                subprocess.run([sys.executable, TOOL, "--url", "https://localhost:%d/mcp" % port, "--ca", os.path.join(d, "ca.pem"),
                                "--token-file", tf, "--expect-name", "localhost", "--expect-tool", "admin_apply", "--output", out],
                               capture_output=True, text=True, timeout=120)
                checks = {c["check"]: c for c in json.load(open(out))["checks"]}
            finally:
                server.shutdown()
        self.assertEqual(checks["mcp-initialize-and-list"]["status"], "FAIL")
        self.assertIn("admin_apply", checks["mcp-initialize-and-list"]["detail"])


if __name__ == "__main__":
    unittest.main()
