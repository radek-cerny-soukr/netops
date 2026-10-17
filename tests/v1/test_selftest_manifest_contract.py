import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from netops import cli


HELPER_TOOLS = {
    "helper_status", "target_scope", "read_query_catalog", "dns_probe",
    "tcp_probe", "icmp_probe", "tls_probe", "ssh_read", "schema_read",
    "fortios_diagnostics", "sftp_stat", "snmp_get", "ftp_list",
}


class SelftestManifestContract(unittest.IsolatedAsyncioTestCase):
    async def manifest(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(await cli.selftest(), 0)
        value = json.loads(output.getvalue())
        self.assertEqual(value["version"], "1.0.0")
        roles = value["roles"]
        self.assertEqual(set(roles), {"helper", "auditor", "admin"})
        self.assertEqual(set(roles["helper"]["names"]), HELPER_TOOLS)
        for role, count in (("helper", 13), ("auditor", 7), ("admin", 6)):
            self.assertEqual(roles[role]["tools"], count)
            self.assertEqual(len(roles[role]["names"]), count)
            self.assertEqual(len(set(roles[role]["names"])), count)
        return value

    async def test_shipped_manifest_matches_documented_helper_tools(self):
        await self.manifest()

    async def test_image_selftest_needs_no_instance_state_or_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            (state / "gateway").mkdir()
            (state / "gateway" / "config.json").write_text(
                '{"admin_enabled":false,"private":"synthetic-selftest-canary"}'
            )
            with patch.object(cli, "STATE", state), patch.object(
                cli, "read_private", side_effect=AssertionError("selftest must not load instance secrets")
            ):
                value = await self.manifest()
            self.assertNotIn("synthetic-selftest-canary", json.dumps(value))


if __name__ == "__main__":
    unittest.main()
