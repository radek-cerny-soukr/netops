import contextlib
import io
import itertools
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from netops import cli, operator
from netops.files import UIDS, write_private
from netops_auditor import cli as auditor
from netops.state import OperatorAccessError

HINT = "Auditor inventory could not be loaded or the device selected; configure Auditor inventory/vault, or check --inventory and --device"
SUFFIX = "; operation failed without automatic retry\n"
CANARY = "SYNTHETIC-PRIVATE-ALIAS-CANARY"


class CollectInventoryGuidance(unittest.TestCase):
    def invoke(self, data, explicit, fault=None):
        uid = os.getuid()
        with tempfile.TemporaryDirectory() as raw:
            state = Path(raw)
            for role in ("gateway", "auditor"):
                (state / role).mkdir(mode=0o700)
            write_private(state / "gateway/config.json", b'{"version":1,"product_version":"1.0.4","audit":{"mode":"local"}}')
            write_private(state / "auditor/config.json", b'{"tenant":"default","catalog":"fortios"}')
            if data is not None:
                write_private(state / "auditor/inventory.json", data)
            if data == b'{"version":2,"devices":[]}':
                auditor.inventory.load(state / "auditor/inventory.json")
            before = {path.name: path.read_bytes() for path in (state / "auditor").iterdir()}
            arguments = ["auditor", "collect", "--device", CANARY, "--json"]
            if explicit:
                arguments += ["--vault", str(state / "auditor/vault.json")]
            output, errors = io.StringIO(), io.StringIO()
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(operator, "STATE", state))
                stack.enter_context(patch.dict(UIDS, {"gateway": uid, "auditor": uid}))
                stack.enter_context(patch.object(operator, "demote"))
                stack.enter_context(patch.object(operator, "role_environment"))
                stack.enter_context(patch.object(operator.os, "geteuid", side_effect=itertools.chain([0], itertools.repeat(uid))))
                stack.enter_context(patch.object(sys, "argv", ["netops", *arguments]))
                stack.enter_context(contextlib.redirect_stdout(output))
                stack.enter_context(contextlib.redirect_stderr(errors))
                if fault is not None:
                    stack.enter_context(patch.object(auditor, "_inventory_record", side_effect=fault))
                code = cli.main()
            self.assertEqual({path.name: path.read_bytes() for path in (state / "auditor").iterdir()}, before)
            self.assertEqual(code, 2)
            self.assertEqual(output.getvalue(), "")
            self.assertNotIn(CANARY, errors.getvalue())
            return errors.getvalue()

    def test_inventory_absence_malformed_data_and_missing_alias_have_fixed_guidance_with_or_without_vault(self):
        for data in (None, b'{"broken":', b'{"version":2,"devices":[]}'):
            for explicit in (False, True):
                with self.subTest(data=data, explicit_vault=explicit):
                    self.assertEqual(self.invoke(data, explicit), "netops: " + HINT + SUFFIX)

    def test_unexpected_io_fault_is_not_reclassified_as_inventory_selection(self):
        error = self.invoke(b'{"version":2,"devices":[]}', False, OSError(CANARY))
        self.assertEqual(error, "netops: Operation failed; inspect private state and audit before retrying" + SUFFIX)

    def test_uid_and_lock_refusals_precede_inventory_access(self):
        for uid, failure in ((1000, None), (0, OperatorAccessError("Stop the running instance first"))):
            errors = io.StringIO()
            with self.subTest(uid=uid), patch.object(operator.os, "geteuid", return_value=uid), \
                    patch.object(operator, "acquire_state", side_effect=failure) as acquire, \
                    patch.object(auditor, "_inventory_record") as lookup, \
                    patch.object(sys, "argv", ["netops", "auditor", "collect", "--device", CANARY, "--json"]), \
                    contextlib.redirect_stderr(errors):
                self.assertEqual(cli.main(), 2)
                self.assertNotIn(HINT, errors.getvalue())
                self.assertNotIn(CANARY, errors.getvalue())
                lookup.assert_not_called()
                if uid != 0:
                    acquire.assert_not_called()


if __name__ == "__main__":
    unittest.main()
