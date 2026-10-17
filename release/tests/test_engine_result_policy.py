import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "engine_regression.py"
SPEC = importlib.util.spec_from_file_location("engine_result_policy", SOURCE)
ENGINE = importlib.util.module_from_spec(SPEC)
with patch.dict(sys.modules, {"pytest": SimpleNamespace(UsageError=RuntimeError)}):
    SPEC.loader.exec_module(ENGINE)

class CompleteResult(unittest.TestCase):
    def result(self, **changes):
        result = ENGINE.Results()
        result.counts["passed"] = 1
        result.counts.update(changes)
        return result

    def test_complete_success_is_accepted(self):
        self.assertTrue(ENGINE.complete_result(0, self.result()))

    def test_nonzero_exit_and_empty_collection_are_refused(self):
        for code in (1, 2, 3, 4, 5):
            with self.subTest(code=code):
                self.assertFalse(ENGINE.complete_result(code, self.result()))
        self.assertFalse(ENGINE.complete_result(0, ENGINE.Results()))

    def test_any_skipped_test_blocks_an_otherwise_successful_run(self):
        result = self.result()
        result.pytest_runtest_logreport(SimpleNamespace(
            failed=False, skipped=True, when="setup", nodeid="tests/example.py::case",
            longrepr="missing execution condition"))
        self.assertFalse(ENGINE.complete_result(0, result))
        self.assertEqual(len(result.skips), 1)
        self.assertFalse(ENGINE.complete_result(0, self.result(skipped=1)))
        selected = self.result()
        selected.pytest_deselected([object()])
        self.assertFalse(ENGINE.complete_result(0, selected))

    def test_reported_failure_or_error_also_blocks_success_exit(self):
        for category in ("failed", "error", "deselected"):
            with self.subTest(category=category):
                self.assertFalse(ENGINE.complete_result(0, self.result(**{category: 1})))

if __name__ == "__main__":
    unittest.main()
