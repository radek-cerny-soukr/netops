import time
import unittest

from parser_watchdog import measured_growth


class Watchdog(unittest.TestCase):
    def test_returns_parser_result(self):
        self.assertEqual(measured_growth(lambda n: 'x' * n, len, small=10), 10)

    def test_kills_a_blocked_parser(self):
        with self.assertRaisesRegex(AssertionError, 'watchdog'):
            measured_growth(str, lambda _: time.sleep(30), timeout=0.05)

    def test_reports_child_assertions(self):
        def fail(_):
            raise ValueError('parser failure')
        with self.assertRaisesRegex(AssertionError, 'parser failure'):
            measured_growth(str, fail)

    def test_rejects_superlinear_growth(self):
        # Deterministic CPU samples exercise the growth check in the child.
        from unittest.mock import patch
        with patch('parser_watchdog.time.process_time', side_effect=[0, 1] * 3 + [0, 16] * 3):
            with self.assertRaisesRegex(AssertionError, r'\(1, 16\)'):
                measured_growth(str, len)
