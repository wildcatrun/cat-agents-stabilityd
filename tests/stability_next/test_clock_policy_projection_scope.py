"""Timing evidence belongs to policy, not the unrelated profile inventory."""
import sqlite3
import unittest
from test_daemon_clock_bridge import m


class ClockPolicyProjectionScopeTests(unittest.TestCase):
    def test_profile_inventory_does_not_require_a_clock_projection(self):
        with sqlite3.connect(':memory:') as conn:
            result = m.build_hermers_profile_modes(conn, {}, [], {}, {}, {})
        self.assertEqual(result['schemaVersion'], 1)
        self.assertNotIn('clockDiscipline', result)


if __name__ == '__main__':
    unittest.main()
