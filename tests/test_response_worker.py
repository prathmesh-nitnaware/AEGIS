import unittest
from unittest.mock import patch

from agent.response_worker import _execute


class ResponseWorkerTests(unittest.TestCase):
    def test_isolation_is_always_denied(self):
        status, details = _execute({"action_type": "ISOLATE_HOST"})
        self.assertEqual(status, "DENIED")

    def test_unknown_action_is_denied(self):
        status, _ = _execute({"action_type": "RUN_SHELL_COMMAND"})
        self.assertEqual(status, "DENIED")

    def test_destructive_action_simulates_by_default(self):
        with patch.dict("os.environ", {"AEGIS_RESPONSE_MODE": "simulation", "AEGIS_AUTO_REMEDIATE": "false"}):
            status, details = _execute({"action_type": "KILL_PROCESS", "target_pid": 1234,
                                        "parameters": {"details": {"process_name": "dummy"}}})
        self.assertEqual(status, "SIMULATED")
        self.assertTrue(details["simulation"])


if __name__ == "__main__":
    unittest.main()
