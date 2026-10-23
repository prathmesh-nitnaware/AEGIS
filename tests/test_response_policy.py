import os
import unittest
from unittest.mock import patch

from backend.response_policy import decide_response


class ResponsePolicyTests(unittest.TestCase):
    def test_low_score_logs(self):
        result = decide_response({"final_weighted_score": 0.1, "consensus_reached": False})
        self.assertEqual(result["action"], "LOG")

    def test_high_score_without_consensus_only_alerts(self):
        result = decide_response({"final_weighted_score": 0.99, "consensus_reached": False})
        self.assertEqual(result["action"], "ALERT")

    def test_remediation_off_only_alerts(self):
        with patch.dict(os.environ, {"AEGIS_AUTO_REMEDIATE": "false"}, clear=False):
            result = decide_response({
                "final_weighted_score": 0.99, "consensus_reached": True,
                "details": {"pid": 4321, "process_name": "demo"},
            })
        self.assertEqual(result["action"], "ALERT")

    def test_remediation_requires_valid_target(self):
        with patch.dict(os.environ, {"AEGIS_AUTO_REMEDIATE": "true", "AEGIS_KILL_THRESHOLD": "0.9"}, clear=False):
            result = decide_response({"final_weighted_score": 0.99, "consensus_reached": True, "details": {"pid": 4321}})
        self.assertEqual(result["action"], "ALERT")

    def test_validated_process_target_can_be_approved(self):
        with patch.dict(os.environ, {"AEGIS_AUTO_REMEDIATE": "true", "AEGIS_KILL_THRESHOLD": "0.9"}, clear=False):
            result = decide_response({
                "final_weighted_score": 0.99, "consensus_reached": True,
                "details": {"pid": 4321, "process_name": "demo"},
            })
        self.assertEqual(result["action"], "KILL_PROCESS")

    def test_nonfinite_score_is_safe(self):
        result = decide_response({"final_weighted_score": float("nan")})
        self.assertEqual(result["action"], "LOG")


if __name__ == "__main__":
    unittest.main()
