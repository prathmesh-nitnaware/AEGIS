import unittest
import sys
import pickle
import math
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from agent.windows_process_context import (
    WindowsAdvancedV3CandidateFeatureExtractor,
    ProcessContextState
)
from agent.fusion_engine import ThreatFusionEngine

class TestWindowsAdvancedV3Remediation(unittest.TestCase):
    def test_01_feature_transformation_cmd_lengths(self):
        """1. Tests log transformation on various command line lengths."""
        # Short command line
        state_short = ProcessContextState(guid="{test}", pid=1, image="cmd.exe", command_line="whoami")
        feats_short = WindowsAdvancedV3CandidateFeatureExtractor.extract_features(state_short)
        self.assertAlmostEqual(feats_short[0], math.log1p(len("whoami")), places=5)

        # Long command line
        long_cmd = "a" * 1000
        state_long = ProcessContextState(guid="{test}", pid=1, image="cmd.exe", command_line=long_cmd)
        feats_long = WindowsAdvancedV3CandidateFeatureExtractor.extract_features(state_long)
        self.assertAlmostEqual(feats_long[0], math.log1p(1000), places=5)

        # Extremely long command line
        huge_cmd = "b" * 50000
        state_huge = ProcessContextState(guid="{test}", pid=1, image="cmd.exe", command_line=huge_cmd)
        feats_huge = WindowsAdvancedV3CandidateFeatureExtractor.extract_features(state_huge)
        self.assertAlmostEqual(feats_huge[0], math.log1p(50000), places=5)

        # Empty command line
        state_empty = ProcessContextState(guid="{test}", pid=1, image="cmd.exe", command_line="")
        feats_empty = WindowsAdvancedV3CandidateFeatureExtractor.extract_features(state_empty)
        self.assertEqual(feats_empty[0], 0.0)

        # Null command line
        state_null = ProcessContextState(guid="{test}", pid=1, image="cmd.exe", command_line=None)
        feats_null = WindowsAdvancedV3CandidateFeatureExtractor.extract_features(state_null)
        self.assertEqual(feats_null[0], 0.0)

    def test_02_transition_logic_net_net1(self):
        """2. Tests benign vs malicious transitions for net -> net1."""
        # Benign transition (no sensitive arguments)
        state_benign = ProcessContextState(
            guid="{test}", pid=1, image="C:\\Windows\\System32\\net1.exe",
            parent_image="C:\\Windows\\System32\\net.exe", command_line="net1 view"
        )
        p_role = WindowsAdvancedV3CandidateFeatureExtractor.get_process_role(state_benign.parent_image)
        c_role = WindowsAdvancedV3CandidateFeatureExtractor.get_process_role(state_benign.image)
        benign_anomaly = WindowsAdvancedV3CandidateFeatureExtractor.get_parent_child_anomaly(
            p_role, c_role, state_benign.parent_image, state_benign.image, state_benign.command_line
        )
        self.assertEqual(benign_anomaly, 0.0)

        # Malicious transitions (sensitive arguments)
        sensitive_cmdlines = [
            "net1 user /add admin pass",
            "net1 localgroup administrators /add toby",
            "net1 user toby /delete",
            "net1 group /domain"
        ]
        for cmdline in sensitive_cmdlines:
            state_malicious = ProcessContextState(
                guid="{test}", pid=1, image="C:\\Windows\\System32\\net1.exe",
                parent_image="C:\\Windows\\System32\\net.exe", command_line=cmdline
            )
            malicious_anomaly = WindowsAdvancedV3CandidateFeatureExtractor.get_parent_child_anomaly(
                p_role, c_role, state_malicious.parent_image, state_malicious.image, state_malicious.command_line
            )
            self.assertEqual(malicious_anomaly, 1.0, f"Failed to flag sensitive command: {cmdline}")

    def test_03_isolation_controls(self):
        """3. Verifies that the V3 Candidate cannot alter active voting, confidence, or quarantine."""
        engine = ThreatFusionEngine()
        
        # Check active voting weights
        # Candidate V3 must NOT be present in active model weights or list of active threat vectors
        self.assertFalse(hasattr(engine, "_win_v3_candidate_weight"))
        self.assertIsNotNone(engine._win_v3_candidate_payload)
        
        # Candidate V3 cannot trigger quarantine/blocking or alter fusion verdicts
        active_verdict = engine.fuse({"linux_ids": 0.0, "windows_advanced": 0.0, "hdfs": 0.0})
        self.assertEqual(active_verdict, 0.0)


if __name__ == "__main__":
    unittest.main()
