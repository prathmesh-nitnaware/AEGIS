import unittest
import sys
import pickle
import numpy as np
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

class TestWindowsAdvancedV3Model(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v3_dir = _PROJECT_ROOT / "trained_models" / "windows_advanced_v3"
        cls.v2_dir = _PROJECT_ROOT / "trained_models" / "windows_advanced_v2"
        cls.v3_path = cls.v3_dir / "windows_advanced_v3.pkl"
        cls.v2_path = cls.v2_dir / "windows_advanced_v2.pkl"

    def test_01_artifact_loads_successfully(self):
        """1. V3 Model artifact loads successfully."""
        self.assertTrue(self.v3_path.exists(), f"V3 model not found at {self.v3_path}")
        with open(self.v3_path, "rb") as f:
            payload = pickle.load(f)
        self.assertIsNotNone(payload)
        self.assertEqual(payload.get("model_version"), "windows_advanced_v3")

    def test_02_model_accepts_exactly_9_features(self):
        """2. V3 Model accepts exactly 9 input features."""
        with open(self.v3_path, "rb") as f:
            payload = pickle.load(f)
        model = payload["model"]
        
        # Test prediction with 9-dimensional fake feature vector
        dummy_input = np.zeros((1, 9))
        probs = model.predict_proba(dummy_input)[0]
        self.assertEqual(len(probs), 2)

    def test_03_feature_ordering_correct(self):
        """3. Feature names list in metadata matches exactly V3 order."""
        with open(self.v3_path, "rb") as f:
            payload = pickle.load(f)
        expected_features = [
            "command_line_length",
            "encoded_command_flag",
            "scripting_indicator",
            "parent_child_anomaly_v3",
            "integrity_level_numeric",
            "network_conn_count",
            "masquerading_indicator",
            "process_role_logon",
            "process_role_admin"
        ]
        self.assertEqual(payload.get("feature_names"), expected_features)
        self.assertEqual(payload.get("feature_count"), 9)

    def test_04_probability_output_valid(self):
        """4. Model output probabilities are in valid [0, 1] range."""
        with open(self.v3_path, "rb") as f:
            payload = pickle.load(f)
        model = payload["model"]
        
        dummy_input = np.array([[50.0, 1.0, 1.0, 1.0, 3.0, 2.0, 0.0, 0.0, 0.0]])
        probs = model.predict_proba(dummy_input)[0]
        self.assertTrue(0.0 <= probs[0] <= 1.0)
        self.assertTrue(0.0 <= probs[1] <= 1.0)
        self.assertAlmostEqual(sum(probs), 1.0, places=5)

    def test_05_metadata_present(self):
        """5. V3 artifact metadata contains all expected fields."""
        with open(self.v3_path, "rb") as f:
            payload = pickle.load(f)
        self.assertEqual(payload.get("feature_version"), "v3")
        self.assertEqual(payload.get("probability_type"), "raw_xgboost_probability")
        self.assertEqual(payload.get("random_seed"), 42)
        self.assertIn("model_hyperparameters", payload)
        self.assertIn("training_date", payload)

    def test_06_v2_artifact_unchanged(self):
        """6. V2 artifact remains completely unchanged."""
        self.assertTrue(self.v2_path.exists())
        with open(self.v2_path, "rb") as f:
            payload = pickle.load(f)
        
        # V2 should remain 6 features, calibrated=none, threshold 0.90
        self.assertEqual(payload.get("feature_count", 6), 6)
        self.assertEqual(payload.get("threshold"), 0.90)
        # Ensure it has no V3 indicators
        self.assertNotEqual(payload.get("model_version"), "windows_advanced_v3")

    def test_07_v3_shadow_isolation_checks(self):
        """7. Verifies V3 shadow mode does not affect active fusion scoring/voting."""
        from agent.fusion_engine import ThreatFusionEngine
        engine = ThreatFusionEngine()
        
        # Verify V3 payload is loaded but not in active model weights
        self.assertIsNotNone(engine._win_v3_payload)
        self.assertFalse(hasattr(engine, "_win_v3_weight"))
        
        # Verify threshold is 0.90
        v3_threshold = engine._win_v3_payload.get("threshold", 0.90)
        self.assertEqual(v3_threshold, 0.90)
        
        # Verify probabilities type is raw_xgboost_probability
        self.assertEqual(engine._win_v3_payload.get("probability_type"), "raw_xgboost_probability")

    def test_08_scoring_non_interference(self):
        """8. V2 and V3 score same event without interference."""
        from agent.fusion_engine import ThreatFusionEngine
        from agent.windows_process_context import WindowsAdvancedV2FeatureExtractor, WindowsAdvancedV3FeatureExtractor, ProcessContextState
        
        engine = ThreatFusionEngine()
        state = ProcessContextState(
            guid="{test-interf}", pid=999, image="C:\\Windows\\System32\\cmd.exe",
            parent_image="explorer.exe", command_line="whoami", integrity_level="High"
        )
        
        v2_feats = WindowsAdvancedV2FeatureExtractor.extract_features(state)
        v3_feats = WindowsAdvancedV3FeatureExtractor.extract_features(state)
        
        score_v2 = engine.score_windows_v2(v2_feats)
        score_v3 = engine.score_windows_v3(v3_feats)
        
        self.assertIsNotNone(score_v2)
        self.assertIsNotNone(score_v3)
        self.assertNotEqual(score_v2, score_v3)


if __name__ == "__main__":
    unittest.main()
