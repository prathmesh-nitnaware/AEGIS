import unittest
from pathlib import Path
import joblib
import numpy as np

# Ensure project root is in sys.path
import sys
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from agent.fusion_engine import ThreatFusionEngine
from agent.confidence_engine import compute_confidence


class TestWindowsAdvancedEDR(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Initialize the ThreatFusionEngine
        cls.engine = ThreatFusionEngine()
        cls.model_dir = _PROJECT_ROOT / "trained_models" / "windows_advanced"

    def test_01_model_artifact_loads(self):
        """1. Model artifact loads successfully."""
        model_path = self.model_dir / "windows_advanced_xgboost.pkl"
        self.assertTrue(model_path.exists(), f"Missing model: {model_path}")
        model = joblib.load(model_path)
        self.assertIsNotNone(model)
        self.assertEqual(type(model).__name__, "XGBClassifier")

    def test_02_model_classes_correct(self):
        """2. Model classes are 'Attack' and 'Normal'."""
        le_path = self.model_dir / "label_encoder.pkl"
        self.assertTrue(le_path.exists(), f"Missing LabelEncoder: {le_path}")
        le = joblib.load(le_path)
        classes = list(le.classes_)
        self.assertIn("Normal", classes)
        self.assertIn("Attack", classes)
        self.assertEqual(set(classes), {"Normal", "Attack"})

    def test_03_attack_probability_maps_correctly(self):
        """3. Attack probability maps correctly (Attack has index 0 -> Threat score is high)."""
        # Mock high-risk probabilities [P(Attack)=0.95, P(Normal)=0.05]
        # Our engine returns: 1.0 - P(Normal) = 1.0 - 0.05 = 0.95
        # Let's bypass compatibility check to test the scoring function directly
        old_compat = self.engine.model_compatibility["windows"]["compatible"]
        try:
            self.engine.model_compatibility["windows"]["compatible"] = True
            
            # Mock the predict_proba to return high attack probability
            original_predict_proba = self.engine._win_model.predict_proba
            try:
                self.engine._win_model.predict_proba = lambda x: np.array([[0.95, 0.05]])
                score = self.engine._score_windows(["some_token"])
                self.assertIsNotNone(score)
                self.assertAlmostEqual(score, 0.95, places=2)
            finally:
                self.engine._win_model.predict_proba = original_predict_proba
        finally:
            self.engine.model_compatibility["windows"]["compatible"] = old_compat

    def test_04_normal_probability_maps_correctly(self):
        """4. Normal probability maps correctly (Normal has index 1 -> Threat score is low)."""
        # Mock low-risk probabilities [P(Attack)=0.02, P(Normal)=0.98]
        # Threat score: 1.0 - 0.98 = 0.02
        old_compat = self.engine.model_compatibility["windows"]["compatible"]
        try:
            self.engine.model_compatibility["windows"]["compatible"] = True
            original_predict_proba = self.engine._win_model.predict_proba
            try:
                self.engine._win_model.predict_proba = lambda x: np.array([[0.02, 0.98]])
                score = self.engine._score_windows(["some_token"])
                self.assertIsNotNone(score)
                self.assertAlmostEqual(score, 0.02, places=2)
            finally:
                self.engine._win_model.predict_proba = original_predict_proba
        finally:
            self.engine.model_compatibility["windows"]["compatible"] = old_compat

    def test_05_incompatible_live_telemetry_rejected(self):
        """5. Incompatible live DLL-name telemetry is rejected."""
        # Sysmon Event ID 7 produces plain DLL names, e.g. "ntdll.dll"
        # Since compatibility is False, _score_windows should skip it
        score = self.engine.score_process_event(api_call_sequence=["ntdll.dll", "kernel32.dll"])
        self.assertIsNone(score)

    def test_06_rejection_does_not_produce_fake_threat_score(self):
        """6. Rejection does not produce a fake threat score."""
        score = self.engine.score_process_event(api_call_sequence=["ntdll.dll"])
        self.assertIsNone(score)
        # Verify it doesn't affect fusion outcome when skipped
        fused = self.engine.fuse({"windows": score, "linux": 0.10})
        self.assertEqual(fused, 0.10)

    def test_07_windows_does_not_affect_confidence_while_incompatible(self):
        """7. Windows does not affect confidence while incompatible."""
        # Sub-scores dictionary containing only windows
        r = compute_confidence({"windows": 0.85}, event_type="process_windows", fusion_engine=self.engine)
        self.assertEqual(r.confidence, 0.0)
        self.assertEqual(r.completeness_factor, 1.0) # no expected models with reliability > 0

        # Sub-scores containing linux + windows
        r2 = compute_confidence({"linux": 0.40, "windows": 0.85}, event_type="process_windows", fusion_engine=self.engine)
        # Windows should be filtered out fromExpected and Fired, leaving only single-model fallback
        self.assertNotIn("windows", r2.models_fired)

    def test_08_score_process_event_contract(self):
        """8. score_process_event() returns the expected contract (Optional[float])."""
        # When scoring Windows (incompatible -> returns None)
        win_score = self.engine.score_process_event(api_call_sequence=["ntdll.dll"])
        self.assertIsNone(win_score)

        # When scoring Linux (compatible -> returns float or None if failed)
        # Mock _score_linux to return 0.42
        original_score_linux = self.engine._score_linux
        try:
            self.engine._score_linux = lambda seq: 0.42
            linux_score = self.engine.score_process_event(syscall_sequence=[1, 2, 3])
            self.assertEqual(linux_score, 0.42)
        finally:
            self.engine._score_linux = original_score_linux

    def test_09_get_verdict_receives_numeric_score(self):
        """9. get_verdict() receives a numeric score and returns correct string."""
        self.assertEqual(self.engine.get_verdict(0.15), "LOW")
        self.assertEqual(self.engine.get_verdict(0.45), "MEDIUM")
        self.assertEqual(self.engine.get_verdict(0.72), "HIGH")
        self.assertEqual(self.engine.get_verdict(0.95), "CRITICAL")

    def test_10_other_detectors_continue_when_windows_unavailable(self):
        """10. Other AEGIS detectors continue operating when Windows is unavailable."""
        scores = {
            "linux": 0.35,
            "windows": None,
            "cicids": 0.85,
        }
        fused = self.engine.fuse(scores)
        # Weighted average of linux (1.0) and cicids (1.0): (0.35 + 0.85) / 2.0 = 0.60
        self.assertAlmostEqual(fused, 0.60, places=2)


if __name__ == "__main__":
    unittest.main()
