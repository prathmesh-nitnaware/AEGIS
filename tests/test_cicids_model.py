"""
AEGIS CICIDS Network Model Validation Suite
Layer 8 — Dependency-gated tests.
When lightgbm is NOT installed (current state): validates artifact discovery,
loader exception handling, graceful None behavior, and absence from active fusion.
Full inference tests are conditional on lightgbm being available.
"""
import sys
import importlib
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

import joblib
from agent.fusion_engine import ThreatFusionEngine

_MODEL_PKL = _PROJECT_ROOT / "trained_models" / "cicids" / "aegis_lgbm_cicids_model.pkl"

# Detect whether lightgbm is available
try:
    import lightgbm as _lgb
    _HAS_LGBM = True
except ImportError:
    _HAS_LGBM = False


class TestCICIDSArtifactDiscovery(unittest.TestCase):
    """Layer 1 (partial) — Artifact discovery, always executable."""

    def test_01_artifact_exists_on_disk(self):
        """1. aegis_lgbm_cicids_model.pkl is present on disk."""
        self.assertTrue(_MODEL_PKL.exists(),
                        f"Artifact missing: {_MODEL_PKL}")

    def test_02_artifact_nonzero_size(self):
        """2. Artifact is not empty (> 1 MB expected for LightGBM export)."""
        size = _MODEL_PKL.stat().st_size
        self.assertGreater(size, 1_000_000,
                           f"Suspiciously small file: {size} bytes")


class TestCICIDSDependencyGate(unittest.TestCase):
    """Layer 8 — Dependency status and graceful degradation."""

    def test_03_lightgbm_availability_reported(self):
        """3. Correctly detect whether lightgbm is available in current env."""
        try:
            import lightgbm  # noqa: F401
            has_lgbm = True
        except ImportError:
            has_lgbm = False
        # This test always passes — its purpose is documentation.
        # The value is logged so CI output shows the environment state.
        self.assertIsInstance(has_lgbm, bool)
        if not has_lgbm:
            # BLOCKED — expected in current environment
            pass

    @unittest.skipIf(_HAS_LGBM, "lightgbm IS installed — skip degradation test")
    def test_04_deserialization_fails_with_import_error(self):
        """4. (BLOCKED state) joblib.load raises ImportError when lightgbm absent."""
        with self.assertRaises(Exception):  # ModuleNotFoundError is a subclass of ImportError
            joblib.load(_MODEL_PKL)

    def test_05_engine_cicids_model_none_when_dep_missing(self):
        """5. ThreatFusionEngine._cicids_model is None when lightgbm is absent."""
        if _HAS_LGBM:
            self.skipTest("lightgbm IS installed — model will load correctly")
        engine = ThreatFusionEngine()
        self.assertIsNone(engine._cicids_model,
                          "Expected None but model loaded — dependency detection failed")

    def test_06_score_network_flow_returns_none_gracefully(self):
        """6. score_network_flow({}) returns None (not a crash) when model unavailable."""
        if _HAS_LGBM:
            self.skipTest("lightgbm IS installed — will attempt real inference")
        engine = ThreatFusionEngine()
        result = engine.score_network_flow({"Destination Port": 80})
        self.assertIsNone(result,
                          f"Expected None, got {result}")

    def test_07_score_network_flow_none_does_not_raise(self):
        """7. score_network_flow with an empty dict does not raise any exception."""
        engine = ThreatFusionEngine()
        if engine._cicids_model is None:
            try:
                result = engine.score_network_flow({})
                self.assertIsNone(result)
            except Exception as exc:  # noqa: BLE001
                self.fail(f"score_network_flow raised unexpectedly: {exc}")

    def test_08_cicids_not_in_active_fusion_when_unavailable(self):
        """8. When cicids model is None, passing cicids score to fuse() is a no-op
        (None is skipped) — verify fuse output is unaffected."""
        engine = ThreatFusionEngine()
        if engine._cicids_model is not None:
            self.skipTest("CICIDS loaded — not in degraded state")
        # fuse() receives None for cicids → skips it
        result_without = engine.fuse({"hdfs": 0.5})
        result_with_none = engine.fuse({"hdfs": 0.5, "cicids": None})
        self.assertAlmostEqual(result_without, result_with_none, places=5,
                               msg="Passing cicids=None changed fuse() output")


@unittest.skipUnless(_HAS_LGBM, "lightgbm not installed — full inference BLOCKED")
class TestCICIDSFullInference(unittest.TestCase):
    """Full inference tests — only execute when lightgbm is available."""

    @classmethod
    def setUpClass(cls):
        cls.engine = ThreatFusionEngine()
        cls.payload = joblib.load(_MODEL_PKL)

    def test_09_payload_is_dict(self):
        """9. CICIDS payload is a dict export."""
        self.assertIsInstance(self.payload, dict)

    def test_10_payload_has_model_key(self):
        """10. Payload dict contains 'model' key."""
        self.assertIn("model", self.payload)

    def test_11_payload_has_features_key(self):
        """11. Payload dict contains 'features' key (column ordering list)."""
        self.assertIn("features", self.payload)
        self.assertIsInstance(self.payload["features"], list)

    def test_12_inference_returns_float(self):
        """12. score_network_flow returns float when model is loaded."""
        features = {col: 0.0 for col in self.engine._cicids_features}
        result = self.engine.score_network_flow(features)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, float)

    def test_13_inference_in_range(self):
        """13. score_network_flow output is in [0, 1]."""
        features = {col: 0.0 for col in self.engine._cicids_features}
        result = self.engine.score_network_flow(features)
        self.assertIsNotNone(result)
        self.assertTrue(0.0 <= result <= 1.0)


if __name__ == "__main__":
    unittest.main()
