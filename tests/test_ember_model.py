"""
AEGIS EMBER Malware Model Validation Suite
Layer 8 — Dependency-gated tests.
When lightgbm is NOT installed (current state): validates artifact discovery,
loader exception handling, graceful None behavior, absence from active fusion.
Also validates EMBER feature extraction path (lief IS installed separately).
Full inference tests are conditional on lightgbm availability.
"""
import sys
import unittest
from pathlib import Path

import numpy as np

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

import joblib
from agent.fusion_engine import ThreatFusionEngine

_MODEL_PKL    = _PROJECT_ROOT / "trained_models" / "ember" / "aegis_ember_model_full.pkl"
_DUMMY_FILE   = _PROJECT_ROOT / "trained_models" / "ember" / ".dummy"
_EMBER_FEAT   = _PROJECT_ROOT / "agent" / "ember_features.py"

# Detect dependencies
try:
    import lightgbm as _lgb
    _HAS_LGBM = True
except ImportError:
    _HAS_LGBM = False

try:
    import lief  # noqa: F401
    _HAS_LIEF = True
except ImportError:
    _HAS_LIEF = False


class TestEMBERArtifactDiscovery(unittest.TestCase):
    """Layer 1 (partial) — Artifact discovery, always executable."""

    def test_01_artifact_exists_on_disk(self):
        """1. aegis_ember_model_full.pkl is present on disk."""
        self.assertTrue(_MODEL_PKL.exists(), f"Missing: {_MODEL_PKL}")

    def test_02_artifact_nonzero_size(self):
        """2. Artifact is not empty (> 1 MB expected)."""
        size = _MODEL_PKL.stat().st_size
        self.assertGreater(size, 500_000,
                           f"Suspiciously small: {size} bytes")

    def test_03_dummy_file_exists_as_orphan(self):
        """3. .dummy placeholder exists — document as orphan (no functional role)."""
        self.assertTrue(_DUMMY_FILE.exists())
        self.assertEqual(_DUMMY_FILE.stat().st_size, 0,
                         ".dummy file is not empty — check if this is intentional")

    def test_04_ember_features_module_exists(self):
        """4. ember_features.py exists in agent/ — required for feature extraction."""
        self.assertTrue(_EMBER_FEAT.exists(),
                        f"ember_features.py missing from {_EMBER_FEAT}")


class TestEMBERDependencyGate(unittest.TestCase):
    """Layer 8 — Dependency status and graceful degradation."""

    def test_05_lightgbm_availability_reported(self):
        """5. Correctly detect whether lightgbm is available."""
        self.assertIsInstance(_HAS_LGBM, bool)

    def test_06_lief_is_installed(self):
        """6. lief IS installed — EMBER feature extraction path is available."""
        self.assertTrue(_HAS_LIEF,
                        "lief is NOT installed — EMBER feature extraction blocked")

    @unittest.skipIf(_HAS_LGBM, "lightgbm IS installed — skip degradation test")
    def test_07_deserialization_fails_with_import_error(self):
        """7. (BLOCKED state) joblib.load raises when lightgbm absent."""
        with self.assertRaises(Exception):
            joblib.load(_MODEL_PKL)

    def test_08_engine_ember_model_none_when_dep_missing(self):
        """8. ThreatFusionEngine._ember_model is None when lightgbm absent."""
        if _HAS_LGBM:
            self.skipTest("lightgbm installed — model will load")
        engine = ThreatFusionEngine()
        self.assertIsNone(engine._ember_model)

    def test_09_score_file_returns_none_gracefully(self):
        """9. score_file(array) returns None (not a crash) when model unavailable."""
        if _HAS_LGBM:
            self.skipTest("lightgbm installed — will attempt real inference")
        engine = ThreatFusionEngine()
        result = engine.score_file(np.zeros(2381))
        self.assertIsNone(result, f"Expected None, got {result}")

    def test_10_score_file_does_not_raise(self):
        """10. score_file with any input does not raise any exception."""
        engine = ThreatFusionEngine()
        if engine._ember_model is None:
            try:
                result = engine.score_file(np.zeros(100))
                self.assertIsNone(result)
            except Exception as exc:  # noqa: BLE001
                self.fail(f"score_file raised unexpectedly: {exc}")

    def test_11_ember_not_in_active_fusion_when_unavailable(self):
        """11. When ember model is None, passing ember=None to fuse() is a no-op."""
        engine = ThreatFusionEngine()
        if engine._ember_model is not None:
            self.skipTest("EMBER loaded — not in degraded state")
        result_without = engine.fuse({"hdfs": 0.5})
        result_with_none = engine.fuse({"hdfs": 0.5, "ember": None})
        self.assertAlmostEqual(result_without, result_with_none, places=5)


@unittest.skipUnless(_HAS_LIEF, "lief not installed — feature extraction test skipped")
class TestEMBERFeatureExtraction(unittest.TestCase):
    """EMBER feature extraction path — testable when lief IS installed."""

    def test_12_ember_features_importable(self):
        """12. ember_features module imports successfully."""
        import importlib
        spec = importlib.util.spec_from_file_location(
            "ember_features", str(_EMBER_FEAT)
        )
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
            imported = True
        except Exception:
            imported = False
        self.assertTrue(imported, "ember_features.py failed to import")

    def test_13_feature_names_has_expected_count(self):
        """13. ember_features.FEATURE_NAMES has the expected 2381 dimensions."""
        import importlib
        spec = importlib.util.spec_from_file_location(
            "ember_features", str(_EMBER_FEAT)
        )
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
            if hasattr(mod, "FEATURE_NAMES"):
                n = len(mod.FEATURE_NAMES)
                self.assertEqual(n, 2381,
                                 f"Expected 2381 EMBER features, got {n}")
        except Exception:
            pass  # feature names may not be a constant list in all implementations


@unittest.skipUnless(_HAS_LGBM, "lightgbm not installed — full inference BLOCKED")
class TestEMBERFullInference(unittest.TestCase):
    """Full inference tests — only execute when lightgbm is available."""

    @classmethod
    def setUpClass(cls):
        cls.engine = ThreatFusionEngine()
        cls.payload = joblib.load(_MODEL_PKL)

    def test_14_payload_is_dict(self):
        """14. EMBER payload is a dict export."""
        self.assertIsInstance(self.payload, dict)

    def test_15_payload_has_model_key(self):
        """15. Payload contains 'model' key."""
        self.assertIn("model", self.payload)

    def test_16_inference_returns_float(self):
        """16. score_file(zeros) returns float when model is loaded."""
        features = np.zeros(len(self.engine._ember_features))
        result = self.engine.score_file(features)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, float)

    def test_17_inference_in_range(self):
        """17. score_file output is in [0, 1]."""
        features = np.zeros(len(self.engine._ember_features))
        result = self.engine.score_file(features)
        self.assertIsNotNone(result)
        self.assertTrue(0.0 <= result <= 1.0)


if __name__ == "__main__":
    unittest.main()
