"""
AEGIS HDFS Log Model Validation Suite
Tests: artifact, feature contract (two-stage TF-IDF), inference,
       routing, safe-failure, active enforcement integration.
Layer coverage: 1, 2, 3, 4, 5, 7.
"""
import sys
import unittest
from pathlib import Path

import numpy as np

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

import joblib
from agent.fusion_engine import ThreatFusionEngine

_MODEL_DIR    = _PROJECT_ROOT / "trained_models" / "hdfs"
_MODEL_PKL    = _MODEL_DIR / "hdfs_xgboost_model.pkl"
_VECTORIZER   = _MODEL_DIR / "hdfs_vectorizer.pkl"
_LE_PKL       = _MODEL_DIR / "hdfs_label_encoder.pkl"

# Representative log lines sourced from the HDFS anomaly-detection dataset
_NORMAL_LOG   = ("081109 204011 143 INFO dfs.DataNode$PacketResponder: "
                 "PacketResponder 0 for block blk_38865049274842714 terminating")
_ANOMALY_LOG  = ("081109 204127 13 ERROR dfs.DataNode$DataXceiver: "
                 "writeBlock blk_-6670958622368987959 received exception "
                 "java.io.IOException: Broken pipe")


class TestHDFSArtifact(unittest.TestCase):
    """Layer 1 — Artifact integrity."""

    def test_01_model_file_exists(self):
        """1. hdfs_xgboost_model.pkl exists."""
        self.assertTrue(_MODEL_PKL.exists(), f"Missing: {_MODEL_PKL}")

    def test_02_vectorizer_file_exists(self):
        """2. hdfs_vectorizer.pkl exists."""
        self.assertTrue(_VECTORIZER.exists(), f"Missing: {_VECTORIZER}")

    def test_03_label_encoder_file_exists(self):
        """3. hdfs_label_encoder.pkl exists."""
        self.assertTrue(_LE_PKL.exists(), f"Missing: {_LE_PKL}")

    def test_04_model_deserializes_as_xgboost(self):
        """4. Model deserialises to XGBClassifier."""
        model = joblib.load(_MODEL_PKL)
        self.assertEqual(type(model).__name__, "XGBClassifier")

    def test_05_vectorizer_deserializes_as_tfidf(self):
        """5. Vectorizer deserialises to TfidfVectorizer."""
        vec = joblib.load(_VECTORIZER)
        self.assertEqual(type(vec).__name__, "TfidfVectorizer")

    def test_06_label_encoder_classes(self):
        """6. Label encoder has exactly ['Anomaly', 'Normal']."""
        le = joblib.load(_LE_PKL)
        classes = sorted(str(c) for c in le.classes_)
        self.assertEqual(classes, ["Anomaly", "Normal"],
                         f"Unexpected classes: {classes}")

    def test_07_anomaly_class_at_index_0(self):
        """7. 'Anomaly' is at index 0 (alphabetically first) — score = P(Anomaly) = proba[0]."""
        le = joblib.load(_LE_PKL)
        self.assertEqual(str(le.classes_[0]).lower(), "anomaly",
                         "Anomaly not at index 0 — score formula would be wrong")

    def test_08_engine_loads_hdfs_model(self):
        """8. ThreatFusionEngine loads _hdfs_model, _hdfs_vectorizer, and _hdfs_le."""
        engine = ThreatFusionEngine()
        self.assertIsNotNone(engine._hdfs_model)
        self.assertIsNotNone(engine._hdfs_vectorizer)
        self.assertIsNotNone(engine._hdfs_le)


class TestHDFSFeatureContract(unittest.TestCase):
    """Layer 2 — Feature contract: raw text → TF-IDF sparse (1, 5000)."""

    @classmethod
    def setUpClass(cls):
        cls.vectorizer = joblib.load(_VECTORIZER)

    def test_09_vectorizer_output_shape(self):
        """9. transform([log_line]) produces a (1, 5000) sparse matrix."""
        sparse = self.vectorizer.transform([_NORMAL_LOG])
        self.assertEqual(sparse.shape, (1, 5000),
                         f"Unexpected shape: {sparse.shape}")

    def test_10_vectorizer_output_not_nan(self):
        """10. Vectorized output has no NaN values."""
        sparse = self.vectorizer.transform([_NORMAL_LOG])
        arr = sparse.toarray()
        self.assertFalse(np.any(np.isnan(arr)))

    def test_11_vectorizer_output_not_inf(self):
        """11. Vectorized output has no Inf values."""
        sparse = self.vectorizer.transform([_NORMAL_LOG])
        arr = sparse.toarray()
        self.assertFalse(np.any(np.isinf(arr)))

    def test_12_empty_string_does_not_crash(self):
        """12. Empty log line transforms without error."""
        sparse = self.vectorizer.transform([""])
        self.assertEqual(sparse.shape[1], 5000)

    def test_13_two_stage_inference_chain(self):
        """13. Two-stage chain (vectorize → predict_proba) produces (2,) proba array."""
        model = joblib.load(_MODEL_PKL)
        sparse = self.vectorizer.transform([_NORMAL_LOG])
        proba = model.predict_proba(sparse)[0]
        self.assertEqual(len(proba), 2)
        self.assertAlmostEqual(float(np.sum(proba)), 1.0, places=5)


class TestHDFSInference(unittest.TestCase):
    """Layer 3 — Inference smoke test via score_log_line()."""

    @classmethod
    def setUpClass(cls):
        cls.engine = ThreatFusionEngine()

    def test_14_score_log_line_returns_float(self):
        """14. score_log_line(text) returns a float."""
        score = self.engine.score_log_line(_NORMAL_LOG)
        self.assertIsNotNone(score)
        self.assertIsInstance(score, float)

    def test_15_score_in_range(self):
        """15. Score is in [0, 1]."""
        score = self.engine.score_log_line(_NORMAL_LOG)
        self.assertIsNotNone(score)
        self.assertTrue(0.0 <= score <= 1.0, f"Out of range: {score}")

    def test_16_score_no_nan_inf(self):
        """16. Score is finite."""
        score = self.engine.score_log_line(_NORMAL_LOG)
        self.assertIsNotNone(score)
        self.assertFalse(np.isnan(score))
        self.assertFalse(np.isinf(score))

    def test_17_anomaly_log_scores_non_trivially(self):
        """17. Anomalous log line produces a non-None score (numeric output)."""
        score = self.engine.score_log_line(_ANOMALY_LOG)
        self.assertIsNotNone(score)
        self.assertTrue(0.0 <= score <= 1.0)

    def test_18_vectorizer_none_returns_none(self):
        """18. When _hdfs_vectorizer is None, score_log_line returns None (safe failure)."""
        engine = ThreatFusionEngine()
        original = engine._hdfs_vectorizer
        try:
            engine._hdfs_vectorizer = None
            result = engine.score_log_line(_NORMAL_LOG)
            self.assertIsNone(result)
        finally:
            engine._hdfs_vectorizer = original

    def test_19_model_none_returns_none(self):
        """19. When _hdfs_model is None, score_log_line returns None (safe failure)."""
        engine = ThreatFusionEngine()
        original = engine._hdfs_model
        try:
            engine._hdfs_model = None
            result = engine.score_log_line(_NORMAL_LOG)
            self.assertIsNone(result)
        finally:
            engine._hdfs_model = original

    def test_20_empty_log_line_does_not_crash(self):
        """20. Empty log line string scores without exception."""
        score = self.engine.score_log_line("")
        # Score may be any float or None — must not raise
        if score is not None:
            self.assertTrue(0.0 <= score <= 1.0)


class TestHDFSRouting(unittest.TestCase):
    """Layer 4 — Active enforcement routing and label validity."""

    @classmethod
    def setUpClass(cls):
        cls.engine = ThreatFusionEngine()

    def test_21_hdfs_in_active_weights(self):
        """21. 'hdfs' key is present in fusion weight dict."""
        self.assertIn("hdfs", self.engine._weights)
        self.assertGreater(self.engine._weights["hdfs"], 0.0)

    def test_22_hdfs_labels_valid_true(self):
        """22. _hdfs_labels_valid is True — 'Anomaly' class matches threat keyword."""
        self.assertTrue(self.engine._hdfs_labels_valid)

    def test_23_fuse_includes_hdfs_score(self):
        """23. fuse({'hdfs': 0.8}) returns 0.8 — HDFS participates in fusion."""
        result = self.engine.fuse({"hdfs": 0.8})
        self.assertAlmostEqual(result, 0.8, places=3)

    def test_24_fuse_with_none_hdfs_skips_gracefully(self):
        """24. fuse({'hdfs': None, 'zero_day': 0.5}) skips None and uses zero_day only."""
        result = self.engine.fuse({"hdfs": None, "zero_day": 0.5})
        self.assertAlmostEqual(result, 0.5, places=3)


if __name__ == "__main__":
    unittest.main()
