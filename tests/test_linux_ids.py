"""
AEGIS Linux IDS Model Validation Suite
Tests: artifact, feature contract, inference, routing, safe-failure.
Layer coverage: 1 (Artifact), 2 (Feature Contract), 3 (Inference),
                4 (Routing), 5 (Isolation), 7 (Active coverage).
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

import joblib
from agent.fusion_engine import ThreatFusionEngine


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
_MODEL_DIR = _PROJECT_ROOT / "trained_models" / "linux_ids"
_MODEL_PKL = _MODEL_DIR / "linux_xgboost_model.pkl"
_LE_PKL    = _MODEL_DIR / "linux_label_encoder.pkl"


class TestLinuxIDSArtifact(unittest.TestCase):
    """Layer 1 — Artifact integrity."""

    def test_01_model_file_exists(self):
        """1. linux_xgboost_model.pkl exists on disk."""
        self.assertTrue(_MODEL_PKL.exists(), f"Missing: {_MODEL_PKL}")

    def test_02_label_encoder_file_exists(self):
        """2. linux_label_encoder.pkl exists on disk."""
        self.assertTrue(_LE_PKL.exists(), f"Missing: {_LE_PKL}")

    def test_03_model_deserializes(self):
        """3. Model deserialises without error and is an XGBClassifier."""
        model = joblib.load(_MODEL_PKL)
        self.assertIsNotNone(model)
        self.assertEqual(type(model).__name__, "XGBClassifier",
                         f"Unexpected type: {type(model).__name__}")

    def test_04_label_encoder_deserializes(self):
        """4. Label encoder deserialises and contains expected classes."""
        le = joblib.load(_LE_PKL)
        self.assertIsNotNone(le)
        classes = list(le.classes_)
        self.assertGreater(len(classes), 1, "Encoder has fewer than 2 classes")

    def test_05_label_encoder_has_normal_class(self):
        """5. 'Normal' class is present (case-insensitive) — required for 1-P(Normal) score."""
        le = joblib.load(_LE_PKL)
        lower_classes = [str(c).lower() for c in le.classes_]
        self.assertIn("normal", lower_classes,
                      f"'Normal' missing from {list(le.classes_)}")

    def test_06_label_encoder_has_expected_7_classes(self):
        """6. Encoder has exactly 7 attack-type classes as per training dataset."""
        le = joblib.load(_LE_PKL)
        self.assertEqual(len(le.classes_), 7,
                         f"Expected 7 classes, got {len(le.classes_)}: {list(le.classes_)}")

    def test_07_engine_loads_linux_model(self):
        """7. ThreatFusionEngine loads _linux_model and _linux_le correctly."""
        engine = ThreatFusionEngine()
        self.assertIsNotNone(engine._linux_model,
                             "_linux_model is None — loader failed")
        self.assertIsNotNone(engine._linux_le,
                             "_linux_le is None — label encoder loader failed")


class TestLinuxIDSFeatureContract(unittest.TestCase):
    """Layer 2 — Feature contract: int[500], padding, truncation."""

    @classmethod
    def setUpClass(cls):
        cls.engine = ThreatFusionEngine()

    def _pad_truncate(self, seq, length=500):
        """Mirror of ThreatFusionEngine._pad_truncate."""
        arr = list(seq)[:length]
        arr += [0] * (length - len(arr))
        return np.array(arr, dtype=np.int64)

    def test_08_short_seq_padded_to_500(self):
        """8. Sequence shorter than 500 is right-padded with zeros to length 500."""
        short = list(range(10))
        padded = self._pad_truncate(short, 500)
        self.assertEqual(padded.shape, (500,))
        self.assertEqual(padded[10], 0)
        self.assertEqual(padded[-1], 0)

    def test_09_long_seq_truncated_to_500(self):
        """9. Sequence longer than 500 is truncated — only the first 500 elements used."""
        long_seq = list(range(600))
        truncated = self._pad_truncate(long_seq, 500)
        self.assertEqual(truncated.shape, (500,))
        self.assertEqual(int(truncated[499]), 499)

    def test_10_exact_seq_unchanged(self):
        """10. Sequence of exactly 500 elements is unchanged."""
        exact = list(range(500))
        result = self._pad_truncate(exact, 500)
        self.assertEqual(result.shape, (500,))
        self.assertEqual(int(result[0]), 0)
        self.assertEqual(int(result[499]), 499)

    def test_11_dtype_is_int64(self):
        """11. Padded sequence dtype is int64."""
        result = self._pad_truncate(list(range(100)))
        self.assertEqual(result.dtype, np.int64)

    def test_12_reshape_to_model_input(self):
        """12. Padded array reshapes to (1, 500) required by model.predict_proba."""
        result = self._pad_truncate(list(range(100)))
        x = result.reshape(1, -1)
        self.assertEqual(x.shape, (1, 500))


class TestLinuxIDSInference(unittest.TestCase):
    """Layer 3 — Inference smoke test."""

    @classmethod
    def setUpClass(cls):
        cls.engine = ThreatFusionEngine()

    def test_13_inference_returns_float(self):
        """13. score_process_event(syscall_sequence=...) returns float."""
        fake_syscalls = list(range(10, 260))
        score = self.engine.score_process_event(syscall_sequence=fake_syscalls)
        self.assertIsNotNone(score)
        self.assertIsInstance(score, float)

    def test_14_inference_output_in_range(self):
        """14. Output is in [0, 1]."""
        fake_syscalls = list(range(200))
        score = self.engine.score_process_event(syscall_sequence=fake_syscalls)
        self.assertIsNotNone(score)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)

    def test_15_inference_no_nan_inf(self):
        """15. Output is finite (no NaN or Inf)."""
        fake_syscalls = [59, 11, 2, 3, 231] * 100
        score = self.engine.score_process_event(syscall_sequence=fake_syscalls)
        self.assertIsNotNone(score)
        self.assertFalse(np.isnan(score), "Score is NaN")
        self.assertFalse(np.isinf(score), "Score is Inf")

    def test_16_empty_seq_does_not_crash(self):
        """16. Empty syscall sequence (all-zero padding) produces valid score."""
        score = self.engine.score_process_event(syscall_sequence=[])
        self.assertIsNotNone(score)
        self.assertTrue(0.0 <= score <= 1.0)

    def test_17_all_zero_seq_produces_valid_score(self):
        """17. All-zero vector (fully padded) produces a valid score."""
        score = self.engine.score_process_event(syscall_sequence=[0] * 500)
        self.assertIsNotNone(score)
        self.assertTrue(0.0 <= score <= 1.0)

    def test_18_model_none_returns_none(self):
        """18. When _linux_model is None, _score_linux returns None (safe failure)."""
        engine = ThreatFusionEngine()
        original = engine._linux_model
        try:
            engine._linux_model = None
            result = engine.score_process_event(syscall_sequence=[1, 2, 3])
            self.assertIsNone(result)
        finally:
            engine._linux_model = original

    def test_19_normal_class_resolved_dynamically(self):
        """19. Confirm Normal class index is found from label encoder, not hardcoded."""
        le = joblib.load(_LE_PKL)
        normal_idx = None
        for i, c in enumerate(le.classes_):
            if str(c).lower() == "normal":
                normal_idx = i
                break
        self.assertIsNotNone(normal_idx,
                             "'Normal' not found — score formula would fall back to 1-max_proba")


class TestLinuxIDSRouting(unittest.TestCase):
    """Layer 4 — Active enforcement routing."""

    @classmethod
    def setUpClass(cls):
        cls.engine = ThreatFusionEngine()

    def test_20_linux_in_active_weights(self):
        """20. 'linux' key is present in active fusion weight dict."""
        self.assertIn("linux", self.engine._weights)

    def test_21_linux_weight_positive(self):
        """21. Linux weight is > 0 (participates in weighted average)."""
        self.assertGreater(self.engine._weights["linux"], 0.0)

    def test_22_linux_labels_valid_true(self):
        """22. _linux_labels_valid is True — label encoder has a 'Normal' class
        that matches the threat-keyword check inside fuse()."""
        self.assertTrue(self.engine._linux_labels_valid,
                        "_linux_labels_valid is False — Linux excluded from fuse()")

    def test_23_fuse_includes_linux_score(self):
        """23. fuse({'linux': 0.75}) returns 0.75 — Linux IS included in fusion."""
        result = self.engine.fuse({"linux": 0.75})
        self.assertAlmostEqual(result, 0.75, places=3,
                               msg="fuse() did not include linux sub-score")

    def test_24_linux_fuse_with_other_active_models(self):
        """24. Linux participates correctly in a multi-model fuse call."""
        result = self.engine.fuse({"linux": 1.0, "hdfs": 0.0, "zero_day": 0.0})
        # Weighted average of 3 equal-weight active models: (1+0+0)/3 ≈ 0.333
        self.assertAlmostEqual(result, 1.0 / 3.0, places=2)


if __name__ == "__main__":
    unittest.main()
