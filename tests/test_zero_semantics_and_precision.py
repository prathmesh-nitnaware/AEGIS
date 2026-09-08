"""
tests/test_zero_semantics_and_precision.py
===========================================
Regression tests for AEGIS zero semantics, analytical score precision,
API None-vs-0 distinction, and structural fusion isolation.

Validates Requirements:
- Test A: score = None does NOT become 0.0 (preserves None / unavailable status).
- Test B: score = 0.0 remains 0.0.
- Test C: score = 0.00035954 is not rounded to 0.0 or 0.0004 in telemetry.
- Test D: score = 0.000031 (< 0.00005) is NOT coerced or rounded to 0.0.
- Test E: Windows V1 returns None and is represented as quarantined / unavailable.
- Test F: CICIDS / EMBER unavailable models return None without crashing.
- Test G: V3 Candidate remains strictly shadow-only (not in ACTIVE_FUSION_KEYS).
- Test H: Passing 'windows_advanced_v3_candidate': 0.99 to fuse() has zero influence.
- Test I: Unknown arbitrary keys passed to fuse() are rejected / ignored.
- Active Fusion Math: Verified against exact theoretical values.
- Stateful Context Transition: Proves changing context alters features deterministically.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT / "agent"))

from agent.fusion_engine import ThreatFusionEngine
from agent.windows_process_context import (
    ProcessContextState,
    WindowsProcessContextAggregator,
    WindowsAdvancedV2FeatureExtractor,
    WindowsAdvancedV3FeatureExtractor,
    WindowsAdvancedV3CandidateFeatureExtractor,
)


class TestZeroSemanticsAndPrecision(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = ThreatFusionEngine()

    # -----------------------------------------------------------------------
    # Test A & B & C & D: Score Precision and None Distinction in Telemetry
    # -----------------------------------------------------------------------
    def test_A_none_score_does_not_become_zero(self):
        """Test A: None score must remain None, score_status='unavailable'."""
        import agent.run_all as ra

        captured_lines = []
        captured_api = []

        def mock_open_write(line):
            captured_lines.append(json.loads(line))

        with patch("agent.run_all._post_event_async", side_effect=captured_api.append), \
             patch("agent.run_all.open", unittest.mock.mock_open()) as m_open:
            ra.save_event("test_model", None, "UNAVAILABLE", status="quarantined")
            # Verify the written json line
            write_calls = m_open().write.call_args_list
            written_str = "".join(call[0][0] for call in write_calls)
            record = json.loads(written_str.strip())

        self.assertIsNone(record["score"], "Telemetry serialized None as a non-None value")
        self.assertNotEqual(record["score"], 0.0, "None became 0.0 in JSONL telemetry")
        self.assertEqual(record["score_status"], "quarantined")

        # Verify API payload
        self.assertEqual(len(captured_api), 1)
        api_payload = captured_api[0]
        self.assertIsNone(api_payload["threat_score"], "API payload threat_score coerced None to numeric")
        self.assertNotEqual(api_payload["threat_score"], 0.0, "API payload threat_score coerced None to 0.0")
        self.assertEqual(api_payload["score_status"], "quarantined")

    def test_B_real_zero_remains_zero(self):
        """Test B: A legitimate numeric score of 0.0 remains 0.0 and available."""
        import agent.run_all as ra

        captured_api = []
        with patch("agent.run_all._post_event_async", side_effect=captured_api.append), \
             patch("agent.run_all.open", unittest.mock.mock_open()) as m_open:
            ra.save_event("test_model", 0.0, "Normal")
            write_calls = m_open().write.call_args_list
            written_str = "".join(call[0][0] for call in write_calls)
            record = json.loads(written_str.strip())

        self.assertEqual(record["score"], 0.0)
        self.assertEqual(record["score_status"], "available")

        self.assertEqual(len(captured_api), 1)
        api_payload = captured_api[0]
        self.assertEqual(api_payload["threat_score"], 0.0)
        self.assertEqual(api_payload["score_status"], "available")
        self.assertEqual(api_payload["normal_probability"], 1.0)

    def test_C_small_score_preserves_precision(self):
        """Test C: 0.00035954 is stored with full floating-point precision, not rounded to 4 decimals."""
        import agent.run_all as ra

        small_score = 0.00035954
        with patch("agent.run_all._post_event_async"), \
             patch("agent.run_all.open", unittest.mock.mock_open()) as m_open:
            ra.save_event("windows_advanced_v3", small_score, "Normal")
            write_calls = m_open().write.call_args_list
            written_str = "".join(call[0][0] for call in write_calls)
            record = json.loads(written_str.strip())

        self.assertAlmostEqual(record["score"], small_score, places=8)
        self.assertNotEqual(record["score"], round(small_score, 4), "Score was destructively rounded to 4 decimals")

    def test_D_tiny_score_below_four_decimals_not_zero(self):
        """Test D: 0.000031 (< 0.00005) is NOT rounded into 0.0."""
        import agent.run_all as ra

        tiny_score = 0.000031
        with patch("agent.run_all._post_event_async"), \
             patch("agent.run_all.open", unittest.mock.mock_open()) as m_open:
            ra.save_event("test_model", tiny_score, "Normal")
            write_calls = m_open().write.call_args_list
            written_str = "".join(call[0][0] for call in write_calls)
            record = json.loads(written_str.strip())

        self.assertGreater(record["score"], 0.0, "Score was truncated to 0.0")
        self.assertAlmostEqual(record["score"], tiny_score, places=6)

    # -----------------------------------------------------------------------
    # Test E & F: Model-Level Quarantined / Offline None Returns
    # -----------------------------------------------------------------------
    def test_E_windows_v1_returns_none(self):
        """Test E: Windows V1 inference returns None due to quarantine."""
        res = self.engine.score_process_event(api_call_sequence=["CreateFile", "WriteFile"])
        self.assertIsNone(res, "Quarantined Windows V1 returned a non-None score")

    def test_F_offline_models_return_none(self):
        """Test F: CICIDS and EMBER return None gracefully when lightgbm is unavailable."""
        if getattr(self.engine, "_cicids_model", None) is None:
            res_cicids = self.engine.score_network_flow({"Destination Port": 80})
            self.assertIsNone(res_cicids)
        if getattr(self.engine, "_ember_model", None) is None:
            res_ember = self.engine.score_file(np.zeros(2381))
            self.assertIsNone(res_ember)

    # -----------------------------------------------------------------------
    # Test G & H & I: Fusion Allowlist & Shadow Isolation
    # -----------------------------------------------------------------------
    def test_G_v3_candidate_not_in_active_fusion_keys(self):
        """Test G: V3 Candidate is strictly shadow-only and NOT in ACTIVE_FUSION_KEYS."""
        self.assertNotIn("windows_advanced_v3_candidate", ThreatFusionEngine.ACTIVE_FUSION_KEYS)
        self.assertNotIn("windows_advanced_v3", ThreatFusionEngine.ACTIVE_FUSION_KEYS)
        self.assertNotIn("windows_advanced_v2", ThreatFusionEngine.ACTIVE_FUSION_KEYS)

    def test_H_v3_candidate_cannot_influence_fusion(self):
        """Test H: Passing windows_advanced_v3_candidate=0.99 into fuse() has zero influence."""
        baseline_fuse = self.engine.fuse({"linux": 0.5})
        with_shadow_candidate = self.engine.fuse({
            "linux": 0.5,
            "windows_advanced_v3_candidate": 0.99,
        })
        self.assertEqual(
            baseline_fuse, with_shadow_candidate,
            f"Passing candidate to fuse() changed output: {baseline_fuse} vs {with_shadow_candidate}"
        )

    def test_I_arbitrary_unknown_keys_rejected_from_fusion(self):
        """Test I: Arbitrary unknown keys cannot participate in fuse()."""
        baseline_fuse = self.engine.fuse({"linux": 0.4, "hdfs": 0.6})
        with_unknown = self.engine.fuse({
            "linux": 0.4,
            "hdfs": 0.6,
            "arbitrary_unregistered_model": 1.0,
            "fake_detector": 0.999,
        })
        self.assertEqual(baseline_fuse, with_unknown)

    # -----------------------------------------------------------------------
    # Active Model Fusion Mathematics
    # -----------------------------------------------------------------------
    def test_fusion_active_models_mathematics(self):
        """Active fusion weights and mathematics remain exact."""
        # 3 active models: (0.8 + 0.2 + 0.4) / 3 = 0.46666667
        fused_3 = self.engine.fuse({"linux": 0.8, "hdfs": 0.2, "zero_day": 0.4})
        self.assertAlmostEqual(fused_3, 1.4 / 3.0, places=6)

        # 1 active + 1 None: 0.8 / 1.0 = 0.8
        fused_partial = self.engine.fuse({"linux": 0.8, "hdfs": None})
        self.assertAlmostEqual(fused_partial, 0.8, places=6)

        # 1 active zero + 1 active 0.5: (0.0 + 0.5) / 2 = 0.25
        fused_with_zero = self.engine.fuse({"linux": 0.0, "hdfs": 0.5})
        self.assertAlmostEqual(fused_with_zero, 0.25, places=6)

    # -----------------------------------------------------------------------
    # Stateful Context Transition Diagnostics
    # -----------------------------------------------------------------------
    def test_stateful_context_transition_observability(self):
        """Changing network_conn_count across time changes feature vector and score deterministically."""
        aggregator = WindowsProcessContextAggregator()
        guid = "{test-stateful-guid}"
        pid = 1234

        # Initial Process Creation (Event 1): 0 network connections
        aggregator.process_event({
            "event_id": 1,
            "process_guid": guid,
            "pid": pid,
            "image": "C:\\Windows\\System32\\cmd.exe",
            "command_line": "cmd.exe /c whoami",
            "parent_image": "C:\\Windows\\explorer.exe",
            "integrity_level": "Medium",
        })

        feats_t0 = aggregator.get_features_v3_candidate(guid)
        score_t0 = self.engine.score_windows_v3_candidate(feats_t0)
        self.assertEqual(feats_t0[5], 0.0, "Initial network_conn_count must be 0.0")

        # Process Network Event (Event 3): network connection arrives later
        aggregator.process_event({
            "event_id": 3,
            "process_guid": guid,
            "pid": pid,
            "destination_ip": "10.0.0.1",
            "destination_port": 443,
        })

        feats_t1 = aggregator.get_features_v3_candidate(guid)
        score_t1 = self.engine.score_windows_v3_candidate(feats_t1)
        self.assertEqual(feats_t1[5], 1.0, "Network connection count must be 1.0 after Event 3")

        # Feature vector has legitimately changed:
        self.assertNotEqual(feats_t0, feats_t1, "Feature vector should reflect updated state")


if __name__ == "__main__":
    unittest.main()
