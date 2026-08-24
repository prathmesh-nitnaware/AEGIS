import unittest
from pathlib import Path
import pickle
import numpy as np
import sys

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from agent.fusion_engine import ThreatFusionEngine
from agent.windows_process_context import (
    WindowsProcessContextAggregator,
    WindowsAdvancedV2FeatureExtractor,
    ProcessContextState
)


class TestWindowsAdvancedV2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = ThreatFusionEngine()
        cls.v2_dir = _PROJECT_ROOT / "trained_models" / "windows_advanced_v2"

    def test_01_artifact_loads_successfully(self):
        """1. Model artifact exists and loads successfully."""
        model_path = self.v2_dir / "windows_advanced_v2.pkl"
        self.assertTrue(model_path.exists(), f"V2 model not found at {model_path}")
        
        with open(model_path, "rb") as f:
            payload = pickle.load(f)
            
        self.assertIsNotNone(payload)
        self.assertIn("model", payload)
        self.assertIn("feature_names", payload)
        self.assertIn("threshold", payload)
        self.assertIn("class_mapping", payload)

    def test_02_feature_names_match_schema(self):
        """2. Feature names and ordering match the 6-dimensional schema."""
        model_path = self.v2_dir / "windows_advanced_v2.pkl"
        with open(model_path, "rb") as f:
            payload = pickle.load(f)
            
        expected_features = [
            "command_line_length",
            "encoded_command_flag",
            "scripting_indicator",
            "parent_spawn_anomaly",
            "integrity_level_numeric",
            "network_conn_count"
        ]
        self.assertEqual(payload["feature_names"], expected_features)

    def test_03_aggregator_tracks_lifecycle(self):
        """3. ProcessContextAggregator correctly tracks process creation and updates state."""
        agg = WindowsProcessContextAggregator(max_processes=10)
        
        # Simulating Event ID 1: Process Create
        agg.process_event({
            "event_id": 1,
            "process_guid": "{test-guid-1}",
            "pid": 1234,
            "image": "C:\\Windows\\System32\\cmd.exe",
            "command_line": "cmd.exe /c whoami",
            "integrity_level": "High",
            "parent_image": "explorer.exe",
            "parent_pid": 999
        })
        
        self.assertIn("{test-guid-1}", agg.processes)
        state = agg.processes["{test-guid-1}"]
        self.assertEqual(state.pid, 1234)
        self.assertEqual(state.image, "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(state.integrity_level, "High")
        self.assertEqual(len(state.network_destinations), 0)

        # Simulating Event ID 3: Network connection
        agg.process_event({
            "event_id": 3,
            "process_guid": "{test-guid-1}",
            "pid": 1234,
            "destination_ip": "1.1.1.1",
            "destination_port": 443
        })
        self.assertEqual(len(state.network_destinations), 1)
        self.assertIn("1.1.1.1:443", state.network_destinations)

        # Simulating Event ID 5: Process Terminated
        agg.process_event({
            "event_id": 5,
            "process_guid": "{test-guid-1}",
            "pid": 1234
        })
        self.assertTrue(state.terminated)
        self.assertNotIn(1234, agg.pid_to_guid)

    def test_04_aggregator_eviction_lru(self):
        """4. Aggregator enforces bounded cache and evicts oldest items first."""
        agg = WindowsProcessContextAggregator(max_processes=3)
        
        for i in range(5):
            agg.process_event({
                "event_id": 1,
                "process_guid": f"{{guid-{i}}}",
                "pid": 1000 + i,
                "image": f"proc_{i}.exe"
            })
            
        # Max capacity is 3. Older ones (guid-0 and guid-1) must have been evicted.
        self.assertEqual(len(agg.processes), 3)
        self.assertNotIn("{guid-0}", agg.processes)
        self.assertNotIn("{guid-1}", agg.processes)
        self.assertIn("{guid-2}", agg.processes)
        self.assertIn("{guid-3}", agg.processes)
        self.assertIn("{guid-4}", agg.processes)

    def test_05_feature_extractor_returns_correct_shapes_and_defaults(self):
        """5. Feature extractor generates expected values for basic and missing features."""
        # Test basic features
        state = ProcessContextState(
            guid="{test}",
            pid=456,
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            parent_image="excel.exe",
            command_line="powershell.exe -enc AAAAAA==",
            integrity_level="High"
        )
        state.network_destinations.add("8.8.8.8:53")
        
        feats = WindowsAdvancedV2FeatureExtractor.extract_features(state)
        # 1. command_line_length
        self.assertEqual(feats[0], float(len("powershell.exe -enc AAAAAA==")))
        # 2. encoded_command_flag
        self.assertEqual(feats[1], 1.0)
        # 3. scripting_indicator
        self.assertEqual(feats[2], 1.0)
        # 4. parent_spawn_anomaly (excel spawning powershell)
        self.assertEqual(feats[3], 1.0)
        # 5. integrity_level_numeric (High -> 3)
        self.assertEqual(feats[4], 3.0)
        # 6. network_conn_count
        self.assertEqual(feats[5], 1.0)

    def test_06_score_windows_v2_inference(self):
        """6. score_windows_v2 returns correct probability float in [0, 1]."""
        feats = [50.0, 0.0, 0.0, 0.0, 2.0, 0.0]
        score = self.engine.score_windows_v2(feats)
        self.assertIsNotNone(score)
        self.assertTrue(0.0 <= score <= 1.0)

    def test_07_quarantine_v1_remains_quarantined(self):
        """7. Windows Advanced v1 model remains quarantined, returning None."""
        score = self.engine.score_process_event(api_call_sequence=["ntdll.dll", "kernel32.dll"])
        self.assertIsNone(score)

    def test_08_verdict_mapping_correct(self):
        """8. Threshold verdict checks Attack vs Normal mapping correctly."""
        model_path = self.v2_dir / "windows_advanced_v2.pkl"
        with open(model_path, "rb") as f:
            payload = pickle.load(f)
        threshold = payload.get("threshold", 0.90)
        
        # Test verdict string assignment boundary
        verdict_normal = "Attack" if 0.15 >= threshold else "Normal"
        verdict_attack = "Attack" if 0.98 >= threshold else "Normal"
        
        self.assertEqual(verdict_normal, "Normal")
        self.assertEqual(verdict_attack, "Attack")

    def test_09_prevent_calibrated_model_uncalibrated_threshold(self):
        """9. Regression test preventing wrapping model in calibration with high threshold."""
        model_path = self.v2_dir / "windows_advanced_v2.pkl"
        with open(model_path, "rb") as f:
            payload = pickle.load(f)
            
        model = payload["model"]
        self.assertNotEqual(type(model).__name__, "CalibratedClassifierCV",
                            "Model is wrapped in CalibratedClassifierCV but has uncalibrated threshold of 0.90!")
        self.assertEqual(payload.get("calibration", "none"), "none")
        self.assertEqual(payload.get("probability_type"), "raw_xgboost_probability")


if __name__ == "__main__":
    unittest.main()
