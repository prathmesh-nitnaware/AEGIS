"""
tests/test_windows_v3_pipeline_integration.py
=============================================
Integration verification suite for the Windows Advanced Layered Architecture:
1. ETW Telemetry Collector event parsing and aggregation.
2. WindowsProcessContextAggregator PID-to-GUID state mapping and network event binding.
3. 9-Dimensional V3 Feature Extraction from ProcessContextState.
4. Unified ThreatFusionEngine.score_process_event() routing to Windows V3 model.
5. Benign baseline vs High-severity adversary attack discrimination.
6. Legacy Model 1/2 isolation verification (quarantine maintained).
"""

import sys
import unittest
from pathlib import Path
import numpy as np

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from agent.fusion_engine import ThreatFusionEngine
from agent.windows_process_context import (
    WindowsProcessContextAggregator,
    WindowsAdvancedV3FeatureExtractor,
    ProcessContextState,
)
from agent.collectors.etw_collector import ETWTelemetryCollector


class TestWindowsV3PipelineIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = ThreatFusionEngine()
        cls.collector = ETWTelemetryCollector(force_emulation=True)

    def test_01_etw_event_parsing_and_aggregator_linking(self):
        """1. Raw ETW events are parsed and aggregated into state without pre-existing GUIDs."""
        aggregator = WindowsProcessContextAggregator()

        # Simulate Event 1 (Process Create) from ETW collector
        raw_props_1 = {
            "ProcessId": 4820,
            "ParentProcessId": 1024,
            "Image": "C:\\Windows\\System32\\powershell.exe",
            "CommandLine": "powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=",
            "User": "DOMAIN\\Administrator",
        }
        event_1 = self.collector.parse_etw_event(1, "Microsoft-Windows-Kernel-Process", raw_props_1)
        aggregator.process_event(event_1)

        self.assertIn(4820, aggregator.pid_to_guid)
        guid = aggregator.pid_to_guid[4820]
        self.assertIn(guid, aggregator.processes)

        state = aggregator.processes[guid]
        self.assertEqual(state.pid, 4820)
        self.assertEqual(state.image, "C:\\Windows\\System32\\powershell.exe")

        # Simulate Event 3 (Network Connect) from ETW collector for same PID
        raw_props_3 = {
            "ProcessId": 4820,
            "DestinationIp": "198.51.100.42",
            "DestinationPort": 4444,
        }
        event_3 = self.collector.parse_etw_event(3, "Microsoft-Windows-Kernel-Network", raw_props_3)
        aggregator.process_event(event_3)

        self.assertIn("198.51.100.42:4444", state.network_destinations)

    def test_02_v3_feature_extraction_from_state(self):
        """2. Aggregator state extracts into exact 9-dimensional V3 feature vector."""
        aggregator = WindowsProcessContextAggregator()
        raw_props = {
            "ProcessId": 5100,
            "ParentProcessId": 800,
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "User": "SYSTEM",
        }
        event = self.collector.parse_etw_event(1, "Microsoft-Windows-Kernel-Process", raw_props)
        aggregator.process_event(event)

        guid = aggregator.pid_to_guid[5100]
        feats = aggregator.get_features_v3(guid)

        self.assertIsNotNone(feats)
        self.assertEqual(len(feats), 9)
        self.assertEqual(feats[0], float(len("cmd.exe /c whoami")))

    def test_03_score_process_event_with_context_state(self):
        """3. score_process_event dynamically accepts ProcessContextState and yields V3 score."""
        state_benign = ProcessContextState(
            guid="{benign-guid}",
            pid=1004,
            image="C:\\Windows\\System32\\svchost.exe",
            parent_image="C:\\Windows\\System32\\services.exe",
            command_line="svchost.exe -k netsvcs",
            integrity_level="System",
        )

        score_benign = self.engine.score_process_event(process_features=state_benign)
        self.assertIsNotNone(score_benign)
        self.assertLess(score_benign, 0.25, f"Benign service flagged suspiciously: {score_benign}")

    def test_04_adversary_attacks_flagged_with_high_threat(self):
        """4. Malicious PowerShell and Mimikatz process contexts trigger high threat (>0.85)."""
        # Obfuscated PowerShell execution
        state_powershell = ProcessContextState(
            guid="{attack-ps}",
            pid=6600,
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            parent_image="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            command_line="powershell.exe -ExecutionPolicy Bypass -encodedcommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA=",
            integrity_level="Medium",
        )
        state_powershell.network_destinations.add("203.0.113.5:8080")

        # Mimikatz credential dumping
        state_mimikatz = ProcessContextState(
            guid="{attack-mimi}",
            pid=7700,
            image="C:\\Users\\Public\\mimikatz.exe",
            parent_image="C:\\Windows\\System32\\cmd.exe",
            command_line="mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit",
            integrity_level="High",
        )

        score_ps = self.engine.score_process_event(process_features=state_powershell)
        score_mimi = self.engine.score_process_event(process_features=state_mimikatz)

        self.assertIsNotNone(score_ps)
        self.assertIsNotNone(score_mimi)
        self.assertGreater(score_ps, 0.85, f"Obfuscated PowerShell missed: {score_ps}")
        self.assertGreater(score_mimi, 0.85, f"Mimikatz execution missed: {score_mimi}")

    def test_05_legacy_adfa_model_quarantine_integrity(self):
        """5. Legacy ADFA model remains quarantined and does not execute via raw tokens."""
        # Directly invoking with api_call_sequence returns None due to compatibility guard
        score_legacy = self.engine.score_process_event(api_call_sequence=["ntdll.dll+0x16d33"])
        self.assertIsNone(score_legacy)

        # Fusion engine skips quarantined windows model when compatible=False
        fusion_score = self.engine.fuse({"windows": 0.95})
        self.assertEqual(fusion_score, 0.0)


if __name__ == "__main__":
    unittest.main()
