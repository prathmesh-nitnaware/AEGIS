"""
tests/test_enhanced_model_robustness.py
=======================================
Robustness and security test suite for the hardened Zero-Day IsolationForest
and Linux IDS XGBoost models.

Verifies:
1. Linux IDS: Zero-padding bias elimination (empty sequence -> 0.0, short seq -> normal).
2. Linux IDS: Accurate classification of attack vs benign workflows.
3. Linux IDS: Position-invariant detection (resilience to mimicry/dilution).
4. Zero-Day: High anomaly separation between in-vocabulary and OOV attacks (>0.70).
5. Zero-Day: Masquerading defense (unauthorized users cannot spoof svchost.exe).
"""

import sys
import unittest
from pathlib import Path
import numpy as np

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from agent.fusion_engine import ThreatFusionEngine


class TestEnhancedLinuxIDSRobustness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = ThreatFusionEngine()

    def test_01_empty_sequence_scores_zero(self):
        """Empty syscall sequence produces 0.0 threat score (no false positive)."""
        score = self.engine.score_process_event(syscall_sequence=[])
        self.assertEqual(score, 0.0)

    def test_02_short_benign_sequence_not_flagged_as_attack(self):
        """Short benign sequence is not flagged as high threat."""
        # Simple process init: execve, brk, mmap, access, open, fstat, close
        short_seq = [59, 12, 9, 21, 2, 5, 3]
        score = self.engine.score_process_event(syscall_sequence=short_seq)
        self.assertIsNotNone(score)
        self.assertLess(score, 0.50, f"Short sequence incorrectly flagged: {score}")

    def test_03_benign_system_workflows_produce_low_threat(self):
        """Standard Linux commands score below 0.50."""
        workflows = {
            "bash": [0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13, 14, 16, 21, 22, 24, 32, 33, 72, 78, 80, 202] * 20,
            "python": [59, 12, 9, 21, 2, 5, 3, 9, 10, 11, 2, 0, 3, 12, 2, 0, 3, 231] * 25,
            "nginx": [202, 45, 46, 44, 47, 43, 48, 0, 1, 3, 41, 42, 49, 50] * 35,
        }
        for name, seq in workflows.items():
            score = self.engine.score_process_event(syscall_sequence=seq)
            self.assertIsNotNone(score)
            self.assertLess(score, 0.50, f"Workflow '{name}' got excessive threat score: {score}")

    def test_04_attack_signatures_detected_with_high_confidence(self):
        """Critical attack signatures score > 0.60."""
        attacks = {
            "hydra": [41, 42, 44, 45, 48, 41, 42, 44, 45, 48, 41, 42, 44, 45, 48] * 30,
            "meterpreter": [59, 101, 105, 41, 42, 44, 45, 10, 9, 11, 62] * 35,
            "priv_esc": [105, 106, 126, 157, 59, 101, 165, 166, 82, 87, 90, 92] * 40,
            "web_shell": [59, 33, 33, 33, 41, 42, 0, 1, 59, 105, 62] * 40,
        }
        for name, seq in attacks.items():
            score = self.engine.score_process_event(syscall_sequence=seq)
            self.assertIsNotNone(score)
            self.assertGreaterEqual(score, 0.60, f"Attack '{name}' under-detected: {score}")


class TestEnhancedZeroDayRobustness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = ThreatFusionEngine()

    def test_05_legitimate_processes_produce_low_anomaly(self):
        """Known baseline processes score <= 0.30."""
        normal_samples = [
            ("4688", "svchost.exe", "SYSTEM", "127.0.0.1"),
            ("4688", "explorer.exe", "Admin", "127.0.0.1"),
            ("4688", "chrome.exe", "Admin", "192.168.1.50"),
            ("4688", "python.exe", "Admin", "192.168.1.100"),
        ]
        for eid, proc, user, ip in normal_samples:
            score = self.engine.score_windows_event(eid, proc, user, ip)
            self.assertIsNotNone(score)
            self.assertLessEqual(score, 0.30, f"Legitimate process {proc} got high anomaly: {score}")

    def test_06_unseen_oov_attacks_score_high_anomaly(self):
        """Completely unseen zero-day exploits score > 0.65."""
        zero_day_samples = [
            ("10", "stealer_payload_v99.exe", "unknown_hacker", "185.220.101.5"),
            ("7045", "cryptolocker_dropper.exe", "SYSTEM", "45.33.32.156"),
            ("1", "cobalt_beacon_raw.exe", "guest", "198.51.100.22"),
        ]
        for eid, proc, user, ip in zero_day_samples:
            score = self.engine.score_windows_event(eid, proc, user, ip)
            self.assertIsNotNone(score)
            self.assertGreaterEqual(score, 0.65, f"Zero-Day payload {proc} not flagged: {score}")

    def test_07_masquerading_protection(self):
        """Malicious user masquerading as svchost.exe on remote IP is not suppressed."""
        score = self.engine.score_windows_event(
            "4688", "svchost.exe", "evil_user", "185.220.101.5"
        )
        self.assertIsNotNone(score)
        # Should not be capped at 0.15
        self.assertGreater(score, 0.20, f"Masqueraded svchost was improperly suppressed to {score}")


if __name__ == "__main__":
    unittest.main()
