"""
tests/test_all_6_models_hardened.py
===================================
Comprehensive Hardened Model Verification Suite for all 6 AEGIS Layer 1 Engines:
1. Linux IDS (Model 1)
2. Windows Advanced v3 (Model 2c)
3. CICIDS Network Flow (Model 3)
4. EMBER Static PE Binary (Model 4)
5. HDFS Log Anomaly (Model 5)
6. Zero-Day Isolation Forest (Model 6)
"""

import sys
import unittest
from pathlib import Path
import numpy as np

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from agent.fusion_engine import ThreatFusionEngine
from agent.windows_process_context import WindowsAdvancedV3FeatureExtractor, ProcessContextState


class TestAll6ModelsHardened(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = ThreatFusionEngine()

    def test_01_all_artifacts_loaded(self):
        self.assertIsNotNone(self.engine._linux_model, "Linux IDS model missing")
        self.assertIsNotNone(self.engine._win_v3_payload, "Windows v3 payload missing")
        self.assertIsNotNone(self.engine._cicids_model, "CICIDS model missing")
        self.assertIsNotNone(self.engine._ember_model, "EMBER model missing")
        self.assertIsNotNone(self.engine._hdfs_model, "HDFS model missing")
        self.assertIsNotNone(self.engine._zday_model, "Zero-Day model missing")

    def test_02_linux_ids_scoring(self):
        # Benign: read, write, openat, close, mmap, fstat
        benign_seq = [0, 1, 257, 3, 9, 5] * 20
        # Attack: execve, ptrace, init_module, delete_module, reboot
        attack_seq = [59, 101, 175, 176, 169] * 10
        
        score_benign = self.engine.score_process_event(syscall_sequence=benign_seq)
        score_attack = self.engine.score_process_event(syscall_sequence=attack_seq)
        score_empty = self.engine.score_process_event(syscall_sequence=[])
        
        self.assertIsNotNone(score_benign)
        self.assertIsNotNone(score_attack)
        self.assertLess(score_benign, 0.40, "Linux benign syscalls flagged as threat")
        self.assertGreater(score_attack, 0.80, "Linux exploit syscalls not flagged")
        self.assertEqual(score_empty, 0.0, "Empty syscalls should score 0.0")

    def test_03_windows_v3_scoring(self):
        # 9-features: [cmd_len, enc_flag, script_flag, anomaly, il_val, net_count, masq, role_logon, role_admin]
        benign_svchost = [45.0, 0.0, 0.0, 0.0, 4.0, 0.0, 0.0, 1.0, 0.0]
        benign_explorer = [120.0, 0.0, 0.0, 0.0, 2.0, 2.0, 0.0, 0.0, 0.0]
        attack_powershell = [4500.0, 1.0, 1.0, 1.0, 2.0, 5.0, 0.0, 0.0, 0.0]
        attack_mimikatz = [85.0, 0.0, 0.0, 1.0, 3.0, 1.0, 1.0, 0.0, 1.0]

        score_svc = self.engine.score_windows_v3(benign_svchost)
        score_exp = self.engine.score_windows_v3(benign_explorer)
        score_ps = self.engine.score_windows_v3(attack_powershell)
        score_mimi = self.engine.score_windows_v3(attack_mimikatz)

        self.assertLess(score_svc, 0.20)
        self.assertLess(score_exp, 0.20)
        self.assertGreater(score_ps, 0.85)
        self.assertGreater(score_mimi, 0.85)

    def test_04_cicids_network_flow(self):
        benign_dns = {"Destination Port": 53.0, "Flow Duration": 1500.0, "Total Fwd Packets": 1.0}
        attack_syn_flood = {"Destination Port": 80.0, "Flow Duration": 500.0, "Total Fwd Packets": 250.0, "SYN Flag Count": 250.0}
        attack_portscan = {"Destination Port": 445.0, "Flow Duration": 10.0, "Total Fwd Packets": 1.0, "SYN Flag Count": 1.0}

        score_dns = self.engine.score_network_flow(benign_dns)
        score_syn = self.engine.score_network_flow(attack_syn_flood)
        score_pscan = self.engine.score_network_flow(attack_portscan)
        score_empty = self.engine.score_network_flow({})

        self.assertLess(score_dns, 0.20, f"DNS flow false positive: {score_dns}")
        self.assertGreater(score_syn, 0.85, f"SYN flood missed: {score_syn}")
        self.assertGreater(score_pscan, 0.85, f"PortScan missed: {score_pscan}")
        self.assertEqual(score_empty, 0.0)

    def test_05_ember_pe_scoring(self):
        # Benign: flat byte distribution, low entropy
        benign_pe = {f: 0.01 for f in self.engine._ember_features}
        for i in range(256):
            benign_pe[self.engine._ember_features[i]] = 0.0039
        for i in range(256, 512):
            benign_pe[self.engine._ember_features[i]] = 0.001

        # Ransomware: extreme entropy spike
        ransomware_pe = {f: 0.0 for f in self.engine._ember_features}
        for i in range(256, 512):
            ransomware_pe[self.engine._ember_features[i]] = 0.95

        score_benign = self.engine.score_file(benign_pe)
        score_mal = self.engine.score_file(ransomware_pe)
        score_empty = self.engine.score_file({})

        self.assertLess(score_benign, 0.20, f"Benign PE false positive: {score_benign}")
        self.assertGreater(score_mal, 0.85, f"Ransomware PE missed: {score_mal}")
        self.assertEqual(score_empty, 0.0)

    def test_06_hdfs_log_scoring(self):
        benign_log = "081109 203520 23 INFO dfs.FSNamesystem: BLOCK* NameSystem.allocateBlock: /user/hadoop/data_12.csv. blk_1002"
        anomaly_corrupt = "081109 203604 147 ERROR dfs.DataNode$BlockReceiver: Block blk_1002 is corrupted, checksum verification failed"
        anomaly_wiping = "081109 203613 99 FATAL dfs.FSNamesystem: System audit logs wiped and deleted by root administrator"

        score_benign = self.engine.score_log_line(benign_log)
        score_corrupt = self.engine.score_log_line(anomaly_corrupt)
        score_wiping = self.engine.score_log_line(anomaly_wiping)
        score_empty = self.engine.score_log_line("")

        self.assertLess(score_benign, 0.20, f"HDFS benign false positive: {score_benign}")
        self.assertGreater(score_corrupt, 0.85, f"HDFS corrupt block missed: {score_corrupt}")
        self.assertGreater(score_wiping, 0.85, f"HDFS log wiping missed: {score_wiping}")
        self.assertEqual(score_empty, 0.0)

    def test_07_zero_day_scoring(self):
        score_benign = self.engine.score_windows_event("4624", "explorer.exe", "DOMAIN\\User", "192.168.1.50")
        score_attack = self.engine.score_windows_event("7045", "mimikatz.exe", "SYSTEM", "10.0.0.99")

        self.assertIsNotNone(score_benign)
        self.assertIsNotNone(score_attack)
        self.assertLess(score_benign, 0.35, f"Zero day benign false positive: {score_benign}")
        self.assertGreater(score_attack, 0.65, f"Zero day attack missed: {score_attack}")


if __name__ == "__main__":
    unittest.main()
