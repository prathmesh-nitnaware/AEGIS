import unittest
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from agent.windows_process_context import (
    WindowsProcessContextAggregator,
    WindowsAdvancedV3FeatureExtractor,
    ProcessContextState
)


class TestWindowsAdvancedV3Features(unittest.TestCase):
    def test_01_feature_ordering_and_names(self):
        """1. V3 feature names list matches the expected 9 features in exact order."""
        expected_features = [
            "command_line_length",
            "encoded_command_flag",
            "scripting_indicator",
            "parent_child_anomaly_v3",
            "integrity_level_numeric",
            "network_conn_count",
            "masquerading_indicator",
            "process_role_logon",
            "process_role_admin"
        ]
        self.assertEqual(WindowsAdvancedV3FeatureExtractor.FEATURE_NAMES, expected_features)

    def test_02_command_line_length(self):
        """2. command_line_length calculates correctly."""
        state = ProcessContextState(
            guid="{test}", pid=100, image="C:\\Windows\\System32\\cmd.exe",
            command_line="cmd.exe /c whoami"
        )
        feats = WindowsAdvancedV3FeatureExtractor.extract_features(state)
        # Length of "cmd.exe /c whoami" is 17
        self.assertEqual(feats[0], 17.0)

        # Missing command line defaults to 0
        state_empty = ProcessContextState(guid="{test}", pid=100, image="cmd.exe")
        feats_empty = WindowsAdvancedV3FeatureExtractor.extract_features(state_empty)
        self.assertEqual(feats_empty[0], 0.0)

    def test_03_encoded_command_flag(self):
        """3. encoded_command_flag flags base64 commands."""
        # PowerShell base64 flag
        state_enc = ProcessContextState(
            guid="{test}", pid=100, image="powershell.exe",
            command_line="powershell.exe -enc AAAAA="
        )
        feats_enc = WindowsAdvancedV3FeatureExtractor.extract_features(state_enc)
        self.assertEqual(feats_enc[1], 1.0)

        # Normal command has 0
        state_norm = ProcessContextState(
            guid="{test}", pid=100, image="powershell.exe",
            command_line="powershell.exe Get-Process"
        )
        feats_norm = WindowsAdvancedV3FeatureExtractor.extract_features(state_norm)
        self.assertEqual(feats_norm[1], 0.0)

    def test_04_scripting_indicator(self):
        """4. scripting_indicator flags scripting engines correctly."""
        # PowerShell is a scripting engine
        state_ps = ProcessContextState(guid="{test}", pid=100, image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
        feats_ps = WindowsAdvancedV3FeatureExtractor.extract_features(state_ps)
        self.assertEqual(feats_ps[2], 1.0)

        # svchost is not
        state_svc = ProcessContextState(guid="{test}", pid=100, image="C:\\Windows\\System32\\svchost.exe")
        feats_svc = WindowsAdvancedV3FeatureExtractor.extract_features(state_svc)
        self.assertEqual(feats_svc[2], 0.0)

    def test_05_integrity_mapping(self):
        """5. integrity_level_numeric maps strings to expected numeric scales."""
        integrity_tests = [
            ("Low", 1.0),
            ("Untrusted", 1.0),
            ("Medium", 2.0),
            ("High", 3.0),
            ("System", 4.0),
            ("", 2.0) # default fallback
        ]
        for il_str, expected in integrity_tests:
            state = ProcessContextState(guid="{test}", pid=100, image="cmd.exe", integrity_level=il_str)
            feats = WindowsAdvancedV3FeatureExtractor.extract_features(state)
            self.assertEqual(feats[4], expected, f"Failed for {il_str}")

    def test_06_network_connection_counting(self):
        """6. network_conn_count increments correctly with unique destinations."""
        agg = WindowsProcessContextAggregator()
        agg.process_event({
            "event_id": 1,
            "process_guid": "{test-net}",
            "pid": 500,
            "image": "C:\\Windows\\System32\\curl.exe"
        })
        
        # Add network connections
        agg.process_event({
            "event_id": 3,
            "process_guid": "{test-net}",
            "pid": 500,
            "destination_ip": "10.0.0.1",
            "destination_port": 80
        })
        # Duplicate connection should not double count
        agg.process_event({
            "event_id": 3,
            "process_guid": "{test-net}",
            "pid": 500,
            "destination_ip": "10.0.0.1",
            "destination_port": 80
        })
        # Unique destination IP
        agg.process_event({
            "event_id": 3,
            "process_guid": "{test-net}",
            "pid": 500,
            "destination_ip": "10.0.0.2",
            "destination_port": 80
        })
        
        feats = agg.get_features_v3("{test-net}")
        self.assertEqual(feats[5], 2.0)

    def test_07_process_role_mapping(self):
        """7. get_process_role maps executables and system paths correctly."""
        # System Logon
        self.assertEqual(WindowsAdvancedV3FeatureExtractor.get_process_role("C:\\Windows\\System32\\userinit.exe"), "SYSTEM_LOGON")
        # System Shell
        self.assertEqual(WindowsAdvancedV3FeatureExtractor.get_process_role("cmd.exe"), "SYSTEM_SHELL")
        # Sysadmin Tool
        self.assertEqual(WindowsAdvancedV3FeatureExtractor.get_process_role("net1.exe"), "SYSADMIN_TOOL")
        # Normal System Helper in System32
        self.assertEqual(WindowsAdvancedV3FeatureExtractor.get_process_role("C:\\Windows\\System32\\taskhostw.exe"), "NORMAL_SYSTEM_HELPER")
        # Custom binary in Temp
        self.assertEqual(WindowsAdvancedV3FeatureExtractor.get_process_role("C:\\Windows\\Temp\\legit_looking.exe"), "UNKNOWN_USER_BINARY")

    def test_08_parent_child_transitions(self):
        """8. Validates parent-child transition anomalies."""
        # 1. SYSTEM_LOGON -> SYSTEM_LOGON (Normal)
        self.assertEqual(WindowsAdvancedV3FeatureExtractor.get_parent_child_anomaly(
            "SYSTEM_LOGON", "SYSTEM_LOGON", "winlogon.exe", "userinit.exe"
        ), 0.0)

        # 2. SYSTEM_SHELL -> SYSADMIN_TOOL (Suspicious)
        self.assertEqual(WindowsAdvancedV3FeatureExtractor.get_parent_child_anomaly(
            "SYSTEM_SHELL", "SYSADMIN_TOOL", "powershell.exe", "sdclt.exe"
        ), 1.0)

        # 3. SYSTEM_SHELL -> UNKNOWN_USER_BINARY (Suspicious)
        self.assertEqual(WindowsAdvancedV3FeatureExtractor.get_parent_child_anomaly(
            "SYSTEM_SHELL", "UNKNOWN_USER_BINARY", "powershell.exe", "m.exe"
        ), 1.0)

        # 4. WMI -> SYSTEM_SHELL (Suspicious)
        self.assertEqual(WindowsAdvancedV3FeatureExtractor.get_parent_child_anomaly(
            "NORMAL_SYSTEM_HELPER", "SYSTEM_SHELL", "C:\\Windows\\System32\\wbem\\wmiprvse.exe", "powershell.exe"
        ), 1.0)

    def test_09_masquerading_detection(self):
        """9. Flags known Windows executables running from unexpected locations."""
        # Valid location
        self.assertEqual(WindowsAdvancedV3FeatureExtractor.get_masquerading_indicator("C:\\Windows\\System32\\svchost.exe"), 0.0)
        # Invalid location (user profile or Temp folder)
        self.assertEqual(WindowsAdvancedV3FeatureExtractor.get_masquerading_indicator("C:\\Users\\Admin\\AppData\\Local\\Temp\\svchost.exe"), 1.0)

    def test_10_userinit_vs_sdclt_collision_resolved(self):
        """10. V3 successfully distinguishes userinit.exe logon from sdclt.exe hijack."""
        userinit_state = ProcessContextState(
            guid="{userinit-guid}", pid=1000,
            image="C:\\Windows\\System32\\userinit.exe",
            parent_image="C:\\Windows\\System32\\winlogon.exe",
            command_line="C:\\windows\\system32\\userinit.exe",
            integrity_level="Medium"
        )
        
        sdclt_state = ProcessContextState(
            guid="{sdclt-guid}", pid=2000,
            image="C:\\Windows\\System32\\sdclt.exe",
            parent_image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="C:\\windows\\system32\\sdclt.exe",
            integrity_level="Medium"
        )

        userinit_feats = WindowsAdvancedV3FeatureExtractor.extract_features(userinit_state)
        sdclt_feats = WindowsAdvancedV3FeatureExtractor.extract_features(sdclt_state)

        # Confirm they produce DIFFERENT vectors in V3
        self.assertNotEqual(userinit_feats, sdclt_feats)
        # userinit should have logon_role=1 and anomaly=0
        self.assertEqual(userinit_feats[7], 1.0) # logon_role
        self.assertEqual(userinit_feats[3], 0.0) # anomaly
        # sdclt should have admin_role=1 and anomaly=1
        self.assertEqual(sdclt_feats[8], 1.0) # admin_role
        self.assertEqual(sdclt_feats[3], 1.0) # anomaly

    def test_11_train_production_feature_parity(self):
        """11. Confirms training and production pipelines use the identical extraction logic."""
        # They both rely on the same class implementation
        state = ProcessContextState(
            guid="{test}", pid=999, image="C:\\Windows\\System32\\cmd.exe",
            parent_image="explorer.exe", command_line="whoami", integrity_level="High"
        )
        feats_extracted_directly = WindowsAdvancedV3FeatureExtractor.extract_features(state)
        
        agg = WindowsProcessContextAggregator()
        agg.process_event({
            "event_id": 1,
            "process_guid": "{test}",
            "pid": 999,
            "image": "C:\\Windows\\System32\\cmd.exe",
            "parent_image": "explorer.exe",
            "command_line": "whoami",
            "integrity_level": "High"
        })
        feats_via_aggregator = agg.get_features_v3("{test}")
        self.assertEqual(feats_extracted_directly, feats_via_aggregator)

    def test_12_no_identity_leakage(self):
        """12. Verifies that no forbidden identity fields (usernames, computer names, IPs) are present."""
        state = ProcessContextState(
            guid="{test}", pid=999, image="C:\\Windows\\System32\\cmd.exe",
            parent_image="explorer.exe", command_line="whoami", integrity_level="High",
            user="Administrator"
        )
        feats = WindowsAdvancedV3FeatureExtractor.extract_features(state)
        # The length is 9. None of the elements represent username string or computer name.
        self.assertEqual(len(feats), 9)
        for val in feats:
            self.assertTrue(isinstance(val, float))


if __name__ == "__main__":
    unittest.main()
