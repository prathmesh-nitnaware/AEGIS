import re
import time
import math
from pathlib import Path
from typing import Dict, List, Optional, Set, Union


class ProcessContextState:
    """Represents the real-time context of a single Windows process."""

    def __init__(self, guid: str, pid: int, image: str, user: str = "", parent_guid: str = "", parent_pid: int = 0, parent_image: str = "", parent_command_line: str = "", command_line: str = "", integrity_level: str = ""):
        self.guid = guid
        self.pid = pid
        self.image = image
        self.user = user
        self.parent_guid = parent_guid
        self.parent_pid = parent_pid
        self.parent_image = parent_image
        self.parent_command_line = parent_command_line
        self.command_line = command_line
        self.integrity_level = integrity_level
        self.created_at = time.time()
        self.last_active_at = time.time()
        self.network_destinations: Set[str] = set()  # set of "dest_ip:port"
        self.terminated = False


class WindowsAdvancedV2FeatureExtractor:
    """Extracts a 6-dimensional numeric feature vector from a process context."""

    FEATURE_NAMES = [
        "command_line_length",
        "encoded_command_flag",
        "scripting_indicator",
        "parent_spawn_anomaly",
        "integrity_level_numeric",
        "network_conn_count",
    ]

    SCRIPTING_ENGINES = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
        "cscript.exe", "mshta.exe", "bash.exe", "wsl.exe"
    }

    SUSPICIOUS_PARENTS = {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
        "msaccess.exe", "acrord32.exe", "chrome.exe", "msedge.exe",
        "firefox.exe", "sqlservr.exe", "w3wp.exe", "tomcat.exe"
    }

    @classmethod
    def extract_features(cls, state: ProcessContextState) -> List[float]:
        # 1. command_line_length
        cmd_len = len(state.command_line) if state.command_line else 0
        
        # 2. encoded_command_flag
        enc_flag = 0
        if state.command_line:
            cmd_lower = state.command_line.lower()
            if re.search(r"\s-[eE]([nN][cC]([oO][dD][eE][dD][cC][oO][mM][mM][aA][nN][dD])?)?\s", cmd_lower) or "-encodedcommand" in cmd_lower:
                enc_flag = 1

        # 3. scripting_indicator
        script_flag = 0
        img_name = Path(state.image).name.lower() if state.image else ""
        if img_name in cls.SCRIPTING_ENGINES:
            script_flag = 1

        # 4. parent_spawn_anomaly
        parent_anomaly = 0
        parent_name = Path(state.parent_image).name.lower() if state.parent_image else ""
        if script_flag == 1 and parent_name in cls.SUSPICIOUS_PARENTS:
            parent_anomaly = 1

        # 5. integrity_level_numeric
        integrity_map = {
            "untrusted": 1,
            "low": 1,
            "medium": 2,
            "high": 3,
            "system": 4
        }
        il_str = state.integrity_level.lower() if state.integrity_level else ""
        il_val = integrity_map.get(il_str, 2)

        # 6. network_conn_count
        net_count = len(state.network_destinations)

        return [
            float(cmd_len),
            float(enc_flag),
            float(script_flag),
            float(parent_anomaly),
            float(il_val),
            float(net_count)
        ]


class WindowsAdvancedV3FeatureExtractor:
    """Extracts a 9-dimensional V3 numeric feature vector from a process context."""

    FEATURE_NAMES = [
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

    SYSTEM_LOGON = {"userinit.exe", "winlogon.exe"}
    SYSTEM_SHELL = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "bash.exe", "wsl.exe"}
    SYSADMIN_TOOL = {"net.exe", "net1.exe", "psexec.exe", "psexec64.exe", "sc.exe", "reg.exe", "whoami.exe", "klist.exe", "sdclt.exe"}
    NORMAL_SYSTEM_HELPER = {"conhost.exe", "taskhostw.exe", "services.exe", "svchost.exe", "spoolsv.exe"}
    
    KNOWN_SYSTEM_EXECUTABLES = {
        "userinit.exe", "winlogon.exe", "svchost.exe", "services.exe",
        "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe", "cmd.exe",
        "powershell.exe", "sdclt.exe", "taskhostw.exe", "conhost.exe", "spoolsv.exe"
    }

    @classmethod
    def get_process_role(cls, image_path: str) -> str:
        if not image_path:
            return "UNKNOWN_USER_BINARY"
            
        p = Path(image_path)
        img_name = p.name.lower()
        
        if img_name in cls.SYSTEM_LOGON:
            return "SYSTEM_LOGON"
        if img_name in cls.SYSTEM_SHELL:
            return "SYSTEM_SHELL"
        if img_name in cls.SYSADMIN_TOOL:
            return "SYSADMIN_TOOL"
        if img_name in cls.NORMAL_SYSTEM_HELPER:
            return "NORMAL_SYSTEM_HELPER"
            
        # Check standard Windows paths
        img_dir = str(p.parent).lower().replace("\\", "/")
        is_system_path = False
        if "c:/windows/system32" in img_dir or "c:/windows/syswow64" in img_dir:
            is_system_path = True
        elif img_dir.startswith("c:/windows") and not "temp" in img_dir:
            is_system_path = True
        elif "program files" in img_dir:
            is_system_path = True
            
        if is_system_path:
            return "NORMAL_SYSTEM_HELPER"
            
        return "UNKNOWN_USER_BINARY"

    @classmethod
    def get_parent_child_anomaly(cls, parent_role: str, child_role: str, parent_image: str, child_image: str) -> float:
        if parent_role == "SYSTEM_LOGON" and child_role == "SYSTEM_LOGON":
            return 0.0
            
        if parent_role == "SYSTEM_SHELL" and child_role == "SYSADMIN_TOOL":
            return 1.0
            
        if parent_role == "SYSTEM_SHELL" and child_role == "UNKNOWN_USER_BINARY":
            return 1.0
            
        p_name = Path(parent_image).name.lower() if parent_image else ""
        if p_name == "wmiprvse.exe" and child_role == "SYSTEM_SHELL":
            return 1.0
            
        SUSPICIOUS_PARENTS = {
            "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
            "msaccess.exe", "acrord32.exe"
        }
        if p_name in SUSPICIOUS_PARENTS and child_role == "SYSTEM_SHELL":
            return 1.0
            
        if p_name == "services.exe" and child_role == "SYSTEM_SHELL":
            return 1.0
            
        return 0.0

    @classmethod
    def get_masquerading_indicator(cls, image_path: str) -> float:
        if not image_path:
            return 0.0
        p = Path(image_path)
        img_name = p.name.lower()
        if img_name in cls.KNOWN_SYSTEM_EXECUTABLES:
            img_dir = str(p.parent).lower().replace("\\", "/")
            valid_dirs = [
                "c:/windows/system32",
                "c:/windows/syswow64",
                "c:/windows/system32/windowspowershell/v1.0"
            ]
            if not any(vd in img_dir for vd in valid_dirs):
                return 1.0
        return 0.0

    @classmethod
    def extract_features(cls, state: ProcessContextState) -> List[float]:
        # 1. command_line_length
        cmd_len = len(state.command_line) if state.command_line else 0
        
        # 2. encoded_command_flag
        enc_flag = 0
        if state.command_line:
            cmd_lower = state.command_line.lower()
            if re.search(r"\s-[eE]([nN][cC]([oO][dD][eE][dD][cC][oO][mM][mM][aA][nN][dD])?)?\s", cmd_lower) or "-encodedcommand" in cmd_lower:
                enc_flag = 1
                
        # 3. scripting_indicator
        script_flag = 0
        img_name = Path(state.image).name.lower() if state.image else ""
        if img_name in cls.SYSTEM_SHELL:
            script_flag = 1
            
        # 4. parent_child_anomaly_v3
        parent_role = cls.get_process_role(state.parent_image)
        child_role = cls.get_process_role(state.image)
        anomaly_v3 = cls.get_parent_child_anomaly(parent_role, child_role, state.parent_image, state.image)
        
        # 5. integrity_level_numeric
        integrity_map = {
            "untrusted": 1,
            "low": 1,
            "medium": 2,
            "high": 3,
            "system": 4
        }
        il_str = state.integrity_level.lower() if state.integrity_level else ""
        il_val = integrity_map.get(il_str, 2)
        
        # 6. network_conn_count
        net_count = len(state.network_destinations)
        
        # 7. masquerading_indicator
        masq_ind = cls.get_masquerading_indicator(state.image)
        
        # 8. process_role_logon
        role_logon = 1.0 if child_role == "SYSTEM_LOGON" else 0.0
        
        # 9. process_role_admin
        role_admin = 1.0 if child_role == "SYSADMIN_TOOL" else 0.0
        
        return [
            float(cmd_len),
            float(enc_flag),
            float(script_flag),
            float(anomaly_v3),
            float(il_val),
            float(net_count),
            float(masq_ind),
            float(role_logon),
            float(role_admin)
        ]


class WindowsAdvancedV3CandidateFeatureExtractor:
    """Extracts a 9-dimensional V3 candidate numeric feature vector with log command length and sysadmin transition checks."""

    FEATURE_NAMES = [
        "log_command_line_length",
        "encoded_command_flag",
        "scripting_indicator",
        "parent_child_anomaly_v3",
        "integrity_level_numeric",
        "network_conn_count",
        "masquerading_indicator",
        "process_role_logon",
        "process_role_admin"
    ]

    SYSTEM_LOGON = {"userinit.exe", "winlogon.exe"}
    SYSTEM_SHELL = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "bash.exe", "wsl.exe"}
    SYSADMIN_TOOL = {"net.exe", "net1.exe", "psexec.exe", "psexec64.exe", "sc.exe", "reg.exe", "whoami.exe", "klist.exe", "sdclt.exe"}
    NORMAL_SYSTEM_HELPER = {"conhost.exe", "taskhostw.exe", "services.exe", "svchost.exe", "spoolsv.exe"}
    
    KNOWN_SYSTEM_EXECUTABLES = {
        "userinit.exe", "winlogon.exe", "svchost.exe", "services.exe",
        "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe", "cmd.exe",
        "powershell.exe", "sdclt.exe", "taskhostw.exe", "conhost.exe", "spoolsv.exe"
    }

    @classmethod
    def get_process_role(cls, image_path: str) -> str:
        if not image_path:
            return "UNKNOWN_USER_BINARY"
            
        p = Path(image_path)
        img_name = p.name.lower()
        
        if img_name in cls.SYSTEM_LOGON:
            return "SYSTEM_LOGON"
        if img_name in cls.SYSTEM_SHELL:
            return "SYSTEM_SHELL"
        if img_name in cls.SYSADMIN_TOOL:
            return "SYSADMIN_TOOL"
        if img_name in cls.NORMAL_SYSTEM_HELPER:
            return "NORMAL_SYSTEM_HELPER"
            
        # Check standard Windows paths
        img_dir = str(p.parent).lower().replace("\\", "/")
        is_system_path = False
        if "c:/windows/system32" in img_dir or "c:/windows/syswow64" in img_dir:
            is_system_path = True
        elif img_dir.startswith("c:/windows") and not "temp" in img_dir:
            is_system_path = True
        elif "program files" in img_dir:
            is_system_path = True
            
        if is_system_path:
            return "NORMAL_SYSTEM_HELPER"
            
        return "UNKNOWN_USER_BINARY"

    @classmethod
    def get_parent_child_anomaly(cls, parent_role: str, child_role: str, parent_image: str, child_image: str, child_command_line: str = "") -> float:
        if parent_role == "SYSTEM_LOGON" and child_role == "SYSTEM_LOGON":
            return 0.0
            
        if parent_role == "SYSTEM_SHELL" and child_role == "SYSADMIN_TOOL":
            return 1.0
            
        if parent_role == "SYSTEM_SHELL" and child_role == "UNKNOWN_USER_BINARY":
            return 1.0
            
        p_name = Path(parent_image).name.lower() if parent_image else ""
        if p_name == "wmiprvse.exe" and child_role == "SYSTEM_SHELL":
            return 1.0
            
        SUSPICIOUS_PARENTS = {
            "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
            "msaccess.exe", "acrord32.exe"
        }
        if p_name in SUSPICIOUS_PARENTS and child_role == "SYSTEM_SHELL":
            return 1.0
            
        if p_name == "services.exe" and child_role == "SYSTEM_SHELL":
            return 1.0
            
        # SYSADMIN_TOOL -> SYSADMIN_TOOL with sensitive arguments
        if parent_role == "SYSADMIN_TOOL" and child_role == "SYSADMIN_TOOL":
            if child_command_line:
                cmd_lower = child_command_line.lower()
                sensitive_args = {"/add", "/delete", "/localgroup", "localgroup", "user", "/user", "/domain"}
                if any(arg in cmd_lower for arg in sensitive_args):
                    return 1.0
                    
        return 0.0

    @classmethod
    def get_masquerading_indicator(cls, image_path: str) -> float:
        if not image_path:
            return 0.0
        p = Path(image_path)
        img_name = p.name.lower()
        if img_name in cls.KNOWN_SYSTEM_EXECUTABLES:
            img_dir = str(p.parent).lower().replace("\\", "/")
            valid_dirs = [
                "c:/windows/system32",
                "c:/windows/syswow64",
                "c:/windows/system32/windowspowershell/v1.0"
            ]
            if not any(vd in img_dir for vd in valid_dirs):
                return 1.0
        return 0.0

    @classmethod
    def extract_features(cls, state: ProcessContextState) -> List[float]:
        # 1. log_command_line_length
        cmd_len = len(state.command_line) if state.command_line else 0
        log_cmd_len = math.log1p(cmd_len)
        
        # 2. encoded_command_flag
        enc_flag = 0
        if state.command_line:
            cmd_lower = state.command_line.lower()
            if re.search(r"\s-[eE]([nN][cC]([oO][dD][eE][dD][cC][oO][mM][mM][aA][nN][dD])?)?\s", cmd_lower) or "-encodedcommand" in cmd_lower:
                enc_flag = 1
                
        # 3. scripting_indicator
        script_flag = 0
        img_name = Path(state.image).name.lower() if state.image else ""
        if img_name in cls.SYSTEM_SHELL:
            script_flag = 1
            
        # 4. parent_child_anomaly_v3
        parent_role = cls.get_process_role(state.parent_image)
        child_role = cls.get_process_role(state.image)
        anomaly_v3 = cls.get_parent_child_anomaly(parent_role, child_role, state.parent_image, state.image, state.command_line)
        
        # 5. integrity_level_numeric
        integrity_map = {
            "untrusted": 1,
            "low": 1,
            "medium": 2,
            "high": 3,
            "system": 4
        }
        il_str = state.integrity_level.lower() if state.integrity_level else ""
        il_val = integrity_map.get(il_str, 2)
        
        # 6. network_conn_count
        net_count = len(state.network_destinations)
        
        # 7. masquerading_indicator
        masq_ind = cls.get_masquerading_indicator(state.image)
        
        # 8. process_role_logon
        role_logon = 1.0 if child_role == "SYSTEM_LOGON" else 0.0
        
        # 9. process_role_admin
        role_admin = 1.0 if child_role == "SYSADMIN_TOOL" else 0.0
        
        return [
            float(log_cmd_len),
            float(enc_flag),
            float(script_flag),
            float(anomaly_v3),
            float(il_val),
            float(net_count),
            float(masq_ind),
            float(role_logon),
            float(role_admin)
        ]


class WindowsProcessContextAggregator:
    """Manages active process context states using a bounded in-memory cache."""

    def __init__(self, max_processes: int = 1000, stale_timeout_hours: float = 12.0):
        self.max_processes = max_processes
        self.stale_timeout_seconds = stale_timeout_hours * 3600.0
        self.processes: Dict[str, ProcessContextState] = {}
        self.pid_to_guid: Dict[int, str] = {}
        self.last_cleanup = time.time()

    def process_event(self, ev: dict) -> None:
        """Process a Sysmon event log dictionary to update states."""
        self._periodic_cleanup()

        event_id = ev.get("event_id")
        guid = ev.get("process_guid")
        pid = ev.get("pid")

        if not guid:
            if pid and pid in self.pid_to_guid:
                guid = self.pid_to_guid[pid]
            else:
                return

        if pid:
            self.pid_to_guid[pid] = guid

        if event_id == 1:
            state = ProcessContextState(
                guid=guid,
                pid=pid,
                image=ev.get("image", ""),
                user=ev.get("user", ""),
                parent_guid=ev.get("parent_process_guid", ""),
                parent_pid=ev.get("parent_pid", 0),
                parent_image=ev.get("parent_image", ""),
                parent_command_line=ev.get("parent_command_line", ""),
                command_line=ev.get("command_line", ""),
                integrity_level=ev.get("integrity_level", "")
            )
            if len(self.processes) >= self.max_processes:
                self._evict_lru()

            self.processes[guid] = state

        elif event_id == 3:
            state = self.processes.get(guid)
            if state:
                state.last_active_at = time.time()
                dest_ip = ev.get("destination_ip", "")
                dest_port = ev.get("destination_port", 0)
                if dest_ip:
                    state.network_destinations.add(f"{dest_ip}:{dest_port}")

        elif event_id == 5:
            state = self.processes.get(guid)
            if state:
                state.terminated = True
                if pid in self.pid_to_guid and self.pid_to_guid[pid] == guid:
                    self.pid_to_guid.pop(pid, None)

    def get_features(self, guid: str) -> Optional[List[float]]:
        """Extract the numeric feature vector for a given process guid."""
        state = self.processes.get(guid)
        if not state:
            return None
        return WindowsAdvancedV2FeatureExtractor.extract_features(state)

    def get_features_v3(self, guid: str) -> Optional[List[float]]:
        """Extract the 9-dimensional V3 numeric feature vector for a given process guid."""
        state = self.processes.get(guid)
        if not state:
            return None
        return WindowsAdvancedV3FeatureExtractor.extract_features(state)

    def get_features_v3_candidate(self, guid: str) -> Optional[List[float]]:
        """Extract the 9-dimensional V3 candidate numeric feature vector for a given process guid."""
        state = self.processes.get(guid)
        if not state:
            return None
        return WindowsAdvancedV3CandidateFeatureExtractor.extract_features(state)

    def _evict_lru(self) -> None:
        if not self.processes:
            return
        oldest_guid = min(self.processes.keys(), key=lambda g: self.processes[g].created_at)
        self.processes.pop(oldest_guid)

    def _periodic_cleanup(self) -> None:
        now = time.time()
        if now - self.last_cleanup < 300.0:
            return
        self.last_cleanup = now

        stale_guids = []
        for guid, state in self.processes.items():
            if state.terminated or (now - state.last_active_at > self.stale_timeout_seconds):
                stale_guids.append(guid)

        for guid in stale_guids:
            state = self.processes.pop(guid, None)
            if state and state.pid in self.pid_to_guid and self.pid_to_guid[state.pid] == guid:
                self.pid_to_guid.pop(state.pid, None)
