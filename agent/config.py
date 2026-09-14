"""
agent/config.py
===============
AEGIS Cross-Platform Agent Configuration Manager.
Loads settings from environment variables, configuration files, and command-line arguments.
Standard config paths:
  - Linux:   /etc/aegis/agent.conf or ~/.config/aegis/agent.conf
  - Windows: C:\\ProgramData\\AEGIS\\agent.conf or %APPDATA%\\AEGIS\\agent.conf
"""

from __future__ import annotations

import json
import os
import platform
import socket
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


def get_default_config_path() -> Path:
    """Returns the platform-specific default configuration file path."""
    system = platform.system().lower()
    if system == "windows":
        program_data = os.environ.get("ProgramData", r"C:\ProgramData")
        return Path(program_data) / "AEGIS" / "agent.conf"
    else:
        # Linux / Unix
        return Path("/etc/aegis/agent.conf")


def get_default_quarantine_dir() -> Path:
    """Returns the platform-specific default quarantine vault directory."""
    system = platform.system().lower()
    if system == "windows":
        program_data = os.environ.get("ProgramData", r"C:\ProgramData")
        return Path(program_data) / "AEGIS" / "Quarantine"
    else:
        return Path("/var/lib/aegis/quarantine")


def get_default_log_dir() -> Path:
    """Returns the platform-specific default log directory."""
    system = platform.system().lower()
    if system == "windows":
        program_data = os.environ.get("ProgramData", r"C:\ProgramData")
        return Path(program_data) / "AEGIS" / "Logs"
    else:
        return Path("/var/log/aegis")


@dataclass
class AegisAgentConfig:
    """Core configuration for an AEGIS EDR Agent daemon."""

    # Node Identity & Central Server
    agent_id: str = field(default_factory=lambda: os.environ.get("AGENT_ID", socket.gethostname()))
    command_node_url: str = field(default_factory=lambda: os.environ.get("COMMAND_NODE_URL", "http://127.0.0.1:8000"))
    
    # Heartbeat & Silence-as-Alarm Thresholds
    heartbeat_interval: float = field(default_factory=lambda: float(os.environ.get("HEARTBEAT_INTERVAL", "5.0")))
    silence_threshold: float = field(default_factory=lambda: float(os.environ.get("SILENCE_THRESHOLD", "15.0")))

    # P2P Wire Mesh Consensus (Layer 2)
    p2p_enabled: bool = field(default_factory=lambda: os.environ.get("P2P_ENABLED", "true").lower() in ("true", "1", "yes"))
    p2p_bind_port: int = field(default_factory=lambda: int(os.environ.get("P2P_BIND_PORT", "9001")))
    p2p_peers: List[str] = field(default_factory=lambda: [p.strip() for p in os.environ.get("P2P_PEERS", "").split(",") if p.strip()])

    # Telemetry Collectors Configuration
    pe_watch_dir: str = field(default_factory=lambda: os.environ.get("PE_WATCH_DIR", str(Path.home() / "Downloads")))
    hdfs_log_path: str = field(default_factory=lambda: os.environ.get("HDFS_LOG_PATH", ""))
    scapy_interface: Optional[str] = field(default_factory=lambda: os.environ.get("SCAPY_INTERFACE", None))
    
    # Active Mitigation & Response Driver
    enable_active_response: bool = field(default_factory=lambda: os.environ.get("ENABLE_ACTIVE_RESPONSE", "true").lower() in ("true", "1", "yes"))
    quarantine_dir: str = field(default_factory=lambda: os.environ.get("QUARANTINE_DIR", str(get_default_quarantine_dir())))
    log_dir: str = field(default_factory=lambda: os.environ.get("LOG_DIR", str(get_default_log_dir())))

    # Model Weights & Thresholds
    threat_threshold_critical: float = 0.85
    threat_threshold_high: float = 0.65
    threat_threshold_medium: float = 0.40

    @classmethod
    def load(cls, config_path: Optional[str | Path] = None) -> AegisAgentConfig:
        """Loads configuration merging defaults, file settings, and environment overrides."""
        cfg = cls()

        target_path = Path(config_path) if config_path else get_default_config_path()

        # Try loading from JSON/CONF file if present
        if target_path.exists():
            try:
                with open(target_path, "r", encoding="utf-8") as f:
                    file_data = json.load(f)
                    for k, v in file_data.items():
                        if hasattr(cfg, k):
                            setattr(cfg, k, v)
            except Exception as exc:
                print(f"[AEGIS Config] Warning: Could not parse config file at {target_path}: {exc}")

        # Ensure directories exist if we have permissions
        try:
            Path(cfg.quarantine_dir).mkdir(parents=True, exist_ok=True)
            Path(cfg.log_dir).mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        return cfg

    def save(self, config_path: Optional[str | Path] = None) -> Path:
        """Saves current configuration to disk."""
        target_path = Path(config_path) if config_path else get_default_config_path()
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(asdict(self), f, indent=2)
        return target_path
