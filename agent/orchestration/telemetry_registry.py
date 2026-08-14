"""
agent/orchestration/telemetry_registry.py
============================================
Static, declarative table describing which collectors EXIST, which OS(es)
each one is compatible with, and whether it is critical or optional to
AEGIS's core function.

This file is metadata ONLY. It does not import, reference, or wrap any
collector class -- run_all.py still owns the actual start-up code for
each collector (it needs to close over `engine` and `save_event`, which
live in run_all.py). This registry just tells collector_manager.py which
names are allowed to run on which OS.

Extending to a new OS later:
    1. Add the OS's platform.system() string to os_detector.SUPPORTED_OS
    2. Add that OS name to the "platforms" list of any collector entry
       below that should run on it
    3. If the new OS needs its own collector(s), add a new entry here and
       wire a matching start function into run_all.py's start_fns dict --
       no other file needs to change.
"""
from __future__ import annotations

from typing import Dict

COLLECTORS: Dict[str, dict] = {
    "zero_day": {
        "label": "Zero-Day (process events)",
        "platforms": ["Windows", "Linux"],
        "critical": False,
    },
    "cicids": {
        "label": "Network / CICIDS (flow features)",
        "platforms": ["Windows", "Linux"],
        "critical": False,
    },
    "ember": {
        "label": "Files / EMBER (PE scan)",
        "platforms": ["Windows", "Linux"],
        "critical": False,
    },
    "hdfs": {
        "label": "HDFS (log anomaly)",
        "platforms": ["Windows", "Linux"],
        "critical": False,
    },
    "windows_advanced": {
        "label": "Windows Event Logs / Sysmon (API-DLL)",
        "platforms": ["Windows"],
        "critical": False,
    },
    "linux_ids": {
        "label": "Linux Syscalls (bpftrace IDS)",
        "platforms": ["Linux"],
        "critical": False,
    },
}


def collectors_for_platform(os_name: str) -> Dict[str, dict]:
    """Return {name: meta} for every collector compatible with os_name."""
    return {
        name: meta
        for name, meta in COLLECTORS.items()
        if os_name in meta["platforms"]
    }
