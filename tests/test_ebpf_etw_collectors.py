"""
tests/test_ebpf_etw_collectors.py
=================================
Unit and integration tests for AEGIS Kernel-Level Telemetry Collectors:
- Linux eBPF C program source inspection & probe syntax verification
- EBPFTelemetryCollector lifecycle, callbacks, and fallback emulation
- ETWTelemetryCollector event parser, Event ID 1 (Process), ID 3 (Network), ID 6 (Driver)
"""

import time
import pytest
from pathlib import Path

from agent.collectors.ebpf_collector import EBPFTelemetryCollector
from agent.collectors.etw_collector import ETWTelemetryCollector


def test_ebpf_c_source_validity():
    """Verify that the eBPF C source file exists and contains essential tracepoint probes."""
    c_path = Path("agent/collectors/ebpf_tracer.c").resolve()
    assert c_path.exists(), "ebpf_tracer.c must exist in agent/collectors/"

    content = c_path.read_text(encoding="utf-8")
    assert "sys_enter_execve" in content
    assert "sys_enter_connect" in content
    assert "sys_enter_openat" in content
    assert "sys_enter_kill" in content
    assert "sys_enter_ptrace" in content
    assert "BPF_PERF_OUTPUT" in content


def test_ebpf_collector_lifecycle_and_callback():
    """Test eBPF telemetry collector startup, callback reception, and graceful shutdown."""
    received_events = []

    def handle_event(event):
        received_events.append(event)

    collector = EBPFTelemetryCollector(callback=handle_event, force_emulation=True)
    collector.start()

    time.sleep(1.5)
    status = collector.get_status()
    assert status["is_running"] is True
    assert collector.events_collected > 0
    assert len(received_events) > 0

    evt = received_events[0]
    assert "pid" in evt
    assert "event_type" in evt
    assert evt["event_type"] in ("EXECVE", "CONNECT", "OPENAT", "KILL", "PTRACE")

    collector.stop()
    assert collector.get_status()["is_running"] is False


def test_etw_collector_event_normalization():
    """Test Windows ETW collector event parsing for Process (1), Network (3), and Driver (6)."""
    collector = ETWTelemetryCollector()

    # 1. Event ID 1 - Process Creation
    p_props = {
        "ProcessId": 1234,
        "ParentProcessId": 5678,
        "CommandLine": "powershell.exe -ExecutionPolicy Bypass",
        "User": "NT AUTHORITY\\SYSTEM",
    }
    p_evt = collector.parse_etw_event(1, "Microsoft-Windows-Kernel-Process", p_props)
    assert p_evt["event_type"] == "PROCESS_CREATE"
    assert p_evt["pid"] == 1234
    assert p_evt["parent_pid"] == 5678
    assert "powershell" in p_evt["command_line"]

    # 2. Event ID 3 - Network Connection
    n_props = {
        "ProcessId": 1234,
        "DestinationIp": "192.168.1.100",
        "DestinationPort": 443,
    }
    n_evt = collector.parse_etw_event(3, "Microsoft-Windows-Kernel-Network", n_props)
    assert n_evt["event_type"] == "NETWORK_CONNECT"
    assert n_evt["dest_ip"] == "192.168.1.100"
    assert n_evt["dest_port"] == 443

    # 3. Event ID 6 - Driver Load
    d_props = {
        "ImageLoaded": "C:\\Windows\\System32\\drivers\\rootkit.sys",
        "Hashes": {"SHA256": "abcdef1234567890"},
    }
    d_evt = collector.parse_etw_event(6, "Microsoft-Windows-Kernel-Driver", d_props)
    assert d_evt["event_type"] == "DRIVER_LOAD"
    assert "rootkit.sys" in d_evt["driver_path"]


def test_etw_collector_lifecycle_and_callback():
    """Test ETW collector loop execution and stream callback."""
    received = []
    collector = ETWTelemetryCollector(callback=lambda e: received.append(e), force_emulation=True)
    collector.start()

    time.sleep(1.5)
    assert collector.events_collected > 0
    assert len(received) > 0
    assert "event_type" in received[0]

    collector.stop()
    assert collector.get_status()["is_running"] is False
