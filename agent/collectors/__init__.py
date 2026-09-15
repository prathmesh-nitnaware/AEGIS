"""
agent/collectors
================
Kernel-Level Real-Time Telemetry Collectors (eBPF & ETW) for AEGIS Autonomous EDR.
"""

from agent.collectors.ebpf_collector import EBPFTelemetryCollector
from agent.collectors.etw_collector import ETWTelemetryCollector

__all__ = ["EBPFTelemetryCollector", "ETWTelemetryCollector"]
