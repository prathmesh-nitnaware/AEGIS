"""
tests/test_graceful_shutdown.py
================================
Unit tests verifying graceful shutdown handling and silence alarm suppression.
"""

import time
import pytest
from agent.heartbeat import SilenceDetector


def test_graceful_shutdown_suppresses_silence_alarm():
    alarms = []
    detector = SilenceDetector(
        silence_threshold=0.5,
        check_interval=0.1,
        on_silent_alarm=lambda p: alarms.append(p),
    )

    # 1. Register agent
    detector.record_heartbeat({
        "agent_id": "test-vm",
        "status": "healthy",
        "cpu": 10.0,
        "timestamp": time.time(),
    })

    # 2. Issue graceful shutdown
    detector.record_shutdown("test-vm", reason="OS_SHUTDOWN")

    # 3. Wait past silence threshold
    time.sleep(0.7)
    fired = detector._check_silence()

    assert len(fired) == 0, "Silence alarm must be suppressed for OFFLINE_GRACEFUL agent"
    assert len(alarms) == 0


def test_unannounced_silence_triggers_alarm():
    alarms = []
    detector = SilenceDetector(
        silence_threshold=0.5,
        check_interval=0.1,
        on_silent_alarm=lambda p: alarms.append(p),
    )

    # 1. Register agent
    detector.record_heartbeat({
        "agent_id": "test-victim",
        "status": "healthy",
        "cpu": 10.0,
        "timestamp": time.time(),
    })

    # 2. Wait past silence threshold without graceful shutdown
    time.sleep(0.7)
    fired = detector._check_silence()

    assert len(fired) == 1, "Silence alarm must fire when agent vanishes without shutdown beacon"
    assert fired[0]["agent_id"] == "test-victim"
    assert fired[0]["severity"] == "CRITICAL"


def test_agent_recovery_from_graceful_shutdown():
    detector = SilenceDetector(
        silence_threshold=1.0,
        check_interval=0.1,
    )

    detector.record_shutdown("test-vm", reason="OS_SHUTDOWN")
    assert detector._agents["test-vm"].status == "OFFLINE_GRACEFUL"

    # Next boot heartbeat
    detector.record_heartbeat({
        "agent_id": "test-vm",
        "status": "healthy",
        "cpu": 15.0,
        "timestamp": time.time(),
    })
    assert detector._agents["test-vm"].status == "healthy"
    assert not detector._agents["test-vm"].alarm_raised
