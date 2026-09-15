"""
tests/test_alert_dispatcher.py
==============================
Test suite for AEGIS Enterprise SIEM & SOC Webhook Alert Dispatcher.
Verifies CEF, Syslog RFC 5424, Syslog RFC 3164, Slack, Teams, Discord,
PagerDuty, Splunk HEC, and Elasticsearch formatting and dispatching.
"""

import time
import pytest
from unittest.mock import MagicMock, patch

from backend.services.alert_dispatcher import (
    AlertDispatcher,
    AlertPayload,
    format_cef,
    format_discord_payload,
    format_elasticsearch_doc,
    format_pagerduty_payload,
    format_slack_payload,
    format_teams_payload,
    format_splunk_hec_event,
    format_syslog_rfc3164,
    format_syslog_rfc5424,
)


@pytest.fixture
def sample_critical_alert():
    return AlertPayload(
        alert_id="ALERT-CRIT-001",
        event_type="ransomware_dropper",
        threat_score=0.9850,
        confidence=0.9900,
        severity="CRITICAL",
        origin_agent_id="vm1-linux",
        target_ip="172.30.0.21",
        source_ip="192.168.1.100",
        details={"process": "vssadmin.exe", "pid": 4012, "cmd": "delete shadows /all"},
        mitre_tactics=["Impact (TA0040)", "Inhibit System Recovery (T1490)"],
        mitigation_action="KILL_PROCESS_AND_ISOLATE",
        consensus_peers=4,
        total_peer_weight=3.8,
        timestamp=1700000000.0,
    )


def test_format_cef(sample_critical_alert):
    """Verify ArcSight Common Event Format (CEF) string generation."""
    cef_str = format_cef(sample_critical_alert)
    assert cef_str.startswith("CEF:0|AEGIS|EDR-Swarm|1.0|AEGIS-RANSOMWARE_DROPPER|")
    assert "|10|" in cef_str  # CRITICAL maps to severity 10
    assert "src=192.168.1.100" in cef_str
    assert "dst=172.30.0.21" in cef_str
    assert "dhost=vm1-linux" in cef_str
    assert "act=KILL_PROCESS_AND_ISOLATE" in cef_str
    assert "cfp1=0.9850" in cef_str
    assert "cn1=4" in cef_str


def test_format_syslog_rfc5424(sample_critical_alert):
    """Verify RFC 5424 structured syslog string generation."""
    syslog_str = format_syslog_rfc5424(sample_critical_alert, hostname="aegis-command", app_name="aegis-edr")
    assert "<10>1 " in syslog_str  # facility 1 (user) * 8 + sev 2 (critical) = 10
    assert "aegis-command aegis-edr" in syslog_str
    assert '[aegis@32473 score="0.9850"' in syslog_str
    assert 'action="KILL_PROCESS_AND_ISOLATE"' in syslog_str
    assert "AEGIS Threat Verdict: CRITICAL (ransomware_dropper) on vm1-linux" in syslog_str


def test_format_syslog_rfc3164(sample_critical_alert):
    """Verify BSD RFC 3164 classic syslog string generation."""
    syslog_str = format_syslog_rfc3164(sample_critical_alert, hostname="aegis-node")
    assert "<10>" in syslog_str
    assert "aegis-node aegis-edr:" in syslog_str
    assert "[CRITICAL] Event=ransomware_dropper Score=0.9850" in syslog_str


def test_format_slack_block_kit(sample_critical_alert):
    """Verify Slack Block Kit JSON structure and fields."""
    slack_data = format_slack_payload(sample_critical_alert)
    assert "blocks" in slack_data
    assert any("CRITICAL" in b.get("text", {}).get("text", "") for b in slack_data["blocks"] if b["type"] == "header")
    # Check fields
    section = [b for b in slack_data["blocks"] if b["type"] == "section"][0]
    field_texts = [f["text"] for f in section["fields"]]
    assert any("ransomware_dropper" in t for t in field_texts)
    assert any("0.9850" in t for t in field_texts)
    assert any("KILL_PROCESS_AND_ISOLATE" in t for t in field_texts)


def test_format_teams_message_card(sample_critical_alert):
    """Verify Microsoft Teams Adaptive Card / MessageCard structure."""
    teams_data = format_teams_payload(sample_critical_alert)
    assert teams_data["@type"] == "MessageCard"
    assert teams_data["themeColor"] == "D9381E"  # CRITICAL red
    facts = teams_data["sections"][0]["facts"]
    fact_dict = {f["name"]: f["value"] for f in facts}
    assert fact_dict["Threat Score"] == "0.9850"
    assert fact_dict["Severity Level"] == "CRITICAL"
    assert fact_dict["Autonomous Response"] == "KILL_PROCESS_AND_ISOLATE"


def test_format_discord_embed(sample_critical_alert):
    """Verify Discord Embed payload structure and color code."""
    discord_data = format_discord_payload(sample_critical_alert)
    assert len(discord_data["embeds"]) == 1
    embed = discord_data["embeds"][0]
    assert embed["color"] == 0xFF0000  # Red
    assert "CRITICAL" in embed["title"]
    field_dict = {f["name"]: f["value"] for f in embed["fields"]}
    assert field_dict["Threat Score"] == "`0.9850`"
    assert field_dict["Event Type"] == "`ransomware_dropper`"


def test_format_pagerduty(sample_critical_alert):
    """Verify PagerDuty Events API v2 payload structure."""
    pd_data = format_pagerduty_payload(sample_critical_alert, routing_key="TEST_KEY")
    assert pd_data["routing_key"] == "TEST_KEY"
    assert pd_data["event_action"] == "trigger"
    assert pd_data["payload"]["severity"] == "critical"
    assert pd_data["payload"]["source"] == "vm1-linux"
    assert pd_data["payload"]["custom_details"]["threat_score"] == 0.9850


def test_format_splunk_hec(sample_critical_alert):
    """Verify Splunk HEC event wrapper formatting."""
    splunk_data = format_splunk_hec_event(sample_critical_alert, index="aegis_sec")
    assert splunk_data["source"] == "aegis:edr:swarm"
    assert splunk_data["index"] == "aegis_sec"
    assert splunk_data["event"]["alert_id"] == "ALERT-CRIT-001"
    assert splunk_data["event"]["threat_score"] == 0.9850


def test_format_elasticsearch_doc(sample_critical_alert):
    """Verify Elasticsearch document dictionary formatting."""
    es_doc = format_elasticsearch_doc(sample_critical_alert)
    assert "@timestamp" in es_doc
    assert es_doc["alert_id"] == "ALERT-CRIT-001"
    assert es_doc["severity"] == "CRITICAL"


def test_alert_dispatcher_threshold_and_dispatch(sample_critical_alert):
    """Verify AlertDispatcher destination registration, severity filtering, and dispatch logic."""
    dispatcher = AlertDispatcher(min_severity="HIGH")

    # Configure multiple mock destinations
    dispatcher.configure_destination("soc_slack", "slack", {"webhook_url": "https://hooks.slack.com/test"})
    dispatcher.configure_destination("siem_syslog", "syslog", {"host": "127.0.0.1", "port": 514, "format": "cef"})
    dispatcher.configure_destination("splunk_hec", "splunk", {"hec_url": "https://splunk:8088/event", "token": "abc"})

    assert len(dispatcher.destinations) == 3

    # Test threshold: LOW alert should not be dispatched
    low_alert = AlertPayload(
        alert_id="ALERT-LOW-001",
        event_type="port_scan_recon",
        threat_score=0.25,
        confidence=0.80,
        severity="LOW",
        origin_agent_id="vm1-linux",
    )
    low_res = dispatcher.dispatch(low_alert)
    assert len(low_res) == 0

    # Test critical alert dispatch with mocked delivery helpers
    with patch("backend.services.alert_dispatcher.send_http_json", return_value=True) as mock_http, \
         patch("backend.services.alert_dispatcher.send_syslog_udp", return_value=True) as mock_syslog:
        
        results = dispatcher.dispatch(sample_critical_alert)
        assert results["soc_slack"] is True
        assert results["siem_syslog"] is True
        assert results["splunk_hec"] is True
        assert mock_http.call_count >= 2
        assert mock_syslog.call_count == 1
        assert len(dispatcher.dispatch_history) >= 1
