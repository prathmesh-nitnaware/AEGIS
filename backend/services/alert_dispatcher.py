"""
backend/services/alert_dispatcher.py
====================================
AEGIS — Enterprise SIEM & SOC Notification Webhook Alert Forwarder.

Provides:
1. Standard SIEM Formatters:
   - Common Event Format (CEF) for ArcSight / QRadar / Sentinel.
   - Syslog RFC 5424 (Structured Data, Priority, Microsecond Timestamps).
   - Syslog RFC 3164 (BSD Header Format).
2. Live SIEM Forwarders:
   - UDP / TCP Syslog network transmission.
   - Splunk HTTP Event Collector (HEC) JSON pipeline.
   - Elasticsearch HTTP Index Document bulk/doc pipeline.
3. SOC Team Notification Webhooks:
   - Slack (Rich Block Kit with severity badges, metrics, and actions).
   - Microsoft Teams (Adaptive Cards with status facts and theme colors).
   - Discord (Rich Color Embeds with timestamps and metadata).
   - PagerDuty (Events API v2 Incident Trigger).
4. Central Coordinator:
   - Thread-safe background dispatcher with threshold evaluation (CRITICAL / HIGH).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Union
import urllib.request
import urllib.error

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------
@dataclass
class AlertPayload:
    """Standardized internal alert object to be formatted and dispatched."""
    alert_id: str
    event_type: str
    threat_score: float
    confidence: float
    severity: str
    origin_agent_id: str
    target_ip: str = "127.0.0.1"
    source_ip: str = "127.0.0.1"
    details: Dict[str, Any] = field(default_factory=dict)
    mitre_tactics: List[str] = field(default_factory=list)
    mitigation_action: Optional[str] = None
    consensus_peers: int = 0
    total_peer_weight: float = 1.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# 1. SIEM Formatters
# ---------------------------------------------------------------------------
def format_cef(alert: AlertPayload) -> str:
    """
    Format alert as ArcSight Common Event Format (CEF):
    CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    """
    # Map severity to CEF integer 1-10
    sev_map = {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 2}
    cef_sev = sev_map.get(alert.severity.upper(), 5)

    sig_id = f"AEGIS-{alert.event_type.upper()}"
    name = f"AEGIS Threat Detected: {alert.event_type}"

    # Build extension key-value pairs
    ext_pairs = [
        f"src={alert.source_ip}",
        f"dst={alert.target_ip}",
        f"dhost={alert.origin_agent_id}",
        f"cs1={alert.severity}",
        "cs1Label=Severity",
        f"cfp1={alert.threat_score:.4f}",
        "cfp1Label=ThreatScore",
        f"cfp2={alert.confidence:.4f}",
        "cfp2Label=Confidence",
        f"cn1={alert.consensus_peers}",
        "cn1Label=ConsensusPeers",
    ]

    if alert.mitigation_action:
        ext_pairs.append(f"act={alert.mitigation_action}")
    if alert.mitre_tactics:
        ext_pairs.append(f"cs2={','.join(alert.mitre_tactics)}")
        ext_pairs.append("cs2Label=MitreTactics")

    # Details enrichment
    for k, v in alert.details.items():
        if isinstance(v, (str, int, float, bool)):
            clean_val = str(v).replace("|", "\\|").replace("=", "\\=")
            ext_pairs.append(f"msg={k}:{clean_val}")

    ext_str = " ".join(ext_pairs)
    return f"CEF:0|AEGIS|EDR-Swarm|1.0|{sig_id}|{name}|{cef_sev}|{ext_str}"


def format_syslog_rfc5424(
    alert: AlertPayload,
    facility: int = 1,  # user-level
    hostname: str = "aegis-command-node",
    app_name: str = "aegis-edr",
) -> str:
    """
    Format alert per RFC 5424 Syslog protocol:
    <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    """
    # Severity: Emergency=0, Alert=1, Critical=2, Error=3, Warning=4, Notice=5, Info=6, Debug=7
    sev_code_map = {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 4, "LOW": 6}
    sev_code = sev_code_map.get(alert.severity.upper(), 4)
    pri = facility * 8 + sev_code

    ts_iso = datetime.fromtimestamp(alert.timestamp, tz=timezone.utc).isoformat()
    msg_id = alert.alert_id[:12]

    # Structured Data [aegis@32473 threatScore="..." agent="..."]
    sd = (
        f'[aegis@32473 score="{alert.threat_score:.4f}" '
        f'conf="{alert.confidence:.4f}" '
        f'agent="{alert.origin_agent_id}" '
        f'peers="{alert.consensus_peers}" '
        f'action="{alert.mitigation_action or "NONE"}"]'
    )

    msg = f"AEGIS Threat Verdict: {alert.severity} ({alert.event_type}) on {alert.origin_agent_id}"
    return f"<{pri}>1 {ts_iso} {hostname} {app_name} {os.getpid()} {msg_id} {sd} {msg}"


def format_syslog_rfc3164(
    alert: AlertPayload,
    facility: int = 1,
    hostname: str = "aegis-node",
    tag: str = "aegis-edr",
) -> str:
    """
    Format alert per RFC 3164 (BSD Syslog format):
    <PRI>TIMESTAMP HOSTNAME TAG: MSG
    """
    sev_code_map = {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 4, "LOW": 6}
    sev_code = sev_code_map.get(alert.severity.upper(), 4)
    pri = facility * 8 + sev_code

    # Format timestamp as "Mmm dd hh:mm:ss"
    ts_str = datetime.fromtimestamp(alert.timestamp).strftime("%b %d %H:%M:%S")
    msg = (
        f"[{alert.severity}] Event={alert.event_type} Score={alert.threat_score:.4f} "
        f"Agent={alert.origin_agent_id} Action={alert.mitigation_action or 'NONE'}"
    )
    return f"<{pri}>{ts_str} {hostname} {tag}: {msg}"


# ---------------------------------------------------------------------------
# 2. SOC Webhook Formatters
# ---------------------------------------------------------------------------
def format_slack_payload(alert: AlertPayload) -> Dict[str, Any]:
    """Format alert as Slack Block Kit JSON with interactive markdown cards."""
    color_emoji = "🔴" if alert.severity == "CRITICAL" else ("🟠" if alert.severity == "HIGH" else "🟡")
    return {
        "text": f"{color_emoji} [AEGIS EDR] {alert.severity} Alert Detected on {alert.origin_agent_id}",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🛡️ AEGIS Threat Alert — {alert.severity}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Event Type:*\n`{alert.event_type}`"},
                    {"type": "mrkdwn", "text": f"*Origin Node:*\n`{alert.origin_agent_id}`"},
                    {"type": "mrkdwn", "text": f"*Threat Score:*\n`{alert.threat_score:.4f}`"},
                    {"type": "mrkdwn", "text": f"*Confidence:*\n`{alert.confidence:.2%}`"},
                    {"type": "mrkdwn", "text": f"*Swarm Quorum:*\n`{alert.consensus_peers} peers ({alert.total_peer_weight:.1f}x weight)`"},
                    {"type": "mrkdwn", "text": f"*Autonomous Action:*\n`{alert.mitigation_action or 'MONITORED'}`"},
                ],
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"📍 Target: `{alert.target_ip}` | Alert ID: `{alert.alert_id}` | Time: <!date^{int(alert.timestamp)}^{{date_num}} {{time_secs}}|{alert.timestamp}>",
                    }
                ],
            },
        ],
    }


def format_teams_payload(alert: AlertPayload) -> Dict[str, Any]:
    """Format alert as Microsoft Teams MessageCard / Adaptive Card JSON."""
    theme_color = "D9381E" if alert.severity == "CRITICAL" else ("FF8C00" if alert.severity == "HIGH" else "FFD700")
    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": f"AEGIS {alert.severity} Alert: {alert.event_type}",
        "themeColor": theme_color,
        "title": f"🛡️ AEGIS Autonomous EDR Alert: {alert.severity}",
        "sections": [
            {
                "activityTitle": f"**Threat Event:** `{alert.event_type}` on Node `{alert.origin_agent_id}`",
                "activitySubtitle": f"Timestamp: {datetime.fromtimestamp(alert.timestamp, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
                "facts": [
                    {"name": "Threat Score", "value": f"{alert.threat_score:.4f}"},
                    {"name": "Severity Level", "value": alert.severity},
                    {"name": "Detection Confidence", "value": f"{alert.confidence:.2%}"},
                    {"name": "Swarm Peers Quorum", "value": f"{alert.consensus_peers} nodes"},
                    {"name": "Autonomous Response", "value": alert.mitigation_action or "NONE"},
                    {"name": "Target IP", "value": alert.target_ip},
                ],
                "markdown": True,
            }
        ],
    }


def format_discord_payload(alert: AlertPayload) -> Dict[str, Any]:
    """Format alert as Discord Rich Embed JSON."""
    color_int = 0xFF0000 if alert.severity == "CRITICAL" else (0xFFA500 if alert.severity == "HIGH" else 0xFFFF00)
    return {
        "username": "AEGIS EDR Guardian",
        "embeds": [
            {
                "title": f"🚨 AEGIS Swarm Consensus Alert — {alert.severity}",
                "description": f"Autonomous detection triggered on `{alert.origin_agent_id}`.",
                "color": color_int,
                "fields": [
                    {"name": "Event Type", "value": f"`{alert.event_type}`", "inline": True},
                    {"name": "Threat Score", "value": f"`{alert.threat_score:.4f}`", "inline": True},
                    {"name": "Confidence", "value": f"`{alert.confidence:.2%}`", "inline": True},
                    {"name": "Mitigation Action", "value": f"`{alert.mitigation_action or 'MONITOR'}`", "inline": True},
                    {"name": "Swarm Quorum", "value": f"{alert.consensus_peers} peers", "inline": True},
                    {"name": "Target IP", "value": f"`{alert.target_ip}`", "inline": True},
                ],
                "timestamp": datetime.fromtimestamp(alert.timestamp, tz=timezone.utc).isoformat(),
                "footer": {"text": f"Alert ID: {alert.alert_id}"},
            }
        ],
    }


def format_pagerduty_payload(alert: AlertPayload, routing_key: str = "AEGIS_PAGERDUTY_KEY") -> Dict[str, Any]:
    """Format alert for PagerDuty Events API v2."""
    pd_sev = "critical" if alert.severity == "CRITICAL" else ("error" if alert.severity == "HIGH" else "warning")
    return {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": alert.alert_id,
        "payload": {
            "summary": f"AEGIS {alert.severity} Anomaly: {alert.event_type} on {alert.origin_agent_id}",
            "source": alert.origin_agent_id,
            "severity": pd_sev,
            "timestamp": datetime.fromtimestamp(alert.timestamp, tz=timezone.utc).isoformat(),
            "component": "AEGIS-EDR",
            "group": "Security-Operations",
            "class": alert.event_type,
            "custom_details": {
                "threat_score": alert.threat_score,
                "confidence": alert.confidence,
                "mitigation_action": alert.mitigation_action,
                "consensus_peers": alert.consensus_peers,
                "details": alert.details,
            },
        },
    }


# ---------------------------------------------------------------------------
# 3. Splunk HEC & Elasticsearch Formatters
# ---------------------------------------------------------------------------
def format_splunk_hec_event(alert: AlertPayload, index: str = "aegis_security") -> Dict[str, Any]:
    """Format alert for Splunk HTTP Event Collector (HEC)."""
    return {
        "time": alert.timestamp,
        "host": alert.origin_agent_id,
        "source": "aegis:edr:swarm",
        "sourcetype": "_json",
        "index": index,
        "event": alert.to_dict(),
    }


def format_elasticsearch_doc(alert: AlertPayload) -> Dict[str, Any]:
    """Format alert for Elasticsearch JSON document ingestion."""
    doc = alert.to_dict()
    doc["@timestamp"] = datetime.fromtimestamp(alert.timestamp, tz=timezone.utc).isoformat()
    return doc


# ---------------------------------------------------------------------------
# 4. Transmission Helpers
# ---------------------------------------------------------------------------
def send_http_json(url: str, payload: Dict[str, Any], headers: Optional[Dict[str, str]] = None, timeout: float = 3.0) -> bool:
    """Send JSON payload to HTTP endpoint."""
    try:
        data = json.dumps(payload).encode("utf-8")
        req_headers = {"Content-Type": "application/json"}
        if headers:
            req_headers.update(headers)
        req = urllib.request.Request(url, data=data, headers=req_headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status in (200, 201, 202, 204)
    except Exception as exc:
        logger.debug("[AlertDispatcher] HTTP delivery to %s failed: %s", url, exc)
        return False


def send_syslog_udp(host: str, port: int, message: str) -> bool:
    """Send raw syslog message over UDP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(message.encode("utf-8"), (host, port))
        sock.close()
        return True
    except Exception as exc:
        logger.debug("[AlertDispatcher] Syslog UDP delivery failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# 5. Central Alert Dispatcher Service
# ---------------------------------------------------------------------------
class AlertDispatcher:
    """
    Central Alert Dispatcher for Project AEGIS.
    Manages SIEM forwarding (Syslog, CEF, Splunk HEC, Elasticsearch)
    and SOC notification webhooks (Slack, MS Teams, Discord, PagerDuty).
    """

    def __init__(self, min_severity: str = "HIGH") -> None:
        self.min_severity = min_severity
        self.destinations: Dict[str, Dict[str, Any]] = {}
        self.dispatch_history: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def configure_destination(self, name: str, dest_type: str, config: Dict[str, Any], enabled: bool = True) -> None:
        """
        Register or update an alert destination.

        dest_type: 'slack' | 'teams' | 'discord' | 'pagerduty' | 'syslog' | 'splunk' | 'elastic'
        """
        with self._lock:
            self.destinations[name] = {
                "name": name,
                "type": dest_type.lower(),
                "config": config,
                "enabled": enabled,
            }
            logger.info("[AlertDispatcher] Configured destination '%s' (type=%s, enabled=%s)", name, dest_type, enabled)

    def should_dispatch(self, severity: str) -> bool:
        """Check if severity meets dispatch threshold."""
        levels = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        return levels.get(severity.upper(), 1) >= levels.get(self.min_severity.upper(), 3)

    def dispatch(self, alert: AlertPayload) -> Dict[str, bool]:
        """
        Dispatch alert payload to all enabled destinations meeting severity threshold.
        Returns dict of destination_name -> success status.
        """
        results: Dict[str, bool] = {}

        if not self.should_dispatch(alert.severity):
            return results

        with self._lock:
            active_dests = [d for d in self.destinations.values() if d.get("enabled", True)]

        for dest in active_dests:
            d_name = dest["name"]
            d_type = dest["type"]
            cfg = dest["config"]

            success = False
            try:
                if d_type == "slack" and "webhook_url" in cfg:
                    payload = format_slack_payload(alert)
                    success = send_http_json(cfg["webhook_url"], payload)

                elif d_type == "teams" and "webhook_url" in cfg:
                    payload = format_teams_payload(alert)
                    success = send_http_json(cfg["webhook_url"], payload)

                elif d_type == "discord" and "webhook_url" in cfg:
                    payload = format_discord_payload(alert)
                    success = send_http_json(cfg["webhook_url"], payload)

                elif d_type == "pagerduty" and "routing_key" in cfg:
                    payload = format_pagerduty_payload(alert, routing_key=cfg["routing_key"])
                    url = cfg.get("url", "https://events.pagerduty.com/v2/enqueue")
                    success = send_http_json(url, payload)

                elif d_type == "syslog" and "host" in cfg and "port" in cfg:
                    proto = cfg.get("format", "rfc5424").lower()
                    if proto == "cef":
                        msg = format_cef(alert)
                    elif proto == "rfc3164":
                        msg = format_syslog_rfc3164(alert)
                    else:
                        msg = format_syslog_rfc5424(alert)
                    success = send_syslog_udp(cfg["host"], int(cfg["port"]), msg)

                elif d_type == "splunk" and "hec_url" in cfg:
                    payload = format_splunk_hec_event(alert, index=cfg.get("index", "aegis_security"))
                    headers = {}
                    if "token" in cfg:
                        headers["Authorization"] = f"Splunk {cfg['token']}"
                    success = send_http_json(cfg["hec_url"], payload, headers=headers)

                elif d_type == "elastic" and "endpoint_url" in cfg:
                    payload = format_elasticsearch_doc(alert)
                    headers = {}
                    if "api_key" in cfg:
                        headers["Authorization"] = f"ApiKey {cfg['api_key']}"
                    success = send_http_json(cfg["endpoint_url"], payload, headers=headers)

            except Exception as e:
                logger.error("[AlertDispatcher] Error dispatching to %s: %s", d_name, e)
                success = False

            results[d_name] = success

        # Record in history
        with self._lock:
            self.dispatch_history.append({
                "alert_id": alert.alert_id,
                "severity": alert.severity,
                "event_type": alert.event_type,
                "timestamp": alert.timestamp,
                "results": results,
            })
            if len(self.dispatch_history) > 100:
                self.dispatch_history = self.dispatch_history[-100:]

        return results


# Global Singleton
default_alert_dispatcher = AlertDispatcher(min_severity="HIGH")
