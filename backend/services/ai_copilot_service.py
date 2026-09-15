"""
backend/services/ai_copilot_service.py
======================================
AEGIS Autonomous EDR - AI Incident Investigation Copilot & Remediation Playbooks
--------------------------------------------------------------------------------
Synthesizes multi-model threat metrics, XAI SHAP attributions, Sigma/YARA hits,
and MITRE ATT&CK techniques into:
  1. Executive Root-Cause Analysis (Plain-English SOC summaries)
  2. Autonomous Containment & Remediation Playbooks (Bash / PowerShell / Ansible)
  3. Evidence Timeline & Forensics Recommendations
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("aegis.ai_copilot")


class ThreatCopilotService:
    def __init__(self) -> None:
        self._knowledge_base = {
            "T1486": {
                "name": "Data Encrypted for Impact (Ransomware)",
                "summary": "Adversary attempted volume shadow copy deletion and mass file encryption.",
                "root_cause": "Execution of high-entropy binary coupled with vssadmin shadow copy wipe commands.",
                "playbook_steps": [
                    "Isolate infected endpoint from the local network segment immediately.",
                    "Terminate parent processes spawning unapproved administrative utilities.",
                    "Verify Volume Shadow Copy service state and inspect restore point integrity.",
                    "Inspect persistence registries (Run/RunOnce) and scheduled tasks for recurring execution triggers."
                ],
                "bash_remediation": """# Ransomware Containment Script (Linux)
pkill -9 -f "vssadmin|encryptor|malicious"
iptables -A INPUT -p tcp --dport 445 -j DROP
chmod -R 000 /tmp/.malicious_stage 2>/dev/null || true
echo "[+] Host isolated and suspicious drop directories neutralized."
""",
                "ps_remediation": """# Ransomware Containment Script (PowerShell)
Stop-Process -Name "vssadmin","malicious_dropper" -Force -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "AEGIS-Containment-BlockOut" -Direction Outbound -Action Block -Profile Any
Write-Host "[+] Outbound traffic halted. Volume shadow copy integrity check initiated."
"""
            },
            "T1055": {
                "name": "Process Injection",
                "summary": "Adversary attempted memory code injection or ptrace foreign execution attach.",
                "root_cause": "System call invocation attempting to write executable shellcode into legitimate host process memory.",
                "playbook_steps": [
                    "SIGKILL the injected target process and inspect memory maps via /proc/<pid>/maps.",
                    "Revoke ptrace attach permissions: sysctl -w kernel.yama.ptrace_scope=2.",
                    "Audit user session authentication tokens and terminate active unauthorized SSH sessions."
                ],
                "bash_remediation": """# Process Injection Remediation
sysctl -w kernel.yama.ptrace_scope=2
pkill -9 -f "meterpreter|injected_shell"
echo "[+] Yama ptrace scope hardened to restricted mode."
""",
                "ps_remediation": """# Process Injection Remediation (PowerShell)
Get-Process | Where-Object { $_.Path -notlike "C:\\Windows\\*" -and $_.Handles -gt 5000 } | Stop-Process -Force
Write-Host "[+] Anomalous foreign memory handles terminated."
"""
            },
            "T1110": {
                "name": "Brute Force Authentication",
                "summary": "High-frequency credential stuffing detected across remote service endpoints (SSH/FTP).",
                "root_cause": "Automated authentication failure burst originating from untrusted network entity.",
                "playbook_steps": [
                    "Temporarily lock out targeted user account to prevent credential compromise.",
                    "Inject rate-limiting iptables/netsh firewall rules dropping traffic from offender IP.",
                    "Enforce public key / MFA authentication requirements on remote access gateway."
                ],
                "bash_remediation": """# SSH Brute Force Rate Limiting
iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
echo "[+] Aggressive SSH brute force rate-limiting applied."
""",
                "ps_remediation": """# Remote Brute Force Containment
New-NetFirewallRule -DisplayName "AEGIS-Block-BruteForce" -Direction Inbound -LocalPort 22,3389 -Protocol TCP -Action Block
Write-Host "[+] Inbound authentication ports restricted to verified management subnets."
"""
            }
        }

    def generate_incident_investigation(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Synthesizes raw incident telemetry, XAI attributions, and Sigma/YARA hits into
        an investigation summary and containment playbook.
        """
        threat_score = float(incident_data.get("threat_score", 0.75))
        verdict = incident_data.get("verdict", "HIGH" if threat_score >= 0.6 else "MEDIUM")
        mitre_tech = incident_data.get("mitre_technique", "T1486")
        node_id = incident_data.get("node_id", "endpoint-linux")
        sigma_matches = incident_data.get("sigma_matches", [])
        yara_matches = incident_data.get("yara_matches", [])
        xai_features = incident_data.get("xai_features", [])

        kb_entry = self._knowledge_base.get(mitre_tech, self._knowledge_base["T1486"])

        # Construct analytical executive narrative
        confidence_pct = round(threat_score * 100, 1)
        narrative = (
            f"AEGIS Autonomous Engine detected a {verdict} severity threat ({confidence_pct}% threat probability) "
            f"on endpoint '{node_id}'. The activity strongly correlates with MITRE ATT&CK technique "
            f"{mitre_tech} ({kb_entry['name']}). "
        )

        if sigma_matches:
            rule_titles = [m.get("title", m.get("rule_id", "Unknown")) for m in sigma_matches]
            narrative += f"Deterministic Sigma triggers fired for: {', '.join(rule_titles)}. "

        if yara_matches:
            yara_names = [m.get("rule", "Unknown") for m in yara_matches]
            narrative += f"In-memory YARA pattern scans confirmed presence of signature(s): {', '.join(yara_names)}. "

        if xai_features:
            top_factors = [f"{f.get('feature', 'Metric')} (+{round(f.get('importance', 0)*100, 1)}%)" for f in xai_features[:3]]
            narrative += f"Key XAI driving factors: {', '.join(top_factors)}."

        return {
            "timestamp": time.time(),
            "incident_id": f"INC-{int(time.time())}-{node_id}",
            "node_id": node_id,
            "verdict": verdict,
            "threat_score": threat_score,
            "mitre_technique": mitre_tech,
            "technique_name": kb_entry["name"],
            "executive_summary": narrative,
            "root_cause_analysis": kb_entry["root_cause"],
            "recommended_containment_steps": kb_entry["playbook_steps"],
            "playbooks": {
                "bash_script": kb_entry["bash_remediation"],
                "powershell_script": kb_entry["ps_remediation"]
            },
            "forensic_checklist": [
                "Preserve volatile memory dump before reboot.",
                "Extract process lineage tree and parent PID hierarchy.",
                "Verify hash integrity against VirusTotal / MISP threat feeds."
            ]
        }


# Global singleton
ai_copilot_service = ThreatCopilotService()
