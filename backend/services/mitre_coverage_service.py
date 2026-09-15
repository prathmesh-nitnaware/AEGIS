"""
backend/services/mitre_coverage_service.py
==========================================
AEGIS Autonomous EDR - MITRE ATT&CK Automated Coverage Heatmap Service
----------------------------------------------------------------------
Calculates real-time detection & containment coverage across MITRE ATT&CK
Enterprise tactics and techniques, generating structured JSON matrix cards
and high-resolution vector SVG heatmaps.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("aegis.mitre_coverage")

# Comprehensive MITRE ATT&CK Enterprise Matrix Mapping for AEGIS
MITRE_TACTICS_DATA = [
    {
        "id": "TA0043",
        "name": "Reconnaissance",
        "techniques": [
            {"id": "T1595", "name": "Active Scanning", "tested": True, "protected": True, "engine": "cicids/pcap"},
            {"id": "T1590", "name": "Gather Victim Info", "tested": False, "protected": True, "engine": "zero_day"},
        ],
    },
    {
        "id": "TA0001",
        "name": "Initial Access",
        "techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing App", "tested": True, "protected": True, "engine": "linux_ids"},
            {"id": "T1078", "name": "Valid Accounts (Brute Force)", "tested": True, "protected": True, "engine": "linux_ids/cicids"},
            {"id": "T1566", "name": "Phishing Attachment", "tested": True, "protected": True, "engine": "ember"},
        ],
    },
    {
        "id": "TA0002",
        "name": "Execution",
        "techniques": [
            {"id": "T1059", "name": "Command & Scripting Interpreter", "tested": True, "protected": True, "engine": "windows_adv_v3"},
            {"id": "T1204", "name": "User Execution", "tested": True, "protected": True, "engine": "ember"},
            {"id": "T1053", "name": "Scheduled Task/Cron", "tested": True, "protected": True, "engine": "linux_ids"},
        ],
    },
    {
        "id": "TA0003",
        "name": "Persistence",
        "techniques": [
            {"id": "T1547", "name": "Boot/Logon Autostart", "tested": True, "protected": True, "engine": "windows_adv_v3"},
            {"id": "T1136", "name": "Create Account (Adduser)", "tested": True, "protected": True, "engine": "linux_ids"},
        ],
    },
    {
        "id": "TA0004",
        "name": "Privilege Escalation",
        "techniques": [
            {"id": "T1068", "name": "Exploitation for Priv Escalation", "tested": True, "protected": True, "engine": "linux_ids"},
            {"id": "T1548", "name": "Abuse Elevation Mechanism (Sudo)", "tested": True, "protected": True, "engine": "linux_ids"},
        ],
    },
    {
        "id": "TA0005",
        "name": "Defense Evasion",
        "techniques": [
            {"id": "T1070", "name": "Indicator Removal (Log Tamper)", "tested": True, "protected": True, "engine": "windows_adv_v3"},
            {"id": "T1027", "name": "Obfuscated Files/Packers", "tested": True, "protected": True, "engine": "ember"},
            {"id": "T1562", "name": "Impair Defenses (Kill EDR)", "tested": True, "protected": True, "engine": "ebpf/etw"},
        ],
    },
    {
        "id": "TA0006",
        "name": "Credential Access",
        "techniques": [
            {"id": "T1110", "name": "Brute Force (Hydra SSH/FTP)", "tested": True, "protected": True, "engine": "linux_ids"},
            {"id": "T1003", "name": "OS Credential Dumping (LSASS)", "tested": True, "protected": True, "engine": "windows_adv_v3"},
        ],
    },
    {
        "id": "TA0007",
        "name": "Discovery",
        "techniques": [
            {"id": "T1046", "name": "Network Service Discovery", "tested": True, "protected": True, "engine": "cicids"},
            {"id": "T1082", "name": "System Info Discovery", "tested": False, "protected": True, "engine": "zero_day"},
        ],
    },
    {
        "id": "TA0008",
        "name": "Lateral Movement",
        "techniques": [
            {"id": "T1021", "name": "Remote Services (SSH/RDP)", "tested": True, "protected": True, "engine": "cicids"},
            {"id": "T1570", "name": "Lateral Tool Transfer", "tested": True, "protected": True, "engine": "ember"},
        ],
    },
    {
        "id": "TA0009",
        "name": "Collection",
        "techniques": [
            {"id": "T1005", "name": "Data from Local System", "tested": False, "protected": True, "engine": "windows_adv_v3"},
            {"id": "T1074", "name": "Data Staged", "tested": False, "protected": True, "engine": "hdfs_model"},
        ],
    },
    {
        "id": "TA0010",
        "name": "Exfiltration",
        "techniques": [
            {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tested": True, "protected": True, "engine": "cicids"},
            {"id": "T1048", "name": "Exfiltration Over Asymmetric Protocol", "tested": True, "protected": True, "engine": "cicids"},
        ],
    },
    {
        "id": "TA0040",
        "name": "Impact",
        "techniques": [
            {"id": "T1486", "name": "Data Encrypted for Impact (Ransomware)", "tested": True, "protected": True, "engine": "windows_adv_v3"},
            {"id": "T1498", "name": "Network Denial of Service (DDoS)", "tested": True, "protected": True, "engine": "cicids"},
            {"id": "T1489", "name": "Service Stop", "tested": True, "protected": True, "engine": "windows_adv_v3"},
        ],
    },
]


class MITRECoverageService:
    """
    Computes MITRE ATT&CK coverage statistics and renders dynamic vector SVG heatmaps.
    """

    def __init__(self, tactics_data: Optional[List[Dict[str, Any]]] = None) -> None:
        self.tactics = tactics_data or MITRE_TACTICS_DATA

    def get_coverage_summary(self) -> Dict[str, Any]:
        """Calculates global and per-tactic coverage metrics."""
        total_techniques = 0
        tested_count = 0
        protected_count = 0

        tactic_summaries = []
        for t in self.tactics:
            techs = t["techniques"]
            t_total = len(techs)
            t_tested = sum(1 for x in techs if x.get("tested"))
            t_protected = sum(1 for x in techs if x.get("protected"))

            total_techniques += t_total
            tested_count += t_tested
            protected_count += t_protected

            tactic_summaries.append({
                "tactic_id": t["id"],
                "tactic_name": t["name"],
                "total": t_total,
                "tested": t_tested,
                "protected": t_protected,
                "coverage_pct": round((t_protected / t_total) * 100, 1) if t_total else 0.0,
                "techniques": techs,
            })

        overall_coverage_pct = (
            round((protected_count / total_techniques) * 100, 1) if total_techniques else 0.0
        )
        tested_pct = (
            round((tested_count / total_techniques) * 100, 1) if total_techniques else 0.0
        )

        return {
            "total_tactics": len(self.tactics),
            "total_techniques": total_techniques,
            "protected_techniques": protected_count,
            "tested_techniques": tested_count,
            "coverage_pct": overall_coverage_pct,
            "tested_pct": tested_pct,
            "tactics": tactic_summaries,
        }

    def render_svg_heatmap(self) -> str:
        """
        Generates an interactive SVG heatmap matrix visualization.
        """
        summary = self.get_coverage_summary()
        tactics = summary["tactics"]

        card_width = 160
        card_height = 110
        gap = 14
        cols = 4
        rows = (len(tactics) + cols - 1) // cols

        svg_width = cols * card_width + (cols + 1) * gap
        svg_height = rows * card_height + (rows + 1) * gap + 80

        svg_parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {svg_width} {svg_height}" width="{svg_width}" height="{svg_height}" style="background:#0f172a; font-family:Inter, Segoe UI, sans-serif; border-radius:12px;">',
            '  <defs>',
            '    <linearGradient id="headerGrad" x1="0%" y1="0%" x2="100%" y2="100%">',
            '      <stop offset="0%" stop-color="#38bdf8" />',
            '      <stop offset="100%" stop-color="#818cf8" />',
            '    </linearGradient>',
            '  </defs>',
            '  <!-- Title Header -->',
            f'  <text x="20" y="38" fill="url(#headerGrad)" font-size="20" font-weight="700">AEGIS MITRE ATT&amp;CK Matrix Heatmap</text>',
            f'  <text x="20" y="60" fill="#94a3b8" font-size="12">Overall Protection Coverage: {summary["coverage_pct"]}% ({summary["protected_techniques"]}/{summary["total_techniques"]} Techniques Active)</text>',
        ]

        y_offset = 80
        for i, t in enumerate(tactics):
            col_idx = i % cols
            row_idx = i // cols

            x = gap + col_idx * (card_width + gap)
            y = y_offset + row_idx * (card_height + gap)

            cov = t["coverage_pct"]
            if cov >= 90:
                bg_color = "#064e3b"
                border_color = "#10b981"
                cov_color = "#34d399"
            elif cov >= 70:
                bg_color = "#1e3a8a"
                border_color = "#3b82f6"
                cov_color = "#60a5fa"
            else:
                bg_color = "#701a75"
                border_color = "#d946ef"
                cov_color = "#f472b6"

            svg_parts.extend([
                f'  <g transform="translate({x}, {y})">',
                f'    <rect width="{card_width}" height="{card_height}" rx="8" fill="{bg_color}" fill-opacity="0.85" stroke="{border_color}" stroke-width="1.5" />',
                f'    <text x="12" y="24" fill="#f8fafc" font-size="12" font-weight="600">{t["tactic_name"]}</text>',
                f'    <text x="12" y="42" fill="#94a3b8" font-size="10">{t["tactic_id"]}</text>',
                f'    <text x="12" y="66" fill="{cov_color}" font-size="16" font-weight="700">{cov}%</text>',
                f'    <text x="12" y="86" fill="#cbd5e1" font-size="10">Prot: {t["protected"]}/{t["total"]} | Test: {t["tested"]}</text>',
                '  </g>',
            ])

        svg_parts.append('</svg>')
        return "\n".join(svg_parts)


# Singleton instance
mitre_coverage_service = MITRECoverageService()
