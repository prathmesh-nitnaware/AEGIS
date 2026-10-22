#!/usr/bin/env python3
"""
tools/btui_peer_voting.py
==========================
AEGIS Beautiful Terminal UI (BTUI) - Distributed Peer-Voting Consensus Visualizer

Displays real-time consensus voting data from the AEGIS backend:
  1. Attack Detection and Event Details
  2. Threat Score and Risk Level Gauge
  3. Peer-Voting Request & Cluster Status
  4. Registered Peers and Individual Peer Votes Table
  5. Vote Weights, Quorum Progress, and Consensus Progress
  6. Final Consensus Verdict and Autonomous Response Action

Reads actual live data from:
  - Primary: AEGIS Telemetry & Voting REST API (/api/voting/latest, /api/centralized/verdicts)
  - Secondary fallback: Central SQLite database (aegis_local.db / aegis_central_trust.db)

Usage:
  python tools/btui_peer_voting.py              # Single snapshot view
  python tools/btui_peer_voting.py --watch      # Continuous live dashboard
  python tools/btui_peer_voting.py --test-event # Injects a live test event to demonstrate voting
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ANSI Color & Formatting Codes
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
ITALIC = "\033[3m"
UNDERLINE = "\033[4m"

# Foreground Colors
BLACK = "\033[30m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"

# Bright Colors
BRIGHT_RED = "\033[91m"
BRIGHT_GREEN = "\033[92m"
BRIGHT_YELLOW = "\033[93m"
BRIGHT_BLUE = "\033[94m"
BRIGHT_MAGENTA = "\033[95m"
BRIGHT_CYAN = "\033[96m"
BRIGHT_WHITE = "\033[97m"

# Background Colors
BG_DARK = "\033[40m"
BG_BLUE = "\033[44m"
BG_RED = "\033[41m"


def color_severity(severity: str) -> str:
    s = (severity or "LOW").upper()
    if s == "CRITICAL":
        return f"{BRIGHT_RED}{BOLD}{s}{RESET}"
    elif s == "HIGH":
        return f"{RED}{BOLD}{s}{RESET}"
    elif s == "MEDIUM":
        return f"{YELLOW}{BOLD}{s}{RESET}"
    elif s == "LOW":
        return f"{GREEN}{s}{RESET}"
    return f"{WHITE}{s}{RESET}"


def color_action(action: str) -> str:
    a = (action or "LOG").upper()
    if a in ("ISOLATE_HOST", "KILL_PROCESS"):
        return f"{BRIGHT_RED}{BOLD}{a}{RESET}"
    elif a in ("QUARANTINE_FILE", "ALERT"):
        return f"{BRIGHT_YELLOW}{BOLD}{a}{RESET}"
    return f"{CYAN}{a}{RESET}"


def render_gauge(score: float, width: int = 24) -> str:
    clamped = max(0.0, min(1.0, float(score)))
    filled_len = int(round(clamped * width))
    empty_len = width - filled_len
    
    if clamped >= 0.80:
        fill_color = BRIGHT_RED
    elif clamped >= 0.60:
        fill_color = RED
    elif clamped >= 0.30:
        fill_color = YELLOW
    else:
        fill_color = GREEN
        
    bar = f"{fill_color}{'█' * filled_len}{DIM}{'░' * empty_len}{RESET}"
    return f"[{bar}] {fill_color}{clamped:.3f}{RESET}"


def render_quorum_bar(current: int, needed: int, width: int = 20) -> str:
    ratio = min(1.0, current / needed) if needed > 0 else 1.0
    filled = int(round(ratio * width))
    empty = width - filled
    color = BRIGHT_GREEN if current >= needed else BRIGHT_YELLOW
    bar = f"{color}{'▓' * filled}{DIM}{'░' * empty}{RESET}"
    pct = int(round(ratio * 100))
    return f"[{bar}] {color}{current}/{needed}{RESET} ({pct}%)"


def fetch_backend_data(server_url: str, vote_id_filter: Optional[str] = None) -> Dict[str, Any]:
    """
    Fetch live voting and telemetry data from the backend API.
    Falls back to local SQLite if backend is not currently running.
    """
    data: Dict[str, Any] = {
        "source": "none",
        "latest_verdict": None,
        "latest_action": None,
        "recent_verdicts": [],
        "peer_trust": {},
        "recent_telemetry": [],
    }

    url_base = server_url.rstrip("/")

    # 1. Try Live API: Latest Verdict or specific vote_id
    try:
        req = urllib.request.Request(f"{url_base}/api/voting/latest", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            if body.get("status") == "success" and body.get("verdict"):
                v = body["verdict"]
                if not vote_id_filter or v.get("vote_id") == vote_id_filter:
                    data["latest_verdict"] = v
                    data["source"] = "live_api"
    except Exception:
        pass

    # 2. Try Live API: Verdicts history
    try:
        req = urllib.request.Request(f"{url_base}/api/centralized/verdicts?limit=50", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            data["recent_verdicts"] = body.get("verdicts", [])
            if vote_id_filter:
                match = next((x for x in data["recent_verdicts"] if x.get("vote_id") == vote_id_filter), None)
                if match:
                    data["latest_verdict"] = match
                    data["source"] = "live_api"
            elif not data["latest_verdict"] and data["recent_verdicts"]:
                data["latest_verdict"] = data["recent_verdicts"][0]
                data["source"] = "live_api"
    except Exception:
        pass

    # 3. Try Live API: Trust scores
    try:
        req = urllib.request.Request(f"{url_base}/api/admin/trust", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            agents = body.get("agents", [])
            data["peer_trust"] = {a["agent_id"]: a["trust_score"] for a in agents}
    except Exception:
        pass

    # 4. Fallback to Local SQLite DBs if API was unreachable or vote not found
    if not data["latest_verdict"]:
        db_path = _ROOT / "aegis_local.db"
        if db_path.exists():
            try:
                con = sqlite3.connect(str(db_path))
                con.row_factory = sqlite3.Row
                cur = con.cursor()
                if vote_id_filter:
                    row = cur.execute(
                        "SELECT * FROM consensus_verdicts WHERE vote_id = ? LIMIT 1",
                        (vote_id_filter,)
                    ).fetchone()
                else:
                    row = cur.execute(
                        "SELECT * FROM consensus_verdicts ORDER BY verdict_timestamp DESC LIMIT 1"
                    ).fetchone()
                if row:
                    data["latest_verdict"] = dict(row)
                    data["source"] = "local_sqlite (aegis_local.db)"
                con.close()
            except Exception:
                pass

    # 5. Connect associated remote action from pending_actions table
    if data["latest_verdict"]:
        db_path = _ROOT / "aegis_local.db"
        if db_path.exists():
            try:
                con = sqlite3.connect(str(db_path))
                con.row_factory = sqlite3.Row
                cur = con.cursor()
                t_vid = data["latest_verdict"].get("vote_id")
                act_row = cur.execute(
                    "SELECT action_id, agent_id, action_type, vote_id, target_pid, target_file, status, created_at FROM pending_actions WHERE vote_id = ? ORDER BY created_at DESC LIMIT 1",
                    (t_vid,)
                ).fetchone()
                if act_row:
                    data["latest_action"] = dict(act_row)
                con.close()
            except Exception:
                pass

    # 6. Fallback for trust scores
    if not data["peer_trust"]:
        trust_db = _ROOT / "aegis_central_trust.db"
        if trust_db.exists():
            try:
                con = sqlite3.connect(str(trust_db))
                cur = con.cursor()
                rows = cur.execute("SELECT agent_id, trust_score FROM agent_trust").fetchall()
                data["peer_trust"] = {r[0]: float(r[1]) for r in rows}
                con.close()
            except Exception:
                pass

    return data


def inject_test_threat_event(server_url: str) -> None:
    """Inject an actual threat event via the backend API to demonstrate live voting."""
    url = f"{server_url.rstrip('/')}/api/centralized/vote"
    ts_now = time.time()
    payload = {
        "event_type": "network",
        "origin_agent_id": "sensor-cicids-gateway",
        "threat_score": 0.885,
        "confidence": 0.98,
        "details": {
            "dest_ip": "192.168.1.105",
            "port": 4444,
            "attack_type": "Metasploit Reverse TCP Shell",
            "fwd_packets": 34,
            "bwd_packets": 28,
        },
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=3.0) as resp:
        result = json.loads(resp.read().decode("utf-8"))
        print(f"{GREEN}[BTUI] Injected live test threat event successfully! Vote ID: {result.get('verdict', {}).get('vote_id')}{RESET}\n")


def render_btui(data: Dict[str, Any], server_url: str) -> str:
    """Render the full Beautiful Terminal UI dashboard screen."""
    lines: List[str] = []
    width = 86
    h_line = "═" * (width - 2)
    s_line = "─" * (width - 2)

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    source = data.get("source", "unknown")

    # Header Box
    lines.append(f"{BRIGHT_CYAN}╔{h_line}╗{RESET}")
    title = "AEGIS DISTRIBUTED CONSENSUS ENGINE — PEER-VOTING DASHBOARD"
    lines.append(f"{BRIGHT_CYAN}║{BOLD}{BRIGHT_WHITE}{title:^{width-2}}{RESET}{BRIGHT_CYAN}║{RESET}")
    status_line = f"Live Backend: {server_url}   Data Source: {source}   Clock: {now_str}"
    lines.append(f"{BRIGHT_CYAN}║{DIM}{status_line:^{width-2}}{RESET}{BRIGHT_CYAN}║{RESET}")
    lines.append(f"{BRIGHT_CYAN}╠{h_line}╣{RESET}")

    v = data.get("latest_verdict")

    if not v:
        lines.append(f"{BRIGHT_CYAN}║{RESET}  {YELLOW}[!] No consensus verdicts recorded in backend yet.{RESET}{' ' * 34}{BRIGHT_CYAN}║{RESET}")
        lines.append(f"{BRIGHT_CYAN}║{RESET}      Trigger an attack or run with {BRIGHT_WHITE}--test-event{RESET} to generate live consensus telemetry.  {BRIGHT_CYAN}║{RESET}")
        lines.append(f"{BRIGHT_CYAN}╚{h_line}╝{RESET}")
        return "\n".join(lines)

    # 1. ATTACK DETECTION & EVENT DETAILS
    details = v.get("details") or {}
    if isinstance(details, str):
        try:
            details = json.loads(details)
        except Exception:
            details = {}

    v_ts = v.get("timestamp") or v.get("verdict_timestamp") or time.time()
    v_time_str = datetime.fromtimestamp(float(v_ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    origin = v.get("origin_agent_id", "unknown")
    event_type = v.get("event_type", "unknown")
    vote_id = v.get("vote_id", "N/A")

    target_desc = []
    if details.get("process") or details.get("process_name"):
        target_desc.append(f"Process: {details.get('process') or details.get('process_name')}")
    if details.get("pid"):
        target_desc.append(f"PID: {details.get('pid')}")
    if details.get("port"):
        target_desc.append(f"Port: {details.get('port')}")
    if details.get("dest_ip"):
        target_desc.append(f"Dest IP: {details.get('dest_ip')}")
    if details.get("attack_type"):
        target_desc.append(f"Signature: {details.get('attack_type')}")
    if details.get("filename") or details.get("target_file"):
        target_desc.append(f"File: {details.get('filename') or details.get('target_file')}")
    if not target_desc and data.get("latest_action"):
        act = data["latest_action"]
        if act.get("target_pid"):
            target_desc.append(f"PID: {act.get('target_pid')}")
        if act.get("target_file"):
            target_desc.append(f"File: {act.get('target_file')}")

    target_str = " | ".join(target_desc) if target_desc else "General Anomaly Event"

    lines.append(f"{BRIGHT_CYAN}║{RESET} {BOLD}{BRIGHT_WHITE}[1] ATTACK DETECTION & INCOMING EVENT DETAILS{RESET}{' ' * 42}{BRIGHT_CYAN}║{RESET}")
    lines.append(f"{BRIGHT_CYAN}║{RESET}   Vote ID:       {BRIGHT_MAGENTA}{vote_id:<12}{RESET}   Time:        {WHITE}{v_time_str:<22}{RESET}        {BRIGHT_CYAN}║{RESET}")
    lines.append(f"{BRIGHT_CYAN}║{RESET}   Origin Agent:  {BRIGHT_CYAN}{origin:<12}{RESET}   Event Type:  {YELLOW}{event_type:<22}{RESET}        {BRIGHT_CYAN}║{RESET}")
    lines.append(f"{BRIGHT_CYAN}║{RESET}   Event Target:  {WHITE}{target_str[:width-22]:<{width-22}}{RESET} {BRIGHT_CYAN}║{RESET}")
    lines.append(f"{BRIGHT_CYAN}╠{s_line}╣{RESET}")

    # 2. THREAT SCORE & RISK LEVEL
    raw_score = float(v.get("raw_threat_score", 0.0))
    final_score = float(v.get("final_weighted_score", raw_score))
    severity = v.get("severity", "LOW")

    raw_gauge = render_gauge(raw_score, width=16)
    final_gauge = render_gauge(final_score, width=16)
    sev_badge = color_severity(severity)

    lines.append(f"{BRIGHT_CYAN}║{RESET} {BOLD}{BRIGHT_WHITE}[2] THREAT SCORING & RISK LEVEL{RESET}{' ' * 55}{BRIGHT_CYAN}║{RESET}")
    lines.append(f"{BRIGHT_CYAN}║{RESET}   Initial Detection Score:  {raw_gauge}   Severity: [{sev_badge}]        {BRIGHT_CYAN}║{RESET}")
    lines.append(f"{BRIGHT_CYAN}║{RESET}   Aggregated Consensus:     {final_gauge}   Action:   [{color_action(v.get('response_action', 'LOG'))}]   {BRIGHT_CYAN}║{RESET}")
    lines.append(f"{BRIGHT_CYAN}╠{s_line}╣{RESET}")

    # 3. PEER-VOTING STATUS & REGISTERED PEERS
    quorum_status = v.get("quorum_status") or ("CONSENSUS_REACHED" if v.get("consensus_reached") else "NO_QUORUM")
    verdict_type = v.get("verdict_type") or ("PEER_CONSENSUS_VERDICT" if v.get("consensus_reached") else "LOCAL_EMERGENCY_VERDICT")
    participating = int(v.get("participating_peers", 0))
    quorum_needed = int(v.get("quorum_needed", 1))

    if quorum_status == "CONSENSUS_REACHED":
        q_badge = f"{BRIGHT_GREEN}{BOLD}CONSENSUS REACHED{RESET}"
    elif quorum_status == "PARTIAL_QUORUM":
        q_badge = f"{BRIGHT_YELLOW}{BOLD}PARTIAL QUORUM{RESET}"
    else:
        q_badge = f"{BRIGHT_RED}{BOLD}NO QUORUM / PARTITIONED{RESET}"

    if verdict_type == "PEER_CONSENSUS_VERDICT":
        vt_badge = f"{BRIGHT_GREEN}PEER CONSENSUS VERDICT{RESET}"
    elif verdict_type == "LOCAL_EMERGENCY_VERDICT":
        vt_badge = f"{BRIGHT_RED}{BOLD}LOCAL EMERGENCY VERDICT (Safe Containment){RESET}"
    else:
        vt_badge = f"{YELLOW}INSUFFICIENT QUORUM{RESET}"

    total_weight = float(v.get("total_weight", 1.5))
    q_bar = render_quorum_bar(participating, quorum_needed, width=14)

    lines.append(f"{BRIGHT_CYAN}║{RESET} {BOLD}{BRIGHT_WHITE}[3] PEER-VOTING CLUSTER STATUS & QUORUM PROGRESS{RESET}{' ' * 38}{BRIGHT_CYAN}║{RESET}")
    lines.append(f"{BRIGHT_CYAN}║{RESET}   Quorum Status:  {q_badge:<32}  Type: {vt_badge:<32} {BRIGHT_CYAN}║{RESET}")
    lines.append(f"{BRIGHT_CYAN}║{RESET}   Quorum Progress: {q_bar:<30} Total Weight: {CYAN}{total_weight:.2f}{RESET}              {BRIGHT_CYAN}║{RESET}")
    lines.append(f"{BRIGHT_CYAN}╠{s_line}╣{RESET}")

    # 4. INDIVIDUAL PEER VOTES TABLE
    lines.append(f"{BRIGHT_CYAN}║{RESET} {BOLD}{BRIGHT_WHITE}[4] REGISTERED PEER VOTES & TRUST WEIGHT ALLOCATION TABLE{RESET}{' ' * 30}{BRIGHT_CYAN}║{RESET}")
    t_header = f"{DIM}┌───────────────────────────┬──────────────┬──────────────┬──────────────┬──────────────┐{RESET}"
    t_cols   = f"{DIM}│{RESET} {BOLD}Peer Node ID{RESET}              {DIM}│{RESET} {BOLD}Vote Score{RESET}   {DIM}│{RESET} {BOLD}Correlated{RESET}   {DIM}│{RESET} {BOLD}Trust Score{RESET}  {DIM}│{RESET} {BOLD}Vote Weight{RESET}  {DIM}│{RESET}"
    t_sep    = f"{DIM}├───────────────────────────┼──────────────┼──────────────┼──────────────┼──────────────┤{RESET}"
    lines.append(f"{BRIGHT_CYAN}║{RESET} {t_header} {BRIGHT_CYAN}║{RESET}")
    lines.append(f"{BRIGHT_CYAN}║{RESET} {t_cols} {BRIGHT_CYAN}║{RESET}")
    lines.append(f"{BRIGHT_CYAN}║{RESET} {t_sep} {BRIGHT_CYAN}║{RESET}")

    # Row 0: Origin Node
    origin_trust = data.get("peer_trust", {}).get(origin, 1.0)
    origin_weight = round(origin_trust * 1.5, 3)
    row_origin = (
        f"{DIM}│{RESET} {BRIGHT_CYAN}{origin:<25}{RESET} {DIM}│{RESET}"
        f" {BRIGHT_RED if raw_score >= 0.6 else YELLOW}{raw_score:<12.3f}{RESET} {DIM}│{RESET}"
        f" {WHITE}{'ORIGIN':<12}{RESET} {DIM}│{RESET}"
        f" {GREEN}{origin_trust:<12.3f}{RESET} {DIM}│{RESET}"
        f" {BRIGHT_WHITE}{origin_weight:<12.3f}{RESET} {DIM}│{RESET}"
    )
    lines.append(f"{BRIGHT_CYAN}║{RESET} {row_origin} {BRIGHT_CYAN}║{RESET}")

    # Peer votes from verdict
    peer_votes = v.get("peer_votes") or []
    if peer_votes:
        for pv in peer_votes:
            pid = str(pv.get("peer_agent_id", "peer-unknown"))
            pv_score = float(pv.get("peer_vote_score", 0.0))
            pv_corr = bool(pv.get("correlated", False))
            pv_trust = float(pv.get("peer_trust_score", data.get("peer_trust", {}).get(pid, 0.5)))
            pv_weight = float(pv.get("weight", 1.0))
            corr_str = f"{BRIGHT_GREEN}MATCH (2.0x){RESET}" if pv_corr else f"{DIM}NO_MATCH{RESET}"

            row = (
                f"{DIM}│{RESET} {MAGENTA}{pid:<25}{RESET} {DIM}│{RESET}"
                f" {BRIGHT_RED if pv_score >= 0.6 else YELLOW}{pv_score:<12.3f}{RESET} {DIM}│{RESET}"
                f" {corr_str:<21} {DIM}│{RESET}"
                f" {GREEN}{pv_trust:<12.3f}{RESET} {DIM}│{RESET}"
                f" {BRIGHT_WHITE}{pv_weight:<12.3f}{RESET} {DIM}│{RESET}"
            )
            lines.append(f"{BRIGHT_CYAN}║{RESET} {row} {BRIGHT_CYAN}║{RESET}")
    else:
        # Show registered peers from trust tracker if any
        registered = [aid for aid in data.get("peer_trust", {}) if aid != origin]
        if registered:
            for aid in registered[:3]:
                tr = data["peer_trust"].get(aid, 0.5)
                row = (
                    f"{DIM}│{RESET} {DIM}{aid:<25}{RESET} {DIM}│{RESET}"
                    f" {DIM}{'NO_RESPONSE':<12}{RESET} {DIM}│{RESET}"
                    f" {DIM}{'TIMEOUT':<12}{RESET} {DIM}│{RESET}"
                    f" {GREEN}{tr:<12.3f}{RESET} {DIM}│{RESET}"
                    f" {DIM}{'0.000':<12}{RESET} {DIM}│{RESET}"
                )
                lines.append(f"{BRIGHT_CYAN}║{RESET} {row} {BRIGHT_CYAN}║{RESET}")
        else:
            no_peers_row = f"{DIM}│{RESET} {ITALIC}{DIM}{'No external peer responses recorded for this vote.':^78}{RESET} {DIM}│{RESET}"
            lines.append(f"{BRIGHT_CYAN}║{RESET} {no_peers_row} {BRIGHT_CYAN}║{RESET}")

    t_footer = f"{DIM}└───────────────────────────┴──────────────┴──────────────┴──────────────┴──────────────┘{RESET}"
    lines.append(f"{BRIGHT_CYAN}║{RESET} {t_footer} {BRIGHT_CYAN}║{RESET}")
    lines.append(f"{BRIGHT_CYAN}╠{h_line}╣{RESET}")

    # 5. FINAL VERDICT & AUTONOMOUS RESPONSE ACTION
    consensus_reached = bool(v.get("consensus_reached", False))
    reach_badge = f"{BRIGHT_GREEN}{BOLD}YES (PEER CONSENSUS){RESET}" if consensus_reached else f"{BRIGHT_RED}{BOLD}NO (AUTONOMOUS / EMERGENCY){RESET}"
    resp_act = v.get("response_action", "LOG")

    lines.append(f"{BRIGHT_CYAN}║{RESET} {BOLD}{BRIGHT_WHITE}[5] FINAL CONSENSUS VERDICT & AUTONOMOUS MITIGATION ACTION{RESET}{' ' * 28}{BRIGHT_CYAN}║{RESET}")
    lines.append(f"{BRIGHT_CYAN}║{RESET}   Consensus Reached:   {reach_badge:<38}               {BRIGHT_CYAN}║{RESET}")
    lines.append(f"{BRIGHT_CYAN}║{RESET}   Final Threat Level:  {sev_badge} (Score: {final_score:.3f})                                    {BRIGHT_CYAN}║{RESET}")
    lines.append(f"{BRIGHT_CYAN}║{RESET}   Automated Action:    {color_action(resp_act)}                                              {BRIGHT_CYAN}║{RESET}")
    if data.get("latest_action"):
        act = data["latest_action"]
        act_id = act.get("action_id", "N/A")
        act_stat = act.get("status", "DISPATCHED")
        act_pid = act.get("target_pid") or "-"
        stat_color = BRIGHT_GREEN if act_stat in ("SUCCESS", "DISPATCHED") else YELLOW
        lines.append(f"{BRIGHT_CYAN}║{RESET}   Mitigation Dispatch: Action ID: {WHITE}{act_id}{RESET}  Status: {stat_color}{act_stat}{RESET}  Target PID: {WHITE}{act_pid}{RESET}    {BRIGHT_CYAN}║{RESET}")
        if act.get("target_file"):
            lines.append(f"{BRIGHT_CYAN}║{RESET}   Containment Target:  File: {WHITE}{str(act.get('target_file'))[:48]:<48}{RESET}           {BRIGHT_CYAN}║{RESET}")
    lines.append(f"{BRIGHT_CYAN}║{RESET}   Database Status:     {BRIGHT_GREEN}PERSISTED IN CENTRAL DB (consensus_verdicts){RESET}             {BRIGHT_CYAN}║{RESET}")
    lines.append(f"{BRIGHT_CYAN}╚{h_line}╝{RESET}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="AEGIS BTUI Peer-Voting Consensus Visualizer")
    parser.add_argument("--server-url", default="http://127.0.0.1:8000", help="AEGIS Backend API URL")
    parser.add_argument("--vote-id", default=None, help="Inspect a specific vote_id (default: latest)")
    parser.add_argument("--watch", action="store_true", help="Continuously poll and refresh UI in terminal")
    parser.add_argument("--interval", type=float, default=1.5, help="Refresh interval in seconds (default: 1.5s)")
    parser.add_argument("--test-event", action="store_true", help="Inject live test threat event before displaying")
    parser.add_argument("--snapshot", action="store_true", help="Print a single snapshot view and exit (default)")
    args = parser.parse_args()

    # Enable ANSI escape sequences on Windows consoles
    if os.name == "nt":
        os.system("")

    if args.test_event:
        try:
            inject_test_threat_event(args.server_url)
        except Exception as exc:
            print(f"{YELLOW}[BTUI] Note: Could not inject test event via REST ({exc}). Proceeding with existing data.{RESET}\n")

    if not args.watch:
        # Snapshot mode
        data = fetch_backend_data(args.server_url, vote_id_filter=args.vote_id)
        print(render_btui(data, args.server_url))
        return

    # Watch mode
    try:
        while True:
            data = fetch_backend_data(args.server_url, vote_id_filter=args.vote_id)
            # Clear screen (ANSI escape)
            sys.stdout.write("\033[2J\033[H")
            sys.stdout.write(render_btui(data, args.server_url) + "\n")
    except KeyboardInterrupt:
        print(f"\n{GREEN}[BTUI] Exiting live visualizer.{RESET}")


if __name__ == "__main__":
    main()
