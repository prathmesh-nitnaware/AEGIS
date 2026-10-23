"""
agent/run_all.py
=================
AEGIS - OS-aware wiring script: detects the host operating system, then
starts only the collectors compatible with it, printing live scored
verdicts from ThreatFusionEngine for each one.

Place this file in the same agent/ folder as fusion_engine.py and
live_collectors.py, then run:

    python run_all.py                # auto-detects OS (default)
    python run_all.py --os windows   # manual override, for testing only
    python run_all.py --os linux

WHAT WILL WORK IMMEDIATELY (no extra setup, on either OS):
    - Zero-Day      (already proven working)
    - CICIDS        (model file confirmed present -- should load)

WHAT NEEDS ONE-TIME SETUP FIRST (instructions printed at startup if missing):
    - EMBER         -> needs PE_WATCH_DIR below to exist
    - HDFS          -> point HDFS_LOG_PATH below at a real log file
    - Windows Adv.  -> Windows only; install + configure Sysmon first
    - Linux IDS     -> Linux only; needs bpftrace installed + root/sudo

--------------------------------------------------------------------------
ORCHESTRATION NOTE (OS-aware collector selection)
--------------------------------------------------------------------------
This file does NOT contain any collector's actual capture logic -- that
still lives entirely in live_collectors.py, scapy_flow_collector.py, and
linux_collector.py, unmodified. This file only:

    1. Detects the host OS (agent/orchestration/os_detector.py)
    2. Looks up which collectors are compatible with that OS
       (agent/orchestration/telemetry_registry.py)
    3. Calls each compatible collector's start function exactly once
       (agent/orchestration/collector_manager.py)

Every "start_*" function below is unchanged in what it does internally
compared to the previous version of this file -- they are just wrapped
in functions now so the orchestrator can decide, per-OS, which ones to
call, instead of this file unconditionally calling all of them.
"""
from __future__ import annotations
import socket

import argparse
import json
import os
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Optional

_HERE = Path(__file__).resolve().parent          # .../agent/
_PROJECT_ROOT = _HERE.parent                      # .../AEGIS/

# Both paths are needed: _HERE for this file's existing bare imports
# (`from fusion_engine import ...`), _PROJECT_ROOT for linux_collector.py's
# package-qualified import (`from agent.linux_model_adapter import ...`).
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_PROJECT_ROOT))


def load_env_file(path: Path) -> None:
    """Safely loads an environment file into os.environ without overriding existing env vars."""
    if not path.is_file():
        return
    try:
        from dotenv import load_dotenv
        load_dotenv(path, override=False)
        return
    except ImportError:
        pass
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k not in os.environ:
                os.environ[k] = v
    except Exception:
        pass


# Load local agent/.env and root .env before reading configs
load_env_file(_HERE / ".env")
load_env_file(_PROJECT_ROOT / ".env")

from fusion_engine import ThreatFusionEngine  # noqa: E402
from live_collectors import (  # noqa: E402
    ZeroDayEventCollector,
    PEFileCollector,
    HDFSLogCollector,
    WindowsAPICollector,
)
from scapy_flow_collector import ScapyFlowCollector  # noqa: E402
from watchdog.observers import Observer  # noqa: E402

from orchestration.os_detector import resolve_os  # noqa: E402
from orchestration.collector_manager import print_banner, run_collectors  # noqa: E402
from orchestration.telemetry_registry import collectors_for_platform  # noqa: E402

# ---------------------------------------------------------------------------
# EDIT THESE PATHS for your machine before running EMBER / HDFS collectors
# ---------------------------------------------------------------------------
# Windows-style; adjust for Linux paths as needed
PE_WATCH_DIR = r"C:\Users\%USERNAME%\Downloads"
HDFS_LOG_PATH = str(_HERE / "test.log")

# ---------------------------------------------------------------------------
# AEGIS INTERNAL MANAGEMENT / TELEMETRY PORTS (LOOPBACK IPC)
# ---------------------------------------------------------------------------
# 5432: PostgreSQL database
# 8000: FastAPI Command Node API server
# 5173, 5174: Vite React frontend dashboards
# 5555, 5556: P2P ZeroMQ mesh node heartbeats & gossip
# 6379: Redis cache
# Tagged as INTERNAL_IPC on localhost so internal database/API calls are logged
# as benign operational telemetry (LOW) rather than false intrusion alerts.
AEGIS_MANAGEMENT_PORTS = {5432, 8000, 5173, 5174, 5555, 5556, 6379}

# Resolve all local IP addresses on this host (loopback + LAN adapter IPs)
# to correctly classify internal host communications (e.g. backend <-> PostgreSQL)
try:
    LOCAL_IPS = set(socket.gethostbyname_ex(socket.gethostname())[2]) | {
        "127.0.0.1", "::1", "localhost", "0.0.0.0", ""}
except Exception:
    LOCAL_IPS = {"127.0.0.1", "::1", "localhost", "0.0.0.0", ""}

# ---------------------------------------------------------------------------
# CLI: --os override (manual, for testing only -- auto-detect is default)
# ---------------------------------------------------------------------------
parser = argparse.ArgumentParser(description="AEGIS OS-aware telemetry agent")
parser.add_argument(
    "--os", dest="os_override", default=None, choices=["windows", "linux", "Windows", "Linux"],
    help="Manually force a telemetry profile (windows/linux). Default: auto-detect.",
)
parser.add_argument(
    "--p2p-port", dest="p2p_port", type=int, default=0,
    help="Enable P2P mesh node on this UDP port (0 to disable UDP server, default: 0).",
)
parser.add_argument(
    "--p2p-peers", dest="p2p_peers", default=os.environ.get("P2P_PEERS", ""),
    help="Comma-separated list of peer addresses for P2P mesh (e.g. 192.168.0.105:9001).",
)
parser.add_argument(
    "--agent-id", dest="agent_id", default=os.environ.get("AGENT_ID", socket.gethostname()),
    help="Agent ID identifier for peer voting, heartbeats, and telemetry (default: hostname).",
)
parser.add_argument(
    "--no-heartbeat", dest="no_heartbeat", action="store_true", default=False,
    help="Disable automatic background heartbeat pulse emitter.",
)
parser.add_argument(
    "--command-node", "--server", dest="command_node_url", default=None,
    help="URL of central command node (default: COMMAND_NODE_URL or http://127.0.0.1:8000).",
)
parser.add_argument(
    "--no-ip-prompt", dest="no_ip_prompt", action="store_true", default=False,
    help="Skip interactive Main Server IP prompt and use default/environment immediately.",
)
args, _ = parser.parse_known_args()


def clean_server_url(raw_input: str) -> str:
    """Normalize user input to a fully qualified http://<ip>:<port> URL."""
    val = raw_input.strip()
    if not val:
        return "http://127.0.0.1:8000"
    if not val.startswith("http://") and not val.startswith("https://"):
        val = f"http://{val}"
    parsed = urllib.parse.urlsplit(val)
    port = parsed.port or 8000
    host = parsed.hostname or "127.0.0.1"
    return f"{parsed.scheme}://{host}:{port}"


def test_server_connectivity(server_url: str) -> bool:
    """Test reachability to the central Command Node API health endpoint."""
    print(f"[*] Verifying connectivity to Main Server at {server_url}/api/health ...")
    try:
        req = urllib.request.Request(f"{server_url}/api/health", headers={"User-Agent": "AEGIS-Agent"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            if resp.status == 200:
                print(f"  [OK] Successfully connected to Main Server at {server_url} (HTTP 200)!\n")
                return True
    except Exception as exc:
        print(f"  [!] Note: Cannot immediately connect to {server_url}/api/health ({exc}).")
        print("      Telemetry and heartbeats will start and retry connecting in the background.\n")
    return False


def save_agent_server_url(server_url: str) -> None:
    """Persist configured server URL into local agent/.env (gitignored)."""
    try:
        env_file = _HERE / ".env"
        existing = env_file.read_text(encoding="utf-8") if env_file.exists() else ""
        lines = [
            l for l in existing.splitlines()
            if not any(l.startswith(k) for k in ("COMMAND_NODE_URL=", "MAIN_SERVER_IP="))
        ]
        parsed = urllib.parse.urlsplit(server_url)
        ip = parsed.hostname or "127.0.0.1"
        lines.extend([
            f"MAIN_SERVER_IP={ip}",
            f"COMMAND_NODE_URL={server_url}",
        ])
        env_file.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
        print(f"[*] Saved configured server to agent/.env (gitignored)")
    except Exception:
        pass


default_target = (
    args.command_node_url
    or os.environ.get("COMMAND_NODE_URL")
    or (f"http://{os.environ.get('MAIN_SERVER_IP')}:8000" if os.environ.get("MAIN_SERVER_IP") else None)
    or "http://127.0.0.1:8000"
)

COMMAND_NODE_URL = clean_server_url(default_target)

print("\n" + "=" * 80)
print("      AEGIS ENDPOINT AGENT — OS-AWARE TELEMETRY & THREAT DEFENSE")
print("=" * 80)
print(f"  Target Main Server:  {COMMAND_NODE_URL}")
print("  This agent will stream live ML telemetry, verdicts, and heartbeats to this server.")
print("-" * 80)

if args.command_node_url:
    save_agent_server_url(COMMAND_NODE_URL)

test_server_connectivity(COMMAND_NODE_URL)
os.environ["COMMAND_NODE_URL"] = COMMAND_NODE_URL

OS_NAME = resolve_os(args.os_override)
COMPATIBLE_COLLECTORS = collectors_for_platform(OS_NAME)
PROFILE_NAME = OS_NAME.upper()

engine = ThreatFusionEngine()
print("[run_all] ThreatFusionEngine initialised. Check the [loader] lines above")
print("[run_all] for 'Loaded X' vs 'Missing artefact' / 'Failed to load' per model.\n")
print(f"[run_all] Streaming live telemetry to Main Server: {COMMAND_NODE_URL}/api/telemetry\n")

# Start the response-action polling worker in simulation mode by default.
try:
    from response_worker import main as response_worker_main


    os.environ["COMMAND_NODE_URL"] = COMMAND_NODE_URL
    os.environ["AEGIS_AGENT_ID"] = getattr(
        args, "agent_id", "agent-host-local"
    )

    response_thread = threading.Thread(
        target=response_worker_main,
        name="aegis-response-worker",
        daemon=True,
    )
    response_thread.start()
    print("[run_all] Response worker started (simulation unless explicitly configured).")
except Exception as exc:
    print(f"[run_all] Response worker failed to start: {exc}")
# ---------------------------------------------------------------------------
# JSONL output -- every scored event (from every model) is appended here,
# one JSON object per line, in addition to being printed to the console.
# ---------------------------------------------------------------------------
OUTPUT_DIR = _HERE / "telemetry_output"
OUTPUT_FILE = OUTPUT_DIR / "telemetry_scores.jsonl"
OUTPUT_DIR.mkdir(exist_ok=True)

_write_lock = threading.Lock()

# ---------------------------------------------------------------------------
# P2P Mesh & Peer Voting Subsystem
# ---------------------------------------------------------------------------
_p2p_node = None
if getattr(args, "p2p_port", 0) > 0:
    try:
        from p2p_mesh import P2PMeshNode
        _p2p_node = P2PMeshNode(
            agent_id=getattr(args, "agent_id", "agent-host-local"),
            bind_port=args.p2p_port,
            command_node_url=COMMAND_NODE_URL,
        )
        _p2p_node.start()
        peers_str = getattr(args, "p2p_peers", "") or os.environ.get("P2P_PEERS", "")
        for peer in peers_str.split(","):
            peer = peer.strip()
            if ":" in peer:
                h, p = peer.split(":", 1)
                _p2p_node.register_peer(peer_agent_id=f"peer-{h}", host=h, port=int(p))
        print(
            f"[run_all] P2P Wire Mesh node listening on UDP port {args.p2p_port} (peers: {len(_p2p_node._peers)})")
    except Exception as exc:
        print(f"[run_all] Warning: P2P Wire Mesh start failed: {exc}")

_vote_cooldown: dict = {}
_vote_lock = threading.Lock()
_COOLDOWN_SECONDS = 3.0

EVENT_TYPE_MAP = {
    "cicids": "network",
    "ember": "file",
    "hdfs": "log_line",
    "windows_advanced": "process_windows",
    "windows_advanced_v2": "process_windows",
    "windows_advanced_v3": "process_windows",
    "windows_advanced_v3_candidate": "process_windows",
    "zero_day": "windows_event",
    "linux_ids": "process_linux",
    "linux": "process_linux",
}


def _trigger_peer_voting_async(model: str, score: float, verdict: str, extra: dict):
    """
    Trigger peer voting for MEDIUM, HIGH, and CRITICAL threats (score >= 0.30).
    Applies anti-storm cooldown deduplication, maps canonical event_type,
    and dispatches via P2P mesh or centralized command node coordinator.
    """
    # 1. Deduplication key based on attack signature
    if model == "cicids":
        dedup_target = f"port={extra.get('destination_port', 'any')}"
    elif model == "ember":
        dedup_target = f"sha256={str(extra.get('sha256', extra.get('file_path', 'any')))[:16]}"
    elif model in ("windows_advanced", "windows_advanced_v2", "windows_advanced_v3", "windows_advanced_v3_candidate"):
        dedup_target = f"pid={extra.get('pid', 'any')}:proc={extra.get('process_name', 'any')}"
    elif model == "zero_day":
        dedup_target = f"proc={extra.get('process_name', 'any')}:user={extra.get('user_name', 'any')}"
    elif model in ("linux_ids", "linux"):
        dedup_target = f"pid={extra.get('pid', 'any')}:proc={extra.get('process_name', 'any')}"
    else:
        dedup_target = f"proc={extra.get('process_name', extra.get('file_path', 'any'))}"

    dedup_key = f"{model}:{dedup_target}"
    now = time.time()
    with _vote_lock:
        if dedup_key in _vote_cooldown and (now - _vote_cooldown[dedup_key]) < _COOLDOWN_SECONDS:
            return
        _vote_cooldown[dedup_key] = now
        if len(_vote_cooldown) > 2000:
            cutoff = now - _COOLDOWN_SECONDS
            _vote_cooldown.clear()

    # 2. Canonical event type mapping
    event_type = EVENT_TYPE_MAP.get(model, "process_windows")

    # 3. Canonical details mapping
    details = dict(extra)
    if event_type == "network":
        if "destination_port" in details and "port" not in details:
            details["port"] = details["destination_port"]
        if "ip" in details and "dest_ip" not in details:
            details["dest_ip"] = details["ip"]
    elif event_type in ("process_windows", "process_linux"):
        if "process_name" in details and "process" not in details:
            details["process"] = details["process_name"]
    elif event_type in ("file", "log_line"):
        if "file_path" in details and "filename" not in details:
            details["filename"] = PureWindowsPath(details["file_path"]).name

    vote_id = str(uuid.uuid4())[:8]

    def _dispatch_vote():
        print(
            f"[peer_voting] Triggering peer vote for {model} ({event_type}) threat={score:.3f} [{verdict}] vote_id={vote_id}")
        # A. Dispatch via P2P Mesh if active
        if _p2p_node is not None:
            try:
                _p2p_node.initiate_vote(
                    event_type=event_type,
                    threat_score=score,
                    confidence=1.0,
                    details=details,
                    vote_id=vote_id,
                )
            except Exception as exc:
                print(f"[peer_voting] P2P mesh vote dispatch warning: {exc}")

        # B. Forward to Centralized Voting Hub (with vote_id for deduplication)
        try:
            import urllib.request
            payload = {
                "vote_id": vote_id,
                "origin_agent_id": getattr(args, "agent_id", "agent-host-local"),
                "event_type": event_type,
                "threat_score": score,
                "confidence": 1.0,
                "details": details,
                "pid": extra.get("pid"),
                "target_file": extra.get("file_path") or extra.get("filename"),
            }
            cmd_url = getattr(args, 'command_node_url', os.environ.get('COMMAND_NODE_URL', 'http://127.0.0.1:8000')).rstrip('/')
            req = urllib.request.Request(
                f"{cmd_url}/api/centralized/vote",
                data=json.dumps(payload, default=str).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=2.0)
        except Exception:
            pass

    threading.Thread(target=_dispatch_vote, daemon=True).start()


_last_telemetry_error_time = 0.0
_telemetry_delivered_count = 0


def _post_event_async(event_payload: dict) -> None:
    def _send():
        global _last_telemetry_error_time, _telemetry_delivered_count
        target_url = (
            getattr(args, 'command_node_url', None)
            or os.environ.get('COMMAND_NODE_URL')
            or COMMAND_NODE_URL
        ).rstrip('/')
        try:
            import urllib.request
            req = urllib.request.Request(
                f"{target_url}/api/telemetry",
                data=json.dumps(event_payload, default=str).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if resp.status in (200, 201):
                    _telemetry_delivered_count += 1
                    if _telemetry_delivered_count in (1, 5, 10, 25, 50, 100):
                        print(f"  [+] Shipped telemetry event #{_telemetry_delivered_count} ({event_payload.get('model')}) to Main Server ({target_url})")
        except Exception as exc:
            now = time.time()
            if now - _last_telemetry_error_time > 10.0:
                _last_telemetry_error_time = now
                print(f"  [!] Telemetry delivery to {target_url}/api/telemetry failed: {exc}")
    threading.Thread(target=_send, daemon=True).start()


def save_event(model: str, score: Optional[float], verdict: str, **extra):
    """Append one scored event as a JSON line to telemetry_scores.jsonl and POST to backend API."""
    ts = datetime.now(timezone.utc).isoformat()
    current_agent_id = getattr(args, "agent_id", None) or os.environ.get("AGENT_ID", socket.gethostname())

    # Analytical precision: store exact float or None without destructive rounding
    raw_score = float(score) if score is not None else None

    # Determine explicit score status (available, unavailable, quarantined, shadow, etc.)
    if "status" in extra:
        score_status = extra.pop("status")
    elif extra.get("shadow", False):
        score_status = "shadow"
    elif raw_score is not None:
        score_status = "available"
    elif verdict == "UNAVAILABLE":
        score_status = "unavailable"
    else:
        score_status = "unavailable"

    event = {
        "timestamp": ts,
        "agent_id": current_agent_id,
        "model": model,
        "score": raw_score,
        "score_status": score_status,
        "verdict": verdict,
        **extra,
    }
    line = json.dumps(event, default=str)
    with _write_lock:
        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    # Bridge to backend WebSocket API
    # Distinguish None from 0.0: do NOT coerce None to 0.0
    threat_score = raw_score
    norm_prob = (1.0 - threat_score) if threat_score is not None else None
    proc_name = extra.get("process_name", extra.get("process", extra.get("file_path", model)))
    api_payload = {
        "timestamp": ts,
        "agent_id": current_agent_id,
        "model": model,
        "event_type": model,
        "threat_score": threat_score,
        "score_status": score_status,
        "predicted_class": verdict,
        "verdict": verdict,
        "pid": extra.get("pid", 0),
        "uid": extra.get("uid", 0),
        "process": proc_name,
        "process_name": proc_name,
        "normal_probability": norm_prob,
        "probabilities": {
            "Normal": norm_prob,
            "Threat": threat_score,
        } if threat_score is not None else None,
        **extra,
    }
    _post_event_async(api_payload)

    # Automatically trigger peer voting from the live detection/scoring flow for MEDIUM, HIGH, and CRITICAL threats
    if raw_score is not None and (raw_score >= 0.30 or verdict in ("MEDIUM", "HIGH", "CRITICAL")):
        _trigger_peer_voting_async(model, raw_score, verdict, extra)


print(f"[run_all] Scored events will also be saved to: {OUTPUT_FILE}\n")

# Handles kept at module scope so the shutdown block at the bottom can stop
# whichever collectors actually got started this run.
_running_handles: dict = {}


# ===========================================================================
# 1. Zero-Day -- cross-platform, no setup needed
# ===========================================================================

def start_zero_day() -> None:
    def handle_zeroday_event(
        event_id, process_name, user_name, ip, pid=None
    ):
        score = engine.score_windows_event(
            event_id, process_name, user_name, ip
        )
        if score is None:
            return

        verdict = engine.get_verdict(score)
        print(
            f"[zero_day]   {process_name:<30} "
            f"({user_name}@{ip}) pid={pid} "
            f"-> {score:.3f} ({verdict})"
        )

        save_event(
            "zero_day",
            score,
            verdict,
            pid=pid,
            process_name=process_name,
            user_name=user_name,
            ip=ip,
        )

    zday = ZeroDayEventCollector(on_event=handle_zeroday_event)
    zday.start(poll_interval=2.0)
    _running_handles["zero_day"] = zday


# ===========================================================================
# 2. CICIDS -- scapy-based real packet/byte counts. Cross-platform, but
#    requires Administrator/root + Npcap (Windows) or raw-socket privileges
#    (Linux).
# ===========================================================================

def start_cicids() -> None:
    # Captures all network flows without dropping packets, ensuring 100% full-telemetry visibility.
    net_collector = ScapyFlowCollector(flow_timeout=5.0)
    # raises if scapy/privileges unavailable -- caught by collector_manager
    net_collector.start()
    print("[run_all] CICIDS scapy sniffer started (full capture; intelligent loopback IPC & maturity classification enabled).")
    _running_handles["cicids"] = net_collector

    def network_loop():
        while True:
            for flow in net_collector.pop_completed_flows():
                dest_port = int(flow.get('Destination Port', 0))
                src_ip = str(flow.get('_src_ip', ''))
                dst_ip = str(flow.get('_dst_ip', ''))
                fwd_pkts = float(flow.get('Total Fwd Packets', 0.0))
                bwd_pkts = float(flow.get('Total Backward Packets', 0.0))
                fwd_bytes = float(flow.get('Total Length of Fwd Packets', 0.0))
                bwd_bytes = float(flow.get('Total Length of Bwd Packets', 0.0))
                total_pkts = fwd_pkts + bwd_pkts
                total_bytes = fwd_bytes + bwd_bytes

                is_local = (
                    (src_ip in LOCAL_IPS or src_ip.startswith("127.")) and
                    (dst_ip in LOCAL_IPS or dst_ip.startswith("127."))
                )

                # Check if this flow is AEGIS management traffic (port 8000, 5432, 5173/5174, P2P mesh)
                # whether over 127.0.0.1 loopback OR across a VM/LAN bridge to the central Command Node.
                cmd_url = getattr(args, "command_node_url", "")
                cmd_host = urllib.parse.urlparse(cmd_url).hostname if cmd_url else None
                is_command_node = bool(cmd_host and (dst_ip == cmd_host or src_ip == cmd_host))

                # 1. Internal management, Command Node API & DB traffic
                if dest_port in AEGIS_MANAGEMENT_PORTS or is_command_node or (is_local and dest_port > 49151):
                    score = 0.05
                    verdict = "LOW"
                    flow_type = "INTERNAL_IPC"

                # 2. Incomplete / unestablished control fragments (< 5 packets lack statistical variance for 78 flow features)
                elif total_pkts < 5:
                    score = 0.05
                    verdict = "LOW"
                    flow_type = "CONTROL_FRAGMENT"

                # 3. Established network session or attack payload -> score with CICIDS LightGBM
                else:
                    score = engine.score_network_flow(flow)
                    if score is None:
                        continue
                    verdict = engine.get_verdict(score)
                    flow_type = "NETWORK_FLOW"

                print(f"[cicids]     port={dest_port:<5} [{flow_type:<16}] fwd_pkts={int(fwd_pkts):<4} "
                      f"bwd_pkts={int(bwd_pkts):<4} -> {score:.6f} ({verdict})")
                save_event("cicids", score, verdict, destination_port=dest_port,
                           fwd_packets=fwd_pkts, bwd_packets=bwd_pkts, flow_type=flow_type)
            time.sleep(1.0)

    threading.Thread(target=network_loop, daemon=True).start()


# ===========================================================================
# 3. EMBER -- needs a real folder to watch for new/modified .exe/.dll files.
#    Cross-platform (watchdog), path syntax differs by OS -- adjust
#    PE_WATCH_DIR above for Linux if used there.
# ===========================================================================

def start_ember() -> None:
    def handle_pe_features(pe_features: dict, meta: dict):
        score = engine.score_file(pe_features)
        if score is not None:
            verdict = engine.get_verdict(score)
            fname = PureWindowsPath(meta["file_path"]).name
            print(
                f"[ember]      {fname:<25} sha256={meta['sha256'][:12]}... -> {score:.3f} ({verdict})")
            save_event("ember", score, verdict,
                       file_path=meta["file_path"], sha256=meta["sha256"])

    pe_dir = Path(PE_WATCH_DIR.replace("%USERNAME%", Path.home().name))
    if not pe_dir.exists():
        raise FileNotFoundError(
            f"watch folder does not exist: {pe_dir} "
            f"(create it, or edit PE_WATCH_DIR at the top of this file)"
        )

    pe_collector = PEFileCollector(
        on_new_pe_features=handle_pe_features,
        feature_names=getattr(engine, "_ember_features", None),
    )
    pe_observer = Observer()
    pe_observer.schedule(pe_collector, path=str(pe_dir), recursive=False)
    pe_observer.start()
    print(f"[run_all] EMBER collector watching: {pe_dir}")
    _running_handles["ember"] = pe_observer


# ===========================================================================
# 4. HDFS -- needs a real log file path set in HDFS_LOG_PATH above.
#    Cross-platform (watchdog).
# ===========================================================================

def start_hdfs() -> None:
    def handle_block_text(raw_text: str):
        score = engine.score_log_line(raw_text)
        if score is not None:
            verdict = engine.get_verdict(score)
            print(f"[hdfs]       block scored -> {score:.3f} ({verdict})")
            save_event("hdfs", score, verdict)

    hdfs_path = Path(HDFS_LOG_PATH)
    if not hdfs_path.exists():
        raise FileNotFoundError(
            f"set HDFS_LOG_PATH to a real file (currently: {HDFS_LOG_PATH})"
        )

    hdfs_collector = HDFSLogCollector(on_block_text=handle_block_text)
    hdfs_collector.start_flush_thread()
    hdfs_observer = Observer()
    hdfs_observer.schedule(hdfs_collector, path=str(
        hdfs_path.parent), recursive=False)
    hdfs_observer.start()
    print(f"[run_all] HDFS collector watching: {hdfs_path}")
    _running_handles["hdfs"] = hdfs_observer


# ===========================================================================
# 5. Windows Advanced -- WINDOWS ONLY. Needs Sysmon installed + configured.
#    Download: https://learn.microsoft.com/sysinternals/downloads/sysmon
#    Install:  sysmon64.exe -accepteula -i  (as Administrator)
#    Logs to "Microsoft-Windows-Sysmon/Operational" -- once that exists,
#    WindowsAPICollector reads it automatically. No path to edit here.
#    Never attempted on Linux -- the registry excludes it from that
#    platform's profile, so this function is simply never called there.
# ===========================================================================

def start_windows_advanced() -> None:
    from windows_process_context import WindowsProcessContextAggregator

    aggregator = WindowsProcessContextAggregator()

    def handle_sysmon_event(ev: dict):
        aggregator.process_event(ev)

        # Score process creations in SHADOW MODE
        if ev.get("event_id") == 1:
            guid = ev.get("process_guid")
            if not isinstance(guid, str) or not guid:
                return
            # V2 Shadow Scoring
            feats_v2 = aggregator.get_features(guid)
            if feats_v2 is not None:
                score_v2 = engine.score_windows_v2(feats_v2)
                if score_v2 is not None:
                    threshold_v2 = 0.90
                    if engine._win_v2_payload is not None:
                        threshold_v2 = engine._win_v2_payload.get(
                            "threshold", 0.90)
                    verdict_v2 = "Attack" if score_v2 >= threshold_v2 else "Normal"
                    print(
                        f"[windows_v2_shadow] pid={ev.get('pid')} -> {score_v2:.3f} ({verdict_v2})")
                    save_event(
                        "windows_advanced_v2", score_v2, verdict_v2,
                        model_version="v2",
                        status="shadow",
                        pid=ev.get("pid"),
                        guid=guid,
                        process_name=ev.get("image"),
                        parent_process_name=ev.get("parent_image"),
                        command_line=ev.get("command_line", ""),
                        network_conn_count=feats_v2[5] if len(
                            feats_v2) > 5 else 0.0,
                        features=feats_v2,
                        shadow=True
                    )

            # V3 Shadow Scoring
            feats_v3 = aggregator.get_features_v3(guid)
            if feats_v3 is not None:
                score_v3 = engine.score_windows_v3(feats_v3)
                if score_v3 is not None:
                    threshold_v3 = 0.90
                    if engine._win_v3_payload is not None:
                        threshold_v3 = engine._win_v3_payload.get(
                            "threshold", 0.90)
                    verdict_v3 = "Attack" if score_v3 >= threshold_v3 else "Normal"
                    print(
                        f"[windows_v3_shadow] pid={ev.get('pid')} -> {score_v3:.3f} ({verdict_v3})")
                    save_event(
                        "windows_advanced_v3", score_v3, verdict_v3,
                        model_version="v3",
                        status="shadow",
                        probability_type="raw_xgboost_probability",
                        threshold=threshold_v3,
                        pid=ev.get("pid"),
                        guid=guid,
                        process_name=ev.get("image"),
                        parent_process_name=ev.get("parent_image"),
                        command_line=ev.get("command_line", ""),
                        command_line_length=len(
                            ev.get("command_line", "") or ""),
                        integrity_level=ev.get("integrity_level"),
                        network_conn_count=feats_v3[5] if len(
                            feats_v3) > 5 else 0.0,
                        features=feats_v3,
                        shadow=True
                    )

            # V3 Candidate Shadow Scoring
            feats_cand = aggregator.get_features_v3_candidate(guid)
            if feats_cand is not None:
                score_cand = engine.score_windows_v3_candidate(feats_cand)
                if score_cand is not None:
                    threshold_cand = 0.90
                    if engine._win_v3_candidate_payload is not None:
                        threshold_cand = engine._win_v3_candidate_payload.get(
                            "threshold", 0.90)
                    verdict_cand = "Attack" if score_cand >= threshold_cand else "Normal"
                    print(
                        f"[windows_v3_candidate_shadow] pid={ev.get('pid')} -> {score_cand:.3f} ({verdict_cand})")
                    save_event(
                        "windows_advanced_v3_candidate", score_cand, verdict_cand,
                        model_version="v3_candidate",
                        status="shadow",
                        probability_type="raw_xgboost_probability",
                        threshold=threshold_cand,
                        pid=ev.get("pid"),
                        guid=guid,
                        process_name=ev.get("image"),
                        parent_process_name=ev.get("parent_image"),
                        command_line=ev.get("command_line", ""),
                        command_line_length=len(
                            ev.get("command_line", "") or ""),
                        integrity_level=ev.get("integrity_level"),
                        network_conn_count=feats_cand[5] if len(
                            feats_cand) > 5 else 0.0,
                        features=feats_cand,
                        shadow=True
                    )

    win_collector = WindowsAPICollector(on_sysmon_event=handle_sysmon_event)
    win_collector.start()  # raises RuntimeError internally if not on Windows
    print("[run_all] Windows Advanced collector started (reading Sysmon log).")

    def score_loop():
        while True:
            try:
                for pid in win_collector.get_active_pids():
                    seq = win_collector.get_sequence(pid)
                    if len(seq) >= 5:
                        score = engine.score_process_event(
                            api_call_sequence=seq)
                        if score is not None:
                            verdict = engine.get_verdict(score)
                            print(
                                f"[windows_adv] pid={pid} seq_len={len(seq)} -> {score:.3f} ({verdict})")
                            save_event("windows_advanced", score,
                                       verdict, pid=pid, sequence_len=len(seq))
                        else:
                            print(
                                f"[windows_adv] pid={pid} seq_len={len(seq)} -> UNAVAILABLE (incompatible telemetry)")
                            save_event(
                                "windows_advanced", None, "UNAVAILABLE", pid=pid, sequence_len=len(seq),
                                status="quarantined",
                                reason="training feature representation requires module+offset tokens; live collector provides DLL names"
                            )
            except Exception:
                pass
            time.sleep(2.0)

    threading.Thread(target=score_loop, daemon=True).start()
    _running_handles["windows_advanced"] = win_collector


# ===========================================================================
# 6. Linux IDS -- LINUX ONLY. Uses orchestration.linux_ids_adapter.LinuxIDSAdapter,
#    a thin subclass of the existing linux_collector.LinuxTelemetryCollector
#    (bpftrace-based, system-wide syscall capture). linux_collector.py
#    itself is completely unmodified -- the adapter only overrides
#    run_inference() so results flow through ThreatFusionEngine and land in
#    the shared telemetry_scores.jsonl, same as the other 5 collectors,
#    instead of the original class's console-only, direct-to-model path.
#    Needs bpftrace installed + root/sudo.
# ===========================================================================

def start_linux_ids() -> None:
    from orchestration.linux_ids_adapter import LinuxIDSAdapter

    collector = LinuxIDSAdapter(engine, save_event)
    # start() blocks (reads a subprocess pipe in a loop), so it must run in
    # its own background thread, same pattern as the CICIDS network_loop.
    t = threading.Thread(target=collector.start, daemon=True)
    t.start()
    print("[run_all] Linux IDS collector started (bpftrace syscall capture,")
    print("[run_all]       wired through ThreatFusionEngine via LinuxIDSAdapter).")
    _running_handles["linux_ids"] = collector


# ===========================================================================
# Orchestration -- detect OS, print banner, start only what's compatible
# ===========================================================================

def main():
    print_banner(OS_NAME, PROFILE_NAME, COMPATIBLE_COLLECTORS)

    agent_id = getattr(args, "agent_id", None) or os.environ.get("AGENT_ID", socket.gethostname())
    emitter = None
    stop_agent_event = threading.Event()

    # Cascade shutdown watchdog: monitors main server and terminates agent if server goes down
    watchdog = None
    try:
        from server_monitor import ServerShutdownWatchdog

        def _on_server_shutdown(reason: str):
            print(f"\n[run_all] Main server shutdown cascade ({reason}). Stopping agent...\n", flush=True)
            stop_agent_event.set()

        watchdog = ServerShutdownWatchdog(
            command_node_url=COMMAND_NODE_URL,
            agent_id=agent_id,
            on_server_shutdown=_on_server_shutdown,
        )
        watchdog.start()
        print(f"[run_all] ServerShutdownWatchdog active -> monitoring {COMMAND_NODE_URL}/api/health")
    except Exception as exc:
        print(f"[run_all] Warning: Could not start ServerShutdownWatchdog: {exc}")

    # Start Heartbeat Emitter for silence-as-alarm monitoring
    if not getattr(args, "no_heartbeat", False):
        try:
            from heartbeat import HeartbeatEmitter

            def _send_heartbeat(payload: dict) -> None:
                try:
                    data = json.dumps(payload).encode("utf-8")
                    req = urllib.request.Request(
                        f"{COMMAND_NODE_URL}/api/heartbeat",
                        data=data,
                        headers={"Content-Type": "application/json"},
                    )
                    urllib.request.urlopen(req, timeout=2.0)
                except Exception:
                    pass

            emitter = HeartbeatEmitter(
                agent_id=agent_id,
                interval=float(os.environ.get("HEARTBEAT_INTERVAL", "5.0")),
                send_fn=_send_heartbeat,
            )
            emitter.start()
            print(f"[run_all] HeartbeatEmitter active for '{agent_id}' -> {COMMAND_NODE_URL}/api/heartbeat")
        except Exception as exc:
            print(f"[run_all] Warning: Could not start HeartbeatEmitter: {exc}")

    action_daemon = None
    try:
        from action_consumer import ActionConsumerDaemon

        action_daemon = ActionConsumerDaemon(
            agent_id=agent_id,
            command_node_url=COMMAND_NODE_URL,
            poll_interval=2.0,
        )
        action_daemon.start()
        print(f"[run_all] Autonomous Action Consumer active for '{agent_id}' -> {COMMAND_NODE_URL}/api/agents/{agent_id}/actions/pending")
    except Exception as exc:
        print(f"[run_all] Note: Could not auto-start ActionConsumerDaemon ({exc}).")

    START_FNS = {
        "zero_day": start_zero_day,
        "cicids": start_cicids,
        "ember": start_ember,
        "hdfs": start_hdfs,
        "windows_advanced": start_windows_advanced,
        "linux_ids": start_linux_ids,
    }

    print("Starting telemetry collection...\n")
    results = run_collectors(OS_NAME, START_FNS)

    # ===========================================================================
    # Keep running until user interrupt or server shutdown cascade
    # ===========================================================================

    print("\n[run_all] All available collectors started. Press Ctrl+C to stop.\n")
    try:
        while not stop_agent_event.is_set():
            stop_agent_event.wait(timeout=0.5)
    except KeyboardInterrupt:
        print("\n[run_all] Stopping by user interrupt...")
    finally:
        if watchdog:
            try:
                watchdog.stop()
            except Exception:
                pass

        if emitter:
            try:
                emitter.stop()
                if not stop_agent_event.is_set():
                    # Send graceful departure beacon to Command Node so silence alarms are suppressed
                    shutdown_payload = {
                        "agent_id": agent_id,
                        "status": "OFFLINE_GRACEFUL",
                        "reason": "USER_KEYBOARD_INTERRUPT",
                        "timestamp": time.time(),
                    }
                    req = urllib.request.Request(
                        f"{COMMAND_NODE_URL}/api/heartbeat/shutdown",
                        data=json.dumps(shutdown_payload).encode("utf-8"),
                        headers={"Content-Type": "application/json"},
                    )
                    urllib.request.urlopen(req, timeout=2.0)
                    print(f"[run_all] Graceful shutdown beacon sent for '{agent_id}'.")
            except Exception:
                pass

        if action_daemon:
            try:
                action_daemon.stop()
            except Exception:
                pass

        for name, handle in _running_handles.items():
            stop = getattr(handle, "stop", None)
            if callable(stop):
                try:
                    stop()
                except Exception:
                    pass

        if _p2p_node:
            try:
                _p2p_node.stop()
            except Exception:
                pass

        print("[run_all] Agent shut down cleanly.")
        if stop_agent_event.is_set():
            os._exit(0)


if __name__ == "__main__":
    main()
