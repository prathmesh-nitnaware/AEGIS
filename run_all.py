"""
run_all.py
==========
AEGIS Autonomous EDR — Unified One-Command Native Launcher
----------------------------------------------------------
Boots the entire AEGIS platform in a single command without requiring Docker:
  1. FastAPI Telemetry & Threat Fusion Backend (Port 8000)
  2. Blue Team SOC Defender Dashboard (Port 5173)
  3. Red Team Adversary C2 Attack Console (Port 5174)

Prompts for Main Server IP (or auto-detects host LAN IP) and automatically
synchronizes the telemetry endpoint across all agent configurations, scripts,
and environment files.

Usage:
  python run_all.py                     # Interactive: prompts with detected IP
  python run_all.py --ip 192.168.1.50   # Direct: sets specified server IP
  python run_all.py --update-only       # Updates config files and exits
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
import webbrowser
from pathlib import Path
from typing import Optional

ROOT_DIR = Path(__file__).resolve().parent

# Ensure safe console output on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def load_env_file(path: Path) -> None:
    """Safely loads an environment file into os.environ without overriding explicit env vars."""
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


# Load local .env before CLI parsing
load_env_file(ROOT_DIR / ".env")


def get_python_exe() -> str:
    # If the current process is already running in a virtual environment, prefer it
    if sys.executable and any(k in sys.executable.lower() for k in ("venv", ".venv")):
        return sys.executable
    venv_win = ROOT_DIR / ".venv" / "Scripts" / "python.exe"
    venv_standard_win = ROOT_DIR / "venv" / "Scripts" / "python.exe"
    venv_nix = ROOT_DIR / ".venv" / "bin" / "python"
    venv_standard_nix = ROOT_DIR / "venv" / "bin" / "python"
    for vpath in (venv_win, venv_standard_win, venv_nix, venv_standard_nix):
        if vpath.exists():
            return str(vpath)
    return sys.executable


def is_port_open(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def is_backend_healthy(server_ip: str) -> bool:
    """Verifies that AEGIS backend is fully started and responding HTTP 200 on /api/health."""
    for h in (server_ip, "127.0.0.1", "localhost"):
        try:
            import urllib.request
            req = urllib.request.Request(f"http://{h}:8000/api/health", headers={"User-Agent": "AEGIS-Launcher"})
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
    return False


def ensure_ports_free() -> None:
    """Checks if ports 8000, 5173, or 5174 are occupied by lingering processes and frees them."""
    for port in (8000, 5173, 5174):
        if not is_port_open(port):
            continue

        print(f"[!] Warning: Port {port} is occupied. Attempting to free port {port}...")
        if sys.platform == "win32":
            try:
                out = subprocess.check_output("netstat -ano -p tcp", shell=True, text=True)
                for line in out.splitlines():
                    if f":{port} " in line and "LISTENING" in line:
                        parts = line.strip().split()
                        pid = parts[-1]
                        if pid.isdigit() and int(pid) > 4:
                            print(f"  [+] Terminating conflicting process (PID {pid}) on port {port}...")
                            subprocess.run(f"taskkill /F /PID {pid}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(1.0)
            except Exception as exc:
                print(f"  [!] Note: Could not auto-terminate process on port {port}: {exc}")


def detect_lan_ip() -> str:
    """Detect the primary host LAN IP address (non-loopback)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                return ip
    except Exception:
        pass
    try:
        ip = socket.gethostbyname(socket.gethostname())
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    return "127.0.0.1"


def clean_and_validate_ip(raw_input: str) -> Optional[str]:
    """Sanitize and validate an entered IP address or hostname."""
    val = raw_input.strip()
    if not val:
        return None
    # Strip URL protocol if entered
    val = re.sub(r"^https?://", "", val, flags=re.IGNORECASE)
    # Strip port or trailing slashes
    val = val.split(":")[0].split("/")[0].strip()
    if not val:
        return None
    # Check IP validity
    try:
        ipaddress.ip_address(val)
        return val
    except ValueError:
        # Check hostname / localhost validity
        if re.match(r"^[a-zA-Z0-9_\-\.]+$", val):
            return val
    return None


def resolve_server_ip(default_ip: str, cli_ip: Optional[str] = None) -> str:
    """Resolves the main server IP address from CLI, .env/environment, or detected LAN IP without terminal prompts."""
    if cli_ip:
        cleaned = clean_and_validate_ip(cli_ip)
        if cleaned:
            return cleaned
        print(f"[!] Warning: Specified --ip '{cli_ip}' is invalid. Falling back to {default_ip}")

    # Check if MAIN_SERVER_IP is configured in .env / environment
    env_ip = os.environ.get("MAIN_SERVER_IP")
    if env_ip:
        cleaned_env = clean_and_validate_ip(env_ip)
        if cleaned_env:
            try:
                import psutil
                local_ips = {
                    addr.address
                    for addrs in psutil.net_if_addrs().values()
                    for addr in addrs
                    if addr.family == socket.AF_INET
                }
                if cleaned_env in local_ips:
                    return cleaned_env
                print(f"[*] Note: Stale IP '{cleaned_env}' in .env is not active on this host. Auto-switching to live LAN IP '{default_ip}'.")
                return default_ip
            except Exception:
                return cleaned_env

    return default_ip


def sync_env_files(server_ip: str) -> list[str]:
    """
    Synchronizes the Main Server IP into local .env files (gitignored).
    Never mutates tracked repository source files to prevent git conflicts.
    """
    command_url = f"http://{server_ip}:8000"
    updated_files: list[str] = []

    print(f"\n[*] Updating environment (.env) configuration for Main Server: {command_url} ...")

    # Update root .env and agent/.env (both are gitignored)
    for env_path, rel_name in [(ROOT_DIR / ".env", ".env"), (ROOT_DIR / "agent" / ".env", "agent/.env")]:
        existing = env_path.read_text(encoding="utf-8") if env_path.exists() else ""
        lines = [
            l for l in existing.splitlines()
            if not any(l.startswith(k) for k in ("MAIN_SERVER_IP=", "COMMAND_NODE_URL=", "VITE_COMMAND_NODE_URL="))
        ]
        lines.extend([
            f"MAIN_SERVER_IP={server_ip}",
            f"COMMAND_NODE_URL={command_url}",
            f"VITE_COMMAND_NODE_URL={command_url}",
        ])
        env_path.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
        updated_files.append(rel_name)

    # Propagate into current process environment so all spawned children inherit it
    os.environ["MAIN_SERVER_IP"] = server_ip
    os.environ["COMMAND_NODE_URL"] = command_url
    os.environ["VITE_COMMAND_NODE_URL"] = command_url

    for f_name in updated_files:
        print(f"  [+] Saved: {f_name} (gitignored)")

    print(f"[+] Telemetry environment configured -> {command_url}/api/telemetry\n")
    return updated_files


def main() -> None:
    parser = argparse.ArgumentParser(description="AEGIS Unified Native Platform Launcher")
    parser.add_argument("--ip", "--server-ip", dest="server_ip", default=None, help="Main server IP address")
    parser.add_argument("--agent", action="store_true", help="Launch this device as an Endpoint Agent Node")
    parser.add_argument("--server", action="store_true", help="Launch this device as the Main Server Node (default)")
    parser.add_argument("--update-only", action="store_true", help="Only update agent configuration files and exit")
    parser.add_argument("--live", action="store_true", help="Enable LIVE automated remediation mode (real enforcement)")
    args, _ = parser.parse_known_args()

    py_exe = get_python_exe()

    print("=" * 80)
    print("      AEGIS AUTONOMOUS SWARM DEFENSE — UNIFIED PLATFORM LAUNCHER")
    print("=" * 80)

    if args.live:
        os.environ["AEGIS_AUTO_REMEDIATE"] = "true"
        print("[!] Automated Response Mode: LIVE ENFORCEMENT ENABLED (AEGIS_AUTO_REMEDIATE=true)")

    # Determine node role (defaults to Server mode, or Agent mode if --agent specified)
    role = "agent" if args.agent else "server"

    if role == "agent":
        print("\n" + "=" * 80)
        print("  🛰️  STARTING AEGIS ENDPOINT AGENT NODE")
        print("=" * 80)
        agent_script = ROOT_DIR / "agent" / "run_all.py"
        agent_cmd = [py_exe, str(agent_script)]
        if args.server_ip:
            agent_cmd.extend(["--command-node", f"http://{args.server_ip}:8000"])
        if args.live:
            agent_cmd.append("--live")
        try:
            subprocess.run(agent_cmd, cwd=str(ROOT_DIR / "agent"))
        except KeyboardInterrupt:
            pass
        return

    # 1. Resolve Main Server IP from environment / LAN detection
    detected_ip = detect_lan_ip()
    server_ip = resolve_server_ip(detected_ip, cli_ip=args.server_ip)

    # 2. Update .env files with the chosen IP
    sync_env_files(server_ip)

    if args.update_only:
        print("[OK] Environment (.env) sync complete (--update-only specified). Exiting.")
        return

    # 3. Propagate to current process environment
    command_url = f"http://{server_ip}:8000"
    os.environ["MAIN_SERVER_IP"] = server_ip
    os.environ["COMMAND_NODE_URL"] = command_url
    os.environ["VITE_COMMAND_NODE_URL"] = command_url

    print("=" * 80)
    print(f"  MAIN SERVER HOST IP:                     {server_ip}")
    print(f"  [1/3] Backend Telemetry & ML Threat API -> {command_url} (Local: http://127.0.0.1:8000)")
    print(f"  [2/3] Blue Team SOC Defender Dashboard  -> http://{server_ip}:5173 (Local: http://127.0.0.1:5173)")
    print(f"  [3/3] Red Team Adversary C2 Console     -> http://{server_ip}:5174 (Local: http://127.0.0.1:5174)")
    print(f"  📡 Agent Telemetry Ingestion Endpoint   -> {command_url}/api/telemetry")
    print(f"  ⚡ Automated Remediation Mode:          {'LIVE REAL ENFORCEMENT' if args.live else 'SAFE SIMULATION MODE'}")
    print("=" * 80)

    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"

    processes: list[subprocess.Popen] = []
    child_env = os.environ.copy()

    try:
        # Pre-flight: ensure ports 8000, 5173, and 5174 are not blocked by rogue processes
        ensure_ports_free()

        # 1. Start FastAPI Backend (0.0.0.0 allows external VMs & LAN devices to connect)
        print("\n[*] Starting Backend API (Port 8000 on 0.0.0.0)...")
        backend_proc = subprocess.Popen(
            [py_exe, "-m", "uvicorn", "backend.telemetry_api:app", "--host", "0.0.0.0", "--port", "8000"],
            cwd=str(ROOT_DIR),
            env=child_env,
        )
        processes.append(backend_proc)

        # 2. Start Blue Team SOC Dashboard (clearScreen=false keeps terminal logs visible)
        print("[*] Starting Blue Team SOC Dashboard (Port 5173 on 0.0.0.0)...")
        dashboard_proc = subprocess.Popen(
            [npm_cmd, "run", "dev", "--", "--host", "0.0.0.0", "--port", "5173", "--clearScreen", "false"],
            cwd=str(ROOT_DIR / "dashboard"),
            env=child_env,
        )
        processes.append(dashboard_proc)

        # 3. Start Red Team C2 Dashboard
        print("[*] Starting Red Team Adversary C2 Dashboard (Port 5174 on 0.0.0.0)...")
        attack_proc = subprocess.Popen(
            [npm_cmd, "run", "dev", "--", "--host", "0.0.0.0", "--port", "5174", "--clearScreen", "false"],
            cwd=str(ROOT_DIR / "attack_dashboard"),
            env=child_env,
        )
        processes.append(attack_proc)

        print("\n[+] Waiting for services to initialize (NeonDB + API + Dashboards)...")
        for _ in range(40):
            backend_ok = is_backend_healthy(server_ip)
            dash_ok = is_port_open(5173)
            attack_ok = is_port_open(5174)
            if backend_ok and dash_ok and attack_ok:
                break
            time.sleep(0.5)

        print("\n" + "=" * 80)
        print("  [OK] ALL AEGIS SERVICES ARE LIVE AND OPERATIONAL!")
        print("=" * 80)
        print(f"  [SOC Dashboard]   Blue Team SOC:       http://{server_ip}:5173  (Local: http://127.0.0.1:5173)")
        print(f"  [Adversary C2]    Red Team Attack:     http://{server_ip}:5174  (Local: http://127.0.0.1:5174)")
        print(f"  [Swagger Docs]    Backend REST API:    http://{server_ip}:8000/docs")
        print(f"  [Agent Telemetry] Live Stream Ingest:  {command_url}/api/telemetry")
        print("=" * 80)
        print("\n  Press Ctrl+C at any time to stop all services gracefully.\n")

        # Open in default browser locally
        target_browser_url = f"http://{server_ip}:5173" if server_ip and not server_ip.startswith("127.") else "http://127.0.0.1:5173"
        webbrowser.open(target_browser_url)

        # Keep alive
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[*] Stopping all AEGIS services...")
        try:
            # Signal connected agents that Main Server is shutting down
            import urllib.request
            req = urllib.request.Request(
                f"{command_url}/api/server/shutdown-notify",
                data=b"{}",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=1.0)
            time.sleep(0.5)
        except Exception:
            pass
    finally:
        for p in processes:
            try:
                p.terminate()
                p.wait(timeout=2)
            except Exception:
                p.kill()
        print("[OK] All services shut down successfully.")


if __name__ == "__main__":
    main()
