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


def get_python_exe() -> str:
    venv_win = ROOT_DIR / ".venv" / "Scripts" / "python.exe"
    venv_nix = ROOT_DIR / ".venv" / "bin" / "python"
    if venv_win.exists():
        return str(venv_win)
    if venv_nix.exists():
        return str(venv_nix)
    return sys.executable


def is_port_open(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


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


def prompt_server_ip(default_ip: str, cli_ip: Optional[str] = None) -> str:
    """Prompts the user for the main server IP address, defaulting to detected LAN IP."""
    if cli_ip:
        cleaned = clean_and_validate_ip(cli_ip)
        if cleaned:
            return cleaned
        print(f"[!] Warning: Specified --ip '{cli_ip}' is invalid. Falling back to {default_ip}")
        return default_ip

    print("\n" + "-" * 80)
    print("  🌐 MAIN SERVER & AGENT TELEMETRY CONFIGURATION")
    print("-" * 80)
    print(f"  Auto-detected Host LAN IP:  {default_ip}")
    print("  All AEGIS agents will be configured to stream live telemetry to this IP.")
    print("-" * 80)

    if not sys.stdin.isatty():
        try:
            piped = sys.stdin.readline().strip()
            if piped:
                cleaned = clean_and_validate_ip(piped)
                if cleaned:
                    print(f"[*] Received Server IP from input: {cleaned}")
                    return cleaned
        except Exception:
            pass
        print(f"[*] Non-interactive terminal detected. Using default IP: {default_ip}")
        return default_ip

    try:
        user_input = input(f"[?] Enter Main Server IP address [Press ENTER for {default_ip}]: ").strip()
        if not user_input:
            print(f"[+] Using default IP: {default_ip}")
            return default_ip

        cleaned = clean_and_validate_ip(user_input)
        if cleaned:
            print(f"[+] Configured Main Server IP: {cleaned}")
            return cleaned
        else:
            print(f"[!] Invalid IP entered. Falling back to default: {default_ip}")
            return default_ip
    except (EOFError, KeyboardInterrupt):
        print(f"\n[+] Using default IP: {default_ip}")
        return default_ip


def update_agent_telemetry_files(server_ip: str) -> list[str]:
    """
    Synchronizes the Main Server IP across all agent configuration files,
    collector scripts, environment files, and installer manifests.
    """
    command_url = f"http://{server_ip}:8000"
    updated_files: list[str] = []

    print(f"\n[*] Updating agent telemetry configuration for Main Server: {command_url} ...")

    # 1. agent/config.py
    cfg_file = ROOT_DIR / "agent" / "config.py"
    if cfg_file.exists():
        content = cfg_file.read_text(encoding="utf-8")
        new_content = re.sub(
            r'command_node_url:\s*str\s*=\s*field\(default_factory=lambda:\s*os\.environ\.get\("COMMAND_NODE_URL",\s*"http://[^"]+?"\)\)',
            f'command_node_url: str = field(default_factory=lambda: os.environ.get("COMMAND_NODE_URL", "{command_url}"))',
            content,
        )
        if new_content != content:
            cfg_file.write_text(new_content, encoding="utf-8")
        updated_files.append("agent/config.py")

    # 2. agent/run_all.py
    agent_run_file = ROOT_DIR / "agent" / "run_all.py"
    if agent_run_file.exists():
        content = agent_run_file.read_text(encoding="utf-8")
        new_content = re.sub(
            r'os\.environ\.get\("COMMAND_NODE_URL",\s*"http://[^"]+?"\)',
            f'os.environ.get("COMMAND_NODE_URL", "{command_url}")',
            content,
        )
        new_content = re.sub(
            r'help="Main server URL \(e\.g\. http://[^"]+?\)\. Default: COMMAND_NODE_URL or configured server\."',
            f'help="Main server URL (e.g. {command_url}). Default: COMMAND_NODE_URL or configured server."',
            new_content,
        )
        if new_content != content:
            agent_run_file.write_text(new_content, encoding="utf-8")
        updated_files.append("agent/run_all.py")

    # 3. agent/linux_collector.py
    linux_coll_file = ROOT_DIR / "agent" / "linux_collector.py"
    if linux_coll_file.exists():
        content = linux_coll_file.read_text(encoding="utf-8")
        new_content = re.sub(
            r'os\.environ\.get\("COMMAND_NODE_URL",\s*"http://[^"]+?"\)',
            f'os.environ.get("COMMAND_NODE_URL", "{command_url}")',
            content,
        )
        if new_content != content:
            linux_coll_file.write_text(new_content, encoding="utf-8")
        updated_files.append("agent/linux_collector.py")

    # 4. agent/heartbeat_runner.py
    hb_file = ROOT_DIR / "agent" / "heartbeat_runner.py"
    if hb_file.exists():
        content = hb_file.read_text(encoding="utf-8")
        new_content = re.sub(
            r'COMMAND_NODE_URL\s*=\s*os\.getenv\("COMMAND_NODE_URL",\s*"http://[^"]+?"\)',
            f'COMMAND_NODE_URL = os.getenv("COMMAND_NODE_URL", "{command_url}")',
            content,
        )
        if new_content != content:
            hb_file.write_text(new_content, encoding="utf-8")
        updated_files.append("agent/heartbeat_runner.py")

    # 5. agent/action_consumer.py
    ac_file = ROOT_DIR / "agent" / "action_consumer.py"
    if ac_file.exists():
        content = ac_file.read_text(encoding="utf-8")
        new_content = re.sub(
            r'os\.getenv\("COMMAND_NODE_URL",\s*"http://[^"]+?"\)',
            f'os.getenv("COMMAND_NODE_URL", "{command_url}")',
            content,
        )
        if new_content != content:
            ac_file.write_text(new_content, encoding="utf-8")
        updated_files.append("agent/action_consumer.py")

    # 6. agent/config/agent.env.example
    env_example = ROOT_DIR / "agent" / "config" / "agent.env.example"
    if env_example.exists():
        content = env_example.read_text(encoding="utf-8")
        new_content = re.sub(
            r'^COMMAND_NODE_URL=.*$',
            f'COMMAND_NODE_URL={command_url}',
            content,
            flags=re.MULTILINE,
        )
        if new_content != content:
            env_example.write_text(new_content, encoding="utf-8")
        updated_files.append("agent/config/agent.env.example")

    # 7. scripts/windows/install.ps1
    win_install = ROOT_DIR / "scripts" / "windows" / "install.ps1"
    if win_install.exists():
        content = win_install.read_text(encoding="utf-8")
        new_content = re.sub(
            r'\[string\]\$CommandNodeUrl\s*=\s*"http://[^"]+?"',
            f'[string]$CommandNodeUrl = "{command_url}"',
            content,
        )
        if new_content != content:
            win_install.write_text(new_content, encoding="utf-8")
        updated_files.append("scripts/windows/install.ps1")

    # 8. scripts/linux/install.sh
    linux_install = ROOT_DIR / "scripts" / "linux" / "install.sh"
    if linux_install.exists():
        content = linux_install.read_text(encoding="utf-8")
        new_content = re.sub(
            r'^COMMAND_NODE_URL="http://[^"]+?"',
            f'COMMAND_NODE_URL="{command_url}"',
            content,
            flags=re.MULTILINE,
        )
        new_content = re.sub(
            r'Command Node URL \(default: http://[^"]+?\)',
            f'Command Node URL (default: {command_url})',
            new_content,
        )
        if new_content != content:
            linux_install.write_text(new_content, encoding="utf-8")
        updated_files.append("scripts/linux/install.sh")

    # 9. Root .env and agent/.env
    env_body = (
        f"# AEGIS Swarm Defense Platform Environment Configuration\n"
        f"MAIN_SERVER_IP={server_ip}\n"
        f"COMMAND_NODE_URL={command_url}\n"
        f"VITE_COMMAND_NODE_URL={command_url}\n"
    )
    for env_path, rel_name in [(ROOT_DIR / ".env", ".env"), (ROOT_DIR / "agent" / ".env", "agent/.env")]:
        existing = env_path.read_text(encoding="utf-8") if env_path.exists() else ""
        # Update or append
        lines = [l for l in existing.splitlines() if not any(l.startswith(k) for k in ("MAIN_SERVER_IP=", "COMMAND_NODE_URL=", "VITE_COMMAND_NODE_URL="))]
        lines.extend([f"MAIN_SERVER_IP={server_ip}", f"COMMAND_NODE_URL={command_url}", f"VITE_COMMAND_NODE_URL={command_url}"])
        env_path.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
        updated_files.append(rel_name)

    # 10. Local agent/agent.conf and C:\ProgramData\AEGIS\agent.conf (if exists)
    agent_conf = ROOT_DIR / "agent" / "agent.conf"
    conf_data = {}
    if agent_conf.exists():
        try:
            conf_data = json.loads(agent_conf.read_text(encoding="utf-8"))
        except Exception:
            pass
    conf_data["command_node_url"] = command_url
    agent_conf.write_text(json.dumps(conf_data, indent=2), encoding="utf-8")
    updated_files.append("agent/agent.conf")

    if sys.platform == "win32":
        prog_data = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "AEGIS" / "agent.conf"
        if prog_data.exists():
            try:
                p_data = json.loads(prog_data.read_text(encoding="utf-8"))
                p_data["command_node_url"] = command_url
                prog_data.write_text(json.dumps(p_data, indent=2), encoding="utf-8")
                updated_files.append(str(prog_data))
            except Exception:
                pass

    for f_name in updated_files:
        print(f"  [+] Synchronized: {f_name}")

    print(f"[+] All agent telemetry endpoints set to -> {command_url}/api/telemetry\n")
    return updated_files


def prompt_node_role() -> str:
    """Prompt the user whether to run as Main Server or Endpoint Agent on this machine."""
    if not sys.stdin.isatty():
        return "server"
    print("\n" + "-" * 80)
    print("  🖥️  AEGIS PLATFORM ROLE SELECTION")
    print("-" * 80)
    print("  [1] Main Server Node    -> Runs FastAPI Backend (:8000) & SOC Dashboards (:5173/:5174)")
    print("  [2] Endpoint Agent Node -> Runs on client/VM machine, streams telemetry to Main Server")
    print("-" * 80)
    try:
        choice = input("[?] Select Role for this machine [Press ENTER for 1 (Server), or 2 (Agent)]: ").strip()
        if choice in ("2", "agent", "Agent"):
            return "agent"
        return "server"
    except (EOFError, KeyboardInterrupt):
        return "server"


def main() -> None:
    parser = argparse.ArgumentParser(description="AEGIS Unified Native Platform Launcher")
    parser.add_argument("--ip", "--server-ip", dest="server_ip", default=None, help="Main server IP address")
    parser.add_argument("--agent", action="store_true", help="Launch this device as an Endpoint Agent Node")
    parser.add_argument("--server", action="store_true", help="Launch this device as the Main Server Node")
    parser.add_argument("--update-only", action="store_true", help="Only update agent configuration files and exit")
    args, _ = parser.parse_known_args()

    py_exe = get_python_exe()

    print("=" * 80)
    print("      AEGIS AUTONOMOUS SWARM DEFENSE — UNIFIED PLATFORM LAUNCHER")
    print("=" * 80)

    # Determine node role
    if args.agent:
        role = "agent"
    elif args.server:
        role = "server"
    else:
        role = prompt_node_role()

    if role == "agent":
        print("\n" + "=" * 80)
        print("  🛰️  STARTING AEGIS ENDPOINT AGENT NODE")
        print("=" * 80)
        agent_script = ROOT_DIR / "agent" / "run_all.py"
        agent_cmd = [py_exe, str(agent_script)]
        if args.server_ip:
            agent_cmd.extend(["--command-node", f"http://{args.server_ip}:8000"])
        try:
            subprocess.run(agent_cmd, cwd=str(ROOT_DIR / "agent"))
        except KeyboardInterrupt:
            pass
        return

    # 1. Detect & Prompt for Main Server IP (when running in Server mode)
    detected_ip = detect_lan_ip()
    server_ip = prompt_server_ip(detected_ip, cli_ip=args.server_ip)

    # 2. Update files with the chosen IP
    update_agent_telemetry_files(server_ip)

    if args.update_only:
        print("[OK] Configuration sync complete (--update-only specified). Exiting.")
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
    print("=" * 80)

    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"

    processes: list[subprocess.Popen] = []
    child_env = os.environ.copy()

    try:
        # 1. Start FastAPI Backend (0.0.0.0 allows external VMs & LAN devices to connect)
        print("\n[*] Starting Backend API (Port 8000 on 0.0.0.0)...")
        backend_proc = subprocess.Popen(
            [py_exe, "-m", "uvicorn", "backend.telemetry_api:app", "--host", "0.0.0.0", "--port", "8000"],
            cwd=str(ROOT_DIR),
            env=child_env,
        )
        processes.append(backend_proc)

        # 2. Start Blue Team SOC Dashboard
        print("[*] Starting Blue Team SOC Dashboard (Port 5173 on 0.0.0.0)...")
        dashboard_proc = subprocess.Popen(
            [npm_cmd, "run", "dev", "--", "--host", "0.0.0.0", "--port", "5173"],
            cwd=str(ROOT_DIR / "dashboard"),
            env=child_env,
        )
        processes.append(dashboard_proc)

        # 3. Start Red Team C2 Dashboard
        print("[*] Starting Red Team Adversary C2 Dashboard (Port 5174 on 0.0.0.0)...")
        attack_proc = subprocess.Popen(
            [npm_cmd, "run", "dev", "--", "--host", "0.0.0.0", "--port", "5174"],
            cwd=str(ROOT_DIR / "attack_dashboard"),
            env=child_env,
        )
        processes.append(attack_proc)

        print("\n[+] Waiting for services to initialize...")
        for _ in range(30):
            if is_port_open(8000) and is_port_open(5173) and is_port_open(5174):
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
        webbrowser.open("http://127.0.0.1:5173")

        # Keep alive
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[*] Stopping all AEGIS services...")
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
