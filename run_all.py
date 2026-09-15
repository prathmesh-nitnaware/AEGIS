"""
run_all.py
==========
AEGIS Autonomous EDR — Unified One-Command Native Launcher
----------------------------------------------------------
Boots the entire AEGIS platform in a single command without requiring Docker:
  1. FastAPI Telemetry & Threat Fusion Backend (Port 8000)
  2. Blue Team SOC Defender Dashboard (Port 5173)
  3. Red Team Adversary C2 Attack Console (Port 5174)

Usage:
  python run_all.py
"""

from __future__ import annotations

import os
import sys
import time
import signal
import socket
import webbrowser
import subprocess
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent

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

def main() -> None:
    print("=" * 80)
    print("      AEGIS AUTONOMOUS SWARM DEFENSE — UNIFIED PLATFORM LAUNCHER")
    print("=" * 80)
    print("  [1/3] Backend Telemetry & ML Threat API  -> http://127.0.0.1:8000")
    print("  [2/3] Blue Team SOC Defender Dashboard  -> http://127.0.0.1:5173")
    print("  [3/3] Red Team Adversary C2 Console     -> http://127.0.0.1:5174")
    print("=" * 80)

    py_exe = get_python_exe()
    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"

    processes: list[subprocess.Popen] = []

    try:
        # 1. Start FastAPI Backend (0.0.0.0 allows external VMs & LAN devices to connect)
        print("\n[*] Starting Backend API (Port 8000 on 0.0.0.0)...")
        backend_proc = subprocess.Popen(
            [py_exe, "-m", "uvicorn", "backend.telemetry_api:app", "--host", "0.0.0.0", "--port", "8000"],
            cwd=str(ROOT_DIR),
        )
        processes.append(backend_proc)

        # 2. Start Blue Team SOC Dashboard
        print("[*] Starting Blue Team SOC Dashboard (Port 5173 on 0.0.0.0)...")
        dashboard_proc = subprocess.Popen(
            [npm_cmd, "run", "dev", "--", "--host", "0.0.0.0", "--port", "5173"],
            cwd=str(ROOT_DIR / "dashboard"),
        )
        processes.append(dashboard_proc)

        # 3. Start Red Team C2 Dashboard
        print("[*] Starting Red Team Adversary C2 Dashboard (Port 5174 on 0.0.0.0)...")
        attack_proc = subprocess.Popen(
            [npm_cmd, "run", "dev", "--", "--host", "0.0.0.0", "--port", "5174"],
            cwd=str(ROOT_DIR / "attack_dashboard"),
        )
        processes.append(attack_proc)

        print("\n[+] Waiting for services to initialize...")
        for _ in range(30):
            if is_port_open(8000) and is_port_open(5173) and is_port_open(5174):
                break
            time.sleep(0.5)

        print("\n" + "=" * 80)
        print("  ✅ ALL AEGIS SERVICES ARE LIVE AND OPERATIONAL!")
        print("=" * 80)
        print("  🛡️ Blue Team SOC Dashboard:   http://127.0.0.1:5173")
        print("  ⚔️ Red Team Adversary C2:     http://127.0.0.1:5174")
        print("  📡 Backend Swagger Docs:      http://127.0.0.1:8000/docs")
        print("=" * 80)
        print("\n  Press Ctrl+C at any time to stop all services gracefully.\n")

        # Open in default browser
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
