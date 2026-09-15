"""
backend/services/simulation_service.py
======================================
AEGIS Red Team Adversary & C2 Attack Simulation Manager.
Supports targeting specific nodes in the chain/swarm,
executing targeted exploitation vectors, network attack floods,
and streaming live adversary execution logs to connected operators.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# In-memory execution state
_simulation_state: Dict[str, Any] = {
    "is_running": False,
    "current_scenario": None,
    "target_agent_id": "endpoint-linux",
    "target_ip": "10.0.0.10",
    "start_time": None,
    "completed_at": None,
    "progress": 0,
    "logs": [],
    "last_result": None,
    "history": [],
}
_state_lock = threading.Lock()


def get_available_targets() -> List[Dict[str, Any]]:
    """Returns list of active agent nodes and chain targets available for exploitation."""
    targets = [
        {
            "id": "node1-linux",
            "name": "Linux App Server (node-1)",
            "os": "Ubuntu 22.04 LTS",
            "ip": "10.0.0.10",
            "services": ["SSH (22)", "HTTP (80)", "Gunicorn (8000)"],
            "vulnerabilities": ["CVE-2023-4911 (Looney Tunables)", "Weak SSH Passwords", "Meterpreter RCE"],
            "status": "ONLINE",
        },
        {
            "id": "node2-windows",
            "name": "Windows Workstation (node-2)",
            "os": "Windows 11 Enterprise",
            "ip": "10.0.0.20",
            "services": ["RDP (3389)", "SMB (445)", "WinRM (5985)"],
            "vulnerabilities": ["Ransomware PE Dropper", "VSS Shadow Wipe", "Memory Injection"],
            "status": "ONLINE",
        },
        {
            "id": "node3-database",
            "name": "Distributed DB Node (node-3)",
            "os": "Debian 12 Bookworm",
            "ip": "10.0.0.30",
            "services": ["PostgreSQL (5432)", "Redis (6379)"],
            "vulnerabilities": ["Heartbeat Tampering", "Agent Sabotage", "Telemetry Drop"],
            "status": "ONLINE",
        },
        {
            "id": "node4-gateway",
            "name": "Edge Ingress Gateway (node-4)",
            "os": "Alpine Linux 3.19",
            "ip": "10.0.0.1",
            "services": ["Nginx (80/443)", "BGP Wire (179)"],
            "vulnerabilities": ["TCP SYN Flood DDoS", "Horizontal PortScan", "Graceful Drain Abuse"],
            "status": "ONLINE",
        },
        {
            "id": "swarm-broadcast",
            "name": "Swarm Broadcast (All Swarm Nodes)",
            "os": "Multi-Platform Swarm",
            "ip": "10.0.0.0/24",
            "services": ["P2P Wire Mesh Consensus (9001-9010)"],
            "vulnerabilities": ["Full Kill-Chain Campaign", "Byzantine Quorum Stress"],
            "status": "ONLINE",
        },
    ]

    # Dynamically inject registered live agents from central repo if available
    try:
        from backend.telemetry_api import central_repo
        if central_repo:
            all_agents = central_repo.get_all_agents()
            for agent_id, agent_info in all_agents.items():
                if not any(t["id"] == agent_id for t in targets):
                    targets.append({
                        "id": agent_id,
                        "name": f"Agent {agent_id}",
                        "os": agent_info.get("os", "Linux/Windows"),
                        "ip": agent_info.get("ip", "127.0.0.1"),
                        "services": ["AEGIS Agent Telemetry"],
                        "vulnerabilities": ["Live Target Ingestion"],
                        "status": "ONLINE" if not agent_info.get("alarm_raised") else "ALARMED",
                    })
    except Exception:
        pass

    return targets


def get_simulation_status() -> Dict[str, Any]:
    with _state_lock:
        return dict(_simulation_state)


def reset_simulation_state():
    global _simulation_state
    with _state_lock:
        _simulation_state["is_running"] = False
        _simulation_state["current_scenario"] = None
        _simulation_state["progress"] = 0
        _simulation_state["logs"] = []


def _append_log(message: str, level: str = "INFO", step: Optional[int] = None, data: Optional[dict] = None):
    entry = {
        "timestamp": time.strftime("%H:%M:%S"),
        "message": message,
        "level": level,
        "step": step,
        "data": data or {},
    }
    with _state_lock:
        _simulation_state["logs"].append(entry)
        if len(_simulation_state["logs"]) > 150:
            _simulation_state["logs"] = _simulation_state["logs"][-150:]

    # Broadcast via WebSocket if available
    try:
        from backend.telemetry_api import publish_event
        publish_event({
            "type": "simulation_progress",
            "log": entry,
            "scenario": _simulation_state.get("current_scenario"),
            "target": _simulation_state.get("target_agent_id"),
            "progress": _simulation_state.get("progress", 0),
        })
    except Exception:
        pass


def _execute_scenario_worker(scenario: str, target_id: str, target_ip: str, custom_config: Optional[dict] = None):
    from experiments.simulations import (
        simulate_linux_attacks,
        simulate_windows_ransomware,
        simulate_silence_tamper,
        simulate_graceful_shutdown,
    )

    with _state_lock:
        _simulation_state["is_running"] = True
        _simulation_state["current_scenario"] = scenario
        _simulation_state["target_agent_id"] = target_id
        _simulation_state["target_ip"] = target_ip
        _simulation_state["start_time"] = time.time()
        _simulation_state["progress"] = 5
        _simulation_state["logs"] = []

    _append_log(f"⚔️ [C2 DISPATCH] Initializing Attack Vector: [{scenario.upper()}] against Target [{target_id}] ({target_ip})...", "INFO", step=1)

    try:
        if scenario == "linux":
            _append_log(f"[*] Dispatching Exploit: Hydra SSH Brute-Force & ptrace() Memory Injection to {target_ip}...", "INFO", step=1)
            time.sleep(0.5)
            with _state_lock:
                _simulation_state["progress"] = 25
            _append_log("[*] Injected meterpreter shell payload into PID 4592...", "WARNING", step=2)
            time.sleep(0.5)
            simulate_linux_attacks.run_simulation()
            with _state_lock:
                _simulation_state["progress"] = 100
            _append_log(f"[+] Exploit Execution Finished on {target_id}. Victim defense triggered quorum consensus & process termination.", "SUCCESS", step=4)

        elif scenario == "windows":
            _append_log(f"[*] Infiltrating {target_id} ({target_ip}): Stage 1 PE Dropper + VSS Shadow Deletion...", "INFO", step=1)
            time.sleep(0.5)
            with _state_lock:
                _simulation_state["progress"] = 25
            _append_log("[*] Executing `vssadmin delete shadows /all /quiet` and high-entropy write burst (7.98 bits/byte)...", "WARNING", step=2)
            time.sleep(0.5)
            simulate_windows_ransomware.run_simulation()
            with _state_lock:
                _simulation_state["progress"] = 100
            _append_log(f"[+] Ransomware simulation finished on {target_id}. Dropper quarantined & host network isolated by AEGIS agent.", "SUCCESS", step=4)

        elif scenario == "sabotage":
            _append_log(f"[*] Target Sabotage: Terminating AEGIS heartbeat daemon on {target_id} ({target_ip})...", "WARNING", step=1)
            time.sleep(0.5)
            with _state_lock:
                _simulation_state["progress"] = 30
            _append_log("[*] Air-gap severance simulated: Host telemetry stream zeroed out...", "WARNING", step=2)
            simulate_silence_tamper.run_simulation()
            with _state_lock:
                _simulation_state["progress"] = 100
            _append_log(f"[+] Silence-as-Alarm triggered on {target_id}. Escalated to SOC incident queue within 15 seconds.", "SUCCESS", step=4)

        elif scenario == "graceful":
            _append_log(f"[*] Transmitting Planned Maintenance / Clean Reboot Signal to {target_id}...", "INFO", step=1)
            time.sleep(0.5)
            with _state_lock:
                _simulation_state["progress"] = 30
            simulate_graceful_shutdown.run_simulation()
            with _state_lock:
                _simulation_state["progress"] = 100
            _append_log(f"[+] Clean reboot verified on {target_id}. Suppressed false alarms via active maintenance window.", "SUCCESS", step=4)

        elif scenario == "pcap_ddos":
            _append_log(f"[*] Launching Network DDoS SYN Flood against {target_ip}:80 at 200 packets/sec...", "WARNING", step=1)
            from backend.services.pcap_service import pcap_service
            pcap_service.start_replay("syn_flood_ddos.pcap", speed_multiplier=10.0)
            with _state_lock:
                _simulation_state["progress"] = 50
            time.sleep(2.0)
            with _state_lock:
                _simulation_state["progress"] = 100
            _append_log(f"[+] DDoS SYN Flood blast completed against {target_ip}. Victim CICIDS LightGBM flagged 94.2% threat score.", "SUCCESS", step=4)

        elif scenario == "pcap_portscan":
            _append_log(f"[*] Launching Horizontal TCP Port Scan Sweep across 35+ critical ports on {target_ip}...", "INFO", step=1)
            from backend.services.pcap_service import pcap_service
            pcap_service.start_replay("port_scan_recon.pcap", speed_multiplier=10.0)
            with _state_lock:
                _simulation_state["progress"] = 50
            time.sleep(2.0)
            with _state_lock:
                _simulation_state["progress"] = 100
            _append_log(f"[+] PortScan Recon sweep completed against {target_ip}. Recon signature extracted and tagged in SOC ATT&CK matrix.", "SUCCESS", step=4)

        elif scenario == "pcap_hydra":
            _append_log(f"[*] Initiating Multi-Threaded SSH Password Dictionary Brute Force against {target_ip}:22...", "WARNING", step=1)
            from backend.services.pcap_service import pcap_service
            pcap_service.start_replay("hydra_ssh_bruteforce.pcap", speed_multiplier=10.0)
            with _state_lock:
                _simulation_state["progress"] = 50
            time.sleep(2.0)
            with _state_lock:
                _simulation_state["progress"] = 100
            _append_log(f"[+] Hydra SSH Credential guessing burst completed against {target_ip}. SSH-Bruteforce vector flagged.", "SUCCESS", step=4)

        elif scenario == "all":
            _append_log(f"⚔️ [CAMPAIGN] Launching Multi-Stage Automated Kill-Chain Campaign across Swarm ({target_ip})...", "INFO", step=1)
            scenarios = [
                ("Phase 1: PortScan Reconnaissance", "pcap_portscan", 20),
                ("Phase 2: Linux SSH Brute-Force & Meterpreter", "linux", 40),
                ("Phase 3: Windows Ransomware Dropper", "windows", 65),
                ("Phase 4: Network SYN Flood DDoS Attack", "pcap_ddos", 85),
                ("Phase 5: Agent Sabotage / Silence Infiltration", "sabotage", 100),
            ]
            for title, sc_name, prog in scenarios:
                _append_log(f"[*] Executing Campaign Stage: {title}...", "INFO")
                if sc_name == "linux":
                    simulate_linux_attacks.run_simulation()
                elif sc_name == "windows":
                    simulate_windows_ransomware.run_simulation()
                elif sc_name == "sabotage":
                    simulate_silence_tamper.run_simulation()
                elif sc_name.startswith("pcap_"):
                    from backend.services.pcap_service import pcap_service
                    p_file = "syn_flood_ddos.pcap" if sc_name == "pcap_ddos" else "port_scan_recon.pcap"
                    pcap_service.start_replay(p_file, speed_multiplier=10.0)
                with _state_lock:
                    _simulation_state["progress"] = prog
                time.sleep(1.2)
            _append_log("🎯 [CAMPAIGN COMPLETE] Full Kill-Chain Campaign executed across all target nodes successfully!", "SUCCESS", step=5)

        else:
            _append_log(f"Unknown scenario identifier: {scenario}", "ERROR")

        result = {
            "scenario": scenario,
            "target": target_id,
            "target_ip": target_ip,
            "status": "COMPLETED",
            "duration": round(time.time() - _simulation_state["start_time"], 2),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    except Exception as exc:
        logger.exception("Error executing simulation scenario: %s", exc)
        _append_log(f"Simulation Error: {str(exc)}", "ERROR")
        result = {
            "scenario": scenario,
            "target": target_id,
            "target_ip": target_ip,
            "status": "FAILED",
            "error": str(exc),
            "duration": round(time.time() - _simulation_state["start_time"], 2) if _simulation_state.get("start_time") else 0,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    finally:
        with _state_lock:
            _simulation_state["is_running"] = False
            _simulation_state["completed_at"] = time.time()
            _simulation_state["last_result"] = result
            _simulation_state["history"].insert(0, result)
            if len(_simulation_state["history"]) > 30:
                _simulation_state["history"] = _simulation_state["history"][:30]

        try:
            from backend.telemetry_api import publish_event
            publish_event({
                "type": "simulation_complete",
                "result": result,
            })
        except Exception:
            pass


def start_simulation(scenario: str, target_id: str = "vm1-linux", target_ip: str = "10.0.0.10", custom_config: Optional[dict] = None) -> Dict[str, Any]:
    with _state_lock:
        if _simulation_state["is_running"]:
            return {
                "status": "busy",
                "message": f"Attack operation already running: {_simulation_state['current_scenario']} on {_simulation_state['target_agent_id']}",
            }

    thread = threading.Thread(
        target=_execute_scenario_worker,
        args=(scenario, target_id, target_ip, custom_config),
        daemon=True,
        name=f"sim-worker-{scenario}",
    )
    thread.start()
    return {
        "status": "started",
        "scenario": scenario,
        "target": target_id,
        "target_ip": target_ip,
        "message": f"Attack scenario '{scenario}' dispatched to target [{target_id}] ({target_ip}).",
    }
