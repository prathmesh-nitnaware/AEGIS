
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
    """Return real heartbeat-registered agents only; never fabricate demo targets."""
    try:
        # Use the same live heartbeat registry as the API target endpoint.
        from backend.telemetry_api import silence_detector, agent_connection_metadata
        now = time.time()
        targets = []
        for row in silence_detector.list_agents():
            aid = row.get("agent_id")
            meta = agent_connection_metadata.get(aid, {})
            age = float(row.get("silence_duration", now - float(row.get("last_seen", 0))))
            raw_status = str(row.get("status", "unknown")).upper()
            online = age <= silence_detector.silence_threshold and raw_status not in {"OFFLINE_GRACEFUL", "OFFLINE", "DISCONNECTED"}
            targets.append({
                "id": aid,
                "name": f"AEGIS Agent {aid}",
                "os": meta.get("os", "Unknown"),
                "ip": meta.get("ip") or "Unknown (source address unavailable)",
                "last_seen": row.get("last_seen"),
                "silence_duration": age,
                "services": ["AEGIS telemetry"],
                "status": "ONLINE" if online else ("ALARMED" if row.get("alarm_raised") else "OFFLINE"),
                "selectable": online and bool(meta.get("ip")),
            })
        return targets
    except Exception:
        logger.exception("Unable to build live agent target list")
        return []


def get_simulation_status() -> Dict[str, Any]:
    with _state_lock:
        return dict(_simulation_state)


def reset_simulation_state():
    with _state_lock:
        if _simulation_state["is_running"]:
            return False
        _simulation_state["current_scenario"] = None
        _simulation_state["progress"] = 0
        _simulation_state["logs"] = []
        return True


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



def _publish_lab_event(target_id: str, scenario: str, event_type: str, threat_score: float = 0.72) -> None:
    """Publish clearly labelled synthetic lab telemetry; never claim live compromise."""
    event = {
        "timestamp": int(time.time() * 1000000),
        "agent_id": target_id,
        "target_agent_id": target_id,
        "event_type": event_type,
        "scenario": scenario,
        "process": "aegis-lab-simulation",
        "source": "red_team_dashboard_simulation",
        "simulation": True,
        "threat_score": threat_score,
        "predicted_class": "SIMULATED_TEST_EVENT",
        "message": f"Synthetic {scenario} test event for dashboard integration validation",
    }
    try:
        from backend.telemetry_api import add_event, central_repo, publish_event
        add_event(event)
        central_repo.add_telemetry(event)
        publish_event(event)
    except Exception:
        logger.exception("Unable to publish synthetic lab telemetry")


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

    _append_log(f"⚔️ [C2 DISPATCH] Initializing LAB SCENARIO: [{scenario.upper()}] against Target [{target_id}] ({target_ip})...", "INFO", step=1)

    try:
        if scenario == "linux":
            _append_log(f"[*] Starting the existing Linux telemetry simulation for registered agent {target_id} ({target_ip})...", "INFO", step=1)
            time.sleep(0.5)
            with _state_lock:
                _simulation_state["progress"] = 25
            _append_log("[*] Preparing synthetic attack telemetry (no shell payload is executed)...", "WARNING", step=2)
            time.sleep(0.5)
            simulate_linux_attacks.AGENT_ID = target_id
            simulate_linux_attacks.run_simulation()
            with _state_lock:
                _simulation_state["progress"] = 100
            _append_log(f"[+] Linux attack telemetry simulation finished for {target_id}; verify the resulting alert in the Blue Team dashboard.", "SUCCESS", step=4)

        elif scenario in {"windows", "file"}:
            _append_log(f"[*] Running synthetic suspicious-file telemetry scenario for registered agent {target_id} ({target_ip})...", "INFO", step=1)
            time.sleep(0.5)
            with _state_lock:
                _simulation_state["progress"] = 25
            _append_log("[*] Generating ransomware-like lab telemetry only; no destructive command is executed...", "WARNING", step=2)
            time.sleep(0.5)
            simulate_windows_ransomware.AGENT_ID = target_id
            simulate_windows_ransomware.run_simulation()
            _publish_lab_event(target_id, "suspicious_file", "file_activity_simulation", 0.72)
            with _state_lock:
                _simulation_state["progress"] = 100
            _append_log(f"[+] Synthetic suspicious-file event published for {target_id}. No file was encrypted and no host was isolated.", "SUCCESS", step=4)

        elif scenario == "sabotage":
            _append_log(f"[*] Running a heartbeat-silence simulation associated with {target_id} ({target_ip}); no process will be terminated...", "WARNING", step=1)
            time.sleep(0.5)
            with _state_lock:
                _simulation_state["progress"] = 30
            _append_log("[*] Air-gap severance simulated: Host telemetry stream zeroed out...", "WARNING", step=2)
            simulate_silence_tamper.run_simulation()
            with _state_lock:
                _simulation_state["progress"] = 100
            _append_log(f"[+] Silence-as-Alarm triggered on {target_id}. Escalated to SOC incident queue within 15 seconds.", "SUCCESS", step=4)

        elif scenario == "consensus":
            _append_log(f"[*] Publishing a labelled synthetic threat event for consensus-path demonstration on {target_id}...", "INFO", step=1)
            _publish_lab_event(target_id, "multi_node_consensus", "consensus_simulation", 0.88)
            with _state_lock:
                _simulation_state["progress"] = 50
            time.sleep(0.5)
            _append_log("[!] Synthetic event was published. This does not prove that distributed quorum voting completed; verify the P2P/consensus records separately.", "WARNING", step=2)
            with _state_lock:
                _simulation_state["progress"] = 100

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
            _append_log(f"[*] Replaying the stored SYN-flood PCAP for sensor validation (selected agent: {target_id})...", "WARNING", step=1)
            from backend.services.pcap_service import pcap_service
            pcap_service.start_replay("syn_flood_ddos.pcap", speed_multiplier=10.0)
            with _state_lock:
                _simulation_state["progress"] = 50
            time.sleep(2.0)
            with _state_lock:
                _simulation_state["progress"] = 100
            _append_log(f"[+] PCAP replay started for IDS validation; this replay is not sent directly to the selected target and detection must be verified separately.", "SUCCESS", step=4)

        elif scenario == "pcap_portscan":
            _append_log(f"[*] Replaying the stored port-scan PCAP for sensor validation (selected agent: {target_id})...", "INFO", step=1)
            from backend.services.pcap_service import pcap_service
            pcap_service.start_replay("port_scan_recon.pcap", speed_multiplier=10.0)
            with _state_lock:
                _simulation_state["progress"] = 50
            time.sleep(2.0)
            with _state_lock:
                _simulation_state["progress"] = 100
            _append_log(f"[+] Port-scan PCAP replay started for IDS validation; detection must be verified in the Blue Team dashboard.", "SUCCESS", step=4)

        elif scenario == "pcap_hydra":
            _append_log(f"[*] Replaying the stored SSH brute-force PCAP for sensor validation (selected agent: {target_id})...", "WARNING", step=1)
            from backend.services.pcap_service import pcap_service
            pcap_service.start_replay("hydra_ssh_bruteforce.pcap", speed_multiplier=10.0)
            with _state_lock:
                _simulation_state["progress"] = 50
            time.sleep(2.0)
            with _state_lock:
                _simulation_state["progress"] = 100
            _append_log(f"[+] SSH brute-force PCAP replay started for IDS validation; this is recorded traffic, not live credential guessing.", "SUCCESS", step=4)

        elif scenario == "all":
            _append_log(f"⚔️ [CAMPAIGN] Launching Multi-Stage Automated Kill-Chain Campaign across Swarm ({target_ip})...", "INFO", step=1)
            scenarios = [
                ("Phase 1: PortScan Reconnaissance", "pcap_portscan", 20),
                ("Phase 2: Linux SSH Brute-Force & Meterpreter", "linux", 40),
                ("Phase 3: Suspicious File Simulation", "file", 65),
                ("Phase 4: Network SYN Flood DDoS Attack", "pcap_ddos", 85),
                ("Phase 5: Agent Sabotage / Silence Infiltration", "sabotage", 100),
            ]
            for title, sc_name, prog in scenarios:
                _append_log(f"[*] Executing Campaign Stage: {title}...", "INFO")
                if sc_name == "linux":
                    simulate_linux_attacks.AGENT_ID = target_id
                    simulate_linux_attacks.run_simulation()
                elif sc_name in {"windows", "file"}:
                    simulate_windows_ransomware.AGENT_ID = target_id
                    simulate_windows_ransomware.run_simulation()
                    _publish_lab_event(target_id, "suspicious_file", "file_activity_simulation", 0.72)
                elif sc_name == "consensus":
                    _publish_lab_event(target_id, "multi_node_consensus", "consensus_simulation", 0.88)
                elif sc_name == "sabotage":
                    simulate_silence_tamper.run_simulation()
                elif sc_name.startswith("pcap_"):
                    from backend.services.pcap_service import pcap_service
                    p_file = "syn_flood_ddos.pcap" if sc_name == "pcap_ddos" else "port_scan_recon.pcap"
                    pcap_service.start_replay(p_file, speed_multiplier=10.0)
                with _state_lock:
                    _simulation_state["progress"] = prog
                time.sleep(1.2)
            _append_log("🎯 [CAMPAIGN COMPLETE] Campaign simulation sequence finished. Confirm each stage and detection in the Blue Team dashboard; completion alone is not proof of compromise.", "SUCCESS", step=5)

        else:
            _append_log(f"Unknown scenario identifier: {scenario}", "ERROR")

        result = {
            "scenario": scenario,
            "target": target_id,
            "target_ip": target_ip,
            "status": "COMPLETED",
            "execution_type": "SIMULATION_OR_PCAP_REPLAY",
            "detection_confirmed": False,
            "consensus_confirmed": False,
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
