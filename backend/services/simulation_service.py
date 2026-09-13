"""
backend/services/simulation_service.py
======================================
AEGIS Red Team Interactive Attack Simulation Manager.
Enables 1-click execution of attack scenarios directly from the dashboard,
streaming live execution events and metrics to connected operators.
"""

import asyncio
import threading
import time
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

# In-memory execution state
_simulation_state = {
    "is_running": False,
    "current_scenario": None,
    "start_time": None,
    "completed_at": None,
    "progress": 0,
    "logs": [],
    "last_result": None,
    "history": [],
}
_state_lock = threading.Lock()


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
        # Keep latest 100 logs
        if len(_simulation_state["logs"]) > 100:
            _simulation_state["logs"] = _simulation_state["logs"][-100:]
    
    # Broadcast via WebSocket if available
    try:
        from backend.telemetry_api import publish_event
        publish_event({
            "type": "simulation_progress",
            "log": entry,
            "scenario": _simulation_state.get("current_scenario"),
            "progress": _simulation_state.get("progress", 0),
        })
    except Exception:
        pass


def _execute_scenario_worker(scenario: str):
    from experiments.simulations import (
        simulate_linux_attacks,
        simulate_windows_ransomware,
        simulate_silence_tamper,
        simulate_graceful_shutdown,
    )
    
    with _state_lock:
        _simulation_state["is_running"] = True
        _simulation_state["current_scenario"] = scenario
        _simulation_state["start_time"] = time.time()
        _simulation_state["progress"] = 5
        _simulation_state["logs"] = []

    _append_log(f"Initiating Red Team Simulation: [{scenario.upper()}]...", "INFO", step=1)

    try:
        if scenario == "linux":
            _append_log("Target: vm1-linux | Scenario: Hydra SSH Brute Force & Java Meterpreter RCE", "INFO", step=1)
            with _state_lock:
                _simulation_state["progress"] = 30
            simulate_linux_attacks.run_simulation()
            with _state_lock:
                _simulation_state["progress"] = 100
            _append_log("Simulation Finished: Target vm1-linux isolated, malicious process killed.", "SUCCESS", step=4)

        elif scenario == "windows":
            _append_log("Target: vm2-windows | Scenario: Ransomware Dropper & PE Header Inspection", "INFO", step=1)
            with _state_lock:
                _simulation_state["progress"] = 30
            simulate_windows_ransomware.run_simulation()
            with _state_lock:
                _simulation_state["progress"] = 100
            _append_log("Simulation Finished: PE Dropper quarantined & host network isolated.", "SUCCESS", step=4)

        elif scenario == "sabotage":
            _append_log("Target: vm3-sabotaged-node | Scenario: Host Agent Termination / Tamper", "WARNING", step=1)
            with _state_lock:
                _simulation_state["progress"] = 30
            simulate_silence_tamper.run_simulation()
            with _state_lock:
                _simulation_state["progress"] = 100
            _append_log("Simulation Finished: Silence-as-Alarm triggered and escalated to SOC queue.", "SUCCESS", step=4)

        elif scenario == "graceful":
            _append_log("Target: vm4-planned-reboot | Scenario: Clean OS Shutdown vs False Alarms", "INFO", step=1)
            with _state_lock:
                _simulation_state["progress"] = 30
            simulate_graceful_shutdown.run_simulation()
            with _state_lock:
                _simulation_state["progress"] = 100
            _append_log("Simulation Finished: Node transition cleanly recorded without false alarm.", "SUCCESS", step=4)

        elif scenario == "all":
            scenarios = [
                ("Linux Brute-Force & Meterpreter", simulate_linux_attacks.run_simulation, 25),
                ("Windows Ransomware & Dropper", simulate_windows_ransomware.run_simulation, 50),
                ("Clean OS Shutdown Verification", simulate_graceful_shutdown.run_simulation, 75),
                ("Adversary Sabotage / Silence Alarm", simulate_silence_tamper.run_simulation, 100),
            ]
            for title, fn, prog in scenarios:
                _append_log(f"Executing Stage: {title}...", "INFO")
                fn()
                with _state_lock:
                    _simulation_state["progress"] = prog
                time.sleep(1.5)
            _append_log("Complete Multi-Node Simulation Suite Executed Successfully!", "SUCCESS")

        else:
            _append_log(f"Unknown scenario identifier: {scenario}", "ERROR")

        result = {
            "scenario": scenario,
            "status": "COMPLETED",
            "duration": round(time.time() - _simulation_state["start_time"], 2),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    except Exception as exc:
        logger.exception("Error executing simulation scenario: %s", exc)
        _append_log(f"Simulation Error: {str(exc)}", "ERROR")
        result = {
            "scenario": scenario,
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
            if len(_simulation_state["history"]) > 20:
                _simulation_state["history"] = _simulation_state["history"][:20]

        try:
            from backend.telemetry_api import publish_event
            publish_event({
                "type": "simulation_complete",
                "result": result,
            })
        except Exception:
            pass


def start_simulation(scenario: str) -> Dict[str, Any]:
    with _state_lock:
        if _simulation_state["is_running"]:
            return {
                "status": "busy",
                "message": f"Simulation already running: {_simulation_state['current_scenario']}",
            }
        
    thread = threading.Thread(
        target=_execute_scenario_worker,
        args=(scenario,),
        daemon=True,
        name=f"sim-worker-{scenario}"
    )
    thread.start()
    return {
        "status": "started",
        "scenario": scenario,
        "message": f"Simulation scenario '{scenario}' launched successfully in background.",
    }
