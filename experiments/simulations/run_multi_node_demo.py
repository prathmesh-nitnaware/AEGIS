"""
experiments/simulations/run_multi_node_demo.py
==============================================
AEGIS Phase 5 — Master Multi-Node Attack Simulation Showcase
Interactive and automated CLI harness for demonstrating all AEGIS detection,
consensus, mitigation, and heartbeat resilience scenarios.

Usage:
    python -m experiments.simulations.run_multi_node_demo
"""

import sys
import os
import time

# Ensure project root in pythonpath
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from experiments.simulations import (
    simulate_linux_attacks,
    simulate_windows_ransomware,
    simulate_silence_tamper,
    simulate_graceful_shutdown,
)


def print_banner():
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║       AEGIS — Autonomous Endpoint Guardian Simulation         ║
    ║        Phase 5: Multi-Node Attack & Resilience Showcase       ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)


def menu():
    print_banner()
    print(" Select a simulation scenario to execute:\n")
    print("   [1] Linux Attack: Hydra SSH Brute-Force & Meterpreter (KILL_PROCESS)")
    print("   [2] Windows Attack: Ransomware & PE Dropper (QUARANTINE & ISOLATE_HOST)")
    print("   [3] Adversary Sabotage: Forced Agent Kill (CRITICAL SILENT_ALARM)")
    print("   [4] System Lifecycle: Clean User PC Shutdown vs False Alarms")
    print("   [5] Run Complete Automated Showcase (All Scenarios Sequentially)")
    print("   [0] Exit\n")


def run_all():
    print("\n>>> STARTING COMPLETE AEGIS DEMO SHOWCASE <<<\n")
    simulate_linux_attacks.run_simulation()
    time.sleep(2)
    simulate_windows_ransomware.run_simulation()
    time.sleep(2)
    simulate_graceful_shutdown.run_simulation()
    time.sleep(2)
    simulate_silence_tamper.run_simulation()
    print("\n>>> ALL 4 SIMULATION SCENARIOS COMPLETED SUCCESSFULLY! <<<\n")


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("--all", "-a"):
        run_all()
        return

    while True:
        menu()
        choice = input(" Enter selection [0-5]: ").strip()
        if choice == "1":
            simulate_linux_attacks.run_simulation()
        elif choice == "2":
            simulate_windows_ransomware.run_simulation()
        elif choice == "3":
            simulate_silence_tamper.run_simulation()
        elif choice == "4":
            simulate_graceful_shutdown.run_simulation()
        elif choice == "5":
            run_all()
        elif choice == "0":
            print("Exiting AEGIS Simulation Harness. Goodbye.")
            break
        else:
            print("[!] Invalid selection. Please choose 0-5.")
        
        input("\nPress Enter to return to menu...")


if __name__ == "__main__":
    main()
