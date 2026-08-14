"""
agent/orchestration/collector_manager.py
============================================
The single authoritative path that actually STARTS collectors. Uses
telemetry_registry.py to decide which registered collector names are
compatible with the detected OS, then calls the corresponding start
function supplied by run_all.py -- each collector name is invoked at
most once per run, so there is no risk of double-starting a collector
because of this orchestration layer.

This module never imports a collector class directly. run_all.py still
owns all real collector wiring; this file only decides WHETHER to call
what run_all.py hands it.
"""
from __future__ import annotations

from typing import Callable, Dict

from .telemetry_registry import collectors_for_platform


def print_banner(os_name: str, profile_name: str, compatible: Dict[str, dict]) -> None:
    """
    Prints the startup diagnostic banner showing detected OS, profile, and
    intended ON/OFF state for every known collector (ON = compatible with
    this OS and about to be attempted; OFF = incompatible, not attempted).
    """
    from .telemetry_registry import COLLECTORS  # local import, avoids cycle risk

    print("=" * 42)
    print("        AEGIS TELEMETRY AGENT")
    print("=" * 42)
    print(f"\nOperating System: {os_name}")
    print(f"Telemetry Profile: {profile_name}\n")
    print("Collectors:")
    for name, meta in COLLECTORS.items():
        on = name in compatible
        state = "ON " if on else "OFF"
        print(f"  [{state}] {meta['label']}")
    print()


def run_collectors(os_name: str, start_fns: Dict[str, Callable[[], None]]) -> Dict[str, bool]:
    """
    Starts every collector that is BOTH registered as compatible with
    os_name AND has a start function supplied in start_fns. Each name is
    attempted exactly once (single authoritative call path -- no
    duplicate starts even if this were called twice by mistake, since
    results already recorded are never re-attempted).

    A collector marked "critical" in the registry re-raises its exception
    after logging (so a critical failure surfaces and does not get
    silently swallowed). A non-critical ("optional") collector logs a
    warning and lets the rest of the agent continue.

    Returns {collector_name: True/False} -- True if that collector's
    start function ran without raising.
    """
    compatible = collectors_for_platform(os_name)
    results: Dict[str, bool] = {}

    for name, meta in compatible.items():
        if name in results:
            continue  # already attempted this run -- do not start twice

        if name not in start_fns:
            # Declared as OS-compatible in the registry, but run_all.py
            # did not wire a start function for it this run (e.g. feature
            # not implemented yet for this collector). Not an error --
            # just nothing to start.
            continue

        try:
            start_fns[name]()
            results[name] = True
        except Exception as exc:
            if meta.get("critical"):
                print(f"[CRITICAL FAILURE] {meta['label']} collector failed to start: {exc}")
                results[name] = False
                raise
            else:
                print(f"[WARNING] {meta['label']} collector unavailable: {exc}")
                print(f"[INFO] Continuing with remaining telemetry collectors.")
                results[name] = False

    return results
