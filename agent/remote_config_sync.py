"""
agent/remote_config_sync.py
===========================
AEGIS Autonomous EDR - Remote Fleet Configuration Synchronizer
--------------------------------------------------------------
Allows the SOC Command Center to push real-time configuration updates
(voting weights, anomaly suppression thresholds, polling intervals, ML engines)
to active endpoint agents without requiring service restarts.

Features:
- Schema validation for incoming JSON configurations.
- In-memory hot application with fallback to local persistent cache.
- Event listener callbacks on configuration changes.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("aegis.remote_config_sync")

DEFAULT_CONFIG: Dict[str, Any] = {
    "version": "2.0.0",
    "updated_at": 0.0,
    "polling_interval_sec": 2.0,
    "confidence_threshold": 0.70,
    "threat_score_suppression": 0.30,
    "voting_weights": {
        "ember": 1.2,
        "cicids": 1.1,
        "linux_ids": 1.0,
        "windows_adv": 1.2,
        "zero_day": 1.3,
        "hdfs": 0.8,
    },
    "active_collectors": {
        "ebpf": True,
        "etw": True,
        "scapy": True,
        "proc_mon": True,
    },
    "auto_containment_enabled": True,
}


class RemoteConfigSync:
    """
    Manages dynamic agent configuration synchronization from Command Node.
    """

    def __init__(
        self,
        agent_id: str = "agent-local",
        cache_path: Optional[str] = None,
        on_update_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        self.agent_id = agent_id
        self.cache_path = (
            Path(cache_path).resolve()
            if cache_path
            else Path("logs") / f"config_cache_{agent_id}.json"
        )
        self.on_update_callback = on_update_callback
        self._lock = threading.RLock()
        self._current_config = dict(DEFAULT_CONFIG)
        self._load_cached_config()

    def _load_cached_config(self) -> None:
        """Loads cached config from disk if available."""
        if self.cache_path.exists():
            try:
                with open(self.cache_path, "r", encoding="utf-8") as f:
                    cached = json.load(f)
                self._current_config.update(cached)
                logger.info("[%s] Loaded configuration from cache.", self.agent_id)
            except Exception as exc:
                logger.warning("[%s] Failed to load cached config: %s", self.agent_id, exc)

    def _save_cached_config(self) -> None:
        """Saves current config to disk cache."""
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_path, "w", encoding="utf-8") as f:
                json.dump(self._current_config, f, indent=2)
        except Exception as exc:
            logger.warning("[%s] Failed to write config cache: %s", self.agent_id, exc)

    def get_config(self) -> Dict[str, Any]:
        """Returns a snapshot of the active configuration."""
        with self._lock:
            return dict(self._current_config)

    def apply_remote_config(self, new_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validates and hot-applies incoming configuration payload.
        """
        with self._lock:
            # Validate essential numeric bounds
            if "polling_interval_sec" in new_config:
                val = float(new_config["polling_interval_sec"])
                if val < 0.1 or val > 3600.0:
                    raise ValueError("polling_interval_sec must be between 0.1 and 3600.0")
                self._current_config["polling_interval_sec"] = val

            if "confidence_threshold" in new_config:
                val = float(new_config["confidence_threshold"])
                if not 0.0 <= val <= 1.0:
                    raise ValueError("confidence_threshold must be between 0.0 and 1.0")
                self._current_config["confidence_threshold"] = val

            if "threat_score_suppression" in new_config:
                val = float(new_config["threat_score_suppression"])
                if not 0.0 <= val <= 1.0:
                    raise ValueError("threat_score_suppression must be between 0.0 and 1.0")
                self._current_config["threat_score_suppression"] = val

            if "voting_weights" in new_config and isinstance(new_config["voting_weights"], dict):
                self._current_config["voting_weights"].update(new_config["voting_weights"])

            if "active_collectors" in new_config and isinstance(new_config["active_collectors"], dict):
                self._current_config["active_collectors"].update(new_config["active_collectors"])

            if "auto_containment_enabled" in new_config:
                self._current_config["auto_containment_enabled"] = bool(new_config["auto_containment_enabled"])

            self._current_config["updated_at"] = time.time()
            self._save_cached_config()

            logger.info("[%s] Remote configuration applied successfully.", self.agent_id)

            if self.on_update_callback:
                try:
                    self.on_update_callback(dict(self._current_config))
                except Exception as exc:
                    logger.error("[%s] Error in on_update callback: %s", self.agent_id, exc)

            return {
                "status": "success",
                "agent_id": self.agent_id,
                "config": dict(self._current_config),
            }
