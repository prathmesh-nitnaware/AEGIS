"""
backend/services/update_service.py
==================================
AEGIS Autonomous EDR - Central Fleet Management & Secure Auto-Update Service
----------------------------------------------------------------------------
Orchestrates:
1. Fleet-wide and targeted agent configuration pushes over WebSockets/REST.
2. Cryptographic package signing and distribution verification (Ed25519).
3. Live agent fleet inventory tracking and config convergence.
"""

from __future__ import annotations

import base64
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent.packaging.package_verifier import (
    PackageSignatureVerifier,
    generate_ed25519_keypair,
    sign_package_archive,
)

logger = logging.getLogger("aegis.update_service")


class FleetUpdateService:
    """
    Coordinates fleet-wide configuration pushes and cryptographic updates.
    """

    def __init__(self, private_key_bytes: Optional[bytes] = None) -> None:
        self._lock = threading.RLock()
        if private_key_bytes:
            self._priv_key = private_key_bytes
            # Derive public key
            from cryptography.hazmat.primitives.asymmetric import ed25519

            priv = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
            self._pub_key = priv.public_key().public_bytes(
                encoding=ed25519.serialization.Encoding.Raw,
                format=ed25519.serialization.PublicFormat.Raw,
            )
        else:
            self._priv_key, self._pub_key = generate_ed25519_keypair()

        self.verifier = PackageSignatureVerifier(
            trusted_public_key_b64=base64.b64encode(self._pub_key).decode("ascii")
        )
        self._fleet_configs: Dict[str, Dict[str, Any]] = {}
        self._fleet_agents: Dict[str, Dict[str, Any]] = {}

    def get_public_key_b64(self) -> str:
        """Return base64-encoded root public key."""
        return base64.b64encode(self._pub_key).decode("ascii")

    def register_agent_heartbeat(
        self, agent_id: str, version: str = "2.0.0", platform_name: str = "Linux"
    ) -> None:
        """Register or update an active agent in the fleet registry."""
        with self._lock:
            self._fleet_agents[agent_id] = {
                "agent_id": agent_id,
                "version": version,
                "platform": platform_name,
                "last_seen": time.time(),
                "status": "ONLINE",
            }

    def push_agent_config(
        self, agent_id: str, config_patch: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Store and prepare targeted configuration payload for an agent.
        """
        with self._lock:
            current = self._fleet_configs.get(agent_id, {})
            current.update(config_patch)
            current["updated_at"] = time.time()
            self._fleet_configs[agent_id] = current

            return {
                "status": "queued",
                "agent_id": agent_id,
                "applied_config": current,
            }

    def get_agent_config(self, agent_id: str) -> Dict[str, Any]:
        """Retrieve the latest configuration assigned to an agent."""
        with self._lock:
            return self._fleet_configs.get(agent_id, {})

    def sign_package(self, package_path: str | Path) -> Dict[str, Any]:
        """
        Sign an agent package archive with the fleet's private Ed25519 key.
        """
        path = Path(package_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Package file not found: {path}")

        sig_bytes = sign_package_archive(path, self._priv_key)
        sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
        pub_b64 = self.get_public_key_b64()

        verification = self.verifier.verify_and_check_sha256(
            archive_path=path,
            signature_b64=sig_b64,
            public_key_b64=pub_b64,
        )

        return {
            "status": "success",
            "filename": path.name,
            "signature_b64": sig_b64,
            "public_key_b64": pub_b64,
            "sha256": verification["sha256"],
            "verified": verification["valid"],
        }

    def verify_package(
        self,
        package_path: str | Path,
        signature_b64: str,
        expected_sha256: Optional[str] = None,
        public_key_b64: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Verify any external or downloaded package.
        """
        return self.verifier.verify_and_check_sha256(
            archive_path=package_path,
            signature_b64=signature_b64,
            expected_sha256=expected_sha256,
            public_key_b64=public_key_b64 or self.get_public_key_b64(),
        )

    def list_fleet(self) -> List[Dict[str, Any]]:
        """List all known fleet endpoints with active status."""
        with self._lock:
            now = time.time()
            result = []
            for aid, data in self._fleet_agents.items():
                entry = dict(data)
                entry["is_online"] = (now - entry["last_seen"]) < 60.0
                entry["custom_config"] = self._fleet_configs.get(aid, {})
                result.append(entry)
            return result


# Global singleton
fleet_update_service = FleetUpdateService()
