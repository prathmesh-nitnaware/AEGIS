"""
agent/packaging/package_verifier.py
===================================
AEGIS Autonomous EDR - Cryptographic Agent Package Signature & Verification
---------------------------------------------------------------------------
Implements Ed25519 asymmetric signature generation and verification on agent
release archives (.tar.gz and .zip) to prevent tampering, supply-chain attacks,
and malicious binary hot-patching.

Features:
- Ed25519 asymmetric cryptography via `cryptography`.
- Detached signature generation (.sig) in binary and base64.
- High-speed archive integrity & signature verification prior to extraction.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

logger = logging.getLogger("aegis.package_verifier")


def generate_ed25519_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a new Ed25519 private/public keypair in raw 32-byte format.
    Returns: (private_bytes, public_bytes)
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_raw, pub_raw


def sign_package_archive(archive_path: Path | str, private_key_bytes: bytes) -> bytes:
    """
    Sign an agent archive file (.tar.gz or .zip) with an Ed25519 private key.
    Returns: 64-byte Ed25519 signature.
    """
    path = Path(archive_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Package archive not found at: {path}")

    with open(path, "rb") as f:
        data = f.read()

    priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    signature = priv_key.sign(data)
    return signature


def verify_package_signature(
    archive_path: Path | str,
    signature_bytes: bytes,
    public_key_bytes: bytes,
) -> bool:
    """
    Verify an Ed25519 detached signature for a given package archive.
    Returns True if valid, False if tampered or invalid.
    """
    path = Path(archive_path).resolve()
    if not path.exists():
        logger.error("Archive not found: %s", path)
        return False

    with open(path, "rb") as f:
        data = f.read()

    try:
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pub_key.verify(signature_bytes, data)
        return True
    except (InvalidSignature, ValueError) as exc:
        logger.warning("Cryptographic signature validation failed for %s: %s", path.name, exc)
        return False


class PackageSignatureVerifier:
    """
    Autonomous verifier that validates agent distribution packages before installation.
    """

    def __init__(self, trusted_public_key_b64: Optional[str] = None) -> None:
        if trusted_public_key_b64:
            self.trusted_public_key_bytes = base64.b64decode(trusted_public_key_b64)
        else:
            # Default embedded root public key for dev/test
            _, default_pub = generate_ed25519_keypair()
            self.trusted_public_key_bytes = default_pub

    def verify_and_check_sha256(
        self,
        archive_path: Path | str,
        signature_b64: str,
        expected_sha256: Optional[str] = None,
        public_key_b64: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Performs dual verification:
        1. SHA-256 Checksum Match
        2. Ed25519 Cryptographic Signature Verification
        """
        path = Path(archive_path).resolve()
        if not path.exists():
            return {
                "valid": False,
                "reason": f"File does not exist: {path}",
                "sha256": None,
                "signature_valid": False,
            }

        # 1. Checksum calculation
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        calculated_sha256 = hasher.hexdigest()

        sha256_match = True
        if expected_sha256:
            sha256_match = calculated_sha256.lower() == expected_sha256.lower().strip()

        # 2. Signature verification
        pub_bytes = (
            base64.b64decode(public_key_b64)
            if public_key_b64
            else self.trusted_public_key_bytes
        )

        try:
            sig_bytes = base64.b64decode(signature_b64)
            sig_valid = verify_package_signature(path, sig_bytes, pub_bytes)
        except Exception as exc:
            sig_valid = False
            logger.error("Error decoding signature: %s", exc)

        overall_valid = sha256_match and sig_valid

        return {
            "valid": overall_valid,
            "filename": path.name,
            "size_bytes": path.stat().st_size,
            "sha256": calculated_sha256,
            "sha256_match": sha256_match,
            "signature_valid": sig_valid,
            "reason": "OK" if overall_valid else "Signature or Checksum mismatch",
        }
