"""
agent/packaging
===============
Cryptographic Agent Package Verification & Integrity Management.
"""

from agent.packaging.package_verifier import (
    generate_ed25519_keypair,
    sign_package_archive,
    verify_package_signature,
    PackageSignatureVerifier,
)

__all__ = [
    "generate_ed25519_keypair",
    "sign_package_archive",
    "verify_package_signature",
    "PackageSignatureVerifier",
]
