"""
agent/orchestration/os_detector.py
=====================================
Detects the host operating system and resolves an optional manual
--os override. Pure naming decision -- imports nothing collector-related,
so this module is always safe to import regardless of platform.

Extending to a new OS later: add its platform.system() string to
SUPPORTED_OS below. Nothing else in this file needs to change.
"""
from __future__ import annotations

import platform

# platform.system() returns exactly these strings on the OSes we support
# today. Add new ones here (e.g. "Darwin" for macOS) when support is added.
SUPPORTED_OS = ("Windows", "Linux")


def detect_os() -> str:
    """Return the real, actual host OS as reported by the platform module."""
    return platform.system()


def resolve_os(override: str | None = None) -> str:
    """
    Return the OS name to use for collector selection.

    If `override` is given (e.g. from --os windows), it is validated and
    used instead of the detected OS -- but a mismatch against the REAL
    detected OS is always logged as a warning, never silently accepted.
    Automatic detection remains the default whenever override is None.
    """
    actual = detect_os()

    if not override:
        return actual

    normalized = override.strip().capitalize()  # "windows" -> "Windows"
    if normalized not in SUPPORTED_OS:
        raise ValueError(
            f"Unsupported --os override '{override}'. "
            f"Supported values: {', '.join(SUPPORTED_OS)}"
        )

    if normalized != actual:
        print(f"[orchestration] WARNING: Manual OS override: {normalized}")
        print(f"[orchestration] WARNING: Actual detected OS : {actual}")
        print(f"[orchestration] WARNING: Collectors incompatible with "
              f"'{normalized}' will still be skipped, even though this "
              f"machine is really '{actual}'.")

    return normalized
