"""
conftest.py (project root)
===========================
Ensures D:\\AEGIS is on sys.path for all pytest runs so that
  `from agent.X import ...`
  `from backend.X import ...`
imports work without installing the package.

This was missing previously — older tests that import from `backend.*` worked
because they happened to be collected after something else that added the path,
but it was fragile. This conftest makes it explicit and reliable.
"""
import sys
from pathlib import Path

# Add project root to sys.path so `agent.*` and `backend.*` imports resolve
PROJECT_ROOT = str(Path(__file__).resolve().parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
