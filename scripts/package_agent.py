"""
scripts/package_agent.py
========================
AEGIS Agent Distribution Packaging Tool.
Compiles standalone deployment archives for Linux (.tar.gz) and Windows (.zip)
containing all agent source code, 6 trained ML model artifacts, installers, and configs.
Generates SHA-256 integrity checksums for release validation.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tarfile
import zipfile
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DIST_DIR = _PROJECT_ROOT / "dist" / "agent_packages"


def calculate_sha256(file_path: Path) -> str:
    """Calculates SHA-256 checksum of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def build_package_payload(stage_dir: Path):
    """Copies required agent files and model artifacts to staging directory."""
    stage_dir.mkdir(parents=True, exist_ok=True)

    # 1. Agent source files
    shutil.copytree(_PROJECT_ROOT / "agent", stage_dir / "agent", dirs_exist_ok=True)
    
    # Clean pycache from stage
    for p in stage_dir.rglob("__pycache__"):
        shutil.rmtree(p, ignore_errors=True)

    # 2. Trained ML models
    shutil.copytree(_PROJECT_ROOT / "trained_models", stage_dir / "trained_models", dirs_exist_ok=True)

    # 3. Scripts
    shutil.copytree(_PROJECT_ROOT / "scripts", stage_dir / "scripts", dirs_exist_ok=True)

    # 4. Root metadata files
    shutil.copy(_PROJECT_ROOT / "requirements.txt", stage_dir / "requirements.txt")
    if (_PROJECT_ROOT / "readme.md").exists():
        shutil.copy(_PROJECT_ROOT / "readme.md", stage_dir / "README.md")


def package_linux(stage_dir: Path, output_tar: Path):
    """Builds Linux .tar.gz archive with correct file permissions."""
    output_tar.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output_tar, "w:gz") as tar:
        for file_path in stage_dir.rglob("*"):
            rel_path = file_path.relative_to(stage_dir)
            tar_info = tar.gettarinfo(str(file_path), arcname=str(Path("aegis-agent") / rel_path))
            # Set executable permissions on scripts
            if file_path.suffix in (".sh", ".py") or "scripts" in str(file_path):
                tar_info.mode = 0o755
            else:
                tar_info.mode = 0o644 if file_path.is_file() else 0o755
            if file_path.is_file():
                with open(file_path, "rb") as f:
                    tar.addfile(tar_info, f)
            elif file_path.is_dir():
                tar.addfile(tar_info)


def package_windows(stage_dir: Path, output_zip: Path):
    """Builds Windows .zip archive."""
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for file_path in stage_dir.rglob("*"):
            if file_path.is_file():
                rel_path = file_path.relative_to(stage_dir)
                zip_file.write(file_path, arcname=str(Path("AEGIS_Agent") / rel_path))


def build_all_packages() -> Dict[str, Any]:
    """Generates both Linux and Windows distribution packages and checksums."""
    print("=" * 65)
    print("  AEGIS EDR AGENT - STANDALONE DISTRIBUTION PACKAGER")
    print("=" * 65)

    _DIST_DIR.mkdir(parents=True, exist_ok=True)
    temp_stage = _DIST_DIR / "stage"

    try:
        print("\n[1/4] Preparing agent distribution payload and ML models...")
        build_package_payload(temp_stage)

        # Build Linux package
        linux_pkg = _DIST_DIR / "aegis-agent-linux-x86_64.tar.gz"
        print(f"[2/4] Packaging Linux archive: {linux_pkg.name}...")
        package_linux(temp_stage, linux_pkg)

        # Build Windows package
        windows_pkg = _DIST_DIR / "aegis-agent-windows-x64.zip"
        print(f"[3/4] Packaging Windows archive: {windows_pkg.name}...")
        package_windows(temp_stage, windows_pkg)

        # Generate Checksums
        print("[4/4] Computing SHA-256 integrity checksums...")
        checksums = {
            linux_pkg.name: calculate_sha256(linux_pkg),
            windows_pkg.name: calculate_sha256(windows_pkg),
        }

        checksum_file = _DIST_DIR / "checksums.sha256"
        with open(checksum_file, "w", encoding="utf-8") as f:
            for fname, csum in checksums.items():
                f.write(f"{csum}  {fname}\n")

        print("\n" + "=" * 65)
        print("  [OK] PACKAGING COMPLETE! STANDALONE PACKAGES GENERATED:")
        print("=" * 65)
        print(f"  Linux Package:   {linux_pkg} ({round(linux_pkg.stat().st_size / 1024 / 1024, 2)} MB)")
        print(f"  SHA-256:         {checksums[linux_pkg.name]}")
        print(f"  Windows Package: {windows_pkg} ({round(windows_pkg.stat().st_size / 1024 / 1024, 2)} MB)")
        print(f"  SHA-256:         {checksums[windows_pkg.name]}")
        print(f"  Checksums File:  {checksum_file}")
        print("=" * 65 + "\n")

        return {
            "status": "success",
            "linux_package": str(linux_pkg),
            "windows_package": str(windows_pkg),
            "checksums": checksums,
        }

    finally:
        # Cleanup temporary staging folder
        if temp_stage.exists():
            shutil.rmtree(temp_stage, ignore_errors=True)


if __name__ == "__main__":
    build_all_packages()
