"""
tests/test_agent_packaging.py
=============================
Tests for AEGIS Agent Daemon, Configuration, Systemd/PowerShell Installers, and Standalone Distribution Packager.
"""

import os
import tarfile
import zipfile
from pathlib import Path
import pytest

from agent.config import AegisAgentConfig
from agent.daemon_service import run_doctor
from scripts.package_agent import build_all_packages, calculate_sha256

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestAgentConfiguration:
    def test_config_defaults(self):
        cfg = AegisAgentConfig()
        assert cfg.heartbeat_interval == 5.0
        assert cfg.silence_threshold == 15.0
        assert cfg.p2p_enabled is True
        assert cfg.p2p_bind_port == 9001
        assert cfg.enable_active_response is True

    def test_config_save_and_load(self, tmp_path):
        cfg_file = tmp_path / "test_agent.conf"
        cfg = AegisAgentConfig(
            agent_id="test-custom-node",
            command_node_url="http://10.99.0.1:8000",
            heartbeat_interval=3.0,
            p2p_bind_port=9099,
        )
        saved_path = cfg.save(cfg_file)
        assert saved_path.exists()

        loaded_cfg = AegisAgentConfig.load(cfg_file)
        assert loaded_cfg.agent_id == "test-custom-node"
        assert loaded_cfg.command_node_url == "http://10.99.0.1:8000"
        assert loaded_cfg.heartbeat_interval == 3.0
        assert loaded_cfg.p2p_bind_port == 9099


class TestAgentDoctorProbe:
    def test_doctor_diagnostic_execution(self):
        cfg = AegisAgentConfig(command_node_url="http://127.0.0.1:8000")
        results = run_doctor(cfg)
        assert "ready" in results
        assert "checks" in results
        assert len(results["checks"]) >= 5

        check_names = [c["name"] for c in results["checks"]]
        assert "Python 3.10+ Runtime" in check_names
        assert "Operating System" in check_names
        assert any("ML Model" in name for name in check_names)
        assert "Quarantine Vault Permissions" in check_names


class TestInstallerScriptsAndServiceUnits:
    def test_linux_systemd_unit_syntax(self):
        service_path = _PROJECT_ROOT / "scripts" / "linux" / "aegis-agent.service"
        assert service_path.exists()
        content = service_path.read_text(encoding="utf-8")
        assert "Description=AEGIS" in content
        assert "ExecStart=" in content
        assert "ExecStop=" in content
        assert "Restart=always" in content
        assert "ProtectSystem=full" in content

    def test_linux_installer_scripts(self):
        install_sh = _PROJECT_ROOT / "scripts" / "linux" / "install.sh"
        uninstall_sh = _PROJECT_ROOT / "scripts" / "linux" / "uninstall.sh"
        assert install_sh.exists()
        assert uninstall_sh.exists()
        assert "systemctl" in install_sh.read_text(encoding="utf-8")
        assert "systemctl" in uninstall_sh.read_text(encoding="utf-8")

    def test_windows_powershell_scripts(self):
        install_ps1 = _PROJECT_ROOT / "scripts" / "windows" / "install.ps1"
        uninstall_ps1 = _PROJECT_ROOT / "scripts" / "windows" / "uninstall.ps1"
        assert install_ps1.exists()
        assert uninstall_ps1.exists()
        assert "ScheduledTask" in install_ps1.read_text(encoding="utf-8")
        assert "ScheduledTask" in uninstall_ps1.read_text(encoding="utf-8")


class TestDistributionPackager:
    def test_build_all_packages(self):
        result = build_all_packages()
        assert result["status"] == "success"

        linux_pkg = Path(result["linux_package"])
        windows_pkg = Path(result["windows_package"])

        assert linux_pkg.exists()
        assert windows_pkg.exists()
        assert linux_pkg.stat().st_size > 5_000_000  # > 5 MB
        assert windows_pkg.stat().st_size > 5_000_000 # > 5 MB

        # Verify tar.gz contents
        with tarfile.open(linux_pkg, "r:gz") as tar:
            names = tar.getnames()
            assert any("agent/daemon_service.py" in n for n in names)
            assert any("trained_models" in n for n in names)
            assert any("scripts/linux/install.sh" in n for n in names)

        # Verify zip contents
        with zipfile.ZipFile(windows_pkg, "r") as zf:
            names = zf.namelist()
            assert any("agent/daemon_service.py" in n for n in names)
            assert any("trained_models" in n for n in names)
            assert any("scripts/windows/install.ps1" in n for n in names)

        # Verify SHA-256 Checksums
        csums = result["checksums"]
        assert len(csums[linux_pkg.name]) == 64
        assert len(csums[windows_pkg.name]) == 64
