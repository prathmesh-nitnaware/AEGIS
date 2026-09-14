"""
tests/test_pcap_service.py
==========================
Unit & Integration tests for AEGIS Live PCAP Network Packet Capture & Threat Flow Replayer.
"""

import time
import pytest
from backend.services.pcap_service import PcapReplayerService


class TestPcapService:
    @pytest.fixture(scope="class")
    def service(self):
        return PcapReplayerService()

    def test_sample_pcaps_available(self, service):
        samples = service.list_available_pcaps()
        assert len(samples) >= 4
        filenames = [s["filename"] for s in samples]
        assert "syn_flood_ddos.pcap" in filenames
        assert "port_scan_recon.pcap" in filenames
        assert "hydra_ssh_bruteforce.pcap" in filenames
        assert "benign_web_traffic.pcap" in filenames

    def test_pcap_replay_execution(self, service):
        res = service.start_replay("syn_flood_ddos.pcap", speed_multiplier=50.0)
        assert res["status"] == "started"
        assert res["file"] == "syn_flood_ddos.pcap"

        # Give it a moment to process some packets
        time.sleep(0.5)

        status = service.get_status()
        assert status["status"] in ("replaying", "completed")
        assert status["progress"]["processed_packets"] > 0
        assert len(status["recent_packets"]) > 0
        assert status["metrics"]["total_packets"] > 0

        # Test pause & resume
        service.pause_replay()
        paused_status = service.get_status()
        assert paused_status["status"] in ("paused", "completed")

        service.resume_replay()
        service.stop_replay()
        final_status = service.get_status()
        assert final_status["status"] in ("idle", "completed")

    def test_custom_pcap_upload_save(self, service, tmp_path):
        sample_bytes = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 16  # standard pcap header
        res = service.save_uploaded_file("test_custom_capture.pcap", sample_bytes)
        assert res["status"] == "success"
        assert res["filename"] == "test_custom_capture.pcap"
