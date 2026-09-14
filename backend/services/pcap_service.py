"""
backend/services/pcap_service.py
================================
AEGIS Live PCAP Network Packet Capture & Threat Flow Replayer Service.
Supports reading, generating, uploading, and replaying raw .pcap/.pcapng files.
Processes packets through Scapy and ScapyFlowCollector to extract CICIDS 78-feature flows
and score network anomalies in real-time.
"""

from __future__ import annotations

import io
import os
import random
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Scapy imports
try:
    from scapy.all import IP, TCP, UDP, ICMP, Ether, Raw, rdpcap, wrpcap
    _HAS_SCAPY = True
except ImportError:
    _HAS_SCAPY = False

from agent.scapy_flow_collector import ScapyFlowCollector
from agent.fusion_engine import ThreatFusionEngine

_PCAP_DIR = Path(__file__).resolve().parent.parent.parent / "experiments" / "data" / "pcaps"
_UPLOAD_DIR = Path(__file__).resolve().parent.parent.parent / "experiments" / "data" / "uploads"


class PcapReplayerService:
    """
    Manages PCAP sample generation, custom file ingestion,
    and real-time background packet replay with flow extraction.
    """

    def __init__(self):
        _PCAP_DIR.mkdir(parents=True, exist_ok=True)
        _UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set()  # Not paused by default

        self._status = "idle"  # idle | replaying | paused | completed | error
        self._current_file: Optional[str] = None
        self._speed_multiplier = 1.0
        self._start_time = 0.0
        self._total_packets = 0
        self._processed_packets = 0

        # Ring buffers
        self._packets_stream: List[Dict[str, Any]] = []
        self._max_packets_buffer = 300

        self._flows_extracted: List[Dict[str, Any]] = []
        self._max_flows_buffer = 100

        self._metrics = {
            "total_packets": 0,
            "total_bytes": 0,
            "total_flows": 0,
            "threat_count": 0,
            "max_threat_score": 0.0,
            "current_rate_pps": 0.0,
            "protocol_breakdown": {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0},
            "threat_breakdown": {"BENIGN": 0, "DDoS / SYN Flood": 0, "PortScan Recon": 0, "SSH BruteForce": 0},
        }

        self._fusion_engine = None
        try:
            self._fusion_engine = ThreatFusionEngine()
        except Exception:
            pass

        # Pre-generate synthetic sample PCAPs if absent
        self._ensure_sample_pcaps()

    # -------------------------------------------------------------------------
    # SAMPLE PCAP GENERATION
    # -------------------------------------------------------------------------

    def _ensure_sample_pcaps(self):
        """Generates realistic synthetic PCAPs for DoS, PortScan, Hydra, and Benign if missing."""
        if not _HAS_SCAPY:
            return

        samples = {
            "syn_flood_ddos.pcap": self._generate_syn_flood_pcap,
            "port_scan_recon.pcap": self._generate_port_scan_pcap,
            "hydra_ssh_bruteforce.pcap": self._generate_ssh_bruteforce_pcap,
            "benign_web_traffic.pcap": self._generate_benign_traffic_pcap,
        }

        for filename, generator in samples.items():
            filepath = _PCAP_DIR / filename
            if not filepath.exists() or filepath.stat().st_size < 100:
                try:
                    generator(filepath)
                except Exception as exc:
                    print(f"[PCAP Service] Failed to create sample {filename}: {exc}", file=sys.stderr)

    def _generate_syn_flood_pcap(self, target_path: Path):
        """Generates 180 rapid TCP SYN packets attacking target web server."""
        packets = []
        target_ip = "10.0.0.80"
        target_port = 80
        base_time = time.time() - 300

        for i in range(180):
            src_ip = f"192.168.1.{random.randint(100, 240)}"
            sport = random.randint(30000, 65000)
            pkt_time = base_time + (i * 0.005)  # 200 packets per second
            
            p = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / \
                IP(src=src_ip, dst=target_ip, id=1000 + i, ttl=64) / \
                TCP(sport=sport, dport=target_port, flags="S", seq=100000 + i, window=1024)
            p.time = pkt_time
            packets.append(p)

        wrpcap(str(target_path), packets)

    def _generate_port_scan_pcap(self, target_path: Path):
        """Generates 140 SYN scan packets across 70 ports on target host."""
        packets = []
        attacker_ip = "192.168.1.105"
        target_ip = "10.0.0.15"
        target_ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
            1433, 1521, 3306, 3389, 5432, 5900, 8000, 8080, 8443, 8888, 9000,
            9092, 9200, 27017, 5000, 7000, 8081, 8082, 8088, 9001, 9002
        ]
        base_time = time.time() - 300

        for i, port in enumerate(target_ports * 4):
            sport = 49152 + (i % 1000)
            pkt_time = base_time + (i * 0.02)
            
            # SYN probe
            syn_pkt = Ether() / IP(src=attacker_ip, dst=target_ip, ttl=64) / \
                      TCP(sport=sport, dport=port, flags="S", seq=200000 + i, window=2048)
            syn_pkt.time = pkt_time
            packets.append(syn_pkt)

            # Target response: RST for closed, SYN/ACK for open 80, 443, 22
            if port in (80, 443, 22):
                sa_pkt = Ether() / IP(src=target_ip, dst=attacker_ip, ttl=64) / \
                         TCP(sport=port, dport=sport, flags="SA", seq=500000 + i, ack=200001 + i, window=8192)
                sa_pkt.time = pkt_time + 0.002
                packets.append(sa_pkt)
            else:
                rst_pkt = Ether() / IP(src=target_ip, dst=attacker_ip, ttl=64) / \
                          TCP(sport=port, dport=sport, flags="RA", seq=0, ack=200001 + i, window=0)
                rst_pkt.time = pkt_time + 0.002
                packets.append(rst_pkt)

        wrpcap(str(target_path), packets)

    def _generate_ssh_bruteforce_pcap(self, target_path: Path):
        """Generates 160 packets simulating high-concurrency SSH password dictionary brute forcing."""
        packets = []
        attacker_ip = "192.168.1.188"
        target_ip = "10.0.0.22"
        base_time = time.time() - 300
        cur_time = base_time

        for session_idx in range(12):
            sport = 45000 + session_idx
            # 1. 3-way handshake
            syn = Ether() / IP(src=attacker_ip, dst=target_ip) / TCP(sport=sport, dport=22, flags="S", seq=1000)
            syn.time = cur_time
            packets.append(syn)
            cur_time += 0.003

            sa = Ether() / IP(src=target_ip, dst=attacker_ip) / TCP(sport=22, dport=sport, flags="SA", seq=5000, ack=1001)
            sa.time = cur_time
            packets.append(sa)
            cur_time += 0.002

            ack = Ether() / IP(src=attacker_ip, dst=target_ip) / TCP(sport=sport, dport=22, flags="A", seq=1001, ack=5001)
            ack.time = cur_time
            packets.append(ack)
            cur_time += 0.005

            # 2. SSH Banner Exchange + Auth Payload
            banner_cli = Ether() / IP(src=attacker_ip, dst=target_ip) / TCP(sport=sport, dport=22, flags="PA", seq=1001, ack=5001) / Raw(load=b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
            banner_cli.time = cur_time
            packets.append(banner_cli)
            cur_time += 0.01

            banner_srv = Ether() / IP(src=target_ip, dst=attacker_ip) / TCP(sport=22, dport=sport, flags="PA", seq=5001, ack=1042) / Raw(load=b"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\r\n")
            banner_srv.time = cur_time
            packets.append(banner_srv)
            cur_time += 0.015

            # 3. Auth failure & RST/FIN
            rst = Ether() / IP(src=attacker_ip, dst=target_ip) / TCP(sport=sport, dport=22, flags="FA", seq=1042, ack=5043)
            rst.time = cur_time
            packets.append(rst)
            cur_time += 0.03

        wrpcap(str(target_path), packets)

    def _generate_benign_traffic_pcap(self, target_path: Path):
        """Generates 200 normal HTTP and HTTPS browsing packets with realistic payload sizes."""
        packets = []
        client_ip = "192.168.1.50"
        servers = [("93.184.216.34", 80), ("142.250.190.46", 443), ("104.16.132.229", 443)]
        base_time = time.time() - 300
        cur_time = base_time

        for idx in range(15):
            srv_ip, srv_port = random.choice(servers)
            sport = 52000 + idx

            # Handshake
            syn = Ether() / IP(src=client_ip, dst=srv_ip) / TCP(sport=sport, dport=srv_port, flags="S", seq=100, window=65535)
            syn.time = cur_time
            packets.append(syn)
            cur_time += 0.015

            sa = Ether() / IP(src=srv_ip, dst=client_ip) / TCP(sport=srv_port, dport=sport, flags="SA", seq=1000, ack=101, window=65535)
            sa.time = cur_time
            packets.append(sa)
            cur_time += 0.012

            ack = Ether() / IP(src=client_ip, dst=srv_ip) / TCP(sport=sport, dport=srv_port, flags="A", seq=101, ack=1001, window=65535)
            ack.time = cur_time
            packets.append(ack)
            cur_time += 0.02

            # Data Request
            req_data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n"
            req = Ether() / IP(src=client_ip, dst=srv_ip) / TCP(sport=sport, dport=srv_port, flags="PA", seq=101, ack=1001) / Raw(load=req_data)
            req.time = cur_time
            packets.append(req)
            cur_time += 0.03

            # Server Response (2 segments)
            resp1 = Ether() / IP(src=srv_ip, dst=client_ip) / TCP(sport=srv_port, dport=sport, flags="A", seq=1001, ack=101 + len(req_data)) / Raw(load=b"X" * 1200)
            resp1.time = cur_time
            packets.append(resp1)
            cur_time += 0.005

            resp2 = Ether() / IP(src=srv_ip, dst=client_ip) / TCP(sport=srv_port, dport=sport, flags="PA", seq=2201, ack=101 + len(req_data)) / Raw(load=b"Y" * 800)
            resp2.time = cur_time
            packets.append(resp2)
            cur_time += 0.01

            # Teardown
            fin = Ether() / IP(src=client_ip, dst=srv_ip) / TCP(sport=sport, dport=srv_port, flags="FA", seq=101 + len(req_data), ack=3001)
            fin.time = cur_time
            packets.append(fin)
            cur_time += 0.05

        wrpcap(str(target_path), packets)

    # -------------------------------------------------------------------------
    # PUBLIC QUERY & MANAGEMENT
    # -------------------------------------------------------------------------

    def list_available_pcaps(self) -> List[Dict[str, Any]]:
        """Returns catalog of sample and uploaded PCAP files with metadata."""
        results = []
        all_dirs = [("Sample", _PCAP_DIR), ("Uploaded", _UPLOAD_DIR)]

        metadata_map = {
            "syn_flood_ddos.pcap": {
                "title": "DDoS SYN Flood Attack Capture",
                "category": "DoS / DDoS Attack",
                "mitre": "T1498.001 - Network DoS",
                "description": "High-frequency TCP SYN packet burst saturating target port 80 with unacknowledged half-open connections.",
            },
            "port_scan_recon.pcap": {
                "title": "Horizontal TCP Port Scan Sweep",
                "category": "Discovery & Recon",
                "mitre": "T1046 - Network Service Discovery",
                "description": "Systematic TCP SYN sweep probing 35+ critical service ports across enterprise subnets.",
            },
            "hydra_ssh_bruteforce.pcap": {
                "title": "Hydra Multi-Threaded SSH Brute Force",
                "category": "Credential Access",
                "mitre": "T1110.001 - Password Guessing",
                "description": "High-velocity parallel SSH credential guessing and authentication attempt bursts on port 22.",
            },
            "benign_web_traffic.pcap": {
                "title": "Normal Web & TLS Baseline Session",
                "category": "Benign Baseline",
                "mitre": "N/A - Legitimate",
                "description": "Standard bi-directional HTTP/1.1 and TLS 1.3 user browsing traffic with valid handshake completions.",
            },
        }

        for source_type, directory in all_dirs:
            if not directory.exists():
                continue
            for f in sorted(directory.glob("*.pcap*")):
                meta = metadata_map.get(f.name, {
                    "title": f.name,
                    "category": "Custom Uploaded Capture",
                    "mitre": "T1071 - Application Protocol",
                    "description": f"User-uploaded packet capture ({round(f.stat().st_size / 1024, 1)} KB).",
                })
                
                pkt_count = 0
                try:
                    if _HAS_SCAPY:
                        pkts = rdpcap(str(f))
                        pkt_count = len(pkts)
                except Exception:
                    pkt_count = max(1, int(f.stat().st_size / 120))

                results.append({
                    "filename": f.name,
                    "path": str(f),
                    "source_type": source_type,
                    "size_bytes": f.stat().st_size,
                    "size_formatted": f"{round(f.stat().st_size / 1024, 1)} KB",
                    "packet_count": pkt_count,
                    "title": meta["title"],
                    "category": meta["category"],
                    "mitre": meta["mitre"],
                    "description": meta["description"],
                })

        return results

    def save_uploaded_file(self, filename: str, content: bytes) -> Dict[str, Any]:
        """Saves and inspects an uploaded .pcap or .pcapng file."""
        clean_name = os.path.basename(filename).replace(" ", "_")
        if not (clean_name.endswith(".pcap") or clean_name.endswith(".pcapng")):
            clean_name += ".pcap"

        target_file = _UPLOAD_DIR / clean_name
        with open(target_file, "wb") as f:
            f.write(content)

        pkt_count = 0
        if _HAS_SCAPY:
            try:
                pkts = rdpcap(str(target_file))
                pkt_count = len(pkts)
            except Exception as exc:
                print(f"[PCAP Upload] Scapy parse warning: {exc}", file=sys.stderr)

        return {
            "status": "success",
            "filename": clean_name,
            "size_bytes": len(content),
            "packet_count": pkt_count,
            "message": f"Successfully loaded {clean_name} ({pkt_count} packets).",
        }

    # -------------------------------------------------------------------------
    # PLAYBACK CONTROL
    # -------------------------------------------------------------------------

    def start_replay(self, filename: str, speed_multiplier: float = 1.0) -> Dict[str, Any]:
        """Starts real-time replaying and flow feature extraction of the given PCAP."""
        with self._lock:
            if self._status == "replaying":
                self.stop_replay()

            pcap_path = _PCAP_DIR / filename
            if not pcap_path.exists():
                pcap_path = _UPLOAD_DIR / filename
            if not pcap_path.exists():
                raise FileNotFoundError(f"PCAP file not found: {filename}")

            self._current_file = filename
            self._speed_multiplier = max(0.1, min(speed_multiplier, 50.0))
            self._status = "replaying"
            self._stop_event.clear()
            self._pause_event.set()
            self._processed_packets = 0
            self._packets_stream.clear()
            self._flows_extracted.clear()
            self._start_time = time.time()

            self._metrics = {
                "total_packets": 0,
                "total_bytes": 0,
                "total_flows": 0,
                "threat_count": 0,
                "max_threat_score": 0.0,
                "current_rate_pps": 0.0,
                "protocol_breakdown": {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0},
                "threat_breakdown": {"BENIGN": 0, "DDoS / SYN Flood": 0, "PortScan Recon": 0, "SSH BruteForce": 0},
            }

            self._thread = threading.Thread(
                target=self._replay_worker,
                args=(str(pcap_path),),
                daemon=True,
            )
            self._thread.start()

        return {
            "status": "started",
            "file": filename,
            "speed": self._speed_multiplier,
            "message": f"Started replaying {filename} at {self._speed_multiplier}x speed.",
        }

    def pause_replay(self):
        """Pauses the replay playback."""
        with self._lock:
            if self._status == "replaying":
                self._pause_event.clear()
                self._status = "paused"

    def resume_replay(self):
        """Resumes the paused playback."""
        with self._lock:
            if self._status == "paused":
                self._pause_event.set()
                self._status = "replaying"

    def stop_replay(self):
        """Stops the active replay thread."""
        self._stop_event.set()
        self._pause_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.5)
        with self._lock:
            self._status = "idle"

    # -------------------------------------------------------------------------
    # REPLAY WORKER & FLOW SCORING
    # -------------------------------------------------------------------------

    def _replay_worker(self, pcap_path: str):
        """Background thread executing packet-by-packet playback & flow feature extraction."""
        try:
            if not _HAS_SCAPY:
                self._status = "error"
                return

            packets = rdpcap(pcap_path)
            self._total_packets = len(packets)
            flow_collector = ScapyFlowCollector(flow_timeout=2.0, idle_threshold=0.5)

            last_pkt_time = None
            rate_window_start = time.time()
            packets_in_window = 0

            for idx, pkt in enumerate(packets):
                if self._stop_event.is_set():
                    break

                self._pause_event.wait()
                if self._stop_event.is_set():
                    break

                current_pkt_time = float(getattr(pkt, "time", time.time()))
                if last_pkt_time is not None:
                    delta = max(0.0, current_pkt_time - last_pkt_time)
                    sleep_sec = delta / self._speed_multiplier
                    if sleep_sec > 0.001:
                        time.sleep(min(sleep_sec, 0.2))
                else:
                    time.sleep(0.01)

                last_pkt_time = current_pkt_time

                pkt_info = self._format_packet(idx + 1, pkt)
                flow_collector._on_packet(pkt)

                with self._lock:
                    self._processed_packets = idx + 1
                    self._packets_stream.append(pkt_info)
                    if len(self._packets_stream) > self._max_packets_buffer:
                        self._packets_stream.pop(0)

                    self._metrics["total_packets"] += 1
                    self._metrics["total_bytes"] += pkt_info["length"]
                    proto = pkt_info["protocol"]
                    if proto in self._metrics["protocol_breakdown"]:
                        self._metrics["protocol_breakdown"][proto] += 1
                    else:
                        self._metrics["protocol_breakdown"]["Other"] += 1

                    packets_in_window += 1
                    now = time.time()
                    if now - rate_window_start >= 0.5:
                        self._metrics["current_rate_pps"] = round(packets_in_window / (now - rate_window_start), 1)
                        rate_window_start = now
                        packets_in_window = 0

                if (idx + 1) % 10 == 0 or (idx + 1) == len(packets):
                    completed_flows = flow_collector.pop_completed_flows(force_all=((idx + 1) == len(packets)))
                    if completed_flows:
                        self._process_flows(completed_flows)

            final_flows = flow_collector.pop_completed_flows(force_all=True)
            if final_flows:
                self._process_flows(final_flows)

            with self._lock:
                self._status = "completed"

        except Exception as exc:
            print(f"[PCAP Service] Error in replay worker: {exc}", file=sys.stderr)
            with self._lock:
                self._status = "error"

    def _format_packet(self, seq_id: int, pkt) -> Dict[str, Any]:
        """Formats a Scapy packet into a structured Wireshark-like representation."""
        proto_name = "Other"
        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        src_port = 0
        dst_port = 0
        flags_str = ""
        info = ""

        if IP in pkt:
            ip = pkt[IP]
            src_ip = ip.src
            dst_ip = ip.dst

            if TCP in pkt:
                proto_name = "TCP"
                tcp = pkt[TCP]
                src_port = int(tcp.sport)
                dst_port = int(tcp.dport)
                flags = int(tcp.flags)
                flag_names = []
                if flags & 0x02: flag_names.append("SYN")
                if flags & 0x10: flag_names.append("ACK")
                if flags & 0x08: flag_names.append("PSH")
                if flags & 0x01: flag_names.append("FIN")
                if flags & 0x04: flag_names.append("RST")
                flags_str = "[" + ", ".join(flag_names) + "]" if flag_names else "[]"
                info = f"{src_port} \u2192 {dst_port} {flags_str} Seq={tcp.seq} Win={tcp.window} Len={len(tcp.payload)}"
            elif UDP in pkt:
                proto_name = "UDP"
                udp = pkt[UDP]
                src_port = int(udp.sport)
                dst_port = int(udp.dport)
                info = f"{src_port} \u2192 {dst_port} Len={len(udp.payload)}"
            elif ICMP in pkt:
                proto_name = "ICMP"
                icmp = pkt[ICMP]
                info = f"Type={icmp.type} Code={icmp.code}"
        
        pkt_len = len(pkt)
        return {
            "id": seq_id,
            "timestamp": round(float(getattr(pkt, "time", time.time())), 4),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto_name,
            "length": pkt_len,
            "flags": flags_str,
            "info": info or f"{proto_name} Frame ({pkt_len} bytes)",
        }

    def _process_flows(self, flow_dicts: List[Dict[str, Any]]):
        """Evaluates CICIDS flow feature dicts and classifies threats."""
        for flow in flow_dicts:
            flow_id = f"flow_{len(self._flows_extracted) + 1}"
            flow_threat_score = 0.0
            predicted_label = "BENIGN"

            if self._fusion_engine:
                try:
                    score = self._fusion_engine.score_network_flow(flow)
                    if score is not None:
                        flow_threat_score = float(score)
                except Exception:
                    pass

            syn_cnt = float(flow.get("SYN Flag Count", 0.0))
            ack_cnt = float(flow.get("ACK Flag Count", 0.0))
            fwd_pkts = float(flow.get("Total Fwd Packets", 1.0))
            bwd_pkts = float(flow.get("Total Backward Packets", 0.0))
            flow_duration = float(flow.get("Flow Duration", 1000.0))
            dst_port = int(flow.get("Destination Port", 0))

            if syn_cnt > 15 and ack_cnt < 2:
                flow_threat_score = max(flow_threat_score, 0.94)
                predicted_label = "DDoS / SYN Flood"
            elif (fwd_pkts + bwd_pkts) < 4 and flow_duration < 50000 and syn_cnt >= 1:
                flow_threat_score = max(flow_threat_score, 0.88)
                predicted_label = "PortScan Recon"
            elif dst_port == 22 and fwd_pkts > 8:
                flow_threat_score = max(flow_threat_score, 0.91)
                predicted_label = "SSH BruteForce"
            elif flow_threat_score > 0.6:
                predicted_label = "Suspicious Network Flow"
            else:
                predicted_label = "BENIGN"

            top_features = [
                {"name": "SYN Flag Count", "value": f"{int(syn_cnt)}", "importance": 0.35 if syn_cnt > 5 else 0.05},
                {"name": "ACK Flag Count", "value": f"{int(ack_cnt)}", "importance": -0.25 if ack_cnt > 5 else 0.20},
                {"name": "Flow Packets/s", "value": f"{round(float(flow.get('Flow Packets/s', 0.0)), 1)}", "importance": 0.28},
                {"name": "Destination Port", "value": str(dst_port), "importance": 0.18},
                {"name": "Flow Duration (µs)", "value": f"{int(flow_duration)}", "importance": 0.15},
            ]

            is_threat = flow_threat_score >= 0.65

            flow_record = {
                "flow_id": flow_id,
                "protocol": "TCP" if syn_cnt > 0 or ack_cnt > 0 else "UDP",
                "dst_port": dst_port,
                "fwd_packets": int(fwd_pkts),
                "bwd_packets": int(bwd_pkts),
                "total_packets": int(fwd_pkts + bwd_pkts),
                "total_bytes": int(float(flow.get("Total Length of Fwd Packets", 0)) + float(flow.get("Total Length of Bwd Packets", 0))),
                "duration_ms": round(flow_duration / 1000.0, 2),
                "threat_score": round(flow_threat_score, 3),
                "threat_label": predicted_label,
                "is_threat": is_threat,
                "top_features": top_features,
                "raw_features": {k: round(v, 4) if isinstance(v, float) else v for k, v in list(flow.items())[:20]},
            }

            with self._lock:
                self._flows_extracted.append(flow_record)
                if len(self._flows_extracted) > self._max_flows_buffer:
                    self._flows_extracted.pop(0)

                self._metrics["total_flows"] += 1
                if is_threat:
                    self._metrics["threat_count"] += 1
                self._metrics["max_threat_score"] = max(self._metrics["max_threat_score"], flow_threat_score)
                if predicted_label in self._metrics["threat_breakdown"]:
                    self._metrics["threat_breakdown"][predicted_label] += 1
                elif is_threat:
                    self._metrics["threat_breakdown"]["PortScan Recon"] += 1
                else:
                    self._metrics["threat_breakdown"]["BENIGN"] += 1

    # -------------------------------------------------------------------------
    # STATE STATUS
    # -------------------------------------------------------------------------

    def get_status(self) -> Dict[str, Any]:
        """Returns the full replay engine state, latest packets slice, and extracted flows."""
        with self._lock:
            pct = 0.0
            if self._total_packets > 0:
                pct = round((self._processed_packets / self._total_packets) * 100.0, 1)

            elapsed = 0.0
            if self._start_time > 0:
                elapsed = round(time.time() - self._start_time, 2)

            return {
                "status": self._status,
                "current_file": self._current_file,
                "speed_multiplier": self._speed_multiplier,
                "progress": {
                    "total_packets": self._total_packets,
                    "processed_packets": self._processed_packets,
                    "percent": pct,
                    "elapsed_seconds": elapsed,
                },
                "metrics": self._metrics,
                "recent_packets": self._packets_stream[-60:],
                "recent_flows": self._flows_extracted[-30:],
            }


# Singleton service instance
pcap_service = PcapReplayerService()
