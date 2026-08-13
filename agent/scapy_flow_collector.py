"""
agent/scapy_flow_collector.py
================================
Aggregates sniffed network packets into CICIDS-style flow feature dicts with
REAL packet/byte counts, TCP flag counts, header lengths, initial window sizes,
and inter-arrival time (IAT) statistics.

Column names in emitted dicts EXACTLY match trained feature names in the
CICIDS LightGBM model export (aegis_lgbm_cicids_model.pkl).

Install (if not already):
    pip install scapy

IMPORTANT: sniffing packets requires Administrator/root privileges and
Npcap installed on Windows (https://npcap.com/#download).
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Dict, List, Tuple

try:
    from scapy.all import sniff, IP, TCP, UDP
except ImportError:
    sniff = None  # handled at start() time with a clear error


class ScapyFlowCollector:
    """
    Aggregates sniffed packets into CICIDS-style flow feature dicts.

    A "flow" is keyed by (src_ip, src_port, dst_ip, dst_port, protocol).
    The FIRST direction seen for a key is "forward"; replies in the reverse
    direction are counted as "backward" -- standard flow convention.
    """

    def __init__(self, flow_timeout: float = 10.0):
        self.flow_timeout = flow_timeout
        self._flows: Dict[tuple, dict] = {}
        self._lock = threading.Lock()
        self._sniff_thread = None
        self._stop = threading.Event()

    def _flow_key(self, src_ip, src_port, dst_ip, dst_port, proto) -> Tuple:
        """Canonical key so both directions of a conversation map to one flow."""
        a = (src_ip, src_port)
        b = (dst_ip, dst_port)
        if a <= b:
            return (a, b, proto)
        return (b, a, proto)

    def _on_packet(self, pkt):
        if IP not in pkt:
            return
        ip_layer = pkt[IP]
        length = len(pkt)

        fin = syn = rst = psh = ack = urg = ece = cwe = 0
        hdr_len = 20  # default IP header len
        win_size = 0
        payload_len = 0

        if TCP in pkt:
            proto = "TCP"
            tcp = pkt[TCP]
            sport, dport = tcp.sport, tcp.dport
            flags = int(tcp.flags)
            fin = 1 if (flags & 0x01) else 0
            syn = 1 if (flags & 0x02) else 0
            rst = 1 if (flags & 0x04) else 0
            psh = 1 if (flags & 0x08) else 0
            ack = 1 if (flags & 0x10) else 0
            urg = 1 if (flags & 0x20) else 0
            ece = 1 if (flags & 0x40) else 0
            cwe = 1 if (flags & 0x80) else 0

            data_offset = getattr(tcp, "dataofs", 5) or 5
            hdr_len = data_offset * 4
            win_size = int(getattr(tcp, "window", 0) or 0)

            payload = bytes(tcp.payload) if hasattr(tcp, "payload") else b""
            payload_len = len(payload)
        elif UDP in pkt:
            proto = "UDP"
            udp = pkt[UDP]
            sport, dport = udp.sport, udp.dport
            hdr_len = 8
            payload = bytes(udp.payload) if hasattr(udp, "payload") else b""
            payload_len = len(payload)
        else:
            return

        src, dst = ip_layer.src, ip_layer.dst
        key = self._flow_key(src, sport, dst, dport, proto)
        now = time.time()

        with self._lock:
            if key not in self._flows:
                self._flows[key] = {
                    "start": now,
                    "last": now,
                    "fwd_key": (src, sport),  # first-seen direction = forward
                    "dst_port": dport,
                    "fwd_packets": 0,
                    "bwd_packets": 0,
                    "fwd_bytes": 0,
                    "bwd_bytes": 0,
                    "fwd_lengths": [],
                    "bwd_lengths": [],
                    "fwd_times": [now],
                    "bwd_times": [],
                    "flow_times": [now],
                    "fwd_hdr_len": 0,
                    "bwd_hdr_len": 0,
                    "fin_cnt": 0,
                    "syn_cnt": 0,
                    "rst_cnt": 0,
                    "psh_cnt": 0,
                    "ack_cnt": 0,
                    "urg_cnt": 0,
                    "ece_cnt": 0,
                    "cwe_cnt": 0,
                    "fwd_psh": 0,
                    "bwd_psh": 0,
                    "fwd_urg": 0,
                    "bwd_urg": 0,
                    "init_win_fwd": 0,
                    "init_win_bwd": 0,
                    "act_data_pkt_fwd": 0,
                    "min_seg_size_fwd": hdr_len,
                }
            flow = self._flows[key]
            flow["last"] = now
            flow["flow_times"].append(now)

            flow["fin_cnt"] += fin
            flow["syn_cnt"] += syn
            flow["rst_cnt"] += rst
            flow["psh_cnt"] += psh
            flow["ack_cnt"] += ack
            flow["urg_cnt"] += urg
            flow["ece_cnt"] += ece
            flow["cwe_cnt"] += cwe

            if (src, sport) == flow["fwd_key"]:
                flow["fwd_packets"] += 1
                flow["fwd_bytes"] += length
                flow["fwd_lengths"].append(length)
                flow["fwd_times"].append(now)
                flow["fwd_hdr_len"] += hdr_len
                flow["fwd_psh"] += psh
                flow["fwd_urg"] += urg
                if flow["init_win_fwd"] == 0 and win_size > 0:
                    flow["init_win_fwd"] = win_size
                if payload_len > 0:
                    flow["act_data_pkt_fwd"] += 1
                if flow["min_seg_size_fwd"] == 0 or hdr_len < flow["min_seg_size_fwd"]:
                    flow["min_seg_size_fwd"] = hdr_len
            else:
                flow["bwd_packets"] += 1
                flow["bwd_bytes"] += length
                flow["bwd_lengths"].append(length)
                flow["bwd_times"].append(now)
                flow["bwd_hdr_len"] += hdr_len
                flow["bwd_psh"] += psh
                flow["bwd_urg"] += urg
                if flow["init_win_bwd"] == 0 and win_size > 0:
                    flow["init_win_bwd"] = win_size

    def start(self):
        if sniff is None:
            raise RuntimeError(
                "scapy is not installed. Run: pip install scapy\n"
                "On Windows you also need Npcap: https://npcap.com/#download"
            )
        self._sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._sniff_thread.start()

    def _sniff_loop(self):
        sniff(prn=self._on_packet, store=False, stop_filter=lambda p: self._stop.is_set())

    @staticmethod
    def _calc_iats(timestamps: List[float]) -> Tuple[float, float, float, float]:
        """Return (Total_IAT_us, Mean_IAT_us, Max_IAT_us, Min_IAT_us). Timestamps in sec, result in microseconds."""
        if len(timestamps) < 2:
            return 0.0, 0.0, 0.0, 0.0
        iats_us = [(timestamps[i] - timestamps[i - 1]) * 1e6 for i in range(1, len(timestamps))]
        tot = sum(iats_us)
        mean = tot / len(iats_us)
        mx = max(iats_us)
        mn = min(iats_us)
        return tot, mean, mx, mn

    def pop_completed_flows(self, force_all: bool = False) -> List[Dict[str, float]]:
        """
        Call this periodically (e.g. every 1-5s). Returns CICIDS-shaped feature
        dicts with exact trained column names for any flow idle longer than flow_timeout
        (or all buffered flows if force_all=True).
        """
        now = time.time()
        completed = []
        with self._lock:
            if force_all:
                stale_keys = list(self._flows.keys())
            else:
                stale_keys = [k for k, f in self._flows.items() if now - f["last"] > self.flow_timeout]
            for k in stale_keys:
                flow = self._flows.pop(k)
                duration_sec = flow["last"] - flow["start"]
                duration_us = duration_sec * 1e6
                duration_ms = duration_sec * 1000.0

                fwd_len = flow["fwd_lengths"]
                bwd_len = flow["bwd_lengths"]
                all_len = fwd_len + bwd_len

                fwd_max = float(max(fwd_len)) if fwd_len else 0.0
                fwd_min = float(min(fwd_len)) if fwd_len else 0.0
                fwd_mean = float(sum(fwd_len) / len(fwd_len)) if fwd_len else 0.0

                bwd_max = float(max(bwd_len)) if bwd_len else 0.0
                bwd_min = float(min(bwd_len)) if bwd_len else 0.0
                bwd_mean = float(sum(bwd_len) / len(bwd_len)) if bwd_len else 0.0

                tot_bytes = float(flow["fwd_bytes"] + flow["bwd_bytes"])
                tot_pkts = float(flow["fwd_packets"] + flow["bwd_packets"])

                flow_bytes_sec = (tot_bytes / duration_sec) if duration_sec > 0 else 0.0
                flow_pkts_sec = (tot_pkts / duration_sec) if duration_sec > 0 else 0.0

                all_max = float(max(all_len)) if all_len else 0.0
                all_min = float(min(all_len)) if all_len else 0.0
                all_mean = float(tot_bytes / tot_pkts) if tot_pkts > 0 else 0.0

                flow_tot_iat, flow_mean_iat, flow_max_iat, flow_min_iat = self._calc_iats(flow["flow_times"])
                fwd_tot_iat, fwd_mean_iat, fwd_max_iat, fwd_min_iat = self._calc_iats(flow["fwd_times"])
                bwd_tot_iat, bwd_mean_iat, bwd_max_iat, bwd_min_iat = self._calc_iats(flow["bwd_times"])

                flow_dict = {
                    "Destination Port": float(flow["dst_port"]),
                    "Flow Duration": float(duration_us),
                    "Total Fwd Packets": float(flow["fwd_packets"]),
                    "Total Backward Packets": float(flow["bwd_packets"]),
                    "Total Length of Fwd Packets": float(flow["fwd_bytes"]),
                    "Total Length of Bwd Packets": float(flow["bwd_bytes"]),
                    "Fwd Packet Length Max": fwd_max,
                    "Fwd Packet Length Min": fwd_min,
                    "Fwd Packet Length Mean": fwd_mean,
                    "Bwd Packet Length Max": bwd_max,
                    "Bwd Packet Length Min": bwd_min,
                    "Bwd Packet Length Mean": bwd_mean,
                    "Flow Bytes/s": flow_bytes_sec,
                    "Flow Packets/s": flow_pkts_sec,
                    "Flow IAT Mean": flow_mean_iat,
                    "Flow IAT Max": flow_max_iat,
                    "Flow IAT Min": flow_min_iat,
                    "Fwd IAT Total": fwd_tot_iat,
                    "Fwd IAT Mean": fwd_mean_iat,
                    "Fwd IAT Max": fwd_max_iat,
                    "Fwd IAT Min": fwd_min_iat,
                    "Bwd IAT Total": bwd_tot_iat,
                    "Bwd IAT Mean": bwd_mean_iat,
                    "Bwd IAT Max": bwd_max_iat,
                    "Bwd IAT Min": bwd_min_iat,
                    "Fwd PSH Flags": float(flow["fwd_psh"]),
                    "Bwd PSH Flags": float(flow["bwd_psh"]),
                    "Fwd URG Flags": float(flow["fwd_urg"]),
                    "Bwd URG Flags": float(flow["bwd_urg"]),
                    "Fwd Header Length": float(flow["fwd_hdr_len"]),
                    "Bwd Header Length": float(flow["bwd_hdr_len"]),
                    "Fwd Packets/s": float(flow["fwd_packets"] / duration_sec) if duration_sec > 0 else 0.0,
                    "Bwd Packets/s": float(flow["bwd_packets"] / duration_sec) if duration_sec > 0 else 0.0,
                    "Min Packet Length": all_min,
                    "Max Packet Length": all_max,
                    "Packet Length Mean": all_mean,
                    "FIN Flag Count": float(flow["fin_cnt"]),
                    "SYN Flag Count": float(flow["syn_cnt"]),
                    "RST Flag Count": float(flow["rst_cnt"]),
                    "PSH Flag Count": float(flow["psh_cnt"]),
                    "ACK Flag Count": float(flow["ack_cnt"]),
                    "URG Flag Count": float(flow["urg_cnt"]),
                    "CWE Flag Count": float(flow["cwe_cnt"]),
                    "ECE Flag Count": float(flow["ece_cnt"]),
                    "Down/Up Ratio": float(flow["bwd_packets"] / flow["fwd_packets"]) if flow["fwd_packets"] > 0 else 0.0,
                    "Average Packet Size": all_mean,
                    "Avg Fwd Segment Size": fwd_mean,
                    "Avg Bwd Segment Size": bwd_mean,
                    "Fwd Header Length.1": float(flow["fwd_hdr_len"]),
                    "Subflow Fwd Packets": float(flow["fwd_packets"]),
                    "Subflow Fwd Bytes": float(flow["fwd_bytes"]),
                    "Subflow Bwd Packets": float(flow["bwd_packets"]),
                    "Subflow Bwd Bytes": float(flow["bwd_bytes"]),
                    "Init_Win_bytes_forward": float(flow["init_win_fwd"]),
                    "Init_Win_bytes_backward": float(flow["init_win_bwd"]),
                    "act_data_pkt_fwd": float(flow["act_data_pkt_fwd"]),
                    "min_seg_size_forward": float(flow["min_seg_size_fwd"]),
                }
                completed.append(flow_dict)
        return completed

    def stop(self):
        self._stop.set()