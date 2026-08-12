"""
agent/scapy_flow_collector.py
================================
Fixes CICIDS's "flow not extracted correctly" issue: the old
NetworkFlowCollector (in live_collectors.py) hardcoded packet/byte counts to
0.0 because it only used psutil connection snapshots, not real packets.

This version uses scapy to sniff real packets and aggregate them into proper
per-flow stats -- actual forward/backward packet counts and byte totals --
matching the CICIDS feature names far more closely.

Install (if not already):
    pip install scapy

IMPORTANT: sniffing packets requires Administrator/root privileges and
Npcap installed on Windows (https://npcap.com/#download) -- scapy needs this
to capture from a network interface on Windows.

Usage (drop-in replacement for NetworkFlowCollector):
    from scapy_flow_collector import ScapyFlowCollector
    collector = ScapyFlowCollector(flow_timeout=10)
    collector.start()
    ...
    for flow in collector.pop_completed_flows():
        score = engine.score_network_flow(flow)
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
    Aggregates sniffed packets into CICIDS-style flow feature dicts with
    REAL packet/byte counts (unlike the psutil-only version).

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

        if TCP in pkt:
            proto = "TCP"
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            proto = "UDP"
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
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
                }
            flow = self._flows[key]
            flow["last"] = now
            if (src, sport) == flow["fwd_key"]:
                flow["fwd_packets"] += 1
                flow["fwd_bytes"] += length
            else:
                flow["bwd_packets"] += 1
                flow["bwd_bytes"] += length

    def start(self):
        if sniff is None:
            raise RuntimeError(
                "scapy is not installed. Run: pip install scapy\n"
                "On Windows you also need Npcap: https://npcap.com/#download"
            )
        self._sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._sniff_thread.start()

    def _sniff_loop(self):
        # store=False keeps memory flat; stop_filter lets us exit cleanly
        sniff(prn=self._on_packet, store=False, stop_filter=lambda p: self._stop.is_set())

    def pop_completed_flows(self) -> List[Dict[str, float]]:
        """
        Call this periodically (e.g. every 5s). Returns CICIDS-shaped feature
        dicts for any flow that's been idle longer than flow_timeout, and
        removes them from the internal buffer.
        """
        now = time.time()
        completed = []
        with self._lock:
            stale_keys = [k for k, f in self._flows.items() if now - f["last"] > self.flow_timeout]
            for k in stale_keys:
                flow = self._flows.pop(k)
                completed.append({
                    "Destination Port": float(flow["dst_port"]),
                    "Flow Duration": float((flow["last"] - flow["start"]) * 1000),  # ms
                    "Total Fwd Packets": float(flow["fwd_packets"]),
                    "Total Backward Packets": float(flow["bwd_packets"]),
                    "Total Length of Fwd Packets": float(flow["fwd_bytes"]),
                    "Total Length of Bwd Packets": float(flow["bwd_bytes"]),
                })
        return completed

    def stop(self):
        self._stop.set()