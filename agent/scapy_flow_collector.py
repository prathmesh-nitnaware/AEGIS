"""
agent/scapy_flow_collector.py
=============================
Aggregates sniffed network packets into CICIDS-style flow feature dicts with
REAL packet/byte counts, TCP flag counts, header lengths, initial window sizes,
inter-arrival time (IAT) statistics, packet length statistics,
active/idle statistics, and bulk flow metrics.

Column names in emitted dicts EXACTLY match trained feature names (all 78
columns) in the CICIDS LightGBM model export.

Windows:
- Npcap is required.
- For localhost / 127.0.0.1 traffic, use:
    iface=r"\\Device\\NPF_Loopback"
"""

from __future__ import annotations

import math
import threading
import time
from collections import defaultdict
from typing import Dict, List, Tuple, Optional

import numpy as np

try:
    from scapy.all import sniff, IP, TCP, UDP
except ImportError:
    sniff = None


class ScapyFlowCollector:
    """
    Aggregates sniffed packets into CICIDS-style flow features.

    A flow is identified by the two endpoints and protocol.

    The first direction seen for a flow is treated as forward.
    Reverse packets are treated as backward.

    iface:
        Scapy interface used for packet capture.

        For Windows localhost traffic:
            r"\\Device\\NPF_Loopback"

        If None, Scapy chooses its default interface.
    """

    def __init__(
        self,
        flow_timeout: float = 10.0,
        idle_threshold: float = 1.0,
        iface: Optional[str] = None,
    ):
        self.flow_timeout = flow_timeout
        self.idle_threshold = idle_threshold
        self.iface = iface

        self._flows: Dict[tuple, dict] = {}
        self._lock = threading.Lock()

        self._sniff_thread = None
        self._stop = threading.Event()

    # ------------------------------------------------------------------
    # FLOW KEY
    # ------------------------------------------------------------------

    def _flow_key(
        self,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        proto,
    ) -> Tuple:
        """
        Canonical key so both directions of a conversation
        map to the same flow.
        """

        a = (src_ip, src_port)
        b = (dst_ip, dst_port)

        if a <= b:
            return (a, b, proto)

        return (b, a, proto)

    # ------------------------------------------------------------------
    # PACKET PROCESSING
    # ------------------------------------------------------------------

    def _on_packet(self, pkt):

        if IP not in pkt:
            return

        ip_layer = pkt[IP]

        # Default packet properties
        fin = 0
        syn = 0
        rst = 0
        psh = 0
        ack = 0
        urg = 0
        ece = 0
        cwe = 0

        hdr_len = 20
        win_size = 0
        payload_len = 0

        # --------------------------------------------------------------
        # TCP
        # --------------------------------------------------------------

        if TCP in pkt:

            proto = "TCP"

            tcp = pkt[TCP]

            sport = int(tcp.sport)
            dport = int(tcp.dport)

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

            hdr_len = int(data_offset) * 4

            win_size = int(
                getattr(tcp, "window", 0) or 0
            )

            payload = (
                bytes(tcp.payload)
                if hasattr(tcp, "payload")
                else b""
            )

            payload_len = len(payload)

        # --------------------------------------------------------------
        # UDP
        # --------------------------------------------------------------

        elif UDP in pkt:

            proto = "UDP"

            udp = pkt[UDP]

            sport = int(udp.sport)
            dport = int(udp.dport)

            hdr_len = 8

            payload = (
                bytes(udp.payload)
                if hasattr(udp, "payload")
                else b""
            )

            payload_len = len(payload)

        else:
            return

        src = ip_layer.src
        dst = ip_layer.dst

        key = self._flow_key(
            src,
            sport,
            dst,
            dport,
            proto,
        )

        # Use the packet's libpcap capture timestamp (what CICFlowMeter uses
        # for every time-based CICIDS feature) rather than the wall-clock time
        # of this callback. The callback runs after sniff dispatch and thread
        # scheduling, adding hundreds of microseconds to milliseconds of
        # latency -- that jitter dwarfs the real sub-100us gaps in a port-scan
        # flow and made Flow Duration / Flow IAT / all per-second rate features
        # come out 10-100x wrong, pushing scan flows into the benign region.
        try:
            now = float(pkt.time)
        except (AttributeError, TypeError, ValueError):
            now = time.time()
        if now <= 0.0:
            now = time.time()

        # --------------------------------------------------------------
        # ADD / UPDATE FLOW
        # --------------------------------------------------------------

        with self._lock:

            if key not in self._flows:

                self._flows[key] = {

                    "start": now,
                    "last": now,

                    # First observed direction
                    "fwd_key": (src, sport),

                    "dst_port": dport,

                    # Packet counts
                    "fwd_packets": 0,
                    "bwd_packets": 0,

                    # Byte counts
                    "fwd_bytes": 0,
                    "bwd_bytes": 0,

                    # Packet lengths
                    "fwd_lengths": [],
                    "bwd_lengths": [],

                    # Packet timestamps (populated by the per-packet appends
                    # below -- must start empty so the first packet is not
                    # counted twice, which would inject a spurious 0 into the
                    # Flow/Fwd IAT statistics)
                    "fwd_times": [],
                    "bwd_times": [],

                    # All timestamps
                    "flow_times": [],

                    # Header lengths
                    "fwd_hdr_len": 0,
                    "bwd_hdr_len": 0,

                    # TCP flags
                    "fin_cnt": 0,
                    "syn_cnt": 0,
                    "rst_cnt": 0,
                    "psh_cnt": 0,
                    "ack_cnt": 0,
                    "urg_cnt": 0,
                    "ece_cnt": 0,
                    "cwe_cnt": 0,

                    # Direction-specific flags
                    "fwd_psh": 0,
                    "bwd_psh": 0,

                    "fwd_urg": 0,
                    "bwd_urg": 0,

                    # Initial TCP windows
                    "init_win_fwd": 0,
                    "init_win_bwd": 0,

                    # Active data packets
                    "act_data_pkt_fwd": 0,

                    # Minimum segment size
                    "min_seg_size_fwd": hdr_len,
                }

            flow = self._flows[key]

            flow["last"] = now

            flow["flow_times"].append(now)

            # ----------------------------------------------------------
            # TCP FLAG COUNTS
            # ----------------------------------------------------------

            flow["fin_cnt"] += fin
            flow["syn_cnt"] += syn
            flow["rst_cnt"] += rst
            flow["psh_cnt"] += psh
            flow["ack_cnt"] += ack
            flow["urg_cnt"] += urg
            flow["ece_cnt"] += ece
            flow["cwe_cnt"] += cwe

            # ----------------------------------------------------------
            # FORWARD DIRECTION
            # ----------------------------------------------------------

            if (src, sport) == flow["fwd_key"]:

                flow["fwd_packets"] += 1

                flow["fwd_bytes"] += payload_len

                flow["fwd_lengths"].append(payload_len)

                flow["fwd_times"].append(now)

                flow["fwd_hdr_len"] += hdr_len

                flow["fwd_psh"] += psh

                flow["fwd_urg"] += urg

                # Initial forward window
                if (
                    flow["init_win_fwd"] == 0
                    and win_size > 0
                ):
                    flow["init_win_fwd"] = win_size

                # Active data packet
                if payload_len > 0:
                    flow["act_data_pkt_fwd"] += 1

                # Minimum segment size
                if (
                    flow["min_seg_size_fwd"] == 0
                    or hdr_len < flow["min_seg_size_fwd"]
                ):
                    flow["min_seg_size_fwd"] = hdr_len

            # ----------------------------------------------------------
            # BACKWARD DIRECTION
            # ----------------------------------------------------------

            else:

                flow["bwd_packets"] += 1

                flow["bwd_bytes"] += payload_len

                flow["bwd_lengths"].append(payload_len)

                flow["bwd_times"].append(now)

                flow["bwd_hdr_len"] += hdr_len

                flow["bwd_psh"] += psh

                flow["bwd_urg"] += urg

                # Initial backward window
                if (
                    flow["init_win_bwd"] == 0
                    and win_size > 0
                ):
                    flow["init_win_bwd"] = win_size

    # ------------------------------------------------------------------
    # START CAPTURE
    # ------------------------------------------------------------------

    def start(self):

        if sniff is None:

            raise RuntimeError(
                "Scapy is not installed.\n"
                "Run: pip install scapy\n"
                "On Windows you also need Npcap."
            )

        self._stop.clear()

        self._sniff_thread = threading.Thread(
            target=self._sniff_loop,
            daemon=True,
        )

        self._sniff_thread.start()

    # ------------------------------------------------------------------
    # SNIFF LOOP
    # ------------------------------------------------------------------

    def _sniff_loop(self):

        try:

            sniff(
                iface=self.iface,
                prn=self._on_packet,
                store=False,
                stop_filter=lambda p: self._stop.is_set(),
            )

        except Exception as exc:

            print(
                f"[ScapyFlowCollector] Capture error: {exc}"
            )

    # ------------------------------------------------------------------
    # BASIC STATISTICS
    # ------------------------------------------------------------------

    @staticmethod
    def _calc_stats(
        values: List[float],
    ) -> Tuple[float, float, float, float]:
        """
        Returns:

            Mean
            Std
            Max
            Min
        """

        if not values:

            return (
                0.0,
                0.0,
                0.0,
                0.0,
            )

        arr = np.array(
            values,
            dtype=np.float64,
        )

        mean = float(np.mean(arr))

        std = (
            float(np.std(arr, ddof=1))
            if len(arr) > 1
            else 0.0
        )

        mx = float(np.max(arr))

        mn = float(np.min(arr))

        return (
            mean,
            std,
            mx,
            mn,
        )

    # ------------------------------------------------------------------
    # IAT STATISTICS
    # ------------------------------------------------------------------

    @staticmethod
    def _calc_iats(
        timestamps: List[float],
    ) -> Tuple[
        float,
        float,
        float,
        float,
        float,
    ]:

        """
        Returns:

            Total IAT
            Mean IAT
            Std IAT
            Max IAT
            Min IAT

        All values are in microseconds.
        """

        if len(timestamps) < 2:

            return (
                0.0,
                0.0,
                0.0,
                0.0,
                0.0,
            )

        iats_us = [
            (
                timestamps[i]
                - timestamps[i - 1]
            )
            * 1e6
            for i in range(
                1,
                len(timestamps),
            )
        ]

        arr = np.array(
            iats_us,
            dtype=np.float64,
        )

        total = float(
            np.sum(arr)
        )

        mean = float(
            np.mean(arr)
        )

        std = (
            float(np.std(arr, ddof=1))
            if len(arr) > 1
            else 0.0
        )

        mx = float(
            np.max(arr)
        )

        mn = float(
            np.min(arr)
        )

        return (
            total,
            mean,
            std,
            mx,
            mn,
        )

    # ------------------------------------------------------------------
    # ACTIVE / IDLE
    # ------------------------------------------------------------------

    @staticmethod
    def _calc_active_idle(
        timestamps: List[float],
        idle_thresh_sec: float = 1.0,
    ):

        """
        Calculates active and idle timing statistics.

        Returns values in microseconds.
        """

        if len(timestamps) < 2:

            return (
                (
                    0.0,
                    0.0,
                    0.0,
                    0.0,
                ),
                (
                    0.0,
                    0.0,
                    0.0,
                    0.0,
                ),
            )

        active_times_us = []

        idle_times_us = []

        current_active_start = timestamps[0]

        last_timestamp = timestamps[0]

        for ts in timestamps[1:]:

            gap = ts - last_timestamp

            if gap > idle_thresh_sec:

                active_duration = (
                    last_timestamp
                    - current_active_start
                ) * 1e6

                if active_duration > 0:

                    active_times_us.append(
                        active_duration
                    )

                idle_times_us.append(
                    gap * 1e6
                )

                current_active_start = ts

            last_timestamp = ts

        # Final active block

        final_active = (
            last_timestamp
            - current_active_start
        ) * 1e6

        if final_active > 0:

            active_times_us.append(
                final_active
            )

        (
            act_mean,
            act_std,
            act_max,
            act_min,
        ) = ScapyFlowCollector._calc_stats(
            active_times_us
        )

        (
            idle_mean,
            idle_std,
            idle_max,
            idle_min,
        ) = ScapyFlowCollector._calc_stats(
            idle_times_us
        )

        return (
            (
                act_mean,
                act_std,
                act_max,
                act_min,
            ),
            (
                idle_mean,
                idle_std,
                idle_max,
                idle_min,
            ),
        )

    # ------------------------------------------------------------------
    # POP COMPLETED FLOWS
    # ------------------------------------------------------------------

    def pop_completed_flows(
        self,
        force_all: bool = False,
    ) -> List[Dict[str, float]]:

        """
        Returns completed flows using the exact
        78 CICIDS feature names.

        A flow is completed when it has been idle
        longer than flow_timeout.

        force_all=True returns all current flows.
        """

        now = time.time()

        completed = []

        with self._lock:

            if force_all:

                stale_keys = list(
                    self._flows.keys()
                )

            else:

                stale_keys = [
                    k
                    for k, f in self._flows.items()
                    if now - f["last"]
                    > self.flow_timeout
                ]

            for k in stale_keys:

                flow = self._flows.pop(k)

                duration_sec = (
                    flow["last"]
                    - flow["start"]
                )

                duration_us = (
                    duration_sec * 1e6
                )

                fwd_len = flow[
                    "fwd_lengths"
                ]

                bwd_len = flow[
                    "bwd_lengths"
                ]

                all_len = (
                    fwd_len + bwd_len
                )

                # ------------------------------------------------------
                # PACKET LENGTH STATS
                # ------------------------------------------------------

                (
                    fwd_mean,
                    fwd_std,
                    fwd_max,
                    fwd_min,
                ) = self._calc_stats(
                    fwd_len
                )

                (
                    bwd_mean,
                    bwd_std,
                    bwd_max,
                    bwd_min,
                ) = self._calc_stats(
                    bwd_len
                )

                (
                    all_mean,
                    all_std,
                    all_max,
                    all_min,
                ) = self._calc_stats(
                    all_len
                )

                all_var = (
                    float(
                        np.var(
                            all_len,
                            ddof=1,
                        )
                    )
                    if len(all_len) > 1
                    else 0.0
                )

                # ------------------------------------------------------
                # TOTALS
                # ------------------------------------------------------

                tot_bytes = float(
                    flow["fwd_bytes"]
                    + flow["bwd_bytes"]
                )

                tot_pkts = float(
                    flow["fwd_packets"]
                    + flow["bwd_packets"]
                )

                # ------------------------------------------------------
                # FLOW RATES
                # ------------------------------------------------------

                flow_bytes_sec = (
                    tot_bytes
                    / duration_sec
                    if duration_sec > 0
                    else 0.0
                )

                flow_pkts_sec = (
                    tot_pkts
                    / duration_sec
                    if duration_sec > 0
                    else 0.0
                )

                # ------------------------------------------------------
                # IAT
                # ------------------------------------------------------

                (
                    flow_tot_iat,
                    flow_mean_iat,
                    flow_std_iat,
                    flow_max_iat,
                    flow_min_iat,
                ) = self._calc_iats(
                    flow["flow_times"]
                )

                (
                    fwd_tot_iat,
                    fwd_mean_iat,
                    fwd_std_iat,
                    fwd_max_iat,
                    fwd_min_iat,
                ) = self._calc_iats(
                    flow["fwd_times"]
                )

                (
                    bwd_tot_iat,
                    bwd_mean_iat,
                    bwd_std_iat,
                    bwd_max_iat,
                    bwd_min_iat,
                ) = self._calc_iats(
                    flow["bwd_times"]
                )

                # ------------------------------------------------------
                # ACTIVE / IDLE
                # ------------------------------------------------------

                (
                    (
                        act_mean,
                        act_std,
                        act_max,
                        act_min,
                    ),
                    (
                        idle_mean,
                        idle_std,
                        idle_max,
                        idle_min,
                    ),
                ) = self._calc_active_idle(
                    flow["flow_times"],
                    self.idle_threshold,
                )

                # ------------------------------------------------------
                # 78 CICIDS FEATURES
                # ------------------------------------------------------

                flow_dict = {

                    "Destination Port":
                        float(
                            flow["dst_port"]
                        ),

                    "Flow Duration":
                        float(
                            duration_us
                        ),

                    "Total Fwd Packets":
                        float(
                            flow["fwd_packets"]
                        ),

                    "Total Backward Packets":
                        float(
                            flow["bwd_packets"]
                        ),

                    "Total Length of Fwd Packets":
                        float(
                            flow["fwd_bytes"]
                        ),

                    "Total Length of Bwd Packets":
                        float(
                            flow["bwd_bytes"]
                        ),

                    "Fwd Packet Length Max":
                        fwd_max,

                    "Fwd Packet Length Min":
                        fwd_min,

                    "Fwd Packet Length Mean":
                        fwd_mean,

                    "Fwd Packet Length Std":
                        fwd_std,

                    "Bwd Packet Length Max":
                        bwd_max,

                    "Bwd Packet Length Min":
                        bwd_min,

                    "Bwd Packet Length Mean":
                        bwd_mean,

                    "Bwd Packet Length Std":
                        bwd_std,

                    "Flow Bytes/s":
                        flow_bytes_sec,

                    "Flow Packets/s":
                        flow_pkts_sec,

                    "Flow IAT Mean":
                        flow_mean_iat,

                    "Flow IAT Std":
                        flow_std_iat,

                    "Flow IAT Max":
                        flow_max_iat,

                    "Flow IAT Min":
                        flow_min_iat,

                    "Fwd IAT Total":
                        fwd_tot_iat,

                    "Fwd IAT Mean":
                        fwd_mean_iat,

                    "Fwd IAT Std":
                        fwd_std_iat,

                    "Fwd IAT Max":
                        fwd_max_iat,

                    "Fwd IAT Min":
                        fwd_min_iat,

                    "Bwd IAT Total":
                        bwd_tot_iat,

                    "Bwd IAT Mean":
                        bwd_mean_iat,

                    "Bwd IAT Std":
                        bwd_std_iat,

                    "Bwd IAT Max":
                        bwd_max_iat,

                    "Bwd IAT Min":
                        bwd_min_iat,

                    "Fwd PSH Flags":
                        float(
                            flow["fwd_psh"]
                        ),

                    "Bwd PSH Flags":
                        float(
                            flow["bwd_psh"]
                        ),

                    "Fwd URG Flags":
                        float(
                            flow["fwd_urg"]
                        ),

                    "Bwd URG Flags":
                        float(
                            flow["bwd_urg"]
                        ),

                    "Fwd Header Length":
                        float(
                            flow["fwd_hdr_len"]
                        ),

                    "Bwd Header Length":
                        float(
                            flow["bwd_hdr_len"]
                        ),

                    "Fwd Packets/s":
                        float(
                            flow["fwd_packets"]
                            / duration_sec
                        )
                        if duration_sec > 0
                        else 0.0,

                    "Bwd Packets/s":
                        float(
                            flow["bwd_packets"]
                            / duration_sec
                        )
                        if duration_sec > 0
                        else 0.0,

                    "Min Packet Length":
                        all_min,

                    "Max Packet Length":
                        all_max,

                    "Packet Length Mean":
                        all_mean,

                    "Packet Length Std":
                        all_std,

                    "Packet Length Variance":
                        all_var,

                    "FIN Flag Count":
                        float(
                            flow["fin_cnt"]
                        ),

                    "SYN Flag Count":
                        float(
                            flow["syn_cnt"]
                        ),

                    "RST Flag Count":
                        float(
                            flow["rst_cnt"]
                        ),

                    "PSH Flag Count":
                        float(
                            flow["psh_cnt"]
                        ),

                    "ACK Flag Count":
                        float(
                            flow["ack_cnt"]
                        ),

                    "URG Flag Count":
                        float(
                            flow["urg_cnt"]
                        ),

                    "CWE Flag Count":
                        float(
                            flow["cwe_cnt"]
                        ),

                    "ECE Flag Count":
                        float(
                            flow["ece_cnt"]
                        ),

                    "Down/Up Ratio":
                        float(
                            flow["bwd_packets"]
                            / flow["fwd_packets"]
                        )
                        if flow["fwd_packets"] > 0
                        else 0.0,

                    "Average Packet Size":
                        all_mean,

                    "Avg Fwd Segment Size":
                        fwd_mean,

                    "Avg Bwd Segment Size":
                        bwd_mean,

                    "Fwd Header Length.1":
                        float(
                            flow["fwd_hdr_len"]
                        ),

                    "Fwd Avg Bytes/Bulk":
                        0.0,

                    "Fwd Avg Packets/Bulk":
                        0.0,

                    "Fwd Avg Bulk Rate":
                        0.0,

                    "Bwd Avg Bytes/Bulk":
                        0.0,

                    "Bwd Avg Packets/Bulk":
                        0.0,

                    "Bwd Avg Bulk Rate":
                        0.0,

                    "Subflow Fwd Packets":
                        float(
                            flow["fwd_packets"]
                        ),

                    "Subflow Fwd Bytes":
                        float(
                            flow["fwd_bytes"]
                        ),

                    "Subflow Bwd Packets":
                        float(
                            flow["bwd_packets"]
                        ),

                    "Subflow Bwd Bytes":
                        float(
                            flow["bwd_bytes"]
                        ),

                    "Init_Win_bytes_forward":
                        float(
                            flow["init_win_fwd"]
                        ),

                    "Init_Win_bytes_backward":
                        float(
                            flow["init_win_bwd"]
                        ),

                    "act_data_pkt_fwd":
                        float(
                            flow["act_data_pkt_fwd"]
                        ),

                    "min_seg_size_forward":
                        float(
                            flow["min_seg_size_fwd"]
                        ),

                    "Active Mean":
                        act_mean,

                    "Active Std":
                        act_std,

                    "Active Max":
                        act_max,

                    "Active Min":
                        act_min,

                    "Idle Mean":
                        idle_mean,

                    "Idle Std":
                        idle_std,

                    "Idle Max":
                        idle_max,

                    "Idle Min":
                        idle_min,
                }

                completed.append(
                    flow_dict
                )

        return completed

    # ------------------------------------------------------------------
    # STOP
    # ------------------------------------------------------------------

    def stop(self):

        self._stop.set()

        # Give the sniff thread a moment to exit
        if (
            self._sniff_thread is not None
            and self._sniff_thread.is_alive()
        ):
            self._sniff_thread.join(
                timeout=2.0
            )