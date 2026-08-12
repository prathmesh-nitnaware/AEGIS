"""
agent/live_collectors.py
=========================
AEGIS - Layer 1c: Live Telemetry Collectors
---------------------------------------------
Captures live machine telemetry and reshapes it into the EXACT input formats
that agent/fusion_engine.py's ThreatFusionEngine methods expect:

    ThreatFusionEngine.score_process_event(syscall_sequence=[...])       -> Linux
    ThreatFusionEngine.score_process_event(api_call_sequence=[...])      -> Windows
    ThreatFusionEngine.score_network_flow(flow_features: dict)           -> CICIDS
    ThreatFusionEngine.score_file(pe_features: dict)                     -> EMBER
    ThreatFusionEngine.score_log_line(raw_text: str)                     -> HDFS
    ThreatFusionEngine.score_windows_event(event_id, process_name,
                                            user_name, ip)               -> Zero-Day

This module does NOT do any scoring, padding, encoding, or vectorizing --
fusion_engine.py already owns all of that. Each collector's only job is to
produce raw values shaped correctly for that model's public method.

Design note: collectors are intentionally decoupled from ThreatFusionEngine.
You wire them together in agent/main.py (or wherever your agent loop lives)
by importing ThreatFusionEngine, instantiating it once, and passing each
collector's output straight into the matching score_*() call.
"""
from __future__ import annotations

import os
import platform
import re
import subprocess
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Deque, Dict, List, Optional, Union

import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

import ember_features  # local module -- lief-based EMBER extractor (agent/ember_features.py)

IS_LINUX = platform.system() == "Linux"
IS_WINDOWS = platform.system() == "Windows"


# ===========================================================================
# 1. Linux IDS collector -> syscall_sequence: List[int]
# ===========================================================================

class LinuxSyscallCollector:
    """
    Captures per-process syscall numbers on Linux via `strace -f -e trace=all`
    and buffers the last N syscalls (raw integers) per PID.

    fusion_engine.py pads/truncates to 500 internally -- we just need to hand
    it a list of ints; any length is fine, but we cap the buffer at 500 so
    memory doesn't grow unbounded on long-lived processes.

    Requirements: `strace` installed, and either root or CAP_SYS_PTRACE.
    Note: strace prints syscall NAMES, not raw numbers, by default. We map
    name -> number via the same table the kernel uses (/usr/include or the
    `syscalls` man page numbering for your architecture). If your training
    pipeline used a different syscall->int mapping, swap SYSCALL_NUM_MAP for
    that exact mapping -- this is the one place where the collector's output
    must match training-time vocabulary exactly.
    """

    MAX_BUFFER = 500

    # Minimal x86_64 syscall name -> number table (extend as needed).
    # Source: Linux syscall table for x86_64. Replace with the exact table
    # used during model training if it differs.
    SYSCALL_NUM_MAP: Dict[str, int] = {
        "read": 0, "write": 1, "open": 2, "close": 3, "stat": 4, "fstat": 5,
        "lstat": 6, "poll": 7, "lseek": 8, "mmap": 9, "mprotect": 10,
        "munmap": 11, "brk": 12, "rt_sigaction": 13, "rt_sigprocmask": 14,
        "ioctl": 16, "pread64": 17, "pwrite64": 18, "readv": 19, "writev": 20,
        "access": 21, "pipe": 22, "select": 23, "sched_yield": 24,
        "mremap": 25, "msync": 26, "mincore": 27, "madvise": 28,
        "dup": 32, "dup2": 33, "pause": 34, "nanosleep": 35,
        "socket": 41, "connect": 42, "accept": 43, "sendto": 44,
        "recvfrom": 45, "sendmsg": 46, "recvmsg": 47, "shutdown": 48,
        "bind": 49, "listen": 50, "clone": 56, "fork": 57, "vfork": 58,
        "execve": 59, "exit": 60, "wait4": 61, "kill": 62, "uname": 63,
        "fcntl": 72, "getdents": 78, "chdir": 80, "rename": 82, "mkdir": 83,
        "rmdir": 84, "unlink": 87, "symlink": 88, "chmod": 90, "chown": 92,
        "ptrace": 101, "setuid": 105, "setgid": 106, "capset": 126,
        "prctl": 157, "arch_prctl": 158, "mount": 165, "umount2": 166,
        "gettid": 186, "futex": 202, "exit_group": 231,
    }
    UNKNOWN_SYSCALL_NUM = -1  # sentinel for names not in the map

    def __init__(self):
        self._buffers: Dict[int, Deque[int]] = defaultdict(
            lambda: deque(maxlen=self.MAX_BUFFER)
        )
        self._lock = threading.Lock()
        self._proc: Optional[subprocess.Popen] = None
        self._stop = threading.Event()

    def start(self, target_pid: Optional[int] = None):
        """
        Start capturing syscalls. If target_pid is given, attaches to that
        single process (`strace -p PID`). Otherwise traces all new processes
        system-wide via `strace -f -p 1` is not valid for system-wide -- for
        a real system-wide capture use auditd instead (see note below).
        """
        if not IS_LINUX:
            raise RuntimeError("LinuxSyscallCollector only runs on Linux.")

        cmd = ["strace", "-f", "-tt"]
        if target_pid:
            cmd += ["-p", str(target_pid)]
        else:
            raise ValueError(
                "System-wide syscall tracing needs auditd, not strace -- "
                "pass a specific target_pid, or swap this for an auditd/eBPF "
                "backed collector for whole-machine coverage."
            )

        self._proc = subprocess.Popen(
            cmd, stderr=subprocess.PIPE, stdout=subprocess.DEVNULL, text=True
        )
        threading.Thread(target=self._read_loop, args=(target_pid,), daemon=True).start()

    def _read_loop(self, pid: int):
        # strace -f writes syscall trace lines to stderr, e.g.:
        #   14:32:01.123456 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3
        pattern = re.compile(r"\)\s*=\s*-?\d+")  # confirms a completed syscall line
        name_pattern = re.compile(r"^\S+\s+(\w+)\(")
        assert self._proc is not None and self._proc.stderr is not None
        for line in self._proc.stderr:
            if self._stop.is_set():
                break
            m = name_pattern.match(line)
            if not m or not pattern.search(line):
                continue
            syscall_name = m.group(1)
            num = self.SYSCALL_NUM_MAP.get(syscall_name, self.UNKNOWN_SYSCALL_NUM)
            with self._lock:
                self._buffers[pid].append(num)

    def get_sequence(self, pid: int) -> List[int]:
        """Return the current buffered syscall sequence (ints) for a PID."""
        with self._lock:
            return list(self._buffers.get(pid, []))

    def stop(self):
        self._stop.set()
        if self._proc:
            self._proc.terminate()


# ===========================================================================
# 2. Windows Advanced collector -> api_call_sequence: List[str]
# ===========================================================================

class WindowsAPICollector:
    """
    Captures API/DLL call names per process on Windows.

    There is no built-in Python way to hook API calls without a kernel driver
    or a tool like Sysmon / ETW (Event Tracing for Windows) / API Monitor.
    The practical, low-friction approach:

      1. Use Sysmon (https://learn.microsoft.com/sysinternals/downloads/sysmon)
         with a config that logs Image Load (Event ID 7) and Process Access
         (Event ID 10) events -- these give you DLL loads and cross-process
         API-adjacent activity.
      2. Read Sysmon's events from the Windows Event Log via `pywin32`
         (win32evtlog) or `python-evtx`, and treat each loaded DLL / accessed
         API name as one token in the sequence.

    This class provides the READING side once Sysmon is installed and logging
    to the "Microsoft-Windows-Sysmon/Operational" channel. It does NOT install
    or configure Sysmon for you -- that's a one-time machine setup step.
    """

    MAX_BUFFER = 1000

    def __init__(self):
        self._buffers: Dict[int, Deque[str]] = defaultdict(
            lambda: deque(maxlen=self.MAX_BUFFER)
        )
        self._lock = threading.Lock()
        self._stop = threading.Event()

    def start(self):
        if not IS_WINDOWS:
            raise RuntimeError("WindowsAPICollector only runs on Windows.")
        threading.Thread(target=self._poll_loop, daemon=True).start()

    def _poll_loop(self):
        import win32evtlog  # pywin32 -- pip install pywin32

        server = "localhost"
        log_type = "Microsoft-Windows-Sysmon/Operational"
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        while not self._stop.is_set():
            try:
                hand = win32evtlog.OpenEventLog(server, log_type)
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                for ev in events:
                    # EventID 7 = Image loaded (DLL load) -- StringInserts
                    # typically contains [UtcTime, ProcessGuid, ProcessId,
                    # Image, ImageLoaded, ...]. Field order depends on the
                    # Sysmon config schema in use -- verify against your
                    # actual Sysmon manifest before relying on index 4.
                    if ev.EventID == 7 and ev.StringInserts and len(ev.StringInserts) > 4:
                        pid = int(ev.StringInserts[2])
                        dll_name = Path(ev.StringInserts[4]).name
                        with self._lock:
                            self._buffers[pid].append(dll_name)
                win32evtlog.CloseEventLog(hand)
            except Exception:
                pass  # log & continue in production; kept minimal here
            time.sleep(2)

    def get_sequence(self, pid: int) -> List[str]:
        """Return the current buffered API/DLL token sequence for a PID."""
        with self._lock:
            return list(self._buffers.get(pid, []))

    def stop(self):
        self._stop.set()


# ===========================================================================
# 3. CICIDS collector -> flow_features: Dict[str, float]
# ===========================================================================

class NetworkFlowCollector:
    """
    Builds CICIDS-style network flow feature dicts from live connections.

    IMPORTANT: score_network_flow() reindexes your dict against
    export["features"] (the exact CICIDS column list baked into the model
    pkl) and fills anything missing with 0.0. That means you do NOT need to
    supply every CICIDS column -- only the ones you can actually compute live
    will be used; the rest default to 0.0. For best accuracy, get the real
    column list from the model once and compute as many as you can:

        import joblib
        export = joblib.load("trained_models/cicids/aegis_lgbm_cicids_model.pkl")
        print(export["features"])

    For a serious deployment, replace this psutil-based approximation with
    CICFlowMeter (the actual tool used to build the CICIDS dataset) running
    against a live pcap/interface, then map its output CSV columns directly
    into flow_features -- that will match the training distribution far
    better than hand-computed approximations.

    This class computes basic per-connection stats from psutil, tracked from
    connection-open to close, as a reasonable placeholder until CICFlowMeter
    is wired in.
    """

    def __init__(self):
        self._flow_start: Dict[tuple, float] = {}
        self._flow_bytes: Dict[tuple, list] = defaultdict(list)

    def poll_once(self) -> List[Dict[str, float]]:
        """
        Snapshot current connections and emit one flow_features dict per
        active connection. Call this periodically (e.g. every 5s) from your
        agent loop.
        """
        flows = []
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            return flows

        now = time.time()
        for c in conns:
            if not c.raddr or not c.laddr:
                continue
            key = (c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port)
            start = self._flow_start.setdefault(key, now)
            duration_ms = (now - start) * 1000

            flows.append({
                "Destination Port": float(c.raddr.port),
                "Flow Duration": float(duration_ms),
                # Real per-packet/byte counters need packet capture (scapy)
                # for accuracy -- left at 0.0 here; score_network_flow()
                # fills any column you omit with 0.0 automatically.
                "Total Fwd Packets": 0.0,
                "Total Backward Packets": 0.0,
                "Total Length of Fwd Packets": 0.0,
                "Total Length of Bwd Packets": 0.0,
            })
        return flows


# ===========================================================================
# 4. EMBER collector -> pe_features: Dict[str, float]
# ===========================================================================

class PEFileCollector(FileSystemEventHandler):
    """
    Watches a directory for new/modified PE files (.exe, .dll, .sys) and
    extracts EMBER-schema features via ember_features.py -- a lief-based
    reimplementation of the EMBER feature scheme. We do NOT use the
    official `ember` pip package: it hard-pins to lief==0.9.0 and is
    broken on modern Python, which is exactly what was blocking this
    collector before. See ember_features.py's module docstring for the
    full feature-group breakdown (2381 dims, canonical EMBER order).

    `feature_names` should be the model's REAL expected column order
    (e.g. `engine._ember_features` from the loaded model export) so the
    extracted vector lines up correctly with score_file()'s reindex,
    regardless of whether those columns happen to be named descriptively
    or as generic indices. Falls back to ember_features.FEATURE_NAMES if
    not supplied -- but always pass the real list in production, or
    scores will silently come out wrong (reindexed to mostly zeros).

    Usage:
        collector = PEFileCollector(
            on_new_pe_features=my_callback,
            feature_names=engine._ember_features,
        )
        observer = Observer()
        observer.schedule(collector, path="C:/Users/you/Downloads", recursive=False)
        observer.start()
    """

    PE_EXTENSIONS = {".exe", ".dll", ".sys"}

    # File-stability guard: don't extract from a file that's still being
    # written (e.g. a download in progress) -- wait for its size to stop
    # changing first, same debounce logic as ember_telemetry_monitor.py.
    STABILIZE_POLL = 0.25
    STABILIZE_MAX_WAIT = 15.0
    STABILIZE_STABLE_READS = 3

    def __init__(
        self,
        on_new_pe_features: Callable[[Dict[str, float], Dict], None],
        feature_names: Optional[List[str]] = None,
        debounce_seconds: float = 3.0,
    ):
        super().__init__()
        self._callback = on_new_pe_features
        self._feature_names = feature_names or ember_features.FEATURE_NAMES
        self._debounce_seconds = debounce_seconds
        self._last_scanned: Dict[str, float] = {}

    def _wait_until_stable(self, path: str) -> bool:
        deadline = time.time() + self.STABILIZE_MAX_WAIT
        last_size, stable_reads = -1, 0
        while time.time() < deadline:
            try:
                size = Path(path).stat().st_size
            except FileNotFoundError:
                return False  # genuinely gone (e.g. temp download artifact cleaned up)
            except OSError:
                # Transient lock -- e.g. Windows Defender / another process
                # briefly holding the file right after it's written. Don't
                # give up, just wait and retry until the deadline.
                stable_reads = 0
                time.sleep(self.STABILIZE_POLL)
                continue
            if size == last_size:
                stable_reads += 1
                if stable_reads >= self.STABILIZE_STABLE_READS:
                    return True
            else:
                stable_reads = 0
                last_size = size
            time.sleep(self.STABILIZE_POLL)
        return False

    def _handle_file(self, path: str):
        p = Path(path)
        if p.suffix.lower() not in self.PE_EXTENSIONS:
            return

        now = time.time()
        last = self._last_scanned.get(path)
        if last is not None and (now - last) < self._debounce_seconds:
            return  # collapse create+modify bursts from one copy/save into one scan
        self._last_scanned[path] = now

        if not self._wait_until_stable(path):
            print(f"[ember_collector] Skipped (file never stabilised): {path}")
            return
        try:
            vector, meta = ember_features.extract_from_path(path)
        except ValueError:
            print(f"[ember_collector] Skipped (not a valid PE): {path}")
            return
        except Exception as exc:
            print(f"[ember_collector] Failed to extract features from {path}: {exc}")
            return

        if len(vector) != len(self._feature_names):
            print(
                f"[ember_collector] WARNING: extracted {len(vector)} features but "
                f"model expects {len(self._feature_names)} -- names will misalign. "
                f"Run diagnostics/check_ember_feature_alignment.py before trusting scores."
            )
        pe_features = dict(zip(self._feature_names, vector))
        meta["file_path"] = path
        self._callback(pe_features, meta)

    @staticmethod
    def _as_str(path: Union[str, bytes]) -> str:
        return os.fsdecode(path) if isinstance(path, bytes) else path

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._handle_file(self._as_str(event.src_path))

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._handle_file(self._as_str(event.src_path))


# ===========================================================================
# 5. HDFS collector -> raw_text: str  (block-grouped log text)
# ===========================================================================

class HDFSLogCollector(FileSystemEventHandler):
    """
    Tails a log file, groups lines by HDFS block ID (blk_-XXXXXXXXXX), and
    fires a callback with the concatenated block text once a block appears
    complete. score_log_line() runs its own TF-IDF vectorize+predict on
    whatever string you hand it -- so the ONLY job here is producing a good
    block-level text blob (the grouping was flagged as Open Issue #4).

    A block is considered "complete" when either:
      (a) BLOCK_TIMEOUT seconds pass with no new lines for that block, or
      (b) a configured terminal marker (e.g. "PacketResponder ... terminating")
          appears in a line for that block.

    Usage:
        collector = HDFSLogCollector(on_block_text=my_callback)
        observer = Observer()
        observer.schedule(collector, path="/var/log/hadoop", recursive=True)
        observer.start()
        collector.start_flush_thread()
    """

    BLOCK_ID_RE = re.compile(r"(blk_-?\d+)")
    TERMINAL_MARKERS = ("terminating", "Verification succeeded")
    BLOCK_TIMEOUT = 10.0  # seconds of inactivity before a block auto-flushes

    def __init__(self, on_block_text: Callable[[str], None]):
        super().__init__()
        self._callback = on_block_text
        self._blocks: Dict[str, List[str]] = defaultdict(list)
        self._last_seen: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._offsets: Dict[str, int] = {}
        self._stop = threading.Event()

    def _ingest_line(self, line: str):
        m = self.BLOCK_ID_RE.search(line)
        if not m:
            return
        block_id = m.group(1)
        with self._lock:
            self._blocks[block_id].append(line.strip())
            self._last_seen[block_id] = time.time()
        if any(marker in line for marker in self.TERMINAL_MARKERS):
            self._flush_block(block_id)

    def _flush_block(self, block_id: str):
        with self._lock:
            lines = self._blocks.pop(block_id, None)
            self._last_seen.pop(block_id, None)
        if lines:
            # Block-level concatenated text -- this is the "raw_text" that
            # goes straight into ThreatFusionEngine.score_log_line().
            self._callback(" ".join(lines))

    def _timeout_flush_loop(self):
        while not self._stop.is_set():
            now = time.time()
            with self._lock:
                stale = [
                    bid for bid, ts in self._last_seen.items()
                    if now - ts > self.BLOCK_TIMEOUT
                ]
            for bid in stale:
                self._flush_block(bid)
            time.sleep(2)

    def start_flush_thread(self):
        threading.Thread(target=self._timeout_flush_loop, daemon=True).start()

    def stop(self):
        self._stop.set()

    # watchdog handler: tail newly appended lines on modify
    def on_modified(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        path = os.fsdecode(event.src_path) if isinstance(event.src_path, bytes) else event.src_path
        try:
            with open(path, "r", errors="ignore") as f:
                f.seek(self._offsets.get(path, 0))
                new_lines = f.readlines()
                self._offsets[path] = f.tell()
            for line in new_lines:
                self._ingest_line(line)
        except Exception as exc:
            print(f"[hdfs_collector] Error tailing {path}: {exc}")


# ===========================================================================
# 6. Zero-Day collector -> event_id, process_name, user_name, ip
# ===========================================================================

class ZeroDayEventCollector:
    """
    Emits the 4 flat fields score_windows_event() needs:
        event_id, process_name, user_name, ip

    Cross-platform version built on psutil process-creation polling (works
    on Linux and Windows alike, unlike the Sysmon-only Windows API collector
    above). "event_id" here is synthesized ("PROC_CREATE") for non-Windows
    hosts; on Windows, prefer real Event IDs (e.g. "4688") read from the
    Security event log via pywin32 if you want exact parity with how the
    Zero-Day model's event_encoder.pkl was likely fit on Windows Event IDs --
    check event_encoder.classes_ to see whether it expects real numeric
    Windows Event IDs or synthetic labels, then match that exactly.
    """

    def __init__(self, on_event: Callable[[str, str, str, str], None]):
        self._callback = on_event
        self._seen_pids: set = set()
        self._stop = threading.Event()

    def start(self, poll_interval: float = 2.0):
        threading.Thread(
            target=self._poll_loop, args=(poll_interval,), daemon=True
        ).start()

    def _poll_loop(self, poll_interval: float):
        while not self._stop.is_set():
            try:
                current_pids = set(psutil.pids())
                new_pids = current_pids - self._seen_pids
                for pid in new_pids:
                    try:
                        p = psutil.Process(pid)
                        process_name = p.name()
                        user_name = p.username()
                        # Best-effort remote IP: first established connection, else "0.0.0.0"
                        ip = "0.0.0.0"
                        try:
                            for c in p.connections(kind="inet"):
                                if c.raddr:
                                    ip = c.raddr.ip
                                    break
                        except (psutil.AccessDenied, psutil.ZombieProcess):
                            pass
                        event_id = "4688" if IS_WINDOWS else "PROC_CREATE"
                        self._callback(event_id, process_name, user_name, ip)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                self._seen_pids = current_pids
            except Exception as exc:
                print(f"[zeroday_collector] Poll error: {exc}")
            time.sleep(poll_interval)

    def stop(self):
        self._stop.set()


# ===========================================================================
# Example wiring (reference only -- adapt into your real agent loop)
# ===========================================================================

if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from fusion_engine import ThreatFusionEngine  # noqa: E402

    engine = ThreatFusionEngine()

    # --- Zero-Day: cross-platform, easiest to demo live ---
    def handle_zeroday_event(event_id, process_name, user_name, ip):
        score = engine.score_windows_event(event_id, process_name, user_name, ip)
        verdict = engine.get_verdict(score) if score is not None else "N/A"
        print(f"[zero_day] {process_name} ({user_name}@{ip}) -> {score} ({verdict})")

    zday = ZeroDayEventCollector(on_event=handle_zeroday_event)
    zday.start(poll_interval=2.0)

    # --- CICIDS: poll connections every 5s ---
    net_collector = NetworkFlowCollector()

    def network_loop():
        while True:
            for flow in net_collector.poll_once():
                score = engine.score_network_flow(flow)
                if score is not None:
                    print(f"[cicids] {flow['Destination Port']} -> {score} ({engine.get_verdict(score)})")
            time.sleep(5)

    threading.Thread(target=network_loop, daemon=True).start()

    print("Collectors running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        zday.stop()
        print("Stopped.")