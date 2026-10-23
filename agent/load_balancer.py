"""
agent/load_balancer.py
======================
AEGIS Agent - Multi-Server Load Balancer & Failover Controller
--------------------------------------------------------------
When an agent starts it receives an ordered list of backend Command Node
URLs (primary first, then zero or more fallbacks).  This module keeps track
of which server is *currently active*, health-probes all servers in the
background, and exposes a single ``get_active_url()`` function that always
returns the best available endpoint.

Failover Logic
--------------
* Servers are tried in **priority order** (index 0 = highest priority).
* A server is considered **healthy** if GET /api/health returns HTTP 200
  within the configured timeout.
* If the current active server fails health checks for
  ``CONSECUTIVE_FAILS_BEFORE_FAILOVER`` consecutive cycles, the balancer
  promotes the next healthy server in the priority list.
* The balancer continuously probes ALL servers in the background.  When a
  higher-priority server becomes healthy again it is automatically promoted
  back (primary preference restoration).
* All state changes are logged to stdout with a ``[lb]`` prefix so they are
  visible in the agent console.

Environment Variables
---------------------
AEGIS_LB_SERVERS          Comma-separated fallback URLs added *after* the
                          primary (COMMAND_NODE_URL).  Example:
                            AEGIS_LB_SERVERS=http://192.168.1.20:8000,http://192.168.1.21:8000
AEGIS_LB_PROBE_INTERVAL   Seconds between health-probe cycles (default: 5).
AEGIS_LB_TIMEOUT          HTTP timeout per health probe in seconds (default: 3).
AEGIS_LB_FAIL_THRESHOLD   Consecutive probe failures before failover (default: 2).
"""

from __future__ import annotations

import os
import threading
import time
import urllib.error
import urllib.request
from typing import List, Optional

# ---------------------------------------------------------------------------
# Defaults (overridable via environment variables)
# ---------------------------------------------------------------------------
_PROBE_INTERVAL: float = float(os.environ.get("AEGIS_LB_PROBE_INTERVAL", "5"))
_PROBE_TIMEOUT: float  = float(os.environ.get("AEGIS_LB_TIMEOUT", "3"))
_FAIL_THRESHOLD: int   = int(os.environ.get("AEGIS_LB_FAIL_THRESHOLD", "2"))


def _probe(url: str) -> bool:
    """Return True if the server at *url* responds with HTTP 200 on /api/health."""
    try:
        req = urllib.request.Request(
            f"{url.rstrip('/')}/api/health",
            headers={"User-Agent": "AEGIS-LoadBalancer"},
        )
        with urllib.request.urlopen(req, timeout=_PROBE_TIMEOUT) as resp:
            return resp.status == 200
    except Exception:
        return False


# ---------------------------------------------------------------------------
# ServerLoadBalancer
# ---------------------------------------------------------------------------
class ServerLoadBalancer:
    """
    Maintains an ordered list of Command Node URLs and transparently fails
    over to the next healthy server when the active one becomes unreachable.

    Parameters
    ----------
    servers : list[str]
        Ordered list of server base URLs, e.g.
        ["http://192.168.1.10:8000", "http://192.168.1.11:8000"].
        Index 0 has the highest priority.
    probe_interval : float
        Seconds between background health-probe cycles.
    probe_timeout : float
        HTTP timeout per health probe in seconds.
    fail_threshold : int
        Number of consecutive failures before the active server is replaced.
    """

    def __init__(
        self,
        servers: List[str],
        probe_interval: float = _PROBE_INTERVAL,
        probe_timeout: float = _PROBE_TIMEOUT,
        fail_threshold: int = _FAIL_THRESHOLD,
    ) -> None:
        if not servers:
            raise ValueError("ServerLoadBalancer requires at least one server URL.")

        # Normalise URLs (strip trailing slash)
        self._servers: List[str] = [s.rstrip("/") for s in servers]
        self._probe_interval = probe_interval
        self._probe_timeout = probe_timeout
        self._fail_threshold = fail_threshold

        # Shared mutable state (guarded by lock)
        self._lock = threading.Lock()
        self._active_index: int = 0          # index into self._servers
        self._fail_counts: List[int] = [0] * len(self._servers)
        self._healthy: List[Optional[bool]] = [None] * len(self._servers)

        # Background probe thread
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def servers(self) -> List[str]:
        """Immutable view of the configured server list (priority order)."""
        return list(self._servers)

    def get_active_url(self) -> str:
        """Return the URL of the currently active (healthy) server."""
        with self._lock:
            return self._servers[self._active_index]

    def report_failure(self, url: str) -> None:
        """
        Manually report a delivery failure for *url* (e.g. from the telemetry
        sender).  Increments the fail counter immediately; if the threshold is
        crossed the balancer switches to the next server without waiting for
        the next probe cycle.
        """
        with self._lock:
            try:
                idx = self._servers.index(url.rstrip("/"))
            except ValueError:
                return
            self._fail_counts[idx] += 1
            if (
                idx == self._active_index
                and self._fail_counts[idx] >= self._fail_threshold
            ):
                self._failover_locked()

    def start(self) -> "ServerLoadBalancer":
        """Start the background health-probe thread and return self (fluent)."""
        if self._thread and self._thread.is_alive():
            return self
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._probe_loop,
            name="aegis-lb-prober",
            daemon=True,
        )
        self._thread.start()
        print(
            f"[lb] Load balancer started - {len(self._servers)} server(s) "
            f"| probe every {self._probe_interval}s "
            f"| fail-threshold {self._fail_threshold}"
        )
        for i, srv in enumerate(self._servers):
            label = "PRIMARY" if i == 0 else f"FALLBACK-{i}"
            print(f"[lb]   [{label}] {srv}")
        return self

    def stop(self) -> None:
        """Signal the background thread to stop."""
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _probe_loop(self) -> None:
        """Background loop: probe all servers, failover / restore as needed."""
        while not self._stop_event.wait(self._probe_interval):
            results: List[bool] = []
            for srv in self._servers:
                results.append(_probe(srv))

            with self._lock:
                prev_active = self._active_index

                for i, ok in enumerate(results):
                    self._healthy[i] = ok
                    if ok:
                        self._fail_counts[i] = 0  # reset on recovery
                    else:
                        if i == self._active_index:
                            self._fail_counts[i] += 1

                # 1. If active server is consistently failing -> failover
                if (
                    not results[self._active_index]
                    and self._fail_counts[self._active_index] >= self._fail_threshold
                ):
                    self._failover_locked(results)

                # 2. If a higher-priority server recovered -> restore it
                elif results[self._active_index]:
                    for hi in range(self._active_index):
                        if results[hi]:
                            self._active_index = hi
                            break

                if self._active_index != prev_active:
                    old = self._servers[prev_active]
                    new = self._servers[self._active_index]
                    label = "PRIMARY" if self._active_index == 0 else f"FALLBACK-{self._active_index}"
                    print(
                        f"[lb] Active server switched: {old} -> {new}  [{label}]"
                    )
                    # Propagate into process environment so all submodules that
                    # read os.environ["COMMAND_NODE_URL"] at call-time get the
                    # updated URL without needing a restart.
                    os.environ["COMMAND_NODE_URL"] = new

    def _failover_locked(self, health_results: Optional[List[bool]] = None) -> None:
        """
        Select the next healthy server in priority order.
        Must be called with ``self._lock`` already held.
        If *health_results* is None, probes are run inline (blocking, brief).
        """
        n = len(self._servers)
        for offset in range(1, n):
            candidate_idx = (self._active_index + offset) % n
            # Use provided results if available, otherwise probe inline
            if health_results is not None:
                ok = health_results[candidate_idx]
            else:
                ok = _probe(self._servers[candidate_idx])

            if ok:
                old_url = self._servers[self._active_index]
                self._active_index = candidate_idx
                self._fail_counts[candidate_idx] = 0
                new_url = self._servers[self._active_index]
                label = "PRIMARY" if candidate_idx == 0 else f"FALLBACK-{candidate_idx}"
                print(
                    f"[lb] Failover triggered: {old_url} is unhealthy -> "
                    f"switching to {new_url}  [{label}]"
                )
                os.environ["COMMAND_NODE_URL"] = new_url
                return

        # No healthy server found - stay on current but log a warning
        print(
            f"[lb] WARNING: ALL servers appear unreachable. "
            f"Staying on {self._servers[self._active_index]} - will retry."
        )


# ---------------------------------------------------------------------------
# Module-level singleton & convenience helpers
# ---------------------------------------------------------------------------

_balancer: Optional[ServerLoadBalancer] = None
_balancer_lock = threading.Lock()


def init_load_balancer(
    primary_url: str,
    extra_servers: Optional[List[str]] = None,
    probe_interval: float = _PROBE_INTERVAL,
    probe_timeout: float = _PROBE_TIMEOUT,
    fail_threshold: int = _FAIL_THRESHOLD,
) -> ServerLoadBalancer:
    """
    Initialise and start the module-level load balancer singleton.

    Parameters
    ----------
    primary_url : str
        The primary (highest-priority) Command Node URL.
    extra_servers : list[str] | None
        Additional fallback URLs in priority order.  Also reads
        ``AEGIS_LB_SERVERS`` from the environment (comma-separated) if this
        is not provided.
    """
    global _balancer
    with _balancer_lock:
        if _balancer is not None:
            return _balancer

        # Merge CLI/env extra servers
        env_extras = [
            s.strip()
            for s in os.environ.get("AEGIS_LB_SERVERS", "").split(",")
            if s.strip()
        ]
        all_extras = list(extra_servers or []) + [
            s for s in env_extras if s not in (extra_servers or [])
        ]

        server_list = [primary_url] + [
            s for s in all_extras if s != primary_url
        ]

        _balancer = ServerLoadBalancer(
            servers=server_list,
            probe_interval=probe_interval,
            probe_timeout=probe_timeout,
            fail_threshold=fail_threshold,
        ).start()
        return _balancer


def get_active_url() -> str:
    """
    Return the active server URL from the singleton balancer.
    Falls back to ``os.environ["COMMAND_NODE_URL"]`` or localhost if the
    balancer has not been initialised yet.
    """
    with _balancer_lock:
        if _balancer is not None:
            return _balancer.get_active_url()
    return os.environ.get("COMMAND_NODE_URL", "http://127.0.0.1:8000").rstrip("/")


def report_delivery_failure(url: str) -> None:
    """
    Report a delivery failure to the singleton balancer so it can trigger
    an early failover without waiting for the next probe cycle.
    """
    with _balancer_lock:
        if _balancer is not None:
            _balancer.report_failure(url)
