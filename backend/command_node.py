"""
backend/command_node.py
=======================
AEGIS - Centralized Command Node & Telemetry/Voting Coordinator
----------------------------------------------------------------
Provides a centralized server hub for accessing all agent telemetries,
monitoring agent health, performing cross-agent signal correlation, and
coordinating centralized voting consensus and response action dispatching.

Architecture:
* **CentralizedTelemetryRepository**: Thread-safe in-memory store indexing all agent
  telemetry events (network, process, file, log, zero-day) with filterable queries
  by agent_id, event_type, threat score threshold, and timestamp range.
* **CentralizedVotingCoordinator**: Receives threat voting requests from agents,
  evaluates cross-agent signal correlation against recent telemetries across the entire
  network, fetches agent trust scores, applies AEGIS weighted consensus multipliers,
  and determines automated response actions:
    - LOW (score < 0.30)       -> LOG (local audit record)
    - MEDIUM (score < 0.60)    -> ALERT (admin notification + elevated telemetry)
    - HIGH (score < 0.80)      -> KILL_PROCESS (terminate malicious PID + quarantine)
    - CRITICAL (score >= 0.80)  -> ISOLATE_HOST (network host isolation + emergency alert)
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from agent.confidence_engine import AgentTrustTracker
from agent.p2p_mesh import ConsensusVerdict, VotingRequest, VotingResponse, WeightedConsensusAggregator

# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)


# ===========================================================================
# Centralized Telemetry Repository
# ===========================================================================
class CentralizedTelemetryRepository:
    """
    Thread-safe repository indexing all incoming agent telemetry feeds.
    """

    def __init__(self, max_capacity: int = 10000) -> None:
        self.max_capacity = max_capacity
        self._events: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def add_telemetry(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Store an incoming telemetry event and attach metadata."""
        record = {
            "id": str(uuid.uuid4())[:8],
            "timestamp": event.get("timestamp", time.time()),
            "agent_id": event.get("agent_id", "agent-unknown"),
            "event_type": event.get("event_type", "unknown"),
            "threat_score": float(event.get("threat_score", event.get("score", 0.0))),
            "details": event.get("details", event),
            "received_at": time.time(),
        }

        with self._lock:
            self._events.append(record)
            if len(self._events) > self.max_capacity:
                self._events.pop(0)

        return record

    def query_telemetry(
        self,
        agent_id: Optional[str] = None,
        event_type: Optional[str] = None,
        min_score: float = 0.0,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Query stored telemetries with optional filters.
        """
        with self._lock:
            results = []
            for item in reversed(self._events):
                if agent_id and item["agent_id"] != agent_id:
                    continue
                if event_type and item["event_type"] != event_type:
                    continue
                if item["threat_score"] < min_score:
                    continue

                results.append(item)
                if len(results) >= limit:
                    break

            return results

    def get_stats(self) -> Dict[str, Any]:
        """Compute aggregate system telemetry metrics."""
        with self._lock:
            total = len(self._events)
            agents = {e["agent_id"] for e in self._events}
            high_threats = sum(1 for e in self._events if e["threat_score"] >= 0.60)
            critical_threats = sum(1 for e in self._events if e["threat_score"] >= 0.80)

            event_types: Dict[str, int] = {}
            for e in self._events:
                t = e["event_type"]
                event_types[t] = event_types.get(t, 0) + 1

            return {
                "total_events": total,
                "active_agents": len(agents),
                "high_threat_events": high_threats,
                "critical_threat_events": critical_threats,
                "event_type_counts": event_types,
                "timestamp": time.time(),
            }


# ===========================================================================
# Centralized Voting & Response Coordinator
# ===========================================================================
class CentralizedVotingCoordinator:
    """
    Central Coordinator that evaluates threat voting requests across all agents,
    checks cross-agent signal correlation, applies trust weights, and determines
    automated response actions.
    """

    RESPONSE_ACTIONS = {
        "LOW": "LOG",
        "MEDIUM": "ALERT",
        "HIGH": "KILL_PROCESS",
        "CRITICAL": "ISOLATE_HOST",
    }

    def __init__(
        self,
        repository: CentralizedTelemetryRepository,
        trust_tracker: Optional[AgentTrustTracker] = None,
    ) -> None:
        self.repository = repository
        self.trust_tracker = trust_tracker or AgentTrustTracker(db_path="aegis_central_trust.db")
        self.aggregator = WeightedConsensusAggregator()

        self._verdicts_history: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def _check_cross_agent_correlation(
        self, req: VotingRequest, time_window_seconds: float = 120.0
    ) -> List[VotingResponse]:
        """
        Search stored telemetry across all agents to see if peer agents observed
        correlated indicators (matching ports, IP addresses, process names).
        """
        recent_telemetry = self.repository.query_telemetry(
            event_type=req.event_type, limit=200
        )
        now = time.time()

        peer_observations: Dict[str, Tuple[bool, float]] = {}  # agent_id -> (correlated, max_score)

        for event in recent_telemetry:
            peer_id = event["agent_id"]
            # Don't correlate origin agent against itself
            if peer_id == req.origin_agent_id:
                continue

            if now - event["timestamp"] > time_window_seconds:
                continue

            local_details = event.get("details", {})
            req_details = req.details

            is_corr = False
            # Correlation checks:
            if req.event_type == "network":
                if (local_details.get("port") and local_details.get("port") == req_details.get("port")) or \
                   (local_details.get("dest_ip") and local_details.get("dest_ip") == req_details.get("dest_ip")):
                    is_corr = True
            elif req.event_type in ("process_linux", "process_windows"):
                if (local_details.get("process") and local_details.get("process") == req_details.get("process")) or \
                   (local_details.get("pid") and local_details.get("pid") == req_details.get("pid")):
                    is_corr = True
            elif req.event_type in ("file", "log_line"):
                if local_details.get("filename") and local_details.get("filename") == req_details.get("filename"):
                    is_corr = True

            current_corr, current_score = peer_observations.get(peer_id, (False, 0.0))
            new_corr = current_corr or is_corr
            new_score = max(current_score, event["threat_score"])
            peer_observations[peer_id] = (new_corr, new_score)

        # Convert peer observations into VotingResponse objects
        responses: List[VotingResponse] = []
        for peer_id, (is_corr, peer_score) in peer_observations.items():
            trust = self.trust_tracker.get_trust(peer_id)
            resp = VotingResponse(
                vote_id=req.vote_id,
                peer_agent_id=peer_id,
                peer_trust_score=trust,
                correlated=is_corr,
                peer_vote_score=peer_score if is_corr else req.threat_score * 0.5,
            )
            responses.append(resp)

        return responses

    def process_vote_request(
        self,
        event_type: str,
        origin_agent_id: str,
        threat_score: float,
        confidence: float = 1.0,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Process a voting request centrally: evaluate correlation, aggregate weighted
        consensus, and map to an automated response action.
        """
        vote_id = str(uuid.uuid4())[:8]
        details = details or {}

        req = VotingRequest(
            vote_id=vote_id,
            origin_agent_id=origin_agent_id,
            event_type=event_type,
            threat_score=threat_score,
            confidence=confidence,
            details=details,
        )

        # 1. Store request in repository
        self.repository.add_telemetry({
            "agent_id": origin_agent_id,
            "event_type": event_type,
            "threat_score": threat_score,
            "details": details,
            "timestamp": req.timestamp,
        })

        # 2. Check cross-agent correlation
        peer_responses = self._check_cross_agent_correlation(req)

        # 3. Aggregate weighted consensus
        origin_trust = self.trust_tracker.get_trust(origin_agent_id)
        verdict: ConsensusVerdict = self.aggregator.aggregate(
            req, peer_responses, origin_trust=origin_trust
        )

        # 4. Map severity to automated response action
        response_action = self.RESPONSE_ACTIONS.get(verdict.severity, "LOG")

        result = {
            "vote_id": verdict.vote_id,
            "origin_agent_id": verdict.origin_agent_id,
            "event_type": verdict.event_type,
            "raw_threat_score": verdict.raw_threat_score,
            "final_weighted_score": verdict.final_weighted_score,
            "severity": verdict.severity,
            "response_action": response_action,
            "consensus_reached": verdict.consensus_reached,
            "participating_peers": verdict.participating_peers,
            "total_weight": verdict.total_weight,
            "timestamp": verdict.timestamp,
        }

        with self._lock:
            self._verdicts_history.append(result)
            if len(self._verdicts_history) > 1000:
                self._verdicts_history.pop(0)

        logger.info(
            "[CommandNode] CENTRALIZED CONSENSUS: vote_id=%s agent=%s severity=%s action=%s (peers=%d)",
            result["vote_id"],
            result["origin_agent_id"],
            result["severity"],
            result["response_action"],
            result["participating_peers"],
        )

        return result

    def get_verdicts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent consensus verdicts."""
        with self._lock:
            return list(reversed(self._verdicts_history[-limit:]))


# ===========================================================================
# Runnable Demo
# ===========================================================================
if __name__ == "__main__":
    print("=" * 72)
    print("AEGIS Centralized Command Node Verification Demo")
    print("=" * 72)

    repo = CentralizedTelemetryRepository()
    coordinator = CentralizedVotingCoordinator(repository=repo)

    # 1. Simulate agent 2 (vm2) reporting network telemetry earlier
    repo.add_telemetry({
        "agent_id": "vm2",
        "event_type": "network",
        "threat_score": 0.82,
        "details": {"port": 443, "dest_ip": "172.16.255.36"},
        "timestamp": time.time() - 10,
    })

    # 2. Agent 1 (vm1) submits a central vote request for matching port 443
    print("\n[Demo] vm1 submitting central vote request (port=443, score=0.88)...")
    res = coordinator.process_vote_request(
        event_type="network",
        origin_agent_id="vm1",
        threat_score=0.88,
        details={"port": 443, "dest_ip": "172.16.255.36"},
    )

    print(f"\n[Demo] Centralized Consensus Verdict Result:")
    print(f"  Vote ID            : {res['vote_id']}")
    print(f"  Origin Agent       : {res['origin_agent_id']}")
    print(f"  Raw Score          : {res['raw_threat_score']}")
    print(f"  Final Score        : {res['final_weighted_score']}")
    print(f"  Severity           : {res['severity']}")
    print(f"  Response Action    : {res['response_action']}")
    print(f"  Peers Correlated   : {res['participating_peers']}")
    print(f"  Total Weight       : {res['total_weight']}")

    print("\n[Demo] Centralized Repository Stats:")
    print(f"  {repo.get_stats()}")
    print("=" * 72)
