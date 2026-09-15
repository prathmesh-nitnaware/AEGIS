"""
agent/p2p_mesh.py
==================
AEGIS - Layer 2 Peer-to-Peer Consensus Voting Protocol Engine
--------------------------------------------------------------
Implements a distributed P2P consensus mesh network for monitored endpoint agents.

Architecture & Protocol Overview:
* **Peer-to-Peer Signal Correlation**: When an endpoint agent detects an anomaly, it
  broadcasts a `VotingRequest` to peer nodes in the local network mesh.
* **Correlated Feature Checking**: Receiving peers evaluate their local telemetry buffer
  to verify if matching correlated signals (e.g., matching network port, host IP, or
  process hash) were observed within a short time window.
* **Trust-Weighted Consensus**: Responses (`VotingResponse`) are weighted by the peer's
  running trust score (via `AgentTrustTracker`) and correlation status:
    - 2.0x multiplier: Peer observed correlated signal AND high trust (> 0.7)
    - 1.0x multiplier: Correlated signal with standard trust OR high trust without correlation
    - 0.5x multiplier: Standard node without direct correlation
    - 0.3x multiplier: Low trust / unverified node (< 0.4)
* **Consensus Verdict Aggregation**: Calculates a final weighted threat score and
  determines the network-wide consensus verdict (LOW / MEDIUM / HIGH / CRITICAL).
"""

from __future__ import annotations

import json
import logging
import socket
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from agent.confidence_engine import AgentTrustTracker

# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)


# ===========================================================================
# Dataclasses & Protocol Schemas
# ===========================================================================
@dataclass
class VotingRequest:
    """
    Broadcast request emitted by an agent when a local threat anomaly is detected.
    """
    vote_id: str
    origin_agent_id: str
    event_type: str
    threat_score: float
    confidence: float
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> VotingRequest:
        return cls(
            vote_id=data["vote_id"],
            origin_agent_id=data["origin_agent_id"],
            event_type=data["event_type"],
            threat_score=float(data["threat_score"]),
            confidence=float(data["confidence"]),
            details=data.get("details", {}),
            timestamp=float(data.get("timestamp", time.time())),
        )


@dataclass
class VotingResponse:
    """
    Response returned by a peer node evaluating a received VotingRequest.
    """
    vote_id: str
    peer_agent_id: str
    peer_trust_score: float
    correlated: bool
    peer_vote_score: float
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> VotingResponse:
        return cls(
            vote_id=data["vote_id"],
            peer_agent_id=data["peer_agent_id"],
            peer_trust_score=float(data["peer_trust_score"]),
            correlated=bool(data["correlated"]),
            peer_vote_score=float(data["peer_vote_score"]),
            timestamp=float(data.get("timestamp", time.time())),
        )


@dataclass
class ConsensusVerdict:
    """
    Final consensus decision aggregated from peer responses.
    """
    vote_id: str
    origin_agent_id: str
    event_type: str
    raw_threat_score: float
    final_weighted_score: float
    severity: str
    consensus_reached: bool
    participating_peers: int
    total_weight: float
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ===========================================================================
# PeerCorrelationEngine
# ===========================================================================
class PeerCorrelationEngine:
    """
    Evaluates whether an incoming VotingRequest correlates with local node telemetry.

    Maintains a rolling buffer of recent local telemetry events (network flows,
    process events, system logs) to cross-reference against peer requests.
    """

    def __init__(self, buffer_ttl_seconds: float = 60.0) -> None:
        self.buffer_ttl_seconds = buffer_ttl_seconds
        self._recent_events: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def record_local_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """Record a recent local telemetry event into the rolling memory buffer."""
        now = time.time()
        with self._lock:
            # Clean expired events
            self._recent_events = [
                e for e in self._recent_events
                if now - e["timestamp"] <= self.buffer_ttl_seconds
            ]
            self._recent_events.append({
                "event_type": event_type,
                "details": details,
                "timestamp": now,
            })

    def check_correlation(self, req: VotingRequest) -> Tuple[bool, float]:
        """
        Check if any recent local event correlates with the incoming VotingRequest.

        Returns
        -------
        (is_correlated, suggested_peer_score)
            is_correlated: bool indicating match found.
            suggested_peer_score: float score observed locally (or request score if matching).
        """
        now = time.time()
        with self._lock:
            for ev in reversed(self._recent_events):
                if now - ev["timestamp"] > self.buffer_ttl_seconds:
                    continue

                if ev["event_type"] != req.event_type:
                    continue

                local_details = ev["details"]
                req_details = req.details

                # Correlation rules across event types:
                # 1. Network: Matching port, IP, or destination
                if req.event_type == "network":
                    if (local_details.get("port") and local_details.get("port") == req_details.get("port")) or \
                       (local_details.get("dest_ip") and local_details.get("dest_ip") == req_details.get("dest_ip")):
                        logger.info("[CorrelationEngine] Match found on network details: %s", req_details)
                        return True, req.threat_score

                # 2. Process: Matching process name or PID
                elif req.event_type in ("process_linux", "process_windows"):
                    if (local_details.get("process") and local_details.get("process") == req_details.get("process")) or \
                       (local_details.get("pid") and local_details.get("pid") == req_details.get("pid")):
                        logger.info("[CorrelationEngine] Match found on process details: %s", req_details)
                        return True, req.threat_score

                # 3. File / Log: Matching filename or template
                elif req.event_type in ("file", "log_line"):
                    if local_details.get("filename") and local_details.get("filename") == req_details.get("filename"):
                        logger.info("[CorrelationEngine] Match found on file details: %s", req_details)
                        return True, req.threat_score

        return False, req.threat_score * 0.5


# ===========================================================================
# WeightedConsensusAggregator
# ===========================================================================
class WeightedConsensusAggregator:
    """
    Computes weighted consensus verdict from origin request and peer responses.
    """

    @staticmethod
    def calculate_weight(trust_score: float, is_correlated: bool) -> float:
        """
        AEGIS Weight Multiplier Spec:
        - 2.0x: Correlated AND high trust (> 0.7)
        - 1.0x: Correlated standard trust OR high trust without correlation
        - 0.5x: Standard node without direct correlation
        - 0.3x: Low trust / unverified node (< 0.4)
        """
        high_trust = trust_score >= 0.7
        low_trust = trust_score < 0.4

        if is_correlated and high_trust:
            return 2.0 * trust_score
        elif is_correlated or high_trust:
            return 1.0 * trust_score
        elif low_trust:
            return 0.3 * trust_score
        else:
            return 0.5 * trust_score

    @staticmethod
    def determine_severity(score: float) -> str:
        if score >= 0.80:
            return "CRITICAL"
        elif score >= 0.60:
            return "HIGH"
        elif score >= 0.30:
            return "MEDIUM"
        return "LOW"

    def aggregate(
        self,
        req: VotingRequest,
        responses: List[VotingResponse],
        origin_trust: float = 1.0,
    ) -> ConsensusVerdict:
        """
        Aggregate votes from origin agent and peers into a final ConsensusVerdict.
        """
        # Origin node counts as origin_trust * 1.5 weight
        origin_weight = origin_trust * 1.5
        total_weighted_score = req.threat_score * origin_weight
        total_weight = origin_weight

        for resp in responses:
            w = self.calculate_weight(resp.peer_trust_score, resp.correlated)
            total_weighted_score += resp.peer_vote_score * w
            total_weight += w

        final_score = total_weighted_score / total_weight if total_weight > 0 else req.threat_score
        final_score = max(0.0, min(1.0, final_score))

        severity = self.determine_severity(final_score)
        # Consensus is reached if at least 1 peer responded or if severity is CRITICAL
        consensus_reached = len(responses) > 0 or severity == "CRITICAL"

        return ConsensusVerdict(
            vote_id=req.vote_id,
            origin_agent_id=req.origin_agent_id,
            event_type=req.event_type,
            raw_threat_score=req.threat_score,
            final_weighted_score=round(final_score, 4),
            severity=severity,
            consensus_reached=consensus_reached,
            participating_peers=len(responses),
            total_weight=round(total_weight, 3),
        )


# ===========================================================================
# P2PMeshNode
# ===========================================================================
class P2PMeshNode:
    """
    Distributed peer node for broadcasting requests, listening for votes,
    and computing consensus over UDP sockets / REST seams.

    Parameters
    ----------
    agent_id : str
        Unique node/agent identifier.
    bind_port : int
        UDP port to listen for peer voting messages.
    trust_tracker : AgentTrustTracker, optional
        Persisted sqlite trust tracker instance.
    on_verdict : Callable[[ConsensusVerdict], None], optional
        Callback invoked when a consensus verdict is calculated.
    """

    def __init__(
        self,
        agent_id: str,
        bind_port: int = 9001,
        trust_tracker: Optional[AgentTrustTracker] = None,
        on_verdict: Optional[Callable[[ConsensusVerdict], None]] = None,
    ) -> None:
        self.agent_id = agent_id
        self.bind_port = bind_port
        self.trust_tracker = trust_tracker or AgentTrustTracker(db_path=f"aegis_trust_{agent_id}.db")
        self.on_verdict = on_verdict or self._default_verdict_handler

        self.correlation_engine = PeerCorrelationEngine()
        self.aggregator = WeightedConsensusAggregator()

        self._peers: Dict[str, Tuple[str, int]] = {}  # agent_id -> (host, port)
        self._active_votes: Dict[str, Dict[str, Any]] = {}  # vote_id -> tracking dict
        self._lock = threading.Lock()

        self._socket: Optional[socket.socket] = None
        self._stop_event = threading.Event()
        self._listen_thread: Optional[threading.Thread] = None
        self._is_running: bool = False

    @staticmethod
    def _default_verdict_handler(verdict: ConsensusVerdict) -> None:
        logger.info(
            "[P2PMesh] CONSENSUS VERDICT: vote_id=%s agent=%s severity=%s (score=%.4f, peers=%d)",
            verdict.vote_id,
            verdict.origin_agent_id,
            verdict.severity,
            verdict.final_weighted_score,
            verdict.participating_peers,
        )

    def register_peer(self, peer_agent_id: str, host: str, port: int) -> None:
        """Register a known peer agent address."""
        with self._lock:
            self._peers[peer_agent_id] = (host, port)
            logger.info("[P2PMesh] Registered peer '%s' at %s:%d", peer_agent_id, host, port)

    def evaluate_incoming_request(self, req: VotingRequest) -> VotingResponse:
        """Evaluate an incoming request from a peer node."""
        correlated, suggested_score = self.correlation_engine.check_correlation(req)
        local_trust = self.trust_tracker.get_trust(self.agent_id)

        resp = VotingResponse(
            vote_id=req.vote_id,
            peer_agent_id=self.agent_id,
            peer_trust_score=local_trust,
            correlated=correlated,
            peer_vote_score=suggested_score,
        )
        return resp

    def initiate_vote(
        self,
        event_type: str,
        threat_score: float,
        confidence: float,
        details: Dict[str, Any],
        timeout: float = 2.0,
    ) -> ConsensusVerdict:
        """
        Initiate a network-wide consensus voting process for an anomaly.

        Broadcasts `VotingRequest` to registered peers, waits up to `timeout`
        seconds for responses, aggregates results, and returns `ConsensusVerdict`.
        """
        vote_id = str(uuid.uuid4())[:8]
        req = VotingRequest(
            vote_id=vote_id,
            origin_agent_id=self.agent_id,
            event_type=event_type,
            threat_score=threat_score,
            confidence=confidence,
            details=details,
        )

        responses: List[VotingResponse] = []
        response_event = threading.Event()

        with self._lock:
            self._active_votes[vote_id] = {
                "request": req,
                "responses": responses,
                "event": response_event,
                "expected_peers": len(self._peers),
            }

        # Broadcast payload over socket if available, otherwise direct evaluation
        payload_bytes = json.dumps({"type": "VOTE_REQUEST", "data": req.to_dict()}).encode("utf-8")

        with self._lock:
            peer_list = list(self._peers.values())

        if self._socket and peer_list:
            for host, port in peer_list:
                try:
                    self._socket.sendto(payload_bytes, (host, port))
                except Exception as exc:
                    logger.warning("[P2PMesh] Failed to send vote request to %s:%d: %s", host, port, exc)

        # Wait for responses or timeout
        response_event.wait(timeout=timeout)

        with self._lock:
            vote_data = self._active_votes.pop(vote_id, None)
            collected_responses = vote_data["responses"] if vote_data else responses

        origin_trust = self.trust_tracker.get_trust(self.agent_id)
        verdict = self.aggregator.aggregate(req, collected_responses, origin_trust=origin_trust)

        try:
            self.on_verdict(verdict)
        except Exception as cb_exc:
            logger.warning("[P2PMesh] Error in on_verdict callback: %s", cb_exc)

        return verdict

    def _handle_received_message(self, raw_bytes: bytes, sender_addr: Tuple[str, int]) -> None:
        """Parse and process an incoming UDP socket message."""
        try:
            msg = json.loads(raw_bytes.decode("utf-8"))
            msg_type = msg.get("type")
            data = msg.get("data", {})

            if msg_type == "VOTE_REQUEST":
                req = VotingRequest.from_dict(data)
                # Ignore self requests
                if req.origin_agent_id == self.agent_id:
                    return

                resp = self.evaluate_incoming_request(req)
                resp_payload = json.dumps({"type": "VOTE_RESPONSE", "data": resp.to_dict()}).encode("utf-8")
                if self._socket:
                    self._socket.sendto(resp_payload, sender_addr)

            elif msg_type == "VOTE_RESPONSE":
                resp = VotingResponse.from_dict(data)
                with self._lock:
                    vote_entry = self._active_votes.get(resp.vote_id)
                    if vote_entry:
                        vote_entry["responses"].append(resp)
                        if len(vote_entry["responses"]) >= vote_entry["expected_peers"]:
                            vote_entry["event"].set()

        except Exception as exc:
            logger.warning("[P2PMesh] Error handling socket packet: %s", exc)

    def _listen_loop(self) -> None:
        """Background UDP socket listener thread."""
        logger.info("[P2PMesh] Listener started for agent '%s' on port %d", self.agent_id, self.bind_port)
        while not self._stop_event.is_set():
            try:
                if self._socket:
                    data, addr = self._socket.recvfrom(65535)
                    self._handle_received_message(data, addr)
            except socket.timeout:
                continue
            except Exception as exc:
                if not self._stop_event.is_set():
                    logger.warning("[P2PMesh] Socket receive error: %s", exc)

    def start(self) -> None:
        """Start the background P2P listener socket and thread."""
        if self._is_running:
            return

        self._stop_event.clear()
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind(("0.0.0.0", self.bind_port))
            self._socket.settimeout(0.5)
        except Exception as exc:
            logger.error("[P2PMesh] Failed to bind UDP socket on port %d: %s", self.bind_port, exc)
            self._socket = None

        self._listen_thread = threading.Thread(
            target=self._listen_loop,
            name=f"AEGIS-P2PMesh-{self.agent_id}",
            daemon=True,
        )
        self._is_running = True
        self._listen_thread.start()

    def stop(self, timeout: float = 3.0) -> None:
        """Stop background listener and clean up resources."""
        if not self._is_running:
            return

        self._stop_event.set()
        if self._listen_thread:
            self._listen_thread.join(timeout=timeout)

        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None

        self._is_running = False
        logger.info("[P2PMesh] Node '%s' stopped.", self.agent_id)


# ===========================================================================
# Demo Runnable
# ===========================================================================
if __name__ == "__main__":
    print("=" * 72)
    print("AEGIS Layer 2 — P2P Mesh Consensus Voting Verification Demo")
    print("=" * 72)

    # 1. Instantiate 3 P2P Mesh Nodes
    node1 = P2PMeshNode(agent_id="node-1", bind_port=9101)
    node2 = P2PMeshNode(agent_id="node-2", bind_port=9102)
    node3 = P2PMeshNode(agent_id="node-3", bind_port=9103)

    node1.start()
    node2.start()
    node3.start()

    # 2. Register mesh topology
    node1.register_peer("node-2", "127.0.0.1", 9102)
    node1.register_peer("node-3", "127.0.0.1", 9103)

    node2.register_peer("node-1", "127.0.0.1", 9101)
    node3.register_peer("node-1", "127.0.0.1", 9101)

    # Pre-record a correlated event on node 2
    node2.correlation_engine.record_local_event(
        event_type="network",
        details={"port": 443, "dest_ip": "192.168.1.100"},
    )

    print("\n[Demo] Initiating voting from node-1 for a network anomaly (score=0.85, port=443)...")
    verdict = node1.initiate_vote(
        event_type="network",
        threat_score=0.85,
        confidence=0.90,
        details={"port": 443, "dest_ip": "192.168.1.100"},
        timeout=1.5,
    )

    print(f"\n[Demo] Verdict Received:")
    print(f"  Vote ID            : {verdict.vote_id}")
    print(f"  Raw Score          : {verdict.raw_threat_score}")
    print(f"  Final Weighted Score: {verdict.final_weighted_score}")
    print(f"  Severity           : {verdict.severity}")
    print(f"  Peers Participated : {verdict.participating_peers}")
    print(f"  Total Weight       : {verdict.total_weight}")

    node1.stop()
    node2.stop()
    node3.stop()
    print("=" * 72)
