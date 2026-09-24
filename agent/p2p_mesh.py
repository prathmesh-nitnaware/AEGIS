"""
agent/p2p_mesh.py
==================
AEGIS - Layer 2 Peer-to-Peer Consensus Voting Protocol Engine
--------------------------------------------------------------
Implements a distributed P2P consensus mesh network for monitored endpoint agents.

Architecture & Protocol Overview:
* **Ed25519 Cryptographic Peer Authentication**: Each endpoint agent possesses a
  persistent Ed25519 keypair. VotingRequest and VotingResponse messages are digitally
  signed by the emitting node. Receiving peers verify cryptographic signatures before
  accepting any votes, rejecting messages from forged or unknown identities.
* **Replay Protection**: Messages include unique vote IDs, random nonces, and unix
  epoch timestamps. Stale packets (> max_message_age), clock-skewed packets, and
  previously seen vote IDs/nonces are rejected.
* **Input Bounds Validation**: Scores (threat, confidence, trust, vote) are strictly
  enforced within [0.0, 1.0]. Event types are checked against an explicit allowlist.
  Telemetry details are bounded in size.
* **Peer Response Deduplication**: A peer can contribute at most ONE response per vote.
* **Explicit Quorum Model**: Replaces simplistic single-peer checks with configurable
  quorum rules. Distinguishes NO_QUORUM, PARTIAL_QUORUM, and CONSENSUS_REACHED.
  Distinguishes LOCAL_EMERGENCY_VERDICT from PEER_CONSENSUS_VERDICT.
"""

from __future__ import annotations

import json
import logging
import math
import secrets
import socket
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from agent.confidence_engine import AgentTrustTracker

# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)

# ---------------------------------------------------------------------------
# Protocol Constraints & Constants
# ---------------------------------------------------------------------------
ALLOWED_EVENT_TYPES = frozenset({
    "network",
    "process_linux",
    "process_windows",
    "file",
    "log_line",
    "windows_event",
    "zero_day",
    "sabotage",
    "ransomware_simulation",
})

MAX_DETAILS_BYTES = 65536  # 64 KB limit on payload details
DEFAULT_MAX_MESSAGE_AGE = 30.0  # seconds
DEFAULT_CLOCK_SKEW_TOLERANCE = 5.0  # seconds


# ===========================================================================
# Cryptographic Identity & Verification Helper
# ===========================================================================
class PeerCrypto:
    """Helper for Ed25519 digital signature signing and verification."""

    @staticmethod
    def generate_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        priv = ed25519.Ed25519PrivateKey.generate()
        return priv, priv.public_key()

    @staticmethod
    def public_key_to_hex(pub: ed25519.Ed25519PublicKey) -> str:
        return pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()

    @staticmethod
    def public_key_from_hex(hex_str: str) -> ed25519.Ed25519PublicKey:
        raw = bytes.fromhex(hex_str)
        return ed25519.Ed25519PublicKey.from_public_bytes(raw)

    @staticmethod
    def sign_bytes(priv: ed25519.Ed25519PrivateKey, data: bytes) -> str:
        return priv.sign(data).hex()

    @staticmethod
    def verify_signature(pub: ed25519.Ed25519PublicKey, data: bytes, sig_hex: str) -> bool:
        if not sig_hex:
            return False
        try:
            pub.verify(bytes.fromhex(sig_hex), data)
            return True
        except (InvalidSignature, ValueError, Exception):
            return False


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
    nonce: str = field(default_factory=lambda: secrets.token_hex(8))
    sender_public_key: str = ""
    signature: str = ""

    def canonical_bytes(self) -> bytes:
        """Deterministic canonical byte serialization for cryptographic signing."""
        content = {
            "vote_id": str(self.vote_id),
            "origin_agent_id": str(self.origin_agent_id),
            "event_type": str(self.event_type),
            "threat_score": round(float(self.threat_score), 6),
            "confidence": round(float(self.confidence), 6),
            "timestamp": round(float(self.timestamp), 3),
            "nonce": str(self.nonce),
        }
        return json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign(self, priv_key: ed25519.Ed25519PrivateKey) -> None:
        """Sign request in-place using private key."""
        self.signature = PeerCrypto.sign_bytes(priv_key, self.canonical_bytes())

    def verify(self, pub_key: ed25519.Ed25519PublicKey) -> bool:
        """Verify request signature using public key."""
        return PeerCrypto.verify_signature(pub_key, self.canonical_bytes(), self.signature)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> VotingRequest:
        return cls(
            vote_id=str(data["vote_id"]),
            origin_agent_id=str(data["origin_agent_id"]),
            event_type=str(data["event_type"]),
            threat_score=float(data["threat_score"]),
            confidence=float(data["confidence"]),
            details=data.get("details", {}),
            timestamp=float(data.get("timestamp", time.time())),
            nonce=str(data.get("nonce", "")),
            sender_public_key=str(data.get("sender_public_key", "")),
            signature=str(data.get("signature", "")),
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
    nonce: str = field(default_factory=lambda: secrets.token_hex(8))
    sender_public_key: str = ""
    signature: str = ""

    def canonical_bytes(self) -> bytes:
        """Deterministic canonical byte serialization for cryptographic signing."""
        content = {
            "vote_id": str(self.vote_id),
            "peer_agent_id": str(self.peer_agent_id),
            "peer_trust_score": round(float(self.peer_trust_score), 6),
            "correlated": bool(self.correlated),
            "peer_vote_score": round(float(self.peer_vote_score), 6),
            "timestamp": round(float(self.timestamp), 3),
            "nonce": str(self.nonce),
        }
        return json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign(self, priv_key: ed25519.Ed25519PrivateKey) -> None:
        """Sign response in-place using private key."""
        self.signature = PeerCrypto.sign_bytes(priv_key, self.canonical_bytes())

    def verify(self, pub_key: ed25519.Ed25519PublicKey) -> bool:
        """Verify response signature using public key."""
        return PeerCrypto.verify_signature(pub_key, self.canonical_bytes(), self.signature)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> VotingResponse:
        return cls(
            vote_id=str(data["vote_id"]),
            peer_agent_id=str(data["peer_agent_id"]),
            peer_trust_score=float(data["peer_trust_score"]),
            correlated=bool(data["correlated"]),
            peer_vote_score=float(data["peer_vote_score"]),
            timestamp=float(data.get("timestamp", time.time())),
            nonce=str(data.get("nonce", "")),
            sender_public_key=str(data.get("sender_public_key", "")),
            signature=str(data.get("signature", "")),
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
    quorum_status: str = "CONSENSUS_REACHED"  # NO_QUORUM, PARTIAL_QUORUM, CONSENSUS_REACHED
    verdict_type: str = "PEER_CONSENSUS_VERDICT"  # PEER_CONSENSUS_VERDICT, LOCAL_EMERGENCY_VERDICT, INSUFFICIENT_QUORUM

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ===========================================================================
# Replay Protection Helper
# ===========================================================================
class ReplayProtector:
    """Thread-safe replay protection tracker with LRU expiration."""

    def __init__(self, max_age_seconds: float = DEFAULT_MAX_MESSAGE_AGE, max_entries: int = 10000) -> None:
        self.max_age_seconds = max_age_seconds
        self.max_entries = max_entries
        self._seen: Dict[str, float] = {}
        self._lock = threading.Lock()

    def validate_and_record(self, sender_id: str, nonce: str, msg_timestamp: float) -> bool:
        """
        Returns True if the message is fresh and not replayed, False otherwise.
        """
        now = time.time()
        # Freshness / clock skew check
        if (now - msg_timestamp) > self.max_age_seconds:
            return False
        if (msg_timestamp - now) > 60.0:  # Future clock skew > 60s
            return False

        key = f"{sender_id}:{nonce}"
        with self._lock:
            if key in self._seen:
                return False

            # Cleanup expired entries if size exceeds limit
            if len(self._seen) >= self.max_entries:
                cutoff = now - self.max_age_seconds
                self._seen = {k: ts for k, ts in self._seen.items() if ts > cutoff}

            self._seen[key] = msg_timestamp
            return True


# ===========================================================================
# Validation Helpers
# ===========================================================================
def validate_voting_request(
    req: VotingRequest,
    max_age: float = DEFAULT_MAX_MESSAGE_AGE,
    clock_skew: float = DEFAULT_CLOCK_SKEW_TOLERANCE,
) -> Tuple[bool, str]:
    """Validate numerical ranges, event allowlist, details size, and timestamps."""
    if not (0.0 <= req.threat_score <= 1.0):
        return False, f"Invalid threat_score: {req.threat_score}. Must be in [0, 1]."
    if not (0.0 <= req.confidence <= 1.0):
        return False, f"Invalid confidence: {req.confidence}. Must be in [0, 1]."
    if req.event_type not in ALLOWED_EVENT_TYPES:
        return False, f"Invalid event_type '{req.event_type}'. Not in allowlist."

    try:
        details_bytes = json.dumps(req.details).encode("utf-8")
        if len(details_bytes) > MAX_DETAILS_BYTES:
            return False, f"Details size {len(details_bytes)} bytes exceeds max {MAX_DETAILS_BYTES} bytes."
    except Exception as exc:
        return False, f"Malformed details payload: {exc}"

    now = time.time()
    if (now - req.timestamp) > max_age:
        return False, f"Stale VotingRequest: age {round(now - req.timestamp, 2)}s exceeds max {max_age}s."
    if (req.timestamp - now) > clock_skew:
        return False, f"Clock-skewed VotingRequest: timestamp is {round(req.timestamp - now, 2)}s in the future."

    return True, "OK"


def validate_voting_response(
    resp: VotingResponse,
    max_age: float = DEFAULT_MAX_MESSAGE_AGE,
    clock_skew: float = DEFAULT_CLOCK_SKEW_TOLERANCE,
) -> Tuple[bool, str]:
    """Validate numerical ranges and timestamp freshness for a VotingResponse."""
    if not (0.0 <= resp.peer_trust_score <= 1.0):
        return False, f"Invalid peer_trust_score: {resp.peer_trust_score}. Must be in [0, 1]."
    if not (0.0 <= resp.peer_vote_score <= 1.0):
        return False, f"Invalid peer_vote_score: {resp.peer_vote_score}. Must be in [0, 1]."

    now = time.time()
    if (now - resp.timestamp) > max_age:
        return False, f"Stale VotingResponse: age {round(now - resp.timestamp, 2)}s exceeds max {max_age}s."
    if (resp.timestamp - now) > clock_skew:
        return False, f"Clock-skewed VotingResponse: timestamp is {round(resp.timestamp - now, 2)}s in the future."

    return True, "OK"


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
                if req.event_type == "network":
                    if (local_details.get("port") and local_details.get("port") == req_details.get("port")) or \
                       (local_details.get("dest_ip") and local_details.get("dest_ip") == req_details.get("dest_ip")):
                        logger.info("[CorrelationEngine] Match found on network details: %s", req_details)
                        return True, req.threat_score

                elif req.event_type in ("process_linux", "process_windows"):
                    if (local_details.get("process") and local_details.get("process") == req_details.get("process")) or \
                       (local_details.get("pid") and local_details.get("pid") == req_details.get("pid")):
                        logger.info("[CorrelationEngine] Match found on process details: %s", req_details)
                        return True, req.threat_score

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
    Computes weighted consensus verdict from origin request and peer responses
    using an explicit quorum model.
    """

    @staticmethod
    def calculate_weight(trust_score: float, is_correlated: bool) -> float:
        """
        AEGIS Weight Multiplier Spec:
        - 2.0x: Correlated AND high trust (>= 0.7)
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
        expected_peers: Optional[int] = None,
        min_quorum: Optional[int] = None,
    ) -> ConsensusVerdict:
        """
        Aggregate votes from origin agent and peers into a final ConsensusVerdict.

        Quorum Model:
        - expected_peers: Total peer nodes in cluster/expected to participate.
        - min_quorum: Minimum peer responses required to reach consensus.
          Default: math.ceil((expected_peers + 1) / 2) if expected_peers specified, else 1 if len(responses) > 0.
        - Quorum States:
          * NO_QUORUM: 0 peer responses received.
          * PARTIAL_QUORUM: responses > 0 but < min_quorum.
          * CONSENSUS_REACHED: responses >= min_quorum.
        - Verdict Types:
          * PEER_CONSENSUS_VERDICT: consensus_reached is True.
          * LOCAL_EMERGENCY_VERDICT: local/critical score without quorum (consensus_reached is False).
          * INSUFFICIENT_QUORUM: non-critical score without quorum (consensus_reached is False).
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

        # Quorum evaluation
        num_responses = len(responses)
        if expected_peers is not None and expected_peers > 0:
            quorum_needed = min_quorum if min_quorum is not None else max(1, math.ceil((expected_peers + 1) / 2))
        else:
            quorum_needed = min_quorum if min_quorum is not None else (1 if num_responses > 0 else 1)

        if num_responses == 0:
            quorum_status = "NO_QUORUM"
            consensus_reached = False
        elif num_responses < quorum_needed:
            quorum_status = "PARTIAL_QUORUM"
            consensus_reached = False
        else:
            quorum_status = "CONSENSUS_REACHED"
            consensus_reached = True

        # Distinguish local emergency verdict from distributed peer consensus
        if consensus_reached:
            verdict_type = "PEER_CONSENSUS_VERDICT"
        elif severity == "CRITICAL" or req.threat_score >= 0.80:
            verdict_type = "LOCAL_EMERGENCY_VERDICT"
        else:
            verdict_type = "INSUFFICIENT_QUORUM"

        return ConsensusVerdict(
            vote_id=req.vote_id,
            origin_agent_id=req.origin_agent_id,
            event_type=req.event_type,
            raw_threat_score=req.threat_score,
            final_weighted_score=round(final_score, 4),
            severity=severity,
            consensus_reached=consensus_reached,
            participating_peers=num_responses,
            total_weight=round(total_weight, 3),
            quorum_status=quorum_status,
            verdict_type=verdict_type,
        )


# ===========================================================================
# P2PMeshNode
# ===========================================================================
class P2PMeshNode:
    """
    Distributed peer node for broadcasting requests, listening for votes,
    and computing consensus over UDP sockets with Ed25519 peer authentication
    and replay protection.

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
    private_key : ed25519.Ed25519PrivateKey, optional
        Persistent Ed25519 private key. If omitted, generates a fresh keypair.
    min_quorum : int, optional
        Configurable minimum peer responses for quorum consensus.
    max_message_age : float
        Replay protection age limit in seconds (default 30.0).
    clock_skew_tolerance : float
        Allowed clock skew in seconds (default 5.0).
    """

    def __init__(
        self,
        agent_id: str,
        bind_port: int = 9001,
        trust_tracker: Optional[AgentTrustTracker] = None,
        on_verdict: Optional[Callable[[ConsensusVerdict], None]] = None,
        private_key: Optional[ed25519.Ed25519PrivateKey] = None,
        min_quorum: Optional[int] = None,
        max_message_age: float = DEFAULT_MAX_MESSAGE_AGE,
        clock_skew_tolerance: float = DEFAULT_CLOCK_SKEW_TOLERANCE,
    ) -> None:
        self.agent_id = agent_id
        self.bind_port = bind_port
        self.trust_tracker = trust_tracker or AgentTrustTracker(db_path=f"aegis_trust_{agent_id}.db")
        self.on_verdict = on_verdict or self._default_verdict_handler

        self.min_quorum = min_quorum
        self.max_message_age = max_message_age
        self.clock_skew_tolerance = clock_skew_tolerance

        # Cryptographic Identity
        if private_key is not None:
            self._private_key = private_key
            self._public_key = private_key.public_key()
        else:
            self._private_key, self._public_key = PeerCrypto.generate_keypair()

        self.public_key_hex = PeerCrypto.public_key_to_hex(self._public_key)

        self.correlation_engine = PeerCorrelationEngine()
        self.aggregator = WeightedConsensusAggregator()

        self._peers: Dict[str, Tuple[str, int]] = {}  # agent_id -> (host, port)
        self._peer_keys: Dict[str, ed25519.Ed25519PublicKey] = {}  # agent_id -> Ed25519PublicKey
        self._active_votes: Dict[str, Dict[str, Any]] = {}  # vote_id -> tracking dict

        # Replay & Deduplication protection structures
        self._seen_messages: Dict[str, float] = {}  # message/nonce/vote_id -> timestamp
        self._peer_responses_per_vote: Dict[str, Set[str]] = {}  # vote_id -> set of peer_ids who voted

        self._lock = threading.Lock()

        self._socket: Optional[socket.socket] = None
        self._stop_event = threading.Event()
        self._listen_thread: Optional[threading.Thread] = None
        self._is_running: bool = False

    @staticmethod
    def _default_verdict_handler(verdict: ConsensusVerdict) -> None:
        logger.info(
            "[P2PMesh] CONSENSUS VERDICT: vote_id=%s agent=%s severity=%s (score=%.4f, peers=%d, quorum=%s, type=%s)",
            verdict.vote_id,
            verdict.origin_agent_id,
            verdict.severity,
            verdict.final_weighted_score,
            verdict.participating_peers,
            verdict.quorum_status,
            verdict.verdict_type,
        )

    def register_peer(
        self,
        peer_agent_id: str,
        host: str,
        port: int,
        public_key_hex: Optional[str] = None,
    ) -> None:
        """
        Register a known peer agent address and its Ed25519 public key.
        """
        with self._lock:
            self._peers[peer_agent_id] = (host, port)
            if public_key_hex:
                try:
                    self._peer_keys[peer_agent_id] = PeerCrypto.public_key_from_hex(public_key_hex)
                except Exception as exc:
                    logger.warning("[P2PMesh] Failed to parse public key for peer '%s': %s", peer_agent_id, exc)
            logger.info("[P2PMesh] Registered peer '%s' at %s:%d (has_key=%s)", peer_agent_id, host, port, peer_agent_id in self._peer_keys)

    def evaluate_incoming_request(self, req: VotingRequest) -> VotingResponse:
        """Evaluate an incoming request from a peer node and sign the response."""
        correlated, suggested_score = self.correlation_engine.check_correlation(req)
        local_trust = self.trust_tracker.get_trust(self.agent_id)

        resp = VotingResponse(
            vote_id=req.vote_id,
            peer_agent_id=self.agent_id,
            peer_trust_score=local_trust,
            correlated=correlated,
            peer_vote_score=suggested_score,
            timestamp=time.time(),
            sender_public_key=self.public_key_hex,
        )
        resp.sign(self._private_key)
        return resp

    def _clean_replay_cache(self, now: float) -> None:
        """Evict expired entries from replay cache."""
        cutoff = now - (self.max_message_age * 2)
        expired = [k for k, ts in self._seen_messages.items() if ts < cutoff]
        for k in expired:
            self._seen_messages.pop(k, None)

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

        Broadcasts signed `VotingRequest` to registered peers, waits up to `timeout`
        seconds for responses, aggregates results with explicit quorum, and returns `ConsensusVerdict`.
        """
        vote_id = str(uuid.uuid4())[:8]
        req = VotingRequest(
            vote_id=vote_id,
            origin_agent_id=self.agent_id,
            event_type=event_type,
            threat_score=threat_score,
            confidence=confidence,
            details=details,
            timestamp=time.time(),
            sender_public_key=self.public_key_hex,
        )
        req.sign(self._private_key)

        responses: List[VotingResponse] = []
        response_event = threading.Event()

        with self._lock:
            expected_peers = len(self._peers)
            self._active_votes[vote_id] = {
                "request": req,
                "responses": responses,
                "event": response_event,
                "expected_peers": expected_peers,
                "start_time": time.time(),
            }
            self._peer_responses_per_vote[vote_id] = set()
            self._seen_messages[vote_id] = req.timestamp
            if req.nonce:
                self._seen_messages[req.nonce] = req.timestamp

            peer_list = list(self._peers.values())

        # Broadcast signed payload over socket
        payload_bytes = json.dumps({"type": "VOTE_REQUEST", "data": req.to_dict()}).encode("utf-8")

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
            self._peer_responses_per_vote.pop(vote_id, None)

        origin_trust = self.trust_tracker.get_trust(self.agent_id)
        verdict = self.aggregator.aggregate(
            req,
            collected_responses,
            origin_trust=origin_trust,
            expected_peers=expected_peers,
            min_quorum=self.min_quorum,
        )

        try:
            self.on_verdict(verdict)
        except Exception as cb_exc:
            logger.warning("[P2PMesh] Error in on_verdict callback: %s", cb_exc)

        return verdict

    def _handle_received_message(self, raw_bytes: bytes, sender_addr: Tuple[str, int]) -> None:
        """Parse, cryptographically verify, validate, and process incoming UDP message."""
        now = time.time()
        try:
            msg = json.loads(raw_bytes.decode("utf-8"))
            msg_type = msg.get("type")
            data = msg.get("data", {})

            with self._lock:
                self._clean_replay_cache(now)

            if msg_type == "VOTE_REQUEST":
                req = VotingRequest.from_dict(data)

                # 1. Ignore self requests
                if req.origin_agent_id == self.agent_id:
                    return

                # 2. Replay check
                with self._lock:
                    if req.vote_id in self._seen_messages or (req.nonce and req.nonce in self._seen_messages):
                        logger.warning("[P2PMesh] Replay detected for vote_id=%s nonce=%s. Rejecting packet.", req.vote_id, req.nonce)
                        return
                    self._seen_messages[req.vote_id] = req.timestamp
                    if req.nonce:
                        self._seen_messages[req.nonce] = req.timestamp

                # 3. Payload validation
                valid, reason = validate_voting_request(
                    req, max_age=self.max_message_age, clock_skew=self.clock_skew_tolerance
                )
                if not valid:
                    logger.warning("[P2PMesh] Invalid VotingRequest from %s: %s", req.origin_agent_id, reason)
                    return

                # 4. Cryptographic signature and identity verification
                with self._lock:
                    peer_key = self._peer_keys.get(req.origin_agent_id)
                    is_registered = req.origin_agent_id in self._peers

                if not is_registered:
                    logger.warning("[P2PMesh] Rejecting VotingRequest from unknown peer identity: %s", req.origin_agent_id)
                    return

                # If peer is registered but public key was not pre-shared, bind from valid signed request
                if not peer_key and req.sender_public_key:
                    try:
                        peer_key = PeerCrypto.public_key_from_hex(req.sender_public_key)
                        with self._lock:
                            self._peer_keys[req.origin_agent_id] = peer_key
                    except Exception as exc:
                        logger.warning("[P2PMesh] Failed to decode sender_public_key from '%s': %s", req.origin_agent_id, exc)
                        return

                if peer_key:
                    if not req.verify(peer_key):
                        logger.warning("[P2PMesh] Signature verification FAILED for peer '%s' (vote_id=%s)", req.origin_agent_id, req.vote_id)
                        return
                else:
                    logger.warning("[P2PMesh] Cannot verify signature: no public key available for peer '%s'", req.origin_agent_id)
                    return

                # 5. Evaluate and reply with signed VotingResponse
                resp = self.evaluate_incoming_request(req)
                resp_payload = json.dumps({"type": "VOTE_RESPONSE", "data": resp.to_dict()}).encode("utf-8")
                if self._socket:
                    self._socket.sendto(resp_payload, sender_addr)

            elif msg_type == "VOTE_RESPONSE":
                resp = VotingResponse.from_dict(data)

                # 1. Check if vote is active
                with self._lock:
                    vote_entry = self._active_votes.get(resp.vote_id)
                    if not vote_entry:
                        logger.debug("[P2PMesh] Received VotingResponse for inactive/expired vote_id=%s from %s", resp.vote_id, resp.peer_agent_id)
                        return

                    # 2. Reject duplicate response from the SAME peer for this vote
                    peers_voted = self._peer_responses_per_vote.setdefault(resp.vote_id, set())
                    if resp.peer_agent_id in peers_voted:
                        logger.warning("[P2PMesh] Duplicate VotingResponse from peer '%s' for vote_id=%s. Rejecting.", resp.peer_agent_id, resp.vote_id)
                        return

                    peer_key = self._peer_keys.get(resp.peer_agent_id)
                    is_registered = resp.peer_agent_id in self._peers

                # 3. Check registered peer identity
                if not is_registered:
                    logger.warning("[P2PMesh] Rejecting VotingResponse from unknown peer identity: %s", resp.peer_agent_id)
                    return

                # If peer is registered but public key was not pre-shared, bind from response
                if not peer_key and resp.sender_public_key:
                    try:
                        peer_key = PeerCrypto.public_key_from_hex(resp.sender_public_key)
                        with self._lock:
                            self._peer_keys[resp.peer_agent_id] = peer_key
                    except Exception as exc:
                        logger.warning("[P2PMesh] Failed to decode sender_public_key from '%s': %s", resp.peer_agent_id, exc)
                        return

                # 4. Cryptographic signature verification
                if peer_key:
                    if not resp.verify(peer_key):
                        logger.warning("[P2PMesh] Response signature verification FAILED for peer '%s' (vote_id=%s)", resp.peer_agent_id, resp.vote_id)
                        return
                else:
                    logger.warning("[P2PMesh] Cannot verify signature: no public key available for peer '%s'", resp.peer_agent_id)
                    return

                # 5. Validate response ranges & freshness
                valid, reason = validate_voting_response(
                    resp, max_age=self.max_message_age, clock_skew=self.clock_skew_tolerance
                )
                if not valid:
                    logger.warning("[P2PMesh] Invalid VotingResponse from %s: %s", resp.peer_agent_id, reason)
                    return

                # 6. Record response
                with self._lock:
                    # Double-check vote entry still active
                    vote_entry = self._active_votes.get(resp.vote_id)
                    if vote_entry:
                        peers_voted = self._peer_responses_per_vote.setdefault(resp.vote_id, set())
                        peers_voted.add(resp.peer_agent_id)
                        vote_entry["responses"].append(resp)

                        # Trigger completion if expected peers arrived
                        if len(vote_entry["responses"]) >= vote_entry["expected_peers"]:
                            vote_entry["event"].set()

        except Exception as exc:
            logger.warning("[P2PMesh] Error handling socket packet from %s: %s", sender_addr, exc)

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
