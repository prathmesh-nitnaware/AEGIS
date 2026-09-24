"""
backend/schemas.py
===================
AEGIS Autonomous EDR - Pydantic Request & Response Schemas
----------------------------------------------------------
Defines strict, validated schemas for all Command Node HTTP API endpoints:
- Inbound Heartbeats & Silence Beacons
- Centralized and P2P Threat Consensus Voting
- Remote Action Enqueuing & Acknowledgement Lifecycle
- Operator Trust Feedback & Maintenance Window Scheduling
- Collector Health & System Observability
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


# ===========================================================================
# Action Allowlist & Lifecycle Statuses
# ===========================================================================
ALLOWED_ACTION_TYPES = Literal[
    "LOG",
    "ALERT",
    "KILL_PROCESS",
    "QUARANTINE_FILE",
    "ISOLATE_HOST",
    "UNISOLATE_HOST",
]

ALLOWED_ACTION_STATUSES = Literal[
    "PENDING",
    "DISPATCHED",
    "EXECUTING",
    "SUCCESS",
    "FAILED",
    "PARTIAL",
    "NOT_FOUND",
    "DENIED",
    "SIMULATED",
    "EXECUTED",
]

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


# ===========================================================================
# 1. Heartbeat & Shutdown Schemas
# ===========================================================================
class HeartbeatPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    agent_id: str = Field(..., min_length=1, max_length=128, description="Monitored agent identifier")
    status: Literal["healthy", "degraded", "offline"] = Field("healthy", description="Agent health state")
    cpu: float = Field(0.0, ge=0.0, le=100.0, description="CPU utilization percentage [0, 100]")
    timestamp: float = Field(default_factory=time.time, description="Unix timestamp of heartbeat")
    nonce: Optional[str] = Field(None, max_length=64, description="Replay prevention nonce")
    signature: Optional[str] = Field(None, max_length=256, description="Optional Ed25519 signature hex")


class HeartbeatShutdownPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    agent_id: str = Field(..., min_length=1, max_length=128)
    reason: str = Field("user_initiated_shutdown", max_length=256)
    timestamp: float = Field(default_factory=time.time)
    nonce: Optional[str] = Field(None, max_length=64)
    signature: Optional[str] = Field(None, max_length=256)


# ===========================================================================
# 2. Centralized & P2P Voting Schemas
# ===========================================================================
class CentralizedVotePayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    event_type: str = Field(..., min_length=1, max_length=64)
    origin_agent_id: Optional[str] = Field(None, min_length=1, max_length=128)
    agent_id: Optional[str] = Field(None, min_length=1, max_length=128)
    threat_score: float = Field(..., ge=0.0, le=1.0)
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    details: Dict[str, Any] = Field(default_factory=dict)
    pid: Optional[int] = None
    target_file: Optional[str] = None

    def get_origin_agent_id(self) -> str:
        return self.origin_agent_id or self.agent_id or "agent-local"


class P2PVotePayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    vote_id: str = Field(..., min_length=1, max_length=64)
    origin_agent_id: str = Field(..., min_length=1, max_length=128)
    event_type: str = Field(..., min_length=1, max_length=64)
    threat_score: float = Field(..., ge=0.0, le=1.0)
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    details: Dict[str, Any] = Field(default_factory=dict)
    timestamp: float = Field(default_factory=time.time)
    nonce: Optional[str] = Field(None, max_length=64)
    signature: Optional[str] = Field(None, max_length=256)


class P2PConsensusPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    vote_id: str = Field(..., min_length=1, max_length=64)
    origin_agent_id: str = Field(..., min_length=1, max_length=128)
    event_type: str = Field(..., min_length=1, max_length=64)
    raw_threat_score: float = Field(..., ge=0.0, le=1.0)
    final_weighted_score: float = Field(..., ge=0.0, le=1.0)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "LOW"
    consensus_reached: bool = False
    participating_peers: int = Field(0, ge=0)
    total_weight: float = Field(0.0, ge=0.0)
    timestamp: float = Field(default_factory=time.time)
    quorum_status: Optional[str] = None
    verdict_type: Optional[str] = None


# ===========================================================================
# 3. Remote Action Dispatcher Schemas
# ===========================================================================
class RemoteActionEnqueuePayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    agent_id: str = Field(..., min_length=1, max_length=128)
    action_type: ALLOWED_ACTION_TYPES
    vote_id: Optional[str] = Field(None, max_length=64)
    target_pid: Optional[int] = None
    target_file: Optional[str] = Field(None, max_length=512)
    command_node_ip: str = Field("127.0.0.1", max_length=64)
    parameters: Optional[Dict[str, Any]] = Field(default_factory=dict)


class RemoteActionAckPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    status: ALLOWED_ACTION_STATUSES = "SUCCESS"
    result_details: Optional[Dict[str, Any]] = Field(default_factory=dict)
    details: Optional[Dict[str, Any]] = None

    def get_effective_details(self) -> Dict[str, Any]:
        return self.result_details or self.details or {}


# ===========================================================================
# 4. Trust Feedback & Maintenance Schemas
# ===========================================================================
class TrustFeedbackPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    vote_id: Optional[str] = Field(None, max_length=64)
    agent_id: Optional[str] = Field(None, max_length=128)
    confirmed: bool = True
    confirmed_by: str = Field("admin", min_length=1, max_length=128)
    feedback_type: Optional[str] = None
    adjustment: Optional[float] = Field(None, ge=-1.0, le=1.0)
    reason: Optional[str] = None


class MaintenanceSchedulePayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    agent_id: str = Field("*", min_length=1, max_length=128)
    duration_seconds: float = Field(3600.0, ge=1.0, le=604800.0)  # Min 1s, Max 7 days
    approved_by: str = Field("admin", min_length=1, max_length=128)
    reason: str = Field("Scheduled System Maintenance", min_length=1, max_length=512)


class MaintenanceCancelPayload(BaseModel):
    window_id: str = Field(..., min_length=1, max_length=64)


# ===========================================================================
# 5. User Login & Token Request Schemas
# ===========================================================================
class UserLoginPayload(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)


class AgentTokenIssuePayload(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=128)
    cluster_id: str = Field("cluster-alpha", min_length=1, max_length=64)
    ttl_days: Optional[int] = Field(30, ge=1, le=365)
