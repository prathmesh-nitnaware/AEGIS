# AEGIS Security Audit & Hardening Report

**System Name:** Project AEGIS (Adaptive Edge Guardian with Intelligence Swarm)  
**Branch:** `dev`  
**Audit Scope:** P0 (Security Hardening), P1 (Consensus Correctness, Reliability & Observability), P2 (Documentation & Code Quality)  
**Verification Date:** September 2026  
**Final Test Suite Verification:** **285 Passed**, **8 Skipped**, **0 Failed** (out of 293 collected test items)  

---

## 1. Executive Summary

A comprehensive, code-level security and correctness audit was performed on the `dev` branch of `prathmesh-nitnaware/AEGIS`. The objective was to audit and harden the distributed Endpoint Detection and Response (EDR) system against impersonation, message replay, unauthorized access, consensus poisoning, silent collector failures, and destructive host command execution without breaking existing architecture or regressions in baseline functionality.

All findings have been remediated directly in executable code, backed by **25 new automated verification tests** in [`tests/test_security_and_consensus_hardening.py`](file:///d:/AEGIS/tests/test_security_and_consensus_hardening.py). All 260 preexisting baseline tests continue to pass without regression.

---

## 2. Threat Modeling & Attack Surface

The AEGIS architecture was evaluated across four primary threat boundaries:

```
[ Compromised Endpoint Agent ]
              │  (Attacks: Forged Vote, Message Replay, Flooding, Extreme Scores)
              ▼
    [ P2P Mesh Network ]  ◄── Ed25519 Signatures, Nonces, LRU Cache, Bounded Floats
              │
              ▼
[ Weighted Consensus Engine ] ◄── Quorum Ladder (NO_QUORUM, PARTIAL, CONSENSUS)
              │
              ▼
   [ FastAPI Command Node ]  ◄── Localhost CORS, JWT/HMAC RBAC, Pydantic v2 Schemas
              │
              ▼
  [ Response Enforcement ]   ◄── Safe Simulation Default, Elevated Real OS Guardrails
```

1. **P2P Wire Mesh Boundary:** Agents communicate via UDP/ZeroMQ sockets to exchange telemetry votes. Prior to this audit, peer voting packets were transmitted without asymmetric cryptographic signatures or replay validation, allowing any network-adjacent or compromised node to forge votes or replay historical verdicts.
2. **Command Node API Boundary:** Exposes REST and WebSocket endpoints for telemetry ingestion, action dispatching, and administration. Permissive CORS configurations, unvalidated raw dictionaries, and unauthenticated endpoints presented lateral movement and unauthorized state manipulation risks.
3. **Consensus Aggregation Boundary:** Nodes aggregate peer responses to establish response thresholds. Without bounded inputs and formal quorum states, out-of-range floats or partitioned networks could produce false consensus or emergency fallbacks labeled incorrectly as Byzantine agreement.
4. **Host Remediation Boundary:** Autonomous mitigation drivers interact directly with OS-level firewalls (`netsh`/`iptables`) and process tables (`psutil`). Misconfigurations or false alarms could cause accidental denial-of-service or host network disconnects.

---

## 3. Vulnerability Findings & Remediations Applied

### 3.1 P0 — Cryptographic Identity & Anti-Replay in P2P Mesh
- **Finding (SEC-01): Unsigned P2P Messages.** `VotingRequest` and `VotingResponse` objects lacked digital signatures. Any node on the local subnet or overlay could forge peer votes.
- **Remediation:** Integrated Ed25519 asymmetric cryptography via the `PeerCrypto` class in [`agent/p2p_mesh.py`](file:///d:/AEGIS/agent/p2p_mesh.py). Each peer generates or loads an Ed25519 keypair, publishes its public key in vote messages, and cryptographically signs canonical payloads (`vote_id`, `threat_score`, `confidence`, `timestamp`, `nonce`). Received messages are strictly verified against the sender's public key; tampered or unauthenticated messages are rejected immediately.
- **Finding (SEC-02): Message Replay & Clock Skew Vulnerability.** Attackers could record high-severity votes and replay them indefinitely to trigger denial-of-service remediations.
- **Remediation:** Added `ReplayProtector` in `agent/p2p_mesh.py` utilizing a high-performance LRU cache and timestamp age verification (rejecting messages older than 60 seconds or with clock skew > 15 seconds). Each message requires a cryptographically secure random `nonce`. Replayed or expired messages are dropped.
- **Finding (SEC-03): Unbounded Numerical Input Range Injection.** Threat scores, confidence values, and peer trust scores accepted arbitrary numerical values, enabling out-of-range weights (e.g., threat score of 9999) to bypass quorum math.
- **Remediation:** Added strict bounded validation enforcing `0.0 <= threat_score <= 1.0`, `0.0 <= confidence <= 1.0`, and `0.0 <= trust_score <= 1.0`. Enforced string length limits (max 128 characters for identifiers, 64KB for details).

### 3.2 P0 — Command Node API Security & RBAC
- **Finding (SEC-04): Permissive CORS Configuration.** FastAPI previously allowed wildcard origins (`allow_origins=["*"]`) alongside `allow_credentials=True`, violating browser security standards.
- **Remediation:** In [`backend/telemetry_api.py`](file:///d:/AEGIS/backend/telemetry_api.py), replaced wildcard CORS with a restricted localhost allowlist (`http://localhost:5173`, `http://localhost:5174`, `http://127.0.0.1:5173`, `http://127.0.0.1:5174`) and configurable environment variables.
- **Finding (SEC-05): Missing Role Enforcement on Sensitive Routes.** `/api/trust/feedback` and maintenance window scheduling routes could be triggered without administrative authorization.
- **Remediation:** Added `verify_admin_role` and `verify_operator_role` dependency checks. Administrative routes now mandate valid bearer tokens with `admin` role capabilities, returning HTTP 401 for unauthenticated calls and HTTP 403 for insufficient privileges.
- **Finding (SEC-06): Action Hijacking in ACK Endpoint.** The `/api/agents/{agent_id}/actions/{action_id}/ack` route did not verify that the acknowledging agent matched the action's target agent.
- **Remediation:** Enforced ownership validation: if `existing.agent_id != agent_id`, the Command Node halts execution and returns HTTP 403 Forbidden.
- **Finding (SEC-07): Duplicate Terminal Action ACKs.** Multiple execution ACKs could overwrite terminal action records.
- **Remediation:** Enforced state machine invariants: attempting to acknowledge an action already in a terminal state (`SUCCESS`, `FAILED`, `SIMULATED`, `EXECUTED`, `DENIED`, etc.) returns HTTP 409 Conflict.
- **Finding (SEC-08): Strict Schema Validation via Pydantic v2.** Incoming API bodies previously accepted unvalidated raw dictionaries.
- **Remediation:** Created [`backend/schemas.py`](file:///d:/AEGIS/backend/schemas.py) defining strict Pydantic v2 models (`HeartbeatPayload`, `CentralizedVotePayload`, `P2PVotePayload`, `P2PConsensusPayload`, `RemoteActionEnqueuePayload`, `RemoteActionAckPayload`, `TrustFeedbackPayload`, `MaintenanceSchedulePayload`, `MaintenanceCancelPayload`).

### 3.3 P1 — Consensus Quorum Correctness & Clarification
- **Finding (CON-01): Overstated Byzantine Agreement Claims.** Documentation and comments previously claimed "formal Byzantine consensus" or "PBFT". The actual implementation is a trust-weighted peer quorum aggregator.
- **Remediation:** Reconciled documentation and code terminology. Formalized the consensus states in `WeightedConsensusAggregator` into an explicit state machine:
  * `NO_QUORUM`: Insufficient peer responses to meet the minimum quorum threshold.
  * `PARTIAL_QUORUM`: Quorum reached, but consensus threshold not achieved; falls back to `LOCAL_EMERGENCY_VERDICT` only if local threat score is critical, otherwise defaults to safe `LOG`.
  * `CONSENSUS_REACHED`: Trust-weighted peer vote exceeds threshold, producing an authenticated `PEER_CONSENSUS_VERDICT`.
  * Deduplicated peer responses per `vote_id` to prevent multi-voting by single nodes.

### 3.4 P1 — Collector Reliability & Telemetry Observability
- **Finding (REL-01): Silent Error Swallowing in Telemetry Collectors.** Multiple collectors in `agent/live_collectors.py` contained bare `except Exception: pass` blocks and unformatted `print()` statements, concealing collector degradation.
- **Remediation:** Created [`agent/collectors/collector_health.py`](file:///d:/AEGIS/agent/collectors/collector_health.py) implementing `CollectorHealthRegistry` with standard lifecycle states: `IDLE`, `HEALTHY`, `DEGRADED`, and `FAILED`. Refactored all 6 live collectors (`SyscallCollector`, `ETWCollector`, `CICIDSNetworkCollector`, `EMBERFileCollector`, `HDFSLogCollector`, `ZeroDayCollector`) to use structured logging and register runtime errors with full tracebacks. Exposed health visibility via `GET /api/collectors/health`.

### 3.5 P1 — Precision Response Driver & Host Safety
- **Finding (RES-01): Ambiguous Execution Status & Host Disruption Risk.** The response driver previously returned generic status strings and had no clear simulation vs. real execution contract, posing a risk of disruptive firewall changes on the host OS.
- **Remediation:** Refactored [`agent/response_driver.py`](file:///d:/AEGIS/agent/response_driver.py) to standardize on explicit response status codes: `SIMULATED`, `EXECUTED`, `FAILED`, `PARTIAL`, `NOT_FOUND`, and `DENIED`. Safe simulation mode (`AEGIS_RESPONSE_MODE=simulation`) is the guaranteed default. Real OS enforcement (`AEGIS_RESPONSE_MODE=real`) explicitly requires elevated OS privileges (Administrator/root) and returns `DENIED` or `NOT_FOUND` rather than misleading success codes.

### 3.6 P1 — Model Isolation: Windows v3 Shadow Mode
- **Finding (MOD-01): Experimental Model Fusion Isolation.** An experimental Windows v3 model candidate was under evaluation alongside production models.
- **Remediation:** Verified and enforced that `windows_v3` is strictly excluded from `ThreatFusionEngine.ACTIVE_FUSION_KEYS` (`agent/fusion_engine.py`). It operates purely in shadow mode for telemetry evaluation, guaranteeing zero influence on live consensus threat scores or autonomous mitigation triggers.

---

## 4. Verification Test Matrix

All hardened components were verified using pytest on Python 3.11.9. 

### 4.1 New Hardening Test Suite (`tests/test_security_and_consensus_hardening.py`)

| Test Name | Category | Objective | Result |
| :--- | :--- | :--- | :--- |
| `test_invalid_signature_rejected` | Crypto Identity | Tampered payload fails Ed25519 verification | **PASSED** |
| `test_forged_peer_identity_rejected` | Crypto Identity | Mismatched public key / sender ID rejected | **PASSED** |
| `test_replayed_p2p_message_rejected` | Anti-Replay | Duplicate nonce rejected via LRU cache | **PASSED** |
| `test_stale_p2p_message_rejected` | Anti-Replay | Message with expired timestamp rejected | **PASSED** |
| `test_duplicate_vote_response_from_same_peer_deduplicated` | Quorum Correctness | Peer sending multiple votes for same vote_id counted once | **PASSED** |
| `test_unknown_peer_dynamic_discovery_behavior` | P2P Identity | Verifies dynamic key discovery and signature check | **PASSED** |
| `test_bounded_inputs_threat_score` | Input Validation | `threat_score` outside [0, 1] rejected | **PASSED** |
| `test_bounded_inputs_confidence` | Input Validation | `confidence` outside [0, 1] rejected | **PASSED** |
| `test_bounded_inputs_trust_score` | Input Validation | `peer_trust_score` outside [0, 1] rejected | **PASSED** |
| `test_quorum_1_peer_out_of_5` | Quorum Ladder | 1/5 peers -> `NO_QUORUM`, safe fallback | **PASSED** |
| `test_quorum_2_peers_out_of_5` | Quorum Ladder | 2/5 peers -> `NO_QUORUM`, safe fallback | **PASSED** |
| `test_quorum_3_peers_out_of_5` | Quorum Ladder | 3/5 peers -> `CONSENSUS_REACHED` (majority) | **PASSED** |
| `test_quorum_4_peers_out_of_5` | Quorum Ladder | 4/5 peers -> `CONSENSUS_REACHED` (super-majority) | **PASSED** |
| `test_quorum_5_peers_out_of_5` | Quorum Ladder | 5/5 peers -> `CONSENSUS_REACHED` (unanimous) | **PASSED** |
| `test_unauthorized_api_call_without_token` | RBAC Security | Sensitive endpoints reject missing token (HTTP 401) | **PASSED** |
| `test_unauthorized_trust_feedback_non_admin` | RBAC Security | Non-admin token rejected on trust feedback (HTTP 403) | **PASSED** |
| `test_unauthorized_maintenance_schedule_non_admin` | RBAC Security | Non-admin token rejected on maintenance (HTTP 403) | **PASSED** |
| `test_unauthorized_action_enqueue_invalid_token` | RBAC Security | Invalid bearer token on action enqueue rejected (HTTP 401) | **PASSED** |
| `test_wrong_agent_action_ack_rejected` | State Guardrails | Agent acknowledging another agent's action rejected (HTTP 403) | **PASSED** |
| `test_duplicate_action_ack_rejected` | State Guardrails | Duplicate ACK on terminal action rejected (HTTP 409) | **PASSED** |
| `test_heartbeat_clock_skew_rejected` | Input Validation | Heartbeat with excessive clock skew rejected (HTTP 400) | **PASSED** |
| `test_simulated_response_status` | Response Precision | Simulation mode returns `SIMULATED` status | **PASSED** |
| `test_real_response_failure_status` | Response Precision | Real mode on non-existent PID returns `NOT_FOUND` / `FAILED` | **PASSED** |
| `test_windows_v3_shadow_isolation` | Model Isolation | `windows_v3` strictly excluded from `ACTIVE_FUSION_KEYS` | **PASSED** |
| `test_collector_health_visibility` | Observability | Registry accurately transitions `IDLE` -> `HEALTHY` -> `DEGRADED` | **PASSED** |

### 4.2 Full System Regression Run
```text
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.1.1, pluggy-1.6.0
rootdir: D:\AEGIS
plugins: anyio-4.13.0
collected 293 items

=========== 285 passed, 8 skipped, 88 warnings in 209.37s (0:03:29) ===========
```

---

## 5. Security Recommendations for Future Iterations

1. **Mutual TLS (mTLS) for Wire Mesh:** While Ed25519 message signatures ensure data authenticity and integrity at the application layer, transport-layer mTLS on ZeroMQ / UDP wire sockets will provide confidentiality against passive eavesdroppers.
2. **Hardware Security Module (HSM) / TPM Key Storage:** On production Linux/Windows endpoints, store agent private keys within the TPM (Trusted Platform Module) rather than local filesystem keyrings.
3. **Automated Signature Key Rotation:** Implement periodic asymmetric key rollover with signed revocation receipts broadcast to the peer swarm.
