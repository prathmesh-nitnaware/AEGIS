# AEGIS Progress Checklist

**Summary:**
- **Layer 1 — EDR Agent (Models, Fusion, Collectors, Heartbeat, Confidence & Trust Engine):** 50 / 50 items complete (100.0%)
- **Layer 2 — Peer Voting Protocol:** 4 / 4 items complete (100.0%) — *Phase 2 Complete*
- **Layer 3 — Command Node + Dashboard:** 6 / 6 items complete (100.0%) — *Centralized Telemetry, Voting Hub, Active Response & Maintenance Portal Complete*
- **Cross-cutting:** 3 / 3 items complete (100.0%) — *169/169 Pytest tests passing + conftest.py root path fix*
- **Phase A — NeonDB Persistence Layer:** 9 / 9 items complete (100.0%) — *All 7 tables created, all write paths wired*
- **Phase B — Response Driver Hardening:** 2 / 2 items complete (100.0%) — *Real firewall commands, real unisolate*
- **Phase C — Trust Feedback Loop:** 3 / 3 items complete (100.0%) — *POST /api/trust/feedback wired*
- **Overall Completion:** 77 / 77 items complete (100.0%)

---

## Layer 1 — EDR Agent

### 1a. Model training (per model)

#### Linux IDS (`linux_ids`)
- [x] Model trained and serialized (`trained_models/linux_ids/linux_xgboost_model.pkl`, `XGBClassifier` via `joblib.load`; trained via `ml_notebooks/linux_ids/Linux_XGBoost.ipynb`)
- [x] Label encoder artifact present (`trained_models/linux_ids/linux_label_encoder.pkl` — 7 classes: `Adduser`, `Hydra_FTP`, `Hydra_SSH`, `Java_Meterpreter`, `Meterpreter`, `Normal`, `Web_Shell`)
- [x] Label mapping verified correct (`agent/diagnostics/check_linux_label_mapping.py` — real samples)
- [x] Usable threat score achievable (`1 - P(Normal)`, dynamic index lookup of "Normal" class)

#### Windows Advanced v3 (`windows_advanced_v3`)
- [x] Model trained and serialized (`trained_models/windows_advanced_v3/windows_advanced_v3.pkl`, `XGBClassifier`; verified against Windows event context)
- [x] Token & label encoder artifacts present and verified
- [x] Label mapping verified correct (`tests/test_windows_advanced_v3_model.py` and `tests/test_windows_advanced_v3_remediation.py`)
- [x] Usable threat score achievable (`P(malicious)` / supervised attack classification integrated into `fusion_engine.py`)

#### CICIDS Network (`cicids`)
- [x] Model trained and serialized (`trained_models/cicids/aegis_lgbm_cicids_model.pkl`, dict export containing LightGBM model; trained via `ml_notebooks/cicids/cicids_training.ipynb`)
- [x] Label encoder + feature list present (embedded inside the dict export)
- [x] Label mapping verified (`agent/diagnostics/check_cicids_label_mapping.py` — found and fixed integer-label serialization)
- [x] Usable threat score achievable (`1 - P(BENIGN)`, dynamic index lookup of "BENIGN" class)

#### EMBER File Model (`ember`)
- [x] Model trained and serialized (`trained_models/ember/aegis_ember_model_full.pkl`, dict export containing LightGBM model; trained via `ml_notebooks/ember/ember.ipynb`)
- [x] Feature list present (embedded inside the dict export)
- [x] Label mapping verified correct (`agent/diagnostics/check_ember_label_mapping.py` — 6/6 PASS on real samples)
- [x] Usable threat score achievable (`P(malicious)`, class index 1)

#### HDFS Log Anomaly (`hdfs`)
- [x] Model trained and serialized (`trained_models/hdfs/hdfs_xgboost_model.pkl`, `XGBClassifier`; trained via `ml_notebooks/hdfs/HDFS_Anomaly_Detection.ipynb`)
- [x] Vectorizer + label encoder present (`hdfs_vectorizer.pkl` — 5000-dim TF-IDF; `hdfs_label_encoder.pkl`)
- [x] Label mapping verified correct (`agent/diagnostics/check_hdfs_label_mapping.py` — verified label mapping)
- [x] Usable threat score achievable (`P(Anomaly)`, dynamic index lookup)

#### Zero-Day Anomaly (`zero_day`)
- [x] Model trained and serialized (`trained_models/zero_day/aegis_zero_day_model.pkl`, `IsolationForest`; trained via `ml_notebooks/Zero_day/ZeroDay_Detection.ipynb`)
- [x] Three categorical encoders present (`event_encoder.pkl`, `process_encoder.pkl`, `user_encoder.pkl`)
- [x] Label mapping verified (`tests/test_zero_semantics_and_precision.py` and `tests/test_zero_day_model.py`)
- [x] Usable threat score achievable (`1 - sigmoid(decision_function)`)

---

### 1b. Fusion adapter (`agent/fusion_engine.py`)
- [x] `ThreatFusionEngine` class with scoring methods for all 6 models (`_score_linux`, `_score_windows`, `score_network_flow`, `score_file`, `score_log_line`, `score_windows_event`)
- [x] `fuse()` implemented — configurable per-model weights, normalized by ratio, graceful degradation for missing/`None` sub-scores
- [x] `get_verdict()` implemented — `<0.30` LOW, `<0.60` MEDIUM, `<0.80` HIGH, `>=0.80` CRITICAL
- [x] Multi-model validity guards implemented (`_linux_labels_valid`, `_windows_labels_valid`, `_hdfs_labels_valid`, `_ember_labels_valid`, `_cicids_labels_valid`, `_zeroday_labels_valid`)
- [x] Integrated with `ConfidenceEngine` for dynamically scaling fusion weight based on model reliability

---

### 1c. Live telemetry collectors
- [x] **Linux IDS (`linux_collector.py`):** Syscall sequence buffer, formatting 500 integer sequences for `score_process_event()`
- [x] **Windows Advanced (`windows_process_context.py`):** Windows event telemetry, process tree inspection, registry and privilege monitoring
- [x] **CICIDS Network (`scapy_flow_collector.py`):** Live network flow feature extraction via Scapy, matching CICIDS 78-feature schema
- [x] **EMBER File Model (`ember_features.py`):** PE binary parsing and feature extraction using LIEF for execution/write events
- [x] **HDFS Log Anomaly (`generate_hdfs_samples.py` & live log reader):** Log telemetry capture and TF-IDF vectorization
- [x] **Zero-Day Anomaly (`live_collectors.py`):** Event ID, process name, user context, and IP event telemetry collector
- [x] **Orchestration Agent (`agent/run_all.py` & `agent/run_live_telemetry_analysis.py`):** Unified cross-platform runner auto-detecting host OS and streaming fused threat metrics

---

### 1d. Heartbeat mechanism (`agent/heartbeat.py` & `agent/heartbeat_runner.py`)
- [x] `HeartbeatEmitter` implemented — background thread, 5s default interval (AEGIS spec), payload = `agent_id`, `status`, `cpu`, `timestamp`, `degraded` state detection
- [x] `SilenceDetector` implemented — 15s default silence threshold (AEGIS spec), thread-safe multi-agent tracking, alarm suppression/re-arm on recovery

---

### 1e. Confidence & Trust engine (`agent/confidence_engine.py`)
- [x] `ConfidenceResult` dataclass implemented (`confidence`, `completeness_factor`, `agreement_factor`, `models_fired`, `models_expected`, `models_missing`)
- [x] `compute_confidence()` implemented — completeness factor × agreement factor, single-model fallback constant (0.6)
- [x] Per-model reliability weights configured (`ember` 1.0, `hdfs`/`linux`/`cicids` 0.9, `windows_advanced_v3` 0.95, `zero_day` 0.7)
- [x] Auto-sync with `ThreatFusionEngine` validity flags
- [x] `AgentTrustTracker` implemented — per-agent running trust score via exponential moving average, persisted to SQLite (`agent_trust` table: `agent_id`, `trust_score`, `total_events`, `correct_events`, `last_updated`)

---

## Layer 2 — Peer Voting Protocol (Phase 2 Complete)
- [x] VotingRequest broadcast implemented (UDP Sockets / REST P2P mesh messaging via `agent/p2p_mesh.py`)
- [x] Peer correlation-check logic implemented (`PeerCorrelationEngine` verifying network, process, and file signals)
- [x] Weighted vote calculation implemented (`WeightedConsensusAggregator` with 2.0x / 1.0x / 0.5x / 0.3x multipliers per spec)
- [x] Tested with 2+ agents on separate processes/machines in P2P mesh network (`tests/test_p2p_mesh.py`)

---

## Layer 3 — Command Node + Dashboard

- [x] FastAPI backend scaffolded (`backend/main.py`)
- [x] SQLite schema defined & integrated (`agent_trust` table and telemetry storage)
- [x] WebSocket live telemetry streaming endpoint (`ws://127.0.0.1:8000/ws/telemetry` via `backend/telemetry_api.py`)
- [x] React + Vite real-time security dashboard (`dashboard/`) with live threat feed, score gauge, agent health, and incident log
- [x] Verdict aggregation & response action dispatch (`LOG`, `ALERT`, `KILL_PROCESS`, `ISOLATE_HOST`) (`backend/command_node.py` & `/api/centralized/vote`)
- [x] Admin Trust System, Maintenance Window Portal & Active Response Enforcement (`agent/admin_trust.py`, `agent/response_driver.py` & `/api/maintenance/*`)

---

## Phase A — NeonDB Persistence Layer (NEW — Complete)
- [x] `asyncpg`, `sqlalchemy[asyncio]`, `aiosqlite`, `python-dotenv` installed
- [x] `backend/db/database.py` — async engine reading `DATABASE_URL` from `.env`, SSL normalisation for NeonDB, SQLite fallback
- [x] `backend/db/models.py` — 7 ORM tables: `TelemetryEvent`, `ModelDetection`, `ConsensusVerdict`, `SilenceAlarm`, `AgentTrust`, `MaintenanceWindowRecord`, `AuditLogEntry`
- [x] `backend/db/repository.py` — async CRUD helpers for all 7 tables, compatible with both PostgreSQL and SQLite
- [x] `.env` with NeonDB `DATABASE_URL` (gitignored), `AGENT_ID`, `COMMAND_NODE_URL`
- [x] `POST /api/telemetry` → persists `TelemetryEvent` to NeonDB on every call
- [x] `POST /api/centralized/vote` → persists `ConsensusVerdict` to NeonDB
- [x] `SilenceDetector` alarm → persists `SilenceAlarm` via background coroutine
- [x] `MaintenanceWindowPortal` → persists to `maintenance_windows` table; restored from DB on server startup (survives restart)

## Phase B — Response Driver Hardening (NEW — Complete)
- [x] `isolate_host()` — Windows: actually executes `netsh advfirewall` rules (`AEGIS_AllowCN` + `AEGIS_BlockAll`); CN IP bypass correctly applied
- [x] `isolate_host()` — Linux: actually executes `iptables -I OUTPUT` rules with ESTABLISHED/RELATED allow + CN allowlist + DROP all
- [x] `unisolate_host()` — Windows: deletes named rules (`AEGIS_BlockAll`, `AEGIS_AllowCN`) by name; Linux: removes specific OUTPUT chain rules
- [x] Both methods fall back to `simulated_success` when running without admin privileges (preserves test compatibility)

## Phase C — Trust Feedback Loop (NEW — Complete)
- [x] `POST /api/trust/feedback` endpoint — admin confirms/denies verdicts by `vote_id`
- [x] Updates `ConsensusVerdict.admin_confirmed` in NeonDB
- [x] Updates central `AgentTrust` EMA in NeonDB via `upsert_agent_trust()`
- [x] Also calls `local_trust_tracker.record_outcome()` to keep local SQLite in sync
- [x] `GET /api/agents/{agent_id}/trust` — returns trust score with NeonDB→SQLite fallback
- [x] `GET /api/agents/trust/all` — all agent trust scores from NeonDB
- [x] `GET /api/alerts` — active unacknowledged silence alarms from NeonDB
- [x] `POST /api/alerts/{id}/ack` — acknowledge alarm with admin name
- [x] `GET /api/audit` — paginated audit log from NeonDB
- [x] `GET /api/centralized/verdicts` now paginated (limit + offset) with NeonDB source, in-memory fallback
- [x] `GET /api/centralized/telemetry` now paginated with NeonDB source, in-memory fallback

---

## Cross-cutting
- [x] `progress_status.md` and repository documentation reconciled with current state
- [x] Pytest test suite fully passing (169 passed test cases across all model, P2P mesh, centralized server, and response components)
- [x] `conftest.py` added at project root — ensures `agent.*` and `backend.*` imports resolve correctly in all pytest runs

---

## Roadmap & Upcoming Phased Build Plan
- **Phase A (COMPLETE):** NeonDB persistence layer — all 7 tables, all write paths wired.
- **Phase B (COMPLETE):** `isolate_host()` / `unisolate_host()` — real firewall commands.
- **Phase C (COMPLETE):** Trust feedback loop — `POST /api/trust/feedback` wired end-to-end.
- **Phase D (COMPLETE):** Dashboard UI — Global Silence Alarm banner with instant acknowledge action, Consensus Verdicts NeonDB table with "Confirm Threat" and "False Positive" trust calibration buttons, Maintenance Window management portal with dual-approval scheduling and cancellation, Fleet Health & NeonDB Trust Meter (EMA) visualization, and Mitigation Audit Trail.
- **Phase 5 (COMPLETE):** Multi-node attack simulation suite (`experiments/simulations/` with Linux Hydra/Meterpreter attacks, Windows Ransomware/PE dropper, adversary silence sabotage, and master runner `run_multi_node_demo.py`).
- **Graceful Shutdown & Heartbeat Lifecycle (COMPLETE):** OS shutdown hooks (Windows `win32api.SetConsoleCtrlHandler` & Linux `SIGTERM`), emergency synchronous Last-Gasp goodbye beacon (`POST /api/heartbeat/shutdown`), `OFFLINE_GRACEFUL` state, silence alarm suppression, and automatic reconnection on boot.


---

## Layer 1 — EDR Agent

### 1a. Model training (per model)

#### Linux IDS (`linux_ids`)
- [x] Model trained and serialized (`trained_models/linux_ids/linux_xgboost_model.pkl`, `XGBClassifier` via `joblib.load`; trained via `ml_notebooks/linux_ids/Linux_XGBoost.ipynb`)
- [x] Label encoder artifact present (`trained_models/linux_ids/linux_label_encoder.pkl` — 7 classes: `Adduser`, `Hydra_FTP`, `Hydra_SSH`, `Java_Meterpreter`, `Meterpreter`, `Normal`, `Web_Shell`)
- [x] Label mapping verified correct (`agent/diagnostics/check_linux_label_mapping.py` — real samples)
- [x] Usable threat score achievable (`1 - P(Normal)`, dynamic index lookup of "Normal" class)

#### Windows Advanced v3 (`windows_advanced_v3`)
- [x] Model trained and serialized (`trained_models/windows_advanced_v3/windows_advanced_v3.pkl`, `XGBClassifier`; verified against Windows event context)
- [x] Token & label encoder artifacts present and verified
- [x] Label mapping verified correct (`tests/test_windows_advanced_v3_model.py` and `tests/test_windows_advanced_v3_remediation.py`)
- [x] Usable threat score achievable (`P(malicious)` / supervised attack classification integrated into `fusion_engine.py`)

#### CICIDS Network (`cicids`)
- [x] Model trained and serialized (`trained_models/cicids/aegis_lgbm_cicids_model.pkl`, dict export containing LightGBM model; trained via `ml_notebooks/cicids/cicids_training.ipynb`)
- [x] Label encoder + feature list present (embedded inside the dict export)
- [x] Label mapping verified (`agent/diagnostics/check_cicids_label_mapping.py` — found and fixed integer-label serialization)
- [x] Usable threat score achievable (`1 - P(BENIGN)`, dynamic index lookup of "BENIGN" class)

#### EMBER File Model (`ember`)
- [x] Model trained and serialized (`trained_models/ember/aegis_ember_model_full.pkl`, dict export containing LightGBM model; trained via `ml_notebooks/ember/ember.ipynb`)
- [x] Feature list present (embedded inside the dict export)
- [x] Label mapping verified correct (`agent/diagnostics/check_ember_label_mapping.py` — 6/6 PASS on real samples)
- [x] Usable threat score achievable (`P(malicious)`, class index 1)

#### HDFS Log Anomaly (`hdfs`)
- [x] Model trained and serialized (`trained_models/hdfs/hdfs_xgboost_model.pkl`, `XGBClassifier`; trained via `ml_notebooks/hdfs/HDFS_Anomaly_Detection.ipynb`)
- [x] Vectorizer + label encoder present (`hdfs_vectorizer.pkl` — 5000-dim TF-IDF; `hdfs_label_encoder.pkl`)
- [x] Label mapping verified correct (`agent/diagnostics/check_hdfs_label_mapping.py` — verified label mapping)
- [x] Usable threat score achievable (`P(Anomaly)`, dynamic index lookup)

#### Zero-Day Anomaly (`zero_day`)
- [x] Model trained and serialized (`trained_models/zero_day/aegis_zero_day_model.pkl`, `IsolationForest`; trained via `ml_notebooks/Zero_day/ZeroDay_Detection.ipynb`)
- [x] Three categorical encoders present (`event_encoder.pkl`, `process_encoder.pkl`, `user_encoder.pkl`)
- [x] Label mapping verified (`tests/test_zero_semantics_and_precision.py` and `tests/test_zero_day_model.py`)
- [x] Usable threat score achievable (`1 - sigmoid(decision_function)`)

---

### 1b. Fusion adapter (`agent/fusion_engine.py`)
- [x] `ThreatFusionEngine` class with scoring methods for all 6 models (`_score_linux`, `_score_windows`, `score_network_flow`, `score_file`, `score_log_line`, `score_windows_event`)
- [x] `fuse()` implemented — configurable per-model weights, normalized by ratio, graceful degradation for missing/`None` sub-scores
- [x] `get_verdict()` implemented — `<0.30` LOW, `<0.60` MEDIUM, `<0.80` HIGH, `>=0.80` CRITICAL
- [x] Multi-model validity guards implemented (`_linux_labels_valid`, `_windows_labels_valid`, `_hdfs_labels_valid`, `_ember_labels_valid`, `_cicids_labels_valid`, `_zeroday_labels_valid`)
- [x] Integrated with `ConfidenceEngine` for dynamically scaling fusion weight based on model reliability

---

### 1c. Live telemetry collectors
- [x] **Linux IDS (`linux_collector.py`):** Syscall sequence buffer, formatting 500 integer sequences for `score_process_event()`
- [x] **Windows Advanced (`windows_process_context.py`):** Windows event telemetry, process tree inspection, registry and privilege monitoring
- [x] **CICIDS Network (`scapy_flow_collector.py`):** Live network flow feature extraction via Scapy, matching CICIDS 78-feature schema
- [x] **EMBER File Model (`ember_features.py`):** PE binary parsing and feature extraction using LIEF for execution/write events
- [x] **HDFS Log Anomaly (`generate_hdfs_samples.py` & live log reader):** Log telemetry capture and TF-IDF vectorization
- [x] **Zero-Day Anomaly (`live_collectors.py`):** Event ID, process name, user context, and IP event telemetry collector
- [x] **Orchestration Agent (`agent/run_all.py` & `agent/run_live_telemetry_analysis.py`):** Unified cross-platform runner auto-detecting host OS and streaming fused threat metrics

---

### 1d. Heartbeat mechanism (`agent/heartbeat.py` & `agent/heartbeat_runner.py`)
- [x] `HeartbeatEmitter` implemented — background thread, 5s default interval (AEGIS spec), payload = `agent_id`, `status`, `cpu`, `timestamp`, `degraded` state detection
- [x] `SilenceDetector` implemented — 15s default silence threshold (AEGIS spec), thread-safe multi-agent tracking, alarm suppression/re-arm on recovery

---

### 1e. Confidence & Trust engine (`agent/confidence_engine.py`)
- [x] `ConfidenceResult` dataclass implemented (`confidence`, `completeness_factor`, `agreement_factor`, `models_fired`, `models_expected`, `models_missing`)
- [x] `compute_confidence()` implemented — completeness factor × agreement factor, single-model fallback constant (0.6)
- [x] Per-model reliability weights configured (`ember` 1.0, `hdfs`/`linux`/`cicids` 0.9, `windows_advanced_v3` 0.95, `zero_day` 0.7)
- [x] Auto-sync with `ThreatFusionEngine` validity flags
- [x] `AgentTrustTracker` implemented — per-agent running trust score via exponential moving average, persisted to SQLite (`agent_trust` table: `agent_id`, `trust_score`, `total_events`, `correct_events`, `last_updated`)

---

## Layer 2 — Peer Voting Protocol (Phase 2 Complete)
- [x] VotingRequest broadcast implemented (UDP Sockets / REST P2P mesh messaging via `agent/p2p_mesh.py`)
- [x] Peer correlation-check logic implemented (`PeerCorrelationEngine` verifying network, process, and file signals)
- [x] Weighted vote calculation implemented (`WeightedConsensusAggregator` with 2.0x / 1.0x / 0.5x / 0.3x multipliers per spec)
- [x] Tested with 2+ agents on separate processes/machines in P2P mesh network (`tests/test_p2p_mesh.py`)

---

## Layer 3 — Command Node + Dashboard

- [x] FastAPI backend scaffolded (`backend/main.py`)
- [x] SQLite schema defined & integrated (`agent_trust` table and telemetry storage)
- [x] WebSocket live telemetry streaming endpoint (`ws://127.0.0.1:8000/ws/telemetry` via `backend/telemetry_api.py`)
- [x] React + Vite real-time security dashboard (`dashboard/`) with live threat feed, score gauge, agent health, and incident log
- [x] Verdict aggregation & response action dispatch (`LOG`, `ALERT`, `KILL_PROCESS`, `ISOLATE_HOST`) (`backend/command_node.py` & `/api/centralized/vote`)
- [x] Admin Trust System, Maintenance Window Portal & Active Response Enforcement (`agent/admin_trust.py`, `agent/response_driver.py` & `/api/maintenance/*`)

---

## Cross-cutting
- [x] `progress_status.md` and repository documentation reconciled with current state
- [x] Pytest test suite fully passing (169 passed test cases across all model, P2P mesh, centralized server, and response components)

---

## Roadmap & Upcoming Phased Build Plan
- **Phase 1 (COMPLETE):** Single agent EDR telemetry collectors, 6 ML models, Threat Fusion Engine, Confidence Engine, SQLite Trust Tracker, FastAPI Backend, React Dashboard.
- **Phase 2 (UPCOMING):** P2P consensus voting network over ZeroMQ/UDP sockets, peer signal correlation, silence-as-alarm mesh verification.
- **Phase 3 (UPCOMING):** Command Node automated verdict aggregation & response action dispatch (`KILL_PROCESS`, `ISOLATE_HOST`, `QUARANTINE_FILE`).
- **Phase 4 (UPCOMING):** Admin Trust System (Identity context, behavioral sequence analysis, dual-approval maintenance windows).
- **Phase 5 (UPCOMING):** Multi-node VM attack simulations (VirtualBox, Wireshark, live ransomware & malware testing, benchmark evaluation).