# Project AEGIS – Progress State Report

**Adaptive Edge Guardian with Intelligence Swarm (AEGIS)**  
*Distributed EDR with Peer-Consensus Voting and ML Threat Fusion*

---

## 📅 Status Overview
- **Repository:** [AEGIS](https://github.com/prathmesh-nitnaware/AEGIS)
- **Current Phase:** **Phase 1 Complete (100%)** | **Phase 2 & 3 Foundations Active**
- **Test Suite Status:** **147 / 147 PASSING** (`pytest tests/`)
- **Primary Tech Stack:** Python 3.10–3.14 (FastAPI, Scapy, LIEF, XGBoost, LightGBM, scikit-learn), React + Vite (Node.js)

---

## ✅ Completed Components & Achievements

### 1. ML Threat Detection Suite (6 / 6 Models Trained & Verified)

| Dataset / Model | Algorithm | Purpose & Detection Focus | Artifact Location | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Linux IDS** | XGBoost | Linux process execution & privilege escalation (Adduser, Hydra, Meterpreter, Web Shell) | `trained_models/linux_ids/` | **COMPLETE & VERIFIED** |
| **Windows Advanced v3** | XGBoost | Windows persistent attack vectors, registry tampering, and process context | `trained_models/windows_advanced_v3/` | **COMPLETE & VERIFIED** |
| **CICIDS Network** | LightGBM | Network flow intrusion detection (DoS, DDoS, Brute Force, PortScan, Botnet) | `trained_models/cicids/` | **COMPLETE & VERIFIED** |
| **EMBER PE Binary** | LightGBM | Executable file payload inspection, PE header features, section entropy | `trained_models/ember/` | **COMPLETE & VERIFIED** |
| **HDFS Logs** | XGBoost + TF-IDF | Big-data log sequence anomaly detection, bulk file/ransomware behavior | `trained_models/hdfs/` | **COMPLETE & VERIFIED** |
| **Zero-Day Anomaly** | Isolation Forest | Unsupervised anomaly detection for unknown process/event telemetry | `trained_models/zero_day/` | **COMPLETE & VERIFIED** |

---

### 2. Threat Fusion & Confidence Engines

- **Threat Fusion Engine (`agent/fusion_engine.py`)**:
  - Blends predictions across all 6 ML engines into a normalized 0.0–1.0 Threat Score.
  - Dynamically enforces model validity guards (e.g., label verification) to skip invalid models cleanly.
  - Generates 4-tier security verdicts: `LOW` (<0.30), `MEDIUM` (<0.60), `HIGH` (<0.80), `CRITICAL` (≥0.80).

- **Confidence Engine (`agent/confidence_engine.py`)**:
  - Calculates event confidence based on completeness factor (coverage of expected telemetry) × agreement factor (variance across active models).
  - Single-model fallback strategy avoids over-trusting isolated detections.
  - Includes **`AgentTrustTracker`**: SQLite-backed reputation tracker tracking running agent trust using exponential moving averages.

---

### 3. Live Telemetry Collectors & Agent Orchestration

- **`scapy_flow_collector.py`**: Sniffs network interface packets in real-time, aggregates network flows, and computes 78 CICIDS-compatible flow features.
- **`ember_features.py`**: Extract PE file structural header features on file write/execution events using LIEF.
- **`windows_process_context.py`**: Interrogates Windows process creation, parent-child relationships, command-line arguments, and privilege tokens.
- **`linux_collector.py`**: Buffers live Linux system call events into exact 500-integer vectors.
- **`live_collectors.py`**: Discrete telemetry collector for process events, user context, and network socket activity.
- **`agent/run_all.py`**: Cross-platform unified entry point auto-detecting OS environment (Windows vs. Linux) and executing active telemetry collectors.
- **`agent/heartbeat.py`**: Emits agent heartbeat frames every 5s with CPU metrics, while `SilenceDetector` tracks missing heartbeats (>15s threshold) for silence-as-alarm detection.

---

### 4. Backend API & Command Node

- **FastAPI Telemetry Server (`backend/main.py` & `backend/telemetry_api.py`)**:
  - Ingestion endpoints for live telemetry signals and agent registration.
  - **WebSocket Live Stream (`ws://127.0.0.1:8000/ws/telemetry`)**: Broadcasts real-time threat scores, model sub-scores, confidence metrics, and heartbeats directly to connected clients.
  - SQLite persistence layer for event history and agent trust metrics.

---

### 5. Real-Time React Security Dashboard

- **Frontend Application (`dashboard/`)**:
  - Built with React + Vite.
  - Features real-time WebSocket connection to Command Node.
  - Displays live threat score gauges, interactive telemetry event feed, model sub-score breakdown, agent health monitor, and incident log.

---

### 6. Automated Testing Suite

- **147 Pytest Test Cases (`tests/`)**:
  - `test_cicids_model.py`: Model deserialization, feature mapping, float output validation.
  - `test_ember_model.py`: PE feature extraction, scoring accuracy.
  - `test_hdfs_model.py`: TF-IDF vectorization, anomaly score bounds.
  - `test_linux_ids.py`: Syscall buffer formatting, 7-class multiclass scoring.
  - `test_windows_advanced_v3_...`: Token encoding, model inference, remediation mapping.
  - `test_zero_day_model.py` & `test_zero_semantics_and_precision.py`: Isolation Forest decision score transformation, precision bounds.

---

## 🚀 Upcoming Roadmap & Phased Execution

### Phase 2: Peer-to-Peer Consensus Voting Protocol (Upcoming)
- **Goal:** Enable multi-agent peer voting across local network nodes.
- **Key Deliverables:**
  - Implement `VotingRequest` and `VotingResponse` P2P broadcast messaging (ZeroMQ / UDP sockets).
  - Implement peer correlation check (verify if neighboring nodes observe correlated anomaly signals).
  - Apply weighted vote calculation per AEGIS specification (correlated signals = higher weight, unverified nodes = lower weight).
  - Multi-agent P2P integration testing across isolated processes.

### Phase 3: Automated Response Actions & Verdict Aggregation (Upcoming)
- **Goal:** Turn consensus verdicts into automated agent response actions.
- **Key Deliverables:**
  - Build response dispatch engine supporting 4 severity tiers:
    - **Low:** Event logging & local audit trail.
    - **Medium:** Administrative alert + elevated telemetry frequency.
    - **High:** Process termination (`KILL_PROCESS`) + file quarantine (`QUARANTINE_FILE`).
    - **Critical:** Network host isolation (`ISOLATE_HOST`) + immediate alert dispatch.

### Phase 4: Admin Trust System & Maintenance Window Portal (Upcoming)
- **Goal:** Eliminate false positives during legitimate administrative tasks.
- **Key Deliverables:**
  - **3-Layer Trust System**:
    1. *Identity Context:* Verify user SID, hour of operation, workstation identity.
    2. *Behavioral Analysis:* Differentiate administrative bulk actions from automated malware sequences.
    3. *Pre-Announced Maintenance Windows:* Admin dashboard portal supporting dual-approval suppression windows.

### Phase 5: Multi-Node VM Attack Simulations & Benchmark Evaluation (Upcoming)
- **Goal:** Evaluate AEGIS under realistic cyber attack scenarios in isolated network environments.
- **Key Deliverables:**
  - Provision 3-node host-only network in VirtualBox.
  - Execute attack scenarios: ransomware propagation, agent termination attempt, SSH brute-force attack, crypto-miner execution.
  - Measure performance metrics: Threat Detection Rate (TPR), False Positive Rate (FPR), Mean Time to Detect (MTTD), Mean Time to Respond (MTTR), Consensus Latency.

---

## 🔗 Repository
GitHub: [AEGIS Project Repository](https://github.com/prathmesh-nitnaware/AEGIS)
