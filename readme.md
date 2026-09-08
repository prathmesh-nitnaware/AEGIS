# Project AEGIS
**Adaptive Edge Guardian with Intelligence Swarm**  
*Distributed Endpoint Detection & Response (EDR) with Peer-Consensus Voting*

---

## 🚀 Overview
Project AEGIS is a **distributed EDR system** that integrates **machine learning threat fusion** with a **peer-consensus voting protocol** to detect, evaluate, and respond to threats across local networks. Unlike conventional isolated EDR tools, AEGIS treats every node as both a **sensor** and a **voter**, building a **collective intelligence layer** over the network.

Inspired by biological immune systems, AEGIS ensures that **no single agent makes high-severity response decisions alone** — every critical action requires peer agreement.

---

## 🧠 Core Architecture & Layers

AEGIS operates across **three primary layers**:

| Layer | Component | Description & Current Progress |
| :--- | :--- | :--- |
| **Layer 1** | **EDR Agent & ML Suite** | Live telemetry collectors, 6 serialized ML models (Linux IDS, Windows Advanced v3, CICIDS, EMBER, HDFS, Zero-Day), Threat Fusion Engine, Confidence & Trust Engine, Heartbeat Emitter |
| **Layer 2** | **Peer Voting Protocol** | Peer-to-peer broadcast system for signal correlation, silence-as-alarm detection, and weighted vote consensus *(Phase 2 Scope)* |
| **Layer 3** | **Command Node & Dashboard** | Telemetry ingestion server, FastAPI WebSocket broadcast stream (`/ws/telemetry`), SQLite event persistence, and React + Vite security dashboard |

---

## 🔬 Layer 1 – ML Threat Detection Suite

AEGIS combines **6 distinct ML detection engines** into a unified scoring pipeline:

1. **Linux IDS Engine (`linux_ids`)**: XGBoost classifier trained on syscall sequences (7 target classes including `Meterpreter`, `Hydra`, `Web_Shell`, `Adduser`).
2. **Windows Advanced Engine (`windows_advanced_v3`)**: XGBoost classifier detecting Windows process creation, token misuse, and registry persistence.
3. **CICIDS Network Intrusion Engine (`cicids`)**: LightGBM flow classifier analyzing live network traffic (DoS, DDoS, Brute Force, PortScan).
4. **EMBER File Payload Engine (`ember`)**: LightGBM binary classifier parsing PE file headers and section entropy via LIEF.
5. **HDFS Log Anomaly Engine (`hdfs`)**: XGBoost + TF-IDF log sequence analyzer catching ransomware and bulk file anomalies.
6. **Zero-Day Anomaly Engine (`zero_day`)**: Isolation Forest model detecting novel zero-day behavioral anomalies.

### Threat Fusion & Confidence Engine
- **Threat Fusion Engine (`agent/fusion_engine.py`)**: Blends sub-scores into a normalized 0.0–1.0 Threat Score and assigns 4-tier verdicts (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Confidence Engine (`agent/confidence_engine.py`)**: Evaluates completeness factor × agreement factor across active engines.
- **Agent Trust Tracker (`AgentTrustTracker`)**: SQLite-backed reputation system tracking agent historical accuracy using exponential moving averages.

---

## 🛠️ Tech Stack
- **Languages**: Python 3.10 – 3.14, JavaScript (ES6+), SQL (SQLite)
- **Backend & Telemetry Server**: FastAPI, Uvicorn, WebSockets
- **Dashboard UI**: React, Vite, Node.js
- **ML & Parsing Engines**: Scikit-Learn, LightGBM, XGBoost, Scapy, LIEF, Joblib
- **Testing**: Pytest (147 passing test cases)

---

## ⚡ Quick Start & Setup

### 1. Install Dependencies
Ensure your virtual environment is active:
```bash
pip install -r requirements.txt
```

### 2. Run Test Suite
Verify that all 147 test cases pass:
```bash
pytest tests/
```

### 3. Launch Command Node Telemetry Server (Terminal 1)
```bash
python backend/main.py
```
*Starts FastAPI server on `http://127.0.0.1:8000` with WebSocket endpoint at `ws://127.0.0.1:8000/ws/telemetry`.*

### 4. Launch Live Telemetry Agent (Terminal 2)
```bash
python agent/run_all.py
```
*Auto-detects host OS (Windows/Linux) and starts active collectors (Network Scapy flow, Windows process context, Linux syscalls, PE file analysis).*

### 5. Launch React Security Dashboard (Terminal 3)
```bash
cd dashboard
npm install
npm run dev
```
*Opens real-time security dashboard at `http://localhost:5173`.*

---

## 📅 Roadmap & Upcoming Milestones

- [x] **Phase 1: Single-Agent EDR & ML Suite (COMPLETE)**
  - 6 ML models trained, verified, and integrated into `ThreatFusionEngine`.
  - Live telemetry collectors for Linux, Windows, Network, Files, and Logs.
  - FastAPI server with WebSocket telemetry streaming.
  - React + Vite real-time security dashboard.
  - 147 Pytest test cases passing.

- [ ] **Phase 2: P2P Peer Consensus Voting Protocol (UPCOMING)**
  - ZeroMQ / UDP P2P broadcast for `VotingRequest` and `VotingResponse`.
  - Weighted peer vote calculation (correlation multiplier, distance, trust weights).
  - Silence-as-alarm mesh correlation across network nodes.

- [ ] **Phase 3: Automated Response Actions & Verdict Aggregation (UPCOMING)**
  - Automated remediation actions: `KILL_PROCESS`, `QUARANTINE_FILE`, `ISOLATE_HOST`.
  - Command Node SQLite verdict persistence & audit trail.

- [ ] **Phase 4: Admin Trust System & Maintenance Window Protocol (UPCOMING)**
  - 3-layer trust system (Identity Context, Behavioral Sequence Analysis, Maintenance Windows with dual approval).

- [ ] **Phase 5: Multi-Node VM Attack Simulation Suite (UPCOMING)**
  - 3-node VirtualBox VM network deployment.
  - Live malware attack simulations (ransomware, agent kill attempt, credential dumping).
  - Evaluation of TPR, FPR, MTTD, MTTR, and consensus latency metrics.

---

## 🔗 Repository
GitHub: [AEGIS Project Repository](https://github.com/prathmesh-nitnaware/AEGIS)
