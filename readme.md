# Project AEGIS
**Adaptive Edge Guardian with Intelligence Swarm**  
*Distributed Endpoint Detection & Response (EDR) with Peer‑Consensus Voting*

---

## 🚀 Overview
Project AEGIS is a **distributed EDR system** that integrates **machine learning** with a **peer‑consensus voting protocol** to detect, evaluate, and respond to threats across a local network. Unlike conventional EDR tools that operate in isolation, AEGIS treats every node as both a **sensor** and a **voter**, building a **collective intelligence layer** over the network.

Inspired by biological immune systems, AEGIS ensures that **no single agent makes a high‑severity decision alone** — every critical action requires peer agreement.

---

## 🧠 Core Philosophy
- **Single agent weakness:** A lone EDR agent can be silenced or overloaded.  
- **Collective resilience:** A network of agents verifying each other’s signals is harder to compromise.  
- **Biological analogy:** Just like white blood cells coordinate with the immune system, AEGIS agents coordinate across the LAN.  

---

## 🏗️ System Architecture
AEGIS is built across **three layers**:

| Layer | Component       | Responsibility |
|-------|----------------|----------------|
| 1     | **EDR Agent**  | Collects telemetry, runs ML models, detects anomalies, casts votes, executes response actions |
| 2     | **Voting Protocol** | Peer‑to‑peer broadcast system for signals, correlation, and weighted votes |
| 3     | **Command Node** | Aggregates votes, computes verdicts, issues responses, stores events, serves dashboard |

---

## 🔍 Layer 1 – EDR Agent
- **Telemetry Collection:** Process monitoring, file events, network connections, resource usage, logs, registry changes.  
- **ML Detection Pipeline:**  
  - *Isolation Forest* (unsupervised, zero‑day detection)  
  - *Random Forest* (supervised, CICIDS + EMBER datasets, low false positives)  
- **Hybrid Threat Score:** Weighted blend of anomaly + classification outputs.  

---

## 🗳️ Layer 2 – Peer Voting Protocol
- **Consensus before action:** Agents broadcast VotingRequests and peers respond.  
- **Weighted votes:** Correlated signals = higher weight; unreliable agents = lower weight.  
- **Severity thresholds:**  
  - Low → log only  
  - Medium → admin alert + deeper telemetry  
  - High → kill process + quarantine file  
  - Critical → full isolation + immediate alert  

---

## 🛡️ Challenge Solutions
### 1. Compromised Node Problem
- **Passive heartbeat detection:** Silence = alarm.  
- **Cross‑correlation:** Silence + peer anomalies = critical alert.  

### 2. Admin Misclassification
- **3‑Layer Trust System:**  
  - Identity context (trusted registry, hours, machine)  
  - Behavioural pattern analysis (human vs attacker sequences)  
  - Pre‑announced maintenance windows (dual approval, contextual suppression)  

---

## 📊 Layer 3 – Command Node & Dashboard
- **Responsibilities:** Heartbeat monitoring, vote aggregation, verdict computation, response dispatch, event persistence.  
- **Dashboard Panels:** Live threat feed, network vote map, incident timeline, agent health monitor, maintenance window portal, manual override.  

---

## 🛠️ Tech Stack
- **Python 3.10 – 3.14** (`.venv` virtual environment for agent and backend)
- **FastAPI + Uvicorn + WebSockets** (Command node, REST endpoints, live telemetry socket)
- **React + Vite** (Modern real-time dashboard UI on Node.js)
- **ML & Telemetry Engines**: `xgboost`, `lightgbm`, `scikit-learn`, `lief`, `scapy`, `watchdog`, `psutil`, `pywin32`

---

## ⚡ Quick Start & Setup

### 1. Install Python Dependencies
Ensure your virtual environment is active, then install all required libraries:
```bash
pip install -r requirements.txt
```

### 2. Launch Backend Telemetry Server (Terminal 1)
```bash
python backend/main.py
```
*Runs FastAPI on `http://127.0.0.1:8000` with WebSocket support at `ws://127.0.0.1:8000/ws/telemetry`.*

### 3. Launch Live Telemetry Agent (Terminal 2)
```bash
python agent/run_all.py
```
*Auto-detects host OS (Windows/Linux) and activates compatible threat collectors (Zero-Day, CICIDS, EMBER, HDFS, Windows Advanced/Sysmon, Linux IDS).*

### 4. Launch React Dashboard (Terminal 3)
```bash
cd dashboard
npm install
npm run dev
```
*Opens the real-time security overview at `http://localhost:5173`.*

---

## ✨ Key Contributions
- Peer‑mesh consensus voting  
- Silence as alarm signal  
- Admin trust layers + maintenance windows  
- SHAP explainability in dashboard  
- Fully offline LAN‑local operation  
- Zero Trust alignment  

---

## 📅 Build Plan
- **Phase 1:** Single agent telemetry + ML  
- **Phase 2:** Voting protocol live  
- **Phase 3:** Full command node + responses  
- **Phase 4:** Admin trust system  
- **Phase 5:** Dashboard + malware testing  

---

## 🧪 Testing Strategy
- Safe VM environment (VirtualBox, Wireshark, MalwareBazaar samples)  
- Scenarios: ransomware, agent kill, admin bulk access, crypto miner  
- Metrics: Detection rate, false positives, MTTD, MTTR, heartbeat latency  

---

## 📖 Glossary
- **EDR:** Endpoint Detection & Response  
- **Byzantine Generals Problem:** Consensus with compromised nodes  
- **LOLBins:** Legitimate binaries abused by attackers  
- **Zero Trust:** No implicit trust, context‑based verification  
- **SHAP Values:** Explainable ML predictions  

---

## 🔗 Repository
GitHub: [AEGIS Project](https://github.com/prathmesh-nitnaware/AEGIS)

---
