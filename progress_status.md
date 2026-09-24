# Project AEGIS – Master Progress State Report

**Adaptive Edge Guardian with Intelligence Swarm (AEGIS)**  
*Distributed EDR with Peer-Consensus Voting, Explainable AI, Live PCAP Replayer, and Standalone Adversary C2*

---

## 📅 Status Overview
- **Repository:** [AEGIS](https://github.com/prathmesh-nitnaware/AEGIS)
- **Test Suite Status:** **285 Tests Passing** (8 skipped, 0 failing across 293 total tests via `pytest tests/`)
- **Primary Tech Stack:** Python 3.10–3.14 (FastAPI, Scapy, PyZMQ, XGBoost, LightGBM, PyTorch, ReportLab, Cryptography), React 19 + Vite 8, Docker & Docker Compose, NeonDB PostgreSQL + SQLite

---

## ✅ Completed Milestones & Subsystems

### 1. Dual-Dashboard Architecture
- **Blue Team SOC Defender Dashboard (`:5173`)**: 11 feature tabs covering Security Overview, Verdicts, Maintenance, Fleet Trust, Audit Logs, Processes, Detections, Models, MITRE ATT&CK, PCAP Replayer, System Benchmarks, and PDF Reports.
- **Red Team Adversary C2 Console (`:5174`)**: Standalone attack operations console for targeting specific chain systems (`vm1` through `vm4` or custom IPs), firing 7 tactical exploitation modules, and monitoring adversary kill-chains in real-time.

### 2. Multi-Model Threat Detection Suite (6 / 6 Models Trained & Verified)
- **Linux IDS (XGBoost)**: 7-class multiclass syscall anomaly detection (Hydra SSH/FTP, Java Meterpreter, Web Shell, Adduser).
- **Windows Advanced v3 (XGBoost)**: Persistent Windows attack vectors, registry tampering, and process context.
- **CICIDS Network Flow (LightGBM)**: Network flow intrusion detection (DoS, DDoS, Brute Force, PortScan, Botnet).
- **EMBER PE Binary (LightGBM)**: Portable Executable structural header inspection, section entropy, and API import analysis.
- **HDFS Logs (XGBoost + TF-IDF)**: Big-data distributed log sequence anomaly detection.
- **Zero-Day Anomaly (Isolation Forest & Autoencoder)**: Unsupervised anomaly detection on unfamiliar process telemetry.

### 3. Explainable AI (XAI) & SHAP Feature Attribution
- **`backend/services/xai_service.py`**: Computes SHAP feature attribution waterfalls, baseline deltas, and natural language SOC narratives.
- **`dashboard/src/XAIExplanationModal.jsx`**: Interactive modal drilldown from telemetry events, process table, and PCAP flows.

### 4. Live PCAP Network Packet Capture & Threat Flow Replayer
- **`backend/services/pcap_service.py`**: Real-time packet streaming via Scapy at `0.5x` to `10.0x` speeds.
- **`agent/scapy_flow_collector.py`**: Extracts 78-feature CICIDS bidirectional flow statistics dynamically.
- **Pre-provisioned sample captures**: `syn_flood_ddos.pcap`, `port_scan_recon.pcap`, `hydra_ssh_bruteforce.pcap`, `benign_web_traffic.pcap` + custom `.pcap` upload support.

### 5. Automated Performance & Latency Benchmark Suite
- **`experiments/benchmarks/benchmark_suite.py`**: High-resolution latency profiling across 4,800 sample cycles.
- **Key KPIs**: MTTD = 0.070 ms, MTTR = 0.686 ms, Byzantine Quorum Latency = 0.609 ms, Peak Throughput = 26,641 ev/s.
- **`dashboard/src/BenchmarkTab.jsx`**: Visual KPI stat cards, latency percentiles, and 1-click test runner.

### 6. Decentralized Direct ZeroMQ / UDP Wire Mesh Consensus
- **`agent/p2p_mesh.py`**: Pure P2P consensus voting independent of the central Command Node.
- **`PeerCorrelationEngine` & `WeightedConsensusAggregator`**: Trust multipliers ($2.0\times$ correlated, $1.0\times$ standard, $0.3\times$ degraded).

### 7. Executive & Incident PDF Compliance Reports
- **`backend/reports/report_generator.py`**: High-fidelity ReportLab PDF generation (`/api/reports/executive`, `/api/reports/incident`).
- **`dashboard/src/ReportModal.jsx`**: Compliance metadata picker and 1-click PDF download.

### 8. Docker Multi-Node Cluster Orchestration
- Multi-stage Dockerfiles (`Dockerfile.backend`, `Dockerfile.dashboard`, `Dockerfile.attacker`, `Dockerfile.agent`).
- `docker-compose.yml` multi-node cluster configuration with isolated bridge network.
