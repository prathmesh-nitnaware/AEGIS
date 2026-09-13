# Project AEGIS

**Adaptive Edge Guardian with Intelligence Swarm**  
*Distributed Endpoint Detection & Response (EDR) with Peer-Consensus Voting*

[![Tests](https://img.shields.io/badge/tests-169%20passing-brightgreen)](#testing)
[![Completion](https://img.shields.io/badge/overall~90%25%20complete-blue)](#project-status)

---

## Overview

Project AEGIS is a **distributed EDR system** that combines **6 ML detection engines**, a **peer-consensus voting protocol**, and an **automated response pipeline** into a single security operations platform. Every node acts as both a **sensor** and a **voter** — no single agent can trigger high-severity remediation alone.

Inspired by biological immune systems, AEGIS correlates signals across the fleet, persists verdicts to a central command node, and gives SOC operators a live React dashboard for monitoring, trust calibration, and incident response.

---

## Project Status

| Area | Completion | Status |
| :--- | :--- | :--- |
| ML models & threat fusion | ~98% | All 6 models trained, verified, and integrated |
| Live telemetry collectors | ~85% | Implemented; OS/privilege setup required |
| P2P peer consensus | ~90% | UDP mesh + REST fallback, tested |
| Command Node API | ~95% | 38+ REST/WebSocket endpoints |
| Database persistence (NeonDB/SQLite) | ~85% | 7 tables; `ModelDetection` write path unwired |
| Active response driver | ~90% | Real firewall/process actions + simulated fallback |
| React SOC dashboard | ~92% | 10 tabs; hardcoded API URLs |
| Attack simulation suite | ~90% | CLI + dashboard + backend service |
| Docker deployment | ~75% | Multi-node compose; agents run in demo mode |
| XAI / explainability | ~40% | UI-ready; synthetic SHAP values |
| PDF report export | ~60% | Generator exists; `reportlab` not in requirements |
| CI/CD & production hardening | ~5% | Not started |
| **Overall** | **~90%** | **Demo-ready; not production-hardened** |

> **Bottom line:** Core EDR functionality is built and working. Remaining work is polish, production readiness, and wiring a few incomplete integration paths.

---

## Architecture

AEGIS operates across three primary layers:

| Layer | Component | Description |
| :--- | :--- | :--- |
| **Layer 1** | **EDR Agent & ML Suite** | Live collectors, 6 ML models, Threat Fusion Engine, Confidence Engine, Heartbeat & Silence Detection |
| **Layer 2** | **Peer Voting Protocol** | UDP P2P mesh for `VotingRequest`/`VotingResponse`, weighted consensus, silence-as-alarm correlation |
| **Layer 3** | **Command Node & Dashboard** | FastAPI server, NeonDB/PostgreSQL persistence, WebSocket broadcast, React SOC dashboard, automated response dispatch |

```
┌─────────────────────────────────────────────────────────────────┐
│                     React SOC Dashboard (:5173)                 │
│  Overview · Verdicts · Maintenance · Fleet · Audit · MITRE   │
└────────────────────────────┬────────────────────────────────────┘
                             │ WebSocket + REST
┌────────────────────────────▼────────────────────────────────────┐
│              Command Node — FastAPI (:8000)                     │
│  Telemetry · Consensus · Trust · Actions · Reports · Simulation │
└──────┬──────────────────┬──────────────────┬────────────────────┘
       │                  │                  │
  ┌────▼────┐        ┌────▼────┐        ┌────▼────┐
  │ Agent 1 │◄─UDP──►│ Agent 2 │◄─UDP──►│ Agent 3 │
  │ ML+Resp │        │ ML+Resp │        │ ML+Resp │
  └─────────┘        └─────────┘        └─────────┘
```

---

## What's Done

### Phase 1 — Single-Agent EDR & ML Suite ✅

**6 ML detection engines** trained, serialized, and integrated into `ThreatFusionEngine`:

| Model | Algorithm | Detects | Artifact |
| :--- | :--- | :--- | :--- |
| **Linux IDS** | XGBoost | Syscall attacks (Meterpreter, Hydra, Web Shell, Adduser) | `trained_models/linux_ids/` |
| **Windows Advanced v3** | XGBoost | Process creation, token misuse, registry persistence | `trained_models/windows_advanced_v3/` |
| **CICIDS Network** | LightGBM | DoS, DDoS, Brute Force, PortScan, Botnet | `trained_models/cicids/` |
| **EMBER File** | LightGBM | PE binary analysis via LIEF (header entropy, sections) | `trained_models/ember/` |
| **HDFS Logs** | XGBoost + TF-IDF | Log sequence anomalies, ransomware behavior | `trained_models/hdfs/` |
| **Zero-Day** | Isolation Forest | Unsupervised behavioral anomalies | `trained_models/zero_day/` |

**Core engines:**
- `agent/fusion_engine.py` — blends sub-scores into 0.0–1.0 threat score; 4-tier verdicts (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
- `agent/confidence_engine.py` — completeness × agreement confidence; `AgentTrustTracker` with SQLite EMA
- `agent/run_all.py` — cross-platform orchestrator; auto-detects OS and starts active collectors
- Live collectors: `linux_collector.py`, `scapy_flow_collector.py`, `ember_features.py`, `windows_process_context.py`, `live_collectors.py`

**Heartbeat & silence detection:**
- `agent/heartbeat.py` — 5s heartbeat interval, 15s silence threshold
- `agent/heartbeat_runner.py` — daemon with graceful shutdown hooks (Windows `SetConsoleCtrlHandler`, Linux `SIGTERM`)
- Endpoints: `POST /api/heartbeat`, `POST /api/heartbeat/shutdown`, `GET /api/agents`

---

### Phase 2 — P2P Peer Consensus Voting ✅

- `agent/p2p_mesh.py` — `VotingRequest`/`VotingResponse`, UDP broadcast, weighted consensus (2.0× / 1.0× / 0.5× / 0.3× multipliers)
- `PeerCorrelationEngine` — verifies correlated network, process, and file signals across peers
- Endpoints: `POST /api/p2p/consensus`, `POST /api/p2p/vote`
- Tests: `tests/test_p2p_mesh.py` (8 tests)

---

### Phase 3 — Automated Response & Verdict Aggregation ✅

- `agent/response_driver.py` — `LOG`, `ALERT`, `KILL_PROCESS`, `QUARANTINE_FILE`, `ISOLATE_HOST`, `UNISOLATE_HOST`
  - Windows: real `netsh advfirewall` rules; Linux: real `iptables` rules
  - Falls back to `simulated_success` without admin/root privileges
- `agent/action_consumer.py` — polls command node and executes pending actions
- `backend/command_node.py` — centralized voting hub and response dispatch
- Endpoints: `POST /api/centralized/vote`, `POST /api/actions/enqueue`, `GET /api/actions`, agent action ack routes
- Tests: `test_admin_trust_and_response.py`, `test_remote_action_dispatcher.py`, `test_graceful_shutdown.py`

---

### Phase 4 — Admin Trust & Maintenance Windows ✅

- `agent/admin_trust.py` — `IdentityContext`, `MaintenanceWindowPortal`, `AdminTrustEngine`
- Maintenance windows persisted to DB and restored on server startup
- Trust feedback loop: `POST /api/trust/feedback` updates EMA in NeonDB + local SQLite
- Endpoints: `/api/maintenance/schedule`, `/api/maintenance/windows`, `/api/maintenance/cancel`, `/api/agents/{id}/trust`, `/api/alerts`, `/api/audit`

---

### Phase 5 — Multi-Node Attack Simulation Suite ✅

- `experiments/simulations/simulate_linux_attacks.py` — Hydra, Meterpreter, Web Shell scenarios
- `experiments/simulations/simulate_windows_ransomware.py` — ransomware + PE dropper
- `experiments/simulations/simulate_silence_tamper.py` — adversary silence sabotage
- `experiments/simulations/simulate_graceful_shutdown.py` — agent lifecycle testing
- `experiments/simulations/run_multi_node_demo.py` — CLI menu for all scenarios
- `backend/services/simulation_service.py` — dashboard-triggered simulation runs
- Endpoints: `POST /api/simulation/launch`, `GET /api/simulation/status`, `POST /api/simulation/reset`

---

### NeonDB Persistence Layer ✅

- `backend/db/database.py` — async SQLAlchemy engine; NeonDB PostgreSQL primary, SQLite fallback
- `backend/db/models.py` — 7 ORM tables: `TelemetryEvent`, `ModelDetection`, `ConsensusVerdict`, `SilenceAlarm`, `AgentTrust`, `MaintenanceWindowRecord`, `AuditLogEntry`
- `backend/db/repository.py` — async CRUD for all tables; PostgreSQL + SQLite compatible
- Write paths wired for telemetry, verdicts, silence alarms, maintenance windows, trust, and audit log

---

### React SOC Dashboard ✅

Built with React 19 + Vite 8. Real-time WebSocket connection to command node.

| Tab | Purpose |
| :--- | :--- |
| **Security Overview** | Threat score gauge, live telemetry feed, silence alarm banner |
| **Consensus & Feedback** | NeonDB verdicts; Confirm Threat / False Positive trust calibration |
| **Maintenance Windows** | Schedule and cancel suppression windows |
| **Fleet & Trust Tracker** | Agent health, CPU metrics, NeonDB trust EMA |
| **Mitigation Audit Log** | Paginated response action history |
| **Live Processes** | Real-time process telemetry from WebSocket |
| **Threat Detections** | Alert feed with severity badges |
| **ML Inference Engine** | Per-model probability breakdown |
| **MITRE ATT&CK Matrix** | Static technique mapping from detections (`MitreAttackTab.jsx`) |
| **Red Team Simulation Lab** | Launch and monitor attack scenarios (`SimulationLabTab.jsx`) |
| **Export Security Report** | Executive / incident PDF reports (`ReportModal.jsx`) |

---

### Docker Multi-Node Cluster ✅ (new)

```
docker compose up --build
```

| Service | Role | Port |
| :--- | :--- | :--- |
| `command-node` | FastAPI backend + WebSocket | `:8000` |
| `dashboard` | Nginx-served React UI | `:5173→80` |
| `agent-vm1/2/3` | EDR agents (heartbeat + action consumer) | internal |

Files: `docker-compose.yml`, `Dockerfile.backend`, `Dockerfile.agent`, `Dockerfile.dashboard`, `docker/nginx.conf`, `.env.docker`

---

### Testing ✅

**169 pytest tests** covering all models, P2P mesh, centralized server, response driver, and trust system.

```bash
pytest tests/
```

| Test file | Coverage |
| :--- | :--- |
| `test_linux_ids.py` | Syscall buffer, 7-class scoring |
| `test_windows_advanced*.py` | Token encoding, inference, remediation |
| `test_cicids_model.py` | Flow feature mapping, LightGBM output |
| `test_ember_model.py` | PE feature extraction |
| `test_hdfs_model.py` | TF-IDF vectorization, anomaly bounds |
| `test_zero_day_model.py` | Isolation Forest decision scores |
| `test_p2p_mesh.py` | Consensus voting, correlation |
| `test_centralized_server.py` | Command node API |
| `test_admin_trust_and_response.py` | Trust engine + response actions |
| `test_graceful_shutdown.py` | Heartbeat lifecycle |

---

## What's Partially Done

| Feature | Current State | Remaining Work |
| :--- | :--- | :--- |
| **XAI / SHAP explanations** | `backend/services/xai_service.py` returns synthetic values | Integrate real SHAP library against model inputs |
| **PDF report export** | `backend/reports/report_generator.py` uses ReportLab | Add `reportlab` to `requirements.txt`; wire live DB metrics instead of static fallbacks |
| **Report preview metrics** | `/api/reports/preview` returns hardcoded `"consensus_accuracy": "99.4%"` | Compute from actual NeonDB verdict data |
| **`ModelDetection` DB table** | Schema + repository exist | Wire write path from telemetry ingestion |
| **Docker agents** | Heartbeat + action consumer only | Run full `run_all.py` ML collectors in containers |
| **Dashboard API URLs** | Hardcoded `http://127.0.0.1:8000` | Use relative URLs via nginx proxy in production |
| **Dual-approval maintenance** | UI label says "dual-approval" | Implement second approver workflow |
| **Admin trust behavioral analysis** | Scaffolded in `admin_trust.py` | Deep integration with live telemetry path |
| **CICIDS flow collector** | Scapy-based; placeholder until CICFlowMeter | Optional CICFlowMeter integration for higher fidelity |

---

## What's To Do

### Production Readiness (High Priority)

- [ ] Add `reportlab` to `requirements.txt` and verify PDF export on clean install
- [ ] Wire `ModelDetection` table writes from telemetry ingestion
- [ ] Replace synthetic XAI with real SHAP/feature-attribution per model
- [ ] Use relative API URLs in dashboard (works with nginx proxy and Docker)
- [ ] Remove duplicate `/api/audit` route definition in `telemetry_api.py`
- [ ] Add API authentication / authorization (currently open on all endpoints)
- [ ] Add GitHub Actions CI pipeline (lint + pytest on push/PR)

### Infrastructure & Deployment

- [ ] Run full ML collectors inside Docker agents (not just heartbeat demo mode)
- [ ] Automated VirtualBox 3-node lab provisioning (currently manual; Docker is the substitute)
- [ ] Kubernetes / Terraform deployment manifests (optional)
- [ ] Environment-specific config (dev/staging/prod) without hardcoded URLs

### Feature Enhancements

- [ ] Real dual-approver maintenance window workflow
- [ ] Live incident report data from NeonDB (replace static fallback content)
- [ ] Benchmark evaluation dashboard: TPR, FPR, MTTD, MTTR, consensus latency metrics
- [ ] CICFlowMeter integration for production-grade network flow features
- [ ] Windows Sysmon collector auto-setup script

### Collector Prerequisites (Manual Setup)

These collectors require OS-level setup before `run_all.py` can use them:

| Collector | Requirement |
| :--- | :--- |
| Linux IDS | `bpftrace` installed + root privileges |
| Windows Advanced | Sysmon installed and logging |
| EMBER | `PE_WATCH_DIR` environment variable set |
| HDFS | `HDFS_LOG_PATH` pointing to real log files |
| CICIDS | Network interface access (Scapy; may need admin/root) |

---

## Tech Stack

| Layer | Technologies |
| :--- | :--- |
| **Languages** | Python 3.10–3.14, JavaScript (ES6+), SQL |
| **Backend** | FastAPI, Uvicorn, WebSockets, SQLAlchemy async, asyncpg, aiosqlite |
| **Frontend** | React 19, Vite 8, Recharts, Lucide icons |
| **ML** | XGBoost, LightGBM, scikit-learn, Isolation Forest, Joblib |
| **Telemetry** | Scapy, LIEF, Watchdog, psutil, bpftrace (Linux) |
| **Agent networking** | UDP P2P mesh, HTTP REST, requests |
| **Database** | NeonDB PostgreSQL (primary) + SQLite fallback |
| **Reports** | ReportLab (used; add to requirements) |
| **Testing** | Pytest (169 tests) |
| **Containerization** | Docker Compose, Python 3.11-slim, Node 20, Nginx 1.27 |

---

## Quick Start

### Option A — Local Development (3 terminals)

**1. Install dependencies**
```bash
pip install -r requirements.txt
cd dashboard && npm install && cd ..
```

**2. Run tests**
```bash
pytest tests/
```

**3. Terminal 1 — Command Node**
```bash
python backend/main.py
# → http://127.0.0.1:8000  |  ws://127.0.0.1:8000/ws/telemetry
```

**4. Terminal 2 — EDR Agent**
```bash
python agent/run_all.py
# Auto-detects OS and starts active collectors
```

**5. Terminal 3 — Dashboard**
```bash
cd dashboard && npm run dev
# → http://localhost:5173
```

**Optional — Heartbeat-only agent (lightweight)**
```bash
python agent/heartbeat_runner.py
python agent/action_consumer.py
```

---

### Option B — Docker Cluster (recommended for demos)

**1. Configure environment**
```bash
cp .env.docker .env.docker.local
# Edit DATABASE_URL if using NeonDB; defaults to SQLite
```

**2. Start full cluster**
```bash
docker compose up --build
# Dashboard → http://localhost:5173
# API       → http://localhost:8000
```

**3. Run attack simulations**
```bash
docker compose exec agent-vm1 python -m experiments.simulations.run_multi_node_demo --all
```

**4. View logs**
```bash
docker compose logs -f
```

**5. Shut down**
```bash
docker compose down -v
```

---

## API Reference (Key Endpoints)

| Method | Endpoint | Purpose |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Server health check |
| `POST` | `/api/telemetry` | Ingest telemetry event |
| `GET` | `/api/telemetry/latest` | Latest telemetry snapshot |
| `WS` | `/ws/telemetry` | Real-time telemetry broadcast |
| `POST` | `/api/centralized/vote` | Submit consensus vote |
| `GET` | `/api/centralized/verdicts` | Paginated verdict history |
| `POST` | `/api/p2p/consensus` | P2P consensus result |
| `POST` | `/api/heartbeat` | Agent heartbeat |
| `POST` | `/api/heartbeat/shutdown` | Graceful shutdown beacon |
| `GET` | `/api/agents` | Fleet agent list |
| `POST` | `/api/actions/enqueue` | Queue remote response action |
| `POST` | `/api/trust/feedback` | Admin trust calibration |
| `GET` | `/api/alerts` | Active silence alarms |
| `POST` | `/api/maintenance/schedule` | Schedule maintenance window |
| `GET` | `/api/audit` | Mitigation audit log |
| `POST` | `/api/simulation/launch` | Launch attack simulation |
| `GET` | `/api/reports/preview` | Report metrics preview |
| `POST` | `/api/reports/executive` | Generate executive PDF |
| `GET/POST` | `/api/xai/explain` | Model explanation (synthetic) |

Full API surface: 38+ routes in `backend/telemetry_api.py`.

---

## Repository Structure

```
AEGIS/
├── agent/                  # EDR agent: collectors, ML fusion, P2P, response
│   ├── run_all.py          # Main agent entry point
│   ├── fusion_engine.py    # ThreatFusionEngine
│   ├── p2p_mesh.py         # Peer consensus voting
│   ├── response_driver.py  # Automated remediation
│   └── heartbeat.py        # Heartbeat + silence detection
├── backend/                # Command Node (FastAPI)
│   ├── main.py             # Server entry point
│   ├── telemetry_api.py    # All REST + WebSocket routes
│   ├── command_node.py     # Voting hub
│   ├── db/                 # NeonDB/SQLite persistence
│   ├── services/           # Simulation, XAI services
│   └── reports/            # PDF report generator
├── dashboard/              # React SOC dashboard
│   └── src/
│       ├── App.jsx         # Main dashboard (8 tabs)
│       ├── MitreAttackTab.jsx
│       ├── SimulationLabTab.jsx
│       └── ReportModal.jsx
├── trained_models/         # Serialized ML artifacts (6 models)
├── ml_notebooks/           # Jupyter training notebooks
├── experiments/simulations/# Attack simulation scripts
├── tests/                  # Pytest suite (169 tests)
├── docker-compose.yml      # Multi-node Docker cluster
└── requirements.txt
```

---

## Roadmap Summary

| Phase | Description | Status |
| :--- | :--- | :--- |
| **Phase 1** | Single-agent EDR, 6 ML models, fusion engine, dashboard | ✅ Complete |
| **Phase 2** | P2P peer consensus voting (UDP mesh) | ✅ Complete |
| **Phase 3** | Automated response actions & verdict aggregation | ✅ Complete |
| **Phase 4** | Admin trust system & maintenance windows | ✅ Complete |
| **Phase 5** | Multi-node attack simulation suite | ✅ Complete |
| **Phase A** | NeonDB persistence layer (7 tables) | ✅ Complete |
| **Phase B** | Response driver hardening (real firewall commands) | ✅ Complete |
| **Phase C** | Trust feedback loop (admin calibration) | ✅ Complete |
| **Phase D** | Dashboard UI (verdicts, maintenance, fleet, audit) | ✅ Complete |
| **Phase E** | Docker multi-node cluster | ✅ Complete |
| **Phase F** | MITRE ATT&CK tab, Simulation Lab, PDF reports, XAI | 🟡 Partial |
| **Phase G** | CI/CD, API auth, production hardening | ⬜ Not started |

---

## Contributing & Documentation

- Detailed item-level checklist: [`PROGRESS_CHECKLIST.md`](PROGRESS_CHECKLIST.md)
- Historical progress report: [`progress_status.md`](progress_status.md)

---

## Repository

GitHub: [AEGIS Project Repository](https://github.com/prathmesh-nitnaware/AEGIS)
