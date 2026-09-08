# AEGIS Real-Time Security Dashboard

The **AEGIS Security Dashboard** is a modern, real-time web application built with **React** and **Vite** that provides security administrators with live visibility into endpoint telemetry, machine learning threat scores, agent health, and consensus voting states.

---

## 🎨 Features & Interface Panels

- **Real-Time Threat Score Gauge**: Displays fused 0.0–1.0 Threat Scores and 4-tier security verdicts (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Model Sub-Score Breakdown**: Visualizes predictions from all 6 ML engines (Linux IDS, Windows Advanced v3, CICIDS Network, EMBER PE Binary, HDFS Log Anomaly, Zero-Day Anomaly).
- **Live Telemetry Feed**: Real-time event stream received via WebSocket connection from the Command Node.
- **Agent Health & Silence Monitor**: Displays heartbeat status, CPU utilization, degradation status, and silence alarms.
- **Network Vote Map**: Visual representation of P2P peer consensus voting and node correlation *(Phase 2 Ready)*.

---

## 🏗️ Architecture & WebSocket Connection

The dashboard connects to the AEGIS Command Node via WebSocket:
```
ws://127.0.0.1:8000/ws/telemetry
```

When connected, the server streams real-time JSON frames containing:
- `agent_id`
- `timestamp`
- `fused_score`
- `verdict`
- `confidence`
- `model_scores` (sub-score per ML engine)
- `heartbeat` (status, cpu)

---

## 🛠️ Setup & Development Commands

### Prerequisites
- Node.js (v18+)
- npm or yarn

### Installation
```bash
npm install
```

### Start Development Server
```bash
npm run dev
```
Starts the Vite dev server at `http://localhost:5173`.

### Production Build
```bash
npm run build
```
Outputs static assets into the `dist/` directory.

### Preview Production Build
```bash
npm run preview
```
