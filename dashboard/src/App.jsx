import { useState, useEffect, useCallback } from "react";
import {
  Activity,
  AlertTriangle,
  Bell,
  CheckCircle2,
  ChevronRight,
  Clock,
  Cpu,
  Database,
  Eye,
  Filter,
  RefreshCw,
  Server,
  Shield,
  Terminal,
  Wifi,
  X,
  Zap,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from "recharts";
import "./App.css";

/* ═══════════════════════════════════════════════
   Comprehensive Syscall Mapping Dictionary
   ═══════════════════════════════════════════════ */
const SYSCALL_NAMES = {
  0: "read",
  1: "write",
  2: "open",
  3: "close",
  4: "stat",
  5: "fstat",
  6: "lstat",
  7: "poll",
  8: "lseek",
  9: "mmap",
  10: "mprotect",
  11: "munmap",
  12: "brk",
  13: "rt_sigaction",
  14: "rt_sigprocmask",
  16: "ioctl",
  21: "access",
  22: "pipe",
  39: "getpid",
  41: "socket",
  42: "connect",
  43: "accept",
  44: "sendto",
  45: "recvfrom",
  56: "clone",
  57: "fork",
  59: "execve",
  60: "exit",
  62: "kill",
  78: "getdents",
  87: "unlink",
  101: "ptrace",
  202: "futex",
  217: "getdents64",
  231: "exit_group",
  257: "openat",
  281: "epoll_pwait",
  317: "seccomp",
};

function formatNumber(n) {
  return (n || 0).toLocaleString("en-US");
}

function formatTimestamp(ts) {
  if (!ts) return "Just now";
  // Handle microsecond/nanosecond timestamps
  let ms = ts;
  if (ts > 1e14) ms = Math.floor(ts / 1000000);
  else if (ts > 1e11) ms = Math.floor(ts / 1000);
  
  const date = new Date(ms);
  if (isNaN(date.getTime())) return "Live";
  return date.toLocaleTimeString("en-GB", { hour12: false });
}

function getThreatColor(score) {
  if (score >= 0.6) return "#ef4444";
  if (score >= 0.35) return "#f59e0b";
  return "#10b981";
}

function getThreatLabel(score) {
  if (score >= 0.6) return "CRITICAL";
  if (score >= 0.35) return "SUSPICIOUS";
  return "SAFE";
}

/* ═══════════════════════════════════════════════
   Custom Chart Tooltip
   ═══════════════════════════════════════════════ */
function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  const score = payload[0].value;
  const color = getThreatColor(score);

  return (
    <div className="custom-tooltip">
      <div className="tooltip-time">{label}</div>
      <div className="tooltip-row">
        <div className="tooltip-dot" style={{ background: color }} />
        <span className="tooltip-label">Threat Score</span>
        <span className="tooltip-value" style={{ color }}>
          {(score * 100).toFixed(1)}%
        </span>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════
   Stat Card
   ═══════════════════════════════════════════════ */
function StatCard({ icon: Icon, label, value, subtext, iconColor, statusClass }) {
  return (
    <div className="stat-card">
      <div className={`stat-icon ${iconColor}`}>
        <Icon size={20} />
      </div>
      <div className="stat-info">
        <div className="stat-label">{label}</div>
        <div className="stat-value">{value}</div>
        {subtext && <div className={`stat-subtext ${statusClass}`}>{subtext}</div>}
      </div>
    </div>
  );
}

export default function App() {
  const [activeTab, setActiveTab] = useState("overview");
  const [wsStatus, setWsStatus] = useState("CONNECTING");
  const [threatData, setThreatData] = useState([]);
  const [currentThreat, setCurrentThreat] = useState(0);
  const [latestEvent, setLatestEvent] = useState(null);
  const [processes, setProcesses] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [selectedProcess, setSelectedProcess] = useState(null);
  const [totalTelemetryCount, setTotalTelemetryCount] = useState(0);
  const [serverUptime, setServerUptime] = useState(0);
  const [hostOS, setHostOS] = useState("Windows");
  const [clock, setClock] = useState(new Date());

  /* Uptime and health check ticker */
  useEffect(() => {
    const id1 = setInterval(() => setClock(new Date()), 1000);
    const fetchHealth = async () => {
      try {
        const res = await fetch("http://127.0.0.1:8000/api/health");
        const data = await res.json();
        if (data.uptime !== undefined) setServerUptime(Math.floor(data.uptime));
        if (data.platform) setHostOS(data.platform);
      } catch (e) {
        // Backend offline
      }
    };
    fetchHealth();
    const id2 = setInterval(fetchHealth, 3000);
    return () => {
      clearInterval(id1);
      clearInterval(id2);
    };
  }, []);

  /* Trigger test telemetry event */
  const sendTestPulse = async () => {
    try {
      await fetch("http://127.0.0.1:8000/api/telemetry/test", { method: "POST" });
    } catch (err) {
      console.error("Test pulse error:", err);
    }
  };

  /* WebSocket Connection Handler */
  useEffect(() => {
    let ws;
    let reconnectTimer;
    let stopped = false;

    const connect = () => {
      if (stopped) return;
      setWsStatus("CONNECTING");
      ws = new WebSocket("ws://127.0.0.1:8000/ws/telemetry");

      ws.onopen = () => setWsStatus("LIVE");

      ws.onmessage = (message) => {
        try {
          const event = JSON.parse(message.data);
          if (event.type === "heartbeat") return;

          const threatScore = typeof event.threat_score === "number" 
            ? event.threat_score 
            : (typeof event.score === "number" ? event.score : 0);

          setLatestEvent(event);
          setCurrentThreat(threatScore);
          setTotalTelemetryCount((prev) => prev + 1);

          const timeStr = formatTimestamp(event.timestamp);

          // Update threat timeline chart
          setThreatData((prev) =>
            [
              ...prev,
              {
                time: timeStr,
                score: Number(threatScore.toFixed(3)),
              },
            ].slice(-20)
          );

          const procName = event.process || event.process_name || (event.file_path ? event.file_path.split(/[\/\\]/).pop() : null) || event.model || "unknown";
          const modelTag = (event.model || "event").toUpperCase();

          // Update active processes/events table
          setProcesses((prev) => {
            const updated = [
              {
                process: procName,
                model: modelTag,
                pid: event.pid || 0,
                uid: event.uid || 0,
                syscall: event.syscall || (event.destination_port ? `Port ${event.destination_port}` : "N/A"),
                window_size: event.window_size || 500,
                threat_score: threatScore,
                predicted_class: event.predicted_class || event.verdict || "Normal",
                normal_probability: event.normal_probability || (1 - threatScore),
                probabilities: event.probabilities || {},
                timestamp: event.timestamp,
              },
              ...prev.filter((p) => p.pid !== (event.pid || 0) || p.process !== procName),
            ];
            return updated.slice(0, 10);
          });

          // Generate alert if threat threshold is met
          if (threatScore >= 0.35) {
            setAlerts((prev) => [
              {
                id: `${event.timestamp}-${event.pid || Math.random()}`,
                severity: threatScore >= 0.6 ? "critical" : "warning",
                process: procName,
                pid: event.pid || 0,
                message: `[${modelTag}] Anomaly on ${procName} — ${
                  event.predicted_class || event.verdict || "MEDIUM"
                } (${(threatScore * 100).toFixed(1)}% threat score)`,
                time: timeStr,
                tag: event.predicted_class || event.verdict || "Alert",
              },
              ...prev,
            ].slice(0, 10));
          }
        } catch (error) {
          console.error("Invalid telemetry stream format:", error);
        }
      };

      ws.onerror = () => setWsStatus("ERROR");
      ws.onclose = () => {
        if (stopped) return;
        setWsStatus("DISCONNECTED");
        reconnectTimer = setTimeout(connect, 2500);
      };
    };

    connect();
    return () => {
      stopped = true;
      clearTimeout(reconnectTimer);
      if (ws) ws.close();
    };
  }, []);

  /* Fetch initial latest state from backend */
  useEffect(() => {
    fetch("http://127.0.0.1:8000/api/telemetry/latest")
      .then((res) => res.json())
      .then((event) => {
        if (event && (typeof event.threat_score === "number" || typeof event.score === "number") && event.timestamp) {
          const threatScore = typeof event.threat_score === "number" ? event.threat_score : event.score;
          setLatestEvent(event);
          setCurrentThreat(threatScore);
          setThreatData([
            {
              time: formatTimestamp(event.timestamp),
              score: Number(threatScore.toFixed(3)),
            },
          ]);
        }
      })
      .catch(() => {});
  }, []);

  /* Formatting calculations */
  const hrs = Math.floor(serverUptime / 3600);
  const mins = Math.floor((serverUptime % 3600) / 60);
  const secs = serverUptime % 60;
  const uptimeStr = `${hrs}h ${mins}m ${secs}s`;

  const clockStr = clock.toLocaleTimeString("en-GB", { hour12: false });
  const dateStr = clock.toLocaleDateString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
  });

  const probabilities = latestEvent?.probabilities
    ? Object.entries(latestEvent.probabilities)
        .map(([name, value]) => ({
          name,
          value,
          level: name === "Normal" ? "safe" : value >= 0.2 ? "danger" : "warning",
        }))
        .sort((a, b) => b.value - a.value)
    : [];

  const threatLabel = getThreatLabel(currentThreat);

  return (
    <div className="app">
      {/* ═══ Sidebar ═══ */}
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            <Shield size={22} />
          </div>
          <div>
            <h1>AEGIS</h1>
            <span>Endpoint Guardian</span>
          </div>
        </div>

        <nav className="nav-menu">
          <div className="nav-section">NAVIGATION</div>

          <button
            className={`nav-item ${activeTab === "overview" ? "active" : ""}`}
            onClick={() => setActiveTab("overview")}
          >
            <Activity size={16} />
            Security Overview
          </button>

          <button
            className={`nav-item ${activeTab === "processes" ? "active" : ""}`}
            onClick={() => setActiveTab("processes")}
          >
            <Cpu size={16} />
            Live Processes
            {processes.length > 0 && <span className="nav-badge">{processes.length}</span>}
          </button>

          <button
            className={`nav-item ${activeTab === "detections" ? "active" : ""}`}
            onClick={() => setActiveTab("detections")}
          >
            <AlertTriangle size={16} />
            Threat Detections
            {alerts.length > 0 && <span className="nav-badge alert">{alerts.length}</span>}
          </button>

          <button
            className={`nav-item ${activeTab === "models" ? "active" : ""}`}
            onClick={() => setActiveTab("models")}
          >
            <Shield size={16} />
            ML Inference Engine
          </button>
        </nav>

        <div className="agent-status-card">
          <div className={`status-indicator ${wsStatus.toLowerCase()}`} />
          <div className="agent-status-text">
            <strong>Backend API: {wsStatus}</strong>
            <span>Port 8000 · Up {uptimeStr}</span>
          </div>
        </div>
      </aside>

      {/* ═══ Main Area ═══ */}
      <main className="main">
        {/* Topbar */}
        <header className="topbar">
          <div>
            <h2>AEGIS Command Node</h2>
            <p className="topbar-subtitle">
              Live {hostOS} Telemetry & Multi-Model Threat Engine
            </p>
          </div>

          <div className="topbar-actions">
            <button className="btn-test-pulse" onClick={sendTestPulse} title="Trigger mock telemetry packet">
              <Zap size={14} /> Send Test Event
            </button>

            <span className="topbar-time">
              {dateStr} · {clockStr}
            </span>

            <div className={`ws-badge ${wsStatus.toLowerCase()}`}>
              <span className="ws-dot" />
              {wsStatus}
            </div>
          </div>
        </header>

        {/* Dynamic Metric Cards */}
        <section className="stats-grid">
          <StatCard
            icon={Cpu}
            label="Monitored Processes"
            value={processes.length}
            subtext={processes.length > 0 ? "Active PIDs in memory" : "Awaiting telemetry"}
            iconColor="blue"
            statusClass="neutral"
          />

          <StatCard
            icon={Activity}
            label="Events Processed"
            value={formatNumber(totalTelemetryCount)}
            subtext={latestEvent ? `Window size: ${latestEvent.window_size || 500}` : "No events yet"}
            iconColor="green"
            statusClass="up"
          />

          <StatCard
            icon={AlertTriangle}
            label="Security Alerts"
            value={alerts.length}
            subtext={alerts.length > 0 ? "Threats detected" : "0 Anomaly alerts"}
            iconColor={alerts.length > 0 ? "amber" : "blue"}
            statusClass={alerts.length > 0 ? "down" : "neutral"}
          />

          <StatCard
            icon={Shield}
            label="Current Threat Score"
            value={`${(currentThreat * 100).toFixed(1)}%`}
            subtext={`Status: ${threatLabel}`}
            iconColor={currentThreat >= 0.35 ? "red" : "green"}
            statusClass={currentThreat >= 0.35 ? "down" : "up"}
          />
        </section>

        {/* TAB 1: OVERVIEW & GENERAL VIEWS */}
        {(activeTab === "overview" || activeTab === "models") && (
          <section className="content-grid">
            {/* Real-time Threat Chart */}
            <div className="panel chart-panel">
              <div className="panel-header">
                <div>
                  <h3 className="panel-title">Threat Timeline</h3>
                  <p className="panel-subtitle">Rolling XGBoost model threat score stream</p>
                </div>
                <div className="panel-badge">WEBSOCKET LIVE</div>
              </div>

              <div className="chart-container">
                {threatData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={threatData}>
                      <defs>
                        <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="#ef4444" stopOpacity={0.4} />
                          <stop offset="50%" stopColor="#f59e0b" stopOpacity={0.15} />
                          <stop offset="100%" stopColor="#10b981" stopOpacity={0} />
                        </linearGradient>
                      </defs>

                      <XAxis
                        dataKey="time"
                        stroke="#334155"
                        tickLine={false}
                        axisLine={false}
                        tick={{ fill: "#64748b", fontSize: 10 }}
                      />
                      <YAxis
                        domain={[0, 1]}
                        stroke="#334155"
                        tickLine={false}
                        axisLine={false}
                        tick={{ fill: "#64748b", fontSize: 10 }}
                        tickFormatter={(v) => `${(v * 100).toFixed(0)}%`}
                      />

                      <ReferenceLine y={0.35} stroke="#f59e0b" strokeDasharray="4 4" label={{ value: "Warning Threshold", fill: "#f59e0b", fontSize: 10 }} />
                      <ReferenceLine y={0.6} stroke="#ef4444" strokeDasharray="4 4" label={{ value: "Critical Threshold", fill: "#ef4444", fontSize: 10 }} />

                      <Tooltip content={<ChartTooltip />} />

                      <Area
                        type="monotone"
                        dataKey="score"
                        stroke={getThreatColor(currentThreat)}
                        fill="url(#threatGrad)"
                        strokeWidth={2}
                        dot={{ r: 3, fill: "#0b1019" }}
                        activeDot={{ r: 5, fill: "#ef4444" }}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="empty-chart-placeholder">
                    <RefreshCw className="spin-icon" size={24} />
                    <p>Awaiting live telemetry events from Linux collector...</p>
                    <button className="btn-small-pulse" onClick={sendTestPulse}>
                      Send Test Event
                    </button>
                  </div>
                )}
              </div>
            </div>

            {/* Model Inference Breakdown */}
            <div className="panel model-panel">
              <div className="panel-header">
                <div>
                  <h3 className="panel-title">Linux XGBoost Pipeline</h3>
                  <p className="panel-subtitle">Syscall classification probabilities</p>
                </div>
                <span className={`model-status-badge ${latestEvent ? "online" : "waiting"}`}>
                  <span className="dot" />
                  {latestEvent ? "ACTIVE" : "READY"}
                </span>
              </div>

              {latestEvent ? (
                <>
                  <div className="prediction-block">
                    <div className="prediction-label">Predicted Class</div>
                    <div className={`prediction-class ${latestEvent.predicted_class === "Normal" ? "safe" : "danger"}`}>
                      {latestEvent.predicted_class}
                    </div>
                    <div className="prediction-time">
                      Inference at: {formatTimestamp(latestEvent.timestamp)}
                    </div>
                  </div>

                  <div className="model-scores-row">
                    <div className="score-box">
                      <span className="score-label">P(Normal)</span>
                      <strong className="score-value safe">
                        {((latestEvent.normal_probability || 0) * 100).toFixed(1)}%
                      </strong>
                    </div>
                    <div className="score-box">
                      <span className="score-label">Threat Score</span>
                      <strong className="score-value danger">
                        {((latestEvent.threat_score || 0) * 100).toFixed(1)}%
                      </strong>
                    </div>
                  </div>

                  <div className="probabilities-list">
                    {probabilities.map((p) => (
                      <div className="probability-row" key={p.name}>
                        <div className="probability-header">
                          <span className="prob-name">{p.name}</span>
                          <span className="prob-pct">{(p.value * 100).toFixed(1)}%</span>
                        </div>
                        <div className="probability-bar">
                          <div
                            className={`probability-fill ${p.level}`}
                            style={{ width: `${Math.max(3, p.value * 100)}%` }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <div className="empty-model-state">
                  <Shield size={32} className="muted-icon" />
                  <p>No model inference received yet.</p>
                  <span>Run <code>python agent/run_all.py</code></span>
                </div>
              )}
            </div>
          </section>
        )}

        {/* TAB 2: LIVE PROCESS ACTIVITY TABLE */}
        {(activeTab === "overview" || activeTab === "processes") && (
          <section className="panel activity-panel">
            <div className="panel-header">
              <div>
                <h3 className="panel-title">Live Process Telemetry</h3>
                <p className="panel-subtitle">Monitored process syscall windows</p>
              </div>
              <span className="panel-count-badge">{processes.length} Processes</span>
            </div>

            <div className="table-wrapper">
              {processes.length > 0 ? (
                <table>
                  <thead>
                    <tr>
                      <th>Process Name</th>
                      <th>PID</th>
                      <th>UID</th>
                      <th>Last Syscall</th>
                      <th>Threat Score</th>
                      <th>Prediction</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {processes.map((p) => (
                      <tr key={p.pid} className={p.threat_score >= 0.35 ? "highlight-row" : ""}>
                        <td>
                          <div className="process-cell">
                            <Terminal size={15} className="process-icon" />
                            <strong>{p.process}</strong>
                          </div>
                        </td>
                        <td><code>{p.pid}</code></td>
                        <td><code>{p.uid}</code></td>
                        <td>
                          <code>{p.syscall}</code>
                          <span className="syscall-tag">
                            {SYSCALL_NAMES[p.syscall] || "sys_enter"}
                          </span>
                        </td>
                        <td>
                          <span
                            className="threat-pill"
                            style={{
                              background: getThreatColor(p.threat_score) + "22",
                              color: getThreatColor(p.threat_score),
                              borderColor: getThreatColor(p.threat_score) + "55",
                            }}
                          >
                            {(p.threat_score * 100).toFixed(1)}%
                          </span>
                        </td>
                        <td>
                          <span className={`verdict-badge ${p.predicted_class === "Normal" ? "normal" : "alert"}`}>
                            {p.predicted_class}
                          </span>
                        </td>
                        <td>
                          <button
                            className="btn-inspect"
                            onClick={() => setSelectedProcess(p)}
                            title="Inspect full payload"
                          >
                            <Eye size={14} /> Inspect
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="empty-table-placeholder">
                  <Terminal size={28} className="muted-icon" />
                  <p>No active process telemetry recorded.</p>
                </div>
              )}
            </div>
          </section>
        )}

        {/* TAB 3: THREAT DETECTIONS & ALERTS */}
        {(activeTab === "overview" || activeTab === "detections") && (
          <section className="bottom-grid">
            {/* Alerts Feed */}
            <div className="panel alerts-panel">
              <div className="panel-header">
                <div>
                  <h3 className="panel-title">
                    <Bell size={15} style={{ display: "inline", verticalAlign: "-2px", marginRight: 6 }} />
                    Alert Feed
                  </h3>
                  <p className="panel-subtitle">Real-time threat alerts</p>
                </div>
                <div className="panel-badge">{alerts.length} ALERTS</div>
              </div>

              <div className="alerts-list">
                {alerts.length > 0 ? (
                  alerts.map((a) => (
                    <div className="alert-item" key={a.id}>
                      <div className={`alert-indicator ${a.severity}`} />
                      <div className="alert-content">
                        <div className="alert-message">{a.message}</div>
                        <div className="alert-meta">
                          <span className="alert-time">{a.time}</span>
                          <span className={`alert-tag ${a.severity}`}>{a.tag}</span>
                        </div>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="empty-alerts">
                    <CheckCircle2 size={24} className="safe-icon" />
                    <p>No high-severity threats detected.</p>
                  </div>
                )}
              </div>
            </div>

            {/* Agent Component Status */}
            <div className="panel health-panel">
              <div className="panel-header">
                <div>
                  <h3 className="panel-title">System Status</h3>
                  <p className="panel-subtitle">AEGIS Local Subsystems</p>
                </div>
                <div className="panel-badge">ONLINE</div>
              </div>

              <div className="health-list">
                {hostOS.toLowerCase().includes("win") ? (
                  <>
                    <div className="health-item">
                      <Wifi size={16} className="health-icon" />
                      <div className="health-info">
                        <div className="health-name">Zero-Day & Sysmon Monitor</div>
                        <div className="health-detail">Process creation & Event Log collector</div>
                      </div>
                      <div className={`health-dot ${wsStatus === "LIVE" ? "active" : "waiting"}`} />
                    </div>

                    <div className="health-item">
                      <Activity size={16} className="health-icon" />
                      <div className="health-info">
                        <div className="health-name">FastAPI Telemetry Hub</div>
                        <div className="health-detail">Endpoint ws://127.0.0.1:8000/ws/telemetry</div>
                      </div>
                      <div className={`health-dot ${wsStatus.toLowerCase()}`} />
                    </div>

                    <div className="health-item">
                      <Cpu size={16} className="health-icon" />
                      <div className="health-info">
                        <div className="health-name">Threat Fusion Engine</div>
                        <div className="health-detail">Multi-Model (CICIDS, EMBER, Zero-Day)</div>
                      </div>
                      <div className={`health-dot ${wsStatus === "LIVE" ? "active" : "waiting"}`} />
                    </div>
                  </>
                ) : (
                  <>
                    <div className="health-item">
                      <Wifi size={16} className="health-icon" />
                      <div className="health-info">
                        <div className="health-name">Kernel bpftrace Probe</div>
                        <div className="health-detail">Syscall tracepoint raw_syscalls</div>
                      </div>
                      <div className={`health-dot ${wsStatus === "LIVE" ? "active" : "waiting"}`} />
                    </div>

                    <div className="health-item">
                      <Activity size={16} className="health-icon" />
                      <div className="health-info">
                        <div className="health-name">FastAPI Telemetry Hub</div>
                        <div className="health-detail">Endpoint ws://127.0.0.1:8000/ws/telemetry</div>
                      </div>
                      <div className={`health-dot ${wsStatus.toLowerCase()}`} />
                    </div>

                    <div className="health-item">
                      <Cpu size={16} className="health-icon" />
                      <div className="health-info">
                        <div className="health-name">XGBoost ML Inference Adapter</div>
                        <div className="health-detail">Linux 7-class anomaly model</div>
                      </div>
                      <div className={`health-dot ${wsStatus === "LIVE" ? "active" : "waiting"}`} />
                    </div>
                  </>
                )}
              </div>
            </div>
          </section>
        )}

        {/* ═══ INSPECT MODAL ═══ */}
        {selectedProcess && (
          <div className="modal-overlay" onClick={() => setSelectedProcess(null)}>
            <div className="modal-content" onClick={(e) => e.stopPropagation()}>
              <div className="modal-header">
                <div>
                  <h3>Telemetry Inspector — {selectedProcess.process}</h3>
                  <span>PID: {selectedProcess.pid} · UID: {selectedProcess.uid}</span>
                </div>
                <button className="btn-close" onClick={() => setSelectedProcess(null)}>
                  <X size={18} />
                </button>
              </div>

              <div className="modal-body">
                <div className="modal-grid">
                  <div className="modal-stat">
                    <span className="stat-key">Predicted Verdict</span>
                    <strong className={`stat-val ${selectedProcess.predicted_class === "Normal" ? "safe" : "danger"}`}>
                      {selectedProcess.predicted_class}
                    </strong>
                  </div>

                  <div className="modal-stat">
                    <span className="stat-key">Threat Score</span>
                    <strong className="stat-val danger">
                      {(selectedProcess.threat_score * 100).toFixed(2)}%
                    </strong>
                  </div>

                  <div className="modal-stat">
                    <span className="stat-key">Syscall Window</span>
                    <strong className="stat-val">
                      {selectedProcess.window_size || 500} calls
                    </strong>
                  </div>

                  <div className="modal-stat">
                    <span className="stat-key">Last Syscall ID</span>
                    <strong className="stat-val">
                      {selectedProcess.syscall} ({SYSCALL_NAMES[selectedProcess.syscall] || "unknown"})
                    </strong>
                  </div>
                </div>

                <div className="modal-section-title">Raw Telemetry Event Payload</div>
                <pre className="json-code">
                  {JSON.stringify(selectedProcess, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
