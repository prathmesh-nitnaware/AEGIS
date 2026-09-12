import { useState, useEffect, useCallback } from "react";
import {
  Activity,
  AlertTriangle,
  Bell,
  Calendar,
  Check,
  CheckCircle2,
  ChevronRight,
  Clock,
  Cpu,
  Database,
  Eye,
  FileText,
  Filter,
  RefreshCw,
  Server,
  Shield,
  Terminal,
  ThumbsDown,
  ThumbsUp,
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
  const [agents, setAgents] = useState({}); // agent_id -> { agentId, status, cpu, alarmed, lastSeen }

  // New Phase D States (NeonDB, Trust Feedback, Maintenance, Silence Alarms, Audit)
  const [verdicts, setVerdicts] = useState([]);
  const [maintenanceWindows, setMaintenanceWindows] = useState([]);
  const [silenceAlarms, setSilenceAlarms] = useState([]);
  const [agentTrustMap, setAgentTrustMap] = useState({});
  const [auditLogs, setAuditLogs] = useState([]);
  const [feedbackToast, setFeedbackToast] = useState(null);
  const [maintForm, setMaintForm] = useState({
    agent_id: "*",
    duration_minutes: 60,
    reason: "Scheduled Security Patching",
    approved_by: "SecOps Admin",
  });

  const showToast = (msg) => {
    setFeedbackToast(msg);
    setTimeout(() => setFeedbackToast(null), 4500);
  };

  const fetchVerdicts = useCallback(async () => {
    try {
      const res = await fetch("http://127.0.0.1:8000/api/centralized/verdicts?limit=50");
      const data = await res.json();
      if (data && data.verdicts) setVerdicts(data.verdicts);
    } catch (e) {
      console.error("Failed to fetch verdicts:", e);
    }
  }, []);

  const fetchMaintenance = useCallback(async () => {
    try {
      const res = await fetch("http://127.0.0.1:8000/api/maintenance/windows?active_only=false");
      const data = await res.json();
      if (data && data.windows) setMaintenanceWindows(data.windows);
    } catch (e) {
      console.error("Failed to fetch maintenance:", e);
    }
  }, []);

  const fetchSilenceAlarms = useCallback(async () => {
    try {
      const res = await fetch("http://127.0.0.1:8000/api/alerts");
      const data = await res.json();
      if (data && data.alerts) setSilenceAlarms(data.alerts);
    } catch (e) {
      console.error("Failed to fetch alarms:", e);
    }
  }, []);

  const fetchAgentTrust = useCallback(async () => {
    try {
      const res = await fetch("http://127.0.0.1:8000/api/agents/trust/all");
      const data = await res.json();
      if (data && data.agents) setAgentTrustMap(data.agents);
    } catch (e) {
      console.error("Failed to fetch agent trust:", e);
    }
  }, []);

  const fetchAudit = useCallback(async () => {
    try {
      const res = await fetch("http://127.0.0.1:8000/api/audit?limit=50");
      const data = await res.json();
      if (data && data.entries) setAuditLogs(data.entries);
    } catch (e) {
      console.error("Failed to fetch audit:", e);
    }
  }, []);

  // Poll active silence alarms and health
  useEffect(() => {
    fetchSilenceAlarms();
    const id = setInterval(fetchSilenceAlarms, 4000);
    return () => clearInterval(id);
  }, [fetchSilenceAlarms]);

  // Tab switch fetcher
  useEffect(() => {
    if (activeTab === "verdicts") fetchVerdicts();
    if (activeTab === "maintenance") fetchMaintenance();
    if (activeTab === "agents") {
      fetchAgentTrust();
      fetchSilenceAlarms();
    }
    if (activeTab === "audit") fetchAudit();
  }, [activeTab, fetchVerdicts, fetchMaintenance, fetchAgentTrust, fetchSilenceAlarms, fetchAudit]);

  const handleTrustFeedback = async (voteId, confirmed) => {
    try {
      const res = await fetch("http://127.0.0.1:8000/api/trust/feedback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          vote_id: voteId,
          confirmed: confirmed,
          confirmed_by: "SecOps Admin",
        }),
      });
      const data = await res.json();
      if (res.ok) {
        showToast(
          `Verdict ${voteId} marked as ${confirmed ? "CONFIRMED THREAT" : "FALSE POSITIVE"}. Updated trust: ${(data.new_trust_score * 100).toFixed(1)}%`
        );
        setVerdicts((prev) =>
          prev.map((v) =>
            v.vote_id === voteId
              ? { ...v, admin_confirmed: confirmed, confirmed_by: "SecOps Admin" }
              : v
          )
        );
        fetchAgentTrust();
      } else {
        showToast(`Feedback error: ${data.detail || "Request failed"}`);
      }
    } catch (err) {
      console.error("Error submitting trust feedback:", err);
      showToast("Network error submitting feedback");
    }
  };

  const handleAcknowledgeAlarm = async (alarmId) => {
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/alerts/${alarmId}/ack`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ acknowledged_by: "SecOps Admin" }),
      });
      if (res.ok) {
        showToast(`Silence alarm #${alarmId} acknowledged`);
        setSilenceAlarms((prev) => prev.filter((a) => a.id !== alarmId));
      }
    } catch (err) {
      console.error("Error acknowledging alarm:", err);
    }
  };

  const handleScheduleMaintenance = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch("http://127.0.0.1:8000/api/maintenance/schedule", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          agent_id: maintForm.agent_id,
          duration_seconds: (maintForm.duration_minutes || 60) * 60,
          approved_by: maintForm.approved_by,
          reason: maintForm.reason,
        }),
      });
      const data = await res.json();
      if (res.ok) {
        showToast(`Maintenance window scheduled for agent ${maintForm.agent_id}`);
        fetchMaintenance();
      } else {
        showToast(`Failed: ${data.detail || "Could not schedule window"}`);
      }
    } catch (err) {
      console.error("Schedule maintenance error:", err);
    }
  };

  const handleCancelMaintenance = async (windowId) => {
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/maintenance/cancel?window_id=${windowId}`, {
        method: "DELETE",
      });
      if (res.ok) {
        showToast("Maintenance window cancelled");
        fetchMaintenance();
      }
    } catch (err) {
      console.error("Cancel maintenance error:", err);
    }
  };

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

          // Per-agent heartbeat/silent-alarm events - handled separately
          // from the general telemetry stream below, and BEFORE the
          // reserved "heartbeat" keepalive check (different type string,
          // but keep them visually grouped since they're related).
          if (event.type === "agent_heartbeat") {
            setAgents((prev) => ({
              ...prev,
              [event.agent_id]: {
                agentId: event.agent_id,
                status: event.status || "healthy",
                cpu: event.cpu,
                alarmed: false,
                lastSeen: event.timestamp,
              },
            }));
            return;
          }

          if (event.type === "agent_alarm") {
            setAgents((prev) => ({
              ...prev,
              [event.agent_id]: {
                ...(prev[event.agent_id] || { agentId: event.agent_id, cpu: 0 }),
                agentId: event.agent_id,
                status: "silent",
                alarmed: true,
              },
            }));
            setAlerts((prev) =>
              [
                {
                  id: `alarm-${event.agent_id}-${event.timestamp}`,
                  severity: "critical",
                  process: event.agent_id,
                  pid: 0,
                  message: event.message || `${event.agent_id} is SILENT`,
                  time: new Date(event.timestamp * 1000).toLocaleTimeString("en-GB", { hour12: false }),
                  tag: "SILENT_ALARM",
                },
                ...prev,
              ].slice(0, 10)
            );
            return;
          }

          if (event.type === "agent_shutdown") {
            setAgents((prev) => ({
              ...prev,
              [event.agent_id]: {
                ...(prev[event.agent_id] || { agentId: event.agent_id, cpu: 0 }),
                agentId: event.agent_id,
                status: "OFFLINE_GRACEFUL",
                alarmed: false,
                reason: event.reason,
              },
            }));
            showToast(`Agent ${event.agent_id} completed graceful shutdown (${event.reason || "Planned offline"})`);
            return;
          }

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

  /* Fetch initial agent heartbeat snapshot */
  useEffect(() => {
    fetch("http://127.0.0.1:8000/api/agents")
      .then((res) => res.json())
      .then((data) => {
        const map = {};
        (data.agents || []).forEach((a) => {
          map[a.agent_id] = {
            agentId: a.agent_id,
            status: a.alarm_raised ? "silent" : a.status,
            cpu: a.cpu,
            alarmed: a.alarm_raised,
            lastSeen: a.last_seen,
          };
        });
        setAgents(map);
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
          <div className="nav-section">AEGIS SOC</div>

          <button
            className={`nav-item ${activeTab === "overview" ? "active" : ""}`}
            onClick={() => setActiveTab("overview")}
          >
            <Activity size={16} />
            Security Overview
          </button>

          <button
            className={`nav-item ${activeTab === "verdicts" ? "active" : ""}`}
            onClick={() => setActiveTab("verdicts")}
          >
            <Database size={16} />
            Consensus & Feedback
            {verdicts.length > 0 && <span className="nav-badge">{verdicts.length}</span>}
          </button>

          <button
            className={`nav-item ${activeTab === "maintenance" ? "active" : ""}`}
            onClick={() => setActiveTab("maintenance")}
          >
            <Calendar size={16} />
            Maintenance Windows
            {maintenanceWindows.filter((w) => w.is_active).length > 0 && (
              <span className="nav-badge">{maintenanceWindows.filter((w) => w.is_active).length}</span>
            )}
          </button>

          <button
            className={`nav-item ${activeTab === "agents" ? "active" : ""}`}
            onClick={() => setActiveTab("agents")}
          >
            <Server size={16} />
            Fleet & Trust Tracker
            {silenceAlarms.length > 0 && <span className="nav-badge alert">{silenceAlarms.length}</span>}
          </button>

          <button
            className={`nav-item ${activeTab === "audit" ? "active" : ""}`}
            onClick={() => setActiveTab("audit")}
          >
            <FileText size={16} />
            Mitigation Audit Log
          </button>

          <div className="nav-section" style={{ marginTop: 14 }}>TELEMETRY</div>

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

        {/* ═══ Silence Alarm Alert Banner ═══ */}
        {silenceAlarms.length > 0 && (
          <div className="silence-alarm-banner">
            <div className="alarm-banner-left">
              <AlertTriangle size={20} className="alarm-pulse-icon" />
              <div>
                <strong>CRITICAL: Node Heartbeat Lost ({silenceAlarms.length} active silence alarms)</strong>
                <div>
                  Agent <code>{silenceAlarms[0].agent_id}</code> has missed heartbeats (silent for{" "}
                  {Math.round(silenceAlarms[0].silence_duration || 15)}s). Active threat alarms armed.
                </div>
              </div>
            </div>
            <button
              className="btn-ack-alarm"
              onClick={() => handleAcknowledgeAlarm(silenceAlarms[0].id)}
            >
              <CheckCircle2 size={15} /> Acknowledge Alert
            </button>
          </div>
        )}

        {/* ═══ Feedback / Action Toast ═══ */}
        {feedbackToast && (
          <div className="feedback-toast">
            <Check size={16} style={{ color: "#38bdf8" }} />
            <span>{feedbackToast}</span>
          </div>
        )}

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

        {/* AGENT HEALTH MONITOR - LAN heartbeat / silent-alarm status per machine */}
        {activeTab === "overview" && (
          <section className="panel agent-health-panel" style={{ marginTop: 20 }}>
            <div className="panel-header">
              <div>
                <h3 className="panel-title">
                  <Server size={15} style={{ display: "inline", verticalAlign: "-2px", marginRight: 6 }} />
                  Agent Health Monitor
                </h3>
                <p className="panel-subtitle">LAN heartbeat status per machine</p>
              </div>
              <div className="panel-badge">{Object.keys(agents).length} AGENTS</div>
            </div>

            <div className="health-list">
              {Object.keys(agents).length > 0 ? (
                Object.values(agents)
                  .sort((a, b) => a.agentId.localeCompare(b.agentId))
                  .map((a) => (
                    <div className="health-item" key={a.agentId}>
                      <Server size={16} className="health-icon" />
                      <div className="health-info">
                        <div className="health-name">{a.agentId}</div>
                        <div className="health-detail">
                          {a.alarmed
                            ? "SILENT — no heartbeat received"
                            : `${a.status} · CPU ${typeof a.cpu === "number" ? a.cpu.toFixed(1) : a.cpu}%`}
                        </div>
                      </div>
                      <div
                        className={`health-dot ${
                          a.alarmed ? "disconnected" : a.status === "degraded" ? "connecting" : "active"
                        }`}
                      />
                    </div>
                  ))
              ) : (
                <div className="empty-table-placeholder">
                  <Server size={28} className="muted-icon" />
                  <p>No agents registered yet. Waiting for first heartbeat...</p>
                </div>
              )}
            </div>
          </section>
        )}

        {/* ═══ TAB: CONSENSUS VERDICTS & TRUST FEEDBACK ═══ */}
        {activeTab === "verdicts" && (
          <section className="panel activity-panel">
            <div className="panel-header">
              <div>
                <h3 className="panel-title">
                  <Database size={16} style={{ display: "inline", verticalAlign: "-2px", marginRight: 8 }} />
                  Consensus Verdicts & Human Feedback (NeonDB)
                </h3>
                <p className="panel-subtitle">
                  Peer-weighted consensus verdicts with active admin trust calibration
                </p>
              </div>
              <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                <span className="panel-count-badge">{verdicts.length} Recorded Verdicts</span>
                <button className="btn-small-pulse" onClick={fetchVerdicts} title="Refresh verdicts from NeonDB">
                  <RefreshCw size={13} /> Refresh
                </button>
              </div>
            </div>

            <div className="table-wrapper">
              {verdicts.length > 0 ? (
                <table>
                  <thead>
                    <tr>
                      <th>Vote ID</th>
                      <th>Origin Agent</th>
                      <th>Event Type</th>
                      <th>Raw Score</th>
                      <th>Weighted Score</th>
                      <th>Severity</th>
                      <th>Action Dispatched</th>
                      <th>Peers</th>
                      <th>Admin Feedback Loop</th>
                    </tr>
                  </thead>
                  <tbody>
                    {verdicts.map((v) => (
                      <tr key={v.vote_id}>
                        <td><code>{v.vote_id.slice(0, 10)}...</code></td>
                        <td><strong>{v.origin_agent_id}</strong></td>
                        <td><span className="syscall-tag">{v.event_type}</span></td>
                        <td>
                          <span
                            className="threat-pill"
                            style={{
                              background: getThreatColor(v.raw_threat_score) + "22",
                              color: getThreatColor(v.raw_threat_score),
                              borderColor: getThreatColor(v.raw_threat_score) + "55",
                            }}
                          >
                            {((v.raw_threat_score || 0) * 100).toFixed(1)}%
                          </span>
                        </td>
                        <td>
                          <strong style={{ color: getThreatColor(v.final_weighted_score) }}>
                            {((v.final_weighted_score || 0) * 100).toFixed(1)}%
                          </strong>
                        </td>
                        <td>
                          <span className={`verdict-badge ${v.severity === "LOW" ? "normal" : "alert"}`}>
                            {v.severity}
                          </span>
                        </td>
                        <td>
                          <span className={`action-badge ${v.response_action}`}>
                            {v.response_action}
                          </span>
                        </td>
                        <td>{v.participating_peers ? v.participating_peers.length : 1}</td>
                        <td>
                          <div className="verdicts-actions-cell">
                            {v.admin_confirmed === true ? (
                              <span className="feedback-status-badge confirmed">
                                <Check size={12} /> Confirmed Threat ({v.confirmed_by || "Admin"})
                              </span>
                            ) : v.admin_confirmed === false ? (
                              <span className="feedback-status-badge false-positive">
                                <X size={12} /> False Positive ({v.confirmed_by || "Admin"})
                              </span>
                            ) : (
                              <>
                                <button
                                  className="btn-feedback confirm"
                                  onClick={() => handleTrustFeedback(v.vote_id, true)}
                                  title="Confirm malicious threat & reinforce agent trust"
                                >
                                  <ThumbsUp size={12} /> Confirm Threat
                                </button>
                                <button
                                  className="btn-feedback false-positive"
                                  onClick={() => handleTrustFeedback(v.vote_id, false)}
                                  title="Mark as false positive & decrease agent trust weight"
                                >
                                  <ThumbsDown size={12} /> False Positive
                                </button>
                              </>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="empty-table-placeholder">
                  <Database size={28} className="muted-icon" />
                  <p>No consensus verdicts recorded in NeonDB yet.</p>
                  <span>Verdicts from peer voting nodes will appear here in real time.</span>
                </div>
              )}
            </div>
          </section>
        )}

        {/* ═══ TAB: MAINTENANCE WINDOWS ═══ */}
        {activeTab === "maintenance" && (
          <section className="maintenance-container">
            {/* Schedule Form */}
            <div className="maintenance-form-panel">
              <div className="panel-header" style={{ marginBottom: 16 }}>
                <div>
                  <h3 className="panel-title">
                    <Calendar size={16} style={{ display: "inline", verticalAlign: "-2px", marginRight: 8 }} />
                    Schedule Window
                  </h3>
                  <p className="panel-subtitle">Dual-approval alarm suppression</p>
                </div>
              </div>

              <form onSubmit={handleScheduleMaintenance}>
                <div className="form-group">
                  <label className="form-label">Target Agent ID</label>
                  <input
                    className="form-input"
                    type="text"
                    value={maintForm.agent_id}
                    onChange={(e) => setMaintForm({ ...maintForm, agent_id: e.target.value })}
                    placeholder="vm1, vm2 or * for all"
                    required
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Duration (Minutes)</label>
                  <input
                    className="form-input"
                    type="number"
                    min="5"
                    max="1440"
                    value={maintForm.duration_minutes}
                    onChange={(e) => setMaintForm({ ...maintForm, duration_minutes: Number(e.target.value) })}
                    required
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Maintenance Reason</label>
                  <input
                    className="form-input"
                    type="text"
                    value={maintForm.reason}
                    onChange={(e) => setMaintForm({ ...maintForm, reason: e.target.value })}
                    placeholder="e.g. Kernel security upgrade"
                    required
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Approving Officer</label>
                  <input
                    className="form-input"
                    type="text"
                    value={maintForm.approved_by}
                    onChange={(e) => setMaintForm({ ...maintForm, approved_by: e.target.value })}
                    required
                  />
                </div>

                <button type="submit" className="btn-primary-action">
                  <Calendar size={14} /> Schedule Maintenance Window
                </button>
              </form>
            </div>

            {/* List of Windows */}
            <div className="panel" style={{ background: "#0b1019" }}>
              <div className="panel-header">
                <div>
                  <h3 className="panel-title">Active & Scheduled Windows (NeonDB)</h3>
                  <p className="panel-subtitle">Windows survive backend restarts</p>
                </div>
                <button className="btn-small-pulse" onClick={fetchMaintenance}>
                  <RefreshCw size={13} /> Refresh
                </button>
              </div>

              <div className="windows-list-grid" style={{ marginTop: 16 }}>
                {maintenanceWindows.length > 0 ? (
                  maintenanceWindows.map((w) => (
                    <div className={`window-card ${w.is_active ? "active" : ""}`} key={w.window_id}>
                      <div className="window-info-main">
                        <div className="window-title">
                          <span>Agent: <code>{w.agent_id}</code></span>
                          <span className={`window-badge ${w.is_active ? "active" : "inactive"}`}>
                            {w.is_active ? "ACTIVE SUPPRESSION" : "COMPLETED / CANCELLED"}
                          </span>
                        </div>
                        <div className="window-subtitle">
                          {w.reason} · Approved by: <strong>{w.approved_by}</strong>
                        </div>
                        <div className="window-subtitle" style={{ fontSize: 11, color: "#94a3b8" }}>
                          Window ID: <code>{w.window_id}</code> · Until {new Date(w.end_time * 1000).toLocaleTimeString("en-GB")}
                        </div>
                      </div>

                      {w.is_active && (
                        <button
                          className="btn-cancel-win"
                          onClick={() => handleCancelMaintenance(w.window_id)}
                          title="Revoke maintenance window & re-enable alerts"
                        >
                          <X size={13} /> Cancel Window
                        </button>
                      )}
                    </div>
                  ))
                ) : (
                  <div className="empty-table-placeholder">
                    <Calendar size={28} className="muted-icon" />
                    <p>No maintenance windows currently active or scheduled.</p>
                  </div>
                )}
              </div>
            </div>
          </section>
        )}

        {/* ═══ TAB: FLEET & TRUST TRACKER ═══ */}
        {activeTab === "agents" && (
          <section className="panel activity-panel">
            <div className="panel-header">
              <div>
                <h3 className="panel-title">
                  <Server size={16} style={{ display: "inline", verticalAlign: "-2px", marginRight: 8 }} />
                  Fleet Health & Consensus Trust Tracker
                </h3>
                <p className="panel-subtitle">
                  Autonomous peer voting weights dynamically scaled by historical accuracy (NeonDB)
                </p>
              </div>
              <button className="btn-small-pulse" onClick={fetchAgentTrust}>
                <RefreshCw size={13} /> Refresh Trust
              </button>
            </div>

            <div className="fleet-grid" style={{ marginTop: 18 }}>
              {Array.from(new Set([...Object.keys(agents), ...Object.keys(agentTrustMap)])).length > 0 ? (
                Array.from(new Set([...Object.keys(agents), ...Object.keys(agentTrustMap)])).map((agentId) => {
                  const live = agents[agentId] || {};
                  const dbTrust = agentTrustMap[agentId];
                  const trustScore = dbTrust?.trust_score !== undefined ? dbTrust.trust_score : 0.85;
                  const trustLevel = trustScore >= 0.85 ? "high" : trustScore >= 0.65 ? "med" : "low";

                  return (
                    <div className="agent-trust-card" key={agentId}>
                      <div className="agent-card-header">
                        <div className="agent-name-box">
                          <Server size={18} style={{ color: "#38bdf8" }} />
                          <strong>{agentId}</strong>
                        </div>
                        <span
                          className={`verdict-badge ${
                            live.alarmed ? "alert" : live.status === "degraded" ? "warning" : "normal"
                          }`}
                        >
                          {live.alarmed ? "SILENT / ALARMED" : live.status || "ACTIVE"}
                        </span>
                      </div>

                      <div className="trust-meter-container">
                        <div className="trust-meter-header">
                          <span>Consensus Trust Score (EMA)</span>
                          <strong style={{ color: trustLevel === "high" ? "#34d399" : trustLevel === "med" ? "#fbbf24" : "#f87171" }}>
                            {(trustScore * 100).toFixed(1)}%
                          </strong>
                        </div>
                        <div className="trust-meter-bar">
                          <div
                            className={`trust-meter-fill ${trustLevel}`}
                            style={{ width: `${Math.max(5, trustScore * 100)}%` }}
                          />
                        </div>
                      </div>

                      <div className="agent-stats-row">
                        <div className="agent-stat-item">
                          <span>CPU Utilization</span>
                          <strong>{live.cpu !== undefined ? `${live.cpu.toFixed(1)}%` : "N/A"}</strong>
                        </div>
                        <div className="agent-stat-item">
                          <span>Verified Events</span>
                          <strong>
                            {dbTrust ? `${dbTrust.correct_events} / ${dbTrust.total_events}` : "Initializing"}
                          </strong>
                        </div>
                        <div className="agent-stat-item">
                          <span>Voting Multiplier</span>
                          <strong>{trustScore >= 0.85 ? "2.0x (Verified)" : trustScore >= 0.65 ? "1.0x (Standard)" : "0.5x (Degraded)"}</strong>
                        </div>
                        <div className="agent-stat-item">
                          <span>Last Heartbeat</span>
                          <strong>{live.lastSeen ? formatTimestamp(live.lastSeen) : "Live"}</strong>
                        </div>
                      </div>
                    </div>
                  );
                })
              ) : (
                <div className="empty-table-placeholder">
                  <Server size={28} className="muted-icon" />
                  <p>No agents registered yet.</p>
                </div>
              )}
            </div>
          </section>
        )}

        {/* ═══ TAB: MITIGATION AUDIT LOG ═══ */}
        {activeTab === "audit" && (
          <section className="panel activity-panel">
            <div className="panel-header">
              <div>
                <h3 className="panel-title">
                  <FileText size={16} style={{ display: "inline", verticalAlign: "-2px", marginRight: 8 }} />
                  Automated Mitigation & Audit Trail (NeonDB)
                </h3>
                <p className="panel-subtitle">
                  Tamper-evident record of process kills, host isolations, and quarantine actions
                </p>
              </div>
              <button className="btn-small-pulse" onClick={fetchAudit}>
                <RefreshCw size={13} /> Refresh Audit
              </button>
            </div>

            <div className="table-wrapper">
              {auditLogs.length > 0 ? (
                <table>
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Origin Node</th>
                      <th>Action Executed</th>
                      <th>Target Identifier</th>
                      <th>Status</th>
                      <th>Details / Verdict Reference</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditLogs.map((log) => (
                      <tr key={log.id}>
                        <td>{formatTimestamp(log.executed_at)}</td>
                        <td><strong>{log.agent_id}</strong></td>
                        <td>
                          <span className={`action-badge ${log.action}`}>
                            {log.action}
                          </span>
                        </td>
                        <td>
                          <code>
                            {log.target_pid ? `PID ${log.target_pid}` : log.target_file || "Host Firewall"}
                          </code>
                        </td>
                        <td>
                          <span className={`audit-status-tag ${log.status || "SUCCESS"}`}>
                            {log.status || "SUCCESS"}
                          </span>
                        </td>
                        <td style={{ fontSize: 12, color: "#94a3b8" }}>
                          {log.details ? (typeof log.details === "object" ? JSON.stringify(log.details) : log.details) : `Ref Vote: ${log.vote_id || "N/A"}`}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="empty-table-placeholder">
                  <FileText size={28} className="muted-icon" />
                  <p>No response action audit entries found in NeonDB.</p>
                  <span>Automated response actions dispatched by AEGIS will be permanently logged here.</span>
                </div>
              )}
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
