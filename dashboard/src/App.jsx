import React, { useState, useEffect, useCallback, Component } from "react";
import {
  Activity,
  AlertTriangle,
  Bell,
  BrainCircuit,
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
  Gauge,
  Network,
  RefreshCw,
  Server,
  Shield,
  Target,
  Terminal,
  ThumbsDown,
  ThumbsUp,
  Wifi,
  X,
  Zap,
  Radio,
  Skull,
  Award,
  Globe,
  Lock,
  Key,
  UserCheck,
  ArrowRight,
  ArrowLeft,
  ArrowUp,
  Search,
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
import MitreAttackTab from "./MitreAttackTab";
import SimulationLabTab from "./SimulationLabTab";
import ReportModal from "./ReportModal";
import XAIExplanationModal from "./XAIExplanationModal";
import BenchmarkTab from "./BenchmarkTab";
import PcapReplayerTab from "./PcapReplayerTab";
import KernelCollectorsTab from "./KernelCollectorsTab";
import ComplianceAuditTab from "./ComplianceAuditTab";
import CopilotAdvisorTab from "./CopilotAdvisorTab";
import ThreatIntelTab from "./ThreatIntelTab";
import RbacAuthTab from "./RbacAuthTab";
import LivePeerVotingVisualization from "./LivePeerVotingVisualization";
import AgentMachineCockpit from "./AgentMachineCockpit";



const API_BASE = typeof window !== "undefined"
  ? `${window.location.protocol}//${window.location.hostname || "127.0.0.1"}:8000`
  : "http://127.0.0.1:8000";

const WS_BASE = typeof window !== "undefined"
  ? `${window.location.protocol === "https:" ? "wss:" : "ws:"}//${window.location.hostname || "127.0.0.1"}:8000`
  : "ws://127.0.0.1:8000";

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

function safeToISOString(ts) {
  if (!ts) return new Date().toISOString();
  try {
    if (typeof ts === "string") {
      const d = new Date(ts);
      if (!isNaN(d.getTime())) return d.toISOString();
      const num = Number(ts);
      if (!isNaN(num)) ts = num;
      else return new Date().toISOString();
    }
    if (typeof ts === "number") {
      let ms = ts;
      if (ts > 1e14) ms = Math.floor(ts / 1000000);
      else if (ts > 1e11) ms = Math.floor(ts / 1000);
      else if (ts > 1e8) ms = ts * 1000;
      const d = new Date(ms);
      if (!isNaN(d.getTime())) return d.toISOString();
    }
  } catch (e) {}
  return new Date().toISOString();
}

class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }
  componentDidCatch(error, errorInfo) {
    console.error("[AEGIS ErrorBoundary]", error, errorInfo);
  }
  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: 24, textAlign: "center", color: "#f87171", background: "rgba(239, 68, 68, 0.08)", borderRadius: 10, border: "1px solid rgba(239, 68, 68, 0.25)", margin: 16 }}>
          <h4 style={{ marginBottom: 6, color: "#f87171" }}>Unable to display view component</h4>
          <p style={{ fontSize: 12, color: "#94a3b8", marginBottom: 12 }}>{this.state.error?.message || "Render error"}</p>
          <button className="btn-small-pulse" onClick={() => this.setState({ hasError: false, error: null })}>
            Reload View
          </button>
        </div>
      );
    }
    return this.props.children;
  }
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
  const [serverHostname, setServerHostname] = useState("Izuku");
  const [serverIp, setServerIp] = useState("127.0.0.1");
  const [clock, setClock] = useState(new Date());
  const [agents, setAgents] = useState({}); // agent_id -> { agentId, status, cpu, alarmed, lastSeen, ip, os, role }

  // New Phase D States (NeonDB, Trust Feedback, Maintenance, Silence Alarms, Audit)
  const [verdicts, setVerdicts] = useState([]);
  const [telemetryRecords, setTelemetryRecords] = useState([]);
  const [isTelemetryLoading, setIsTelemetryLoading] = useState(false);
  const [selectedTelemetryForVoting, setSelectedTelemetryForVoting] = useState(null);
  const [maintenanceWindows, setMaintenanceWindows] = useState([]);
  const [silenceAlarms, setSilenceAlarms] = useState([]);
  const [agentTrustMap, setAgentTrustMap] = useState({});
  const [auditLogs, setAuditLogs] = useState([]);
  const [feedbackToast, setFeedbackToast] = useState(null);

  // System and Machine IP Telemetry Filtering States
  const [selectedSystemFilter, setSelectedSystemFilter] = useState(null);
  const [systemSearchQuery, setSystemSearchQuery] = useState("");
  const [selectedAgentForTelemetry, setSelectedAgentForTelemetry] = useState(null);

  const selectTab = (tab) => {
    setActiveTab(tab);
    setSelectedAgentForTelemetry(null);
    setSelectedSystemFilter(null);
  };
  const [maintForm, setMaintForm] = useState({
    agent_id: "*",
    duration_minutes: 60,
    reason: "Scheduled Security Patching",
    approved_by: "SecOps Admin",
  });
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);
  const [latestWsEvent, setLatestWsEvent] = useState(null);
  const [xaiModalConfig, setXaiModalConfig] = useState({
    isOpen: false,
    modelKey: "linux_ids",
    threatScore: 0.94,
    eventData: null,
  });

  const showToast = (msg) => {
    setFeedbackToast(msg);
    setTimeout(() => setFeedbackToast(null), 4500);
  };

  const fetchVerdicts = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/centralized/verdicts?limit=50`);
      const data = await res.json();
      if (data && data.verdicts) setVerdicts(data.verdicts);
    } catch (e) {
      console.error("Failed to fetch verdicts:", e);
    }
  }, []);

  const fetchTelemetry = useCallback(async () => {
    setIsTelemetryLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/centralized/telemetry?limit=50`);
      const data = await res.json();
      if (data && Array.isArray(data.telemetries)) {
        setTelemetryRecords(data.telemetries);
      }
    } catch (e) {
      console.error("Failed to fetch telemetry:", e);
    } finally {
      setIsTelemetryLoading(false);
    }
  }, []);

  const fetchMaintenance = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/maintenance/windows?active_only=false`);
      const data = await res.json();
      if (data && data.windows) setMaintenanceWindows(data.windows);
    } catch (e) {
      console.error("Failed to fetch maintenance:", e);
    }
  }, []);

  const fetchSilenceAlarms = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/alerts`);
      const data = await res.json();
      if (data && data.alerts) setSilenceAlarms(data.alerts);
    } catch (e) {
      console.error("Failed to fetch alarms:", e);
    }
  }, []);

  const fetchAgentTrust = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/agents/trust/all`);
      const data = await res.json();
      if (data && data.agents) setAgentTrustMap(data.agents);
    } catch (e) {
      console.error("Failed to fetch agent trust:", e);
    }
  }, []);

  const fetchAudit = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/audit?limit=50`);
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
    if (activeTab === "peer_voting") {
      fetchTelemetry();
      fetchVerdicts();
      if (typeof fetchAgents === "function") fetchAgents();
      fetchAgentTrust();
    }
    if (activeTab === "verdicts") fetchVerdicts();
    if (activeTab === "maintenance") fetchMaintenance();
    if (activeTab === "agents") {
      fetchAgentTrust();
      fetchSilenceAlarms();
      if (typeof fetchAgents === "function") fetchAgents();
    }
    if (activeTab === "audit") fetchAudit();
  }, [activeTab, fetchTelemetry, fetchVerdicts, fetchMaintenance, fetchAgentTrust, fetchSilenceAlarms, fetchAudit]);

  const handleTrustFeedback = async (voteId, confirmed) => {
    try {
      const res = await fetch(`${API_BASE}/api/trust/feedback`, {
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
      const res = await fetch(`${API_BASE}/api/alerts/${alarmId}/ack`, {
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
      const res = await fetch(`${API_BASE}/api/maintenance/schedule`, {
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
      const res = await fetch(`${API_BASE}/api/maintenance/cancel?window_id=${windowId}`, {
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
        const res = await fetch(`${API_BASE}/api/health`);
        const data = await res.json();
        if (data.uptime !== undefined) setServerUptime(Math.floor(data.uptime));
        if (data.platform) setHostOS(data.platform);
        if (data.hostname) setServerHostname(data.hostname);
        if (data.server_ip) setServerIp(data.server_ip);
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
  const sendTestPulse = async (aid = null) => {
    try {
      const url = aid
        ? `${API_BASE}/api/telemetry/test?agent_id=${encodeURIComponent(aid)}`
        : `${API_BASE}/api/telemetry/test`;
      await fetch(url, { method: "POST" });
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
      ws = new WebSocket(`${WS_BASE}/ws/telemetry`);

      ws.onopen = () => setWsStatus("LIVE");

      ws.onmessage = (message) => {
        try {
          const event = JSON.parse(message.data);
          setLatestWsEvent(event);

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
                ip: event.ip || prev[event.agent_id]?.ip || "127.0.0.1",
                os: event.os || prev[event.agent_id]?.os || "Unknown",
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
            setAlerts((prev) => [
              {
                id: `shutdown-${event.agent_id}-${Date.now()}`,
                severity: "warning",
                process: event.agent_id,
                agent_id: event.agent_id,
                pid: 0,
                message: `${event.agent_id} completed GRACEFUL SHUTDOWN (${event.reason || "Planned offline"})`,
                time: new Date().toLocaleTimeString("en-GB", { hour12: false }),
                tag: "GRACEFUL_SHUTDOWN",
              },
              ...prev,
            ].slice(0, 10));
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
          const agentIdTag = event.agent_id || event.agentId || "local-node";
          const agentIp = event.ip || event.source_ip || agents[agentIdTag]?.ip || "127.0.0.1";

          // Update active processes/events table
          setProcesses((prev) => {
            const updated = [
              {
                process: procName,
                agent_id: agentIdTag,
                ip: agentIp,
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
            return updated.slice(0, 20);
          });

          // Also sync live event into telemetry records stream
          setTelemetryRecords((prev) => [
            {
              id: event.id || `live-${Date.now()}-${event.pid || 0}`,
              agent_id: agentIdTag,
              ip: agentIp,
              event_type: procName,
              threat_score: threatScore,
              verdict: event.predicted_class || event.verdict || "Normal",
              received_at: new Date().toISOString(),
              payload: event,
            },
            ...prev.slice(0, 49),
          ]);

          // Generate alert if threat threshold is met
          if (threatScore >= 0.35) {
            setAlerts((prev) => [
              {
                id: `${event.timestamp}-${event.pid || Math.random()}`,
                severity: threatScore >= 0.6 ? "critical" : "warning",
                process: procName,
                agent_id: agentIdTag,
                pid: event.pid || 0,
                message: `[${modelTag}] (${agentIdTag}) Anomaly on ${procName} — ${
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
      if (ws) {
        if (ws.readyState === WebSocket.OPEN) {
          try { ws.close(); } catch (e) {}
        } else if (ws.readyState === WebSocket.CONNECTING) {
          ws.onopen = () => {
            try { ws.close(); } catch (e) {}
          };
        }
      }
    };
  }, []);

  /* Fetch initial latest state from backend */
  useEffect(() => {
    fetch(`${API_BASE}/api/telemetry/latest`)
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

  /* Fetch and poll agent heartbeat snapshot */
  const fetchAgents = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/agents`);
      if (!res.ok) return;
      const data = await res.json();
      const map = {};
      (data.agents || []).forEach((a) => {
        const isAlarmed = !!a.alarm_raised || a.status === "silent";
        const isGraceful = a.status === "OFFLINE_GRACEFUL";
        map[a.agent_id] = {
          agentId: a.agent_id,
          status: isGraceful ? "OFFLINE_GRACEFUL" : (isAlarmed ? "silent" : a.status),
          cpu: isGraceful || isAlarmed ? 0.0 : a.cpu,
          ip: a.ip || "127.0.0.1",
          os: a.os || "Unknown",
          role: a.role || (a.agent_id === serverHostname ? "Command Node (Server)" : "Endpoint Agent"),
          alarmed: isAlarmed,
          lastSeen: a.last_seen,
          reason: a.reason,
        };
      });
      setAgents(map);

      // Ensure active silent alarms are immediately reflected in Alert Feed if not already present
      (data.agents || []).forEach((a) => {
        if ((a.alarm_raised || a.status === "silent") && a.agent_id !== serverHostname) {
          setAlerts((prev) => {
            const hasRecentAlarm = prev.some(
              (al) => al.agent_id === a.agent_id && al.tag === "SILENT_ALARM"
            );
            if (!hasRecentAlarm) {
              return [
                {
                  id: `alarm-${a.agent_id}-${Date.now()}`,
                  severity: "critical",
                  process: a.agent_id,
                  agent_id: a.agent_id,
                  pid: 0,
                  message: `${a.agent_id} is SILENT — no heartbeat received`,
                  time: new Date().toLocaleTimeString("en-GB", { hour12: false }),
                  tag: "SILENT_ALARM",
                },
                ...prev,
              ].slice(0, 10);
            }
            return prev;
          });
        }
      });
    } catch (e) {}
  }, []);

  useEffect(() => {
    fetchAgents();
    const id = setInterval(fetchAgents, 3500);
    return () => clearInterval(id);
  }, [fetchAgents]);

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

  // Derive unique known systems with their IPs and statuses
  const knownSystems = (() => {
    const sysMap = new Map();
    // 1. Registered agents from heartbeat
    Object.values(agents).forEach((a) => {
      sysMap.set(a.agentId, {
        agentId: a.agentId,
        ip: a.ip || "127.0.0.1",
        os: a.os || "Unknown",
        status: a.alarmed ? "silent" : (a.status || "healthy"),
      });
    });
    // 2. Any additional origin nodes from processes
    processes.forEach((p) => {
      if (p.agent_id && !sysMap.has(p.agent_id)) {
        sysMap.set(p.agent_id, {
          agentId: p.agent_id,
          ip: p.ip || "127.0.0.1",
          os: "Unknown",
          status: "active",
        });
      }
    });
    // 3. Any additional nodes from telemetryRecords
    telemetryRecords.forEach((t) => {
      if (t.agent_id && !sysMap.has(t.agent_id)) {
        sysMap.set(t.agent_id, {
          agentId: t.agent_id,
          ip: t.ip || "127.0.0.1",
          os: "Unknown",
          status: "active",
        });
      }
    });
    return Array.from(sysMap.values()).sort((a, b) => a.agentId.localeCompare(b.agentId));
  })();

  const filteredProcesses = processes.filter((p) => {
    const agentIp = p.ip || agents[p.agent_id]?.ip || "";
    const matchesSystem = !selectedSystemFilter || p.agent_id === selectedSystemFilter;
    const q = systemSearchQuery.trim().toLowerCase();
    const matchesQuery =
      !q ||
      p.process.toLowerCase().includes(q) ||
      (p.agent_id && p.agent_id.toLowerCase().includes(q)) ||
      agentIp.toLowerCase().includes(q) ||
      String(p.pid).includes(q) ||
      (p.syscall && String(p.syscall).toLowerCase().includes(q));
    return matchesSystem && matchesQuery;
  });

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
            className={`nav-item ${activeTab === "overview" && !selectedAgentForTelemetry ? "active" : ""}`}
            onClick={() => selectTab("overview")}
          >
            <Activity size={16} />
            Security Overview
          </button>

          <button
            className={`nav-item ${activeTab === "verdicts" ? "active" : ""}`}
            onClick={() => selectTab("verdicts")}
          >
            <Database size={16} />
            Consensus & Feedback
            {verdicts.length > 0 && <span className="nav-badge">{verdicts.length}</span>}
          </button>

          <button
            className={`nav-item ${activeTab === "peer_voting" ? "active" : ""}`}
            onClick={() => selectTab("peer_voting")}
          >
            <Network size={16} />
            Live Peer Voting
            <span className="nav-badge" style={{ background: "rgba(56, 189, 248, 0.2)", color: "#38bdf8" }}>MESH</span>
          </button>

          <button
            className={`nav-item ${activeTab === "maintenance" ? "active" : ""}`}
            onClick={() => selectTab("maintenance")}
          >
            <Calendar size={16} />
            Maintenance Windows
            {maintenanceWindows.filter((w) => w.is_active).length > 0 && (
              <span className="nav-badge">{maintenanceWindows.filter((w) => w.is_active).length}</span>
            )}
          </button>

          <button
            className={`nav-item ${activeTab === "agents" ? "active" : ""}`}
            onClick={() => selectTab("agents")}
          >
            <Server size={16} />
            Fleet & Trust Tracker
            {silenceAlarms.length > 0 && <span className="nav-badge alert">{silenceAlarms.length}</span>}
          </button>

          <button
            className={`nav-item ${activeTab === "audit" ? "active" : ""}`}
            onClick={() => selectTab("audit")}
          >
            <FileText size={16} />
            Mitigation Audit Log
          </button>

          <div className="nav-section" style={{ marginTop: 14 }}>TELEMETRY</div>

          <button
            className={`nav-item ${activeTab === "processes" ? "active" : ""}`}
            onClick={() => selectTab("processes")}
          >
            <Cpu size={16} />
            Live Processes
            {processes.length > 0 && <span className="nav-badge">{processes.length}</span>}
          </button>

          <button
            className={`nav-item ${activeTab === "detections" ? "active" : ""}`}
            onClick={() => selectTab("detections")}
          >
            <AlertTriangle size={16} />
            Threat Detections
            {alerts.length > 0 && <span className="nav-badge alert">{alerts.length}</span>}
          </button>

          <button
            className={`nav-item ${activeTab === "models" ? "active" : ""}`}
            onClick={() => selectTab("models")}
          >
            <Shield size={16} />
            ML Inference Engine
          </button>

          <button
            className={`nav-item ${activeTab === "mitre" ? "active" : ""}`}
            onClick={() => selectTab("mitre")}
          >
            <Target size={16} />
            MITRE ATT&amp;CK Matrix
          </button>

          <button
            className={`nav-item ${activeTab === "simulation" ? "active" : ""}`}
            onClick={() => selectTab("simulation")}
          >
            <Zap size={16} />
            Red Team Simulation Lab
          </button>

          <button
            className={`nav-item ${activeTab === "benchmark" ? "active" : ""}`}
            onClick={() => selectTab("benchmark")}
          >
            <Gauge size={16} />
            System Benchmarks
          </button>

          <button
            className={`nav-item ${activeTab === "pcap" ? "active" : ""}`}
            onClick={() => selectTab("pcap")}
          >
            <Radio size={16} />
            PCAP Capture & Replayer
          </button>

          <div className="nav-section" style={{ marginTop: 14 }}>ENTERPRISE &amp; WARFARE</div>

          <button
            className={`nav-item ${activeTab === "kernel" ? "active" : ""}`}
            onClick={() => selectTab("kernel")}
          >
            <Cpu size={16} />
            Kernel eBPF &amp; ETW
          </button>

          <button
            className={`nav-item ${activeTab === "copilot_advisor" ? "active" : ""}`}
            onClick={() => selectTab("copilot_advisor")}
          >
            <BrainCircuit size={16} />
            AI Copilot &amp; Playbooks
          </button>

          <button
            className={`nav-item ${activeTab === "threat_intel" ? "active" : ""}`}
            onClick={() => selectTab("threat_intel")}
          >
            <Globe size={16} />
            Threat Intel (STIX/TAXII)
          </button>

          <button
            className={`nav-item ${activeTab === "rbac_auth" ? "active" : ""}`}
            onClick={() => selectTab("rbac_auth")}
          >
            <Lock size={16} />
            SOC RBAC &amp; Access Control
          </button>

          <button
            className={`nav-item ${activeTab === "compliance_tab" ? "active" : ""}`}
            onClick={() => selectTab("compliance_tab")}
          >
            <Award size={16} />
            Compliance &amp; Audit PDF
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
            <button
              className="btn-test-pulse"
              onClick={() =>
                setXaiModalConfig({
                  isOpen: true,
                  modelKey: "linux_ids",
                  threatScore: 0.97,
                  eventData: latestEvent,
                })
              }
              style={{
                background: "linear-gradient(135deg, rgba(168, 85, 247, 0.2) 0%, rgba(139, 92, 246, 0.3) 100%)",
                border: "1px solid rgba(168, 85, 247, 0.5)",
                color: "#c084fc",
              }}
              title="Explain Model Predictions via SHAP Feature Attributions"
            >
              <BrainCircuit size={14} /> Explain AI (XAI)
            </button>

            <button
              className="btn-test-pulse"
              onClick={() => setIsReportModalOpen(true)}
              style={{
                background: "linear-gradient(135deg, rgba(59, 130, 246, 0.2) 0%, rgba(37, 99, 235, 0.3) 100%)",
                border: "1px solid rgba(59, 130, 246, 0.5)",
                color: "#38bdf8",
              }}
              title="Generate Executive / Incident Compliance PDF Report"
            >
              <FileText size={14} /> Export Security Report
            </button>

            <a
              href="http://localhost:5174"
              target="_blank"
              rel="noreferrer"
              className="btn-test-pulse"
              style={{
                background: "linear-gradient(135deg, rgba(239, 68, 68, 0.25) 0%, rgba(185, 28, 28, 0.35) 100%)",
                border: "1px solid rgba(239, 68, 68, 0.6)",
                color: "#f87171",
                textDecoration: "none",
                fontWeight: "700",
                display: "inline-flex",
                alignItems: "center",
                gap: "6px",
              }}
              title="Open Standalone Red Team Adversary C2 Attack Dashboard (Port 5174)"
            >
              <Skull size={14} /> Attacker C2 Console
            </a>

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

        {/* ═══ CONDITIONAL FULL-PAGE AGENT MACHINE COCKPIT ═══ */}
        {selectedAgentForTelemetry ? (
          <AgentMachineCockpit
            agentId={selectedAgentForTelemetry}
            agents={agents}
            onSelectAgent={(id) => {
              setSelectedAgentForTelemetry(id);
              setSelectedSystemFilter(id);
            }}
            onClose={() => {
              setSelectedAgentForTelemetry(null);
              setSelectedSystemFilter(null);
            }}
            processes={processes}
            telemetryRecords={telemetryRecords}
            alerts={alerts}
            agentTrustMap={agentTrustMap}
            maintenanceWindows={maintenanceWindows}
            silenceAlarms={silenceAlarms}
            sendTestPulse={sendTestPulse}
            onInspectProcess={(t) => setSelectedProcess(t)}
            API_BASE={API_BASE}
          />
        ) : (
          <>
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
                  <h3 className="panel-title">
                    {latestEvent?.model
                      ? `${latestEvent.model.replace(/_/g, " ").toUpperCase()} Pipeline`
                      : "Multi-Model Threat Pipeline"}
                  </h3>
                  <p className="panel-subtitle">
                    {latestEvent?.model === "cicids"
                      ? "Live Network Flow Anomaly Classification"
                      : latestEvent?.model?.startsWith("windows")
                      ? "Windows Process Context & ETW Telemetry"
                      : latestEvent?.model === "linux_ids"
                      ? "Syscall classification probabilities"
                      : "Autonomous EDR Multi-Model Telemetry"}
                  </p>
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
            <div className="panel-header" style={{ flexWrap: "wrap", gap: 12 }}>
              <div>
                <h3 className="panel-title">
                  <Activity size={16} style={{ display: "inline", verticalAlign: "-2px", marginRight: 8, color: "#38bdf8" }} />
                  Live Process Telemetry
                </h3>
                <p className="panel-subtitle">Monitored process syscall windows across connected systems</p>
              </div>

              <div className="telemetry-filter-controls">
                {/* System / Machine Dropdown Filter */}
                <div className="system-filter-box" title="Filter telemetry by specific system machine IP">
                  <Filter size={13} style={{ color: "#38bdf8" }} />
                  <select
                    className="system-select-dropdown"
                    value={selectedSystemFilter || "ALL"}
                    onChange={(e) => {
                      const val = e.target.value === "ALL" ? null : e.target.value;
                      setSelectedSystemFilter(val);
                      setSelectedAgentForTelemetry(val);
                    }}
                  >
                    <option value="ALL">All Systems &amp; IPs ({knownSystems.length})</option>
                    {knownSystems.map((sys) => (
                      <option key={sys.agentId} value={sys.agentId}>
                        {sys.agentId} — IP: {sys.ip} {sys.os !== "Unknown" ? `(${sys.os})` : ""}
                      </option>
                    ))}
                  </select>
                </div>

                {/* Instant Search input */}
                <div className="system-search-box">
                  <Search size={13} style={{ color: "#64748b" }} />
                  <input
                    type="text"
                    placeholder="Search system, IP, PID..."
                    value={systemSearchQuery}
                    onChange={(e) => setSystemSearchQuery(e.target.value)}
                    className="system-search-input"
                  />
                  {systemSearchQuery && (
                    <button
                      className="btn-clear-chip"
                      onClick={() => setSystemSearchQuery("")}
                      title="Clear search"
                    >
                      ✕
                    </button>
                  )}
                </div>

                <span className="panel-count-badge">
                  {filteredProcesses.length} / {processes.length} Processes
                </span>
              </div>
            </div>

            {/* Active filter chip if filtering */}
            {selectedSystemFilter && (
              <div className="active-filter-banner">
                <span className="active-filter-label">
                  <Wifi size={13} />
                  Filtered to Machine: <strong>{selectedSystemFilter}</strong>
                  <span className="filter-ip-tag">
                    IP: {agents[selectedSystemFilter]?.ip || knownSystems.find((s) => s.agentId === selectedSystemFilter)?.ip || "127.0.0.1"}
                  </span>
                </span>
                <button
                  className="btn-reset-filter"
                  onClick={() => {
                    setSelectedSystemFilter(null);
                    setSelectedAgentForTelemetry(null);
                  }}
                  title="Clear system filter"
                >
                  ✕ Show All Machines
                </button>
              </div>
            )}

            <div className="table-wrapper">
              {filteredProcesses.length > 0 ? (
                <table>
                  <thead>
                    <tr>
                      <th>Process Name</th>
                      <th>Origin Machine &amp; IP</th>
                      <th>PID</th>
                      <th>UID</th>
                      <th>Last Syscall / Port</th>
                      <th>Threat Score</th>
                      <th>Prediction</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredProcesses.map((p) => {
                      const machineIp = p.ip || agents[p.agent_id]?.ip || knownSystems.find((s) => s.agentId === p.agent_id)?.ip || "127.0.0.1";
                      return (
                        <tr key={`${p.pid}-${p.process}-${p.agent_id}`} className={p.threat_score >= 0.35 ? "highlight-row" : ""}>
                          <td>
                            <div className="process-cell">
                              <Terminal size={15} className="process-icon" />
                              <strong>{p.process}</strong>
                            </div>
                          </td>
                          <td>
                            <div className="origin-machine-badge" title={`Machine IP: ${machineIp}`}>
                              <span className="origin-agent-name">{p.agent_id || "node"}</span>
                              <span
                                className="origin-ip-chip"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setSelectedSystemFilter(p.agent_id);
                                  setSelectedAgentForTelemetry(p.agent_id);
                                }}
                                title="Click to filter to this machine"
                              >
                                <Wifi size={10} /> {machineIp}
                              </span>
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
                              onClick={() => setSelectedProcess({ ...p, ip: machineIp })}
                              title="Inspect full payload"
                            >
                              <Eye size={14} /> Inspect
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              ) : (
                <div className="empty-table-placeholder">
                  <Terminal size={28} className="muted-icon" />
                  <p>
                    {selectedSystemFilter
                      ? `No process telemetry recorded for system "${selectedSystemFilter}".`
                      : "No active process telemetry recorded."}
                  </p>
                  {selectedSystemFilter && (
                    <button
                      className="btn-small-pulse"
                      style={{ marginTop: 8 }}
                      onClick={() => {
                        setSelectedSystemFilter(null);
                        setSelectedAgentForTelemetry(null);
                        setSystemSearchQuery("");
                      }}
                    >
                      Reset Filter (Show All)
                    </button>
                  )}
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
                  Agent Health Monitor &amp; Live Telemetry Inspector
                </h3>
                <p className="panel-subtitle">
                  LAN heartbeat status per machine — Click any agent to inspect its isolated telemetry stream
                </p>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                {selectedAgentForTelemetry && (
                  <button
                    className="btn-reset-filter"
                    onClick={() => {
                      setSelectedAgentForTelemetry(null);
                      setSelectedSystemFilter(null);
                    }}
                    title="Clear agent filter"
                  >
                    ✕ Close Selected ({selectedAgentForTelemetry})
                  </button>
                )}
                <div className="panel-badge">{Object.keys(agents).length} AGENTS</div>
              </div>
            </div>

            <div className="health-list">
              {Object.keys(agents).length > 0 ? (
                Object.values(agents)
                  .sort((a, b) => a.agentId.localeCompare(b.agentId))
                  .map((a) => {
                    const isSelected = selectedAgentForTelemetry === a.agentId;
                    const agentIp = a.ip || "127.0.0.1";

                    // Collect telemetry events belonging to this agent
                    const agentEvents = [
                      ...processes.filter((p) => p.agent_id === a.agentId),
                      ...telemetryRecords
                        .filter((r) => r.agent_id === a.agentId)
                        .map((r) => ({
                          process: r.event_type || r.payload?.process || "Telemetry Event",
                          agent_id: r.agent_id,
                          ip: r.ip || agentIp,
                          pid: r.payload?.pid ?? "N/A",
                          syscall: r.payload?.syscall || "sys_enter",
                          threat_score: r.threat_score ?? 0.0,
                          predicted_class: r.verdict || "Normal",
                          timestamp: r.received_at,
                          payload: r.payload,
                        })),
                    ];

                    // Deduplicate events by process + pid + timestamp
                    const dedupedAgentEvents = [];
                    const seenEvt = new Set();
                    agentEvents.forEach((ev) => {
                      const k = `${ev.process}-${ev.pid}-${ev.timestamp}`;
                      if (!seenEvt.has(k)) {
                        seenEvt.add(k);
                        dedupedAgentEvents.push(ev);
                      }
                    });

                    return (
                      <div key={a.agentId} className={`agent-card-wrapper ${isSelected ? "is-selected" : ""}`}>
                        <div
                          className={`health-item clickable ${isSelected ? "selected-agent" : ""}`}
                          onClick={() => {
                            if (isSelected) {
                              setSelectedAgentForTelemetry(null);
                              setSelectedSystemFilter(null);
                            } else {
                              setSelectedAgentForTelemetry(a.agentId);
                              setSelectedSystemFilter(a.agentId);
                            }
                          }}
                          title={`Click to ${isSelected ? "collapse" : "expand"} telemetry listing for ${a.agentId} (${agentIp})`}
                        >
                          <Server size={18} className="health-icon" />
                          <div className="health-info">
                            <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                              <span className="health-name">{a.agentId}</span>
                              <span className="agent-ip-pill" title={`Observed IP address for ${a.agentId}`}>
                                <Wifi size={11} /> {agentIp}
                              </span>
                              {a.os && a.os !== "Unknown" && (
                                <span className="agent-os-pill">{a.os}</span>
                              )}
                              <span className="agent-telemetry-count-badge">
                                {dedupedAgentEvents.length} Telemetries
                              </span>
                              {isSelected && (
                                <span className="active-agent-badge">
                                  SHOWING TELEMETRY (CLICK TO CLOSE)
                                </span>
                              )}
                            </div>
                            <div className="health-detail">
                              {a.alarmed || a.status === "silent" ? (
                                <span style={{ color: "#f87171", fontWeight: 600 }}>
                                  SILENT / UNRESPONSIVE — Heartbeat lost (Silence Alarm Active)
                                </span>
                              ) : a.status === "OFFLINE_GRACEFUL" ? (
                                <span style={{ color: "#94a3b8", fontWeight: 500 }}>
                                  OFFLINE (GRACEFUL) — Planned shutdown recorded ({a.reason || "OS service stopped"})
                                </span>
                              ) : (
                                <span style={{ color: "#34d399" }}>
                                  {`${(a.status || "healthy").toUpperCase()} · CPU ${typeof a.cpu === "number" ? a.cpu.toFixed(1) : a.cpu}% · Heartbeat verified`}
                                </span>
                              )}
                            </div>
                          </div>
                          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                            <button
                              className="btn-open-cockpit"
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedAgentForTelemetry(a.agentId);
                                setSelectedSystemFilter(a.agentId);
                              }}
                              title={`Inspect full machine cockpit, telemetry stream & ECG heartbeat for ${a.agentId}`}
                            >
                              <Activity size={12} />
                              <span>Inspect Cockpit &amp; ECG ↗</span>
                            </button>
                            <div
                              className={`health-dot ${
                                a.alarmed || a.status === "silent"
                                  ? "disconnected"
                                  : a.status === "OFFLINE_GRACEFUL"
                                  ? "offline-graceful"
                                  : a.status === "degraded"
                                  ? "connecting"
                                  : "active"
                              }`}
                              title={
                                a.alarmed || a.status === "silent"
                                  ? "Silent Alarm: Agent lost heartbeat"
                                  : a.status === "OFFLINE_GRACEFUL"
                                  ? "Offline: Graceful shutdown recorded"
                                  : "Healthy: Live heartbeat receiving"
                              }
                            />
                          </div>
                        </div>
                      </div>
                    );
                  })
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

        {/* ═══ TAB: LIVE PEER VOTING & TELEMETRY TABLE ═══ */}
        {activeTab === "peer_voting" && (
          <ErrorBoundary>
            <section className="content-grid" style={{ display: "block" }}>
            <LivePeerVotingVisualization
              liveVerdicts={verdicts}
              selectedTelemetry={selectedTelemetryForVoting}
              onBack={selectedTelemetryForVoting ? () => setSelectedTelemetryForVoting(null) : null}
              agents={agents}
              agentTrustMap={agentTrustMap}
              telemetryRecords={telemetryRecords}
              apiBase={API_BASE}
              serverHostname={serverHostname}
              serverIp={serverIp}
              serverOS={hostOS}
            />

            <div className="panel full-width" style={{ marginTop: 20 }}>
              <div className="panel-header" style={{ flexWrap: "wrap", gap: 12 }}>
                <div>
                  <h3 className="panel-title" style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <Network size={18} style={{ color: "#38bdf8" }} />
                    Live Peer Voting Telemetry Feed
                  </h3>
                  <p className="panel-subtitle">
                    Active endpoint telemetry records and P2P Byzantine consensus verdicts. Click any telemetry row to view its distributed peer-voting correlation above.
                  </p>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                  {/* System / Machine Dropdown Filter */}
                  <div className="system-filter-box" title="Filter peer voting telemetry by machine IP">
                    <Filter size={13} style={{ color: "#38bdf8" }} />
                    <select
                      className="system-select-dropdown"
                      value={selectedSystemFilter || "ALL"}
                      onChange={(e) => {
                        const val = e.target.value === "ALL" ? null : e.target.value;
                        setSelectedSystemFilter(val);
                        setSelectedAgentForTelemetry(val);
                      }}
                    >
                      <option value="ALL">All Systems &amp; IPs ({knownSystems.length})</option>
                      {knownSystems.map((sys) => (
                        <option key={sys.agentId} value={sys.agentId}>
                          {sys.agentId} — IP: {sys.ip} {sys.os !== "Unknown" ? `(${sys.os})` : ""}
                        </option>
                      ))}
                    </select>
                  </div>

                  {/* Search box */}
                  <div className="system-search-box">
                    <Search size={13} style={{ color: "#64748b" }} />
                    <input
                      type="text"
                      placeholder="Search telemetry, IP, PID..."
                      value={systemSearchQuery}
                      onChange={(e) => setSystemSearchQuery(e.target.value)}
                      className="system-search-input"
                    />
                    {systemSearchQuery && (
                      <button
                        className="btn-clear-chip"
                        onClick={() => setSystemSearchQuery("")}
                        title="Clear search"
                      >
                        ✕
                      </button>
                    )}
                  </div>

                  <button
                    className="btn-badge-chip"
                    onClick={() => {
                      fetchTelemetry();
                      fetchVerdicts();
                    }}
                    disabled={isTelemetryLoading}
                    title="Refresh telemetry and verdict records"
                    style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
                  >
                    <RefreshCw size={13} className={isTelemetryLoading ? "spin-icon" : ""} />
                    {isTelemetryLoading ? "Refreshing..." : "Refresh"}
                  </button>
                  {selectedTelemetryForVoting && (
                    <button
                      className="btn-badge-chip"
                      onClick={() => setSelectedTelemetryForVoting(null)}
                      style={{ color: "#38bdf8", borderColor: "rgba(56, 189, 248, 0.4)" }}
                      title="Reset visualization to general peer topology"
                    >
                      Reset to General Topology
                    </button>
                  )}
                </div>
              </div>

              {/* Active filter chip if filtering */}
              {selectedSystemFilter && (
                <div className="active-filter-banner" style={{ margin: "10px 14px 0" }}>
                  <span className="active-filter-label">
                    <Wifi size={13} />
                    Filtered to Machine: <strong>{selectedSystemFilter}</strong>
                    <span className="filter-ip-tag">
                      IP: {agents[selectedSystemFilter]?.ip || knownSystems.find((s) => s.agentId === selectedSystemFilter)?.ip || "127.0.0.1"}
                    </span>
                  </span>
                  <button
                    className="btn-reset-filter"
                    onClick={() => {
                      setSelectedSystemFilter(null);
                      setSelectedAgentForTelemetry(null);
                    }}
                    title="Clear system filter"
                  >
                    ✕ Show All Machines
                  </button>
                </div>
              )}

              <div className="table-wrapper" style={{ marginTop: 14 }}>
                {(() => {
                  // Combine backend telemetry records with live processes and verdicts
                  const combinedRows = [];
                  const seenKeys = new Set();

                  // 1. Backend stored/live telemetries
                  telemetryRecords.forEach((item) => {
                    const payload = item.payload || {};
                    const pid = payload.pid ?? item.pid ?? (typeof payload.process_id === "number" ? payload.process_id : null);
                    const tName = item.event_type || payload.process || payload.process_name || payload.model || "System Telemetry";
                    const score = typeof item.threat_score === "number" ? item.threat_score : (typeof payload.threat_score === "number" ? payload.threat_score : 0.0);
                    const key = `${tName}-${pid ?? item.id}`;
                    seenKeys.add(key);

                    // Match associated verdict if available
                    const matchedVerdict = verdicts.find(
                      (v) => (v && v.details && v.details.pid === pid) || (v && v.event_type === item.event_type) || (v && v.origin_agent_id === item.agent_id)
                    );

                    const verdictText = matchedVerdict
                      ? (matchedVerdict.severity || matchedVerdict.verdict_type || "CONSENSUS_VERDICT")
                      : (item.verdict || (score >= 0.75 ? "CRITICAL" : score >= 0.5 ? "SUSPICIOUS" : "NORMAL"));

                    const votingStatus = matchedVerdict
                      ? (matchedVerdict.consensus_reached ? "QUORUM_REACHED" : "PARTIAL_QUORUM")
                      : (score >= 0.5 ? "VOTING_IN_PROGRESS" : "VERIFIED_BENIGN");

                    const rowAid = item.agent_id || "agent-linux-01";
                    const rowIp = item.ip || payload.ip || agents[rowAid]?.ip || "127.0.0.1";

                    combinedRows.push({
                      id: item.id || key,
                      name: tName,
                      pid: pid,
                      agent_id: rowAid,
                      ip: rowIp,
                      threat_score: score,
                      peer_voting_verdict: verdictText,
                      voting_status: votingStatus,
                      timestamp: safeToISOString(item.received_at || payload.timestamp),
                      target: payload.process || payload.file_path || payload.target_file || tName,
                      verdict_obj: matchedVerdict || null,
                    });
                  });

                  // 2. Active processes in memory from live stream
                  processes.forEach((proc) => {
                    const key = `${proc.process}-${proc.pid}`;
                    if (!seenKeys.has(key)) {
                      seenKeys.add(key);
                      const matchedVerdict = verdicts.find(
                        (v) => (v && v.details && v.details.pid === proc.pid) || (v && v.event_type === proc.process)
                      );

                      const verdictText = matchedVerdict
                        ? (matchedVerdict.severity || matchedVerdict.verdict_type)
                        : (proc.predicted_class || (proc.threat_score >= 0.75 ? "CRITICAL" : proc.threat_score >= 0.5 ? "SUSPICIOUS" : "NORMAL"));

                      const votingStatus = matchedVerdict
                        ? (matchedVerdict.consensus_reached ? "QUORUM_REACHED" : "PARTIAL_QUORUM")
                        : (proc.threat_score >= 0.5 ? "VOTING_IN_PROGRESS" : "VERIFIED_BENIGN");

                      const procAid = proc.agent_id || "agent-node-01";
                      const procIp = proc.ip || agents[procAid]?.ip || "127.0.0.1";

                      combinedRows.push({
                        id: `proc-${proc.pid}-${proc.process}`,
                        name: proc.process,
                        pid: proc.pid,
                        agent_id: procAid,
                        ip: procIp,
                        threat_score: proc.threat_score,
                        peer_voting_verdict: verdictText,
                        voting_status: votingStatus,
                        timestamp: safeToISOString(proc.timestamp),
                        target: proc.process,
                        verdict_obj: matchedVerdict || null,
                      });
                    }
                  });

                  // 3. Fallback: historical verdicts from NeonDB
                  if (combinedRows.length === 0 && verdicts.length > 0) {
                    verdicts.forEach((v) => {
                      if (!v) return;
                      const pid = v.details?.pid ?? (v.target_pid || null);
                      const vAid = v.origin_agent_id || "agent-linux";
                      const vIp = v.ip || agents[vAid]?.ip || "127.0.0.1";
                      combinedRows.push({
                        id: v.vote_id,
                        name: v.event_type || "Telemetry Event",
                        pid: pid,
                        agent_id: vAid,
                        ip: vIp,
                        threat_score: v.final_weighted_score ?? v.raw_threat_score ?? 0.0,
                        peer_voting_verdict: v.severity || (v.consensus_reached ? "CONSENSUS_REACHED" : "EVALUATED"),
                        voting_status: v.consensus_reached ? "QUORUM_REACHED" : "PARTIAL_QUORUM",
                        timestamp: safeToISOString(v.timestamp),
                        target: v.event_type,
                        verdict_obj: v,
                      });
                    });
                  }

                  // Apply active system and search filters
                  const filteredRows = combinedRows.filter((row) => {
                    const matchesSystem = !selectedSystemFilter || row.agent_id === selectedSystemFilter;
                    const q = systemSearchQuery.trim().toLowerCase();
                    const rowIp = row.ip || agents[row.agent_id]?.ip || "";
                    const matchesQuery =
                      !q ||
                      row.name.toLowerCase().includes(q) ||
                      (row.agent_id && row.agent_id.toLowerCase().includes(q)) ||
                      rowIp.toLowerCase().includes(q) ||
                      (row.pid !== null && String(row.pid).includes(q)) ||
                      (row.peer_voting_verdict && row.peer_voting_verdict.toLowerCase().includes(q));
                    return matchesSystem && matchesQuery;
                  });

                  if (filteredRows.length === 0) {
                    return (
                      <div className="empty-table-placeholder" style={{ padding: "30px 20px" }}>
                        <Network size={30} className="muted-icon" style={{ color: "#38bdf8", opacity: 0.7 }} />
                        <p style={{ marginTop: 10, fontSize: 14, fontWeight: 600 }}>
                          {selectedSystemFilter
                            ? `No peer voting telemetry found for system "${selectedSystemFilter}".`
                            : "Awaiting Telemetry Ingress"}
                        </p>
                        <span style={{ fontSize: 12, color: "#64748b" }}>
                          {selectedSystemFilter ? (
                            <button
                              className="btn-small-pulse"
                              style={{ marginTop: 8 }}
                              onClick={() => {
                                setSelectedSystemFilter(null);
                                setSelectedAgentForTelemetry(null);
                                setSystemSearchQuery("");
                              }}
                            >
                              Reset System Filter
                            </button>
                          ) : (
                            "Trigger a test telemetry pulse or run endpoint agents to populate live records."
                          )}
                        </span>
                      </div>
                    );
                  }

                  return (
                    <table className="aegis-table">
                      <thead>
                        <tr>
                          <th>Telemetry Name</th>
                          <th>PID</th>
                          <th>Threat Score</th>
                          <th>Peer Voting Verdict</th>
                          <th>Voting Status</th>
                          <th>Timestamp</th>
                          <th style={{ textAlign: "right" }}>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredRows.map((row) => {
                          const threatColor = getThreatColor(row.threat_score);
                          const isQuorumReached = row.voting_status === "QUORUM_REACHED" || row.voting_status === "CONSENSUS_REACHED";
                          const isPending = row.voting_status === "VOTING_IN_PROGRESS" || row.voting_status === "PARTIAL_QUORUM";

                          return (
                            <tr
                              key={row.id}
                              onClick={() => setSelectedTelemetryForVoting(row)}
                              style={{ cursor: "pointer", transition: "background 0.15s ease" }}
                              className="telemetry-clickable-row"
                              title="Click to view distributed peer voting visualization for this record"
                            >
                              <td>
                                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                  <span style={{ width: 8, height: 8, borderRadius: "50%", background: threatColor }} />
                                  <strong>{row.name}</strong>
                                  {row.agent_id && (
                                    <span
                                      style={{
                                        fontSize: 10,
                                        color: "#38bdf8",
                                        background: "rgba(56, 189, 248, 0.1)",
                                        padding: "2px 6px",
                                        borderRadius: 4,
                                        border: "1px solid rgba(56, 189, 248, 0.25)",
                                        fontFamily: "JetBrains Mono, Consolas, monospace",
                                      }}
                                      title={`Machine IP: ${row.ip || agents[row.agent_id]?.ip || "127.0.0.1"}`}
                                    >
                                      {row.agent_id} · {row.ip || agents[row.agent_id]?.ip || "127.0.0.1"}
                                    </span>
                                  )}
                                </div>
                              </td>
                              <td>
                                <code>{row.pid !== null && row.pid !== undefined ? row.pid : "N/A"}</code>
                              </td>
                              <td>
                                <span
                                  className="threat-pill"
                                  style={{
                                    background: `${threatColor}1f`,
                                    color: threatColor,
                                    borderColor: `${threatColor}55`,
                                    display: "inline-block",
                                    fontWeight: 700,
                                    padding: "2px 8px",
                                    borderRadius: 4,
                                    border: "1px solid",
                                  }}
                                >
                                  {((row.threat_score || 0) * 100).toFixed(1)}%
                                </span>
                              </td>
                              <td>
                                <span
                                  className={`verdict-badge ${row.peer_voting_verdict === "LOW" || row.peer_voting_verdict === "NORMAL" || row.peer_voting_verdict === "VERIFIED_BENIGN" ? "normal" : "alert"}`}
                                >
                                  {row.peer_voting_verdict}
                                </span>
                              </td>
                              <td>
                                <span
                                  style={{
                                    display: "inline-flex",
                                    alignItems: "center",
                                    gap: 6,
                                    fontSize: 11,
                                    fontWeight: 600,
                                    padding: "3px 8px",
                                    borderRadius: 12,
                                    background: isQuorumReached ? "rgba(16, 185, 129, 0.15)" : isPending ? "rgba(56, 189, 248, 0.15)" : "rgba(100, 116, 139, 0.15)",
                                    color: isQuorumReached ? "#10b981" : isPending ? "#38bdf8" : "#94a3b8",
                                    border: `1px solid ${isQuorumReached ? "rgba(16, 185, 129, 0.3)" : isPending ? "rgba(56, 189, 248, 0.3)" : "rgba(100, 116, 139, 0.3)"}`,
                                  }}
                                >
                                  <span style={{ width: 6, height: 6, borderRadius: "50%", background: isQuorumReached ? "#10b981" : isPending ? "#38bdf8" : "#94a3b8" }} />
                                  {row.voting_status}
                                </span>
                              </td>
                              <td style={{ fontSize: 12, color: "#94a3b8", fontFamily: "JetBrains Mono, monospace" }}>
                                {typeof row.timestamp === "string" && row.timestamp.includes("T")
                                  ? row.timestamp.replace("T", " ").slice(0, 19)
                                  : row.timestamp}
                              </td>
                              <td style={{ textAlign: "right" }}>
                                <button
                                  className="btn-badge-chip"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setSelectedTelemetryForVoting(row);
                                  }}
                                  style={{
                                    display: "inline-flex",
                                    alignItems: "center",
                                    gap: 4,
                                    borderColor: "rgba(56, 189, 248, 0.4)",
                                    color: "#38bdf8",
                                  }}
                                >
                                  Inspect In Mesh <ArrowRight size={12} />
                                </button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  );
                })()}
              </div>
            </div>
          </section>
        </ErrorBoundary>
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
                    placeholder="node-1, node-2 or * for all"
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
          </>
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

                  <div className="modal-stat">
                    <span className="stat-key">Origin Machine &amp; IP</span>
                    <strong className="stat-val" style={{ color: "#38bdf8", fontFamily: "JetBrains Mono, monospace" }}>
                      {selectedProcess.agent_id || "node"} ({selectedProcess.ip || agents[selectedProcess.agent_id]?.ip || "127.0.0.1"})
                    </strong>
                  </div>
                </div>

                <div style={{ margin: "14px 0" }}>
                  <button
                    onClick={() =>
                      setXaiModalConfig({
                        isOpen: true,
                        modelKey: selectedProcess.model || "linux_ids",
                        threatScore: selectedProcess.threat_score || 0.94,
                        eventData: selectedProcess,
                      })
                    }
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "8px",
                      width: "100%",
                      justifyContent: "center",
                      background: "linear-gradient(135deg, rgba(168, 85, 247, 0.2) 0%, rgba(139, 92, 246, 0.3) 100%)",
                      border: "1px solid rgba(168, 85, 247, 0.5)",
                      color: "#c084fc",
                      padding: "10px",
                      borderRadius: "6px",
                      fontWeight: "700",
                      fontSize: "0.85rem",
                      cursor: "pointer",
                    }}
                  >
                    <BrainCircuit size={16} />
                    Drill Down Feature Attributions (SHAP Waterfall)
                  </button>
                </div>

                <div className="modal-section-title">Raw Telemetry Event Payload</div>
                <pre className="json-code">
                  {JSON.stringify(selectedProcess, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        )}

        {/* TAB: MITRE ATT&CK MATRIX */}
        {activeTab === "mitre" && (
          <section className="content-grid" style={{ display: "block" }}>
            <MitreAttackTab />
          </section>
        )}

        {/* TAB: RED TEAM SIMULATION LAB */}
        {activeTab === "simulation" && (
          <section className="content-grid" style={{ display: "block" }}>
            <SimulationLabTab apiBase="http://127.0.0.1:8000" wsData={latestWsEvent} />
          </section>
        )}

        {/* TAB: SYSTEM BENCHMARKS */}
        {activeTab === "benchmark" && (
          <section className="content-grid" style={{ display: "block" }}>
            <BenchmarkTab apiBase="http://127.0.0.1:8000" />
          </section>
        )}

        {/* TAB: PCAP REPLAYER & FLOW INSPECTOR */}
        {activeTab === "pcap" && (
          <section className="content-grid" style={{ display: "block" }}>
            <PcapReplayerTab
              apiBase="http://127.0.0.1:8000"
              onOpenXAI={({ model, threatScore, eventData }) => {
                setXaiModalConfig({
                  isOpen: true,
                  modelKey: model || "cicids",
                  threatScore: threatScore || 0.92,
                  eventData: eventData || null,
                });
              }}
            />
          </section>
        )}

        {/* TAB: KERNEL eBPF & ETW TELEMETRY */}
        {activeTab === "kernel" && (
          <section className="content-grid" style={{ display: "block" }}>
            <KernelCollectorsTab />
          </section>
        )}

        {/* TAB: COMPLIANCE & AUDIT REPORTING */}
        {activeTab === "compliance_tab" && (
          <section className="content-grid" style={{ display: "block" }}>
            <ComplianceAuditTab />
          </section>
        )}

        {/* TAB: AI INCIDENT INVESTIGATION COPILOT */}
        {activeTab === "copilot_advisor" && (
          <section className="content-grid" style={{ display: "block" }}>
            <CopilotAdvisorTab />
          </section>
        )}

        {/* TAB: STIX 2.1 / TAXII & MISP THREAT INTEL */}
        {activeTab === "threat_intel" && (
          <section className="content-grid" style={{ display: "block" }}>
            <ThreatIntelTab />
          </section>
        )}

        {/* TAB: ENTERPRISE RBAC & AUTH CLEARANCE */}
        {activeTab === "rbac_auth" && (
          <section className="content-grid" style={{ display: "block" }}>
            <RbacAuthTab />
          </section>
        )}


        {/* Executive / Incident Report Modal */}
        <ReportModal
          isOpen={isReportModalOpen}
          onClose={() => setIsReportModalOpen(false)}
          apiBase={API_BASE}
        />

        {/* Explainable AI (XAI) Modal */}
        <XAIExplanationModal
          isOpen={xaiModalConfig.isOpen}
          onClose={() => setXaiModalConfig((prev) => ({ ...prev, isOpen: false }))}
          modelKey={xaiModalConfig.modelKey}
          threatScore={xaiModalConfig.threatScore}
          eventData={xaiModalConfig.eventData}
          apiBase={API_BASE}
        />
      </main>
    </div>
  );
}
