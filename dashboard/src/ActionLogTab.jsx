/**
 * ActionLogTab.jsx — AEGIS Action Dispatch & Response Log
 * Shows every action dispatched to every agent with filters, stats, and expandable details.
 */
import React, { useState, useEffect, useCallback, useRef } from "react";
import {
  Shield, Zap, CheckCircle2, XCircle, RefreshCw,
  Filter, Search, Clock, Server, ChevronDown, ChevronUp,
  Activity, Cpu, FileWarning, Wifi, Lock, Radio, Bell, Skull,
} from "lucide-react";

const API_BASE =
  typeof window !== "undefined"
    ? `${window.location.protocol}//${window.location.hostname || "127.0.0.1"}:8000`
    : "http://127.0.0.1:8000";

function fmtTs(ts) {
  if (!ts) return "—";
  let ms = ts;
  if (typeof ts === "string") {
    const d = new Date(ts);
    if (!isNaN(d.getTime())) return d.toLocaleTimeString("en-GB", { hour12: false }) + " " + d.toLocaleDateString("en-GB");
    ms = Number(ts);
  }
  if (ms > 1e12) ms = Math.floor(ms / 1000);
  const d = new Date(ms * 1000);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleTimeString("en-GB", { hour12: false }) + " " + d.toLocaleDateString("en-GB");
}

function latencyMs(created, executed) {
  if (!created || !executed) return null;
  const toMs = (v) => {
    if (typeof v === "string") return new Date(v).getTime();
    if (v > 1e12) return Math.floor(v / 1000);
    return v * 1000;
  };
  const diff = toMs(executed) - toMs(created);
  return isNaN(diff) || diff < 0 ? null : diff;
}

const ACTION_META = {
  KILL_PROCESS:     { color: "#ef4444", bg: "rgba(239,68,68,0.12)",   icon: Skull,       label: "Kill Process"    },
  SUSPEND_PROCESS:  { color: "#f97316", bg: "rgba(249,115,22,0.12)",  icon: Cpu,         label: "Suspend Process" },
  RESUME_PROCESS:   { color: "#10b981", bg: "rgba(16,185,129,0.12)",  icon: Cpu,         label: "Resume Process"  },
  QUARANTINE_FILE:  { color: "#a855f7", bg: "rgba(168,85,247,0.12)",  icon: FileWarning, label: "Quarantine File" },
  ISOLATE_HOST:     { color: "#dc2626", bg: "rgba(220,38,38,0.15)",   icon: Lock,        label: "Isolate Host"    },
  UNISOLATE_HOST:   { color: "#06b6d4", bg: "rgba(6,182,212,0.12)",   icon: Wifi,        label: "Unisolate Host"  },
  BLOCK_REMOTE_IP:  { color: "#f59e0b", bg: "rgba(245,158,11,0.12)",  icon: Radio,       label: "Block Remote IP" },
  UNBLOCK_REMOTE_IP:{ color: "#22d3ee", bg: "rgba(34,211,238,0.12)",  icon: Wifi,        label: "Unblock IP"      },
  ALERT:            { color: "#60a5fa", bg: "rgba(96,165,250,0.12)",  icon: Bell,        label: "Alert"           },
  LOG:              { color: "#64748b", bg: "rgba(100,116,139,0.10)", icon: Activity,    label: "Log"             },
  SHUTDOWN_AGENT:   { color: "#ef4444", bg: "rgba(239,68,68,0.15)",   icon: XCircle,     label: "Shutdown Agent"  },
};

const STATUS_META = {
  DISPATCHED:        { color: "#f59e0b", label: "Dispatched"    },
  SUCCESS:           { color: "#10b981", label: "Success"       },
  SIMULATED_SUCCESS: { color: "#38bdf8", label: "Simulated"     },
  FAILED:            { color: "#ef4444", label: "Failed"        },
  DENIED:            { color: "#a855f7", label: "Denied"        },
  PENDING:           { color: "#94a3b8", label: "Pending"       },
  HALTED:            { color: "#64748b", label: "Agent Halted"  },  // SHUTDOWN_AGENT — agent terminated itself
  DROPPED:           { color: "#dc2626", label: "Dropped"       },  // Agent is offline/unreachable
  TIMED_OUT:         { color: "#f97316", label: "Timed Out"     },  // Dispatched but no ACK within standard 5-minute EDR window
};

// Standard enterprise EDR command execution timeout:
// CrowdStrike Falcon RTR & Microsoft Defender for Endpoint default to 300s (5 minutes).
const REAL_EDR_TIMEOUT_MS = 5 * 60 * 1000; // 300,000 ms (5 minutes)

// ─── Smart status resolver ───
// Determines display status from raw DB status + action type + agent liveness.
function resolveStatus(action, agentMap) {
  const raw = action.status || "PENDING";

  // Already finalized — show as-is
  if (["SUCCESS", "SIMULATED_SUCCESS", "FAILED", "DENIED"].includes(raw)) return raw;

  // SHUTDOWN_AGENT that was dispatched:
  // The agent halts its process on receipt — expected behavior, not an error.
  if (action.action_type === "SHUTDOWN_AGENT" && (raw === "DISPATCHED" || raw === "PENDING")) {
    return "HALTED";
  }

  // For any other dispatched or pending action, check target agent liveness
  if (raw === "DISPATCHED" || raw === "PENDING") {
    const agentInfo = agentMap[action.agent_id];
    if (agentInfo) {
      const isOffline =
        agentInfo.status === "silent" ||
        agentInfo.status === "OFFLINE" ||
        agentInfo.status === "OFFLINE_GRACEFUL" ||
        agentInfo.alarm_raised === true;
      if (isOffline) return "DROPPED";
    } else if (agentMap && Object.keys(agentMap).length > 0) {
      // Known fleet is loaded and target agent is absent
      return "DROPPED";
    }

    // Check age against standard 5-minute EDR command TTL
    const toMs = (v) => {
      if (!v) return 0;
      if (typeof v === "string") return new Date(v).getTime();
      if (v > 1e12) return Math.floor(v / 1000);
      return v * 1000;
    };
    const age = Date.now() - toMs(action.created_at);
    if (age > REAL_EDR_TIMEOUT_MS) return "TIMED_OUT";
  }

  return raw;
}

function ActionBadge({ type }) {
  const meta = ACTION_META[type] || { color: "#64748b", bg: "rgba(100,116,139,0.12)", icon: Shield, label: type };
  const Icon = meta.icon;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 5,
      padding: "3px 10px", borderRadius: 20,
      background: meta.bg, color: meta.color,
      fontSize: 11, fontWeight: 700, letterSpacing: "0.03em",
      border: `1px solid ${meta.color}33`,
    }}>
      <Icon size={11} />
      {meta.label || type}
    </span>
  );
}

function StatusBadge({ status }) {
  const meta = STATUS_META[status] || STATUS_META["PENDING"];
  // Special icons for derived states
  const prefix =
    status === "HALTED"    ? "⬛ " :
    status === "DROPPED"   ? "🔴 " :
    status === "TIMED_OUT" ? "⏱ " :
    status === "SUCCESS"   ? "✓ " :
    status === "FAILED"    ? "✗ " : "";
  return (
    <span title={status === "HALTED" ? "Agent shut itself down on receipt — expected behavior" :
                 status === "DROPPED" ? "Agent is offline/unreachable — action could not be executed" :
                 status === "TIMED_OUT" ? "Action expired after 5-minute EDR command timeout without ACK" :
                 status === "DISPATCHED" ? "In Flight — dispatched to agent, awaiting local execution ACK (5m EDR timeout)" : ""}
      style={{
        display: "inline-block", padding: "2px 10px", borderRadius: 12,
        background: `${meta.color}18`, color: meta.color,
        fontSize: 11, fontWeight: 700, border: `1px solid ${meta.color}44`,
        cursor: ["HALTED","DROPPED","TIMED_OUT","DISPATCHED"].includes(status) ? "help" : "default",
      }}>
      {prefix}{meta.label}
    </span>
  );
}

function ExpandedDetail({ action }) {
  const params = action.parameters || {};
  const result = action.result_details || {};
  const lat = latencyMs(action.created_at, action.executed_at);
  return (
    <div style={{
      padding: "14px 20px 14px 48px",
      background: "rgba(15,23,42,0.6)",
      borderTop: "1px solid rgba(96,165,250,0.08)",
      display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 16, fontSize: 12,
    }}>
      <div>
        <div style={{ color: "#64748b", fontSize: 10, fontWeight: 700, marginBottom: 6, textTransform: "uppercase" }}>Timeline</div>
        <div style={{ color: "#94a3b8", marginBottom: 3 }}><span style={{ color: "#64748b" }}>Created: </span>{fmtTs(action.created_at)}</div>
        <div style={{ color: "#94a3b8", marginBottom: 3 }}><span style={{ color: "#64748b" }}>Dispatched: </span>{fmtTs(action.dispatched_at)}</div>
        <div style={{ color: "#94a3b8", marginBottom: 3 }}><span style={{ color: "#64748b" }}>Executed: </span>{fmtTs(action.executed_at)}</div>
        {lat !== null && <div style={{ color: "#38bdf8", fontWeight: 600, marginTop: 4 }}>Lightning Latency: {lat < 1000 ? `${lat}ms` : `${(lat/1000).toFixed(2)}s`}</div>}
      </div>
      <div>
        <div style={{ color: "#64748b", fontSize: 10, fontWeight: 700, marginBottom: 6, textTransform: "uppercase" }}>Event Parameters</div>
        {Object.keys(params).length > 0
          ? Object.entries(params).slice(0, 8).map(([k, v]) => (
              <div key={k} style={{ color: "#94a3b8", marginBottom: 3 }}>
                <span style={{ color: "#64748b" }}>{k}: </span>
                <span style={{ color: "#e2e8f0", fontFamily: "monospace" }}>
                  {typeof v === "object" ? JSON.stringify(v).slice(0, 80) : String(v).slice(0, 80)}
                </span>
              </div>
            ))
          : <span style={{ color: "#334155" }}>No parameters</span>}
      </div>
      <div>
        <div style={{ color: "#64748b", fontSize: 10, fontWeight: 700, marginBottom: 6, textTransform: "uppercase" }}>Execution Result</div>
        {Object.keys(result).length > 0
          ? Object.entries(result).slice(0, 8).map(([k, v]) => (
              <div key={k} style={{ color: "#94a3b8", marginBottom: 3 }}>
                <span style={{ color: "#64748b" }}>{k}: </span>
                <span style={{ color: "#e2e8f0", fontFamily: "monospace" }}>
                  {typeof v === "object" ? JSON.stringify(v).slice(0, 80) : String(v).slice(0, 80)}
                </span>
              </div>
            ))
          : <span style={{ color: "#334155" }}>Awaiting execution</span>}
      </div>
    </div>
  );
}

const ALL_ACTIONS = ["ALL","KILL_PROCESS","SUSPEND_PROCESS","QUARANTINE_FILE","ISOLATE_HOST","BLOCK_REMOTE_IP","ALERT","LOG","SHUTDOWN_AGENT"];
const ALL_STATUSES = ["ALL","SUCCESS","SIMULATED_SUCCESS","HALTED","DROPPED","TIMED_OUT","DISPATCHED","FAILED","DENIED"];

export default function ActionLogTab() {
  const [actions, setActions] = useState([]);
  const [agentMap, setAgentMap] = useState({});   // agent_id -> { status, alarm_raised }
  const [loading, setLoading] = useState(false);
  const [lastRefresh, setLastRefresh] = useState(null);
  const [filterAction, setFilterAction] = useState("ALL");
  const [filterStatus, setFilterStatus] = useState("ALL");
  const [filterAgent, setFilterAgent] = useState("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [expandedId, setExpandedId] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const intervalRef = useRef(null);
  const agentIntervalRef = useRef(null);

  const fetchActions = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/actions?limit=200`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (data && Array.isArray(data.actions)) {
        setActions(data.actions.sort((a, b) => (b.created_at || 0) - (a.created_at || 0)));
      }
      setLastRefresh(new Date());
    } catch (e) {
      console.error("ActionLogTab fetch error:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchAgents = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/agents`);
      if (!res.ok) return;
      const data = await res.json();
      const map = {};
      (data.agents || []).forEach((a) => { map[a.agent_id] = a; });
      setAgentMap(map);
    } catch (e) { /* silent */ }
  }, []);

  useEffect(() => { fetchActions(); }, [fetchActions]);
  useEffect(() => { fetchAgents(); }, [fetchAgents]);

  useEffect(() => {
    if (autoRefresh) {
      intervalRef.current = setInterval(fetchActions, 4000);
      agentIntervalRef.current = setInterval(fetchAgents, 5000);
    } else {
      clearInterval(intervalRef.current);
      clearInterval(agentIntervalRef.current);
    }
    return () => {
      clearInterval(intervalRef.current);
      clearInterval(agentIntervalRef.current);
    };
  }, [autoRefresh, fetchActions, fetchAgents]);

  const uniqueAgents = ["ALL", ...Array.from(new Set(actions.map((a) => a.agent_id).filter(Boolean))).sort()];

  const filtered = actions.filter((a) => {
    if (filterAction !== "ALL" && a.action_type !== filterAction) return false;
    // Use resolved status for filter matching
    if (filterStatus !== "ALL" && resolveStatus(a, agentMap) !== filterStatus) return false;
    if (filterAgent !== "ALL" && a.agent_id !== filterAgent) return false;
    const q = searchQuery.trim().toLowerCase();
    if (q) {
      const hay = [a.agent_id, a.action_type, a.vote_id, a.action_id,
        a.target_pid && `PID ${a.target_pid}`, a.target_file,
        JSON.stringify(a.parameters || {})].join(" ").toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  const stats = {
    total: actions.length,
    success: actions.filter((a) => resolveStatus(a, agentMap) === "SUCCESS").length,
    dropped: actions.filter((a) => ["DROPPED", "TIMED_OUT"].includes(resolveStatus(a, agentMap))).length,
    failed: actions.filter((a) => resolveStatus(a, agentMap) === "FAILED").length,
    simulated: actions.filter((a) => resolveStatus(a, agentMap) === "SIMULATED_SUCCESS").length,
    destructive: actions.filter((a) => ["KILL_PROCESS","QUARANTINE_FILE","ISOLATE_HOST","BLOCK_REMOTE_IP","SUSPEND_PROCESS"].includes(a.action_type)).length,
  };

  const sel = { padding: "6px 10px", background: "rgba(30,41,59,0.9)", border: "1px solid rgba(96,165,250,0.2)", borderRadius: 7, color: "#e2e8f0", fontSize: 12, cursor: "pointer", outline: "none" };

  return (
    <section style={{ padding: "0 0 40px 0" }}>
      <div style={{ background: "linear-gradient(135deg,rgba(239,68,68,0.08),rgba(96,165,250,0.05))", border: "1px solid rgba(239,68,68,0.2)", borderRadius: 14, padding: "20px 24px", marginBottom: 20, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <h3 style={{ margin: 0, fontSize: 17, fontWeight: 700, color: "#f1f5f9", display: "flex", alignItems: "center", gap: 10 }}>
            <Zap size={18} style={{ color: "#ef4444" }} />
            Action Dispatch &amp; Response Log
          </h3>
          <p style={{ margin: "4px 0 0", fontSize: 12, color: "#64748b" }}>Every automated action dispatched by AEGIS Command Node — kill, isolate, block, quarantine, alert</p>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <button onClick={() => setAutoRefresh((v) => !v)} style={{ padding: "6px 14px", borderRadius: 8, border: "none", cursor: "pointer", fontSize: 12, fontWeight: 600, background: autoRefresh ? "rgba(16,185,129,0.15)" : "rgba(100,116,139,0.15)", color: autoRefresh ? "#10b981" : "#64748b" }}>
            <Radio size={12} style={{ verticalAlign: -2, marginRight: 5 }} />{autoRefresh ? "Live" : "Paused"}
          </button>
          <button onClick={fetchActions} disabled={loading} style={{ padding: "6px 14px", borderRadius: 8, border: "1px solid rgba(96,165,250,0.3)", background: "rgba(96,165,250,0.1)", color: "#60a5fa", cursor: "pointer", fontSize: 12, fontWeight: 600 }}>
            <RefreshCw size={12} style={{ verticalAlign: -2, marginRight: 5 }} />Refresh
          </button>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(6,1fr)", gap: 10, marginBottom: 20 }}>
        {[
          { label: "Total Actions", value: stats.total,       color: "#60a5fa", icon: Activity     },
          { label: "Executed",      value: stats.success,     color: "#10b981", icon: CheckCircle2 },
          { label: "Dropped/Lost",  value: stats.dropped,     color: "#dc2626", icon: XCircle      },
          { label: "Failed",        value: stats.failed,      color: "#ef4444", icon: XCircle      },
          { label: "Simulated",     value: stats.simulated,   color: "#38bdf8", icon: Shield       },
          { label: "Destructive",   value: stats.destructive, color: "#f97316", icon: Skull        },
        ].map(({ label, value, color, icon: Icon }) => (
          <div key={label} style={{ background: "rgba(15,23,42,0.7)", border: `1px solid ${color}22`, borderRadius: 10, padding: "12px 14px", textAlign: "center" }}>
            <Icon size={16} style={{ color, marginBottom: 4 }} />
            <div style={{ fontSize: 22, fontWeight: 800, color, lineHeight: 1 }}>{value}</div>
            <div style={{ fontSize: 10, color: "#64748b", marginTop: 3, fontWeight: 600 }}>{label}</div>
          </div>
        ))}
      </div>

      <div style={{ display: "flex", gap: 10, marginBottom: 16, flexWrap: "wrap", alignItems: "center", padding: "12px 16px", background: "rgba(15,23,42,0.5)", border: "1px solid rgba(96,165,250,0.1)", borderRadius: 10 }}>
        <Filter size={14} style={{ color: "#64748b" }} />
        <div style={{ position: "relative", flex: "1 1 180px" }}>
          <Search size={13} style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", color: "#64748b" }} />
          <input type="text" placeholder="Search action, agent, PID, vote_id…" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)}
            style={{ width: "100%", paddingLeft: 30, paddingRight: 10, paddingTop: 6, paddingBottom: 6, background: "rgba(30,41,59,0.8)", border: "1px solid rgba(96,165,250,0.2)", borderRadius: 7, color: "#e2e8f0", fontSize: 12, outline: "none", boxSizing: "border-box" }} />
        </div>
        <select value={filterAgent} onChange={(e) => setFilterAgent(e.target.value)} style={sel}>
          {uniqueAgents.map((a) => <option key={a} value={a}>{a === "ALL" ? "All Agents" : `Agent: ${a}`}</option>)}
        </select>
        <select value={filterAction} onChange={(e) => setFilterAction(e.target.value)} style={sel}>
          {ALL_ACTIONS.map((a) => <option key={a} value={a}>{a === "ALL" ? "All Action Types" : a}</option>)}
        </select>
        <select value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)} style={sel}>
          {ALL_STATUSES.map((s) => <option key={s} value={s}>{s === "ALL" ? "All Statuses" : s}</option>)}
        </select>
        <span style={{ color: "#64748b", fontSize: 11, marginLeft: "auto" }}>
          {filtered.length} / {actions.length} · {lastRefresh && `Updated ${lastRefresh.toLocaleTimeString("en-GB")}`}
        </span>
      </div>

      <div style={{ background: "rgba(10,15,28,0.85)", border: "1px solid rgba(96,165,250,0.12)", borderRadius: 12, overflow: "hidden" }}>
        <div style={{ display: "grid", gridTemplateColumns: "140px 1fr 160px 160px 120px 120px 28px", padding: "10px 16px", background: "rgba(15,23,42,0.8)", borderBottom: "1px solid rgba(96,165,250,0.12)", fontSize: 10, fontWeight: 700, color: "#64748b", textTransform: "uppercase", letterSpacing: "0.06em", gap: 8 }}>
          <div>Time</div><div>Agent → Action</div><div>Target</div><div>Event / Vote Ref</div><div>Status</div><div>Latency</div><div></div>
        </div>
        {filtered.length === 0 ? (
          <div style={{ textAlign: "center", padding: "48px 24px", color: "#334155" }}>
            <Zap size={32} style={{ opacity: 0.3, marginBottom: 12 }} />
            <p style={{ margin: 0, fontSize: 14 }}>No actions found matching your filters</p>
            <p style={{ margin: "6px 0 0", fontSize: 12, color: "#1e293b" }}>Actions are dispatched when AEGIS detects a threat and consensus is reached</p>
          </div>
        ) : filtered.map((action, idx) => {
          const isExpanded = expandedId === action.action_id;
          const meta = ACTION_META[action.action_type] || {};
          const lat = latencyMs(action.created_at, action.executed_at);
          const target = action.target_pid
            ? `PID ${action.target_pid}`
            : action.target_file
            ? action.target_file.split(/[/\\]/).pop()
            : (action.parameters?.remote_ip || action.parameters?.src_ip || action.parameters?.ip || "Host");
          return (
            <div key={action.action_id || idx}>
              <div onClick={() => setExpandedId(isExpanded ? null : action.action_id)}
                style={{ display: "grid", gridTemplateColumns: "140px 1fr 160px 160px 120px 120px 28px", padding: "10px 16px", gap: 8, borderBottom: isExpanded ? "none" : "1px solid rgba(96,165,250,0.07)", background: isExpanded ? (meta.bg || "rgba(96,165,250,0.05)") : idx % 2 === 0 ? "transparent" : "rgba(15,23,42,0.3)", cursor: "pointer", alignItems: "center" }}>
                <div style={{ fontSize: 11, color: "#64748b", fontFamily: "monospace" }}>{fmtTs(action.created_at)}</div>
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <Server size={12} style={{ color: "#38bdf8" }} />
                    <span style={{ fontSize: 13, fontWeight: 700, color: "#e2e8f0" }}>{action.agent_id}</span>
                  </div>
                  <ActionBadge type={action.action_type} />
                </div>
                <div style={{ fontSize: 12, color: "#94a3b8", fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{target}</div>
                <div style={{ fontSize: 11, color: "#475569", fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{action.vote_id ? `#${action.vote_id.slice(0,8)}` : action.action_id?.slice(0,12) || "—"}</div>
                <div><StatusBadge status={resolveStatus(action, agentMap)} /></div>
                <div style={{ fontSize: 11, color: lat !== null ? "#10b981" : "#334155", fontFamily: "monospace" }}>{lat !== null ? (lat < 1000 ? `${lat}ms` : `${(lat/1000).toFixed(1)}s`) : "—"}</div>
                <div style={{ color: "#475569" }}>{isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}</div>
              </div>
              {isExpanded && <ExpandedDetail action={action} />}
            </div>
          );
        })}
      </div>
    </section>
  );
}
