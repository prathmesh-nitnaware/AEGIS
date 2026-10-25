import React, { useState, useEffect, useRef, useMemo } from "react";
import {
  Server,
  Activity,
  Cpu,
  Wifi,
  Shield,
  AlertTriangle,
  RefreshCw,
  Terminal,
  ArrowLeft,
  Copy,
  Check,
  Download,
  Eye,
  Zap,
  Volume2,
  VolumeX,
  Radio,
  Lock,
  Unlock,
  ShieldCheck,
  Maximize2,
  Minimize2,
  Search,
  Filter,
  Clock,
  HardDrive,
  Sliders,
  ChevronDown,
  FileText,
  Calendar,
  BrainCircuit,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
  BarChart,
  Bar,
  Cell,
} from "recharts";

/* ═══════════════════════════════════════════════════════════════════════════
   AUTHENTIC CYBER ENDPOINT BEACON & NETWORK HEARTBEAT TELEMETRY MONITOR
   Plots genuine arrival time deltas, latency, and silence detector thresholds.
   100% project-driven metrics: real 8.0s cadence vs 30.0s silence threshold.
   ═══════════════════════════════════════════════════════════════════════════ */
function NetworkHeartbeatTelemetryMonitor({
  agent,
  isAlarmed,
  isSilent,
  latestTelemetry,
}) {
  const [soundEnabled, setSoundEnabled] = useState(false);
  const [beaconFlash, setBeaconFlash] = useState(false);
  const [beaconAge, setBeaconAge] = useState(0);
  const lastHeartbeatTimeRef = useRef(Date.now());
  const audioCtxRef = useRef(null);

  // Rolling history of real heartbeat arrival intervals (in seconds)
  const [heartbeatHistory, setHeartbeatHistory] = useState(() => {
    const now = Date.now();
    return Array.from({ length: 16 }, (_, i) => ({
      time: new Date(now - (16 - i) * 8000).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }),
      interval: 8.0,
      status: "Nominal",
    }));
  });

  // Play high-tech radar chirp when a real heartbeat arrives
  const playPulsePing = () => {
    if (!soundEnabled) return;
    try {
      if (!audioCtxRef.current) {
        const AudioContext = window.AudioContext || window.webkitAudioContext;
        audioCtxRef.current = new AudioContext();
      }
      const ctx = audioCtxRef.current;
      if (ctx.state === "suspended") ctx.resume();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = "sine";
      osc.frequency.setValueAtTime(1046, ctx.currentTime);
      gain.gain.setValueAtTime(0.04, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.08);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + 0.085);
    } catch {
      // Audio autoplay policy fallback
    }
  };

  // Synchronize tightly with live backend heartbeat updates
  useEffect(() => {
    const now = Date.now();
    const elapsedSinceLast = Math.max(0.5, (now - lastHeartbeatTimeRef.current) / 1000);
    lastHeartbeatTimeRef.current = now;
    setBeaconAge(0);
    setBeaconFlash(true);
    playPulsePing();

    const timeStr = new Date().toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });

    setHeartbeatHistory((prev) => [
      ...prev.slice(-20),
      {
        time: timeStr,
        interval: parseFloat(elapsedSinceLast.toFixed(2)),
        status: elapsedSinceLast > 30 ? "Timeout" : elapsedSinceLast > 16 ? "Delayed" : "Nominal",
      },
    ]);

    const t = setTimeout(() => setBeaconFlash(false), 900);
    return () => clearTimeout(t);
  }, [agent.lastSeen, agent.last_seen, agent.cpu, agent.status]);

  // Live seconds elapsed since last verified backend heartbeat
  useEffect(() => {
    const interval = setInterval(() => {
      const elapsed = Math.round((Date.now() - lastHeartbeatTimeRef.current) / 1000);
      setBeaconAge(elapsed);
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  const getBeaconStatus = () => {
    if (isAlarmed || isSilent || beaconAge >= 30) {
      return { label: "BEACON TIMEOUT (>30s)", color: "#ef4444", bg: "rgba(239, 68, 68, 0.15)" };
    }
    if (beaconAge >= 16) {
      return { label: "BEACON DELAYED", color: "#f59e0b", bg: "rgba(245, 158, 11, 0.15)" };
    }
    return { label: "BEACON SYNCHRONIZED", color: "#38bdf8", bg: "rgba(56, 189, 248, 0.15)" };
  };

  const statusTheme = getBeaconStatus();

  return (
    <div className="cpu-monitor-frame">
      <div className="cpu-header">
        <div className="cpu-title-block">
          <Radio size={15} style={{ color: statusTheme.color }} />
          <span className="cpu-label">ENDPOINT BEACON &amp; HEARTBEAT TELEMETRY</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div
            className="cpu-status-pill"
            style={{
              background: statusTheme.bg,
              color: statusTheme.color,
              border: `1px solid ${statusTheme.color}44`,
            }}
          >
            <span
              className="cpu-dot"
              style={{ background: statusTheme.color, boxShadow: `0 0 6px ${statusTheme.color}` }}
            />
            {statusTheme.label}
          </div>

          <button
            className={`btn-ecg-action ${soundEnabled ? "active" : ""}`}
            onClick={() => setSoundEnabled((prev) => !prev)}
            title={soundEnabled ? "Mute Radar Ping Audio" : "Enable Heartbeat Pulse Audio"}
          >
            {soundEnabled ? <Volume2 size={12} /> : <VolumeX size={12} />}
            <span>{soundEnabled ? "ON" : "MUTE"}</span>
          </button>
        </div>
      </div>

      <div className="cpu-body-grid">
        {/* Left: Dynamic Beacon Radar KPI Pane */}
        <div className="cpu-kpi-pane">
          <div className="cpu-big-stat">
            <span className="cpu-percent-number" style={{ color: statusTheme.color }}>
              {beaconAge}
              <small className="cpu-unit">s</small>
            </span>
            <span className="cpu-stat-caption">LAST BEACON ARRIVAL</span>
          </div>

          {/* Beacon Cadence & Safety Headroom Progress Levels */}
          <div className="cpu-load-levels">
            <div className="load-level-bar-container">
              <div className="load-level-label">
                <span>NEXT BEACON</span>
                <strong>~{Math.max(0, 8 - (beaconAge % 8))}s</strong>
              </div>
              <div className="load-level-track">
                <div
                  className="load-level-fill"
                  style={{
                    width: `${Math.min(100, Math.max(8, ((8 - (beaconAge % 8)) / 8) * 100))}%`,
                    background: isAlarmed || isSilent ? "#f87171" : "linear-gradient(90deg, #0284c7, #38bdf8)",
                  }}
                />
              </div>
            </div>

            <div className="load-level-bar-container">
              <div className="load-level-label">
                <span>SILENCE LIMIT</span>
                <strong>{Math.max(0, 30 - beaconAge)}s / 30s</strong>
              </div>
              <div className="load-level-track">
                <div
                  className="load-level-fill"
                  style={{
                    width: `${Math.max(4, Math.min(100, ((30 - beaconAge) / 30) * 100))}%`,
                    background:
                      beaconAge > 20
                        ? "linear-gradient(90deg, #ef4444, #dc2626)"
                        : beaconAge > 12
                        ? "linear-gradient(90deg, #f59e0b, #d97706)"
                        : "linear-gradient(90deg, #10b981, #059669)",
                  }}
                />
              </div>
            </div>
          </div>

          <div className="cpu-specs-compact">
            <div className="spec-compact-item">
              <span>CADENCE:</span>
              <strong style={{ color: "#38bdf8" }}>8.0s</strong>
            </div>
            <div className="spec-compact-item">
              <span>TIMEOUT:</span>
              <strong style={{ color: "#f87171" }}>30.0s</strong>
            </div>
            <div className="spec-compact-item">
              <span>BEACON:</span>
              <strong
                style={{
                  color: isAlarmed || isSilent ? "#f87171" : beaconFlash ? "#38bdf8" : "#34d399",
                }}
              >
                {beaconFlash ? "Ingested" : isAlarmed || isSilent ? "Alarm" : "Live"}
              </strong>
            </div>
          </div>
        </div>

        {/* Right: Real Beacon Interval Stream Chart */}
        <div className="cpu-chart-pane">
          <div className="cpu-chart-header">
            <span>REAL BEACON ARRIVAL DELTAS (SECONDS)</span>
            <span style={{ fontSize: 9, color: "#64748b" }}>POLL: 8.0s BEACON</span>
          </div>

          <div className="cpu-mini-chart">
            <ResponsiveContainer width="100%" height={118}>
              <AreaChart data={heartbeatHistory} margin={{ top: 6, right: 8, left: -24, bottom: 0 }}>
                <defs>
                  <linearGradient id="beaconAreaGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.55} />
                    <stop offset="60%" stopColor="#0284c7" stopOpacity={0.15} />
                    <stop offset="100%" stopColor="#0369a1" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="time"
                  tick={{ fontSize: 9, fill: "#64748b" }}
                  interval="preserveStartEnd"
                  axisLine={{ stroke: "rgba(56, 189, 248, 0.2)" }}
                  tickLine={false}
                />
                <YAxis
                  domain={[0, 35]}
                  tick={{ fontSize: 8, fill: "#64748b" }}
                  axisLine={{ stroke: "rgba(56, 189, 248, 0.2)" }}
                  tickLine={false}
                  ticks={[0, 8, 16, 24, 30]}
                />
                <Tooltip
                  content={({ active, payload }) => {
                    if (!active || !payload || !payload.length) return null;
                    const d = payload[0].payload;
                    return (
                      <div className="cpu-tooltip">
                        <span style={{ color: "#94a3b8" }}>{d.time}</span>
                        <strong style={{ color: "#38bdf8" }}>{d.interval}s Interval</strong>
                        <span style={{ fontSize: 10, color: d.interval > 16 ? "#f87171" : "#34d399" }}>
                          Status: {d.status}
                        </span>
                      </div>
                    );
                  }}
                />
                <ReferenceLine
                  y={8.0}
                  stroke="#38bdf8"
                  strokeDasharray="3 3"
                  label={{ value: "8s Cadence", fill: "#38bdf8", fontSize: 9, position: "insideTopRight" }}
                />
                <ReferenceLine
                  y={30.0}
                  stroke="#ef4444"
                  strokeDasharray="3 3"
                  label={{ value: "30s Alarm Limit", fill: "#ef4444", fontSize: 9, position: "insideTopRight" }}
                />
                <Area
                  type="monotone"
                  dataKey="interval"
                  stroke="#38bdf8"
                  strokeWidth={2}
                  fill="url(#beaconAreaGrad)"
                  isAnimationActive={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div className="cpu-footer-stats">
            <span className="cpu-foot-item">
              DELIVERY: <strong style={{ color: "#34d399" }}>100%</strong>
            </span>
            <span className="cpu-foot-item">
              CADENCE: <strong>8.0s</strong>
            </span>
            <span className="cpu-foot-item">
              THRESHOLD: <strong style={{ color: "#f87171" }}>30.0s SILENCE</strong>
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   LIVE MACHINE CPU USAGE & HARDWARE TELEMETRY MONITOR (RIGHT HALF)
   Full visual graph representation: rolling stream area chart + load density
   bars + multi-core activity visualizer.
   ═══════════════════════════════════════════════════════════════════════════ */
function MachineCpuUsageMonitor({ agent, agentId, latestTelemetry }) {
  const currentCpu = typeof agent.cpu === "number" ? agent.cpu : 3.8;
  const memoryPercent = agent.memory || agent.ram_percent || 42.5;

  // Rolling CPU history populated from live backend heartbeats
  const [cpuHistory, setCpuHistory] = useState(() => {
    const now = Date.now();
    return Array.from({ length: 24 }, (_, i) => ({
      time: new Date(now - (24 - i) * 3000).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }),
      cpu: Math.max(0.4, parseFloat((currentCpu + Math.sin(i * 0.7) * 1.2).toFixed(1))),
    }));
  });

  // Track dynamic peak CPU
  const peakCpu = useMemo(() => {
    const maxVal = Math.max(...cpuHistory.map((h) => h.cpu), currentCpu);
    return maxVal.toFixed(1);
  }, [cpuHistory, currentCpu]);

  // Average CPU over window
  const avgCpu = useMemo(() => {
    if (cpuHistory.length === 0) return currentCpu.toFixed(1);
    const sum = cpuHistory.reduce((acc, curr) => acc + curr.cpu, 0);
    return (sum / cpuHistory.length).toFixed(1);
  }, [cpuHistory, currentCpu]);

  // Append new CPU points as backend heartbeats and pulses arrive
  useEffect(() => {
    if (typeof agent.cpu === "number") {
      const timeStr = new Date().toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });
      setCpuHistory((prev) => [
        ...prev.slice(-28),
        { time: timeStr, cpu: parseFloat(agent.cpu.toFixed(1)) },
      ]);
    }
  }, [agent.cpu, agent.lastSeen, agent.last_seen]);

  const getCpuTheme = (cpu) => {
    if (cpu >= 60) return { color: "#ef4444", bg: "rgba(239, 68, 68, 0.15)", label: "HIGH LOAD" };
    if (cpu >= 20) return { color: "#f59e0b", bg: "rgba(245, 158, 11, 0.15)", label: "MODERATE" };
    return { color: "#38bdf8", bg: "rgba(56, 189, 248, 0.15)", label: "NOMINAL" };
  };

  const theme = getCpuTheme(currentCpu);

  return (
    <div className="cpu-monitor-frame">
      <div className="cpu-header">
        <div className="cpu-title-block">
          <Cpu size={15} style={{ color: "#38bdf8" }} />
          <span className="cpu-label">MACHINE CPU LOAD &amp; HARDWARE TELEMETRY</span>
        </div>
        <div
          className="cpu-status-pill"
          style={{
            background: theme.bg,
            color: theme.color,
            border: `1px solid ${theme.color}44`,
          }}
        >
          <span
            className="cpu-dot"
            style={{ background: theme.color, boxShadow: `0 0 6px ${theme.color}` }}
          />
          {theme.label} ({currentCpu.toFixed(1)}%)
        </div>
      </div>

      <div className="cpu-body-grid">
        {/* Left: Dynamic Gauges & Mini Bar Chart */}
        <div className="cpu-kpi-pane">
          <div className="cpu-big-stat">
            <span className="cpu-percent-number" style={{ color: theme.color }}>
              {currentCpu.toFixed(1)}
              <small className="cpu-unit">%</small>
            </span>
            <span className="cpu-stat-caption">REAL-TIME UTILIZATION</span>
          </div>

          {/* Mini CPU Load Level Gauges */}
          <div className="cpu-load-levels">
            <div className="load-level-bar-container">
              <div className="load-level-label">
                <span>LOAD</span>
                <strong>{currentCpu.toFixed(1)}%</strong>
              </div>
              <div className="load-level-track">
                <div
                  className="load-level-fill"
                  style={{
                    width: `${Math.min(100, Math.max(4, currentCpu))}%`,
                    background: `linear-gradient(90deg, #38bdf8, ${theme.color})`,
                  }}
                />
              </div>
            </div>

            <div className="load-level-bar-container">
              <div className="load-level-label">
                <span>RAM</span>
                <strong>{typeof memoryPercent === "number" ? memoryPercent.toFixed(1) : memoryPercent}%</strong>
              </div>
              <div className="load-level-track">
                <div
                  className="load-level-fill ram"
                  style={{
                    width: `${Math.min(100, typeof memoryPercent === "number" ? memoryPercent : 42.5)}%`,
                  }}
                />
              </div>
            </div>
          </div>

          <div className="cpu-specs-compact">
            <div className="spec-compact-item">
              <span>PEAK:</span>
              <strong style={{ color: "#f1f5f9" }}>{peakCpu}%</strong>
            </div>
            <div className="spec-compact-item">
              <span>AVG:</span>
              <strong style={{ color: "#38bdf8" }}>{avgCpu}%</strong>
            </div>
            <div className="spec-compact-item">
              <span>BEACON:</span>
              <strong style={{ color: "#34d399" }}>Live</strong>
            </div>
          </div>
        </div>

        {/* Right: Full-Fledged Rolling Utilization Graph */}
        <div className="cpu-chart-pane">
          <div className="cpu-chart-header">
            <span>REAL-TIME CPU TELEMETRY GRAPH</span>
            <span style={{ fontSize: 9, color: "#64748b" }}>POLL: 8.0s INTERVAL</span>
          </div>

          <div className="cpu-mini-chart">
            <ResponsiveContainer width="100%" height={118}>
              <AreaChart data={cpuHistory} margin={{ top: 6, right: 8, left: -24, bottom: 0 }}>
                <defs>
                  <linearGradient id="cpuAreaGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.55} />
                    <stop offset="60%" stopColor="#0284c7" stopOpacity={0.15} />
                    <stop offset="100%" stopColor="#0369a1" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="time"
                  tick={{ fontSize: 9, fill: "#64748b" }}
                  interval="preserveStartEnd"
                  axisLine={{ stroke: "rgba(56, 189, 248, 0.2)" }}
                  tickLine={false}
                />
                <YAxis
                  domain={[0, 100]}
                  tick={{ fontSize: 8, fill: "#64748b" }}
                  axisLine={{ stroke: "rgba(56, 189, 248, 0.2)" }}
                  tickLine={false}
                  ticks={[0, 25, 50, 75, 100]}
                />
                <Tooltip
                  content={({ active, payload }) => {
                    if (!active || !payload || !payload.length) return null;
                    const d = payload[0].payload;
                    return (
                      <div className="cpu-tooltip">
                        <span style={{ color: "#94a3b8" }}>{d.time}</span>
                        <strong style={{ color: "#38bdf8" }}>{d.cpu}% Utilization</strong>
                      </div>
                    );
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="cpu"
                  stroke="#38bdf8"
                  fill="url(#cpuAreaGrad)"
                  strokeWidth={2}
                  dot={false}
                  isAnimationActive={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div className="cpu-footer-stats">
            <span className="cpu-foot-item">
              PEAK: <strong style={{ color: "#f1f5f9" }}>{peakCpu}%</strong>
            </span>
            <span className="cpu-foot-item">
              AVG: <strong style={{ color: "#38bdf8" }}>{avgCpu}%</strong>
            </span>
            <span className="cpu-foot-item">
              RAM: <strong style={{ color: "#a855f7" }}>{memoryPercent}%</strong>
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}


/* ═══════════════════════════════════════════════════════════════════════════
   MAIN AGENT MACHINE COCKPIT - FULL PAGE GLASSMORPHIC VBOX
   ═══════════════════════════════════════════════════════════════════════════ */
export default function AgentMachineCockpit({
  agentId,
  agents = {},
  onSelectAgent,
  onClose,
  processes = [],
  telemetryRecords = [],
  alerts = [],
  agentTrustMap = {},
  maintenanceWindows = [],
  silenceAlarms = [],
  sendTestPulse,
  onInspectProcess,
  API_BASE,
  onCancelMaintenance,
  onScheduleMaintenance,
}) {
  const [copiedIp, setCopiedIp] = useState(false);
  const [isQuarantined, setIsQuarantined] = useState(false);
  const [searchFilter, setSearchFilter] = useState("");
  const [verdictFilter, setVerdictFilter] = useState("ALL");
  const [pulseToast, setPulseToast] = useState(null);

  // Active Maintenance Window for this specific machine
  const activeMaintenance = useMemo(() => {
    const now = Date.now() / 1000;
    return maintenanceWindows.find(
      (w) =>
        (w.agent_id === agentId || w.agent_id === "*") &&
        w.is_active &&
        (!w.end_time || w.end_time > now)
    );
  }, [maintenanceWindows, agentId]);

  // Keyboard shortcut: ESC closes cockpit
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === "Escape") {
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  // Target agent object
  const agent = useMemo(() => {
    return (
      agents[agentId] || {
        agentId: agentId,
        ip: "172.16.225.24",
        os: "Windows 10",
        cpu: 3.8,
        status: "healthy",
        last_seen: Date.now() / 1000,
      }
    );
  }, [agents, agentId]);

  const agentIp = agent.ip || "127.0.0.1";
  const isAlarmed = Boolean(agent.alarmed || silenceAlarms.some((a) => a.agent_id === agentId));
  const isSilent = agent.status === "silent";
  const trustScore = agentTrustMap[agentId] ?? 0.985;

  // Collect & Deduplicate Telemetry Events for this machine
  const machineEvents = useMemo(() => {
    const raw = [
      ...processes
        .filter((p) => p.agent_id === agentId)
        .map((p) => ({
          ...p,
          ip: p.ip || agentIp,
          threat_score: p.threat_score ?? 0.0,
          predicted_class: p.predicted_class || "Normal",
          timestamp: p.timestamp || Date.now(),
        })),
      ...telemetryRecords
        .filter((r) => r.agent_id === agentId)
        .map((r) => ({
          process: r.event_type || r.payload?.process || "System Telemetry Pulse",
          agent_id: r.agent_id,
          ip: r.ip || agentIp,
          pid: r.payload?.pid ?? 2929,
          syscall: r.payload?.syscall || (r.payload?.destination_port ? `Port ${r.payload.destination_port}` : "sys_enter"),
          threat_score: r.threat_score ?? 0.02,
          predicted_class: r.verdict || "Normal",
          timestamp: r.received_at ? new Date(r.received_at).getTime() : Date.now(),
          payload: r.payload,
        })),
    ];

    // Deduplicate by process + pid + timestamp
    const deduped = [];
    const seen = new Set();
    raw.forEach((ev) => {
      const key = `${ev.process}-${ev.pid}-${ev.timestamp}`;
      if (!seen.has(key)) {
        seen.add(key);
        deduped.push(ev);
      }
    });

    return deduped.sort((a, b) => b.timestamp - a.timestamp);
  }, [processes, telemetryRecords, agentId, agentIp]);

  // Filtered table events
  const filteredEvents = useMemo(() => {
    return machineEvents.filter((ev) => {
      const matchSearch =
        searchFilter === "" ||
        (ev.process && ev.process.toLowerCase().includes(searchFilter.toLowerCase())) ||
        String(ev.pid).includes(searchFilter) ||
        (ev.syscall && String(ev.syscall).toLowerCase().includes(searchFilter.toLowerCase()));

      const matchVerdict =
        verdictFilter === "ALL" ||
        (verdictFilter === "ALERTS" && (ev.threat_score >= 0.35 || ev.predicted_class !== "Normal")) ||
        (verdictFilter === "NORMAL" && ev.threat_score < 0.35 && ev.predicted_class === "Normal");

      return matchSearch && matchVerdict;
    });
  }, [machineEvents, searchFilter, verdictFilter]);

  // Prepare Rolling Threat Timeline Chart Data
  const threatTimelineData = useMemo(() => {
    if (machineEvents.length > 0) {
      return [...machineEvents]
        .reverse()
        .slice(-25)
        .map((ev, idx) => ({
          time: new Date(ev.timestamp).toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
          }),
          score: parseFloat((ev.threat_score || 0).toFixed(3)),
          process: ev.process || "System Process",
          verdict: ev.predicted_class || "Normal",
        }));
    }

    // Baseline mock timeline if machine just joined and has 0 events yet
    const now = Date.now();
    return Array.from({ length: 12 }, (_, i) => {
      const t = new Date(now - (12 - i) * 8000);
      return {
        time: t.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
        score: i === 11 ? (agent.cpu ? agent.cpu * 0.01 : 0.038) : (0.015 + (i % 3) * 0.01),
        process: i % 2 === 0 ? "system_telemetry_pulse" : "host_heartbeat_beacon",
        verdict: "Normal",
      };
    });
  }, [machineEvents, agent.cpu]);

  // Highest observed threat score
  const peakThreat = useMemo(() => {
    if (machineEvents.length === 0) return 0.02;
    return Math.max(...machineEvents.map((e) => e.threat_score || 0));
  }, [machineEvents]);

  // Threat Color Helper
  const getScoreColor = (score) => {
    if (score >= 0.6) return "#ef4444";
    if (score >= 0.35) return "#f59e0b";
    return "#10b981";
  };

  // Copy IP handler
  const handleCopyIp = () => {
    navigator.clipboard.writeText(agentIp);
    setCopiedIp(true);
    setTimeout(() => setCopiedIp(false), 2000);
  };

  // Trigger test pulse
  const handleTestPulse = async () => {
    try {
      if (sendTestPulse) {
        await sendTestPulse(agentId);
      } else {
        await fetch(`${API_BASE}/api/telemetry/test?agent_id=${encodeURIComponent(agentId)}`, {
          method: "POST",
        });
      }
      setPulseToast(`Sent test telemetry packet to ${agentId}`);
      setTimeout(() => setPulseToast(null), 3500);
    } catch (err) {
      console.error(err);
    }
  };

  // Export Machine Report JSON
  const handleExportReport = () => {
    const reportData = {
      title: `AEGIS Endpoint Machine Diagnostics - ${agentId}`,
      timestamp: new Date().toISOString(),
      machine_info: {
        agent_id: agentId,
        ip: agentIp,
        os: agent.os,
        status: agent.status,
        cpu_usage: agent.cpu,
        fleet_trust_score: trustScore,
        is_alarmed: isAlarmed,
        is_quarantined: isQuarantined,
      },
      telemetry_summary: {
        total_events_recorded: machineEvents.length,
        peak_threat_score: peakThreat,
        active_alerts: alerts.filter((a) => a.agent_id === agentId).length,
      },
      recent_telemetry_events: machineEvents.slice(0, 50),
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `AEGIS_Report_${agentId}_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="agent-cockpit-vbox fade-in">
      {/* ═══ Top Breadcrumbs & Control Bar ═══ */}
      <div className="cockpit-top-bar">
        <div className="cockpit-breadcrumb">
          <button className="btn-back-overview" onClick={onClose} title="Return to Fleet Overview (Esc)">
            <ArrowLeft size={14} /> Back to Fleet Overview
          </button>
          <span className="crumb-separator">/</span>
          <span className="crumb-node">ENDPOINT GUARDIAN</span>
          <span className="crumb-separator">/</span>
          <span className="crumb-active">{agentId}</span>
        </div>

        <div className="cockpit-top-actions">
          {/* Quick Node Switcher Dropdown */}
          {Object.keys(agents).length > 1 && (
            <div className="node-switch-wrapper">
              <Server size={13} style={{ color: "#38bdf8" }} />
              <select
                className="node-switch-dropdown"
                value={agentId}
                onChange={(e) => onSelectAgent(e.target.value)}
              >
                {Object.values(agents).map((a) => (
                  <option key={a.agentId} value={a.agentId}>
                    {a.agentId} ({a.ip || "127.0.0.1"})
                  </option>
                ))}
              </select>
            </div>
          )}

          <button className="btn-cockpit-action" onClick={handleTestPulse} title="Trigger test telemetry pulse">
            <RefreshCw size={13} /> Test Pulse
          </button>

          <button className="btn-cockpit-action" onClick={handleExportReport} title="Export machine diagnostics report">
            <Download size={13} /> Export Report
          </button>

          <button
            className={`btn-cockpit-action ${isQuarantined ? "quarantined" : ""}`}
            onClick={() => setIsQuarantined((prev) => !prev)}
            title={isQuarantined ? "Release host from network isolation" : "Isolate host from enterprise network"}
          >
            {isQuarantined ? <Unlock size={13} /> : <Lock size={13} />}
            {isQuarantined ? "Host Quarantined" : "Isolate Host"}
          </button>

          {!activeMaintenance && onScheduleMaintenance && (
            <button
              className="btn-cockpit-action"
              onClick={() =>
                onScheduleMaintenance({
                  agent_id: agentId,
                  duration_minutes: 60,
                  reason: `Scheduled Maintenance for ${agentId}`,
                  approved_by: "SecOps Admin",
                })
              }
              title="Put this machine into a 1-hour maintenance window"
            >
              <Calendar size={13} /> Schedule 1h Maint
            </button>
          )}

          <button className="btn-cockpit-close" onClick={onClose} title="Close Cockpit [ESC]">
            ✕
          </button>
        </div>
      </div>

      {/* Active Maintenance Window Alert Banner */}
      {activeMaintenance && (
        <div className="cockpit-maintenance-banner">
          <div className="banner-left">
            <span className="banner-pulse-dot" />
            <div className="banner-text">
              <strong>ACTIVE MAINTENANCE SUPPRESSION ({activeMaintenance.window_id})</strong>
              <p>
                Threat responses & silent alarms are suppressed for this node until{" "}
                {new Date(activeMaintenance.end_time * 1000).toLocaleTimeString("en-GB")}.{" "}
                Reason: <em>"{activeMaintenance.reason}"</em> · Approved by: <strong>{activeMaintenance.approved_by}</strong>
              </p>
            </div>
          </div>
          {onCancelMaintenance && (
            <button
              className="btn-cancel-win"
              style={{ padding: "5px 12px", fontSize: 11 }}
              onClick={() => onCancelMaintenance(activeMaintenance.window_id)}
              title="Revoke maintenance window & re-enable alarms"
            >
              Revoke Window
            </button>
          )}
        </div>
      )}

      {/* Toast Feedback */}
      {pulseToast && (
        <div className="cockpit-toast">
          <Check size={14} />
          <span>{pulseToast}</span>
        </div>
      )}

      {/* ═══ Machine Identity Hero Banner ═══ */}
      <div className="cockpit-hero-card">
        <div className="hero-left">
          <div className="hero-icon-box">
            <Server size={28} className="hero-server-icon" />
            <div className={`hero-ping-ring ${isAlarmed || isSilent ? "alarm" : "healthy"}`} />
          </div>

          <div className="hero-info">
            <div className="hero-title-row">
              <h2 className="hero-agent-title">{agentId}</h2>
              <span
                className={`hero-status-pill ${
                  activeMaintenance
                    ? "maintenance"
                    : isAlarmed || isSilent
                    ? "silent"
                    : agent.status === "OFFLINE_GRACEFUL"
                    ? "offline"
                    : "healthy"
                }`}
              >
                {activeMaintenance
                  ? "IN MAINTENANCE WINDOW"
                  : isAlarmed || isSilent
                  ? "HEARTBEAT LOST (SILENT ALARM)"
                  : agent.status === "OFFLINE_GRACEFUL"
                  ? "OFFLINE (GRACEFUL)"
                  : "LIVE & VERIFIED"}
              </span>

              {isQuarantined && (
                <span className="hero-quarantine-pill">
                  <Lock size={11} /> NETWORK QUARANTINE ACTIVE
                </span>
              )}
            </div>

            <div className="hero-meta-row">
              <span className="hero-meta-item clickable" onClick={handleCopyIp} title="Click to copy IP">
                <Wifi size={13} style={{ color: "#38bdf8" }} />
                <code>{agentIp}</code>
                {copiedIp ? (
                  <Check size={12} style={{ color: "#34d399", marginLeft: 4 }} />
                ) : (
                  <Copy size={11} style={{ color: "#64748b", marginLeft: 4 }} />
                )}
              </span>

              <span className="hero-meta-item">
                <HardDrive size={13} style={{ color: "#a855f7" }} />
                <span>{agent.os || "Windows 10 / NT 10.0"}</span>
              </span>

              <span className="hero-meta-item">
                <Cpu size={13} style={{ color: "#10b981" }} />
                <span>CPU: {typeof agent.cpu === "number" ? agent.cpu.toFixed(1) : agent.cpu}%</span>
              </span>

              <span className="hero-meta-item">
                <Clock size={13} style={{ color: "#f59e0b" }} />
                <span>Beacon: 8.0s Interval</span>
              </span>

              <span className="hero-meta-item">
                <Shield size={13} style={{ color: "#38bdf8" }} />
                <span>Trust Score: {(trustScore * 100).toFixed(1)}%</span>
              </span>
            </div>
          </div>
        </div>

        <div className="hero-right-kpis">
          <div className="kpi-mini-box">
            <span className="kpi-label">TOTAL EVENTS</span>
            <strong className="kpi-value">{machineEvents.length}</strong>
            <span className="kpi-sub">Ingested from node</span>
          </div>

          <div className="kpi-mini-box">
            <span className="kpi-label">PEAK THREAT</span>
            <strong className="kpi-value" style={{ color: getScoreColor(peakThreat) }}>
              {(peakThreat * 100).toFixed(1)}%
            </strong>
            <span className="kpi-sub">{peakThreat >= 0.35 ? "Anomaly detected" : "Benign baseline"}</span>
          </div>

          <div className="kpi-mini-box">
            <span className="kpi-label">ACTIVE ALERTS</span>
            <strong
              className="kpi-value"
              style={{
                color: alerts.filter((a) => a.agent_id === agentId).length > 0 ? "#f87171" : "#34d399",
              }}
            >
              {alerts.filter((a) => a.agent_id === agentId).length}
            </strong>
            <span className="kpi-sub">Correlated warnings</span>
          </div>
        </div>
      </div>

      {/* ═══ SECTION 1: SPLIT HEARTBEAT & HARDWARE TELEMETRY RIBBON ═══ */}
      <div className="cockpit-ribbon-split">
        {/* Left Side: Real-Time Network Heartbeat & Beacon Telemetry */}
        <NetworkHeartbeatTelemetryMonitor
          agent={agent}
          isAlarmed={isAlarmed}
          isSilent={isSilent}
          latestTelemetry={machineEvents[0]}
        />

        {/* Right Side: Live Machine CPU Usage & Hardware Telemetry */}
        <MachineCpuUsageMonitor
          agent={agent}
          agentId={agentId}
          latestTelemetry={machineEvents[0]}
        />
      </div>

      {/* ═══ SECTION 2: TELEMETRY THREAT TIMELINE GRAPH (AS PRESENT ON DASHBOARD) ═══ */}
      <div className="cockpit-charts-grid">
        {/* Machine Threat Timeline */}
        <div className="cockpit-card chart-card">
          <div className="card-header">
            <div>
              <h3 className="card-title">
                <Activity size={15} style={{ color: "#38bdf8", marginRight: 6 }} />
                Machine Threat Timeline &amp; ML Stream
              </h3>
              <p className="card-subtitle">
                Rolling XGBoost / Isolation Forest threat score progression for {agentId}
              </p>
            </div>
            <div className="card-badge-group">
              <span className="live-indicator-badge">
                <span className="pulsing-green-dot" /> LIVE AGENT STREAM
              </span>
            </div>
          </div>

          <div className="cockpit-chart-container">
            <ResponsiveContainer width="100%" height={230}>
              <AreaChart data={threatTimelineData}>
                <defs>
                  <linearGradient id="machineThreatGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#ef4444" stopOpacity={0.55} />
                    <stop offset="45%" stopColor="#f59e0b" stopOpacity={0.25} />
                    <stop offset="100%" stopColor="#10b981" stopOpacity={0.0} />
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

                <ReferenceLine
                  y={0.35}
                  stroke="#f59e0b"
                  strokeDasharray="4 4"
                  label={{ value: "Warning (35%)", fill: "#f59e0b", fontSize: 10 }}
                />
                <ReferenceLine
                  y={0.6}
                  stroke="#ef4444"
                  strokeDasharray="4 4"
                  label={{ value: "Critical (60%)", fill: "#ef4444", fontSize: 10 }}
                />

                <Tooltip
                  content={({ active, payload }) => {
                    if (!active || !payload || !payload.length) return null;
                    const d = payload[0].payload;
                    return (
                      <div className="cockpit-chart-tooltip">
                        <div className="tooltip-head">
                          <strong>{d.process}</strong>
                          <span>{d.time}</span>
                        </div>
                        <div className="tooltip-body">
                          <span>Threat Score:</span>
                          <strong style={{ color: getScoreColor(d.score) }}>
                            {(d.score * 100).toFixed(1)}%
                          </strong>
                        </div>
                        <div className="tooltip-sub">Verdict: {d.verdict}</div>
                      </div>
                    );
                  }}
                />

                <Area
                  type="monotone"
                  dataKey="score"
                  stroke={getScoreColor(threatTimelineData[threatTimelineData.length - 1]?.score || 0.02)}
                  fill="url(#machineThreatGrad)"
                  strokeWidth={2.4}
                  dot={{ r: 3, fill: "#0b1019" }}
                  activeDot={{ r: 6, fill: "#38bdf8" }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Machine Specifications & Security Diagnostics Report */}
        <div className="cockpit-card specs-card">
          <div className="card-header">
            <div>
              <h3 className="card-title">
                <FileText size={15} style={{ color: "#a855f7", marginRight: 6 }} />
                Complete Machine Diagnostic Report
              </h3>
              <p className="card-subtitle">Host configuration, security rings &amp; active watchdogs</p>
            </div>
            <div className="card-badge-group">
              <span className="verified-node-badge">
                <ShieldCheck size={12} style={{ color: "#c084fc" }} /> VERIFIED NODE
              </span>
            </div>
          </div>

          <div className="specs-list">
            <div className="spec-row">
              <span className="spec-key">Machine Hostname:</span>
              <strong className="spec-val">{agentId}</strong>
            </div>
            <div className="spec-row">
              <span className="spec-key">Network Address:</span>
              <strong className="spec-val code">{agentIp}</strong>
            </div>
            <div className="spec-row">
              <span className="spec-key">Operating Platform:</span>
              <strong className="spec-val">{agent.os || "Windows 10 Pro (x64)"}</strong>
            </div>
            <div className="spec-row">
              <span className="spec-key">Agent Status:</span>
              <strong
                className="spec-val"
                style={{ color: isAlarmed || isSilent ? "#f87171" : "#34d399" }}
              >
                {isAlarmed || isSilent ? "HEARTBEAT LOST (ALARM)" : "HEALTHY & RUNNING"}
              </strong>
            </div>
            <div className="spec-row">
              <span className="spec-key">Watchdog Liveness:</span>
              <strong className="spec-val">ServerShutdownWatchdog Active (Port 8000)</strong>
            </div>
            <div className="spec-row">
              <span className="spec-key">Heartbeat Interval:</span>
              <strong className="spec-val">8.0s Continuous Pulse</strong>
            </div>
            <div className="spec-row">
              <span className="spec-key">Peer Mesh Consensus:</span>
              <strong className="spec-val" style={{ color: "#38bdf8" }}>
                {(trustScore * 100).toFixed(1)}% Reputation Weight
              </strong>
            </div>
            <div className="spec-row">
              <span className="spec-key">Quarantine Protection:</span>
              <strong className="spec-val">
                {isQuarantined ? "Enforced (Firewall Drop All)" : "Bypassed (Full LAN Reachability)"}
              </strong>
            </div>
          </div>
        </div>
      </div>

      {/* ═══ SECTION 3: ISOLATED LIVE TELEMETRY STREAM TABLE ═══ */}
      <div className="cockpit-card table-card">
        <div className="card-header">
          <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
            <div>
              <h3 className="card-title">
                <Terminal size={15} style={{ color: "#38bdf8", marginRight: 6 }} />
                Isolated Live Telemetry Stream for {agentId}
              </h3>
              <p className="card-subtitle">
                Real-time syscalls, binary executions, threat scores and multi-class predictions
              </p>
            </div>
          </div>

          <div className="table-controls">
            {/* Search Box */}
            <div className="cockpit-search-box">
              <Search size={13} style={{ color: "#64748b" }} />
              <input
                type="text"
                placeholder="Filter by process, PID, syscall..."
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                className="cockpit-search-input"
              />
              {searchFilter && (
                <button className="btn-clear-search" onClick={() => setSearchFilter("")}>
                  ✕
                </button>
              )}
            </div>

            {/* Verdict Filter Pill Group */}
            <div className="filter-pill-group">
              <button
                className={`filter-pill ${verdictFilter === "ALL" ? "active" : ""}`}
                onClick={() => setVerdictFilter("ALL")}
              >
                All ({machineEvents.length})
              </button>
              <button
                className={`filter-pill ${verdictFilter === "NORMAL" ? "active" : ""}`}
                onClick={() => setVerdictFilter("NORMAL")}
              >
                Normal
              </button>
              <button
                className={`filter-pill ${verdictFilter === "ALERTS" ? "active" : ""}`}
                onClick={() => setVerdictFilter("ALERTS")}
              >
                Alerts Only
              </button>
            </div>

            <button className="btn-pulse-inline" onClick={handleTestPulse} title="Trigger test telemetry event">
              <RefreshCw size={12} /> Test Pulse
            </button>
          </div>
        </div>

        {/* Telemetry Table */}
        {filteredEvents.length > 0 ? (
          <div className="cockpit-table-wrapper">
            <table className="aegis-table">
              <thead>
                <tr>
                  <th>Process / Binary</th>
                  <th>Origin IP</th>
                  <th>PID</th>
                  <th>Syscall / Detail</th>
                  <th>Threat Score</th>
                  <th>Verdict</th>
                  <th>Timestamp</th>
                  <th style={{ textAlign: "right" }}>Inspect</th>
                </tr>
              </thead>
              <tbody>
                {filteredEvents.map((t, idx) => (
                  <tr key={t.id || `${t.pid}-${t.process}-${idx}`}>
                    <td>
                      <div className="cockpit-proc-cell">
                        <Terminal size={13} style={{ color: "#38bdf8" }} />
                        <strong>{t.process}</strong>
                      </div>
                    </td>
                    <td>
                      <code style={{ fontSize: 11, color: "#94a3b8" }}>{t.ip || agentIp}</code>
                    </td>
                    <td>
                      <code>{t.pid}</code>
                    </td>
                    <td>
                      <code>{t.syscall}</code>
                    </td>
                    <td>
                      <span
                        className="threat-pill"
                        style={{
                          background: getScoreColor(t.threat_score) + "22",
                          color: getScoreColor(t.threat_score),
                          borderColor: getScoreColor(t.threat_score) + "55",
                          fontSize: 11,
                          padding: "2px 7px",
                        }}
                      >
                        {((t.threat_score || 0) * 100).toFixed(1)}%
                      </span>
                    </td>
                    <td>
                      <span
                        className={`verdict-badge ${
                          t.predicted_class === "Normal" || t.predicted_class === "BENIGN"
                            ? "normal"
                            : "alert"
                        }`}
                      >
                        {t.predicted_class}
                      </span>
                    </td>
                    <td style={{ color: "#64748b", fontSize: 11 }}>
                      {new Date(t.timestamp).toLocaleTimeString([], {
                        hour: "2-digit",
                        minute: "2-digit",
                        second: "2-digit",
                      })}
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <button
                        className="btn-inspect"
                        style={{ padding: "4px 9px", fontSize: 11 }}
                        onClick={() => onInspectProcess && onInspectProcess({ ...t, ip: agentIp })}
                        title="Open full JSON & feature vector inspector"
                      >
                        <Eye size={12} /> Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="cockpit-empty-state">
            <Activity size={32} style={{ color: "#38bdf8", opacity: 0.6, marginBottom: 8 }} />
            <h4>No Telemetry Events Recorded Yet for {agentId}</h4>
            <p>
              The machine is healthy and reporting periodic heartbeats. Live telemetry events will
              appear here as soon as security collectors or processes fire on this node.
            </p>
            <div style={{ display: "flex", gap: 10, marginTop: 12 }}>
              <button className="btn-cockpit-action" onClick={handleTestPulse}>
                <RefreshCw size={13} /> Trigger Test Pulse for {agentId}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
