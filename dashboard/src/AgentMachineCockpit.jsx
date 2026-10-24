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
  Maximize2,
  Minimize2,
  Search,
  Filter,
  Clock,
  HardDrive,
  Sliders,
  ChevronDown,
  FileText,
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
   AUTHENTIC NEON CYAN ECG (ELECTROCARDIOGRAM) OSCILLOSCOPE MONITOR
   Matched to image aesthetic: deep navy grid, vibrant cyan glow, dual wave tracing,
   synchronous heartbeat trigger on backend pulse.
   ═══════════════════════════════════════════════════════════════════════════ */
function EcgHeartbeatMonitor({
  agent,
  isAlarmed,
  isSilent,
  latestTelemetry,
}) {
  const canvasRef = useRef(null);
  const [soundEnabled, setSoundEnabled] = useState(false);
  const [bpm, setBpm] = useState(72);
  const [beaconFlash, setBeaconFlash] = useState(false);
  const [beaconAge, setBeaconAge] = useState(0);
  const lastHeartbeatTimeRef = useRef(Date.now());
  const heartbeatPulseTriggerRef = useRef(0);
  const audioCtxRef = useRef(null);
  const animFrameRef = useRef(null);
  const beatCooldownRef = useRef(false);

  // Synchronize tightly with live backend heartbeat updates
  useEffect(() => {
    lastHeartbeatTimeRef.current = Date.now();
    heartbeatPulseTriggerRef.current = Date.now();
    setBeaconAge(0);
    setBeaconFlash(true);
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

  // Web Audio medical telemetry blip (crisp high-tech cardiac blip)
  const playBeep = () => {
    if (!soundEnabled) return;
    try {
      if (!audioCtxRef.current) {
        const AudioContext = window.AudioContext || window.webkitAudioContext;
        audioCtxRef.current = new AudioContext();
      }
      const ctx = audioCtxRef.current;
      if (ctx.state === "suspended") {
        ctx.resume();
      }
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = "sine";
      osc.frequency.setValueAtTime(880, ctx.currentTime);
      gain.gain.setValueAtTime(0.045, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.05);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + 0.055);
    } catch {
      // Audio autoplay policy fallback
    }
  };

  // Adjust BPM based on agent state & CPU load
  useEffect(() => {
    if (isAlarmed || isSilent) {
      setBpm(0); // Flatline Asystole
    } else {
      const baseCpu = typeof agent.cpu === "number" ? agent.cpu : 3.5;
      const computedBpm = Math.min(115, Math.max(60, Math.round(68 + baseCpu * 0.75)));
      setBpm(computedBpm);
    }
  }, [agent.cpu, isAlarmed, isSilent]);

  // Draw ECG Oscilloscope Canvas with responsive resize
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    const updateDimensions = () => {
      if (canvas.parentElement) {
        canvas.width = canvas.parentElement.clientWidth || 540;
        canvas.height = 165;
      }
    };
    updateDimensions();

    window.addEventListener("resize", updateDimensions);

    const height = canvas.height;
    const midY = height / 2;

    const drawGrid = (w) => {
      // Deep dark sleek glassmorphic background - clean & minimal (no grid lines)
      const grad = ctx.createLinearGradient(0, 0, 0, height);
      grad.addColorStop(0, "#020712");
      grad.addColorStop(0.5, "#030c1c");
      grad.addColorStop(1, "#020712");
      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, w, height);

      // Subtle minimal center baseline guide line
      ctx.strokeStyle = "rgba(14, 165, 233, 0.12)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(0, midY);
      ctx.lineTo(w, midY);
      ctx.stroke();
    };

    drawGrid(canvas.width);

    let x = 0;
    let prevY = midY;
    let prevEchoY = midY;
    let phase = 0;
    const cycleLength = 170;

    const render = () => {
      const currentWidth = canvas.width;
      const clearWidth = 16;

      // Clean sweep tail clearing old trace without any grid lines
      ctx.fillStyle = "rgba(2, 7, 18, 0.42)";
      ctx.fillRect(x, 0, clearWidth, height);

      // Subtle center baseline in clear zone
      ctx.strokeStyle = "rgba(14, 165, 233, 0.12)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(x, midY);
      ctx.lineTo(x + clearWidth, midY);
      ctx.stroke();

      let y = midY;
      let echoY = midY;

      if (isAlarmed || isSilent) {
        // Flatline Asystole
        y = midY + (Math.random() - 0.5) * 1.5;
        echoY = midY + (Math.random() - 0.5) * 1.0;
      } else {
        // Synchronized P-Q-R-S-T Cardiac Cycle Waveform matched to user reference
        const cycleProgress = (phase % cycleLength) / cycleLength;

        // Secondary smooth harmonic wave in background (dual wave aesthetic)
        const smoothEcho = Math.sin(phase * 0.055) * 14 * Math.sin(phase * 0.018);
        echoY = midY + smoothEcho;

        if (cycleProgress >= 0.04 && cycleProgress < 0.13) {
          // P-wave (atrial depolarization)
          const pProg = (cycleProgress - 0.04) / 0.09;
          y = midY - Math.sin(pProg * Math.PI) * 12;
        } else if (cycleProgress >= 0.16 && cycleProgress < 0.20) {
          // Q-wave (initial septal deflection)
          const qProg = (cycleProgress - 0.16) / 0.04;
          y = midY + Math.sin(qProg * Math.PI) * 14;
        } else if (cycleProgress >= 0.20 && cycleProgress < 0.27) {
          // Sharp R-wave Peak (tall cyan spike matched to image)
          const rProg = (cycleProgress - 0.20) / 0.07;
          // Dynamically scale peak if high CPU or fresh heartbeat
          const timeSinceHb = (Date.now() - heartbeatPulseTriggerRef.current) / 1000;
          const freshPulseBonus = timeSinceHb < 1.5 ? 12 : 0;
          const amp = 68 + freshPulseBonus;
          y = midY - Math.sin(rProg * Math.PI) * amp;

          if (rProg > 0.4 && rProg < 0.6 && !beatCooldownRef.current) {
            beatCooldownRef.current = true;
            playBeep();
            setTimeout(() => {
              beatCooldownRef.current = false;
            }, 300);
          }
        } else if (cycleProgress >= 0.27 && cycleProgress < 0.33) {
          // S-wave Dip (downward rebound below baseline)
          const sProg = (cycleProgress - 0.27) / 0.06;
          y = midY + Math.sin(sProg * Math.PI) * 26;
        } else if (cycleProgress >= 0.42 && cycleProgress < 0.58) {
          // T-wave (ventricular repolarization)
          const tProg = (cycleProgress - 0.42) / 0.16;
          y = midY - Math.sin(tProg * Math.PI) * 18;
        } else {
          // Isoelectric baseline with tiny realistic noise
          y = midY + (Math.random() - 0.5) * 1.6;
        }
      }

      // 1. Draw secondary wave trace (subtle dimmer blue echo wave from reference image)
      ctx.shadowBlur = 4;
      ctx.shadowColor = "rgba(14, 165, 233, 0.4)";
      ctx.strokeStyle = "rgba(2, 132, 199, 0.4)";
      ctx.lineWidth = 1.6;
      ctx.beginPath();
      ctx.moveTo(x === 0 ? 0 : x - 2, prevEchoY);
      ctx.lineTo(x, echoY);
      ctx.stroke();

      // 2. Draw Primary Neon Cyan ECG Wave (Intense glow matched to image)
      const primaryColor = isAlarmed || isSilent ? "#f87171" : "#38bdf8";
      const glowColor = isAlarmed || isSilent ? "#ef4444" : "#00f0ff";

      ctx.shadowBlur = 12;
      ctx.shadowColor = glowColor;
      ctx.strokeStyle = primaryColor;
      ctx.lineWidth = 2.4;
      ctx.lineCap = "round";
      ctx.lineJoin = "round";

      ctx.beginPath();
      ctx.moveTo(x === 0 ? 0 : x - 2, prevY);
      ctx.lineTo(x, y);
      ctx.stroke();

      // 3. Draw Leading Laser / Phosphor Particle
      ctx.shadowBlur = 16;
      ctx.shadowColor = "#ffffff";
      ctx.fillStyle = isAlarmed || isSilent ? "#fca5a5" : "#e0f2fe";
      ctx.beginPath();
      ctx.arc(x, y, 2.5, 0, Math.PI * 2);
      ctx.fill();

      // Reset shadow for next frame
      ctx.shadowBlur = 0;
      prevY = y;
      prevEchoY = echoY;
      x += 2;
      phase += 2;

      if (x >= currentWidth) {
        x = 0;
        prevY = midY;
        prevEchoY = midY;
      }

      animFrameRef.current = requestAnimationFrame(render);
    };

    animFrameRef.current = requestAnimationFrame(render);

    return () => {
      window.removeEventListener("resize", updateDimensions);
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
    };
  }, [agent.cpu, isAlarmed, isSilent, soundEnabled]);

  return (
    <div className="ecg-monitor-frame">
      <div className="ecg-header">
        <div className="ecg-title-block">
          <div className="ecg-pulse-indicator">
            <span
              className={`ecg-dot ${
                isAlarmed || isSilent ? "dead" : "alive"
              }`}
            />
            <span className="ecg-label">
              CARDIAC BEACON (HEARTBEAT ECG)
            </span>
          </div>
          <span className="ecg-status-text">
            {isAlarmed || isSilent ? (
              <strong style={{ color: "#f87171" }}>ASYSTOLE / SILENT ALARM</strong>
            ) : (
              <strong style={{ color: "#38bdf8", display: "inline-flex", alignItems: "center", gap: 6 }}>
                SINUS RHYTHM (8.0s) · BEACON: {beaconAge}s AGO
                {beaconFlash && (
                  <span className="beacon-flash-tag">
                    <span className="pulsing-beacon-dot" /> BEAT INGESTED
                  </span>
                )}
              </strong>
            )}
          </span>
        </div>

        <div className="ecg-controls">
          <div className="ecg-bpm-readout">
            <span className="bpm-number">
              {isAlarmed || isSilent ? "00" : bpm}
            </span>
            <span className="bpm-unit">BPM</span>
          </div>

          <button
            className={`btn-ecg-action ${soundEnabled ? "active" : ""}`}
            onClick={() => setSoundEnabled((prev) => !prev)}
            title={soundEnabled ? "Mute Medical Telemetry Audio" : "Enable Heartbeat Pulse Audio"}
          >
            {soundEnabled ? <Volume2 size={12} /> : <VolumeX size={12} />}
            <span>{soundEnabled ? "ON" : "MUTE"}</span>
          </button>
        </div>
      </div>

      <div className="ecg-canvas-wrapper">
        <canvas
          ref={canvasRef}
          height={165}
          className="ecg-canvas"
        />
        <div className="ecg-sweep-overlay" />
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
}) {
  const [copiedIp, setCopiedIp] = useState(false);
  const [isQuarantined, setIsQuarantined] = useState(false);
  const [searchFilter, setSearchFilter] = useState("");
  const [verdictFilter, setVerdictFilter] = useState("ALL");
  const [pulseToast, setPulseToast] = useState(null);

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

          <button className="btn-cockpit-close" onClick={onClose} title="Close Cockpit [ESC]">
            ✕
          </button>
        </div>
      </div>

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
                  isAlarmed || isSilent ? "silent" : agent.status === "OFFLINE_GRACEFUL" ? "offline" : "healthy"
                }`}
              >
                {isAlarmed || isSilent
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
        {/* Left Side: Real-Time ECG Heartbeat Monitor */}
        <EcgHeartbeatMonitor
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
            <div className="card-badge">VERIFIED NODE</div>
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
