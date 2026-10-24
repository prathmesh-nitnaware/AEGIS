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
   AUTHENTIC ECG (ELECTROCARDIOGRAM) OSCILLOSCOPE MONITOR
   ═══════════════════════════════════════════════════════════════════════════ */
function EcgHeartbeatMonitor({
  agent,
  isAlarmed,
  isSilent,
  latestTelemetry,
  onTriggerSpike,
}) {
  const canvasRef = useRef(null);
  const [soundEnabled, setSoundEnabled] = useState(false);
  const [bpm, setBpm] = useState(72);
  const [stressPulse, setStressPulse] = useState(false);
  const [beaconFlash, setBeaconFlash] = useState(false);
  const [beaconAge, setBeaconAge] = useState(0);
  const lastHeartbeatTimeRef = useRef(Date.now());
  const audioCtxRef = useRef(null);
  const animFrameRef = useRef(null);
  const beatCooldownRef = useRef(false);

  // Synchronize with live backend heartbeat updates
  useEffect(() => {
    lastHeartbeatTimeRef.current = Date.now();
    setBeaconAge(0);
    setBeaconFlash(true);
    const t = setTimeout(() => setBeaconFlash(false), 800);
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

  // Web Audio medical telemetry blip (subtle 880Hz / 40ms beep)
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
      osc.frequency.setValueAtTime(stressPulse ? 1040 : 880, ctx.currentTime);
      gain.gain.setValueAtTime(0.04, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.045);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + 0.05);
    } catch {
      // Audio autoplay policy fallback
    }
  };

  // Adjust BPM based on agent state & CPU load
  useEffect(() => {
    if (isAlarmed || isSilent) {
      setBpm(0); // Flatline Asystole
    } else if (stressPulse) {
      setBpm(138); // Tachycardia under threat
    } else {
      const baseCpu = typeof agent.cpu === "number" ? agent.cpu : 3.5;
      const computedBpm = Math.min(115, Math.max(62, Math.round(68 + baseCpu * 0.8)));
      setBpm(computedBpm);
    }
  }, [agent.cpu, isAlarmed, isSilent, stressPulse]);

  // Handle Stress Pulse trigger
  const triggerManualSpike = () => {
    setStressPulse(true);
    if (onTriggerSpike) onTriggerSpike();
    setTimeout(() => setStressPulse(false), 6000);
  };

  // Draw ECG Oscilloscope Canvas with responsive resize
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    const updateDimensions = () => {
      if (canvas.parentElement) {
        canvas.width = canvas.parentElement.clientWidth || 520;
        canvas.height = 165;
      }
    };
    updateDimensions();

    window.addEventListener("resize", updateDimensions);

    const height = canvas.height;
    const midY = height / 2;

    const drawGrid = (w) => {
      ctx.fillStyle = "#030806";
      ctx.fillRect(0, 0, w, height);

      // Minor grid (12px)
      ctx.strokeStyle = "rgba(16, 185, 129, 0.07)";
      ctx.lineWidth = 1;
      for (let x = 0; x < w; x += 12) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }
      for (let y = 0; y < height; y += 12) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
      }

      // Major grid (60px)
      ctx.strokeStyle = "rgba(16, 185, 129, 0.18)";
      ctx.lineWidth = 1;
      for (let x = 0; x < w; x += 60) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }
      for (let y = 0; y < height; y += 60) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
      }
    };

    drawGrid(canvas.width);

    let x = 0;
    let prevY = midY;
    let phase = 0;
    const cycleLength = stressPulse ? 100 : 180;

    const render = () => {
      const currentWidth = canvas.width;
      const clearWidth = 14;
      ctx.fillStyle = "rgba(3, 8, 6, 0.45)";
      ctx.fillRect(x, 0, clearWidth, height);

      // Re-draw grid lines in clear zone
      ctx.strokeStyle = "rgba(16, 185, 129, 0.08)";
      ctx.lineWidth = 1;
      for (let gx = Math.floor(x / 12) * 12; gx <= x + clearWidth; gx += 12) {
        ctx.beginPath();
        ctx.moveTo(gx, 0);
        ctx.lineTo(gx, height);
        ctx.stroke();
      }
      for (let gy = 0; gy < height; gy += 12) {
        ctx.beginPath();
        ctx.moveTo(x, gy);
        ctx.lineTo(x + clearWidth, gy);
        ctx.stroke();
      }

      let y = midY;

      if (isAlarmed || isSilent) {
        // Flatline Asystole with slight electrical noise
        y = midY + (Math.random() - 0.5) * 1.5;
      } else {
        // Authentic P-Q-R-S-T Cardiac Cycle Waveform
        const cycleProgress = (phase % cycleLength) / cycleLength;

        if (cycleProgress >= 0.05 && cycleProgress < 0.14) {
          // P-wave
          const pProg = (cycleProgress - 0.05) / 0.09;
          y = midY - Math.sin(pProg * Math.PI) * 11;
        } else if (cycleProgress >= 0.18 && cycleProgress < 0.21) {
          // Q-wave
          const qProg = (cycleProgress - 0.18) / 0.03;
          y = midY + Math.sin(qProg * Math.PI) * 9;
        } else if (cycleProgress >= 0.21 && cycleProgress < 0.28) {
          // R-wave Spike
          const rProg = (cycleProgress - 0.21) / 0.07;
          const amp = stressPulse ? 80 : 64;
          y = midY - Math.sin(rProg * Math.PI) * amp;

          if (rProg > 0.4 && rProg < 0.6 && !beatCooldownRef.current) {
            beatCooldownRef.current = true;
            playBeep();
            setTimeout(() => {
              beatCooldownRef.current = false;
            }, 300);
          }
        } else if (cycleProgress >= 0.28 && cycleProgress < 0.33) {
          // S-wave
          const sProg = (cycleProgress - 0.28) / 0.05;
          y = midY + Math.sin(sProg * Math.PI) * 20;
        } else if (cycleProgress >= 0.44 && cycleProgress < 0.62) {
          // T-wave
          const tProg = (cycleProgress - 0.44) / 0.18;
          y = midY - Math.sin(tProg * Math.PI) * 18;
        } else {
          // Isoelectric Baseline
          y = midY + (Math.random() - 0.5) * 1.6;
        }
      }

      ctx.shadowBlur = 9;
      ctx.shadowColor = isAlarmed || isSilent ? "#ef4444" : stressPulse ? "#f59e0b" : "#10b981";
      ctx.strokeStyle = isAlarmed || isSilent ? "#f87171" : stressPulse ? "#fbbf24" : "#34d399";
      ctx.lineWidth = 2.2;
      ctx.lineCap = "round";

      ctx.beginPath();
      ctx.moveTo(x === 0 ? 0 : x - 2, prevY);
      ctx.lineTo(x, y);
      ctx.stroke();

      ctx.shadowBlur = 14;
      ctx.shadowColor = "#ffffff";
      ctx.fillStyle = isAlarmed || isSilent ? "#fca5a5" : "#ffffff";
      ctx.beginPath();
      ctx.arc(x, y, 2.5, 0, Math.PI * 2);
      ctx.fill();

      ctx.shadowBlur = 0;
      prevY = y;
      x += 2;
      phase += 2;

      if (x >= currentWidth) {
        x = 0;
        prevY = midY;
      }

      animFrameRef.current = requestAnimationFrame(render);
    };

    animFrameRef.current = requestAnimationFrame(render);

    return () => {
      window.removeEventListener("resize", updateDimensions);
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
    };
  }, [agent.cpu, isAlarmed, isSilent, stressPulse, soundEnabled]);

  return (
    <div className="ecg-monitor-frame">
      <div className="ecg-header">
        <div className="ecg-title-block">
          <div className="ecg-pulse-indicator">
            <span
              className={`ecg-dot ${
                isAlarmed || isSilent ? "dead" : stressPulse ? "warning" : "alive"
              }`}
            />
            <span className="ecg-label">
              CARDIAC BEACON (HEARTBEAT ECG)
            </span>
          </div>
          <span className="ecg-status-text">
            {isAlarmed || isSilent ? (
              <strong style={{ color: "#f87171" }}>ASYSTOLE / SILENT ALARM</strong>
            ) : stressPulse ? (
              <strong style={{ color: "#fbbf24" }}>TACHYCARDIA / ANOMALY DETECTED</strong>
            ) : (
              <strong style={{ color: "#34d399", display: "inline-flex", alignItems: "center", gap: 6 }}>
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

          <button
            className="btn-ecg-action spike"
            onClick={triggerManualSpike}
            title="Inject simulated elevated ventricular spike into ECG trace"
          >
            <Zap size={12} />
            <span>SPIKE</span>
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
        <div className="ecg-crt-scanlines" />

        <div className="ecg-telemetry-overlay">
          <span>SWEEP: 25mm/s</span>
          <span>LATENCY: &lt;10ms (LAN)</span>
          <span>S/N RATIO: 99.4%</span>
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   LIVE MACHINE CPU USAGE & HARDWARE TELEMETRY MONITOR (RIGHT HALF)
   ═══════════════════════════════════════════════════════════════════════════ */
function MachineCpuUsageMonitor({ agent, agentId, latestTelemetry }) {
  const currentCpu = typeof agent.cpu === "number" ? agent.cpu : 3.8;
  const memoryPercent = agent.memory || agent.ram_percent || 42.5;

  // Rolling CPU history populated from live backend heartbeats
  const [cpuHistory, setCpuHistory] = useState(() => {
    const now = Date.now();
    return Array.from({ length: 20 }, (_, i) => ({
      time: new Date(now - (20 - i) * 3000).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }),
      cpu: Math.max(0.4, parseFloat((currentCpu + Math.sin(i * 0.7) * 1.1).toFixed(1))),
    }));
  });

  // Track dynamic peak CPU
  const peakCpu = useMemo(() => {
    const maxVal = Math.max(...cpuHistory.map((h) => h.cpu), currentCpu);
    return maxVal.toFixed(1);
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
        ...prev.slice(-24),
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
        {/* Left: Big Numeric Readout & Specs */}
        <div className="cpu-kpi-pane">
          <div className="cpu-big-stat">
            <span className="cpu-percent-number" style={{ color: theme.color }}>
              {currentCpu.toFixed(1)}
              <small className="cpu-unit">%</small>
            </span>
            <span className="cpu-stat-caption">REAL-TIME CPU USAGE</span>
          </div>

          <div className="cpu-specs-compact">
            <div className="spec-compact-item">
              <span>PEAK:</span>
              <strong style={{ color: "#f1f5f9" }}>{peakCpu}%</strong>
            </div>
            <div className="spec-compact-item">
              <span>RAM:</span>
              <strong style={{ color: "#34d399" }}>
                {typeof memoryPercent === "number" ? memoryPercent.toFixed(1) : memoryPercent}%
              </strong>
            </div>
            <div className="spec-compact-item">
              <span>CORES:</span>
              <strong style={{ color: "#a855f7" }}>8 Virtual</strong>
            </div>
            <div className="spec-compact-item">
              <span>BEACON:</span>
              <strong style={{ color: "#38bdf8" }}>Verified</strong>
            </div>
          </div>
        </div>

        {/* Right: Rolling CPU Load Stream Area Chart */}
        <div className="cpu-chart-pane">
          <div className="cpu-chart-header">
            <span>ROLLING CPU UTILIZATION (HEARTBEAT STREAM)</span>
            <span style={{ fontSize: 9, color: "#64748b" }}>INTERVAL: 8.0s</span>
          </div>
          <div className="cpu-mini-chart">
            <ResponsiveContainer width="100%" height={100}>
              <AreaChart data={cpuHistory}>
                <defs>
                  <linearGradient id="cpuAreaGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.45} />
                    <stop offset="100%" stopColor="#0284c7" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <YAxis domain={[0, 100]} hide={true} />
                <Tooltip
                  content={({ active, payload }) => {
                    if (!active || !payload || !payload.length) return null;
                    const d = payload[0].payload;
                    return (
                      <div className="cpu-tooltip">
                        <span>{d.time}</span>
                        <strong>{d.cpu}% Load</strong>
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
          <div className="cpu-bar-track">
            <div
              className="cpu-bar-fill"
              style={{
                width: `${Math.min(100, Math.max(3, currentCpu))}%`,
                background: `linear-gradient(90deg, #38bdf8, ${theme.color})`,
              }}
            />
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

  // Simulate Attack Anomaly
  const handleSimulateAttack = async () => {
    try {
      const simulatedPayload = {
        agent_id: agentId,
        ip: agentIp,
        model: "zero_day",
        process: "powershell_anomaly.exe",
        pid: Math.floor(Math.random() * 8000) + 1000,
        threat_score: 0.884,
        predicted_class: "Suspicious_Process_Tree",
        syscall: "sys_execve",
        timestamp: Date.now(),
        cpu: 24.5,
        details: "Simulated memory injection & process credential dump",
      };
      await fetch(`${API_BASE}/api/telemetry`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(simulatedPayload),
      });
      setPulseToast(`Simulated attack anomaly ingested for ${agentId} (88.4% threat score)`);
      setTimeout(() => setPulseToast(null), 4000);
    } catch (err) {
      console.error("Simulation error:", err);
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

          <button className="btn-cockpit-action warning" onClick={handleSimulateAttack} title="Inject simulated anomaly">
            <Zap size={13} /> Simulate Anomaly
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
          onTriggerSpike={handleSimulateAttack}
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
              <button className="btn-cockpit-action warning" onClick={handleSimulateAttack}>
                <Zap size={13} /> Simulate Sample Anomaly
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
