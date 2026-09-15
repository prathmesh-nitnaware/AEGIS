import React, { useState, useEffect, useCallback } from "react";
import {
  Swords,
  Play,
  Square,
  Shield,
  Activity,
  Zap,
  Clock,
  CheckCircle2,
  AlertTriangle,
  FileDown,
  RefreshCw,
  Skull,
  Crosshair,
  Lock,
  Cpu,
  Flame,
} from "lucide-react";

const KILL_CHAIN_PHASES = [
  { id: "Phase 1: Recon (PortScan)", name: "Phase 1: Reconnaissance", desc: "Horizontal SYN Sweep on critical ports", icon: Crosshair },
  { id: "Phase 2: Initial Access (SSH Brute Force)", name: "Phase 2: Initial Access", desc: "12-thread Hydra dictionary attack on Port 22", icon: Lock },
  { id: "Phase 3: Privilege Escalation (Ptrace/Exploit)", name: "Phase 3: Privilege Escalation", desc: "Kernel exploit & ptrace memory tampering", icon: Flame },
  { id: "Phase 4: Ransomware Dropper", name: "Phase 4: Ransomware Dropper", desc: "VSS shadow deletion & high-entropy payload", icon: Skull },
  { id: "Phase 5: Defense Evasion & Sabotage", name: "Phase 5: Defense Evasion", desc: "Agent heartbeat sabotage & silence alarm", icon: Zap },
];

export default function BattleArenaTab() {
  const [battleState, setBattleState] = useState(null);
  const [loading, setLoading] = useState(false);
  const [targetAgent, setTargetAgent] = useState("vm1-linux");
  const [stepDelay, setStepDelay] = useState(1.5);
  const [toast, setToast] = useState(null);

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch("http://127.0.0.1:8000/api/battle/status");
      if (res.ok) {
        const data = await res.json();
        setBattleState(data);
      }
    } catch (e) {
      console.error("Failed to fetch battle status:", e);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 1500);
    return () => clearInterval(interval);
  }, [fetchStatus]);

  const startBattle = async () => {
    setLoading(true);
    try {
      const res = await fetch("http://127.0.0.1:8000/api/battle/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_agent_id: targetAgent,
          target_ip: "172.30.0.21",
          step_delay: Number(stepDelay),
        }),
      });
      if (res.ok) {
        setToast("5-Phase Adversary Campaign launched against " + targetAgent);
      } else {
        const err = await res.json();
        setToast(err.detail || "Failed to start battle campaign");
      }
    } catch (e) {
      setToast("Error connecting to Command Node: " + e.message);
    } finally {
      setLoading(false);
      fetchStatus();
    }
  };

  const stopBattle = async () => {
    try {
      await fetch("http://127.0.0.1:8000/api/battle/stop", { method: "POST" });
      setToast("Battle campaign aborted.");
      fetchStatus();
    } catch (e) {
      console.error(e);
    }
  };

  const isRunning = battleState?.status === "RUNNING";
  const currentPhaseIndex = KILL_CHAIN_PHASES.findIndex((p) => p.id === battleState?.current_phase);
  const kpis = battleState?.kpi_metrics || {};

  return (
    <div className="battle-arena-container" style={{ padding: "4px 0" }}>
      {/* Toast */}
      {toast && (
        <div
          style={{
            background: "#1e293b",
            border: "1px solid #38bdf8",
            color: "#f8fafc",
            padding: "10px 16px",
            borderRadius: "8px",
            marginBottom: "16px",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <span>{toast}</span>
          <button
            onClick={() => setToast(null)}
            style={{ background: "transparent", border: "none", color: "#94a3b8", cursor: "pointer" }}
          >
            ✕
          </button>
        </div>
      )}

      {/* Header Banner */}
      <div
        style={{
          background: "linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%)",
          border: "1px solid #312e81",
          borderRadius: "12px",
          padding: "20px 24px",
          marginBottom: "20px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
        }}
      >
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "6px" }}>
            <Swords size={24} color="#818cf8" />
            <h2 style={{ margin: 0, fontSize: "20px", color: "#f8fafc", fontWeight: 800 }}>
              Automated Red vs. Blue Live Battle Campaign
            </h2>
            <span
              style={{
                background: isRunning ? "#ef4444" : "#10b981",
                color: "#fff",
                fontSize: "11px",
                fontWeight: 700,
                padding: "3px 10px",
                borderRadius: "20px",
                textTransform: "uppercase",
                letterSpacing: "0.5px",
              }}
            >
              {battleState?.status || "IDLE"}
            </span>
          </div>
          <p style={{ margin: 0, fontSize: "13px", color: "#94a3b8" }}>
            5-Phase MITRE ATT&amp;CK Kill-Chain Simulation vs. Autonomous Bayesian Swarm Defense
          </p>
        </div>

        <div style={{ display: "flex", gap: "12px", alignItems: "center" }}>
          <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
            <label style={{ fontSize: "11px", color: "#94a3b8" }}>Target System</label>
            <select
              value={targetAgent}
              onChange={(e) => setTargetAgent(e.target.value)}
              disabled={isRunning}
              style={{
                background: "#0f172a",
                border: "1px solid #334155",
                color: "#f8fafc",
                borderRadius: "6px",
                padding: "6px 10px",
                fontSize: "12px",
              }}
            >
              <option value="vm1-linux">vm1-linux (172.30.0.21)</option>
              <option value="vm2-windows">vm2-windows (172.30.0.22)</option>
              <option value="vm3-server">vm3-server (172.30.0.23)</option>
            </select>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
            <label style={{ fontSize: "11px", color: "#94a3b8" }}>Step Pace</label>
            <select
              value={stepDelay}
              onChange={(e) => setStepDelay(e.target.value)}
              disabled={isRunning}
              style={{
                background: "#0f172a",
                border: "1px solid #334155",
                color: "#f8fafc",
                borderRadius: "6px",
                padding: "6px 10px",
                fontSize: "12px",
              }}
            >
              <option value="1.0">Fast (1.0s)</option>
              <option value="2.0">Standard (2.0s)</option>
              <option value="3.5">Slow-Mo (3.5s)</option>
            </select>
          </div>

          {!isRunning ? (
            <button
              onClick={startBattle}
              disabled={loading}
              style={{
                background: "linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%)",
                border: "none",
                color: "#fff",
                fontWeight: 700,
                fontSize: "13px",
                padding: "10px 20px",
                borderRadius: "8px",
                display: "flex",
                alignItems: "center",
                gap: "8px",
                boxShadow: "0 4px 14px rgba(99, 102, 241, 0.4)",
              }}
            >
              <Play size={16} />
              Launch Battle
            </button>
          ) : (
            <button
              onClick={stopBattle}
              style={{
                background: "#ef4444",
                border: "none",
                color: "#fff",
                fontWeight: 700,
                fontSize: "13px",
                padding: "10px 20px",
                borderRadius: "8px",
                display: "flex",
                alignItems: "center",
                gap: "8px",
              }}
            >
              <Square size={16} />
              Abort Battle
            </button>
          )}
        </div>
      </div>

      {/* KPI Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "16px", marginBottom: "20px" }}>
        <div style={{ background: "#0b1019", border: "1px solid #1c2533", borderRadius: "10px", padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "#64748b", textTransform: "uppercase", marginBottom: "4px" }}>
            Avg Detection Latency
          </div>
          <div style={{ fontSize: "22px", fontWeight: 800, color: "#38bdf8" }}>
            {kpis.avg_detection_latency_us ? `${kpis.avg_detection_latency_us} µs` : "0.0 µs"}
          </div>
          <div style={{ fontSize: "11px", color: "#10b981", marginTop: "4px" }}>⚡ Sub-Millisecond Speed</div>
        </div>

        <div style={{ background: "#0b1019", border: "1px solid #1c2533", borderRadius: "10px", padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "#64748b", textTransform: "uppercase", marginBottom: "4px" }}>
            Processes Terminated
          </div>
          <div style={{ fontSize: "22px", fontWeight: 800, color: "#ef4444" }}>
            {kpis.processes_killed || 0}
          </div>
          <div style={{ fontSize: "11px", color: "#94a3b8", marginTop: "4px" }}>Autonomous SIGKILL</div>
        </div>

        <div style={{ background: "#0b1019", border: "1px solid #1c2533", borderRadius: "10px", padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "#64748b", textTransform: "uppercase", marginBottom: "4px" }}>
            Firewall Rules Injected
          </div>
          <div style={{ fontSize: "22px", fontWeight: 800, color: "#f59e0b" }}>
            {kpis.firewall_rules_applied || 0}
          </div>
          <div style={{ fontSize: "11px", color: "#94a3b8", marginTop: "4px" }}>Port / Source Drop Rules</div>
        </div>

        <div style={{ background: "#0b1019", border: "1px solid #1c2533", borderRadius: "10px", padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "#64748b", textTransform: "uppercase", marginBottom: "4px" }}>
            Host Network Isolations
          </div>
          <div style={{ fontSize: "22px", fontWeight: 800, color: "#a855f7" }}>
            {kpis.hosts_isolated || 0}
          </div>
          <div style={{ fontSize: "11px", color: "#94a3b8", marginTop: "4px" }}>Quarantine Containment</div>
        </div>
      </div>

      {/* 5-Phase Progression Kill-Chain Card */}
      <div style={{ background: "#0b1019", border: "1px solid #1c2533", borderRadius: "10px", padding: "20px", marginBottom: "20px" }}>
        <h3 style={{ margin: "0 0 16px 0", fontSize: "14px", color: "#f8fafc", fontWeight: 700 }}>
          Adversary Kill-Chain Timeline
        </h3>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: "12px" }}>
          {KILL_CHAIN_PHASES.map((phase, idx) => {
            const isCurrent = currentPhaseIndex === idx && isRunning;
            const isPast = currentPhaseIndex > idx || (!isRunning && battleState?.status === "COMPLETED");
            const Icon = phase.icon;

            let borderColor = "#1c2533";
            let bgColor = "#0f172a";
            let statusBadge = "PENDING";
            let badgeColor = "#64748b";

            if (isCurrent) {
              borderColor = "#f59e0b";
              bgColor = "rgba(245, 158, 11, 0.1)";
              statusBadge = "ATTACKING";
              badgeColor = "#f59e0b";
            } else if (isPast) {
              borderColor = "#10b981";
              bgColor = "rgba(16, 185, 129, 0.08)";
              statusBadge = "DEFENDED";
              badgeColor = "#10b981";
            }

            return (
              <div
                key={phase.id}
                style={{
                  background: bgColor,
                  border: `1.5px solid ${borderColor}`,
                  borderRadius: "8px",
                  padding: "14px",
                  display: "flex",
                  flexDirection: "column",
                  gap: "8px",
                  transition: "all 0.3s ease",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <Icon size={18} color={badgeColor} />
                  <span
                    style={{
                      fontSize: "10px",
                      fontWeight: 700,
                      color: badgeColor,
                      textTransform: "uppercase",
                    }}
                  >
                    {statusBadge}
                  </span>
                </div>
                <div style={{ fontSize: "12px", fontWeight: 700, color: "#f8fafc" }}>
                  {phase.name}
                </div>
                <div style={{ fontSize: "11px", color: "#94a3b8", lineHeight: "1.4" }}>
                  {phase.desc}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Live Battle Log Stream */}
      <div style={{ background: "#0b1019", border: "1px solid #1c2533", borderRadius: "10px", padding: "20px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px" }}>
          <h3 style={{ margin: 0, fontSize: "14px", color: "#f8fafc", fontWeight: 700 }}>
            Live Battle Events &amp; Autonomous Defender Actions
          </h3>
          {battleState?.incident_report_pdf && (
            <a
              href="http://127.0.0.1:8000/api/reports/executive"
              target="_blank"
              rel="noreferrer"
              style={{
                display: "flex",
                alignItems: "center",
                gap: "6px",
                color: "#38bdf8",
                fontSize: "12px",
                fontWeight: 600,
                textDecoration: "none",
              }}
            >
              <FileDown size={14} /> Download Incident Audit PDF
            </a>
          )}
        </div>

        <div
          style={{
            maxHeight: "260px",
            overflowY: "auto",
            display: "flex",
            flexDirection: "column",
            gap: "8px",
            fontFamily: "JetBrains Mono, Consolas, monospace",
            fontSize: "11px",
          }}
        >
          {battleState?.logs && battleState.logs.length > 0 ? (
            battleState.logs
              .slice()
              .reverse()
              .map((log, i) => {
                const isAction = log.includes("DEFENDER ACTION") || log.includes("MITIGATION");
                const isPhase = log.includes("STARTING PHASE");
                const isComplete = log.includes("CAMPAIGN COMPLETE");

                let color = "#cbd5e1";
                if (isAction) color = "#34d399";
                if (isPhase) color = "#fbbf24";
                if (isComplete) color = "#60a5fa";

                return (
                  <div
                    key={i}
                    style={{
                      background: "#070b12",
                      border: "1px solid #182232",
                      borderRadius: "6px",
                      padding: "8px 12px",
                      color: color,
                      display: "flex",
                      gap: "10px",
                    }}
                  >
                    <span style={{ color: "#64748b" }}>[{new Date().toLocaleTimeString()}]</span>
                    <span>{log}</span>
                  </div>
                );
              })
          ) : (
            <div style={{ color: "#64748b", textAlign: "center", padding: "20px" }}>
              No active battle logs. Click "Launch Battle" to simulate adversary engagement.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
