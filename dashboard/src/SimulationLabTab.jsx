import React, { useState, useEffect, useRef } from "react";
import {
  Zap,
  Play,
  Terminal,
  ShieldAlert,
  Cpu,
  Server,
  Skull,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Activity,
  ArrowRight,
} from "lucide-react";

export default function SimulationLabTab({ apiBase, wsData }) {
  const [simState, setSimState] = useState({
    is_running: false,
    current_scenario: null,
    progress: 0,
    logs: [],
    history: [],
  });
  const [loadingAction, setLoadingAction] = useState(null);
  const terminalEndRef = useRef(null);

  // Fetch initial simulation status
  const fetchStatus = async () => {
    try {
      const res = await fetch(`${apiBase}/api/simulation/status`);
      if (res.ok) {
        const data = await res.json();
        setSimState(data);
      }
    } catch (err) {
      console.error("Failed to fetch simulation status:", err);
    }
  };

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 3000);
    return () => clearInterval(interval);
  }, [apiBase]);

  // Listen for WebSocket live simulation events
  useEffect(() => {
    if (!wsData) return;
    if (wsData.type === "simulation_progress" && wsData.log) {
      setSimState((prev) => ({
        ...prev,
        is_running: true,
        current_scenario: wsData.scenario || prev.current_scenario,
        progress: wsData.progress !== undefined ? wsData.progress : prev.progress,
        logs: [...(prev.logs || []), wsData.log].slice(-100),
      }));
    } else if (wsData.type === "simulation_complete") {
      setSimState((prev) => ({
        ...prev,
        is_running: false,
        progress: 100,
        last_result: wsData.result,
        history: [wsData.result, ...(prev.history || [])].slice(0, 20),
      }));
    }
  }, [wsData]);

  // Auto-scroll terminal to bottom when new logs arrive
  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [simState.logs]);

  const launchScenario = async (scenarioKey) => {
    setLoadingAction(scenarioKey);
    try {
      const res = await fetch(`${apiBase}/api/simulation/launch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenario: scenarioKey }),
      });
      const data = await res.json();
      if (res.ok) {
        setSimState((prev) => ({
          ...prev,
          is_running: true,
          current_scenario: scenarioKey,
          progress: 10,
        }));
      } else {
        alert(data.message || "Failed to launch simulation.");
      }
    } catch (err) {
      alert("Error connecting to Command Node: " + err.message);
    } finally {
      setLoadingAction(null);
    }
  };

  const resetSimulation = async () => {
    try {
      await fetch(`${apiBase}/api/simulation/reset`, { method: "POST" });
      setSimState((prev) => ({
        ...prev,
        is_running: false,
        current_scenario: null,
        progress: 0,
        logs: [],
      }));
    } catch (err) {
      console.error("Failed to reset simulation:", err);
    }
  };

  const scenarios = [
    {
      id: "linux",
      title: "Linux Multi-Stage Attack",
      subtitle: "Hydra SSH Brute-Force & Java Meterpreter RCE",
      target: "endpoint-linux",
      os: "Linux / Debian",
      icon: Terminal,
      color: "#ef4444",
      bgGlow: "rgba(239, 68, 68, 0.12)",
      techniques: ["T1110 (Brute Force)", "T1059 (Meterpreter Shell)"],
      expectedAction: "KILL_PROCESS (PID 1420)",
      description: "Generates brute-force SSH password spraying followed by reverse Meterpreter TCP connection. Verifies multi-agent consensus quorum and autonomous process termination.",
    },
    {
      id: "windows",
      title: "Windows Ransomware & Dropper",
      subtitle: "EMBER PE Inspection & High-Entropy Encryption",
      target: "endpoint-windows",
      os: "Windows 11",
      icon: Skull,
      color: "#f59e0b",
      bgGlow: "rgba(245, 158, 11, 0.12)",
      techniques: ["T1486 (Data Encrypted)", "T1027 (Obfuscated File)"],
      expectedAction: "QUARANTINE_FILE + ISOLATE_HOST",
      description: "Injects simulated malicious PE executable header and bulk file encryption telemetry. Verifies immediate file quarantine and dynamic firewall host isolation.",
    },
    {
      id: "sabotage",
      title: "Adversary Node Sabotage",
      subtitle: "Forced Process Kill / Agent Tampering",
      target: "node3-sabotaged-node",
      os: "Ubuntu Server",
      icon: ShieldAlert,
      color: "#ec4899",
      bgGlow: "rgba(236, 72, 153, 0.12)",
      techniques: ["T1562.001 (Disable Tools)", "Silence-as-Alarm"],
      expectedAction: "CRITICAL SILENT_ALARM Escalation",
      description: "Abruptly halts agent daemon with SIGKILL to simulate adversary tampering. Verifies the Silence Detector catches missing heartbeats without receiving a goodbye packet.",
    },
    {
      id: "graceful",
      title: "System Lifecycle & Reboot",
      subtitle: "Clean User Shutdown vs False Alarms",
      target: "node4-planned-reboot",
      os: "CentOS Stream",
      icon: Server,
      color: "#3b82f6",
      bgGlow: "rgba(59, 130, 246, 0.12)",
      techniques: ["OS Shutdown Hook", "Synchronous Goodbye Beacon"],
      expectedAction: "OFFLINE_GRACEFUL (Suppressed)",
      description: "Simulates normal operator maintenance shutdown emitting a last-gasp goodbye packet. Confirms zero false alarms and clean restoration on reboot.",
    },
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
      {/* Top Banner */}
      <div
        style={{
          background: "linear-gradient(135deg, rgba(239, 68, 68, 0.08) 0%, rgba(15, 23, 42, 0.6) 100%)",
          border: "1px solid rgba(239, 68, 68, 0.25)",
          borderRadius: "12px",
          padding: "20px 24px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "16px",
        }}
      >
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "6px" }}>
            <Zap size={22} color="#ef4444" />
            <h2 style={{ fontSize: "1.25rem", fontWeight: "700", margin: 0, color: "#f8fafc" }}>
              Red Team Attack Simulation & Chaos Lab
            </h2>
            <span
              style={{
                fontSize: "0.72rem",
                padding: "3px 8px",
                borderRadius: "20px",
                fontWeight: "700",
                background: simState.is_running ? "rgba(239, 68, 68, 0.2)" : "rgba(16, 185, 129, 0.15)",
                color: simState.is_running ? "#f87171" : "#34d399",
                border: `1px solid ${simState.is_running ? "rgba(239, 68, 68, 0.4)" : "rgba(16, 185, 129, 0.3)"}`,
              }}
            >
              {simState.is_running ? "⚡ SIMULATION ACTIVE" : "● READY TO INJECT"}
            </span>
          </div>
          <p style={{ color: "#94a3b8", fontSize: "0.85rem", margin: 0, maxWidth: "750px" }}>
            Launch 1-click live simulated cyber attacks across cluster nodes to test ML detection accuracy,
            Byzantine consensus quorum, and autonomous mitigation in real-time.
          </p>
        </div>

        {/* Master Run All & Attacker C2 Link */}
        <div style={{ display: "flex", gap: "10px", alignItems: "center", flexWrap: "wrap" }}>
          <a
            href="http://localhost:5174"
            target="_blank"
            rel="noreferrer"
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              background: "rgba(239, 68, 68, 0.2)",
              border: "1px solid rgba(239, 68, 68, 0.6)",
              color: "#fca5a5",
              borderRadius: "8px",
              padding: "10px 16px",
              fontWeight: "700",
              fontSize: "0.85rem",
              textDecoration: "none",
            }}
          >
            <Skull size={16} color="#ef4444" />
            Open Standalone Attacker C2 (Port 5174) &rarr;
          </a>

          <button
            onClick={() => launchScenario("all")}
            disabled={simState.is_running}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              background: "linear-gradient(135deg, #ef4444 0%, #b91c1c 100%)",
              color: "#ffffff",
              border: "none",
              borderRadius: "8px",
              padding: "10px 20px",
              fontWeight: "700",
              fontSize: "0.88rem",
              cursor: simState.is_running ? "not-allowed" : "pointer",
              boxShadow: "0 4px 14px rgba(239, 68, 68, 0.4)",
              opacity: simState.is_running ? 0.6 : 1,
              transition: "all 0.2s ease",
            }}
          >
            <Flame size={18} />
            Execute Full Showcase (All 4 Scenarios)
          </button>

          {simState.is_running && (
            <button
              onClick={resetSimulation}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "6px",
                background: "rgba(51, 65, 85, 0.6)",
                color: "#cbd5e1",
                border: "1px solid rgba(148, 163, 184, 0.2)",
                borderRadius: "8px",
                padding: "10px 14px",
                fontSize: "0.85rem",
                cursor: "pointer",
              }}
            >
              <RotateCcw size={15} />
              Reset
            </button>
          )}
        </div>
      </div>

      {/* Scenarios Grid */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
          gap: "16px",
        }}
      >
        {scenarios.map((sc) => {
          const IconComp = sc.icon;
          const isThisRunning = simState.is_running && (simState.current_scenario === sc.id || simState.current_scenario === "all");
          return (
            <div
              key={sc.id}
              style={{
                background: "#0f172a",
                border: isThisRunning ? `1.5px solid ${sc.color}` : "1px solid rgba(51, 65, 85, 0.4)",
                borderRadius: "10px",
                padding: "18px",
                display: "flex",
                flexDirection: "column",
                justifyContent: "space-between",
                gap: "14px",
                boxShadow: isThisRunning ? `0 0 20px ${sc.bgGlow}` : "none",
                position: "relative",
                overflow: "hidden",
                transition: "all 0.25s ease",
              }}
            >
              {/* Header */}
              <div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "10px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    <div
                      style={{
                        width: "36px",
                        height: "36px",
                        borderRadius: "8px",
                        background: sc.bgGlow,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        border: `1px solid ${sc.color}40`,
                      }}
                    >
                      <IconComp size={20} color={sc.color} />
                    </div>
                    <div>
                      <h3 style={{ fontSize: "0.98rem", fontWeight: "700", margin: 0, color: "#f1f5f9" }}>
                        {sc.title}
                      </h3>
                      <span style={{ fontSize: "0.75rem", color: "#94a3b8" }}>{sc.subtitle}</span>
                    </div>
                  </div>
                </div>

                <p style={{ color: "#94a3b8", fontSize: "0.8rem", lineHeight: "1.4", margin: "8px 0 14px" }}>
                  {sc.description}
                </p>

                {/* Target & Techniques badges */}
                <div style={{ display: "flex", flexDirection: "column", gap: "6px", fontSize: "0.76rem" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", color: "#cbd5e1" }}>
                    <span style={{ color: "#64748b" }}>Target Node:</span>
                    <span style={{ fontFamily: "monospace", color: "#38bdf8", fontWeight: "600" }}>{sc.target}</span>
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between", color: "#cbd5e1" }}>
                    <span style={{ color: "#64748b" }}>Expected Action:</span>
                    <span style={{ color: "#a855f7", fontWeight: "600" }}>{sc.expectedAction}</span>
                  </div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "4px", marginTop: "4px" }}>
                    {sc.techniques.map((t, idx) => (
                      <span
                        key={idx}
                        style={{
                          background: "rgba(30, 41, 59, 0.8)",
                          color: "#cbd5e1",
                          padding: "2px 6px",
                          borderRadius: "4px",
                          fontSize: "0.7rem",
                          border: "1px solid rgba(71, 85, 105, 0.4)",
                        }}
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* Action Button */}
              <button
                onClick={() => launchScenario(sc.id)}
                disabled={simState.is_running}
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: "8px",
                  background: isThisRunning ? sc.color : "rgba(30, 41, 59, 0.8)",
                  color: isThisRunning ? "#ffffff" : "#f1f5f9",
                  border: `1px solid ${sc.color}60`,
                  borderRadius: "6px",
                  padding: "9px 14px",
                  fontSize: "0.82rem",
                  fontWeight: "600",
                  cursor: simState.is_running ? "not-allowed" : "pointer",
                  transition: "all 0.2s ease",
                  opacity: simState.is_running && !isThisRunning ? 0.5 : 1,
                }}
              >
                <Play size={14} fill={isThisRunning ? "#fff" : sc.color} color={sc.color} />
                {isThisRunning ? "Simulating Scenario..." : "Inject Attack Scenario"}
              </button>
            </div>
          );
        })}
      </div>

      {/* Live Simulation Terminal Console */}
      <div
        style={{
          background: "#090d16",
          border: "1px solid rgba(51, 65, 85, 0.5)",
          borderRadius: "10px",
          padding: "16px 20px",
          display: "flex",
          flexDirection: "column",
          gap: "12px",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid rgba(51, 65, 85, 0.4)", paddingBottom: "10px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Terminal size={18} color="#38bdf8" />
            <h3 style={{ fontSize: "0.92rem", fontWeight: "700", margin: 0, color: "#f8fafc" }}>
              Live Telemetry & Consensus Execution Stream
            </h3>
            {simState.is_running && (
              <span style={{ fontSize: "0.75rem", color: "#f59e0b", display: "flex", alignItems: "center", gap: "4px" }}>
                <Activity size={14} className="spin" /> Executing {simState.current_scenario}...
              </span>
            )}
          </div>
          <div style={{ display: "flex", gap: "12px", alignItems: "center" }}>
            <span style={{ fontSize: "0.75rem", color: "#64748b" }}>
              {simState.logs?.length || 0} events logged
            </span>
            <button
              onClick={() => setSimState((prev) => ({ ...prev, logs: [] }))}
              style={{
                background: "transparent",
                border: "none",
                color: "#64748b",
                fontSize: "0.75rem",
                cursor: "pointer",
                textDecoration: "underline",
              }}
            >
              Clear Console
            </button>
          </div>
        </div>

        {/* Progress bar */}
        {simState.is_running && (
          <div style={{ width: "100%", height: "4px", background: "#1e293b", borderRadius: "2px", overflow: "hidden" }}>
            <div
              style={{
                width: `${simState.progress || 20}%`,
                height: "100%",
                background: "linear-gradient(90deg, #3b82f6, #ef4444)",
                transition: "width 0.4s ease",
              }}
            />
          </div>
        )}

        {/* Terminal Content Box */}
        <div
          style={{
            height: "240px",
            overflowY: "auto",
            fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
            fontSize: "0.8rem",
            color: "#e2e8f0",
            display: "flex",
            flexDirection: "column",
            gap: "4px",
            padding: "8px 0",
          }}
        >
          {(!simState.logs || simState.logs.length === 0) ? (
            <div style={{ color: "#475569", fontStyle: "italic", padding: "20px 0", textAlign: "center" }}>
              Console ready. Click any attack scenario above to stream live telemetry injection, consensus votes, and autonomous mitigations.
            </div>
          ) : (
            simState.logs.map((lg, i) => {
              const color = lg.level === "SUCCESS" ? "#34d399" : (lg.level === "ERROR" ? "#f87171" : (lg.level === "WARNING" ? "#fbbf24" : "#94a3b8"));
              return (
                <div key={i} style={{ display: "flex", gap: "10px", lineHeight: "1.4" }}>
                  <span style={{ color: "#475569", flexShrink: 0 }}>[{lg.timestamp}]</span>
                  <span style={{ color: color, fontWeight: "600", flexShrink: 0 }}>[{lg.level}]</span>
                  <span style={{ color: "#cbd5e1" }}>{lg.message}</span>
                </div>
              );
            })
          )}
          <div ref={terminalEndRef} />
        </div>
      </div>
    </div>
  );
}
