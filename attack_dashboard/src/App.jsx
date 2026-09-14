import React, { useState, useEffect, useRef } from "react";
import {
  Skull,
  Crosshair,
  Terminal,
  Zap,
  ShieldAlert,
  Server,
  Radio,
  Play,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Activity,
  Cpu,
  Layers,
  ExternalLink,
  Sliders,
  Wifi,
  Globe,
  Lock,
} from "lucide-react";

export default function App() {
  const [gatewayUrl, setGatewayUrl] = useState("http://127.0.0.1:8000");
  const [gatewayStatus, setGatewayStatus] = useState("DISCONNECTED");
  const [targets, setTargets] = useState([]);
  const [selectedTarget, setSelectedTarget] = useState({
    id: "vm1-linux",
    name: "Linux App Server (vm1)",
    ip: "10.0.0.10",
    os: "Ubuntu 22.04 LTS",
  });
  const [customIp, setCustomIp] = useState("");
  const [isCustomMode, setIsCustomMode] = useState(false);

  const [attackState, setAttackState] = useState({
    is_running: false,
    current_scenario: null,
    progress: 0,
    logs: [],
    history: [],
  });

  const [exploitStats, setExploitStats] = useState({
    totalLaunched: 0,
    successfulBreaches: 0,
    victimQuorumsTriggered: 0,
  });

  const [customConfig, setCustomConfig] = useState({
    targetPort: 80,
    concurrency: 10,
    intensity: "high",
    payloadType: "meterpreter",
  });
  const [isConfigOpen, setIsConfigOpen] = useState(false);

  const terminalEndRef = useRef(null);
  const pollTimerRef = useRef(null);

  // 1. Fetch available target systems in the chain
  const fetchTargets = async () => {
    try {
      const res = await fetch(`${gatewayUrl}/api/attack/targets`);
      if (res.ok) {
        const data = await res.json();
        setTargets(data);
        setGatewayStatus("CONNECTED");
        if (data.length > 0 && !selectedTarget) {
          setSelectedTarget(data[0]);
        }
      } else {
        setGatewayStatus("ERROR");
      }
    } catch {
      setGatewayStatus("OFFLINE");
    }
  };

  // 2. Poll simulation/attack status
  const pollStatus = async () => {
    try {
      const res = await fetch(`${gatewayUrl}/api/attack/status`);
      if (res.ok) {
        const data = await res.json();
        setAttackState(data);
        if (data.history) {
          setExploitStats((prev) => ({
            ...prev,
            totalLaunched: data.history.length,
            successfulBreaches: data.history.filter((h) => h.status === "COMPLETED").length,
            victimQuorumsTriggered: data.history.length,
          }));
        }
      }
    } catch (err) {
      console.error("Failed to poll attack status:", err);
    }
  };

  useEffect(() => {
    fetchTargets();
    pollStatus();
    pollTimerRef.current = setInterval(pollStatus, 400);
    return () => {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    };
  }, [gatewayUrl]);

  // Auto-scroll terminal to bottom on new logs
  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [attackState.logs]);

  // 3. Launch Exploitation Vector
  const launchAttack = async (scenarioKey) => {
    try {
      const targetId = isCustomMode ? "custom-target" : selectedTarget.id;
      const targetIp = isCustomMode ? (customIp || "10.0.0.99") : selectedTarget.ip;

      const res = await fetch(`${gatewayUrl}/api/attack/launch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scenario: scenarioKey,
          target_id: targetId,
          target_ip: targetIp,
          custom_config: customConfig,
        }),
      });

      if (res.ok) {
        pollStatus();
      }
    } catch (err) {
      console.error("Failed to launch attack:", err);
    }
  };

  const resetAttack = async () => {
    try {
      await fetch(`${gatewayUrl}/api/attack/reset`, { method: "POST" });
      pollStatus();
    } catch (err) {
      console.error("Failed to reset attack:", err);
    }
  };

  const ATTACK_MODULES = [
    {
      id: "linux",
      title: "Linux Memory & Privilege Escalation",
      tag: "RCE / INJECTION",
      icon: Terminal,
      color: "#ef4444",
      bgGradient: "linear-gradient(135deg, rgba(239, 68, 68, 0.15) 0%, rgba(185, 28, 28, 0.25) 100%)",
      mitre: "T1055.008 (ptrace) · T1548.001 (setuid)",
      description: "Injects shellcode via ptrace(), triggers setuid(0) root escalation, dumps password hashes, and opens a Meterpreter reverse shell.",
      payloads: ["ptrace memory injection", "setuid(0) exploit", "/etc/shadow dump", "Java Meterpreter reverse shell"],
    },
    {
      id: "windows",
      title: "Windows Ransomware & Dropper Infiltration",
      tag: "MALWARE / IMPACT",
      icon: Skull,
      color: "#f97316",
      bgGradient: "linear-gradient(135deg, rgba(249, 115, 22, 0.15) 0%, rgba(194, 65, 12, 0.25) 100%)",
      mitre: "T1486 (Data Encrypted) · T1490 (Inhibit Recovery)",
      description: "Deploys an uncompiled PE dropper with RWX sections, executes vssadmin delete shadows /all, and fires high-entropy file encryption bursts.",
      payloads: ["PE Dropper with RWX section", "vssadmin shadow purge", "7.98 bits/byte entropy spike", "Lockbit-style IOCs"],
    },
    {
      id: "pcap_ddos",
      title: "Network TCP SYN Flood DDoS Attack",
      tag: "NETWORK DOS",
      icon: Flame,
      color: "#ec4899",
      bgGradient: "linear-gradient(135deg, rgba(236, 72, 153, 0.15) 0%, rgba(190, 24, 93, 0.25) 100%)",
      mitre: "T1498.001 (Network DoS)",
      description: "Transmits 200 pkts/sec rapid TCP SYN bursts with randomized source addresses to saturate victim port 80/443 and exhaust connection states.",
      payloads: ["180 raw SYN packets", "Zero ACK handshake", "Port 80/443 target blast", "CICIDS LightGBM trigger"],
    },
    {
      id: "pcap_portscan",
      title: "Horizontal TCP PortScan Reconnaissance",
      tag: "DISCOVERY / RECON",
      icon: Crosshair,
      color: "#06b6d4",
      bgGradient: "linear-gradient(135deg, rgba(6, 182, 212, 0.15) 0%, rgba(14, 116, 144, 0.25) 100%)",
      mitre: "T1046 (Network Service Discovery)",
      description: "Performs systematic TCP SYN sweeps probing 35+ critical service ports (SSH, RDP, DBs, Web) across target enterprise host subnets.",
      payloads: ["280 SYN scan probes", "35+ critical service ports", "SYN/ACK vs RST profiling", "MITRE T1046 signature"],
    },
    {
      id: "pcap_hydra",
      title: "Hydra Multi-Threaded SSH Password Brute Force",
      tag: "CREDENTIAL ACCESS",
      icon: Lock,
      color: "#eab308",
      bgGradient: "linear-gradient(135deg, rgba(234, 179, 8, 0.15) 0%, rgba(161, 98, 7, 0.25) 100%)",
      mitre: "T1110.001 (Password Guessing)",
      description: "Spawns 12 parallel threads executing rapid SSH authentication handshakes and dictionary credential bursts against target port 22.",
      payloads: ["Parallel SSH handshakes", "OpenSSH 8.9 banner payload", "Dictionary password spray", "Multi-thread burst"],
    },
    {
      id: "sabotage",
      title: "Agent Sabotage & Air-Gap Silence Injection",
      tag: "DEFENSE EVASION",
      icon: ShieldAlert,
      color: "#a855f7",
      bgGradient: "linear-gradient(135deg, rgba(168, 85, 247, 0.15) 0%, rgba(126, 34, 206, 0.25) 100%)",
      mitre: "T1562.001 (Disable Security Tools)",
      description: "Abruptly terminates the AEGIS heartbeat daemon on target to test the victim's 15-second Silence-as-Alarm autonomous detection logic.",
      payloads: ["SIGKILL on daemon PID", "Zero heartbeat signal", "15s Silence Alarm test", "Isolation escalation"],
    },
    {
      id: "graceful",
      title: "Stealth Drain & Planned Maintenance Probe",
      tag: "MAINTENANCE PROBE",
      icon: Activity,
      color: "#10b981",
      bgGradient: "linear-gradient(135deg, rgba(16, 185, 129, 0.15) 0%, rgba(4, 120, 87, 0.25) 100%)",
      mitre: "Benign Admin Action",
      description: "Sends an authorized OS shutdown and maintenance token to ensure the victim defense system suppresses false alarms during approved work.",
      payloads: ["SIGTERM graceful drain", "Maintenance window token", "Zero false-alarm verification"],
    },
  ];

  return (
    <div style={{ minHeight: "100vh", backgroundColor: "#09090b", color: "#f8fafc", padding: "24px", display: "flex", flexDirection: "column", gap: "24px" }}>
      {/* ═══ Top C2 Header Bar ═══ */}
      <header
        style={{
          background: "linear-gradient(135deg, rgba(24, 24, 27, 0.95) 0%, rgba(9, 9, 11, 0.98) 100%)",
          border: "1px solid rgba(239, 68, 68, 0.4)",
          borderRadius: "14px",
          padding: "20px 24px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "16px",
          boxShadow: "0 0 30px rgba(239, 68, 68, 0.15)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
          <div
            style={{
              background: "linear-gradient(135deg, #ef4444 0%, #991b1b 100%)",
              padding: "12px",
              borderRadius: "10px",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              boxShadow: "0 0 20px rgba(239, 68, 68, 0.5)",
            }}
          >
            <Skull size={28} color="#fff" />
          </div>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              <h1 style={{ margin: 0, fontSize: "1.6rem", fontWeight: "900", letterSpacing: "-0.02em", color: "#f8fafc" }}>
                AEGIS <span style={{ color: "#ef4444" }}>ADVERSARY C2</span>
              </h1>
              <span
                style={{
                  background: "rgba(239, 68, 68, 0.2)",
                  color: "#f87171",
                  border: "1px solid rgba(239, 68, 68, 0.5)",
                  padding: "3px 8px",
                  borderRadius: "4px",
                  fontSize: "0.75rem",
                  fontWeight: "800",
                  letterSpacing: "0.05em",
                }}
              >
                RED TEAM OPERATIONS
              </span>
            </div>
            <p style={{ margin: "4px 0 0 0", color: "#a1a1aa", fontSize: "0.85rem" }}>
              Standalone Attack Injection Console · Targeted Swarm Exploitation &amp; Kill-Chain Simulation
            </p>
          </div>
        </div>

        {/* Target Gateway URL & Connection State */}
        <div style={{ display: "flex", alignItems: "center", gap: "14px" }}>
          <div style={{ display: "flex", alignItems: "center", background: "rgba(24, 24, 27, 0.8)", border: "1px solid rgba(239, 68, 68, 0.3)", borderRadius: "8px", padding: "6px 12px", gap: "8px" }}>
            <Globe size={16} color="#ef4444" />
            <input
              type="text"
              value={gatewayUrl}
              onChange={(e) => setGatewayUrl(e.target.value)}
              placeholder="Target Gateway (http://127.0.0.1:8000)"
              style={{
                background: "transparent",
                border: "none",
                color: "#f8fafc",
                fontSize: "0.82rem",
                fontFamily: "var(--font-mono)",
                outline: "none",
                width: "210px",
              }}
            />
            <button
              onClick={fetchTargets}
              style={{
                background: "rgba(239, 68, 68, 0.2)",
                border: "1px solid rgba(239, 68, 68, 0.5)",
                color: "#f87171",
                padding: "3px 8px",
                borderRadius: "4px",
                fontSize: "0.75rem",
                fontWeight: "700",
                cursor: "pointer",
              }}
            >
              Ping
            </button>
          </div>

          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "6px",
              padding: "6px 12px",
              borderRadius: "8px",
              background: gatewayStatus === "CONNECTED" ? "rgba(16, 185, 129, 0.15)" : "rgba(239, 68, 68, 0.15)",
              border: `1px solid ${gatewayStatus === "CONNECTED" ? "rgba(16, 185, 129, 0.4)" : "rgba(239, 68, 68, 0.4)"}`,
              fontSize: "0.8rem",
              fontWeight: "700",
              color: gatewayStatus === "CONNECTED" ? "#34d399" : "#f87171",
            }}
          >
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: gatewayStatus === "CONNECTED" ? "#10b981" : "#ef4444", boxShadow: gatewayStatus === "CONNECTED" ? "0 0 10px #10b981" : "0 0 10px #ef4444" }} />
            {gatewayStatus}
          </div>

          <a
            href="http://localhost:5173"
            target="_blank"
            rel="noreferrer"
            style={{
              display: "flex",
              alignItems: "center",
              gap: "6px",
              background: "rgba(39, 39, 42, 0.8)",
              border: "1px solid rgba(113, 113, 122, 0.4)",
              color: "#e4e4e7",
              padding: "8px 14px",
              borderRadius: "8px",
              fontSize: "0.82rem",
              fontWeight: "600",
              textDecoration: "none",
            }}
          >
            <span>Open SOC Defender</span>
            <ExternalLink size={14} />
          </a>
        </div>
      </header>

      {/* ═══ Target Selection Deck ═══ */}
      <section
        style={{
          background: "rgba(24, 24, 27, 0.8)",
          border: "1px solid rgba(239, 68, 68, 0.3)",
          borderRadius: "14px",
          padding: "20px",
          display: "flex",
          flexDirection: "column",
          gap: "14px",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "10px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Crosshair size={18} color="#ef4444" />
            <span style={{ fontWeight: "800", fontSize: "1rem", color: "#f8fafc", letterSpacing: "0.02em" }}>
              TARGET SYSTEM IN THE CHAIN
            </span>
            <span style={{ fontSize: "0.78rem", color: "#71717a" }}>({targets.length} chain nodes discovered)</span>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <button
              onClick={() => setIsCustomMode(!isCustomMode)}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "6px",
                background: isCustomMode ? "rgba(239, 68, 68, 0.3)" : "rgba(39, 39, 42, 0.6)",
                border: `1px solid ${isCustomMode ? "rgba(239, 68, 68, 0.8)" : "rgba(113, 113, 122, 0.4)"}`,
                color: isCustomMode ? "#fca5a5" : "#a1a1aa",
                padding: "6px 12px",
                borderRadius: "6px",
                fontSize: "0.8rem",
                fontWeight: "700",
                cursor: "pointer",
              }}
            >
              <Sliders size={14} />
              {isCustomMode ? "Using Custom Target IP" : "Specify Custom Target"}
            </button>
          </div>
        </div>

        {isCustomMode && (
          <div style={{ display: "flex", alignItems: "center", gap: "12px", background: "rgba(9, 9, 11, 0.8)", padding: "12px 16px", borderRadius: "8px", border: "1px solid rgba(239, 68, 68, 0.4)" }}>
            <span style={{ fontSize: "0.82rem", color: "#f87171", fontWeight: "700" }}>CUSTOM TARGET IP / HOST:</span>
            <input
              type="text"
              value={customIp}
              onChange={(e) => setCustomIp(e.target.value)}
              placeholder="e.g. 192.168.1.150 or edge-node-09.internal"
              style={{
                flex: 1,
                background: "rgba(24, 24, 27, 0.9)",
                border: "1px solid rgba(239, 68, 68, 0.3)",
                borderRadius: "6px",
                padding: "6px 12px",
                color: "#f8fafc",
                fontFamily: "var(--font-mono)",
                fontSize: "0.82rem",
                outline: "none",
              }}
            />
          </div>
        )}

        {/* Target Node Cards */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "12px" }}>
          {targets.map((t) => {
            const isSelected = !isCustomMode && selectedTarget?.id === t.id;
            return (
              <div
                key={t.id}
                onClick={() => {
                  setSelectedTarget(t);
                  setIsCustomMode(false);
                }}
                style={{
                  background: isSelected ? "linear-gradient(135deg, rgba(239, 68, 68, 0.18) 0%, rgba(185, 28, 28, 0.25) 100%)" : "rgba(39, 39, 42, 0.4)",
                  border: `1px solid ${isSelected ? "rgba(239, 68, 68, 0.8)" : "rgba(63, 63, 70, 0.5)"}`,
                  borderRadius: "10px",
                  padding: "14px",
                  cursor: "pointer",
                  transition: "all 0.2s ease",
                  display: "flex",
                  flexDirection: "column",
                  gap: "6px",
                  position: "relative",
                  boxShadow: isSelected ? "0 0 15px rgba(239, 68, 68, 0.2)" : "none",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                  <span style={{ fontWeight: "800", fontSize: "0.92rem", color: isSelected ? "#fca5a5" : "#f4f4f5" }}>
                    {t.name}
                  </span>
                  <span style={{ fontSize: "0.7rem", padding: "1px 6px", borderRadius: 4, background: isSelected ? "#ef4444" : "rgba(63, 63, 70, 0.6)", color: "#fff", fontWeight: "700" }}>
                    {t.ip}
                  </span>
                </div>
                <div style={{ fontSize: "0.75rem", color: "#a1a1aa" }}>{t.os}</div>
                <div style={{ fontSize: "0.72rem", color: "#71717a", marginTop: "2px" }}>
                  {t.services ? t.services.join(" · ") : "AEGIS Target Node"}
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* ═══ Attack Arsenal Deck (Exploitation Modules) ═══ */}
      <section style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "10px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Zap size={20} color="#ef4444" />
            <h2 style={{ margin: 0, fontSize: "1.15rem", fontWeight: "800", color: "#f8fafc", letterSpacing: "-0.01em" }}>
              TACTICAL EXPLOITATION MODULES
            </h2>
          </div>

          <button
            onClick={() => launchAttack("all")}
            disabled={attackState.is_running}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              background: "linear-gradient(135deg, #ef4444 0%, #b91c1c 100%)",
              border: "none",
              color: "#fff",
              padding: "10px 20px",
              borderRadius: "8px",
              fontWeight: "800",
              fontSize: "0.88rem",
              cursor: attackState.is_running ? "not-allowed" : "pointer",
              boxShadow: "0 0 20px rgba(239, 68, 68, 0.4)",
              opacity: attackState.is_running ? 0.6 : 1,
            }}
          >
            <Skull size={18} />
            Launch Full Kill-Chain Campaign
          </button>
        </div>

        {/* Modules Grid */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "16px" }}>
          {ATTACK_MODULES.map((m) => {
            const Icon = m.icon;
            const isRunningThis = attackState.is_running && attackState.current_scenario === m.id;
            return (
              <div
                key={m.id}
                style={{
                  background: m.bgGradient,
                  border: `1px solid ${isRunningThis ? "#ef4444" : "rgba(239, 68, 68, 0.25)"}`,
                  borderRadius: "12px",
                  padding: "20px",
                  display: "flex",
                  flexDirection: "column",
                  justifyContent: "space-between",
                  gap: "14px",
                  boxShadow: isRunningThis ? "0 0 25px rgba(239, 68, 68, 0.3)" : "none",
                  transition: "all 0.2s ease",
                }}
              >
                <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                      <div style={{ background: "rgba(9, 9, 11, 0.6)", padding: "8px", borderRadius: "8px", color: m.color, display: "flex" }}>
                        <Icon size={20} />
                      </div>
                      <span style={{ fontWeight: "800", fontSize: "0.95rem", color: "#f8fafc" }}>
                        {m.title}
                      </span>
                    </div>
                    <span style={{ fontSize: "0.68rem", fontWeight: "800", background: "rgba(9, 9, 11, 0.6)", color: m.color, padding: "3px 8px", borderRadius: 4, border: `1px solid ${m.color}40` }}>
                      {m.tag}
                    </span>
                  </div>

                  <p style={{ margin: 0, fontSize: "0.8rem", color: "#d4d4d8", lineHeight: "1.4" }}>
                    {m.description}
                  </p>

                  <div style={{ fontSize: "0.72rem", color: "#a1a1aa", marginTop: "2px" }}>
                    <strong>MITRE:</strong> {m.mitre}
                  </div>

                  {/* Payloads List */}
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", marginTop: "4px" }}>
                    {m.payloads.map((p, i) => (
                      <span key={i} style={{ fontSize: "0.68rem", background: "rgba(9, 9, 11, 0.5)", color: "#e4e4e7", padding: "2px 6px", borderRadius: 4 }}>
                        {p}
                      </span>
                    ))}
                  </div>
                </div>

                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderTop: "1px solid rgba(255, 255, 255, 0.08)", paddingTop: "12px" }}>
                  <span style={{ fontSize: "0.75rem", color: "#a1a1aa" }}>
                    Target: <strong style={{ color: "#f87171" }}>{isCustomMode ? (customIp || "Custom IP") : selectedTarget?.name}</strong>
                  </span>

                  <button
                    onClick={() => launchAttack(m.id)}
                    disabled={attackState.is_running}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "6px",
                      background: isRunningThis ? "#eab308" : "linear-gradient(135deg, #ef4444 0%, #b91c1c 100%)",
                      border: "none",
                      color: "#fff",
                      padding: "8px 16px",
                      borderRadius: "6px",
                      fontWeight: "800",
                      fontSize: "0.8rem",
                      cursor: attackState.is_running ? "not-allowed" : "pointer",
                      boxShadow: "0 2px 10px rgba(239, 68, 68, 0.3)",
                      opacity: attackState.is_running && !isRunningThis ? 0.4 : 1,
                    }}
                  >
                    <Play size={14} fill="#fff" />
                    {isRunningThis ? "Executing..." : "Fire Exploit"}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* ═══ Live Adversary Terminal & Victim Feedback ═══ */}
      <section
        style={{
          background: "#09090b",
          border: "1px solid rgba(239, 68, 68, 0.4)",
          borderRadius: "14px",
          padding: "20px",
          display: "flex",
          flexDirection: "column",
          gap: "14px",
          boxShadow: "0 0 25px rgba(0, 0, 0, 0.6)",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "10px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <Terminal size={18} color="#ef4444" />
            <span style={{ fontWeight: "800", fontSize: "1rem", color: "#f8fafc", fontFamily: "var(--font-mono)" }}>
              LIVE ADVERSARY C2 TERMINAL
            </span>
            {attackState.is_running && (
              <span style={{ fontSize: "0.75rem", background: "rgba(239, 68, 68, 0.2)", color: "#f87171", border: "1px solid rgba(239, 68, 68, 0.5)", padding: "2px 8px", borderRadius: 4, fontWeight: "700" }}>
                INJECTION ACTIVE ({attackState.progress}%)
              </span>
            )}
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <button
              onClick={resetAttack}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "6px",
                background: "rgba(39, 39, 42, 0.6)",
                border: "1px solid rgba(113, 113, 122, 0.4)",
                color: "#a1a1aa",
                padding: "6px 12px",
                borderRadius: "6px",
                fontSize: "0.78rem",
                fontWeight: "700",
                cursor: "pointer",
              }}
            >
              <RotateCcw size={14} />
              Clear Console
            </button>
          </div>
        </div>

        {/* Progress Bar */}
        {attackState.is_running && (
          <div style={{ width: "100%", height: "4px", background: "rgba(39, 39, 42, 0.8)", borderRadius: "2px", overflow: "hidden" }}>
            <div style={{ width: `${attackState.progress}%`, height: "100%", background: "linear-gradient(90deg, #f97316, #ef4444)", transition: "width 0.3s ease" }} />
          </div>
        )}

        {/* Console Box */}
        <div
          style={{
            background: "#0c0c0e",
            border: "1px solid rgba(63, 63, 70, 0.5)",
            borderRadius: "8px",
            padding: "16px",
            minHeight: "220px",
            maxHeight: "320px",
            overflowY: "auto",
            fontFamily: "var(--font-mono)",
            fontSize: "0.8rem",
            display: "flex",
            flexDirection: "column",
            gap: "6px",
          }}
        >
          {attackState.logs.length === 0 ? (
            <div style={{ color: "#71717a", textAlign: "center", padding: "40px 0" }}>
              [C2 IDLE] Ready for engagement. Select a target node and fire an exploit module above.
            </div>
          ) : (
            attackState.logs.map((log, idx) => {
              const isError = log.level === "ERROR";
              const isSuccess = log.level === "SUCCESS";
              const isWarn = log.level === "WARNING";
              const color = isError ? "#f87171" : isSuccess ? "#34d399" : isWarn ? "#fbbf24" : "#e4e4e7";
              return (
                <div key={idx} style={{ display: "flex", gap: "10px", color, lineHeight: "1.4" }}>
                  <span style={{ color: "#71717a" }}>[{log.timestamp}]</span>
                  <span>{log.message}</span>
                </div>
              );
            })
          )}
          <div ref={terminalEndRef} />
        </div>
      </section>
    </div>
  );
}
