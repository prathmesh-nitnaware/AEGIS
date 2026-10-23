import React, { useState, useEffect, useRef, useCallback } from "react";
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
  Search,
  Download,
  Send,
  Eye,
  ShieldCheck,
  Clock,
  RefreshCw,
  FileText,
  SlidersHorizontal,
  ChevronRight,
  Filter,
  Check,
  Copy,
} from "lucide-react";

const KILL_CHAIN_STAGES = [
  { id: "RECONNAISSANCE", label: "1. Reconnaissance", desc: "Network & Port Discovery" },
  { id: "WEAPONIZATION", label: "2. Weaponization", desc: "Payload & Exploit Staging" },
  { id: "DELIVERY", label: "3. Delivery", desc: "Infiltration Transmission" },
  { id: "EXPLOITATION", label: "4. Exploitation", desc: "Syscall & RCE Execution" },
  { id: "PRIVILEGE_ESCALATION", label: "5. Escalation", desc: "Setuid(0) / VSS Purge" },
  { id: "DEFENSE_EVASION", label: "6. Evasion", desc: "Air-gap / Silence Tamper" },
  { id: "IMPACT", label: "7. Impact / Mitigation", desc: "AEGIS Swarm Neutralization" },
];

export default function App() {
  const [gatewayUrl, setGatewayUrl] = useState("http://127.0.0.1:8000");
  const [gatewayStatus, setGatewayStatus] = useState("CONNECTING");
  const [pingLatency, setPingLatency] = useState(null);
  const [activeTab, setActiveTab] = useState("operations"); // operations | terminal | defense | weaponization | reports

  // Targets
  const [targets, setTargets] = useState([]);
  const [selectedTarget, setSelectedTarget] = useState({
    id: "node1-linux",
    name: "Linux App Server (node-1)",
    ip: "10.0.0.10",
    os: "Ubuntu 22.04 LTS",
    services: ["SSH (22)", "HTTP (80)", "Gunicorn (8000)"],
    vulnerabilities: ["CVE-2023-4911", "Weak SSH", "Meterpreter RCE"],
  });
  const [customIp, setCustomIp] = useState("");
  const [isCustomMode, setIsCustomMode] = useState(false);
  const [isProbing, setIsProbing] = useState(false);
  const [probeResult, setProbeResult] = useState(null);
  const [launchError, setLaunchError] = useState("");

  // Attack Execution State
  const [attackState, setAttackState] = useState({
    is_running: false,
    current_scenario: null,
    active_phase: "IDLE",
    progress: 0,
    logs: [],
    history: [],
    stats: {
      totalLaunched: 0,
      successfulBreaches: 0,
      thwartedByDefense: 0,
      avgMitigationLatencyMs: 142.0,
    },
    victim_feedback: {
      detected: false,
      detector_model: "None (Awaiting Engagement)",
      threat_score: 0.0,
      consensus_verdict: "NORMAL",
      response_action: "NONE",
      mitigation_time_ms: 0,
      status: "STANDBY",
    },
  });

  // Custom Exploitation Config
  const [customConfig, setCustomConfig] = useState({
    targetPort: 80,
    concurrency: 12,
    intensity: "high", // low | moderate | high | extreme
    payloadType: "meterpreter", // meterpreter | pe_dropper | syn_flood | ssh_brute | silence_tamper
    timeoutSec: 30,
  });
  const [isConfigModalOpen, setIsConfigModalOpen] = useState(false);

  // Interactive Terminal
  const [cliInput, setCliInput] = useState("");
  const [cliHistory, setCliHistory] = useState([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [logFilter, setLogFilter] = useState("ALL"); // ALL | EXPLOIT | VICTIM | ERROR
  const [toastMessage, setToastMessage] = useState(null);

  const terminalEndRef = useRef(null);
  const pollTimerRef = useRef(null);
  const wsRef = useRef(null);

  const showToast = (msg) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3000);
  };

  // 1. Fetch available target systems
  const fetchTargets = useCallback(async () => {
    const tStart = performance.now();
    try {
      const res = await fetch(`${gatewayUrl}/api/attack/targets`);
      const elapsed = Math.round(performance.now() - tStart);
      setPingLatency(elapsed);

      if (res.ok) {
        const data = await res.json();
        const list = Array.isArray(data) ? data : (data.agents || []);
        setTargets(list);
        setGatewayStatus("CONNECTED");
        setSelectedTarget((current) => {
          const stillAvailable = list.find((t) => t.id === current?.id && t.selectable !== false && t.status === "ONLINE");
          return stillAvailable || list.find((t) => t.selectable !== false && t.status === "ONLINE") || null;
        });
      } else {
        setGatewayStatus("ERROR");
      }
    } catch {
      setGatewayStatus("OFFLINE");
      setPingLatency(null);
    }
  }, [gatewayUrl, selectedTarget]);

  // 2. Poll attack state
  const pollStatus = useCallback(async () => {
    try {
      const res = await fetch(`${gatewayUrl}/api/attack/status`);
      if (res.ok) {
        const data = await res.json();
        setAttackState(data);
        if (data.history) {
          setExploitStats((prev) => ({
            ...prev,
            totalLaunched: data.history.length,
            successfulBreaches: data.history.filter((h) => h.detection_confirmed === true).length,
            victimQuorumsTriggered: data.history.filter((h) => h.consensus_confirmed === true).length,
          }));
        }
      }
    } catch (err) {
      console.warn("Poll status error:", err);
    }
  }, [gatewayUrl]);

  // Connect WebSocket for zero-latency live telemetry
  useEffect(() => {
    const wsUrl = gatewayUrl.replace("http://", "ws://").replace("https://", "wss://") + "/ws/telemetry";
    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === "simulation_progress" || msg.type === "simulation_complete") {
            pollStatus();
          }
        } catch {
          // non-json or normal telemetry frame
        }
      };

      ws.onerror = () => {
        // Fallback gracefully to HTTP polling
      };
    } catch {
      // WS unavailable, polling handles it
    }

    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, [gatewayUrl, pollStatus]);

  useEffect(() => {
    fetchTargets();
    pollStatus();
    const targetTimer = setInterval(fetchTargets, 5000);
    pollTimerRef.current = setInterval(pollStatus, 450);
    return () => {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
      clearInterval(targetTimer);
    };
  }, [fetchTargets, pollStatus]);

  // Auto-scroll terminal
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [attackState.logs]);

  // 3. Probe Target
  const handleProbeTarget = async () => {
    setIsProbing(true);
    const targetIp = isCustomMode ? (customIp || "127.0.0.1") : selectedTarget.ip;
    try {
      const res = await fetch(`${gatewayUrl}/api/attack/probe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: targetIp, port: Number(customConfig.targetPort) }),
      });
      if (res.ok) {
        const data = await res.json();
        setProbeResult(data);
        showToast(`Target probe completed: ${data.status} (${data.avg_latency_ms}ms)`);
      } else {
        showToast("Probe request failed.");
      }
    } catch (err) {
      showToast("Probe connection error: " + err.message);
    } finally {
      setIsProbing(false);
    }
  };

  // 4. Launch Exploitation Vector
  const launchAttack = async (scenarioKey) => {
    try {
      setLaunchError("");
      if (!selectedTarget || selectedTarget.status !== "ONLINE" || selectedTarget.selectable === false) {
        setLaunchError("Select a registered online AEGIS agent with a known source IP first.");
        return;
      }
      const res = await fetch(`${gatewayUrl}/api/attack/launch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scenario: scenarioKey,
          target_id: selectedTarget.id,
          custom_config: customConfig,
        }),
      });

      const body = await res.json().catch(() => ({}));
      if (res.ok) {
        showToast(`Exploit ${scenarioKey.toUpperCase()} launched against ${targetIp}`);
        pollStatus();
      } else {
        const errorMsg = body.detail || body.message || `Launch rejected (${res.status})`;
        setLaunchError(errorMsg);
        showToast(errorMsg);
      }
    } catch (err) {
      setLaunchError(`Backend request failed: ${err.message}`);
      showToast("Dispatch error: " + err.message);
    }
  };

  // 5. Reset Console
  const resetAttack = async () => {
    try {
      await fetch(`${gatewayUrl}/api/attack/reset`, { method: "POST" });
      pollStatus();
      setProbeResult(null);
      showToast("C2 console and telemetry reset.");
    } catch (err) {
      showToast("Reset error: " + err.message);
    }
  };

  // 6. Interactive CLI Command Execution
  const handleRunCliCommand = async (e) => {
    e?.preventDefault();
    const cmd = cliInput.trim();
    if (!cmd) return;

    setCliHistory((prev) => [...prev, cmd]);
    setHistoryIndex(-1);
    setCliInput("");

    try {
      const res = await fetch(`${gatewayUrl}/api/attack/command`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command: cmd }),
      });
      if (res.ok) {
        pollStatus();
      }
    } catch (err) {
      console.error("CLI dispatch error:", err);
    }
  };

  // 7. Export Campaign Report
  const handleExportReport = async () => {
    try {
      const res = await fetch(`${gatewayUrl}/api/attack/export`);
      if (res.ok) {
        const data = await res.json();
        const blob = new Blob([data.markdown], { type: "text/markdown;charset=utf-8;" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.setAttribute("download", `AEGIS_RedTeam_Report_${Date.now()}.md`);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        showToast("Executive Penetration Testing Report downloaded.");
      }
    } catch (err) {
      showToast("Export error: " + err.message);
    }
  };

  const ATTACK_MODULES = [
    {
      id: "linux",
      title: "Linux Memory & Privilege Escalation",
      tag: "RCE / MEMORY INJECTION",
      icon: Terminal,
      color: "#ef4444",
      bgGradient: "linear-gradient(135deg, rgba(239, 68, 68, 0.15) 0%, rgba(185, 28, 28, 0.25) 100%)",
      mitre: "T1055.008 (ptrace) · T1548.001 (setuid)",
      description: "Injects shellcode via ptrace(), triggers setuid(0) root escalation, dumps password hashes, and opens a Meterpreter reverse shell.",
      payloads: ["ptrace memory injection", "setuid(0) exploit", "/etc/shadow dump", "Java Meterpreter reverse shell"],
      targetPort: 22,
    },
    {
      id: "file",
      title: "Suspicious File / Ransomware-like Simulation",
      tag: "MALWARE / IMPACT",
      icon: Skull,
      color: "#f97316",
      bgGradient: "linear-gradient(135deg, rgba(249, 115, 22, 0.15) 0%, rgba(194, 65, 12, 0.25) 100%)",
      mitre: "T1486 (Data Encrypted) · T1490 (Inhibit Recovery)",
      description: "Deploys an uncompiled PE dropper with RWX sections, executes vssadmin delete shadows /all, and fires high-entropy file encryption bursts.",
      payloads: ["PE Dropper with RWX section", "vssadmin shadow purge", "7.98 bits/byte entropy spike", "Lockbit-style IOCs"],
      targetPort: 445,
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
      targetPort: 80,
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
      targetPort: 8000,
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
      targetPort: 22,
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
      targetPort: 8000,
    },
    {
      id: "consensus",
      title: "Multi-node Threat Consensus Simulation",
      tag: "DISTRIBUTED DEFENSE",
      icon: Layers,
      color: "#10b981",
      bgGradient: "linear-gradient(135deg, rgba(16, 185, 129, 0.15) 0%, rgba(4, 120, 87, 0.25) 100%)",
      mitre: "AEGIS P2P / Consensus",
      description: "Runs a controlled multi-node consensus workflow simulation and produces a traceable event for dashboard verification.",
      payloads: ["Synthetic threat event", "Consensus path", "Result verification"],
      targetPort: 8000,
    },
  ];

  const filteredLogs = attackState.logs.filter((l) => {
    if (logFilter === "ALL") return true;
    if (logFilter === "EXPLOIT") return l.message.includes("Exploit") || l.message.includes("Dispatch") || l.message.includes("Injected") || l.level === "WARNING";
    if (logFilter === "VICTIM") return l.message.includes("VICTIM") || l.message.includes("AEGIS") || l.message.includes("defense") || l.message.includes("Alarm");
    if (logFilter === "ERROR") return l.level === "ERROR";
    return true;
  });

  const stats = attackState.stats || {
    totalLaunched: 0,
    successfulBreaches: 0,
    thwartedByDefense: 0,
    avgMitigationLatencyMs: 142.0,
  };
  const victimFeedback = attackState.victim_feedback || {};

  return (
    <div style={{ minHeight: "100vh", backgroundColor: "#09090b", color: "#f8fafc", padding: "20px", display: "flex", flexDirection: "column", gap: "20px" }}>
      {/* Toast Notification */}
      {toastMessage && (
        <div
          style={{
            position: "fixed",
            bottom: "24px",
            right: "24px",
            background: "rgba(24, 24, 27, 0.95)",
            border: "1px solid #ef4444",
            boxShadow: "0 0 25px rgba(239, 68, 68, 0.4)",
            padding: "12px 20px",
            borderRadius: "10px",
            fontSize: "0.88rem",
            fontWeight: "700",
            color: "#f8fafc",
            display: "flex",
            alignItems: "center",
            gap: "10px",
            zIndex: 9999,
            animation: "pulse-red 2s infinite",
          }}
        >
          <Zap size={18} color="#ef4444" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* ═══ Header C2 Console Bar ═══ */}
      <header
        style={{
          background: "linear-gradient(135deg, rgba(24, 24, 27, 0.95) 0%, rgba(9, 9, 11, 0.98) 100%)",
          border: "1px solid rgba(239, 68, 68, 0.4)",
          borderRadius: "14px",
          padding: "18px 24px",
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
              <h1 style={{ margin: 0, fontSize: "1.55rem", fontWeight: "900", letterSpacing: "-0.02em", color: "#f8fafc" }}>
                AEGIS <span style={{ color: "#ef4444" }}>ADVERSARY C2</span>
              </h1>
              <span
                style={{
                  background: "rgba(239, 68, 68, 0.2)",
                  color: "#f87171",
                  border: "1px solid rgba(239, 68, 68, 0.5)",
                  padding: "3px 8px",
                  borderRadius: "4px",
                  fontSize: "0.72rem",
                  fontWeight: "800",
                  letterSpacing: "0.05em",
                }}
              >
                STANDALONE RED TEAM OPERATIONS
              </span>
            </div>
            <p style={{ margin: "4px 0 0 0", color: "#a1a1aa", fontSize: "0.82rem" }}>
              Targeted Swarm Exploitation · Automated Kill-Chain Simulation · Live Victim Telemetry
            </p>
          </div>
        </div>

        {/* Target Gateway URL & Controls */}
        <div style={{ display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
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
              title="Ping Command Node"
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
              {pingLatency ? `${pingLatency}ms` : "Ping"}
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
            <div
              style={{
                width: 8,
                height: 8,
                borderRadius: "50%",
                background: gatewayStatus === "CONNECTED" ? "#10b981" : "#ef4444",
                boxShadow: gatewayStatus === "CONNECTED" ? "0 0 10px #10b981" : "0 0 10px #ef4444",
              }}
            />
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
              padding: "7px 14px",
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

      {/* ═══ View Navigation Tabs ═══ */}
      <nav style={{ display: "flex", gap: "10px", flexWrap: "wrap", borderBottom: "1px solid rgba(63, 63, 70, 0.4)", paddingBottom: "12px" }}>
        {[
          { id: "operations", label: "🎯 Attack Operations & Arsenal", icon: Zap },
          { id: "terminal", label: "⚡ Interactive C2 Shell", icon: Terminal },
          { id: "defense", label: "🛡️ Victim Telemetry & Countermeasures", icon: ShieldAlert },
          { id: "weaponization", label: "🛠️ Weaponization & Payload Stager", icon: Sliders },
          { id: "reports", label: "📜 Campaign Audit & Reports", icon: FileText },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                padding: "10px 16px",
                borderRadius: "8px",
                background: isActive ? "linear-gradient(135deg, rgba(239, 68, 68, 0.25) 0%, rgba(185, 28, 28, 0.35) 100%)" : "rgba(24, 24, 27, 0.6)",
                border: `1px solid ${isActive ? "rgba(239, 68, 68, 0.8)" : "rgba(63, 63, 70, 0.4)"}`,
                color: isActive ? "#f87171" : "#a1a1aa",
                fontWeight: "700",
                fontSize: "0.85rem",
                cursor: "pointer",
                boxShadow: isActive ? "0 0 15px rgba(239, 68, 68, 0.2)" : "none",
              }}
            >
              <Icon size={16} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </nav>

      {/* ═══ TAB 1: OPERATIONS & ARSENAL ═══ */}
      {activeTab === "operations" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
          {/* Target Selection Deck */}
          <section
            style={{
              background: "rgba(24, 24, 27, 0.85)",
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
                <span style={{ fontSize: "0.78rem", color: "#71717a" }}>({targets.length} chain targets discovered)</span>
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <button
                  onClick={fetchTargets}
                  style={{ background: "rgba(39,39,42,.7)", border: "1px solid #52525b", color: "#e4e4e7", padding: "6px 12px", borderRadius: "6px", fontSize: "0.8rem", cursor: "pointer" }}
                >
                  Refresh agents
                </button>

                <button
                  onClick={handleProbeTarget}
                  disabled={isProbing}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "6px",
                    background: "rgba(16, 185, 129, 0.2)",
                    border: "1px solid rgba(16, 185, 129, 0.5)",
                    color: "#34d399",
                    padding: "6px 12px",
                    borderRadius: "6px",
                    fontSize: "0.8rem",
                    fontWeight: "700",
                    cursor: isProbing ? "not-allowed" : "pointer",
                  }}
                >
                  <Wifi size={14} />
                  {isProbing ? "Probing Socket..." : "Probe Target Socket"}
                </button>

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
                  {isCustomMode ? "Using Custom Target IP" : "Specify Custom Target IP"}
                </button>
              </div>
            </div>

            <div style={{ color: "#a1a1aa", fontSize: "0.8rem" }}>
              Only agents that have sent a recent heartbeat are selectable. Tests in this dashboard are lab simulations or stored-PCAP replays unless explicitly stated otherwise.
            </div>
            {launchError && (
              <div role="alert" style={{ padding: "10px 12px", borderRadius: "8px", color: "#fecaca", background: "rgba(127,29,29,.35)", border: "1px solid rgba(248,113,113,.5)" }}>
                {launchError}
              </div>
            )}

            {probeResult && (
              <div style={{ background: "rgba(9, 9, 11, 0.9)", padding: "10px 14px", borderRadius: "8px", border: "1px solid rgba(16, 185, 129, 0.4)", display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "0.82rem" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <CheckCircle2 size={16} color="#10b981" />
                  <span>Target {probeResult.target_ip} is <strong>{probeResult.status}</strong> ({probeResult.avg_latency_ms}ms)</span>
                </div>
                <div style={{ color: "#a1a1aa" }}>
                  Open Ports: <strong style={{ color: "#34d399" }}>{probeResult.open_ports?.join(", ") || "None"}</strong>
                </div>
              </div>
            )}

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
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: "12px" }}>
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
                      <span style={{ fontWeight: "800", fontSize: "0.9rem", color: isSelected ? "#fca5a5" : "#f4f4f5" }}>
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

          {/* MITRE Kill-Chain Phase Progression */}
          <section
            style={{
              background: "rgba(24, 24, 27, 0.7)",
              border: "1px solid rgba(63, 63, 70, 0.5)",
              borderRadius: "12px",
              padding: "16px 20px",
              display: "flex",
              flexDirection: "column",
              gap: "10px",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span style={{ fontSize: "0.85rem", fontWeight: "800", color: "#f8fafc", letterSpacing: "0.05em" }}>
                AUTOMATED KILL-CHAIN PIPELINE PROGRESSION
              </span>
              <span style={{ fontSize: "0.78rem", color: attackState.is_running ? "#ef4444" : "#10b981", fontWeight: "700" }}>
                {attackState.is_running ? `PHASE: ${attackState.active_phase} (${attackState.progress}%)` : "STATUS: STANDBY"}
              </span>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))", gap: "8px" }}>
              {KILL_CHAIN_STAGES.map((stg) => {
                const isActive = attackState.active_phase === stg.id;
                const isPassed = attackState.progress === 100 || (attackState.progress > 0 && KILL_CHAIN_STAGES.findIndex((s) => s.id === attackState.active_phase) > KILL_CHAIN_STAGES.findIndex((s) => s.id === stg.id));
                return (
                  <div
                    key={stg.id}
                    style={{
                      background: isActive ? "rgba(239, 68, 68, 0.25)" : isPassed ? "rgba(16, 185, 129, 0.15)" : "rgba(39, 39, 42, 0.4)",
                      border: `1px solid ${isActive ? "#ef4444" : isPassed ? "#10b981" : "rgba(63, 63, 70, 0.4)"}`,
                      borderRadius: "8px",
                      padding: "8px 10px",
                      display: "flex",
                      flexDirection: "column",
                      gap: "2px",
                      transition: "all 0.2s ease",
                      boxShadow: isActive ? "0 0 15px rgba(239, 68, 68, 0.3)" : "none",
                    }}
                  >
                    <span style={{ fontSize: "0.74rem", fontWeight: "800", color: isActive ? "#fca5a5" : isPassed ? "#34d399" : "#a1a1aa" }}>
                      {stg.label}
                    </span>
                    <span style={{ fontSize: "0.68rem", color: "#71717a" }}>{stg.desc}</span>
                  </div>
                );
              })}
            </div>
          </section>

          {/* Red Team Battle KPI Cards */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))", gap: "12px" }}>
            <div style={{ background: "rgba(24, 24, 27, 0.8)", border: "1px solid rgba(63, 63, 70, 0.5)", borderRadius: "10px", padding: "14px", display: "flex", flexDirection: "column", gap: "4px" }}>
              <span style={{ fontSize: "0.75rem", color: "#a1a1aa", fontWeight: "700" }}>EXPLOITS LAUNCHED</span>
              <span style={{ fontSize: "1.45rem", fontWeight: "900", color: "#f8fafc" }}>{stats.totalLaunched}</span>
              <span style={{ fontSize: "0.7rem", color: "#71717a" }}>Active session count</span>
            </div>

            <div style={{ background: "rgba(24, 24, 27, 0.8)", border: "1px solid rgba(16, 185, 129, 0.4)", borderRadius: "10px", padding: "14px", display: "flex", flexDirection: "column", gap: "4px" }}>
              <span style={{ fontSize: "0.75rem", color: "#34d399", fontWeight: "700" }}>THWARTED BY DEFENDER</span>
              <span style={{ fontSize: "1.45rem", fontWeight: "900", color: "#34d399" }}>{stats.thwartedByDefense}</span>
              <span style={{ fontSize: "0.7rem", color: "#71717a" }}>Neutralized by AEGIS Swarm</span>
            </div>

            <div style={{ background: "rgba(24, 24, 27, 0.8)", border: "1px solid rgba(239, 68, 68, 0.4)", borderRadius: "10px", padding: "14px", display: "flex", flexDirection: "column", gap: "4px" }}>
              <span style={{ fontSize: "0.75rem", color: "#f87171", fontWeight: "700" }}>UNMITIGATED BREACHES</span>
              <span style={{ fontSize: "1.45rem", fontWeight: "900", color: "#f87171" }}>{stats.successfulBreaches}</span>
              <span style={{ fontSize: "0.7rem", color: "#71717a" }}>Bypassed defense logic</span>
            </div>

            <div style={{ background: "rgba(24, 24, 27, 0.8)", border: "1px solid rgba(6, 182, 212, 0.4)", borderRadius: "10px", padding: "14px", display: "flex", flexDirection: "column", gap: "4px" }}>
              <span style={{ fontSize: "0.75rem", color: "#06b6d4", fontWeight: "700" }}>AVG RESPONSE LATENCY</span>
              <span style={{ fontSize: "1.45rem", fontWeight: "900", color: "#06b6d4" }}>{stats.avgMitigationLatencyMs} ms</span>
              <span style={{ fontSize: "0.7rem", color: "#71717a" }}>Autonomous containment time</span>
            </div>
          </div>

          {/* Exploitation Modules Arsenal */}
          <section style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "10px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <Zap size={20} color="#ef4444" />
                <h2 style={{ margin: 0, fontSize: "1.15rem", fontWeight: "800", color: "#f8fafc", letterSpacing: "-0.01em" }}>
                  TACTICAL EXPLOITATION MODULES
                </h2>
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <button
                  onClick={() => setIsConfigModalOpen(true)}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "6px",
                    background: "rgba(39, 39, 42, 0.8)",
                    border: "1px solid rgba(113, 113, 122, 0.4)",
                    color: "#e4e4e7",
                    padding: "8px 14px",
                    borderRadius: "8px",
                    fontWeight: "700",
                    fontSize: "0.82rem",
                    cursor: "pointer",
                  }}
                >
                  <SlidersHorizontal size={14} />
                  <span>Configure Stager</span>
                </button>

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
                    padding: "9px 18px",
                    borderRadius: "8px",
                    fontWeight: "800",
                    fontSize: "0.85rem",
                    cursor: attackState.is_running ? "not-allowed" : "pointer",
                    boxShadow: "0 0 20px rgba(239, 68, 68, 0.4)",
                    opacity: attackState.is_running ? 0.6 : 1,
                  }}
                >
                  <Skull size={16} />
                  <span>Launch Full Kill-Chain Campaign</span>
                </button>
              </div>
            </div>

            {/* Modules Grid */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(310px, 1fr))", gap: "16px" }}>
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
                      padding: "18px",
                      display: "flex",
                      flexDirection: "column",
                      justifyContent: "space-between",
                      gap: "12px",
                      boxShadow: isRunningThis ? "0 0 25px rgba(239, 68, 68, 0.3)" : "none",
                      transition: "all 0.2s ease",
                    }}
                  >
                    <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                          <div style={{ background: "rgba(9, 9, 11, 0.6)", padding: "8px", borderRadius: "8px", color: m.color, display: "flex" }}>
                            <Icon size={18} />
                          </div>
                          <span style={{ fontWeight: "800", fontSize: "0.92rem", color: "#f8fafc" }}>
                            {m.title}
                          </span>
                        </div>
                        <span style={{ fontSize: "0.68rem", fontWeight: "800", background: "rgba(9, 9, 11, 0.6)", color: m.color, padding: "3px 8px", borderRadius: 4, border: `1px solid ${m.color}40` }}>
                          {m.tag}
                        </span>
                      </div>

                      <p style={{ margin: 0, fontSize: "0.78rem", color: "#d4d4d8", lineHeight: "1.4" }}>
                        {m.description}
                      </p>

                      <div style={{ fontSize: "0.72rem", color: "#a1a1aa" }}>
                        <strong>MITRE ATT&CK:</strong> {m.mitre}
                      </div>

                      {/* Payloads List */}
                      <div style={{ display: "flex", flexWrap: "wrap", gap: "4px" }}>
                        {m.payloads.map((p, i) => (
                          <span key={i} style={{ fontSize: "0.66rem", background: "rgba(9, 9, 11, 0.5)", color: "#e4e4e7", padding: "2px 6px", borderRadius: 4 }}>
                            {p}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderTop: "1px solid rgba(255, 255, 255, 0.08)", paddingTop: "10px" }}>
                      <span style={{ fontSize: "0.74rem", color: "#a1a1aa" }}>
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
                          padding: "7px 14px",
                          borderRadius: "6px",
                          fontWeight: "800",
                          fontSize: "0.78rem",
                          cursor: attackState.is_running ? "not-allowed" : "pointer",
                          boxShadow: "0 2px 10px rgba(239, 68, 68, 0.3)",
                          opacity: attackState.is_running && !isRunningThis ? 0.4 : 1,
                        }}
                      >
                        <Play size={12} fill="#fff" />
                        {isRunningThis ? "Injecting..." : "Fire Exploit"}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </section>

          {/* Victim Feedback Quick Look */}
          {victimFeedback.detected && (
            <div
              style={{
                background: "linear-gradient(135deg, rgba(16, 185, 129, 0.1) 0%, rgba(9, 9, 11, 0.9) 100%)",
                border: "1px solid rgba(16, 185, 129, 0.5)",
                borderRadius: "12px",
                padding: "16px 20px",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                flexWrap: "wrap",
                gap: "12px",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                <ShieldCheck size={24} color="#10b981" />
                <div>
                  <div style={{ fontWeight: "800", fontSize: "0.92rem", color: "#34d399" }}>
                    VICTIM DEFENSE RESPONSE: {victimFeedback.status}
                  </div>
                  <div style={{ fontSize: "0.78rem", color: "#a1a1aa" }}>
                    Flagged by <strong>{victimFeedback.detector_model}</strong> with {Math.round(victimFeedback.threat_score * 100)}% anomaly score
                  </div>
                </div>
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
                <div>
                  <span style={{ fontSize: "0.72rem", color: "#71717a" }}>Action Enacted: </span>
                  <span style={{ fontSize: "0.82rem", fontWeight: "800", color: "#f87171" }}>{victimFeedback.response_action}</span>
                </div>
                <div>
                  <span style={{ fontSize: "0.72rem", color: "#71717a" }}>Latency: </span>
                  <span style={{ fontSize: "0.82rem", fontWeight: "800", color: "#06b6d4" }}>{victimFeedback.mitigation_time_ms} ms</span>
                </div>
                <button
                  onClick={() => setActiveTab("defense")}
                  style={{
                    background: "rgba(16, 185, 129, 0.2)",
                    border: "1px solid rgba(16, 185, 129, 0.5)",
                    color: "#34d399",
                    padding: "4px 10px",
                    borderRadius: "6px",
                    fontSize: "0.75rem",
                    fontWeight: "700",
                    cursor: "pointer",
                  }}
                >
                  View Details &rarr;
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ═══ TAB 2: INTERACTIVE C2 TERMINAL ═══ */}
      {activeTab === "terminal" && (
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
                INTERACTIVE ADVERSARY C2 TERMINAL
              </span>
              {attackState.is_running && (
                <span style={{ fontSize: "0.75rem", background: "rgba(239, 68, 68, 0.2)", color: "#f87171", border: "1px solid rgba(239, 68, 68, 0.5)", padding: "2px 8px", borderRadius: 4, fontWeight: "700" }}>
                  INJECTION ACTIVE ({attackState.progress}%)
                </span>
              )}
            </div>

            {/* Filter buttons */}
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              {["ALL", "EXPLOIT", "VICTIM", "ERROR"].map((f) => (
                <button
                  key={f}
                  onClick={() => setLogFilter(f)}
                  style={{
                    background: logFilter === f ? "rgba(239, 68, 68, 0.3)" : "rgba(39, 39, 42, 0.5)",
                    border: `1px solid ${logFilter === f ? "rgba(239, 68, 68, 0.8)" : "rgba(63, 63, 70, 0.5)"}`,
                    color: logFilter === f ? "#fca5a5" : "#a1a1aa",
                    padding: "3px 8px",
                    borderRadius: "4px",
                    fontSize: "0.72rem",
                    fontWeight: "700",
                    cursor: "pointer",
                  }}
                >
                  {f}
                </button>
              ))}

              <button
                onClick={resetAttack}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  background: "rgba(39, 39, 42, 0.6)",
                  border: "1px solid rgba(113, 113, 122, 0.4)",
                  color: "#a1a1aa",
                  padding: "5px 10px",
                  borderRadius: "6px",
                  fontSize: "0.75rem",
                  fontWeight: "700",
                  cursor: "pointer",
                }}
              >
                <RotateCcw size={12} />
                Clear
              </button>
            </div>
          </div>

          {/* Terminal Console Box */}
          <div
            style={{
              background: "#0c0c0e",
              border: "1px solid rgba(63, 63, 70, 0.5)",
              borderRadius: "8px",
              padding: "16px",
              minHeight: "360px",
              maxHeight: "480px",
              overflowY: "auto",
              fontFamily: "var(--font-mono)",
              fontSize: "0.82rem",
              display: "flex",
              flexDirection: "column",
              gap: "6px",
            }}
          >
            {filteredLogs.length === 0 ? (
              <div style={{ color: "#71717a", textAlign: "center", padding: "60px 0" }}>
                [C2 IDLE] Ready for engagement. Type 'help' below or select an exploit module from the Operations tab.
              </div>
            ) : (
              filteredLogs.map((log, idx) => {
                const isError = log.level === "ERROR";
                const isSuccess = log.level === "SUCCESS";
                const isWarn = log.level === "WARNING" || log.level === "CRITICAL";
                const color = isError ? "#f87171" : isSuccess ? "#34d399" : isWarn ? "#fbbf24" : "#e4e4e7";
                return (
                  <div key={idx} style={{ display: "flex", gap: "10px", color, lineHeight: "1.4" }}>
                    <span style={{ color: "#71717a", userSelect: "none" }}>[{log.timestamp}]</span>
                    <span>{log.message}</span>
                  </div>
                );
              })
            )}
            <div ref={terminalEndRef} />
          </div>

          {/* Interactive CLI Input Line */}
          <form onSubmit={handleRunCliCommand} style={{ display: "flex", gap: "10px", alignItems: "center" }}>
            <div style={{ display: "flex", alignItems: "center", flex: 1, background: "#0c0c0e", border: "1px solid rgba(239, 68, 68, 0.4)", borderRadius: "6px", padding: "8px 12px", gap: "8px" }}>
              <span style={{ color: "#ef4444", fontFamily: "var(--font-mono)", fontWeight: "800", fontSize: "0.85rem" }}>
                operator@aegis-c2:~$
              </span>
              <input
                type="text"
                value={cliInput}
                onChange={(e) => setCliInput(e.target.value)}
                placeholder="Type 'help', 'scan 10.0.0.10', 'exploit linux', 'status', 'config'..."
                style={{
                  flex: 1,
                  background: "transparent",
                  border: "none",
                  outline: "none",
                  color: "#f8fafc",
                  fontFamily: "var(--font-mono)",
                  fontSize: "0.82rem",
                }}
              />
            </div>

            <button
              type="submit"
              style={{
                display: "flex",
                alignItems: "center",
                gap: "6px",
                background: "linear-gradient(135deg, #ef4444 0%, #b91c1c 100%)",
                border: "none",
                color: "#fff",
                padding: "8px 16px",
                borderRadius: "6px",
                fontWeight: "700",
                fontSize: "0.82rem",
                cursor: "pointer",
              }}
            >
              <Send size={14} />
              <span>Exec</span>
            </button>
          </form>

          {/* Quick CLI suggestion chips */}
          <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", alignItems: "center" }}>
            <span style={{ fontSize: "0.72rem", color: "#71717a" }}>Quick Commands:</span>
            {["help", "targets", "probe", "scan", "exploit linux", "exploit windows", "exploit ddos", "status", "clear"].map((cmd) => (
              <button
                key={cmd}
                onClick={() => setCliInput(cmd)}
                style={{
                  background: "rgba(39, 39, 42, 0.4)",
                  border: "1px solid rgba(63, 63, 70, 0.4)",
                  color: "#a1a1aa",
                  padding: "2px 8px",
                  borderRadius: "4px",
                  fontSize: "0.72rem",
                  fontFamily: "var(--font-mono)",
                  cursor: "pointer",
                }}
              >
                {cmd}
              </button>
            ))}
          </div>
        </section>
      )}

      {/* ═══ TAB 3: VICTIM TELEMETRY & SWARM DEFENSE ═══ */}
      {activeTab === "defense" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
          <section
            style={{
              background: "rgba(24, 24, 27, 0.85)",
              border: "1px solid rgba(16, 185, 129, 0.4)",
              borderRadius: "14px",
              padding: "20px",
              display: "flex",
              flexDirection: "column",
              gap: "16px",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <ShieldAlert size={20} color="#10b981" />
                <h3 style={{ margin: 0, fontSize: "1.1rem", fontWeight: "800", color: "#f8fafc" }}>
                  VICTIM SWARM INTERCEPTION & COUNTERMEASURE TELEMETRY
                </h3>
              </div>
              <span style={{ fontSize: "0.75rem", background: "rgba(16, 185, 129, 0.15)", color: "#34d399", padding: "3px 8px", borderRadius: 4, fontWeight: "700" }}>
                REAL-TIME SWARM FEEDBACK
              </span>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "16px" }}>
              {/* Threat Score Gauge */}
              <div style={{ background: "rgba(9, 9, 11, 0.8)", border: "1px solid rgba(63, 63, 70, 0.5)", borderRadius: "10px", padding: "16px", display: "flex", flexDirection: "column", gap: "10px" }}>
                <span style={{ fontSize: "0.78rem", color: "#a1a1aa", fontWeight: "700" }}>VICTIM THREAT SCORE GAUGE</span>
                <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
                  <div style={{ fontSize: "2.4rem", fontWeight: "900", color: victimFeedback.threat_score > 0.7 ? "#ef4444" : victimFeedback.threat_score > 0.3 ? "#f59e0b" : "#10b981" }}>
                    {Math.round((victimFeedback.threat_score || 0) * 100)}%
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: "2px", flex: 1 }}>
                    <div style={{ width: "100%", height: "8px", background: "rgba(63, 63, 70, 0.4)", borderRadius: "4px", overflow: "hidden" }}>
                      <div
                        style={{
                          width: `${Math.round((victimFeedback.threat_score || 0) * 100)}%`,
                          height: "100%",
                          background: victimFeedback.threat_score > 0.7 ? "linear-gradient(90deg, #f97316, #ef4444)" : "#10b981",
                        }}
                      />
                    </div>
                    <span style={{ fontSize: "0.7rem", color: "#71717a" }}>Threshold: 65.0% for Autonomous Containment</span>
                  </div>
                </div>
              </div>

              {/* Attribution Model */}
              <div style={{ background: "rgba(9, 9, 11, 0.8)", border: "1px solid rgba(63, 63, 70, 0.5)", borderRadius: "10px", padding: "16px", display: "flex", flexDirection: "column", gap: "6px" }}>
                <span style={{ fontSize: "0.78rem", color: "#a1a1aa", fontWeight: "700" }}>DETECTION ENGINE ATTRIBUTION</span>
                <span style={{ fontSize: "1.05rem", fontWeight: "800", color: "#f8fafc" }}>{victimFeedback.detector_model || "Standing by"}</span>
                <span style={{ fontSize: "0.72rem", color: "#71717a" }}>Evaluated across AEGIS 6-Model Hardened Ensemble</span>
              </div>

              {/* Consensus Verdict */}
              <div style={{ background: "rgba(9, 9, 11, 0.8)", border: "1px solid rgba(63, 63, 70, 0.5)", borderRadius: "10px", padding: "16px", display: "flex", flexDirection: "column", gap: "6px" }}>
                <span style={{ fontSize: "0.78rem", color: "#a1a1aa", fontWeight: "700" }}>PEER QUORUM VERDICT</span>
                <span style={{ fontSize: "1.05rem", fontWeight: "800", color: victimFeedback.consensus_verdict === "CRITICAL" ? "#ef4444" : "#10b981" }}>
                  {victimFeedback.consensus_verdict || "STANDBY"}
                </span>
                <span style={{ fontSize: "0.72rem", color: "#71717a" }}>
                  Participating Peer Nodes: {victimFeedback.participating_peers || 3} nodes verified
                </span>
              </div>

              {/* Autonomous Countermeasure */}
              <div style={{ background: "rgba(9, 9, 11, 0.8)", border: "1px solid rgba(63, 63, 70, 0.5)", borderRadius: "10px", padding: "16px", display: "flex", flexDirection: "column", gap: "6px" }}>
                <span style={{ fontSize: "0.78rem", color: "#a1a1aa", fontWeight: "700" }}>DISPATCHED COUNTERMEASURE</span>
                <span style={{ fontSize: "1.05rem", fontWeight: "800", color: "#f87171" }}>{victimFeedback.response_action || "NONE"}</span>
                <span style={{ fontSize: "0.72rem", color: "#71717a" }}>Executed hands-free in {victimFeedback.mitigation_time_ms || 180} ms</span>
              </div>
            </div>
          </section>
        </div>
      )}

      {/* ═══ TAB 4: WEAPONIZATION & PAYLOAD STAGER ═══ */}
      {activeTab === "weaponization" && (
        <section
          style={{
            background: "rgba(24, 24, 27, 0.85)",
            border: "1px solid rgba(239, 68, 68, 0.3)",
            borderRadius: "14px",
            padding: "20px",
            display: "flex",
            flexDirection: "column",
            gap: "16px",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              <Sliders size={20} color="#ef4444" />
              <h3 style={{ margin: 0, fontSize: "1.1rem", fontWeight: "800", color: "#f8fafc" }}>
                CUSTOM EXPLOIT STAGER & WEAPONIZATION BUILDER
              </h3>
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "16px" }}>
            {/* Target Port */}
            <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
              <label style={{ fontSize: "0.78rem", color: "#a1a1aa", fontWeight: "700" }}>TARGET PORT</label>
              <input
                type="number"
                value={customConfig.targetPort}
                onChange={(e) => setCustomConfig({ ...customConfig, targetPort: Number(e.target.value) })}
                style={{
                  background: "rgba(9, 9, 11, 0.8)",
                  border: "1px solid rgba(63, 63, 70, 0.5)",
                  borderRadius: "6px",
                  padding: "8px 12px",
                  color: "#f8fafc",
                  fontFamily: "var(--font-mono)",
                  outline: "none",
                }}
              />
              <span style={{ fontSize: "0.7rem", color: "#71717a" }}>Common: 22 (SSH), 80 (HTTP), 443 (HTTPS), 3389 (RDP)</span>
            </div>

            {/* Concurrency Threads */}
            <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
              <label style={{ fontSize: "0.78rem", color: "#a1a1aa", fontWeight: "700" }}>
                CONCURRENCY THREADS ({customConfig.concurrency})
              </label>
              <input
                type="range"
                min="1"
                max="50"
                value={customConfig.concurrency}
                onChange={(e) => setCustomConfig({ ...customConfig, concurrency: Number(e.target.value) })}
                style={{ accentColor: "#ef4444" }}
              />
              <span style={{ fontSize: "0.7rem", color: "#71717a" }}>Parallel execution workers (1-50)</span>
            </div>

            {/* Attack Intensity */}
            <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
              <label style={{ fontSize: "0.78rem", color: "#a1a1aa", fontWeight: "700" }}>ATTACK INTENSITY</label>
              <select
                value={customConfig.intensity}
                onChange={(e) => setCustomConfig({ ...customConfig, intensity: e.target.value })}
                style={{
                  background: "rgba(9, 9, 11, 0.8)",
                  border: "1px solid rgba(63, 63, 70, 0.5)",
                  borderRadius: "6px",
                  padding: "8px 12px",
                  color: "#f8fafc",
                  outline: "none",
                }}
              >
                <option value="stealth">Stealth (Low PPS, evasion tuned)</option>
                <option value="moderate">Moderate (Standard benchmark rate)</option>
                <option value="high">High (High-velocity saturation)</option>
                <option value="extreme">Extreme (Maximum state table saturation)</option>
              </select>
            </div>

            {/* Payload Type */}
            <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
              <label style={{ fontSize: "0.78rem", color: "#a1a1aa", fontWeight: "700" }}>PAYLOAD TYPE</label>
              <select
                value={customConfig.payloadType}
                onChange={(e) => setCustomConfig({ ...customConfig, payloadType: e.target.value })}
                style={{
                  background: "rgba(9, 9, 11, 0.8)",
                  border: "1px solid rgba(63, 63, 70, 0.5)",
                  borderRadius: "6px",
                  padding: "8px 12px",
                  color: "#f8fafc",
                  outline: "none",
                }}
              >
                <option value="meterpreter">Java / Linux Meterpreter Reverse TCP</option>
                <option value="pe_dropper">Windows High-Entropy PE Dropper</option>
                <option value="syn_flood">Network Raw SYN Flood Blast</option>
                <option value="ssh_brute">Hydra Dictionary Password Spray</option>
                <option value="silence_tamper">Process Kill &amp; Silence Severance</option>
              </select>
            </div>
          </div>

          <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px", marginTop: "10px" }}>
            <button
              onClick={() => {
                showToast("Exploit staging profile updated.");
                setActiveTab("operations");
              }}
              style={{
                background: "linear-gradient(135deg, #ef4444 0%, #b91c1c 100%)",
                border: "none",
                color: "#fff",
                padding: "8px 18px",
                borderRadius: "6px",
                fontWeight: "800",
                fontSize: "0.82rem",
                cursor: "pointer",
              }}
            >
              Save Configuration Profile
            </button>
          </div>
        </section>
      )}

      {/* ═══ TAB 5: CAMPAIGN AUDIT & REPORTS ═══ */}
      {activeTab === "reports" && (
        <section
          style={{
            background: "rgba(24, 24, 27, 0.85)",
            border: "1px solid rgba(239, 68, 68, 0.3)",
            borderRadius: "14px",
            padding: "20px",
            display: "flex",
            flexDirection: "column",
            gap: "16px",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "10px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              <FileText size={20} color="#ef4444" />
              <h3 style={{ margin: 0, fontSize: "1.1rem", fontWeight: "800", color: "#f8fafc" }}>
                RED TEAM CAMPAIGN AUDIT &amp; ENGAGEMENT LOGS
              </h3>
            </div>

            <button
              onClick={handleExportReport}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "6px",
                background: "linear-gradient(135deg, #ef4444 0%, #b91c1c 100%)",
                border: "none",
                color: "#fff",
                padding: "8px 16px",
                borderRadius: "6px",
                fontWeight: "700",
                fontSize: "0.82rem",
                cursor: "pointer",
              }}
            >
              <Download size={14} />
              <span>Download Executive Report (.MD)</span>
            </button>
          </div>

          {/* Operations History Table */}
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.82rem", textAlign: "left" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid rgba(63, 63, 70, 0.6)", color: "#a1a1aa" }}>
                  <th style={{ padding: "10px" }}>TIMESTAMP</th>
                  <th style={{ padding: "10px" }}>VECTOR</th>
                  <th style={{ padding: "10px" }}>TARGET HOST</th>
                  <th style={{ padding: "10px" }}>STATUS</th>
                  <th style={{ padding: "10px" }}>DEFENDER REACTION</th>
                  <th style={{ padding: "10px" }}>LATENCY</th>
                </tr>
              </thead>
              <tbody>
                {attackState.history.length === 0 ? (
                  <tr>
                    <td colSpan={6} style={{ textAlign: "center", padding: "40px", color: "#71717a" }}>
                      No attack campaigns executed yet in this session.
                    </td>
                  </tr>
                ) : (
                  attackState.history.map((h, i) => {
                    const vf = h.victim_feedback || {};
                    return (
                      <tr key={i} style={{ borderBottom: "1px solid rgba(39, 39, 42, 0.4)" }}>
                        <td style={{ padding: "10px", color: "#71717a", fontFamily: "var(--font-mono)" }}>{h.timestamp}</td>
                        <td style={{ padding: "10px", fontWeight: "800", color: "#f87171" }}>{h.scenario.toUpperCase()}</td>
                        <td style={{ padding: "10px", color: "#e4e4e7" }}>{h.target} ({h.target_ip})</td>
                        <td style={{ padding: "10px" }}>
                          <span style={{ background: h.status === "COMPLETED" ? "rgba(16, 185, 129, 0.2)" : "rgba(239, 68, 68, 0.2)", color: h.status === "COMPLETED" ? "#34d399" : "#f87171", padding: "2px 8px", borderRadius: 4, fontWeight: "700", fontSize: "0.72rem" }}>
                            {h.status}
                          </span>
                        </td>
                        <td style={{ padding: "10px", color: "#a1a1aa" }}>{vf.response_action || "NONE"}</td>
                        <td style={{ padding: "10px", color: "#06b6d4", fontFamily: "var(--font-mono)" }}>{h.duration}s</td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* ═══ Config Modal ═══ */}
      {isConfigModalOpen && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0, 0, 0, 0.75)",
            backdropFilter: "blur(6px)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 999,
            padding: "20px",
          }}
        >
          <div
            style={{
              background: "#121215",
              border: "1px solid rgba(239, 68, 68, 0.5)",
              borderRadius: "14px",
              padding: "24px",
              width: "100%",
              maxWidth: "520px",
              display: "flex",
              flexDirection: "column",
              gap: "16px",
              boxShadow: "0 0 35px rgba(239, 68, 68, 0.3)",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h3 style={{ margin: 0, fontSize: "1.1rem", fontWeight: "800", color: "#f8fafc" }}>
                EXPLOITATION VECTOR CONFIGURATION
              </h3>
              <button
                onClick={() => setIsConfigModalOpen(false)}
                style={{ background: "transparent", border: "none", color: "#a1a1aa", fontSize: "1.2rem", cursor: "pointer" }}
              >
                &times;
              </button>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              <div>
                <label style={{ fontSize: "0.75rem", color: "#a1a1aa", fontWeight: "700" }}>TARGET PORT</label>
                <input
                  type="number"
                  value={customConfig.targetPort}
                  onChange={(e) => setCustomConfig({ ...customConfig, targetPort: Number(e.target.value) })}
                  style={{
                    width: "100%",
                    background: "#09090b",
                    border: "1px solid rgba(63, 63, 70, 0.5)",
                    borderRadius: "6px",
                    padding: "8px 12px",
                    color: "#f8fafc",
                    fontFamily: "var(--font-mono)",
                    marginTop: "4px",
                  }}
                />
              </div>

              <div>
                <label style={{ fontSize: "0.75rem", color: "#a1a1aa", fontWeight: "700" }}>
                  CONCURRENCY THREADS: {customConfig.concurrency}
                </label>
                <input
                  type="range"
                  min="1"
                  max="50"
                  value={customConfig.concurrency}
                  onChange={(e) => setCustomConfig({ ...customConfig, concurrency: Number(e.target.value) })}
                  style={{ width: "100%", accentColor: "#ef4444", marginTop: "4px" }}
                />
              </div>

              <div>
                <label style={{ fontSize: "0.75rem", color: "#a1a1aa", fontWeight: "700" }}>INTENSITY LEVEL</label>
                <select
                  value={customConfig.intensity}
                  onChange={(e) => setCustomConfig({ ...customConfig, intensity: e.target.value })}
                  style={{
                    width: "100%",
                    background: "#09090b",
                    border: "1px solid rgba(63, 63, 70, 0.5)",
                    borderRadius: "6px",
                    padding: "8px 12px",
                    color: "#f8fafc",
                    marginTop: "4px",
                  }}
                >
                  <option value="stealth">Stealth (Low rate)</option>
                  <option value="moderate">Moderate (Default)</option>
                  <option value="high">High (High velocity)</option>
                  <option value="extreme">Extreme (Maximum)</option>
                </select>
              </div>
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px", marginTop: "10px" }}>
              <button
                onClick={() => setIsConfigModalOpen(false)}
                style={{
                  background: "linear-gradient(135deg, #ef4444 0%, #b91c1c 100%)",
                  border: "none",
                  color: "#fff",
                  padding: "8px 16px",
                  borderRadius: "6px",
                  fontWeight: "700",
                  cursor: "pointer",
                }}
              >
                Apply Settings
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
