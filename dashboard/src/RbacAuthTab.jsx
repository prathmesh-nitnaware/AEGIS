import React, { useState, useEffect } from "react";
import {
  Shield,
  Key,
  Lock,
  UserCheck,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  RefreshCw,
  Zap,
  Users,
  Terminal,
  Clock,
  Eye,
  Sliders,
  Award,
} from "lucide-react";

export default function RbacAuthTab({ backendUrl = "http://127.0.0.1:8000" }) {
  const [currentUser, setCurrentUser] = useState({
    username: "admin",
    role: "admin",
    full_name: "Principal SOC Administrator",
    token: null,
  });
  const [permissions, setPermissions] = useState([]);
  const [agentIdInput, setAgentIdInput] = useState("agent-node-5");
  const [agentTtlDays, setAgentTtlDays] = useState(30);
  const [generatedAgentToken, setGeneratedAgentToken] = useState(null);
  const [copiedToken, setCopiedToken] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [loginUsername, setLoginUsername] = useState("admin");
  const [loginPassword, setLoginPassword] = useState("admin123");
  const [authError, setAuthError] = useState(null);
  const [authSuccess, setAuthSuccess] = useState(null);

  const capabilityMatrix = [
    { key: "read_telemetry", label: "Read Live Telemetry & Events", minRole: "auditor" },
    { key: "read_consensus", label: "Inspect Consensus Votes & Quorums", minRole: "auditor" },
    { key: "read_audit", label: "Export Audit Logs & PDF Reports", minRole: "auditor" },
    { key: "execute_mitigation", label: "Dispatch Host Isolation & Process Kill", minRole: "analyst" },
    { key: "manage_rules", label: "Compile & Activate Sigma / YARA Rules", minRole: "analyst" },
    { key: "query_copilot", label: "Execute GenAI Root-Cause Synthesis", minRole: "analyst" },
    { key: "import_intel", label: "Ingest STIX 2.1 & MISP Threat Bundles", minRole: "analyst" },
    { key: "manage_agents", label: "Provision Swarm Node HMAC Tokens", minRole: "admin" },
    { key: "admin_config", label: "Push Fleet Configurations & Hot Updates", minRole: "admin" },
  ];

  const roleWeights = { auditor: 1, analyst: 2, admin: 3 };

  const handleLogin = async (username, password) => {
    setIsLoading(true);
    setAuthError(null);
    setAuthSuccess(null);
    try {
      const res = await fetch(`${backendUrl}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      if (res.ok) {
        const data = await res.json();
        setCurrentUser(data);
        fetchUserProfile(data.token);
        setAuthSuccess(`Logged in successfully as ${data.full_name} (${data.role.toUpperCase()})`);
      } else {
        const err = await res.json();
        setAuthError(err.detail || "Invalid operator credentials");
      }
    } catch (err) {
      setAuthError(`Connection error: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const fetchUserProfile = async (token) => {
    if (!token) return;
    try {
      const res = await fetch(`${backendUrl}/api/auth/me`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setPermissions(data.permissions || []);
      }
    } catch (err) {
      console.error("Failed to fetch permissions:", err);
    }
  };

  // Initial login on mount
  useEffect(() => {
    handleLogin("admin", "admin123");
  }, []);

  const handleGenerateAgentToken = async (e) => {
    e.preventDefault();
    if (!agentIdInput.trim()) return;
    setIsLoading(true);
    try {
      const headers = { "Content-Type": "application/json" };
      if (currentUser.token) {
        headers.Authorization = `Bearer ${currentUser.token}`;
      }
      const res = await fetch(`${backendUrl}/api/auth/tokens/agent`, {
        method: "POST",
        headers,
        body: JSON.stringify({ agent_id: agentIdInput.trim(), ttl_days: Number(agentTtlDays) }),
      });
      if (res.ok) {
        const data = await res.json();
        setGeneratedAgentToken(data);
      } else {
        const err = await res.json();
        alert(`Failed to generate token: ${err.detail || "Forbidden"}`);
      }
    } catch (err) {
      alert(`Error generating token: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedToken(true);
    setTimeout(() => setCopiedToken(false), 2000);
  };

  const switchRolePreset = (uname, pwd) => {
    setLoginUsername(uname);
    setLoginPassword(pwd);
    handleLogin(uname, pwd);
  };

  const hasPermission = (minRole) => {
    const userRole = currentUser.role || "auditor";
    return roleWeights[userRole] >= roleWeights[minRole];
  };

  return (
    <div className="rbac-auth-container fade-in">
      {/* ═══ Header Section ═══ */}
      <div className="panel" style={{ marginBottom: 20 }}>
        <div className="panel-header">
          <div>
            <h2 className="panel-title" style={{ display: "flex", alignItems: "center", gap: 8, fontSize: "1.25rem" }}>
              <Lock size={20} style={{ color: "#8b5cf6" }} />
              Enterprise Role-Based Access Control (RBAC) &amp; Swarm Authentication
            </h2>
            <p className="panel-subtitle">
              Cryptographic JWT bearer session tokens, hierarchical role capabilities, and agent HMAC keys
            </p>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <span
              className="panel-badge"
              style={{
                background:
                  currentUser.role === "admin"
                    ? "rgba(239, 68, 68, 0.15)"
                    : currentUser.role === "analyst"
                    ? "rgba(56, 189, 248, 0.15)"
                    : "rgba(148, 163, 184, 0.15)",
                color:
                  currentUser.role === "admin"
                    ? "#f87171"
                    : currentUser.role === "analyst"
                    ? "#38bdf8"
                    : "#94a3b8",
                border: "1px solid currentColor",
                fontWeight: 700,
              }}
            >
              ACTIVE ROLE: {currentUser.role?.toUpperCase() || "UNAUTHENTICATED"}
            </span>
          </div>
        </div>

        {/* Demo Fast Switcher */}
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginTop: 14, flexWrap: "wrap" }}>
          <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>Simulate Operator Role:</span>
          <button
            type="button"
            className={`btn-badge-chip ${currentUser.username === "admin" ? "active" : ""}`}
            onClick={() => switchRolePreset("admin", "admin123")}
            style={{ borderColor: "#ef4444" }}
          >
            👑 Admin (Full L3 Control)
          </button>
          <button
            type="button"
            className={`btn-badge-chip ${currentUser.username === "analyst" ? "active" : ""}`}
            onClick={() => switchRolePreset("analyst", "analyst123")}
            style={{ borderColor: "#38bdf8" }}
          >
            🛡️ Analyst (L2 Threat Hunter)
          </button>
          <button
            type="button"
            className={`btn-badge-chip ${currentUser.username === "auditor" ? "active" : ""}`}
            onClick={() => switchRolePreset("auditor", "auditor123")}
            style={{ borderColor: "#94a3b8" }}
          >
            👁️ Auditor (L1 Read-Only)
          </button>
        </div>
      </div>

      {/* ═══ 2-Column Main Layout: Session Profile & Capability Matrix ═══ */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1.3fr", gap: 20, marginBottom: 20 }}>
        {/* Left Column: Active Operator Session Profile */}
        <div className="panel">
          <div className="panel-header">
            <div>
              <h3 className="panel-title" style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <UserCheck size={16} style={{ color: "#38bdf8" }} />
                Active Operator Profile
              </h3>
              <p className="panel-subtitle">Signed cryptographic session details</p>
            </div>
          </div>

          <div style={{ marginTop: 14, display: "flex", flexDirection: "column", gap: 12 }}>
            <div style={{ display: "flex", justifyContent: "space-between", paddingBottom: 8, borderBottom: "1px solid var(--border-subtle)" }}>
              <span style={{ color: "var(--text-muted)" }}>Operator Name:</span>
              <strong>{currentUser.full_name}</strong>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", paddingBottom: 8, borderBottom: "1px solid var(--border-subtle)" }}>
              <span style={{ color: "var(--text-muted)" }}>Username:</span>
              <code>{currentUser.username}</code>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", paddingBottom: 8, borderBottom: "1px solid var(--border-subtle)" }}>
              <span style={{ color: "var(--text-muted)" }}>Security Clearance:</span>
              <span style={{ fontWeight: 700, color: currentUser.role === "admin" ? "#f87171" : "#38bdf8" }}>
                Level {roleWeights[currentUser.role] || 1} ({currentUser.role?.toUpperCase()})
              </span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", paddingBottom: 8, borderBottom: "1px solid var(--border-subtle)" }}>
              <span style={{ color: "var(--text-muted)" }}>Token Expiry:</span>
              <span>24 Hours (Rolling Session)</span>
            </div>
            <div>
              <span style={{ color: "var(--text-muted)", fontSize: "0.8rem" }}>Session Bearer Token (JWT):</span>
              <div
                style={{
                  marginTop: 6,
                  padding: 10,
                  borderRadius: "var(--radius-sm)",
                  background: "var(--bg-elevated)",
                  border: "1px solid var(--border-default)",
                  fontFamily: "var(--font-mono)",
                  fontSize: "0.75rem",
                  wordBreak: "break-all",
                  color: "#c084fc",
                }}
              >
                {currentUser.token || "Generating session token..."}
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Role Capability Permission Matrix */}
        <div className="panel">
          <div className="panel-header">
            <div>
              <h3 className="panel-title" style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <Shield size={16} style={{ color: "#4ade80" }} />
                Role Capability &amp; Permission Matrix
              </h3>
              <p className="panel-subtitle">Dynamic enforcement based on authenticated clearance</p>
            </div>
            <span className="panel-badge">9 Granular Capabilities</span>
          </div>

          <div style={{ marginTop: 12, display: "flex", flexDirection: "column", gap: 8 }}>
            {capabilityMatrix.map((cap) => {
              const granted = hasPermission(cap.minRole);
              return (
                <div
                  key={cap.key}
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    padding: "8px 12px",
                    borderRadius: "var(--radius-sm)",
                    background: granted ? "rgba(74, 222, 128, 0.05)" : "rgba(239, 68, 68, 0.05)",
                    border: granted ? "1px solid rgba(74, 222, 128, 0.2)" : "1px solid rgba(239, 68, 68, 0.2)",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    {granted ? (
                      <CheckCircle2 size={16} style={{ color: "#4ade80" }} />
                    ) : (
                      <XCircle size={16} style={{ color: "#ef4444" }} />
                    )}
                    <div>
                      <div style={{ fontSize: "0.85rem", fontWeight: 600, color: granted ? "var(--text-primary)" : "var(--text-muted)" }}>
                        {cap.label}
                      </div>
                      <code style={{ fontSize: "0.7rem", color: "var(--text-dim)" }}>{cap.key}</code>
                    </div>
                  </div>
                  <span
                    style={{
                      fontSize: "0.75rem",
                      padding: "2px 8px",
                      borderRadius: 4,
                      fontWeight: 700,
                      background: granted ? "rgba(74, 222, 128, 0.15)" : "rgba(239, 68, 68, 0.15)",
                      color: granted ? "#4ade80" : "#f87171",
                    }}
                  >
                    {granted ? "GRANTED" : `REQUIRES ${cap.minRole.toUpperCase()}`}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* ═══ Swarm Node Cryptographic Key Provisioning Studio ═══ */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h3 className="panel-title" style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <Key size={16} style={{ color: "#f59e0b" }} />
              Swarm Node Cryptographic Token Provisioning
            </h3>
            <p className="panel-subtitle">Generate signed HMAC authorization keys for distributed swarm agents</p>
          </div>
          <span className="panel-badge" style={{ background: "rgba(245, 158, 11, 0.15)", color: "#f59e0b", border: "1px solid rgba(245, 158, 11, 0.3)" }}>
            HMAC-SHA256 Signed
          </span>
        </div>

        {currentUser.role !== "admin" ? (
          <div style={{ padding: 24, textAlign: "center", color: "#f87171" }}>
            <Lock size={32} style={{ margin: "0 auto 8px", opacity: 0.8 }} />
            <h4>Access Restricted</h4>
            <p style={{ fontSize: "0.85rem", color: "var(--text-muted)", marginTop: 4 }}>
              Swarm Agent Token generation requires <strong>ADMIN (L3)</strong> clearance. Switch to Admin mode above to provision keys.
            </p>
          </div>
        ) : (
          <form onSubmit={handleGenerateAgentToken} style={{ marginTop: 14 }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 180px auto", gap: 12 }}>
              <div>
                <label style={{ fontSize: "0.8rem", color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
                  Target Swarm Node ID
                </label>
                <input
                  type="text"
                  className="aegis-input"
                  placeholder="e.g. agent-node-5"
                  value={agentIdInput}
                  onChange={(e) => setAgentIdInput(e.target.value)}
                  style={{ width: "100%" }}
                />
              </div>
              <div>
                <label style={{ fontSize: "0.8rem", color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
                  TTL Duration
                </label>
                <select
                  className="aegis-select"
                  value={agentTtlDays}
                  onChange={(e) => setAgentTtlDays(e.target.value)}
                  style={{ width: "100%", height: 38 }}
                >
                  <option value={7}>7 Days</option>
                  <option value={30}>30 Days</option>
                  <option value={90}>90 Days</option>
                  <option value={365}>1 Year</option>
                </select>
              </div>
              <div style={{ alignSelf: "flex-end" }}>
                <button type="submit" className="btn-primary" disabled={isLoading} style={{ height: 38, padding: "0 20px" }}>
                  <Key size={14} /> Provision Node Key
                </button>
              </div>
            </div>

            {generatedAgentToken && (
              <div
                style={{
                  marginTop: 16,
                  padding: 16,
                  borderRadius: "var(--radius-md)",
                  background: "rgba(56, 189, 248, 0.08)",
                  border: "1px solid rgba(56, 189, 248, 0.4)",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <CheckCircle2 size={16} style={{ color: "#4ade80" }} />
                    <strong style={{ color: "#38bdf8" }}>Node Key Generated: {generatedAgentToken.agent_id}</strong>
                  </div>
                  <button
                    type="button"
                    className="btn-inspect"
                    onClick={() => handleCopy(generatedAgentToken.token)}
                  >
                    {copiedToken ? <Check size={12} style={{ color: "#4ade80" }} /> : <Copy size={12} />}
                    {copiedToken ? "Copied" : "Copy Token"}
                  </button>
                </div>
                <div
                  style={{
                    marginTop: 10,
                    padding: 10,
                    borderRadius: "var(--radius-sm)",
                    background: "var(--bg-elevated)",
                    fontFamily: "var(--font-mono)",
                    fontSize: "0.8rem",
                    color: "#4ade80",
                    wordBreak: "break-all",
                  }}
                >
                  {generatedAgentToken.token}
                </div>
              </div>
            )}
          </form>
        )}
      </div>
    </div>
  );
}
