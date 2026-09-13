import { useState, useMemo } from "react";
import { Shield, ExternalLink, Target, AlertTriangle, Zap, ChevronRight, Info } from "lucide-react";

/* ═══════════════════════════════════════════════════════════════════════════
   MITRE ATT&CK Technique Mapping for all 6 AEGIS ML Models
   Source: https://attack.mitre.org/  (MITRE ATT&CK® Enterprise Matrix v15)
   ═══════════════════════════════════════════════════════════════════════════ */
const MITRE_MAPPINGS = [
  // ─────────── Linux IDS (XGBoost) ───────────
  {
    techniqueId: "T1110",
    name: "Brute Force",
    tactic: "Credential Access",
    tacticId: "TA0006",
    model: "Linux IDS",
    modelIcon: "🐧",
    detectionClass: "Hydra_SSH / Hydra_FTP",
    severity: "HIGH",
    description: "Adversary attempts to gain access by iterating credentials via Hydra SSH/FTP dictionary attacks.",
    platforms: ["Linux"],
    subtechniques: ["T1110.001 – Password Guessing", "T1110.003 – Password Spraying"],
    mitigation: "M1032 – Multi-factor Authentication, M1036 – Account Use Policies",
  },
  {
    techniqueId: "T1059",
    name: "Command & Scripting Interpreter",
    tactic: "Execution",
    tacticId: "TA0002",
    model: "Linux IDS",
    modelIcon: "🐧",
    detectionClass: "Java_Meterpreter / Meterpreter",
    severity: "CRITICAL",
    description: "Meterpreter shells executed via reverse TCP/SSL exploit payloads (Metasploit Framework).",
    platforms: ["Linux"],
    subtechniques: ["T1059.004 – Unix Shell", "T1059.007 – JavaScript"],
    mitigation: "M1038 – Execution Prevention, M1049 – Antivirus/Antimalware",
  },
  {
    techniqueId: "T1505",
    name: "Server Software Component",
    tactic: "Persistence",
    tacticId: "TA0003",
    model: "Linux IDS",
    modelIcon: "🐧",
    detectionClass: "Web_Shell",
    severity: "CRITICAL",
    description: "Adversary uploads malicious server-side scripts (PHP/JSP/ASP web shells) for persistent access.",
    platforms: ["Linux"],
    subtechniques: ["T1505.003 – Web Shell"],
    mitigation: "M1042 – Disable or Remove Feature or Program, M1018 – User Account Management",
  },
  {
    techniqueId: "T1136",
    name: "Create Account",
    tactic: "Persistence",
    tacticId: "TA0003",
    model: "Linux IDS",
    modelIcon: "🐧",
    detectionClass: "Adduser",
    severity: "MEDIUM",
    description: "Adversary creates backdoor OS accounts to maintain access to the compromised system.",
    platforms: ["Linux"],
    subtechniques: ["T1136.001 – Local Account"],
    mitigation: "M1032 – Multi-factor Authentication, M1028 – Operating System Configuration",
  },
  // ─────────── Windows Advanced v3 (XGBoost) ───────────
  {
    techniqueId: "T1112",
    name: "Modify Registry",
    tactic: "Defense Evasion",
    tacticId: "TA0005",
    model: "Windows Advanced",
    modelIcon: "🪟",
    detectionClass: "Registry Tampering",
    severity: "HIGH",
    description: "Adversaries modify the Windows registry to establish persistence, escalate privileges, or evade detection.",
    platforms: ["Windows"],
    subtechniques: ["T1547.001 – Registry Run Keys / Startup Folder"],
    mitigation: "M1024 – Restrict Registry Permissions, M1054 – Software Configuration",
  },
  {
    techniqueId: "T1055",
    name: "Process Injection",
    tactic: "Defense Evasion",
    tacticId: "TA0005",
    model: "Windows Advanced",
    modelIcon: "🪟",
    detectionClass: "Process Context Anomaly",
    severity: "CRITICAL",
    description: "Malicious code injected into legitimate Windows process memory space to evade process-level defenses.",
    platforms: ["Windows"],
    subtechniques: ["T1055.001 – DLL Injection", "T1055.012 – Process Hollowing"],
    mitigation: "M1040 – Behavior Prevention on Endpoint, M1026 – Privileged Account Management",
  },
  {
    techniqueId: "T1078",
    name: "Valid Accounts",
    tactic: "Privilege Escalation",
    tacticId: "TA0004",
    model: "Windows Advanced",
    modelIcon: "🪟",
    detectionClass: "Token Privilege Abuse",
    severity: "HIGH",
    description: "Adversary abuses valid or compromised Windows credentials and privilege tokens to maintain elevated access.",
    platforms: ["Windows"],
    subtechniques: ["T1078.002 – Domain Accounts", "T1078.003 – Local Accounts"],
    mitigation: "M1026 – Privileged Account Management, M1017 – User Training",
  },
  // ─────────── CICIDS Network (LightGBM) ───────────
  {
    techniqueId: "T1498",
    name: "Network Denial of Service",
    tactic: "Impact",
    tacticId: "TA0040",
    model: "CICIDS Network",
    modelIcon: "🌐",
    detectionClass: "DoS / DDoS",
    severity: "HIGH",
    description: "Adversary floods network resources to degrade or deny service availability (DoS/DDoS attacks).",
    platforms: ["Network"],
    subtechniques: ["T1498.001 – Direct Network Flood", "T1498.002 – Reflection Amplification"],
    mitigation: "M1037 – Filter Network Traffic, M1035 – Limit Access to Resource Over Network",
  },
  {
    techniqueId: "T1046",
    name: "Network Service Discovery",
    tactic: "Discovery",
    tacticId: "TA0007",
    model: "CICIDS Network",
    modelIcon: "🌐",
    detectionClass: "PortScan",
    severity: "MEDIUM",
    description: "Adversary enumerates network services and open ports to identify attack surface.",
    platforms: ["Network"],
    subtechniques: [],
    mitigation: "M1031 – Network Intrusion Prevention, M1030 – Network Segmentation",
  },
  {
    techniqueId: "T1071",
    name: "Application Layer Protocol",
    tactic: "Command & Control",
    tacticId: "TA0011",
    model: "CICIDS Network",
    modelIcon: "🌐",
    detectionClass: "Botnet / C2 Traffic",
    severity: "CRITICAL",
    description: "Botnet nodes communicating with C2 servers over standard application protocols to evade inspection.",
    platforms: ["Network"],
    subtechniques: ["T1071.001 – Web Protocols", "T1071.004 – DNS"],
    mitigation: "M1031 – Network Intrusion Prevention, M1037 – Filter Network Traffic",
  },
  // ─────────── EMBER PE Binary (LightGBM) ───────────
  {
    techniqueId: "T1204",
    name: "User Execution",
    tactic: "Execution",
    tacticId: "TA0002",
    model: "EMBER File",
    modelIcon: "📄",
    detectionClass: "Malicious PE Binary",
    severity: "HIGH",
    description: "User executes malicious PE binary (dropper/loader) flagged by EMBER header feature inspection.",
    platforms: ["Windows"],
    subtechniques: ["T1204.002 – Malicious File"],
    mitigation: "M1038 – Execution Prevention, M1049 – Antivirus/Antimalware",
  },
  {
    techniqueId: "T1027",
    name: "Obfuscated Files or Information",
    tactic: "Defense Evasion",
    tacticId: "TA0005",
    model: "EMBER File",
    modelIcon: "📄",
    detectionClass: "High Entropy Sections",
    severity: "HIGH",
    description: "Malicious PE files with packed/encrypted code sections (high entropy) to evade static AV signatures.",
    platforms: ["Windows"],
    subtechniques: ["T1027.002 – Software Packing", "T1027.009 – Embedded Payloads"],
    mitigation: "M1049 – Antivirus/Antimalware, M1040 – Behavior Prevention on Endpoint",
  },
  // ─────────── HDFS Log Anomaly (XGBoost + TF-IDF) ───────────
  {
    techniqueId: "T1486",
    name: "Data Encrypted for Impact",
    tactic: "Impact",
    tacticId: "TA0040",
    model: "HDFS Log",
    modelIcon: "📋",
    detectionClass: "Ransomware Bulk Encryption",
    severity: "CRITICAL",
    description: "Ransomware anomaly detected via bulk file access log patterns — adversary encrypts data for extortion.",
    platforms: ["Linux", "Windows"],
    subtechniques: [],
    mitigation: "M1053 – Data Backup, M1040 – Behavior Prevention on Endpoint",
  },
  {
    techniqueId: "T1530",
    name: "Data from Cloud Storage",
    tactic: "Collection",
    tacticId: "TA0009",
    model: "HDFS Log",
    modelIcon: "📋",
    detectionClass: "Bulk File Access Anomaly",
    severity: "MEDIUM",
    description: "Unusual bulk file read/write sequences detected in distributed log streams suggesting data exfiltration.",
    platforms: ["Linux"],
    subtechniques: [],
    mitigation: "M1022 – Restrict File and Directory Permissions, M1037 – Filter Network Traffic",
  },
  // ─────────── Zero-Day Anomaly (Isolation Forest) ───────────
  {
    techniqueId: "T1190",
    name: "Exploit Public-Facing Application",
    tactic: "Initial Access",
    tacticId: "TA0001",
    model: "Zero-Day",
    modelIcon: "🔬",
    detectionClass: "Unknown Process Anomaly",
    severity: "CRITICAL",
    description: "Zero-day unsupervised anomaly: unknown process/event signature with no known classification — high alert.",
    platforms: ["Linux", "Windows"],
    subtechniques: [],
    mitigation: "M1048 – Application Isolation & Sandboxing, M1030 – Network Segmentation",
  },
  {
    techniqueId: "T1203",
    name: "Exploitation for Client Execution",
    tactic: "Execution",
    tacticId: "TA0002",
    model: "Zero-Day",
    modelIcon: "🔬",
    detectionClass: "Novel Execution Anomaly",
    severity: "HIGH",
    description: "Isolation Forest detects a previously unseen execution pattern that deviates from normal telemetry baseline.",
    platforms: ["Linux", "Windows"],
    subtechniques: [],
    mitigation: "M1048 – Application Isolation & Sandboxing, M1040 – Behavior Prevention on Endpoint",
  },
];

/* Tactic color palette (per-tactic for the ATT&CK matrix columns) */
const TACTIC_COLORS = {
  "Initial Access":        { bg: "#1e1e4a", border: "#6366f1", badge: "#818cf8" },
  "Execution":             { bg: "#1e2e1e", border: "#22c55e", badge: "#4ade80" },
  "Persistence":           { bg: "#2e1e2e", border: "#a855f7", badge: "#c084fc" },
  "Privilege Escalation":  { bg: "#2e2e1e", border: "#f59e0b", badge: "#fbbf24" },
  "Defense Evasion":       { bg: "#1e2a2e", border: "#06b6d4", badge: "#22d3ee" },
  "Credential Access":     { bg: "#2e1e1e", border: "#ef4444", badge: "#f87171" },
  "Discovery":             { bg: "#1e2e2a", border: "#10b981", badge: "#34d399" },
  "Command & Control":     { bg: "#2a1e2e", border: "#ec4899", badge: "#f472b6" },
  "Collection":            { bg: "#252520", border: "#84cc16", badge: "#a3e635" },
  "Impact":                { bg: "#2e1a1a", border: "#f97316", badge: "#fb923c" },
};

const SEVERITY_STYLE = {
  CRITICAL: { bg: "rgba(239,68,68,0.15)", border: "#ef4444", text: "#f87171", dot: "#ef4444" },
  HIGH:     { bg: "rgba(245,158,11,0.15)", border: "#f59e0b", text: "#fbbf24", dot: "#f59e0b" },
  MEDIUM:   { bg: "rgba(59,130,246,0.15)", border: "#3b82f6", text: "#60a5fa", dot: "#3b82f6" },
  LOW:      { bg: "rgba(16,185,129,0.15)", border: "#10b981", text: "#34d399", dot: "#10b981" },
};

const ALL_TACTICS = [
  "Initial Access", "Execution", "Persistence", "Privilege Escalation",
  "Defense Evasion", "Credential Access", "Discovery", "Command & Control",
  "Collection", "Impact",
];

const ALL_MODELS = ["Linux IDS", "Windows Advanced", "CICIDS Network", "EMBER File", "HDFS Log", "Zero-Day"];

export default function MitreAttackTab() {
  const [selectedTechnique, setSelectedTechnique] = useState(null);
  const [filterModel, setFilterModel] = useState("All");
  const [filterSeverity, setFilterSeverity] = useState("All");
  const [viewMode, setViewMode] = useState("heatmap"); // "heatmap" | "table"

  const filtered = useMemo(() =>
    MITRE_MAPPINGS.filter(t =>
      (filterModel === "All" || t.model === filterModel) &&
      (filterSeverity === "All" || t.severity === filterSeverity)
    ), [filterModel, filterSeverity]
  );

  /* Group techniques by tactic for the heatmap */
  const byTactic = useMemo(() => {
    const map = {};
    ALL_TACTICS.forEach(t => (map[t] = []));
    filtered.forEach(t => {
      if (map[t.tactic]) map[t.tactic].push(t);
    });
    return map;
  }, [filtered]);

  const activeTactics = ALL_TACTICS.filter(t => byTactic[t]?.length > 0);

  /* Summary stats */
  const criticalCount = filtered.filter(t => t.severity === "CRITICAL").length;
  const highCount = filtered.filter(t => t.severity === "HIGH").length;
  const uniqueTactics = [...new Set(filtered.map(t => t.tactic))].length;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>

      {/* ── Header ── */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
        <div>
          <h2 style={{ margin: 0, fontSize: 20, fontWeight: 700, color: "#f1f5f9", display: "flex", alignItems: "center", gap: 8 }}>
            <Target size={22} style={{ color: "#ef4444" }} />
            MITRE ATT&amp;CK® Threat Coverage Matrix
          </h2>
          <p style={{ margin: "4px 0 0", fontSize: 12, color: "#64748b" }}>
            AEGIS ML model detections mapped to MITRE ATT&amp;CK Enterprise v15 — {MITRE_MAPPINGS.length} techniques across 6 models
          </p>
        </div>

        {/* View toggle */}
        <div style={{ display: "flex", background: "#0f172a", borderRadius: 8, border: "1px solid #1e293b", overflow: "hidden" }}>
          {["heatmap", "table"].map(v => (
            <button key={v} onClick={() => setViewMode(v)} style={{
              padding: "6px 18px", border: "none", cursor: "pointer", fontSize: 12, fontWeight: 600,
              background: viewMode === v ? "#1d4ed8" : "transparent",
              color: viewMode === v ? "#fff" : "#64748b",
              transition: "all 0.2s",
              textTransform: "capitalize",
            }}>
              {v === "heatmap" ? "🗂 Heatmap" : "📋 Detail Table"}
            </button>
          ))}
        </div>
      </div>

      {/* ── Summary stats ── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}>
        {[
          { label: "Mapped Techniques", value: filtered.length, color: "#60a5fa", icon: "🎯" },
          { label: "CRITICAL Detections", value: criticalCount, color: "#f87171", icon: "🔴" },
          { label: "HIGH Detections", value: highCount, color: "#fbbf24", icon: "🟡" },
          { label: "Tactics Covered", value: uniqueTactics, color: "#34d399", icon: "📊" },
        ].map(s => (
          <div key={s.label} style={{
            background: "#0f172a", border: "1px solid #1e293b", borderRadius: 10,
            padding: "14px 16px", display: "flex", alignItems: "center", gap: 12
          }}>
            <span style={{ fontSize: 22 }}>{s.icon}</span>
            <div>
              <div style={{ fontSize: 22, fontWeight: 700, color: s.color, lineHeight: 1 }}>{s.value}</div>
              <div style={{ fontSize: 11, color: "#64748b", marginTop: 3 }}>{s.label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* ── Filters ── */}
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
        <span style={{ fontSize: 12, color: "#64748b", fontWeight: 600 }}>Filter:</span>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {["All", ...ALL_MODELS].map(m => (
            <button key={m} onClick={() => setFilterModel(m)} style={{
              padding: "4px 12px", borderRadius: 20, border: "1px solid",
              fontSize: 11, fontWeight: 600, cursor: "pointer", transition: "all 0.15s",
              background: filterModel === m ? "#1d4ed8" : "#0f172a",
              borderColor: filterModel === m ? "#3b82f6" : "#1e293b",
              color: filterModel === m ? "#fff" : "#94a3b8",
            }}>
              {m === "All" ? "All Models" : m}
            </button>
          ))}
        </div>
        <div style={{ display: "flex", gap: 6, marginLeft: 8 }}>
          {["All", "CRITICAL", "HIGH", "MEDIUM"].map(s => {
            const sv = SEVERITY_STYLE[s];
            return (
              <button key={s} onClick={() => setFilterSeverity(s)} style={{
                padding: "4px 12px", borderRadius: 20, border: "1px solid",
                fontSize: 11, fontWeight: 600, cursor: "pointer", transition: "all 0.15s",
                background: filterSeverity === s ? (sv?.bg || "#0f172a") : "#0f172a",
                borderColor: filterSeverity === s ? (sv?.border || "#1e293b") : "#1e293b",
                color: filterSeverity === s ? (sv?.text || "#fff") : "#94a3b8",
              }}>
                {s === "All" ? "All Severities" : s}
              </button>
            );
          })}
        </div>
      </div>

      {/* ══ HEATMAP VIEW ══ */}
      {viewMode === "heatmap" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {activeTactics.length === 0 ? (
            <div style={{ textAlign: "center", color: "#64748b", padding: 40, background: "#0f172a", borderRadius: 12, border: "1px solid #1e293b" }}>
              No techniques match the current filter.
            </div>
          ) : (
            activeTactics.map(tactic => {
              const techs = byTactic[tactic];
              const colors = TACTIC_COLORS[tactic] || { bg: "#0f172a", border: "#1e293b", badge: "#64748b" };
              return (
                <div key={tactic} style={{
                  background: colors.bg, border: `1px solid ${colors.border}`,
                  borderRadius: 12, padding: "14px 16px", transition: "border-color 0.2s",
                }}>
                  {/* Tactic header */}
                  <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
                    <span style={{
                      background: colors.border + "33", color: colors.badge,
                      padding: "2px 10px", borderRadius: 12, fontSize: 11, fontWeight: 700,
                      border: `1px solid ${colors.border}44`, letterSpacing: "0.04em"
                    }}>
                      {tactic.toUpperCase()}
                    </span>
                    <span style={{ fontSize: 11, color: "#64748b" }}>
                      {techs.length} technique{techs.length !== 1 ? "s" : ""} detected
                    </span>
                    <a
                      href={`https://attack.mitre.org/tactics/${ALL_TACTICS.indexOf(tactic) < 5 ? "TA000" + (ALL_TACTICS.indexOf(tactic) + 1) : "TA00" + (ALL_TACTICS.indexOf(tactic) + 1)}/`}
                      target="_blank" rel="noopener noreferrer"
                      style={{ marginLeft: "auto", color: colors.badge, fontSize: 11, display: "flex", alignItems: "center", gap: 4, textDecoration: "none" }}
                    >
                      ATT&amp;CK Ref <ExternalLink size={11} />
                    </a>
                  </div>

                  {/* Technique cards */}
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))", gap: 10 }}>
                    {techs.map(tech => {
                      const sv = SEVERITY_STYLE[tech.severity];
                      const isSelected = selectedTechnique?.techniqueId === tech.techniqueId;
                      return (
                        <button
                          key={tech.techniqueId}
                          onClick={() => setSelectedTechnique(isSelected ? null : tech)}
                          style={{
                            background: isSelected ? sv.bg : "#0a1020",
                            border: `1px solid ${isSelected ? sv.border : "#1e293b"}`,
                            borderRadius: 10, padding: "12px 14px",
                            textAlign: "left", cursor: "pointer",
                            transition: "all 0.2s",
                            outline: isSelected ? `2px solid ${sv.border}` : "none",
                          }}
                        >
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 6 }}>
                            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                              <span style={{ fontSize: 16 }}>{tech.modelIcon}</span>
                              <span style={{
                                fontSize: 10, fontWeight: 700, letterSpacing: "0.06em",
                                color: sv.text, padding: "1px 6px", borderRadius: 8,
                                background: sv.bg, border: `1px solid ${sv.border}`,
                              }}>
                                {tech.severity}
                              </span>
                            </div>
                            <span style={{ fontSize: 10, fontFamily: "monospace", color: colors.badge, fontWeight: 700 }}>
                              {tech.techniqueId}
                            </span>
                          </div>
                          <div style={{ fontSize: 13, fontWeight: 600, color: "#e2e8f0", marginBottom: 4 }}>
                            {tech.name}
                          </div>
                          <div style={{ fontSize: 11, color: "#64748b" }}>
                            {tech.model} · {tech.detectionClass}
                          </div>
                          {isSelected && (
                            <div style={{ color: "#94a3b8", display: "flex", alignItems: "center", gap: 4, marginTop: 6, fontSize: 11 }}>
                              <Info size={12} /> Click to collapse
                            </div>
                          )}
                        </button>
                      );
                    })}
                  </div>
                </div>
              );
            })
          )}
        </div>
      )}

      {/* ══ TABLE VIEW ══ */}
      {viewMode === "table" && (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
            <thead>
              <tr style={{ background: "#0f172a", borderBottom: "1px solid #1e293b" }}>
                {["Technique ID", "Name", "Tactic", "AEGIS Model", "Detection Class", "Severity", "Platforms"].map(h => (
                  <th key={h} style={{ padding: "10px 14px", textAlign: "left", fontWeight: 600, color: "#64748b", fontSize: 11, letterSpacing: "0.05em", whiteSpace: "nowrap" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((tech, i) => {
                const sv = SEVERITY_STYLE[tech.severity];
                return (
                  <tr
                    key={tech.techniqueId + i}
                    onClick={() => setSelectedTechnique(selectedTechnique?.techniqueId === tech.techniqueId ? null : tech)}
                    style={{
                      borderBottom: "1px solid #1e293b",
                      background: selectedTechnique?.techniqueId === tech.techniqueId ? sv.bg : (i % 2 === 0 ? "#070b12" : "#0b111d"),
                      cursor: "pointer", transition: "background 0.15s"
                    }}
                  >
                    <td style={{ padding: "10px 14px", fontFamily: "monospace", color: "#60a5fa", fontWeight: 700, fontSize: 12 }}>
                      <a href={`https://attack.mitre.org/techniques/${tech.techniqueId}/`} target="_blank" rel="noopener noreferrer"
                        onClick={e => e.stopPropagation()}
                        style={{ color: "#60a5fa", display: "flex", alignItems: "center", gap: 4 }}>
                        {tech.techniqueId} <ExternalLink size={10} />
                      </a>
                    </td>
                    <td style={{ padding: "10px 14px", color: "#e2e8f0", fontWeight: 600 }}>{tech.name}</td>
                    <td style={{ padding: "10px 14px" }}>
                      <span style={{ fontSize: 11, padding: "2px 8px", borderRadius: 8, background: (TACTIC_COLORS[tech.tactic]?.border || "#1e293b") + "22", color: TACTIC_COLORS[tech.tactic]?.badge || "#94a3b8", border: `1px solid ${(TACTIC_COLORS[tech.tactic]?.border || "#1e293b")}44` }}>
                        {tech.tactic}
                      </span>
                    </td>
                    <td style={{ padding: "10px 14px", color: "#94a3b8" }}>
                      {tech.modelIcon} {tech.model}
                    </td>
                    <td style={{ padding: "10px 14px", color: "#64748b", fontSize: 12 }}>{tech.detectionClass}</td>
                    <td style={{ padding: "10px 14px" }}>
                      <span style={{ fontSize: 11, padding: "2px 8px", borderRadius: 8, background: sv.bg, color: sv.text, border: `1px solid ${sv.border}`, fontWeight: 700 }}>
                        {tech.severity}
                      </span>
                    </td>
                    <td style={{ padding: "10px 14px", color: "#64748b", fontSize: 11 }}>{tech.platforms.join(", ")}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* ══ DETAIL DRAWER ══ */}
      {selectedTechnique && (() => {
        const t = selectedTechnique;
        const sv = SEVERITY_STYLE[t.severity];
        const tc = TACTIC_COLORS[t.tactic] || { bg: "#0f172a", border: "#1e293b", badge: "#64748b" };
        return (
          <div style={{
            background: "#0b1120", border: `1px solid ${sv.border}`,
            borderRadius: 14, padding: 24,
            boxShadow: `0 0 30px ${sv.border}22`,
            position: "relative",
            animation: "fadeIn 0.2s ease",
          }}>
            <button onClick={() => setSelectedTechnique(null)} style={{
              position: "absolute", top: 14, right: 14,
              background: "#1e293b", border: "none", color: "#94a3b8",
              borderRadius: 8, width: 30, height: 30, cursor: "pointer",
              display: "flex", alignItems: "center", justifyContent: "center",
            }}>✕</button>

            <div style={{ display: "flex", alignItems: "flex-start", gap: 16, marginBottom: 18, flexWrap: "wrap" }}>
              <div style={{ fontSize: 36 }}>{t.modelIcon}</div>
              <div style={{ flex: 1 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap", marginBottom: 6 }}>
                  <a href={`https://attack.mitre.org/techniques/${t.techniqueId}/`} target="_blank" rel="noopener noreferrer"
                    style={{ fontSize: 14, fontWeight: 800, fontFamily: "monospace", color: "#60a5fa", display: "flex", alignItems: "center", gap: 5 }}>
                    {t.techniqueId} <ExternalLink size={13} />
                  </a>
                  <span style={{ fontSize: 10, padding: "2px 8px", borderRadius: 8, background: sv.bg, color: sv.text, border: `1px solid ${sv.border}`, fontWeight: 700 }}>
                    {t.severity}
                  </span>
                  <span style={{ fontSize: 10, padding: "2px 8px", borderRadius: 8, background: tc.border + "22", color: tc.badge, border: `1px solid ${tc.border}44`, fontWeight: 700 }}>
                    {t.tactic}
                  </span>
                </div>
                <h3 style={{ margin: 0, fontSize: 18, fontWeight: 700, color: "#f1f5f9" }}>{t.name}</h3>
                <p style={{ margin: "8px 0 0", fontSize: 13, color: "#94a3b8", lineHeight: 1.6 }}>{t.description}</p>
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 14 }}>
              <div style={{ background: "#070b12", borderRadius: 10, padding: "12px 14px", border: "1px solid #1e293b" }}>
                <div style={{ fontSize: 11, color: "#64748b", marginBottom: 6, fontWeight: 600 }}>AEGIS Model</div>
                <div style={{ color: "#e2e8f0", fontWeight: 600 }}>{t.modelIcon} {t.model}</div>
              </div>
              <div style={{ background: "#070b12", borderRadius: 10, padding: "12px 14px", border: "1px solid #1e293b" }}>
                <div style={{ fontSize: 11, color: "#64748b", marginBottom: 6, fontWeight: 600 }}>Detection Class</div>
                <div style={{ color: "#e2e8f0", fontWeight: 600 }}>{t.detectionClass}</div>
              </div>
              <div style={{ background: "#070b12", borderRadius: 10, padding: "12px 14px", border: "1px solid #1e293b" }}>
                <div style={{ fontSize: 11, color: "#64748b", marginBottom: 6, fontWeight: 600 }}>Target Platform</div>
                <div style={{ color: "#e2e8f0", fontWeight: 600 }}>{t.platforms.join(", ")}</div>
              </div>
            </div>

            {t.subtechniques?.length > 0 && (
              <div style={{ marginTop: 14 }}>
                <div style={{ fontSize: 11, color: "#64748b", fontWeight: 600, marginBottom: 8 }}>SUB-TECHNIQUES</div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                  {t.subtechniques.map(sub => (
                    <span key={sub} style={{ fontSize: 11, padding: "3px 10px", borderRadius: 20, background: "#0f172a", color: "#94a3b8", border: "1px solid #1e293b" }}>
                      <ChevronRight size={10} style={{ marginRight: 3 }} />{sub}
                    </span>
                  ))}
                </div>
              </div>
            )}

            <div style={{ marginTop: 14, padding: "10px 14px", background: "#0a1820", borderRadius: 10, border: "1px solid #0f2d40" }}>
              <div style={{ fontSize: 11, color: "#38bdf8", fontWeight: 600, marginBottom: 4, display: "flex", alignItems: "center", gap: 6 }}>
                <Shield size={12} /> MITRE MITIGATIONS
              </div>
              <div style={{ fontSize: 12, color: "#64748b" }}>{t.mitigation}</div>
            </div>
          </div>
        );
      })()}

      {/* Legend */}
      <div style={{ display: "flex", gap: 16, flexWrap: "wrap", padding: "12px 16px", background: "#0f172a", borderRadius: 10, border: "1px solid #1e293b" }}>
        <span style={{ fontSize: 11, color: "#475569", fontWeight: 600 }}>SEVERITY:</span>
        {Object.entries(SEVERITY_STYLE).map(([s, v]) => (
          <div key={s} style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: v.dot }} />
            <span style={{ fontSize: 11, color: v.text, fontWeight: 600 }}>{s}</span>
          </div>
        ))}
        <span style={{ marginLeft: "auto", fontSize: 11, color: "#475569" }}>
          Source: MITRE ATT&amp;CK® Enterprise v15 · attack.mitre.org
        </span>
      </div>
    </div>
  );
}
