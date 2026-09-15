import React, { useState, useEffect } from "react";
import {
  Globe,
  Search,
  Shield,
  Upload,
  Database,
  CheckCircle2,
  AlertTriangle,
  Zap,
  Activity,
  Layers,
  Copy,
  Check,
  RefreshCw,
  FileCode,
  Tag,
  Crosshair,
  Lock,
} from "lucide-react";

export default function ThreatIntelTab({ backendUrl = "http://127.0.0.1:8000" }) {
  const [indicators, setIndicators] = useState([]);
  const [stats, setStats] = useState({
    total_indicators: 0,
    ip_indicators: 0,
    cidr_networks: 0,
    domain_indicators: 0,
    hash_indicators: 0,
    url_indicators: 0,
  });
  const [searchQuery, setSearchQuery] = useState("");
  const [filterType, setFilterType] = useState("all");
  const [lookupValue, setLookupValue] = useState("194.26.29.112");
  const [lookupResult, setLookupResult] = useState(null);
  const [isLookingUp, setIsLookingUp] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [copiedId, setCopiedId] = useState(null);
  const [stixJsonInput, setStixJsonInput] = useState("");
  const [importStatus, setImportStatus] = useState(null);

  const fetchIndicators = async () => {
    setIsLoading(true);
    try {
      const res = await fetch(`${backendUrl}/api/intel/indicators`);
      if (res.ok) {
        const data = await res.json();
        setIndicators(data.indicators || []);
        setStats(data.stats || {});
      }
    } catch (err) {
      console.error("Failed to fetch threat intel indicators:", err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchIndicators();
  }, []);

  const handleLookup = async (e) => {
    if (e) e.preventDefault();
    if (!lookupValue.trim()) return;
    setIsLookingUp(true);
    setLookupResult(null);
    try {
      const res = await fetch(`${backendUrl}/api/intel/lookup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: lookupValue.trim() }),
      });
      if (res.ok) {
        const data = await res.json();
        setLookupResult(data);
      }
    } catch (err) {
      console.error("Lookup query failed:", err);
    } finally {
      setIsLookingUp(false);
    }
  };

  const handleCopy = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleImportStix = async () => {
    if (!stixJsonInput.trim()) return;
    try {
      const parsed = JSON.parse(stixJsonInput);
      const res = await fetch(`${backendUrl}/api/intel/stix/import`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(parsed),
      });
      if (res.ok) {
        const data = await res.json();
        setImportStatus({
          type: "success",
          message: `Successfully ingested ${data.indicators_imported} STIX indicators. Total active IOCs: ${data.total_active_indicators}.`,
        });
        fetchIndicators();
      } else {
        setImportStatus({ type: "error", message: "Failed to parse STIX bundle payload." });
      }
    } catch (err) {
      setImportStatus({ type: "error", message: `Invalid JSON format: ${err.message}` });
    }
  };

  const loadSampleStix = () => {
    const sample = {
      type: "bundle",
      id: "bundle--c0ffee01-8b9a-4e2b-a5d6-000000000099",
      objects: [
        {
          type: "indicator",
          id: "indicator--custom-sample-1",
          pattern: "[ipv4-addr:value = '198.51.100.77']",
          name: "BlackCat Ransomware Ingress Node",
          description: "Active C2 beacon observed in BlackCat ALPHV operations",
          confidence: 95,
          labels: ["ransomware", "alphv", "c2-relay"],
        },
        {
          type: "indicator",
          id: "indicator--custom-sample-2",
          pattern: "[domain-name:value = 'alphv-payload-gateway.org']",
          name: "ALPHV Payload Staging Gateway",
          description: "HTTPS command and exfiltration gateway for multi-stage payloads",
          confidence: 90,
          labels: ["alphv", "exfiltration"],
        },
      ],
    };
    setStixJsonInput(JSON.stringify(sample, null, 2));
  };

  const filteredIndicators = indicators.filter((ind) => {
    const matchesSearch =
      ind.value.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (ind.threat_actor && ind.threat_actor.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (ind.description && ind.description.toLowerCase().includes(searchQuery.toLowerCase()));

    if (filterType === "all") return matchesSearch;
    return matchesSearch && ind.indicator_type.toLowerCase().includes(filterType.toLowerCase());
  });

  return (
    <div className="threat-intel-container fade-in">
      {/* ═══ Header Section ═══ */}
      <div className="panel" style={{ marginBottom: 20 }}>
        <div className="panel-header">
          <div>
            <h2 className="panel-title" style={{ display: "flex", alignItems: "center", gap: 8, fontSize: "1.25rem" }}>
              <Globe size={20} style={{ color: "#38bdf8" }} />
              STIX 2.1 / TAXII &amp; MISP Cyber Threat Intelligence (CTI) Hub
            </h2>
            <p className="panel-subtitle">
              High-performance, in-memory Indicator of Compromise (IOC) matching with sub-microsecond lookups
            </p>
          </div>
          <div style={{ display: "flex", gap: 10 }}>
            <button className="btn-small-pulse" onClick={fetchIndicators} disabled={isLoading}>
              <RefreshCw size={13} className={isLoading ? "spin" : ""} /> Refresh Feed
            </button>
          </div>
        </div>

        {/* CTI KPI Stats Grid */}
        <div className="cti-stats-grid" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12, marginTop: 14 }}>
          <div className="cti-stat-card">
            <div className="cti-stat-label"><Database size={14} style={{ color: "#38bdf8" }} /> Total Active IOCs</div>
            <div className="cti-stat-value" style={{ color: "#38bdf8" }}>{stats.total_indicators || indicators.length}</div>
            <div className="cti-stat-sub">Zero-Allocation Memory Set</div>
          </div>
          <div className="cti-stat-card">
            <div className="cti-stat-label"><Activity size={14} style={{ color: "#4ade80" }} /> IPv4 &amp; Subnets</div>
            <div className="cti-stat-value" style={{ color: "#4ade80" }}>{(stats.ip_indicators || 0) + (stats.cidr_networks || 0)}</div>
            <div className="cti-stat-sub">CIDR Radix Matching</div>
          </div>
          <div className="cti-stat-card">
            <div className="cti-stat-label"><Globe size={14} style={{ color: "#c084fc" }} /> Malicious Domains</div>
            <div className="cti-stat-value" style={{ color: "#c084fc" }}>{stats.domain_indicators || 0}</div>
            <div className="cti-stat-sub">C2 &amp; DNS Sinkholes</div>
          </div>
          <div className="cti-stat-card">
            <div className="cti-stat-label"><FileCode size={14} style={{ color: "#f87171" }} /> File Hashes (SHA256)</div>
            <div className="cti-stat-value" style={{ color: "#f87171" }}>{stats.hash_indicators || 0}</div>
            <div className="cti-stat-sub">Droppers &amp; Ransomware</div>
          </div>
        </div>
      </div>

      {/* ═══ 2-Column Main Layout: Live IOC Sandbox & Bundle Ingester ═══ */}
      <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: 20, marginBottom: 20 }}>
        {/* Left Column: Live IOC Sub-Microsecond Lookup Sandbox */}
        <div className="panel">
          <div className="panel-header">
            <div>
              <h3 className="panel-title" style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <Crosshair size={16} style={{ color: "#38bdf8" }} />
                Real-Time IOC Lookup Engine
              </h3>
              <p className="panel-subtitle">Test incoming telemetry indicators against active CTI memory tables</p>
            </div>
            <span className="panel-badge" style={{ background: "rgba(56, 189, 248, 0.15)", color: "#38bdf8", border: "1px solid rgba(56, 189, 248, 0.3)" }}>
              &lt; 0.05 ms latency
            </span>
          </div>

          <form onSubmit={handleLookup} style={{ marginTop: 12 }}>
            <div style={{ display: "flex", gap: 8 }}>
              <input
                type="text"
                className="aegis-input"
                placeholder="Enter IP, CIDR subnet, Domain, URL, or SHA256 Hash..."
                value={lookupValue}
                onChange={(e) => setLookupValue(e.target.value)}
                style={{ flex: 1 }}
              />
              <button type="submit" className="btn-primary" disabled={isLookingUp} style={{ padding: "0 18px" }}>
                {isLookingUp ? <RefreshCw size={14} className="spin" /> : <Zap size={14} />}
                Lookup IOC
              </button>
            </div>
          </form>

          {/* Preset test buttons */}
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 10, alignItems: "center" }}>
            <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginRight: 4 }}>Quick Samples:</span>
            <button
              type="button"
              className="btn-badge-chip"
              onClick={() => { setLookupValue("194.26.29.112"); }}
            >
              APT29 C2 (IP)
            </button>
            <button
              type="button"
              className="btn-badge-chip"
              onClick={() => { setLookupValue("185.220.101.45"); }}
            >
              Mirai Botnet (CIDR)
            </button>
            <button
              type="button"
              className="btn-badge-chip"
              onClick={() => { setLookupValue("lockbit3-relay.onion-proxy.org"); }}
            >
              LockBit 3.0 Domain
            </button>
            <button
              type="button"
              className="btn-badge-chip"
              onClick={() => { setLookupValue("ed01ebf83334ac636814d94444e1f14ae1f5e8485c19e18e8d34704f145f31f7"); }}
            >
              WannaCry Hash
            </button>
          </div>

          {/* Lookup Result Card */}
          {lookupResult && (
            <div
              className={`cti-result-card ${lookupResult.matched ? "matched" : "clean"}`}
              style={{
                marginTop: 16,
                padding: 16,
                borderRadius: "var(--radius-md)",
                background: lookupResult.matched ? "rgba(239, 68, 68, 0.08)" : "rgba(74, 222, 128, 0.08)",
                border: lookupResult.matched ? "1px solid rgba(239, 68, 68, 0.4)" : "1px solid rgba(74, 222, 128, 0.4)",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  {lookupResult.matched ? (
                    <AlertTriangle size={18} style={{ color: "#ef4444" }} />
                  ) : (
                    <CheckCircle2 size={18} style={{ color: "#4ade80" }} />
                  )}
                  <strong style={{ color: lookupResult.matched ? "#f87171" : "#4ade80", fontSize: "0.95rem" }}>
                    {lookupResult.matched ? "THREAT DETECTED (MATCH IN CTI)" : "CLEAN (NO MATCH IN CTI FEEDS)"}
                  </strong>
                </div>
                <span className="panel-badge">Lookup Time: {lookupResult.lookup_time_ms || "<0.01"} ms</span>
              </div>

              {lookupResult.matched && lookupResult.indicator && (
                <div style={{ marginTop: 12, display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, fontSize: "0.85rem" }}>
                  <div>
                    <span style={{ color: "var(--text-muted)" }}>Threat Actor:</span>{" "}
                    <strong style={{ color: "#f87171" }}>{lookupResult.indicator.threat_actor}</strong>
                  </div>
                  <div>
                    <span style={{ color: "var(--text-muted)" }}>Confidence:</span>{" "}
                    <strong>{lookupResult.indicator.confidence}%</strong>
                  </div>
                  <div>
                    <span style={{ color: "var(--text-muted)" }}>Type:</span>{" "}
                    <code>{lookupResult.indicator.indicator_type}</code>
                  </div>
                  <div>
                    <span style={{ color: "var(--text-muted)" }}>Match Rule:</span>{" "}
                    <code>{lookupResult.match_type || "Exact Value"}</code>
                  </div>
                  <div style={{ gridColumn: "span 2", marginTop: 4 }}>
                    <span style={{ color: "var(--text-muted)" }}>Description:</span>{" "}
                    <span>{lookupResult.indicator.description || "Active high-priority IOC"}</span>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right Column: STIX 2.1 JSON Bundle Importer */}
        <div className="panel">
          <div className="panel-header">
            <div>
              <h3 className="panel-title" style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <Upload size={16} style={{ color: "#c084fc" }} />
                STIX 2.1 &amp; MISP Ingestion Studio
              </h3>
              <p className="panel-subtitle">Ingest custom threat intelligence bundles directly into live memory</p>
            </div>
            <button className="btn-small-pulse" onClick={loadSampleStix}>
              <FileCode size={13} /> Load Sample
            </button>
          </div>

          <textarea
            className="aegis-textarea"
            rows={6}
            placeholder='Paste STIX 2.1 JSON bundle or MISP event payload here...'
            value={stixJsonInput}
            onChange={(e) => setStixJsonInput(e.target.value)}
            style={{ width: "100%", fontFamily: "var(--font-mono)", fontSize: "0.8rem", marginTop: 12 }}
          />

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 10 }}>
            <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
              Supported types: IPv4, IPv6, Domains, URLs, SHA256/MD5 Hashes
            </span>
            <button className="btn-primary" onClick={handleImportStix} disabled={!stixJsonInput.trim()}>
              <Upload size={14} /> Ingest STIX Bundle
            </button>
          </div>

          {importStatus && (
            <div
              style={{
                marginTop: 10,
                padding: "8px 12px",
                borderRadius: "var(--radius-sm)",
                fontSize: "0.8rem",
                background: importStatus.type === "success" ? "rgba(74, 222, 128, 0.1)" : "rgba(239, 68, 68, 0.1)",
                color: importStatus.type === "success" ? "#4ade80" : "#f87171",
                border: importStatus.type === "success" ? "1px solid rgba(74, 222, 128, 0.3)" : "1px solid rgba(239, 68, 68, 0.3)",
              }}
            >
              {importStatus.message}
            </div>
          )}
        </div>
      </div>

      {/* ═══ Active Threat Intel Indicators Directory Table ═══ */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h3 className="panel-title" style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <Layers size={16} style={{ color: "#38bdf8" }} />
              Active Indicators of Compromise (IOC Directory)
            </h3>
            <p className="panel-subtitle">Indexed threat artifacts actively monitored across packet &amp; syscall streams</p>
          </div>
          <span className="panel-count-badge">{filteredIndicators.length} Indicators Active</span>
        </div>

        {/* Filter & Search Bar */}
        <div style={{ display: "flex", gap: 12, margin: "14px 0", flexWrap: "wrap" }}>
          <div style={{ position: "relative", flex: 1, minWidth: 260 }}>
            <Search size={14} style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)", color: "var(--text-muted)" }} />
            <input
              type="text"
              className="aegis-input"
              placeholder="Search indicators, actors, descriptions..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{ width: "100%", paddingLeft: 34 }}
            />
          </div>

          <div style={{ display: "flex", gap: 6 }}>
            {["all", "ip", "domain", "sha256", "url"].map((type) => (
              <button
                key={type}
                type="button"
                className={`filter-btn ${filterType === type ? "active" : ""}`}
                onClick={() => setFilterType(type)}
                style={{
                  padding: "6px 14px",
                  borderRadius: "var(--radius-sm)",
                  fontSize: "0.8rem",
                  background: filterType === type ? "rgba(56, 189, 248, 0.2)" : "var(--bg-elevated)",
                  color: filterType === type ? "#38bdf8" : "var(--text-secondary)",
                  border: filterType === type ? "1px solid rgba(56, 189, 248, 0.5)" : "1px solid var(--border-default)",
                }}
              >
                {type.toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        {/* Table */}
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Type</th>
                <th>Indicator Value</th>
                <th>Threat Actor / Campaign</th>
                <th>Confidence</th>
                <th>Description</th>
                <th>Tags</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredIndicators.length > 0 ? (
                filteredIndicators.map((ind) => (
                  <tr key={ind.id}>
                    <td>
                      <span className={`cti-type-badge ${ind.indicator_type || "ioc"}`}>
                        {(ind.indicator_type || "IOC").toUpperCase()}
                      </span>
                    </td>
                    <td>
                      <code style={{ fontSize: "0.85rem", color: "#38bdf8" }}>{ind.value}</code>
                    </td>
                    <td>
                      <strong style={{ color: "#f87171" }}>{ind.threat_actor || "General Threat"}</strong>
                    </td>
                    <td>
                      <span
                        className="threat-pill"
                        style={{
                          background: ind.confidence >= 90 ? "rgba(239, 68, 68, 0.15)" : "rgba(245, 158, 11, 0.15)",
                          color: ind.confidence >= 90 ? "#ef4444" : "#f59e0b",
                          borderColor: ind.confidence >= 90 ? "rgba(239, 68, 68, 0.4)" : "rgba(245, 158, 11, 0.4)",
                        }}
                      >
                        {ind.confidence}%
                      </span>
                    </td>
                    <td style={{ maxWidth: 280, fontSize: "0.8rem", color: "var(--text-secondary)" }}>
                      {ind.description || "—"}
                    </td>
                    <td>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                        {(ind.tags || []).slice(0, 3).map((tag, idx) => (
                          <span key={idx} className="syscall-tag" style={{ fontSize: "0.7rem" }}>
                            {tag}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td>
                      <button
                        className="btn-inspect"
                        onClick={() => handleCopy(ind.value, ind.id)}
                        title="Copy Indicator Value"
                      >
                        {copiedId === ind.id ? <Check size={12} style={{ color: "#4ade80" }} /> : <Copy size={12} />}
                        {copiedId === ind.id ? "Copied" : "Copy"}
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} style={{ textAlign: "center", padding: "30px 0", color: "var(--text-muted)" }}>
                    No threat indicators found matching query "{searchQuery}".
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
