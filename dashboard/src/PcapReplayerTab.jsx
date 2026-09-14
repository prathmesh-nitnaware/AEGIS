import { useState, useEffect, useRef } from "react";
import {
  Radio,
  Play,
  Pause,
  RotateCcw,
  UploadCloud,
  ShieldAlert,
  Activity,
  Layers,
  Zap,
  Gauge,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Search,
  BrainCircuit,
  FileCode,
  ArrowRight,
} from "lucide-react";

export default function PcapReplayerTab({ apiBase = "http://127.0.0.1:8000", onOpenXAI }) {
  const [samples, setSamples] = useState([]);
  const [selectedFile, setSelectedFile] = useState("syn_flood_ddos.pcap");
  const [speed, setSpeed] = useState(2.0);
  const [playbackStatus, setPlaybackStatus] = useState("idle"); // idle | replaying | paused | completed | error
  const [progress, setProgress] = useState({ total_packets: 0, processed_packets: 0, percent: 0, elapsed_seconds: 0 });
  const [metrics, setMetrics] = useState({
    total_packets: 0,
    total_bytes: 0,
    total_flows: 0,
    threat_count: 0,
    max_threat_score: 0.0,
    current_rate_pps: 0.0,
    protocol_breakdown: { TCP: 0, UDP: 0, ICMP: 0, Other: 0 },
    threat_breakdown: { BENIGN: 0, "DDoS / SYN Flood": 0, "PortScan Recon": 0, "SSH BruteForce": 0 },
  });
  const [recentPackets, setRecentPackets] = useState([]);
  const [recentFlows, setRecentFlows] = useState([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [uploading, setUploading] = useState(false);
  const [uploadMsg, setUploadMsg] = useState(null);

  const fileInputRef = useRef(null);
  const pollIntervalRef = useRef(null);

  // 1. Fetch available PCAP samples on load
  const fetchSamples = async () => {
    try {
      const res = await fetch(`${apiBase}/api/pcap/samples`);
      if (res.ok) {
        const data = await res.json();
        setSamples(data);
        if (data.length > 0 && !selectedFile) {
          setSelectedFile(data[0].filename);
        }
      }
    } catch (err) {
      console.error("Failed to fetch PCAP samples:", err);
    }
  };

  useEffect(() => {
    fetchSamples();
  }, [apiBase]);

  // 2. Status Poller
  const pollStatus = async () => {
    try {
      const res = await fetch(`${apiBase}/api/pcap/status`);
      if (res.ok) {
        const data = await res.json();
        setPlaybackStatus(data.status);
        setProgress(data.progress || {});
        if (data.metrics) setMetrics(data.metrics);
        if (data.recent_packets) setRecentPackets(data.recent_packets);
        if (data.recent_flows) setRecentFlows(data.recent_flows);
      }
    } catch (err) {
      console.error("Error polling PCAP status:", err);
    }
  };

  useEffect(() => {
    pollStatus();
    pollIntervalRef.current = setInterval(pollStatus, 400);
    return () => {
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    };
  }, [apiBase]);

  // 3. Playback Controls
  const handleStartReplay = async () => {
    if (!selectedFile) return;
    try {
      const res = await fetch(`${apiBase}/api/pcap/replay/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filename: selectedFile, speed: speed }),
      });
      if (res.ok) {
        setPlaybackStatus("replaying");
        pollStatus();
      }
    } catch (err) {
      console.error("Failed to start replay:", err);
    }
  };

  const handlePauseReplay = async () => {
    try {
      await fetch(`${apiBase}/api/pcap/replay/pause`, { method: "POST" });
      setPlaybackStatus("paused");
    } catch (err) {
      console.error("Failed to pause replay:", err);
    }
  };

  const handleResumeReplay = async () => {
    try {
      await fetch(`${apiBase}/api/pcap/replay/resume`, { method: "POST" });
      setPlaybackStatus("replaying");
    } catch (err) {
      console.error("Failed to resume replay:", err);
    }
  };

  const handleStopReplay = async () => {
    try {
      await fetch(`${apiBase}/api/pcap/replay/stop`, { method: "POST" });
      setPlaybackStatus("idle");
      pollStatus();
    } catch (err) {
      console.error("Failed to stop replay:", err);
    }
  };

  // 4. File Upload
  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const formData = new FormData();
    formData.append("file", file);

    setUploading(true);
    setUploadMsg(null);

    try {
      const res = await fetch(`${apiBase}/api/pcap/upload`, {
        method: "POST",
        body: formData,
      });
      const data = await res.json();
      if (res.ok) {
        setUploadMsg({ type: "success", text: `Loaded ${data.filename} (${data.packet_count} packets)` });
        await fetchSamples();
        setSelectedFile(data.filename);
      } else {
        setUploadMsg({ type: "error", text: data.detail || "Upload failed" });
      }
    } catch (err) {
      setUploadMsg({ type: "error", text: `Upload error: ${err.message}` });
    } finally {
      setUploading(false);
      setTimeout(() => setUploadMsg(null), 5000);
    }
  };

  // 5. Filtering
  const filteredPackets = recentPackets.filter((p) => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      p.src_ip.toLowerCase().includes(term) ||
      p.dst_ip.toLowerCase().includes(term) ||
      p.protocol.toLowerCase().includes(term) ||
      p.flags.toLowerCase().includes(term) ||
      p.info.toLowerCase().includes(term) ||
      String(p.src_port).includes(term) ||
      String(p.dst_port).includes(term)
    );
  });

  const getThreatBadge = (score, label) => {
    if (score >= 0.8) {
      return (
        <span style={{ background: "rgba(239, 68, 68, 0.2)", color: "#f87171", border: "1px solid rgba(239, 68, 68, 0.4)", padding: "2px 8px", borderRadius: 4, fontWeight: "700", fontSize: "0.75rem" }}>
          🚨 {label || "CRITICAL"} ({(score * 100).toFixed(1)}%)
        </span>
      );
    }
    if (score >= 0.5) {
      return (
        <span style={{ background: "rgba(245, 158, 11, 0.2)", color: "#fbbf24", border: "1px solid rgba(245, 158, 11, 0.4)", padding: "2px 8px", borderRadius: 4, fontWeight: "700", fontSize: "0.75rem" }}>
          ⚠️ {label || "SUSPICIOUS"} ({(score * 100).toFixed(1)}%)
        </span>
      );
    }
    return (
      <span style={{ background: "rgba(16, 185, 129, 0.2)", color: "#34d399", border: "1px solid rgba(16, 185, 129, 0.4)", padding: "2px 8px", borderRadius: 4, fontWeight: "600", fontSize: "0.75rem" }}>
        ✓ {label || "BENIGN"} ({(score * 100).toFixed(1)}%)
      </span>
    );
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "20px", color: "#e2e8f0" }}>
      {/* ═══ Header Card ═══ */}
      <div
        style={{
          background: "linear-gradient(135deg, rgba(15, 23, 42, 0.95) 0%, rgba(30, 41, 59, 0.9) 100%)",
          border: "1px solid rgba(6, 182, 212, 0.3)",
          borderRadius: "12px",
          padding: "24px",
          position: "relative",
          overflow: "hidden",
          boxShadow: "0 10px 30px rgba(0, 0, 0, 0.4)",
        }}
      >
        <div
          style={{
            position: "absolute",
            top: -40,
            right: -40,
            width: "160px",
            height: "160px",
            background: "radial-gradient(circle, rgba(6, 182, 212, 0.15) 0%, transparent 70%)",
            borderRadius: "50%",
            pointerEvents: "none",
          }}
        />

        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "16px" }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "8px" }}>
              <div
                style={{
                  background: "linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%)",
                  padding: "8px",
                  borderRadius: "8px",
                  color: "#fff",
                  display: "flex",
                }}
              >
                <Radio size={22} />
              </div>
              <h2 style={{ margin: 0, fontSize: "1.4rem", fontWeight: "800", color: "#f8fafc", letterSpacing: "-0.02em" }}>
                Live PCAP Network Packet Capture &amp; Threat Flow Replayer
              </h2>
            </div>
            <p style={{ margin: 0, fontSize: "0.88rem", color: "#94a3b8", maxWidth: "800px", lineHeight: "1.4" }}>
              Stream offline or live <code style={{ color: "#38bdf8", background: "rgba(56, 189, 248, 0.1)", padding: "2px 6px", borderRadius: 4 }}>.pcap</code> captures through Scapy, extract 78 CICIDS bidirectional flow statistics in real-time, and run live machine learning threat inference with explainability drilldown.
            </p>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <button
              onClick={() => fileInputRef.current?.click()}
              disabled={uploading}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "6px",
                background: "rgba(30, 41, 59, 0.8)",
                border: "1px solid rgba(148, 163, 184, 0.3)",
                color: "#cbd5e1",
                padding: "8px 14px",
                borderRadius: "6px",
                fontSize: "0.85rem",
                fontWeight: "600",
                cursor: "pointer",
              }}
            >
              <UploadCloud size={16} color="#38bdf8" />
              {uploading ? "Ingesting..." : "Upload .PCAP"}
            </button>
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileUpload}
              accept=".pcap,.pcapng"
              style={{ display: "none" }}
            />
          </div>
        </div>

        {uploadMsg && (
          <div
            style={{
              marginTop: "12px",
              padding: "8px 14px",
              borderRadius: "6px",
              fontSize: "0.82rem",
              fontWeight: "600",
              background: uploadMsg.type === "success" ? "rgba(16, 185, 129, 0.2)" : "rgba(239, 68, 68, 0.2)",
              color: uploadMsg.type === "success" ? "#34d399" : "#f87171",
              border: `1px solid ${uploadMsg.type === "success" ? "rgba(16, 185, 129, 0.4)" : "rgba(239, 68, 68, 0.4)"}`,
            }}
          >
            {uploadMsg.text}
          </div>
        )}
      </div>

      {/* ═══ Metrics Ribbon (5 Stat Cards) ═══ */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "16px" }}>
        {/* Card 1: Packets */}
        <div style={{ background: "rgba(15, 23, 42, 0.8)", border: "1px solid rgba(51, 65, 85, 0.8)", borderRadius: "10px", padding: "16px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", color: "#94a3b8", fontSize: "0.8rem", fontWeight: "600" }}>
            <span>PACKETS REPLAYED</span>
            <Layers size={16} color="#38bdf8" />
          </div>
          <div style={{ fontSize: "1.6rem", fontWeight: "800", color: "#f8fafc", marginTop: "6px" }}>
            {progress.processed_packets || 0} <span style={{ fontSize: "0.9rem", color: "#64748b", fontWeight: "400" }}>/ {progress.total_packets || 0}</span>
          </div>
          <div style={{ width: "100%", height: "4px", background: "rgba(51, 65, 85, 0.5)", borderRadius: "2px", marginTop: "10px", overflow: "hidden" }}>
            <div style={{ width: `${progress.percent || 0}%`, height: "100%", background: "linear-gradient(90deg, #06b6d4, #3b82f6)", transition: "width 0.3s ease" }} />
          </div>
        </div>

        {/* Card 2: Flows */}
        <div style={{ background: "rgba(15, 23, 42, 0.8)", border: "1px solid rgba(51, 65, 85, 0.8)", borderRadius: "10px", padding: "16px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", color: "#94a3b8", fontSize: "0.8rem", fontWeight: "600" }}>
            <span>CICIDS FLOWS</span>
            <Activity size={16} color="#a855f7" />
          </div>
          <div style={{ fontSize: "1.6rem", fontWeight: "800", color: "#c084fc", marginTop: "6px" }}>
            {metrics.total_flows}
          </div>
          <div style={{ fontSize: "0.75rem", color: "#94a3b8", marginTop: "4px" }}>
            78-Feature Vectors Extracted
          </div>
        </div>

        {/* Card 3: Threats Flagged */}
        <div style={{ background: "rgba(15, 23, 42, 0.8)", border: "1px solid rgba(51, 65, 85, 0.8)", borderRadius: "10px", padding: "16px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", color: "#94a3b8", fontSize: "0.8rem", fontWeight: "600" }}>
            <span>THREATS FLAGGED</span>
            <ShieldAlert size={16} color="#ef4444" />
          </div>
          <div style={{ fontSize: "1.6rem", fontWeight: "800", color: metrics.threat_count > 0 ? "#f87171" : "#34d399", marginTop: "6px" }}>
            {metrics.threat_count}
          </div>
          <div style={{ fontSize: "0.75rem", color: metrics.threat_count > 0 ? "#fca5a5" : "#6ee7b7", marginTop: "4px" }}>
            {metrics.threat_count > 0 ? "Malicious signatures detected" : "All traffic normal"}
          </div>
        </div>

        {/* Card 4: Peak Threat Score */}
        <div style={{ background: "rgba(15, 23, 42, 0.8)", border: "1px solid rgba(51, 65, 85, 0.8)", borderRadius: "10px", padding: "16px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", color: "#94a3b8", fontSize: "0.8rem", fontWeight: "600" }}>
            <span>PEAK THREAT SCORE</span>
            <Flame size={16} color="#f59e0b" />
          </div>
          <div style={{ fontSize: "1.6rem", fontWeight: "800", color: metrics.max_threat_score >= 0.7 ? "#ef4444" : metrics.max_threat_score >= 0.4 ? "#fbbf24" : "#34d399", marginTop: "6px" }}>
            {(metrics.max_threat_score * 100).toFixed(1)}%
          </div>
          <div style={{ fontSize: "0.75rem", color: "#94a3b8", marginTop: "4px" }}>
            {metrics.max_threat_score >= 0.7 ? "CRITICAL RISK" : metrics.max_threat_score >= 0.4 ? "SUSPICIOUS" : "LOW RISK"}
          </div>
        </div>

        {/* Card 5: Throughput Rate */}
        <div style={{ background: "rgba(15, 23, 42, 0.8)", border: "1px solid rgba(51, 65, 85, 0.8)", borderRadius: "10px", padding: "16px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", color: "#94a3b8", fontSize: "0.8rem", fontWeight: "600" }}>
            <span>THROUGHPUT</span>
            <Gauge size={16} color="#10b981" />
          </div>
          <div style={{ fontSize: "1.6rem", fontWeight: "800", color: "#34d399", marginTop: "6px" }}>
            {metrics.current_rate_pps} <span style={{ fontSize: "0.85rem", color: "#64748b", fontWeight: "400" }}>pkts/s</span>
          </div>
          <div style={{ fontSize: "0.75rem", color: "#94a3b8", marginTop: "4px" }}>
            Elapsed: {progress.elapsed_seconds || 0}s
          </div>
        </div>
      </div>

      {/* ═══ Control Deck & Scenario Picker ═══ */}
      <div
        style={{
          background: "rgba(15, 23, 42, 0.85)",
          border: "1px solid rgba(51, 65, 85, 0.8)",
          borderRadius: "12px",
          padding: "20px",
          display: "flex",
          flexDirection: "column",
          gap: "16px",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "12px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Zap size={18} color="#06b6d4" />
            <span style={{ fontWeight: "700", fontSize: "0.95rem", color: "#f8fafc" }}>Capture Playback &amp; Attack Scenarios</span>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <div style={{ display: "flex", alignItems: "center", background: "rgba(30, 41, 59, 0.8)", padding: "4px 8px", borderRadius: "6px", border: "1px solid rgba(51, 65, 85, 0.8)", gap: "6px" }}>
              <span style={{ fontSize: "0.75rem", color: "#94a3b8", fontWeight: "600" }}>SPEED:</span>
              {[0.5, 1.0, 2.0, 5.0, 10.0].map((s) => (
                <button
                  key={s}
                  onClick={() => setSpeed(s)}
                  style={{
                    background: speed === s ? "#06b6d4" : "transparent",
                    color: speed === s ? "#0f172a" : "#94a3b8",
                    border: "none",
                    borderRadius: "4px",
                    padding: "2px 6px",
                    fontSize: "0.75rem",
                    fontWeight: "700",
                    cursor: "pointer",
                  }}
                >
                  {s}x
                </button>
              ))}
            </div>

            {/* Play/Pause/Stop Buttons */}
            {playbackStatus !== "replaying" ? (
              <button
                onClick={handleStartReplay}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  background: "linear-gradient(135deg, #10b981 0%, #059669 100%)",
                  border: "none",
                  color: "#ffffff",
                  padding: "8px 16px",
                  borderRadius: "6px",
                  fontWeight: "700",
                  fontSize: "0.85rem",
                  cursor: "pointer",
                  boxShadow: "0 4px 12px rgba(16, 185, 129, 0.3)",
                }}
              >
                <Play size={15} fill="#fff" />
                Replay Stream
              </button>
            ) : (
              <button
                onClick={handlePauseReplay}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  background: "linear-gradient(135deg, #f59e0b 0%, #d97706 100%)",
                  border: "none",
                  color: "#0f172a",
                  padding: "8px 16px",
                  borderRadius: "6px",
                  fontWeight: "700",
                  fontSize: "0.85rem",
                  cursor: "pointer",
                }}
              >
                <Pause size={15} />
                Pause
              </button>
            )}

            {playbackStatus === "paused" && (
              <button
                onClick={handleResumeReplay}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  background: "linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)",
                  border: "none",
                  color: "#ffffff",
                  padding: "8px 16px",
                  borderRadius: "6px",
                  fontWeight: "700",
                  fontSize: "0.85rem",
                  cursor: "pointer",
                }}
              >
                <Play size={15} fill="#fff" />
                Resume
              </button>
            )}

            <button
              onClick={handleStopReplay}
              disabled={playbackStatus === "idle"}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "6px",
                background: "rgba(239, 68, 68, 0.15)",
                border: "1px solid rgba(239, 68, 68, 0.4)",
                color: "#f87171",
                padding: "8px 14px",
                borderRadius: "6px",
                fontWeight: "600",
                fontSize: "0.85rem",
                cursor: playbackStatus === "idle" ? "not-allowed" : "pointer",
                opacity: playbackStatus === "idle" ? 0.5 : 1,
              }}
            >
              <RotateCcw size={15} />
              Reset
            </button>
          </div>
        </div>

        {/* Scenario Grid */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: "12px" }}>
          {samples.map((s) => {
            const isSelected = selectedFile === s.filename;
            return (
              <div
                key={s.filename}
                onClick={() => setSelectedFile(s.filename)}
                style={{
                  background: isSelected ? "rgba(6, 182, 212, 0.12)" : "rgba(30, 41, 59, 0.6)",
                  border: `1px solid ${isSelected ? "rgba(6, 182, 212, 0.6)" : "rgba(51, 65, 85, 0.6)"}`,
                  borderRadius: "8px",
                  padding: "14px",
                  cursor: "pointer",
                  transition: "all 0.2s ease",
                  display: "flex",
                  flexDirection: "column",
                  gap: "6px",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                  <span style={{ fontWeight: "700", fontSize: "0.88rem", color: isSelected ? "#38bdf8" : "#f1f5f9" }}>
                    {s.title}
                  </span>
                  <span style={{ fontSize: "0.7rem", padding: "1px 6px", borderRadius: 4, background: isSelected ? "rgba(6, 182, 212, 0.3)" : "rgba(51, 65, 85, 0.6)", color: isSelected ? "#e0f2fe" : "#94a3b8" }}>
                    {s.packet_count} pkts
                  </span>
                </div>
                <div style={{ fontSize: "0.75rem", color: "#94a3b8", lineHeight: "1.3" }}>
                  {s.description}
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "4px", fontSize: "0.72rem", color: "#64748b" }}>
                  <span>MITRE: {s.mitre}</span>
                  <span style={{ color: "#38bdf8", fontWeight: "600" }}>{s.category}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* ═══ Split Workspaces: Packet Stream + Extracted CICIDS Flows ═══ */}
      <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: "20px" }}>
        {/* Left: Real-Time Packet Capture Stream Table */}
        <div
          style={{
            background: "rgba(15, 23, 42, 0.9)",
            border: "1px solid rgba(51, 65, 85, 0.8)",
            borderRadius: "12px",
            padding: "18px",
            display: "flex",
            flexDirection: "column",
            gap: "12px",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <FileCode size={18} color="#38bdf8" />
              <span style={{ fontWeight: "700", fontSize: "0.95rem", color: "#f8fafc" }}>Real-Time Packet Stream</span>
              <span style={{ fontSize: "0.75rem", color: "#94a3b8" }}>({filteredPackets.length} captured)</span>
            </div>

            <div style={{ position: "relative", width: "200px" }}>
              <Search size={14} style={{ position: "absolute", left: "8px", top: "8px", color: "#64748b" }} />
              <input
                type="text"
                placeholder="Filter IP, port, flags..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                style={{
                  width: "100%",
                  background: "rgba(30, 41, 59, 0.8)",
                  border: "1px solid rgba(51, 65, 85, 0.8)",
                  borderRadius: "6px",
                  padding: "6px 8px 6px 28px",
                  fontSize: "0.75rem",
                  color: "#f8fafc",
                  outline: "none",
                }}
              />
            </div>
          </div>

          {/* Packet Table */}
          <div style={{ maxHeight: "420px", overflowY: "auto", border: "1px solid rgba(51, 65, 85, 0.6)", borderRadius: "8px" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.75rem", fontFamily: "monospace" }}>
              <thead>
                <tr style={{ background: "rgba(30, 41, 59, 0.9)", color: "#94a3b8", textAlign: "left", borderBottom: "1px solid rgba(51, 65, 85, 0.8)" }}>
                  <th style={{ padding: "8px" }}>#</th>
                  <th style={{ padding: "8px" }}>Time</th>
                  <th style={{ padding: "8px" }}>Source &rarr; Dest</th>
                  <th style={{ padding: "8px" }}>Proto</th>
                  <th style={{ padding: "8px" }}>Len</th>
                  <th style={{ padding: "8px" }}>Flags</th>
                  <th style={{ padding: "8px" }}>Summary Info</th>
                </tr>
              </thead>
              <tbody>
                {filteredPackets.length === 0 ? (
                  <tr>
                    <td colSpan={7} style={{ padding: "30px", textAlign: "center", color: "#64748b" }}>
                      {playbackStatus === "idle" ? "Ready for replay. Click ▶ Start Replay to stream packets." : "No matching packets in stream buffer."}
                    </td>
                  </tr>
                ) : (
                  filteredPackets.map((pkt) => {
                    const isTcpSyn = pkt.flags.includes("SYN") && !pkt.flags.includes("ACK");
                    const isSsh = pkt.dst_port === 22 || pkt.src_port === 22;
                    return (
                      <tr
                        key={pkt.id}
                        style={{
                          borderBottom: "1px solid rgba(51, 65, 85, 0.3)",
                          background: isTcpSyn ? "rgba(239, 68, 68, 0.08)" : isSsh ? "rgba(245, 158, 11, 0.05)" : "transparent",
                          transition: "background 0.15s ease",
                        }}
                      >
                        <td style={{ padding: "6px 8px", color: "#64748b" }}>{pkt.id}</td>
                        <td style={{ padding: "6px 8px", color: "#94a3b8" }}>{pkt.timestamp}</td>
                        <td style={{ padding: "6px 8px", color: "#38bdf8" }}>
                          {pkt.src_ip}:{pkt.src_port} &rarr; {pkt.dst_ip}:{pkt.dst_port}
                        </td>
                        <td style={{ padding: "6px 8px" }}>
                          <span style={{ padding: "1px 5px", borderRadius: 3, background: pkt.protocol === "TCP" ? "rgba(6, 182, 212, 0.2)" : "rgba(168, 85, 247, 0.2)", color: pkt.protocol === "TCP" ? "#38bdf8" : "#c084fc", fontWeight: "700" }}>
                            {pkt.protocol}
                          </span>
                        </td>
                        <td style={{ padding: "6px 8px", color: "#cbd5e1" }}>{pkt.length}</td>
                        <td style={{ padding: "6px 8px", color: isTcpSyn ? "#f87171" : "#94a3b8", fontWeight: isTcpSyn ? "700" : "normal" }}>
                          {pkt.flags || "-"}
                        </td>
                        <td style={{ padding: "6px 8px", color: "#e2e8f0", maxWidth: "200px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={pkt.info}>
                          {pkt.info}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right: Extracted CICIDS Threat Flows & XAI Drilldown */}
        <div
          style={{
            background: "rgba(15, 23, 42, 0.9)",
            border: "1px solid rgba(51, 65, 85, 0.8)",
            borderRadius: "12px",
            padding: "18px",
            display: "flex",
            flexDirection: "column",
            gap: "12px",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <ShieldAlert size={18} color="#f87171" />
              <span style={{ fontWeight: "700", fontSize: "0.95rem", color: "#f8fafc" }}>Extracted Threat Flows (CICIDS)</span>
            </div>
            <span style={{ fontSize: "0.75rem", color: "#94a3b8" }}>{recentFlows.length} active sessions</span>
          </div>

          {/* Flow Cards */}
          <div style={{ maxHeight: "420px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "10px" }}>
            {recentFlows.length === 0 ? (
              <div style={{ padding: "40px", textAlign: "center", color: "#64748b", border: "1px dashed rgba(51, 65, 85, 0.6)", borderRadius: "8px" }}>
                No flows extracted yet. Packet conversations will aggregate here dynamically.
              </div>
            ) : (
              recentFlows.map((flow) => (
                <div
                  key={flow.flow_id}
                  style={{
                    background: flow.is_threat ? "rgba(239, 68, 68, 0.08)" : "rgba(30, 41, 59, 0.6)",
                    border: `1px solid ${flow.is_threat ? "rgba(239, 68, 68, 0.4)" : "rgba(51, 65, 85, 0.6)"}`,
                    borderRadius: "8px",
                    padding: "12px",
                    display: "flex",
                    flexDirection: "column",
                    gap: "8px",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                      <span style={{ fontWeight: "700", fontSize: "0.85rem", color: "#f8fafc" }}>
                        {flow.flow_id} (Port {flow.dst_port} · {flow.protocol})
                      </span>
                    </div>
                    {getThreatBadge(flow.threat_score, flow.threat_label)}
                  </div>

                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "8px", fontSize: "0.75rem", color: "#94a3b8" }}>
                    <div>Pkts: <strong style={{ color: "#e2e8f0" }}>{flow.total_packets}</strong> ({flow.fwd_packets} fwd / {flow.bwd_packets} bwd)</div>
                    <div>Bytes: <strong style={{ color: "#e2e8f0" }}>{flow.total_bytes} B</strong></div>
                    <div>Duration: <strong style={{ color: "#e2e8f0" }}>{flow.duration_ms} ms</strong></div>
                  </div>

                  {/* Top Features Pill Ribbon */}
                  {flow.top_features && flow.top_features.length > 0 && (
                    <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", marginTop: "2px" }}>
                      {flow.top_features.slice(0, 3).map((f, i) => (
                        <span key={i} style={{ fontSize: "0.7rem", background: "rgba(51, 65, 85, 0.6)", padding: "2px 6px", borderRadius: 4, color: "#cbd5e1" }}>
                          {f.name}: <strong style={{ color: "#38bdf8" }}>{f.value}</strong>
                        </span>
                      ))}
                    </div>
                  )}

                  {/* Explain in XAI button */}
                  <div style={{ display: "flex", justifyContent: "flex-end", marginTop: "4px" }}>
                    <button
                      onClick={() => {
                        if (onOpenXAI) {
                          onOpenXAI({
                            model: "cicids",
                            threatScore: flow.threat_score,
                            eventData: {
                              ...flow.raw_features,
                              flow_id: flow.flow_id,
                              threat_label: flow.threat_label,
                              dst_port: flow.dst_port,
                              duration_ms: flow.duration_ms,
                            },
                          });
                        }
                      }}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "6px",
                        background: "linear-gradient(135deg, rgba(168, 85, 247, 0.2) 0%, rgba(139, 92, 246, 0.3) 100%)",
                        border: "1px solid rgba(168, 85, 247, 0.5)",
                        color: "#c084fc",
                        padding: "5px 10px",
                        borderRadius: "5px",
                        fontSize: "0.75rem",
                        fontWeight: "700",
                        cursor: "pointer",
                      }}
                    >
                      <BrainCircuit size={13} />
                      Explain Flow (XAI Attribution)
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
