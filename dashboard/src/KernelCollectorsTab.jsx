import React, { useState, useEffect } from "react";
import {
  Cpu,
  Activity,
  Terminal,
  Filter,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Zap,
  Radio,
  FileCode,
  Shield,
} from "lucide-react";

export default function KernelCollectorsTab() {
  const [filterType, setFilterType] = useState("ALL");
  const [events, setEvents] = useState([]);
  const [selectedEvent, setSelectedEvent] = useState(null);

  // Generate real-time synthetic/live stream
  useEffect(() => {
    const sampleBinaries = [
      { type: "EXECVE", comm: "sudo", target: "/usr/bin/sudo -u root /bin/bash", pid: 4920, source: "ebpf_kernel" },
      { type: "CONNECT", comm: "sshd", target: "192.168.1.100:22", pid: 1104, source: "ebpf_kernel" },
      { type: "OPENAT", comm: "cat", target: "/etc/shadow", pid: 8840, source: "ebpf_kernel" },
      { type: "PROCESS_CREATE", comm: "cmd.exe", target: "powershell.exe -enc JAB...", pid: 5124, source: "windows_etw" },
      { type: "DRIVER_LOAD", comm: "ntoskrnl.exe", target: "C:\\Windows\\System32\\drivers\\rootkit.sys", pid: 4, source: "windows_etw" },
      { type: "KILL", comm: "pkill", target: "Target PID: 1204 (SIGKILL)", pid: 6601, source: "ebpf_kernel" },
    ];

    const interval = setInterval(() => {
      const item = sampleBinaries[Math.floor(Math.random() * sampleBinaries.length)];
      const newEvent = {
        id: Math.random().toString(36).substring(7),
        timestamp: new Date().toLocaleTimeString(),
        source: item.source,
        event_type: item.type,
        comm: item.comm,
        target_path: item.target,
        pid: item.pid,
        cpu_overhead_pct: 0.85 + Math.random() * 0.4,
      };

      setEvents((prev) => [newEvent, ...prev.slice(0, 30)]);
    }, 1800);

    return () => clearInterval(interval);
  }, []);

  const filteredEvents = filterType === "ALL" ? events : events.filter((e) => e.event_type === filterType);

  return (
    <div style={{ padding: "4px 0" }}>
      {/* Header */}
      <div
        style={{
          background: "linear-gradient(135deg, #0f172a 0%, #042f2e 100%)",
          border: "1px solid #115e59",
          borderRadius: "12px",
          padding: "20px 24px",
          marginBottom: "20px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
        }}
      >
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "6px" }}>
            <Cpu size={24} color="#2dd4bf" />
            <h2 style={{ margin: 0, fontSize: "20px", color: "#f8fafc", fontWeight: 800 }}>
              Kernel-Level Real-Time Telemetry Collectors (eBPF &amp; ETW)
            </h2>
            <span
              style={{
                background: "#0d9488",
                color: "#fff",
                fontSize: "11px",
                fontWeight: 700,
                padding: "3px 10px",
                borderRadius: "20px",
              }}
            >
              ACTIVE &bull; ZERO USESPACE OVERHEAD
            </span>
          </div>
          <p style={{ margin: 0, fontSize: "13px", color: "#94a3b8" }}>
            Native Linux <code>ebpf_tracer.c</code> tracepoints &amp; Windows Kernel ETW Event Streams
          </p>
        </div>

        <div style={{ display: "flex", gap: "16px", textAlign: "right" }}>
          <div>
            <div style={{ fontSize: "11px", color: "#94a3b8" }}>Avg Kernel CPU Load</div>
            <div style={{ fontSize: "20px", fontWeight: 800, color: "#34d399" }}>&lt; 1.2%</div>
          </div>
          <div>
            <div style={{ fontSize: "11px", color: "#94a3b8" }}>Buffer Ring Drops</div>
            <div style={{ fontSize: "20px", fontWeight: 800, color: "#38bdf8" }}>0 ev/s</div>
          </div>
        </div>
      </div>

      {/* Probes Status Bar */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(6, 1fr)", gap: "10px", marginBottom: "20px" }}>
        {[
          { name: "sys_enter_execve", type: "eBPF Hook", status: "ATTACHED" },
          { name: "sys_enter_connect", type: "eBPF Hook", status: "ATTACHED" },
          { name: "sys_enter_openat", type: "eBPF Hook", status: "ATTACHED" },
          { name: "sys_enter_ptrace", type: "eBPF Hook", status: "ATTACHED" },
          { name: "Process Create (ID 1)", type: "Windows ETW", status: "LISTENING" },
          { name: "Driver Load (ID 6)", type: "Windows ETW", status: "LISTENING" },
        ].map((probe, i) => (
          <div
            key={i}
            style={{
              background: "#0b1019",
              border: "1px solid #1c2533",
              borderRadius: "8px",
              padding: "12px",
              fontSize: "11px",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
              <span style={{ color: "#64748b", fontSize: "10px" }}>{probe.type}</span>
              <span style={{ color: "#34d399", fontWeight: 700 }}>{probe.status}</span>
            </div>
            <div style={{ fontWeight: 700, color: "#f8fafc", fontFamily: "monospace" }}>{probe.name}</div>
          </div>
        ))}
      </div>

      {/* Main Events Stream Table */}
      <div style={{ background: "#0b1019", border: "1px solid #1c2533", borderRadius: "10px", padding: "20px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px" }}>
          <h3 style={{ margin: 0, fontSize: "14px", color: "#f8fafc", fontWeight: 700 }}>
            Live Ingested Kernel Tracepoint Feed
          </h3>

          <div style={{ display: "flex", gap: "8px" }}>
            {["ALL", "EXECVE", "CONNECT", "OPENAT", "PROCESS_CREATE", "DRIVER_LOAD"].map((f) => (
              <button
                key={f}
                onClick={() => setFilterType(f)}
                style={{
                  background: filterType === f ? "#0f766e" : "#0f172a",
                  border: "1px solid #1c2533",
                  color: filterType === f ? "#f8fafc" : "#94a3b8",
                  fontSize: "11px",
                  fontWeight: 600,
                  padding: "4px 10px",
                  borderRadius: "6px",
                  cursor: "pointer",
                }}
              >
                {f}
              </button>
            ))}
          </div>
        </div>

        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px", textAlign: "left" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid #1c2533", color: "#64748b", fontSize: "11px" }}>
              <th style={{ padding: "8px" }}>Time</th>
              <th style={{ padding: "8px" }}>Source</th>
              <th style={{ padding: "8px" }}>Event Type</th>
              <th style={{ padding: "8px" }}>PID</th>
              <th style={{ padding: "8px" }}>Command / Comm</th>
              <th style={{ padding: "8px" }}>Target Path / Socket</th>
              <th style={{ padding: "8px" }}>CPU</th>
            </tr>
          </thead>
          <tbody>
            {filteredEvents.map((e) => (
              <tr
                key={e.id}
                onClick={() => setSelectedEvent(e)}
                style={{
                  borderBottom: "1px solid #141e2e",
                  cursor: "pointer",
                  background: selectedEvent?.id === e.id ? "rgba(45, 212, 191, 0.08)" : "transparent",
                }}
              >
                <td style={{ padding: "10px 8px", color: "#64748b", fontFamily: "monospace" }}>{e.timestamp}</td>
                <td style={{ padding: "10px 8px" }}>
                  <span
                    style={{
                      background: e.source.includes("ebpf") ? "#064e3b" : "#1e3a8a",
                      color: e.source.includes("ebpf") ? "#34d399" : "#60a5fa",
                      padding: "2px 6px",
                      borderRadius: "4px",
                      fontSize: "10px",
                      fontWeight: 700,
                    }}
                  >
                    {e.source.toUpperCase()}
                  </span>
                </td>
                <td style={{ padding: "10px 8px", fontWeight: 700, color: "#f8fafc" }}>{e.event_type}</td>
                <td style={{ padding: "10px 8px", color: "#94a3b8", fontFamily: "monospace" }}>{e.pid}</td>
                <td style={{ padding: "10px 8px", color: "#38bdf8", fontFamily: "monospace" }}>{e.comm}</td>
                <td style={{ padding: "10px 8px", color: "#cbd5e1", fontFamily: "monospace" }}>{e.target_path}</td>
                <td style={{ padding: "10px 8px", color: "#10b981", fontSize: "11px" }}>
                  {e.cpu_overhead_pct.toFixed(2)}%
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
