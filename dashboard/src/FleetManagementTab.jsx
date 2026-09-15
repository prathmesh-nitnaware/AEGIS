import React, { useState, useEffect, useCallback } from "react";
import {
  Server,
  Sliders,
  Send,
  ShieldCheck,
  KeyRound,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  FileArchive,
  Lock,
} from "lucide-react";

export default function FleetManagementTab() {
  const [fleetAgents, setFleetAgents] = useState([]);
  const [selectedAgent, setSelectedAgent] = useState("vm1-linux");
  const [configParams, setConfigParams] = useState({
    polling_interval_sec: 2.0,
    confidence_threshold: 0.70,
    threat_score_suppression: 0.30,
    voting_weights: {
      ember: 1.2,
      cicids: 1.1,
      linux_ids: 1.0,
      windows_adv: 1.2,
      zero_day: 1.3,
      hdfs: 0.8,
    },
  });
  const [toast, setToast] = useState(null);
  const [pkgVerifyPath, setPkgVerifyPath] = useState("dist/agent_packages/aegis-agent-linux-x86_64.tar.gz");
  const [verifyResult, setVerifyResult] = useState(null);

  const fetchInventory = useCallback(async () => {
    try {
      const res = await fetch("http://127.0.0.1:8000/api/fleet/inventory");
      if (res.ok) {
        const data = await res.json();
        setFleetAgents(data.agents || []);
      }
    } catch (e) {
      console.error(e);
    }
  }, []);

  useEffect(() => {
    fetchInventory();
  }, [fetchInventory]);

  const handlePushConfig = async () => {
    try {
      const res = await fetch("http://127.0.0.1:8000/api/fleet/config/push", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          agent_id: selectedAgent,
          config: configParams,
        }),
      });
      if (res.ok) {
        setToast(`Hot-Configuration successfully dispatched to ${selectedAgent}!`);
      } else {
        setToast("Failed to push configuration.");
      }
    } catch (e) {
      setToast("Error: " + e.message);
    }
  };

  const handleVerifyPackage = async () => {
    try {
      const res = await fetch("http://127.0.0.1:8000/api/fleet/packages/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          package_path: pkgVerifyPath,
          signature_b64: "dGVzdF9zaWduYXR1cmVfYnl0ZXNfZm9yX2FwaV92ZXJpZmljYXRpb24=",
        }),
      });
      const data = await res.json();
      setVerifyResult(data);
    } catch (e) {
      setVerifyResult({ valid: false, reason: e.message });
    }
  };

  return (
    <div style={{ padding: "4px 0" }}>
      {/* Toast */}
      {toast && (
        <div
          style={{
            background: "#1e293b",
            border: "1px solid #10b981",
            color: "#f8fafc",
            padding: "10px 16px",
            borderRadius: "8px",
            marginBottom: "16px",
            display: "flex",
            justifyContent: "space-between",
          }}
        >
          <span>{toast}</span>
          <button onClick={() => setToast(null)} style={{ background: "transparent", border: "none", color: "#94a3b8" }}>
            ✕
          </button>
        </div>
      )}

      {/* Header */}
      <div
        style={{
          background: "linear-gradient(135deg, #0f172a 0%, #1e293b 100%)",
          border: "1px solid #334155",
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
            <Server size={24} color="#38bdf8" />
            <h2 style={{ margin: 0, fontSize: "20px", color: "#f8fafc", fontWeight: 800 }}>
              Centralized Fleet Management &amp; Hot-Update Coordinator
            </h2>
          </div>
          <p style={{ margin: 0, fontSize: "13px", color: "#94a3b8" }}>
            Real-time parameter distribution &amp; Ed25519 cryptographic package signature validation
          </p>
        </div>
        <button
          onClick={fetchInventory}
          style={{
            background: "#1e293b",
            border: "1px solid #334155",
            color: "#f8fafc",
            padding: "8px 14px",
            borderRadius: "6px",
            display: "flex",
            alignItems: "center",
            gap: "6px",
            fontSize: "12px",
          }}
        >
          <RefreshCw size={14} /> Refresh Fleet
        </button>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px" }}>
        {/* Left: Dynamic Parameter Synchronizer */}
        <div style={{ background: "#0b1019", border: "1px solid #1c2533", borderRadius: "10px", padding: "20px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
            <h3 style={{ margin: 0, fontSize: "14px", color: "#f8fafc", fontWeight: 700, display: "flex", alignItems: "center", gap: "8px" }}>
              <Sliders size={16} color="#818cf8" /> Live Configuration Push
            </h3>
            <select
              value={selectedAgent}
              onChange={(e) => setSelectedAgent(e.target.value)}
              style={{
                background: "#0f172a",
                border: "1px solid #334155",
                color: "#f8fafc",
                borderRadius: "6px",
                padding: "4px 8px",
                fontSize: "12px",
              }}
            >
              <option value="vm1-linux">vm1-linux</option>
              <option value="vm2-windows">vm2-windows</option>
              <option value="vm3-server">vm3-server</option>
              <option value="*">All Nodes (Broadcast)</option>
            </select>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: "12px", marginBottom: "4px" }}>
                <span style={{ color: "#94a3b8" }}>Confidence Threshold</span>
                <span style={{ color: "#38bdf8", fontWeight: 700 }}>{configParams.confidence_threshold}</span>
              </div>
              <input
                type="range"
                min="0.5"
                max="0.99"
                step="0.01"
                value={configParams.confidence_threshold}
                onChange={(e) => setConfigParams({ ...configParams, confidence_threshold: parseFloat(e.target.value) })}
                style={{ width: "100%", accentColor: "#38bdf8" }}
              />
            </div>

            <div>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: "12px", marginBottom: "4px" }}>
                <span style={{ color: "#94a3b8" }}>Anomaly Suppression Floor</span>
                <span style={{ color: "#f59e0b", fontWeight: 700 }}>{configParams.threat_score_suppression}</span>
              </div>
              <input
                type="range"
                min="0.1"
                max="0.6"
                step="0.05"
                value={configParams.threat_score_suppression}
                onChange={(e) => setConfigParams({ ...configParams, threat_score_suppression: parseFloat(e.target.value) })}
                style={{ width: "100%", accentColor: "#f59e0b" }}
              />
            </div>

            <div style={{ borderTop: "1px solid #1c2533", paddingTop: "12px" }}>
              <div style={{ fontSize: "12px", color: "#f8fafc", fontWeight: 700, marginBottom: "8px" }}>
                Bayesian Voting Weights
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
                {Object.entries(configParams.voting_weights).map(([engine, wt]) => (
                  <div key={engine} style={{ background: "#070b12", border: "1px solid #182232", padding: "6px 10px", borderRadius: "6px", display: "flex", justifyContent: "space-between", fontSize: "11px" }}>
                    <span style={{ color: "#94a3b8", textTransform: "uppercase" }}>{engine}</span>
                    <span style={{ color: "#34d399", fontWeight: 700 }}>{wt}x</span>
                  </div>
                ))}
              </div>
            </div>

            <button
              onClick={handlePushConfig}
              style={{
                background: "linear-gradient(135deg, #2563eb 0%, #4f46e5 100%)",
                border: "none",
                color: "#fff",
                fontWeight: 700,
                fontSize: "12px",
                padding: "10px",
                borderRadius: "6px",
                display: "flex",
                justifyContent: "center",
                alignItems: "center",
                gap: "8px",
                marginTop: "6px",
              }}
            >
              <Send size={14} /> Push Parameters to Node
            </button>
          </div>
        </div>

        {/* Right: Cryptographic Package Verifier */}
        <div style={{ background: "#0b1019", border: "1px solid #1c2533", borderRadius: "10px", padding: "20px" }}>
          <h3 style={{ margin: "0 0 16px 0", fontSize: "14px", color: "#f8fafc", fontWeight: 700, display: "flex", alignItems: "center", gap: "8px" }}>
            <KeyRound size={16} color="#34d399" /> Ed25519 Package Integrity Validator
          </h3>

          <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
            <div>
              <label style={{ fontSize: "11px", color: "#94a3b8", display: "block", marginBottom: "4px" }}>
                Agent Archive Target Path (.tar.gz / .zip)
              </label>
              <input
                type="text"
                value={pkgVerifyPath}
                onChange={(e) => setPkgVerifyPath(e.target.value)}
                style={{
                  width: "100%",
                  background: "#070b12",
                  border: "1px solid #334155",
                  color: "#f8fafc",
                  borderRadius: "6px",
                  padding: "8px 10px",
                  fontSize: "12px",
                  boxSizing: "border-box",
                }}
              />
            </div>

            <div style={{ background: "#070b12", border: "1px solid #182232", borderRadius: "8px", padding: "12px", fontSize: "11px" }}>
              <div style={{ color: "#64748b", marginBottom: "4px" }}>Active Public Key Fingerprint (Ed25519)</div>
              <div style={{ fontFamily: "monospace", color: "#38bdf8", wordBreak: "break-all" }}>
                ED25519-KEY-AEGIS-PROD-98F17A9B04D...
              </div>
            </div>

            <button
              onClick={handleVerifyPackage}
              style={{
                background: "#065f46",
                border: "1px solid #059669",
                color: "#f8fafc",
                fontWeight: 700,
                fontSize: "12px",
                padding: "10px",
                borderRadius: "6px",
                display: "flex",
                justifyContent: "center",
                alignItems: "center",
                gap: "8px",
              }}
            >
              <ShieldCheck size={16} /> Validate Signature &amp; SHA-256
            </button>

            {verifyResult && (
              <div
                style={{
                  background: verifyResult.valid ? "rgba(16, 185, 129, 0.1)" : "rgba(239, 68, 68, 0.1)",
                  border: `1px solid ${verifyResult.valid ? "#10b981" : "#ef4444"}`,
                  borderRadius: "6px",
                  padding: "10px",
                  fontSize: "11px",
                }}
              >
                <div style={{ fontWeight: 700, color: verifyResult.valid ? "#34d399" : "#f87171" }}>
                  {verifyResult.valid ? "VALID ED25519 SIGNATURE & SHA256 MATCH" : "VERIFICATION REJECTED"}
                </div>
                <div style={{ color: "#94a3b8", marginTop: "4px" }}>{verifyResult.reason || "Package validated."}</div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
