import React, { useState, useEffect } from "react";
import {
  BrainCircuit,
  X,
  ShieldAlert,
  CheckCircle,
  HelpCircle,
  Activity,
  Layers,
  ArrowRight,
  TrendingUp,
  Info,
  Sliders,
} from "lucide-react";

export default function XAIExplanationModal({
  isOpen,
  onClose,
  modelKey = "linux_ids",
  threatScore = 0.94,
  eventData = null,
  apiBase = "http://127.0.0.1:8000",
}) {
  const [xaiData, setXaiData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeFilter, setActiveFilter] = useState("all"); // 'all', 'malicious', 'benign'

  useEffect(() => {
    if (!isOpen) return;

    const fetchExplanation = async () => {
      setLoading(true);
      try {
        let res;
        if (eventData) {
          res = await fetch(`${apiBase}/api/xai/explain`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              model: modelKey,
              threat_score: threatScore,
              ...eventData,
            }),
          });
        } else {
          res = await fetch(
            `${apiBase}/api/xai/explain?model=${modelKey}&threat_score=${threatScore}`
          );
        }

        if (res.ok) {
          const data = await res.json();
          setXaiData(data);
        }
      } catch (err) {
        console.error("Failed to load XAI explanation:", err);
      } finally {
        setLoading(false);
      }
    };

    fetchExplanation();
  }, [isOpen, modelKey, threatScore, eventData, apiBase]);

  if (!isOpen) return null;

  const filteredFeatures = (xaiData?.features || []).filter((f) => {
    if (activeFilter === "malicious") return f.direction === "malicious";
    if (activeFilter === "benign") return f.direction === "benign";
    return true;
  });

  return (
    <div
      style={{
        position: "fixed",
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        background: "rgba(0, 0, 0, 0.82)",
        backdropFilter: "blur(6px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 99999,
        padding: "20px",
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: "#0d1322",
          border: "1px solid rgba(139, 92, 246, 0.35)",
          borderRadius: "14px",
          width: "100%",
          maxWidth: "840px",
          maxHeight: "90vh",
          overflowY: "auto",
          boxShadow: "0 25px 50px rgba(0,0,0,0.9), 0 0 35px rgba(139, 92, 246, 0.25)",
          display: "flex",
          flexDirection: "column",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div
          style={{
            padding: "20px 24px",
            borderBottom: "1px solid rgba(51, 65, 85, 0.4)",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            background: "linear-gradient(135deg, rgba(30, 41, 59, 0.9) 0%, rgba(13, 19, 34, 0.95) 100%)",
            position: "sticky",
            top: 0,
            zIndex: 10,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <div
              style={{
                width: "40px",
                height: "40px",
                borderRadius: "10px",
                background: "rgba(139, 92, 246, 0.15)",
                border: "1px solid rgba(139, 92, 246, 0.4)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <BrainCircuit size={22} color="#a855f7" />
            </div>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <h3 style={{ margin: 0, fontSize: "1.1rem", fontWeight: "700", color: "#f8fafc" }}>
                  Explainable AI (XAI) · Model Decision Drilldown
                </h3>
                <span
                  style={{
                    fontSize: "0.72rem",
                    padding: "2px 8px",
                    borderRadius: "20px",
                    fontWeight: "700",
                    background: "rgba(139, 92, 246, 0.2)",
                    color: "#c084fc",
                    border: "1px solid rgba(139, 92, 246, 0.4)",
                  }}
                >
                  SHAP Attributions
                </span>
              </div>
              <span style={{ fontSize: "0.78rem", color: "#94a3b8" }}>
                {xaiData?.model_name || "Neural Inference Classifier"}
              </span>
            </div>
          </div>

          <button
            onClick={onClose}
            style={{
              background: "transparent",
              border: "none",
              color: "#94a3b8",
              cursor: "pointer",
              padding: "6px",
            }}
          >
            <X size={20} />
          </button>
        </div>

        {/* Content Body */}
        {loading ? (
          <div style={{ padding: "60px", textAlign: "center", color: "#94a3b8" }}>
            <Activity className="spin" size={32} color="#a855f7" style={{ marginBottom: "12px" }} />
            <div>Computing SHAP game-theoretic Shapley values and feature attributions...</div>
          </div>
        ) : !xaiData ? (
          <div style={{ padding: "40px", textAlign: "center", color: "#f87171" }}>
            Failed to compute explanation for this event.
          </div>
        ) : (
          <div style={{ padding: "24px", display: "flex", flexDirection: "column", gap: "20px" }}>
            {/* KPI Top Cards */}
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(3, 1fr)",
                gap: "12px",
              }}
            >
              <div
                style={{
                  background: "rgba(15, 23, 42, 0.7)",
                  border: "1px solid rgba(51, 65, 85, 0.5)",
                  borderRadius: "8px",
                  padding: "14px",
                }}
              >
                <div style={{ fontSize: "0.72rem", color: "#94a3b8", textTransform: "uppercase" }}>
                  Model Decision
                </div>
                <div
                  style={{
                    fontSize: "1.2rem",
                    fontWeight: "700",
                    color: xaiData.classification === "MALICIOUS" ? "#ef4444" : "#10b981",
                    marginTop: "4px",
                  }}
                >
                  {xaiData.classification}
                </div>
              </div>

              <div
                style={{
                  background: "rgba(15, 23, 42, 0.7)",
                  border: "1px solid rgba(51, 65, 85, 0.5)",
                  borderRadius: "8px",
                  padding: "14px",
                }}
              >
                <div style={{ fontSize: "0.72rem", color: "#94a3b8", textTransform: "uppercase" }}>
                  Detection Confidence
                </div>
                <div style={{ fontSize: "1.2rem", fontWeight: "700", color: "#38bdf8", marginTop: "4px" }}>
                  {xaiData.confidence}
                </div>
              </div>

              <div
                style={{
                  background: "rgba(15, 23, 42, 0.7)",
                  border: "1px solid rgba(51, 65, 85, 0.5)",
                  borderRadius: "8px",
                  padding: "14px",
                }}
              >
                <div style={{ fontSize: "0.72rem", color: "#94a3b8", textTransform: "uppercase" }}>
                  Evaluated Features
                </div>
                <div style={{ fontSize: "1.2rem", fontWeight: "700", color: "#a855f7", marginTop: "4px" }}>
                  {xaiData.top_features_count} Dimensions
                </div>
              </div>
            </div>

            {/* AI Analyst Narrative */}
            <div
              style={{
                background: "rgba(30, 41, 59, 0.4)",
                border: "1px solid rgba(59, 130, 246, 0.25)",
                borderRadius: "10px",
                padding: "16px",
                display: "flex",
                gap: "12px",
                alignItems: "flex-start",
              }}
            >
              <Info size={20} color="#38bdf8" style={{ flexShrink: 0, marginTop: "2px" }} />
              <div>
                <h4 style={{ margin: "0 0 6px", fontSize: "0.88rem", color: "#f8fafc", fontWeight: "700" }}>
                  SOC Analyst Root-Cause Narrative
                </h4>
                <p style={{ margin: 0, fontSize: "0.82rem", color: "#cbd5e1", lineHeight: "1.5" }}>
                  {xaiData.analyst_narrative}
                </p>
              </div>
            </div>

            {/* SHAP Feature Contribution Waterfall Section */}
            <div>
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  marginBottom: "12px",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <Sliders size={16} color="#c084fc" />
                  <h4 style={{ margin: 0, fontSize: "0.95rem", color: "#f8fafc", fontWeight: "700" }}>
                    SHAP Feature Attribution Breakdown
                  </h4>
                </div>

                {/* Filter buttons */}
                <div style={{ display: "flex", gap: "6px" }}>
                  {[
                    { id: "all", label: "All Features" },
                    { id: "malicious", label: "Malicious Drivers (+)" },
                    { id: "benign", label: "Benign Indicators (-)" },
                  ].map((btn) => (
                    <button
                      key={btn.id}
                      onClick={() => setActiveFilter(btn.id)}
                      style={{
                        background: activeFilter === btn.id ? "rgba(139, 92, 246, 0.3)" : "rgba(30, 41, 59, 0.6)",
                        border: `1px solid ${activeFilter === btn.id ? "rgba(139, 92, 246, 0.6)" : "rgba(51, 65, 85, 0.4)"}`,
                        color: activeFilter === btn.id ? "#c084fc" : "#94a3b8",
                        borderRadius: "4px",
                        padding: "4px 8px",
                        fontSize: "0.72rem",
                        fontWeight: "600",
                        cursor: "pointer",
                      }}
                    >
                      {btn.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Horizontal SHAP Waterfall Bars */}
              <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                {filteredFeatures.map((feat, idx) => {
                  const isPositive = feat.shap_value > 0;
                  const barColor = isPositive ? "linear-gradient(90deg, #ef4444, #f87171)" : "linear-gradient(90deg, #10b981, #34d399)";
                  const barWidth = Math.min(Math.abs(feat.shap_value) * 220, 100);

                  return (
                    <div
                      key={idx}
                      style={{
                        background: "#090d16",
                        border: "1px solid rgba(51, 65, 85, 0.3)",
                        borderRadius: "6px",
                        padding: "10px 14px",
                        display: "flex",
                        flexDirection: "column",
                        gap: "6px",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontSize: "0.82rem", fontWeight: "600", color: "#f1f5f9" }}>
                          {feat.label}
                        </span>
                        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                          <span
                            style={{
                              fontSize: "0.75rem",
                              fontWeight: "700",
                              color: isPositive ? "#f87171" : "#34d399",
                            }}
                          >
                            {isPositive ? "+" : ""}
                            {feat.shap_value.toFixed(3)} SHAP
                          </span>
                          <span style={{ fontSize: "0.72rem", color: "#64748b" }}>
                            ({feat.importance_pct}% imp.)
                          </span>
                        </div>
                      </div>

                      {/* Bar Visual */}
                      <div
                        style={{
                          width: "100%",
                          height: "6px",
                          background: "#1e293b",
                          borderRadius: "3px",
                          overflow: "hidden",
                        }}
                      >
                        <div
                          style={{
                            width: `${barWidth}%`,
                            height: "100%",
                            background: barColor,
                            borderRadius: "3px",
                          }}
                        />
                      </div>

                      {/* Baseline vs Observed metrics */}
                      <div
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          fontSize: "0.72rem",
                          color: "#94a3b8",
                          marginTop: "2px",
                        }}
                      >
                        <span>
                          Observed: <b style={{ color: isPositive ? "#fca5a5" : "#a7f3d0" }}>{feat.observed_value}</b>
                        </span>
                        <span>
                          Normal Baseline: <b style={{ color: "#cbd5e1" }}>{feat.baseline_value}</b>
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Counterfactual What-If Analysis Box */}
            <div
              style={{
                background: "rgba(15, 23, 42, 0.9)",
                border: "1px solid rgba(168, 85, 247, 0.3)",
                borderRadius: "10px",
                padding: "14px 16px",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
                <TrendingUp size={16} color="#a855f7" />
                <h5 style={{ margin: 0, fontSize: "0.82rem", color: "#e2e8f0", fontWeight: "700" }}>
                  Counterfactual & Tipping Point Analysis
                </h5>
              </div>
              <p style={{ margin: 0, fontSize: "0.78rem", color: "#94a3b8", lineHeight: "1.4" }}>
                {xaiData.counterfactual_analysis}
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
