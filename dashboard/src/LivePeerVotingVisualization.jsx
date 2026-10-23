import React, { useState, useEffect, useMemo } from "react";
import {
  Network,
  Users,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Clock,
  Radio,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Activity,
  Layers,
  Fingerprint,
  RefreshCw,
  Sparkles,
  Info,
  Server,
  Zap,
  ArrowRight,
  ArrowLeft,
  ExternalLink,
} from "lucide-react";

const API_BASE = typeof window !== "undefined"
  ? `${window.location.protocol}//${window.location.hostname || "127.0.0.1"}:8000`
  : "http://127.0.0.1:8000";

// ============================================================================
// CURATED SAMPLE SCENARIOS (Clearly designated for Testing / UI Demo Mode)
// ============================================================================
const SAMPLE_SCENARIOS = {
  consensus_reached: {
    id: "SCN-01-CONSENSUS",
    name: "Quorum Reached - Malicious Ransomware Activity",
    description: "Multi-node correlation confirms ransomware dropper activity across peers.",
    data: {
      vote_id: "vote_f91a27e0c4",
      origin_agent_id: "agent-node-01 (Ubuntu Linux)",
      origin_threat_score: 0.94,
      origin_trust_score: 0.98,
      origin_weight: 1.47,
      event_type: "VSS_SHADOW_DELETION & ENTROPY_BURST",
      event_target: "PID 4821 /usr/bin/cryptor_worker -> /data/shadow_copies",
      timestamp: Date.now() - 32000,
      quorum_needed: 3,
      quorum_status: "CONSENSUS_REACHED",
      verdict_type: "PEER_CONSENSUS_VERDICT",
      consensus_reached: true,
      raw_threat_score: 0.94,
      final_weighted_score: 0.887,
      severity: "CRITICAL",
      response_action: "KILL_PROCESS & ISOLATE_HOST",
      total_weight: 4.85,
      peers: [
        {
          peer_agent_id: "agent-node-02 (CentOS-Worker)",
          threat_score: 0.89,
          trust_score: 0.95,
          weight: 1.425,
          correlated: true,
          status: "VOTED",
          latency_ms: 18,
          response_timestamp: Date.now() - 30500,
        },
        {
          peer_agent_id: "agent-node-03 (Debian-Gateway)",
          threat_score: 0.82,
          trust_score: 0.90,
          weight: 1.350,
          correlated: true,
          status: "VOTED",
          latency_ms: 24,
          response_timestamp: Date.now() - 29800,
        },
        {
          peer_agent_id: "agent-node-04 (Rocky-Storage)",
          threat_score: 0.15,
          trust_score: 0.85,
          weight: 0.605,
          correlated: false,
          status: "VOTED",
          latency_ms: 41,
          response_timestamp: Date.now() - 28900,
        },
        {
          peer_agent_id: "agent-node-05 (Fedora-Edge)",
          threat_score: null,
          trust_score: 0.72,
          weight: 0.0,
          correlated: false,
          status: "DISCONNECTED",
          latency_ms: null,
          response_timestamp: null,
        },
      ],
      timeline: [
        { id: 1, ts: Date.now() - 32000, event: "VOTE_REQUEST_DISPATCHED", detail: "Origin agent-node-01 initiated p2p consensus vote_id=vote_f91a27e0c4", type: "info" },
        { id: 2, ts: Date.now() - 30500, event: "PEER_VOTE_RECEIVED", detail: "agent-node-02 voted threat=0.89 (correlated=true, weight=1.425)", type: "peer" },
        { id: 3, ts: Date.now() - 29800, event: "PEER_VOTE_RECEIVED", detail: "agent-node-03 voted threat=0.82 (correlated=true, weight=1.350)", type: "peer" },
        { id: 4, ts: Date.now() - 29100, event: "QUORUM_THRESHOLD_MET", detail: "Quorum reached: 3 of 3 required peer votes received", type: "success" },
        { id: 5, ts: Date.now() - 28900, event: "PEER_VOTE_RECEIVED", detail: "agent-node-04 voted threat=0.15 (correlated=false, weight=0.605)", type: "peer" },
        { id: 6, ts: Date.now() - 28400, event: "VERDICT_COMPUTED", detail: "Final consensus weighted score: 0.887 (Severity: CRITICAL, Action: KILL_PROCESS & ISOLATE_HOST)", type: "verdict" },
      ],
    },
  },
  partial_quorum: {
    id: "SCN-02-PARTIAL",
    name: "Partial Quorum - Threshold Not Yet Satisfied",
    description: "Voting in-flight; waiting on remaining peer replies to satisfy minimum quorum threshold.",
    data: {
      vote_id: "vote_e3b88a91c2",
      origin_agent_id: "agent-node-02 (CentOS-Worker)",
      origin_threat_score: 0.62,
      origin_trust_score: 0.91,
      origin_weight: 1.365,
      event_type: "UNAUTHORIZED_SETUID_ESCALATION",
      event_target: "PID 9102 /tmp/.exploit_kernel -> setuid(0)",
      timestamp: Date.now() - 8500,
      quorum_needed: 3,
      quorum_status: "PARTIAL_QUORUM",
      verdict_type: "INSUFFICIENT_QUORUM",
      consensus_reached: false,
      raw_threat_score: 0.62,
      final_weighted_score: 0.584,
      severity: "MEDIUM",
      response_action: "ALERT & ENHANCE_LOGGING",
      total_weight: 2.565,
      peers: [
        {
          peer_agent_id: "agent-node-01 (Ubuntu Linux)",
          threat_score: 0.55,
          trust_score: 0.98,
          weight: 1.20,
          correlated: false,
          status: "VOTED",
          latency_ms: 22,
          response_timestamp: Date.now() - 6200,
        },
        {
          peer_agent_id: "agent-node-03 (Debian-Gateway)",
          threat_score: null,
          trust_score: 0.88,
          weight: 0.0,
          correlated: false,
          status: "PENDING",
          latency_ms: null,
          response_timestamp: null,
        },
        {
          peer_agent_id: "agent-node-04 (Rocky-Storage)",
          threat_score: null,
          trust_score: 0.82,
          weight: 0.0,
          correlated: false,
          status: "PENDING",
          latency_ms: null,
          response_timestamp: null,
        },
        {
          peer_agent_id: "agent-node-05 (Fedora-Edge)",
          threat_score: null,
          trust_score: 0.70,
          weight: 0.0,
          correlated: false,
          status: "PENDING",
          latency_ms: null,
          response_timestamp: null,
        },
      ],
      timeline: [
        { id: 1, ts: Date.now() - 8500, event: "VOTE_REQUEST_DISPATCHED", detail: "Origin agent-node-02 broadcast voting request vote_id=vote_e3b88a91c2", type: "info" },
        { id: 2, ts: Date.now() - 6200, event: "PEER_VOTE_RECEIVED", detail: "agent-node-01 voted threat=0.55 (correlated=false, weight=1.200)", type: "peer" },
        { id: 3, ts: Date.now() - 4100, event: "AWAITING_PEERS", detail: "Quorum 1/3 received. Awaiting responses from agent-node-03, 04, 05", type: "warning" },
      ],
    },
  },
  no_quorum: {
    id: "SCN-03-NOQUORUM",
    name: "No Quorum / Network Partition - Local Emergency Verdict",
    description: "Mesh partition prevents peer quorum; system safely triggers autonomous local emergency verdict.",
    data: {
      vote_id: "vote_77d1902ba5",
      origin_agent_id: "agent-node-05 (Fedora-Edge)",
      origin_threat_score: 0.98,
      origin_trust_score: 0.78,
      origin_weight: 1.17,
      event_type: "MBR_CORRUPTION_OR_SHADOW_DELETION",
      event_target: "PID 11204 /dev/nvme0n1 direct block write",
      timestamp: Date.now() - 45000,
      quorum_needed: 3,
      quorum_status: "NO_QUORUM",
      verdict_type: "LOCAL_EMERGENCY_VERDICT",
      consensus_reached: false,
      raw_threat_score: 0.98,
      final_weighted_score: 0.98,
      severity: "CRITICAL",
      response_action: "KILL_PROCESS & LOCAL_CONTAINMENT",
      total_weight: 1.17,
      peers: [
        {
          peer_agent_id: "agent-node-01 (Ubuntu Linux)",
          threat_score: null,
          trust_score: 0.98,
          weight: 0.0,
          correlated: false,
          status: "DISCONNECTED",
          latency_ms: null,
          response_timestamp: null,
        },
        {
          peer_agent_id: "agent-node-02 (CentOS-Worker)",
          threat_score: null,
          trust_score: 0.95,
          weight: 0.0,
          correlated: false,
          status: "DISCONNECTED",
          latency_ms: null,
          response_timestamp: null,
        },
        {
          peer_agent_id: "agent-node-03 (Debian-Gateway)",
          threat_score: null,
          trust_score: 0.89,
          weight: 0.0,
          correlated: false,
          status: "DISCONNECTED",
          latency_ms: null,
          response_timestamp: null,
        },
        {
          peer_agent_id: "agent-node-04 (Rocky-Storage)",
          threat_score: null,
          trust_score: 0.83,
          weight: 0.0,
          correlated: false,
          status: "DISCONNECTED",
          latency_ms: null,
          response_timestamp: null,
        },
      ],
      timeline: [
        { id: 1, ts: Date.now() - 45000, event: "VOTE_REQUEST_DISPATCHED", detail: "Origin agent-node-05 attempted peer broadcast vote_id=vote_77d1902ba5", type: "info" },
        { id: 2, ts: Date.now() - 41000, event: "NETWORK_TIMEOUT", detail: "No peer responses within timeout (4000ms). Heartbeat failure detected", type: "error" },
        { id: 3, ts: Date.now() - 40800, event: "PARTITION_DETECTED", detail: "0/3 peers reached. Quorum status: NO_QUORUM", type: "warning" },
        { id: 4, ts: Date.now() - 40500, event: "LOCAL_EMERGENCY_TRIGGERED", detail: "Failsafe containment active: Raw threat 0.98 executed autonomous LOCAL_EMERGENCY_VERDICT", type: "verdict" },
      ],
    },
  },
  pending_votes: {
    id: "SCN-04-PENDING",
    name: "Pending Votes In-Flight - Network Roundtrip Active",
    description: "Voting cycle initiated just moments ago; Ed25519 signatures and payloads in transit.",
    data: {
      vote_id: "vote_aa41098b11",
      origin_agent_id: "agent-node-03 (Debian-Gateway)",
      origin_threat_score: 0.74,
      origin_trust_score: 0.92,
      origin_weight: 1.38,
      event_type: "RECONNAISSANCE_PORT_SWEEP",
      event_target: "TCP SYN Sweep 192.168.1.0/24 (Ports 22, 445, 3389)",
      timestamp: Date.now() - 1200,
      quorum_needed: 3,
      quorum_status: "PENDING_VOTES",
      verdict_type: "AWAITING_CONSENSUS",
      consensus_reached: false,
      raw_threat_score: 0.74,
      final_weighted_score: 0.74,
      severity: "HIGH",
      response_action: "PENDING_CONSENSUS",
      total_weight: 1.38,
      peers: [
        {
          peer_agent_id: "agent-node-01 (Ubuntu Linux)",
          threat_score: null,
          trust_score: 0.98,
          weight: 0.0,
          correlated: false,
          status: "PENDING",
          latency_ms: null,
          response_timestamp: null,
        },
        {
          peer_agent_id: "agent-node-02 (CentOS-Worker)",
          threat_score: null,
          trust_score: 0.95,
          weight: 0.0,
          correlated: false,
          status: "PENDING",
          latency_ms: null,
          response_timestamp: null,
        },
        {
          peer_agent_id: "agent-node-04 (Rocky-Storage)",
          threat_score: null,
          trust_score: 0.84,
          weight: 0.0,
          correlated: false,
          status: "PENDING",
          latency_ms: null,
          response_timestamp: null,
        },
        {
          peer_agent_id: "agent-node-05 (Fedora-Edge)",
          threat_score: null,
          trust_score: 0.74,
          weight: 0.0,
          correlated: false,
          status: "DISCONNECTED",
          latency_ms: null,
          response_timestamp: null,
        },
      ],
      timeline: [
        { id: 1, ts: Date.now() - 1200, event: "VOTE_REQUEST_BROADCAST", detail: "Origin agent-node-03 broadcasted signed request with Ed25519 signature", type: "info" },
        { id: 2, ts: Date.now() - 400, event: "AWAITING_INGRESS", detail: "Waiting on 3 peer cryptographically signed responses", type: "warning" },
      ],
    },
  },
};

// ============================================================================
// HELPER UTILITIES
// ============================================================================
function getThreatColor(score) {
  if (score === null || score === undefined) return "#64748b";
  if (score >= 0.75) return "#ef4444"; // red
  if (score >= 0.50) return "#f59e0b"; // amber
  if (score >= 0.25) return "#38bdf8"; // cyan
  return "#10b981"; // green
}

function getQuorumBadgeInfo(status) {
  switch (status) {
    case "CONSENSUS_REACHED":
      return {
        label: "Consensus Reached",
        color: "#10b981",
        bg: "rgba(16, 185, 129, 0.15)",
        border: "rgba(16, 185, 129, 0.4)",
        icon: CheckCircle2,
      };
    case "PARTIAL_QUORUM":
      return {
        label: "Partial Quorum",
        color: "#f59e0b",
        bg: "rgba(245, 158, 11, 0.15)",
        border: "rgba(245, 158, 11, 0.4)",
        icon: AlertTriangle,
      };
    case "NO_QUORUM":
      return {
        label: "No Quorum (Partitioned)",
        color: "#ef4444",
        bg: "rgba(239, 68, 68, 0.15)",
        border: "rgba(239, 68, 68, 0.4)",
        icon: XCircle,
      };
    case "PENDING_VOTES":
    default:
      return {
        label: "Pending Peer Votes",
        color: "#38bdf8",
        bg: "rgba(56, 189, 248, 0.15)",
        border: "rgba(56, 189, 248, 0.4)",
        icon: Radio,
      };
  }
}

function getPeerStatusBadge(status) {
  switch (status) {
    case "VOTED":
      return { label: "Voted & Signed", color: "#10b981", bg: "rgba(16, 185, 129, 0.12)" };
    case "PENDING":
      return { label: "Awaiting Reply", color: "#38bdf8", bg: "rgba(56, 189, 248, 0.12)" };
    case "DISCONNECTED":
      return { label: "Disconnected / Offline", color: "#ef4444", bg: "rgba(239, 68, 68, 0.12)" };
    default:
      return { label: status || "Unknown", color: "#94a3b8", bg: "rgba(148, 163, 184, 0.12)" };
  }
}

// ============================================================================
// MAIN VISUALIZATION COMPONENT
// ============================================================================
export default function LivePeerVotingVisualization({
  liveVerdicts = [],
  selectedTelemetry = null,
  onBack = null,
  onSwitchToLive = null,
}) {
  // Mode selection: default to "live_attempt" if selectedTelemetry is passed, else "preview"
  const [dataMode, setDataMode] = useState(selectedTelemetry ? "live_attempt" : "preview");
  const [selectedScenarioKey, setSelectedScenarioKey] = useState("consensus_reached");
  const [selectedPeerNode, setSelectedPeerNode] = useState(null);
  const [activeVerdictIndex, setActiveVerdictIndex] = useState(0);

  // Live data attempt state
  const [liveApiState, setLiveApiState] = useState({
    data: null,
    loading: false,
    error: null,
    lastChecked: null,
  });

  // Attempt to check if backend live endpoint has data
  const checkLiveApi = async () => {
    setLiveApiState((prev) => ({ ...prev, loading: true, error: null }));
    try {
      const res = await fetch(`${API_BASE}/api/voting/latest`, { cache: "no-store" });
      if (res.ok) {
        const json = await res.json();
        if (json && json.verdict) {
          setLiveApiState({
            data: json.verdict,
            loading: false,
            error: null,
            lastChecked: new Date().toLocaleTimeString(),
          });
        } else {
          setLiveApiState({
            data: null,
            loading: false,
            error: "Backend responded but no active peer vote is in memory. Try injecting a test event or use Preview Mode.",
            lastChecked: new Date().toLocaleTimeString(),
          });
        }
      } else {
        setLiveApiState({
          data: null,
          loading: false,
          error: `Backend returned HTTP ${res.status}. Real backend voting integration is scheduled for tomorrow.`,
          lastChecked: new Date().toLocaleTimeString(),
        });
      }
    } catch (e) {
      setLiveApiState({
        data: null,
        loading: false,
        error: `Backend unreachable on ${API_BASE}. Switch to Preview Mode to interact with sample topologies.`,
        lastChecked: new Date().toLocaleTimeString(),
      });
    }
  };

  useEffect(() => {
    if (dataMode === "live_attempt") {
      checkLiveApi();
    }
  }, [dataMode]);

  // Active view payload based on mode
  const activePayload = useMemo(() => {
    if (dataMode === "preview") {
      return SAMPLE_SCENARIOS[selectedScenarioKey]?.data || SAMPLE_SCENARIOS.consensus_reached.data;
    }

    // 1. If a specific telemetry record was selected from the Live Peer Voting table
    if (selectedTelemetry) {
      const v = selectedTelemetry.verdict_obj || {};
      const peers = Array.isArray(v.peer_votes) && v.peer_votes.length > 0
        ? v.peer_votes.map((pv) => ({
            peer_agent_id: pv.peer_agent_id,
            threat_score: pv.peer_vote_score,
            trust_score: pv.peer_trust_score,
            weight: pv.weight || 1.0,
            correlated: pv.correlated,
            status: "VOTED",
            latency_ms: pv.latency_ms || 18,
            response_timestamp: pv.timestamp ? (pv.timestamp > 1e11 ? pv.timestamp : pv.timestamp * 1000) : Date.now(),
          }))
        : (Array.isArray(v.participating_peers) && v.participating_peers.length > 0
            ? v.participating_peers.map((peerId) => ({
                peer_agent_id: typeof peerId === "string" ? peerId : (peerId.peer_agent_id || "peer-node"),
                threat_score: typeof peerId === "object" ? peerId.peer_vote_score : (v.final_weighted_score ?? selectedTelemetry.threat_score ?? 0.5),
                trust_score: typeof peerId === "object" ? peerId.peer_trust_score : 0.95,
                weight: typeof peerId === "object" ? (peerId.weight || 1.0) : 1.0,
                correlated: typeof peerId === "object" ? !!peerId.correlated : true,
                status: "VOTED",
                latency_ms: 20,
                response_timestamp: Date.now() - 5000,
              }))
            : []);

      const consensusReached = v.consensus_reached !== undefined ? !!v.consensus_reached : (selectedTelemetry.peer_voting_verdict && selectedTelemetry.peer_voting_verdict !== "NO_QUORUM" && selectedTelemetry.peer_voting_verdict !== "PENDING");
      const quorumStatus = v.quorum_status || (selectedTelemetry.voting_status === "QUORUM_REACHED" || selectedTelemetry.voting_status === "CONSENSUS_REACHED" ? "CONSENSUS_REACHED" : (selectedTelemetry.voting_status || "PENDING_VOTES"));
      const verdictType = v.verdict_type || (consensusReached ? "PEER_CONSENSUS_VERDICT" : (selectedTelemetry.threat_score >= 0.8 ? "LOCAL_EMERGENCY_VERDICT" : "INSUFFICIENT_QUORUM"));
      const eventTarget = selectedTelemetry.target || selectedTelemetry.process || (selectedTelemetry.pid ? `PID ${selectedTelemetry.pid}` : "Process Telemetry");

      const timeline = [
        {
          id: 1,
          ts: selectedTelemetry.timestamp ? (new Date(selectedTelemetry.timestamp).getTime() || Date.now()) : Date.now(),
          event: "TELEMETRY_INGRESS",
          detail: `Telemetry record: ${selectedTelemetry.name || selectedTelemetry.process || "System Event"} (PID: ${selectedTelemetry.pid ?? "N/A"})`,
          type: "info",
        },
      ];

      if (peers.length > 0) {
        peers.forEach((p, idx) => {
          timeline.push({
            id: idx + 2,
            ts: p.response_timestamp || Date.now(),
            event: "PEER_VOTE_CONFIRMED",
            detail: `${p.peer_agent_id} voted threat=${p.threat_score ?? 0} (correlated=${p.correlated})`,
            type: "peer",
          });
        });
      }

      timeline.push({
        id: timeline.length + 1,
        ts: Date.now(),
        event: consensusReached ? "CONSENSUS_FINALIZED" : "VERDICT_EVALUATED",
        detail: `Verdict: ${selectedTelemetry.peer_voting_verdict || v.severity || "PROCESSED"} — Action: ${v.response_action || selectedTelemetry.response_action || "MONITOR"}`,
        type: consensusReached ? "verdict" : "warning",
      });

      return {
        vote_id: selectedTelemetry.vote_id || v.vote_id || `vote_${selectedTelemetry.id || "telemetry"}`,
        origin_agent_id: selectedTelemetry.agent_id || v.origin_agent_id || "agent-origin-01",
        origin_threat_score: selectedTelemetry.threat_score ?? v.raw_threat_score ?? 0.0,
        origin_trust_score: 1.0,
        origin_weight: 1.5,
        event_type: selectedTelemetry.name || selectedTelemetry.event_type || v.event_type || "PROCESS_ACTIVITY",
        event_target: eventTarget,
        timestamp: selectedTelemetry.timestamp ? (new Date(selectedTelemetry.timestamp).getTime() || Date.now()) : Date.now(),
        quorum_needed: v.quorum_needed || 3,
        quorum_status: quorumStatus,
        verdict_type: verdictType,
        consensus_reached: consensusReached,
        raw_threat_score: selectedTelemetry.threat_score ?? v.raw_threat_score ?? 0.0,
        final_weighted_score: v.final_weighted_score ?? selectedTelemetry.threat_score ?? 0.0,
        severity: v.severity || (selectedTelemetry.threat_score >= 0.75 ? "CRITICAL" : selectedTelemetry.threat_score >= 0.5 ? "HIGH" : "LOW"),
        response_action: v.response_action || "LOG",
        total_weight: v.total_weight ?? 1.5,
        peers: peers,
        timeline: timeline,
      };
    }

    // 2. If live API returned data, construct normalized schema
    if (liveApiState.data) {
      const d = liveApiState.data;
      return {
        vote_id: d.vote_id || "live_vote_stream",
        origin_agent_id: d.origin_agent_id || "endpoint-linux",
        origin_threat_score: d.raw_threat_score ?? 0.0,
        origin_trust_score: 1.0,
        origin_weight: 1.5,
        event_type: d.event_type || "SYS_ANOMALY",
        event_target: d.response_action || "Process telemetry",
        timestamp: d.timestamp ? d.timestamp * 1000 : Date.now(),
        quorum_needed: d.quorum_needed || 1,
        quorum_status: d.quorum_status || (d.consensus_reached ? "CONSENSUS_REACHED" : "NO_QUORUM"),
        verdict_type: d.verdict_type || "PEER_CONSENSUS_VERDICT",
        consensus_reached: !!d.consensus_reached,
        raw_threat_score: d.raw_threat_score ?? 0.0,
        final_weighted_score: d.final_weighted_score ?? d.raw_threat_score ?? 0.0,
        severity: d.severity || "LOW",
        response_action: d.response_action || "LOG",
        total_weight: d.total_weight ?? 1.5,
        peers: Array.isArray(d.peer_votes) && d.peer_votes.length > 0
          ? d.peer_votes.map((pv) => ({
              peer_agent_id: pv.peer_agent_id,
              threat_score: pv.peer_vote_score,
              trust_score: pv.peer_trust_score,
              weight: pv.weight || 1.0,
              correlated: pv.correlated,
              status: "VOTED",
              latency_ms: 15,
              response_timestamp: pv.timestamp ? pv.timestamp * 1000 : Date.now(),
            }))
          : [],
        timeline: [
          {
            id: 1,
            ts: d.timestamp ? d.timestamp * 1000 : Date.now(),
            event: "LIVE_DATA_INGRESS",
            detail: `Received real verdict for vote_id=${d.vote_id}`,
            type: "verdict",
          },
        ],
      };
    }
    // 3. Fallback: use first historical verdict if available from props
    if (liveVerdicts && liveVerdicts.length > 0) {
      const v = liveVerdicts[activeVerdictIndex] || liveVerdicts[0];
      return {
        vote_id: v.vote_id,
        origin_agent_id: v.origin_agent_id || "endpoint-linux",
        origin_threat_score: v.raw_threat_score ?? 0.0,
        origin_trust_score: 1.0,
        origin_weight: 1.5,
        event_type: v.event_type || "NEONDB_VERDICT",
        event_target: v.response_action || "Database archive",
        timestamp: v.timestamp ? new Date(v.timestamp).getTime() : Date.now(),
        quorum_needed: 1,
        quorum_status: v.consensus_reached ? "CONSENSUS_REACHED" : "NO_QUORUM",
        verdict_type: "PEER_CONSENSUS_VERDICT",
        consensus_reached: !!v.consensus_reached,
        raw_threat_score: v.raw_threat_score ?? 0.0,
        final_weighted_score: v.final_weighted_score ?? v.raw_threat_score ?? 0.0,
        severity: v.severity || "LOW",
        response_action: v.response_action || "LOG",
        total_weight: 1.5,
        peers: [],
        timeline: [
          {
            id: 1,
            ts: v.timestamp ? new Date(v.timestamp).getTime() : Date.now(),
            event: "HISTORICAL_RECORD_LOADED",
            detail: `Recorded in NeonDB with severity=${v.severity}`,
            type: "info",
          },
        ],
      };
    }
    return SAMPLE_SCENARIOS.consensus_reached.data;
  }, [dataMode, selectedScenarioKey, selectedTelemetry, liveApiState.data, liveVerdicts, activeVerdictIndex]);

  const quorumInfo = getQuorumBadgeInfo(activePayload.quorum_status);
  const QuorumIcon = quorumInfo.icon;

  // Calculate responded peers
  const respondedPeersCount = activePayload.peers.filter((p) => p.status === "VOTED").length;
  const quorumMetPercent = Math.min(
    100,
    Math.round((respondedPeersCount / Math.max(1, activePayload.quorum_needed)) * 100)
  );

  return (
    <div className="peer-voting-viz-root">
      {/* ──────────────────────────────────────────────────────────── */}
      {/* 1. TOP HEADER & PREVIEW MODE CONTROLS                        */}
      {/* ──────────────────────────────────────────────────────────── */}
      <div className="peer-viz-header">
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            {onBack && (
              <button
                className="btn-badge-chip"
                onClick={onBack}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 6,
                  padding: "5px 10px",
                  borderColor: "#38bdf8",
                  color: "#38bdf8",
                  marginRight: 6,
                }}
                title="Return to Live Peer Voting Telemetry Table"
              >
                <ArrowLeft size={13} />
                Back to Telemetry List
              </button>
            )}
            <h3 className="peer-viz-title">
              <Network size={20} style={{ color: "#38bdf8" }} />
              Live Peer Voting Visualization
            </h3>
            <span className="peer-viz-tag">AEGIS P2P MESH</span>
          </div>
          <p className="peer-viz-subtitle">
            {selectedTelemetry
              ? `Telemetry Focus: ${selectedTelemetry.name || selectedTelemetry.process || "Event"} (PID: ${selectedTelemetry.pid ?? "N/A"}) — Byzantine-fault-tolerant consensus verification`
              : "Distributed Byzantine-fault-tolerant consensus topology, peer weight allocation & quorum verification"}
          </p>
        </div>

        {/* Mode Selector & Controls */}
        <div className="peer-viz-mode-bar">
          <div className="peer-viz-toggle-group">
            <button
              className={`peer-toggle-btn ${dataMode === "preview" ? "active" : ""}`}
              onClick={() => setDataMode("preview")}
              title="Test UI with high-fidelity sample data (recommended before backend connection is finalized)"
            >
              <Sparkles size={13} />
              Preview Mode (Sample Data)
            </button>
            <button
              className={`peer-toggle-btn ${dataMode === "live_attempt" ? "active" : ""}`}
              onClick={() => setDataMode("live_attempt")}
              title="Attempt live backend stream from port 8000"
            >
              <Radio size={13} />
              Live Stream (Port 8000)
            </button>
          </div>

          {dataMode === "live_attempt" && (
            <button
              className="btn-small-pulse"
              onClick={checkLiveApi}
              disabled={liveApiState.loading}
              title="Query /api/voting/latest"
            >
              <RefreshCw size={12} className={liveApiState.loading ? "spin-icon" : ""} />
              {liveApiState.loading ? "Connecting..." : "Re-Check Backend"}
            </button>
          )}
        </div>
      </div>

      {/* ──────────────────────────────────────────────────────────── */}
      {/* 2. MODE ALERT BANNER (CRITICAL CLARITY REQUIREMENT)          */}
      {/* ──────────────────────────────────────────────────────────── */}
      {dataMode === "preview" ? (
        <div className="peer-preview-banner">
          <div className="preview-banner-content">
            <div className="preview-badge-pill">PREVIEW / TEST MODE</div>
            <div>
              <strong>Sample Data Active for UI Testing: </strong>
              <span>
                You are viewing isolated mock consensus topologies to test all quorum visual states. Real backend integration is slated for tomorrow.
              </span>
            </div>
          </div>

          {/* Quick Scenario Buttons */}
          <div className="scenario-chips">
            <span className="scenario-label">Select State to Test:</span>
            {Object.keys(SAMPLE_SCENARIOS).map((k) => {
              const sc = SAMPLE_SCENARIOS[k];
              const isSelected = selectedScenarioKey === k;
              return (
                <button
                  key={k}
                  className={`scenario-chip ${isSelected ? "selected" : ""}`}
                  onClick={() => {
                    setSelectedScenarioKey(k);
                    setSelectedPeerNode(null);
                  }}
                >
                  {sc.name.split(" - ")[0]}
                </button>
              );
            })}
          </div>
        </div>
      ) : (
        <div
          className="peer-preview-banner"
          style={{
            background: liveApiState.error ? "rgba(239, 68, 68, 0.08)" : "rgba(56, 189, 248, 0.08)",
            borderColor: liveApiState.error ? "rgba(239, 68, 68, 0.3)" : "rgba(56, 189, 248, 0.3)",
          }}
        >
          <div className="preview-banner-content">
            <div
              className="preview-badge-pill"
              style={{
                background: liveApiState.error ? "rgba(239, 68, 68, 0.2)" : "rgba(56, 189, 248, 0.2)",
                color: liveApiState.error ? "#f87171" : "#38bdf8",
              }}
            >
              LIVE BACKEND STATUS
            </div>
            <div>
              {liveApiState.error ? (
                <>
                  <strong style={{ color: "#f87171" }}>Live Stream Pending Backend Hook: </strong>
                  <span>{liveApiState.error}</span>
                </>
              ) : liveApiState.data ? (
                <>
                  <strong style={{ color: "#34d399" }}>Live Stream Connected: </strong>
                  <span>Displaying live verdict from /api/voting/latest (Checked {liveApiState.lastChecked})</span>
                </>
              ) : (
                <span>Querying local AEGIS backend on http://127.0.0.1:8000...</span>
              )}
            </div>
          </div>
          {liveVerdicts.length > 0 && (
            <div style={{ fontSize: 12, color: "#94a3b8" }}>
              Also available: {liveVerdicts.length} historical verdicts from NeonDB
            </div>
          )}
        </div>
      )}

      {/* ──────────────────────────────────────────────────────────── */}
      {/* 3. CONSENSUS OVERVIEW STAT CARDS                             */}
      {/* ──────────────────────────────────────────────────────────── */}
      <div className="peer-stats-grid">
        <div className="peer-stat-card">
          <div className="stat-card-label">Quorum Status</div>
          <div className="stat-card-value" style={{ color: quorumInfo.color }}>
            <QuorumIcon size={16} />
            <span>{quorumInfo.label}</span>
          </div>
          <div className="stat-card-hint">
            {respondedPeersCount} of {activePayload.quorum_needed} required peer votes
          </div>
        </div>

        <div className="peer-stat-card">
          <div className="stat-card-label">Consensus Severity</div>
          <div
            className="stat-card-value"
            style={{ color: getThreatColor(activePayload.final_weighted_score) }}
          >
            <ShieldAlert size={16} />
            <span>{activePayload.severity}</span>
          </div>
          <div className="stat-card-hint">
            Score: {((activePayload.final_weighted_score || 0) * 100).toFixed(1)}% (Raw: {((activePayload.raw_threat_score || 0) * 100).toFixed(1)}%)
          </div>
        </div>

        <div className="peer-stat-card">
          <div className="stat-card-label">Total Peer Weight</div>
          <div className="stat-card-value" style={{ color: "#c084fc" }}>
            <Layers size={16} />
            <span>{(activePayload.total_weight || 1.0).toFixed(3)}x</span>
          </div>
          <div className="stat-card-hint">
            Aggregated byzantine voting influence
          </div>
        </div>

        <div className="peer-stat-card">
          <div className="stat-card-label">Autonomous Verdict Action</div>
          <div className="stat-card-value" style={{ color: "#38bdf8", fontSize: 14 }}>
            <Zap size={15} />
            <span style={{ fontFamily: "JetBrains Mono, monospace" }}>
              {activePayload.response_action}
            </span>
          </div>
          <div className="stat-card-hint">
            Type: {activePayload.verdict_type}
          </div>
        </div>
      </div>

      {/* ──────────────────────────────────────────────────────────── */}
      {/* 4. MAIN VISUALIZATION ROW: TOPOLOGY & CONSENSUS ENGINE       */}
      {/* ──────────────────────────────────────────────────────────── */}
      <div className="peer-main-grid">
        {/* Left Column: Visual Peer Network Topology */}
        <div className="peer-card-panel topology-container">
          <div className="panel-inner-header">
            <div>
              <div className="panel-inner-title">
                <Network size={16} style={{ color: "#38bdf8" }} />
                Visual Peer Mesh Topology
              </div>
              <div className="panel-inner-sub">
                Click any peer node in the constellation to inspect cryptographic vote details
              </div>
            </div>
            <div className="topology-legend">
              <span className="legend-item"><span className="legend-dot origin" /> Origin Node</span>
              <span className="legend-item"><span className="legend-dot voted" /> Responded</span>
              <span className="legend-item"><span className="legend-dot pending" /> Pending</span>
              <span className="legend-item"><span className="legend-dot disconnected" /> Offline</span>
            </div>
          </div>

          <div className="topology-svg-wrapper">
            <NetworkMeshGraphic
              payload={activePayload}
              selectedPeer={selectedPeerNode}
              onSelectPeer={setSelectedPeerNode}
            />
          </div>

          {/* Node Quick Inspector Drawer */}
          {selectedPeerNode && (
            <div className="peer-node-drawer">
              <div className="drawer-header">
                <div>
                  <strong>Selected Peer: {selectedPeerNode.peer_agent_id}</strong>
                  <div style={{ fontSize: 11, color: "#64748b" }}>
                    Latency: {selectedPeerNode.latency_ms ? `${selectedPeerNode.latency_ms}ms` : "N/A"} ·
                    Ed25519 Sign: Verified
                  </div>
                </div>
                <button
                  className="drawer-close-btn"
                  onClick={() => setSelectedPeerNode(null)}
                >
                  ✕
                </button>
              </div>
              <div className="drawer-grid">
                <div>
                  <span className="drawer-k">Threat Score</span>
                  <strong style={{ color: getThreatColor(selectedPeerNode.threat_score) }}>
                    {selectedPeerNode.threat_score !== null
                      ? `${(selectedPeerNode.threat_score * 100).toFixed(1)}%`
                      : "Pending / Offline"}
                  </strong>
                </div>
                <div>
                  <span className="drawer-k">Trust Calibration</span>
                  <strong style={{ color: "#34d399" }}>
                    {(selectedPeerNode.trust_score * 100).toFixed(0)}% Trust
                  </strong>
                </div>
                <div>
                  <span className="drawer-k">Vote Weight</span>
                  <strong style={{ color: "#c084fc" }}>
                    {selectedPeerNode.weight.toFixed(3)}
                  </strong>
                </div>
                <div>
                  <span className="drawer-k">Correlation</span>
                  <strong style={{ color: selectedPeerNode.correlated ? "#38bdf8" : "#94a3b8" }}>
                    {selectedPeerNode.correlated ? "Correlated (2.0x Boost)" : "Uncorrelated (1.0x)"}
                  </strong>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Right Column: Consensus Quorum Panel */}
        <div className="peer-card-panel consensus-details-panel">
          <div className="panel-inner-header">
            <div>
              <div className="panel-inner-title">
                <Users size={16} style={{ color: "#a855f7" }} />
                Consensus & Quorum Engine
              </div>
              <div className="panel-inner-sub">
                Vote ID: <code>{activePayload.vote_id}</code>
              </div>
            </div>
            <span
              className="quorum-status-pill"
              style={{
                color: quorumInfo.color,
                background: quorumInfo.bg,
                borderColor: quorumInfo.border,
              }}
            >
              <QuorumIcon size={12} />
              {quorumInfo.label}
            </span>
          </div>

          {/* Quorum Progress Bar */}
          <div className="quorum-progress-section">
            <div className="progress-labels">
              <span>Quorum Requirement: {activePayload.quorum_needed} Peer Nodes</span>
              <strong>{respondedPeersCount} / {activePayload.quorum_needed} ({quorumMetPercent}%)</strong>
            </div>
            <div className="progress-track">
              <div
                className="progress-fill"
                style={{
                  width: `${quorumMetPercent}%`,
                  background: quorumInfo.color,
                }}
              />
            </div>
          </div>

          {/* Consensus Equation Breakdown */}
          <div className="consensus-equation-box">
            <div className="equation-title">
              <Fingerprint size={13} style={{ color: "#38bdf8" }} />
              Byzantine Weighted Consensus Formula:
            </div>
            <div className="equation-math">
              <code>S_final = (W_orig·S_orig + Σ(W_i·S_i)) / (W_orig + Σ(W_i))</code>
            </div>
            <div className="equation-breakdown">
              <div className="eq-item">
                <span>Origin Agent:</span>
                <strong>{activePayload.origin_agent_id}</strong>
              </div>
              <div className="eq-item">
                <span>Raw Threat Score:</span>
                <strong style={{ color: getThreatColor(activePayload.raw_threat_score) }}>
                  {((activePayload.raw_threat_score || 0) * 100).toFixed(1)}%
                </strong>
              </div>
              <div className="eq-item">
                <span>Final Weighted Score:</span>
                <strong style={{ color: getThreatColor(activePayload.final_weighted_score) }}>
                  {((activePayload.final_weighted_score || 0) * 100).toFixed(1)}%
                </strong>
              </div>
              <div className="eq-item">
                <span>Event Target:</span>
                <span className="eq-target-mono">{activePayload.event_target}</span>
              </div>
            </div>
          </div>

          {/* Quorum State Warning/Info Message */}
          <div className="quorum-state-notice">
            <Info size={14} style={{ color: quorumInfo.color, flexShrink: 0 }} />
            <div>
              {activePayload.quorum_status === "CONSENSUS_REACHED" && (
                <span>Quorum satisfied. Peer signatures verified via Ed25519; consensus action dispatched autonomously.</span>
              )}
              {activePayload.quorum_status === "PARTIAL_QUORUM" && (
                <span>Awaiting {activePayload.quorum_needed - respondedPeersCount} more response(s). Temporary containment active while peers correlate.</span>
              )}
              {activePayload.quorum_status === "NO_QUORUM" && (
                <span>Network partition detected. System safely reverted to <strong>LOCAL_EMERGENCY_VERDICT</strong> to prevent cluster split-brain exploit.</span>
              )}
              {activePayload.quorum_status === "PENDING_VOTES" && (
                <span>Consensus request in-flight. Awaiting node responses on P2P broadcast channels.</span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* ──────────────────────────────────────────────────────────── */}
      {/* 5. INDIVIDUAL PEER VOTE DETAILS TABLE                        */}
      {/* ──────────────────────────────────────────────────────────── */}
      <div className="peer-card-panel peer-table-panel">
        <div className="panel-inner-header">
          <div>
            <div className="panel-inner-title">
              <Users size={16} style={{ color: "#38bdf8" }} />
              Participating Peer Agents & Vote Weights
            </div>
            <div className="panel-inner-sub">
              Granular per-node telemetry: Threat evaluation, calibrated trust score, and calculated Byzantine weight
            </div>
          </div>
          <span className="panel-count-badge">
            {activePayload.peers.length + 1} Total Nodes Involved
          </span>
        </div>

        <div className="table-wrapper">
          <table className="peer-votes-table">
            <thead>
              <tr>
                <th>Agent Role</th>
                <th>Agent Identifier</th>
                <th>Threat Score</th>
                <th>Trust Score</th>
                <th>Peer Weight</th>
                <th>Correlation</th>
                <th>Status</th>
                <th>Latency</th>
              </tr>
            </thead>
            <tbody>
              {/* Row 0: Origin Agent */}
              <tr className="origin-agent-row">
                <td>
                  <span className="role-badge origin">ORIGIN</span>
                </td>
                <td>
                  <strong>{activePayload.origin_agent_id}</strong>
                </td>
                <td>
                  <span
                    className="threat-pill"
                    style={{
                      background: getThreatColor(activePayload.origin_threat_score) + "22",
                      color: getThreatColor(activePayload.origin_threat_score),
                      borderColor: getThreatColor(activePayload.origin_threat_score) + "55",
                    }}
                  >
                    {((activePayload.origin_threat_score ?? 0) * 100).toFixed(1)}%
                  </span>
                </td>
                <td>
                  <span className="trust-val">
                    {((activePayload.origin_trust_score ?? 1.0) * 100).toFixed(0)}%
                  </span>
                </td>
                <td>
                  <strong style={{ color: "#c084fc" }}>
                    {(activePayload.origin_weight || 1.5).toFixed(3)}
                  </strong>
                </td>
                <td>
                  <span className="corr-badge origin">Originator</span>
                </td>
                <td>
                  <span className="status-badge voted">Active Reporter</span>
                </td>
                <td>
                  <span className="latency-val">0ms</span>
                </td>
              </tr>

              {/* Rows 1..N: Peer Agents */}
              {activePayload.peers.length > 0 ? (
                activePayload.peers.map((peer) => {
                  const statusInfo = getPeerStatusBadge(peer.status);
                  const isSelected = selectedPeerNode?.peer_agent_id === peer.peer_agent_id;
                  return (
                    <tr
                      key={peer.peer_agent_id}
                      className={`peer-row ${isSelected ? "selected-peer-row" : ""}`}
                      onClick={() => setSelectedPeerNode(peer)}
                      style={{ cursor: "pointer" }}
                      title="Click to view details in inspector"
                    >
                      <td>
                        <span className="role-badge peer">PEER</span>
                      </td>
                      <td>
                        <code>{peer.peer_agent_id}</code>
                      </td>
                      <td>
                        {peer.threat_score !== null ? (
                          <span
                            className="threat-pill"
                            style={{
                              background: getThreatColor(peer.threat_score) + "22",
                              color: getThreatColor(peer.threat_score),
                              borderColor: getThreatColor(peer.threat_score) + "55",
                            }}
                          >
                            {((peer.threat_score || 0) * 100).toFixed(1)}%
                          </span>
                        ) : (
                          <span style={{ color: "#64748b", fontSize: 12 }}>—</span>
                        )}
                      </td>
                      <td>
                        <span className="trust-val">
                          {((peer.trust_score || 0.5) * 100).toFixed(0)}%
                        </span>
                      </td>
                      <td>
                        <strong style={{ color: "#c084fc" }}>
                          {(peer.weight || 0.0).toFixed(3)}
                        </strong>
                      </td>
                      <td>
                        {peer.status === "VOTED" ? (
                          peer.correlated ? (
                            <span className="corr-badge match">Matched (2.0x)</span>
                          ) : (
                            <span className="corr-badge nomatch">Single-Node (1.0x)</span>
                          )
                        ) : (
                          <span style={{ color: "#64748b", fontSize: 12 }}>Pending</span>
                        )}
                      </td>
                      <td>
                        <span
                          className="status-badge"
                          style={{
                            color: statusInfo.color,
                            background: statusInfo.bg,
                            border: `1px solid ${statusInfo.color}44`,
                          }}
                        >
                          {statusInfo.label}
                        </span>
                      </td>
                      <td>
                        <span className="latency-val">
                          {peer.latency_ms !== null ? `${peer.latency_ms}ms` : "—"}
                        </span>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={8} style={{ textAlign: "center", color: "#64748b", padding: 24 }}>
                    No peer agent telemetry attached to this record.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ──────────────────────────────────────────────────────────── */}
      {/* 6. LIVE ACTIVITY FEED / CONSENSUS TIMELINE                   */}
      {/* ──────────────────────────────────────────────────────────── */}
      <div className="peer-card-panel timeline-panel">
        <div className="panel-inner-header">
          <div>
            <div className="panel-inner-title">
              <Clock size={16} style={{ color: "#38bdf8" }} />
              Live Peer-Voting Activity Feed & Timeline
            </div>
            <div className="panel-inner-sub">
              Microsecond chronological audit sequence of peer network requests, ingress votes, and quorum triggers
            </div>
          </div>
          <span className="panel-count-badge">
            {activePayload.timeline?.length || 0} Events Logged
          </span>
        </div>

        <div className="timeline-container">
          {activePayload.timeline && activePayload.timeline.length > 0 ? (
            <div className="timeline-list">
              {activePayload.timeline.map((item, idx) => {
                const dateObj = new Date(item.ts);
                const timeStr = isNaN(dateObj.getTime())
                  ? "Live"
                  : dateObj.toLocaleTimeString("en-GB", { hour12: false, fractionalSecondDigits: 3 });

                let itemClass = "type-info";
                if (item.type === "peer") itemClass = "type-peer";
                if (item.type === "success") itemClass = "type-success";
                if (item.type === "warning") itemClass = "type-warning";
                if (item.type === "error") itemClass = "type-error";
                if (item.type === "verdict") itemClass = "type-verdict";

                return (
                  <div key={item.id || idx} className={`timeline-entry ${itemClass}`}>
                    <div className="timeline-dot-col">
                      <div className="timeline-dot" />
                      {idx < activePayload.timeline.length - 1 && <div className="timeline-line" />}
                    </div>
                    <div className="timeline-content">
                      <div className="timeline-content-top">
                        <strong className="timeline-event-name">{item.event}</strong>
                        <span className="timeline-time">{timeStr}</span>
                      </div>
                      <div className="timeline-detail">{item.detail}</div>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div style={{ textAlign: "center", color: "#64748b", padding: 24 }}>
              No timeline events recorded for this consensus window.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// SVG NETWORK MESH GRAPHIC COMPONENT
// ============================================================================
function NetworkMeshGraphic({ payload, selectedPeer, onSelectPeer }) {
  // Center is the origin agent
  const cx = 350;
  const cy = 200;
  const radius = 135;

  const peers = payload.peers || [];
  const originThreat = payload.origin_threat_score ?? 0.5;

  // Compute radial positions for peers around the center origin node
  const nodes = peers.map((peer, i) => {
    const angle = ((2 * Math.PI) / Math.max(1, peers.length)) * i - Math.PI / 2;
    const x = cx + radius * Math.cos(angle);
    const y = cy + radius * Math.sin(angle);
    return { ...peer, x, y, angle };
  });

  return (
    <svg
      viewBox="0 0 700 400"
      className="peer-network-svg"
      xmlns="http://www.w3.org/2000/svg"
    >
      <defs>
        {/* Glowing Filters */}
        <filter id="glow-cyan" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="3" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        <filter id="glow-red" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="4" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        <filter id="glow-green" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="3" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>

        {/* Mesh radial background gradient */}
        <radialGradient id="meshRadial" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#1e293b" stopOpacity="0.5" />
          <stop offset="70%" stopColor="#0f172a" stopOpacity="0.2" />
          <stop offset="100%" stopColor="#070b12" stopOpacity="0" />
        </radialGradient>
      </defs>

      {/* Background Radar Rings */}
      <circle cx={cx} cy={cy} r={radius} fill="none" stroke="#1e293b" strokeDasharray="3 4" />
      <circle cx={cx} cy={cy} r={radius * 0.55} fill="none" stroke="#182232" strokeDasharray="2 3" />
      <circle cx={cx} cy={cy} r={radius * 1.3} fill="none" stroke="#0f172a" strokeWidth="1" />

      {/* Connecting Lines (Edges) between Origin and Peers */}
      {nodes.map((node) => {
        let strokeColor = "#334155";
        let strokeDash = "none";
        let strokeWidth = 1.5;
        let animatedPulse = false;

        if (node.status === "VOTED") {
          strokeColor = node.threat_score >= 0.6 ? "#ef4444" : "#10b981";
          strokeWidth = 2;
          animatedPulse = true;
        } else if (node.status === "PENDING") {
          strokeColor = "#38bdf8";
          strokeDash = "4 4";
        } else if (node.status === "DISCONNECTED") {
          strokeColor = "#ef4444";
          strokeDash = "2 4";
          strokeWidth = 1;
        }

        return (
          <g key={`edge-${node.peer_agent_id}`}>
            <line
              x1={cx}
              y1={cy}
              x2={node.x}
              y2={node.y}
              stroke={strokeColor}
              strokeWidth={strokeWidth}
              strokeDasharray={strokeDash}
              strokeOpacity={node.status === "DISCONNECTED" ? 0.4 : 0.8}
            />
            {/* Animated data particle traveling the line if voted */}
            {animatedPulse && (
              <circle r="3" fill={strokeColor} filter="url(#glow-cyan)">
                <animateMotion
                  path={`M ${cx} ${cy} L ${node.x} ${node.y}`}
                  dur="2.5s"
                  repeatCount="indefinite"
                />
              </circle>
            )}
          </g>
        );
      })}

      {/* Secondary peer-to-peer ring cross-links */}
      {nodes.map((node, i) => {
        const nextNode = nodes[(i + 1) % nodes.length];
        return (
          <line
            key={`mesh-${i}`}
            x1={node.x}
            y1={node.y}
            x2={nextNode.x}
            y2={nextNode.y}
            stroke="#1e293b"
            strokeWidth="0.75"
            strokeDasharray="2 3"
            strokeOpacity="0.5"
          />
        );
      })}

      {/* CENTER NODE: Origin Agent */}
      <g className="mesh-center-node" style={{ cursor: "default" }}>
        {/* Radar Pulse Animation around origin */}
        <circle cx={cx} cy={cy} r="34" fill="none" stroke="#38bdf8" strokeOpacity="0.3">
          <animate attributeName="r" values="30;50;30" dur="3s" repeatCount="indefinite" />
          <animate attributeName="stroke-opacity" values="0.6;0;0.6" dur="3s" repeatCount="indefinite" />
        </circle>
        <circle
          cx={cx}
          cy={cy}
          r="26"
          fill="#0f172a"
          stroke={getThreatColor(originThreat)}
          strokeWidth="2.5"
          filter={originThreat >= 0.6 ? "url(#glow-red)" : "url(#glow-cyan)"}
        />
        {/* Center Icon/Label */}
        <text
          x={cx}
          y={cy - 2}
          textAnchor="middle"
          fill="#f8fafc"
          fontSize="11"
          fontWeight="bold"
          fontFamily="Inter, sans-serif"
        >
          ORIGIN
        </text>
        <text
          x={cx}
          y={cy + 11}
          textAnchor="middle"
          fill={getThreatColor(originThreat)}
          fontSize="9"
          fontWeight="bold"
          fontFamily="JetBrains Mono, monospace"
        >
          {((originThreat || 0) * 100).toFixed(0)}%
        </text>

        {/* Origin Label Below */}
        <rect
          x={cx - 75}
          y={cy + 34}
          width="150"
          height="18"
          rx="4"
          fill="#0b1019"
          stroke="#1e293b"
        />
        <text
          x={cx}
          y={cy + 46}
          textAnchor="middle"
          fill="#cbd5e1"
          fontSize="9"
          fontFamily="JetBrains Mono, monospace"
        >
          {payload.origin_agent_id.split(" ")[0]}
        </text>
      </g>

      {/* SATELLITE PEER NODES */}
      {nodes.map((node) => {
        const isSelected = selectedPeer?.peer_agent_id === node.peer_agent_id;
        let ringColor = "#64748b";
        let fillBg = "#0b1019";

        if (node.status === "VOTED") {
          ringColor = getThreatColor(node.threat_score);
          fillBg = "#0f172a";
        } else if (node.status === "PENDING") {
          ringColor = "#38bdf8";
        } else if (node.status === "DISCONNECTED") {
          ringColor = "#ef4444";
        }

        return (
          <g
            key={node.peer_agent_id}
            className="mesh-peer-node"
            onClick={() => onSelectPeer(node)}
            style={{ cursor: "pointer" }}
          >
            {/* Selection highlight ring */}
            {isSelected && (
              <circle
                cx={node.x}
                cy={node.y}
                r="24"
                fill="none"
                stroke="#38bdf8"
                strokeWidth="2"
                strokeDasharray="3 3"
              />
            )}

            {/* Peer node circle */}
            <circle
              cx={node.x}
              cy={node.y}
              r="17"
              fill={fillBg}
              stroke={ringColor}
              strokeWidth={isSelected ? "2.5" : "1.8"}
              filter={node.status === "VOTED" ? "url(#glow-cyan)" : "none"}
            />

            {/* Peer Score or Status inside Node */}
            <text
              x={node.x}
              y={node.y + 3}
              textAnchor="middle"
              fill={ringColor}
              fontSize="9"
              fontWeight="bold"
              fontFamily="JetBrains Mono, monospace"
            >
              {node.status === "VOTED"
                ? `${((node.threat_score || 0) * 100).toFixed(0)}%`
                : node.status === "PENDING"
                ? "..."
                : "OFF"}
            </text>

            {/* Label pill outside circle */}
            <g transform={`translate(${node.x - 55}, ${node.y > cy ? node.y + 22 : node.y - 34})`}>
              <rect
                width="110"
                height="16"
                rx="3"
                fill="#0b1019"
                stroke={isSelected ? "#38bdf8" : "#1e293b"}
                strokeWidth="1"
              />
              <text
                x="55"
                y="11"
                textAnchor="middle"
                fill={isSelected ? "#38bdf8" : "#94a3b8"}
                fontSize="8"
                fontFamily="JetBrains Mono, monospace"
              >
                {node.peer_agent_id.split(" ")[0]}
              </text>
            </g>
          </g>
        );
      })}
    </svg>
  );
}
