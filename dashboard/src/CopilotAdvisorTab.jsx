import React, { useState } from 'react';

export default function CopilotAdvisorTab() {
  const [selectedScenario, setSelectedScenario] = useState('ransomware');
  const [targetNode, setTargetNode] = useState('endpoint-windows');
  const [activePlaybookTab, setActivePlaybookTab] = useState('ps'); // 'ps' or 'bash'
  const [investigationResult, setInvestigationResult] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [copied, setCopied] = useState(false);

  const scenarioPresets = {
    ransomware: {
      threat_score: 0.94,
      verdict: 'CRITICAL',
      mitre_technique: 'T1486',
      node_id: 'endpoint-windows',
      sigma_matches: [
        { rule_id: 'sigma-win-ransomware-vssadmin', title: 'VSSADMIN Shadow Copies Deletion' }
      ],
      yara_matches: [
        { rule: 'Ransomware_Readme_Note', description: 'Ransomware AES-256 readme notice pattern' }
      ],
      xai_features: [
        { feature: 'Shannon Entropy (7.98 bits/byte)', importance: 0.42 },
        { feature: 'VSSADMIN Command Execution', importance: 0.38 },
        { feature: 'Rapid Bulk File Renames', importance: 0.14 }
      ]
    },
    ptrace: {
      threat_score: 0.88,
      verdict: 'HIGH',
      mitre_technique: 'T1055',
      node_id: 'endpoint-linux',
      sigma_matches: [
        { rule_id: 'sigma-lnx-ptrace-injection', title: 'Linux Ptrace Process Injection' }
      ],
      yara_matches: [
        { rule: 'Metasploit_Reverse_TCP_Stager', description: 'Metasploit shellcode stager' }
      ],
      xai_features: [
        { feature: 'sys_enter_ptrace attach', importance: 0.45 },
        { feature: 'RWX Memory Map Allocations', importance: 0.35 },
        { feature: 'Non-Standard Child Spawn', importance: 0.12 }
      ]
    },
    bruteforce: {
      threat_score: 0.82,
      verdict: 'HIGH',
      mitre_technique: 'T1110',
      node_id: 'srv-primary',
      sigma_matches: [
        { rule_id: 'sigma-net-hydra-ssh-bruteforce', title: 'Hydra Network SSH Brute Force' }
      ],
      yara_matches: [],
      xai_features: [
        { feature: 'SYN Burst Rate (240 pkts/s)', importance: 0.50 },
        { feature: 'Failed SSH Auth Frequency', importance: 0.35 }
      ]
    }
  };

  const handleRunInvestigation = async (presetKey) => {
    setAnalyzing(true);
    const payload = scenarioPresets[presetKey || selectedScenario];
    try {
      const res = await fetch('/api/copilot/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      setInvestigationResult(data);
    } catch (err) {
      console.error('Failed to run AI investigation', err);
    } finally {
      setAnalyzing(false);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header */}
      <div style={{ background: '#131826', padding: '16px 20px', borderRadius: '12px', border: '1px solid #1e293b' }}>
        <h2 style={{ margin: 0, fontSize: '20px', fontWeight: 'bold', color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{ color: '#818cf8' }}>🤖</span> AI Incident Investigation Copilot & Remediation Playbooks
        </h2>
        <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: '#94a3b8' }}>
          Autonomous synthesis of SHAP feature attributions, Sigma rule triggers, and YARA signatures into executive root-cause analyses and containment scripts.
        </p>
      </div>

      {/* Scenario Selector & Generator Banner */}
      <div style={{ background: '#131826', padding: '18px', borderRadius: '12px', border: '1px solid #1e293b', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <span style={{ fontSize: '13px', fontWeight: '600', color: '#f8fafc' }}>Active Incident Scenario:</span>
          <select
            value={selectedScenario}
            onChange={(e) => {
              setSelectedScenario(e.target.value);
              handleRunInvestigation(e.target.value);
            }}
            style={{ background: '#0b0f19', border: '1px solid #334155', color: '#818cf8', padding: '8px 12px', borderRadius: '8px', fontWeight: 'bold' }}
          >
            <option value="ransomware">⚠️ T1486: Ransomware &amp; Shadow Wipe (endpoint-windows)</option>
            <option value="ptrace">💉 T1055: Ptrace Process Injection (endpoint-linux)</option>
            <option value="bruteforce">🔓 T1110: Hydra SSH Brute Force (srv-primary)</option>
          </select>
        </div>

        <button
          onClick={() => handleRunInvestigation(selectedScenario)}
          disabled={analyzing}
          style={{
            background: 'linear-gradient(135deg, #4f46e5, #818cf8)',
            color: '#ffffff',
            border: 'none',
            borderRadius: '8px',
            padding: '10px 20px',
            fontWeight: 'bold',
            cursor: analyzing ? 'not-allowed' : 'pointer'
          }}
        >
          {analyzing ? 'Synthesizing Incident...' : '✨ Run AI Root Cause Analysis'}
        </button>
      </div>

      {/* Analysis Output Pane */}
      {investigationResult && (
        <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '20px' }}>
          {/* Left Column: Executive Summary & Root Cause */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
            {/* Executive Summary Card */}
            <div style={{ background: '#131826', padding: '18px', borderRadius: '12px', border: '1px solid #1e293b' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                <h3 style={{ margin: 0, fontSize: '15px', color: '#f8fafc', fontWeight: 'bold' }}>
                  📋 Executive Incident Summary
                </h3>
                <span style={{
                  padding: '3px 10px',
                  borderRadius: '12px',
                  fontSize: '11px',
                  fontWeight: 'bold',
                  background: investigationResult.verdict === 'CRITICAL' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(234, 179, 8, 0.2)',
                  color: investigationResult.verdict === 'CRITICAL' ? '#ef4444' : '#eab308'
                }}>
                  {investigationResult.verdict} ({round(investigationResult.threat_score * 100)}%)
                </span>
              </div>
              <p style={{ margin: 0, fontSize: '13px', lineHeight: '1.6', color: '#cbd5e1' }}>
                {investigationResult.executive_summary}
              </p>
            </div>

            {/* Root Cause Analysis */}
            <div style={{ background: '#131826', padding: '18px', borderRadius: '12px', border: '1px solid #1e293b' }}>
              <h3 style={{ margin: '0 0 8px 0', fontSize: '15px', color: '#38bdf8', fontWeight: 'bold' }}>
                🔍 Root Cause & MITRE ATT&CK Attribution
              </h3>
              <p style={{ margin: '0 0 12px 0', fontSize: '13px', color: '#94a3b8' }}>
                <strong>Technique:</strong> {investigationResult.mitre_technique} — {investigationResult.technique_name}
              </p>
              <div style={{ background: '#0b0f19', padding: '12px', borderRadius: '8px', border: '1px solid #1e293b', fontSize: '13px', color: '#f8fafc' }}>
                {investigationResult.root_cause_analysis}
              </div>
            </div>

            {/* Recommended Steps */}
            <div style={{ background: '#131826', padding: '18px', borderRadius: '12px', border: '1px solid #1e293b' }}>
              <h3 style={{ margin: '0 0 12px 0', fontSize: '15px', color: '#10b981', fontWeight: 'bold' }}>
                🛡️ Recommended SOC Containment Steps
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {investigationResult.recommended_containment_steps?.map((step, idx) => (
                  <div key={idx} style={{ display: 'flex', gap: '10px', alignItems: 'flex-start', fontSize: '13px', color: '#cbd5e1' }}>
                    <span style={{ background: '#10b981', color: '#0f172a', width: '20px', height: '20px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '11px', fontWeight: 'bold', flexShrink: 0 }}>
                      {idx + 1}
                    </span>
                    <span>{step}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Right Column: Copyable Remediation Playbook Scripts */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
            <div style={{ background: '#131826', padding: '18px', borderRadius: '12px', border: '1px solid #1e293b' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <h3 style={{ margin: 0, fontSize: '15px', color: '#f8fafc', fontWeight: 'bold' }}>
                  ⚡ Automated Containment Playbooks
                </h3>
                <div style={{ display: 'flex', gap: '6px' }}>
                  <button
                    onClick={() => setActivePlaybookTab('ps')}
                    style={{
                      padding: '4px 10px',
                      borderRadius: '6px',
                      border: 'none',
                      background: activePlaybookTab === 'ps' ? '#38bdf8' : '#1e293b',
                      color: activePlaybookTab === 'ps' ? '#0f172a' : '#94a3b8',
                      fontSize: '11px',
                      fontWeight: 'bold',
                      cursor: 'pointer'
                    }}
                  >
                    PowerShell (Win)
                  </button>
                  <button
                    onClick={() => setActivePlaybookTab('bash')}
                    style={{
                      padding: '4px 10px',
                      borderRadius: '6px',
                      border: 'none',
                      background: activePlaybookTab === 'bash' ? '#10b981' : '#1e293b',
                      color: activePlaybookTab === 'bash' ? '#0f172a' : '#94a3b8',
                      fontSize: '11px',
                      fontWeight: 'bold',
                      cursor: 'pointer'
                    }}
                  >
                    Bash (Linux)
                  </button>
                </div>
              </div>

              <div style={{ position: 'relative' }}>
                <pre style={{
                  background: '#0b0f19',
                  border: '1px solid #1e293b',
                  borderRadius: '8px',
                  padding: '14px',
                  color: activePlaybookTab === 'ps' ? '#38bdf8' : '#86efac',
                  fontSize: '12px',
                  lineHeight: '1.5',
                  overflowX: 'auto',
                  margin: 0,
                  fontFamily: 'monospace'
                }}>
                  {activePlaybookTab === 'ps'
                    ? investigationResult.playbooks?.powershell_script
                    : investigationResult.playbooks?.bash_script}
                </pre>

                <button
                  onClick={() => copyToClipboard(activePlaybookTab === 'ps' ? investigationResult.playbooks?.powershell_script : investigationResult.playbooks?.bash_script)}
                  style={{
                    position: 'absolute',
                    top: '10px',
                    right: '10px',
                    background: '#1e293b',
                    color: '#f8fafc',
                    border: '1px solid #334155',
                    borderRadius: '6px',
                    padding: '4px 8px',
                    fontSize: '11px',
                    cursor: 'pointer'
                  }}
                >
                  {copied ? '✓ Copied' : '📋 Copy Script'}
                </button>
              </div>
            </div>

            {/* Forensic Checklist Card */}
            <div style={{ background: '#131826', padding: '18px', borderRadius: '12px', border: '1px solid #1e293b' }}>
              <h3 style={{ margin: '0 0 10px 0', fontSize: '15px', color: '#eab308', fontWeight: 'bold' }}>
                📝 Evidence Preservation Checklist
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {investigationResult.forensic_checklist?.map((item, idx) => (
                  <label key={idx} style={{ display: 'flex', gap: '10px', alignItems: 'center', fontSize: '12px', color: '#cbd5e1', cursor: 'pointer' }}>
                    <input type="checkbox" defaultChecked={false} style={{ accentColor: '#eab308' }} />
                    <span>{item}</span>
                  </label>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function round(val) {
  return Math.round(val);
}
