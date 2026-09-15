import React, { useState, useEffect } from 'react';

export default function RulesEngineTab() {
  const [activeTab, setActiveTab] = useState('sigma'); // 'sigma' or 'yara'
  const [sigmaRules, setSigmaRules] = useState([]);
  const [yaraRules, setYaraRules] = useState([]);
  const [loading, setLoading] = useState(false);
  const [statusMsg, setStatusMsg] = useState(null);

  // Sigma Test Sandbox State
  const [sigmaEventJson, setSigmaEventJson] = useState(`{
  "event_type": "process_creation",
  "image": "vssadmin.exe",
  "command_line": "vssadmin.exe delete shadows /all /quiet",
  "pid": 4120
}`);
  const [sigmaEvalResult, setSigmaEvalResult] = useState(null);

  // YARA Test Sandbox State
  const [yaraPayloadText, setYaraPayloadText] = useState('Attention! Your files have been encrypted with AES-256. Send Bitcoin to address...');
  const [yaraScanResult, setYaraScanResult] = useState(null);

  // Custom Sigma Rule Editor State
  const [customSigmaYaml, setCustomSigmaYaml] = useState(`id: custom-win-suspicious-powershell
title: Suspicious PowerShell Download Cradle
level: high
description: Detects powershell webclient download cradle execution
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - 'DownloadString'
      - 'Net.WebClient'
  condition: selection`);

  // Custom YARA Rule State
  const [customYaraName, setCustomYaraName] = useState('CobaltStrike_Beacon_Pattern');
  const [customYaraStrings, setCustomYaraStrings] = useState('{\n  "$hdr": "{ 4D 5A 90 00 }",\n  "$pipe": "\\\\\\\\.\\\\pipe\\\\msagent_"\n}');
  const [customYaraCondition, setCustomYaraCondition] = useState('any of them');

  const fetchRules = async () => {
    setLoading(true);
    try {
      const [sRes, yRes] = await Promise.all([
        fetch('/api/rules/sigma'),
        fetch('/api/rules/yara')
      ]);
      const sData = await sRes.json();
      const yData = await yRes.json();
      setSigmaRules(sData.rules || []);
      setYaraRules(yData.rules || []);
    } catch (err) {
      setStatusMsg({ type: 'error', text: 'Failed to load rules: ' + err.message });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleEvaluateSigma = async () => {
    try {
      const parsed = JSON.parse(sigmaEventJson);
      const res = await fetch('/api/rules/sigma/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(parsed)
      });
      const data = await res.json();
      setSigmaEvalResult(data);
    } catch (err) {
      setSigmaEvalResult({ error: 'Invalid JSON or Request Error: ' + err.message });
    }
  };

  const handleScanYara = async () => {
    try {
      const res = await fetch('/api/rules/yara/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: yaraPayloadText })
      });
      const data = await res.json();
      setYaraScanResult(data);
    } catch (err) {
      setYaraScanResult({ error: 'Scan error: ' + err.message });
    }
  };

  const handleCompileSigma = async () => {
    try {
      const res = await fetch('/api/rules/sigma/compile', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ yaml: customSigmaYaml })
      });
      const data = await res.json();
      setStatusMsg({ type: 'success', text: `Compiled Sigma rule: ${data.title} (${data.rule_id})` });
      fetchRules();
    } catch (err) {
      setStatusMsg({ type: 'error', text: 'Failed to compile Sigma rule: ' + err.message });
    }
  };

  const handleCompileYara = async () => {
    try {
      const parsedStrings = JSON.parse(customYaraStrings);
      const res = await fetch('/api/rules/yara/compile', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: customYaraName,
          strings_dict: parsedStrings,
          condition: customYaraCondition,
          meta: { severity: 'HIGH', author: 'SOC Operator' }
        })
      });
      const data = await res.json();
      setStatusMsg({ type: 'success', text: `Compiled YARA rule: ${data.rule_name}` });
      fetchRules();
    } catch (err) {
      setStatusMsg({ type: 'error', text: 'Failed to compile YARA rule: ' + err.message });
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: '#131826', padding: '16px 20px', borderRadius: '12px', border: '1px solid #1e293b' }}>
        <div>
          <h2 style={{ margin: 0, fontSize: '20px', fontWeight: 'bold', color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{ color: '#38bdf8' }}>🛡️</span> Sigma & YARA Interactive Threat Rules Engine
          </h2>
          <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: '#94a3b8' }}>
            Deterministic pattern matching & SIEM-compatible signature translation complementing AEGIS 6-model ML fusion.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            onClick={() => setActiveTab('sigma')}
            style={{
              padding: '8px 16px',
              borderRadius: '8px',
              border: 'none',
              background: activeTab === 'sigma' ? '#38bdf8' : '#1e293b',
              color: activeTab === 'sigma' ? '#0f172a' : '#94a3b8',
              fontWeight: '600',
              cursor: 'pointer',
              transition: 'all 0.2s'
            }}
          >
            Sigma YAML Engine ({sigmaRules.length})
          </button>
          <button
            onClick={() => setActiveTab('yara')}
            style={{
              padding: '8px 16px',
              borderRadius: '8px',
              border: 'none',
              background: activeTab === 'yara' ? '#a855f7' : '#1e293b',
              color: activeTab === 'yara' ? '#0f172a' : '#94a3b8',
              fontWeight: '600',
              cursor: 'pointer',
              transition: 'all 0.2s'
            }}
          >
            In-Memory YARA Engine ({yaraRules.length})
          </button>
        </div>
      </div>

      {statusMsg && (
        <div style={{
          padding: '12px 16px',
          borderRadius: '8px',
          background: statusMsg.type === 'error' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(34, 197, 94, 0.15)',
          border: `1px solid ${statusMsg.type === 'error' ? '#ef4444' : '#22c55e'}`,
          color: statusMsg.type === 'error' ? '#fca5a5' : '#86efac',
          fontSize: '13px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <span>{statusMsg.text}</span>
          <button onClick={() => setStatusMsg(null)} style={{ background: 'transparent', border: 'none', color: 'inherit', cursor: 'pointer' }}>✕</button>
        </div>
      )}

      {/* SIGMA TAB */}
      {activeTab === 'sigma' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '20px' }}>
          {/* Left Column: Active Rules & Rule Creator */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <div style={{ background: '#131826', padding: '18px', borderRadius: '12px', border: '1px solid #1e293b' }}>
              <h3 style={{ margin: '0 0 12px 0', fontSize: '15px', color: '#38bdf8', fontWeight: '600' }}>
                Active Pre-Compiled Sigma Rules
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', maxHeight: '280px', overflowY: 'auto' }}>
                {sigmaRules.map((rule) => (
                  <div key={rule.id} style={{ background: '#0b0f19', padding: '12px', borderRadius: '8px', border: '1px solid #1e293b' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontWeight: '600', color: '#f8fafc', fontSize: '13px' }}>{rule.title}</span>
                      <span style={{
                        padding: '2px 8px',
                        borderRadius: '12px',
                        fontSize: '10px',
                        fontWeight: 'bold',
                        background: rule.level === 'critical' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(234, 179, 8, 0.2)',
                        color: rule.level === 'critical' ? '#ef4444' : '#eab308'
                      }}>
                        {rule.level?.toUpperCase()}
                      </span>
                    </div>
                    <p style={{ margin: '4px 0 6px 0', fontSize: '12px', color: '#94a3b8' }}>{rule.description}</p>
                    <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                      {rule.tags?.map((t, idx) => (
                        <span key={idx} style={{ background: '#1e293b', padding: '2px 6px', borderRadius: '4px', fontSize: '10px', color: '#38bdf8' }}>
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Custom Sigma YAML Compiler */}
            <div style={{ background: '#131826', padding: '18px', borderRadius: '12px', border: '1px solid #1e293b' }}>
              <h3 style={{ margin: '0 0 10px 0', fontSize: '15px', color: '#f8fafc', fontWeight: '600' }}>
                Compile Custom Sigma Rule (YAML)
              </h3>
              <textarea
                value={customSigmaYaml}
                onChange={(e) => setCustomSigmaYaml(e.target.value)}
                rows={9}
                style={{
                  width: '100%',
                  background: '#0b0f19',
                  border: '1px solid #334155',
                  color: '#38bdf8',
                  fontFamily: 'monospace',
                  fontSize: '12px',
                  borderRadius: '8px',
                  padding: '10px',
                  boxSizing: 'border-box',
                  resize: 'vertical'
                }}
              />
              <button
                onClick={handleCompileSigma}
                style={{
                  marginTop: '10px',
                  background: 'linear-gradient(135deg, #0284c7, #38bdf8)',
                  color: '#0f172a',
                  border: 'none',
                  borderRadius: '6px',
                  padding: '8px 16px',
                  fontWeight: '600',
                  cursor: 'pointer'
                }}
              >
                Compile & Activate Rule
              </button>
            </div>
          </div>

          {/* Right Column: Live Event Testing Sandbox */}
          <div style={{ background: '#131826', padding: '18px', borderRadius: '12px', border: '1px solid #1e293b', display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <h3 style={{ margin: 0, fontSize: '15px', color: '#f8fafc', fontWeight: '600' }}>
              Sigma Rule Evaluation Sandbox
            </h3>
            <p style={{ margin: 0, fontSize: '12px', color: '#94a3b8' }}>
              Paste an incoming eBPF/ETW JSON event to evaluate against active Sigma predicate matchers.
            </p>
            <textarea
              value={sigmaEventJson}
              onChange={(e) => setSigmaEventJson(e.target.value)}
              rows={8}
              style={{
                width: '100%',
                background: '#0b0f19',
                border: '1px solid #334155',
                color: '#86efac',
                fontFamily: 'monospace',
                fontSize: '12px',
                borderRadius: '8px',
                padding: '10px',
                boxSizing: 'border-box'
              }}
            />
            <button
              onClick={handleEvaluateSigma}
              style={{
                background: '#10b981',
                color: '#0f172a',
                border: 'none',
                borderRadius: '6px',
                padding: '10px',
                fontWeight: 'bold',
                cursor: 'pointer'
              }}
            >
              Evaluate Event Against Sigma Engine
            </button>

            {sigmaEvalResult && (
              <div style={{ background: '#0b0f19', padding: '12px', borderRadius: '8px', border: '1px solid #1e293b' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                  <span style={{ fontSize: '13px', fontWeight: 'bold', color: '#f8fafc' }}>Evaluation Verdict:</span>
                  <span style={{
                    padding: '2px 8px',
                    borderRadius: '12px',
                    fontSize: '11px',
                    fontWeight: 'bold',
                    background: sigmaEvalResult.matched ? 'rgba(239, 68, 68, 0.2)' : 'rgba(34, 197, 94, 0.2)',
                    color: sigmaEvalResult.matched ? '#ef4444' : '#22c55e'
                  }}>
                    {sigmaEvalResult.matched ? `MATCHED (${sigmaEvalResult.match_count} Rule Hits)` : 'NO MATCH (Clean)'}
                  </span>
                </div>
                {sigmaEvalResult.matches?.map((m, i) => (
                  <div key={i} style={{ padding: '6px', borderBottom: '1px solid #1e293b', fontSize: '12px' }}>
                    <span style={{ color: '#ef4444', fontWeight: 'bold' }}>• {m.title}</span>
                    <span style={{ color: '#94a3b8', marginLeft: '8px' }}>({m.rule_id})</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* YARA TAB */}
      {activeTab === 'yara' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '20px' }}>
          {/* Left Column: Active YARA Signatures & Creator */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <div style={{ background: '#131826', padding: '18px', borderRadius: '12px', border: '1px solid #1e293b' }}>
              <h3 style={{ margin: '0 0 12px 0', fontSize: '15px', color: '#c084fc', fontWeight: '600' }}>
                Active In-Memory YARA Signatures
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', maxHeight: '280px', overflowY: 'auto' }}>
                {yaraRules.map((rule) => (
                  <div key={rule.name} style={{ background: '#0b0f19', padding: '12px', borderRadius: '8px', border: '1px solid #1e293b' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontWeight: '600', color: '#f8fafc', fontSize: '13px' }}>{rule.name}</span>
                      <span style={{ background: '#1e293b', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', color: '#c084fc' }}>
                        {rule.string_count} strings
                      </span>
                    </div>
                    <p style={{ margin: '4px 0 0 0', fontSize: '11px', color: '#94a3b8', fontFamily: 'monospace' }}>
                      condition: {rule.condition}
                    </p>
                  </div>
                ))}
              </div>
            </div>

            {/* Custom YARA Rule Compiler */}
            <div style={{ background: '#131826', padding: '18px', borderRadius: '12px', border: '1px solid #1e293b' }}>
              <h3 style={{ margin: '0 0 10px 0', fontSize: '15px', color: '#f8fafc', fontWeight: '600' }}>
                Add Custom YARA Rule
              </h3>
              <input
                type="text"
                value={customYaraName}
                onChange={(e) => setCustomYaraName(e.target.value)}
                placeholder="Rule Name"
                style={{ width: '100%', marginBottom: '8px', background: '#0b0f19', border: '1px solid #334155', color: '#f8fafc', padding: '8px', borderRadius: '6px' }}
              />
              <textarea
                value={customYaraStrings}
                onChange={(e) => setCustomYaraStrings(e.target.value)}
                rows={4}
                placeholder='{"$a": "bad_string", "$hex": "{ 4D 5A ?? 00 }"}'
                style={{ width: '100%', background: '#0b0f19', border: '1px solid #334155', color: '#c084fc', fontFamily: 'monospace', fontSize: '12px', borderRadius: '6px', padding: '8px', boxSizing: 'border-box' }}
              />
              <button
                onClick={handleCompileYara}
                style={{
                  marginTop: '10px',
                  background: 'linear-gradient(135deg, #7e22ce, #a855f7)',
                  color: '#ffffff',
                  border: 'none',
                  borderRadius: '6px',
                  padding: '8px 16px',
                  fontWeight: '600',
                  cursor: 'pointer'
                }}
              >
                Compile YARA Signature
              </button>
            </div>
          </div>

          {/* Right Column: Live Payload Scanner */}
          <div style={{ background: '#131826', padding: '18px', borderRadius: '12px', border: '1px solid #1e293b', display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <h3 style={{ margin: 0, fontSize: '15px', color: '#f8fafc', fontWeight: '600' }}>
              In-Memory YARA Byte Scanner
            </h3>
            <p style={{ margin: 0, fontSize: '12px', color: '#94a3b8' }}>
              Test suspicious text, dropper scripts, or binary fragments against all loaded YARA patterns.
            </p>
            <textarea
              value={yaraPayloadText}
              onChange={(e) => setYaraPayloadText(e.target.value)}
              rows={8}
              style={{
                width: '100%',
                background: '#0b0f19',
                border: '1px solid #334155',
                color: '#e2e8f0',
                fontFamily: 'monospace',
                fontSize: '12px',
                borderRadius: '8px',
                padding: '10px',
                boxSizing: 'border-box'
              }}
            />
            <button
              onClick={handleScanYara}
              style={{
                background: '#a855f7',
                color: '#ffffff',
                border: 'none',
                borderRadius: '6px',
                padding: '10px',
                fontWeight: 'bold',
                cursor: 'pointer'
              }}
            >
              Scan Payload Buffer
            </button>

            {yaraScanResult && (
              <div style={{ background: '#0b0f19', padding: '12px', borderRadius: '8px', border: '1px solid #1e293b' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                  <span style={{ fontSize: '13px', fontWeight: 'bold', color: '#f8fafc' }}>Scan Result:</span>
                  <span style={{
                    padding: '2px 8px',
                    borderRadius: '12px',
                    fontSize: '11px',
                    fontWeight: 'bold',
                    background: yaraScanResult.is_malicious ? 'rgba(239, 68, 68, 0.2)' : 'rgba(34, 197, 94, 0.2)',
                    color: yaraScanResult.is_malicious ? '#ef4444' : '#22c55e'
                  }}>
                    {yaraScanResult.is_malicious ? `DETECTED (${yaraScanResult.matches?.length} Signature Hits)` : 'CLEAN (No Signatures)'}
                  </span>
                </div>
                {yaraScanResult.matches?.map((m, i) => (
                  <div key={i} style={{ padding: '6px', borderBottom: '1px solid #1e293b', fontSize: '12px', color: '#fca5a5' }}>
                    <strong>• {m.rule}</strong> — {m.description || m.meta?.category || 'Malicious Pattern'}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
