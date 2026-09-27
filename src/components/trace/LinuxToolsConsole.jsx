// CyberTrace AI — Linux Tools Forensic Console
// =============================================================================
// Interactive terminal & automated diagnostic workbench for Linux network CLI tools:
//   - dig (DNS A/MX/TXT/SPF/DMARC inspection)
//   - whois (Domain registrar & age intelligence)
//   - host (Reverse DNS PTR lookups)
//   - traceroute (Route hop analysis)
//   - ping (Latency & reachability)
// =============================================================================

import React, { useState, useEffect } from 'react';
import { executeLinuxTool, fetchToolCapabilities, checkBackendHealth } from '../../services/apiClient';

export default function LinuxToolsConsole({ parsedData }) {
  const [capabilities, setCapabilities] = useState(null);
  const [backendStatus, setBackendStatus] = useState({ online: false, checking: true });
  const [selectedTool, setSelectedTool] = useState('dig');
  const [digType, setDigType] = useState('SPF');
  const [targetInput, setTargetInput] = useState('');
  const [executing, setExecuting] = useState(false);
  const [commandHistory, setCommandHistory] = useState([]);
  const [activeOutput, setActiveOutput] = useState(null);

  // Suggested targets from parsed email
  const senderDomain = parsedData?.domainIntelligence?.domain ||
    parsedData?.metadata?.from?.match(/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/)?.[1] ||
    'paypa1-support.com';

  const originIp = parsedData?.hopChain?.[parsedData?.hopChain?.length - 1]?.sourceIp ||
    parsedData?.traceResult?.geo?.ip ||
    '154.16.63.102';

  // Load capabilities & check backend on mount
  useEffect(() => {
    async function init() {
      const health = await checkBackendHealth();
      setBackendStatus({ online: health.online, checking: false, info: health });
      if (health.online) {
        const caps = await fetchToolCapabilities();
        setCapabilities(caps);
      }
    }
    init();
  }, []);

  // Set default target
  useEffect(() => {
    if (!targetInput) {
      setTargetInput(selectedTool === 'host' || selectedTool === 'ping' || selectedTool === 'traceroute' ? originIp : senderDomain);
    }
  }, [selectedTool, senderDomain, originIp]);

  const handleExecute = async (overrideTool, overrideTarget, overrideType) => {
    const tool = overrideTool || selectedTool;
    const target = overrideTarget || targetInput;
    const type = overrideType || digType;

    if (!target) return;

    setExecuting(true);
    const startTs = new Date().toLocaleTimeString();

    const cmdStr =
      tool === 'dig'
        ? `dig +short ${target} ${type}`
        : tool === 'host'
        ? `host ${target}`
        : tool === 'whois'
        ? `whois ${target}`
        : tool === 'traceroute'
        ? `traceroute -m 10 ${target}`
        : `ping -c 3 ${target}`;

    const res = await executeLinuxTool(tool, target, type);
    setExecuting(false);

    const entry = {
      id: Date.now(),
      timestamp: startTs,
      tool,
      target,
      type,
      commandString: cmdStr,
      data: res,
    };

    setCommandHistory((prev) => [entry, ...prev]);
    setActiveOutput(entry);
  };

  return (
    <div
      className="panel fade-in"
      style={{
        background: '#ffffff',
        border: '1px solid #cbd5e1',
        borderRadius: 'var(--radius-sm)',
        boxShadow: '0 1px 4px rgba(15, 23, 42, 0.04)',
        display: 'flex',
        flexDirection: 'column',
        gap: 'var(--sp-4)',
        padding: 'var(--sp-5)',
      }}
    >
      {/* Header & Status */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 12,
          paddingBottom: 'var(--sp-3)',
          borderBottom: '1px solid #e2e8f0',
        }}
      >
        <div>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#0284c7', letterSpacing: '0.06em', textTransform: 'uppercase' }}>
            LINUX NETWORK FORENSICS WORKBENCH
          </div>
          <h2 style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', margin: '2px 0 0' }}>
            CLI Diagnostic Engine (dig, whois, host, traceroute, ping)
          </h2>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              padding: '4px 10px',
              borderRadius: 20,
              fontSize: 11,
              fontWeight: 700,
              background: backendStatus.online ? '#f0fdf4' : '#fef2f2',
              color: backendStatus.online ? '#16a34a' : '#dc2626',
              border: `1px solid ${backendStatus.online ? '#bbf7d0' : '#fecaca'}`,
            }}
          >
            <span>{backendStatus.online ? '●' : '○'}</span>
            <span>{backendStatus.online ? 'BACKEND ONLINE (:3001)' : 'BACKEND OFFLINE'}</span>
          </div>

          {capabilities && (
            <div
              style={{
                fontSize: 10,
                padding: '4px 8px',
                borderRadius: 4,
                background: '#f8fafc',
                border: '1px solid #cbd5e1',
                color: '#475569',
              }}
            >
              Mode: <strong>{capabilities.mode}</strong>
            </div>
          )}
        </div>
      </div>

      {/* Quick Launch Preset Actions */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        <div style={{ fontSize: 10.5, fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
          AUTOMATED FORENSIC SHORTCUTS FOR CURRENT EMAIL:
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button
            onClick={() => handleExecute('dig', senderDomain, 'SPF')}
            disabled={executing}
            style={{
              background: '#f0f9ff',
              border: '1px solid #bae6fd',
              borderRadius: 4,
              padding: '6px 10px',
              fontSize: 11,
              fontWeight: 700,
              color: '#0369a1',
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            <span>📜</span> dig SPF ({senderDomain})
          </button>

          <button
            onClick={() => handleExecute('dig', senderDomain, 'DMARC')}
            disabled={executing}
            style={{
              background: '#f0f9ff',
              border: '1px solid #bae6fd',
              borderRadius: 4,
              padding: '6px 10px',
              fontSize: 11,
              fontWeight: 700,
              color: '#0369a1',
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            <span>🛡️</span> dig DMARC ({senderDomain})
          </button>

          <button
            onClick={() => handleExecute('whois', senderDomain)}
            disabled={executing}
            style={{
              background: '#fefce8',
              border: '1px solid #fef08a',
              borderRadius: 4,
              padding: '6px 10px',
              fontSize: 11,
              fontWeight: 700,
              color: '#854d0e',
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            <span>🏛️</span> whois Domain Age ({senderDomain})
          </button>

          <button
            onClick={() => handleExecute('host', originIp)}
            disabled={executing}
            style={{
              background: '#f5f3ff',
              border: '1px solid #ddd6fe',
              borderRadius: 4,
              padding: '6px 10px',
              fontSize: 11,
              fontWeight: 700,
              color: '#6d28d9',
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            <span>🔄</span> host PTR ({originIp})
          </button>

          <button
            onClick={() => handleExecute('ping', originIp)}
            disabled={executing}
            style={{
              background: '#f8fafc',
              border: '1px solid #cbd5e1',
              borderRadius: 4,
              padding: '6px 10px',
              fontSize: 11,
              fontWeight: 700,
              color: '#334155',
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            <span>⚡</span> ping RTT ({originIp})
          </button>
        </div>
      </div>

      {/* Interactive Command Construction Bar */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: selectedTool === 'dig' ? '120px 100px 1fr auto' : '120px 1fr auto',
          gap: 8,
          alignItems: 'center',
          padding: '12px 14px',
          background: '#f8fafc',
          border: '1px solid #e2e8f0',
          borderRadius: 6,
        }}
      >
        {/* Tool Select */}
        <div>
          <label style={{ display: 'block', fontSize: 10, fontWeight: 700, color: '#64748b', marginBottom: 2 }}>
            TOOL:
          </label>
          <select
            value={selectedTool}
            onChange={(e) => {
              const val = e.target.value;
              setSelectedTool(val);
              if (val === 'host' || val === 'ping' || val === 'traceroute') {
                setTargetInput(originIp);
              } else {
                setTargetInput(senderDomain);
              }
            }}
            className="mono"
            style={{
              width: '100%',
              padding: '6px 8px',
              fontSize: 11,
              fontWeight: 700,
              borderRadius: 4,
              border: '1px solid #cbd5e1',
              background: '#ffffff',
            }}
          >
            <option value="dig">dig (DNS)</option>
            <option value="whois">whois (RDAP)</option>
            <option value="host">host (PTR)</option>
            <option value="traceroute">traceroute</option>
            <option value="ping">ping (RTT)</option>
          </select>
        </div>

        {/* Record Type for dig */}
        {selectedTool === 'dig' && (
          <div>
            <label style={{ display: 'block', fontSize: 10, fontWeight: 700, color: '#64748b', marginBottom: 2 }}>
              RECORD:
            </label>
            <select
              value={digType}
              onChange={(e) => setDigType(e.target.value)}
              className="mono"
              style={{
                width: '100%',
                padding: '6px 8px',
                fontSize: 11,
                fontWeight: 700,
                borderRadius: 4,
                border: '1px solid #cbd5e1',
                background: '#ffffff',
              }}
            >
              <option value="SPF">SPF (TXT)</option>
              <option value="DMARC">DMARC</option>
              <option value="MX">MX</option>
              <option value="TXT">TXT</option>
              <option value="A">A</option>
              <option value="AAAA">AAAA</option>
              <option value="NS">NS</option>
            </select>
          </div>
        )}

        {/* Target Input */}
        <div>
          <label style={{ display: 'block', fontSize: 10, fontWeight: 700, color: '#64748b', marginBottom: 2 }}>
            TARGET DOMAIN / IP:
          </label>
          <input
            type="text"
            value={targetInput}
            onChange={(e) => setTargetInput(e.target.value)}
            placeholder="e.g. domain.com or 198.51.100.1"
            className="mono"
            style={{
              width: '100%',
              padding: '6px 10px',
              fontSize: 12,
              borderRadius: 4,
              border: '1px solid #cbd5e1',
              background: '#ffffff',
              boxSizing: 'border-box',
            }}
          />
        </div>

        {/* Execute Button */}
        <div style={{ alignSelf: 'flex-end' }}>
          <button
            onClick={() => handleExecute()}
            disabled={executing}
            style={{
              padding: '7px 18px',
              background: executing ? '#94a3b8' : '#0284c7',
              color: '#ffffff',
              border: 'none',
              borderRadius: 4,
              fontSize: 12,
              fontWeight: 800,
              cursor: executing ? 'not-allowed' : 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            {executing ? (
              <>
                <span className="spin">⟳</span> Running...
              </>
            ) : (
              <>
                <span>▶</span> Run Tool
              </>
            )}
          </button>
        </div>
      </div>

      {/* Terminal Output Screen */}
      <div
        style={{
          background: '#090d16',
          border: '1px solid #1e293b',
          borderRadius: 6,
          overflow: 'hidden',
          display: 'flex',
          flexDirection: 'column',
          boxShadow: 'inset 0 2px 10px rgba(0,0,0,0.5)',
        }}
      >
        {/* Terminal Titlebar */}
        <div
          style={{
            padding: '8px 12px',
            background: '#0f172a',
            borderBottom: '1px solid #1e293b',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div style={{ display: 'flex', gap: 5 }}>
              <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#ef4444' }}></div>
              <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#f59e0b' }}></div>
              <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#10b981' }}></div>
            </div>
            <span className="mono" style={{ fontSize: 11, color: '#94a3b8', fontWeight: 600 }}>
              cybertrace-analyst@forensics-sandbox:~$
            </span>
          </div>

          {activeOutput && (
            <div className="mono" style={{ fontSize: 10, color: '#38bdf8' }}>
              Execution time: {activeOutput.data?.elapsedMs || 0}ms
            </div>
          )}
        </div>

        {/* Terminal Content Body */}
        <div
          className="mono"
          style={{
            padding: '16px 18px',
            minHeight: 220,
            maxHeight: 400,
            overflowY: 'auto',
            fontSize: 12,
            lineHeight: 1.6,
            color: '#e2e8f0',
          }}
        >
          {activeOutput ? (
            <div>
              {/* Prompt line */}
              <div style={{ color: '#38bdf8', marginBottom: 10, display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ color: '#10b981' }}>analyst@cybertrace:~$</span>
                <span>{activeOutput.commandString}</span>
              </div>

              {/* Formatted Output Highlights */}
              {activeOutput.tool === 'dig' && activeOutput.data?.result && (
                <div style={{ marginBottom: 12, padding: '8px 12px', background: 'rgba(15, 23, 42, 0.7)', borderRadius: 4, border: '1px solid #334155' }}>
                  {activeOutput.data.result.spfRecord && (
                    <div style={{ color: '#86efac' }}>
                      <strong>[SPF RECORD FOUND]</strong> {activeOutput.data.result.spfRecord}
                    </div>
                  )}
                  {activeOutput.data.result.dmarcRecord && (
                    <div style={{ color: '#86efac', marginTop: 4 }}>
                      <strong>[DMARC POLICY]</strong> {activeOutput.data.result.policy?.toUpperCase()} | {activeOutput.data.result.dmarcRecord}
                    </div>
                  )}
                  {activeOutput.data.result.mxRecords && (
                    <div style={{ marginTop: 4 }}>
                      <strong style={{ color: '#38bdf8' }}>[MX SERVERS]:</strong>
                      {activeOutput.data.result.mxRecords.map((m, i) => (
                        <div key={i} style={{ paddingLeft: 12, color: '#cbd5e1' }}>
                          Priority {m.priority}: {m.host}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {activeOutput.tool === 'whois' && activeOutput.data?.result && (
                <div style={{ marginBottom: 12, padding: '8px 12px', background: 'rgba(15, 23, 42, 0.7)', borderRadius: 4, border: '1px solid #334155' }}>
                  <div style={{ color: '#fef08a' }}>
                    <strong>REGISTRAR:</strong> {activeOutput.data.result.registrar}
                  </div>
                  <div style={{ color: '#86efac', marginTop: 2 }}>
                    <strong>AGE CATEGORY:</strong> {activeOutput.data.result.ageCategory} ({activeOutput.data.result.domainAgeDays != null ? `${activeOutput.data.result.domainAgeDays} days old` : 'Unknown'})
                  </div>
                  <div style={{ color: '#94a3b8', fontSize: 11, marginTop: 2 }}>
                    Created: {activeOutput.data.result.created || 'N/A'} | Expires: {activeOutput.data.result.expires || 'N/A'}
                  </div>
                </div>
              )}

              {activeOutput.tool === 'host' && activeOutput.data?.result && (
                <div style={{ marginBottom: 12, padding: '8px 12px', background: 'rgba(15, 23, 42, 0.7)', borderRadius: 4, border: '1px solid #334155' }}>
                  <div style={{ color: activeOutput.data.result.hasPtr ? '#86efac' : '#f87171' }}>
                    <strong>PTR HOSTNAME:</strong> {activeOutput.data.result.hostname || 'NO PTR RECORD (REVERSE DNS MISMATCH)'}
                  </div>
                </div>
              )}

              {/* Raw Tool Output */}
              <div style={{ color: '#94a3b8', fontSize: 11, textTransform: 'uppercase', marginBottom: 4 }}>
                ── RAW COMMAND STREAM OUTPUT ──
              </div>
              <pre
                style={{
                  margin: 0,
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                  color: '#cbd5e1',
                  fontFamily: 'inherit',
                  fontSize: 11.5,
                }}
              >
                {activeOutput.data?.result?.raw ||
                  (Array.isArray(activeOutput.data?.result?.records)
                    ? activeOutput.data.result.records.join('\n')
                    : JSON.stringify(activeOutput.data?.result, null, 2)) ||
                  activeOutput.data?.error ||
                  'No output returned.'}
              </pre>
            </div>
          ) : (
            <div style={{ color: '#64748b', textAlign: 'center', padding: '40px 0' }}>
              <div style={{ fontSize: 24, marginBottom: 8 }}>⚡</div>
              <div>Select a tool above and click <strong>"Run Tool"</strong> or click any of the shortcut buttons.</div>
              <div style={{ fontSize: 11, marginTop: 4, color: '#475569' }}>
                All executions run directly against live network infrastructure via the CyberTrace Linux forensic backend.
              </div>
            </div>
          )}
        </div>
      </div>

      {/* History Log Strip */}
      {commandHistory.length > 1 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <div style={{ fontSize: 10.5, fontWeight: 700, color: '#64748b', textTransform: 'uppercase' }}>
            SESSION EXECUTION HISTORY ({commandHistory.length}):
          </div>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {commandHistory.map((item) => (
              <button
                key={item.id}
                onClick={() => setActiveOutput(item)}
                style={{
                  background: activeOutput?.id === item.id ? '#0f172a' : '#f8fafc',
                  color: activeOutput?.id === item.id ? '#38bdf8' : '#334155',
                  border: '1px solid #cbd5e1',
                  borderRadius: 4,
                  padding: '3px 8px',
                  fontSize: 10.5,
                  cursor: 'pointer',
                  fontFamily: 'monospace',
                }}
              >
                {item.commandString}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
