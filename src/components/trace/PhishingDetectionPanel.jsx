import React, { useState } from 'react';

/**
 * PhishingDetectionPanel
 * ---------------------------------------------------------------------------
 * Comprehensive Phishing, Spoofing, and Email-Fraud Detection Dashboard.
 * Displays:
 *  - Master threat score gauge and severity badge
 *  - Filterable signal matrix (Phishing, Spoofing, Fraud, All) with evidence tiers
 *  - Extracted Indicators of Compromise (IoCs) with clipboard copy
 *  - MITRE ATT&CK techniques mapping
 *  - Actionable remediation and containment directives
 *  - Evidence provenance breakdown (Observed Facts vs Probable Findings vs Unverified)
 */
export default function PhishingDetectionPanel({ detection, parsedData }) {
  const [activeSignalCategory, setActiveSignalCategory] = useState('ALL');
  const [selectedSignal, setSelectedSignal] = useState(null);
  const [iocFilter, setIocFilter] = useState('ALL');
  const [copiedIoc, setCopiedIoc] = useState(null);
  const [copiedAllIocs, setCopiedAllIocs] = useState(false);

  // Fallback to safe defaults if detection is not yet computed
  const data = detection || parsedData?.phishingDetection || {
    overallThreatScore: 0,
    threatCategory: 'ANALYSIS PENDING',
    threatSeverity: 'CLEAN',
    phishingSignals: [],
    spoofingSignals: [],
    fraudSignals: [],
    iocList: [],
    evidenceTiers: { observedFacts: [], probableFindings: [], unverified: [] },
    detectionSummary: 'Forensic evaluation is running or no data was loaded.',
    mitreTechniques: [],
    recommendedActions: [],
    signalCount: 0,
  };

  const {
    overallThreatScore = 0,
    threatCategory = 'CLEAN',
    threatSeverity = 'CLEAN',
    phishingSignals = [],
    spoofingSignals = [],
    fraudSignals = [],
    iocList = [],
    evidenceTiers = { observedFacts: [], probableFindings: [], unverified: [] },
    detectionSummary = '',
    mitreTechniques = [],
    recommendedActions = [],
  } = data;

  const allSignals = [...phishingSignals, ...spoofingSignals, ...fraudSignals];

  const filteredSignals =
    activeSignalCategory === 'ALL'
      ? allSignals
      : activeSignalCategory === 'PHISHING'
      ? phishingSignals
      : activeSignalCategory === 'SPOOFING'
      ? spoofingSignals
      : fraudSignals;

  const filteredIocs =
    iocFilter === 'ALL'
      ? iocList
      : iocList.filter((i) => i.type === iocFilter);

  // Severity styling
  const severityConfig = {
    CRITICAL: { color: '#dc2626', bg: '#fef2f2', border: '#fca5a5', badgeBg: '#dc2626' },
    HIGH: { color: '#ea580c', bg: '#fff7ed', border: '#fdba74', badgeBg: '#ea580c' },
    MEDIUM: { color: '#d97706', bg: '#fffbe6', border: '#fde68a', badgeBg: '#d97706' },
    LOW: { color: '#0284c7', bg: '#f0f9ff', border: '#bae6fd', badgeBg: '#0284c7' },
    CLEAN: { color: '#16a34a', bg: '#f0fdf4', border: '#86efac', badgeBg: '#16a34a' },
  }[threatSeverity] || { color: '#64748b', bg: '#f8fafc', border: '#cbd5e1', badgeBg: '#64748b' };

  const handleCopyIoc = async (val, id) => {
    try {
      await navigator.clipboard.writeText(val);
      setCopiedIoc(id);
      setTimeout(() => setCopiedIoc(null), 1800);
    } catch {
      // fallback
    }
  };

  const handleCopyAllIocs = async () => {
    try {
      const text = iocList.map((i) => `[${i.type}] ${i.value} | Risk: ${i.riskLevel} | Context: ${i.context}`).join('\n');
      await navigator.clipboard.writeText(text);
      setCopiedAllIocs(true);
      setTimeout(() => setCopiedAllIocs(false), 2000);
    } catch {
      // fallback
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
      {/* 1. TOP EXECUTIVE THREAT BANNER */}
      <div
        className="panel fade-in"
        style={{
          background: severityConfig.bg,
          border: `1px solid ${severityConfig.border}`,
          borderLeft: `6px solid ${severityConfig.color}`,
          padding: '16px 20px',
          borderRadius: 'var(--radius-sm)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 14 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <span
                className="mono"
                style={{
                  fontSize: 10,
                  fontWeight: 800,
                  padding: '2px 8px',
                  borderRadius: 3,
                  background: severityConfig.badgeBg,
                  color: '#ffffff',
                  letterSpacing: '0.05em',
                }}
              >
                {threatSeverity} THREAT LEVEL
              </span>
              <span style={{ fontSize: 11, color: '#64748b', fontWeight: 600 }}>
                {allSignals.length} Active Indicator{allSignals.length === 1 ? '' : 's'} Detected
              </span>
            </div>
            <h2 style={{ fontSize: 20, fontWeight: 900, color: '#0f172a', margin: '0 0 6px 0', letterSpacing: '-0.01em' }}>
              {threatCategory}
            </h2>
            <p style={{ margin: 0, fontSize: 13, color: '#334155', maxWidth: 880, lineHeight: 1.55 }}>
              {detectionSummary}
            </p>
          </div>

          {/* Threat Score Dial */}
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              padding: '10px 18px',
              borderRadius: 'var(--radius-sm)',
              background: '#ffffff',
              border: `1px solid ${severityConfig.border}`,
              minWidth: 120,
              boxShadow: '0 1px 3px rgba(0,0,0,0.05)',
            }}
          >
            <div style={{ fontSize: 10, fontWeight: 800, color: '#64748b', letterSpacing: '0.06em' }}>
              THREAT SCORE
            </div>
            <div
              className="mono"
              style={{
                fontSize: 32,
                fontWeight: 900,
                color: severityConfig.color,
                lineHeight: 1.1,
                margin: '2px 0',
              }}
            >
              {overallThreatScore}
              <span style={{ fontSize: 14, color: '#94a3b8' }}>/100</span>
            </div>
            <div style={{ fontSize: 10, fontWeight: 700, color: severityConfig.color }}>
              {threatSeverity} RISK
            </div>
          </div>
        </div>

        {/* Forensic Caveat Footer */}
        <div
          style={{
            marginTop: 14,
            paddingTop: 10,
            borderTop: '1px solid rgba(0,0,0,0.06)',
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            fontSize: 11,
            color: '#64748b',
          }}
        >
          <span>⚖️</span>
          <span>
            <strong>Forensic Provenance Principle:</strong> Geolocation and ISP metadata identify network transit infrastructure, not the physical residence of threat actors. Findings are classified by strict evidence tiers.
          </span>
        </div>
      </div>

      {/* 2. THREE EVIDENCE PROVENANCE TIERS */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 'var(--sp-3)' }}>
        {/* Tier 1: Observed Facts */}
        <div
          className="panel"
          style={{
            background: '#ffffff',
            border: '1px solid #cbd5e1',
            borderTop: '3px solid #16a34a',
            padding: '14px 16px',
            borderRadius: 'var(--radius-sm)',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#16a34a', letterSpacing: '0.05em' }}>
              TIER 1 · OBSERVED FACTS
            </span>
            <span
              className="mono"
              style={{
                fontSize: 11,
                fontWeight: 800,
                background: '#dcfce7',
                color: '#16a34a',
                padding: '1px 6px',
                borderRadius: 10,
              }}
            >
              {evidenceTiers.observedFacts?.length || 0}
            </span>
          </div>
          <div style={{ fontSize: 11, color: '#64748b', marginBottom: 10 }}>
            Mathematically verifiable evidence extracted directly from cryptographic and protocol headers.
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 180, overflowY: 'auto' }}>
            {(evidenceTiers.observedFacts || []).map((fact, idx) => (
              <div
                key={idx}
                style={{
                  fontSize: 11.5,
                  padding: '6px 8px',
                  background: '#f8fafc',
                  borderRadius: 4,
                  border: '1px solid #e2e8f0',
                  color: '#1e293b',
                  lineHeight: 1.4,
                }}
              >
                <strong style={{ color: '#0f172a' }}>{fact.label}:</strong> {fact.fact}
              </div>
            ))}
          </div>
        </div>

        {/* Tier 2: Probable Findings */}
        <div
          className="panel"
          style={{
            background: '#ffffff',
            border: '1px solid #cbd5e1',
            borderTop: '3px solid #d97706',
            padding: '14px 16px',
            borderRadius: 'var(--radius-sm)',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#d97706', letterSpacing: '0.05em' }}>
              TIER 2 · PROBABLE FINDINGS
            </span>
            <span
              className="mono"
              style={{
                fontSize: 11,
                fontWeight: 800,
                background: '#fef3c7',
                color: '#d97706',
                padding: '1px 6px',
                borderRadius: 10,
              }}
            >
              {evidenceTiers.probableFindings?.length || 0}
            </span>
          </div>
          <div style={{ fontSize: 11, color: '#64748b', marginBottom: 10 }}>
            Analytical inferences derived from multi-signal correlation and linguistic heuristics.
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 180, overflowY: 'auto' }}>
            {(evidenceTiers.probableFindings || []).map((finding, idx) => (
              <div
                key={idx}
                style={{
                  fontSize: 11.5,
                  padding: '6px 8px',
                  background: '#f8fafc',
                  borderRadius: 4,
                  border: '1px solid #e2e8f0',
                  color: '#1e293b',
                  lineHeight: 1.4,
                }}
              >
                <strong style={{ color: '#0f172a' }}>{finding.finding}:</strong> {finding.basis}
              </div>
            ))}
          </div>
        </div>

        {/* Tier 3: Unverified Information */}
        <div
          className="panel"
          style={{
            background: '#ffffff',
            border: '1px solid #cbd5e1',
            borderTop: '3px solid #64748b',
            padding: '14px 16px',
            borderRadius: 'var(--radius-sm)',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#64748b', letterSpacing: '0.05em' }}>
              TIER 3 · UNVERIFIED CLAIMS
            </span>
            <span
              className="mono"
              style={{
                fontSize: 11,
                fontWeight: 800,
                background: '#f1f5f9',
                color: '#475569',
                padding: '1px 6px',
                borderRadius: 10,
              }}
            >
              {evidenceTiers.unverified?.length || 0}
            </span>
          </div>
          <div style={{ fontSize: 11, color: '#64748b', marginBottom: 10 }}>
            User-controlled assertions or unconfirmed claims requiring independent out-of-band verification.
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 180, overflowY: 'auto' }}>
            {(evidenceTiers.unverified || []).map((unv, idx) => (
              <div
                key={idx}
                style={{
                  fontSize: 11.5,
                  padding: '6px 8px',
                  background: '#f8fafc',
                  borderRadius: 4,
                  border: '1px solid #e2e8f0',
                  color: '#475569',
                  lineHeight: 1.4,
                }}
              >
                <strong style={{ color: '#0f172a' }}>{unv.field}:</strong> {unv.reason}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* 3. SIGNALS MATRIX WITH FILTER TABS */}
      <div
        className="panel"
        style={{
          background: '#ffffff',
          border: '1px solid #cbd5e1',
          borderRadius: 'var(--radius-sm)',
          padding: '16px 20px',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10, marginBottom: 14 }}>
          <div>
            <div style={{ fontSize: 11, fontWeight: 800, color: '#0284c7', letterSpacing: '0.06em' }}>
              DETECTION TELEMETRY
            </div>
            <h3 style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', margin: 0 }}>
              Correlated Threat Signals
            </h3>
          </div>

          {/* Filter Pills */}
          <div style={{ display: 'flex', gap: 6, background: '#f1f5f9', padding: 3, borderRadius: 6 }}>
            {[
              { id: 'ALL', label: `ALL (${allSignals.length})` },
              { id: 'PHISHING', label: `PHISHING (${phishingSignals.length})` },
              { id: 'SPOOFING', label: `SPOOFING (${spoofingSignals.length})` },
              { id: 'FRAUD', label: `FRAUD (${fraudSignals.length})` },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveSignalCategory(tab.id)}
                style={{
                  border: 'none',
                  background: activeSignalCategory === tab.id ? '#ffffff' : 'transparent',
                  color: activeSignalCategory === tab.id ? '#0284c7' : '#64748b',
                  fontSize: 11,
                  fontWeight: 700,
                  padding: '4px 10px',
                  borderRadius: 4,
                  cursor: 'pointer',
                  boxShadow: activeSignalCategory === tab.id ? '0 1px 2px rgba(0,0,0,0.08)' : 'none',
                  transition: 'all 0.15s ease',
                }}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* Signals List */}
        {filteredSignals.length === 0 ? (
          <div style={{ padding: '24px', textAlign: 'center', color: '#64748b', fontSize: 13 }}>
            No threat signals identified in this category.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {filteredSignals.map((sig) => {
              const sigColor =
                sig.severity === 'CRITICAL'
                  ? '#dc2626'
                  : sig.severity === 'HIGH'
                  ? '#ea580c'
                  : sig.severity === 'MEDIUM'
                  ? '#d97706'
                  : '#0284c7';

              const isExpanded = selectedSignal === sig.id;

              return (
                <div
                  key={sig.id}
                  style={{
                    border: `1px solid ${isExpanded ? sigColor : '#e2e8f0'}`,
                    borderLeft: `4px solid ${sigColor}`,
                    borderRadius: 4,
                    padding: '12px 14px',
                    background: isExpanded ? '#fafafa' : '#ffffff',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 10 }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, flexWrap: 'wrap' }}>
                        <span
                          className="mono"
                          style={{
                            fontSize: 10,
                            fontWeight: 800,
                            color: '#ffffff',
                            background: sigColor,
                            padding: '1px 6px',
                            borderRadius: 3,
                          }}
                        >
                          {sig.severity}
                        </span>
                        <span className="mono" style={{ fontSize: 11, fontWeight: 700, color: '#475569' }}>
                          {sig.id}
                        </span>
                        <span
                          style={{
                            fontSize: 10,
                            fontWeight: 700,
                            padding: '1px 6px',
                            background: '#e0f2fe',
                            color: '#0369a1',
                            borderRadius: 3,
                          }}
                        >
                          {sig.category}
                        </span>
                        <span
                          style={{
                            fontSize: 10,
                            fontWeight: 700,
                            padding: '1px 6px',
                            background: sig.evidenceTier === 'OBSERVED_FACT' ? '#dcfce7' : '#fef3c7',
                            color: sig.evidenceTier === 'OBSERVED_FACT' ? '#16a34a' : '#d97706',
                            borderRadius: 3,
                          }}
                        >
                          {sig.evidenceTier?.replace('_', ' ')}
                        </span>
                      </div>
                      <div style={{ fontSize: 13, fontWeight: 700, color: '#0f172a', marginBottom: 3 }}>
                        {sig.label}
                      </div>
                      <div style={{ fontSize: 12, color: '#334155', lineHeight: 1.5 }}>
                        {sig.detail}
                      </div>
                    </div>

                    <button
                      onClick={() => setSelectedSignal(isExpanded ? null : sig.id)}
                      className="btn"
                      style={{
                        fontSize: 11,
                        fontWeight: 600,
                        padding: '4px 8px',
                        background: '#f1f5f9',
                        color: '#475569',
                        borderColor: '#cbd5e1',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {isExpanded ? 'Hide Evidence ▲' : 'View Evidence ▼'}
                    </button>
                  </div>

                  {/* Expandable Evidence Snippet */}
                  {isExpanded && sig.rawEvidence && (
                    <div
                      style={{
                        marginTop: 10,
                        padding: '10px 12px',
                        background: '#0f172a',
                        borderRadius: 4,
                        color: '#38bdf8',
                        fontSize: 11,
                        lineHeight: 1.5,
                        overflowX: 'auto',
                      }}
                    >
                      <div style={{ fontSize: 10, fontWeight: 700, color: '#94a3b8', marginBottom: 4 }}>
                        RAW EVIDENCE EXTRACTION:
                      </div>
                      <pre className="mono" style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                        {sig.rawEvidence}
                      </pre>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* 4. INDICATORS OF COMPROMISE (IoCs) TABLE & MITRE ATT&CK */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: 'var(--sp-4)' }}>
        {/* IoC Repository */}
        <div
          className="panel"
          style={{
            background: '#ffffff',
            border: '1px solid #cbd5e1',
            borderRadius: 'var(--radius-sm)',
            padding: '16px 20px',
            display: 'flex',
            flexDirection: 'column',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12, flexWrap: 'wrap', gap: 8 }}>
            <div>
              <div style={{ fontSize: 11, fontWeight: 800, color: '#0284c7', letterSpacing: '0.06em' }}>
                FORENSIC ARTIFACTS
              </div>
              <h3 style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', margin: 0 }}>
                Indicators of Compromise (IoCs)
              </h3>
            </div>

            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <select
                value={iocFilter}
                onChange={(e) => setIocFilter(e.target.value)}
                style={{
                  fontSize: 11,
                  fontWeight: 600,
                  padding: '4px 6px',
                  borderRadius: 4,
                  border: '1px solid #cbd5e1',
                  background: '#ffffff',
                }}
              >
                <option value="ALL">All Types</option>
                <option value="IP_ADDRESS">IP Addresses</option>
                <option value="DOMAIN">Domains</option>
                <option value="URL">URLs</option>
                <option value="FILE_HASH">File Hashes</option>
                <option value="EMAIL_ADDRESS">Email Addresses</option>
              </select>

              <button
                onClick={handleCopyAllIocs}
                className="btn btn-primary"
                style={{ fontSize: 11, fontWeight: 700, padding: '4px 10px' }}
                title="Export all IoCs to clipboard"
              >
                {copiedAllIocs ? '✓ Copied' : '⎘ Export IoCs'}
              </button>
            </div>
          </div>

          <div style={{ overflowX: 'auto', flex: 1, maxHeight: 320 }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11.5 }}>
              <thead>
                <tr style={{ background: '#f8fafc', borderBottom: '2px solid #e2e8f0', textAlign: 'left' }}>
                  <th style={{ padding: '6px 8px', color: '#64748b', fontWeight: 700 }}>TYPE</th>
                  <th style={{ padding: '6px 8px', color: '#64748b', fontWeight: 700 }}>VALUE</th>
                  <th style={{ padding: '6px 8px', color: '#64748b', fontWeight: 700 }}>RISK</th>
                  <th style={{ padding: '6px 8px', color: '#64748b', fontWeight: 700 }}>CONTEXT</th>
                  <th style={{ padding: '6px 8px', color: '#64748b', fontWeight: 700, textAlign: 'center' }}>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {filteredIocs.length === 0 ? (
                  <tr>
                    <td colSpan="5" style={{ padding: 16, textAlign: 'center', color: '#94a3b8' }}>
                      No IoCs identified in this category.
                    </td>
                  </tr>
                ) : (
                  filteredIocs.map((ioc, idx) => (
                    <tr
                      key={idx}
                      style={{
                        borderBottom: '1px solid #f1f5f9',
                        background: idx % 2 === 0 ? '#ffffff' : '#fafafa',
                      }}
                    >
                      <td style={{ padding: '6px 8px' }}>
                        <span
                          className="mono"
                          style={{
                            fontSize: 9.5,
                            fontWeight: 800,
                            padding: '1px 5px',
                            background: '#f1f5f9',
                            color: '#334155',
                            borderRadius: 3,
                          }}
                        >
                          {ioc.type.replace('_', ' ')}
                        </span>
                      </td>
                      <td style={{ padding: '6px 8px', maxWidth: 180 }}>
                        <span className="mono" style={{ fontWeight: 600, color: '#0f172a', wordBreak: 'break-all' }}>
                          {ioc.value}
                        </span>
                      </td>
                      <td style={{ padding: '6px 8px' }}>
                        <span
                          style={{
                            fontSize: 10,
                            fontWeight: 800,
                            color:
                              ioc.riskLevel === 'CRITICAL'
                                ? '#dc2626'
                                : ioc.riskLevel === 'HIGH'
                                ? '#ea580c'
                                : '#16a34a',
                          }}
                        >
                          {ioc.riskLevel}
                        </span>
                      </td>
                      <td style={{ padding: '6px 8px', color: '#475569', fontSize: 11 }}>
                        {ioc.context}
                      </td>
                      <td style={{ padding: '6px 8px', textAlign: 'center' }}>
                        <button
                          onClick={() => handleCopyIoc(ioc.value, idx)}
                          style={{
                            border: '1px solid #cbd5e1',
                            background: '#ffffff',
                            borderRadius: 3,
                            padding: '2px 6px',
                            fontSize: 10,
                            cursor: 'pointer',
                          }}
                          title="Copy IoC"
                        >
                          {copiedIoc === idx ? '✓' : '⎘'}
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* MITRE ATT&CK Techniques */}
        <div
          className="panel"
          style={{
            background: '#ffffff',
            border: '1px solid #cbd5e1',
            borderRadius: 'var(--radius-sm)',
            padding: '16px 20px',
            display: 'flex',
            flexDirection: 'column',
          }}
        >
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 11, fontWeight: 800, color: '#7c3aed', letterSpacing: '0.06em' }}>
              ADVERSARY TACTICS
            </div>
            <h3 style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', margin: 0 }}>
              MITRE ATT&CK® Mapping
            </h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, overflowY: 'auto', maxHeight: 320 }}>
            {mitreTechniques.length === 0 ? (
              <div style={{ padding: 16, textAlign: 'center', color: '#94a3b8', fontSize: 12 }}>
                No adversary techniques mapped for this scenario.
              </div>
            ) : (
              mitreTechniques.map((tech) => (
                <div
                  key={tech.id}
                  style={{
                    padding: '10px 12px',
                    borderRadius: 4,
                    border: '1px solid #ede9fe',
                    background: '#faf5ff',
                    borderLeft: '4px solid #7c3aed',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 2 }}>
                    <span className="mono" style={{ fontSize: 11, fontWeight: 800, color: '#7c3aed' }}>
                      {tech.id} · {tech.name}
                    </span>
                    <span
                      style={{
                        fontSize: 9.5,
                        fontWeight: 700,
                        padding: '1px 5px',
                        background: '#ede9fe',
                        color: '#6d28d9',
                        borderRadius: 3,
                      }}
                    >
                      {tech.tactic}
                    </span>
                  </div>
                  <div style={{ fontSize: 11.5, color: '#334155', lineHeight: 1.45 }}>
                    {tech.description}
                  </div>
                  <div style={{ fontSize: 10, color: '#8b5cf6', marginTop: 3, fontWeight: 700 }}>
                    Confidence: {tech.confidence}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* 5. ACTIONABLE INCIDENT RESPONSE DIRECTIVES */}
      <div
        className="panel"
        style={{
          background: '#ffffff',
          border: '1px solid #cbd5e1',
          borderRadius: 'var(--radius-sm)',
          padding: '16px 20px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
          <span style={{ fontSize: 18 }}>🛡️</span>
          <div>
            <div style={{ fontSize: 11, fontWeight: 800, color: '#0284c7', letterSpacing: '0.06em' }}>
              CONTAINMENT STRATEGY
            </div>
            <h3 style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', margin: 0 }}>
              Actionable Incident Response Directives
            </h3>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 10 }}>
          {recommendedActions.map((action, idx) => {
            const isImmediate = action.startsWith('IMMEDIATE:');
            const isUrgent = action.startsWith('URGENT:');
            const isPriority = action.startsWith('PRIORITY:');
            const isDns = action.startsWith('DNS BLOCK:');

            const tagColor = isImmediate ? '#dc2626' : isUrgent ? '#ea580c' : isPriority ? '#d97706' : '#0284c7';
            const tagBg = isImmediate ? '#fef2f2' : isUrgent ? '#fff7ed' : isPriority ? '#fffbe6' : '#f0f9ff';

            return (
              <div
                key={idx}
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: 10,
                  padding: '10px 12px',
                  background: tagBg,
                  borderRadius: 4,
                  border: `1px solid ${tagColor}30`,
                }}
              >
                <span style={{ fontSize: 14, color: tagColor, marginTop: 1 }}>
                  {isImmediate ? '⛔' : isUrgent ? '⚠️' : isDns ? '🛑' : '📋'}
                </span>
                <div style={{ fontSize: 12, color: '#1e293b', lineHeight: 1.45, fontWeight: 500 }}>
                  <strong style={{ color: tagColor }}>{action.split(':')[0]}:</strong>
                  {action.slice(action.indexOf(':') + 1)}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
