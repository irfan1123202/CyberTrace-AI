import React from 'react';
import StatusBadge from '../common/StatusBadge';
import ConfidenceBar from '../common/ConfidenceBar';

export default function VerdictPanel({ result }) {
  const isMalicious = result.verdict === 'malicious';
  const isSuspicious = result.verdict === 'suspicious';
  const isSafe = result.verdict === 'safe';

  let verdictColor = '#dc2626';
  let verdictBg = '#fef2f2';
  let verdictBorder = '#fca5a5';
  let verdictText = 'MALICIOUS';

  if (isSuspicious) {
    verdictColor = '#d97706';
    verdictBg = '#fffbe6';
    verdictBorder = '#fde68a';
    verdictText = 'SUSPICIOUS';
  } else if (isSafe) {
    verdictColor = '#16a34a';
    verdictBg = '#f0fdf4';
    verdictBorder = '#86efac';
    verdictText = 'SAFE / BENIGN';
  }

  // Derive the 5 Signal Matrix points
  const spfStatus = result.auth.spf === 'pass' ? 'PASSED' : 'FAILED';
  const dkimStatus = result.auth.dkim === 'pass' ? 'PASSED' : result.auth.dkim === 'none' ? 'MISSING' : 'FAILED';
  const dmarcStatus = result.auth.dmarc === 'pass' ? 'PASSED' : 'FAILED';
  const hasForgedHop = result.hops.some((h) => h.forged);
  const headerStatus = hasForgedHop ? 'SPOOFED' : 'VALID';
  const originStatus = result.campaignMatches > 0 || result.geo?.ip ? 'MATCHED' : 'UNRESOLVED';

  const signalMatrix = [
    { label: 'SPF', value: spfStatus, bad: spfStatus === 'FAILED' },
    { label: 'DKIM', value: dkimStatus, bad: dkimStatus === 'FAILED' || dkimStatus === 'MISSING' },
    { label: 'DMARC', value: dmarcStatus, bad: dmarcStatus === 'FAILED' },
    { label: 'HEADER', value: headerStatus, bad: headerStatus === 'SPOOFED' },
    { label: 'ORIGIN', value: originStatus, bad: false, highlight: originStatus === 'MATCHED' },
  ];

  return (
    <div
      className="panel fade-in"
      style={{
        padding: 'var(--sp-5)',
        background: '#ffffff',
        border: '1px solid #cbd5e1',
        borderRadius: 'var(--radius-sm)',
        boxShadow: '0 1px 4px rgba(15, 23, 42, 0.04)',
        display: 'flex',
        flexDirection: 'column',
        gap: 'var(--sp-4)',
      }}
    >
      {/* Header */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 8,
          paddingBottom: 'var(--sp-3)',
          borderBottom: '1px solid #f1f5f9',
        }}
      >
        <div>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#0284c7', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 2 }}>
            ANALYST ATTRIBUTION CONCLUSION
          </div>
          <h2 style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', margin: 0, letterSpacing: '-0.01em' }}>
            FORENSIC VERDICT
          </h2>
        </div>
        <StatusBadge variant={result.verdict} />
      </div>

      {/* Primary Conclusion Box */}
      <div
        style={{
          padding: '12px 16px',
          borderRadius: 'var(--radius-sm)',
          background: verdictBg,
          border: `1px solid ${verdictBorder}`,
          borderLeft: `5px solid ${verdictColor}`,
          display: 'flex',
          flexDirection: 'column',
          gap: 2,
        }}
      >
        <div
          className="mono"
          style={{
            fontSize: 18,
            fontWeight: 900,
            color: verdictColor,
            letterSpacing: '0.04em',
          }}
        >
          {verdictText}
        </div>
        <div style={{ fontSize: 13.5, fontWeight: 700, color: '#0f172a' }}>
          {result.intent.label}
        </div>
      </div>

      {/* Confidence Section */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
          <span style={{ fontSize: 11, fontWeight: 700, color: '#475569', letterSpacing: '0.04em' }}>
            MODEL CONFIDENCE
          </span>
          <span className="mono" style={{ fontSize: 11, fontWeight: 700, color: '#64748b' }}>
            DeBERTa-v3 NLP
          </span>
        </div>
        <ConfidenceBar value={result.intent.confidence} color={verdictColor} />
      </div>

      {/* Signal Matrix */}
      <div>
        <div style={{ fontSize: 11, fontWeight: 700, color: '#475569', letterSpacing: '0.04em', marginBottom: 8 }}>
          CRYPTOGRAPHIC & INFRASTRUCTURE SIGNAL MATRIX
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 6 }}>
          {signalMatrix.map((item) => {
            let textColor = item.bad ? '#dc2626' : item.highlight ? '#0369a1' : '#16a34a';
            let itemBg = item.bad ? '#fef2f2' : item.highlight ? '#f0f9ff' : '#f0fdf4';
            let itemBorder = item.bad ? '#fca5a5' : item.highlight ? '#bae6fd' : '#bbf7d0';

            return (
              <div
                key={item.label}
                style={{
                  textAlign: 'center',
                  padding: '8px 4px',
                  borderRadius: 4,
                  background: itemBg,
                  border: `1px solid ${itemBorder}`,
                }}
              >
                <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b', marginBottom: 3 }}>
                  {item.label}
                </div>
                <div className="mono" style={{ fontSize: 11, fontWeight: 800, color: textColor }}>
                  {item.value}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Key Findings */}
      <div>
        <div style={{ fontSize: 11, fontWeight: 700, color: '#475569', letterSpacing: '0.04em', marginBottom: 8 }}>
          KEY FINDINGS
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {result.reasons.map((reason, index) => (
            <div
              key={index}
              style={{
                display: 'flex',
                gap: 8,
                alignItems: 'flex-start',
                padding: '7px 10px',
                borderRadius: 'var(--radius-xs)',
                background: '#f8fafc',
                border: '1px solid #e2e8f0',
                fontSize: 12,
                color: '#334155',
                lineHeight: 1.45,
              }}
            >
              <span
                className="mono"
                style={{
                  fontSize: 10,
                  fontWeight: 800,
                  color: verdictColor,
                  flexShrink: 0,
                  marginTop: 1,
                }}
              >
                [F-0{index + 1}]
              </span>
              <span>{reason}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Campaign Attribution Match */}
      {result.campaignMatches > 0 && (
        <div
          style={{
            padding: '9px 12px',
            borderRadius: 'var(--radius-xs)',
            background: '#f0f9ff',
            border: '1px solid #bae6fd',
            fontSize: 12,
            color: '#0369a1',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}
        >
          <span style={{ fontSize: 14, fontWeight: 800 }}>☍</span>
          <div>
            <strong>CAMPAIGN CLUSTER MATCH:</strong> Infrastructure links to{' '}
            <strong>{result.campaignMatches} active incidents</strong> in threat graph.
          </div>
        </div>
      )}

      <style>{`
        @media (max-width: 600px) {
          div[style*="grid-template-columns: repeat(5, 1fr)"] {
            grid-template-columns: repeat(2, 1fr) !important;
          }
        }
      `}</style>
    </div>
  );
}
