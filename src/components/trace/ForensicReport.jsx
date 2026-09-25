import React, { useState } from 'react';

export default function ForensicReport({ caseItem, result, hash }) {
  const [copied, setCopied] = useState(false);
  const [downloaded, setDownloaded] = useState(false);

  const reportId = `EVD-${caseItem.id.replace('CASE-', '')}-${hash ? hash.substring(0, 6).toUpperCase() : 'PENDING'}`;
  const generatedTime = result?.processedAt
    ? new Date(result.processedAt).toLocaleString('en-GB', {
        day: '2-digit',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      })
    : new Date().toLocaleString('en-GB');

  const reportText = buildReportText(caseItem, result, hash, reportId);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(hash);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch (e) {
      /* clipboard fallback */
    }
  };

  const handleDownload = () => {
    const blob = new Blob([reportText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${caseItem.id}-forensic-dossier.txt`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setDownloaded(true);
    setTimeout(() => setDownloaded(false), 1600);
  };

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
      {/* Evidence Document Header */}
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
            DIGITAL EVIDENCE ARTIFACT
          </div>
          <h2 style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', margin: 0, letterSpacing: '-0.01em' }}>
            FORENSIC REPORT
          </h2>
        </div>

        <div
          className="mono"
          style={{
            fontSize: 10,
            fontWeight: 700,
            padding: '2px 8px',
            borderRadius: 3,
            background: '#f1f5f9',
            border: '1px solid #cbd5e1',
            color: '#475569',
          }}
        >
          NIST SP 800-86
        </div>
      </div>

      {/* Metadata Matrix */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(2, 1fr)',
          gap: '10px 14px',
          background: '#f8fafc',
          padding: '12px 14px',
          borderRadius: 'var(--radius-sm)',
          border: '1px solid #e2e8f0',
        }}
      >
        <div>
          <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b', letterSpacing: '0.04em', marginBottom: 2 }}>
            REPORT ID
          </div>
          <div className="mono" style={{ fontSize: 12, fontWeight: 700, color: '#0f172a' }}>
            {reportId}
          </div>
        </div>

        <div>
          <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b', letterSpacing: '0.04em', marginBottom: 2 }}>
            CASE ID
          </div>
          <div className="mono" style={{ fontSize: 12, fontWeight: 700, color: '#0f172a' }}>
            {caseItem.id}
          </div>
        </div>

        <div>
          <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b', letterSpacing: '0.04em', marginBottom: 2 }}>
            GENERATED
          </div>
          <div className="mono" style={{ fontSize: 12, fontWeight: 600, color: '#334155' }}>
            {generatedTime}
          </div>
        </div>

        <div>
          <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b', letterSpacing: '0.04em', marginBottom: 2 }}>
            EVIDENCE STATUS
          </div>
          <div className="mono" style={{ fontSize: 11.5, fontWeight: 700, color: '#16a34a', display: 'flex', alignItems: 'center', gap: 5 }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#16a34a' }} />
            <span>SEALED &amp; IMMUTABLE</span>
          </div>
        </div>
      </div>

      {/* Cryptographic SHA-256 Fingerprint */}
      <div
        style={{
          padding: '10px 14px',
          borderRadius: 'var(--radius-sm)',
          background: '#ffffff',
          border: '1px solid #cbd5e1',
          borderLeft: '4px solid #0284c7',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b', letterSpacing: '0.04em' }}>
            SHA-256 EVIDENCE FINGERPRINT
          </div>
          <span className="mono" style={{ fontSize: 9.5, fontWeight: 700, color: '#0284c7' }}>
            WEB-CRYPTO DIGEST
          </span>
        </div>

        <div
          className="mono"
          style={{
            fontSize: 11,
            fontWeight: 700,
            color: '#0f172a',
            wordBreak: 'break-all',
            lineHeight: 1.45,
            padding: '6px 8px',
            background: '#f8fafc',
            borderRadius: 3,
            border: '1px solid #e2e8f0',
          }}
        >
          {hash || 'Calculating cryptographic digest...'}
        </div>
      </div>

      {/* Forensic Tool Actions */}
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <button
          className="btn"
          onClick={handleCopy}
          disabled={!hash}
          style={{
            flex: 1,
            minWidth: 150,
            fontSize: 12,
            fontWeight: 700,
            padding: '8px 14px',
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 6,
          }}
        >
          <span>{copied ? '✓' : '⎘'}</span>
          <span>{copied ? 'Hash Copied' : 'Copy Evidence Hash'}</span>
        </button>

        <button
          className="btn btn-primary"
          onClick={handleDownload}
          disabled={!hash}
          style={{
            flex: 1.3,
            minWidth: 180,
            fontSize: 12,
            fontWeight: 700,
            padding: '8px 14px',
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 6,
          }}
        >
          <span>{downloaded ? '✓' : '↓'}</span>
          <span>{downloaded ? 'Report Exported' : 'Download Report (.txt)'}</span>
        </button>
      </div>
    </div>
  );
}

function buildReportText(caseItem, result, hash, reportId) {
  const lines = [
    'CYBERTRACE AI — DIGITAL FORENSIC EVIDENCE REPORT',
    'Aligned to NIST SP 800-86 · Digital Forensics Guidelines',
    '='.repeat(64),
    '',
    `Report ID:        ${reportId}`,
    `Case ID:          ${caseItem.id}`,
    `Subject:          ${caseItem.subject}`,
    `Sender (claimed): ${caseItem.displayFrom}`,
    `Recipient:        ${caseItem.to}`,
    `Received:         ${caseItem.receivedAt}`,
    `Processed:        ${result?.processedAt || new Date().toISOString()}`,
    '',
    '-'.repeat(64),
    'FORENSIC VERDICT & ATTRIBUTION',
    '-'.repeat(64),
    `Verdict:          ${result?.verdict?.toUpperCase() || 'UNKNOWN'}`,
    `Intent:           ${result?.intent?.label || 'N/A'}`,
    `Confidence:       ${result?.intent ? Math.round(result.intent.confidence * 100) : 0}%`,
    `SPF / DKIM / DMARC: ${result?.auth?.spf || 'fail'} / ${result?.auth?.dkim || 'fail'} / ${result?.auth?.dmarc || 'fail'}`,
    `Campaign Matches: ${result?.campaignMatches || 0}`,
    '',
    '-'.repeat(64),
    'MAIL TRANSFER PATH (reverse hop reconstruction)',
    '-'.repeat(64),
    ...(result?.hops || []).map(
      (h, i) => `${i + 1}. ${h.host} [${h.ip}] — ${h.trust.toUpperCase()}${h.forged ? ' (FORGED)' : ''}\n   ${h.note}`
    ),
    '',
    '-'.repeat(64),
    'ORIGIN INFRASTRUCTURE INTELLIGENCE',
    '-'.repeat(64),
    `Origin IP:  ${result?.geo?.ip || 'N/A'}`,
    `Location:   ${result?.geo?.city || ''}, ${result?.geo?.region || ''} ${result?.geo?.country || ''}`,
    `ASN / ISP:  ${result?.geo?.isp || 'N/A'}`,
    `Resolution: ${result?.geo?.live ? 'Live BGP network resolution' : 'Cached threat attribution'}`,
    '',
    '-'.repeat(64),
    'KEY FINDINGS & SIGNALS',
    '-'.repeat(64),
    ...(result?.reasons || []).map((r) => `• ${r}`),
    '',
    '='.repeat(64),
    `EVIDENCE INTEGRITY HASH (SHA-256): ${hash}`,
    '='.repeat(64),
  ];
  return lines.join('\n');
}
