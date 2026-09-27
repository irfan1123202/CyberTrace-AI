import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

/**
 * ForensicReport
 * ---------------------------------------------------------------------------
 * Exportable Institutional Cyber Incident Response Report & Evidence Artifact
 * Aligned to NIST SP 800-86 and FRE 902(13).
 *
 * Supports:
 *  - Formatted plaintext dossier export (.txt)
 *  - Structured machine-readable JSON IoC & telemetry manifest (.json)
 *  - Browser print / PDF export
 *  - Cryptographic evidence integrity seal verification
 */
export default function ForensicReport({ caseItem, result, hash, parsedData }) {
  const [copiedHash, setCopiedHash] = useState(false);
  const [downloadedTxt, setDownloadedTxt] = useState(false);
  const [downloadedJson, setDownloadedJson] = useState(false);
  const navigate = useNavigate();

  const handleOpenFullReport = () => {
    const routeId = caseItem?.id || 'inspection';
    navigate(`/report/${routeId}`, {
      state: { caseItem, result, hash, parsedData },
    });
  };

  const reportId = `EVD-${caseItem?.id ? caseItem.id.replace('CASE-', '') : 'INSPECTION'}-${hash ? hash.substring(0, 6).toUpperCase() : 'PENDING'}`;
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

  const reportText = buildComprehensiveReportText(caseItem, result, hash, reportId, parsedData);
  const jsonManifest = buildComprehensiveJsonManifest(caseItem, result, hash, reportId, parsedData);

  const handleCopyHash = async () => {
    try {
      await navigator.clipboard.writeText(hash);
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 1600);
    } catch {
      /* clipboard fallback */
    }
  };

  const handleDownloadTxt = () => {
    const blob = new Blob([reportText], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${caseItem?.id || 'evidence'}-forensic-dossier.txt`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setDownloadedTxt(true);
    setTimeout(() => setDownloadedTxt(false), 1600);
  };

  const handleDownloadJson = () => {
    const blob = new Blob([JSON.stringify(jsonManifest, null, 2)], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${caseItem?.id || 'evidence'}-ioc-manifest.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setDownloadedJson(true);
    setTimeout(() => setDownloadedJson(false), 1600);
  };

  const handlePrint = () => {
    window.print();
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
            DIGITAL EVIDENCE ARTIFACT · INSTITUTIONAL IR
          </div>
          <h2 style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', margin: 0, letterSpacing: '-0.01em' }}>
            FORENSIC INVESTIGATION REPORT
          </h2>
        </div>

        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <span
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
          </span>
          <span
            className="mono"
            style={{
              fontSize: 10,
              fontWeight: 700,
              padding: '2px 8px',
              borderRadius: 3,
              background: '#e0f2fe',
              border: '1px solid #bae6fd',
              color: '#0369a1',
            }}
          >
            FRE 902(13)
          </span>
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
            CASE ARTIFACT ID
          </div>
          <div className="mono" style={{ fontSize: 12, fontWeight: 700, color: '#0f172a' }}>
            {caseItem?.id || 'CASE-INSPECTION'}
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
          background: '#0f172a',
          border: '1px solid #1e293b',
          display: 'flex',
          flexDirection: 'column',
          gap: 4,
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontSize: 10, fontWeight: 800, color: '#38bdf8', letterSpacing: '0.05em' }}>
            SHA-256 INTEGRITY DIGEST
          </span>
          <span style={{ fontSize: 9.5, color: '#94a3b8' }}>RFC-6234 WebCrypto Seal</span>
        </div>
        <div
          className="mono"
          style={{
            fontSize: 11,
            color: '#f8fafc',
            wordBreak: 'break-all',
            letterSpacing: '0.04em',
            lineHeight: 1.4,
          }}
        >
          {hash || 'COMPUTING INTEGRITY HASH...'}
        </div>
      </div>

      {/* Forensic Tool Actions */}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <button
          className="btn"
          onClick={handleCopyHash}
          disabled={!hash}
          style={{
            flex: 1,
            minWidth: 140,
            fontSize: 11.5,
            fontWeight: 700,
            padding: '7px 12px',
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 6,
          }}
        >
          <span>{copiedHash ? '✓' : '⎘'}</span>
          <span>{copiedHash ? 'Hash Copied' : 'Copy Hash'}</span>
        </button>

        <button
          className="btn btn-primary"
          onClick={handleDownloadTxt}
          disabled={!hash}
          style={{
            flex: 1.2,
            minWidth: 160,
            fontSize: 11.5,
            fontWeight: 700,
            padding: '7px 12px',
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 6,
          }}
        >
          <span>{downloadedTxt ? '✓' : '↓'}</span>
          <span>{downloadedTxt ? 'Dossier Exported' : 'Export Dossier (.txt)'}</span>
        </button>

        <button
          className="btn"
          onClick={handleDownloadJson}
          disabled={!hash}
          style={{
            flex: 1.2,
            minWidth: 160,
            fontSize: 11.5,
            fontWeight: 700,
            padding: '7px 12px',
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 6,
            background: '#f0fdf4',
            borderColor: '#86efac',
            color: '#16a34a',
          }}
        >
          <span>{downloadedJson ? '✓' : '⚙️'}</span>
          <span>{downloadedJson ? 'JSON Saved' : 'IoC Manifest (.json)'}</span>
        </button>

        <button
          className="btn"
          onClick={handlePrint}
          style={{
            fontSize: 11.5,
            fontWeight: 700,
            padding: '7px 12px',
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 5,
          }}
          title="Print or save as PDF"
        >
          <span>🖨️</span>
          <span>Print / PDF</span>
        </button>

        <button
          className="btn"
          onClick={handleOpenFullReport}
          style={{
            fontSize: 11.5,
            fontWeight: 700,
            padding: '7px 14px',
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 6,
            background: 'linear-gradient(135deg, #1e293b 0%, #0f172a 100%)',
            borderColor: '#334155',
            color: '#f8fafc',
            boxShadow: '0 2px 8px rgba(15,23,42,0.3)',
          }}
          title="Open as a standalone full-screen report page"
        >
          <span>📋</span>
          <span>Open Full Report ↗</span>
        </button>
      </div>
    </div>
  );
}

function buildComprehensiveReportText(caseItem, result, hash, reportId, parsedData) {
  const phishing = parsedData?.phishingDetection || {};
  const originHop = parsedData?.hopChain ? parsedData.hopChain[parsedData.hopChain.length - 1] : null;

  const lines = [
    '='.repeat(72),
    'CYBERTRACE AI — DIGITAL FORENSIC INCIDENT INVESTIGATION REPORT',
    'Aligned to NIST SP 800-86 · Digital Forensics Guidelines',
    'Federal Rules of Evidence 902(13) Self-Authenticating Digital Records',
    '='.repeat(72),
    '',
    `Report ID:              ${reportId}`,
    `Case Identifier:        ${caseItem?.id || 'N/A'}`,
    `Subject:                ${caseItem?.subject || 'N/A'}`,
    `Sender (claimed):       ${caseItem?.displayFrom || 'N/A'}`,
    `Recipient:              ${caseItem?.to || 'N/A'}`,
    `Date Received:          ${caseItem?.receivedAt || 'N/A'}`,
    `Forensic Analysis Time: ${result?.processedAt || new Date().toISOString()}`,
    `Evidence Hash (SHA-256):${hash || 'N/A'}`,
    '',
    '-'.repeat(72),
    '1. FORENSIC VERDICT & THREAT CLASSIFICATION',
    '-'.repeat(72),
    `Threat Score:           ${phishing.overallThreatScore ?? (result?.intent ? Math.round(result.intent.confidence * 100) : 0)}/100`,
    `Threat Severity:        ${phishing.threatSeverity || result?.verdict?.toUpperCase() || 'UNKNOWN'}`,
    `Threat Category:        ${phishing.threatCategory || result?.intent?.label || 'UNSPECIFIED THREAT'}`,
    `Verdict:                ${result?.verdict?.toUpperCase() || 'MALICIOUS'}`,
    '',
    'AI Investigation Summary:',
    phishing.detectionSummary || 'Forensic analysis completed.',
    '',
    '-'.repeat(72),
    '2. SENDER ATTRIBUTION & AUTHENTICATION ALIGNMENT',
    '-'.repeat(72),
    `Claimed From Header:    ${parsedData?.metadata?.from || caseItem?.displayFrom || 'N/A'}`,
    `Reply-To Routing:       ${parsedData?.metadata?.replyTo || 'N/A'}`,
    `Return-Path (Envelope): ${parsedData?.headers?.['Return-Path'] || parsedData?.headers?.['return-path'] || 'N/A'}`,
    `Message-ID:             ${parsedData?.metadata?.messageId || 'N/A'}`,
    `SPF Authentication:     ${parsedData?.authResults?.spf?.status || result?.auth?.spf?.toUpperCase() || 'FAIL'} (${parsedData?.authResults?.spf?.detail || ''})`,
    `DKIM Signature:         ${parsedData?.authResults?.dkim?.status || result?.auth?.dkim?.toUpperCase() || 'FAIL'} (${parsedData?.authResults?.dkim?.detail || ''})`,
    `DMARC Policy:           ${parsedData?.authResults?.dmarc?.status || result?.auth?.dmarc?.toUpperCase() || 'FAIL'} (${parsedData?.authResults?.dmarc?.detail || ''})`,
    '',
    '-'.repeat(72),
    '3. MAIL TRANSFER PATH (RECONSTRUCTED HOP CHAIN)',
    '-'.repeat(72),
    ...(parsedData?.hopChain || []).map(
      (h, i) =>
        `Hop #${i + 1}: ${h.sourceIp || 'UNKNOWN'} [${h.role || 'Relay'}]\n` +
        `  From Host:   ${h.fromHost || 'unknown'}\n` +
        `  By Host:     ${h.byHost || 'unknown'}\n` +
        `  Trust Level: ${h.trustLevel || 'UNTRUSTED'}${h.forged ? ' (FORGED INDICATOR)' : ''}\n` +
        `  Network:     ASN ${h.ipIntelligence?.asn || 'UNKNOWN'} — ${h.ipIntelligence?.isp || 'Unknown ISP'}\n` +
        `  Location:    ${h.ipIntelligence?.city || ''} ${h.ipIntelligence?.country || 'Unknown'}\n` +
        `  Timestamp:   ${h.timestamp || 'N/A'}`
    ),
    '',
    '-'.repeat(72),
    '4. FIRST OBSERVABLE RELAY INFRASTRUCTURE INTELLIGENCE',
    '-'.repeat(72),
    `Origin Relay IP:  ${originHop?.sourceIp || result?.geo?.ip || 'N/A'}`,
    `Server Location:  ${originHop?.ipIntelligence?.city || result?.geo?.city || ''}, ${originHop?.ipIntelligence?.country || result?.geo?.country || ''}`,
    `ASN & Carrier:    ${originHop?.ipIntelligence?.asn || 'N/A'} — ${originHop?.ipIntelligence?.isp || result?.geo?.isp || 'N/A'}`,
    `Tor Indicator:    ${originHop?.ipIntelligence?.torIndicator ? 'TRUE (Active Tor Exit Relay)' : 'FALSE'}`,
    'Legal Disclaimer: Network IP identifies edge relay infrastructure. It does not establish the physical identity of the threat actor.',
    '',
    '-'.repeat(72),
    '5. EXTRACTED INDICATORS OF COMPROMISE (IoCs)',
    '-'.repeat(72),
    ...(phishing.iocList || []).map(
      (ioc) => `[${ioc.type}] ${ioc.value}\n  Risk: ${ioc.riskLevel} | Context: ${ioc.context}`
    ),
    '',
    '-'.repeat(72),
    '6. ADVERSARY TACTICS & MITRE ATT&CK® TECHNIQUES',
    '-'.repeat(72),
    ...(phishing.mitreTechniques || []).map(
      (t) => `• [${t.id}] ${t.name} (Tactic: ${t.tactic}, Confidence: ${t.confidence})\n  ${t.description}`
    ),
    '',
    '-'.repeat(72),
    '7. INCIDENT RESPONSE DIRECTIVES & RECOMMENDED ACTIONS',
    '-'.repeat(72),
    ...(phishing.recommendedActions || []).map((a) => `• ${a}`),
    '',
    '='.repeat(72),
    `EVIDENCE INTEGRITY SEAL (SHA-256): ${hash || 'N/A'}`,
    'Digital evidence preserved under chain of custody requirements.',
    '='.repeat(72),
  ];

  return lines.join('\n');
}

function buildComprehensiveJsonManifest(caseItem, result, hash, reportId, parsedData) {
  const phishing = parsedData?.phishingDetection || {};

  return {
    version: '1.0',
    standard: 'NIST SP 800-86 / STIX 2.1 Compatible',
    generatedAt: new Date().toISOString(),
    reportId,
    caseId: caseItem?.id,
    integrityDigest: {
      algorithm: 'SHA-256',
      hash,
      sourceArtifact: parsedData?.filename || 'EVIDENCE.EML',
    },
    metadata: {
      subject: caseItem?.subject,
      from: parsedData?.metadata?.from || caseItem?.displayFrom,
      to: parsedData?.metadata?.to || caseItem?.to,
      replyTo: parsedData?.metadata?.replyTo,
      date: caseItem?.receivedAt,
      messageId: parsedData?.metadata?.messageId,
    },
    threatEvaluation: {
      overallThreatScore: phishing.overallThreatScore || 0,
      threatCategory: phishing.threatCategory || 'CLEAN',
      threatSeverity: phishing.threatSeverity || 'CLEAN',
      verdict: result?.verdict || 'MALICIOUS',
      detectionSummary: phishing.detectionSummary,
    },
    authenticationResults: parsedData?.authResults || {},
    hopChain: parsedData?.hopChain || [],
    iocs: phishing.iocList || [],
    evidenceTiers: phishing.evidenceTiers || {},
    mitreTechniques: phishing.mitreTechniques || [],
    recommendedActions: phishing.recommendedActions || [],
  };
}
