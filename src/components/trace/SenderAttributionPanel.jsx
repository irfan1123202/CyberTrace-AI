import React, { useState } from 'react';

/**
 * SenderAttributionPanel
 * ---------------------------------------------------------------------------
 * Correlates:
 *  - From vs Reply-To vs Return-Path vs Display Name
 *  - SPF, DKIM, and DMARC Cryptographic Alignment
 *  - Domain Age, Registrar, and Lookalike / Typosquatting Analysis
 *  - Origin Infrastructure (First Hop IP, ASN, ISP, PTR, Anonymity Network)
 *
 * Adheres strictly to defensive forensic standards:
 *  - Clearly separates Observed Facts vs Analytical Inferences vs Unverified Claims.
 *  - Does NOT claim that an IP identifies the physical attacker.
 */
export default function SenderAttributionPanel({ parsedData }) {
  const [activeTab, setActiveTab] = useState('CORRELATION');
  const [copiedText, setCopiedText] = useState(null);

  if (!parsedData) {
    return (
      <div className="panel" style={{ padding: 24, textAlign: 'center', color: '#64748b' }}>
        No email forensic telemetry available for sender attribution.
      </div>
    );
  }

  const {
    metadata = {},
    headers = {},
    authResults = {},
    protocolAnalysis = {},
    domainIntelligence = {},
    attributionAssessment = {},
    hopChain = [],
  } = parsedData;

  // Extract from fields
  const fromHeader = metadata.from || headers['From'] || '';
  const replyToHeader = metadata.replyTo || headers['Reply-To'] || fromHeader;
  const returnPathHeader = headers['Return-Path'] || headers['return-path'] || 'N/A';
  const messageId = metadata.messageId || headers['Message-ID'] || 'N/A';

  // Display name extraction
  const displayNameMatch = fromHeader.match(/^"?([^"<]+)"?\s*</);
  const displayName = displayNameMatch ? displayNameMatch[1].trim() : 'N/A (Bare address)';

  // From email address extraction
  const fromEmailMatch = fromHeader.match(/<([^>]+)>/) || fromHeader.match(/([^\s<]+@[^\s>]+)/);
  const fromEmail = fromEmailMatch ? fromEmailMatch[1].trim() : fromHeader;
  const fromDomain = fromEmail.includes('@') ? fromEmail.split('@')[1].toLowerCase() : 'UNKNOWN';

  // Reply-To email extraction
  const replyToEmailMatch = replyToHeader.match(/<([^>]+)>/) || replyToHeader.match(/([^\s<]+@[^\s>]+)/);
  const replyToEmail = replyToEmailMatch ? replyToEmailMatch[1].trim() : replyToHeader;
  const replyToDomain = replyToEmail.includes('@') ? replyToEmail.split('@')[1].toLowerCase() : fromDomain;

  // Return-path extraction
  const returnPathClean = returnPathHeader.replace(/[<>]/g, '').trim();
  const returnPathDomain = returnPathClean.includes('@') ? returnPathClean.split('@')[1].toLowerCase() : 'UNKNOWN';

  // Divergence flags
  const replyToDiverges = replyToDomain !== 'unknown' && fromDomain !== 'unknown' && replyToDomain !== fromDomain;
  const returnPathDiverges = returnPathDomain !== 'unknown' && fromDomain !== 'unknown' && returnPathDomain !== fromDomain;

  // Cryptographic authentication checks
  const spfStatus = (authResults.spf?.status || 'UNKNOWN').toUpperCase();
  const dkimStatus = (authResults.dkim?.status || 'UNKNOWN').toUpperCase();
  const dmarcStatus = (authResults.dmarc?.status || 'UNKNOWN').toUpperCase();

  const spfPass = spfStatus === 'PASS';
  const dkimPass = dkimStatus === 'PASS';
  const dmarcPass = dmarcStatus === 'PASS';

  // Origin hop (Earliest public relay)
  const originHop = hopChain[hopChain.length - 1] || null;
  const originIp = originHop?.sourceIp || 'UNKNOWN';
  const originAsn = originHop?.ipIntelligence?.asn || 'UNKNOWN';
  const originIsp = originHop?.ipIntelligence?.isp || 'UNKNOWN';
  const originCity = originHop?.ipIntelligence?.city || 'UNKNOWN';
  const originCountry = originHop?.ipIntelligence?.country || 'UNKNOWN';
  const isTor = originHop?.ipIntelligence?.torIndicator || false;

  // Attribution conclusion classification
  let attributionVerdict = 'LEGITIMATE SENDER (ALIGNED)';
  let verdictColor = '#16a34a';
  let verdictBg = '#f0fdf4';
  let verdictBorder = '#86efac';

  if (replyToDiverges && !spfPass) {
    attributionVerdict = 'CRITICAL: SPOOFED SENDER IDENTITY WITH REPLY-TO HIJACK';
    verdictColor = '#dc2626';
    verdictBg = '#fef2f2';
    verdictBorder = '#fca5a5';
  } else if (!spfPass && !dkimPass) {
    attributionVerdict = 'HIGH RISK: UNAUTHORIZED TRANSMISSION (SPF & DKIM FAILED)';
    verdictColor = '#ea580c';
    verdictBg = '#fff7ed';
    verdictBorder = '#fdba74';
  } else if (domainIntelligence.typosquatting?.isLookalike) {
    attributionVerdict = 'HIGH RISK: TYPOSQUATTED / LOOKALIKE DOMAIN IMPERSONATION';
    verdictColor = '#dc2626';
    verdictBg = '#fef2f2';
    verdictBorder = '#fca5a5';
  } else if (replyToDiverges) {
    attributionVerdict = 'SUSPICIOUS: REPLY-TO ROUTING DIVERGENCE DETECTED';
    verdictColor = '#d97706';
    verdictBg = '#fffbe6';
    verdictBorder = '#fde68a';
  } else if (!spfPass || !dkimPass) {
    attributionVerdict = 'ANOMALOUS: PARTIAL AUTHENTICATION ALIGNMENT FAILURE';
    verdictColor = '#d97706';
    verdictBg = '#fffbe6';
    verdictBorder = '#fde68a';
  }

  const handleCopy = async (text, id) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedText(id);
      setTimeout(() => setCopiedText(null), 1600);
    } catch {
      // fallback
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
      {/* 1. MASTER ATTRIBUTION VERDICT BANNER */}
      <div
        className="panel fade-in"
        style={{
          background: verdictBg,
          border: `1px solid ${verdictBorder}`,
          borderLeft: `6px solid ${verdictColor}`,
          padding: '16px 20px',
          borderRadius: 'var(--radius-sm)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <span
                className="mono"
                style={{
                  fontSize: 10,
                  fontWeight: 800,
                  padding: '2px 8px',
                  borderRadius: 3,
                  background: verdictColor,
                  color: '#ffffff',
                }}
              >
                SENDER ATTRIBUTION EVALUATION
              </span>
              <span style={{ fontSize: 11, fontWeight: 700, color: '#64748b' }}>
                RFC-5322 &amp; Cryptographic Proof Correlation
              </span>
            </div>
            <h2 style={{ fontSize: 18, fontWeight: 900, color: '#0f172a', margin: '0 0 6px 0' }}>
              {attributionVerdict}
            </h2>
            <div style={{ fontSize: 12.5, color: '#334155', lineHeight: 1.5, maxWidth: 900 }}>
              Sender authenticity is established by correlating the displayed identity with underlying envelope routing, cryptographic signatures (SPF, DKIM, DMARC), and first observable relay infrastructure.
            </div>
          </div>

          <div
            style={{
              padding: '10px 16px',
              borderRadius: 'var(--radius-sm)',
              background: '#ffffff',
              border: `1px solid ${verdictBorder}`,
              textAlign: 'center',
              minWidth: 150,
            }}
          >
            <div style={{ fontSize: 10, fontWeight: 800, color: '#64748b', letterSpacing: '0.04em' }}>
              ATTRIBUTION CONFIDENCE
            </div>
            <div
              className="mono"
              style={{
                fontSize: 22,
                fontWeight: 900,
                color: verdictColor,
                marginTop: 2,
              }}
            >
              {attributionAssessment.confidence || (spfPass && dkimPass ? 'HIGH' : 'LOW')}
            </div>
            <div style={{ fontSize: 10, fontWeight: 600, color: '#64748b' }}>
              {spfPass && dkimPass ? 'Cryptographically Proven' : 'Heuristic Correlation'}
            </div>
          </div>
        </div>

        {/* Forensic Caveat */}
        <div
          style={{
            marginTop: 12,
            paddingTop: 8,
            borderTop: '1px solid rgba(0,0,0,0.06)',
            fontSize: 11,
            color: '#64748b',
            display: 'flex',
            alignItems: 'center',
            gap: 6,
          }}
        >
          <span>⚖️</span>
          <span>
            <strong>Forensic Attribution Note:</strong> Sender attribution distinguishes verified cryptographic claims (Observed Facts) from user-crafted headers (Unverified). Network IPs identify relay infrastructure and not the physical person behind the keyboard.
          </span>
        </div>
      </div>

      {/* 2. HEADER DIVERGENCE CORRELATION MATRIX */}
      <div
        className="panel"
        style={{
          background: '#ffffff',
          border: '1px solid #cbd5e1',
          borderRadius: 'var(--radius-sm)',
          padding: '16px 20px',
        }}
      >
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 11, fontWeight: 800, color: '#0284c7', letterSpacing: '0.06em' }}>
            IDENTITY PROVENANCE
          </div>
          <h3 style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', margin: 0 }}>
            Header Alignment &amp; Divergence Matrix
          </h3>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ background: '#f8fafc', borderBottom: '2px solid #e2e8f0', textAlign: 'left' }}>
                <th style={{ padding: '8px 10px', color: '#64748b', fontWeight: 700 }}>HEADER FIELD</th>
                <th style={{ padding: '8px 10px', color: '#64748b', fontWeight: 700 }}>VALUE IN MESSAGE</th>
                <th style={{ padding: '8px 10px', color: '#64748b', fontWeight: 700 }}>EXTRACTED DOMAIN</th>
                <th style={{ padding: '8px 10px', color: '#64748b', fontWeight: 700 }}>ALIGNMENT STATUS</th>
                <th style={{ padding: '8px 10px', color: '#64748b', fontWeight: 700 }}>EVIDENCE TIER</th>
              </tr>
            </thead>
            <tbody>
              {/* Row 1: Display Name */}
              <tr style={{ borderBottom: '1px solid #f1f5f9' }}>
                <td style={{ padding: '8px 10px', fontWeight: 700, color: '#0f172a' }}>
                  From Display Name
                </td>
                <td style={{ padding: '8px 10px', color: '#334155' }}>
                  <span style={{ fontWeight: 600 }}>{displayName}</span>
                </td>
                <td style={{ padding: '8px 10px', color: '#64748b' }}>
                  N/A (Free text)
                </td>
                <td style={{ padding: '8px 10px' }}>
                  <span
                    style={{
                      fontSize: 10,
                      fontWeight: 800,
                      padding: '2px 6px',
                      borderRadius: 3,
                      background: '#f1f5f9',
                      color: '#475569',
                    }}
                  >
                    ARBITRARY / USER-CONTROLLED
                  </span>
                </td>
                <td style={{ padding: '8px 10px' }}>
                  <span style={{ fontSize: 10, fontWeight: 700, color: '#64748b' }}>
                    UNVERIFIED CLAIM
                  </span>
                </td>
              </tr>

              {/* Row 2: Header From (RFC-5322.From) */}
              <tr style={{ borderBottom: '1px solid #f1f5f9', background: '#fafafa' }}>
                <td style={{ padding: '8px 10px', fontWeight: 700, color: '#0f172a' }}>
                  Header From: (Claimed)
                </td>
                <td style={{ padding: '8px 10px' }}>
                  <span className="mono" style={{ fontWeight: 600, color: '#0f172a' }}>
                    {fromEmail}
                  </span>
                </td>
                <td style={{ padding: '8px 10px' }}>
                  <span className="mono" style={{ color: '#0284c7', fontWeight: 700 }}>
                    {fromDomain}
                  </span>
                </td>
                <td style={{ padding: '8px 10px' }}>
                  <span
                    style={{
                      fontSize: 10,
                      fontWeight: 800,
                      padding: '2px 6px',
                      borderRadius: 3,
                      background: '#e0f2fe',
                      color: '#0369a1',
                    }}
                  >
                    BASELINE IDENTITY
                  </span>
                </td>
                <td style={{ padding: '8px 10px' }}>
                  <span style={{ fontSize: 10, fontWeight: 700, color: '#16a34a' }}>
                    OBSERVED HEADER
                  </span>
                </td>
              </tr>

              {/* Row 3: Reply-To */}
              <tr style={{ borderBottom: '1px solid #f1f5f9' }}>
                <td style={{ padding: '8px 10px', fontWeight: 700, color: '#0f172a' }}>
                  Reply-To: (Response Path)
                </td>
                <td style={{ padding: '8px 10px' }}>
                  <span className="mono" style={{ fontWeight: 600, color: replyToDiverges ? '#dc2626' : '#0f172a' }}>
                    {replyToEmail}
                  </span>
                </td>
                <td style={{ padding: '8px 10px' }}>
                  <span className="mono" style={{ color: replyToDiverges ? '#dc2626' : '#0284c7', fontWeight: 700 }}>
                    {replyToDomain}
                  </span>
                </td>
                <td style={{ padding: '8px 10px' }}>
                  <span
                    style={{
                      fontSize: 10,
                      fontWeight: 800,
                      padding: '2px 6px',
                      borderRadius: 3,
                      background: replyToDiverges ? '#fef2f2' : '#f0fdf4',
                      color: replyToDiverges ? '#dc2626' : '#16a34a',
                    }}
                  >
                    {replyToDiverges ? '⚠️ DIVERGENT (HIJACK RISK)' : '✓ ALIGNED WITH FROM'}
                  </span>
                </td>
                <td style={{ padding: '8px 10px' }}>
                  <span style={{ fontSize: 10, fontWeight: 700, color: '#16a34a' }}>
                    OBSERVED HEADER
                  </span>
                </td>
              </tr>

              {/* Row 4: Return-Path (SMTP Envelope Sender) */}
              <tr style={{ borderBottom: '1px solid #f1f5f9', background: '#fafafa' }}>
                <td style={{ padding: '8px 10px', fontWeight: 700, color: '#0f172a' }}>
                  Return-Path (Envelope)
                </td>
                <td style={{ padding: '8px 10px' }}>
                  <span className="mono" style={{ fontWeight: 600, color: returnPathDiverges ? '#ea580c' : '#0f172a' }}>
                    {returnPathClean}
                  </span>
                </td>
                <td style={{ padding: '8px 10px' }}>
                  <span className="mono" style={{ color: returnPathDiverges ? '#ea580c' : '#0284c7', fontWeight: 700 }}>
                    {returnPathDomain}
                  </span>
                </td>
                <td style={{ padding: '8px 10px' }}>
                  <span
                    style={{
                      fontSize: 10,
                      fontWeight: 800,
                      padding: '2px 6px',
                      borderRadius: 3,
                      background: returnPathDiverges ? '#fff7ed' : '#f0fdf4',
                      color: returnPathDiverges ? '#ea580c' : '#16a34a',
                    }}
                  >
                    {returnPathDiverges ? 'MISMATCHED ENVELOPE' : '✓ MATCHES HEADER FROM'}
                  </span>
                </td>
                <td style={{ padding: '8px 10px' }}>
                  <span style={{ fontSize: 10, fontWeight: 700, color: '#16a34a' }}>
                    OBSERVED HEADER
                  </span>
                </td>
              </tr>

              {/* Row 5: Message-ID */}
              <tr>
                <td style={{ padding: '8px 10px', fontWeight: 700, color: '#0f172a' }}>
                  Message-ID
                </td>
                <td style={{ padding: '8px 10px', maxWidth: 280 }}>
                  <span className="mono" style={{ fontSize: 11, color: '#475569', wordBreak: 'break-all' }}>
                    {messageId}
                  </span>
                </td>
                <td style={{ padding: '8px 10px' }}>
                  <span className="mono" style={{ color: '#64748b' }}>
                    {messageId.includes('@') ? messageId.split('@')[1].replace('>', '') : 'N/A'}
                  </span>
                </td>
                <td style={{ padding: '8px 10px' }}>
                  <span
                    style={{
                      fontSize: 10,
                      fontWeight: 800,
                      padding: '2px 6px',
                      borderRadius: 3,
                      background: '#f1f5f9',
                      color: '#475569',
                    }}
                  >
                    MTA GENERATED
                  </span>
                </td>
                <td style={{ padding: '8px 10px' }}>
                  <span style={{ fontSize: 10, fontWeight: 700, color: '#16a34a' }}>
                    OBSERVED HEADER
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* 3. CRYPTOGRAPHIC AUTHENTICATION & DOMAIN INTELLIGENCE */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: 'var(--sp-4)' }}>
        {/* Cryptographic Auth Alignment */}
        <div
          className="panel"
          style={{
            background: '#ffffff',
            border: '1px solid #cbd5e1',
            borderRadius: 'var(--radius-sm)',
            padding: '16px 20px',
          }}
        >
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 11, fontWeight: 800, color: '#0284c7', letterSpacing: '0.06em' }}>
              CRYPTOGRAPHIC PROOF
            </div>
            <h3 style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', margin: 0 }}>
              SPF / DKIM / DMARC Alignment
            </h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {/* SPF Card */}
            <div
              style={{
                padding: '10px 12px',
                borderRadius: 4,
                border: `1px solid ${spfPass ? '#86efac' : '#fca5a5'}`,
                background: spfPass ? '#f0fdf4' : '#fef2f2',
                display: 'flex',
                alignItems: 'flex-start',
                justifyContent: 'space-between',
                gap: 10,
              }}
            >
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
                  <span className="mono" style={{ fontSize: 11, fontWeight: 800, color: spfPass ? '#16a34a' : '#dc2626' }}>
                    SPF: {spfStatus}
                  </span>
                  <span style={{ fontSize: 10, color: '#64748b' }}>Sender Policy Framework</span>
                </div>
                <div style={{ fontSize: 11.5, color: '#334155', lineHeight: 1.4 }}>
                  {authResults.spf?.detail || 'SPF evaluation result extracted from Authentication-Results.'}
                </div>
              </div>
              <span style={{ fontSize: 18 }}>{spfPass ? '✅' : '❌'}</span>
            </div>

            {/* DKIM Card */}
            <div
              style={{
                padding: '10px 12px',
                borderRadius: 4,
                border: `1px solid ${dkimPass ? '#86efac' : '#fca5a5'}`,
                background: dkimPass ? '#f0fdf4' : '#fef2f2',
                display: 'flex',
                alignItems: 'flex-start',
                justifyContent: 'space-between',
                gap: 10,
              }}
            >
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
                  <span className="mono" style={{ fontSize: 11, fontWeight: 800, color: dkimPass ? '#16a34a' : '#dc2626' }}>
                    DKIM: {dkimStatus}
                  </span>
                  <span style={{ fontSize: 10, color: '#64748b' }}>DomainKeys Identified Mail</span>
                </div>
                <div style={{ fontSize: 11.5, color: '#334155', lineHeight: 1.4 }}>
                  {authResults.dkim?.detail || 'DKIM signature cryptographic verification status.'}
                </div>
              </div>
              <span style={{ fontSize: 18 }}>{dkimPass ? '✅' : '❌'}</span>
            </div>

            {/* DMARC Card */}
            <div
              style={{
                padding: '10px 12px',
                borderRadius: 4,
                border: `1px solid ${dmarcPass ? '#86efac' : '#fde68a'}`,
                background: dmarcPass ? '#f0fdf4' : '#fffbe6',
                display: 'flex',
                alignItems: 'flex-start',
                justifyContent: 'space-between',
                gap: 10,
              }}
            >
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
                  <span className="mono" style={{ fontSize: 11, fontWeight: 800, color: dmarcPass ? '#16a34a' : '#d97706' }}>
                    DMARC: {dmarcStatus}
                  </span>
                  <span style={{ fontSize: 10, color: '#64748b' }}>Domain-based Message Auth</span>
                </div>
                <div style={{ fontSize: 11.5, color: '#334155', lineHeight: 1.4 }}>
                  {authResults.dmarc?.detail || 'DMARC policy enforcement and alignment verification.'}
                </div>
              </div>
              <span style={{ fontSize: 18 }}>{dmarcPass ? '✅' : '⚠️'}</span>
            </div>
          </div>
        </div>

        {/* Sender Domain Intelligence */}
        <div
          className="panel"
          style={{
            background: '#ffffff',
            border: '1px solid #cbd5e1',
            borderRadius: 'var(--radius-sm)',
            padding: '16px 20px',
          }}
        >
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 11, fontWeight: 800, color: '#0284c7', letterSpacing: '0.06em' }}>
              DOMAIN FORENSICS
            </div>
            <h3 style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', margin: 0 }}>
              Sender Domain Registration &amp; Reputation
            </h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 10 }}>
              <div style={{ padding: '8px 10px', background: '#f8fafc', borderRadius: 4, border: '1px solid #e2e8f0' }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b' }}>DOMAIN</div>
                <div className="mono" style={{ fontSize: 12, fontWeight: 700, color: '#0f172a' }}>
                  {domainIntelligence.domain || fromDomain}
                </div>
              </div>

              <div style={{ padding: '8px 10px', background: '#f8fafc', borderRadius: 4, border: '1px solid #e2e8f0' }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b' }}>DOMAIN AGE</div>
                <div className="mono" style={{ fontSize: 12, fontWeight: 700, color: domainIntelligence.domainAgeDays < 30 ? '#dc2626' : '#0f172a' }}>
                  {domainIntelligence.domainAgeDays !== undefined ? `${domainIntelligence.domainAgeDays} days` : 'UNKNOWN'}
                </div>
              </div>

              <div style={{ padding: '8px 10px', background: '#f8fafc', borderRadius: 4, border: '1px solid #e2e8f0' }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b' }}>REGISTRAR</div>
                <div style={{ fontSize: 11, fontWeight: 600, color: '#334155' }}>
                  {domainIntelligence.registrar || 'Private Registration / Redacted'}
                </div>
              </div>

              <div style={{ padding: '8px 10px', background: '#f8fafc', borderRadius: 4, border: '1px solid #e2e8f0' }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b' }}>TYPOSQUATTING</div>
                <div style={{ fontSize: 11, fontWeight: 700, color: domainIntelligence.typosquatting?.isLookalike ? '#dc2626' : '#16a34a' }}>
                  {domainIntelligence.typosquatting?.isLookalike ? `YES (Target: ${domainIntelligence.typosquatting.targetedBrand})` : 'NO LOOKALIKE DETECTED'}
                </div>
              </div>
            </div>

            {/* Lookalike Warning if present */}
            {domainIntelligence.typosquatting?.isLookalike && (
              <div
                style={{
                  padding: '10px 12px',
                  background: '#fef2f2',
                  border: '1px solid #fca5a5',
                  borderRadius: 4,
                  fontSize: 11.5,
                  color: '#991b1b',
                  lineHeight: 1.45,
                }}
              >
                <strong>Homoglyph / Typosquat Alert:</strong> Sender domain mimics legitimate brand "
                {domainIntelligence.typosquatting.targetedBrand}" using {domainIntelligence.typosquatting.technique}.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 4. ORIGIN INFRASTRUCTURE PROVENANCE */}
      <div
        className="panel"
        style={{
          background: '#ffffff',
          border: '1px solid #cbd5e1',
          borderRadius: 'var(--radius-sm)',
          padding: '16px 20px',
        }}
      >
        <div style={{ marginBottom: 12 }}>
          <div style={{ fontSize: 11, fontWeight: 800, color: '#0284c7', letterSpacing: '0.06em' }}>
            INFRASTRUCTURE ATTRIBUTION
          </div>
          <h3 style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', margin: 0 }}>
            Earliest Observable Relay &amp; Network Ingestion Point
          </h3>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12 }}>
          <div style={{ padding: '10px 12px', background: '#f8fafc', borderRadius: 4, border: '1px solid #e2e8f0' }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b' }}>FIRST RELAY IP</div>
            <div className="mono" style={{ fontSize: 13, fontWeight: 800, color: '#0f172a', marginTop: 2 }}>
              {originIp}
            </div>
            <div style={{ fontSize: 10, color: '#64748b', marginTop: 2 }}>
              Extracted from earliest Received: header
            </div>
          </div>

          <div style={{ padding: '10px 12px', background: '#f8fafc', borderRadius: 4, border: '1px solid #e2e8f0' }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b' }}>AUTONOMOUS SYSTEM (ASN)</div>
            <div className="mono" style={{ fontSize: 13, fontWeight: 800, color: '#0f172a', marginTop: 2 }}>
              {originAsn}
            </div>
            <div style={{ fontSize: 10, color: '#64748b', marginTop: 2 }}>
              BGP Autonomous System Routing
            </div>
          </div>

          <div style={{ padding: '10px 12px', background: '#f8fafc', borderRadius: 4, border: '1px solid #e2e8f0' }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b' }}>ISP / CARRIER NETWORK</div>
            <div style={{ fontSize: 12, fontWeight: 700, color: '#0f172a', marginTop: 2 }}>
              {originIsp}
            </div>
            <div style={{ fontSize: 10, color: '#64748b', marginTop: 2 }}>
              Hosting / Access Provider
            </div>
          </div>

          <div style={{ padding: '10px 12px', background: '#f8fafc', borderRadius: 4, border: '1px solid #e2e8f0' }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b' }}>INGESTION LOCATION (INFRASTRUCTURE)</div>
            <div style={{ fontSize: 12, fontWeight: 700, color: '#0f172a', marginTop: 2 }}>
              {originCity !== 'UNKNOWN' ? `${originCity}, ` : ''}{originCountry}
            </div>
            <div style={{ fontSize: 10, color: '#dc2626', marginTop: 2, fontWeight: 600 }}>
              *Server Location Only
            </div>
          </div>
        </div>

        {/* Tor / Proxy Alert */}
        {isTor && (
          <div
            style={{
              marginTop: 12,
              padding: '10px 14px',
              background: '#fef2f2',
              border: '1px solid #fca5a5',
              borderRadius: 4,
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              fontSize: 12,
              color: '#991b1b',
            }}
          >
            <span style={{ fontSize: 18 }}>🧅</span>
            <span>
              <strong>Tor Exit Relay Node Detected:</strong> The originating IP is a documented Tor exit relay. The sender used an anonymity network to mask their original client network connection prior to relaying.
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
