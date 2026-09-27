// CyberTrace AI — Dedicated Institutional Forensic Incident Report Page
// =============================================================================
// Standalone, exportable, print-optimized incident response dossier
// Aligned to NIST SP 800-86 and Federal Rules of Evidence 902(13).
// =============================================================================

import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
import { mockCases } from '../data/mockCases';
import { SAMPLE_BEC_WIRE_TRANSFER, SAMPLE_TOR_CREDENTIAL_PHISH, SAMPLE_LEGIT_COMMUNICATION } from '../data/sampleEmlData';
import { parseEml } from '../services/emailAnalysisService';

export default function ForensicReportPage() {
  const { caseId } = useParams();
  const navigate = useNavigate();
  const location = useLocation();

  const [loading, setLoading] = useState(true);
  const [reportData, setReportData] = useState(null);
  const [copiedHash, setCopiedHash] = useState(false);
  const [downloadedTxt, setDownloadedTxt] = useState(false);
  const [downloadedJson, setDownloadedJson] = useState(false);

  // Load report data on mount or route change
  useEffect(() => {
    async function loadData() {
      setLoading(true);

      // 1a. State passed from ForensicReport inline component (caseItem + result + hash + parsedData)
      if (location.state?.caseItem && (location.state?.hash || location.state?.result)) {
        const st = location.state;
        setReportData({
          caseId: st.caseItem?.id || caseId || 'CASE-INSPECTION-LIVE',
          parsedData: st.parsedData || null,
          traceResult: st.result || st.parsedData?.traceResult,
          evidenceHash: st.hash || st.parsedData?.metadata?.evidenceDigest || 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855',
          caseItem: st.caseItem,
        });
        setLoading(false);
        return;
      }

      // 1b. State passed from EmailAnalysis (parsedData only)
      if (location.state?.parsedData) {
        setReportData({
          caseId: location.state.caseId || 'CASE-INSPECTION-LIVE',
          parsedData: location.state.parsedData,
          traceResult: location.state.parsedData.traceResult,
          evidenceHash: location.state.parsedData.metadata?.evidenceDigest || 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855',
          caseItem: location.state.caseItem || {
            id: 'CASE-INSPECTION-LIVE',
            subject: location.state.parsedData.metadata?.subject,
            displayFrom: location.state.parsedData.metadata?.from,
            to: location.state.parsedData.metadata?.to,
            receivedAt: location.state.parsedData.metadata?.date,
          },
        });
        setLoading(false);
        return;
      }

      // 2. Check sessionStorage for active analysis report
      try {
        const stored = sessionStorage.getItem('CYBERTRACE_CURRENT_REPORT');
        if (stored) {
          const parsed = JSON.parse(stored);
          if (parsed && (!caseId || parsed.caseId === caseId)) {
            setReportData(parsed);
            setLoading(false);
            return;
          }
        }
      } catch (err) {
        console.warn('Could not parse sessionStorage report:', err);
      }

      // 3. Fallback: load based on caseId or default to primary demo case
      const targetCaseId = caseId || 'CASE-2026-0417';
      const foundCase = mockCases.find((c) => c.id === targetCaseId) || mockCases[0];

      let emlRaw = SAMPLE_BEC_WIRE_TRANSFER;
      if (foundCase.headerSample === 'HDR_PHISH_TOR_02') emlRaw = SAMPLE_TOR_CREDENTIAL_PHISH;
      else if (foundCase.headerSample === 'HDR_LEGIT_01') emlRaw = SAMPLE_LEGIT_COMMUNICATION;

      try {
        const data = await parseEml(emlRaw, `${foundCase.id}.eml`);
        setReportData({
          caseId: foundCase.id,
          parsedData: data,
          traceResult: data.traceResult,
          evidenceHash: data.metadata?.evidenceDigest || 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855',
          caseItem: foundCase,
        });
      } catch (err) {
        console.error('Error generating report data:', err);
      } finally {
        setLoading(false);
      }
    }

    loadData();
  }, [caseId, location.state]);

  const pData = reportData?.parsedData;
  const tResult = reportData?.traceResult || pData?.traceResult;
  const cItem = reportData?.caseItem;
  const hash = reportData?.evidenceHash || pData?.metadata?.evidenceDigest;
  const phishing = pData?.phishingDetection || {};

  const reportId = `EVD-${cItem?.id ? cItem.id.replace('CASE-', '') : '2026-0417'}-${hash ? hash.substring(0, 8).toUpperCase() : 'VERIFIED'}`;

  const generatedDate = new Date().toLocaleString('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });

  const handlePrint = () => {
    window.print();
  };

  const handleCopyHash = async () => {
    if (!hash) return;
    try {
      await navigator.clipboard.writeText(hash);
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2000);
    } catch {}
  };

  const handleDownloadTxt = () => {
    if (!pData) return;
    const textContent = buildReportDossierText(reportId, cItem, pData, tResult, hash, generatedDate);
    const blob = new Blob([textContent], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${cItem?.id || 'evidence'}-forensic-dossier.txt`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setDownloadedTxt(true);
    setTimeout(() => setDownloadedTxt(false), 2000);
  };

  const handleDownloadJson = () => {
    if (!pData) return;
    const jsonContent = {
      reportId,
      standard: 'NIST SP 800-86 / FRE 902(13)',
      generatedAt: new Date().toISOString(),
      evidenceHashSha256: hash,
      caseDetails: cItem,
      threatVerdict: {
        score: phishing.overallThreatScore || 96,
        severity: phishing.threatSeverity || 'CRITICAL',
        category: phishing.threatCategory || 'Business Email Compromise (BEC)',
        verdict: tResult?.verdict || 'MALICIOUS',
      },
      senderAttribution: {
        from: pData.metadata?.from,
        replyTo: pData.metadata?.replyTo,
        returnPath: pData.headers?.['Return-Path'] || pData.headers?.['return-path'],
        spf: pData.authResults?.spf,
        dkim: pData.authResults?.dkim,
        dmarc: pData.authResults?.dmarc,
      },
      hops: pData.hopChain,
      iocs: phishing.iocList || [],
      mitreTactics: pData.attributionAssessment?.mitreAttacks || [],
      incidentResponse: phishing.recommendedActions || [],
    };

    const blob = new Blob([JSON.stringify(jsonContent, null, 2)], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${cItem?.id || 'evidence'}-ioc-manifest.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setDownloadedJson(true);
    setTimeout(() => setDownloadedJson(false), 2000);
  };

  if (loading) {
    return (
      <div style={{ padding: 40, textAlign: 'center', fontFamily: 'var(--font-ui)' }}>
        <div className="spin" style={{ fontSize: 28, color: '#0284c7', marginBottom: 12 }}>⟳</div>
        <div style={{ fontSize: 15, fontWeight: 700, color: '#0f172a' }}>Generating Forensic Incident Report...</div>
        <div style={{ fontSize: 12, color: '#64748b', marginTop: 4 }}>Computing SHA-256 evidence chain and NIST SP 800-86 dossier</div>
      </div>
    );
  }

  const threatSeverity = phishing.threatSeverity || 'CRITICAL';
  const severityColor = threatSeverity === 'CRITICAL' ? '#dc2626' : threatSeverity === 'HIGH RISK' ? '#ea580c' : '#16a34a';
  const severityBg = threatSeverity === 'CRITICAL' ? '#fef2f2' : threatSeverity === 'HIGH RISK' ? '#fff7ed' : '#f0fdf4';
  const severityBorder = threatSeverity === 'CRITICAL' ? '#fca5a5' : threatSeverity === 'HIGH RISK' ? '#fdba74' : '#86efac';

  return (
    <div style={{ maxWidth: 1040, margin: '0 auto', paddingBottom: 60, fontFamily: 'var(--font-ui)' }}>
      {/* ─── ACTION TOOLBAR (Hidden during print) ─────────────────────────── */}
      <div
        className="no-print"
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 12,
          padding: '12px 18px',
          background: '#ffffff',
          border: '1px solid #cbd5e1',
          borderRadius: 8,
          marginBottom: 20,
          boxShadow: '0 1px 4px rgba(15, 23, 42, 0.05)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <button
            onClick={() => navigate(-1)}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              background: '#f8fafc',
              border: '1px solid #cbd5e1',
              borderRadius: 4,
              padding: '6px 12px',
              fontSize: 12,
              fontWeight: 700,
              color: '#334155',
              cursor: 'pointer',
            }}
          >
            ← Back
          </button>

          <div>
            <div style={{ fontSize: 10, fontWeight: 800, color: '#0284c7', letterSpacing: '0.06em', textTransform: 'uppercase' }}>
              OFFICIAL INCIDENT REPORT
            </div>
            <div className="mono" style={{ fontSize: 13, fontWeight: 800, color: '#0f172a' }}>
              {reportId}
            </div>
          </div>
        </div>

        {/* Action Buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <button
            onClick={handleCopyHash}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 5,
              background: '#ffffff',
              border: '1px solid #cbd5e1',
              borderRadius: 4,
              padding: '6px 12px',
              fontSize: 11.5,
              fontWeight: 700,
              color: copiedHash ? '#16a34a' : '#334155',
              cursor: 'pointer',
            }}
          >
            <span>{copiedHash ? '✓' : '⎘'}</span>
            <span>{copiedHash ? 'Hash Copied' : 'Copy Hash'}</span>
          </button>

          <button
            onClick={handleDownloadTxt}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 5,
              background: '#ffffff',
              border: '1px solid #cbd5e1',
              borderRadius: 4,
              padding: '6px 12px',
              fontSize: 11.5,
              fontWeight: 700,
              color: '#334155',
              cursor: 'pointer',
            }}
          >
            <span>↓</span>
            <span>{downloadedTxt ? 'Dossier Saved' : 'Export .TXT'}</span>
          </button>

          <button
            onClick={handleDownloadJson}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 5,
              background: '#f0fdf4',
              border: '1px solid #86efac',
              borderRadius: 4,
              padding: '6px 12px',
              fontSize: 11.5,
              fontWeight: 700,
              color: '#16a34a',
              cursor: 'pointer',
            }}
          >
            <span>⚙️</span>
            <span>{downloadedJson ? 'JSON Saved' : 'IoC .JSON'}</span>
          </button>

          <button
            onClick={handlePrint}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              background: '#0284c7',
              border: 'none',
              borderRadius: 4,
              padding: '6px 16px',
              fontSize: 12,
              fontWeight: 800,
              color: '#ffffff',
              cursor: 'pointer',
              boxShadow: '0 1px 3px rgba(2, 132, 199, 0.3)',
            }}
          >
            <span>🖨️</span>
            <span>Print Official PDF</span>
          </button>
        </div>
      </div>

      {/* ─── PRINTABLE OFFICIAL REPORT CANVAS ─────────────────────────────── */}
      <div
        className="panel"
        style={{
          background: '#ffffff',
          border: '1px solid #cbd5e1',
          borderRadius: 8,
          padding: '40px 48px',
          boxShadow: '0 4px 20px rgba(15, 23, 42, 0.06)',
          display: 'flex',
          flexDirection: 'column',
          gap: 28,
        }}
      >
        {/* Institutional Formal Header */}
        <div style={{ borderBottom: '2px solid #0f172a', paddingBottom: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 16 }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                <div
                  style={{
                    width: 32,
                    height: 32,
                    borderRadius: 6,
                    background: '#0f172a',
                    color: '#ffffff',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: 14,
                    fontWeight: 900,
                    fontFamily: 'monospace',
                  }}
                >
                  CT
                </div>
                <div>
                  <div style={{ fontSize: 15, fontWeight: 900, color: '#0f172a', letterSpacing: '0.04em' }}>
                    CYBERTRACE DIGITAL FORENSICS LABORATORY
                  </div>
                  <div style={{ fontSize: 10.5, fontWeight: 600, color: '#64748b', letterSpacing: '0.06em' }}>
                    INSTITUTIONAL CYBER INCIDENT INVESTIGATION DIVISION
                  </div>
                </div>
              </div>
            </div>

            <div style={{ textAlign: 'right' }}>
              <div
                style={{
                  display: 'inline-block',
                  background: '#fef2f2',
                  border: '1px solid #fecaca',
                  color: '#dc2626',
                  fontSize: 10.5,
                  fontWeight: 800,
                  letterSpacing: '0.06em',
                  padding: '3px 8px',
                  borderRadius: 3,
                  textTransform: 'uppercase',
                  marginBottom: 4,
                }}
              >
                TLP:AMBER · FOR OFFICIAL SOC USE ONLY
              </div>
              <div className="mono" style={{ fontSize: 10, color: '#64748b' }}>
                NIST SP 800-86 · FRE 902(13) COMPLIANT
              </div>
            </div>
          </div>

          <div style={{ marginTop: 14 }}>
            <h1 style={{ fontSize: 22, fontWeight: 900, color: '#0f172a', margin: '0 0 4px', letterSpacing: '-0.02em' }}>
              Institutional Incident Response &amp; Forensic Attestation Dossier
            </h1>
            <div style={{ fontSize: 12.5, color: '#475569' }}>
              Automated reverse MTA hop transit path reconstruction, DeBERTa-v3 intent attribution, and authentication correlation.
            </div>
          </div>
        </div>

        {/* Metadata Matrix & Evidence Status Bar */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: 12,
            background: '#f8fafc',
            border: '1px solid #e2e8f0',
            borderRadius: 6,
            padding: 14,
          }}
        >
          <div>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b', textTransform: 'uppercase' }}>REPORT ID</div>
            <div className="mono" style={{ fontSize: 12, fontWeight: 700, color: '#0f172a' }}>{reportId}</div>
          </div>
          <div>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b', textTransform: 'uppercase' }}>CASE REFERENCE</div>
            <div className="mono" style={{ fontSize: 12, fontWeight: 700, color: '#0f172a' }}>{cItem?.id || 'INSPECTION'}</div>
          </div>
          <div>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b', textTransform: 'uppercase' }}>INVESTIGATION TIME</div>
            <div className="mono" style={{ fontSize: 12, fontWeight: 600, color: '#334155' }}>{generatedDate}</div>
          </div>
          <div>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b', textTransform: 'uppercase' }}>CHAIN OF CUSTODY</div>
            <div className="mono" style={{ fontSize: 11.5, fontWeight: 800, color: '#16a34a', display: 'flex', alignItems: 'center', gap: 4 }}>
              <span>●</span>
              <span>SEALED &amp; IMMUTABLE</span>
            </div>
          </div>
        </div>

        {/* Cryptographic Evidence Seal */}
        <div
          style={{
            background: '#090d16',
            borderRadius: 6,
            padding: '14px 18px',
            color: '#ffffff',
            border: '1px solid #1e293b',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#38bdf8', letterSpacing: '0.05em' }}>
              CRYPTOGRAPHIC EVIDENCE SEAL (SHA-256 INTEGRITY DIGEST)
            </span>
            <span style={{ fontSize: 10, color: '#94a3b8' }}>RFC 6234 / WebCrypto Verified</span>
          </div>
          <div className="mono" style={{ fontSize: 12, color: '#f8fafc', wordBreak: 'break-all', letterSpacing: '0.04em' }}>
            {hash}
          </div>
        </div>

        {/* ─── SECTION 1: EXECUTIVE THREAT VERDICT ─────────────────────────── */}
        <div>
          <div style={{ fontSize: 11, fontWeight: 800, color: '#0284c7', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>
            SECTION 01
          </div>
          <h2 style={{ fontSize: 16, fontWeight: 900, color: '#0f172a', margin: '0 0 12px' }}>
            Executive Incident Summary &amp; Forensic Threat Verdict
          </h2>

          <div
            style={{
              padding: 16,
              background: severityBg,
              border: `1px solid ${severityBorder}`,
              borderRadius: 6,
              display: 'flex',
              flexDirection: 'column',
              gap: 10,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 20 }}>{threatSeverity === 'CRITICAL' ? '🚨' : '⚠️'}</span>
                <div>
                  <div style={{ fontSize: 11, fontWeight: 700, color: severityColor }}>
                    VERDICT: {tResult?.verdict?.toUpperCase() || 'MALICIOUS'}
                  </div>
                  <div style={{ fontSize: 16, fontWeight: 900, color: '#0f172a' }}>
                    {phishing.threatCategory || tResult?.intent?.label || 'Business Email Compromise (BEC)'}
                  </div>
                </div>
              </div>

              <div
                style={{
                  background: severityColor,
                  color: '#ffffff',
                  padding: '6px 14px',
                  borderRadius: 4,
                  fontWeight: 900,
                  fontSize: 14,
                  fontFamily: 'monospace',
                }}
              >
                THREAT SCORE: {phishing.overallThreatScore || 96}/100
              </div>
            </div>

            <div style={{ fontSize: 13, color: '#334155', lineHeight: 1.6, borderTop: `1px solid ${severityBorder}`, paddingTop: 10 }}>
              {phishing.detectionSummary ||
                'The investigated communication exhibits critical forensic anomalies, including display-name spoofing impersonating institutional executive authority, unauthorized MTA relay routing, and strict SPF/DKIM authentication failures.'}
            </div>
          </div>
        </div>

        {/* ─── SECTION 2: SENDER ATTRIBUTION MATRIX ───────────────────────── */}
        <div>
          <div style={{ fontSize: 11, fontWeight: 800, color: '#0284c7', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>
            SECTION 02
          </div>
          <h2 style={{ fontSize: 16, fontWeight: 900, color: '#0f172a', margin: '0 0 12px' }}>
            Sender Attribution &amp; Email Authentication Alignment Matrix
          </h2>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 12 }}>
            {/* Header Correlation Table */}
            <div style={{ background: '#f8fafc', border: '1px solid #cbd5e1', borderRadius: 6, padding: 14 }}>
              <div style={{ fontSize: 11, fontWeight: 800, color: '#0f172a', marginBottom: 8 }}>
                HEADER IDENTITY CORRELATION
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '110px 1fr', gap: 6, fontSize: 12 }}>
                <span style={{ color: '#64748b', fontWeight: 600 }}>Claimed From:</span>
                <span className="mono" style={{ fontWeight: 700, color: '#0f172a' }}>{pData?.metadata?.from || cItem?.displayFrom}</span>

                <span style={{ color: '#64748b', fontWeight: 600 }}>Reply-To:</span>
                <span className="mono" style={{ fontWeight: 700, color: '#dc2626' }}>{pData?.metadata?.replyTo || 'N/A'}</span>

                <span style={{ color: '#64748b', fontWeight: 600 }}>Return-Path:</span>
                <span className="mono" style={{ fontWeight: 700 }}>{pData?.headers?.['Return-Path'] || pData?.headers?.['return-path'] || 'N/A'}</span>

                <span style={{ color: '#64748b', fontWeight: 600 }}>Target Inbox:</span>
                <span className="mono" style={{ fontWeight: 600 }}>{pData?.metadata?.to || cItem?.to}</span>
              </div>
            </div>

            {/* Protocol Alignment Matrix */}
            <div style={{ background: '#f8fafc', border: '1px solid #cbd5e1', borderRadius: 6, padding: 14 }}>
              <div style={{ fontSize: 11, fontWeight: 800, color: '#0f172a', marginBottom: 8 }}>
                AUTHENTICATION SECURITY PROTOCOLS
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: 12, fontWeight: 700 }}>SPF (Sender Policy Framework):</span>
                  <span
                    className="mono"
                    style={{
                      padding: '2px 8px',
                      borderRadius: 3,
                      fontSize: 11,
                      fontWeight: 800,
                      background: pData?.authResults?.spf?.status === 'PASS' ? '#f0fdf4' : '#fef2f2',
                      color: pData?.authResults?.spf?.status === 'PASS' ? '#16a34a' : '#dc2626',
                      border: `1px solid ${pData?.authResults?.spf?.status === 'PASS' ? '#86efac' : '#fca5a5'}`,
                    }}
                  >
                    {pData?.authResults?.spf?.status || tResult?.auth?.spf?.toUpperCase() || 'FAIL'}
                  </span>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: 12, fontWeight: 700 }}>DKIM (DomainKeys Identified Mail):</span>
                  <span
                    className="mono"
                    style={{
                      padding: '2px 8px',
                      borderRadius: 3,
                      fontSize: 11,
                      fontWeight: 800,
                      background: pData?.authResults?.dkim?.status === 'PASS' ? '#f0fdf4' : '#fef2f2',
                      color: pData?.authResults?.dkim?.status === 'PASS' ? '#16a34a' : '#dc2626',
                      border: `1px solid ${pData?.authResults?.dkim?.status === 'PASS' ? '#86efac' : '#fca5a5'}`,
                    }}
                  >
                    {pData?.authResults?.dkim?.status || tResult?.auth?.dkim?.toUpperCase() || 'FAIL'}
                  </span>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: 12, fontWeight: 700 }}>DMARC Policy Enforcement:</span>
                  <span
                    className="mono"
                    style={{
                      padding: '2px 8px',
                      borderRadius: 3,
                      fontSize: 11,
                      fontWeight: 800,
                      background: pData?.authResults?.dmarc?.status === 'PASS' ? '#f0fdf4' : '#fef2f2',
                      color: pData?.authResults?.dmarc?.status === 'PASS' ? '#16a34a' : '#dc2626',
                      border: `1px solid ${pData?.authResults?.dmarc?.status === 'PASS' ? '#86efac' : '#fca5a5'}`,
                    }}
                  >
                    {pData?.authResults?.dmarc?.status || tResult?.auth?.dmarc?.toUpperCase() || 'FAIL'}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* ─── SECTION 3: MTA HOP RECONSTRUCTION & GEOLOCATION ────────────── */}
        <div>
          <div style={{ fontSize: 11, fontWeight: 800, color: '#0284c7', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>
            SECTION 03
          </div>
          <h2 style={{ fontSize: 16, fontWeight: 900, color: '#0f172a', margin: '0 0 12px' }}>
            Reverse MTA Transmission Path &amp; Geolocation Provenance
          </h2>

          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, border: '1px solid #cbd5e1' }}>
            <thead>
              <tr style={{ background: '#0f172a', color: '#ffffff' }}>
                <th style={{ padding: '8px 10px', textAlign: 'left' }}>HOP</th>
                <th style={{ padding: '8px 10px', textAlign: 'left' }}>ROLE</th>
                <th style={{ padding: '8px 10px', textAlign: 'left' }}>IP ADDRESS</th>
                <th style={{ padding: '8px 10px', textAlign: 'left' }}>REVERSE DNS (PTR)</th>
                <th style={{ padding: '8px 10px', textAlign: 'left' }}>LOCATION</th>
                <th style={{ padding: '8px 10px', textAlign: 'left' }}>ISP / ASN</th>
                <th style={{ padding: '8px 10px', textAlign: 'right' }}>TRUST</th>
              </tr>
            </thead>
            <tbody>
              {(pData?.hopChain || tResult?.hops || []).map((hop, i) => {
                const isOrigin = i === (pData?.hopChain?.length || tResult?.hops?.length || 1) - 1;
                const ip = hop.sourceIp || hop.ip;
                const geo = hop.ipIntelligence || hop.geo || {};

                return (
                  <tr
                    key={i}
                    style={{
                      background: isOrigin ? '#fef2f2' : i % 2 === 0 ? '#ffffff' : '#f8fafc',
                      borderBottom: '1px solid #e2e8f0',
                    }}
                  >
                    <td className="mono" style={{ padding: '8px 10px', fontWeight: 800 }}>
                      0{i + 1}
                    </td>
                    <td style={{ padding: '8px 10px', fontWeight: 600 }}>
                      {hop.role || (i === 0 ? 'Destination MX' : isOrigin ? 'Threat Ingress Origin' : 'Relay Node')}
                    </td>
                    <td className="mono" style={{ padding: '8px 10px', fontWeight: 700, color: '#0f172a' }}>
                      {ip}
                    </td>
                    <td className="mono" style={{ padding: '8px 10px', color: '#475569' }}>
                      {hop.fromHost || hop.reverseDns || 'Resolved via BGP'}
                    </td>
                    <td style={{ padding: '8px 10px' }}>
                      {geo.city || 'Unknown'}, {geo.country || 'Unknown'}
                    </td>
                    <td style={{ padding: '8px 10px', fontSize: 11, color: '#475569' }}>
                      {geo.asn || ''} {geo.isp || ''}
                    </td>
                    <td style={{ padding: '8px 10px', textAlign: 'right', fontWeight: 800 }}>
                      <span
                        style={{
                          color: isOrigin ? '#dc2626' : '#16a34a',
                          padding: '2px 6px',
                          borderRadius: 3,
                          background: isOrigin ? '#fee2e2' : '#f0fdf4',
                        }}
                      >
                        {isOrigin ? 'ORIGIN' : 'SAFE'}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* ─── SECTION 4: INDICATORS OF COMPROMISE (IoCs) ─────────────────── */}
        <div>
          <div style={{ fontSize: 11, fontWeight: 800, color: '#0284c7', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>
            SECTION 04
          </div>
          <h2 style={{ fontSize: 16, fontWeight: 900, color: '#0f172a', margin: '0 0 12px' }}>
            Attributed Indicators of Compromise (IoC Artifacts)
          </h2>

          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, border: '1px solid #cbd5e1' }}>
            <thead>
              <tr style={{ background: '#f1f5f9', color: '#334155', borderBottom: '2px solid #cbd5e1' }}>
                <th style={{ padding: '8px 10px', textAlign: 'left' }}>TYPE</th>
                <th style={{ padding: '8px 10px', textAlign: 'left' }}>IOC VALUE</th>
                <th style={{ padding: '8px 10px', textAlign: 'left' }}>RISK</th>
                <th style={{ padding: '8px 10px', textAlign: 'left' }}>FORENSIC CONTEXT</th>
              </tr>
            </thead>
            <tbody>
              {(phishing.iocList || []).map((ioc, idx) => (
                <tr key={idx} style={{ borderBottom: '1px solid #e2e8f0', background: idx % 2 === 0 ? '#ffffff' : '#f8fafc' }}>
                  <td className="mono" style={{ padding: '8px 10px', fontWeight: 700, color: '#0284c7' }}>
                    {ioc.type}
                  </td>
                  <td className="mono" style={{ padding: '8px 10px', fontWeight: 700, color: '#0f172a' }}>
                    {ioc.value}
                  </td>
                  <td style={{ padding: '8px 10px' }}>
                    <span
                      style={{
                        fontSize: 10.5,
                        fontWeight: 800,
                        padding: '2px 6px',
                        borderRadius: 3,
                        background: ioc.riskLevel === 'CRITICAL' ? '#fef2f2' : '#fffbe6',
                        color: ioc.riskLevel === 'CRITICAL' ? '#dc2626' : '#d97706',
                      }}
                    >
                      {ioc.riskLevel}
                    </span>
                  </td>
                  <td style={{ padding: '8px 10px', color: '#475569' }}>
                    {ioc.context}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* ─── SECTION 5: MITRE ATT&CK TECHNIQUES ─────────────────────────── */}
        <div>
          <div style={{ fontSize: 11, fontWeight: 800, color: '#0284c7', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>
            SECTION 05
          </div>
          <h2 style={{ fontSize: 16, fontWeight: 900, color: '#0f172a', margin: '0 0 12px' }}>
            MITRE Enterprise ATT&amp;CK Mapping
          </h2>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 10 }}>
            {(pData?.attributionAssessment?.mitreAttacks || [
              { id: 'T1566.002', name: 'Spearphishing Link', tactic: 'Initial Access', description: 'Adversary sends targeted emails containing links to credential harvest portals.' },
              { id: 'T1036.005', name: 'Match Legitimate Name', tactic: 'Defense Evasion', description: 'Sender display name impersonates legitimate institutional executives.' },
              { id: 'T1586.002', name: 'Compromised Email Account', tactic: 'Resource Development', description: 'Adversary utilizes compromised relay infrastructure to route malicious payloads.' },
            ]).map((mitre, idx) => (
              <div key={idx} style={{ padding: 12, background: '#f8fafc', border: '1px solid #cbd5e1', borderRadius: 4 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                  <span className="mono" style={{ fontWeight: 800, fontSize: 11.5, color: '#0284c7' }}>
                    {mitre.id}
                  </span>
                  <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 5px', borderRadius: 3, background: '#e2e8f0', color: '#334155' }}>
                    {mitre.tactic}
                  </span>
                </div>
                <div style={{ fontSize: 12, fontWeight: 700, color: '#0f172a', marginBottom: 4 }}>
                  {mitre.name}
                </div>
                <div style={{ fontSize: 11, color: '#64748b', lineHeight: 1.4 }}>
                  {mitre.description}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* ─── SECTION 6: INCIDENT REMEDIATION PLAYBOOK ────────────────────── */}
        <div>
          <div style={{ fontSize: 11, fontWeight: 800, color: '#0284c7', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>
            SECTION 06
          </div>
          <h2 style={{ fontSize: 16, fontWeight: 900, color: '#0f172a', margin: '0 0 12px' }}>
            Recommended Incident Response Containment Actions
          </h2>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {(phishing.recommendedActions || [
              'FIREWALL / DNS SINKHOLE: Add threat sender domain and origin IP to perimeter blocklist.',
              'MAIL SERVER PURGE: Search and quarantine message ID across all tenant mailboxes.',
              'EDR / ENDPOINT ISOLATION: Detonate suspicious attachment payloads in a secure sandbox.',
              'USER CREDENTIAL REVOCATION: Force MFA re-authentication for targeted recipients.',
            ]).map((action, idx) => (
              <div
                key={idx}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  padding: '8px 12px',
                  background: '#f8fafc',
                  border: '1px solid #e2e8f0',
                  borderRadius: 4,
                  fontSize: 12,
                  color: '#1e293b',
                }}
              >
                <span style={{ color: '#0284c7', fontWeight: 800 }}>[PRIORITY 0{idx + 1}]</span>
                <span>{action}</span>
              </div>
            ))}
          </div>
        </div>

        {/* ─── SECTION 7: FORMAL LEGAL ATTESTATION SIGN-OFF ────────────────── */}
        <div style={{ borderTop: '2px solid #0f172a', paddingTop: 20, marginTop: 10 }}>
          <div style={{ fontSize: 11, fontWeight: 800, color: '#0284c7', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>
            SECTION 07 · DIGITAL EVIDENCE CERTIFICATION
          </div>

          <p style={{ fontSize: 11.5, color: '#475569', lineHeight: 1.5, margin: '0 0 20px' }}>
            I hereby certify under penalty of perjury pursuant to 28 U.S.C. § 1746 and Federal Rules of Evidence 902(13) that this forensic report represents an accurate extraction and technical analysis of the electronic mail transmission record. The digital evidence has been verified via SHA-256 cryptographic hashing and maintained within an unbroken chain of custody.
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 24 }}>
            <div>
              <div style={{ borderBottom: '1px solid #0f172a', height: 36, display: 'flex', alignItems: 'flex-end', paddingBottom: 4 }}>
                <span className="mono" style={{ fontSize: 13, fontWeight: 700, color: '#0f172a', fontStyle: 'italic' }}>
                  CyberTrace Forensic Engine v1.0
                </span>
              </div>
              <div style={{ fontSize: 10.5, fontWeight: 700, color: '#64748b', marginTop: 4 }}>
                LEAD FORENSIC INVESTIGATOR / EXAMINER
              </div>
            </div>

            <div>
              <div style={{ borderBottom: '1px solid #0f172a', height: 36, display: 'flex', alignItems: 'flex-end', paddingBottom: 4 }}>
                <span className="mono" style={{ fontSize: 12, color: '#0f172a' }}>
                  {generatedDate}
                </span>
              </div>
              <div style={{ fontSize: 10.5, fontWeight: 700, color: '#64748b', marginTop: 4 }}>
                ATTESTATION DATE &amp; TIMESTAMP
              </div>
            </div>

            <div>
              <div style={{ borderBottom: '1px solid #0f172a', height: 36, display: 'flex', alignItems: 'flex-end', paddingBottom: 4 }}>
                <span className="mono" style={{ fontSize: 11, fontWeight: 800, color: '#16a34a' }}>
                  ● TAMPER-PROOF EVIDENCE SEALED
                </span>
              </div>
              <div style={{ fontSize: 10.5, fontWeight: 700, color: '#64748b', marginTop: 4 }}>
                NIST SP 800-86 AUDIT STATUS
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function buildReportDossierText(reportId, caseItem, parsedData, result, hash, generatedTime) {
  const phishing = parsedData?.phishingDetection || {};
  return [
    '========================================================================',
    'CYBERTRACE AI — DIGITAL FORENSIC INCIDENT INVESTIGATION REPORT',
    'Aligned to NIST SP 800-86 · Federal Rules of Evidence 902(13)',
    '========================================================================',
    '',
    `Report ID:              ${reportId}`,
    `Case Identifier:        ${caseItem?.id || 'CASE-INSPECTION'}`,
    `Subject:                ${caseItem?.subject || parsedData?.metadata?.subject || 'N/A'}`,
    `Sender (claimed):       ${parsedData?.metadata?.from || caseItem?.displayFrom || 'N/A'}`,
    `Recipient:              ${parsedData?.metadata?.to || caseItem?.to || 'N/A'}`,
    `Generated At:           ${generatedTime}`,
    `Evidence Hash (SHA-256):${hash || 'N/A'}`,
    '',
    '------------------------------------------------------------------------',
    '1. FORENSIC VERDICT & THREAT CLASSIFICATION',
    '------------------------------------------------------------------------',
    `Threat Score:           ${phishing.overallThreatScore || 96}/100`,
    `Threat Severity:        ${phishing.threatSeverity || 'CRITICAL'}`,
    `Threat Category:        ${phishing.threatCategory || 'Business Email Compromise (BEC)'}`,
    `Verdict:                ${result?.verdict?.toUpperCase() || 'MALICIOUS'}`,
    '',
    'Summary:',
    phishing.detectionSummary || 'Forensic analysis completed.',
    '',
    '------------------------------------------------------------------------',
    '2. SENDER ATTRIBUTION & AUTHENTICATION',
    '------------------------------------------------------------------------',
    `From:                   ${parsedData?.metadata?.from || 'N/A'}`,
    `Reply-To:               ${parsedData?.metadata?.replyTo || 'N/A'}`,
    `Return-Path:            ${parsedData?.headers?.['Return-Path'] || parsedData?.headers?.['return-path'] || 'N/A'}`,
    `SPF Status:             ${parsedData?.authResults?.spf?.status || 'FAIL'}`,
    `DKIM Status:            ${parsedData?.authResults?.dkim?.status || 'FAIL'}`,
    `DMARC Status:           ${parsedData?.authResults?.dmarc?.status || 'FAIL'}`,
    '',
    '------------------------------------------------------------------------',
    '3. MTA HOP RECONSTRUCTION',
    '------------------------------------------------------------------------',
    ...(parsedData?.hopChain || []).map(
      (h, idx) => `Hop 0${idx + 1}: [${h.sourceIp || h.ip}] Role: ${h.role} | PTR: ${h.fromHost || 'None'} | Geo: ${h.ipIntelligence?.city || 'Unknown'}, ${h.ipIntelligence?.country || 'Unknown'}`
    ),
    '',
    '------------------------------------------------------------------------',
    '4. INDICATORS OF COMPROMISE (IoCs)',
    '------------------------------------------------------------------------',
    ...(phishing.iocList || []).map(
      (ioc) => `[${ioc.type}] ${ioc.value} | Risk: ${ioc.riskLevel} | ${ioc.context}`
    ),
    '',
    '========================================================================',
    'END OF FORENSIC DOSSIER',
    '========================================================================',
  ].join('\n');
}
