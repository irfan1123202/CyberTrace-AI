import React, { useState, useEffect, useRef } from 'react';
import { parseEml, maskPii } from '../services/emailAnalysisService';
import { SAMPLE_BEC_WIRE_TRANSFER, DEMO_EMAIL_OPTIONS } from '../data/sampleEmlData';
import GmailConnectorModal from '../components/analysis/GmailConnectorModal';
import SafeUrlModal from '../components/analysis/SafeUrlModal';
import HopMap from '../components/trace/HopMap';
import GeoPanel from '../components/trace/GeoPanel';
import VerdictPanel from '../components/trace/VerdictPanel';
import ForensicReport from '../components/trace/ForensicReport';
import PhishingDetectionPanel from '../components/trace/PhishingDetectionPanel';
import SenderAttributionPanel from '../components/trace/SenderAttributionPanel';
import InvestigationTimeline from '../components/trace/InvestigationTimeline';
import IncidentResponsePanel from '../components/trace/IncidentResponsePanel';
import InteractiveGeoMap from '../components/trace/InteractiveGeoMap';
import LinuxToolsConsole from '../components/trace/LinuxToolsConsole';

const TABS = [
  { id: 'trace', label: 'FORENSIC TRACE', icon: '◈' },
  { id: 'phishing', label: 'PHISHING & FRAUD', icon: '🎯' },
  { id: 'attribution', label: 'SENDER ATTRIBUTION', icon: '👤' },
  { id: 'timeline', label: 'INVESTIGATION TIMELINE', icon: '⏱️' },
  { id: 'incident', label: 'INCIDENT RESPONSE', icon: '🛡️' },
  { id: 'nlp', label: 'NLP THREAT ENGINE', icon: '🧠' },
  { id: 'protocol', label: 'PROTOCOL & HEADERS', icon: '☵' },
  { id: 'origin', label: 'ORIGIN & GEOLOCATION', icon: '🌐' },
  { id: 'linux', label: 'LINUX TOOLS (CLI)', icon: '🐧' },
  { id: 'domain', label: 'DOMAIN INTELLIGENCE', icon: '🏛️' },
  { id: 'graph', label: 'RELATIONSHIP GRAPH', icon: '🕸️' },
  { id: 'links', label: 'LINKS & ATTACHMENTS', icon: '☍' },
  { id: 'custody', label: 'CHAIN OF CUSTODY', icon: '📜' },
];

export default function EmailAnalysis() {
  const [selectedDemoId, setSelectedDemoId] = useState('sample-bec');
  const [isDemo, setIsDemo] = useState(true);
  const [filename, setFilename] = useState('sample-bec-wire-transfer.eml');
  const [parsedData, setParsedData] = useState(null);
  const [activeTab, setActiveTab] = useState('trace');
  const [headerSearch, setHeaderSearch] = useState('');
  const [gmailModalOpen, setGmailModalOpen] = useState(false);
  const [inspectUrl, setInspectUrl] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [privacyMode, setPrivacyMode] = useState(false);
  const [selectedGraphNode, setSelectedGraphNode] = useState(null);

  const fileInputRef = useRef(null);

  // Load default demo email on initial mount
  useEffect(() => {
    loadEmailContent(SAMPLE_BEC_WIRE_TRANSFER, 'sample-bec-wire-transfer.eml', true);
  }, []);

  const loadEmailContent = async (rawEml, sourceName, isDemoEmail = false) => {
    setLoading(true);
    setError(null);
    try {
      const data = await parseEml(rawEml, sourceName);
      setParsedData(data);
      setFilename(sourceName);
      setIsDemo(isDemoEmail);
      if (data.graphModel?.nodes?.length > 0) {
        setSelectedGraphNode(data.graphModel.nodes[0]);
      }
    } catch (err) {
      setError(err.message || 'Failed to parse RFC-5322 MIME email document.');
      setParsedData(null);
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result;
      if (typeof content === 'string') {
        loadEmailContent(content, file.name, false);
      }
    };
    reader.onerror = () => {
      setError('Failed to read the local file from disk.');
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  const handleUseDemo = (demoId = 'sample-bec') => {
    setSelectedDemoId(demoId);
    const demo = DEMO_EMAIL_OPTIONS.find((d) => d.id === demoId) || DEMO_EMAIL_OPTIONS[0];
    loadEmailContent(demo.content, `${demo.id}.eml`, true);
  };

  const caseItemAdapter = parsedData
    ? {
        id: parsedData.filename || 'EVIDENCE-SAMPLE.EML',
        subject: privacyMode ? maskPii(parsedData.metadata.subject) : parsedData.metadata.subject,
        displayFrom: privacyMode ? maskPii(parsedData.metadata.from) : parsedData.metadata.from,
        to: privacyMode ? maskPii(parsedData.metadata.to) : parsedData.metadata.to,
        receivedAt: parsedData.metadata.date,
      }
    : null;

  return (
    <div
      style={{
        maxWidth: 1240,
        margin: '0 auto',
        display: 'flex',
        flexDirection: 'column',
        gap: 'var(--sp-4)',
        paddingBottom: 'var(--sp-8)',
        fontFamily: 'var(--font-ui)',
      }}
    >
      {/* Modals */}
      <GmailConnectorModal isOpen={gmailModalOpen} onClose={() => setGmailModalOpen(false)} />
      <SafeUrlModal urlItem={inspectUrl} onClose={() => setInspectUrl(null)} />

      {/* 1. EMAIL ANALYSIS ENTRY HEADER */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 12,
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
            <span
              className="mono"
              style={{
                fontSize: 11,
                fontWeight: 800,
                color: '#0284c7',
                background: '#e0f2fe',
                padding: '1px 6px',
                borderRadius: 3,
                border: '1px solid #bae6fd',
              }}
            >
              DEFENSIVE PLATFORM
            </span>
            <span style={{ color: '#cbd5e1' }}>/</span>
            <span style={{ fontSize: 11, fontWeight: 700, color: '#64748b', letterSpacing: '0.04em' }}>
              SECURE WORKSPACE
            </span>
          </div>

          <h1 style={{ fontSize: 20, fontWeight: 800, color: '#0f172a', margin: 0, letterSpacing: '-0.01em' }}>
            Email Threat Detection &amp; Forensic Intelligence
          </h1>
        </div>

        {/* Entry Actions Strip */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          {/* Action 1: Gmail Connector (NOT CONFIGURED) */}
          <button
            onClick={() => setGmailModalOpen(true)}
            className="btn"
            style={{
              fontSize: 11.5,
              fontWeight: 700,
              padding: '6px 12px',
              color: '#475569',
              background: '#f8fafc',
              borderColor: '#cbd5e1',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
            }}
            title="Inspect OAuth2 read-only backend requirement"
          >
            <span>✉</span>
            <span>GMAIL CONNECTOR</span>
            <span
              className="mono"
              style={{
                fontSize: 9,
                fontWeight: 800,
                background: '#fef2f2',
                color: '#dc2626',
                padding: '1px 5px',
                borderRadius: 2,
                border: '1px solid #fca5a5',
              }}
            >
              NOT CONFIGURED
            </span>
          </button>

          <span style={{ color: '#cbd5e1' }}>|</span>

          {/* Action 2: IMPORT .EML */}
          <button
            onClick={() => fileInputRef.current?.click()}
            className="btn btn-primary"
            style={{
              fontSize: 11.5,
              fontWeight: 700,
              padding: '6px 14px',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              cursor: 'pointer',
            }}
          >
            <span>📁</span>
            <span>IMPORT .EML</span>
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".eml,.txt,.msg"
            onChange={handleFileUpload}
            style={{ display: 'none' }}
          />

          {/* Action 3: USE DEMO EMAIL */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <button
              onClick={() => handleUseDemo(selectedDemoId)}
              className="btn"
              style={{
                fontSize: 11.5,
                fontWeight: 700,
                padding: '6px 12px',
                color: '#0284c7',
                background: '#f0f9ff',
                borderColor: '#bae6fd',
                display: 'inline-flex',
                alignItems: 'center',
                gap: 5,
              }}
            >
              <span>⚡</span>
              <span>USE DEMO EMAIL</span>
            </button>

            <select
              value={selectedDemoId}
              onChange={(e) => handleUseDemo(e.target.value)}
              style={{
                padding: '6px 8px',
                fontSize: 11.5,
                fontWeight: 600,
                borderRadius: 'var(--radius-xs)',
                border: '1px solid #cbd5e1',
                background: '#ffffff',
                color: '#0f172a',
                outline: 'none',
                cursor: 'pointer',
              }}
              title="Select a simulated forensic scenario"
            >
              {DEMO_EMAIL_OPTIONS.map((opt) => (
                <option key={opt.id} value={opt.id}>
                  {opt.name}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Loading Indicator */}
      {loading && (
        <div className="panel" style={{ padding: 'var(--sp-6)', textAlign: 'center', background: '#ffffff' }}>
          <span className="pulse" style={{ width: 8, height: 8, borderRadius: '50%', background: '#0284c7', display: 'inline-block', marginRight: 8 }} />
          <span className="mono" style={{ fontSize: 13, fontWeight: 700 }}>PARSING RFC-5322 MIME HEADERS &amp; EXECUTING FORENSIC ENGINES...</span>
        </div>
      )}

      {/* Invalid File / Parsing Error Alert */}
      {error && (
        <div
          className="panel fade-in"
          style={{
            padding: '14px 16px',
            background: '#fef2f2',
            border: '1px solid #fca5a5',
            borderRadius: 'var(--radius-sm)',
            display: 'flex',
            alignItems: 'flex-start',
            gap: 12,
          }}
        >
          <span style={{ color: '#dc2626', fontSize: 18, fontWeight: 800 }}>✕</span>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 13, fontWeight: 800, color: '#991b1b', marginBottom: 2 }}>
              FILE VALIDATION ERROR
            </div>
            <div style={{ fontSize: 12, color: '#7f1d1d', lineHeight: 1.45 }}>
              {error}
            </div>
            <div style={{ fontSize: 11, color: '#b91c1c', marginTop: 6 }}>
              Please select a valid RFC-5322 MIME document (.eml or .txt) or test using <strong>[ USE DEMO EMAIL ]</strong>.
            </div>
          </div>
          <button
            onClick={() => handleUseDemo('sample-bec')}
            className="btn btn-sm"
            style={{ fontSize: 11, fontWeight: 700, padding: '4px 10px' }}
          >
            Load Safe Demo
          </button>
        </div>
      )}

      {parsedData && (
        <>
          {/* COMPONENT 5: REAL-TIME PRE-INTERACTION FORENSIC ALERT BANNER */}
          {parsedData.realTimeAlert && (
            <div
              style={{
                padding: '12px 16px',
                borderRadius: 'var(--radius-sm)',
                background: parsedData.realTimeAlert.alertLevel === 'CRITICAL' ? '#fef2f2' : parsedData.realTimeAlert.alertLevel === 'HIGH' ? '#fffbe6' : '#f0fdf4',
                border: `1px solid ${parsedData.realTimeAlert.alertLevel === 'CRITICAL' ? '#fca5a5' : parsedData.realTimeAlert.alertLevel === 'HIGH' ? '#fde68a' : '#86efac'}`,
                borderLeft: `5px solid ${parsedData.realTimeAlert.alertLevel === 'CRITICAL' ? '#dc2626' : parsedData.realTimeAlert.alertLevel === 'HIGH' ? '#d97706' : '#16a34a'}`,
                display: 'flex',
                flexDirection: 'column',
                gap: 8,
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span
                    className="mono"
                    style={{
                      fontSize: 10.5,
                      fontWeight: 800,
                      padding: '2px 7px',
                      borderRadius: 3,
                      background: parsedData.realTimeAlert.alertLevel === 'CRITICAL' ? '#dc2626' : parsedData.realTimeAlert.alertLevel === 'HIGH' ? '#d97706' : '#16a34a',
                      color: '#ffffff',
                    }}
                  >
                    {parsedData.realTimeAlert.alertLevel} ALERT
                  </span>
                  <span style={{ fontSize: 13, fontWeight: 800, color: '#0f172a' }}>
                    {parsedData.realTimeAlert.headline}
                  </span>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <span className="mono" style={{ fontSize: 11, fontWeight: 700, color: '#475569' }}>
                    FRAUD PROBABILITY: <strong style={{ color: parsedData.realTimeAlert.alertLevel === 'CRITICAL' ? '#dc2626' : '#0f172a' }}>{parsedData.realTimeAlert.fraudScore}%</strong>
                  </span>
                  <span
                    className="mono"
                    style={{
                      fontSize: 10,
                      fontWeight: 800,
                      padding: '2px 6px',
                      borderRadius: 3,
                      background: '#0f172a',
                      color: '#ffffff',
                    }}
                  >
                    PRE-INTERACTION INTERCEPTION
                  </span>
                </div>
              </div>

              {/* Actionable recommendations */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap', fontSize: 11.5, color: '#334155' }}>
                <strong style={{ color: '#0f172a' }}>RECOMMENDED SOC PROTOCOL:</strong>
                {parsedData.realTimeAlert.actionItems.map((act, idx) => (
                  <span key={idx} style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                    <span style={{ color: parsedData.realTimeAlert.alertLevel === 'CRITICAL' ? '#dc2626' : '#16a34a', fontWeight: 800 }}>✓</span>
                    <span>{act}</span>
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Evidence Identifier & Demo Banner with PII Privacy Mode Toggle */}
          <div
            style={{
              padding: '10px 14px',
              borderRadius: 'var(--radius-xs)',
              background: isDemo ? '#fffbe6' : '#f8fafc',
              border: `1px solid ${isDemo ? '#fde68a' : '#cbd5e1'}`,
              borderLeft: `4px solid ${isDemo ? '#d97706' : '#0284c7'}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: 10,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span
                className="mono"
                style={{
                  fontSize: 10,
                  fontWeight: 800,
                  padding: '2px 6px',
                  borderRadius: 3,
                  background: isDemo ? '#d97706' : '#0284c7',
                  color: '#ffffff',
                  letterSpacing: '0.04em',
                }}
              >
                {isDemo ? 'DEMO EMAIL · SIMULATED FORENSIC DATA' : 'EVIDENCE FILE · LOCAL CLIENT INGESTION'}
              </span>

              <span style={{ fontSize: 12, fontWeight: 700, color: '#0f172a' }}>
                EVIDENCE FILE: <span className="mono">{filename}</span>
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              {/* COMPONENT 6: PII Masking Privacy Mode Toggle */}
              <button
                onClick={() => setPrivacyMode(!privacyMode)}
                className="btn btn-sm"
                style={{
                  fontSize: 11,
                  fontWeight: 700,
                  padding: '3px 8px',
                  background: privacyMode ? '#f0fdf4' : '#ffffff',
                  color: privacyMode ? '#16a34a' : '#475569',
                  borderColor: privacyMode ? '#86efac' : '#cbd5e1',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 5,
                }}
                title="Toggle PII Masking under GDPR Article 5(1)(c) data minimization"
              >
                <span>{privacyMode ? '👁️' : '🕶️'}</span>
                <span>{privacyMode ? 'PII MASKING: ACTIVE (GDPR)' : 'PRIVACY MODE: OFF (FULL TIER-3)'}</span>
              </button>

              <div className="mono" style={{ fontSize: 11, color: '#475569' }}>
                SHA-256: <strong style={{ color: '#0f172a' }}>{parsedData.metadata.evidenceDigest.substring(0, 24)}...</strong>
              </div>
            </div>
          </div>

          {/* Core Email Metadata Card */}
          <div
            className="panel"
            style={{
              padding: '16px 20px',
              background: '#ffffff',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid #cbd5e1',
              boxShadow: '0 1px 4px rgba(15, 23, 42, 0.04)',
              display: 'flex',
              flexDirection: 'column',
              gap: 12,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
              <div style={{ flex: 1, minWidth: 300 }}>
                <div style={{ fontSize: 10.5, fontWeight: 700, color: '#64748b', letterSpacing: '0.04em', textTransform: 'uppercase', marginBottom: 2 }}>
                  EMAIL INVESTIGATION DOSSIER
                </div>
                <h2 style={{ fontSize: 18, fontWeight: 800, color: '#0f172a', margin: '0 0 4px', letterSpacing: '-0.01em' }}>
                  {privacyMode ? maskPii(parsedData.metadata.subject) : parsedData.metadata.subject}
                </h2>
                <div className="mono" style={{ fontSize: 11, color: '#64748b' }}>
                  MESSAGE-ID: {parsedData.metadata.messageId}
                </div>
              </div>

              {/* Authentication Summary Badges */}
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                <MiniAuthBadge label="SPF" status={parsedData.authResults.spf.status} />
                <MiniAuthBadge label="DKIM" status={parsedData.authResults.dkim.status} />
                <MiniAuthBadge label="DMARC" status={parsedData.authResults.dmarc.status} />
                <span
                  className="mono"
                  style={{
                    fontSize: 10.5,
                    fontWeight: 700,
                    padding: '3px 8px',
                    borderRadius: 3,
                    background: '#f8fafc',
                    color: '#0f172a',
                    border: '1px solid #cbd5e1',
                  }}
                >
                  HOPS: {parsedData.hopChain.length}
                </span>
              </div>
            </div>

            {/* Email Metadata Grid: FROM / TO / SUBJECT / DATE */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                gap: '8px 14px',
                background: '#f8fafc',
                padding: '10px 14px',
                borderRadius: 'var(--radius-xs)',
                border: '1px solid #e2e8f0',
                fontSize: 12,
              }}
            >
              <div>
                <span style={{ color: '#64748b', fontWeight: 700, fontSize: 11, marginRight: 6 }}>FROM:</span>
                <strong style={{ color: '#0f172a' }}>
                  {privacyMode ? maskPii(parsedData.metadata.from) : parsedData.metadata.from}
                </strong>
              </div>

              <div>
                <span style={{ color: '#64748b', fontWeight: 700, fontSize: 11, marginRight: 6 }}>TO:</span>
                <span style={{ color: '#334155' }}>
                  {privacyMode ? maskPii(parsedData.metadata.to) : parsedData.metadata.to}
                </span>
              </div>

              <div>
                <span style={{ color: '#64748b', fontWeight: 700, fontSize: 11, marginRight: 6 }}>REPLY-TO:</span>
                <span className="mono" style={{ color: '#334155' }}>
                  {privacyMode ? maskPii(parsedData.metadata.replyTo) : parsedData.metadata.replyTo}
                </span>
              </div>

              <div>
                <span style={{ color: '#64748b', fontWeight: 700, fontSize: 11, marginRight: 6 }}>DATE:</span>
                <span className="mono" style={{ color: '#334155' }}>{parsedData.metadata.date}</span>
              </div>
            </div>
          </div>

          {/* Tabs Navigation */}
          <div
            style={{
              display: 'flex',
              gap: 4,
              borderBottom: '1px solid #cbd5e1',
              paddingBottom: 0,
              overflowX: 'auto',
            }}
          >
            {TABS.map((tab) => {
              const active = activeTab === tab.id;
              let badge = null;
              if (tab.id === 'links') badge = parsedData.urls.length + parsedData.attachments.length;
              if (tab.id === 'origin') badge = parsedData.hopChain.length;
              if (tab.id === 'nlp') badge = `${parsedData.nlpAnalysis.overallFraudScore}%`;
              if (tab.id === 'graph') badge = parsedData.graphModel?.nodes?.length || 0;

              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 6,
                    padding: '9px 14px',
                    fontSize: 11.5,
                    fontWeight: active ? 800 : 600,
                    color: active ? '#0284c7' : '#64748b',
                    background: active ? '#ffffff' : 'transparent',
                    border: '1px solid',
                    borderColor: active ? '#cbd5e1 #cbd5e1 #ffffff #cbd5e1' : 'transparent',
                    borderTopLeftRadius: 4,
                    borderTopRightRadius: 4,
                    marginBottom: -1,
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                    whiteSpace: 'nowrap',
                  }}
                >
                  <span>{tab.icon}</span>
                  <span>{tab.label}</span>
                  {badge !== null && (
                    <span
                      className="mono"
                      style={{
                        fontSize: 9.5,
                        fontWeight: 700,
                        padding: '1px 5px',
                        borderRadius: 3,
                        background: active ? '#e0f2fe' : '#f1f5f9',
                        color: active ? '#0284c7' : '#64748b',
                        border: '1px solid #cbd5e1',
                      }}
                    >
                      {badge}
                    </span>
                  )}
                </button>
              );
            })}
          </div>

          {/* TAB 1: FORENSIC TRACE RESULT */}
          {activeTab === 'trace' && (
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '1.2fr 1fr',
                gap: 'var(--sp-4)',
                alignItems: 'start',
              }}
            >
              {/* Left Column: InteractiveGeoMap + HopMap + GeoPanel */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
                <InteractiveGeoMap
                  hops={parsedData.hopChain || parsedData.traceResult.hops}
                  originGeo={parsedData.traceResult.geo}
                  title="Geographic MTA Transmission Map"
                  height={320}
                />
                <HopMap hops={parsedData.traceResult.hops} />
                <GeoPanel geo={parsedData.traceResult.geo} />
              </div>

              {/* Right Column: VerdictPanel + ForensicReport */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
                <VerdictPanel result={parsedData.traceResult} />
                <ForensicReport
                  caseItem={caseItemAdapter}
                  result={parsedData.traceResult}
                  hash={parsedData.metadata.evidenceDigest}
                  parsedData={parsedData}
                />
              </div>
            </div>
          )}

          {/* TAB: PHISHING, SPOOFING & FRAUD DETECTION */}
          {activeTab === 'phishing' && (
            <PhishingDetectionPanel
              detection={parsedData.phishingDetection}
              parsedData={parsedData}
            />
          )}

          {/* TAB: SENDER ATTRIBUTION CORRELATION */}
          {activeTab === 'attribution' && (
            <SenderAttributionPanel
              parsedData={parsedData}
            />
          )}

          {/* TAB: INVESTIGATION TIMELINE */}
          {activeTab === 'timeline' && (
            <InvestigationTimeline
              parsedData={parsedData}
            />
          )}

          {/* TAB: INCIDENT RESPONSE WORKFLOW */}
          {activeTab === 'incident' && (
            <IncidentResponsePanel
              parsedData={parsedData}
              privacyMode={privacyMode}
              setPrivacyMode={setPrivacyMode}
              onExportReport={() => setActiveTab('custody')}
            />
          )}

          {/* TAB 2: COMPONENT 1 — NLP THREAT DETECTION ENGINE */}
          {activeTab === 'nlp' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
              {/* Threat Classification & Social Engineering Radar */}
              <div
                className="panel"
                style={{
                  padding: '18px 20px',
                  background: '#ffffff',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid #cbd5e1',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10, marginBottom: 12 }}>
                  <div>
                    <div style={{ fontSize: 11, fontWeight: 700, color: '#0284c7', textTransform: 'uppercase' }}>
                      NATURAL LANGUAGE PROCESSING (NLP) DEBERTA-V3 ENGINE
                    </div>
                    <h3 style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', margin: '2px 0 0' }}>
                      Behavioral &amp; Social Engineering Analysis
                    </h3>
                  </div>

                  <span
                    className="mono"
                    style={{
                      fontSize: 11,
                      fontWeight: 800,
                      padding: '4px 10px',
                      borderRadius: 3,
                      background: parsedData.nlpAnalysis.severity === 'CRITICAL' ? '#fef2f2' : parsedData.nlpAnalysis.severity === 'HIGH' ? '#fffbe6' : '#f0fdf4',
                      color: parsedData.nlpAnalysis.severity === 'CRITICAL' ? '#dc2626' : parsedData.nlpAnalysis.severity === 'HIGH' ? '#d97706' : '#16a34a',
                      border: `1px solid ${parsedData.nlpAnalysis.severity === 'CRITICAL' ? '#fca5a5' : '#86efac'}`,
                    }}
                  >
                    CLASSIFICATION: {parsedData.nlpAnalysis.threatClassification}
                  </span>
                </div>

                {/* 4 Threat Metric Bars */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12, marginBottom: 16 }}>
                  <ThreatScoreBar label="Temporal Urgency & Deadlines" score={parsedData.nlpAnalysis.urgencyScore} color="#dc2626" />
                  <ThreatScoreBar label="Executive Authority & Coercion" score={parsedData.nlpAnalysis.coercionScore} color="#ea580c" />
                  <ThreatScoreBar label="Financial & Wire Diversion" score={parsedData.nlpAnalysis.financialRiskScore} color="#d97706" />
                  <ThreatScoreBar label="Credential Theft & Login Cues" score={parsedData.nlpAnalysis.credentialTheftScore} color="#7c3aed" />
                </div>

                {/* Analytical Narrative */}
                <div
                  style={{
                    padding: '12px 14px',
                    borderRadius: 4,
                    background: '#f8fafc',
                    border: '1px solid #e2e8f0',
                    fontSize: 12,
                    lineHeight: 1.5,
                    color: '#334155',
                  }}
                >
                  <strong>Linguistic Forensic Assessment:</strong> {parsedData.nlpAnalysis.nlpSummary}
                </div>
              </div>

              {/* Detected Social Engineering Tactics */}
              <div
                className="panel"
                style={{
                  padding: '16px 20px',
                  background: '#ffffff',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid #cbd5e1',
                }}
              >
                <div style={{ fontSize: 11, fontWeight: 700, color: '#0284c7', textTransform: 'uppercase', marginBottom: 2 }}>
                  ATTACK PATTERNS IDENTIFIED
                </div>
                <h4 style={{ fontSize: 15, fontWeight: 800, color: '#0f172a', margin: '0 0 12px' }}>
                  Deceptive Influence Tactics ({parsedData.nlpAnalysis.tactics.length})
                </h4>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 10 }}>
                  {parsedData.nlpAnalysis.tactics.map((tac, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: '12px',
                        borderRadius: 3,
                        background: '#ffffff',
                        border: '1px solid #cbd5e1',
                        borderLeft: `4px solid ${tac.severity === 'CRITICAL' ? '#dc2626' : '#ea580c'}`,
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                        <strong style={{ fontSize: 12, color: '#0f172a' }}>{tac.tactic}</strong>
                        <span className="mono" style={{ fontSize: 9.5, fontWeight: 800, color: tac.severity === 'CRITICAL' ? '#dc2626' : '#ea580c' }}>
                          ● {tac.severity}
                        </span>
                      </div>
                      <div style={{ fontSize: 11.5, color: '#475569', lineHeight: 1.45 }}>
                        {tac.description}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Message Content Viewer with PII Privacy Mode */}
              <div
                className="panel"
                style={{
                  padding: '16px 20px',
                  background: '#ffffff',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid #cbd5e1',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 12,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ fontSize: 13, fontWeight: 800, color: '#0f172a' }}>
                    Isolated Message Body Viewer
                  </div>
                  <div className="mono" style={{ fontSize: 11, color: privacyMode ? '#16a34a' : '#64748b' }}>
                    {privacyMode ? '✓ PII REDACTED MODE (COMPLIANT)' : 'UNMASKED EVIDENCE MODE'}
                  </div>
                </div>

                {parsedData.body.html ? (
                  <div
                    style={{
                      padding: '16px',
                      borderRadius: 4,
                      border: '1px solid #e2e8f0',
                      background: '#ffffff',
                      color: '#0f172a',
                      lineHeight: 1.6,
                      fontSize: 13,
                    }}
                    dangerouslySetInnerHTML={{
                      __html: privacyMode ? maskPii(parsedData.body.html) : parsedData.body.html,
                    }}
                  />
                ) : (
                  <pre
                    className="mono"
                    style={{
                      padding: '16px',
                      borderRadius: 4,
                      border: '1px solid #e2e8f0',
                      background: '#f8fafc',
                      color: '#0f172a',
                      lineHeight: 1.5,
                      fontSize: 12,
                      whiteSpace: 'pre-wrap',
                    }}
                  >
                    {privacyMode ? maskPii(parsedData.body.text) : parsedData.body.text}
                  </pre>
                )}
              </div>
            </div>
          )}

          {/* TAB 3: COMPONENT 2 — EMAIL HEADER & PROTOCOL ANALYSIS */}
          {activeTab === 'protocol' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
              {/* Deep Protocol Matrix */}
              <div
                className="panel"
                style={{
                  padding: '16px 20px',
                  background: '#ffffff',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid #cbd5e1',
                }}
              >
                <div style={{ fontSize: 11, fontWeight: 700, color: '#0284c7', textTransform: 'uppercase', marginBottom: 2 }}>
                  SMTP PROTOCOL &amp; AUTHENTICATION INTEGRITY
                </div>
                <h3 style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', margin: '0 0 12px' }}>
                  Header Alignment &amp; Relay Manipulation Analysis
                </h3>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 12, marginBottom: 14 }}>
                  <ProtocolCheckCard
                    label="Envelope Sender Alignment"
                    status={parsedData.protocolAnalysis.envelopeMismatch ? 'FAIL / MISMATCH' : 'ALIGNED'}
                    detail={`From domain: ${parsedData.protocolAnalysis.fromDomain} vs Return-Path: ${parsedData.protocolAnalysis.returnPathDomain}`}
                    isError={parsedData.protocolAnalysis.envelopeMismatch}
                  />

                  <ProtocolCheckCard
                    label="Reply-To Thread Integrity"
                    status={parsedData.protocolAnalysis.replyToDivergence ? 'DIVERGED (HIJACK RISK)' : 'ALIGNED'}
                    detail={`Replies directed to: ${parsedData.protocolAnalysis.replyToDomain}`}
                    isError={parsedData.protocolAnalysis.replyToDivergence}
                  />

                  <ProtocolCheckCard
                    label="Message-ID Origin Alignment"
                    status={parsedData.protocolAnalysis.messageIdDomainMismatch ? 'ANOMALOUS GENERATOR' : 'ALIGNED'}
                    detail={`Generated host: ${parsedData.protocolAnalysis.messageId}`}
                    isError={parsedData.protocolAnalysis.messageIdDomainMismatch}
                  />

                  <ProtocolCheckCard
                    label="DMARC Policy Enforcement"
                    status={parsedData.protocolAnalysis.dmarcStatus}
                    detail="Validates DKIM/SPF alignment against published DNS policy"
                    isError={parsedData.protocolAnalysis.dmarcStatus === 'FAIL'}
                  />
                </div>

                {/* Routing Anomalies Checklist */}
                {parsedData.protocolAnalysis.routingAnomalies.length > 0 && (
                  <div style={{ border: '1px solid #fca5a5', background: '#fef2f2', borderRadius: 4, padding: '12px 14px' }}>
                    <strong style={{ fontSize: 12, color: '#991b1b', display: 'block', marginBottom: 6 }}>
                      DETECTED ROUTING &amp; HEADER ANOMALIES:
                    </strong>
                    <ul style={{ margin: 0, paddingLeft: 18, fontSize: 11.5, color: '#7f1d1d', lineHeight: 1.5 }}>
                      {parsedData.protocolAnalysis.routingAnomalies.map((anom, i) => (
                        <li key={i} style={{ marginBottom: 4 }}>
                          <strong>{anom.type}:</strong> {anom.detail}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>

              {/* Unfolded RFC-5322 Headers Table */}
              <div
                className="panel"
                style={{
                  padding: '16px 20px',
                  background: '#ffffff',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid #cbd5e1',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 12,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' }}>
                  <input
                    type="text"
                    placeholder="Search unfolded RFC-5322 headers (e.g. Received, From, SPF, DKIM)..."
                    value={headerSearch}
                    onChange={(e) => setHeaderSearch(e.target.value)}
                    style={{
                      width: 380,
                      padding: '7px 12px',
                      borderRadius: 'var(--radius-xs)',
                      border: '1px solid #cbd5e1',
                      fontSize: 12,
                      outline: 'none',
                    }}
                  />
                  <div className="mono" style={{ fontSize: 11, color: '#64748b' }}>
                    {parsedData.unfoldedHeaderCount} UNFOLDED RFC-5322 HEADER LINES
                  </div>
                </div>

                <div
                  style={{
                    border: '1px solid #e2e8f0',
                    borderRadius: 4,
                    overflow: 'hidden',
                    maxHeight: 500,
                    overflowY: 'auto',
                  }}
                >
                  {Object.entries(parsedData.headers)
                    .filter(([key, val]) => {
                      const q = headerSearch.toLowerCase();
                      return !q || key.toLowerCase().includes(q) || String(val).toLowerCase().includes(q);
                    })
                    .map(([key, val], idx) => {
                      const isAuth = key.toLowerCase().includes('authentication') || key.toLowerCase().includes('dkim');
                      const isReceived = key.toLowerCase() === 'received';
                      return (
                        <div
                          key={`${key}-${idx}`}
                          style={{
                            display: 'grid',
                            gridTemplateColumns: '220px 1fr',
                            gap: 12,
                            padding: '8px 12px',
                            borderBottom: '1px solid #f1f5f9',
                            background: isAuth ? '#f0f9ff' : isReceived ? '#fafcfe' : idx % 2 === 0 ? '#ffffff' : '#f8fafc',
                            fontSize: 11.5,
                          }}
                        >
                          <div className="mono" style={{ fontWeight: 700, color: isAuth ? '#0284c7' : '#0f172a' }}>
                            {key}:
                          </div>
                          <div className="mono" style={{ color: '#334155', wordBreak: 'break-all', lineHeight: 1.4 }}>
                            {Array.isArray(val) ? val.join('\n\n') : String(val)}
                          </div>
                        </div>
                      );
                    })}
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: COMPONENT 3 — ORIGIN TRACEABILITY & LOCATION ANALYSIS */}
          {activeTab === 'origin' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
              {/* Interactive GeoMap with Leaflet and Google Maps */}
              <InteractiveGeoMap
                hops={parsedData.hopChain}
                originGeo={parsedData.traceResult.geo}
                title="Geographic Origin & Transmission Pathway Map"
                height={400}
              />

              {/* Mandatory Anti-Fabrication Guarantee */}
              <div
                style={{
                  padding: '10px 14px',
                  background: '#f8fafc',
                  border: '1px solid #cbd5e1',
                  borderLeft: '4px solid #0f172a',
                  borderRadius: 'var(--radius-xs)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                }}
              >
                <span style={{ fontSize: 16 }}>⚖</span>
                <div style={{ fontSize: 11.5, color: '#1e293b', lineHeight: 1.45 }}>
                  <strong>INFRASTRUCTURE PROVENANCE STANDARD:</strong> IP geolocation designates the transmission network endpoint and BGP routing infrastructure. It does NOT represent the exact physical location of the threat actor.
                </div>
              </div>

              {/* Earliest Reliable Sending Node Callout */}
              <div
                className="panel"
                style={{
                  padding: '16px 20px',
                  background: '#ffffff',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid #cbd5e1',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  flexWrap: 'wrap',
                  gap: 12,
                }}
              >
                <div>
                  <div style={{ fontSize: 10.5, fontWeight: 700, color: '#0284c7', letterSpacing: '0.04em', textTransform: 'uppercase' }}>
                    EARLIEST OBSERVABLE TRANSMISSION NODE
                  </div>
                  <div className="mono" style={{ fontSize: 18, fontWeight: 800, color: '#0f172a', marginTop: 2 }}>
                    {parsedData.hopChain[parsedData.hopChain.length - 1]?.sourceIp}
                  </div>
                  <div style={{ fontSize: 12, color: '#475569', marginTop: 2 }}>
                    Hostname: {parsedData.hopChain[parsedData.hopChain.length - 1]?.fromHost} · Transit Role: Ingress Gateway
                  </div>
                </div>

                <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                  <div style={{ padding: '6px 12px', background: '#f8fafc', border: '1px solid #cbd5e1', borderRadius: 3 }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b' }}>NETWORK TYPE:</div>
                    <div className="mono" style={{ fontSize: 12, fontWeight: 700, color: '#0f172a' }}>
                      {parsedData.hopChain[parsedData.hopChain.length - 1]?.ipIntelligence.networkType}
                    </div>
                  </div>

                  <div style={{ padding: '6px 12px', background: '#f8fafc', border: '1px solid #cbd5e1', borderRadius: 3 }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b' }}>PRECISION TIER:</div>
                    <div className="mono" style={{ fontSize: 12, fontWeight: 700, color: '#0284c7' }}>
                      {parsedData.hopChain[parsedData.hopChain.length - 1]?.ipIntelligence.precision}
                    </div>
                  </div>
                </div>
              </div>

              {/* Hop-by-Hop Reconstruction Table */}
              <div
                className="panel"
                style={{
                  padding: '16px 20px',
                  background: '#ffffff',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid #cbd5e1',
                }}
              >
                <div style={{ fontSize: 11, fontWeight: 700, color: '#0284c7', textTransform: 'uppercase', marginBottom: 2 }}>
                  MTA TRANSIT CHRONOLOGY
                </div>
                <h3 style={{ fontSize: 15, fontWeight: 800, color: '#0f172a', margin: '0 0 12px' }}>
                  Reverse Hop Reconstruction (Inbox MX → Relays → Ingress Origin)
                </h3>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {parsedData.hopChain.map((hop) => (
                    <div
                      key={hop.hopNumber}
                      style={{
                        padding: '12px 14px',
                        borderRadius: 'var(--radius-xs)',
                        border: '1px solid #cbd5e1',
                        borderLeft: `4px solid ${hop.trustLevel === 'TRUSTED' ? '#16a34a' : hop.trustLevel === 'PARTIALLY TRUSTED' ? '#0284c7' : '#dc2626'}`,
                        background: '#ffffff',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 8,
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span
                            className="mono"
                            style={{
                              fontSize: 10.5,
                              fontWeight: 800,
                              padding: '1px 6px',
                              borderRadius: 3,
                              background: '#0f172a',
                              color: '#ffffff',
                            }}
                          >
                            HOP 0{hop.hopNumber}
                          </span>
                          <span style={{ fontSize: 12, fontWeight: 700, color: '#0f172a' }}>
                            {hop.role}
                          </span>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span className="mono" style={{ fontSize: 10, color: '#64748b' }}>
                            CONFIDENCE: {hop.parsingConfidence}
                          </span>
                          <span
                            className="mono"
                            style={{
                              fontSize: 10,
                              fontWeight: 800,
                              padding: '2px 7px',
                              borderRadius: 3,
                              background: hop.trustLevel === 'TRUSTED' ? '#f0fdf4' : hop.trustLevel === 'PARTIALLY TRUSTED' ? '#f0f9ff' : '#fef2f2',
                              color: hop.trustLevel === 'TRUSTED' ? '#16a34a' : hop.trustLevel === 'PARTIALLY TRUSTED' ? '#0284c7' : '#dc2626',
                              border: `1px solid ${hop.trustLevel === 'TRUSTED' ? '#86efac' : '#fca5a5'}`,
                            }}
                          >
                            ● {hop.trustLevel}
                          </span>
                        </div>
                      </div>

                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '6px 12px', fontSize: 11.5 }}>
                        <div>
                          <span style={{ color: '#64748b', fontWeight: 700, fontSize: 10 }}>IP ADDRESS:</span>
                          <div className="mono" style={{ fontWeight: 800, color: '#0f172a' }}>{hop.sourceIp}</div>
                        </div>
                        <div>
                          <span style={{ color: '#64748b', fontWeight: 700, fontSize: 10 }}>HOSTNAME:</span>
                          <div className="mono" style={{ color: '#334155' }}>{hop.fromHost}</div>
                        </div>
                        <div>
                          <span style={{ color: '#64748b', fontWeight: 700, fontSize: 10 }}>GEOLOCATION:</span>
                          <div style={{ color: '#0f172a' }}>{hop.ipIntelligence.city !== 'UNKNOWN' ? `${hop.ipIntelligence.city}, ` : ''}{hop.ipIntelligence.country}</div>
                        </div>
                        <div>
                          <span style={{ color: '#64748b', fontWeight: 700, fontSize: 10 }}>ISP &amp; ASN:</span>
                          <div className="mono" style={{ color: '#334155' }}>{hop.ipIntelligence.asn} {hop.ipIntelligence.isp}</div>
                        </div>
                      </div>

                      <div style={{ fontSize: 10.5, color: '#64748b', background: '#f8fafc', padding: '5px 8px', borderRadius: 3, border: '1px solid #e2e8f0' }}>
                        <span style={{ fontWeight: 700 }}>RAW EVIDENCE:</span>{' '}
                        <span className="mono" style={{ color: '#334155', wordBreak: 'break-all' }}>{hop.evidenceSnippet}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB: LINUX NETWORK FORENSIC TOOLS */}
          {activeTab === 'linux' && (
            <LinuxToolsConsole parsedData={parsedData} />
          )}

          {/* TAB 5: COMPONENT 3 — DOMAIN INTELLIGENCE */}
          {activeTab === 'domain' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
              <div
                className="panel"
                style={{
                  padding: '16px 20px',
                  background: '#ffffff',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid #cbd5e1',
                }}
              >
                <div style={{ fontSize: 11, fontWeight: 700, color: '#0284c7', textTransform: 'uppercase', marginBottom: 2 }}>
                  DOMAIN REGISTRATION &amp; WHOIS REPUTATION
                </div>
                <h3 style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', margin: '0 0 12px' }}>
                  Sender Infrastructure Profile: {parsedData.domainIntelligence.domain}
                </h3>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 12, marginBottom: 14 }}>
                  <div style={{ padding: '12px', background: '#f8fafc', borderRadius: 3, border: '1px solid #e2e8f0' }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b' }}>DOMAIN AGE &amp; CREATION:</div>
                    <div style={{ fontSize: 13, fontWeight: 800, color: '#0f172a', marginTop: 2 }}>
                      {parsedData.domainIntelligence.creationDate}
                    </div>
                    <span
                      className="mono"
                      style={{
                        fontSize: 9.5,
                        fontWeight: 800,
                        padding: '1px 6px',
                        borderRadius: 2,
                        marginTop: 4,
                        display: 'inline-block',
                        background: parsedData.domainIntelligence.ageRiskLevel.includes('CRITICAL') ? '#fef2f2' : '#f0fdf4',
                        color: parsedData.domainIntelligence.ageRiskLevel.includes('CRITICAL') ? '#dc2626' : '#16a34a',
                        border: `1px solid ${parsedData.domainIntelligence.ageRiskLevel.includes('CRITICAL') ? '#fca5a5' : '#86efac'}`,
                      }}
                    >
                      {parsedData.domainIntelligence.ageRiskLevel}
                    </span>
                  </div>

                  <div style={{ padding: '12px', background: '#f8fafc', borderRadius: 3, border: '1px solid #e2e8f0' }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b' }}>REGISTRAR:</div>
                    <div style={{ fontSize: 13, fontWeight: 800, color: '#0f172a', marginTop: 2 }}>
                      {parsedData.domainIntelligence.registrar}
                    </div>
                    <div className="mono" style={{ fontSize: 10, color: '#64748b', marginTop: 2 }}>
                      WHOIS: {parsedData.domainIntelligence.whoisPrivacy}
                    </div>
                  </div>

                  <div style={{ padding: '12px', background: '#f8fafc', borderRadius: 3, border: '1px solid #e2e8f0' }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b' }}>MX RECORD STATUS:</div>
                    <div style={{ fontSize: 12, fontWeight: 700, color: '#0f172a', marginTop: 2 }}>
                      {parsedData.domainIntelligence.mxRecordStatus}
                    </div>
                    <div className="mono" style={{ fontSize: 10, color: '#64748b', marginTop: 2 }}>
                      NAMESERVERS: {parsedData.domainIntelligence.nameServers.join(', ')}
                    </div>
                  </div>

                  <div style={{ padding: '12px', background: '#f8fafc', borderRadius: 3, border: '1px solid #e2e8f0' }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b' }}>TYPOSQUATTING / LOOKALIKE:</div>
                    <div style={{ fontSize: 12, fontWeight: 800, color: parsedData.domainIntelligence.typosquatting.isLookalike ? '#dc2626' : '#16a34a', marginTop: 2 }}>
                      {parsedData.domainIntelligence.typosquatting.isLookalike ? 'LOOKALIKE VARIATION DETECTED' : 'NO HOMOGLYPH DETECTED'}
                    </div>
                    <div style={{ fontSize: 11, color: '#475569', marginTop: 2 }}>
                      {parsedData.domainIntelligence.typosquatting.technique}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 6: COMPONENT 4 — RELATIONSHIP GRAPH & ATTRIBUTION */}
          {activeTab === 'graph' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
              <div
                className="panel"
                style={{
                  padding: '16px 20px',
                  background: '#ffffff',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid #cbd5e1',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10, marginBottom: 12 }}>
                  <div>
                    <div style={{ fontSize: 11, fontWeight: 700, color: '#0284c7', textTransform: 'uppercase' }}>
                      GRAPH-BASED RELATIONSHIP ANALYSIS
                    </div>
                    <h3 style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', margin: '2px 0 0' }}>
                      Entity Topology &amp; Attack Vector Path
                    </h3>
                  </div>

                  <span
                    className="mono"
                    style={{
                      fontSize: 11,
                      fontWeight: 800,
                      padding: '3px 8px',
                      borderRadius: 3,
                      background: '#0f172a',
                      color: '#ffffff',
                    }}
                  >
                    CAMPAIGN: {parsedData.attributionAssessment.attributedThreatGroup}
                  </span>
                </div>

                {/* Visual Node Grid */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12, marginBottom: 16 }}>
                  {parsedData.graphModel?.nodes?.map((node) => {
                    const isSelected = selectedGraphNode?.id === node.id;
                    return (
                      <div
                        key={node.id}
                        onClick={() => setSelectedGraphNode(node)}
                        style={{
                          padding: '12px 14px',
                          borderRadius: 'var(--radius-xs)',
                          border: `1px solid ${isSelected ? '#0284c7' : '#cbd5e1'}`,
                          borderLeft: `4px solid ${node.status === 'critical' ? '#dc2626' : node.status === 'warning' ? '#d97706' : node.status === 'safe' ? '#16a34a' : '#64748b'}`,
                          background: isSelected ? '#f0f9ff' : '#ffffff',
                          cursor: 'pointer',
                          transition: 'all 0.15s ease',
                          boxShadow: isSelected ? '0 0 0 2px #bae6fd' : 'none',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                          <span style={{ fontSize: 14 }}>{node.icon}</span>
                          <span
                            className="mono"
                            style={{
                              fontSize: 9.5,
                              fontWeight: 800,
                              padding: '1px 5px',
                              borderRadius: 2,
                              background: node.status === 'critical' ? '#fef2f2' : '#f8fafc',
                              color: node.status === 'critical' ? '#dc2626' : '#64748b',
                            }}
                          >
                            {node.badge}
                          </span>
                        </div>

                        <div style={{ fontSize: 12, fontWeight: 800, color: '#0f172a' }}>
                          {node.label}
                        </div>
                        <div className="mono" style={{ fontSize: 11, color: '#475569', wordBreak: 'break-all', marginTop: 2 }}>
                          {node.sublabel}
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Selected Node Telemetry Inspector */}
                {selectedGraphNode && (
                  <div
                    style={{
                      background: '#f8fafc',
                      borderRadius: 4,
                      border: '1px solid #cbd5e1',
                      padding: '14px 16px',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                      <span style={{ fontSize: 16 }}>{selectedGraphNode.icon}</span>
                      <strong style={{ fontSize: 13, color: '#0f172a' }}>
                        NODE TELEMETRY: {selectedGraphNode.label} ({selectedGraphNode.sublabel})
                      </strong>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '8px 12px', fontSize: 11.5 }}>
                      {Object.entries(selectedGraphNode.details || {}).map(([k, v]) => (
                        <div key={k}>
                          <span style={{ color: '#64748b', fontWeight: 700, fontSize: 10 }}>{k.toUpperCase()}:</span>
                          <div className="mono" style={{ color: '#0f172a', fontWeight: 600 }}>{String(v)}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* MITRE ATT&CK TTP Alignment */}
              <div
                className="panel"
                style={{
                  padding: '16px 20px',
                  background: '#ffffff',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid #cbd5e1',
                }}
              >
                <div style={{ fontSize: 11, fontWeight: 700, color: '#0284c7', textTransform: 'uppercase', marginBottom: 2 }}>
                  TACTICS, TECHNIQUES &amp; PROCEDURES
                </div>
                <h4 style={{ fontSize: 15, fontWeight: 800, color: '#0f172a', margin: '0 0 12px' }}>
                  MITRE Enterprise ATT&amp;CK Mapping
                </h4>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 10 }}>
                  {parsedData.attributionAssessment.mitreAttacks.map((mitre) => (
                    <div
                      key={mitre.id}
                      style={{
                        padding: '10px 12px',
                        background: '#f8fafc',
                        border: '1px solid #e2e8f0',
                        borderRadius: 3,
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 4,
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span className="mono" style={{ fontSize: 11, fontWeight: 800, color: '#0284c7' }}>
                          {mitre.id}
                        </span>
                        <span className="mono" style={{ fontSize: 10, color: '#64748b' }}>
                          {mitre.tactic}
                        </span>
                      </div>
                      <strong style={{ fontSize: 12, color: '#0f172a' }}>{mitre.name}</strong>
                      <div style={{ fontSize: 11, color: '#475569' }}>{mitre.evidence}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 7: LINKS & ATTACHMENTS */}
          {activeTab === 'links' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
              {/* Extracted Hyperlinks */}
              <div
                className="panel"
                style={{
                  padding: '16px 20px',
                  background: '#ffffff',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid #cbd5e1',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                  <div>
                    <div style={{ fontSize: 11, fontWeight: 700, color: '#0284c7', textTransform: 'uppercase' }}>
                      URL TELEMETRY
                    </div>
                    <h3 style={{ fontSize: 15, fontWeight: 800, color: '#0f172a', margin: 0 }}>
                      Extracted Links ({parsedData.urls.length})
                    </h3>
                  </div>
                  <div className="mono" style={{ fontSize: 11, color: '#dc2626', fontWeight: 700 }}>
                    SAFE ANALYSIS: NOT YET CONFIGURED
                  </div>
                </div>

                {parsedData.urls.length === 0 ? (
                  <div style={{ padding: '20px', textAlign: 'center', color: '#64748b', fontSize: 12 }}>
                    No hyperlinks detected in email body.
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    {parsedData.urls.map((u, i) => (
                      <div
                        key={i}
                        style={{
                          padding: '12px 14px',
                          borderRadius: 'var(--radius-xs)',
                          border: '1px solid #cbd5e1',
                          borderLeft: `4px solid ${u.riskRating === 'HIGH RISK' ? '#dc2626' : '#d97706'}`,
                          background: '#ffffff',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: 8,
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
                          <span className="mono" style={{ fontSize: 10, fontWeight: 800, color: u.riskRating === 'HIGH RISK' ? '#dc2626' : '#d97706' }}>
                            ● {u.riskRating} · {u.safeAnalysisStatus}
                          </span>
                          <button
                            onClick={() => setInspectUrl(u)}
                            className="btn btn-sm"
                            style={{ fontSize: 11, fontWeight: 700, padding: '4px 10px' }}
                          >
                            SAFE INSPECT →
                          </button>
                        </div>

                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '6px 12px', fontSize: 11.5 }}>
                          <div style={{ gridColumn: '1 / -1' }}>
                            <span style={{ color: '#64748b', fontWeight: 700, fontSize: 10 }}>ORIGINAL URL:</span>
                            <div className="mono" style={{ fontSize: 12, fontWeight: 700, color: '#0f172a', wordBreak: 'break-all' }}>
                              {u.originalUrl}
                            </div>
                          </div>
                          <div>
                            <span style={{ color: '#64748b', fontWeight: 700, fontSize: 10 }}>DOMAIN:</span>
                            <div className="mono" style={{ color: '#0f172a', fontWeight: 700 }}>{u.domain}</div>
                          </div>
                          <div>
                            <span style={{ color: '#64748b', fontWeight: 700, fontSize: 10 }}>REDIRECT STATUS:</span>
                            <div className="mono" style={{ color: '#64748b' }}>{u.redirectStatus}</div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Attachments Section */}
              <div
                className="panel"
                style={{
                  padding: '16px 20px',
                  background: '#ffffff',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid #cbd5e1',
                }}
              >
                <div style={{ fontSize: 11, fontWeight: 700, color: '#0284c7', textTransform: 'uppercase', marginBottom: 2 }}>
                  MIME ATTACHMENT INVENTORY
                </div>
                <h3 style={{ fontSize: 15, fontWeight: 800, color: '#0f172a', margin: '0 0 12px' }}>
                  Extracted Files ({parsedData.attachments.length})
                </h3>

                {parsedData.attachments.length === 0 ? (
                  <div style={{ padding: '20px', textAlign: 'center', color: '#64748b', fontSize: 12 }}>
                    No file attachments identified in message headers or boundaries.
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    {parsedData.attachments.map((att, idx) => (
                      <div
                        key={idx}
                        style={{
                          padding: '12px 14px',
                          borderRadius: 'var(--radius-xs)',
                          border: '1px solid #cbd5e1',
                          borderLeft: '4px solid #dc2626',
                          background: '#ffffff',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: 8,
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <span style={{ fontSize: 18 }}>📎</span>
                            <div>
                              <div style={{ fontSize: 13, fontWeight: 800, color: '#0f172a' }}>{att.filename}</div>
                              <div className="mono" style={{ fontSize: 11, color: '#64748b' }}>
                                TYPE: {att.mimeType} · SIZE: ~{Math.round(att.sizeBytes / 1024)} KB · EXT: .{att.extension}
                              </div>
                            </div>
                          </div>
                          <span className="mono" style={{ fontSize: 10, fontWeight: 800, padding: '3px 8px', borderRadius: 3, background: '#fef2f2', color: '#dc2626', border: '1px solid #fca5a5' }}>
                            {att.sandboxedStatus}
                          </span>
                        </div>

                        <div style={{ background: '#f8fafc', padding: '6px 10px', borderRadius: 3, border: '1px solid #e2e8f0' }}>
                          <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b', marginBottom: 2 }}>
                            AUTHENTIC WEB-CRYPTO SHA-256 DIGEST:
                          </div>
                          <div className="mono" style={{ fontSize: 11, fontWeight: 700, color: '#0f172a', wordBreak: 'break-all' }}>
                            {att.sha256}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 8: COMPONENT 6 — CHAIN OF CUSTODY & FORENSIC REPORT */}
          {activeTab === 'custody' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
              {/* Chain of Custody Ledger Card */}
              <div
                className="panel"
                style={{
                  padding: '16px 20px',
                  background: '#ffffff',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid #cbd5e1',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8, marginBottom: 12 }}>
                  <div>
                    <div style={{ fontSize: 11, fontWeight: 700, color: '#0284c7', textTransform: 'uppercase' }}>
                      EVIDENTIARY INTEGRITY &amp; PROVENANCE RECORD
                    </div>
                    <h3 style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', margin: '2px 0 0' }}>
                      Legal Chain of Custody (NIST SP 800-86 / FRE 902(13))
                    </h3>
                  </div>

                  <span
                    className="mono"
                    style={{
                      fontSize: 10.5,
                      fontWeight: 800,
                      padding: '3px 8px',
                      borderRadius: 3,
                      background: '#f0fdf4',
                      color: '#16a34a',
                      border: '1px solid #86efac',
                    }}
                  >
                    ✓ {parsedData.chainOfCustody.integritySeal}
                  </span>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 10, marginBottom: 14 }}>
                  <div style={{ padding: '10px 12px', background: '#f8fafc', borderRadius: 3, border: '1px solid #e2e8f0' }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b' }}>EVIDENCE IDENTIFIER:</div>
                    <div className="mono" style={{ fontSize: 12, fontWeight: 800, color: '#0f172a' }}>
                      {parsedData.chainOfCustody.evidenceId}
                    </div>
                  </div>

                  <div style={{ padding: '10px 12px', background: '#f8fafc', borderRadius: 3, border: '1px solid #e2e8f0' }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b' }}>INGESTION TIMESTAMP:</div>
                    <div className="mono" style={{ fontSize: 11.5, color: '#0f172a' }}>
                      {parsedData.chainOfCustody.ingestionTimestamp}
                    </div>
                  </div>

                  <div style={{ padding: '10px 12px', background: '#f8fafc', borderRadius: 3, border: '1px solid #e2e8f0' }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b' }}>CUSTODY OFFICER:</div>
                    <div style={{ fontSize: 12, fontWeight: 700, color: '#0f172a' }}>
                      {parsedData.chainOfCustody.ingestingOfficer}
                    </div>
                  </div>

                  <div style={{ padding: '10px 12px', background: '#f8fafc', borderRadius: 3, border: '1px solid #e2e8f0' }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b' }}>LEGAL STANDARD:</div>
                    <div style={{ fontSize: 11, color: '#334155' }}>
                      {parsedData.chainOfCustody.admissibilityStandard}
                    </div>
                  </div>
                </div>

                <div style={{ background: '#f8fafc', padding: '10px 12px', borderRadius: 3, border: '1px solid #e2e8f0', marginBottom: 12 }}>
                  <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b', marginBottom: 2 }}>
                    NON-REPUDIABLE SHA-256 CRYPTOGRAPHIC DIGEST:
                  </div>
                  <div className="mono" style={{ fontSize: 12, fontWeight: 800, color: '#0f172a', wordBreak: 'break-all' }}>
                    {parsedData.chainOfCustody.sha256Digest}
                  </div>
                </div>

                {/* Compliance Standards Checklist */}
                <div>
                  <div style={{ fontSize: 11, fontWeight: 700, color: '#475569', marginBottom: 6 }}>
                    COMPLIANCE &amp; LEGAL ADMISSIBILITY CERTIFICATIONS:
                  </div>
                  <ul style={{ margin: 0, paddingLeft: 18, fontSize: 11.5, color: '#334155', lineHeight: 1.5 }}>
                    {parsedData.chainOfCustody.complianceCertifications.map((cert, idx) => (
                      <li key={idx} style={{ marginBottom: 4 }}>{cert}</li>
                    ))}
                  </ul>
                </div>
              </div>

              {/* Forensic Report Component */}
              <ForensicReport
                caseItem={caseItemAdapter}
                result={parsedData.traceResult}
                hash={parsedData.metadata.evidenceDigest}
                parsedData={parsedData}
              />
            </div>
          )}
        </>
      )}

      <style>{`
        @media (max-width: 960px) {
          div[style*="grid-template-columns: 1.2fr 1fr"] {
            grid-template-columns: 1fr !important;
          }
        }
      `}</style>
    </div>
  );
}

function ThreatScoreBar({ label, score, color }) {
  return (
    <div style={{ padding: '10px 12px', background: '#f8fafc', borderRadius: 3, border: '1px solid #e2e8f0' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
        <span style={{ fontSize: 11, fontWeight: 700, color: '#475569' }}>{label}</span>
        <span className="mono" style={{ fontSize: 12, fontWeight: 800, color }}>{score}%</span>
      </div>
      <div style={{ height: 6, width: '100%', background: '#e2e8f0', borderRadius: 3, overflow: 'hidden' }}>
        <div style={{ width: `${score}%`, height: '100%', background: color, transition: 'width 0.4s ease' }} />
      </div>
    </div>
  );
}

function ProtocolCheckCard({ label, status, detail, isError }) {
  return (
    <div
      style={{
        padding: '12px',
        borderRadius: 3,
        background: isError ? '#fef2f2' : '#f0fdf4',
        border: `1px solid ${isError ? '#fca5a5' : '#86efac'}`,
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
        <strong style={{ fontSize: 11.5, color: '#0f172a' }}>{label}</strong>
        <span
          className="mono"
          style={{
            fontSize: 9.5,
            fontWeight: 800,
            padding: '1px 5px',
            borderRadius: 2,
            background: isError ? '#dc2626' : '#16a34a',
            color: '#ffffff',
          }}
        >
          {status}
        </span>
      </div>
      <div style={{ fontSize: 11, color: '#475569', lineHeight: 1.4 }}>
        {detail}
      </div>
    </div>
  );
}

function MiniAuthBadge({ label, status }) {
  const isPass = status === 'PASS' || status === 'PASSED';
  const isFail = status === 'FAIL' || status === 'FAILED';

  let color = '#d97706';
  let bg = '#fffbe6';
  let border = '#fde68a';

  if (isPass) {
    color = '#16a34a';
    bg = '#f0fdf4';
    border = '#86efac';
  } else if (isFail) {
    color = '#dc2626';
    bg = '#fef2f2';
    border = '#fca5a5';
  }

  return (
    <span
      className="mono"
      style={{
        fontSize: 10.5,
        fontWeight: 700,
        padding: '3px 8px',
        borderRadius: 3,
        background: bg,
        color,
        border: `1px solid ${border}`,
        display: 'inline-flex',
        alignItems: 'center',
        gap: 4,
      }}
    >
      <span>{label}:</span>
      <strong>{status}</strong>
    </span>
  );
}
