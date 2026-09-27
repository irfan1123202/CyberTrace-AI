import React, { useState } from 'react';
import { maskPii } from '../../services/emailAnalysisService';

/**
 * IncidentResponsePanel
 * ---------------------------------------------------------------------------
 * Implements an institutional-grade Incident Response (IR) workflow aligned
 * with NIST SP 800-61 Rev 2 from email submission through containment,
 * eradication, confidential data masking, and formal closure.
 */
export default function IncidentResponsePanel({ parsedData, privacyMode, setPrivacyMode, onExportReport }) {
  const [incidentStatus, setIncidentStatus] = useState('CONTAINMENT ACTIVE');
  const [containmentActions, setContainmentActions] = useState({
    quarantineMailbox: true,
    blockPerimeterIp: true,
    sinkholeDomain: false,
    revokeCredentials: false,
    notifyFinance: true,
    submitThreatIntel: false,
  });
  const [analystNotes, setAnalystNotes] = useState('');
  const [actionLog, setActionLog] = useState([
    { time: new Date(Date.now() - 1000 * 60 * 18).toLocaleTimeString(), action: 'Case ingested into CyberTrace-AI triage queue.', actor: 'SYSTEM' },
    { time: new Date(Date.now() - 1000 * 60 * 17).toLocaleTimeString(), action: 'Cryptographic integrity digest computed (SHA-256).', actor: 'SYSTEM' },
    { time: new Date(Date.now() - 1000 * 60 * 15).toLocaleTimeString(), action: 'Automated detection flagged high-confidence BEC / Spoofing signals.', actor: 'ANALYSIS ENGINE' },
  ]);

  if (!parsedData) {
    return (
      <div className="panel" style={{ padding: 24, textAlign: 'center', color: '#64748b' }}>
        No case telemetry loaded for incident response operations.
      </div>
    );
  }

  const {
    metadata = {},
    phishingDetection = {},
    domainIntelligence = {},
    hopChain = [],
  } = parsedData;

  const originHop = hopChain[hopChain.length - 1] || null;
  const originIp = originHop?.sourceIp || 'UNKNOWN';
  const threatScore = phishingDetection.overallThreatScore || 0;
  const threatSeverity = phishingDetection.threatSeverity || 'CLEAN';

  const toggleContainment = (key, label) => {
    const updated = !containmentActions[key];
    setContainmentActions((prev) => ({ ...prev, [key]: updated }));

    setActionLog((prev) => [
      {
        time: new Date().toLocaleTimeString(),
        action: `${updated ? 'Executed' : 'Revoked'} containment: ${label}`,
        actor: 'LEAD SOC ANALYST',
      },
      ...prev,
    ]);
  };

  const handleAddNote = (e) => {
    e.preventDefault();
    if (!analystNotes.trim()) return;

    setActionLog((prev) => [
      {
        time: new Date().toLocaleTimeString(),
        action: `Analyst Note: ${analystNotes.trim()}`,
        actor: 'LEAD SOC ANALYST',
      },
      ...prev,
    ]);
    setAnalystNotes('');
  };

  // Status badge styling
  const statusColors = {
    'OPEN': { color: '#0284c7', bg: '#f0f9ff', border: '#bae6fd' },
    'UNDER INVESTIGATION': { color: '#d97706', bg: '#fffbe6', border: '#fde68a' },
    'CONTAINMENT ACTIVE': { color: '#dc2626', bg: '#fef2f2', border: '#fca5a5' },
    'REMEDIATED': { color: '#16a34a', bg: '#f0fdf4', border: '#86efac' },
    'CLOSED': { color: '#475569', bg: '#f8fafc', border: '#cbd5e1' },
  }[incidentStatus] || { color: '#475569', bg: '#f8fafc', border: '#cbd5e1' };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
      {/* 1. INCIDENT WORKFLOW HEADER BANNER */}
      <div
        className="panel fade-in"
        style={{
          background: statusColors.bg,
          border: `1px solid ${statusColors.border}`,
          borderLeft: `6px solid ${statusColors.color}`,
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
                  background: statusColors.color,
                  color: '#ffffff',
                }}
              >
                INCIDENT RESPONSE LIFECYCLE
              </span>
              <span style={{ fontSize: 11, fontWeight: 700, color: '#64748b' }}>
                NIST SP 800-61 Rev 2 Framework
              </span>
            </div>
            <h2 style={{ fontSize: 18, fontWeight: 900, color: '#0f172a', margin: '0 0 6px 0' }}>
              Case #{metadata.evidenceDigest ? metadata.evidenceDigest.substring(0, 10).toUpperCase() : 'IR-PENDING'} · Status: {incidentStatus}
            </h2>
            <div style={{ fontSize: 12.5, color: '#334155', maxWidth: 850 }}>
              Orchestrate triage, active containment, forensic artifact handling, and institutional stakeholder notification in compliance with cyber incident handling standards.
            </div>
          </div>

          {/* Workflow Status Selector */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, minWidth: 180 }}>
            <label style={{ fontSize: 10, fontWeight: 700, color: '#64748b' }}>
              INCIDENT PHASE DISPOSITION
            </label>
            <select
              value={incidentStatus}
              onChange={(e) => {
                setIncidentStatus(e.target.value);
                setActionLog((prev) => [
                  {
                    time: new Date().toLocaleTimeString(),
                    action: `Incident lifecycle phase updated to: ${e.target.value}`,
                    actor: 'INCIDENT COMMANDER',
                  },
                  ...prev,
                ]);
              }}
              style={{
                padding: '6px 10px',
                fontSize: 12,
                fontWeight: 700,
                borderRadius: 4,
                border: `1px solid ${statusColors.border}`,
                background: '#ffffff',
                color: statusColors.color,
                outline: 'none',
                cursor: 'pointer',
              }}
            >
              <option value="OPEN">1. OPEN / TRIAGE</option>
              <option value="UNDER INVESTIGATION">2. UNDER INVESTIGATION</option>
              <option value="CONTAINMENT ACTIVE">3. CONTAINMENT ACTIVE</option>
              <option value="REMEDIATED">4. REMEDIATED</option>
              <option value="CLOSED">5. CLOSED / ARCHIVED</option>
            </select>
          </div>
        </div>

        {/* 2. CONFIDENTIALITY & PRIVACY MASKING TOGGLE STRIP */}
        <div
          style={{
            marginTop: 14,
            paddingTop: 10,
            borderTop: '1px solid rgba(0,0,0,0.06)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: 10,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 16 }}>🔒</span>
            <div>
              <div style={{ fontSize: 11.5, fontWeight: 700, color: '#0f172a' }}>
                Confidential Data &amp; PII Redaction Mode (GDPR / Institutional IR Compliance)
              </div>
              <div style={{ fontSize: 10.5, color: '#64748b' }}>
                Masks human identities, email localparts, and sensitive payload tokens for external reporting.
              </div>
            </div>
          </div>

          <button
            onClick={() => setPrivacyMode && setPrivacyMode(!privacyMode)}
            className="btn"
            style={{
              fontSize: 11,
              fontWeight: 800,
              padding: '5px 12px',
              background: privacyMode ? '#f0fdf4' : '#f8fafc',
              borderColor: privacyMode ? '#86efac' : '#cbd5e1',
              color: privacyMode ? '#16a34a' : '#475569',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            <span>{privacyMode ? '🛡️ PII MASKING: ACTIVE' : '👁️ PII MASKING: OFF'}</span>
          </button>
        </div>
      </div>

      {/* 3. 5-STAGE NIST SP 800-61 PIPELINE PROGRESS */}
      <div
        className="panel"
        style={{
          background: '#ffffff',
          border: '1px solid #cbd5e1',
          borderRadius: 'var(--radius-sm)',
          padding: '16px 20px',
        }}
      >
        <div style={{ fontSize: 11, fontWeight: 800, color: '#0284c7', letterSpacing: '0.06em', marginBottom: 2 }}>
          FRAMEWORK PROGRESSION
        </div>
        <h3 style={{ fontSize: 15, fontWeight: 800, color: '#0f172a', margin: '0 0 14px 0' }}>
          Incident Handling Stages (NIST SP 800-61 Rev 2)
        </h3>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 10 }}>
          {[
            { stage: '1. PREPARATION & INTAKE', desc: 'SHA-256 evidence sealed', complete: true },
            { stage: '2. DETECTION & ANALYSIS', desc: `${phishingDetection.signalCount || 0} signals identified`, complete: true },
            { stage: '3. CONTAINMENT', desc: 'Perimeter & mailbox blocks', active: incidentStatus.includes('CONTAINMENT') || incidentStatus === 'UNDER INVESTIGATION', complete: incidentStatus === 'REMEDIATED' || incidentStatus === 'CLOSED' },
            { stage: '4. ERADICATION', desc: 'Credentials & tenant purge', active: incidentStatus === 'REMEDIATED', complete: incidentStatus === 'CLOSED' },
            { stage: '5. POST-INCIDENT', desc: 'Formal dossier export', active: incidentStatus === 'CLOSED', complete: false },
          ].map((item, idx) => {
            const isCompleted = item.complete;
            const isActive = item.active;

            const bg = isCompleted ? '#f0fdf4' : isActive ? '#fef2f2' : '#f8fafc';
            const border = isCompleted ? '#86efac' : isActive ? '#fca5a5' : '#e2e8f0';
            const textColor = isCompleted ? '#16a34a' : isActive ? '#dc2626' : '#64748b';

            return (
              <div
                key={idx}
                style={{
                  padding: '10px 12px',
                  background: bg,
                  border: `1px solid ${border}`,
                  borderRadius: 4,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 3,
                }}
              >
                <div style={{ fontSize: 11, fontWeight: 800, color: textColor, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span>{item.stage}</span>
                  <span>{isCompleted ? '✓' : isActive ? '●' : '○'}</span>
                </div>
                <div style={{ fontSize: 10.5, color: '#475569' }}>
                  {item.desc}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 4. ACTIVE CONTAINMENT DIRECTIVES & CONTROLS */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: 'var(--sp-4)' }}>
        {/* Containment Checklist */}
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
            <div style={{ fontSize: 11, fontWeight: 800, color: '#dc2626', letterSpacing: '0.06em' }}>
              IMMEDIATE MITIGATION
            </div>
            <h3 style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', margin: 0 }}>
              Active Containment Operations
            </h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {[
              {
                key: 'quarantineMailbox',
                label: 'Tenant-Wide Mailbox Quarantine',
                desc: 'Purge all delivered copies across enterprise Office 365 / Google Workspace inboxes.',
                critical: true,
              },
              {
                key: 'blockPerimeterIp',
                label: `Perimeter Firewall Block (${originIp})`,
                desc: `Push originating IP (${originIp}) to edge perimeter and SIEM threat blocklists.`,
                critical: true,
              },
              {
                key: 'sinkholeDomain',
                label: `DNS Sinkhole / Domain Block (${domainIntelligence.domain || 'Sender Domain'})`,
                desc: 'Prevent internal DNS resolution of the sender domain and associated infrastructure.',
                critical: false,
              },
              {
                key: 'revokeCredentials',
                label: 'Revoke Recipient Active Sessions & Reset Password',
                desc: 'Invalidate active OAuth2 / Kerberos / SSO tokens for affected recipient account.',
                critical: false,
              },
              {
                key: 'notifyFinance',
                label: 'Finance / Executive Emergency Advisory',
                desc: 'Instruct treasury and accounts payable to halt any pending wire disbursements.',
                critical: threatSeverity === 'CRITICAL',
              },
              {
                key: 'submitThreatIntel',
                label: 'Broadcast IoCs to Threat Intelligence (MISP / CISA)',
                desc: 'Share sanitized cryptographic hashes and IP/domain indicators with threat feeds.',
                critical: false,
              },
            ].map((action) => {
              const checked = containmentActions[action.key];

              return (
                <div
                  key={action.key}
                  onClick={() => toggleContainment(action.key, action.label)}
                  style={{
                    padding: '10px 12px',
                    borderRadius: 4,
                    border: `1px solid ${checked ? '#86efac' : '#e2e8f0'}`,
                    background: checked ? '#f0fdf4' : '#ffffff',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: 10,
                    transition: 'all 0.15s ease',
                  }}
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={() => {}}
                    style={{ marginTop: 2, cursor: 'pointer' }}
                  />
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 12, fontWeight: 700, color: checked ? '#16a34a' : '#0f172a' }}>
                      {action.label}
                    </div>
                    <div style={{ fontSize: 11, color: '#64748b', marginTop: 1 }}>
                      {action.desc}
                    </div>
                  </div>
                  {action.critical && (
                    <span
                      style={{
                        fontSize: 9.5,
                        fontWeight: 800,
                        padding: '1px 5px',
                        borderRadius: 3,
                        background: '#fef2f2',
                        color: '#dc2626',
                        border: '1px solid #fca5a5',
                      }}
                    >
                      CRITICAL
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Analyst Activity & Audit Log */}
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
            <div style={{ fontSize: 11, fontWeight: 800, color: '#0284c7', letterSpacing: '0.06em' }}>
              FORENSIC AUDIT TRAIL
            </div>
            <h3 style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', margin: 0 }}>
              Incident Response Activity Log
            </h3>
          </div>

          {/* Add Note Form */}
          <form onSubmit={handleAddNote} style={{ display: 'flex', gap: 6, marginBottom: 12 }}>
            <input
              type="text"
              value={analystNotes}
              onChange={(e) => setAnalystNotes(e.target.value)}
              placeholder="Record forensic note or decision..."
              style={{
                flex: 1,
                fontSize: 11.5,
                padding: '6px 10px',
                borderRadius: 4,
                border: '1px solid #cbd5e1',
                outline: 'none',
              }}
            />
            <button
              type="submit"
              className="btn btn-primary"
              style={{ fontSize: 11.5, fontWeight: 700, padding: '6px 12px' }}
            >
              Add Note
            </button>
          </form>

          {/* Activity Log List */}
          <div
            style={{
              flex: 1,
              maxHeight: 260,
              overflowY: 'auto',
              display: 'flex',
              flexDirection: 'column',
              gap: 6,
            }}
          >
            {actionLog.map((log, idx) => (
              <div
                key={idx}
                style={{
                  padding: '6px 10px',
                  background: '#f8fafc',
                  borderRadius: 4,
                  border: '1px solid #e2e8f0',
                  fontSize: 11,
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'flex-start',
                  gap: 8,
                }}
              >
                <div style={{ flex: 1, color: '#1e293b', lineHeight: 1.4 }}>
                  {log.action}
                </div>
                <div style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                  <span className="mono" style={{ fontSize: 10, color: '#64748b' }}>
                    {log.time}
                  </span>
                  <div style={{ fontSize: 9.5, fontWeight: 700, color: '#0284c7' }}>
                    {log.actor}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
