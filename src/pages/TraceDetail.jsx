import React, { useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { mockCases } from '../data/mockCases';
import { useTrace } from '../hooks/useTrace';
import LoadingTrace from '../components/common/LoadingTrace';
import HopMap from '../components/trace/HopMap';
import GeoPanel from '../components/trace/GeoPanel';
import VerdictPanel from '../components/trace/VerdictPanel';
import ForensicReport from '../components/trace/ForensicReport';
import StatusBadge from '../components/common/StatusBadge';

const RISK_MAP = {
  critical: { label: 'CRITICAL', color: '#dc2626', bg: '#fef2f2', border: '#fca5a5' },
  high: { label: 'HIGH', color: '#d97706', bg: '#fffbe6', border: '#fde68a' },
  medium: { label: 'MEDIUM', color: '#0369a1', bg: '#f0f9ff', border: '#bae6fd' },
  low: { label: 'LOW', color: '#475569', bg: '#f1f5f9', border: '#cbd5e1' },
};

export default function TraceDetail() {
  const { caseId } = useParams();
  const navigate = useNavigate();
  const caseItem = mockCases.find((c) => c.id === caseId);
  const { status, activeStage, result, hash, stages, start, reset } = useTrace();

  useEffect(() => {
    reset();
  }, [caseId]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!caseItem) {
    return (
      <div
        className="panel"
        style={{
          maxWidth: 600,
          margin: '60px auto',
          textAlign: 'center',
          padding: 'var(--sp-8)',
          background: '#ffffff',
          borderRadius: 'var(--radius-sm)',
          border: '1px solid #cbd5e1',
        }}
      >
        <div className="mono" style={{ fontSize: 24, marginBottom: 8, color: '#dc2626' }}>
          [404_CASE_NOT_FOUND]
        </div>
        <h2 style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', margin: '0 0 8px' }}>
          Incident Record Not Found
        </h2>
        <p style={{ color: '#475569', fontSize: 13, marginBottom: 20 }}>
          "{caseId}" does not exist in the active ingestion buffer or has been archived.
        </p>
        <button className="btn" onClick={() => navigate('/dashboard')}>
          ← Return to Case Queue
        </button>
      </div>
    );
  }

  const risk = RISK_MAP[caseItem.priority] || RISK_MAP.low;
  const dateTimeStr = new Date(caseItem.receivedAt).toLocaleString('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });

  return (
    <div
      style={{
        maxWidth: 1180,
        margin: '0 auto',
        display: 'flex',
        flexDirection: 'column',
        gap: 'var(--sp-4)',
        paddingBottom: 'var(--sp-8)',
        fontFamily: 'var(--font-ui)',
      }}
    >
      {/* Breadcrumb Navigation Strip */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <button
          className="mono"
          onClick={() => navigate('/dashboard')}
          style={{
            background: 'none',
            border: 'none',
            color: '#64748b',
            fontSize: 12,
            fontWeight: 700,
            padding: 0,
            cursor: 'pointer',
            display: 'inline-flex',
            alignItems: 'center',
            gap: 6,
          }}
        >
          <span>←</span>
          <span>QUEUE TRIAGE</span>
          <span style={{ color: '#cbd5e1' }}>/</span>
          <span style={{ color: '#0f172a' }}>DOSSIER [{caseItem.id}]</span>
        </button>

        <div className="mono" style={{ fontSize: 11, color: '#64748b' }}>
          PROTOCOL: RFC-5322 MIME FORENSICS · NIST SP 800-86
        </div>
      </div>

      {/* 1. CASE HEADER */}
      <div
        className="panel"
        style={{
          padding: 'var(--sp-4) var(--sp-5)',
          background: '#ffffff',
          borderRadius: 'var(--radius-sm)',
          border: '1px solid #cbd5e1',
          borderLeft: '4px solid #0284c7',
          boxShadow: '0 1px 4px rgba(15, 23, 42, 0.04)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          gap: 'var(--sp-4)',
          flexWrap: 'wrap',
        }}
      >
        <div style={{ flex: 1, minWidth: 320 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, flexWrap: 'wrap' }}>
            <span
              className="mono"
              style={{
                fontSize: 12.5,
                fontWeight: 800,
                color: '#0284c7',
                letterSpacing: '0.02em',
              }}
            >
              {caseItem.id}
            </span>
            <span style={{ color: '#cbd5e1' }}>|</span>
            <span
              style={{
                fontSize: 11,
                fontWeight: 700,
                color: '#64748b',
                letterSpacing: '0.05em',
                textTransform: 'uppercase',
              }}
            >
              EMAIL INFRASTRUCTURE INVESTIGATION
            </span>
          </div>

          <h1
            style={{
              fontSize: 18,
              fontWeight: 800,
              color: '#0f172a',
              margin: '0 0 10px',
              letterSpacing: '-0.01em',
            }}
          >
            {caseItem.subject}
          </h1>

          {/* Compact Metadata Matrix: SOURCE | DATE/TIME | STATUS | RISK */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
              gap: '6px 14px',
              fontSize: 12,
              background: '#f8fafc',
              padding: '8px 12px',
              borderRadius: 'var(--radius-xs)',
              border: '1px solid #e2e8f0',
            }}
          >
            <div>
              <span style={{ color: '#64748b', marginRight: 6, fontWeight: 700, fontSize: 11 }}>SOURCE:</span>
              <strong style={{ color: '#0f172a' }}>{caseItem.displayFrom}</strong>
            </div>

            <div>
              <span style={{ color: '#64748b', marginRight: 6, fontWeight: 700, fontSize: 11 }}>DATE / TIME:</span>
              <span className="mono" style={{ color: '#334155', fontWeight: 600 }}>{dateTimeStr}</span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ color: '#64748b', fontWeight: 700, fontSize: 11 }}>STATUS:</span>
              <StatusBadge variant={caseItem.status} />
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ color: '#64748b', fontWeight: 700, fontSize: 11 }}>RISK:</span>
              <span
                className="mono"
                style={{
                  fontSize: 10.5,
                  fontWeight: 800,
                  padding: '1px 6px',
                  borderRadius: 3,
                  background: risk.bg,
                  color: risk.color,
                  border: `1px solid ${risk.border}`,
                }}
              >
                ● {risk.label}
              </span>
            </div>
          </div>
        </div>

        {/* Primary Operational Action */}
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 8 }}>
          {status === 'idle' && (
            <button
              className="btn btn-primary"
              onClick={() => start(caseItem)}
              style={{
                padding: '9px 20px',
                fontSize: 13,
                fontWeight: 700,
                letterSpacing: '0.02em',
                display: 'inline-flex',
                alignItems: 'center',
                gap: 8,
              }}
            >
              <span>⚡</span>
              <span>RUN FORENSIC TRACE</span>
            </button>
          )}

          {status === 'running' && (
            <button
              className="btn btn-primary"
              disabled
              style={{
                padding: '9px 18px',
                fontSize: 12.5,
                fontWeight: 700,
                opacity: 0.85,
                cursor: 'not-allowed',
                display: 'inline-flex',
                alignItems: 'center',
                gap: 8,
              }}
            >
              <span className="pulse" style={{ width: 7, height: 7, borderRadius: '50%', background: '#ffffff' }} />
              <span>EXECUTING TRACE...</span>
            </button>
          )}

          {status === 'done' && (
            <button
              className="btn"
              onClick={() => start(caseItem)}
              style={{
                padding: '8px 16px',
                fontSize: 12,
                fontWeight: 700,
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
              }}
            >
              <span>↻</span>
              <span>RE-RUN FORENSIC TRACE</span>
            </button>
          )}

          <div className="mono" style={{ fontSize: 10, color: '#64748b' }}>
            SAMPLE: {caseItem.headerSample}
          </div>
        </div>
      </div>

      {/* 2. TRACE PIPELINE (Execution State) */}
      {status === 'running' && (
        <LoadingTrace stages={stages} activeStage={activeStage} />
      )}

      {/* Persistent Pipeline Summary Bar (when idle or done) */}
      {status !== 'running' && (
        <div
          className="panel"
          style={{
            padding: '8px 14px',
            background: '#ffffff',
            border: '1px solid #cbd5e1',
            borderRadius: 'var(--radius-sm)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: 10,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 10.5, fontWeight: 700, color: '#64748b', letterSpacing: '0.05em' }}>
              TRACE PIPELINE:
            </span>
            <div className="mono" style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11 }}>
              <span style={{ color: status === 'done' ? '#16a34a' : '#0f172a', fontWeight: 700 }}>INGEST</span>
              <span style={{ color: '#cbd5e1' }}>→</span>
              <span style={{ color: status === 'done' ? '#16a34a' : '#0f172a', fontWeight: 700 }}>HEADER PARSE</span>
              <span style={{ color: '#cbd5e1' }}>→</span>
              <span style={{ color: status === 'done' ? '#16a34a' : '#0f172a', fontWeight: 700 }}>AUTH VERIFY</span>
              <span style={{ color: '#cbd5e1' }}>→</span>
              <span style={{ color: status === 'done' ? '#16a34a' : '#0f172a', fontWeight: 700 }}>GEO TRACE</span>
              <span style={{ color: '#cbd5e1' }}>→</span>
              <span style={{ color: status === 'done' ? '#16a34a' : '#0f172a', fontWeight: 700 }}>AI CLASSIFY</span>
              <span style={{ color: '#cbd5e1' }}>→</span>
              <span style={{ color: status === 'done' ? '#16a34a' : '#0f172a', fontWeight: 700 }}>ATTRIBUTION</span>
            </div>
          </div>

          <div className="mono" style={{ fontSize: 10.5, fontWeight: 700 }}>
            {status === 'done' ? (
              <span style={{ color: '#16a34a' }}>✓ ALL 6 PHASES COMPLETE</span>
            ) : (
              <span style={{ color: '#64748b' }}>STATUS: READY TO EXECUTE</span>
            )}
          </div>
        </div>
      )}

      {/* IDLE STATE: Staged Incident Staging Box */}
      {status === 'idle' && (
        <div
          className="panel fade-in"
          style={{
            padding: 'var(--sp-8)',
            textAlign: 'center',
            background: '#ffffff',
            borderRadius: 'var(--radius-sm)',
            border: '1px dashed #cbd5e1',
          }}
        >
          <div className="mono" style={{ fontSize: 20, marginBottom: 6, color: '#0284c7' }}>
            [INCIDENT_STAGED_READY]
          </div>
          <div style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', marginBottom: 6 }}>
            Ready for Reverse Hop &amp; Attacker Infrastructure Reconstruction
          </div>
          <div
            style={{
              fontSize: 13,
              color: '#475569',
              maxWidth: 580,
              margin: '0 auto 20px',
              lineHeight: 1.55,
            }}
          >
            Raw RFC-5322 transit headers are ingested in the local buffer. Executing the forensic trace will
            traverse every intermediate MTA hop, verify domain cryptographic keys (SPF/DKIM/DMARC), resolve
            autonomous system BGP coordinates, and classify attacker intent using DeBERTa-v3 NLP.
          </div>
          <button
            className="btn btn-primary"
            onClick={() => start(caseItem)}
            style={{ padding: '10px 24px', fontSize: 13.5, fontWeight: 700, gap: 8 }}
          >
            <span>⚡</span>
            <span>RUN FORENSIC TRACE</span>
          </button>
        </div>
      )}

      {/* ERROR STATE */}
      {status === 'error' && (
        <div
          className="panel fade-in"
          style={{
            padding: 'var(--sp-6)',
            textAlign: 'center',
            borderColor: '#fca5a5',
            background: '#fef2f2',
            borderRadius: 'var(--radius-sm)',
          }}
        >
          <div className="mono" style={{ fontSize: 20, marginBottom: 6, color: '#dc2626' }}>
            [PIPELINE_FAULT]
          </div>
          <div style={{ color: '#dc2626', fontSize: 13.5, fontWeight: 700, marginBottom: 12 }}>
            Forensic trace execution encountered an unhandled pipeline error.
          </div>
          <button className="btn" onClick={() => start(caseItem)}>
            Retry Trace
          </button>
        </div>
      )}

      {/* 8. PAGE COMPOSITION (DONE STATE) */}
      {status === 'done' && result && (
        <div
          className="fade-in"
          style={{
            display: 'grid',
            gridTemplateColumns: '1.2fr 1fr',
            gap: 'var(--sp-4)',
            alignItems: 'start',
          }}
        >
          {/* LEFT COLUMN: Hop Reconstruction (Visual Centerpiece) & Origin Intelligence */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
            <HopMap hops={result.hops} />
            <GeoPanel geo={result.geo} />
          </div>

          {/* RIGHT COLUMN: Forensic Verdict & Forensic Report (Evidence Artifact) */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
            <VerdictPanel result={result} />
            <ForensicReport caseItem={caseItem} result={result} hash={hash} />
          </div>
        </div>
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
