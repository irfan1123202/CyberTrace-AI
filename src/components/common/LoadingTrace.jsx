import React from 'react';

const STAGE_METADATA = {
  parse: {
    title: 'HEADER PARSE',
    category: 'MIME INGEST',
    detail: 'Extracting MIME boundaries, Received headers, and Message-ID tokens...',
  },
  hops: {
    title: 'HOP TRACE',
    category: 'TRANSIT GRAPH',
    detail: 'Reconstructing MTA transit chain from internal MX to edge perimeter...',
  },
  auth: {
    title: 'AUTH VERIFY',
    category: 'CRYPTO AUDIT',
    detail: 'Evaluating SPF record alignment, DKIM cryptographic signature & DMARC policy...',
  },
  geo: {
    title: 'GEO TRACE',
    category: 'BGP TELEMETRY',
    detail: 'Resolving origin Autonomous System (ASN), BGP routing table & coordinates...',
  },
  nlp: {
    title: 'AI CLASSIFY',
    category: 'INTENT ENGINE',
    detail: 'Executing DeBERTa-v3 semantic model for BEC / credential phishing classification...',
  },
  graph: {
    title: 'ATTRIBUTION',
    category: 'GLOBAL INTEL',
    detail: 'Cross-referencing campaign graph clusters and known threat actor infrastructure...',
  },
};

export default function LoadingTrace({ stages, activeStage }) {
  const activeIndex = stages.findIndex((s) => s.key === activeStage);

  const activeMeta = STAGE_METADATA[activeStage] || {
    title: 'PIPELINE EXECUTION',
    category: 'TELEMETRY',
    detail: 'Processing forensic telemetry stages...',
  };

  return (
    <div
      className="panel fade-in"
      style={{
        padding: 'var(--sp-5)',
        background: '#ffffff',
        border: '1px solid #cbd5e1',
        borderLeft: '4px solid #0284c7',
        borderRadius: 'var(--radius-sm)',
        boxShadow: '0 4px 16px rgba(15, 23, 42, 0.05)',
      }}
    >
      {/* Pipeline Status Header */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: 'var(--sp-4)',
          flexWrap: 'wrap',
          gap: 8,
          borderBottom: '1px solid #f1f5f9',
          paddingBottom: 10,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span
            className="pulse"
            style={{ width: 8, height: 8, borderRadius: '50%', background: '#0284c7' }}
          />
          <div style={{ fontSize: 13, fontWeight: 800, color: '#0f172a', letterSpacing: '-0.01em' }}>
            FORENSIC RECONSTRUCTION PIPELINE
          </div>
          <span style={{ color: '#cbd5e1' }}>|</span>
          <span className="mono" style={{ fontSize: 11, color: '#0284c7', fontWeight: 700 }}>
            {activeMeta.category}
          </span>
        </div>

        <div className="mono" style={{ fontSize: 11, color: '#64748b' }}>
          STAGE <strong style={{ color: '#0f172a' }}>{Math.max(1, activeIndex + 1)}</strong> OF {stages.length}
        </div>
      </div>

      {/* 6-Stage Pipeline Sequence */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(6, 1fr)',
          gap: 8,
          marginBottom: 'var(--sp-4)',
        }}
      >
        {stages.map((s, i) => {
          const isComplete = activeIndex > i;
          const isRunning = activeIndex === i;
          const meta = STAGE_METADATA[s.key] || { title: s.key.toUpperCase() };

          let stateLabel = 'QUEUED';
          let stateColor = '#94a3b8';
          let bg = '#f8fafc';
          let border = '#e2e8f0';

          if (isComplete) {
            stateLabel = 'COMPLETE';
            stateColor = '#16a34a';
            bg = '#ffffff';
            border = '#86efac';
          } else if (isRunning) {
            stateLabel = 'RUNNING';
            stateColor = '#0284c7';
            bg = '#f0f9ff';
            border = '#0284c7';
          }

          return (
            <div
              key={s.key}
              style={{
                padding: '8px 10px',
                borderRadius: 'var(--radius-sm)',
                background: bg,
                border: `1px solid ${border}`,
                boxShadow: isRunning ? '0 0 0 1px #0284c7, 0 2px 6px rgba(2, 132, 199, 0.12)' : 'none',
                transition: 'all 0.2s ease',
                position: 'relative',
              }}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  marginBottom: 4,
                }}
              >
                <span
                  className="mono"
                  style={{
                    fontSize: 10,
                    fontWeight: 700,
                    color: isRunning ? '#0284c7' : isComplete ? '#16a34a' : '#94a3b8',
                  }}
                >
                  0{i + 1}
                </span>

                <span
                  className="mono"
                  style={{
                    fontSize: 9.5,
                    fontWeight: 800,
                    color: stateColor,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 3,
                  }}
                >
                  {isComplete ? '✓' : isRunning ? '●' : '—'} {stateLabel}
                </span>
              </div>

              <div
                style={{
                  fontSize: 11.5,
                  fontWeight: isRunning || isComplete ? 700 : 600,
                  color: isRunning ? '#0284c7' : isComplete ? '#0f172a' : '#64748b',
                  lineHeight: 1.25,
                }}
              >
                {meta.title}
              </div>
            </div>
          );
        })}
      </div>

      {/* Live Operational Console Feed */}
      <div
        className="mono"
        style={{
          fontSize: 11.5,
          color: '#334155',
          background: '#f8fafc',
          padding: '8px 12px',
          borderRadius: 'var(--radius-xs)',
          border: '1px solid #e2e8f0',
          display: 'flex',
          alignItems: 'center',
          gap: 10,
        }}
      >
        <span style={{ color: '#0284c7', fontWeight: 800 }}>&gt;</span>
        <span style={{ fontWeight: 600 }}>{activeMeta.detail}</span>
      </div>

      <style>{`
        @media (max-width: 900px) {
          div[style*="grid-template-columns: repeat(6, 1fr)"] {
            grid-template-columns: repeat(2, 1fr) !important;
          }
        }
      `}</style>
    </div>
  );
}
