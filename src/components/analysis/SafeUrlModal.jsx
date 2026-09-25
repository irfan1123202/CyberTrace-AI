import React from 'react';

export default function SafeUrlModal({ urlItem, onClose }) {
  if (!urlItem) return null;

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(15, 23, 42, 0.65)',
        backdropFilter: 'blur(2px)',
        zIndex: 1000,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 'var(--sp-4)',
        fontFamily: 'var(--font-ui)',
      }}
      onClick={onClose}
    >
      <div
        className="panel fade-in"
        style={{
          width: '100%',
          maxWidth: 600,
          background: '#ffffff',
          borderRadius: 'var(--radius-sm)',
          border: '1px solid #cbd5e1',
          boxShadow: '0 20px 25px -5px rgba(15, 23, 42, 0.25)',
          overflow: 'hidden',
          display: 'flex',
          flexDirection: 'column',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div
          style={{
            padding: '16px 20px',
            borderBottom: '1px solid #f1f5f9',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: '#f8fafc',
          }}
        >
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#dc2626', letterSpacing: '0.05em', textTransform: 'uppercase' }}>
              ISOLATED INSPECTOR // DEFENSIVE URL DEFENSE
            </div>
            <h3 style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', margin: '2px 0 0' }}>
              Safe URL Interception &amp; Profiling
            </h3>
          </div>

          <button
            onClick={onClose}
            style={{
              background: 'none',
              border: 'none',
              fontSize: 18,
              cursor: 'pointer',
              color: '#64748b',
              padding: 4,
            }}
          >
            ✕
          </button>
        </div>

        {/* Content */}
        <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: 14 }}>
          {/* Security Alert Banner */}
          <div
            style={{
              padding: '10px 14px',
              borderRadius: 'var(--radius-xs)',
              background: '#fef2f2',
              border: '1px solid #fca5a5',
              display: 'flex',
              gap: 10,
              alignItems: 'center',
            }}
          >
            <span style={{ color: '#dc2626', fontSize: 14, fontWeight: 800 }}>🛡</span>
            <div style={{ fontSize: 12, color: '#991b1b', fontWeight: 600 }}>
              Direct browser navigation is blocked. Untrusted link intercepted to prevent credential harvesting or drive-by payload delivery.
            </div>
          </div>

          {/* Target URL Block */}
          <div
            style={{
              padding: '10px 12px',
              background: '#f8fafc',
              border: '1px solid #e2e8f0',
              borderRadius: 'var(--radius-xs)',
            }}
          >
            <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b', letterSpacing: '0.04em', marginBottom: 4 }}>
              NORMALIZED URL TARGET
            </div>
            <div className="mono" style={{ fontSize: 12, fontWeight: 700, color: '#0f172a', wordBreak: 'break-all' }}>
              {urlItem.normalizedUrl}
            </div>
          </div>

          {/* Technical Intelligence Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 10 }}>
            <div>
              <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b', letterSpacing: '0.04em', marginBottom: 2 }}>
                TARGET DOMAIN
              </div>
              <div className="mono" style={{ fontSize: 12.5, fontWeight: 700, color: '#0f172a' }}>
                {urlItem.domain}
              </div>
            </div>

            <div>
              <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b', letterSpacing: '0.04em', marginBottom: 2 }}>
                PROTOCOL / TLS
              </div>
              <div className="mono" style={{ fontSize: 12, fontWeight: 600, color: '#334155' }}>
                {urlItem.tlsCertificate}
              </div>
            </div>

            <div>
              <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b', letterSpacing: '0.04em', marginBottom: 2 }}>
                RISK RATING
              </div>
              <div className="mono" style={{ fontSize: 11.5, fontWeight: 800, color: urlItem.riskRating === 'HIGH RISK' ? '#dc2626' : '#d97706' }}>
                ● {urlItem.riskRating}
              </div>
            </div>

            <div>
              <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b', letterSpacing: '0.04em', marginBottom: 2 }}>
                DETONATION ENVIRONMENT
              </div>
              <div className="mono" style={{ fontSize: 11, fontWeight: 700, color: '#dc2626' }}>
                MICROVM SANDBOX REQUIRED
              </div>
            </div>
          </div>

          {/* Reputation Signal */}
          <div
            style={{
              padding: '10px 12px',
              background: '#ffffff',
              border: '1px solid #cbd5e1',
              borderRadius: 'var(--radius-xs)',
            }}
          >
            <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b', letterSpacing: '0.04em', marginBottom: 2 }}>
              HEURISTIC / PHISHING REPUTATION SIGNAL
            </div>
            <div style={{ fontSize: 12, color: '#334155', fontWeight: 600 }}>
              {urlItem.reputationSignal}
            </div>
          </div>

          {/* Workflow Architecture Notice */}
          <div
            className="mono"
            style={{
              fontSize: 10.5,
              color: '#64748b',
              background: '#f8fafc',
              padding: '8px 12px',
              borderRadius: 3,
              border: '1px solid #e2e8f0',
            }}
          >
            WORKFLOW: URL NORMALIZATION → DNS RESOLUTION → HEADLESS MICROVM DETONATION → REDIRECT TRACE → SCREENSHOT
          </div>
        </div>

        {/* Footer */}
        <div
          style={{
            padding: '12px 20px',
            borderTop: '1px solid #f1f5f9',
            background: '#f8fafc',
            display: 'flex',
            justifyContent: 'flex-end',
          }}
        >
          <button className="btn" onClick={onClose} style={{ padding: '6px 14px', fontSize: 12 }}>
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
}
