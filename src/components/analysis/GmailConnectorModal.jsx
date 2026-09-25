import React from 'react';

export default function GmailConnectorModal({ isOpen, onClose }) {
  if (!isOpen) return null;

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
          maxWidth: 640,
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
              CONNECTOR SPECIFICATION // ARCHITECTURAL REQUIREMENT
            </div>
            <h3 style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', margin: '2px 0 0' }}>
              Gmail Secure Read-Only Connector
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

        {/* Modal Body */}
        <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: 14, maxHeight: '75vh', overflowY: 'auto' }}>
          {/* Status Alert */}
          <div
            style={{
              padding: '12px 14px',
              borderRadius: 'var(--radius-xs)',
              background: '#fef2f2',
              border: '1px solid #fca5a5',
              display: 'flex',
              gap: 10,
              alignItems: 'flex-start',
            }}
          >
            <span style={{ color: '#dc2626', fontSize: 16, fontWeight: 800 }}>⚠</span>
            <div>
              <div style={{ fontSize: 13, fontWeight: 800, color: '#991b1b' }}>
                STATUS: NOT CONFIGURED (REQUIRES SECURE OAUTH2 BACKEND)
              </div>
              <div style={{ fontSize: 12, color: '#7f1d1d', marginTop: 3, lineHeight: 1.45 }}>
                Direct browser-to-Gmail authorization without a secure backend server is explicitly prohibited.
                Frontend source code must never store OAuth client secrets, exchange refresh tokens, or process raw mail APIs.
              </div>
            </div>
          </div>

          {/* Secure Architecture Flow */}
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#475569', letterSpacing: '0.04em', textTransform: 'uppercase', marginBottom: 8 }}>
              MANDATORY ENTERPRISE SECURITY ARCHITECTURE
            </div>

            <div
              className="mono"
              style={{
                fontSize: 11,
                background: '#f8fafc',
                padding: '12px',
                borderRadius: 'var(--radius-xs)',
                border: '1px solid #e2e8f0',
                color: '#1e293b',
                lineHeight: 1.6,
              }}
            >
              ANALYST BROWSER<br />
              &nbsp;&nbsp;↓ 1. Initiates Authorization Request<br />
              FASTAPI BACKEND SERVICE (Environment: GMAIL_CLIENT_ID / SECRET)<br />
              &nbsp;&nbsp;↓ 2. OAuth2 Authorization Code + PKCE Flow<br />
              GOOGLE OAUTH ENDPOINT<br />
              &nbsp;&nbsp;↓ 3. Scopes: https://www.googleapis.com/auth/gmail.readonly (STRICTLY READ-ONLY)<br />
              EPHEMERAL TOKEN VAULT (Server-Side Storage Only)<br />
              &nbsp;&nbsp;↓ 4. Sanitized Raw MIME Stream Ingestion<br />
              CYBERTRACE ISOLATED WORKSPACE SESSION
            </div>
          </div>

          {/* Security Guarantees */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 10 }}>
            <div
              style={{
                padding: '10px 12px',
                background: '#ffffff',
                border: '1px solid #cbd5e1',
                borderRadius: 'var(--radius-xs)',
              }}
            >
              <div style={{ fontSize: 10, fontWeight: 700, color: '#16a34a', letterSpacing: '0.04em', marginBottom: 2 }}>
                ✓ ZERO CREDENTIAL ACCESS
              </div>
              <div style={{ fontSize: 11.5, color: '#475569', lineHeight: 1.4 }}>
                User passwords are never collected or stored. Authentication relies strictly on scoped OAuth2 bearer tokens.
              </div>
            </div>

            <div
              style={{
                padding: '10px 12px',
                background: '#ffffff',
                border: '1px solid #cbd5e1',
                borderRadius: 'var(--radius-xs)',
              }}
            >
              <div style={{ fontSize: 10, fontWeight: 700, color: '#16a34a', letterSpacing: '0.04em', marginBottom: 2 }}>
                ✓ STRICTLY READ-ONLY
              </div>
              <div style={{ fontSize: 11.5, color: '#475569', lineHeight: 1.4 }}>
                Write, delete, or send permissions are prohibited. Connector access is limited to message metadata and RFC-5322 raw bytes.
              </div>
            </div>
          </div>

          {/* Developer Environment Notice */}
          <div
            style={{
              padding: '10px 12px',
              borderRadius: 'var(--radius-xs)',
              background: '#f8fafc',
              border: '1px solid #e2e8f0',
              fontSize: 11.5,
              color: '#64748b',
              lineHeight: 1.45,
            }}
          >
            <strong>To test in the current prototype:</strong> Use <strong>[ IMPORT .EML ]</strong> or <strong>[ USE DEMO EMAIL ]</strong> to analyze RFC-5322 samples with full hop reconstruction and IP intelligence.
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
            Close Specification
          </button>
        </div>
      </div>
    </div>
  );
}
