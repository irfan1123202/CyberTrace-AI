import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('analyst@cybertrace.ai');
  const [password, setPassword] = useState('••••••••••••');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      login(email, password);
      navigate('/dashboard', { replace: true });
    } catch (err) {
      setError(err.message || 'Authentication failed. Please verify credentials.');
      setLoading(false);
    }
  };

  const handleFillDemo = () => {
    setEmail('analyst@cybertrace.ai');
    setPassword('CyberTrace2026!');
    setError('');
  };

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        background: '#f8fafc',
        position: 'relative',
        overflow: 'hidden',
        fontFamily: 'var(--font-ui)',
      }}
    >
      {/* Subtle technical background grid */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          backgroundImage:
            'linear-gradient(to right, rgba(203, 213, 225, 0.3) 1px, transparent 1px), linear-gradient(to bottom, rgba(203, 213, 225, 0.3) 1px, transparent 1px)',
          backgroundSize: '36px 36px',
          opacity: 0.7,
          pointerEvents: 'none',
        }}
      />

      <div
        style={{
          position: 'relative',
          width: '100%',
          maxWidth: 1040,
          margin: 'auto',
          padding: 'var(--sp-6)',
          display: 'grid',
          gridTemplateColumns: '1.1fr 1fr',
          gap: 'var(--sp-8)',
          alignItems: 'center',
          boxSizing: 'border-box',
        }}
      >
        {/* LEFT SIDE: Brand & Forensic Identity */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-6)' }}>
          {/* Header Brand */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
              <div
                style={{
                  width: 28,
                  height: 28,
                  borderRadius: 'var(--radius-xs)',
                  background: '#0f172a',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#ffffff',
                  fontWeight: 800,
                  fontSize: 13,
                  fontFamily: 'var(--font-mono)',
                }}
              >
                CT
              </div>
              <div style={{ fontSize: 18, fontWeight: 800, color: '#0f172a', letterSpacing: '-0.02em' }}>
                CYBERTRACE AI
              </div>
            </div>

            <div style={{ fontSize: 13, fontWeight: 600, color: '#0284c7', letterSpacing: '0.04em', textTransform: 'uppercase' }}>
              Digital Forensics & Threat Attribution
            </div>
          </div>

          {/* Statement */}
          <div>
            <h1
              style={{
                fontSize: 26,
                fontWeight: 800,
                color: '#0f172a',
                lineHeight: 1.25,
                margin: '0 0 12px',
                letterSpacing: '-0.02em',
              }}
            >
              Trace suspicious email infrastructure from inbox to origin.
            </h1>
            <p style={{ fontSize: 14, color: '#475569', lineHeight: 1.6, margin: 0 }}>
              Reconstruct multi-hop transit paths, evaluate SPF/DKIM/DMARC domain alignment, and attribute coordinated phishing campaigns using deep NLP embeddings.
            </p>
          </div>

          {/* Subtle Technical Status Monitors */}
          <div
            style={{
              background: '#ffffff',
              border: '1px solid #cbd5e1',
              borderRadius: 'var(--radius-sm)',
              padding: '12px 16px',
              display: 'flex',
              flexDirection: 'column',
              gap: 8,
              boxShadow: 'var(--shadow-subtle)',
            }}
          >
            <div
              className="mono"
              style={{
                fontSize: 10,
                fontWeight: 700,
                color: '#64748b',
                letterSpacing: '0.08em',
                paddingBottom: 6,
                borderBottom: '1px solid #e2e8f0',
              }}
            >
              SYSTEM SUBSYSTEM TELEMETRY
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 11.5 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: '#334155', fontWeight: 500 }}>FORENSIC TRACE ENGINE</span>
                <span className="mono" style={{ color: '#16a34a', fontWeight: 700 }}>● READY</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: '#334155', fontWeight: 500 }}>GEO INTELLIGENCE</span>
                <span className="mono" style={{ color: '#16a34a', fontWeight: 700 }}>● ONLINE</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: '#334155', fontWeight: 500 }}>EVIDENCE ANALYSIS</span>
                <span className="mono" style={{ color: '#0284c7', fontWeight: 700 }}>● READY</span>
              </div>
            </div>
          </div>

          {/* Standard Tag */}
          <div className="mono" style={{ fontSize: 10.5, color: '#64748b' }}>
            FRAMEWORK: NIST SP 800-86 · RFC-5322 MIME FORENSICS
          </div>
        </div>

        {/* RIGHT SIDE: Clean Sign In Panel */}
        <div>
          <div
            className="panel"
            style={{
              background: '#ffffff',
              border: '1px solid #cbd5e1',
              borderRadius: 'var(--radius-md)',
              padding: 'var(--sp-6) var(--sp-6)',
              boxShadow: '0 4px 20px rgba(15, 23, 42, 0.06)',
            }}
          >
            <div style={{ marginBottom: 'var(--sp-5)' }}>
              <h2
                style={{
                  fontSize: 20,
                  fontWeight: 800,
                  color: '#0f172a',
                  margin: '0 0 6px',
                  letterSpacing: '-0.01em',
                }}
              >
                SIGN IN
              </h2>
              <p style={{ fontSize: 13, color: '#475569', margin: 0 }}>
                Access your investigation workspace.
              </p>
            </div>

            <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
              {error && (
                <div
                  style={{
                    padding: '8px 12px',
                    borderRadius: 'var(--radius-xs)',
                    background: '#fef2f2',
                    border: '1px solid #fca5a5',
                    color: '#dc2626',
                    fontSize: 12,
                    fontWeight: 600,
                  }}
                >
                  {error}
                </div>
              )}

              <div>
                <label
                  htmlFor="login-email"
                  style={{
                    display: 'block',
                    fontSize: 12,
                    fontWeight: 700,
                    color: '#334155',
                    marginBottom: 5,
                  }}
                >
                  Email / Analyst Identifier
                </label>
                <input
                  id="login-email"
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@cybertrace.ai"
                  style={{
                    width: '100%',
                    padding: '9px 12px',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid #cbd5e1',
                    fontSize: 13,
                    color: '#0f172a',
                    background: '#ffffff',
                    outline: 'none',
                    boxSizing: 'border-box',
                    fontFamily: 'var(--font-ui)',
                    transition: 'border-color 0.15s',
                  }}
                  onFocus={(e) => (e.target.style.borderColor = '#0284c7')}
                  onBlur={(e) => (e.target.style.borderColor = '#cbd5e1')}
                />
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 5 }}>
                  <label
                    htmlFor="login-password"
                    style={{
                      fontSize: 12,
                      fontWeight: 700,
                      color: '#334155',
                    }}
                  >
                    Password
                  </label>
                  <button
                    type="button"
                    onClick={handleFillDemo}
                    style={{
                      background: 'none',
                      border: 'none',
                      padding: 0,
                      fontSize: 11,
                      fontWeight: 600,
                      color: '#0284c7',
                      cursor: 'pointer',
                    }}
                  >
                    Autofill Demo Credentials
                  </button>
                </div>
                <input
                  id="login-password"
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  style={{
                    width: '100%',
                    padding: '9px 12px',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid #cbd5e1',
                    fontSize: 13,
                    color: '#0f172a',
                    background: '#ffffff',
                    outline: 'none',
                    boxSizing: 'border-box',
                    fontFamily: 'var(--font-ui)',
                    transition: 'border-color 0.15s',
                  }}
                  onFocus={(e) => (e.target.style.borderColor = '#0284c7')}
                  onBlur={(e) => (e.target.style.borderColor = '#cbd5e1')}
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="btn btn-primary"
                style={{
                  width: '100%',
                  padding: '10px 16px',
                  fontSize: 13.5,
                  fontWeight: 700,
                  marginTop: 6,
                }}
              >
                {loading ? 'Authenticating...' : 'Sign In'}
              </button>

              <div
                style={{
                  paddingTop: 'var(--sp-3)',
                  borderTop: '1px solid #e2e8f0',
                  fontSize: 11,
                  color: '#64748b',
                  lineHeight: 1.45,
                  textAlign: 'center',
                }}
              >
                Authorized security personnel and SOC analysts only. Session telemetry is cryptographically recorded.
              </div>
            </form>
          </div>
        </div>
      </div>

      <style>{`
        @media (max-width: 800px) {
          div[style*="grid-template-columns: 1.1fr 1fr"] {
            grid-template-columns: 1fr !important;
            gap: var(--sp-6) !important;
          }
        }
      `}</style>
    </div>
  );
}
