import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function LoginPage({ initialMode = 'login' }) {
  const { login, signup, fastTrackLogin } = useAuth();
  const navigate = useNavigate();

  const [mode, setMode] = useState(initialMode); // 'login' | 'signup'

  // Sign In fields
  const [email, setEmail] = useState('analyst@cybertrace.ai');
  const [password, setPassword] = useState('••••••••••••');

  // Sign Up fields
  const [signupName, setSignupName] = useState('');
  const [signupEmail, setSignupEmail] = useState('');
  const [signupRole, setSignupRole] = useState('Tier-2 SOC Analyst');
  const [signupClearance, setSignupClearance] = useState('CLR-L2');
  const [signupPassword, setSignupPassword] = useState('');
  const [signupConfirmPassword, setSignupConfirmPassword] = useState('');

  // Status & Feedback
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');
  const [loading, setLoading] = useState(false);

  // Handle Login submission
  const handleLoginSubmit = (e) => {
    e.preventDefault();
    setError('');
    setSuccessMsg('');
    setLoading(true);

    try {
      login(email, password);
      navigate('/dashboard', { replace: true });
    } catch (err) {
      setError(err.message || 'Authentication failed. Please verify credentials.');
      setLoading(false);
    }
  };

  // Handle Sign Up submission
  const handleSignupSubmit = (e) => {
    e.preventDefault();
    setError('');
    setSuccessMsg('');

    if (!signupName.trim()) {
      setError('Please enter your full analyst name.');
      return;
    }
    if (!signupEmail.trim() || !signupEmail.includes('@')) {
      setError('Please enter a valid official email address.');
      return;
    }
    if (!signupPassword || signupPassword.length < 6) {
      setError('Password must be at least 6 characters long.');
      return;
    }
    if (signupPassword !== signupConfirmPassword) {
      setError('Passwords do not match. Please re-check.');
      return;
    }

    setLoading(true);

    try {
      signup({
        name: signupName,
        email: signupEmail,
        role: signupRole,
        clearance: signupClearance,
        password: signupPassword,
      });
      setSuccessMsg('Analyst account provisioned successfully. Accessing workspace...');
      setTimeout(() => {
        navigate('/dashboard', { replace: true });
      }, 350);
    } catch (err) {
      setError(err.message || 'Registration failed. Please try again.');
      setLoading(false);
    }
  };

  // Autofill demo for Sign In
  const handleFillDemoLogin = () => {
    setEmail('analyst@cybertrace.ai');
    setPassword('CyberTrace2026!');
    setError('');
  };

  // Quick fill sample analyst for Sign Up
  const handleFillSampleSignup = () => {
    setSignupName('Jordan Reyes');
    setSignupEmail('jordan.reyes@cybertrace.ai');
    setSignupRole('Tier-2 SOC Analyst');
    setSignupClearance('CLR-L2');
    setSignupPassword('CyberTrace2026!');
    setSignupConfirmPassword('CyberTrace2026!');
    setError('');
  };

  // Fast-track 1-click launch to the website
  const handleFastTrackLaunch = () => {
    setError('');
    setLoading(true);
    try {
      fastTrackLogin('Guest Forensics Analyst', 'Live Evaluation Analyst');
      navigate('/dashboard', { replace: true });
    } catch (err) {
      setError('Fast-track launch failed. Please sign in normally.');
      setLoading(false);
    }
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
          maxWidth: 1060,
          margin: 'auto',
          padding: 'var(--sp-6)',
          display: 'grid',
          gridTemplateColumns: '1.05fr 1fr',
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

        {/* RIGHT SIDE: Interactive Auth Panel (Sign In & Sign Up) */}
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
            {/* Top Mode Switcher Tabs */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                background: '#f1f5f9',
                padding: 3,
                borderRadius: 'var(--radius-sm)',
                marginBottom: 'var(--sp-4)',
                border: '1px solid #e2e8f0',
              }}
            >
              <button
                type="button"
                id="tab-sign-in"
                onClick={() => {
                  setMode('login');
                  setError('');
                  setSuccessMsg('');
                }}
                style={{
                  padding: '7px 12px',
                  borderRadius: 'var(--radius-xs)',
                  border: 'none',
                  fontSize: 12.5,
                  fontWeight: mode === 'login' ? 700 : 500,
                  color: mode === 'login' ? '#0f172a' : '#64748b',
                  background: mode === 'login' ? '#ffffff' : 'transparent',
                  boxShadow: mode === 'login' ? '0 1px 3px rgba(15, 23, 42, 0.08)' : 'none',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: 6,
                }}
              >
                <span>Sign In</span>
              </button>

              <button
                type="button"
                id="tab-sign-up"
                onClick={() => {
                  setMode('signup');
                  setError('');
                  setSuccessMsg('');
                }}
                style={{
                  padding: '7px 12px',
                  borderRadius: 'var(--radius-xs)',
                  border: 'none',
                  fontSize: 12.5,
                  fontWeight: mode === 'signup' ? 700 : 500,
                  color: mode === 'signup' ? '#0f172a' : '#64748b',
                  background: mode === 'signup' ? '#ffffff' : 'transparent',
                  boxShadow: mode === 'signup' ? '0 1px 3px rgba(15, 23, 42, 0.08)' : 'none',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: 6,
                }}
              >
                <span>New Analyst Sign Up</span>
              </button>
            </div>

            {/* Fast-Track Instant Access Box (Make It Faster / Skip to Website) */}
            <div
              style={{
                background: 'linear-gradient(135deg, #f0fdf4 0%, #ecfdf5 100%)',
                border: '1px solid #bbf7d0',
                borderRadius: 'var(--radius-sm)',
                padding: '9px 12px',
                marginBottom: 'var(--sp-4)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: 10,
              }}
            >
              <div>
                <div style={{ fontSize: 11.5, fontWeight: 700, color: '#166534', display: 'flex', alignItems: 'center', gap: 5 }}>
                  <span style={{ fontSize: 13 }}>⚡</span>
                  <span>FAST-TRACK INSTANT ACCESS</span>
                </div>
                <div style={{ fontSize: 11, color: '#15803d', marginTop: 1 }}>
                  Skip registration and launch workspace immediately
                </div>
              </div>

              <button
                type="button"
                id="btn-fast-track"
                onClick={handleFastTrackLaunch}
                disabled={loading}
                className="btn btn-sm"
                style={{
                  background: '#16a34a',
                  color: '#ffffff',
                  borderColor: '#15803d',
                  fontWeight: 700,
                  padding: '5px 12px',
                  whiteSpace: 'nowrap',
                  fontSize: 11.5,
                }}
                title="Immediate 1-click access to the forensics dashboard"
              >
                Launch ➜
              </button>
            </div>

            {/* Feedback Banners */}
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
                  marginBottom: 'var(--sp-3)',
                }}
              >
                {error}
              </div>
            )}

            {successMsg && (
              <div
                style={{
                  padding: '8px 12px',
                  borderRadius: 'var(--radius-xs)',
                  background: '#f0fdf4',
                  border: '1px solid #86efac',
                  color: '#16a34a',
                  fontSize: 12,
                  fontWeight: 600,
                  marginBottom: 'var(--sp-3)',
                }}
              >
                {successMsg}
              </div>
            )}

            {/* SIGN IN FORM */}
            {mode === 'login' ? (
              <div>
                <div style={{ marginBottom: 'var(--sp-4)' }}>
                  <h2
                    style={{
                      fontSize: 19,
                      fontWeight: 800,
                      color: '#0f172a',
                      margin: '0 0 4px',
                      letterSpacing: '-0.01em',
                    }}
                  >
                    SIGN IN
                  </h2>
                  <p style={{ fontSize: 12.5, color: '#475569', margin: 0 }}>
                    Access your investigation workspace.
                  </p>
                </div>

                <form onSubmit={handleLoginSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-3)' }}>
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
                        id="btn-autofill-demo"
                        onClick={handleFillDemoLogin}
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
                    id="btn-submit-login"
                    disabled={loading}
                    className="btn btn-primary"
                    style={{
                      width: '100%',
                      padding: '10px 16px',
                      fontSize: 13.5,
                      fontWeight: 700,
                      marginTop: 4,
                    }}
                  >
                    {loading ? 'Authenticating...' : 'Sign In'}
                  </button>

                  <div style={{ display: 'flex', justifyContent: 'center', marginTop: 4 }}>
                    <button
                      type="button"
                      onClick={() => {
                        setMode('signup');
                        setError('');
                      }}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: '#0284c7',
                        fontSize: 12,
                        fontWeight: 600,
                        cursor: 'pointer',
                        padding: '4px 8px',
                      }}
                    >
                      New analyst? Create an account →
                    </button>
                  </div>

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
            ) : (
              /* SIGN UP / REGISTRATION FORM */
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 'var(--sp-4)' }}>
                  <div>
                    <h2
                      style={{
                        fontSize: 19,
                        fontWeight: 800,
                        color: '#0f172a',
                        margin: '0 0 4px',
                        letterSpacing: '-0.01em',
                      }}
                    >
                      NEW ANALYST SIGN UP
                    </h2>
                    <p style={{ fontSize: 12.5, color: '#475569', margin: 0 }}>
                      Provision digital forensics access.
                    </p>
                  </div>

                  <button
                    type="button"
                    id="btn-autofill-signup"
                    onClick={handleFillSampleSignup}
                    style={{
                      background: '#f0f9ff',
                      border: '1px solid #bae6fd',
                      color: '#0284c7',
                      fontSize: 11,
                      fontWeight: 700,
                      cursor: 'pointer',
                      padding: '4px 8px',
                      borderRadius: 'var(--radius-xs)',
                    }}
                    title="1-click sample profile autofill"
                  >
                    ⚡ Quick Autofill
                  </button>
                </div>

                <form onSubmit={handleSignupSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-3)' }}>
                  {/* Name Input */}
                  <div>
                    <label
                      htmlFor="signup-name"
                      style={{
                        display: 'block',
                        fontSize: 12,
                        fontWeight: 700,
                        color: '#334155',
                        marginBottom: 4,
                      }}
                    >
                      Full Name / Analyst Name
                    </label>
                    <input
                      id="signup-name"
                      type="text"
                      required
                      value={signupName}
                      onChange={(e) => setSignupName(e.target.value)}
                      placeholder="e.g. Jordan Reyes"
                      style={{
                        width: '100%',
                        padding: '8px 12px',
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

                  {/* Email Input */}
                  <div>
                    <label
                      htmlFor="signup-email"
                      style={{
                        display: 'block',
                        fontSize: 12,
                        fontWeight: 700,
                        color: '#334155',
                        marginBottom: 4,
                      }}
                    >
                      Official Email Address
                    </label>
                    <input
                      id="signup-email"
                      type="email"
                      required
                      value={signupEmail}
                      onChange={(e) => setSignupEmail(e.target.value)}
                      placeholder="e.g. jordan.reyes@cybertrace.ai"
                      style={{
                        width: '100%',
                        padding: '8px 12px',
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

                  {/* Role & Clearance 2-column layout */}
                  <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr', gap: 8 }}>
                    <div>
                      <label
                        htmlFor="signup-role"
                        style={{
                          display: 'block',
                          fontSize: 12,
                          fontWeight: 700,
                          color: '#334155',
                          marginBottom: 4,
                        }}
                      >
                        Operational Role
                      </label>
                      <select
                        id="signup-role"
                        value={signupRole}
                        onChange={(e) => setSignupRole(e.target.value)}
                        style={{
                          width: '100%',
                          padding: '8px 10px',
                          borderRadius: 'var(--radius-sm)',
                          border: '1px solid #cbd5e1',
                          fontSize: 12.5,
                          color: '#0f172a',
                          background: '#ffffff',
                          outline: 'none',
                          boxSizing: 'border-box',
                          fontFamily: 'var(--font-ui)',
                        }}
                      >
                        <option value="Tier-2 SOC Analyst">Tier-2 SOC Analyst</option>
                        <option value="Tier-1 Triage Specialist">Tier-1 Triage Specialist</option>
                        <option value="Forensic Investigator">Forensic Investigator</option>
                        <option value="Incident Response Officer">Incident Response Officer</option>
                        <option value="Threat Intelligence Lead">Threat Intelligence Lead</option>
                      </select>
                    </div>

                    <div>
                      <label
                        htmlFor="signup-clearance"
                        style={{
                          display: 'block',
                          fontSize: 12,
                          fontWeight: 700,
                          color: '#334155',
                          marginBottom: 4,
                        }}
                      >
                        Clearance
                      </label>
                      <select
                        id="signup-clearance"
                        value={signupClearance}
                        onChange={(e) => setSignupClearance(e.target.value)}
                        style={{
                          width: '100%',
                          padding: '8px 10px',
                          borderRadius: 'var(--radius-sm)',
                          border: '1px solid #cbd5e1',
                          fontSize: 12.5,
                          color: '#0f172a',
                          background: '#ffffff',
                          outline: 'none',
                          boxSizing: 'border-box',
                          fontFamily: 'var(--font-ui)',
                        }}
                      >
                        <option value="CLR-L1">CLR-L1 (Triage)</option>
                        <option value="CLR-L2">CLR-L2 (Forensic)</option>
                        <option value="CLR-L3">CLR-L3 (Full)</option>
                      </select>
                    </div>
                  </div>

                  {/* Password & Confirm Password 2-column layout */}
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                    <div>
                      <label
                        htmlFor="signup-password"
                        style={{
                          display: 'block',
                          fontSize: 12,
                          fontWeight: 700,
                          color: '#334155',
                          marginBottom: 4,
                        }}
                      >
                        Password
                      </label>
                      <input
                        id="signup-password"
                        type="password"
                        required
                        value={signupPassword}
                        onChange={(e) => setSignupPassword(e.target.value)}
                        placeholder="••••••••"
                        style={{
                          width: '100%',
                          padding: '8px 12px',
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
                      <label
                        htmlFor="signup-confirm-password"
                        style={{
                          display: 'block',
                          fontSize: 12,
                          fontWeight: 700,
                          color: '#334155',
                          marginBottom: 4,
                        }}
                      >
                        Confirm
                      </label>
                      <input
                        id="signup-confirm-password"
                        type="password"
                        required
                        value={signupConfirmPassword}
                        onChange={(e) => setSignupConfirmPassword(e.target.value)}
                        placeholder="••••••••"
                        style={{
                          width: '100%',
                          padding: '8px 12px',
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
                  </div>

                  <button
                    type="submit"
                    id="btn-submit-signup"
                    disabled={loading}
                    className="btn btn-primary"
                    style={{
                      width: '100%',
                      padding: '10px 16px',
                      fontSize: 13.5,
                      fontWeight: 700,
                      marginTop: 4,
                    }}
                  >
                    {loading ? 'Provisioning Account...' : 'Create Account & Enter Workspace'}
                  </button>

                  <div style={{ display: 'flex', justifyContent: 'center', marginTop: 4 }}>
                    <button
                      type="button"
                      onClick={() => {
                        setMode('login');
                        setError('');
                      }}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: '#0284c7',
                        fontSize: 12,
                        fontWeight: 600,
                        cursor: 'pointer',
                        padding: '4px 8px',
                      }}
                    >
                      Already have an analyst account? Sign in here →
                    </button>
                  </div>
                </form>
              </div>
            )}
          </div>
        </div>
      </div>

      <style>{`
        @media (max-width: 800px) {
          div[style*="grid-template-columns: 1.05fr 1fr"] {
            grid-template-columns: 1fr !important;
            gap: var(--sp-6) !important;
          }
        }
      `}</style>
    </div>
  );
}
