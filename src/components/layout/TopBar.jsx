import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { getDatabaseStatus } from '../../services/dbService';

export default function TopBar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const dbStatus = getDatabaseStatus();

  const handleLogout = () => {
    logout();
    navigate('/', { replace: true });
  };

  return (
    <header
      style={{
        height: 44,
        borderBottom: '1px solid var(--border-hairline)',
        background: '#ffffff',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 var(--sp-6)',
        fontSize: 12,
        userSelect: 'none',
        position: 'sticky',
        top: 0,
        zIndex: 50,
        boxSizing: 'border-box',
        fontFamily: 'var(--font-ui)',
      }}
    >
      {/* Top Header Identity */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <div style={{ fontWeight: 800, fontSize: 13, color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
          CYBERTRACE AI
        </div>
        <span style={{ color: 'var(--border-hairline)' }}>/</span>
        <div style={{ fontSize: 12, color: 'var(--text-secondary)', fontWeight: 500 }}>
          Digital Forensics / Investigation Workspace
        </div>
      </div>

      {/* Right Controls: Telemetry, Session & Logout */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--signal-safe)', fontWeight: 600, fontSize: 11 }}>
          <span
            className="pulse"
            style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--signal-safe)' }}
          />
          <span className="mono">FEED: LIVE</span>
        </div>

        <span style={{ color: 'var(--border-hairline)' }}>|</span>

        <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, fontWeight: 600 }} title={dbStatus.provider}>
          <span
            style={{
              width: 6,
              height: 6,
              borderRadius: '50%',
              background: dbStatus.connected ? 'var(--signal-safe)' : '#0284c7',
            }}
          />
          <span className="mono" style={{ color: dbStatus.connected ? 'var(--signal-safe)' : 'var(--text-tertiary)' }}>
            {dbStatus.connected ? 'DB: SUPABASE CLOUD' : 'DB: CLOUD READY'}
          </span>
        </div>

        <span style={{ color: 'var(--border-hairline)' }}>|</span>

        {/* Analyst Session Badge */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 7, fontSize: 11.5 }}>
          <span
            className="mono"
            style={{
              padding: '2px 6px',
              borderRadius: 'var(--radius-xs)',
              background: 'var(--bg-inset)',
              border: '1px solid var(--border-hairline)',
              fontWeight: 700,
              color: 'var(--text-primary)',
            }}
          >
            {user?.name || 'S. Kavitha'}
          </span>
          <span style={{ color: 'var(--text-tertiary)' }}>· {user?.role || 'Tier-2 SOC'}</span>
          {user?.clearance && (
            <span
              className="mono"
              style={{
                fontSize: 10,
                padding: '1px 4px',
                borderRadius: 'var(--radius-xs)',
                background: 'var(--accent-bg)',
                color: 'var(--accent)',
                fontWeight: 700,
                border: '1px solid var(--accent-border)',
              }}
            >
              {user.clearance}
            </span>
          )}
        </div>

        <span style={{ color: 'var(--border-hairline)' }}>|</span>

        {/* Sign Out Button */}
        <button
          onClick={handleLogout}
          className="btn btn-sm"
          style={{
            padding: '4px 10px',
            fontSize: 11,
            color: 'var(--text-secondary)',
            borderColor: 'var(--border-hairline)',
          }}
          title="End session and return to Sign In"
        >
          Sign Out
        </button>
      </div>
    </header>
  );
}

