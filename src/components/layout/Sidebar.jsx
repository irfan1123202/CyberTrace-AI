import React from 'react';
import { NavLink, useLocation } from 'react-router-dom';

export default function Sidebar() {
  const location = useLocation();

  const NAV_ITEMS = [
    { to: '/dashboard', label: 'OVERVIEW', icon: '▣' },
    { to: '/dashboard', label: 'INVESTIGATIONS', icon: '☍', badge: '5' },
    { to: '/analysis', label: 'EMAIL ANALYSIS', icon: '✉' },
    { to: '/case/CASE-2026-0417', label: 'TRACE', icon: '◈' },
    { to: '/analysis', label: 'EVIDENCE', icon: '☵' },
    { to: '/dashboard', label: 'REPORTS', icon: '▤' },
  ];

  return (
    <aside
      style={{
        borderRight: '1px solid var(--border-hairline)',
        background: '#ffffff',
        padding: 'var(--sp-4)',
        display: 'flex',
        flexDirection: 'column',
        gap: 'var(--sp-5)',
        height: '100%',
        boxSizing: 'border-box',
        userSelect: 'none',
        fontFamily: 'var(--font-ui)',
      }}
    >
      {/* Brand Header */}
      <div
        style={{
          paddingBottom: 'var(--sp-3)',
          borderBottom: '1px solid var(--border-hairline-soft)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 3 }}>
          <div
            style={{
              width: 24,
              height: 24,
              borderRadius: 'var(--radius-xs)',
              background: '#0f172a',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#ffffff',
              fontWeight: 800,
              fontSize: 11,
              fontFamily: 'var(--font-mono)',
            }}
          >
            CT
          </div>
          <div>
            <div style={{ fontWeight: 800, fontSize: 14, color: '#0f172a', letterSpacing: '-0.02em', lineHeight: 1.1 }}>
              CYBERTRACE AI
            </div>
          </div>
        </div>
        <div style={{ fontSize: 11, fontWeight: 600, color: '#64748b', letterSpacing: '0.02em' }}>
          Threat Origin Forensics
        </div>
      </div>

      {/* Navigation */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
        {NAV_ITEMS.map((item, index) => {
          // Determine active status cleanly without fake duplicate routes
          const isItemActive =
            item.label === 'TRACE'
              ? location.pathname.startsWith('/case/')
              : (item.label === 'EMAIL ANALYSIS' || item.label === 'EVIDENCE')
              ? location.pathname === '/analysis'
              : (item.label === 'OVERVIEW' || item.label === 'INVESTIGATIONS') && location.pathname === '/dashboard';

          return (
            <NavLink
              key={`${item.label}-${index}`}
              to={item.to}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '8px 10px',
                borderRadius: 'var(--radius-sm)',
                fontSize: 12,
                fontWeight: isItemActive ? 700 : 600,
                textDecoration: 'none',
                color: isItemActive ? '#0284c7' : '#334155',
                background: isItemActive ? '#e0f2fe' : 'transparent',
                border: `1px solid ${isItemActive ? '#bae6fd' : 'transparent'}`,
                transition: 'all 0.15s ease-in-out',
                letterSpacing: '0.04em',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
                <span style={{ fontSize: 12, color: isItemActive ? '#0284c7' : '#64748b' }}>
                  {item.icon}
                </span>
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span
                  className="mono"
                  style={{
                    fontSize: 10,
                    fontWeight: 700,
                    padding: '1px 5px',
                    borderRadius: 'var(--radius-xs)',
                    background: isItemActive ? '#ffffff' : '#f1f5f9',
                    border: '1px solid var(--border-hairline-soft)',
                    color: isItemActive ? '#0284c7' : '#64748b',
                  }}
                >
                  {item.badge}
                </span>
              )}
            </NavLink>
          );
        })}
      </div>

      {/* Bottom Compact System Status */}
      <div style={{ marginTop: 'auto', display: 'flex', flexDirection: 'column', gap: 8 }}>
        <div
          style={{
            padding: '10px 12px',
            background: 'var(--bg-inset)',
            border: '1px solid var(--border-hairline-soft)',
            borderRadius: 'var(--radius-sm)',
          }}
        >
          <div style={{ fontSize: 10.5, fontWeight: 700, color: '#64748b', letterSpacing: '0.06em', marginBottom: 6, textTransform: 'uppercase' }}>
            SYSTEM STATUS
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5, fontSize: 11 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: '#334155' }}>
              <span style={{ fontWeight: 500 }}>TRACE ENGINE</span>
              <span className="mono" style={{ color: 'var(--signal-safe)', fontWeight: 700 }}>● ONLINE</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: '#334155' }}>
              <span style={{ fontWeight: 500 }}>GEO INTELLIGENCE</span>
              <span className="mono" style={{ color: 'var(--signal-safe)', fontWeight: 700 }}>● ONLINE</span>
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
}



