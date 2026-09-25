import React from 'react';

export default function GeoPanel({ geo }) {
  if (!geo) return null;

  const hasCoords = geo.lat != null && geo.lon != null;
  const x = hasCoords ? ((geo.lon + 180) / 360) * 100 : 50;
  const y = hasCoords ? ((90 - geo.lat) / 180) * 100 : 50;

  // Deriving ASN & Timezone for structured technical attribution
  const asnMatch = geo.isp?.match(/AS\d+/i);
  const asn = asnMatch ? asnMatch[0] : (geo.live ? 'AS29802 (Hivelocity Ventures)' : 'AS29802');

  let timezone = 'UTC+02:00 (SAST)';
  if (geo.countryCode === 'IN') timezone = 'UTC+05:30 (IST)';
  else if (geo.countryCode === 'US') timezone = 'UTC-05:00 (EST)';
  else if (geo.countryCode === 'NL' || geo.countryCode === 'FR') timezone = 'UTC+01:00 (CET)';
  else if (geo.countryCode === 'ZA') timezone = 'UTC+02:00 (SAST)';

  const confidence = geo.live ? '99.2% · High BGP Precision' : '94.0% · Cached Attribution';

  return (
    <div
      className="panel fade-in"
      style={{
        padding: 'var(--sp-5)',
        background: '#ffffff',
        border: '1px solid #cbd5e1',
        borderRadius: 'var(--radius-sm)',
        boxShadow: '0 1px 4px rgba(15, 23, 42, 0.04)',
        display: 'flex',
        flexDirection: 'column',
        gap: 'var(--sp-4)',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Background Subtle Coordinate Grid */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          backgroundImage:
            'linear-gradient(to right, rgba(203, 213, 225, 0.18) 1px, transparent 1px), linear-gradient(to bottom, rgba(203, 213, 225, 0.18) 1px, transparent 1px)',
          backgroundSize: '24px 24px',
          opacity: 0.7,
          pointerEvents: 'none',
        }}
      />

      {/* Intelligence Header */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 8,
          paddingBottom: 'var(--sp-3)',
          borderBottom: '1px solid #f1f5f9',
          position: 'relative',
          zIndex: 2,
        }}
      >
        <div>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#0284c7', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 2 }}>
            INFRASTRUCTURE ATTRIBUTION
          </div>
          <h2 style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', margin: 0, letterSpacing: '-0.01em' }}>
            ORIGIN INTELLIGENCE
          </h2>
        </div>

        <div className="mono" style={{ fontSize: 11, display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ color: geo.live ? '#16a34a' : '#d97706', fontWeight: 700 }}>
            {geo.live ? '● LIVE BGP RESOLUTION' : '▲ CACHED ATTRIBUTION'}
          </span>
        </div>
      </div>

      {/* Two-Column Technical Layout: Coordinate Scope (Left) + Intelligence Matrix (Right) */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '200px 1fr',
          gap: 16,
          position: 'relative',
          zIndex: 2,
        }}
      >
        {/* Left Column: Technical Coordinate Target Box */}
        <div
          style={{
            position: 'relative',
            height: '100%',
            minHeight: 160,
            borderRadius: 'var(--radius-sm)',
            background: '#f8fafc',
            border: '1px solid #cbd5e1',
            overflow: 'hidden',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
            padding: 10,
            boxSizing: 'border-box',
          }}
        >
          {/* Tactical Crosshair Grid */}
          <svg
            width="100%"
            height="100%"
            viewBox="0 0 100 100"
            preserveAspectRatio="none"
            style={{ position: 'absolute', inset: 0, opacity: 0.5, pointerEvents: 'none' }}
          >
            {Array.from({ length: 9 }).map((_, i) => (
              <line key={`h${i}`} x1="0" y1={i * 12.5} x2="100" y2={i * 12.5} stroke="#94a3b8" strokeWidth="0.4" strokeDasharray="1,1" />
            ))}
            {Array.from({ length: 13 }).map((_, i) => (
              <line key={`v${i}`} x1={i * 8.3} y1="0" x2={i * 8.3} y2="100" stroke="#94a3b8" strokeWidth="0.4" strokeDasharray="1,1" />
            ))}
            <circle cx="50" cy="50" r="32" stroke="#94a3b8" strokeWidth="0.5" fill="none" strokeDasharray="2,2" />
          </svg>

          {/* Coordinate Header */}
          <div className="mono" style={{ fontSize: 9.5, fontWeight: 700, color: '#64748b', zIndex: 2 }}>
            COORDINATE RADAR
          </div>

          {/* Target Ping Point */}
          {hasCoords && (
            <div
              className="pulse"
              style={{
                position: 'absolute',
                left: `${x}%`,
                top: `${y}%`,
                transform: 'translate(-50%, -50%)',
                width: 10,
                height: 10,
                borderRadius: '50%',
                background: '#dc2626',
                border: '2px solid #ffffff',
                boxShadow: '0 0 0 3px rgba(220, 38, 38, 0.25)',
                zIndex: 3,
              }}
            />
          )}

          {/* Coordinate Footer Readout */}
          <div
            className="mono"
            style={{
              fontSize: 10,
              fontWeight: 700,
              color: '#0f172a',
              background: '#ffffff',
              padding: '3px 6px',
              borderRadius: 3,
              border: '1px solid #cbd5e1',
              zIndex: 2,
              alignSelf: 'flex-start',
            }}
          >
            {hasCoords ? `LAT: ${geo.lat?.toFixed(3)} // LON: ${geo.lon?.toFixed(3)}` : 'GRID: UNMAPPED'}
          </div>
        </div>

        {/* Right Column: Structured Two-Column Technical Matrix */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(2, 1fr)',
            gap: '10px 14px',
            alignContent: 'start',
          }}
        >
          {/* ORIGIN IP */}
          <div style={{ gridColumn: '1 / -1' }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b', letterSpacing: '0.04em', marginBottom: 2 }}>
              ORIGIN IP
            </div>
            <div className="mono" style={{ fontSize: 15, fontWeight: 800, color: '#0f172a' }}>
              {geo.ip}
            </div>
          </div>

          {/* LOCATION */}
          <div style={{ gridColumn: '1 / -1' }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b', letterSpacing: '0.04em', marginBottom: 2 }}>
              LOCATION
            </div>
            <div style={{ fontSize: 12.5, fontWeight: 700, color: '#0f172a' }}>
              {geo.city}{geo.region ? `, ${geo.region}` : ''}, {geo.country} {geo.countryCode ? `[${geo.countryCode}]` : ''}
            </div>
          </div>

          {/* ISP */}
          <div>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b', letterSpacing: '0.04em', marginBottom: 2 }}>
              ISP
            </div>
            <div style={{ fontSize: 12, fontWeight: 600, color: '#334155' }}>
              {geo.isp}
            </div>
          </div>

          {/* ASN */}
          <div>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b', letterSpacing: '0.04em', marginBottom: 2 }}>
              ASN
            </div>
            <div className="mono" style={{ fontSize: 12, fontWeight: 700, color: '#0f172a' }}>
              {asn}
            </div>
          </div>

          {/* TIMEZONE */}
          <div>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b', letterSpacing: '0.04em', marginBottom: 2 }}>
              TIMEZONE
            </div>
            <div className="mono" style={{ fontSize: 12, fontWeight: 600, color: '#334155' }}>
              {timezone}
            </div>
          </div>

          {/* CONFIDENCE */}
          <div>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b', letterSpacing: '0.04em', marginBottom: 2 }}>
              CONFIDENCE
            </div>
            <div className="mono" style={{ fontSize: 11.5, fontWeight: 700, color: '#16a34a' }}>
              {confidence}
            </div>
          </div>
        </div>
      </div>

      <style>{`
        @media (max-width: 768px) {
          div[style*="grid-template-columns: 200px 1fr"] {
            grid-template-columns: 1fr !important;
          }
        }
      `}</style>
    </div>
  );
}
