import React from 'react';

const NODE_STATUS_STYLES = {
  safe: {
    color: '#0369a1',
    bg: '#f0f9ff',
    border: '#bae6fd',
    label: 'VERIFIED',
    icon: '●',
  },
  suspicious: {
    color: '#d97706',
    bg: '#fffbe6',
    border: '#fde68a',
    label: 'SUSPICIOUS',
    icon: '▲',
  },
  malicious: {
    color: '#dc2626',
    bg: '#fef2f2',
    border: '#fca5a5',
    label: 'FORGED',
    icon: '✕',
  },
};

export default function HopMap({ hops }) {
  // hops array from traceService:
  // index 0 = internal destination MX
  // index 1 = intermediate relay
  // index 2 = origin
  // This matches the natural forensic reconstruction flow: Target Mailbox → Intermediate Relays → Attributed Threat Origin
  const hopList = hops;

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
      }}
    >
      {/* Network Reconstruction Header */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 10,
          paddingBottom: 'var(--sp-3)',
          borderBottom: '1px solid #f1f5f9',
        }}
      >
        <div>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#0284c7', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 2 }}>
            NETWORK INFRASTRUCTURE RECONSTRUCTION
          </div>
          <h2 style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', margin: 0, letterSpacing: '-0.01em' }}>
            Reverse MTA Hop Chain
          </h2>
        </div>

        {/* Legend */}
        <div className="mono" style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: 10 }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#0369a1', fontWeight: 700 }}>
            ● VERIFIED
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#d97706', fontWeight: 700 }}>
            ▲ SUSPICIOUS
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#dc2626', fontWeight: 700 }}>
            ✕ FORGED
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#0f172a', fontWeight: 800 }}>
            ◎ ORIGIN
          </span>
        </div>
      </div>

      {/* Forensic Node Sequence with Thin Connectors */}
      <div style={{ display: 'flex', flexDirection: 'column', position: 'relative' }}>
        {hopList.map((hop, index) => {
          const isTarget = index === 0;
          const isOrigin = index === hopList.length - 1;
          const statusStyle = NODE_STATUS_STYLES[hop.trust] || NODE_STATUS_STYLES.safe;

          // Determine node type
          let nodeType = 'RELAY NODE';
          if (isTarget) nodeType = 'TARGET MAIL SERVER (INBOX MX)';
          if (isOrigin) nodeType = 'ATTRIBUTED THREAT ORIGIN';

          // Node border & background treatment
          let borderColor = '#cbd5e1';
          let borderLeft = '3px solid #64748b';
          let bgColor = '#ffffff';

          if (isOrigin) {
            borderColor = '#0f172a';
            borderLeft = '4px solid #0f172a';
            bgColor = '#f8fafc';
          } else if (hop.forged) {
            borderColor = '#fca5a5';
            borderLeft = '4px solid #dc2626';
            bgColor = '#fffbfb';
          } else if (isTarget) {
            borderLeft = '4px solid #0284c7';
          }

          return (
            <div key={index} style={{ display: 'flex', flexDirection: 'column' }}>
              {/* Forensic Node */}
              <div
                style={{
                  padding: '12px 16px',
                  background: bgColor,
                  border: `1px solid ${borderColor}`,
                  borderLeft: borderLeft,
                  borderRadius: 'var(--radius-sm)',
                  boxShadow: isOrigin
                    ? '0 2px 8px rgba(15, 23, 42, 0.08)'
                    : hop.forged
                    ? '0 2px 8px rgba(220, 38, 38, 0.06)'
                    : 'none',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 6,
                  transition: 'all 0.15s ease',
                }}
              >
                {/* Node Metadata Bar */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    {/* Node Number */}
                    <span
                      className="mono"
                      style={{
                        fontSize: 11,
                        fontWeight: 800,
                        color: isOrigin ? '#ffffff' : '#0f172a',
                        background: isOrigin ? '#0f172a' : '#f1f5f9',
                        padding: '1px 6px',
                        borderRadius: 3,
                        border: `1px solid ${isOrigin ? '#0f172a' : '#cbd5e1'}`,
                      }}
                    >
                      0{index + 1}
                    </span>

                    {/* Node Type */}
                    <span
                      style={{
                        fontSize: 11.5,
                        fontWeight: 700,
                        color: isOrigin ? '#0f172a' : '#334155',
                        letterSpacing: '0.02em',
                      }}
                    >
                      {nodeType}
                    </span>

                    {/* Threat Origin Badge */}
                    {isOrigin && (
                      <span
                        className="mono"
                        style={{
                          fontSize: 9.5,
                          fontWeight: 800,
                          padding: '1px 6px',
                          borderRadius: 3,
                          background: '#0284c7',
                          color: '#ffffff',
                          letterSpacing: '0.04em',
                        }}
                      >
                        ◎ PRIMARY ATTRIBUTION
                      </span>
                    )}

                    {/* Forged Anomaly Pill */}
                    {hop.forged && (
                      <span
                        className="mono"
                        style={{
                          fontSize: 9.5,
                          fontWeight: 800,
                          padding: '1px 6px',
                          borderRadius: 3,
                          background: '#fef2f2',
                          color: '#dc2626',
                          border: '1px solid #fca5a5',
                          letterSpacing: '0.04em',
                        }}
                      >
                        ⚠ FORGED HOP
                      </span>
                    )}
                  </div>

                  {/* Status Indicator */}
                  <span
                    className="mono"
                    style={{
                      fontSize: 10.5,
                      fontWeight: 700,
                      padding: '2px 7px',
                      borderRadius: 4,
                      background: statusStyle.bg,
                      color: statusStyle.color,
                      border: `1px solid ${statusStyle.border}`,
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 4,
                    }}
                  >
                    <span>{statusStyle.icon}</span>
                    <span>{hop.forged ? 'FORGED' : statusStyle.label}</span>
                  </span>
                </div>

                {/* Primary Technical Identifiers: IP + Hostname */}
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'baseline',
                    justifyContent: 'space-between',
                    gap: 12,
                    flexWrap: 'wrap',
                    paddingTop: 2,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, flexWrap: 'wrap' }}>
                    <div style={{ fontSize: 14, fontWeight: 800, color: '#0f172a' }} className="mono">
                      {hop.ip}
                    </div>
                    <div className="mono" style={{ fontSize: 12, color: '#475569' }}>
                      {hop.host}
                    </div>
                  </div>

                  <div style={{ fontSize: 11, color: '#64748b' }}>
                    ROLE: <strong style={{ color: '#0f172a' }}>{hop.by}</strong>
                  </div>
                </div>

                {/* Forensic Analysis Note */}
                <div style={{ fontSize: 12, color: '#475569', lineHeight: 1.45 }}>
                  {hop.note}
                </div>
              </div>

              {/* Connecting Transit Line & Indicator */}
              {index < hopList.length - 1 && (
                <div
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    height: 28,
                    position: 'relative',
                  }}
                >
                  {/* Vertical line */}
                  <div
                    style={{
                      width: 2,
                      height: '100%',
                      background: hopList[index + 1]?.forged ? '#f87171' : '#cbd5e1',
                    }}
                  />

                  {/* Centered Transit Tag */}
                  <div
                    className="mono"
                    style={{
                      position: 'absolute',
                      background: '#ffffff',
                      padding: '1px 8px',
                      fontSize: 9.5,
                      fontWeight: 700,
                      color: hopList[index + 1]?.forged ? '#dc2626' : '#64748b',
                      border: `1px solid ${hopList[index + 1]?.forged ? '#fca5a5' : '#cbd5e1'}`,
                      borderRadius: 3,
                      display: 'flex',
                      alignItems: 'center',
                      gap: 4,
                    }}
                  >
                    <span>│</span>
                    <span>▼</span>
                    <span>{hopList[index + 1]?.forged ? 'REVERSE-DNS MISMATCH' : 'MTA TRANSIT'}</span>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
