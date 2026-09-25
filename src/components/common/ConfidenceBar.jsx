import React from 'react';

export default function ConfidenceBar({ value, color = '#0284c7' }) {
  const pct = Math.round(value * 100);
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      <div
        style={{
          flex: 1,
          height: 10,
          borderRadius: 3,
          background: '#f1f5f9',
          overflow: 'hidden',
          border: '1px solid #cbd5e1',
          position: 'relative',
        }}
      >
        <div
          style={{
            width: `${pct}%`,
            height: '100%',
            background: color,
            transition: 'width 0.6s cubic-bezier(0.2, 0.8, 0.2, 1)',
          }}
        />
        {/* Calibrated Instrument Ticks */}
        <div
          style={{
            position: 'absolute',
            inset: 0,
            display: 'flex',
            justifyContent: 'space-between',
            pointerEvents: 'none',
            padding: '0 4px',
          }}
        >
          {Array.from({ length: 9 }).map((_, idx) => (
            <div key={idx} style={{ width: 1, height: '100%', background: 'rgba(255, 255, 255, 0.5)' }} />
          ))}
        </div>
      </div>
      <span className="mono" style={{ fontSize: 12, fontWeight: 800, color: '#0f172a', minWidth: 38, textAlign: 'right' }}>
        {pct}%
      </span>
    </div>
  );
}


