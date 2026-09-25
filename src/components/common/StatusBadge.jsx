import React from 'react';

const VARIANTS = {
  safe: { color: '#15803d', bg: '#f0fdf4', border: '#bbf7d0', label: 'CLEARED' },
  suspicious: { color: '#b45309', bg: '#fffbe6', border: '#fde68a', label: 'SUSPICIOUS' },
  malicious: { color: '#b91c1c', bg: '#fef2f2', border: '#fca5a5', label: 'MALICIOUS' },
  pending: { color: '#334155', bg: '#f1f5f9', border: '#cbd5e1', label: 'PENDING' },
  escalated: { color: '#b91c1c', bg: '#fef2f2', border: '#fca5a5', label: 'ESCALATED' },
  cleared: { color: '#15803d', bg: '#f0fdf4', border: '#bbf7d0', label: 'CLEARED' },
};

export default function StatusBadge({ variant = 'pending', label }) {
  const v = VARIANTS[variant] || VARIANTS.pending;
  return (
    <span
      className="mono"
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        padding: '3px 8px',
        borderRadius: 4,
        fontSize: 11,
        fontWeight: 700,
        letterSpacing: '0.04em',
        color: v.color,
        background: v.bg,
        border: `1px solid ${v.border}`,
        boxShadow: '0 1px 2px rgba(15, 23, 42, 0.03)',
      }}
    >
      <span
        style={{
          width: 6,
          height: 6,
          borderRadius: '50%',
          background: v.color,
          flexShrink: 0,
        }}
      />
      {label || v.label}
    </span>
  );
}

