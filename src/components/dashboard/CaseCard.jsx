import React from 'react';
import StatusBadge from '../common/StatusBadge';

const RISK_CONFIG = {
  critical: { label: 'CRITICAL', color: '#b91c1c', bg: '#fef2f2', border: '#fca5a5' },
  high: { label: 'HIGH', color: '#b45309', bg: '#fffbe6', border: '#fde68a' },
  medium: { label: 'MEDIUM', color: '#0369a1', bg: '#f0f9ff', border: '#bae6fd' },
  low: { label: 'LOW', color: '#475569', bg: '#f1f5f9', border: '#cbd5e1' },
};

export default function CaseCard({ item, onOpen, isLast }) {
  const isPrimaryDemo = item.id === 'CASE-2026-0417';
  const risk = RISK_CONFIG[item.priority] || RISK_CONFIG.low;

  const d = new Date(item.receivedAt);
  const timeStr = d.toLocaleTimeString('en-US', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
  const dateStr = d.toLocaleDateString('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
  });

  return (
    <div
      onClick={() => onOpen(item)}
      className="case-table-row"
      style={{
        display: 'grid',
        gridTemplateColumns: '170px 110px 1fr 90px 110px 120px',
        gap: 12,
        padding: '12px 16px',
        alignItems: 'center',
        background: isPrimaryDemo ? '#f8fbfe' : '#ffffff',
        borderBottom: isLast ? 'none' : '1px solid #f1f5f9',
        borderLeft: isPrimaryDemo ? '3px solid #0284c7' : '3px solid transparent',
        transition: 'background 0.15s ease',
        cursor: 'pointer',
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.background = isPrimaryDemo ? '#f0f7fd' : '#f8fafc';
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.background = isPrimaryDemo ? '#f8fbfe' : '#ffffff';
      }}
    >
      {/* CASE ID & Demo indicator */}
      <div>
        <div
          className="mono"
          style={{
            fontSize: 12.5,
            fontWeight: 700,
            color: '#0f172a',
            letterSpacing: '0.02em',
          }}
        >
          {item.id}
        </div>
        {isPrimaryDemo && (
          <div
            style={{
              fontSize: 9.5,
              fontWeight: 700,
              padding: '1px 5px',
              borderRadius: 'var(--radius-xs)',
              background: '#e0f2fe',
              border: '1px solid #bae6fd',
              color: '#0284c7',
              letterSpacing: '0.03em',
              display: 'inline-block',
              marginTop: 3,
            }}
          >
            DEMO INVESTIGATION
          </div>
        )}
      </div>

      {/* DATE / TIME */}
      <div>
        <div
          className="mono"
          style={{
            fontSize: 12,
            fontWeight: 600,
            color: '#1e293b',
          }}
        >
          {timeStr}
        </div>
        <div
          className="mono"
          style={{
            fontSize: 10.5,
            color: '#64748b',
          }}
        >
          {dateStr}
        </div>
      </div>

      {/* SUBJECT / SOURCE */}
      <div style={{ minWidth: 0, overflow: 'hidden' }}>
        <div
          style={{
            fontSize: 13,
            fontWeight: 700,
            color: '#0f172a',
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            marginBottom: 2,
          }}
          title={item.subject}
        >
          {item.subject}
        </div>
        <div
          style={{
            fontSize: 11.5,
            color: '#64748b',
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
          }}
        >
          <span style={{ color: '#94a3b8', marginRight: 4, fontWeight: 600 }}>FROM:</span>
          <span>{item.displayFrom}</span>
        </div>
      </div>

      {/* RISK */}
      <div>
        <span
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 5,
            padding: '2px 7px',
            borderRadius: 4,
            fontSize: 11,
            fontWeight: 700,
            letterSpacing: '0.04em',
            color: risk.color,
            background: risk.bg,
            border: `1px solid ${risk.border}`,
          }}
        >
          <span
            style={{
              width: 5,
              height: 5,
              borderRadius: '50%',
              background: risk.color,
            }}
          />
          {risk.label}
        </span>
      </div>

      {/* STATUS */}
      <div>
        <StatusBadge variant={item.status} />
      </div>

      {/* ACTION */}
      <div style={{ textAlign: 'right' }}>
        <button
          onClick={(e) => {
            e.stopPropagation();
            onOpen(item);
          }}
          className="btn btn-sm"
          style={{
            padding: '5px 11px',
            fontSize: 11.5,
            fontWeight: 700,
            color: isPrimaryDemo ? '#0284c7' : '#334155',
            background: isPrimaryDemo ? '#e0f2fe' : '#ffffff',
            border: `1px solid ${isPrimaryDemo ? '#bae6fd' : '#cbd5e1'}`,
            borderRadius: 'var(--radius-sm)',
            cursor: 'pointer',
            display: 'inline-flex',
            alignItems: 'center',
            gap: 4,
            transition: 'all 0.15s ease',
          }}
        >
          <span>OPEN CASE</span>
          <span>→</span>
        </button>
      </div>
    </div>
  );
}
