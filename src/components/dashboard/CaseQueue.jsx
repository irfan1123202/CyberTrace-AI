import React, { useMemo, useState } from 'react';
import CaseCard from './CaseCard';

const FILTERS = [
  { key: 'all', label: 'All Incidents' },
  { key: 'pending', label: 'Pending Triage' },
  { key: 'escalated', label: 'Escalated' },
  { key: 'cleared', label: 'Cleared' },
];

export default function CaseQueue({ cases, onOpen }) {
  const [filter, setFilter] = useState('all');
  const [query, setQuery] = useState('');

  const filtered = useMemo(() => {
    return cases.filter((c) => {
      const matchesFilter = filter === 'all' || c.status === filter;
      const q = query.trim().toLowerCase();
      const matchesQuery =
        !q ||
        c.subject.toLowerCase().includes(q) ||
        c.from.toLowerCase().includes(q) ||
        c.id.toLowerCase().includes(q);
      return matchesFilter && matchesQuery;
    });
  }, [cases, filter, query]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-3)', fontFamily: 'var(--font-ui)' }}>
      {/* Triage Search & Filter Control Strip */}
      <div
        style={{
          display: 'flex',
          gap: 'var(--sp-3)',
          alignItems: 'center',
          flexWrap: 'wrap',
          justifyContent: 'space-between',
        }}
      >
        <div style={{ position: 'relative', flex: 1, minWidth: 260 }}>
          <input
            type="text"
            placeholder="Query by Subject, Sender domain, or Case ID (e.g., CASE-2026-0417)…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            style={{
              width: '100%',
              padding: '8px 12px 8px 30px',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--border-hairline)',
              background: '#ffffff',
              color: 'var(--text-primary)',
              fontSize: 12.5,
              fontWeight: 500,
              boxShadow: 'var(--shadow-subtle)',
              outline: 'none',
              fontFamily: 'var(--font-ui)',
            }}
          />
          <span
            className="mono"
            style={{
              position: 'absolute',
              left: 10,
              top: '50%',
              transform: 'translateY(-50%)',
              color: 'var(--text-tertiary)',
              fontSize: 11,
              pointerEvents: 'none',
            }}
          >
            ⌕
          </span>
        </div>

        {/* Filter Pills */}
        <div style={{ display: 'flex', gap: 4 }}>
          {FILTERS.map((f) => {
            const active = filter === f.key;
            const count = f.key === 'all' ? cases.length : cases.filter((c) => c.status === f.key).length;
            return (
              <button
                key={f.key}
                onClick={() => setFilter(f.key)}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 6,
                  padding: '6px 11px',
                  borderRadius: 'var(--radius-sm)',
                  border: `1px solid ${active ? 'var(--accent)' : 'var(--border-hairline)'}`,
                  background: active ? 'var(--accent-bg)' : '#ffffff',
                  color: active ? 'var(--accent)' : 'var(--text-secondary)',
                  fontSize: 11.5,
                  fontWeight: 600,
                  boxShadow: active ? '0 1px 2px rgba(2, 132, 199, 0.12)' : 'var(--shadow-subtle)',
                  transition: 'all 0.15s ease',
                  cursor: 'pointer',
                }}
              >
                <span>{f.label}</span>
                <span
                  className="mono"
                  style={{
                    fontSize: 10,
                    fontWeight: 700,
                    padding: '0 4px',
                    borderRadius: 'var(--radius-xs)',
                    background: active ? '#ffffff' : 'var(--bg-inset)',
                    color: active ? 'var(--accent)' : 'var(--text-tertiary)',
                    border: '1px solid var(--border-hairline-soft)',
                  }}
                >
                  {count}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Structured Forensic Investigation Table */}
      <div
        className="panel"
        style={{
          background: '#ffffff',
          border: '1px solid var(--border-hairline)',
          borderRadius: 'var(--radius-sm)',
          overflow: 'hidden',
          boxShadow: 'var(--shadow-subtle)',
        }}
      >
        {/* Table Column Header */}
        <div
          className="case-table-header"
          style={{
            display: 'grid',
            gridTemplateColumns: '170px 110px 1fr 90px 110px 120px',
            gap: 12,
            padding: '9px 16px',
            background: 'var(--bg-subtle)',
            borderBottom: '1px solid var(--border-hairline)',
            fontSize: 11,
            fontWeight: 700,
            color: '#64748b',
            letterSpacing: '0.04em',
            textTransform: 'uppercase',
            alignItems: 'center',
          }}
        >
          <div>CASE ID</div>
          <div>DATE / TIME</div>
          <div>SUBJECT / SOURCE</div>
          <div>RISK</div>
          <div>STATUS</div>
          <div style={{ textAlign: 'right' }}>ACTION</div>
        </div>

        {/* Table Rows */}
        {filtered.length === 0 ? (
          <div
            style={{
              padding: 'var(--sp-8)',
              textAlign: 'center',
              color: 'var(--text-tertiary)',
            }}
          >
            <div className="mono" style={{ fontSize: 20, marginBottom: 6 }}>[EMPTY_RESULT]</div>
            <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 2 }}>
              No Incidents Match Active Query
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              Verify query string or switch filter tabs.
            </div>
          </div>
        ) : (
          filtered.map((item, idx) => (
            <CaseCard
              key={item.id}
              item={item}
              onOpen={onOpen}
              isLast={idx === filtered.length - 1}
            />
          ))
        )}
      </div>

      <style>{`
        @media (max-width: 900px) {
          .case-table-header {
            display: none !important;
          }
          .case-table-row {
            display: flex !important;
            flex-direction: column !important;
            align-items: flex-start !important;
            gap: 8px !important;
          }
        }
      `}</style>
    </div>
  );
}



