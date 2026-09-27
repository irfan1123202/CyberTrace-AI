import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import CaseQueue from '../components/dashboard/CaseQueue';
import { mockCases } from '../data/mockCases';
import { fetchCases } from '../services/dbService';

export default function Dashboard() {
  const navigate = useNavigate();
  const [cases, setCases] = useState(mockCases);

  useEffect(() => {
    let active = true;
    fetchCases().then((res) => {
      if (active && res && res.length > 0) {
        setCases(res);
      }
    });
    return () => {
      active = false;
    };
  }, []);

  const pendingCount = cases.filter((c) => c.status === 'pending').length;
  const escalatedCount = cases.filter((c) => c.status === 'escalated').length;

  return (
    <div style={{ maxWidth: 1160, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 'var(--sp-6)', fontFamily: 'var(--font-ui)' }}>
      {/* Compact Dashboard Hero */}
      <div
        className="panel"
        style={{
          padding: 'var(--sp-5) var(--sp-6)',
          background: '#ffffff',
          borderRadius: 'var(--radius-sm)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: 'var(--sp-5)',
          flexWrap: 'wrap',
          borderLeft: '4px solid #0284c7',
        }}
      >
        <div style={{ flex: 1, minWidth: 280 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#0284c7', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 4 }}>
            INVESTIGATION WORKSPACE
          </div>
          <h1 style={{ fontSize: 20, fontWeight: 800, color: '#0f172a', margin: '0 0 6px', letterSpacing: '-0.01em' }}>
            Trace suspicious infrastructure. Analyze email evidence. Generate forensic reports.
          </h1>
          <p style={{ fontSize: 13, color: '#475569', margin: 0, lineHeight: 1.5 }}>
            Automated hop-by-hop reverse MTA transit reconstruction and deep DeBERTa-v3 NLP attribution for tier-2 SOC teams.
          </p>
        </div>

        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          <button
            className="btn"
            onClick={() => navigate('/analysis')}
            style={{
              padding: '9px 16px',
              fontSize: 13,
              fontWeight: 700,
              gap: 6,
              whiteSpace: 'nowrap',
              color: '#0f172a',
              background: '#f8fafc',
              borderColor: '#cbd5e1',
            }}
          >
            <span>✉</span>
            <span>SECURE EMAIL ANALYSIS</span>
          </button>

          <button
            className="btn btn-primary"
            onClick={() => navigate('/case/CASE-2026-0417')}
            style={{ padding: '9px 18px', fontSize: 13, gap: 8, whiteSpace: 'nowrap' }}
          >
            <span>OPEN INVESTIGATION</span>
            <span>→</span>
          </button>
        </div>
      </div>

      {/* Active Investigations Section */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--sp-3)', flexWrap: 'wrap', gap: 8 }}>
          <div>
            <h2 style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', margin: '0 0 2px', letterSpacing: '-0.01em' }}>
              ACTIVE INVESTIGATIONS
            </h2>
            <div style={{ fontSize: 12, color: '#64748b' }}>
              {pendingCount} awaiting review · {escalatedCount} escalated priority incident
            </div>
          </div>
        </div>

        {/* Case Queue Table */}
        <CaseQueue cases={cases} onOpen={(item) => navigate(`/case/${item.id}`)} />
      </div>
    </div>
  );
}



