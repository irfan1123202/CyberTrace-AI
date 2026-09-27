import { supabase, isSupabaseConfigured } from './supabaseClient';
import { mockCases } from '../data/mockCases';

/**
 * Returns current database connectivity status
 */
export function getDatabaseStatus() {
  if (isSupabaseConfigured()) {
    return {
      connected: true,
      provider: 'Supabase (PostgreSQL Cloud)',
      badge: '● DB: SUPABASE CLOUD',
      type: 'supabase',
    };
  }
  return {
    connected: false,
    provider: 'Local Prototype Storage (In-Memory / LocalStorage)',
    badge: '● DB: PROTOTYPE (OFFLINE-READY)',
    type: 'local',
  };
}

/**
 * Fetch all investigation cases
 */
export async function fetchCases() {
  if (isSupabaseConfigured() && supabase) {
    try {
      const { data, error } = await supabase
        .from('cases')
        .select('*')
        .order('received_at', { ascending: false });

      if (!error && data && data.length > 0) {
        return data.map((row) => ({
          id: row.id,
          subject: row.subject,
          from: row.from_addr || row.from,
          displayFrom: row.display_from || row.displayFrom,
          to: row.to_addr || row.to,
          receivedAt: row.received_at || row.receivedAt,
          status: row.status,
          priority: row.priority,
          preview: row.preview,
          headerSample: row.header_sample || row.headerSample,
        }));
      }
    } catch (err) {
      console.warn('Supabase fetch failed, falling back to prototype dataset:', err);
    }
  }

  // Local fallback (cached cases or mockCases)
  const localCases = localStorage.getItem('cybertrace_cases');
  if (localCases) {
    try {
      return JSON.parse(localCases);
    } catch (e) {
      // fallback
    }
  }
  return mockCases;
}

/**
 * Fetch single case by ID
 */
export async function fetchCaseById(caseId) {
  if (isSupabaseConfigured() && supabase) {
    try {
      const { data, error } = await supabase
        .from('cases')
        .select('*')
        .eq('id', caseId)
        .single();

      if (!error && data) {
        return {
          id: data.id,
          subject: data.subject,
          from: data.from_addr || data.from,
          displayFrom: data.display_from || data.displayFrom,
          to: data.to_addr || data.to,
          receivedAt: data.received_at || data.receivedAt,
          status: data.status,
          priority: data.priority,
          preview: data.preview,
          headerSample: data.header_sample || data.headerSample,
        };
      }
    } catch (err) {
      console.warn('Supabase case lookup failed, using local lookup:', err);
    }
  }

  // Local lookup
  const cases = await fetchCases();
  return cases.find((c) => c.id === caseId) || null;
}

/**
 * Update case status (e.g. pending -> escalated | cleared)
 */
export async function updateCaseStatus(caseId, status) {
  if (isSupabaseConfigured() && supabase) {
    try {
      await supabase
        .from('cases')
        .update({ status })
        .eq('id', caseId);
    } catch (err) {
      console.warn('Supabase update failed:', err);
    }
  }

  // Update in localStorage cache
  const cases = await fetchCases();
  const updated = cases.map((c) => (c.id === caseId ? { ...c, status } : c));
  localStorage.setItem('cybertrace_cases', JSON.stringify(updated));
  return updated;
}

/**
 * Save forensic evidence report to database
 */
export async function saveForensicReport(reportData) {
  if (isSupabaseConfigured() && supabase) {
    try {
      const { data, error } = await supabase
        .from('forensic_reports')
        .insert([
          {
            case_id: reportData.caseId,
            evidence_hash: reportData.hash,
            verdict: reportData.verdict,
            hops: reportData.hops,
            geo_origin: reportData.origin,
            created_at: new Date().toISOString(),
          },
        ]);
      if (!error) return data;
    } catch (err) {
      console.warn('Failed to save report to Supabase:', err);
    }
  }

  // Save to local reports collection
  const existing = JSON.parse(localStorage.getItem('cybertrace_reports') || '[]');
  existing.push({
    ...reportData,
    savedAt: new Date().toISOString(),
  });
  localStorage.setItem('cybertrace_reports', JSON.stringify(existing));
  return reportData;
}
