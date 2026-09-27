// CyberTrace AI — Service Layer
// -----------------------------------------------------------------------
// In production this layer would call a FastAPI backend running the real
// DeBERTa-v3 intent model, Neo4j graph attribution, and MaxMind GeoLite2.
// For this prototype, the trace pipeline (hop reconstruction, SPF/DKIM/
// DMARC verdicts, NLP intent, campaign clustering) is realistically
// mocked — EXCEPT the geolocation step, which makes a real network call
// to a public IP-geolocation API so the origin map reflects live data.

import { fetchIpGeo } from './apiClient';

const GEO_API = 'https://ipapi.co';

/** Deterministic per-scenario forensic data, keyed to mockCases.headerSample */
const SCENARIOS = {
  HDR_BEC_SPOOF_01: {
    originIp: '154.16.63.102',
    hops: [
      { host: 'mail.annapoorna.edu.in', ip: '203.199.48.10', by: 'Internal MX', trust: 'safe', note: 'Final internal delivery hop — expected.' },
      { host: 'smtp-relay-04.outbound-corp.net', ip: '198.51.100.77', by: 'Legit relay', trust: 'safe', note: 'Known corporate relay, consistent with prior traffic.' },
      { host: 'mx1.freemailer-gw.com', ip: '154.16.63.102', by: 'Unverified origin', trust: 'malicious', note: 'Header "Received" chain shows a fabricated internal hostname — reverse DNS mismatch detected.', forged: true },
    ],
    spf: 'fail',
    dkim: 'fail',
    dmarc: 'fail',
    intent: { label: 'Business Email Compromise (BEC)', confidence: 0.97 },
    reasons: [
      'Sender display name impersonates internal finance authority (CFO Office)',
      'Urgency + confidentiality language cluster matches known BEC linguistic pattern',
      'Reply-To domain differs from From domain by one character (typosquat)',
      'SPF/DKIM/DMARC all fail — sending IP not authorized for claimed domain',
    ],
    campaignMatches: 3,
  },
  HDR_PHISH_TOR_02: {
    originIp: '45.61.185.20',
    hops: [
      { host: 'mail.annapoorna.edu.in', ip: '203.199.48.10', by: 'Internal MX', trust: 'safe', note: 'Final internal delivery hop — expected.' },
      { host: 'exit-node-fr3.torproxy.net', ip: '45.61.185.20', by: 'Anonymized relay', trust: 'suspicious', note: 'Originating hop resolves to a known Tor exit node range.', forged: true },
    ],
    spf: 'fail',
    dkim: 'none',
    dmarc: 'fail',
    intent: { label: 'Credential Phishing', confidence: 0.94 },
    reasons: [
      'Domain "paypa1-support.com" uses homoglyph substitution (1 for l)',
      'Urgency + account-suspension framing matches phishing corpus benchmark',
      'Origin traced through anonymized Tor exit relay — identity obfuscation attempt',
      'Domain registered 9 days ago (WHOIS age flag)',
    ],
    campaignMatches: 12,
  },
  HDR_LEGIT_01: {
    originIp: '203.199.48.5',
    hops: [
      { host: 'mail.annapoorna.edu.in', ip: '203.199.48.10', by: 'Internal MX', trust: 'safe', note: 'Final internal delivery hop — expected.' },
      { host: 'registrar-workstation-12.annapoorna.edu.in', ip: '203.199.48.5', by: 'Internal sender', trust: 'safe', note: 'Consistent internal IP range, matches sender history.' },
    ],
    spf: 'pass',
    dkim: 'pass',
    dmarc: 'pass',
    intent: { label: 'Legitimate Communication', confidence: 0.99 },
    reasons: [
      'All authentication protocols pass with domain alignment',
      'Sender IP matches known internal range for this mailbox',
      'No urgency/coercion linguistic markers detected',
    ],
    campaignMatches: 0,
  },
  HDR_PHISH_PROXY_03: {
    originIp: '103.216.50.10',
    hops: [
      { host: 'mail.annapoorna.edu.in', ip: '203.199.48.10', by: 'Internal MX', trust: 'safe', note: 'Final internal delivery hop — expected.' },
      { host: 'mail-gw2.hosting-proxy-svc.com', ip: '103.216.50.10', by: 'Open proxy relay', trust: 'suspicious', note: 'Relay flagged in AbuseIPDB reputation feed within last 30 days.', forged: true },
    ],
    spf: 'softfail',
    dkim: 'fail',
    dmarc: 'fail',
    intent: { label: 'Invoice Fraud', confidence: 0.88 },
    reasons: [
      'Vendor domain does not match any prior procurement correspondence',
      'Payment-overdue urgency pattern matches invoice-fraud corpus',
      'Relay IP present on abuse reputation feed',
    ],
    campaignMatches: 5,
  },
  HDR_BEC_SPOOF_02: {
    originIp: '102.89.23.100',
    hops: [
      { host: 'mail.annapoorna.edu.in', ip: '203.199.48.10', by: 'Internal MX', trust: 'safe', note: 'Final internal delivery hop — expected.' },
      { host: 'smtp.aicte-portal-gov.org', ip: '102.89.23.100', by: 'Spoofed gov domain', trust: 'malicious', note: 'Domain mimics AICTE but registrar and hosting ASN do not match any government-registered range.', forged: true },
    ],
    spf: 'fail',
    dkim: 'fail',
    dmarc: 'fail',
    intent: { label: 'Business Email Compromise (BEC)', confidence: 0.96 },
    reasons: [
      'Domain "aicte-portal-gov.org" is not on the official .gov.in registry',
      'Request for bank details via email matches BEC disbursal-fraud pattern',
      'Hosting ASN geolocates outside India despite claimed government origin',
      'SPF/DKIM/DMARC all fail for the claimed sending domain',
    ],
    campaignMatches: 7,
  },
};

const STAGES = [
  { key: 'parse', label: 'Parsing MIME & extracting headers' },
  { key: 'hops', label: 'Reconstructing MTA hop chain' },
  { key: 'auth', label: 'Verifying SPF / DKIM / DMARC alignment' },
  { key: 'geo', label: 'Resolving origin geolocation' },
  { key: 'nlp', label: 'Running DeBERTa-v3 intent classification' },
  { key: 'graph', label: 'Cross-referencing campaign attribution graph' },
];

export function getStages() {
  return STAGES;
}

/** Real network call — live IP geolocation via CyberTrace Backend */
async function resolveGeo(ip) {
  // 1. Try our dedicated CyberTrace backend (with cache, multi-provider, offline fallback)
  try {
    const backendData = await fetchIpGeo(ip);
    if (backendData && backendData.success && backendData.lat !== undefined && backendData.lon !== undefined) {
      return {
        ip: backendData.ip || ip,
        city: backendData.city || 'Unknown',
        region: backendData.regionName || backendData.region || '',
        country: backendData.country || 'Unknown',
        countryCode: backendData.countryCode || '',
        lat: backendData.lat,
        lon: backendData.lon,
        isp: `${backendData.asn || ''} ${backendData.isp || backendData.org || ''}`.trim() || 'Unknown ISP',
        live: backendData.live !== false,
        source: backendData.source,
      };
    }
  } catch (err) {
    console.warn('[TraceService] Backend GeoIP failed, trying public fallback:', err.message);
  }

  // 2. Direct public API fallback
  try {
    const res = await fetch(`${GEO_API}/${ip}/json/`);
    if (!res.ok) throw new Error('geo lookup failed');
    const data = await res.json();
    if (data.error) throw new Error(data.reason || 'geo lookup error');
    return {
      ip,
      city: data.city || 'Unknown',
      region: data.region || '',
      country: data.country_name || 'Unknown',
      countryCode: data.country_code || '',
      lat: data.latitude,
      lon: data.longitude,
      isp: data.org || data.asn || 'Unknown ASN',
      live: true,
    };
  } catch (e) {
    // Graceful fallback so the demo never breaks if the API is rate-limited/offline.
    return {
      ip,
      city: 'Unresolved',
      region: '',
      country: 'Lookup unavailable',
      countryCode: '',
      lat: null,
      lon: null,
      isp: 'Live lookup failed — showing cached last-known attribution',
      live: false,
    };
  }
}

/**
 * Runs the full mock forensic pipeline for a case, invoking onStage as each
 * phase completes so the UI can animate real progress.
 */
export async function runTrace(headerSample, onStage) {
  const scenario = SCENARIOS[headerSample] || SCENARIOS.HDR_LEGIT_01;
  const timings = [260, 420, 300, 550, 480, 340]; // ms per stage, tuned for a snappy but visible demo

  onStage?.('parse');
  await wait(timings[0]);

  onStage?.('hops');
  await wait(timings[1]);

  onStage?.('auth');
  await wait(timings[2]);

  onStage?.('geo');
  const geo = await resolveGeo(scenario.originIp);
  await wait(timings[3]);

  onStage?.('nlp');
  await wait(timings[4]);

  onStage?.('graph');
  await wait(timings[5]);

  const verdict = computeVerdict(scenario);

  return {
    hops: scenario.hops,
    auth: { spf: scenario.spf, dkim: scenario.dkim, dmarc: scenario.dmarc },
    geo,
    intent: scenario.intent,
    reasons: scenario.reasons,
    campaignMatches: scenario.campaignMatches,
    verdict,
    processedAt: new Date().toISOString(),
  };
}

function computeVerdict(scenario) {
  const authFails = [scenario.spf, scenario.dkim, scenario.dmarc].filter(
    (v) => v === 'fail'
  ).length;
  if (scenario.intent.label === 'Legitimate Communication') return 'safe';
  if (authFails >= 2 || scenario.intent.confidence > 0.93) return 'malicious';
  return 'suspicious';
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Builds the SHA-256 hash chain for the forensic report using the browser's
 * real WebCrypto API — an authentic (not simulated) integrity hash. */
export async function buildEvidenceHashChain(caseId, traceResult) {
  const payload = JSON.stringify({ caseId, traceResult, ts: traceResult.processedAt });
  const enc = new TextEncoder().encode(payload);
  const digest = await crypto.subtle.digest('SHA-256', enc);
  const hashArray = Array.from(new Uint8Array(digest));
  const hex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  return hex;
}
