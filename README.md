# CyberTrace AI — Prototype

**SIH 2026 · Problem Statement 26106 · Team Syndicate**
AI-powered email threat detection, geolocation, and forensic intelligence platform.

## Run it

```bash
npm install
npm run dev
```

Open the printed localhost URL. No backend or API key needed — the origin
geolocation panel makes a real, free call to `ipapi.co` for live IP lookup;
everything else (hop reconstruction, SPF/DKIM/DMARC, NLP intent, campaign
graph matches) is a realistic mocked forensic pipeline standing in for the
production DeBERTa-v3 / Neo4j / MaxMind stack described in the idea deck.

## Judge demo flow (~2 minutes)

1. **Open the Case Queue** — point out the mix of pending/escalated cases,
   the priority dots, and that this looks like a real SOC triage inbox, not
   a spam folder.
2. **Click `CASE-2026-0417`** (the CFO wire-transfer BEC case) — show the
   case header, then click **"Run Forensic Trace."**
3. **Narrate the pipeline as it runs** — "parsing headers → reconstructing
   hops → verifying auth → resolving origin → running DeBERTa-v3 → checking
   the attribution graph" — it finishes in under 3 seconds, matching the
   deck's own claim.
4. **Point at the Hop Map** — the forged final hop is visually distinct
   (colored, ringed, labeled "FORGED HOP"), with a plain-English reason.
5. **Point at the Geolocation panel** — call out the **"● LIVE LOOKUP"**
   badge; this is a real network call resolving the attacker's real-world
   location, not a static mock.
6. **Point at the Verdict panel** — confidence score, SPF/DKIM/DMARC grid,
   the explainable "why" list, and the campaign-graph match count.
7. **Click "Download Report"** — a hash-chained, NIST SP 800-86–aligned
   evidence file downloads instantly. This is the artifact SOC/law
   enforcement could actually hand off.
8. **Close on the value line**: "days of manual header forensics, down to
   under three seconds — court-admissible, not just a spam label."

## What's real vs. mocked

| Layer | This prototype | Production (per idea deck) |
|---|---|---|
| Hop reconstruction | Deterministic mock scenarios | RFC 5322 header parsing, reverse MTA trace |
| SPF/DKIM/DMARC | Mock verdicts per scenario | RFC 7208/6376/7489 verification |
| Geolocation | **Real `ipapi.co` API call** | MaxMind GeoLite2 offline DB |
| NLP intent | Mock label + confidence | Fine-tuned DeBERTa-v3 |
| Campaign graph | Mock match count | Neo4j + NetworkX community detection |
| Evidence hash | **Real SHA-256 via WebCrypto** | Same, server-side, chained per NIST SP 800-86 |

## Project structure

```
src/
├── main.jsx, App.jsx        — entry point, router shell
├── styles/                  — design tokens + global CSS (no framework)
├── data/mockCases.js        — demo case queue
├── services/traceService.js — mock pipeline + real GeoIP call + real SHA-256
├── hooks/useTrace.js         — trace pipeline state machine
├── components/
│   ├── layout/               — Sidebar
│   ├── dashboard/             — CaseQueue, CaseCard
│   ├── trace/                 — HopMap, GeoPanel, VerdictPanel, ForensicReport
│   └── common/                 — StatusBadge, ConfidenceBar, LoadingTrace
└── pages/                    — Dashboard, TraceDetail
```
