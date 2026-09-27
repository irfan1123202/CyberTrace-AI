// CyberTrace AI — Threat Intelligence Routes
// =============================================================================
// GET /api/threat/ip/:ip       — AbuseIPDB reputation lookup / heuristic threat score
// GET /api/threat/url/:b64url  — VirusTotal URL analysis / security assessment
// =============================================================================

const express = require('express');
const axios = require('axios');
const router = express.Router();
const { isPrivateIp } = require('../services/geoipService');

/**
 * GET /api/threat/ip/:ip
 */
router.get('/ip/:ip', async (req, res, next) => {
  try {
    const { ip } = req.params;
    if (!ip) {
      return res.status(400).json({ error: 'IP parameter is required' });
    }

    const apiKey = process.env.ABUSEIPDB_API_KEY;

    if (isPrivateIp(ip)) {
      return res.json({
        ip,
        isPrivate: true,
        abuseConfidenceScore: 0,
        totalReports: 0,
        threatLevel: 'SAFE',
        verdict: 'Private RFC1918 Address — No external abuse history possible',
        mode: 'internal',
      });
    }

    if (apiKey) {
      try {
        const resp = await axios.get('https://api.abuseipdb.com/api/v2/check', {
          params: { ipAddress: ip, maxAgeInDays: 90 },
          headers: { Key: apiKey, Accept: 'application/json' },
          timeout: 5000,
        });
        const data = resp.data?.data || {};
        const score = data.abuseConfidenceScore || 0;
        return res.json({
          ip,
          abuseConfidenceScore: score,
          totalReports: data.totalReports || 0,
          lastReportedAt: data.lastReportedAt || null,
          threatLevel: score > 50 ? 'CRITICAL' : score > 20 ? 'SUSPICIOUS' : 'SAFE',
          isWhitelisted: data.isWhitelisted || false,
          countryCode: data.countryCode,
          usageType: data.usageType,
          mode: 'abuseipdb-live',
        });
      } catch (apiErr) {
        console.warn(`[ThreatIntel] AbuseIPDB live query failed: ${apiErr.message}`);
      }
    }

    // Heuristic assessment when no API key configured
    // Known test / malicious simulation ranges
    let score = 5;
    let threatLevel = 'SAFE';
    let verdict = 'No known public blacklisting found in baseline threat intelligence feeds.';

    if (ip.startsWith('185.220.') || ip.startsWith('45.154.') || ip.startsWith('194.26.')) {
      score = 92;
      threatLevel = 'CRITICAL';
      verdict = 'High-frequency bulletproof hosting provider / Tor exit node network.';
    } else if (ip.startsWith('198.51.100.') || ip.startsWith('203.0.113.')) {
      score = 75;
      threatLevel = 'SUSPICIOUS';
      verdict = 'TEST-NET / Unsanctioned public routing simulation prefix.';
    }

    res.json({
      ip,
      abuseConfidenceScore: score,
      threatLevel,
      verdict,
      mode: 'heuristic',
      notice: apiKey ? undefined : 'Configure ABUSEIPDB_API_KEY in backend/.env for live queries.',
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/threat/url/:b64url
 * Base64-encoded URL parameter
 */
router.get('/url/:b64url', async (req, res, next) => {
  try {
    const { b64url } = req.params;
    let url = '';
    try {
      url = Buffer.from(b64url, 'base64').toString('utf-8');
    } catch {
      return res.status(400).json({ error: 'Invalid base64 URL parameter' });
    }

    const vtKey = process.env.VIRUSTOTAL_API_KEY;

    if (vtKey) {
      try {
        const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');
        const resp = await axios.get(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
          headers: { 'x-apikey': vtKey },
          timeout: 6000,
        });
        const stats = resp.data?.data?.attributes?.last_analysis_stats || {};
        return res.json({
          url,
          malicious: stats.malicious || 0,
          suspicious: stats.suspicious || 0,
          harmless: stats.harmless || 0,
          undetected: stats.undetected || 0,
          mode: 'virustotal-live',
        });
      } catch (vtErr) {
        console.warn(`[ThreatIntel] VirusTotal query failed: ${vtErr.message}`);
      }
    }

    // Heuristic inspection
    let risk = 'LOW';
    const suspiciousTlds = ['.ru', '.top', '.xyz', '.work', '.click', '.loan', '.gq', '.cf', '.tk', '.ml'];
    const isSuspiciousTld = suspiciousTlds.some((tld) => url.toLowerCase().includes(tld));
    const hasIpUrl = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i.test(url);
    const hasBrandSpoof = /paypal|secure-bank|wellsfargo|microsoft-login|appleid|chase-verify/i.test(url);

    if (hasBrandSpoof || (hasIpUrl && isSuspiciousTld)) {
      risk = 'MALICIOUS';
    } else if (hasIpUrl || isSuspiciousTld) {
      risk = 'SUSPICIOUS';
    }

    res.json({
      url,
      riskLevel: risk,
      hasIpHost: hasIpUrl,
      suspiciousTld: isSuspiciousTld,
      brandSpoofDetected: hasBrandSpoof,
      mode: 'heuristic',
      notice: vtKey ? undefined : 'Configure VIRUSTOTAL_API_KEY in backend/.env for live VirusTotal scans.',
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
