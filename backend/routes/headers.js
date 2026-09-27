// CyberTrace AI — Email Headers Forensic Analysis Routes
// =============================================================================
// POST /api/headers/analyze
// Parses Received: chains, resolves reverse DNS (PTR via Linux host),
// performs multi-hop IP geolocation, queries SPF & DMARC via Linux dig,
// and resolves domain age via WHOIS.
// =============================================================================

const express = require('express');
const router = express.Router();
const { reverseDns, lookupSpf, lookupDmarc, whoisLookup, dig } = require('../services/linuxTools');
const { getIpGeo, batchGeolocate, isPrivateIp } = require('../services/geoipService');

/**
 * Extract IP from a Received header string
 */
function extractIpFromReceived(header) {
  // Look for [x.x.x.x] or (x.x.x.x) or standalone IP
  const bracketMatch = header.match(/\[(\d{1,3}(?:\.\d{1,3}){3})\]/);
  if (bracketMatch) return bracketMatch[1];

  const parenMatch = header.match(/\((\d{1,3}(?:\.\d{1,3}){3})\)/);
  if (parenMatch) return parenMatch[1];

  const genericMatch = header.match(/from\s+[^(\n]+\(\s*[^)]*?(\d{1,3}(?:\.\d{1,3}){3})\s*\)/i);
  if (genericMatch) return genericMatch[1];

  const anyIp = header.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
  return anyIp ? anyIp[1] : null;
}

/**
 * Extract sender domain from From or Return-Path
 */
function extractDomain(headerValue) {
  if (!headerValue) return null;
  const match = headerValue.match(/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  return match ? match[1].toLowerCase() : null;
}

/**
 * POST /api/headers/analyze
 * Body: { rawHeaders: string, senderDomain?: string }
 */
router.post('/analyze', async (req, res, next) => {
  try {
    const { rawHeaders, senderDomain: explicitDomain } = req.body;
    if (!rawHeaders || typeof rawHeaders !== 'string') {
      return res.status(400).json({ error: 'Body must contain "rawHeaders" string' });
    }

    // Unfold multi-line headers (RFC 5322)
    const unfolded = rawHeaders.replace(/\r?\n[ \t]+/g, ' ');
    const lines = unfolded.split(/\r?\n/);

    // Extract Received headers (in order of appearance: top = destination MX, bottom = origin)
    const receivedHeaders = [];
    let fromHeader = '';
    let returnPath = '';
    let replyTo = '';
    let subject = '';
    let messageId = '';
    let authResults = '';

    for (const line of lines) {
      if (/^Received:\s*/i.test(line)) {
        receivedHeaders.push(line.replace(/^Received:\s*/i, '').trim());
      } else if (/^From:\s*/i.test(line)) {
        fromHeader = line.replace(/^From:\s*/i, '').trim();
      } else if (/^Return-Path:\s*/i.test(line)) {
        returnPath = line.replace(/^Return-Path:\s*/i, '').trim();
      } else if (/^Reply-To:\s*/i.test(line)) {
        replyTo = line.replace(/^Reply-To:\s*/i, '').trim();
      } else if (/^Subject:\s*/i.test(line)) {
        subject = line.replace(/^Subject:\s*/i, '').trim();
      } else if (/^Message-ID:\s*/i.test(line)) {
        messageId = line.replace(/^Message-ID:\s*/i, '').trim();
      } else if (/^Authentication-Results:\s*/i.test(line)) {
        authResults = line.replace(/^Authentication-Results:\s*/i, '').trim();
      }
    }

    const domain = explicitDomain || extractDomain(returnPath) || extractDomain(fromHeader);

    // Extract IPs from received headers
    const rawHops = receivedHeaders.map((hdr, idx) => {
      const ip = extractIpFromReceived(hdr);
      // Parse by / from tokens
      const fromMatch = hdr.match(/from\s+([^\s;]+)/i);
      const byMatch = hdr.match(/by\s+([^\s;]+)/i);
      const withMatch = hdr.match(/with\s+([^\s;]+)/i);
      const dateMatch = hdr.match(/;\s*(.+)$/);

      return {
        hopIndex: idx + 1,
        raw: hdr,
        ip: ip || 'unknown',
        from: fromMatch ? fromMatch[1] : 'unknown',
        by: byMatch ? byMatch[1] : 'unknown',
        withProto: withMatch ? withMatch[1] : 'ESMTP',
        timestamp: dateMatch ? dateMatch[1].trim() : null,
      };
    });

    const validIps = rawHops.map((h) => h.ip).filter((ip) => ip && ip !== 'unknown');

    // Run parallel forensic resolution:
    // 1. Batch IP Geolocation
    // 2. Reverse DNS for each hop IP
    // 3. SPF / DMARC / WHOIS for sender domain (if found)
    const [geoResults, ptrResults, domainDns, domainWhois] = await Promise.all([
      batchGeolocate(validIps),
      Promise.all(validIps.map((ip) => reverseDns(ip))),
      domain
        ? Promise.all([lookupSpf(domain), lookupDmarc(domain)])
        : Promise.resolve([null, null]),
      domain ? whoisLookup(domain) : Promise.resolve(null),
    ]);

    const geoMap = new Map();
    geoResults.forEach((g) => {
      if (g && g.ip) geoMap.set(g.ip, g);
    });

    const ptrMap = new Map();
    ptrResults.forEach((p) => {
      if (p && p.ip) ptrMap.set(p.ip, p);
    });

    // Merge hop data
    const enrichedHops = rawHops.map((hop, index) => {
      const isTarget = index === 0;
      const isOrigin = index === rawHops.length - 1;
      const geo = geoMap.get(hop.ip) || null;
      const ptr = ptrMap.get(hop.ip) || null;

      let trust = 'safe';
      if (isOrigin) {
        trust = geo?.isHosting || geo?.isProxy ? 'suspicious' : 'safe';
      }

      return {
        ...hop,
        isTarget,
        isOrigin,
        trust,
        reverseDns: ptr?.hostname || null,
        hasPtr: !!ptr?.hasPtr,
        geo: geo
          ? {
              country: geo.country,
              countryCode: geo.countryCode,
              city: geo.city,
              lat: geo.lat,
              lon: geo.lon,
              isp: geo.isp,
              org: geo.org,
              asn: geo.asn,
              isProxy: geo.isProxy,
              isHosting: geo.isHosting,
            }
          : null,
      };
    });

    // Attributed threat origin (last hop)
    const originHop = enrichedHops[enrichedHops.length - 1] || null;

    res.json({
      success: true,
      timestamp: new Date().toISOString(),
      metadata: {
        from: fromHeader,
        returnPath,
        replyTo,
        subject,
        messageId,
        authResults,
        senderDomain: domain,
      },
      hopCount: enrichedHops.length,
      hops: enrichedHops,
      origin: originHop,
      dnsSecurity: {
        spf: domainDns[0],
        dmarc: domainDns[1],
      },
      whois: domainWhois,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
