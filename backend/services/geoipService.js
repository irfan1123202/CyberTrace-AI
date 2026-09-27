// CyberTrace AI — GeoIP Service
// =============================================================================
// Provides multi-tiered IP Geolocation with:
//   1. In-memory LRU cache
//   2. RFC1918 private IP detection
//   3. Primary provider: ip-api.com (detailed fields: proxy, hosting, ASN, ISP)
//   4. Secondary fallback: ipinfo.io
//   5. Offline fallback: geoip-lite (local GeoLite database, zero network needed)
// =============================================================================

const axios = require('axios');
const geoipLite = require('geoip-lite');

// In-memory cache: ip -> { data, expiresAt }
const cache = new Map();
const CACHE_TTL_MS = 1000 * 60 * 60; // 1 hour

/**
 * Check if an IP address is a private / loopback RFC1918 address
 */
function isPrivateIp(ip) {
  if (!ip || typeof ip !== 'string') return true;
  const cleanIp = ip.trim();
  if (cleanIp === '127.0.0.1' || cleanIp === '::1' || cleanIp === 'localhost') return true;
  if (/^10\./.test(cleanIp)) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(cleanIp)) return true;
  if (/^192\.168\./.test(cleanIp)) return true;
  if (/^169\.254\./.test(cleanIp)) return true;
  if (/^fc00:|^fe80:/i.test(cleanIp)) return true;
  return false;
}

/**
 * Normalizes geolocation output across providers
 */
function formatGeoResponse(raw, source = 'ip-api') {
  return {
    ip: raw.query || raw.ip,
    success: true,
    source,
    country: raw.country || 'Unknown',
    countryCode: raw.countryCode || raw.country_code || '',
    region: raw.region || '',
    regionName: raw.regionName || raw.region || '',
    city: raw.city || 'Unknown',
    lat: typeof raw.lat === 'number' ? raw.lat : parseFloat(raw.lat) || 0,
    lon: typeof raw.lon === 'number' ? raw.lon : parseFloat(raw.lon) || 0,
    timezone: raw.timezone || 'UTC',
    isp: raw.isp || raw.org || 'Unknown ISP',
    org: raw.org || raw.isp || 'Unknown Org',
    asn: raw.as || (raw.asn ? `AS${raw.asn}` : 'Unknown ASN'),
    asname: raw.asname || '',
    reverse: raw.reverse || '',
    isProxy: !!(raw.proxy || raw.hosting),
    isHosting: !!raw.hosting,
    live: source !== 'geoip-lite-offline',
  };
}

/**
 * Lookup Geolocation for a single IP address
 * @param {string} ip
 */
async function getIpGeo(ip) {
  if (!ip) throw new Error('IP address parameter is required');
  const cleanIp = ip.trim();

  // Check cache
  const cached = cache.get(cleanIp);
  if (cached && cached.expiresAt > Date.now()) {
    return { ...cached.data, cached: true };
  }

  // Handle RFC1918 Private / Localhost
  if (isPrivateIp(cleanIp)) {
    const privRes = {
      ip: cleanIp,
      success: true,
      source: 'rfc1918-private',
      country: 'Private Network',
      countryCode: 'LAN',
      region: 'Local',
      regionName: 'Internal Network',
      city: 'RFC1918 Local Subnet',
      lat: 0,
      lon: 0,
      timezone: 'UTC',
      isp: 'Private Address Space',
      org: 'Local Network / Gateway',
      asn: 'AS-PRIVATE',
      asname: 'Private Network',
      reverse: 'localhost',
      isProxy: false,
      isHosting: false,
      live: false,
    };
    cache.set(cleanIp, { data: privRes, expiresAt: Date.now() + CACHE_TTL_MS });
    return privRes;
  }

  // 1. Try ip-api.com
  try {
    const fields = process.env.GEOIP_API_FIELDS || 'status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query';
    const url = `${process.env.GEOIP_API_BASE || 'http://ip-api.com/json'}/${cleanIp}?fields=${fields}`;
    const resp = await axios.get(url, { timeout: 4000 });
    if (resp.data && resp.data.status === 'success') {
      const formatted = formatGeoResponse(resp.data, 'ip-api.com');
      cache.set(cleanIp, { data: formatted, expiresAt: Date.now() + CACHE_TTL_MS });
      return formatted;
    }
  } catch (err) {
    console.warn(`[GeoIP] ip-api.com lookup failed for ${cleanIp}: ${err.message}. Trying secondary...`);
  }

  // 2. Try ipinfo.io
  try {
    const token = process.env.IPINFO_TOKEN;
    const url = token ? `https://ipinfo.io/${cleanIp}?token=${token}` : `https://ipinfo.io/${cleanIp}/json`;
    const resp = await axios.get(url, { timeout: 4000 });
    if (resp.data && resp.data.ip) {
      const [latStr, lonStr] = (resp.data.loc || '0,0').split(',');
      const formatted = formatGeoResponse(
        {
          query: resp.data.ip,
          country: resp.data.country,
          countryCode: resp.data.country,
          regionName: resp.data.region,
          city: resp.data.city,
          lat: parseFloat(latStr) || 0,
          lon: parseFloat(lonStr) || 0,
          timezone: resp.data.timezone,
          isp: resp.data.org,
          org: resp.data.org,
          as: resp.data.org,
        },
        'ipinfo.io'
      );
      cache.set(cleanIp, { data: formatted, expiresAt: Date.now() + CACHE_TTL_MS });
      return formatted;
    }
  } catch (err) {
    console.warn(`[GeoIP] ipinfo.io lookup failed for ${cleanIp}: ${err.message}. Trying local offline...`);
  }

  // 3. Fallback to local geoip-lite (offline MaxMind)
  try {
    const geo = geoipLite.lookup(cleanIp);
    if (geo) {
      const formatted = formatGeoResponse(
        {
          query: cleanIp,
          country: geo.country,
          countryCode: geo.country,
          region: geo.region,
          regionName: geo.region,
          city: geo.city || 'Unknown',
          lat: geo.ll ? geo.ll[0] : 0,
          lon: geo.ll ? geo.ll[1] : 0,
          timezone: geo.timezone || 'UTC',
          isp: 'Resolved via GeoLite database',
          org: 'MaxMind GeoLite',
          as: 'Unknown ASN',
        },
        'geoip-lite-offline'
      );
      cache.set(cleanIp, { data: formatted, expiresAt: Date.now() + CACHE_TTL_MS });
      return formatted;
    }
  } catch (err) {
    console.error(`[GeoIP] geoip-lite lookup failed: ${err.message}`);
  }

  // Ultimate fallback if all failed
  return {
    ip: cleanIp,
    success: false,
    source: 'none',
    country: 'Unknown',
    countryCode: 'XX',
    region: 'Unknown',
    regionName: 'Unknown',
    city: 'Unknown',
    lat: 0,
    lon: 0,
    timezone: 'UTC',
    isp: 'Unknown ISP',
    org: 'Unknown Org',
    asn: 'Unknown',
    asname: '',
    reverse: '',
    isProxy: false,
    isHosting: false,
    live: false,
  };
}

/**
 * Batch lookup for multiple IPs
 * @param {string[]} ips
 */
async function batchGeolocate(ips) {
  if (!Array.isArray(ips) || ips.length === 0) return [];
  const uniqueIps = [...new Set(ips.filter(Boolean))].slice(0, 50);

  // Separate cached vs uncached
  const results = [];
  const toFetch = [];

  for (const ip of uniqueIps) {
    const cached = cache.get(ip);
    if (cached && cached.expiresAt > Date.now()) {
      results.push({ ...cached.data, cached: true });
    } else {
      toFetch.push(ip);
    }
  }

  if (toFetch.length === 0) {
    return results;
  }

  // Query remaining IPs in parallel (batch of 10)
  const chunkSize = 10;
  for (let i = 0; i < toFetch.length; i += chunkSize) {
    const chunk = toFetch.slice(i, i + chunkSize);
    const chunkPromises = chunk.map((ip) => getIpGeo(ip));
    const chunkResults = await Promise.allSettled(chunkPromises);
    chunkResults.forEach((res, idx) => {
      if (res.status === 'fulfilled') {
        results.push(res.value);
      } else {
        results.push({ ip: chunk[idx], success: false, country: 'Unknown' });
      }
    });
  }

  return results;
}

module.exports = {
  getIpGeo,
  batchGeolocate,
  isPrivateIp,
};
