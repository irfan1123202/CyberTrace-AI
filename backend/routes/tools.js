// CyberTrace AI — Linux Tools Direct Execution Routes
// =============================================================================
// Exposes Linux network forensic CLI tools directly to the frontend console:
//   - dig (DNS A/MX/TXT/SPF/DMARC)
//   - whois (Domain registration intelligence)
//   - host (Reverse DNS PTR)
//   - traceroute (Route hop latency & IP path)
//   - ping (Network RTT & reachability)
// =============================================================================

const express = require('express');
const router = express.Router();
const os = require('os');
const {
  dig,
  lookupSpf,
  lookupDmarc,
  lookupMx,
  reverseDns,
  whoisLookup,
  traceroute,
  ping,
  isWslAvailable,
} = require('../services/linuxTools');

/**
 * GET /api/tools/capabilities
 * Reports which Linux / WSL tools are active
 */
router.get('/capabilities', async (_req, res, next) => {
  try {
    const wsl = await isWslAvailable();
    res.json({
      success: true,
      platform: os.platform(),
      arch: os.arch(),
      wslAvailable: wsl,
      mode: os.platform() === 'win32' && wsl ? 'WSL (Linux Subsystem)' : os.platform() === 'win32' ? 'Windows Native PowerShell Fallback' : 'Native Linux CLI',
      tools: [
        { name: 'dig', description: 'DNS query tool for A, MX, TXT, SPF, DMARC records' },
        { name: 'whois', description: 'Domain registry & RDAP intelligence lookup' },
        { name: 'host', description: 'DNS & Reverse PTR record resolver' },
        { name: 'traceroute', description: 'Hop-by-hop packet route tracing' },
        { name: 'ping', description: 'ICMP echo request latency measurement' },
      ],
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/tools/execute
 * Body: { tool: string, target: string, type?: string }
 */
router.post('/execute', async (req, res, next) => {
  try {
    const { tool, target, type = 'A' } = req.body;

    if (!tool || !target) {
      return res.status(400).json({ error: 'Both "tool" and "target" are required.' });
    }

    // Sanitize target to prevent command injection
    const cleanTarget = target.trim().replace(/[;&|`$><!\\'"\r\n\s]/g, '');
    if (!cleanTarget) {
      return res.status(400).json({ error: 'Invalid target character set.' });
    }

    let result = null;
    const startMs = Date.now();

    switch (tool.toLowerCase()) {
      case 'dig': {
        const cleanType = (type || 'A').toUpperCase();
        if (cleanType === 'SPF') {
          result = await lookupSpf(cleanTarget);
        } else if (cleanType === 'DMARC') {
          result = await lookupDmarc(cleanTarget);
        } else if (cleanType === 'MX') {
          result = await lookupMx(cleanTarget);
        } else {
          result = await dig(cleanTarget, cleanType);
        }
        break;
      }
      case 'whois': {
        result = await whoisLookup(cleanTarget);
        break;
      }
      case 'host':
      case 'ptr': {
        result = await reverseDns(cleanTarget);
        break;
      }
      case 'traceroute':
      case 'tracert': {
        result = await traceroute(cleanTarget, 10);
        break;
      }
      case 'ping': {
        result = await ping(cleanTarget);
        break;
      }
      default:
        return res.status(400).json({
          error: `Unsupported tool: "${tool}". Supported tools: dig, whois, host, traceroute, ping.`,
        });
    }

    const elapsedMs = Date.now() - startMs;

    res.json({
      success: true,
      tool,
      target: cleanTarget,
      elapsedMs,
      timestamp: new Date().toISOString(),
      result,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
