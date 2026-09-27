// CyberTrace AI — DNS & Protocol Analysis Routes
// =============================================================================
// GET /api/dns/:domain       — Complete DNS inspection (A, MX, TXT, SPF, DMARC)
// GET /api/dns/reverse/:ip   — Reverse DNS (PTR) using Linux `host` / `dig`
// GET /api/dns/spf/:domain   — Specific SPF record extraction
// GET /api/dns/dmarc/:domain — Specific DMARC record and policy analysis
// =============================================================================

const express = require('express');
const router = express.Router();
const {
  dig,
  lookupSpf,
  lookupDmarc,
  lookupMx,
  reverseDns,
} = require('../services/linuxTools');

/**
 * GET /api/dns/reverse/:ip
 */
router.get('/reverse/:ip', async (req, res, next) => {
  try {
    const { ip } = req.params;
    const result = await reverseDns(ip);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/dns/spf/:domain
 */
router.get('/spf/:domain', async (req, res, next) => {
  try {
    const { domain } = req.params;
    const result = await lookupSpf(domain);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/dns/dmarc/:domain
 */
router.get('/dmarc/:domain', async (req, res, next) => {
  try {
    const { domain } = req.params;
    const result = await lookupDmarc(domain);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/dns/:domain
 * Full DNS report
 */
router.get('/:domain', async (req, res, next) => {
  try {
    const { domain } = req.params;
    if (!domain) {
      return res.status(400).json({ error: 'Domain parameter is required' });
    }

    // Run parallel DNS queries
    const [aRecords, mxRecords, txtRecords, spfData, dmarcData] = await Promise.all([
      dig(domain, 'A'),
      lookupMx(domain),
      dig(domain, 'TXT'),
      lookupSpf(domain),
      lookupDmarc(domain),
    ]);

    res.json({
      domain,
      timestamp: new Date().toISOString(),
      aRecords: aRecords.records,
      mxRecords: mxRecords.mxRecords,
      txtRecords: txtRecords.records,
      spf: spfData,
      dmarc: dmarcData,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
