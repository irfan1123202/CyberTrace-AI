// CyberTrace AI — WHOIS Routes
// =============================================================================
// GET /api/whois/:domain — Domain WHOIS inspection via Linux CLI & RDAP fallback
// =============================================================================

const express = require('express');
const router = express.Router();
const { whoisLookup } = require('../services/linuxTools');

router.get('/:domain', async (req, res, next) => {
  try {
    const { domain } = req.params;
    if (!domain) {
      return res.status(400).json({ error: 'Domain parameter is required' });
    }
    const cleanDomain = domain.toLowerCase().trim().replace(/^https?:\/\//, '').split('/')[0];
    const whoisData = await whoisLookup(cleanDomain);
    res.json(whoisData);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
