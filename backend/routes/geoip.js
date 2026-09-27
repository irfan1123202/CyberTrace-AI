// CyberTrace AI — GeoIP Routes
// =============================================================================
// GET  /api/geoip/:ip     — Single IP geolocation lookup
// POST /api/geoip/batch   — Multi-IP batch geolocation
// =============================================================================

const express = require('express');
const router = express.Router();
const { getIpGeo, batchGeolocate } = require('../services/geoipService');

/**
 * GET /api/geoip/:ip
 */
router.get('/:ip', async (req, res, next) => {
  try {
    const { ip } = req.params;
    if (!ip) {
      return res.status(400).json({ error: 'IP parameter is required' });
    }
    const data = await getIpGeo(ip);
    res.json(data);
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/geoip/batch
 * Body: { ips: string[] }
 */
router.post('/batch', async (req, res, next) => {
  try {
    const { ips } = req.body;
    if (!Array.isArray(ips)) {
      return res.status(400).json({ error: 'Body must contain an array of "ips"' });
    }
    const results = await batchGeolocate(ips);
    res.json({ count: results.length, data: results });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
