const express = require('express');
const { enrich } = require('../controllers/intelController');
const { rateLimiter } = require('../utils/rateLimiter');

const router = express.Router();
router.use(rateLimiter);

// Look up known CVEs (NVD), exploited CVEs (CISA KEV), exploit chances (EPSS)
// and internet exposure (Shodan InternetDB) for hosts found by a scan.
router.post('/enrich', enrich);

module.exports = router;
