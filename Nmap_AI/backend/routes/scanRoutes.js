const express = require('express');
const { runScan } = require('../controllers/scanController');
const { rateLimiter } = require('../utils/rateLimiter');
const router = express.Router();

// Apply rate limiting to scan routes
router.use(rateLimiter);

router.post('/', runScan);

module.exports = router;
