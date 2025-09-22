const express = require('express');
const { generateReport } = require('../controllers/reportController');
const { rateLimiter } = require('../utils/rateLimiter');
const router = express.Router();

// Apply rate limiting to report routes
router.use(rateLimiter);

router.post('/', generateReport);

module.exports = router;
