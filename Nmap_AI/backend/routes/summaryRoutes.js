const express = require('express');
const { getSummary } = require('../controllers/summaryController');
const { rateLimiter } = require('../utils/rateLimiter');
const router = express.Router();

// Apply rate limiting to AI routes
router.use(rateLimiter);

// Generate AI-powered security analysis from Nmap scan output
router.post('/', getSummary);

module.exports = router;
