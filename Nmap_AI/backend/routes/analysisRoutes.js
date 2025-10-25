const express = require('express');
const router = express.Router();
const analysisController = require('../controllers/analysisController');

// ML Analysis Routes
router.post('/start-tcpdump', analysisController.startTcpdump);
router.post('/stop-tcpdump', analysisController.stopTcpdump);
router.post('/score', analysisController.scorePcap);
router.post('/predict', analysisController.predict);
router.get('/files', analysisController.listFiles);
router.get('/download/:filename', analysisController.downloadFile);

module.exports = router;
