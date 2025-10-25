const fetch = require('node-fetch');

const ML_API_URL = process.env.ML_API_URL || 'http://localhost:5000';

/**
 * Proxy requests to Python ML API
 */
async function proxyToMLAPI(endpoint, method = 'GET', body = null) {
  try {
    const url = `${ML_API_URL}${endpoint}`;
    const options = {
      method,
      headers: {
        'Content-Type': 'application/json',
      },
    };

    if (body) {
      options.body = JSON.stringify(body);
    }

    const response = await fetch(url, options);
    const data = await response.json();
    
    return {
      status: response.status,
      data
    };
  } catch (error) {
    console.error('ML API Proxy Error:', error);
    throw error;
  }
}

/**
 * Start tcpdump to capture network traffic
 */
exports.startTcpdump = async (req, res) => {
  try {
    const { duration, interface } = req.body;
    const result = await proxyToMLAPI('/api/analysis/start-tcpdump', 'POST', {
      duration: duration || 30,
      interface: interface || 'eth0'
    });
    
    res.status(result.status).json(result.data);
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
};

/**
 * Stop tcpdump
 */
exports.stopTcpdump = async (req, res) => {
  try {
    const result = await proxyToMLAPI('/api/analysis/stop-tcpdump', 'POST');
    res.status(result.status).json(result.data);
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
};

/**
 * Score pcap file using scorer.py
 */
exports.scorePcap = async (req, res) => {
  try {
    const result = await proxyToMLAPI('/api/analysis/score', 'POST', req.body);
    res.status(result.status).json(result.data);
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
};

/**
 * Run ML model predictions
 */
exports.predict = async (req, res) => {
  try {
    const result = await proxyToMLAPI('/api/analysis/predict', 'POST', req.body);
    res.status(result.status).json(result.data);
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
};

/**
 * List available result files
 */
exports.listFiles = async (req, res) => {
  try {
    const result = await proxyToMLAPI('/api/analysis/list-files', 'GET');
    res.status(result.status).json(result.data);
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
};

/**
 * Download a result file
 */
exports.downloadFile = async (req, res) => {
  try {
    const { filename } = req.params;
    const url = `${ML_API_URL}/api/analysis/download/${filename}`;
    const response = await fetch(url);
    
    if (!response.ok) {
      return res.status(response.status).json({ error: 'File not found' });
    }
    
    const buffer = await response.buffer();
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(buffer);
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
};
