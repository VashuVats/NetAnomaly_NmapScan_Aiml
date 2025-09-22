const { spawn } = require('child_process');
const { isValidTarget } = require('../utils/validator');

// Map scan type -> args
const scanOptions = {
  basic: ['-F', '-T4'],
  aggressive: ['-A', '-T4'],
  passive: ['-sS', '-T3', '-Pn'],
};

exports.runScan = async (req, res) => {
  const { target, scanType } = req.body;

  // Input validation
  if (!target || !isValidTarget(target)) {
    return res.status(400).json({ 
      error: 'Invalid or missing target. Provide a valid IP or hostname.',
      validFormats: ['IPv4 addresses', 'hostnames (example.com)']
    });
  }
  
  if (!scanType || !scanOptions[scanType]) {
    return res.status(400).json({ 
      error: 'Invalid scan type.',
      validTypes: Object.keys(scanOptions)
    });
  }

  // Security: Prevent scanning private/local networks in production
  if (process.env.NODE_ENV === 'production' && isPrivateNetwork(target)) {
    return res.status(403).json({ 
      error: 'Scanning private networks is not allowed in production' 
    });
  }

  try {
    console.log(`Starting ${scanType} scan for target: ${target}`);
    const output = await runNmap([...scanOptions[scanType], target]);
    
    console.log(`Scan completed for target: ${target}`);
    return res.json({ 
      scanOutput: output,
      target,
      scanType,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error(`Scan failed for target ${target}:`, err.message);
    return res.status(500).json({ 
      error: 'Scan failed', 
      details: err.message,
      target,
      scanType
    });
  }
};

// Helper: run nmap with spawn
function runNmap(args) {
  return new Promise((resolve, reject) => {
    const p = spawn('nmap', args);
    let out = '';
    let err = '';

    p.stdout.on('data', d => out += d.toString());
    p.stderr.on('data', d => err += d.toString());

    p.on('close', code => {
      if (code === 0 || out) resolve(out);
      else reject(new Error(err || 'Unknown error'));
    });

    // Timeout after 5 minutes
    setTimeout(() => {
      p.kill();
      reject(new Error('Scan timeout - operation took too long'));
    }, 300000);
  });
}

// Helper: Check if target is a private network
function isPrivateNetwork(target) {
  const privateRanges = [
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
    /^192\.168\./,
    /^127\./,
    /^169\.254\./,
    /^::1$/,
    /^fc00:/,
    /^fe80:/
  ];
  
  return privateRanges.some(range => range.test(target));
}
