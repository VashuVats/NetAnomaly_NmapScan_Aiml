const rateLimitMap = new Map();

const RATE_LIMIT_WINDOW = 15 * 60 * 1000; 
const MAX_REQUESTS_PER_WINDOW = 10;

exports.rateLimiter = (req, res, next) => {
  const clientIP = req.ip || req.connection.remoteAddress || 'unknown';
  const now = Date.now();
  
  // Clean up old entries
  for (const [ip, data] of rateLimitMap.entries()) {
    if (now - data.firstRequest > RATE_LIMIT_WINDOW) {
      rateLimitMap.delete(ip);
    }
  }
  
  const clientData = rateLimitMap.get(clientIP);
  
  if (!clientData) {
    // First request from this IP
    rateLimitMap.set(clientIP, {
      firstRequest: now,
      requestCount: 1
    });
    return next();
  }
  
  if (now - clientData.firstRequest > RATE_LIMIT_WINDOW) {
    // Reset window
    rateLimitMap.set(clientIP, {
      firstRequest: now,
      requestCount: 1
    });
    return next();
  }
  
  if (clientData.requestCount >= MAX_REQUESTS_PER_WINDOW) {
    return res.status(429).json({
      error: 'Rate limit exceeded',
      message: `Too many requests. Limit: ${MAX_REQUESTS_PER_WINDOW} requests per ${RATE_LIMIT_WINDOW / 60000} minutes`,
      retryAfter: Math.ceil((RATE_LIMIT_WINDOW - (now - clientData.firstRequest)) / 1000)
    });
  }
  
  // Increment request count
  clientData.requestCount++;
  next();
};

// Cleanup function to prevent memory leaks
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of rateLimitMap.entries()) {
    if (now - data.firstRequest > RATE_LIMIT_WINDOW) {
      rateLimitMap.delete(ip);
    }
  }
}, 5 * 60 * 1000); // Clean up every 5 minutes
