exports.isValidTarget = (target) => {
  if (!target || typeof target !== 'string') {
    return false;
  }

  // Trim whitespace
  target = target.trim();
  
  // Check length limits
  if (target.length < 1 || target.length > 253) {
    return false;
  }

  // IPv4 validation
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?!$)|$)){4}$/;
  if (ipv4Regex.test(target)) {
    return true;
  }

  // IPv6 validation (basic)
  const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;
  if (ipv6Regex.test(target)) {
    return true;
  }

  // Hostname validation
  const hostnameRegex = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*(\.[A-Za-z]{2,6})?$/;
  if (hostnameRegex.test(target)) {
    return true;
  }

  // CIDR notation validation (e.g., 192.168.1.0/24)
  const cidrRegex = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?!$)|$)){4}\/(?:[0-9]|[1-2][0-9]|3[0-2])$/;
  if (cidrRegex.test(target)) {
    return true;
  }

  return false;
};

exports.sanitizeInput = (input) => {
  if (typeof input !== 'string') {
    return '';
  }
  
  return input
    .trim()
    .replace(/[<>\"'&]/g, '') // Remove potentially dangerous characters
    .substring(0, 1000); // Limit length
};

exports.validateScanType = (scanType) => {
  const validTypes = ['basic', 'aggressive', 'passive'];
  return validTypes.includes(scanType);
};
