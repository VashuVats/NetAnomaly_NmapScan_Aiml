// Badge colour for a CVSS severity word
export const severityTone = (sev) => ({ CRITICAL: 'critical', HIGH: 'warning', MEDIUM: 'info', LOW: 'neutral' }[sev] || 'neutral');
