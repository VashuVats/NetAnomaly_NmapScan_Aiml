const { createIntel } = require('../services/intel');

const intel = createIntel();
const MAX_HOSTS = 64;
const MAX_PORTS_PER_HOST = 1000;

function cleanHosts(hosts) {
  if (!Array.isArray(hosts)) return null;
  return hosts.slice(0, MAX_HOSTS).map((h) => ({
    address: typeof h.address === 'string' ? h.address.slice(0, 64) : '',
    ports: (Array.isArray(h.ports) ? h.ports : []).slice(0, MAX_PORTS_PER_HOST).map((p) => ({
      port: Number(p.port) || 0,
      protocol: typeof p.protocol === 'string' ? p.protocol : 'tcp',
      state: typeof p.state === 'string' ? p.state : '',
      // only well-formed CPE 2.3 strings are sent to NVD
      cpes: (Array.isArray(p.cpes) ? p.cpes : []).filter((c) => typeof c === 'string' && /^cpe:2\.3:[aho](:[^:\s]*){1,10}$/.test(c)).slice(0, 5),
    })),
  }));
}

/** POST /api/intel/enrich  { hosts: [...from /api/scan] } */
exports.enrich = async (req, res) => {
  const hosts = cleanHosts(req.body && req.body.hosts);
  if (!hosts) {
    return res.status(400).json({ error: 'Send the "hosts" list from a scan result.' });
  }
  try {
    const result = await intel.enrichHosts(hosts);
    return res.json({ success: true, ...result, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Threat intel lookup failed:', err);
    return res.status(502).json({ error: 'Threat intel lookup failed', details: err.message });
  }
};

exports._cleanHosts = cleanHosts;
