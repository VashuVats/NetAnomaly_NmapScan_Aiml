const { XMLParser } = require('fast-xml-parser');

// Elements that can appear once or many times. Always give them back as arrays.
const ARRAY_TAGS = new Set(['host', 'port', 'address', 'hostname', 'cpe', 'osmatch', 'extraports']);

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '',
  isArray: (name) => ARRAY_TAGS.has(name),
  // do not turn "1.18.0" or "6.6.1p1" into numbers
  parseAttributeValue: false,
  parseTagValue: false,
  processEntities: true,
});

/** Turn the old CPE 2.2 form (cpe:/a:vendor:product:version) into CPE 2.3 (used by NVD). */
function toCpe23(cpe) {
  if (!cpe || typeof cpe !== 'string') return null;
  if (cpe.startsWith('cpe:2.3:')) return cpe;
  if (!cpe.startsWith('cpe:/')) return null;
  const parts = cpe.slice(5).split(':');
  while (parts.length < 11) parts.push('*');
  return `cpe:2.3:${parts.slice(0, 11).map((p) => p || '*').join(':')}`;
}

/** True when the CPE names a specific version (so a CVE lookup makes sense). */
function cpeHasVersion(cpe23) {
  if (!cpe23) return false;
  const parts = cpe23.split(':');
  return parts.length > 5 && parts[5] && parts[5] !== '*' && parts[5] !== '-';
}

function text(value) {
  if (value == null) return '';
  if (typeof value === 'object') return value['#text'] || '';
  return String(value);
}

/**
 * Parse nmap XML output (-oX) into a small, UI-friendly structure.
 * @returns {{ hosts: Array, stats: Object }}
 */
function parseNmapXml(xml) {
  const doc = parser.parse(xml || '');
  const run = doc.nmaprun;
  if (!run) throw new Error('Not nmap XML output');

  const hosts = (run.host || []).map((h) => {
    const addresses = h.address || [];
    const ip = addresses.find((a) => a.addrtype === 'ipv4' || a.addrtype === 'ipv6');
    const mac = addresses.find((a) => a.addrtype === 'mac');
    const hostnames = [...new Set(((h.hostnames && h.hostnames.hostname) || []).map((n) => n.name))];
    const ports = ((h.ports && h.ports.port) || []).map((p) => {
      const s = p.service || {};
      const cpes = (s.cpe || []).map(text).filter(Boolean);
      return {
        port: Number(p.portid),
        protocol: p.protocol,
        state: (p.state && p.state.state) || 'unknown',
        service: s.name || '',
        product: s.product || '',
        version: s.version || '',
        extrainfo: s.extrainfo || '',
        tunnel: s.tunnel || '',
        cpes: cpes.map(toCpe23).filter(Boolean),
      };
    });
    const osMatches = (h.os && h.os.osmatch) || [];
    return {
      address: ip ? ip.addr : (addresses[0] && addresses[0].addr) || '',
      addressType: ip ? ip.addrtype : '',
      mac: mac ? mac.addr : null,
      vendor: mac ? mac.vendor || null : null,
      hostnames,
      status: (h.status && h.status.state) || 'unknown',
      os: osMatches.length ? { name: osMatches[0].name, accuracy: Number(osMatches[0].accuracy) } : null,
      ports,
      openPorts: ports.filter((p) => p.state === 'open').length,
    };
  });

  const finished = (run.runstats && run.runstats.finished) || {};
  const counts = (run.runstats && run.runstats.hosts) || {};
  return {
    hosts,
    stats: {
      nmapVersion: run.version || '',
      args: run.args || '',
      elapsedSeconds: Number(finished.elapsed || 0),
      hostsUp: Number(counts.up || 0),
      hostsDown: Number(counts.down || 0),
      summary: finished.summary || '',
    },
  };
}

module.exports = { parseNmapXml, toCpe23, cpeHasVersion };
