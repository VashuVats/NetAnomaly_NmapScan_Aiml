/**
 * Threat intel lookups for scan results. All sources are free.
 *
 *  - NVD CVE API 2.0 : known vulnerabilities (CVEs) for a product version (CPE)
 *  - CISA KEV        : CVEs that are known to be exploited in the wild right now
 *  - FIRST EPSS      : chance that a CVE will be exploited in the next 30 days
 *  - Shodan InternetDB: what the internet already sees on a public IP (no key needed)
 */
const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_URL = 'https://api.first.org/data/v1/epss';
const INTERNETDB_URL = 'https://internetdb.shodan.io';

const DAY = 24 * 60 * 60 * 1000;
const REQUEST_TIMEOUT_MS = 15000;
const MAX_CVES_PER_PRODUCT = 10;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
function ipv4ToInt(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

const PRIVATE_V4 = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 3],
].map(([base, bits]) => [ipv4ToInt(base), bits]);

/** True only for public (internet-routable) addresses. Private hosts are never sent to Shodan. */
function isPublicIp(ip) {
  if (typeof ip !== 'string') return false;
  const n = ipv4ToInt(ip);
  if (n !== null) {
    return !PRIVATE_V4.some(([base, bits]) => {
      const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
      return ((n & mask) >>> 0) === ((base & mask) >>> 0);
    });
  }
  // IPv6: only global unicast 2000::/3, and not the documentation range 2001:db8::/32
  const lower = ip.toLowerCase();
  return /^[23][0-9a-f]{3}:/.test(lower) && !lower.startsWith('2001:db8:');
}

function pickCvss(metrics = {}) {
  const order = ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'];
  for (const key of order) {
    const list = metrics[key];
    if (Array.isArray(list) && list.length) {
      const m = list.find((x) => x.type === 'Primary') || list[0];
      const data = m.cvssData || {};
      return {
        version: data.version || key.replace('cvssMetricV', '').replace(/(\d)(\d)/, '$1.$2'),
        score: typeof data.baseScore === 'number' ? data.baseScore : null,
        severity: (data.baseSeverity || m.baseSeverity || '').toUpperCase() || null,
        vector: data.vectorString || null,
      };
    }
  }
  return { version: null, score: null, severity: null, vector: null };
}

function severityFromScore(score) {
  if (score == null) return 'UNKNOWN';
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'NONE';
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// Factory (so tests can pass a fake fetch)
// ---------------------------------------------------------------------------
function createIntel({
  fetchImpl = globalThis.fetch,
  nvdApiKey = process.env.NVD_API_KEY || '',
  enabled = (process.env.INTEL_ENABLED || 'true').toLowerCase() !== 'false',
  nvdIntervalMs, // NVD asks for at most 5 requests / 30 s without a key, 50 / 30 s with one
  log = console,
} = {}) {
  const interval = nvdIntervalMs ?? (nvdApiKey ? 700 : 6500);
  const cache = new Map(); // key -> { value, expires }
  let nvdChain = Promise.resolve();
  let lastNvdCall = 0;

  function cached(key, ttl, loader) {
    const hit = cache.get(key);
    if (hit && hit.expires > Date.now()) return hit.value;
    const value = loader().catch((err) => { cache.delete(key); throw err; });
    cache.set(key, { value, expires: Date.now() + ttl });
    return value;
  }

  async function getJson(url, headers = {}) {
    const res = await fetchImpl(url, { headers: { Accept: 'application/json', ...headers }, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`${new URL(url).host} answered ${res.status}`);
    return res.json();
  }

  function nvdThrottled(fn) {
    const run = nvdChain.then(async () => {
      const wait = lastNvdCall + interval - Date.now();
      if (wait > 0) await sleep(wait);
      lastNvdCall = Date.now();
      return fn();
    });
    nvdChain = run.catch(() => {});
    return run;
  }

  /** CVEs for one product version, e.g. cpe:2.3:a:apache:http_server:2.4.49:... */
  function cvesForCpe(cpe23) {
    // NVD's virtualMatchString wants the CPE without the trailing wildcards
    const match = cpe23.split(':').slice(0, 6).join(':');
    return cached(`nvd:${match}`, DAY, () => nvdThrottled(async () => {
      const url = `${NVD_URL}?virtualMatchString=${encodeURIComponent(match)}&resultsPerPage=200`;
      const data = await getJson(url, nvdApiKey ? { apiKey: nvdApiKey } : {});
      const items = (data && data.vulnerabilities) || [];
      return items.map(({ cve }) => {
        const cvss = pickCvss(cve.metrics);
        const desc = (cve.descriptions || []).find((d) => d.lang === 'en');
        return {
          id: cve.id,
          published: cve.published || null,
          description: desc ? desc.value : '',
          cvss: cvss.score,
          cvssVersion: cvss.version,
          severity: cvss.severity || severityFromScore(cvss.score),
          url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
        };
      });
    }));
  }

  /** CISA Known Exploited Vulnerabilities, as a Map of CVE id -> details. */
  function kevCatalog() {
    return cached('kev', DAY, async () => {
      const data = await getJson(KEV_URL);
      const map = new Map();
      for (const v of (data && data.vulnerabilities) || []) {
        map.set(v.cveID, {
          dateAdded: v.dateAdded,
          name: v.vulnerabilityName,
          ransomware: (v.knownRansomwareCampaignUse || '').toLowerCase() === 'known',
          requiredAction: v.requiredAction,
          dueDate: v.dueDate,
        });
      }
      return map;
    });
  }

  /** EPSS scores for many CVEs (batched, 100 per request). Returns Map id -> {epss, percentile}. */
  async function epssScores(cveIds) {
    const out = new Map();
    const unique = [...new Set(cveIds)];
    for (let i = 0; i < unique.length; i += 100) {
      const batch = unique.slice(i, i + 100);
      const key = `epss:${batch.join(',')}`;
      const data = await cached(key, DAY, () => getJson(`${EPSS_URL}?cve=${batch.join(',')}`));
      for (const row of (data && data.data) || []) {
        out.set(row.cve, { epss: Number(row.epss), percentile: Number(row.percentile) });
      }
    }
    return out;
  }

  /** What Shodan already knows about a public IP. Null when there is nothing. */
  function internetDb(ip) {
    if (!isPublicIp(ip)) return Promise.resolve(null);
    return cached(`idb:${ip}`, DAY, async () => {
      const data = await getJson(`${INTERNETDB_URL}/${encodeURIComponent(ip)}`);
      if (!data || data.detail) return null;
      return {
        ports: data.ports || [],
        vulns: data.vulns || [],
        tags: data.tags || [],
        hostnames: data.hostnames || [],
        cpes: data.cpes || [],
      };
    });
  }

  /**
   * Add CVE and exposure data to parsed nmap hosts.
   * @param {Array} hosts from parseNmapXml().hosts
   * @param {{maxProducts?: number}} options
   */
  async function enrichHosts(hosts, { maxProducts } = {}) {
    const warnings = [];
    if (!enabled) {
      return { enabled: false, hosts: [], summary: null, warnings: ['Threat intel lookups are turned off (INTEL_ENABLED=false).'] };
    }
    const limit = maxProducts ?? (nvdApiKey ? 20 : 5);

    // 1) unique product versions found on open ports
    const productCpes = [];
    for (const h of hosts) {
      for (const p of h.ports || []) {
        if (p.state !== 'open') continue;
        for (const cpe of p.cpes || []) {
          const parts = cpe.split(':');
          if (parts[2] === 'a' && parts[5] && parts[5] !== '*' && parts[5] !== '-' && !productCpes.includes(cpe)) {
            productCpes.push(cpe);
          }
        }
      }
    }
    if (productCpes.length > limit) {
      warnings.push(`Looked up ${limit} of ${productCpes.length} product versions to stay inside NVD rate limits. Add NVD_API_KEY to look up more.`);
    }
    const toLookUp = productCpes.slice(0, limit);

    // 2) CVEs per product, KEV and InternetDB in parallel (NVD calls queue themselves)
    const [cveLists, kev, idb] = await Promise.all([
      Promise.all(toLookUp.map((cpe) => cvesForCpe(cpe).catch((e) => { warnings.push(`NVD lookup failed for ${cpe}: ${e.message}`); return []; }))),
      kevCatalog().catch((e) => { warnings.push(`CISA KEV list unavailable: ${e.message}`); return new Map(); }),
      Promise.all(hosts.map((h) => internetDb(h.address).catch((e) => { warnings.push(`Shodan InternetDB failed for ${h.address}: ${e.message}`); return null; }))),
    ]);
    const cvesByCpe = new Map(toLookUp.map((cpe, i) => [cpe, cveLists[i]]));

    // 3) EPSS for every CVE we found (plus the ones Shodan reported)
    const allIds = [...cveLists.flat().map((c) => c.id), ...idb.flatMap((x) => (x ? x.vulns : []))];
    const epss = await epssScores(allIds).catch((e) => { warnings.push(`EPSS scores unavailable: ${e.message}`); return new Map(); });

    const decorate = (c) => {
      const k = kev.get(c.id);
      const e = epss.get(c.id);
      return { ...c, kev: Boolean(k), kevDetails: k || null, ransomware: k ? k.ransomware : false,
        epss: e ? e.epss : null, epssPercentile: e ? e.percentile : null };
    };
    const rank = (a, b) => (Number(b.kev) - Number(a.kev)) || ((b.epss ?? -1) - (a.epss ?? -1)) || ((b.cvss ?? -1) - (a.cvss ?? -1));

    const summary = { hosts: hosts.length, productsChecked: toLookUp.length, cves: 0, critical: 0, high: 0, kev: 0 };
    const enriched = hosts.map((h, hi) => {
      const ports = (h.ports || []).map((p) => {
        const seen = new Set();
        const vulns = [];
        for (const cpe of p.cpes || []) {
          for (const c of cvesByCpe.get(cpe) || []) {
            if (!seen.has(c.id)) { seen.add(c.id); vulns.push(decorate(c)); }
          }
        }
        vulns.sort(rank);
        return { port: p.port, protocol: p.protocol, total: vulns.length, vulns: vulns.slice(0, MAX_CVES_PER_PRODUCT),
          checked: (p.cpes || []).some((c) => cvesByCpe.has(c)) };
      });
      const all = ports.flatMap((p) => p.vulns);
      summary.cves += ports.reduce((s, p) => s + p.total, 0);
      summary.critical += all.filter((v) => v.severity === 'CRITICAL').length;
      summary.high += all.filter((v) => v.severity === 'HIGH').length;
      summary.kev += all.filter((v) => v.kev).length;
      const exposure = idb[hi];
      return {
        address: h.address,
        ports,
        topRisk: all.sort(rank)[0] || null,
        internetDb: exposure ? { ...exposure, vulns: exposure.vulns.map((id) => decorate({ id, url: `https://nvd.nist.gov/vuln/detail/${id}` })).sort(rank).slice(0, 15), totalVulns: exposure.vulns.length } : null,
        isPublic: isPublicIp(h.address),
      };
    });

    return { enabled: true, hosts: enriched, summary, warnings, sources: ['NVD', 'CISA KEV', 'FIRST EPSS', 'Shodan InternetDB'] };
  }

  return { enrichHosts, cvesForCpe, kevCatalog, epssScores, internetDb, _cache: cache, log };
}

module.exports = { createIntel, isPublicIp, pickCvss, severityFromScore };
