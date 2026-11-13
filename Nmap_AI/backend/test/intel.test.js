const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { createIntel, isPublicIp, pickCvss } = require('../services/intel');
const { parseNmapXml } = require('../utils/nmapXml');
const { formatIntelForPrompt } = require('../controllers/summaryController');
const { _cleanHosts } = require('../controllers/intelController');

// Responses shaped like the real APIs (trimmed)
const NVD = {
  resultsPerPage: 2, startIndex: 0, totalResults: 2,
  vulnerabilities: [
    { cve: { id: 'CVE-2021-41773', published: '2021-10-05T09:15:07.593',
      descriptions: [{ lang: 'en', value: 'Path traversal in Apache HTTP Server 2.4.49.' }],
      metrics: { cvssMetricV31: [{ source: 'nvd@nist.gov', type: 'Primary', cvssData: { version: '3.1', baseScore: 7.5, baseSeverity: 'HIGH', vectorString: 'CVSS:3.1/AV:N' } }] } } },
    { cve: { id: 'CVE-2021-42013', published: '2021-10-07T16:15:09.270',
      descriptions: [{ lang: 'en', value: 'Incomplete fix for CVE-2021-41773.' }],
      metrics: { cvssMetricV31: [{ source: 'nvd@nist.gov', type: 'Primary', cvssData: { version: '3.1', baseScore: 9.8, baseSeverity: 'CRITICAL' } }] } } },
  ],
};
const KEV = { title: 'CISA Catalog', vulnerabilities: [
  { cveID: 'CVE-2021-41773', vulnerabilityName: 'Apache path traversal', dateAdded: '2021-11-03', knownRansomwareCampaignUse: 'Known', requiredAction: 'Patch', dueDate: '2021-11-17' },
] };
const EPSS = { status: 'OK', data: [
  { cve: 'CVE-2021-41773', epss: '0.94', percentile: '0.99', date: '2026-11-12' },
  { cve: 'CVE-2021-42013', epss: '0.93', percentile: '0.99', date: '2026-11-12' },
] };
const IDB = { ip: '45.33.32.156', ports: [22, 80], vulns: ['CVE-2021-41773'], tags: [], hostnames: ['scanme.example'], cpes: [] };

function fakeFetch(calls) {
  return async (url, opts) => {
    calls.push({ url, opts });
    const u = new URL(url);
    let body = null; let status = 200;
    if (u.host === 'services.nvd.nist.gov') body = u.searchParams.get('virtualMatchString').includes('http_server') ? NVD : { vulnerabilities: [] };
    else if (u.host === 'www.cisa.gov') body = KEV;
    else if (u.host === 'api.first.org') body = EPSS;
    else if (u.host === 'internetdb.shodan.io') body = IDB;
    else status = 500;
    return { ok: status === 200, status, json: async () => body };
  };
}

const hosts = parseNmapXml(fs.readFileSync(path.join(__dirname, 'fixtures', 'nmap_sample.xml'), 'utf8')).hosts;

test('enrichHosts ranks exploited CVEs first and adds EPSS and Shodan data', async () => {
  const calls = [];
  const intel = createIntel({ fetchImpl: fakeFetch(calls), nvdApiKey: '', nvdIntervalMs: 0 });
  const r = await intel.enrichHosts(hosts);
  assert.strictEqual(r.enabled, true);
  const a = r.hosts.find((h) => h.address === '45.33.32.156');
  const http = a.ports.find((p) => p.port === 80);
  assert.strictEqual(http.total, 2);
  assert.strictEqual(http.vulns[0].id, 'CVE-2021-41773'); // in KEV, so first even with lower CVSS
  assert.strictEqual(http.vulns[0].kev, true);
  assert.strictEqual(http.vulns[0].ransomware, true);
  assert.strictEqual(http.vulns[0].epss, 0.94);
  assert.strictEqual(http.vulns[1].severity, 'CRITICAL');
  assert.deepStrictEqual(a.internetDb.ports, [22, 80]);
  assert.strictEqual(r.summary.kev, 1);
  assert.strictEqual(r.summary.critical, 1);
  // private host is never sent to Shodan
  assert.ok(!calls.some((c) => c.url.includes('192.168.1.10')));
  assert.strictEqual(r.hosts.find((h) => h.address === '192.168.1.10').internetDb, null);
  // the OS CPE (no version) is not looked up
  assert.ok(!calls.some((c) => c.url.includes('linux_kernel')));
});

test('results are cached', async () => {
  const calls = [];
  const intel = createIntel({ fetchImpl: fakeFetch(calls), nvdIntervalMs: 0 });
  await intel.enrichHosts(hosts);
  const first = calls.length;
  await intel.enrichHosts(hosts);
  assert.strictEqual(calls.length, first);
});

test('NVD API key is sent as a header and raises the product limit', async () => {
  const calls = [];
  const intel = createIntel({ fetchImpl: fakeFetch(calls), nvdApiKey: 'k123', nvdIntervalMs: 0 });
  await intel.enrichHosts(hosts);
  const nvd = calls.find((c) => c.url.includes('nvd.nist.gov'));
  assert.strictEqual(nvd.opts.headers.apiKey, 'k123');
});

test('without a key only 5 products are looked up, with a warning', async () => {
  const many = [{ address: '10.0.0.1', ports: Array.from({ length: 8 }, (_, i) => ({ port: 1000 + i, state: 'open', cpes: [`cpe:2.3:a:v:p${i}:1.0:*:*:*:*:*:*:*`] })) }];
  const calls = [];
  const intel = createIntel({ fetchImpl: fakeFetch(calls), nvdIntervalMs: 0 });
  const r = await intel.enrichHosts(many);
  assert.strictEqual(calls.filter((c) => c.url.includes('nvd.nist.gov')).length, 5);
  assert.match(r.warnings.join(' '), /NVD_API_KEY/);
});

test('a failing source becomes a warning, not an error', async () => {
  const intel = createIntel({ fetchImpl: async () => { throw new Error('offline'); }, nvdIntervalMs: 0 });
  const r = await intel.enrichHosts(hosts);
  assert.ok(r.warnings.length >= 2);
  assert.strictEqual(r.summary.cves, 0);
});

test('can be turned off', async () => {
  const intel = createIntel({ fetchImpl: fakeFetch([]), enabled: false });
  const r = await intel.enrichHosts(hosts);
  assert.strictEqual(r.enabled, false);
});

test('isPublicIp', () => {
  for (const ip of ['10.1.2.3', '192.168.0.1', '172.20.1.1', '127.0.0.1', '169.254.1.1', '100.64.0.1', '192.0.2.5', '::1', 'fe80::1', '2001:db8::1', 'not-an-ip']) {
    assert.strictEqual(isPublicIp(ip), false, ip);
  }
  for (const ip of ['8.8.8.8', '45.33.32.156', '172.32.0.1', '2606:4700::1111']) {
    assert.strictEqual(isPublicIp(ip), true, ip);
  }
});

test('pickCvss prefers newest CVSS version and handles v2 severity', () => {
  assert.strictEqual(pickCvss({ cvssMetricV2: [{ cvssData: { baseScore: 5 }, baseSeverity: 'MEDIUM' }] }).severity, 'MEDIUM');
  assert.strictEqual(pickCvss({ cvssMetricV2: [{ cvssData: { baseScore: 5 } }], cvssMetricV31: [{ type: 'Primary', cvssData: { baseScore: 8.1, baseSeverity: 'HIGH' } }] }).score, 8.1);
});

test('input cleaning drops bad CPEs', () => {
  const out = _cleanHosts([{ address: '1.2.3.4', ports: [{ port: '80', cpes: ['cpe:2.3:a:x:y:1:*:*:*:*:*:*:*', 'evil&param=1', 5] }] }]);
  assert.deepStrictEqual(out[0].ports[0].cpes, ['cpe:2.3:a:x:y:1:*:*:*:*:*:*:*']);
  assert.strictEqual(_cleanHosts('nope'), null);
});

test('AI prompt gets real CVE facts', async () => {
  const intel = createIntel({ fetchImpl: fakeFetch([]), nvdIntervalMs: 0 });
  const r = await intel.enrichHosts(hosts);
  const text = formatIntelForPrompt(r);
  assert.match(text, /CVE-2021-41773/);
  assert.match(text, /KNOWN EXPLOITED/);
  assert.strictEqual(formatIntelForPrompt(null), '');
});
