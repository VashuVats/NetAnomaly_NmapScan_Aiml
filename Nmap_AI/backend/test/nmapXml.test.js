const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { parseNmapXml, toCpe23, cpeHasVersion } = require('../utils/nmapXml');

const xml = fs.readFileSync(path.join(__dirname, 'fixtures', 'nmap_sample.xml'), 'utf8');

test('parses hosts, ports, versions and CPEs', () => {
  const { hosts, stats } = parseNmapXml(xml);
  assert.strictEqual(hosts.length, 2);
  const [a, b] = hosts;
  assert.strictEqual(a.address, '45.33.32.156');
  assert.deepStrictEqual(a.hostnames, ['scanme.example']);
  assert.strictEqual(a.openPorts, 3);
  const http = a.ports.find((p) => p.port === 80);
  assert.strictEqual(http.product, 'Apache httpd');
  assert.strictEqual(http.version, '2.4.49'); // must stay a string, not the number 2.4
  assert.deepStrictEqual(http.cpes, ['cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*']);
  assert.strictEqual(a.ports.find((p) => p.port === 31337).state, 'filtered');
  assert.strictEqual(b.mac, '00:11:22:33:44:55');
  assert.strictEqual(b.ports[0].tunnel, 'ssl');
  assert.strictEqual(stats.hostsUp, 2);
  assert.strictEqual(stats.elapsedSeconds, 11.5);
});

test('single host and single port still come back as arrays', () => {
  const one = '<nmaprun><host><status state="up"/><address addr="1.2.3.4" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host></nmaprun>';
  const { hosts } = parseNmapXml(one);
  assert.strictEqual(hosts.length, 1);
  assert.strictEqual(hosts[0].ports.length, 1);
  assert.strictEqual(hosts[0].ports[0].port, 22);
});

test('CPE conversion', () => {
  assert.strictEqual(toCpe23('cpe:/a:openbsd:openssh:6.6.1p1'), 'cpe:2.3:a:openbsd:openssh:6.6.1p1:*:*:*:*:*:*:*');
  assert.strictEqual(toCpe23('cpe:/o:linux:linux_kernel'), 'cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*');
  assert.ok(cpeHasVersion(toCpe23('cpe:/a:apache:http_server:2.4.49')));
  assert.ok(!cpeHasVersion(toCpe23('cpe:/o:linux:linux_kernel')));
});

test('rejects non-nmap XML', () => {
  assert.throws(() => parseNmapXml('<foo/>'), /Not nmap XML/);
});
