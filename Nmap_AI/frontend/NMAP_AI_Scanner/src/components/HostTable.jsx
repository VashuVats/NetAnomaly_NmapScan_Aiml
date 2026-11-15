import React from 'react';
import { Badge, Mono } from './ui';
import { severityTone } from '../utils/severity';

const pct = (v) => (v == null ? '-' : `${(v * 100).toFixed(v < 0.1 ? 1 : 0)}%`);

function VulnList({ vulns, total }) {
  return (
    <ul className="mt-2 space-y-2">
      {vulns.map((v) => (
        <li key={v.id} className="text-sm">
          <div className="flex flex-wrap items-center gap-1.5">
            <a href={v.url} target="_blank" rel="noreferrer" className="font-mono text-[0.85em] underline decoration-line underline-offset-2 hover:decoration-ink">{v.id}</a>
            {v.severity && <Badge tone={severityTone(v.severity)}>{v.cvss != null ? `${v.cvss.toFixed(1)} ` : ''}{v.severity.toLowerCase()}</Badge>}
            {v.kev && <Badge tone="critical" title="Listed in CISA's Known Exploited Vulnerabilities catalog">exploited in the wild</Badge>}
            {v.ransomware && <Badge tone="critical">used by ransomware</Badge>}
            {v.epss != null && <span className="text-xs text-muted" title="EPSS: chance of exploitation in the next 30 days">{pct(v.epss)} chance of attack in 30 days</span>}
          </div>
          {v.description && <p className="mt-0.5 line-clamp-2 text-muted">{v.description}</p>}
        </li>
      ))}
      {total > vulns.length && <li className="text-xs text-muted">and {total - vulns.length} more</li>}
    </ul>
  );
}

function RiskCell({ intelPort, isEnriching, hasVersion }) {
  if (!intelPort) {
    if (isEnriching && hasVersion) return <span className="text-xs text-muted">checking</span>;
    return <span className="text-xs text-muted">{hasVersion ? '-' : 'no version found'}</span>;
  }
  if (!intelPort.total) return <span className="text-xs text-safe">{intelPort.checked ? 'no known CVEs' : '-'}</span>;
  const top = intelPort.vulns[0];
  return (
    <details>
      <summary className="cursor-pointer list-inside">
        <span className="inline-flex flex-wrap items-center gap-1.5">
          <Badge tone={top.kev ? 'critical' : severityTone(top.severity)}>
            {intelPort.total} CVE{intelPort.total === 1 ? '' : 's'}
          </Badge>
          {intelPort.vulns.some((v) => v.kev) && <Badge tone="critical">exploited</Badge>}
        </span>
      </summary>
      <VulnList vulns={intelPort.vulns} total={intelPort.total} />
    </details>
  );
}

export default function HostTable({ hosts, intel, isEnriching }) {
  if (!hosts.length) return null;
  const intelByHost = new Map((intel?.hosts || []).map((h) => [h.address, h]));

  return (
    <div className="space-y-4">
      {hosts.map((host) => {
        const hi = intelByHost.get(host.address);
        const ports = [...host.ports].sort((a, b) => (a.state === 'open' ? 0 : 1) - (b.state === 'open' ? 0 : 1) || a.port - b.port);
        return (
          <section key={host.address} className="rounded-lg border border-line bg-surface" aria-label={`Host ${host.address}`}>
            <header className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-b border-line px-4 py-3">
              <h3 className="font-mono text-base font-medium">{host.address}</h3>
              {host.hostnames.length > 0 && <span className="text-sm text-muted">{host.hostnames.join(', ')}</span>}
              <span className="text-sm text-muted">{host.openPorts} open port{host.openPorts === 1 ? '' : 's'}</span>
              {host.os && <span className="text-sm text-muted">{host.os.name}</span>}
              {host.vendor && <span className="text-sm text-muted">{host.vendor}</span>}
            </header>
            {hi?.internetDb && (
              <p className="border-b border-line px-4 py-2 text-sm">
                <span className="text-muted">Shodan already sees ports </span>
                <Mono>{hi.internetDb.ports.join(', ') || 'none'}</Mono>
                {hi.internetDb.totalVulns > 0 && <span className="text-muted"> and lists {hi.internetDb.totalVulns} CVE{hi.internetDb.totalVulns === 1 ? '' : 's'} for this IP</span>}
              </p>
            )}
            {ports.length === 0 ? (
              <p className="px-4 py-3 text-sm text-muted">No open ports found on this host.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="text-xs text-muted">
                    <tr className="border-b border-line">
                      <th className="px-4 py-2 font-medium">Port</th>
                      <th className="px-4 py-2 font-medium">State</th>
                      <th className="px-4 py-2 font-medium">Service</th>
                      <th className="px-4 py-2 font-medium">Software</th>
                      <th className="px-4 py-2 font-medium">Known vulnerabilities</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ports.map((p) => {
                      const ip = hi?.ports.find((x) => x.port === p.port && x.protocol === p.protocol);
                      return (
                        <tr key={`${p.protocol}/${p.port}`} className={`border-b border-line last:border-0 align-top ${p.state !== 'open' ? 'text-muted' : ''}`}>
                          <td className="px-4 py-2"><Mono>{p.port}/{p.protocol}</Mono></td>
                          <td className="px-4 py-2">{p.state === 'open' ? <Badge tone="info">open</Badge> : <span className="text-xs">{p.state}</span>}</td>
                          <td className="px-4 py-2">{p.service || '-'}{p.tunnel ? ` (${p.tunnel})` : ''}</td>
                          <td className="px-4 py-2">{[p.product, p.version].filter(Boolean).join(' ') || '-'}</td>
                          <td className="px-4 py-2 min-w-48">
                            {p.state === 'open' ? <RiskCell intelPort={ip} isEnriching={isEnriching} hasVersion={p.cpes.some((c) => c.split(':')[5] && c.split(':')[5] !== '*')} /> : null}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        );
      })}
    </div>
  );
}
