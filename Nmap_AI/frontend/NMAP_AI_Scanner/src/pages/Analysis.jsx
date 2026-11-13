import React, { useEffect, useRef, useState } from 'react';
import { Badge, Button, Mono, Notice, Panel, Spinner } from '../components/ui';
import { apiDownloadResult, apiMlHealth, apiPredict, apiRunZeek, apiStartCapture, apiStopCapture } from '../utils/api';

const LABEL_TONE = { DoS: 'critical', Probe: 'warning', R2L: 'critical', U2R: 'critical', Unusual: 'unusual' };
const LABEL_HELP = {
  DoS: 'Denial of service: floods meant to knock a service over',
  Probe: 'Scanning: someone mapping hosts and ports',
  R2L: 'Remote access attempts, such as password guessing',
  U2R: 'Attempts to gain admin rights',
  Unusual: 'Not a known attack type, but very different from normal traffic',
};
const BAR = { critical: 'bg-critical', warning: 'bg-warning', unusual: 'bg-unusual', info: 'bg-info' };
const pct = (v) => (v == null ? '-' : `${(v * 100).toFixed(1)}%`);
const fileName = (p) => (p ? String(p).split(/[\\/]/).pop() : '');

function ModelNote({ health }) {
  if (!health) return null;
  if (!health.reachable) return <Notice tone="warning">{health.error}</Notice>;
  if (!health.model_loaded) return <Notice tone="warning">The ML API is running but has no model. {health.model_error}</Notice>;
  const m = health.model?.test_metrics;
  return (
    <p className="text-sm text-muted">
      Model: LightGBM classifier plus an unusual-traffic detector, trained on {health.model?.trained_on === 'uwf' ? 'UWF-ZeekData22' : 'NSL-KDD'}.
      {m && <> On a test set it had never seen, it caught {pct(m.attack_detection_rate)} of attacks with {pct(m.false_positive_rate)} false alarms ({pct(m.accuracy)} accuracy).</>}
      {' '}Treat alerts as leads to check, not proof.
    </p>
  );
}

function Breakdown({ breakdown, unusual, total }) {
  const rows = [...Object.entries(breakdown || {}), ...(unusual ? [['Unusual', unusual]] : [])].sort((a, b) => b[1] - a[1]);
  if (!rows.length) return null;
  return (
    <div className="space-y-2">
      {rows.map(([label, count]) => (
        <div key={label} className="grid grid-cols-[6rem_1fr_4rem] items-center gap-3 text-sm" title={LABEL_HELP[label]}>
          <span>{label}</span>
          <span className="h-2 rounded bg-surface-2" aria-hidden="true">
            <span className={`block h-2 rounded ${BAR[LABEL_TONE[label] || 'info']}`} style={{ width: `${Math.max(2, (count / total) * 100)}%` }} />
          </span>
          <span className="text-right tabular-nums text-muted">{count.toLocaleString()}</span>
        </div>
      ))}
    </div>
  );
}

function IncidentTable({ incidents }) {
  if (!incidents?.length) return null;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="text-xs text-muted">
          <tr className="border-b border-line">
            <th className="px-3 py-2 font-medium">Type</th>
            <th className="px-3 py-2 font-medium">Target</th>
            <th className="px-3 py-2 font-medium">From</th>
            <th className="px-3 py-2 font-medium">Connections</th>
            <th className="px-3 py-2 font-medium">Why it was flagged</th>
          </tr>
        </thead>
        <tbody>
          {incidents.map((inc) => (
            <tr key={`${inc.label}-${inc.dst_ip}`} className="border-b border-line align-top last:border-0 [&>td:not(:last-child)]:whitespace-nowrap">
              <td className="px-3 py-2">
                <Badge tone={LABEL_TONE[inc.label] || 'info'} title={LABEL_HELP[inc.label]}>{inc.label}</Badge>
                {inc.kind === 'known_attack' && <div className="mt-1 text-xs text-muted">{pct(inc.max_confidence)} sure</div>}
              </td>
              <td className="px-3 py-2"><Mono>{inc.dst_ip}</Mono>{inc.ports > 1 && <div className="text-xs text-muted">{inc.ports} ports</div>}</td>
              <td className="px-3 py-2">
                {inc.sources === 1 ? <Mono>{inc.top_sources[0]}</Mono> : <span>{inc.sources} sources</span>}
              </td>
              <td className="px-3 py-2 tabular-nums">
                {inc.connections.toLocaleString()}
                {inc.last_ts > inc.first_ts && <div className="text-xs text-muted">over {(inc.last_ts - inc.first_ts).toFixed(1)}s</div>}
              </td>
              <td className="min-w-[16rem] px-3 py-2">
                <ul className="space-y-0.5">
                  {inc.reasons.map((r) => (
                    <li key={r.feature}>{r.description}: <strong className="font-medium">{r.value}</strong>{r.typical != null && <span className="text-muted"> (normal: {r.typical})</span>}</li>
                  ))}
                </ul>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function verdict(r) {
  if (!r.total_records) return { tone: 'neutral', text: 'No connections were captured. Try a longer capture or another interface.' };
  const known = r.attacks || 0;
  const unusual = r.anomalies_not_known_attack || 0;
  const knownIncidents = (r.incidents || []).filter((i) => i.kind === 'known_attack').length;
  if (r.high_confidence_alerts > 0) return { tone: 'critical', text: `${knownIncidents} likely attack${knownIncidents === 1 ? '' : 's'} found in ${r.total_records.toLocaleString()} connections.` };
  if (known) return { tone: 'warning', text: `${known.toLocaleString()} connection${known === 1 ? ' looks' : 's look'} like an attack, but the model is not very sure.` };
  if (unusual) return { tone: 'warning', text: `No known attacks, but ${unusual.toLocaleString()} connection${unusual === 1 ? ' is' : 's are'} unusual.` };
  return { tone: 'safe', text: `All ${r.total_records.toLocaleString()} connections look normal.` };
}
const VERDICT_STYLE = { critical: 'border-critical text-critical', warning: 'border-warning text-warning', safe: 'border-safe text-safe', neutral: 'border-line text-ink' };

export default function Analysis() {
  const [duration, setDuration] = useState(30);
  const [networkInterface, setNetworkInterface] = useState('eth0');
  const [health, setHealth] = useState(null);
  const [capture, setCapture] = useState(null); // { file, endsAt }
  const [remaining, setRemaining] = useState(0);
  const [phase, setPhase] = useState('idle'); // idle | capturing | zeek | scoring
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const timer = useRef(null);

  useEffect(() => {
    apiMlHealth().then(setHealth).catch((e) => setHealth({ reachable: false, error: e.message }));
    return () => clearInterval(timer.current);
  }, []);

  const startCapture = async () => {
    setError(null);
    setResults(null);
    try {
      const data = await apiStartCapture({ duration, networkInterface });
      if (!data.success) throw new Error(data.error || 'Could not start the capture');
      const endsAt = Date.now() + duration * 1000;
      setCapture({ file: fileName(data.pcap_file), endsAt });
      setPhase('capturing');
      setRemaining(duration);
      clearInterval(timer.current);
      timer.current = setInterval(() => {
        const left = Math.max(0, Math.round((endsAt - Date.now()) / 1000));
        setRemaining(left);
        if (left === 0) { clearInterval(timer.current); setPhase('idle'); }
      }, 500);
    } catch (e) {
      setError(e.message);
      setPhase('idle');
    }
  };

  const stopCapture = async () => {
    clearInterval(timer.current);
    try { await apiStopCapture(); } catch (e) { setError(e.message); }
    setPhase('idle');
  };

  const analyse = async () => {
    setError(null);
    try {
      setPhase('zeek');
      const z = await apiRunZeek({ pcapFile: capture?.file });
      if (!z.success) throw new Error(z.error || 'Zeek could not read the capture');
      setPhase('scoring');
      setResults(await apiPredict({ connLog: fileName(z.conn_log) }));
    } catch (e) {
      setError(e.message);
    } finally {
      setPhase('idle');
    }
  };

  const busy = phase !== 'idle';
  const v = results ? verdict(results) : null;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Traffic analysis</h1>
        <p className="mt-1 text-muted">Capture live traffic, turn it into connections with Zeek, and let the model look for attacks.</p>
        <div className="mt-2"><ModelNote health={health} /></div>
      </div>

      <Panel title="Capture traffic">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
          <label>
            <span className="mb-1 block text-sm font-medium">Seconds</span>
            <input type="number" min="5" max="600" value={duration} disabled={busy}
              onChange={(e) => setDuration(Number(e.target.value))}
              className="w-28 rounded-md border border-line bg-bg px-3 py-2 text-sm" />
          </label>
          <label>
            <span className="mb-1 block text-sm font-medium">Network interface</span>
            <input value={networkInterface} disabled={busy} spellCheck="false"
              onChange={(e) => setNetworkInterface(e.target.value)}
              className="w-40 rounded-md border border-line bg-bg px-3 py-2 font-mono text-sm" />
          </label>
          {phase === 'capturing'
            ? <Button variant="danger" onClick={stopCapture}>Stop capture</Button>
            : <Button onClick={startCapture} disabled={busy || duration < 5 || duration > 600}>Start capture</Button>}
          <Button variant="secondary" onClick={analyse} disabled={busy || !capture}>Analyse capture</Button>
        </div>
        <div className="mt-3 text-sm">
          {phase === 'capturing' && <Spinner label={`Capturing on ${networkInterface}: ${remaining}s left`} />}
          {phase === 'zeek' && <Spinner label="Zeek is turning packets into connections" />}
          {phase === 'scoring' && <Spinner label="Scoring every connection" />}
          {phase === 'idle' && capture && !results && <span className="text-muted">Captured to <Mono>{capture.file}</Mono>. Press Analyse capture.</span>}
          {phase === 'idle' && !capture && <span className="text-muted">Needs tcpdump and Zeek on the machine running the ML API (use WSL on Windows). Run <Mono>tcpdump -D</Mono> to list interfaces.</span>}
        </div>
      </Panel>

      {error && <Notice tone="critical">{error}</Notice>}

      {results && (
        <>
          <div className={`border-l-4 pl-4 ${VERDICT_STYLE[v.tone]}`}>
            <p className="text-xl font-medium leading-snug sm:text-2xl">{v.text}</p>
            {results.warning && <p className="mt-1 text-sm text-muted">{results.warning}</p>}
          </div>

          <div className="grid gap-6 lg:grid-cols-3">
            <Panel title="What was found" className="min-w-0 lg:col-span-1">
              <dl className="mb-4 grid grid-cols-2 gap-y-2 text-sm">
                <dt className="text-muted">Connections</dt><dd className="text-right tabular-nums">{results.total_records.toLocaleString()}</dd>
                <dt className="text-muted">Look normal</dt><dd className="text-right tabular-nums">{results.normal.toLocaleString()}</dd>
                <dt className="text-muted">Known attack types</dt><dd className="text-right tabular-nums">{results.attacks.toLocaleString()}</dd>
                <dt className="text-muted">Unusual only</dt><dd className="text-right tabular-nums">{(results.anomalies_not_known_attack || 0).toLocaleString()}</dd>
              </dl>
              <Breakdown breakdown={results.attack_breakdown} unusual={results.anomalies_not_known_attack} total={results.total_records} />
              {results.output_csv && (
                <Button variant="ghost" className="mt-4 -ml-2" onClick={() => apiDownloadResult(results.output_csv).catch((e) => setError(e.message))}>
                  Download all connections (CSV)
                </Button>
              )}
            </Panel>
            <Panel title="Incidents" className="min-w-0 lg:col-span-2">
              {results.incidents?.length
                ? <IncidentTable incidents={results.incidents} />
                : <p className="text-sm text-muted">Nothing to look at. Every connection matched normal traffic.</p>}
            </Panel>
          </div>
        </>
      )}
    </div>
  );
}
