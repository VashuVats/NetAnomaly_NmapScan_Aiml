import React from 'react';
import ScanForm from '../components/ScanForm';
import HostTable from '../components/HostTable';
import ResultPanel from '../components/ResultPanel';
import AISummary from '../components/AISummary';
import DownloadButton from '../components/DownloadButton';
import { Button, Notice, Spinner } from '../components/ui';
import { useScanAPI } from '../hooks/useScanAPI';

/** One sentence that says how worried to be, coloured by severity. */
function verdict(state) {
  const openPorts = state.hosts.reduce((n, h) => n + h.openPorts, 0);
  const s = state.intel?.summary;
  if (s?.kev) return { tone: 'critical', text: `${s.kev} vulnerabilit${s.kev === 1 ? 'y is' : 'ies are'} being exploited in the wild right now. Patch ${s.kev === 1 ? 'it' : 'them'} first.` };
  if (s?.critical) return { tone: 'critical', text: `${s.critical} critical vulnerabilit${s.critical === 1 ? 'y' : 'ies'} found on the software versions running.` };
  if (s?.high) return { tone: 'warning', text: `${s.high} high-severity vulnerabilit${s.high === 1 ? 'y' : 'ies'} found. None are known to be exploited yet.` };
  if (!state.hosts.length) return { tone: 'neutral', text: 'No hosts answered. The target may be down or blocking scans.' };
  if (!openPorts) return { tone: 'safe', text: `No open ports found on ${state.hosts.length} host${state.hosts.length === 1 ? '' : 's'}.` };
  const base = `${openPorts} open port${openPorts === 1 ? '' : 's'} on ${state.hosts.length} host${state.hosts.length === 1 ? '' : 's'}.`;
  if (state.isEnriching) return { tone: 'neutral', text: `${base} Checking the software versions for known vulnerabilities.` };
  if (state.intel) return { tone: 'safe', text: `${base} No known vulnerabilities for the versions found.` };
  return { tone: 'neutral', text: base };
}

const VERDICT_STYLE = {
  critical: 'border-critical text-critical',
  warning: 'border-warning text-warning',
  safe: 'border-safe text-safe',
  neutral: 'border-line text-ink',
};

export default function Home() {
  const { state, startScan, lookUpVulnerabilities, generateAISummary, downloadReport, canGenerateAI, canDownload } = useScanAPI();
  const done = !!state.scanOutput;
  const v = done ? verdict(state) : null;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Port scan</h1>
        <p className="mt-1 text-muted">Find open ports, the software behind them, and which known vulnerabilities apply.</p>
      </div>

      <ScanForm onStartScan={({ target, scanType }) => startScan(target, scanType)} isLoading={state.isScanning} />

      {state.scanError && <Notice tone="critical">Scan failed: {state.scanError}</Notice>}

      {done && (
        <>
          <div className={`border-l-4 pl-4 ${VERDICT_STYLE[v.tone]}`}>
            <p className="text-xl font-medium leading-snug sm:text-2xl">{v.text}</p>
            <p className="mt-1 text-sm text-muted">
              Target <span className="font-mono">{state.target}</span>
              {state.timestamp && <>, scanned {new Date(state.timestamp).toLocaleString()}</>}
            </p>
          </div>

          <div className="grid gap-6 lg:grid-cols-3">
            <div className="min-w-0 space-y-4 lg:col-span-2">
              <div className="flex flex-wrap items-center gap-3">
                <h2 className="text-lg font-semibold">Hosts and ports</h2>
                {state.isEnriching && <Spinner label="Checking NVD, CISA KEV, EPSS and Shodan. Can take 30 seconds without an NVD key." />}
                {!state.isEnriching && state.hosts.length > 0 && (
                  <Button variant="ghost" onClick={() => lookUpVulnerabilities(state.hosts)}>
                    {state.intel ? 'Check vulnerabilities again' : 'Check vulnerabilities'}
                  </Button>
                )}
              </div>
              {state.intelError && <Notice tone="warning">Vulnerability check failed: {state.intelError}</Notice>}
              {state.intel?.warnings?.length > 0 && (
                <Notice tone="warning">
                  <ul className="list-disc pl-4">{state.intel.warnings.map((w) => <li key={w}>{w}</li>)}</ul>
                </Notice>
              )}
              <HostTable hosts={state.hosts} intel={state.intel} isEnriching={state.isEnriching} />
              <ResultPanel scanOutput={state.scanOutput} stats={state.stats} />
            </div>

            <div className="min-w-0 space-y-4">
              <AISummary
                aiSummary={state.aiSummary}
                onGenerate={generateAISummary}
                isSummarizing={state.isAnalyzing}
                canGenerate={canGenerateAI}
                hasIntel={!!state.intel}
                error={state.aiError}
              />
              <div className="flex flex-col gap-2">
                <DownloadButton onClick={downloadReport} isDownloading={state.isDownloading} canDownload={canDownload} />
                {state.downloadError && <p className="text-sm text-critical">{state.downloadError}</p>}
              </div>
            </div>
          </div>
        </>
      )}

      {!done && !state.isScanning && !state.scanError && (
        <p className="text-sm text-muted">Results show up here: each host, its open ports, the software versions, and any known vulnerabilities with how likely they are to be attacked.</p>
      )}
    </div>
  );
}
