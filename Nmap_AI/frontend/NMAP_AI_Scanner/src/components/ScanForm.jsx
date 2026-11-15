import React, { useState } from 'react';
import { Button, Spinner } from './ui';

const SCAN_TYPES = [
  { value: 'basic', label: 'Quick', help: 'Top 100 ports and service versions (-F -sV)' },
  { value: 'aggressive', label: 'Deep', help: 'Versions, OS detection and default scripts (-A). Slower.' },
  { value: 'passive', label: 'Stealth', help: 'SYN scan without version checks (-sS -Pn). Needs admin rights.' },
];

const TARGET_RE = /^[a-zA-Z0-9.:/-]{1,253}$/;

export default function ScanForm({ onStartScan, isLoading = false }) {
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('basic');
  const [error, setError] = useState('');

  async function submit(e) {
    e.preventDefault();
    const value = target.trim();
    if (!value) return setError('Enter an IP address, host name or network (for example 192.168.1.0/24).');
    if (!TARGET_RE.test(value)) return setError('That does not look like an IP address, host name or network.');
    setError('');
    await onStartScan({ target: value, scanType });
  }

  const help = SCAN_TYPES.find((t) => t.value === scanType).help;

  return (
    <form onSubmit={submit} className="rounded-lg border border-line bg-surface p-4" noValidate>
      <div className="flex flex-col gap-3 md:flex-row md:items-end">
        <label className="flex-1">
          <span className="mb-1 block text-sm font-medium">Target</span>
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="scanme.nmap.org or 192.168.1.10"
            autoComplete="off"
            spellCheck="false"
            aria-invalid={!!error}
            className="w-full rounded-md border border-line bg-bg px-3 py-2 font-mono text-sm placeholder:font-sans placeholder:text-muted"
          />
        </label>
        <fieldset className="md:w-auto">
          <legend className="mb-1 text-sm font-medium">Scan type</legend>
          <div className="flex rounded-md border border-line bg-bg p-0.5">
            {SCAN_TYPES.map((t) => (
              <label key={t.value} className={`cursor-pointer rounded px-3 py-1.5 text-sm ${scanType === t.value ? 'bg-surface font-medium shadow-sm' : 'text-muted'}`}>
                <input type="radio" name="scanType" value={t.value} checked={scanType === t.value} onChange={() => setScanType(t.value)} className="sr-only" />
                {t.label}
              </label>
            ))}
          </div>
        </fieldset>
        <Button type="submit" disabled={isLoading} className="md:w-32">
          {isLoading ? 'Scanning' : 'Start scan'}
        </Button>
      </div>
      <p className="mt-2 text-xs text-muted">{help} Only scan networks you own or have permission to test.</p>
      {error && <p className="mt-2 text-sm text-critical">{error}</p>}
      {isLoading && <div className="mt-3"><Spinner label="Running nmap. A quick scan usually takes under a minute." /></div>}
    </form>
  );
}
