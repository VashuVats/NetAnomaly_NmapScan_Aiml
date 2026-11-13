import React from 'react';

export default function ResultPanel({ scanOutput, stats }) {
  return (
    <details className="rounded-lg border border-line bg-surface">
      <summary className="cursor-pointer px-4 py-3 text-sm font-medium">
        Raw nmap output{stats?.elapsedSeconds ? <span className="font-normal text-muted"> (took {stats.elapsedSeconds}s)</span> : null}
      </summary>
      <pre className="max-h-96 overflow-auto border-t border-line bg-code-bg p-4 font-mono text-xs leading-relaxed"><code>{scanOutput}</code></pre>
    </details>
  );
}
