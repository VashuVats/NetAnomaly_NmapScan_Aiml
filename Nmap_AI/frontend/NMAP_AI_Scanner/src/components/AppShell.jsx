import React from 'react';
import { useTheme } from '../theme/ThemeContext';
import { navigate, ROUTES } from '../hooks/useRoute';
import { ScanIcon } from './Icons';

const NAV = [
  { key: 'scan', label: 'Port scan', path: ROUTES.scan },
  { key: 'traffic', label: 'Traffic analysis', path: ROUTES.traffic },
];

function ThemeSwitch() {
  const { choice, setChoice } = useTheme();
  const options = [['system', 'Auto'], ['light', 'Light'], ['dark', 'Dark']];
  return (
    <div role="radiogroup" aria-label="Colour theme" className="flex rounded-md border border-line bg-surface p-0.5 text-xs">
      {options.map(([value, label]) => (
        <button
          key={value}
          role="radio"
          aria-checked={choice === value}
          onClick={() => setChoice(value)}
          className={`rounded px-2.5 py-1 ${choice === value ? 'bg-surface-2 font-medium text-ink' : 'text-muted hover:text-ink'}`}
        >
          {label}
        </button>
      ))}
    </div>
  );
}

export default function AppShell({ page, children }) {
  return (
    <div className="min-h-screen bg-bg text-ink">
      <header className="border-b border-line bg-surface">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-6 gap-y-3 px-4 py-3 sm:px-6">
          <a href={ROUTES.scan} onClick={(e) => { e.preventDefault(); navigate(ROUTES.scan); }} className="flex items-center gap-2 font-semibold">
            <ScanIcon className="h-5 w-5 text-accent" />
            NetScan AI
          </a>
          <nav aria-label="Main" className="flex gap-1">
            {NAV.map((item) => (
              <a
                key={item.key}
                href={item.path}
                aria-current={page === item.key ? 'page' : undefined}
                onClick={(e) => { e.preventDefault(); navigate(item.path); }}
                className={`rounded-md px-3 py-1.5 text-sm ${page === item.key ? 'bg-surface-2 font-medium' : 'text-muted hover:text-ink'}`}
              >
                {item.label}
              </a>
            ))}
          </nav>
          <div className="ml-auto"><ThemeSwitch /></div>
        </div>
      </header>
      <main className="mx-auto max-w-7xl px-4 py-6 sm:px-6">{children}</main>
    </div>
  );
}
