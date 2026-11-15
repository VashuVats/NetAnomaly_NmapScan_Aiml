import React from 'react';

export function Button({ variant = 'primary', className = '', ...props }) {
  const styles = {
    primary: 'bg-accent text-accent-ink hover:opacity-90',
    secondary: 'bg-surface-2 text-ink hover:bg-line',
    danger: 'bg-critical text-white hover:opacity-90',
    ghost: 'text-ink hover:bg-surface-2',
  };
  return (
    <button
      className={`inline-flex items-center justify-center gap-2 rounded-md px-4 py-2 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${styles[variant]} ${className}`}
      {...props}
    />
  );
}

export function Panel({ title, actions, children, className = '' }) {
  return (
    <section className={`rounded-lg border border-line bg-surface ${className}`}>
      {(title || actions) && (
        <header className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-3">
          {title && <h2 className="text-base font-semibold">{title}</h2>}
          {actions}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

const TONES = {
  critical: 'text-critical border-critical/40 bg-critical/10',
  warning: 'text-warning border-warning/40 bg-warning/10',
  safe: 'text-safe border-safe/40 bg-safe/10',
  info: 'text-info border-info/40 bg-info/10',
  unusual: 'text-unusual border-unusual/40 bg-unusual/10',
  neutral: 'text-muted border-line bg-surface-2',
};

export function Badge({ tone = 'neutral', children, title }) {
  return (
    <span title={title} className={`inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-medium whitespace-nowrap ${TONES[tone]}`}>
      {children}
    </span>
  );
}

export function Notice({ tone = 'info', children }) {
  return (
    <div role={tone === 'critical' ? 'alert' : 'status'} className={`rounded-md border px-4 py-3 text-sm ${TONES[tone]}`}>
      <div className="text-ink">{children}</div>
    </div>
  );
}

export function Spinner({ label }) {
  return (
    <span className="inline-flex items-center gap-2 text-sm text-muted" role="status">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-line border-t-accent" aria-hidden="true" />
      {label}
    </span>
  );
}

export function Mono({ children, className = '' }) {
  return <span className={`font-mono text-[0.85em] ${className}`}>{children}</span>;
}
