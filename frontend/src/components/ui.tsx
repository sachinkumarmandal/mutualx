import type { ReactNode } from 'react';

export function Card({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <section className={`glass p-5 sm:p-7 ${className}`}>{children}</section>;
}

export function Notice({ tone = 'info', children }: { tone?: 'info' | 'warn' | 'error'; children: ReactNode }) {
  const t = { info: 'bg-emerald-500/10 text-emerald-800 border-emerald-600/20', warn: 'bg-amber-400/15 text-amber-900 border-amber-500/30', error: 'bg-rose-500/10 text-rose-800 border-rose-500/30' }[tone];
  return <div role={tone === 'error' ? 'alert' : 'status'} className={`rounded-2xl border px-4 py-3 text-sm ${t}`}>{children}</div>;
}

export function Spinner({ label = 'Loading' }: { label?: string }) {
  return (
    <div role="status" className="flex items-center gap-3 py-10 text-sm text-navy-800/70">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-emerald-600 border-t-transparent" />
      {label}…
    </div>
  );
}

export function fmtDate(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}
