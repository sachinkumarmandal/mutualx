import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Card, fmtDate, Notice, Spinner } from '../components/ui';
import { api, ApiError, loginUrl, type AuditRow, type CheckResult, type CheckStatus, type SecurityReport, type Severity } from '../lib/api';
import { useAuth } from '../lib/auth';

const STATUS: Record<CheckStatus, { label: string; chip: string; dot: string }> = {
  pass: { label: 'Pass', chip: 'bg-emerald-500 text-white', dot: 'bg-emerald-500' },
  needs_review: { label: 'Needs review', chip: 'bg-amber-400 text-navy-900', dot: 'bg-amber-400' },
  fail: { label: 'Fail', chip: 'bg-rose-600 text-white', dot: 'bg-rose-600' },
};
const SEV: Record<Severity, string> = { critical: 'text-rose-700', high: 'text-orange-700', medium: 'text-amber-700', low: 'text-navy-800/60' };

function Ring({ pass, total }: { pass: number; total: number }) {
  const r = 52, c = 2 * Math.PI * r, frac = total ? pass / total : 0;
  return (
    <svg viewBox="0 0 128 128" className="h-32 w-32" role="img" aria-label={`${pass} of ${total} checks pass`}>
      <circle cx="64" cy="64" r={r} fill="none" stroke="#10b98122" strokeWidth="12" />
      <circle cx="64" cy="64" r={r} fill="none" stroke="#10b981" strokeWidth="12" strokeLinecap="round" strokeDasharray={`${c * frac} ${c}`} transform="rotate(-90 64 64)" className="transition-[stroke-dasharray] duration-700" />
      <text x="64" y="64" textAnchor="middle" className="fill-navy-800 font-display" fontSize="34">{pass}</text>
      <text x="64" y="84" textAnchor="middle" className="fill-navy-800/60" fontSize="11" fontWeight="700">of {total} pass</text>
    </svg>
  );
}

function Row({ c, open, toggle }: { c: CheckResult; open: boolean; toggle: () => void }) {
  const s = STATUS[c.status];
  const panel = `panel-${c.id}`;
  return (
    <li className={`overflow-hidden rounded-2xl transition-colors duration-200 ${open ? 'bg-navy-800 text-white' : 'bg-white/55 hover:bg-white/80'}`}>
      <button className="flex w-full items-center gap-3 px-4 py-3.5 text-left" aria-expanded={open} aria-controls={panel} onClick={toggle}>
        <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${s.dot}`} aria-hidden="true" />
        <span className={`w-6 shrink-0 text-xs font-bold tabular-nums ${open ? 'text-white/50' : 'text-navy-800/40'}`}>{String(c.id).padStart(2, '0')}</span>
        <span className="min-w-0 flex-1 text-sm font-bold">{c.title}</span>
        <span className={`hidden text-[11px] font-bold uppercase tracking-wide sm:inline ${open ? 'text-white/70' : SEV[c.severity]}`}>{c.severity}</span>
        <span className={`shrink-0 rounded-full px-2.5 py-0.5 text-[11px] font-bold ${s.chip}`}>{s.label}</span>
        <span aria-hidden="true" className={`transition-transform duration-200 ${open ? 'rotate-180' : ''}`}>⌄</span>
      </button>
      {open && (
        <div id={panel} className="grid gap-5 px-4 pb-5 pt-1 text-sm md:grid-cols-2">
          <div className="space-y-4">
            <div><h4 className="eyebrow !text-emerald-300">Implementation</h4><p className="mt-1 text-white/85">{c.implementation}</p></div>
            <div><h4 className="eyebrow !text-emerald-300">Explanation</h4><p className="mt-1 text-white/85">{c.explanation}</p></div>
            <p className="text-xs text-white/55">Method: {c.methods.join(', ')} · Severity: {c.severity} · Last verified {fmtDate(c.verifiedAt)}</p>
          </div>
          <div className="space-y-4">
            <div><h4 className="eyebrow !text-emerald-300">Evidence</h4><ul className="mt-1 list-disc space-y-1 pl-4 text-white/80">{c.evidence.map((e, i) => <li key={i}>{e}</li>)}</ul></div>
            <div><h4 className="eyebrow !text-emerald-300">Remediation</h4><ul className="mt-1 list-disc space-y-1 pl-4 text-white/80">{c.remediation.map((e, i) => <li key={i}>{e}</li>)}</ul></div>
          </div>
        </div>
      )}
    </li>
  );
}

export default function Security() {
  const { me, loading, unreachable } = useAuth();
  const [report, setReport] = useState<SecurityReport | null>(null);
  const [audit, setAudit] = useState<AuditRow[]>([]);
  const [error, setError] = useState<ApiError | null>(null);
  const [running, setRunning] = useState(false);
  const [open, setOpen] = useState<number | null>(null);
  const [filter, setFilter] = useState<CheckStatus | 'all'>('all');

  const load = useCallback(async (fresh = false) => {
    setRunning(true); setError(null);
    try {
      setReport(await (fresh ? api.runChecks() : api.checks()));
      api.audit().then((r) => setAudit(r.events.slice(0, 12))).catch(() => undefined);
    } catch (e) { setError(e instanceof ApiError ? e : new ApiError(0, 'network')); }
    finally { setRunning(false); }
  }, []);
  useEffect(() => { if (me?.user.role === 'admin') void load(); }, [me, load]);

  const grouped = useMemo(() => report?.categories.map((cat) => ({ cat, checks: report.checks.filter((c) => c.category === cat.id && (filter === 'all' || c.status === filter)) })) ?? [], [report, filter]);

  if (loading) return <Spinner />;
  if (!me) return <Card className="mx-auto max-w-xl text-center"><h1 className="font-display text-4xl">Admin sign-in required</h1><p className="mt-3 text-sm text-navy-800/75">The security dashboard shows implementation details, so it is limited to administrators.</p><a className="btn-primary mt-6" href={loginUrl}>Connect with Instagram</a>{unreachable && <div className="mt-4"><Notice tone="warn">The MutualX API is not reachable right now.</Notice></div>}</Card>;
  if (me.user.role !== 'admin') return <Card className="mx-auto max-w-xl text-center"><h1 className="font-display text-4xl">Administrators only</h1><p className="mt-3 text-sm text-navy-800/75">Your account doesn’t have the admin role.</p><Link className="btn-ghost mt-6" to="/account">Back to your account</Link></Card>;

  return (
    <div className="space-y-6">
      <Card>
        <div className="flex flex-wrap items-center gap-6">
          {report && <Ring pass={report.summary.pass} total={report.summary.total} />}
          <div className="min-w-0 flex-1">
            <p className="eyebrow">Security monitoring · {report?.environment ?? '…'}</p>
            <h1 className="mt-1 font-display text-4xl">20-point security dashboard</h1>
            <p className="mt-2 max-w-xl text-sm text-navy-800/70">Every verdict comes from a live probe, configuration inspection or scan — never a hard-coded pass. Anything that can’t be proven from here is marked <b>Needs review</b>.</p>
            {report && <p className="mt-2 text-xs text-navy-800/55">Generated {fmtDate(report.generatedAt)}</p>}
          </div>
          <button className="btn-primary" disabled={running} onClick={() => void load(true)}>{running ? 'Verifying…' : 'Run checks now'}</button>
        </div>
        {report && (
          <div className="mt-5 flex flex-wrap gap-2" role="group" aria-label="Filter by status">
            {([['all', 'All', report.summary.total], ['pass', 'Pass', report.summary.pass], ['needs_review', 'Needs review', report.summary.needs_review], ['fail', 'Fail', report.summary.fail]] as const).map(([k, label, n]) => (
              <button key={k} aria-pressed={filter === k} onClick={() => setFilter(k)} className={`rounded-full px-4 py-1.5 text-sm font-semibold transition ${filter === k ? 'bg-navy-800 text-white' : 'bg-white/60 hover:bg-white/90'}`}>{label} <span className="opacity-60">{n}</span></button>
            ))}
          </div>
        )}
      </Card>

      {error && <Notice tone="error">{error.status === 403 ? 'You don’t have permission to view this.' : error.status === 0 ? 'The MutualX API is not reachable.' : 'Could not load the security report.'}</Notice>}
      {!report && !error && <Spinner label="Running checks" />}

      {grouped.map(({ cat, checks }) => checks.length > 0 && (
        <Card key={cat.id}>
          <h2 className="mb-4 flex items-baseline gap-3"><span className="eyebrow">{cat.index}</span><span className="font-display text-3xl">{cat.label}</span></h2>
          <ul className="space-y-2">{checks.map((c) => <Row key={c.id} c={c} open={open === c.id} toggle={() => setOpen(open === c.id ? null : c.id)} />)}</ul>
        </Card>
      ))}

      {report && (
        <Card>
          <p className="eyebrow">Outside the app’s reach</p>
          <h2 className="font-display text-3xl">Manual review items</h2>
          <p className="mt-1 text-sm text-navy-800/70">These controls can’t be proven by code. Confirm them by hand before calling the deployment production-ready.</p>
          <ul className="mt-4 grid gap-2 md:grid-cols-2">{report.manualReviewItems.map((m, i) => <li key={i} className="flex gap-3 rounded-2xl bg-white/55 p-3 text-sm"><span className="mt-1.5 h-2 w-2 shrink-0 rounded-full bg-amber-400" aria-hidden="true" />{m}</li>)}</ul>
        </Card>
      )}

      {audit.length > 0 && (
        <Card>
          <p className="eyebrow">Audit log</p>
          <h2 className="font-display text-3xl">Recent security events</h2>
          <div className="mt-4 overflow-x-auto"><table className="w-full text-left text-sm"><thead className="text-xs uppercase tracking-wide text-navy-800/50"><tr><th className="py-2 pr-4">When</th><th className="pr-4">Event</th><th>Outcome</th></tr></thead><tbody>{audit.map((a, i) => <tr key={i} className="border-t border-navy-800/5"><td className="py-2 pr-4 tabular-nums">{fmtDate(a.at)}</td><td className="pr-4 font-semibold">{a.event}</td><td>{a.outcome}</td></tr>)}</tbody></table></div>
        </Card>
      )}
    </div>
  );
}
