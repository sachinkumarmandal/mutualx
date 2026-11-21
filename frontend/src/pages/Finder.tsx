import { useEffect, useMemo, useState } from 'react';
import DropZone from '../components/DropZone';
import { Card, Notice, Spinner } from '../components/ui';
import { api, type Limitation } from '../lib/api';
import type { ParsedList } from '../lib/exportParser';
import { computeMutuals, computeStats, diffSnapshots, toCsv } from '../lib/mutuals';

type Tab = 'mutuals' | 'notFollowingBack' | 'fans' | 'newFollowers' | 'lostFollowers';
const TABS: { id: Tab; label: string; desc: string }[] = [
  { id: 'mutuals', label: 'Mutuals', desc: 'You follow each other' },
  { id: 'notFollowingBack', label: 'Not following back', desc: 'You follow them, they don’t follow you' },
  { id: 'fans', label: 'Fans', desc: 'They follow you, you don’t follow them' },
];
const DIFF_TABS: { id: Tab; label: string; desc: string }[] = [
  { id: 'newFollowers', label: 'New followers', desc: 'Follow you now, not in the older export' },
  { id: 'lostFollowers', label: 'Lost followers', desc: 'Gone since the older export (unfollowed, deactivated or renamed)' },
];
const PAGE = 100;

function Steps() {
  return (
    <ol className="mt-3 list-decimal space-y-1.5 pl-5 text-sm text-navy-800/80">
      <li>Instagram → <b>Settings</b> → <b>Accounts Center</b> → <b>Your information and permissions</b> → <b>Export your information</b>.</li>
      <li>Create an export of <b>Followers and following</b> only, format <b>JSON</b>, date range <b>All time</b>.</li>
      <li>When Instagram emails you, download and unzip it. You need <code>followers_1.json</code> (and any <code>followers_2…</code>) and <code>following.json</code>, inside <code>connections/followers_and_following</code>.</li>
    </ol>
  );
}

const fmtPct = (n: number | null) => (n === null ? '—' : `${n}%`);

function Results({ followers, following, older }: { followers: ParsedList; following: ParsedList; older: ParsedList | null }) {
  const base = useMemo(() => computeMutuals(followers.usernames, following.usernames), [followers, following]);
  const stats = useMemo(() => computeStats(followers.usernames, following.usernames, base.mutuals.length), [followers, following, base]);
  const result = useMemo(() => ({ ...base, ...(older ? diffSnapshots(older.usernames, followers.usernames) : { newFollowers: [], lostFollowers: [] }) }), [base, older, followers]);
  const tabs = older ? [...TABS, ...DIFF_TABS] : TABS;
  const [desc, setDesc] = useState(false);
  const [copied, setCopied] = useState(false);
  const [tab, setTab] = useState<Tab>('mutuals');
  const [q, setQ] = useState('');
  const [limit, setLimit] = useState(PAGE);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const list = result[tab].filter((u) => !needle || u.includes(needle));
    return desc ? [...list].reverse() : list;
  }, [result, tab, q, desc]);

  async function copy() {
    try {
      await navigator.clipboard.writeText(rows.join('\n'));
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
    }
  }

  function download() {
    const blob = new Blob([toCsv(result[tab], tab)], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `mutualx-${tab}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <Card className="mt-6" >
      <div className="grid gap-3 sm:grid-cols-3" role="tablist" aria-label="Result groups">
        {tabs.map((t) => {
          const active = tab === t.id;
          return (
            <button
              key={t.id}
              role="tab"
              aria-selected={active}
              onClick={() => { setTab(t.id); setLimit(PAGE); }}
              className={`rounded-2xl p-4 text-left transition duration-200 ${active ? 'bg-navy-800 text-white shadow-lg shadow-navy-900/20' : 'bg-white/60 hover:bg-white/90'}`}
            >
              <span className={`text-[11px] font-bold uppercase tracking-[.14em] ${active ? 'text-emerald-300' : 'text-emerald-700'}`}>{t.label}</span>
              <span className="stat-num mt-2 block" data-testid={`count-${t.id}`}>{result[t.id].length.toLocaleString()}</span>
              <span className={`mt-1 block text-xs ${active ? 'text-white/70' : 'text-navy-800/60'}`}>{t.desc}</span>
            </button>
          );
        })}
      </div>

      <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-3" data-testid="stats">
        <div className="rounded-2xl bg-white/55 p-3"><dt className="text-navy-800/60">They follow you back</dt><dd className="font-display text-3xl">{fmtPct(stats.followBackRate)}</dd><dd className="text-xs text-navy-800/50">of the accounts you follow</dd></div>
        <div className="rounded-2xl bg-white/55 p-3"><dt className="text-navy-800/60">You follow them back</dt><dd className="font-display text-3xl">{fmtPct(stats.mutualShareOfFollowers)}</dd><dd className="text-xs text-navy-800/50">of your followers</dd></div>
        <div className="rounded-2xl bg-white/55 p-3"><dt className="text-navy-800/60">Followers ÷ following</dt><dd className="font-display text-3xl">{stats.ratio ?? '—'}</dd><dd className="text-xs text-navy-800/50">above 1 means more follow you</dd></div>
      </dl>

      <div className="mt-5 flex flex-wrap items-center gap-3">
        <input
          type="search"
          value={q}
          onChange={(e) => { setQ(e.target.value); setLimit(PAGE); }}
          placeholder="Search usernames"
          aria-label="Search usernames"
          maxLength={30}
          className="min-w-0 flex-1 rounded-full border border-white/80 bg-white/70 px-4 py-2.5 text-sm placeholder:text-navy-800/40"
        />
        <button className="btn-ghost" onClick={() => setDesc((d) => !d)} aria-label="Toggle sort order">{desc ? 'Z → A' : 'A → Z'}</button>
        <button className="btn-ghost" onClick={() => void copy()} disabled={!rows.length}>{copied ? 'Copied ✓' : 'Copy list'}</button>
        <button className="btn-ghost" onClick={download} disabled={!result[tab].length}>Download CSV</button>
      </div>

      <ul className="mt-4 divide-y divide-navy-800/5 overflow-hidden rounded-2xl bg-white/50" data-testid="result-list">
        {rows.slice(0, limit).map((u) => (
          <li key={u}>
            <a
              href={`https://www.instagram.com/${u}/`}
              target="_blank"
              rel="noopener noreferrer nofollow"
              className="flex items-center justify-between px-4 py-3 text-sm transition duration-150 hover:bg-navy-800 hover:text-white"
            >
              <span className="font-semibold">@{u}</span>
              <span aria-hidden="true" className="text-xs opacity-60">open ↗</span>
            </a>
          </li>
        ))}
        {!rows.length && <li className="px-4 py-8 text-center text-sm text-navy-800/60">{q ? 'No usernames match your search.' : 'Nothing in this group.'}</li>}
      </ul>
      {rows.length > limit && <button className="btn-ghost mt-4" onClick={() => setLimit((l) => l + PAGE)}>Show more ({rows.length - limit} left)</button>}
    </Card>
  );
}

function Limitations() {
  const [items, setItems] = useState<Limitation[] | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => { api.limitations().then((r) => setItems(r.limitations)).catch(() => setFailed(true)); }, []);
  const badge = { available: 'bg-emerald-500 text-white', partial: 'bg-amber-400 text-navy-900', unavailable: 'bg-navy-800/10 text-navy-800' } as const;
  return (
    <Card className="mt-6">
      <p className="eyebrow">Transparency</p>
      <h2 className="mt-1 font-display text-3xl">What Instagram’s official API can and can’t do</h2>
      <p className="mt-2 max-w-2xl text-sm text-navy-800/70">Meta does not let apps read follower lists. That’s why MutualX works from the export Instagram gives you, instead of scraping.</p>
      {!items && !failed && <Spinner />}
      {failed && <div className="mt-4"><Notice tone="warn">The MutualX API is not reachable right now, so the live capability list can’t be shown. The Mutuals tool above does not need the API.</Notice></div>}
      {items && (
        <ul className="mt-4 grid gap-3 md:grid-cols-2">
          {items.map((l) => (
            <li key={l.id} className="rounded-2xl bg-white/55 p-4">
              <div className="flex items-start justify-between gap-3">
                <h3 className="text-sm font-bold">{l.capability}</h3>
                <span className={`shrink-0 rounded-full px-2.5 py-0.5 text-[11px] font-bold uppercase tracking-wide ${badge[l.status]}`}>{l.status}</span>
              </div>
              <p className="mt-1.5 text-sm text-navy-800/70">{l.detail}</p>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

const SAMPLE_FOLLOWERS = ['ananya.k', 'ben_ortiz', 'cyrus.dev', 'dee.designs', 'ines_valle', 'jo.wanders', 'kai.cooks', 'lena.m'];
const SAMPLE_FOLLOWING = ['ben_ortiz', 'cyrus.dev', 'dee.designs', 'eli_runs', 'fay.studio', 'gus.photo', 'ines_valle', 'jo.wanders'];

export default function Finder() {
  const [followers, setFollowers] = useState<ParsedList | null>(null);
  const [following, setFollowing] = useState<ParsedList | null>(null);
  const [older, setOlder] = useState<ParsedList | null>(null);
  const [sample, setSample] = useState(false);
  const loadSample = () => {
    setFollowers({ usernames: SAMPLE_FOLLOWERS, skipped: 0 });
    setFollowing({ usernames: SAMPLE_FOLLOWING, skipped: 0 });
    setOlder({ usernames: [...SAMPLE_FOLLOWERS.slice(1), 'old.friend', 'moved.on'], skipped: 0 });
    setSample(true);
  };

  return (
    <>
      <div className="max-w-3xl">
        <p className="eyebrow">Private by construction</p>
        <h1 className="mt-2 font-display text-5xl leading-[1.05] sm:text-6xl">Find your mutuals — without handing over a password.</h1>
        <p className="mt-4 text-lg text-navy-800/75">Drop in the data export Instagram gives you. MutualX compares the lists <b>inside your browser</b>; the files are never uploaded, stored or sent anywhere.</p>
      </div>

      <Card className="mt-8">
        <div className="grid gap-4 md:grid-cols-2">
          <DropZone label="Followers" hint="followers_1.json (select several if you have more)" onParsed={(l) => { setSample(false); setFollowers(l); }} />
          <DropZone label="Following" hint="following.json" onParsed={(l) => { setSample(false); setFollowing(l); }} />
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <button className="btn-ghost" onClick={loadSample}>Try with example data</button>
          <span className="text-xs text-navy-800/60">Invented accounts so you can see the result without an export.</span>
        </div>
        <details className="mt-4 rounded-2xl bg-white/50 px-4 py-3">
          <summary className="cursor-pointer text-sm font-bold">Optional: compare with an older export (who followed or left)</summary>
          <p className="mt-2 text-sm text-navy-800/70">Add your <b>followers</b> file from an earlier export. MutualX shows who is new and who is gone. Instagram doesn’t say why someone is gone, so it may be an unfollow, a deactivated account or a username change.</p>
          <div className="mt-3 max-w-md"><DropZone label="Older followers" hint="followers_1.json from an earlier export" onParsed={setOlder} /></div>
        </details>
        <details className="mt-5 rounded-2xl bg-white/50 px-4 py-3">
          <summary className="cursor-pointer text-sm font-bold">How do I get these files?</summary>
          <Steps />
        </details>
      </Card>

      {sample && followers && following && <div className="mt-6"><Notice tone="warn">You’re looking at example data, not a real account. Add your own files above to replace it.</Notice></div>}
      {followers && following ? <Results followers={followers} following={following} older={older} /> : (
        <div className="mt-6"><Notice>Add both files to see your results. Nothing leaves this page — you can check the Network tab in your browser’s developer tools.</Notice></div>
      )}

      <Limitations />
    </>
  );
}
