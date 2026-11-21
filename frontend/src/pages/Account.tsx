import { useCallback, useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Card, fmtDate, Notice, Spinner } from '../components/ui';
import { api, ApiError, loginUrl, type Profile, type SessionRow } from '../lib/api';
import { useAuth } from '../lib/auth';

export default function Account() {
  const { me, loading, refresh, clear } = useAuth();
  const nav = useNavigate();
  const [sessions, setSessions] = useState<SessionRow[]>([]);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [msg, setMsg] = useState<{ tone: 'info' | 'error'; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState('');

  const loadSessions = useCallback(() => { api.sessions().then((r) => setSessions(r.sessions)).catch(() => undefined); }, []);
  useEffect(() => { if (me) loadSessions(); }, [me, loadSessions]);

  async function act(fn: () => Promise<unknown>, done: string, after?: () => void) {
    setBusy(true); setMsg(null);
    try { await fn(); setMsg({ tone: 'info', text: done }); after?.(); }
    catch (e) { setMsg({ tone: 'error', text: e instanceof ApiError && e.status === 409 ? 'Instagram needs you to reconnect.' : 'That did not work. Please try again.' }); }
    finally { setBusy(false); }
  }

  if (loading) return <Spinner />;
  if (!me) {
    return (
      <Card className="mx-auto max-w-xl text-center">
        <h1 className="font-display text-4xl">You’re not signed in</h1>
        <p className="mt-3 text-sm text-navy-800/75">Signing in is optional. It lets you view your connection, manage sessions and delete your data.</p>
        <a className="btn-primary mt-6" href={loginUrl}>Connect with Instagram</a>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <Card>
        <p className="eyebrow">Connection</p>
        <h1 className="mt-1 font-display text-4xl">@{me.user.username}</h1>
        <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-3">
          <div className="rounded-2xl bg-white/55 p-4"><dt className="text-navy-800/60">Account type</dt><dd className="mt-1 font-bold">{me.user.accountType ?? 'Unknown'}</dd></div>
          <div className="rounded-2xl bg-white/55 p-4"><dt className="text-navy-800/60">Instagram token</dt><dd className="mt-1 font-bold">{me.user.connected ? 'Stored, encrypted' : 'Not stored'}</dd></div>
          <div className="rounded-2xl bg-white/55 p-4"><dt className="text-navy-800/60">Token expires</dt><dd className="mt-1 font-bold">{me.user.tokenExpiresAt ? fmtDate(me.user.tokenExpiresAt) : '—'}</dd></div>
        </dl>
        <div className="mt-5 flex flex-wrap gap-3">
          <button className="btn-ghost" disabled={busy || !me.user.connected} onClick={() => act(async () => setProfile(await api.profile()), 'Fetched live from Instagram. Nothing was saved.')}>Fetch live profile counts</button>
          {me.user.role === 'admin' && <Link className="btn-primary" to="/security">Security dashboard</Link>}
        </div>
        {profile && (
          <p className="mt-4 rounded-2xl bg-white/55 p-4 text-sm">
            Followers <b>{profile.followersCount ?? '—'}</b> · Following <b>{profile.followsCount ?? '—'}</b> · Posts <b>{profile.mediaCount ?? '—'}</b>
            <span className="ml-2 text-navy-800/55">(live from Instagram’s API at {fmtDate(profile.fetchedAt)}; counts only, not lists)</span>
          </p>
        )}
        {msg && <div className="mt-4"><Notice tone={msg.tone}>{msg.text}</Notice></div>}
      </Card>

      <Card>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div><p className="eyebrow">Sessions</p><h2 className="font-display text-3xl">Where you’re signed in</h2></div>
          <button className="btn-ghost" disabled={busy} onClick={() => act(api.logoutAll, 'Signed out everywhere.', () => { clear(); nav('/'); })}>Sign out everywhere</button>
        </div>
        <ul className="mt-4 space-y-2">
          {sessions.map((s) => (
            <li key={s.id} className={`flex flex-wrap items-center justify-between gap-2 rounded-2xl px-4 py-3 text-sm ${s.current ? 'bg-navy-800 text-white' : 'bg-white/55'}`}>
              <span>{s.current ? 'This device' : 'Another session'} · active {fmtDate(s.lastSeenAt)} · expires {fmtDate(s.expiresAt)}</span>
              {!s.current && <button className="rounded-full bg-white px-3 py-1 text-xs font-bold text-navy-800" disabled={busy} onClick={() => act(() => api.revokeSession(s.id), 'Session revoked.', loadSessions)}>Revoke</button>}
            </li>
          ))}
        </ul>
        <div className="mt-4"><button className="btn-ghost" disabled={busy} onClick={() => act(api.logout, 'Signed out.', () => { clear(); nav('/'); })}>Sign out</button></div>
      </Card>

      <Card>
        <p className="eyebrow">Your data</p>
        <h2 className="font-display text-3xl">Disconnect or delete</h2>
        <p className="mt-2 max-w-2xl text-sm text-navy-800/70">MutualX stores only your Instagram user id, username, account type and an encrypted access token. Your follower/following files are never stored.</p>
        <div className="mt-4 flex flex-wrap gap-3">
          <button className="btn-ghost" disabled={busy} onClick={() => act(api.disconnect, 'Disconnected. Your token was destroyed.', () => { clear(); nav('/'); })}>Disconnect Instagram</button>
        </div>
        <div className="mt-6 rounded-2xl border border-rose-500/30 bg-rose-500/5 p-4">
          <label htmlFor="del" className="text-sm font-bold text-rose-800">Delete my account and all stored data</label>
          <p className="mt-1 text-xs text-rose-900/70">Type DELETE to confirm. This cannot be undone.</p>
          <div className="mt-3 flex flex-wrap gap-3">
            <input id="del" value={confirm} onChange={(e) => setConfirm(e.target.value)} maxLength={6} autoComplete="off" className="w-32 rounded-full border border-rose-500/30 bg-white/80 px-4 py-2 text-sm" />
            <button className="btn-danger" disabled={busy || confirm !== 'DELETE'} onClick={() => act(api.deleteAccount, 'Your account and data were deleted.', () => { clear(); void refresh(); nav('/'); })}>Delete everything</button>
          </div>
        </div>
      </Card>
    </div>
  );
}
