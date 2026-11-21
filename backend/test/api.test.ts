import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createProbeEnv, send, type ProbeEnv } from '../src/checks/probe.js';
import { oauthCookieName } from '../src/auth/session.js';
import { testConfig } from './helpers.js';

let env: ProbeEnv;
beforeAll(async () => {
  env = await createProbeEnv(testConfig());
});
afterAll(async () => {
  await env.close();
});

describe('public endpoints', () => {
  it('health reports ok without leaking details', async () => {
    const r = await send(env.base, '/api/health');
    expect(r.status).toBe(200);
    expect(r.json).toEqual({ status: 'ok' });
  });
  it('limitations explicitly say mutuals are unavailable', async () => {
    const r = await send(env.base, '/api/limitations');
    const list = (r.json as { limitations: { id: string; status: string }[] }).limitations;
    expect(list.find((l) => l.id === 'mutuals')?.status).toBe('unavailable');
    expect(list.find((l) => l.id === 'follower_lists')?.status).toBe('unavailable');
  });
});

describe('error handling', () => {
  it('returns generic errors for unknown routes and bad JSON', async () => {
    expect((await send(env.base, '/api/nope')).json).toEqual({ error: 'not_found' });
    const bad = await send(env.base, '/api/me/disconnect', { method: 'POST', body: '{"a":', contentType: 'application/json', origin: env.origin });
    expect(bad.status).toBe(400);
    expect(bad.json).toEqual({ error: 'invalid_json' });
  });
  it('rejects oversized bodies', async () => {
    const r = await send(env.base, '/api/me/disconnect', { method: 'POST', json: { a: 'x'.repeat(20_000) }, origin: env.origin });
    expect(r.status).toBe(413);
  });
  it('does not leak stack traces or file paths', async () => {
    const r = await send(env.base, '/api/me/sessions/not-a-uuid', { method: 'DELETE', cookie: env.users.user.cookie, origin: env.origin, csrf: env.csrf(env.users.user.sessionId) });
    expect(r.status).toBe(400);
    expect(JSON.stringify(r.json)).not.toMatch(/\/home|node_modules|at .*\(/);
  });
});

describe('authenticated flows', () => {
  it('returns the session summary and a CSRF token', async () => {
    const r = await send(env.base, '/api/me', { cookie: env.users.user.cookie });
    expect(r.status).toBe(200);
    const body = r.json as { user: { username: string; role: string }; csrfToken: string };
    expect(body.user.role).toBe('user');
    expect(body.csrfToken).toBe(env.csrf(env.users.user.sessionId));
  });
  it('profile requires reconnection when no token is stored', async () => {
    const r = await send(env.base, '/api/me/profile', { cookie: env.users.user.cookie });
    expect(r.status).toBe(409);
  });
  it('disconnect revokes sessions', async () => {
    const e = await createProbeEnv(testConfig());
    try {
      const u = e.users.user;
      const r = await send(e.base, '/api/me/disconnect', { method: 'POST', cookie: u.cookie, origin: e.origin, csrf: e.csrf(u.sessionId), json: {} });
      expect(r.status).toBe(200);
      expect((await send(e.base, '/api/me', { cookie: u.cookie })).status).toBe(401);
    } finally {
      await e.close();
    }
  });
  it('full OAuth flow (stubbed Meta) creates a hardened session and reads live counts', async () => {
    const e = await createProbeEnv(testConfig());
    try {
      const login = await send(e.base, '/api/auth/instagram/login');
      expect(login.status).toBe(302);
      const state = new URL(login.headers.get('location')!).searchParams.get('state')!;
      const binding = login.setCookies.find((c) => c.startsWith(oauthCookieName(e.config)))!.split(';')[0]!;
      const cb = await send(e.base, `/api/auth/instagram/callback?code=abcdefghij1234&state=${state}`, { cookie: binding });
      expect(cb.status).toBe(302);
      const sid = cb.setCookies.find((c) => c.startsWith('mx_sid='))!;
      expect(sid).toMatch(/HttpOnly/i);
      expect(sid).toMatch(/SameSite=Lax/i);
      const cookie = sid.split(';')[0]!;
      const me = await send(e.base, '/api/me', { cookie });
      expect((me.json as { user: { username: string; connected: boolean } }).user).toMatchObject({ username: 'probe.user', connected: true });
      // The stored token is ciphertext, never the plaintext token.
      const stored = [...e.store.users.values()].find((u) => u.igUserId === '17841400000000001')!;
      expect(stored.tokenCiphertext).toBeTruthy();
      expect(stored.tokenCiphertext).not.toContain('long_');
      // Replay of the single-use state fails.
      const replay = await send(e.base, `/api/auth/instagram/callback?code=abcdefghij1234&state=${state}`, { cookie: binding });
      expect(replay.headers.get('location')).toContain('error=oauth_failed');
    } finally {
      await e.close();
    }
  });
});

describe('abuse protection', () => {
  it('blocks scanner probes and escalates to a temporary block', async () => {
    const e = await createProbeEnv(testConfig());
    try {
      const statuses: number[] = [];
      for (let i = 0; i < 7; i++) statuses.push((await send(e.base, '/wp-admin/setup.php')).status);
      expect(statuses.slice(0, 4).every((s) => s === 404)).toBe(true);
      expect(statuses.at(-1)).toBe(429);
    } finally {
      await e.close();
    }
  });
  it('refuses form-encoded and multipart state-changing requests', async () => {
    const r = await send(env.base, '/api/me/disconnect', { method: 'POST', contentType: 'application/x-www-form-urlencoded', body: 'a=b', origin: env.origin });
    expect(r.status).toBe(415);
  });
});
