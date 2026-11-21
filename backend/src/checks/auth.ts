import path from 'node:path';
import { sha256Hex } from '../security/crypto.js';
import { LIMITS, createRateLimiter } from '../security/rateLimit.js';
import { oauthCookieName, SessionService } from '../auth/session.js';
import { MemoryStore } from '../store/memory.js';
import type { AppConfig } from '../config.js';
import express from 'express';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { CheckDefinition, CheckOutcome } from './types.js';
import { createProbeEnv, dirExists, readTextIfExists, send, walk } from './probe.js';

const cookieValue = (setCookies: string[], name: string) => setCookies.map((c) => c.split(';')[0] ?? '').find((c) => c.startsWith(`${name}=`));

export const authChecks: CheckDefinition[] = [
  {
    id: 6,
    key: 'official_oauth',
    category: 'auth',
    title: 'Official OAuth Authorization',
    severity: 'critical',
    methods: ['config-inspection', 'runtime-probe'],
    async run(ctx): Promise<CheckOutcome> {
      const evidence: string[] = [];
      const problems: string[] = [];
      const real = ctx.config.meta;
      if (real) {
        evidence.push(`META_APP_ID, META_APP_SECRET and META_REDIRECT_URI are configured (redirect: ${real.redirectUri})`);
        if (new URL(real.redirectUri).origin !== ctx.config.apiPublicUrl) problems.push('Redirect URI origin differs from API_PUBLIC_URL');
        if (ctx.config.isProd && !real.redirectUri.startsWith('https://')) problems.push('Redirect URI is not https');
      }

      const env = await createProbeEnv(ctx.config);
      try {
        const cName = oauthCookieName(env.config);
        const login = await send(env.base, '/api/auth/instagram/login');
        const loc = login.headers.get('location') ?? '';
        const target = loc ? new URL(loc) : null;
        if (login.status === 302 && target?.origin === 'https://www.instagram.com' && target.pathname === '/oauth/authorize') evidence.push('Login redirects to https://www.instagram.com/oauth/authorize (official Meta endpoint)');
        else problems.push(`Login did not redirect to Meta's authorize endpoint (HTTP ${login.status})`);
        const state = target?.searchParams.get('state') ?? '';
        const redirectUri = target?.searchParams.get('redirect_uri') ?? '';
        (state.length >= 43 ? evidence : problems).push(`state parameter length ${state.length} (≥43 base64url chars = 256 bits)`);
        (redirectUri === env.config.meta?.redirectUri ? evidence : problems).push('redirect_uri sent to Meta equals the configured, validated URI');
        const binding = cookieValue(login.setCookies, cName);
        (binding && login.setCookies.some((c) => /httponly/i.test(c) && c.startsWith(cName)) ? evidence : problems).push('Browser-binding cookie is set HttpOnly');

        const bad = await send(env.base, `/api/auth/instagram/callback?code=probe-code-1234567890&state=${'A'.repeat(43)}`, { cookie: binding });
        (bad.status === 302 && !cookieValue(bad.setCookies, env.config.isProd ? '__Host-mx_sid' : 'mx_sid') ? evidence : problems).push('Forged state → rejected, no session issued');

        const noBinding = await send(env.base, `/api/auth/instagram/callback?code=probe-code-1234567890&state=${state}`);
        (noBinding.status === 302 && !noBinding.setCookies.some((c) => /mx_sid/.test(c) && !/Max-Age=0|Expires=Thu, 01 Jan 1970/i.test(c)) ? evidence : problems).push('Valid state without the browser-binding cookie (login CSRF) → rejected');

        // The failed attempt above consumed the state (single use). Run a full flow with a fresh login.
        const login2 = await send(env.base, '/api/auth/instagram/login');
        const state2 = new URL(login2.headers.get('location') ?? 'https://x.invalid').searchParams.get('state') ?? '';
        const binding2 = cookieValue(login2.setCookies, cName);
        const good = await send(env.base, `/api/auth/instagram/callback?code=probe-code-1234567890&state=${state2}`, { cookie: binding2 });
        const sid = good.setCookies.find((c) => /mx_sid=/.test(c));
        if (good.status === 302 && sid && /httponly/i.test(sid)) evidence.push('Complete flow (Meta responses stubbed) → HttpOnly session cookie issued');
        else problems.push(`Complete flow did not issue a session (HTTP ${good.status})`);
        const replay = await send(env.base, `/api/auth/instagram/callback?code=probe-code-1234567890&state=${state2}`, { cookie: binding2 });
        (!replay.setCookies.some((c) => /mx_sid=[^;]/.test(c) && !/Max-Age=0|1970/i.test(c)) ? evidence : problems).push('Replayed state → rejected (single use)');
      } finally {
        await env.close();
      }

      if (problems.length) {
        return { status: 'fail', implementation: 'Authorization-code flow against Meta with single-use state, browser binding and strict redirect URI validation.', explanation: `OAuth implementation problems: ${problems.join('; ')}`, evidence: [...evidence, ...problems], remediation: ['Fix the failing flow step before enabling login in production'] };
      }
      if (!real) {
        return {
          status: 'needs_review',
          implementation: 'Authorization-code flow against Meta with single-use state, browser binding and strict redirect URI validation (verified with stubbed Meta responses).',
          explanation: 'The flow logic passes every probe, but Meta credentials are not configured in this environment, so the real handshake with Meta cannot be verified here.',
          evidence,
          remediation: ['Create a Meta app, set META_APP_ID / META_APP_SECRET / META_REDIRECT_URI', 'Register the redirect URI in the Meta app dashboard', 'Run one manual end-to-end login in staging and record the result'],
        };
      }
      return {
        status: 'pass',
        implementation: 'Authorization-code flow against Meta with single-use state, browser binding and strict redirect URI validation.',
        explanation: 'Flow logic verified with stubbed Meta responses and configuration is present. The live handshake with Meta is not exercised by automated checks.',
        evidence,
        remediation: ['Perform a manual end-to-end login after every Meta app or redirect URI change'],
      };
    },
  },
  {
    id: 7,
    key: 'session_security',
    category: 'auth',
    title: 'Session Security',
    severity: 'critical',
    methods: ['runtime-probe', 'config-inspection'],
    async run(ctx): Promise<CheckOutcome> {
      const evidence: string[] = [];
      const problems: string[] = [];
      const c = ctx.config;
      const min = (ms: number) => Math.round(ms / 60_000);
      (min(c.sessionIdleMs) <= 120 ? evidence : problems).push(`Idle timeout ${min(c.sessionIdleMs)} min (limit 120)`);
      (c.sessionAbsoluteMs <= 24 * 3_600_000 ? evidence : problems).push(`Absolute lifetime ${c.sessionAbsoluteMs / 3_600_000} h (limit 24)`);
      (c.sessionRotateMs <= c.sessionIdleMs ? evidence : problems).push(`Token rotation every ${min(c.sessionRotateMs)} min`);

      let clock = new Date('2026-01-01T00:00:00Z');
      const store = new MemoryStore();
      const svc = new SessionService(store, c, () => clock);
      const user = await store.upsertUser({ igUserId: '1', username: 'probe', role: 'user', tokenCiphertext: null, tokenExpiresAt: null, lastLoginAt: clock });

      const a = await svc.create(user.id);
      const rec = [...store.sessions.values()][0];
      (rec && rec.tokenHash === sha256Hex(a.token) && !JSON.stringify([...store.sessions.values()]).includes(a.token) ? evidence : problems).push('Only the SHA-256 of the session token is stored; raw token absent from the store');
      (a.token.length >= 43 ? evidence : problems).push(`Token entropy: ${a.token.length} base64url chars (≥256 bits)`);
      (await svc.authenticate(a.token) ? evidence : problems).push('Fresh session authenticates');

      clock = new Date(clock.getTime() + c.sessionRotateMs + 1000);
      const rotated = await svc.authenticate(a.token);
      if (rotated?.rotatedToken) {
        evidence.push('Token rotated after the rotation interval');
        (await svc.authenticate(rotated.rotatedToken) ? evidence : problems).push('New token valid');
        (await svc.authenticate(a.token) ? evidence : problems).push('Old token still valid inside the 30 s in-flight grace window');
        clock = new Date(clock.getTime() + 31_000);
        (!(await svc.authenticate(a.token)) ? evidence : problems).push('Old token rejected after the grace window (rotation invalidates it)');
      } else problems.push('Token was not rotated after the rotation interval');

      const b = await svc.create(user.id);
      clock = new Date(clock.getTime() + c.sessionIdleMs + 1000);
      (!(await svc.authenticate(b.token)) ? evidence : problems).push('Idle session expires');
      const d = await svc.create(user.id);
      (await svc.revoke([...store.sessions.values()].find((s) => s.tokenHash === sha256Hex(d.token))!.id, user.id) && !(await svc.authenticate(d.token)) ? evidence : problems).push('Revoked session is rejected immediately');
      const e1 = await svc.create(user.id);
      await svc.create(user.id);
      const revoked = await svc.revokeAll(user.id);
      (revoked >= 2 && !(await svc.authenticate(e1.token)) ? evidence : problems).push(`Revoke-all invalidated ${revoked} sessions`);

      return {
        status: problems.length ? 'fail' : 'pass',
        implementation: 'Opaque 256-bit random session tokens (hash-only storage), idle + absolute expiry, periodic rotation with a short grace window, per-session and global revocation, new session on every login.',
        explanation: problems.length ? `Session problems: ${problems.join('; ')}` : 'Session lifecycle verified against a controllable clock.',
        evidence: [...evidence, ...problems],
        remediation: problems.length ? ['Review SessionService and the SESSION_* settings'] : ['Shorten SESSION_IDLE_MINUTES further if your risk appetite is lower'],
      };
    },
  },
  {
    id: 8,
    key: 'passwordless',
    category: 'auth',
    title: 'Passwordless Instagram Connection',
    severity: 'critical',
    methods: ['runtime-probe', 'static-scan'],
    async run(ctx): Promise<CheckOutcome> {
      const evidence: string[] = [];
      const problems: string[] = [];
      const env = await createProbeEnv(ctx.config);
      try {
        for (const field of ['password', 'instagram_password', 'passwd']) {
          const r = await send(env.base, '/api/me/disconnect', { method: 'POST', json: { [field]: 'hunter2' } });
          (r.status === 400 ? evidence : problems).push(`Body field "${field}" → HTTP ${r.status} (expected 400)`);
        }
        const login = await send(env.base, '/api/auth/instagram/login', { method: 'POST', json: { username: 'x', password: 'y' } });
        (login.status !== 200 && login.status !== 302 ? evidence : problems).push(`Credential login via POST → HTTP ${login.status} (no such route)`);
      } finally {
        await env.close();
      }
      const files = walk(ctx.backendSrcDir, ['.ts', '.js']);
      const hits = files.filter((f) => /req\.body\??\.(password|passwd)|type=["']password["']/i.test(readTextIfExists(f) ?? ''));
      (hits.length ? problems : evidence).push(hits.length ? `Password handling found in: ${hits.map((h) => path.basename(h)).join(', ')}` : `No password handling in ${files.length} backend source files`);
      const fe = path.join(ctx.repoRoot, 'frontend', 'src');
      let reviewedFrontend = false;
      if (dirExists(fe)) {
        reviewedFrontend = true;
        const feFiles = walk(fe, ['.ts', '.tsx'], ['node_modules']);
        const pw = feFiles.filter((f) => /type=["']password["']|autoComplete=["'](current|new)-password/i.test(readTextIfExists(f) ?? ''));
        (pw.length ? problems : evidence).push(pw.length ? `Password inputs in frontend: ${pw.map((h) => path.basename(h)).join(', ')}` : 'No password inputs in the frontend');
      }
      return {
        status: problems.length ? 'fail' : reviewedFrontend ? 'pass' : 'needs_review',
        implementation: 'Instagram is connected only through Meta’s OAuth redirect; no endpoint, schema field or form accepts a password, and any request containing a credential-like field is rejected.',
        explanation: problems.length ? `Credential handling detected: ${problems.join('; ')}` : reviewedFrontend ? 'There is no code path that can receive an Instagram password.' : 'Backend verified; frontend sources were unavailable for inspection.',
        evidence: [...evidence, ...problems],
        remediation: problems.length ? ['Remove all credential collection; use the OAuth redirect only'] : reviewedFrontend ? ['Keep the credential-field rejection in sanitize.ts'] : ['Re-run from a full checkout to inspect the frontend'],
      };
    },
  },
  {
    id: 9,
    key: 'rate_limiting',
    category: 'auth',
    title: 'Rate Limiting',
    severity: 'high',
    methods: ['runtime-probe'],
    async run(ctx): Promise<CheckOutcome> {
      const evidence: string[] = [];
      const problems: string[] = [];

      // Limiter behaviour in isolation.
      const app = express();
      app.set('trust proxy', 1);
      app.use(createRateLimiter({ windowMs: 60_000, limit: 3 }, 'probe'));
      app.get('/x', (_q, r) => void r.json({ ok: true }));
      const server = createServer(app);
      await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
      try {
        const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
        const statuses: number[] = [];
        for (let i = 0; i < 5; i++) statuses.push((await send(base, '/x')).status);
        (statuses.join() === '200,200,200,429,429' ? evidence : problems).push(`Limiter of 3 requests → statuses ${statuses.join(', ')}`);
      } finally {
        await new Promise<void>((r) => server.close(() => r()));
      }

      // Real login-abuse protection on the real app.
      const env = await createProbeEnv(ctx.config);
      try {
        const limit = LIMITS.auth.limit;
        let first429 = -1;
        for (let i = 1; i <= limit + 3; i++) {
          const r = await send(env.base, '/api/auth/instagram/callback');
          if (r.status === 429) {
            first429 = i;
            break;
          }
        }
        (first429 === limit + 1 ? evidence : problems).push(`Login/callback endpoints blocked from request #${first429} (configured: ${limit} per ${LIMITS.auth.windowMs / 60_000} min)`);
      } finally {
        await env.close();
      }
      (LIMITS.auth.limit <= 30 ? evidence : problems).push(`Auth limit ${LIMITS.auth.limit}/15 min, sensitive ops ${LIMITS.sensitive.limit}/15 min, global ${LIMITS.global.limit}/min per IP`);

      return {
        status: problems.length ? 'fail' : 'pass',
        implementation: 'express-rate-limit: global per-IP budget, tighter budgets on login/callback and on account-changing endpoints, plus a scanner/probe strike system that temporarily blocks abusive IPs.',
        explanation: problems.length ? `Rate limiting problems: ${problems.join('; ')}` : 'Limiter behaviour verified, including enforcement on the real login endpoints.',
        evidence: [...evidence, ...problems],
        remediation: problems.length ? ['Mount limiters.auth on every authentication route'] : ['Counters are in-memory per instance. If you run more than one instance, switch to a shared store (Redis/Mongo) so limits are global.'],
      };
    },
  },
  {
    id: 10,
    key: 'access_control',
    category: 'auth',
    title: 'Access Control',
    severity: 'critical',
    methods: ['runtime-probe'],
    async run(ctx): Promise<CheckOutcome> {
      const evidence: string[] = [];
      const problems: string[] = [];
      const env = await createProbeEnv(ctx.config);
      const expect = (label: string, got: number, want: number) => (got === want ? evidence : problems).push(`${label} → HTTP ${got} (expected ${want})`);
      try {
        const { user, admin, other } = env.users;
        expect('Anonymous GET /api/me', (await send(env.base, '/api/me')).status, 401);
        expect('Anonymous GET /api/security/checks', (await send(env.base, '/api/security/checks')).status, 401);
        expect('Forged session cookie', (await send(env.base, '/api/me', { cookie: `${user.cookie.split('=')[0]}=${'z'.repeat(43)}` })).status, 401);
        expect('User role GET /api/security/checks', (await send(env.base, '/api/security/checks', { cookie: user.cookie })).status, 403);
        expect('User role GET /api/security/audit', (await send(env.base, '/api/security/audit', { cookie: user.cookie })).status, 403);
        expect('Admin role GET /api/security/audit', (await send(env.base, '/api/security/audit', { cookie: admin.cookie })).status, 200);
        expect('User revoking ANOTHER user’s session', (await send(env.base, `/api/me/sessions/${other.sessionId}`, { method: 'DELETE', cookie: user.cookie, origin: env.origin, csrf: env.csrf(user.sessionId) })).status, 404);
        const stillValid = await send(env.base, '/api/me', { cookie: other.cookie });
        expect('Other user’s session unaffected', stillValid.status, 200);
        const list = (await send(env.base, '/api/me/sessions', { cookie: user.cookie })).json as { sessions?: { id: string }[] };
        (list.sessions?.every((s) => s.id !== other.sessionId) ? evidence : problems).push('Session listing only contains the caller’s own sessions');
      } finally {
        await env.close();
      }
      return {
        status: problems.length ? 'fail' : 'pass',
        implementation: 'Default-deny: every non-public route requires a server-validated session; roles (user < admin) are enforced per route; admin comes only from the ADMIN_IG_USER_IDS allow-list and is re-derived at each login; resources are always scoped to the session’s user.',
        explanation: problems.length ? `Access control failures: ${problems.join('; ')}` : 'Anonymous, forged, wrong-role and cross-user access attempts are all refused.',
        evidence: [...evidence, ...problems],
        remediation: problems.length ? ['Add requireSession/requireRole to the failing routes and scope queries by the session user id'] : ['Keep ADMIN_IG_USER_IDS minimal; review it when staff change'],
      };
    },
  },
];

export type { AppConfig };
