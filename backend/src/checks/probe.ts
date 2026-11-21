import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { pino } from 'pino';
import { AuditLogger } from '../audit/audit.js';
import { sessionCookieName, SessionService } from '../auth/session.js';
import { createApp } from '../app.js';
import type { AppConfig } from '../config.js';
import type { Deps } from '../deps.js';
import { csrfTokenFor } from '../security/csrf.js';
import { MemoryStore } from '../store/memory.js';

/** Fake Meta credentials used only inside probe apps when the real config has none. */
export const PROBE_META = {
  appId: '1234567890',
  appSecret: 'probe-app-secret-0123456789abcdef0123456789',
  redirectUri: '', // filled per config
  scopes: 'instagram_business_basic',
};

const metaStub: typeof fetch = async (input) => {
  const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url);
  const json = (b: unknown) => new Response(JSON.stringify(b), { status: 200, headers: { 'content-type': 'application/json' } });
  if (url.hostname === 'api.instagram.com' && url.pathname === '/oauth/access_token') return json({ access_token: `short_${'x'.repeat(30)}` });
  if (url.hostname === 'graph.instagram.com' && url.pathname === '/access_token') return json({ access_token: `long_${'y'.repeat(40)}`, expires_in: 5_184_000 });
  if (url.hostname === 'graph.instagram.com' && url.pathname === '/me') return json({ user_id: '17841400000000001', username: 'probe.user', account_type: 'BUSINESS' });
  return new Response('{}', { status: 404 });
};

export interface ProbeEnv {
  base: string;
  origin: string;
  config: AppConfig;
  deps: Deps;
  store: MemoryStore;
  users: { user: { id: string; cookie: string; sessionId: string }; admin: { id: string; cookie: string; sessionId: string }; other: { id: string; cookie: string; sessionId: string } };
  csrf(sessionId: string): string;
  close(): Promise<void>;
}

/**
 * Boots the *real* Express app (same middleware stack, same config) against an
 * in-memory store on an ephemeral localhost port. Probes therefore exercise
 * actual code paths, but never touch production data.
 */
export async function createProbeEnv(config: AppConfig, overrides: Partial<AppConfig> = {}): Promise<ProbeEnv> {
  const probeConfig: AppConfig = {
    ...config,
    trustProxy: 1,
    ...overrides,
    meta: overrides.meta ?? config.meta ?? { ...PROBE_META, redirectUri: `${config.apiPublicUrl}/api/auth/instagram/callback` },
  };
  const store = new MemoryStore();
  const logger = pino({ level: 'silent' });
  const audit = new AuditLogger(store, logger, probeConfig.sessionSecret);
  const sessions = new SessionService(store, probeConfig);
  const deps: Deps = {
    config: probeConfig,
    store,
    audit,
    logger,
    sessions,
    fetchImpl: metaStub,
    resolver: async () => ['93.184.216.34'],
  };
  const app = createApp(deps);
  const server: Server = createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  const cookieName = sessionCookieName(probeConfig);
  const seed = async (igUserId: string, username: string, role: 'user' | 'admin') => {
    const u = await store.upsertUser({ igUserId, username, role, tokenCiphertext: null, tokenExpiresAt: null, lastLoginAt: new Date() });
    const { token, record } = await sessions.create(u.id, { ip: '203.0.113.7', ua: 'probe' });
    return { id: u.id, cookie: `${cookieName}=${token}`, sessionId: record.id };
  };
  const users = {
    user: await seed('1001', 'probe.user', 'user'),
    admin: await seed('1002', 'probe.admin', 'admin'),
    other: await seed('1003', 'probe.other', 'user'),
  };

  return {
    base,
    origin: probeConfig.frontendOrigin,
    config: probeConfig,
    deps,
    store,
    users,
    csrf: (sessionId) => csrfTokenFor(probeConfig, sessionId),
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

export interface ProbeResponse {
  status: number;
  headers: Headers;
  setCookies: string[];
  json: unknown;
}

export async function send(
  base: string,
  pathname: string,
  opts: { method?: string; headers?: Record<string, string>; body?: string; cookie?: string; origin?: string; csrf?: string; json?: unknown; contentType?: string } = {},
): Promise<ProbeResponse> {
  const headers: Record<string, string> = { ...opts.headers };
  if (opts.cookie) headers.cookie = opts.cookie;
  if (opts.origin) headers.origin = opts.origin;
  if (opts.csrf) headers['x-csrf-token'] = opts.csrf;
  let body = opts.body;
  if (opts.json !== undefined) {
    body = JSON.stringify(opts.json);
    headers['content-type'] = 'application/json';
  }
  if (opts.contentType) headers['content-type'] = opts.contentType;
  const res = await fetch(`${base}${pathname}`, { method: opts.method ?? 'GET', headers, body, redirect: 'manual' });
  const text = await res.text();
  let json: unknown = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return { status: res.status, headers: res.headers, setCookies: res.headers.getSetCookie(), json };
}

/* ---------- filesystem helpers for static scans ---------- */

export function readTextIfExists(file: string): string | null {
  try {
    return readFileSync(file, 'utf8');
  } catch {
    return null;
  }
}

export function dirExists(dir: string): boolean {
  try {
    return statSync(dir).isDirectory();
  } catch {
    return false;
  }
}

export function walk(dir: string, exts: string[], skip: string[] = ['node_modules', 'dist', '.git', 'checks']): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    if (skip.includes(name)) continue;
    const full = path.join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) out.push(...walk(full, exts, skip));
    else if (exts.includes(path.extname(name))) out.push(full);
  }
  return out;
}
