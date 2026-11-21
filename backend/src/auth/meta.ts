import { z } from 'zod';
import type { AppConfig } from '../config.js';
import type { Deps } from '../deps.js';
import { hmacBase64Url, safeEqual } from '../security/crypto.js';
import { safeFetch, UpstreamError } from '../security/ssrf.js';

/**
 * Instagram API with Instagram Login (Meta). Endpoint paths follow Meta's
 * documentation at the time of writing — re-verify them against
 * https://developers.facebook.com/docs/instagram-platform before launch.
 */
const AUTHORIZE_URL = 'https://www.instagram.com/oauth/authorize';
const TOKEN_URL = 'https://api.instagram.com/oauth/access_token';
const GRAPH = 'https://graph.instagram.com';

type MetaConfig = NonNullable<AppConfig['meta']>;

export function buildAuthorizeUrl(meta: MetaConfig, state: string): string {
  const u = new URL(AUTHORIZE_URL);
  u.searchParams.set('client_id', meta.appId);
  u.searchParams.set('redirect_uri', meta.redirectUri);
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('scope', meta.scopes);
  u.searchParams.set('state', state);
  return u.toString();
}

const shortTokenSchema = z.object({ access_token: z.string().min(10).max(1024) });
const longTokenSchema = z.object({ access_token: z.string().min(10).max(1024), expires_in: z.number().int().positive() });
const idSchema = z.union([z.string().regex(/^\d{1,32}$/), z.number().int().positive()]).transform(String);
const profileSchema = z.object({
  user_id: idSchema,
  username: z.string().regex(/^[A-Za-z0-9._]{1,64}$/),
  account_type: z.enum(['BUSINESS', 'MEDIA_CREATOR', 'PERSONAL']).optional(),
});
const countsSchema = z.object({
  username: z.string().regex(/^[A-Za-z0-9._]{1,64}$/),
  account_type: z.string().max(32).optional(),
  followers_count: z.number().int().nonnegative().optional(),
  follows_count: z.number().int().nonnegative().optional(),
  media_count: z.number().int().nonnegative().optional(),
});

function fetchOpts(deps: Deps) {
  return { fetchImpl: deps.fetchImpl, resolver: deps.resolver };
}

export class MetaAuthError extends Error {
  constructor(public readonly kind: 'rejected' | 'unavailable' | 'bad_response') {
    super(`meta auth error: ${kind}`);
  }
}

async function call(deps: Deps, url: string, init: Parameters<typeof safeFetch>[1] = {}) {
  try {
    const res = await safeFetch(url, { ...fetchOpts(deps), ...init });
    if (res.status >= 400 && res.status < 500) throw new MetaAuthError('rejected');
    if (res.status >= 500) throw new MetaAuthError('unavailable');
    return res.json;
  } catch (err) {
    if (err instanceof MetaAuthError) throw err;
    if (err instanceof UpstreamError) throw new MetaAuthError('unavailable');
    throw err;
  }
}

export async function exchangeCodeForToken(deps: Deps, meta: MetaConfig, code: string): Promise<string> {
  const body = new URLSearchParams({
    client_id: meta.appId,
    client_secret: meta.appSecret,
    grant_type: 'authorization_code',
    redirect_uri: meta.redirectUri,
    code,
  });
  const json = await call(deps, TOKEN_URL, { method: 'POST', body });
  const parsed = shortTokenSchema.safeParse(json);
  if (!parsed.success) throw new MetaAuthError('bad_response');
  return parsed.data.access_token;
}

export async function exchangeForLongLivedToken(deps: Deps, meta: MetaConfig, shortToken: string): Promise<{ token: string; expiresAt: Date }> {
  const u = new URL(`${GRAPH}/access_token`);
  u.searchParams.set('grant_type', 'ig_exchange_token');
  u.searchParams.set('client_secret', meta.appSecret);
  u.searchParams.set('access_token', shortToken);
  const json = await call(deps, u.toString());
  const parsed = longTokenSchema.safeParse(json);
  if (!parsed.success) throw new MetaAuthError('bad_response');
  const now = deps.now?.() ?? new Date();
  return { token: parsed.data.access_token, expiresAt: new Date(now.getTime() + parsed.data.expires_in * 1000) };
}

export async function fetchIdentity(deps: Deps, token: string) {
  const u = new URL(`${GRAPH}/me`);
  u.searchParams.set('fields', 'user_id,username,account_type');
  const json = await call(deps, u.toString(), { headers: { authorization: `Bearer ${token}` } });
  const parsed = profileSchema.safeParse(json);
  if (!parsed.success) throw new MetaAuthError('bad_response');
  return { igUserId: parsed.data.user_id, username: parsed.data.username, accountType: parsed.data.account_type };
}

/** Counts are the only follower-related data the official API exposes. */
export async function fetchProfileCounts(deps: Deps, token: string) {
  const u = new URL(`${GRAPH}/me`);
  u.searchParams.set('fields', 'username,account_type,followers_count,follows_count,media_count');
  const json = await call(deps, u.toString(), { headers: { authorization: `Bearer ${token}` } });
  const parsed = countsSchema.safeParse(json);
  if (!parsed.success) throw new MetaAuthError('bad_response');
  return parsed.data;
}

/**
 * Verifies Meta's `signed_request` (deauthorize / data-deletion callbacks):
 * `base64url(HMAC-SHA256(payload, appSecret)) . base64url(payload)`.
 */
export function verifySignedRequest(signedRequest: string, appSecret: string): { userId: string } | null {
  const parts = signedRequest.split('.');
  if (parts.length !== 2) return null;
  const [sig, payload] = parts as [string, string];
  if (!safeEqual(sig, hmacBase64Url(appSecret, payload))) return null;
  try {
    const data = z
      .object({ user_id: idSchema, algorithm: z.string().regex(/^HMAC-SHA256$/i).optional() })
      .parse(JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')));
    return { userId: data.user_id };
  } catch {
    return null;
  }
}
