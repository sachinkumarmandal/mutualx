import { z } from 'zod';

/** Heuristics for secrets that must never be used in production. */
const WEAK_PATTERN = /(changeme|change-me|change_me|default|password|example|your[-_]?secret|replace|placeholder|secret123|letmein|admin123)/i;

export function isWeakSecret(value: string): boolean {
  if (value.length < 32) return true;
  if (WEAK_PATTERN.test(value)) return true;
  // Very low character diversity (e.g. "aaaaaaaa...") indicates a placeholder.
  return new Set(value).size < 10;
}

export interface EncryptionKey {
  id: string;
  key: Buffer;
}

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(8080),
  /** Full public URL of the frontend (may include a path such as /mutualx/). */
  FRONTEND_URL: z.url(),
  /** Public base URL of this API (used to validate the OAuth redirect URI). */
  API_PUBLIC_URL: z.url(),
  MONGODB_URI: z.string().min(1).optional(),
  SESSION_SECRET: z.string().min(32),
  /** "keyId:base64Key,olderKeyId:base64Key" — first entry encrypts, all entries decrypt. */
  ENCRYPTION_KEYS: z.string().min(1),
  META_APP_ID: z.string().regex(/^\d{5,32}$/).optional(),
  META_APP_SECRET: z.string().min(16).optional(),
  META_REDIRECT_URI: z.url().optional(),
  META_SCOPES: z.string().regex(/^[a-z_,]+$/).default('instagram_business_basic'),
  /** Comma separated Instagram user ids that receive the admin role. */
  ADMIN_IG_USER_IDS: z.string().regex(/^[0-9,\s]*$/).default(''),
  COOKIE_SAMESITE: z.enum(['strict', 'lax', 'none']).default('lax'),
  SESSION_IDLE_MINUTES: z.coerce.number().int().min(1).max(240).default(30),
  SESSION_ABSOLUTE_HOURS: z.coerce.number().int().min(1).max(72).default(8),
  SESSION_ROTATE_MINUTES: z.coerce.number().int().min(1).max(120).default(15),
  AUDIT_RETENTION_DAYS: z.coerce.number().int().min(7).max(730).default(90),
  TRUST_PROXY: z.coerce.number().int().min(0).max(5).default(1),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'silent']).default('info'),
});

export interface AppConfig {
  env: 'development' | 'test' | 'production';
  isProd: boolean;
  port: number;
  frontendUrl: string;
  frontendOrigin: string;
  apiPublicUrl: string;
  mongoUri?: string;
  sessionSecret: string;
  encryptionKeys: EncryptionKey[];
  meta?: { appId: string; appSecret: string; redirectUri: string; scopes: string };
  adminIgUserIds: Set<string>;
  cookieSameSite: 'strict' | 'lax' | 'none';
  sessionIdleMs: number;
  sessionAbsoluteMs: number;
  sessionRotateMs: number;
  auditRetentionDays: number;
  trustProxy: number;
  logLevel: string;
}

export class ConfigError extends Error {
  constructor(public readonly problems: string[]) {
    super(`Invalid configuration:\n - ${problems.join('\n - ')}`);
    this.name = 'ConfigError';
  }
}

export function parseEncryptionKeys(raw: string): EncryptionKey[] {
  const keys: EncryptionKey[] = [];
  for (const part of raw.split(',')) {
    const [id, b64, ...rest] = part.trim().split(':');
    if (!id || !b64 || rest.length > 0 || !/^[A-Za-z0-9_-]{1,16}$/.test(id)) {
      throw new ConfigError(['ENCRYPTION_KEYS entries must look like "keyId:base64Key"']);
    }
    const key = Buffer.from(b64, 'base64');
    if (key.length !== 32) throw new ConfigError([`ENCRYPTION_KEYS key "${id}" must decode to exactly 32 bytes`]);
    keys.push({ id, key });
  }
  if (keys.length === 0) throw new ConfigError(['ENCRYPTION_KEYS must contain at least one key']);
  if (new Set(keys.map((k) => k.id)).size !== keys.length) throw new ConfigError(['ENCRYPTION_KEYS ids must be unique']);
  return keys;
}

/**
 * Validates and normalises environment variables. Error messages never include
 * the offending values so secrets cannot leak into logs.
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = envSchema.safeParse(env);
  if (!parsed.success) {
    throw new ConfigError(parsed.error.issues.map((i) => `${i.path.join('.') || 'env'}: ${i.message}`));
  }
  const e = parsed.data;
  const isProd = e.NODE_ENV === 'production';
  const problems: string[] = [];

  const frontend = new URL(e.FRONTEND_URL);
  const api = new URL(e.API_PUBLIC_URL);
  const encryptionKeys = parseEncryptionKeys(e.ENCRYPTION_KEYS);

  const metaVars = [e.META_APP_ID, e.META_APP_SECRET, e.META_REDIRECT_URI];
  const metaCount = metaVars.filter(Boolean).length;
  if (metaCount > 0 && metaCount < 3) problems.push('META_APP_ID, META_APP_SECRET and META_REDIRECT_URI must be set together');

  if (e.META_REDIRECT_URI) {
    const redirect = new URL(e.META_REDIRECT_URI);
    if (redirect.origin !== api.origin || redirect.pathname !== '/api/auth/instagram/callback') {
      problems.push('META_REDIRECT_URI must be API_PUBLIC_URL + /api/auth/instagram/callback');
    }
    if (redirect.search || redirect.hash) problems.push('META_REDIRECT_URI must not contain a query or fragment');
  }

  if (e.COOKIE_SAMESITE === 'none' && !isProd) {
    problems.push('COOKIE_SAMESITE=none requires HTTPS and is only allowed in production');
  }

  if (isProd) {
    if (frontend.protocol !== 'https:') problems.push('FRONTEND_URL must use https in production');
    if (api.protocol !== 'https:') problems.push('API_PUBLIC_URL must use https in production');
    if (!e.MONGODB_URI) problems.push('MONGODB_URI is required in production');
    else if (!/^mongodb(\+srv)?:\/\//.test(e.MONGODB_URI)) problems.push('MONGODB_URI must be a mongodb:// or mongodb+srv:// URI');
    else if (e.MONGODB_URI.startsWith('mongodb://') && /[?&]tls=false/i.test(e.MONGODB_URI)) problems.push('MONGODB_URI must not disable TLS');
    if (isWeakSecret(e.SESSION_SECRET)) problems.push('SESSION_SECRET is weak or a placeholder');
    if (e.COOKIE_SAMESITE === 'none') problems.push('COOKIE_SAMESITE=none is not allowed; use a shared parent domain with lax/strict');
    if (!metaCount) problems.push('META_APP_ID, META_APP_SECRET and META_REDIRECT_URI are required in production');
  }

  if (problems.length) throw new ConfigError(problems);

  return {
    env: e.NODE_ENV,
    isProd,
    port: e.PORT,
    frontendUrl: frontend.toString(),
    frontendOrigin: frontend.origin,
    apiPublicUrl: api.origin,
    mongoUri: e.MONGODB_URI,
    sessionSecret: e.SESSION_SECRET,
    encryptionKeys,
    meta:
      e.META_APP_ID && e.META_APP_SECRET && e.META_REDIRECT_URI
        ? { appId: e.META_APP_ID, appSecret: e.META_APP_SECRET, redirectUri: e.META_REDIRECT_URI, scopes: e.META_SCOPES }
        : undefined,
    adminIgUserIds: new Set(e.ADMIN_IG_USER_IDS.split(',').map((s) => s.trim()).filter(Boolean)),
    cookieSameSite: e.COOKIE_SAMESITE,
    sessionIdleMs: e.SESSION_IDLE_MINUTES * 60_000,
    sessionAbsoluteMs: e.SESSION_ABSOLUTE_HOURS * 3_600_000,
    sessionRotateMs: e.SESSION_ROTATE_MINUTES * 60_000,
    auditRetentionDays: e.AUDIT_RETENTION_DAYS,
    trustProxy: e.TRUST_PROXY,
    logLevel: e.LOG_LEVEL,
  };
}
