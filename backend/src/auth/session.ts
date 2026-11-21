import type { CookieOptions, Response } from 'express';
import { randomUUID } from 'node:crypto';
import type { AppConfig } from '../config.js';
import { hmacBase64Url, randomToken, sha256Hex } from '../security/crypto.js';
import type { SessionRecord, Store, UserRecord } from '../store/types.js';

export const SESSION_COOKIE_DEV = 'mx_sid';
/** `__Host-` prefix: browser enforces Secure, Path=/ and no Domain attribute. */
export const SESSION_COOKIE_PROD = '__Host-mx_sid';
export const OAUTH_COOKIE_DEV = 'mx_oauth';
export const OAUTH_COOKIE_PROD = '__Host-mx_oauth';

export const sessionCookieName = (c: AppConfig) => (c.isProd ? SESSION_COOKIE_PROD : SESSION_COOKIE_DEV);
export const oauthCookieName = (c: AppConfig) => (c.isProd ? OAUTH_COOKIE_PROD : OAUTH_COOKIE_DEV);

export function sessionCookieOptions(config: AppConfig, expires?: Date): CookieOptions {
  return {
    httpOnly: true,
    secure: config.isProd,
    sameSite: config.cookieSameSite,
    path: '/',
    expires,
  };
}

/** The OAuth binding cookie must be Lax so it survives the top-level redirect back from Meta. */
export function oauthCookieOptions(config: AppConfig): CookieOptions {
  return { httpOnly: true, secure: config.isProd, sameSite: 'lax', path: '/', maxAge: 10 * 60_000 };
}

export function setSessionCookie(res: Response, config: AppConfig, token: string, expires: Date): void {
  res.cookie(sessionCookieName(config), token, sessionCookieOptions(config, expires));
}

export function clearSessionCookie(res: Response, config: AppConfig): void {
  const { expires: _e, ...opts } = sessionCookieOptions(config);
  res.clearCookie(sessionCookieName(config), opts);
}

export interface AuthContext {
  session: SessionRecord;
  user: UserRecord;
  /** Set when the token was rotated; the caller must send it as the new cookie. */
  rotatedToken?: string;
}

export class SessionService {
  constructor(
    private store: Store,
    private config: AppConfig,
    private now: () => Date = () => new Date(),
  ) {}

  /** Keyed hash of a client attribute — raw IPs / UAs are never persisted. */
  fingerprint(label: string, value: string | undefined): string | undefined {
    return value ? hmacBase64Url(this.config.sessionSecret, `${label}:${value}`).slice(0, 22) : undefined;
  }

  async create(userId: string, meta: { ip?: string; ua?: string } = {}): Promise<{ token: string; record: SessionRecord }> {
    const now = this.now();
    const token = randomToken(32); // 256 bits of entropy
    const record: SessionRecord = {
      id: randomUUID(),
      tokenHash: sha256Hex(token),
      userId,
      createdAt: now,
      lastSeenAt: now,
      rotatedAt: now,
      expiresAt: new Date(now.getTime() + this.config.sessionAbsoluteMs),
      ipHash: this.fingerprint('ip', meta.ip),
      uaHash: this.fingerprint('ua', meta.ua),
    };
    await this.store.createSession(record);
    return { token, record };
  }

  async authenticate(token: string | undefined): Promise<AuthContext | null> {
    if (!token || token.length < 32 || token.length > 128) return null;
    const now = this.now();
    const session = await this.store.findSessionByTokenHash(sha256Hex(token), now);
    if (!session || session.revokedAt) return null;
    if (session.expiresAt <= now || now.getTime() - session.lastSeenAt.getTime() > this.config.sessionIdleMs) {
      await this.store.updateSession(session.id, { revokedAt: now });
      return null;
    }
    const user = await this.store.getUserById(session.userId);
    if (!user) return null;

    const patch: Partial<SessionRecord> = {};
    let rotatedToken: string | undefined;
    if (now.getTime() - session.rotatedAt.getTime() > this.config.sessionRotateMs) {
      rotatedToken = randomToken(32);
      patch.tokenHash = sha256Hex(rotatedToken);
      patch.prevTokenHash = session.tokenHash;
      patch.prevValidUntil = new Date(now.getTime() + 30_000); // grace for in-flight requests
      patch.rotatedAt = now;
    }
    if (now.getTime() - session.lastSeenAt.getTime() > 60_000 || rotatedToken) patch.lastSeenAt = now;
    if (Object.keys(patch).length) await this.store.updateSession(session.id, patch);

    return { session: { ...session, ...patch }, user, rotatedToken };
  }

  revoke(sessionId: string, userId: string): Promise<boolean> {
    return this.store.revokeSession(sessionId, userId, this.now());
  }

  revokeAll(userId: string, exceptId?: string): Promise<number> {
    return this.store.revokeAllSessions(userId, this.now(), exceptId);
  }
}
