import { Router, type Response } from 'express';
import { z } from 'zod';
import { AuditEvents } from '../audit/audit.js';
import { buildAuthorizeUrl, exchangeCodeForToken, exchangeForLongLivedToken, fetchIdentity, MetaAuthError } from '../auth/meta.js';
import { clearSessionCookie, oauthCookieName, oauthCookieOptions, setSessionCookie } from '../auth/session.js';
import type { Deps } from '../deps.js';
import { requireSession } from '../middleware/auth.js';
import { encrypt, randomToken, safeEqual, sha256Hex } from '../security/crypto.js';
import { requireCsrf } from '../security/csrf.js';
import { AppError } from '../security/errors.js';
import type { createLimiters } from '../security/rateLimit.js';

const callbackQuery = z
  .object({
    code: z.string().regex(/^[A-Za-z0-9_.~-]{10,700}$/).optional(),
    state: z.string().regex(/^[A-Za-z0-9_-]{43}$/).optional(),
    error: z.string().max(64).optional(),
    error_reason: z.string().max(64).optional(),
    error_description: z.string().max(256).optional(),
  })
  .strict();

function frontendRedirect(deps: Deps, hash: string): string {
  const u = new URL(deps.config.frontendUrl);
  u.hash = hash;
  return u.toString();
}

export function authRouter(deps: Deps, limiters: ReturnType<typeof createLimiters>): Router {
  const { config, store, audit, sessions } = deps;
  const r = Router();

  /** Step 1: create single-use, browser-bound `state` and send the user to Instagram. */
  r.get('/instagram/login', limiters.auth, async (req, res, next) => {
    try {
      if (!config.meta) throw new AppError(503, 'oauth_not_configured');
      const state = randomToken(32);
      const binding = randomToken(32);
      const now = deps.now?.() ?? new Date();
      await store.saveOAuthState({
        stateHash: sha256Hex(state),
        bindingHash: sha256Hex(binding),
        createdAt: now,
        expiresAt: new Date(now.getTime() + 10 * 60_000),
      });
      res.cookie(oauthCookieName(config), binding, oauthCookieOptions(config));
      void audit.record(AuditEvents.loginStarted, 'success', { ip: req.ip });
      res.redirect(302, buildAuthorizeUrl(config.meta, state));
    } catch (err) {
      next(err);
    }
  });

  /** Step 2: validate state + binding, exchange the code, create a session. */
  r.get('/instagram/callback', limiters.auth, async (req, res, next) => {
    const failure = (reason: string) => {
      res.clearCookie(oauthCookieName(config), { ...oauthCookieOptions(config), maxAge: undefined });
      void audit.record(AuditEvents.loginFailure, 'failure', { ip: req.ip, meta: { reason } });
      res.redirect(302, frontendRedirect(deps, '/login?error=oauth_failed'));
    };
    try {
      if (!config.meta) return void failure('not_configured');
      const q = callbackQuery.safeParse(req.query);
      if (!q.success || q.data.error || !q.data.code || !q.data.state) return void failure('bad_callback');

      const binding = req.cookies?.[oauthCookieName(config)] as string | undefined;
      const record = await store.consumeOAuthState(sha256Hex(q.data.state), deps.now?.() ?? new Date()); // single use
      if (!record || typeof binding !== 'string' || !safeEqual(sha256Hex(binding), record.bindingHash)) return void failure('state_mismatch');

      let identity;
      let longLived;
      try {
        const shortToken = await exchangeCodeForToken(deps, config.meta, q.data.code);
        longLived = await exchangeForLongLivedToken(deps, config.meta, shortToken);
        identity = await fetchIdentity(deps, longLived.token);
      } catch (err) {
        if (err instanceof MetaAuthError) return void failure(err.kind);
        throw err;
      }

      const now = deps.now?.() ?? new Date();
      const user = await store.upsertUser({
        igUserId: identity.igUserId,
        username: identity.username,
        accountType: identity.accountType,
        role: config.adminIgUserIds.has(identity.igUserId) ? 'admin' : 'user', // re-derived on every login
        tokenCiphertext: null,
        tokenExpiresAt: longLived.expiresAt,
        lastLoginAt: now,
      });
      await store.updateUser(user.id, { tokenCiphertext: encrypt(longLived.token, config.encryptionKeys, `ig-token:${user.id}`) });

      // New session on every login (fixation protection): old sessions of this user stay valid but are independent.
      const { token, record: sessionRecord } = await sessions.create(user.id, { ip: req.ip, ua: req.get('user-agent') });
      res.clearCookie(oauthCookieName(config), { ...oauthCookieOptions(config), maxAge: undefined });
      setSessionCookie(res, config, token, sessionRecord.expiresAt);
      void audit.record(AuditEvents.loginSuccess, 'success', { userId: user.id, ip: req.ip });
      res.redirect(302, frontendRedirect(deps, '/dashboard'));
    } catch (err) {
      next(err);
    }
  });

  const authed = [requireSession(deps), requireCsrf(config, audit)];

  r.post('/logout', ...authed, async (req, res, next) => {
    try {
      await sessions.revoke(req.auth!.session.id, req.auth!.user.id);
      clearSessionCookie(res, config);
      void audit.record(AuditEvents.logout, 'success', { userId: req.auth!.user.id, ip: req.ip });
      res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  });

  r.post('/logout-all', ...authed, async (req, res, next) => {
    try {
      const n = await sessions.revokeAll(req.auth!.user.id);
      clearSessionCookie(res, config);
      void audit.record(AuditEvents.logoutAll, 'success', { userId: req.auth!.user.id, ip: req.ip, meta: { revoked: n } });
      res.json({ ok: true, revoked: n });
    } catch (err) {
      next(err);
    }
  });

  return r;
}

export type { Response };
