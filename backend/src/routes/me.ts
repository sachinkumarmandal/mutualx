import { Router } from 'express';
import { z } from 'zod';
import { AuditEvents } from '../audit/audit.js';
import { fetchProfileCounts, MetaAuthError } from '../auth/meta.js';
import { clearSessionCookie } from '../auth/session.js';
import type { Deps } from '../deps.js';
import { requireSession } from '../middleware/auth.js';
import { decrypt } from '../security/crypto.js';
import { csrfTokenFor, requireCsrf } from '../security/csrf.js';
import { AppError } from '../security/errors.js';
import type { createLimiters } from '../security/rateLimit.js';

const sessionIdParam = z.object({ id: z.uuid() }).strict();

export function meRouter(deps: Deps, limiters: ReturnType<typeof createLimiters>): Router {
  const { config, store, audit, sessions } = deps;
  const r = Router();
  r.use(requireSession(deps));

  r.get('/', (req, res) => {
    const { user, session } = req.auth!;
    res.json({
      user: {
        username: user.username,
        accountType: user.accountType ?? null,
        role: user.role,
        connected: Boolean(user.tokenCiphertext),
        tokenExpiresAt: user.tokenExpiresAt?.toISOString() ?? null,
      },
      session: { expiresAt: session.expiresAt.toISOString() },
      csrfToken: csrfTokenFor(config, session.id), // kept in memory by the SPA, never persisted
    });
  });

  /** Live data from the official API; nothing returned here is persisted. */
  r.get('/profile', async (req, res, next) => {
    try {
      const { user } = req.auth!;
      if (!user.tokenCiphertext) throw new AppError(409, 'reconnect_required');
      try {
        const token = decrypt(user.tokenCiphertext, config.encryptionKeys, `ig-token:${user.id}`);
        const p = await fetchProfileCounts(deps, token);
        res.json({
          source: 'instagram_api',
          fetchedAt: (deps.now?.() ?? new Date()).toISOString(),
          username: p.username,
          accountType: p.account_type ?? null,
          followersCount: p.followers_count ?? null,
          followsCount: p.follows_count ?? null,
          mediaCount: p.media_count ?? null,
        });
      } catch (err) {
        if (err instanceof MetaAuthError && err.kind === 'rejected') throw new AppError(409, 'reconnect_required');
        if (err instanceof MetaAuthError) throw new AppError(502, 'instagram_unavailable');
        throw err;
      }
    } catch (err) {
      next(err);
    }
  });

  r.get('/sessions', async (req, res, next) => {
    try {
      const list = await store.listSessions(req.auth!.user.id, deps.now?.() ?? new Date());
      res.json({
        sessions: list.map((s) => ({
          id: s.id,
          createdAt: s.createdAt.toISOString(),
          lastSeenAt: s.lastSeenAt.toISOString(),
          expiresAt: s.expiresAt.toISOString(),
          current: s.id === req.auth!.session.id,
        })),
      });
    } catch (err) {
      next(err);
    }
  });

  r.delete('/sessions/:id', requireCsrf(config, audit), async (req, res, next) => {
    try {
      const { id } = sessionIdParam.parse(req.params);
      // Scoped by userId: users can only revoke their own sessions.
      const ok = await sessions.revoke(id, req.auth!.user.id);
      if (!ok) throw new AppError(404, 'not_found');
      void audit.record(AuditEvents.sessionRevoked, 'success', { userId: req.auth!.user.id, ip: req.ip });
      if (id === req.auth!.session.id) clearSessionCookie(res, config);
      res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  });

  /** Disconnect: destroy the stored Instagram token and every session. The account record can be deleted separately. */
  r.post('/disconnect', limiters.sensitive, requireCsrf(config, audit), async (req, res, next) => {
    try {
      const { user } = req.auth!;
      await store.updateUser(user.id, { tokenCiphertext: null, tokenExpiresAt: null });
      await sessions.revokeAll(user.id);
      clearSessionCookie(res, config);
      void audit.record(AuditEvents.accountDisconnected, 'success', { userId: user.id, ip: req.ip });
      res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  });

  /** User-requested erasure: removes the user record, token and sessions. */
  r.delete('/', limiters.sensitive, requireCsrf(config, audit), async (req, res, next) => {
    try {
      const { user } = req.auth!;
      await store.deleteUser(user.id);
      clearSessionCookie(res, config);
      void audit.record(AuditEvents.accountDeleted, 'success', { userId: user.id, ip: req.ip });
      res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  });

  return r;
}
