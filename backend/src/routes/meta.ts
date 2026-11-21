import { Router } from 'express';
import { z } from 'zod';
import { AuditEvents } from '../audit/audit.js';
import { verifySignedRequest } from '../auth/meta.js';
import type { Deps } from '../deps.js';
import { randomToken } from '../security/crypto.js';

const body = z.object({ signed_request: z.string().min(10).max(4096) }).strict();

/**
 * Callbacks Meta requires: deauthorize + data deletion. Authenticity is
 * proven by the HMAC `signed_request`, not by cookies, so these routes are
 * exempt from the browser-oriented CSRF/Origin checks.
 */
export function metaRouter(deps: Deps): Router {
  const { config, store, audit, sessions } = deps;
  const r = Router();

  const verify = (raw: unknown) => {
    const parsed = body.safeParse(raw);
    if (!parsed.success || !config.meta) return null;
    return verifySignedRequest(parsed.data.signed_request, config.meta.appSecret);
  };

  r.post('/deauthorize', async (req, res, next) => {
    try {
      const v = verify(req.body);
      if (!v) {
        void audit.record(AuditEvents.metaDeauthorize, 'failure', { ip: req.ip, meta: { reason: 'bad_signature' } });
        res.status(401).json({ error: 'invalid_signature' });
        return;
      }
      const user = await store.getUserByIgId(v.userId);
      if (user) {
        await store.updateUser(user.id, { tokenCiphertext: null, tokenExpiresAt: null });
        await sessions.revokeAll(user.id);
      }
      void audit.record(AuditEvents.metaDeauthorize, 'success', { userId: user?.id, ip: req.ip });
      res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  });

  r.post('/data-deletion', async (req, res, next) => {
    try {
      const v = verify(req.body);
      if (!v) {
        void audit.record(AuditEvents.metaDataDeletion, 'failure', { ip: req.ip, meta: { reason: 'bad_signature' } });
        res.status(401).json({ error: 'invalid_signature' });
        return;
      }
      const user = await store.getUserByIgId(v.userId);
      if (user) await store.deleteUser(user.id);
      const code = randomToken(16);
      void audit.record(AuditEvents.metaDataDeletion, 'success', { userId: user?.id, ip: req.ip });
      const u = new URL(config.frontendUrl);
      u.hash = `/deletion?code=${code}`;
      res.json({ url: u.toString(), confirmation_code: code });
    } catch (err) {
      next(err);
    }
  });

  return r;
}
