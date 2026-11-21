import type { RequestHandler } from 'express';
import { AuditEvents } from '../audit/audit.js';
import { sessionCookieName, setSessionCookie, clearSessionCookie } from '../auth/session.js';
import type { Deps } from '../deps.js';
import type { Role } from '../store/types.js';

/** Zero-trust: every protected route re-validates the session against the store on each request. */
export function requireSession(deps: Deps): RequestHandler {
  return async (req, res, next) => {
    try {
      const token = req.cookies?.[sessionCookieName(deps.config)] as string | undefined;
      const ctx = await deps.sessions.authenticate(typeof token === 'string' ? token : undefined);
      if (!ctx) {
        if (token) clearSessionCookie(res, deps.config);
        void deps.audit.record(AuditEvents.accessDenied, 'blocked', { ip: req.ip, meta: { reason: token ? 'invalid_session' : 'no_session', path: req.path } });
        res.status(401).json({ error: 'unauthenticated' });
        return;
      }
      if (ctx.rotatedToken) setSessionCookie(res, deps.config, ctx.rotatedToken, ctx.session.expiresAt);
      req.auth = ctx;
      next();
    } catch (err) {
      next(err);
    }
  };
}

const RANK: Record<Role, number> = { user: 1, admin: 2 };

/** Role-based access control (least privilege): default deny, explicit minimum role per route. */
export function requireRole(deps: Deps, minimum: Role): RequestHandler {
  return (req, res, next) => {
    const role = req.auth?.user.role;
    if (!role || RANK[role] < RANK[minimum]) {
      void deps.audit.record(AuditEvents.accessDenied, 'blocked', { userId: req.auth?.user.id, ip: req.ip, meta: { reason: 'role', path: req.path } });
      res.status(403).json({ error: 'forbidden' });
      return;
    }
    next();
  };
}
