import type { NextFunction, Request, RequestHandler, Response } from 'express';
import type { AuditLogger } from '../audit/audit.js';
import { AuditEvents } from '../audit/audit.js';
import type { AppConfig } from '../config.js';
import { hmacBase64Url, safeEqual } from './crypto.js';

const UNSAFE = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/** Per-session token: HMAC(secret, sessionId). Changes automatically when the session is re-created. */
export function csrfTokenFor(config: AppConfig, sessionId: string): string {
  return hmacBase64Url(config.sessionSecret, `csrf:${sessionId}`);
}

/**
 * Layer 1 — Origin check for every state-changing request: the browser-set
 * `Origin` header must equal the configured frontend origin.
 */
export function originGuard(config: AppConfig, audit: AuditLogger): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!UNSAFE.has(req.method)) return next();
    if (req.headers.origin !== config.frontendOrigin) {
      void audit.record(AuditEvents.csrfBlocked, 'blocked', { ip: req.ip, meta: { reason: 'origin', path: req.path } });
      res.status(403).json({ error: 'forbidden' });
      return;
    }
    next();
  };
}

/** Layer 2 — synchroniser token bound to the session, sent in `X-CSRF-Token`. */
export function requireCsrf(config: AppConfig, audit: AuditLogger): RequestHandler {
  return (req, res, next) => {
    if (!UNSAFE.has(req.method)) return next();
    const sent = req.get('x-csrf-token');
    const sessionId = req.auth?.session.id;
    if (!sent || !sessionId || !safeEqual(sent, csrfTokenFor(config, sessionId))) {
      void audit.record(AuditEvents.csrfBlocked, 'blocked', { userId: req.auth?.user.id, ip: req.ip, meta: { reason: 'token', path: req.path } });
      res.status(403).json({ error: 'forbidden' });
      return;
    }
    next();
  };
}
