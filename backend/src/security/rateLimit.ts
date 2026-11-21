import type { RequestHandler } from 'express';
import { rateLimit } from 'express-rate-limit';
import type { AuditLogger } from '../audit/audit.js';
import { AuditEvents } from '../audit/audit.js';

export interface LimiterSpec {
  windowMs: number;
  limit: number;
}

/** Documented budgets (see docs/SECURITY.md). */
export const LIMITS = {
  global: { windowMs: 60_000, limit: 120 },
  /** Login start + callback: brute-force / abuse protection. */
  auth: { windowMs: 15 * 60_000, limit: 20 },
  /** State-changing account operations. */
  sensitive: { windowMs: 15 * 60_000, limit: 30 },
} satisfies Record<string, LimiterSpec>;

export function createRateLimiter(spec: LimiterSpec, name: string, audit?: AuditLogger): RequestHandler {
  return rateLimit({
    windowMs: spec.windowMs,
    limit: spec.limit,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    handler: (req, res) => {
      void audit?.record(AuditEvents.rateLimited, 'blocked', { ip: req.ip, meta: { limiter: name, path: req.path } });
      res.status(429).json({ error: 'rate_limited' });
    },
  });
}

export function createLimiters(audit?: AuditLogger) {
  return {
    global: createRateLimiter(LIMITS.global, 'global', audit),
    auth: createRateLimiter(LIMITS.auth, 'auth', audit),
    sensitive: createRateLimiter(LIMITS.sensitive, 'sensitive', audit),
  };
}
