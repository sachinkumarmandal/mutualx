import { Router } from 'express';
import { AuditEvents } from '../audit/audit.js';
import type { Deps } from '../deps.js';
import { requireRole, requireSession } from '../middleware/auth.js';
import { requireCsrf } from '../security/csrf.js';
import { AppError } from '../security/errors.js';

/** Admin-only: verification results reveal implementation details and remediation guidance. */
export function securityRouter(deps: Deps): Router {
  const r = Router();
  r.use(requireSession(deps), requireRole(deps, 'admin'));

  r.get('/checks', async (_req, res, next) => {
    try {
      if (!deps.securityRunner) throw new AppError(503, 'unavailable');
      res.json(await deps.securityRunner.run(false));
    } catch (err) {
      next(err);
    }
  });

  r.post('/checks/run', requireCsrf(deps.config, deps.audit), async (req, res, next) => {
    try {
      if (!deps.securityRunner) throw new AppError(503, 'unavailable');
      void deps.audit.record(AuditEvents.securityScan, 'success', { userId: req.auth!.user.id, ip: req.ip });
      res.json(await deps.securityRunner.run(true));
    } catch (err) {
      next(err);
    }
  });

  r.get('/audit', async (_req, res, next) => {
    try {
      const rows = await deps.store.listAudit(100);
      res.json({
        events: rows.map((a) => ({ at: a.at.toISOString(), event: a.event, outcome: a.outcome, userId: a.userId ?? null, meta: a.meta ?? null })),
      });
    } catch (err) {
      next(err);
    }
  });

  return r;
}
