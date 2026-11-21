import cookieParser from 'cookie-parser';
import express, { type Express, type RequestHandler } from 'express';
import { AuditEvents } from './audit/audit.js';
import type { Deps } from './deps.js';
import { authRouter } from './routes/auth.js';
import { meRouter } from './routes/me.js';
import { metaRouter } from './routes/meta.js';
import { publicRouter } from './routes/public.js';
import { securityRouter } from './routes/security.js';
import { botGuard } from './security/botGuard.js';
import { corsMiddleware } from './security/cors.js';
import { originGuard } from './security/csrf.js';
import { errorHandler, notFound, requestId } from './security/errors.js';
import { enforceHttps, securityHeaders } from './security/headers.js';
import { createLimiters } from './security/rateLimit.js';
import { rejectUnsafeInput } from './security/sanitize.js';

const UNSAFE = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/** State-changing requests may only carry JSON (this also rules out multipart uploads and form-post CSRF). */
const jsonOnly: RequestHandler = (req, res, next) => {
  const ct = req.headers['content-type'];
  if (UNSAFE.has(req.method) && ct && !/^application\/json(\s*;|$)/i.test(ct)) {
    res.status(415).json({ error: 'unsupported_media_type' });
    return;
  }
  next();
};

export function createApp(deps: Deps): Express {
  const { config, audit } = deps;
  const limiters = createLimiters(audit);
  const app = express();

  app.disable('x-powered-by');
  app.disable('etag');
  app.set('trust proxy', config.trustProxy);

  app.use(requestId);
  app.use(...securityHeaders());
  app.use(enforceHttps(config));
  app.use(botGuard(audit));
  app.use(corsMiddleware(config));
  app.use(limiters.global);
  app.use(cookieParser());

  // Meta server-to-server callbacks: form-encoded, authenticated by HMAC signature (mounted before the JSON stack).
  app.use('/api/meta', express.urlencoded({ extended: false, limit: '4kb', parameterLimit: 5 }), metaRouter(deps));

  app.use(express.json({ limit: '8kb', strict: true, type: 'application/json' }));
  app.use(jsonOnly);
  app.use(
    rejectUnsafeInput((req, err) => {
      void audit.record(AuditEvents.inputBlocked, 'blocked', { ip: req.ip, meta: { reason: err.reason, path: req.path.slice(0, 80) } });
    }),
  );
  app.use('/api', originGuard(config, audit));

  app.use('/api', publicRouter(deps));
  app.use('/api/auth', authRouter(deps, limiters));
  app.use('/api/me', meRouter(deps, limiters));
  app.use('/api/security', securityRouter(deps));

  app.use(notFound);
  app.use(errorHandler(deps));
  return app;
}
