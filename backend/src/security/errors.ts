import type { ErrorRequestHandler, RequestHandler } from 'express';
import { ZodError } from 'zod';
import { randomUUID } from 'node:crypto';
import type { Deps } from '../deps.js';

export class AppError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
  ) {
    super(code);
    this.name = 'AppError';
  }
}

export const requestId: RequestHandler = (req, res, next) => {
  req.requestId = randomUUID();
  res.setHeader('X-Request-Id', req.requestId);
  next();
};

export const notFound: RequestHandler = (_req, res) => {
  res.status(404).json({ error: 'not_found' });
};

/**
 * Central error handler. Clients only ever receive a stable error code (and a
 * request id for support); stack traces, messages and upstream details stay in
 * the (redacted) server log.
 */
export function errorHandler(deps: Pick<Deps, 'logger'>): ErrorRequestHandler {
  return (err, req, res, _next) => {
    if (res.headersSent) return;

    if (err instanceof AppError) {
      res.status(err.status).json({ error: err.code });
      return;
    }
    if (err instanceof ZodError) {
      res.status(400).json({ error: 'invalid_request' });
      return;
    }
    const type = (err as { type?: string })?.type;
    if (type === 'entity.parse.failed') {
      res.status(400).json({ error: 'invalid_json' });
      return;
    }
    if (type === 'entity.too.large') {
      res.status(413).json({ error: 'payload_too_large' });
      return;
    }

    deps.logger.error({ requestId: req.requestId, errName: (err as Error)?.name, path: req.path }, 'unhandled error');
    res.status(500).json({ error: 'internal_error', requestId: req.requestId });
  };
}
