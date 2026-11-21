import type { NextFunction, Request, Response, RequestHandler } from 'express';
import helmet from 'helmet';
import type { AppConfig } from '../config.js';

/**
 * The API only serves JSON, so its CSP is the strictest possible
 * (`default-src 'none'`). The browser app ships its own CSP (see frontend/index.html).
 */
export const API_CSP_DIRECTIVES = {
  defaultSrc: ["'none'"],
  baseUri: ["'none'"],
  formAction: ["'none'"],
  frameAncestors: ["'none'"],
};

export const HSTS_MAX_AGE = 63_072_000; // 2 years

export function securityHeaders(): RequestHandler[] {
  return [
    helmet({
      contentSecurityPolicy: { useDefaults: false, directives: API_CSP_DIRECTIVES },
      strictTransportSecurity: { maxAge: HSTS_MAX_AGE, includeSubDomains: true, preload: true },
      referrerPolicy: { policy: 'no-referrer' },
      crossOriginOpenerPolicy: { policy: 'same-origin' },
      crossOriginResourcePolicy: { policy: 'same-site' },
      frameguard: { action: 'deny' },
      xPermittedCrossDomainPolicies: { permittedPolicies: 'none' },
      hidePoweredBy: true,
    }),
    (_req: Request, res: Response, next: NextFunction) => {
      res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()');
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Pragma', 'no-cache');
      next();
    },
  ];
}

/** Redirect / refuse plain HTTP in production. `/api/health` is exempt for platform health checks. */
export function enforceHttps(config: AppConfig): RequestHandler {
  return (req, res, next) => {
    if (!config.isProd || req.secure || req.path === '/api/health') return next();
    if (req.method === 'GET' || req.method === 'HEAD') {
      const host = new URL(config.apiPublicUrl).host;
      res.redirect(308, `https://${host}${req.originalUrl}`);
      return;
    }
    res.status(400).json({ error: 'https_required' });
  };
}
