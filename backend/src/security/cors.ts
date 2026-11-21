import cors, { type CorsOptions } from 'cors';
import type { AppConfig } from '../config.js';

/** Exact-match origin allow-list; no wildcards, no reflection of arbitrary origins. */
export function corsOptions(config: AppConfig): CorsOptions {
  return {
    origin(origin, cb) {
      // Requests without an Origin header (same-origin navigation, curl) get no CORS headers.
      cb(null, origin === config.frontendOrigin ? origin : false);
    },
    credentials: true,
    methods: ['GET', 'POST', 'DELETE'],
    allowedHeaders: ['Content-Type', 'X-CSRF-Token'],
    exposedHeaders: [],
    maxAge: 600,
    optionsSuccessStatus: 204,
  };
}

export const corsMiddleware = (config: AppConfig) => cors(corsOptions(config));
