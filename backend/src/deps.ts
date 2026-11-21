import type { Logger } from 'pino';
import type { AuditLogger } from './audit/audit.js';
import type { SessionService, AuthContext } from './auth/session.js';
import type { AppConfig } from './config.js';
import type { Resolver } from './security/ssrf.js';
import type { Store } from './store/types.js';

/** Runs the 20-point security verification; injected so routes do not import the probe engine. */
export interface SecurityRunner {
  run(force?: boolean): Promise<unknown>;
}

export interface Deps {
  securityRunner?: SecurityRunner;
  config: AppConfig;
  store: Store;
  audit: AuditLogger;
  logger: Logger;
  sessions: SessionService;
  /** Injection points so outbound calls can be tested without the network. */
  fetchImpl?: typeof fetch;
  resolver?: Resolver;
  now?: () => Date;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      auth?: AuthContext;
      requestId?: string;
    }
  }
}
