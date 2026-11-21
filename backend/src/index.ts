import { pino } from 'pino';
import { AuditLogger } from './audit/audit.js';
import { createApp } from './app.js';
import { SessionService } from './auth/session.js';
import { SecurityScanner } from './checks/engine.js';
import { ConfigError, loadConfig } from './config.js';
import type { Deps } from './deps.js';
import { PINO_REDACT_PATHS } from './security/redact.js';
import { MemoryStore } from './store/memory.js';
import { MongoStore } from './store/mongo.js';
import type { Store } from './store/types.js';

async function main() {
  let config;
  try {
    config = loadConfig();
  } catch (err) {
    // ConfigError messages never contain secret values.
    console.error(err instanceof ConfigError ? err.message : 'Failed to load configuration');
    process.exit(1);
  }

  const logger = pino({ level: config.logLevel, redact: { paths: PINO_REDACT_PATHS, censor: '[REDACTED]' } });

  let store: Store;
  if (config.mongoUri) {
    store = await MongoStore.connect(config.mongoUri, config.auditRetentionDays);
  } else {
    logger.warn('MONGODB_URI not set — using the in-memory store (development only; data is lost on restart)');
    store = new MemoryStore();
  }

  const audit = new AuditLogger(store, logger, config.sessionSecret);
  const sessions = new SessionService(store, config);
  const deps: Deps = { config, store, audit, logger, sessions };
  deps.securityRunner = new SecurityScanner(deps);

  const app = createApp(deps);
  const server = app.listen(config.port, () => logger.info({ port: config.port, env: config.env }, 'MutualX API listening'));

  const shutdown = (signal: string) => {
    logger.info({ signal }, 'shutting down');
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('unhandledRejection', (reason) => logger.error({ name: (reason as Error)?.name }, 'unhandled rejection'));
}

void main();
