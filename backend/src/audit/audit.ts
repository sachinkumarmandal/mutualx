import { randomUUID } from 'node:crypto';
import type { Logger } from 'pino';
import { redactString } from '../security/redact.js';
import { hmacBase64Url } from '../security/crypto.js';
import type { AuditOutcome, AuditRecord, Store } from '../store/types.js';

export const AuditEvents = {
  loginStarted: 'auth.login_started',
  loginSuccess: 'auth.login',
  loginFailure: 'auth.login_failed',
  logout: 'auth.logout',
  logoutAll: 'auth.logout_all',
  sessionRevoked: 'session.revoked',
  accessDenied: 'access.denied',
  csrfBlocked: 'csrf.blocked',
  inputBlocked: 'input.blocked',
  botSuspected: 'bot.suspected',
  rateLimited: 'rate_limit.exceeded',
  accountDisconnected: 'account.disconnected',
  accountDeleted: 'account.deleted',
  metaDeauthorize: 'meta.deauthorize',
  metaDataDeletion: 'meta.data_deletion',
  securityScan: 'security.scan',
} as const;

type Meta = Record<string, string | number | boolean | undefined>;

/**
 * Append-only audit trail. IPs are stored only as keyed hashes, metadata is
 * redacted and truncated, and failures to write never break a request.
 */
export class AuditLogger {
  constructor(
    private store: Store,
    private logger: Logger,
    private hashSecret: string,
  ) {}

  hashIp(ip: string | undefined): string | undefined {
    return ip ? hmacBase64Url(this.hashSecret, `ip:${ip}`).slice(0, 22) : undefined;
  }

  async record(event: string, outcome: AuditOutcome, opts: { userId?: string; ip?: string; meta?: Meta } = {}): Promise<void> {
    const meta: Record<string, string | number | boolean> = {};
    for (const [k, v] of Object.entries(opts.meta ?? {})) {
      if (v === undefined) continue;
      meta[k.slice(0, 32)] = typeof v === 'string' ? redactString(v).slice(0, 200) : v;
    }
    const record: AuditRecord = {
      id: randomUUID(),
      at: new Date(),
      event,
      outcome,
      userId: opts.userId,
      ipHash: this.hashIp(opts.ip),
      meta: Object.keys(meta).length ? meta : undefined,
    };
    try {
      await this.store.appendAudit(record);
      this.logger.info({ audit: { event, outcome, userId: opts.userId } }, 'audit');
    } catch {
      this.logger.error({ event }, 'audit write failed');
    }
  }
}
