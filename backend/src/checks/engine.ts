import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Deps, SecurityRunner } from '../deps.js';
import { authChecks } from './auth.js';
import { deploymentChecks } from './deployment.js';
import { injectionChecks } from './injection.js';
import { secretsChecks } from './secrets.js';
import { CATEGORIES, type CheckContext, type CheckDefinition, type CheckResult, type SecurityReport } from './types.js';

export const ALL_CHECKS: CheckDefinition[] = [...injectionChecks, ...authChecks, ...secretsChecks, ...deploymentChecks];

/**
 * Controls that live outside the application and therefore cannot be proven by
 * code. They are listed so nobody mistakes a green dashboard for full coverage.
 */
export const MANUAL_REVIEW_ITEMS = [
  'MongoDB users follow least privilege (readWrite on the mutualx database only; no admin roles).',
  'MongoDB network access is restricted to the Render service’s outbound IPs (Atlas IP access list / private networking).',
  'MongoDB connections use TLS and the cluster enforces encryption at rest.',
  'Automated backups are enabled and a restore has been tested within the last quarter.',
  'GitHub branch protection (required reviews and status checks) is enabled on main.',
  'GitHub secret scanning and push protection are enabled for the repository.',
  'Meta app review, permitted use cases and the deauthorize / data-deletion callback URLs are configured in the Meta developer dashboard.',
  'Frontend and API share a registrable domain so SameSite cookies are delivered (custom domains on GitHub Pages and Render).',
  'Render environment variables are set per environment and development credentials differ from production.',
];

export function resolvePaths(): Pick<CheckContext, 'backendSrcDir' | 'repoRoot'> {
  const here = path.dirname(fileURLToPath(import.meta.url)); // …/backend/(src|dist)/checks
  const backendSrcDir = path.resolve(here, '..');
  return { backendSrcDir, repoRoot: path.resolve(backendSrcDir, '..', '..') };
}

export async function runChecks(deps: Pick<Deps, 'config' | 'now'>, only?: number[]): Promise<SecurityReport> {
  const ctx: CheckContext = { config: deps.config, now: deps.now ?? (() => new Date()), ...resolvePaths() };
  const defs = ALL_CHECKS.filter((c) => !only || only.includes(c.id));
  const checks: CheckResult[] = [];

  for (const def of defs) {
    const verifiedAt = ctx.now().toISOString();
    try {
      const outcome = await def.run(ctx);
      checks.push({ id: def.id, key: def.key, category: def.category, title: def.title, severity: def.severity, methods: def.methods, verifiedAt, ...outcome });
    } catch (err) {
      // A crashed check is never reported as a pass.
      checks.push({
        id: def.id,
        key: def.key,
        category: def.category,
        title: def.title,
        severity: def.severity,
        methods: def.methods,
        verifiedAt,
        status: 'needs_review',
        implementation: 'Verification could not complete.',
        explanation: 'The automated check raised an unexpected error, so no verdict could be produced.',
        evidence: [`Error type: ${(err as Error)?.name ?? 'unknown'}`],
        remediation: ['Run the check locally (npm run security:report) and inspect the failure'],
      });
    }
  }

  const summary = {
    pass: checks.filter((c) => c.status === 'pass').length,
    fail: checks.filter((c) => c.status === 'fail').length,
    needs_review: checks.filter((c) => c.status === 'needs_review').length,
    total: checks.length,
  };
  return {
    generatedAt: ctx.now().toISOString(),
    environment: deps.config.env,
    scope: 'Probes run against the real middleware stack and configuration in an isolated in-memory instance. They verify application code and configuration, not hosting-level controls (see manual review items).',
    summary,
    categories: CATEGORIES,
    checks,
    manualReviewItems: MANUAL_REVIEW_ITEMS,
  };
}

/** Caches the last report for 60 s so the dashboard cannot be used to hammer the probe engine. */
export class SecurityScanner implements SecurityRunner {
  private cache?: { at: number; report: SecurityReport };
  private inflight?: Promise<SecurityReport>;

  constructor(private deps: Pick<Deps, 'config' | 'now'>) {}

  async run(force = false): Promise<SecurityReport> {
    if (!force && this.cache && Date.now() - this.cache.at < 60_000) return this.cache.report;
    if (this.inflight) return this.inflight;
    this.inflight = runChecks(this.deps)
      .then((report) => {
        this.cache = { at: Date.now(), report };
        return report;
      })
      .finally(() => {
        this.inflight = undefined;
      });
    return this.inflight;
  }
}
