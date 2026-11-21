import { describe, expect, it } from 'vitest';
import { runChecks } from '../src/checks/engine.js';
import { testConfig } from './helpers.js';

describe('20-point security verification', () => {
  it('produces exactly the 20 specified checks with complete fields and never crashes', async () => {
    const report = await runChecks({ config: testConfig() });
    expect(report.checks).toHaveLength(20);
    expect(report.checks.map((c) => c.id)).toEqual(Array.from({ length: 20 }, (_, i) => i + 1));
    for (const c of report.checks) {
      expect(['pass', 'fail', 'needs_review']).toContain(c.status);
      expect(['critical', 'high', 'medium', 'low']).toContain(c.severity);
      expect(c.implementation.length).toBeGreaterThan(20);
      expect(c.explanation.length).toBeGreaterThan(10);
      expect(c.evidence.length).toBeGreaterThan(0);
      expect(c.remediation.length).toBeGreaterThan(0);
      expect(Number.isNaN(Date.parse(c.verifiedAt))).toBe(false);
      expect(c.explanation).not.toBe('The automated check raised an unexpected error, so no verdict could be produced.');
    }
    expect(report.summary.pass + report.summary.fail + report.summary.needs_review).toBe(20);
    expect(report.manualReviewItems.length).toBeGreaterThan(0);
  }, 60_000);

  it('does not fail any check on a correctly configured development setup', async () => {
    const report = await runChecks({ config: testConfig() });
    const failing = report.checks.filter((c) => c.status === 'fail').map((c) => `${c.id} ${c.title}: ${c.explanation}`);
    expect(failing).toEqual([]);
  }, 60_000);

  it('is honest: checks that depend on real deployment/credentials are not reported as pass', async () => {
    const report = await runChecks({ config: testConfig() });
    const byId = Object.fromEntries(report.checks.map((c) => [c.id, c]));
    expect(byId[6]!.status).toBe('needs_review'); // no Meta credentials configured
    expect(byId[16]!.status).toBe('needs_review'); // not running in production
    expect(byId[14]!.status).toBe('needs_review'); // no MongoDB / Meta credentials to inspect
  }, 60_000);

  it('fails secret checks when weak secrets are configured (no fabricated passes)', async () => {
    const weakKey = Buffer.alloc(32, 7).toString('base64'); // 32 identical bytes
    const report = await runChecks({
      config: testConfig({ SESSION_SECRET: 'changeme-changeme-changeme-changeme-0000', ENCRYPTION_KEYS: `k1:${weakKey}` }),
    }, [11, 14]);
    expect(report.checks.map((c) => c.status)).toEqual(['fail', 'fail']);
  }, 60_000);
});
