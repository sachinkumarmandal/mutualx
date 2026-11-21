import { writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { runChecks } from '../checks/engine.js';
import { loadConfig } from '../config.js';

/** `npm run security:report` — runs the 20 checks and writes security-reports/security-report.json. Exit code 1 on any failure. */
async function main() {
  const report = await runChecks({ config: loadConfig() });
  const icon = { pass: 'PASS  ', fail: 'FAIL  ', needs_review: 'REVIEW' } as const;
  for (const c of report.checks) console.log(`${String(c.id).padStart(2, '0')} ${icon[c.status]} [${c.severity.padEnd(8)}] ${c.title}`);
  console.log(`\n${report.summary.pass} pass · ${report.summary.fail} fail · ${report.summary.needs_review} needs review (${report.environment})`);
  const dir = path.resolve('security-reports');
  mkdirSync(dir, { recursive: true });
  writeFileSync(path.join(dir, 'security-report.json'), JSON.stringify(report, null, 2));
  console.log(`Report written to ${path.join(dir, 'security-report.json')}`);
  process.exit(report.summary.fail > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error('Report failed:', (e as Error).name);
  process.exit(2);
});
