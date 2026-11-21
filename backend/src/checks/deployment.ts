import { statSync } from 'node:fs';
import path from 'node:path';
import { hmacBase64Url } from '../security/crypto.js';
import { HSTS_MAX_AGE } from '../security/headers.js';
import { PERSISTED_USER_FIELDS } from '../store/types.js';
import type { CheckDefinition, CheckOutcome } from './types.js';
import { createProbeEnv, readTextIfExists, send, walk } from './probe.js';

function signedRequest(secret: string, userId: string): string {
  const payload = Buffer.from(JSON.stringify({ user_id: userId, algorithm: 'HMAC-SHA256' })).toString('base64url');
  return `${hmacBase64Url(secret, payload)}.${payload}`;
}

export const deploymentChecks: CheckDefinition[] = [
  {
    id: 16,
    key: 'https_enforcement',
    category: 'deployment',
    title: 'HTTPS Enforcement',
    severity: 'high',
    methods: ['runtime-probe', 'config-inspection'],
    async run(ctx): Promise<CheckOutcome> {
      const evidence: string[] = [];
      const problems: string[] = [];
      // Evaluate production behaviour regardless of the current NODE_ENV.
      const env = await createProbeEnv(ctx.config, { isProd: true });
      try {
        const http = await send(env.base, '/api/limitations');
        (http.status === 308 && (http.headers.get('location') ?? '').startsWith('https://') ? evidence : problems).push(`Plain-HTTP GET → HTTP ${http.status} redirect to ${http.headers.get('location') ?? 'nothing'}`);
        const post = await send(env.base, '/api/me/disconnect', { method: 'POST', json: {} });
        (post.status === 400 ? evidence : problems).push(`Plain-HTTP POST → HTTP ${post.status} (refused, not redirected)`);
        const https = await send(env.base, '/api/limitations', { headers: { 'x-forwarded-proto': 'https' } });
        (https.status === 200 ? evidence : problems).push(`HTTPS (via proxy header) → HTTP ${https.status}`);
        const hsts = https.headers.get('strict-transport-security') ?? '';
        const maxAge = Number(/max-age=(\d+)/.exec(hsts)?.[1] ?? 0);
        (maxAge >= 15_552_000 && /includeSubDomains/i.test(hsts) ? evidence : problems).push(`HSTS: ${hsts || 'missing'} (code constant ${HSTS_MAX_AGE}s)`);
        const health = await send(env.base, '/api/health');
        (health.status === 200 ? evidence : problems).push('/api/health is exempt so platform health checks keep working');
      } finally {
        await env.close();
      }
      const real = ctx.config;
      const urlsOk = real.apiPublicUrl.startsWith('https://') && real.frontendUrl.startsWith('https://');
      (urlsOk ? evidence : real.isProd ? problems : evidence).push(urlsOk ? 'API_PUBLIC_URL and FRONTEND_URL are https' : 'URLs are http (acceptable only for local development)');

      if (problems.length) return { status: 'fail', implementation: 'Production mode redirects/refuses HTTP and sends HSTS (2 years, includeSubDomains, preload).', explanation: `HTTPS enforcement problems: ${problems.join('; ')}`, evidence: [...evidence, ...problems], remediation: ['Ensure enforceHttps runs first and TRUST_PROXY matches the number of proxies in front of the app'] };
      return {
        status: real.isProd && urlsOk ? 'pass' : 'needs_review',
        implementation: 'Production mode redirects/refuses HTTP and sends HSTS (2 years, includeSubDomains, preload). TLS itself is terminated by the host (Render / GitHub Pages).',
        explanation: real.isProd && urlsOk ? 'Application-level enforcement verified; the active environment is production with https URLs.' : 'Application-level enforcement verified, but this process is not running in production with https URLs, so the deployed environment must be checked separately.',
        evidence,
        remediation: real.isProd && urlsOk ? ['Submit the API domain to hstspreload.org only after confirming every subdomain serves HTTPS'] : ['Run the check in the production environment (NODE_ENV=production)', 'Confirm HTTPS-only is enabled on GitHub Pages and the Render service'],
      };
    },
  },
  {
    id: 17,
    key: 'security_headers',
    category: 'deployment',
    title: 'Security Headers',
    severity: 'high',
    methods: ['runtime-probe'],
    async run(ctx): Promise<CheckOutcome> {
      const evidence: string[] = [];
      const problems: string[] = [];
      const env = await createProbeEnv(ctx.config);
      try {
        const targets = ['/api/limitations', '/api/does-not-exist', '/api/me'];
        for (const t of targets) {
          const res = await send(env.base, t, { headers: { 'x-forwarded-proto': 'https' } });
          const h = res.headers;
          const expect: [string, boolean][] = [
            ['content-security-policy', (h.get('content-security-policy') ?? '').includes("default-src 'none'")],
            ['strict-transport-security', /max-age=\d{7,}/.test(h.get('strict-transport-security') ?? '')],
            ['x-content-type-options', h.get('x-content-type-options') === 'nosniff'],
            ['x-frame-options', (h.get('x-frame-options') ?? '').toUpperCase() === 'DENY'],
            ['referrer-policy', h.get('referrer-policy') === 'no-referrer'],
            ['cross-origin-opener-policy', h.get('cross-origin-opener-policy') === 'same-origin'],
            ['cross-origin-resource-policy', h.get('cross-origin-resource-policy') === 'same-site'],
            ['permissions-policy', Boolean(h.get('permissions-policy'))],
            ['cache-control', (h.get('cache-control') ?? '').includes('no-store')],
          ];
          const missing = expect.filter(([, ok]) => !ok).map(([n]) => n);
          if (h.get('x-powered-by')) missing.push('x-powered-by must be absent');
          (missing.length ? problems : evidence).push(missing.length ? `${t} (HTTP ${res.status}) missing/incorrect: ${missing.join(', ')}` : `${t} (HTTP ${res.status}) carries all ${expect.length} required headers and no X-Powered-By`);
        }
        const evil = await send(env.base, '/api/limitations', { headers: { origin: 'https://evil.example' } });
        (evil.headers.get('access-control-allow-origin') === null ? evidence : problems).push('CORS: foreign origin receives no Access-Control-Allow-Origin');
        const good = await send(env.base, '/api/limitations', { headers: { origin: env.origin } });
        (good.headers.get('access-control-allow-origin') === env.origin && good.headers.get('access-control-allow-credentials') === 'true' ? evidence : problems).push('CORS: configured frontend origin is allowed with credentials (exact match, no wildcard)');
        const pre = await send(env.base, '/api/me/disconnect', { method: 'OPTIONS', headers: { origin: 'https://evil.example', 'access-control-request-method': 'POST' } });
        (pre.headers.get('access-control-allow-origin') === null ? evidence : problems).push('CORS preflight from a foreign origin is not approved');
      } finally {
        await env.close();
      }
      return {
        status: problems.length ? 'fail' : 'pass',
        implementation: 'helmet-based header set on every response (including errors and 404s): strict CSP, HSTS, nosniff, frame deny, no-referrer, COOP/CORP, Permissions-Policy, no-store; exact-origin CORS.',
        explanation: problems.length ? `Header problems: ${problems.join('; ')}` : 'All required headers are present on success, 404 and 401 responses and CORS is exact-match.',
        evidence: [...evidence, ...problems],
        remediation: problems.length ? ['Keep securityHeaders() as the first middleware'] : ['The static frontend on GitHub Pages cannot set these headers; consider fronting it with a host/CDN that can'],
      };
    },
  },
  {
    id: 18,
    key: 'dependency_scanning',
    category: 'deployment',
    title: 'Dependency Vulnerability Scanning',
    severity: 'high',
    methods: ['artifact-review'],
    async run(ctx): Promise<CheckOutcome> {
      const evidence: string[] = [];
      const problems: string[] = [];
      const review: string[] = [];
      const gh = path.join(ctx.repoRoot, '.github');
      const dependabot = readTextIfExists(path.join(gh, 'dependabot.yml'));
      const codeql = readTextIfExists(path.join(gh, 'workflows', 'codeql.yml'));
      const ci = readTextIfExists(path.join(gh, 'workflows', 'ci.yml')) ?? '';
      if (readTextIfExists(path.join(gh, 'workflows', 'ci.yml')) === null && !dependabot) {
        review.push('.github directory not present in this deployment (backend-only build)');
      } else {
        (dependabot ? evidence : problems).push(dependabot ? 'Dependabot configured (.github/dependabot.yml)' : 'dependabot.yml missing');
        (codeql ? evidence : problems).push(codeql ? 'CodeQL workflow configured (.github/workflows/codeql.yml)' : 'codeql.yml missing');
        (/npm audit/.test(ci) ? evidence : problems).push(/npm audit/.test(ci) ? 'CI runs npm audit and fails on high/critical findings' : 'CI does not run npm audit');
      }
      let sawReport = false;
      for (const [label, file] of [
        ['backend', path.resolve(ctx.backendSrcDir, '..', 'security-reports', 'npm-audit.json')],
        ['frontend', path.join(ctx.repoRoot, 'frontend', 'security-reports', 'npm-audit.json')],
      ] as const) {
        const raw = readTextIfExists(file);
        if (!raw) {
          review.push(`No ${label} npm-audit report found (run \`npm run security:audit\`)`);
          continue;
        }
        sawReport = true;
        const ageDays = (ctx.now().getTime() - statSync(file).mtime.getTime()) / 86_400_000;
        try {
          const v = (JSON.parse(raw) as { metadata?: { vulnerabilities?: Record<string, number> } }).metadata?.vulnerabilities ?? {};
          const crit = v.critical ?? 0;
          const high = v.high ?? 0;
          evidence.push(`${label} npm audit (${ageDays.toFixed(1)} days old): critical ${crit}, high ${high}, moderate ${v.moderate ?? 0}, low ${v.low ?? 0}`);
          if (crit + high > 0) problems.push(`${label} has ${crit} critical / ${high} high vulnerabilities`);
          if (ageDays > 7) review.push(`${label} audit report is ${ageDays.toFixed(0)} days old`);
        } catch {
          review.push(`${label} audit report is unreadable`);
        }
      }
      void sawReport;
      return {
        status: problems.length ? 'fail' : review.length ? 'needs_review' : 'pass',
        implementation: 'Dependabot (weekly npm + GitHub Actions updates), CodeQL (push, PR, weekly), `npm audit` gate in CI, and secret scanning guidance.',
        explanation: problems.length ? `Dependency risk: ${problems.join('; ')}` : review.length ? `No known high-severity issues, but evidence is incomplete: ${review.join('; ')}` : 'Scanning is configured and the latest audit reports show no high or critical vulnerabilities.',
        evidence: [...evidence, ...problems, ...review],
        remediation: problems.length ? ['Run npm audit fix or upgrade the affected packages; merge Dependabot PRs promptly'] : review.length ? ['Run `npm run security:audit` in backend/ and frontend/', 'Run these checks from a full checkout'] : ['Enable Dependabot alerts, secret scanning and push protection in the GitHub repository settings'],
      };
    },
  },
  {
    id: 19,
    key: 'data_privacy',
    category: 'deployment',
    title: 'Data Privacy',
    severity: 'high',
    methods: ['runtime-probe', 'static-scan'],
    async run(ctx): Promise<CheckOutcome> {
      const evidence: string[] = [];
      const problems: string[] = [];
      const forbidden = /password|email|phone|follower|following|birth|address|ssn|location/i;
      const bad = PERSISTED_USER_FIELDS.filter((f) => forbidden.test(f));
      (bad.length ? problems : evidence).push(bad.length ? `Sensitive fields persisted: ${bad.join(', ')}` : `Data minimisation: only ${PERSISTED_USER_FIELDS.length} user fields are stored (${PERSISTED_USER_FIELDS.join(', ')}); no follower lists, e-mail or passwords`);
      (ctx.config.auditRetentionDays <= 365 ? evidence : problems).push(`Audit retention ${ctx.config.auditRetentionDays} days`);

      const mongoFile = ['mongo.ts', 'mongo.js'].map((f) => path.join(ctx.backendSrcDir, 'store', f)).find((f) => readTextIfExists(f) !== null);
      const ttl = ((mongoFile ? readTextIfExists(mongoFile) : '') ?? '').match(/expireAfterSeconds/g)?.length ?? 0;
      (ttl >= 3 ? evidence : problems).push(`${ttl} TTL indexes enforce automatic expiry of sessions, OAuth state and audit records`);

      const env = await createProbeEnv(ctx.config);
      try {
        const u = env.users.other;
        const del = await send(env.base, '/api/me', { method: 'DELETE', cookie: u.cookie, origin: env.origin, csrf: env.csrf(u.sessionId) });
        const gone = (await env.store.getUserById(u.id)) === null;
        const after = await send(env.base, '/api/me', { cookie: u.cookie });
        (del.status === 200 && gone && after.status === 401 ? evidence : problems).push(`User-requested deletion → HTTP ${del.status}; record removed: ${gone}; old session afterwards → HTTP ${after.status}`);

        const secret = env.config.meta!.appSecret;
        const form = (v: string) => `signed_request=${encodeURIComponent(v)}`;
        const victim = env.users.user;
        const user = (await env.store.getUserById(victim.id))!;
        const forged = await send(env.base, '/api/meta/data-deletion', { method: 'POST', contentType: 'application/x-www-form-urlencoded', body: form(signedRequest('wrong-secret-wrong-secret-wrong-secret', user.igUserId)) });
        (forged.status === 401 && (await env.store.getUserById(victim.id)) !== null ? evidence : problems).push(`Meta data-deletion callback with forged signature → HTTP ${forged.status}, data untouched`);
        const real = await send(env.base, '/api/meta/data-deletion', { method: 'POST', contentType: 'application/x-www-form-urlencoded', body: form(signedRequest(secret, user.igUserId)) });
        const body = real.json as { url?: string; confirmation_code?: string } | null;
        (real.status === 200 && body?.confirmation_code && (await env.store.getUserById(victim.id)) === null ? evidence : problems).push(`Meta data-deletion callback with valid signature → HTTP ${real.status}, user erased, confirmation code returned`);

        const admin = env.users.admin;
        const adminRec = (await env.store.getUserById(admin.id))!;
        await env.store.updateUser(admin.id, { tokenCiphertext: 'k.i.t.c', tokenExpiresAt: new Date() });
        const deauth = await send(env.base, '/api/meta/deauthorize', { method: 'POST', contentType: 'application/x-www-form-urlencoded', body: form(signedRequest(secret, adminRec.igUserId)) });
        const after2 = (await env.store.getUserById(admin.id))!;
        (deauth.status === 200 && after2.tokenCiphertext === null && (await send(env.base, '/api/me', { cookie: admin.cookie })).status === 401 ? evidence : problems).push('Meta deauthorize callback → token wiped and sessions revoked');
      } finally {
        await env.close();
      }
      return {
        status: problems.length ? 'fail' : 'pass',
        implementation: 'Minimal data model, hashed IPs / UAs, encrypted token at rest, TTL-based retention, self-service disconnect and delete endpoints, and Meta’s deauthorize + data-deletion callbacks with signature verification.',
        explanation: problems.length ? `Privacy problems: ${problems.join('; ')}` : 'Stored data is minimal, expiry is automatic, and erasure works from both the UI and Meta’s callbacks.',
        evidence: [...evidence, ...problems],
        remediation: problems.length ? ['Remove the extra persisted fields', 'Fix the deletion path'] : ['Publish a privacy policy URL and register the callback URLs in the Meta app (required for app review)', 'Verify MongoDB backups also honour deletion requests (see docs/DEPLOYMENT.md)'],
      };
    },
  },
  {
    id: 20,
    key: 'audit_logging',
    category: 'deployment',
    title: 'Security Audit Logging',
    severity: 'medium',
    methods: ['runtime-probe'],
    async run(ctx): Promise<CheckOutcome> {
      const evidence: string[] = [];
      const problems: string[] = [];
      const env = await createProbeEnv(ctx.config);
      try {
        await send(env.base, '/api/me', { cookie: `${env.users.user.cookie.split('=')[0]}=${'q'.repeat(43)}` });
        await send(env.base, '/api/auth/logout', { method: 'POST', cookie: env.users.user.cookie, origin: env.origin, json: {} });
        await send(env.base, '/api/me/disconnect', { method: 'POST', json: JSON.parse('{"$gt":""}') });
        await send(env.base, '/.env', { headers: { 'user-agent': 'sqlmap/1.7' } });
        await env.deps.audit.record('probe.redaction', 'success', { ip: '127.0.0.1', meta: { note: 'Bearer abc.def.ghi', token: 'x'.repeat(60) } });
        const events = (await env.store.listAudit(100)).map((a) => a.event);
        for (const want of ['access.denied', 'csrf.blocked', 'input.blocked', 'bot.suspected']) (events.includes(want) ? evidence : problems).push(`${want} event recorded`);
        const serialized = JSON.stringify(env.store.audit);
        (!/127\.0\.0\.1/.test(serialized) ? evidence : problems).push('Raw IP addresses never appear in audit records (keyed hashes only)');
        (!serialized.includes('abc.def.ghi') && !serialized.includes('x'.repeat(60)) ? evidence : problems).push('Secrets in audit metadata are redacted');
        (env.store.audit.every((a) => a.id && a.at instanceof Date && a.event && a.outcome) ? evidence : problems).push('Every record has id, timestamp, event and outcome');
      } finally {
        await env.close();
      }
      const logged = walk(ctx.backendSrcDir, ['.ts', '.js']).map((f) => readTextIfExists(f) ?? '').join('\n');
      for (const e of ['login', 'logout', 'rate_limit.exceeded', 'account.deleted', 'meta.data_deletion']) (logged.includes(e) ? evidence : problems).push(`Event "${e}" is emitted in code`);
      return {
        status: problems.length ? 'fail' : 'pass',
        implementation: 'Append-only audit trail for authentication, access denials, CSRF/input blocks, bot suspicion, rate limiting and account lifecycle events; IPs hashed, metadata redacted, TTL retention. Admins can read it at /api/security/audit.',
        explanation: problems.length ? `Audit logging gaps: ${problems.join('; ')}` : 'Security-relevant events are recorded without leaking personal data or secrets.',
        evidence: [...evidence, ...problems],
        remediation: problems.length ? ['Emit audit events from the failing code paths'] : ['Forward audit events to an external, append-only log sink and alert on spikes of access.denied / csrf.blocked'],
      };
    },
  },
];
