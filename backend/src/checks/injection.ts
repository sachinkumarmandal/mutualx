import path from 'node:path';
import { assertSafeUrl, isBlockedIp, META_ALLOWED_HOSTS } from '../security/ssrf.js';
import { inspectValue, UnsafeInputError } from '../security/sanitize.js';
import type { CheckContext, CheckDefinition, CheckOutcome } from './types.js';
import { createProbeEnv, dirExists, readTextIfExists, send, walk } from './probe.js';

const SQL_LIBS = ['pg', 'mysql', 'mysql2', 'sqlite3', 'better-sqlite3', 'sequelize', 'knex', 'typeorm', 'mssql', 'oracledb', 'prisma', '@prisma/client'];
const UPLOAD_LIBS = ['multer', 'busboy', 'formidable', 'multiparty', 'express-fileupload', 'connect-busboy'];

function backendPackageJson(ctx: CheckContext): { dependencies?: Record<string, string> } | null {
  const raw = readTextIfExists(path.resolve(ctx.backendSrcDir, '..', 'package.json'));
  try {
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function frontendSrc(ctx: CheckContext): string | null {
  const dir = path.join(ctx.repoRoot, 'frontend', 'src');
  return dirExists(dir) ? dir : null;
}

export const injectionChecks: CheckDefinition[] = [
  {
    id: 1,
    key: 'sql_nosql_injection',
    category: 'injection',
    title: 'SQL Injection Protection',
    severity: 'critical',
    methods: ['runtime-probe', 'static-scan'],
    async run(ctx): Promise<CheckOutcome> {
      const evidence: string[] = [];
      const problems: string[] = [];
      const env = await createProbeEnv(ctx.config);
      try {
        const body = await send(env.base, '/api/me/disconnect', { method: 'POST', json: JSON.parse('{"$ne":null}') });
        (body.status === 400 ? evidence : problems).push(`POST body {"$ne":null} → HTTP ${body.status} (expected 400)`);
        const nested = await send(env.base, '/api/me/disconnect', { method: 'POST', json: JSON.parse('{"a":{"$where":"1"}}') });
        (nested.status === 400 ? evidence : problems).push(`Nested {"$where"} operator → HTTP ${nested.status} (expected 400)`);
        const query = await send(env.base, '/api/auth/instagram/callback?state[$ne]=x');
        (query.status === 400 ? evidence : problems).push(`Query state[$ne]=x → HTTP ${query.status} (expected 400)`);
      } finally {
        await env.close();
      }
      try {
        inspectValue({ ok: 'value' });
        evidence.push('Benign payload accepted by sanitiser');
      } catch (e) {
        if (e instanceof UnsafeInputError) problems.push('Sanitiser rejects benign payloads');
      }

      const pkg = backendPackageJson(ctx);
      if (pkg) {
        const deps = Object.keys(pkg.dependencies ?? {});
        const sql = deps.filter((d) => SQL_LIBS.includes(d));
        if (sql.length) problems.push(`SQL libraries present: ${sql.join(', ')} — each query must be parameterised`);
        else evidence.push('No SQL database client in backend dependencies (no SQL injection surface)');
      }
      const mongoFile = ['mongo.ts', 'mongo.js'].map((f) => path.join(ctx.backendSrcDir, 'store', f)).find((f) => readTextIfExists(f) !== null);
      const mongoSrc = mongoFile ? readTextIfExists(mongoFile) : null;
      if (mongoSrc) {
        const bad = ['$where', '$function', '$accumulator', 'mapReduce'].filter((t) => mongoSrc.includes(t));
        (bad.length ? problems : evidence).push(bad.length ? `Dangerous Mongo operators used: ${bad.join(', ')}` : 'MongoDB store uses no $where/$function/mapReduce operators');
        (mongoSrc.includes("'sanitizeFilter', true") ? evidence : problems).push(mongoSrc.includes("'sanitizeFilter', true") ? 'mongoose sanitizeFilter enabled' : 'mongoose sanitizeFilter not enabled');
      } else problems.push('MongoDB store source not found for review');

      return {
        status: problems.length ? 'fail' : 'pass',
        implementation: 'Allow-list key validation on body/query/params blocks operator keys; the Mongo store casts all values, enables sanitizeFilter and uses strict schemas. No SQL database is used.',
        explanation: problems.length ? `Problems found: ${problems.join('; ')}` : 'Injection payloads are rejected before reaching route handlers, and the data layer has no raw query construction.',
        evidence: [...evidence, ...problems],
        remediation: problems.length ? ['Restore rejectUnsafeInput before routes', 'Cast every filter value with String()/Number()', 'Remove raw query operators from the data layer'] : ['Keep strict Zod schemas on every new route', 'Re-run this check after adding any database code'],
      };
    },
  },
  {
    id: 2,
    key: 'xss',
    category: 'injection',
    title: 'XSS Protection',
    severity: 'high',
    methods: ['runtime-probe', 'static-scan'],
    async run(ctx): Promise<CheckOutcome> {
      const evidence: string[] = [];
      const problems: string[] = [];
      const env = await createProbeEnv(ctx.config);
      try {
        const res = await send(env.base, '/api/limitations');
        const csp = res.headers.get('content-security-policy') ?? '';
        (res.headers.get('content-type')?.startsWith('application/json') ? evidence : problems).push(`API responses are served as ${res.headers.get('content-type')}`);
        (res.headers.get('x-content-type-options') === 'nosniff' ? evidence : problems).push(`X-Content-Type-Options: ${res.headers.get('x-content-type-options')}`);
        (csp.includes("default-src 'none'") && !/unsafe-(inline|eval)/.test(csp) ? evidence : problems).push(`API CSP: ${csp || 'missing'}`);
      } finally {
        await env.close();
      }

      const src = frontendSrc(ctx);
      let frontendReviewed = false;
      if (src) {
        frontendReviewed = true;
        const files = walk(src, ['.ts', '.tsx', '.html'], ['node_modules']);
        const sinks = /dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|document\.write\(|\beval\(|new Function\(|insertAdjacentHTML/;
        const hits = files.filter((f) => sinks.test(readTextIfExists(f) ?? ''));
        (hits.length ? problems : evidence).push(hits.length ? `DOM injection sinks in: ${hits.map((h) => path.basename(h)).join(', ')}` : `No DOM injection sinks in ${files.length} frontend source files (React escapes output by default)`);
        const html = readTextIfExists(path.join(ctx.repoRoot, 'frontend', 'index.html')) ?? '';
        const scriptSrc = /script-src([^;"]*)/.exec(html)?.[1] ?? '';
        if (!scriptSrc) problems.push('Frontend index.html has no CSP script-src directive');
        else if (/unsafe-(inline|eval)/.test(scriptSrc)) problems.push(`Frontend CSP allows unsafe script execution (script-src${scriptSrc})`);
        else evidence.push(`Frontend CSP script-src${scriptSrc.trimEnd()}`);
      }

      if (problems.length) {
        return { status: 'fail', implementation: 'JSON-only API with strict CSP; React frontend with CSP meta tag.', explanation: `Problems found: ${problems.join('; ')}`, evidence: [...evidence, ...problems], remediation: ['Remove unsafe DOM sinks', 'Tighten CSP script-src to \'self\'', 'Send CSP as an HTTP header on the frontend host where possible'] };
      }
      return {
        status: frontendReviewed ? 'pass' : 'needs_review',
        implementation: 'JSON-only API with default-src \'none\' CSP and nosniff; React frontend that never uses innerHTML-style sinks, with a CSP meta tag.',
        explanation: frontendReviewed ? 'API and frontend code paths show no XSS vectors.' : 'API protections verified, but frontend sources are not available in this deployment so the frontend could not be inspected.',
        evidence,
        remediation: frontendReviewed ? ['GitHub Pages cannot set HTTP headers; a CSP meta tag cannot enforce frame-ancestors — put the frontend behind a host that can set headers if clickjacking matters'] : ['Run this check from a full repository checkout (CI does)'],
      };
    },
  },
  {
    id: 3,
    key: 'csrf',
    category: 'injection',
    title: 'CSRF Protection',
    severity: 'high',
    methods: ['runtime-probe'],
    async run(ctx): Promise<CheckOutcome> {
      const env = await createProbeEnv(ctx.config);
      const evidence: string[] = [];
      const problems: string[] = [];
      try {
        const u = env.users.user;
        const t = env.csrf(u.sessionId);
        const noToken = await send(env.base, '/api/auth/logout', { method: 'POST', cookie: u.cookie, origin: env.origin, json: {} });
        (noToken.status === 403 ? evidence : problems).push(`Valid cookie + origin, no CSRF token → HTTP ${noToken.status} (expected 403)`);
        const wrongToken = await send(env.base, '/api/auth/logout', { method: 'POST', cookie: u.cookie, origin: env.origin, csrf: 'A'.repeat(43), json: {} });
        (wrongToken.status === 403 ? evidence : problems).push(`Wrong CSRF token → HTTP ${wrongToken.status} (expected 403)`);
        const evil = await send(env.base, '/api/auth/logout', { method: 'POST', cookie: u.cookie, origin: 'https://evil.example', csrf: t, json: {} });
        (evil.status === 403 ? evidence : problems).push(`Foreign Origin with valid token → HTTP ${evil.status} (expected 403)`);
        const noOrigin = await send(env.base, '/api/auth/logout', { method: 'POST', cookie: u.cookie, csrf: t, json: {} });
        (noOrigin.status === 403 ? evidence : problems).push(`Missing Origin → HTTP ${noOrigin.status} (expected 403)`);
        const otherToken = await send(env.base, '/api/auth/logout', { method: 'POST', cookie: u.cookie, origin: env.origin, csrf: env.csrf(env.users.other.sessionId), json: {} });
        (otherToken.status === 403 ? evidence : problems).push(`Token from another session → HTTP ${otherToken.status} (expected 403)`);
        const ok = await send(env.base, '/api/auth/logout', { method: 'POST', cookie: u.cookie, origin: env.origin, csrf: t, json: {} });
        (ok.status === 200 ? evidence : problems).push(`Correct cookie + origin + token → HTTP ${ok.status} (expected 200)`);
      } finally {
        await env.close();
      }
      return {
        status: problems.length ? 'fail' : 'pass',
        implementation: 'Three layers: SameSite session cookie, mandatory Origin match on every state-changing request, and a per-session HMAC synchroniser token in X-CSRF-Token.',
        explanation: problems.length ? `CSRF protections failed: ${problems.join('; ')}` : 'State-changing requests are rejected unless cookie, Origin and session-bound token all agree.',
        evidence: [...evidence, ...problems],
        remediation: problems.length ? ['Ensure originGuard and requireCsrf are mounted on every state-changing route'] : ['Any new POST/PUT/PATCH/DELETE route must use requireCsrf'],
      };
    },
  },
  {
    id: 4,
    key: 'file_uploads',
    category: 'injection',
    title: 'Secure File Uploads',
    severity: 'medium',
    methods: ['runtime-probe', 'static-scan'],
    async run(ctx): Promise<CheckOutcome> {
      const evidence: string[] = [];
      const problems: string[] = [];
      const env = await createProbeEnv(ctx.config);
      try {
        const res = await send(env.base, '/api/me/disconnect', {
          method: 'POST',
          cookie: env.users.user.cookie,
          origin: env.origin,
          csrf: env.csrf(env.users.user.sessionId),
          contentType: 'multipart/form-data; boundary=----x',
          body: '------x\r\nContent-Disposition: form-data; name="f"; filename="a.php"\r\n\r\n<?php ?>\r\n------x--\r\n',
        });
        (res.status === 415 ? evidence : problems).push(`multipart/form-data upload attempt → HTTP ${res.status} (expected 415)`);
      } finally {
        await env.close();
      }
      const pkg = backendPackageJson(ctx);
      if (pkg) {
        const found = Object.keys(pkg.dependencies ?? {}).filter((d) => UPLOAD_LIBS.includes(d));
        (found.length ? problems : evidence).push(found.length ? `Upload parsers installed: ${found.join(', ')}` : 'No multipart/upload parser in backend dependencies');
      }
      return {
        status: problems.length ? 'fail' : 'pass',
        implementation: 'MutualX intentionally has no file-upload feature. State-changing endpoints accept application/json only, so multipart uploads are refused with 415.',
        explanation: problems.length ? `Upload surface detected: ${problems.join('; ')}` : 'The attack surface does not exist: no upload endpoints, no multipart parser, and non-JSON bodies are rejected.',
        evidence: [...evidence, ...problems],
        remediation: problems.length ? ['Remove upload dependencies or add type/size/content validation, randomised storage names and malware scanning'] : ['If uploads are added later (e.g. data export import), add size limits, magic-byte validation and isolated storage first'],
      };
    },
  },
  {
    id: 5,
    key: 'ssrf',
    category: 'injection',
    title: 'SSRF Protection',
    severity: 'high',
    methods: ['runtime-probe'],
    async run(): Promise<CheckOutcome> {
      const evidence: string[] = [];
      const problems: string[] = [];
      const publicResolver = async () => ['93.184.216.34'];
      const cases: { label: string; url: string; resolver?: () => Promise<string[]> }[] = [
        { label: 'plain http', url: 'http://graph.instagram.com/me' },
        { label: 'non-allow-listed host', url: 'https://evil.example/x' },
        { label: 'cloud metadata IP literal', url: 'https://169.254.169.254/latest/meta-data' },
        { label: 'loopback literal', url: 'https://127.0.0.1/' },
        { label: 'credentials in URL', url: 'https://user:pw@graph.instagram.com/me' },
        { label: 'non-standard port', url: 'https://graph.instagram.com:8443/me' },
        { label: 'allow-listed host resolving to private IP (DNS rebinding)', url: 'https://graph.instagram.com/me', resolver: async () => ['10.0.0.5'] },
        { label: 'allow-listed host resolving to loopback', url: 'https://api.instagram.com/x', resolver: async () => ['127.0.0.1'] },
      ];
      for (const c of cases) {
        try {
          await assertSafeUrl(c.url, META_ALLOWED_HOSTS, c.resolver ?? publicResolver);
          problems.push(`ALLOWED: ${c.label}`);
        } catch {
          evidence.push(`Blocked: ${c.label}`);
        }
      }
      try {
        await assertSafeUrl('https://graph.instagram.com/me', META_ALLOWED_HOSTS, publicResolver);
        evidence.push('Allowed: https://graph.instagram.com on 443 resolving to a public IP');
      } catch {
        problems.push('Legitimate Meta endpoint is rejected');
      }
      const ips: [string, boolean][] = [['10.1.2.3', true], ['172.16.0.1', true], ['192.168.1.1', true], ['169.254.169.254', true], ['100.64.0.1', true], ['::1', true], ['fd00::1', true], ['::ffff:127.0.0.1', true], ['8.8.8.8', false], ['2606:4700::1111', false]];
      for (const [ip, expected] of ips) if (isBlockedIp(ip) !== expected) problems.push(`isBlockedIp(${ip}) should be ${expected}`);
      if (!problems.length) evidence.push(`${ips.length} IP-classification cases correct (private, loopback, link-local, CGNAT, ULA, mapped)`);

      return {
        status: problems.length ? 'fail' : 'pass',
        implementation: 'All outbound HTTP uses safeFetch: https-only, exact-host allow-list (Meta), DNS results must be public, redirects refused, timeout and size caps. Users cannot supply URLs.',
        explanation: problems.length ? `SSRF guard gaps: ${problems.join('; ')}` : 'Every tested SSRF vector is blocked and the allow-listed Meta hosts still work.',
        evidence: [...evidence, ...problems],
        remediation: problems.length ? ['Route every outbound request through safeFetch', 'Do not widen META_ALLOWED_HOSTS without review'] : ['Residual: DNS is resolved separately from the connection; the exact-host allow-list limits rebinding risk. Pin resolved IPs via a custom undici dispatcher if hosts are ever added.'],
      };
    },
  },
];
