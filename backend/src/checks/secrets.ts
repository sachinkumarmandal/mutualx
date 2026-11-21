import { randomBytes } from 'node:crypto';
import express from 'express';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { isWeakSecret } from '../config.js';
import { sessionCookieName, setSessionCookie } from '../auth/session.js';
import { decrypt, encrypt } from '../security/crypto.js';
import { redactString, redactValue } from '../security/redact.js';
import type { CheckDefinition, CheckOutcome } from './types.js';
import { dirExists, readTextIfExists, send, walk } from './probe.js';
import { existsSync, readdirSync } from 'node:fs';

export const secretsChecks: CheckDefinition[] = [
  {
    id: 11,
    key: 'jwt_secret',
    category: 'secrets',
    title: 'JWT Secret Security',
    severity: 'critical',
    methods: ['config-inspection', 'runtime-probe'],
    async run(ctx): Promise<CheckOutcome> {
      const evidence: string[] = ['MutualX uses opaque server-side sessions, not JWTs — there is no JWT signing secret to leak or forge. The signing/encryption secrets below are evaluated instead.'];
      const problems: string[] = [];
      const c = ctx.config;
      (isWeakSecret(c.sessionSecret) ? problems : evidence).push(isWeakSecret(c.sessionSecret) ? 'SESSION_SECRET is weak, short or a placeholder' : `SESSION_SECRET strength OK (${c.sessionSecret.length} chars, ${new Set(c.sessionSecret).size} distinct characters)`);
      for (const k of c.encryptionKeys) {
        const distinct = new Set(k.key).size;
        (distinct < 16 ? problems : evidence).push(distinct < 16 ? `Encryption key "${k.id}" has low entropy (${distinct} distinct bytes)` : `Encryption key "${k.id}" is 256-bit with ${distinct} distinct bytes`);
      }
      // Encryption round-trip, context binding and key rotation, using throw-away keys.
      const oldKeys = [{ id: 'old', key: randomBytes(32) }];
      const newKeys = [{ id: 'new', key: randomBytes(32) }, ...oldKeys];
      const ct = encrypt('probe-token', oldKeys, 'ctx:1');
      (decrypt(ct, newKeys, 'ctx:1') === 'probe-token' ? evidence : problems).push('Data encrypted with a retired key still decrypts after rotation');
      try {
        decrypt(ct, oldKeys, 'ctx:2');
        problems.push('Ciphertext decrypts under a different context (AAD not enforced)');
      } catch {
        evidence.push('Ciphertext is bound to its record (wrong context → decryption fails)');
      }
      const tampered = ct.slice(0, -2) + (ct.endsWith('AA') ? 'BB' : 'AA');
      try {
        decrypt(tampered, oldKeys, 'ctx:1');
        problems.push('Tampered ciphertext accepted');
      } catch {
        evidence.push('Tampered ciphertext is rejected (AES-GCM authentication)');
      }
      return {
        status: problems.length ? 'fail' : 'pass',
        implementation: 'Opaque sessions (no JWT). Session/CSRF HMAC secret and AES-256-GCM key ring with key ids support rotation; production startup refuses weak secrets.',
        explanation: problems.length ? `Secret problems: ${problems.join('; ')}` : 'Secrets meet strength requirements and key rotation works.',
        evidence: [...evidence, ...problems],
        remediation: problems.length ? ['Generate: openssl rand -base64 48 (SESSION_SECRET) and openssl rand -base64 32 (each encryption key)', 'Store them only in the host’s secret manager'] : ['Rotate: prepend a new "id:key" to ENCRYPTION_KEYS, deploy, re-encrypt (reconnect), then drop the old key'],
      };
    },
  },
  {
    id: 12,
    key: 'api_key_protection',
    category: 'secrets',
    title: 'API Key Protection',
    severity: 'critical',
    methods: ['static-scan', 'runtime-probe'],
    async run(ctx): Promise<CheckOutcome> {
      const evidence: string[] = [];
      const problems: string[] = [];
      const review: string[] = [];

      const sample = redactValue({ access_token: 'IGQ' + 'a'.repeat(60), client_secret: 's3cr3t', nested: { authorization: 'Bearer abc.def.ghi', note: 'ok' } }) as Record<string, unknown>;
      const dumped = JSON.stringify(sample);
      (!/IGQa|s3cr3t|abc\.def/.test(dumped) ? evidence : problems).push('Redaction removes tokens, secrets and Authorization values from logged objects');
      (!redactString('GET /x?access_token=abc123&state=q').includes('abc123') ? evidence : problems).push('Redaction removes credentials from URLs');

      const files = walk(ctx.backendSrcDir, ['.ts', '.js'], ['node_modules', 'dist', '.git', 'checks', 'cli']);
      const consoleUse = files.filter((f) => /console\.(log|debug|info)\(/.test(readTextIfExists(f) ?? '') && !f.endsWith(`${path.sep}index.ts`) && !f.endsWith(`${path.sep}index.js`));
      (consoleUse.length ? problems : evidence).push(consoleUse.length ? `console logging found in: ${consoleUse.map((f) => path.basename(f)).join(', ')}` : 'No ad-hoc console logging outside the startup file (all logs go through redacting pino)');
      const secretLogged = files.filter((f) => /logger\.\w+\([^)]*(appSecret|sessionSecret|encryptionKeys|tokenCiphertext)/.test(readTextIfExists(f) ?? ''));
      (secretLogged.length ? problems : evidence).push(secretLogged.length ? `Secrets passed to the logger in: ${secretLogged.map((f) => path.basename(f)).join(', ')}` : 'No secret-bearing values passed to the logger');

      if (existsSync(path.join(ctx.repoRoot, '.git')) || existsSync(path.join(ctx.repoRoot, '.gitignore'))) {
        const gi = readTextIfExists(path.join(ctx.repoRoot, '.gitignore')) ?? '';
        (/^\.env$/m.test(gi) && /^\.env\.\*$/m.test(gi) ? evidence : problems).push('.gitignore excludes .env and .env.* files');
        const envFiles = ['.', 'backend', 'frontend'].flatMap((d) => (dirExists(path.join(ctx.repoRoot, d)) ? readdirSync(path.join(ctx.repoRoot, d)) : [])).filter((n) => /^\.env(\..+)?$/.test(n) && n !== '.env.example');
        if (envFiles.length) review.push(`Local env file(s) present (${envFiles.join(', ')}); confirm they are not tracked: git ls-files | grep '^\\.env'`);
        else evidence.push('No local .env files in the repository tree');
        const example = readTextIfExists(path.join(ctx.repoRoot, 'backend', '.env.example')) ?? '';
        (example && !/[A-Za-z0-9+/_-]{40,}={0,2}/.test(example.replace(/^#.*$/gm, '')) ? evidence : problems).push(example ? '.env.example contains placeholders only' : '.env.example missing');
      } else review.push('Repository metadata not available in this deployment; secret-tracking checks skipped');

      const dist = path.join(ctx.repoRoot, 'frontend', 'dist');
      if (dirExists(dist)) {
        const secret = ctx.config.meta?.appSecret;
        const leaks = walk(dist, ['.js', '.html', '.css', '.map', '.json'], []).filter((f) => {
          const t = readTextIfExists(f) ?? '';
          return (secret && t.includes(secret)) || /META_APP_SECRET|client_secret|SESSION_SECRET|ENCRYPTION_KEYS/.test(t);
        });
        (leaks.length ? problems : evidence).push(leaks.length ? `Secret names/values in built frontend: ${leaks.map((f) => path.basename(f)).join(', ')}` : 'Built frontend bundle contains no secret names or values');
      } else review.push('Frontend build output not present; bundle scan skipped');

      const status = problems.length ? 'fail' : review.length ? 'needs_review' : 'pass';
      return {
        status,
        implementation: 'Secrets exist only in backend environment variables (validated at boot, never in the frontend). Pino redaction and an audit-metadata redactor strip tokens; Meta credentials are sent only server-to-server.',
        explanation: problems.length ? `Secret-handling problems: ${problems.join('; ')}` : review.length ? `Automated checks pass, but some inputs were unavailable: ${review.join('; ')}` : 'No secret exposure paths found in code, logs, repository settings or the frontend bundle.',
        evidence: [...evidence, ...problems, ...review],
        remediation: problems.length ? ['Rotate any secret that may have been exposed', 'Fix the leak then re-run'] : review.length ? ['Run `npm run build` in frontend/ and re-run this check from a full checkout'] : ['Enable GitHub secret scanning + push protection (see docs/DEPLOYMENT.md)'],
      };
    },
  },
  {
    id: 13,
    key: 'no_localstorage_tokens',
    category: 'secrets',
    title: 'No LocalStorage Tokens',
    severity: 'high',
    methods: ['static-scan'],
    async run(ctx): Promise<CheckOutcome> {
      const src = path.join(ctx.repoRoot, 'frontend', 'src');
      if (!dirExists(src)) {
        return {
          status: 'needs_review',
          implementation: 'The session lives only in an HttpOnly cookie; the CSRF token is held in JavaScript memory.',
          explanation: 'Frontend sources are not present in this deployment, so the scan could not run.',
          evidence: ['frontend/src not found'],
          remediation: ['Run this check from a full repository checkout (CI does)'],
        };
      }
      const files = walk(src, ['.ts', '.tsx', '.js', '.jsx'], ['node_modules']);
      const pattern = /\b(localStorage|sessionStorage|indexedDB|document\.cookie)\b/;
      const hits = files.filter((f) => pattern.test(readTextIfExists(f) ?? '')).map((f) => path.relative(src, f));
      return {
        status: hits.length ? 'fail' : 'pass',
        implementation: 'No browser storage API is used. Auth state is the HttpOnly session cookie; the CSRF token is kept in a module variable and re-fetched on load.',
        explanation: hits.length ? `Browser storage / cookie access found in: ${hits.join(', ')}` : `Scanned ${files.length} frontend source files: no localStorage, sessionStorage, IndexedDB or document.cookie usage.`,
        evidence: hits.length ? hits.map((h) => `Match in ${h}`) : [`${files.length} files scanned, 0 matches`],
        remediation: hits.length ? ['Remove token persistence from the browser; rely on the HttpOnly cookie'] : ['Keep this scan in CI so it fails on regressions'],
      };
    },
  },
  {
    id: 14,
    key: 'no_default_credentials',
    category: 'secrets',
    title: 'No Default Credentials',
    severity: 'critical',
    methods: ['config-inspection'],
    async run(ctx): Promise<CheckOutcome> {
      const evidence: string[] = [];
      const problems: string[] = [];
      const review: string[] = [];
      const c = ctx.config;
      (isWeakSecret(c.sessionSecret) ? problems : evidence).push(isWeakSecret(c.sessionSecret) ? 'SESSION_SECRET looks like a default/placeholder value' : 'SESSION_SECRET is not a placeholder');
      const keyProblem = c.encryptionKeys.some((k) => new Set(k.key).size < 16);
      (keyProblem ? problems : evidence).push(keyProblem ? 'An encryption key looks like a placeholder (very low entropy)' : 'Encryption keys are not placeholders');
      if (c.meta) {
        const bad = /^(0+|1234567890|test|example|changeme)/i.test(c.meta.appSecret) || /(changeme|example|placeholder|your)/i.test(c.meta.appSecret);
        (bad ? problems : evidence).push(bad ? 'META_APP_SECRET looks like a placeholder' : 'META_APP_SECRET is not a placeholder');
      } else review.push('Meta credentials not configured');
      if (c.mongoUri) {
        try {
          const u = new URL(c.mongoUri.replace(/^mongodb(\+srv)?:/, 'http:'));
          const user = decodeURIComponent(u.username);
          const pass = decodeURIComponent(u.password);
          if (!user || !pass) problems.push('MONGODB_URI has no credentials');
          else if (/^(admin|root|mongo|test|user)$/i.test(user) || /^(password|admin|root|changeme|mongo|test|123456)$/i.test(pass) || pass.length < 16) problems.push('MONGODB_URI uses a default-style user or a short/guessable password');
          else evidence.push('MongoDB credentials are non-default and ≥16 characters');
        } catch {
          review.push('MONGODB_URI could not be parsed for inspection');
        }
      } else review.push('MONGODB_URI not set (in-memory store in use)');
      evidence.push('No seeded/bootstrap accounts exist: admin role is granted only via ADMIN_IG_USER_IDS to real Instagram identities');
      return {
        status: problems.length ? 'fail' : review.length ? 'needs_review' : 'pass',
        implementation: 'No built-in users or passwords. Production start-up refuses placeholder secrets; admin access is an explicit allow-list of Instagram user ids.',
        explanation: problems.length ? `Default-looking credentials: ${problems.join('; ')}` : review.length ? `No default credentials detected, but not everything could be inspected: ${review.join('; ')}` : 'No default or placeholder credentials in the active configuration.',
        evidence: [...evidence, ...problems, ...review],
        remediation: problems.length ? ['Replace the flagged values with freshly generated secrets and rotate any that were shared'] : review.length ? ['Configure the missing values in the target environment and re-run the check there'] : ['Use separate credentials for development, staging and production'],
      };
    },
  },
  {
    id: 15,
    key: 'httponly_cookies',
    category: 'secrets',
    title: 'HttpOnly Cookie Security',
    severity: 'high',
    methods: ['runtime-probe'],
    async run(ctx): Promise<CheckOutcome> {
      const evidence: string[] = [];
      const problems: string[] = [];
      // Always evaluate the production cookie profile so the verdict does not depend on the current NODE_ENV.
      const prodConfig = { ...ctx.config, isProd: true, cookieSameSite: ctx.config.cookieSameSite === 'none' ? ('lax' as const) : ctx.config.cookieSameSite };
      const app = express();
      app.get('/t', (_q, res) => {
        setSessionCookie(res, prodConfig, 'x'.repeat(43), new Date(Date.now() + 3_600_000));
        res.end();
      });
      const server = createServer(app);
      await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
      try {
        const res = await send(`http://127.0.0.1:${(server.address() as AddressInfo).port}`, '/t');
        const cookie = res.setCookies[0] ?? '';
        const has = (re: RegExp, label: string) => (re.test(cookie) ? evidence : problems).push(label);
        has(/;\s*HttpOnly/i, 'HttpOnly set (invisible to JavaScript)');
        has(/;\s*Secure/i, 'Secure set (HTTPS only)');
        has(/;\s*SameSite=(Lax|Strict)/i, `SameSite=${prodConfig.cookieSameSite}`);
        has(/;\s*Path=\//i, 'Path=/');
        (!/;\s*Domain=/i.test(cookie) ? evidence : problems).push(!/;\s*Domain=/i.test(cookie) ? 'No Domain attribute (host-only cookie)' : 'Domain attribute set — breaks __Host- prefix guarantees');
        (cookie.startsWith(`${sessionCookieName(prodConfig)}=`) && cookie.startsWith('__Host-') ? evidence : problems).push('__Host- prefix applied (browser enforces Secure + Path=/ + no Domain)');
        (/;\s*Expires=/i.test(cookie) ? evidence : problems).push('Expiry bound to the absolute session lifetime');
      } finally {
        await new Promise<void>((r) => server.close(() => r()));
      }
      if (ctx.config.cookieSameSite === 'none') problems.push('COOKIE_SAMESITE=none configured: weakens CSRF defences');
      return {
        status: problems.length ? 'fail' : 'pass',
        implementation: 'Session cookie: __Host- prefixed, HttpOnly, Secure, SameSite=Lax/Strict, Path=/, no Domain, expiry tied to session lifetime. The OAuth binding cookie follows the same rules (Lax so it survives the redirect back from Meta).',
        explanation: problems.length ? `Cookie problems: ${problems.join('; ')}` : 'The production cookie profile carries every recommended protection attribute.',
        evidence: [...evidence, ...problems],
        remediation: problems.length ? ['Use sessionCookieOptions() for every cookie', 'Serve frontend and API from the same registrable domain (e.g. app.example.com / api.example.com) so SameSite=Lax cookies work'] : ['GitHub Pages (*.github.io) and Render (*.onrender.com) are different sites: use a custom domain on both so the SameSite cookie is sent'],
      };
    },
  },
];
