# MutualX

A security-first Instagram **mutuals finder**. It compares the followers/following files from your own Instagram data export, **entirely in your browser**, and never asks for a password or scrapes anything.

## Why it works this way (read this first)

Meta's official APIs do **not** expose follower or following lists, so mutuals cannot be fetched through OAuth. MutualX therefore:

| Capability | How |
|---|---|
| Mutuals / not-following-back / fans | You download your own export from Instagram (JSON) and drop it in. Parsed and compared **client-side**; the files are never uploaded or stored. |
| "Connect with Instagram" | Official Meta OAuth (Instagram API with Instagram Login). Optional. Gives identity and live aggregate counts for the connected professional account only. |
| Scraping, unofficial APIs, passwords | **Not implemented, by design.** |

The live capability list is served at `GET /api/limitations` and shown in the UI.

## Architecture

```
frontend/  React 19 + TypeScript + Tailwind 3 (Vite)   → GitHub Pages
backend/   Node 22 + Express 5 + TypeScript + Zod      → Render
           MongoDB (Mongoose, strict schemas)          → Atlas
```

- **Zero trust / least privilege**: every route validates input with Zod; admin routes need the `admin` role; sessions are opaque, server-side and revocable.
- **No tokens in JavaScript**: sessions live in `HttpOnly; Secure; SameSite` cookies. The only value held in memory by the SPA is a per-session CSRF token (not a credential).
- **Instagram tokens** are encrypted at rest (AES-256-GCM, versioned keys for rotation) and destroyed on disconnect.
- **Defence in depth**: Helmet CSP/HSTS, strict CORS, Origin + token CSRF, NoSQL-operator rejection, SSRF-guarded outbound calls (allow-listed Meta hosts), rate limiting, bot guard, redacted logs, audit trail with retention TTL.

## The 20-point security dashboard

Admin-only page (`#/security`, backend `GET /api/security/checks`). Each check shows status (Pass / Fail / Needs review), severity, implementation, explanation, evidence, remediation and last-verified time. Verdicts come from **live probes against an in-process copy of the API, configuration inspection, or repository scans**. A check that cannot be proven reports *Needs review*, never Pass. Controls outside the app's reach (Mongo user permissions, backups, branch protection…) are listed separately under *Manual review items*.

Run it headless: `cd backend && npm run security:report` (exit code 1 if any check fails; CI does this).

## Local development

```bash
npm run install:all
cp backend/.env.example backend/.env      # fill in generated secrets (see comments in the file)
npm run dev --prefix backend              # API on :8080 (in-memory store if MONGODB_URI is unset)
cp frontend/.env.example frontend/.env
npm run dev --prefix frontend             # UI on :5173
```

Without Meta credentials the Mutuals tool works fully; sign-in reports "not configured".

## Testing

```bash
npm run typecheck && npm test      # Vitest: backend (API, security units, 20 checks) + frontend (parser, maths)
npm run test:e2e                   # Playwright (desktop + mobile). UI tests stub API responses; they test rendering, not data.
```

## Deploying

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) (setup, environment, rollback) and [docs/RISKS.md](docs/RISKS.md) (**unresolved risks — read before launch**).

## License

Add your own license before publishing.
