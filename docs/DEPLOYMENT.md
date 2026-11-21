# Deployment & rollback

Topology: **GitHub Pages** (static UI) → **Render** (API) → **MongoDB Atlas**.

> **Cookie domain requirement.** `*.github.io` and `*.onrender.com` are different *sites*, so `SameSite=Lax` session cookies will not be sent between them (and third-party-cookie blocking breaks `SameSite=None`). Use **custom domains on the same registrable domain**, e.g. `app.example.com` (Pages) and `api.example.com` (Render). Backend check #7 flags this.

## 1. Meta app
1. Create an app at developers.facebook.com with the **Instagram API with Instagram Login** product.
2. Valid OAuth redirect URI: `https://api.example.com/api/auth/instagram/callback`.
3. Set the Deauthorize and Data Deletion callback URLs to the backend's `/api/meta/*` endpoints (see `backend/src/routes/meta.ts`).
4. Request only `instagram_business_basic`. Complete App Review for production use. Only Business/Creator accounts can connect.

## 2. MongoDB Atlas
- Dedicated database `mutualx`; a user with **`readWrite` on that database only**.
- Network access: allow only Render's outbound IPs (or private networking). TLS is mandatory (`mongodb+srv://`).
- Enable continuous backups; **test a restore** at least quarterly (record the date in your runbook).

## 3. Render (backend)
Create the service from `render.yaml`. Set the `sync: false` variables in the dashboard — never in git:

| Variable | Value |
|---|---|
| `FRONTEND_URL` | `https://app.example.com/` |
| `API_PUBLIC_URL` | `https://api.example.com` |
| `MONGODB_URI` | Atlas URI (production user) |
| `SESSION_SECRET` | `openssl rand -base64 48` |
| `ENCRYPTION_KEYS` | `k1:$(openssl rand -base64 32)` |
| `META_APP_ID` / `META_APP_SECRET` / `META_REDIRECT_URI` | from Meta |
| `ADMIN_IG_USER_IDS` | your Instagram user id(s) |

Use **different** values for development, staging and production. The server refuses to boot in production with weak/placeholder secrets or non-https URLs.

**Key rotation:** prepend a new `id:key` to `ENCRYPTION_KEYS`, deploy, have users reconnect (or run a re-encrypt job), then drop the old key. Rotating `SESSION_SECRET` signs everyone out.

## 4. GitHub
1. Settings → Pages → Source: **GitHub Actions**; set the custom domain.
2. Repository **variable** `API_PUBLIC_URL` = the API origin (build-time, public).
3. Repository **secret** `RENDER_DEPLOY_HOOK_URL` (Render → Settings → Deploy Hook).
4. Edit `.github/CODEOWNERS` (replace `@OWNER`).
5. Run `scripts/protect-main.sh OWNER/REPO` (branch protection, secret scanning, push protection, Dependabot security updates).
6. Settings → Code security: enable the **dependency graph** and **CodeQL**.

CI (`.github/workflows/ci.yml`) gates both deploys on: secret scan, typecheck, unit tests, build, `npm audit` (high+), Playwright, and the 20-point report (no FAIL).

## 5. Post-deploy verification
- `GET https://api.example.com/api/health` → `{"status":"ok"}`.
- Sign in as an admin → `#/security` → **Run checks now**. Expect #6, #14, #16 to turn from *Needs review* to *Pass* only if their evidence supports it; investigate anything else.
- Complete the manual items listed on that page.

## Rollback
- **Backend:** Render → Deploys → pick the last good deploy → **Rollback**. Verify `/api/health`.
- **Frontend:** re-run the *CI* workflow on the last good commit (Actions → Run workflow on that ref), or `git revert` and push.
- **Secrets suspected exposed:** rotate immediately (Meta app secret, `SESSION_SECRET`, `ENCRYPTION_KEYS`, Mongo password), which signs all users out and invalidates stored tokens; then disconnect affected users.
- **Bad data change:** restore the Atlas backup to a new cluster, verify, then repoint `MONGODB_URI`.

## Troubleshooting CI
- **`secret-scan` fails on the very first push** with `ambiguous argument '<sha>^..<sha>'` and "no leaks found in partial scan": the gitleaks action tries to read the parent of the repository's root commit, which does not exist. It is not a leak and does not recur from the second push onward. Push any new commit (or re-run with *Run workflow*) and it passes.
- **`deploy-frontend` fails at `configure-pages`**: GitHub Pages is not enabled yet. Settings → Pages → Source: **GitHub Actions**, then re-run the workflow.
