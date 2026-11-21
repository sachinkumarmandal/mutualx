# Unresolved risks & verification status

MutualX is **not declared production-ready** until every item below marked ☐ is closed by a human. Last reviewed: 2026-11-21.

## Verified in this repository
- ✔ Backend: 35 automated tests (API behaviour, security units, the 20 checks).
- ✔ Frontend: unit tests (parser allow-list, set maths, CSV safety) and 12 Playwright tests (desktop + mobile).
- ✔ `npm audit`: 0 known vulnerabilities (backend and frontend) at time of writing.
- ✔ 20-point report in a development environment: **17 pass · 0 fail · 3 needs review** (#6 OAuth, #14 default credentials, #16 HTTPS — each needs real Meta credentials, a production database or a production https deployment to be verified; see below).

## Not verifiable from here (☐ = open)
| | Risk / gap | Why it is open | Action |
|---|---|---|---|
| ☐ | **Real Meta OAuth handshake never exercised** | No Meta app credentials were available; flow was tested against probes and a mocked Meta endpoint. | Configure the app, sign in end-to-end in staging, then re-run check #6. |
| ☐ | **Meta API surface may change** | Endpoints/scopes follow Meta's documentation as understood at build time. | Re-verify against current docs and App Review requirements. |
| ☐ | **Only professional accounts can connect** | Meta API restriction. | Communicated in UI; personal accounts still get the export-based tool. |
| ☐ | **Cross-site cookies** | GitHub Pages and Render default domains are different sites. | Use custom domains on one registrable domain. |
| ☐ | **MongoDB hardening** | Least-privilege user, IP allow-list, TLS, encryption at rest and backups are provider settings. | Verify in Atlas; test a restore. |
| ☐ | **Branch protection / secret scanning** | Repository settings, not code. | Run `scripts/protect-main.sh`. |
| ☐ | **GitHub Action versions** | Pinned to major tags (could not look up SHAs offline). | Pin to commit SHAs; Dependabot keeps them updated. |
| ☐ | **Static frontend headers** | GitHub Pages cannot set HTTP headers; CSP is a `<meta>` tag (no `frame-ancestors`). | Front the site with a host/CDN that can set headers if clickjacking matters. |
| ☐ | **Rate-limit store is in-memory** | Per-instance counters. | Fine for one Render instance; use a shared store before scaling out. |
| ☐ | **Export format drift** | Instagram may change the export JSON layout. | The parser fails closed with a clear message; add fixtures when the format changes. |
| ☐ | **No independent penetration test** | Self-verification only. | Commission a review before handling real users at scale. |
| ☐ | **Privacy policy & legal** | Needed for Meta App Review and GDPR/DPDP-style obligations. | Publish a policy covering: stored fields (IG user id, username, account type, encrypted token, audit events), retention (`AUDIT_RETENTION_DAYS`), deletion. |

## Design decisions worth knowing
- Follower/following files are processed client-side only; the API rejects non-JSON bodies and uploads, so there is no server-side upload surface to exploit.
- The dashboard is admin-only because it reveals implementation detail.
