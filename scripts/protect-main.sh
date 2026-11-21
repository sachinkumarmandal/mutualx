#!/usr/bin/env bash
# Enables branch protection on main. Requires the GitHub CLI authenticated as a repo admin.
# Usage: scripts/protect-main.sh OWNER/REPO
set -euo pipefail
repo="${1:?usage: protect-main.sh OWNER/REPO}"
gh api -X PUT "repos/$repo/branches/main/protection" --input - <<'JSON'
{
  "required_status_checks": { "strict": true, "contexts": ["secret-scan", "backend", "frontend", "e2e", "security-report", "analyze"] },
  "enforce_admins": true,
  "required_pull_request_reviews": { "required_approving_review_count": 1, "require_code_owner_reviews": true, "dismiss_stale_reviews": true },
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true
}
JSON
# Repository-level scanning features
gh api -X PATCH "repos/$repo" --input - <<'JSON'
{ "security_and_analysis": { "secret_scanning": {"status":"enabled"}, "secret_scanning_push_protection": {"status":"enabled"}, "dependabot_security_updates": {"status":"enabled"} } }
JSON
echo "Branch protection and secret scanning enabled on $repo/main"
