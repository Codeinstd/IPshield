#!/usr/bin/env bash
# scripts/clean-repo.sh
#
# Removes node_modules/ and ipshield.db from git tracking
# and optionally purges them from the full commit history.
#
# Run from the root of the IPShield repository.
# Prerequisites: git, and optionally git-filter-repo (pip install git-filter-repo)
#
# Usage:
#   chmod +x scripts/clean-repo.sh
#   ./scripts/clean-repo.sh          # basic cleanup
#   ./scripts/clean-repo.sh --purge  # also purge from full history (recommended)

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

info()    { echo -e "${GREEN}✓${NC}  $*"; }
warn()    { echo -e "${YELLOW}!${NC}  $*"; }
error()   { echo -e "${RED}✗${NC}  $*"; exit 1; }

PURGE=false
[[ "${1:-}" == "--purge" ]] && PURGE=true

# ── Step 1: Update .gitignore ─────────────────────────────────────────────────

GITIGNORE=".gitignore"

add_to_gitignore() {
  local entry="$1"
  if ! grep -qxF "$entry" "$GITIGNORE" 2>/dev/null; then
    echo "$entry" >> "$GITIGNORE"
    info "Added '$entry' to .gitignore"
  else
    warn "'$entry' already in .gitignore"
  fi
}

echo ""
echo "── Step 1: Updating .gitignore ──────────────────────"
add_to_gitignore "node_modules/"
add_to_gitignore "*.db"
add_to_gitignore "*.db-shm"
add_to_gitignore "*.db-wal"
add_to_gitignore ".env"
add_to_gitignore ".env.local"
add_to_gitignore "logs/*.log"

# ── Step 2: Untrack from current index ───────────────────────────────────────

echo ""
echo "── Step 2: Removing from git index ──────────────────"

untrack() {
  local path="$1"
  if git ls-files --error-unmatch "$path" &>/dev/null; then
    git rm -r --cached "$path"
    info "Untracked '$path'"
  else
    warn "'$path' was not tracked — skipping"
  fi
}

untrack "node_modules" 2>/dev/null || true
untrack "ipshield.db"  2>/dev/null || true

# ── Step 3: Commit the cleanup ───────────────────────────────────────────────

echo ""
echo "── Step 3: Committing cleanup ───────────────────────"
if git diff --cached --quiet; then
  warn "Nothing staged to commit — already clean"
else
  git add .gitignore
  git commit -m "chore: remove node_modules and db files from tracking

- Added node_modules/, *.db, *.db-shm, *.db-wal, .env to .gitignore
- Removed existing tracked copies from the git index
- Database is now managed via DATABASE_URL environment variable
- Dependencies are installed via npm install, not committed"
  info "Committed cleanup"
fi

# ── Step 4: History purge (optional) ─────────────────────────────────────────

if [[ "$PURGE" == true ]]; then
  echo ""
  echo "── Step 4: Purging from full history ────────────────"
  warn "This rewrites all commits. Everyone must re-clone after you force-push."
  echo ""
  read -rp "   Are you sure? Type YES to continue: " confirm
  [[ "$confirm" != "YES" ]] && { warn "Aborted."; exit 0; }

  if ! command -v git-filter-repo &>/dev/null; then
    error "git-filter-repo not found. Install it: pip install git-filter-repo"
  fi

  git-filter-repo \
    --path node_modules --invert-paths \
    --path ipshield.db  --invert-paths \
    --path-glob '*.db-shm' --invert-paths \
    --path-glob '*.db-wal' --invert-paths \
    --force

  info "History purged. Force-push all branches to remote:"
  echo "   git push origin --force --all"
  echo "   git push origin --force --tags"
  echo ""
  warn "All collaborators must: git clone <repo> (fresh clone, not pull)"
else
  echo ""
  echo "── Step 4 skipped (run with --purge to rewrite history) ─"
fi

echo ""
info "Done. Next steps:"
echo "   1. Push: git push"
echo "   2. Add DATABASE_URL to your Render/Railway environment"
echo "   3. Run: npm install   (locally, after fresh clone)"
echo ""
