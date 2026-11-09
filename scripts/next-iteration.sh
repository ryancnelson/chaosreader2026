#!/usr/bin/env bash
# next-iteration.sh - Start a new iterate-bot iteration branch
#
# Usage:
#   ./scripts/next-iteration.sh "feature-slug"

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

PROJECT_NAME="$(basename "$PROJECT_ROOT")"
printf '=== %s — New Iteration ===\n\n' "$PROJECT_NAME"

# 1. Require clean git state
if ! git diff-index --quiet HEAD --; then
    printf 'Error: Uncommitted changes present. Commit or stash before starting a new iteration.\n\n' >&2
    git status --short >&2
    exit 1
fi

# 2. Derive iteration count from git log (no state file)
CURRENT_ITERATION="$(git log --oneline --grep='\[iter-' | wc -l | tr -d ' ')"
NEXT_ITERATION=$((CURRENT_ITERATION + 1))

printf 'Completed iterations: %s\n' "$CURRENT_ITERATION"
printf 'Starting iteration:   %s\n\n' "$NEXT_ITERATION"

# 3. Check strategic review cadence (every 8 completed iterations -> before iter 9, 17, 25; or at 8, 16, 24)
if [ $((NEXT_ITERATION % 8)) -eq 0 ]; then
    printf 'NOTE: Strategic review milestone at iteration %s — review STRATEGIC-REVIEW-CHECKLIST.md\n\n' "$NEXT_ITERATION"
fi

# 4. Display top Priority 1 items from BACKLOG.md
if [ -f "BACKLOG.md" ]; then
    printf '=== Top Priority 1 Items (BACKLOG.md) ===\n'
    sed -n '/^## Priority 1:/,/^## Priority 2:/p' BACKLOG.md | grep '^- \[ \]' | head -n 5 || true
    printf '\n'
fi

# 5. Determine branch slug
if [ $# -eq 0 ]; then
    read -r -p "Feature slug (e.g. pcapng-ingest): " FEATURE_NAME
else
    FEATURE_NAME="$1"
fi

SLUG="$(printf '%s' "$FEATURE_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g; s/--*/-/g; s/^-//; s/-$//')"
if [ -z "$SLUG" ]; then
    printf 'Error: Feature slug cannot be empty.\n' >&2
    exit 1
fi

BRANCH_NAME="iter-${NEXT_ITERATION}-${SLUG}"
git checkout -b "$BRANCH_NAME"

cat <<EOF

Ready for iteration $NEXT_ITERATION on branch '$BRANCH_NAME':
  1. RED:      Write one minimal failing test first; run 'cargo test' and watch it fail.
  2. GREEN:    Write minimal code to pass; run 'cargo test'.
  3. REFACTOR: Clean up while keeping 'cargo test' + 'cargo clippy --all-targets -- -D warnings' green.
  4. SAFETY:   Run './scripts/check-public-safety.sh --all'.
  5. COMMIT:   git commit -m "[iter-${NEXT_ITERATION}] feat: ..."
  6. CLOSE:    Merge to main and move item to Completed in BACKLOG.md.
EOF
