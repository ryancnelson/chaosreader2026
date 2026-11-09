#!/usr/bin/env bash
# install-hooks.sh — Install public-safety pre-commit and pre-push git hooks.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
hooks_dir="$(git rev-parse --git-path hooks)"
mkdir -p "$hooks_dir"

chmod +x "$repo_root/scripts/check-public-safety.sh"

cat > "$hooks_dir/pre-commit" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
repo_root="$(git rev-parse --show-toplevel)"
exec "$repo_root/scripts/check-public-safety.sh" --staged
EOF

cat > "$hooks_dir/pre-push" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
repo_root="$(git rev-parse --show-toplevel)"
exec "$repo_root/scripts/check-public-safety.sh" --all
EOF

chmod +x "$hooks_dir/pre-commit" "$hooks_dir/pre-push"
printf 'Installed pre-commit and pre-push safety hooks in %s\n' "$hooks_dir"
