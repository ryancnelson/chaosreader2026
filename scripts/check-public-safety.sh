#!/usr/bin/env bash
# check-public-safety.sh — Prevent accidental commits of captures, keys,
# machine-specific paths/hostnames, internal domains, or credentials.
set -euo pipefail

MODE="${1:---staged}"

fail=0
err() {
    printf 'PUBLIC-SAFETY FAIL: %s\n' "$1" >&2
    fail=1
}

# 1. Verify git author email will not leak a local machine/LAN/VPN hostname.
author_email="$(git config user.email || true)"
if [[ -z "$author_email" ]]; then
    err "git user.email is unset (git would auto-generate user@hostname). Set repo-local user.email (e.g. noreply)."
elif [[ "$author_email" =~ \.(local|lan|internal|home|arpa|ts\.net)$ ]]; then
    err "git user.email ('$author_email') exposes a local/private domain. Use a public or GitHub noreply address."
fi

# Collect target file list and diff content.
if [[ "$MODE" == "--all" ]]; then
    files="$(git ls-files)"
    diff_text="$(git grep -nI '' -- . ':!scripts/check-public-safety.sh' || true)"
else
    files="$(git diff --cached --name-only --diff-filter=ACMR)"
    diff_text="$(git diff --cached -U0 -- . ':!scripts/check-public-safety.sh' | grep -E '^\+[^+]' || true)"
fi

# 2. Block dangerous file types regardless of content.
if [[ -n "$files" ]]; then
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        case "$f" in
            *.pcap|*.pcapng|*.cap|*.dmp|*.snoop|*.erf|*.har|*.etl)
                err "Packet capture staged: $f"
                ;;
            *keylog*|*.pem|*.key|*.p12|*.pfx|*.jks|.env|.env.*|.netrc)
                [[ "$f" == ".env.example" ]] && continue
                err "Key/secret/env file staged: $f"
                ;;
            *.local.md)
                err "Local agent instruction file staged: $f"
                ;;
        esac
    done <<< "$files"
fi

# 3. Scan added lines for local paths, hostnames, private domains, and secret tokens.
if [[ -n "$diff_text" ]]; then
    # Dynamic environment checks (no personal strings stored in repo).
    if [[ -n "${HOME:-}" ]] && grep -Fq "$HOME" <<< "$diff_text"; then
        err "Diff contains literal \$HOME path."
    fi

    short_host="$(hostname -s 2>/dev/null || true)"
    full_host="$(hostname 2>/dev/null || true)"
    for h in "$short_host" "$full_host"; do
        if [[ -n "$h" && "$h" != "localhost" && ${#h} -ge 4 ]]; then
            if grep -Fqi "$h" <<< "$diff_text"; then
                err "Diff references current machine hostname."
            fi
        fi
    done

    # Generic filesystem user path patterns.
    if grep -Eq '(/Users/[A-Za-z0-9._-]+/|/home/[A-Za-z0-9._-]+/|/Volumes/[A-Za-z0-9._-]+/)' <<< "$diff_text"; then
        err "Diff contains an OS user/volume filesystem path (/Users, /home, or /Volumes)."
    fi

    # Internal domains (mDNS, Tailscale, RFC-private naming) and CGNAT/Tailscale 100.64.0.0/10 IPs.
    if grep -Eiq '([a-z0-9-]+\.(ts\.net|local|lan|internal|home\.arpa)\b)' <<< "$diff_text"; then
        err "Diff contains a private/internal hostname (.ts.net, .local, .lan, .internal, .home.arpa)."
    fi
    if grep -Eq '\b100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}\b' <<< "$diff_text"; then
        err "Diff contains a 100.64.0.0/10 CGNAT/VPN IP address."
    fi

    # High-confidence credential patterns.
    if grep -Eq '(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|dp\.(st|pt|ct)\.[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)' <<< "$diff_text"; then
        err "Diff matches a known API token or private key pattern."
    fi
fi

# 4. Run gitleaks if available on PATH.
if command -v gitleaks >/dev/null 2>&1; then
    if [[ "$MODE" == "--all" ]]; then
        gitleaks dir --no-banner . || err "gitleaks flagged repository content."
    else
        gitleaks git --staged --no-banner || err "gitleaks flagged staged changes."
    fi
fi

if [[ "$fail" -ne 0 ]]; then
    exit 1
fi
