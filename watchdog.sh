#!/bin/bash
# bq-watchdog — Linux server security monitor
# https://github.com/BugQuest/bq-watchdog

set -euo pipefail

BQ_VERSION="1.0.0"
BQ_REPO="BugQuest/bq-watchdog"
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${BQ_CONFIG:-$INSTALL_DIR/config}"

# Load config
if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
fi

DISCORD_WEBHOOK="${DISCORD_WEBHOOK:-}"
HEARTBEAT="${HEARTBEAT:-0}"
LOG_FILE="${LOG_FILE:-/var/log/bq-watchdog.log}"
CHECKS_DIR="${CHECKS_DIR:-$INSTALL_DIR/checks}"
LIB_DIR="${LIB_DIR:-$INSTALL_DIR/lib}"

# ── Argument parsing ────────────────────────────────────────────────────────

usage() {
    echo "Usage: $(basename "$0") [--update|--version|--help]"
    echo "  (no args)  Run security audit"
    echo "  --update   Check for and apply updates"
    echo "  --version  Show installed version"
}

case "${1:-}" in
    --version|-v)
        echo "bq-watchdog $BQ_VERSION"
        exit 0
        ;;
    --update|-u)
        _do_update=1
        ;;
    --help|-h)
        usage; exit 0
        ;;
    "")
        _do_update=0
        ;;
    *)
        echo "Unknown option: $1" >&2; usage >&2; exit 1
        ;;
esac

# ── Update logic ─────────────────────────────────────────────────────────────

do_update() {
    echo "bq-watchdog updater"
    echo "Installed : $BQ_VERSION"

    local latest
    latest=$(curl -fsSL "https://api.github.com/repos/${BQ_REPO}/releases/latest" \
        | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\(.*\)".*/\1/')

    if [[ -z "$latest" ]]; then
        echo "ERROR: Could not fetch latest version from GitHub." >&2
        exit 1
    fi

    echo "Latest    : $latest"

    # Strip leading 'v' for comparison
    local cur="${BQ_VERSION#v}"
    local new="${latest#v}"

    if [[ "$cur" == "$new" ]]; then
        echo "Already up to date."
        exit 0
    fi

    echo "Updating $BQ_VERSION → $latest ..."

    local tarball_url="https://github.com/${BQ_REPO}/releases/download/${latest}/bq-watchdog-${latest}.tar.gz"
    local tmp_dir; tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"' EXIT

    curl -fsSL "$tarball_url" -o "$tmp_dir/bq-watchdog.tar.gz" || {
        echo "ERROR: Download failed: $tarball_url" >&2; exit 1
    }

    # Backup config before overwriting
    local config_backup=""
    if [[ -f "$CONFIG_FILE" ]]; then
        config_backup="$tmp_dir/config.bak"
        cp "$CONFIG_FILE" "$config_backup"
    fi

    tar -xzf "$tmp_dir/bq-watchdog.tar.gz" -C "$INSTALL_DIR" --strip-components=1 \
        --exclude='*/config' --exclude='*/config.example'

    # Restore config
    if [[ -n "$config_backup" ]]; then
        cp "$config_backup" "$CONFIG_FILE"
    fi

    chmod +x "$INSTALL_DIR/watchdog.sh"

    echo "Updated to $latest"

    # Discord notification
    if [[ -n "$DISCORD_WEBHOOK" ]]; then
        curl -fsSL -X POST "$DISCORD_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "$(jq -n \
                --arg host "$(hostname)" \
                --arg ver "$latest" \
                '{username:"bq-watchdog",embeds:[{color:5025616,title:("🔄 Mis à jour → "+$ver+" sur "+$host),footer:{text:"bq-watchdog"}}]}')" \
            &>/dev/null || true
    fi

    exit 0
}

[[ "${_do_update:-0}" == "1" ]] && do_update

# ── Audit ─────────────────────────────────────────────────────────────────────

# Setup logging
exec > >(tee -a "$LOG_FILE") 2>&1

# Load libs
source "$LIB_DIR/utils.sh"
source "$LIB_DIR/notify.sh"

log "=== bq-watchdog $BQ_VERSION démarré sur $BQ_HOSTNAME ==="

# Load and run all checks
for check_file in "$CHECKS_DIR"/[0-9]*.sh; do
    [[ -f "$check_file" ]] || continue
    source "$check_file"
    func_name="check_$(basename "$check_file" .sh | sed 's/^[0-9]*-//')"
    if declare -f "$func_name" &>/dev/null; then
        log "Exécution: $func_name"
        "$func_name" || warn "$func_name a échoué"
    fi
done

# Report
COUNT="$(findings_count)"
log "=== Résultat: $COUNT finding(s) ==="

if [[ $COUNT -gt 0 ]]; then
    log "FINDINGS:"
    for entry in "${FINDINGS[@]}"; do
        local_sev="${entry%%|*}"; local_rest="${entry#*|}"; local_title="${local_rest%%|*}"
        log "  [$local_sev] $local_title"
    done
    EMBEDS="$(findings_json_array)"
    discord_send "$EMBEDS"
    exit 2
else
    log "Serveur propre."
    discord_heartbeat
    exit 0
fi
