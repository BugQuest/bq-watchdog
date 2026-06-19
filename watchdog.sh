#!/bin/bash
# bq-watchdog — Linux server security monitor
# https://github.com/BugQuest/bq-watchdog

set -euo pipefail

BQ_VERSION="1.0.0"
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
