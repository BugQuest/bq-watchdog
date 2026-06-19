#!/bin/bash
# Shared utilities

BQ_VERSION="${BQ_VERSION:-dev}"
BQ_HOSTNAME="$(hostname)"
BQ_TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

FINDINGS=()
SEVERITY=0   # 0=clean 1=warning 2=critical

log()  { echo "[$(date +%T)] $*"; }
warn() { log "WARN  $*"; }
err()  { log "ERROR $*" >&2; }

finding() {
    local sev="$1"   # warning | critical
    local title="$2"
    local detail="$3"
    FINDINGS+=("${sev}|${title}|${detail}")
    [[ "$sev" == "critical" ]] && SEVERITY=2
    [[ "$sev" == "warning"  && $SEVERITY -lt 2 ]] && SEVERITY=1
}

findings_count() { echo "${#FINDINGS[@]}"; }

findings_json_array() {
    local json="["
    local first=1
    for entry in "${FINDINGS[@]}"; do
        local sev="${entry%%|*}"; local rest="${entry#*|}"; local title="${rest%%|*}"; local detail="${rest#*|}"
        local color=$( [[ "$sev" == "critical" ]] && echo 15158332 || echo 16776960 )
        [[ $first -eq 0 ]] && json+=","
        json+="{\"color\":${color},\"title\":$(jq -Rn --arg v "[$sev] $title" '$v'),\"description\":$(jq -Rn --arg v "$detail" '$v')}"
        first=0
    done
    json+="]"
    echo "$json"
}

# Check if a command exists
need() { command -v "$1" &>/dev/null || { err "Missing: $1"; return 1; }; }
