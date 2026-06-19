#!/bin/bash
# Discord webhook notification

discord_send() {
    [[ -z "$DISCORD_WEBHOOK" ]] && return 0

    local embeds="$1"
    local status_color status_text status_emoji
    if [[ $SEVERITY -ge 2 ]]; then
        status_color=15158332; status_text="CRITIQUE"; status_emoji="🚨"
    elif [[ $SEVERITY -eq 1 ]]; then
        status_color=16776960; status_text="AVERTISSEMENT"; status_emoji="⚠️"
    else
        status_color=5025616; status_text="PROPRE"; status_emoji="✅"
    fi

    local count; count="$(findings_count)"
    local summary_embed
    summary_embed=$(jq -n \
        --arg host "$BQ_HOSTNAME" \
        --arg ts   "$BQ_TIMESTAMP" \
        --arg ver  "$BQ_VERSION" \
        --arg txt  "$status_emoji $status_text — $count finding(s) sur \`$BQ_HOSTNAME\`" \
        --argjson col "$status_color" \
        '{color:$col, title:$txt, footer:{text:("bq-watchdog "+$ver)}, timestamp:$ts}')

    local all_embeds
    all_embeds=$(jq -n --argjson s "[$summary_embed]" --argjson f "$embeds" '$s + $f')

    curl -fsSL -X POST "$DISCORD_WEBHOOK" \
        -H "Content-Type: application/json" \
        -d "$(jq -n --argjson e "$all_embeds" '{username:"bq-watchdog",embeds:$e}')" \
        &>/dev/null
}

discord_heartbeat() {
    [[ -z "$DISCORD_WEBHOOK" ]] && return 0
    [[ "$HEARTBEAT" != "1" ]] && return 0

    curl -fsSL -X POST "$DISCORD_WEBHOOK" \
        -H "Content-Type: application/json" \
        -d "$(jq -n --arg host "$BQ_HOSTNAME" --arg ts "$BQ_TIMESTAMP" --arg ver "$BQ_VERSION" \
            '{username:"bq-watchdog",embeds:[{color:5025616,title:("✅ Clean — "+$host),footer:{text:("bq-watchdog "+$ver)},timestamp:$ts}]}')" \
        &>/dev/null
}
