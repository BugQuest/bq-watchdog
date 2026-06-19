#!/bin/bash
# Suspicious crontab entries

check_crontabs() {
    # Patterns that indicate malicious crontab usage
    local EVIL_PATTERNS=(
        "curl.*\|.*bash"          # curl pipe to bash
        "wget.*\|.*bash"          # wget pipe to bash
        "curl.*\|.*sh"
        "wget.*\|.*sh"
        "/dev/shm/"               # execution from shared memory
        "/var/tmp/\.[a-z]"        # hidden dirs in /var/tmp
        "base64.*decode"          # base64 encoded payload
        "python.*-c.*exec"        # python exec
        "perl.*-e.*(socket|exec|system|eval|base64|chr\()" # perl one-liner with dangerous functions
        "disown"                  # common in malware crontabs to detach
        "195\.24\.237\.240"       # known C2
    )

    # Collect all crontabs
    local tmpfile; tmpfile=$(mktemp)
    cat /etc/crontab /etc/cron.d/* 2>/dev/null >> "$tmpfile"
    find /var/spool/cron/crontabs -type f 2>/dev/null | xargs cat 2>/dev/null >> "$tmpfile"

    for pat in "${EVIL_PATTERNS[@]}"; do
        local match
        match=$(grep -E "$pat" "$tmpfile" 2>/dev/null | grep -v '^#')
        if [[ -n "$match" ]]; then
            finding critical "Crontab suspect détecté" \
                "Pattern: $pat\nLigne(s):\n$match"
        fi
    done

    rm -f "$tmpfile"

    # Check for crontabs owned by unexpected users running from /tmp or /var/tmp
    for u in $(cut -d: -f1 /etc/passwd 2>/dev/null); do
        local ctab; ctab=$(crontab -u "$u" -l 2>/dev/null)
        [[ -z "$ctab" ]] && continue
        if echo "$ctab" | grep -qE '/tmp/|/var/tmp/|/dev/shm/'; then
            finding warning "Crontab de $u référence un répertoire temporaire" \
                "$(echo "$ctab" | grep -E '/tmp/|/var/tmp/|/dev/shm/')"
        fi
    done
}
