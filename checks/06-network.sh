#!/bin/bash
# Suspicious outbound network connections

check_network() {
    # Known malicious IPs / ranges
    local MALICIOUS_IPS=(
        "195.24.237.240"      # color1337 C2
    )
    local MALICIOUS_RANGES=(
        "45.156.87."          # VMHeaven.io (color1337 attacker infra)
        "176.65.132."         # VMHeaven.io
    )
    local MALICIOUS_DOMAINS=(
        "digital.digitaldatainsights.org"
    )

    local connections; connections=$(ss -tn state established 2>/dev/null)

    for ip in "${MALICIOUS_IPS[@]}"; do
        if echo "$connections" | grep -q "$ip"; then
            finding critical "Connexion active vers IP malveillante connue" \
                "IP: $ip\n$(echo "$connections" | grep "$ip")"
        fi
    done

    for range in "${MALICIOUS_RANGES[@]}"; do
        if echo "$connections" | grep -q "$range"; then
            finding critical "Connexion active vers range IP malveillant (attacker infra)" \
                "Range: ${range}0/24\n$(echo "$connections" | grep "$range")"
        fi
    done

    # Unusual outbound connections from non-standard processes
    # High-CPU processes with network connections = potential miner
    if command -v ss &>/dev/null; then
        # Connections from /tmp or /var/tmp binaries
        while IFS= read -r line; do
            local pid; pid=$(echo "$line" | grep -oP 'pid=\K[0-9]+')
            [[ -z "$pid" ]] && continue
            local exe; exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
            if echo "$exe" | grep -qE '^/tmp/|^/var/tmp/|^/dev/shm/'; then
                finding critical "Processus depuis répertoire temporaire avec connexion réseau" \
                    "PID: $pid | Binaire: $exe\n$line"
            fi
        done < <(ss -tnp state established 2>/dev/null | grep 'pid=')
    fi

    # Check for stratum mining protocol connections (port 3333, 4444, 5555, 7777, 14444, 45700)
    local MINING_PORTS=(3333 4444 5555 7777 14444 45700 14433)
    for port in "${MINING_PORTS[@]}"; do
        if ss -tn 2>/dev/null | grep -q ":${port}[[:space:]]"; then
            finding critical "Connexion vers port de minage détectée (stratum)" \
                "Port: $port\n$(ss -tn 2>/dev/null | grep ":${port}[[:space:]]")"
        fi
    done
}
