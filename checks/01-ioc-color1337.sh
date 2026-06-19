#!/bin/bash
# IoCs for Diicot / color1337 / ElPatrono1337 cryptomining campaign
# Ref: https://invirtuate.com/blog/incidents/ElPatrono1337-color1337-cryptomining-attack

check_ioc_color1337() {
    # Known backdoor SSH public key (same across all documented incidents)
    local BACKDOOR_KEY="AAAAB3NzaC1yc2EAAAABJQAAAQEAoBjnno5GBoIuIYIhrJsQxF6OPHtAbOUIEFB+gdfb1tUTjs+f9zCMGkmNmH45fYVukw6IwmhTZ+AcD3eDpgsTloqmVgcXDUmvjWR/fNiImmgU9wlw/lalf/WrIuCDp0PArQtjNg/vo7HUGq9SrEIE2jvyVW59mvoYOwfnDLUiguKZirZgpjZF2DDKK6WpZVTVpKcH+HEFdmFAqJInem/CRUE0bqjMr88bUyDjVw9FtJ5EmQenctjrFVaB7hswOaJBmFQmn9G/BXkMvZ6mX7LzCUM2PVHnVfVeCLdwiOINikzW9qzlr8WoHw4qEGJLuQBWXjJu+m2+FdaOD6PL53nY3w=="

    # Known C2 IPs / domains
    local C2_IPS=("195.24.237.240")
    local C2_DOMAINS=("digital.digitaldatainsights.org")

    # Known attacker IP ranges (VMHeaven.io)
    local ATTACKER_RANGES=("45.156.87.0/24" "176.65.132.0/24")

    # --- Backdoor SSH key in any authorized_keys ---
    while IFS= read -r -d '' f; do
        if grep -qF "$BACKDOOR_KEY" "$f" 2>/dev/null; then
            finding critical "Clé SSH backdoor ElPatrono1337 détectée" \
                "Fichier: $f\nLa clé SSH de la campagne Diicot/color1337 est présente. Compromission confirmée."
        fi
    done < <(find /root /home -name "authorized_keys" -print0 2>/dev/null)

    # --- Known malware filenames / patterns in temp dirs ---
    local SUSPECT_NAMES=(".ladyg0g0" ".pr1nc35" ".b4nd1d0" "fd93fba7" "ssshd" ".locatione")
    for name in "${SUSPECT_NAMES[@]}"; do
        local found
        found=$(find /var/tmp /tmp /dev/shm /usr/bin /usr/local/bin -name "$name" 2>/dev/null)
        [[ -n "$found" ]] && finding critical "Fichier malveillant color1337 détecté: $name" \
            "Chemin(s): $found"
    done

    # --- Known C2 in active connections ---
    for ip in "${C2_IPS[@]}"; do
        if ss -tn 2>/dev/null | grep -q "$ip"; then
            finding critical "Connexion active vers C2 color1337" \
                "IP C2: $ip — connexion réseau active détectée."
        fi
    done

    for domain in "${C2_DOMAINS[@]}"; do
        if ss -tn 2>/dev/null | grep -q "$domain" || \
           (command -v netstat &>/dev/null && netstat -tn 2>/dev/null | grep -q "$domain"); then
            finding critical "Connexion active vers domaine C2 color1337" \
                "Domaine: $domain"
        fi
    done

    # --- Known malware patterns in crontabs ---
    local CRON_PATTERNS=("\.b4nd1d0" "\.c90a5f7e\|fd93fba7\|21112101\|2958062d" "195\.24\.237\.240" "black3")
    local all_crons
    all_crons=$(cat /etc/cron* /var/spool/cron/crontabs/* 2>/dev/null; \
                for u in $(cut -d: -f1 /etc/passwd); do crontab -u "$u" -l 2>/dev/null; done)
    for pat in "${CRON_PATTERNS[@]}"; do
        if echo "$all_crons" | grep -qE "$pat"; then
            finding critical "Crontab malveillant color1337 détecté" \
                "Pattern trouvé: $pat"
        fi
    done

    # --- User 'node' (worm propagation account) ---
    if id node &>/dev/null; then
        finding critical "User 'node' présent (worm color1337)" \
            "Le malware crée ce compte pour se propager par SSH vers d'autres machines."
    fi

    # --- Systemd persistence service ---
    if [[ -f /usr/lib/systemd/system/myservices.service ]] || \
       [[ -f /etc/systemd/system/myservices.service ]]; then
        finding critical "Service systemd malveillant détecté: myservices.service" \
            "Mécanisme de persistance connu de la campagne color1337."
    fi

    # --- Known C2 outbound connections via DNS ---
    if command -v ss &>/dev/null; then
        for ip in "${C2_IPS[@]}"; do
            ss -tn state established 2>/dev/null | grep -q "$ip" && \
                finding critical "Connexion établie vers C2 color1337: $ip" ""
        done
    fi
}
