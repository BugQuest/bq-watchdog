#!/bin/bash
# Unauthorized users and SSH key anomalies

check_users() {
    # Users with shell access that shouldn't have it
    local SERVICE_USERS_WITH_SHELL=()
    while IFS=: read -r user _ uid _ _ home shell; do
        [[ "$shell" == "/bin/false" || "$shell" == "/usr/sbin/nologin" || "$shell" == "/bin/sync" ]] && continue
        [[ "$uid" -lt 1000 && "$uid" -ne 0 ]] && SERVICE_USERS_WITH_SHELL+=("$user (uid=$uid, shell=$shell)")
    done < /etc/passwd

    for u in "${SERVICE_USERS_WITH_SHELL[@]}"; do
        finding warning "User système avec shell interactif" \
            "$u — les comptes de service ne devraient pas avoir de shell."
    done

    # Check all authorized_keys for suspicious key comments
    while IFS= read -r -d '' f; do
        while IFS= read -r line; do
            [[ "$line" =~ ^#|^$ ]] && continue
            local comment; comment=$(echo "$line" | awk '{print $NF}')
            if echo "$comment" | grep -qiE '1337|h4x|pwn|r00t|backdoor|evil|hack|shell'; then
                finding critical "Clé SSH au nom suspect dans $f" \
                    "Commentaire: $comment\nLigne: ${line:0:80}..."
            fi
        done < "$f"
    done < <(find /root /home -name "authorized_keys" -print0 2>/dev/null)

    # Detect accounts added recently (within last 7 days) with sudo
    local week_ago; week_ago=$(date -d '7 days ago' +%s 2>/dev/null || date -v-7d +%s 2>/dev/null)
    if [[ -n "$week_ago" ]]; then
        while IFS=: read -r user _; do
            local home="/home/$user"
            [[ -d "$home" ]] || continue
            local created; created=$(stat -c %W "$home" 2>/dev/null)
            [[ -z "$created" || "$created" -eq 0 ]] && continue
            if [[ "$created" -gt "$week_ago" ]]; then
                if groups "$user" 2>/dev/null | grep -qE '\bsudo\b|\bwheel\b'; then
                    finding warning "Nouveau compte sudo créé récemment: $user" \
                        "Répertoire créé: $(date -d @$created 2>/dev/null || date -r $created)\nGroupe sudo — vérifier si c'est intentionnel."
                fi
            fi
        done < /etc/passwd
    fi

    # Root account should be locked for password auth
    local root_hash; root_hash=$(sudo awk -F: '$1=="root"{print $2}' /etc/shadow 2>/dev/null)
    if [[ -n "$root_hash" && "$root_hash" != "!" && "$root_hash" != "*" && "$root_hash" != "!!" ]]; then
        # Root has a password — only warn if SSH allows password auth
        local pw_auth; pw_auth=$(sshd -T 2>/dev/null | grep "^passwordauthentication" | awk '{print $2}')
        if [[ "$pw_auth" == "yes" ]]; then
            finding critical "Root a un mot de passe ET SSH accepte les mots de passe" \
                "Combinaison dangereuse — vecteur principal du brute force. Désactiver PasswordAuthentication ou verrouiller le compte root."
        fi
    fi
}
