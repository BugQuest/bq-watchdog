#!/bin/bash
# SSH configuration drift detection

check_ssh_config() {
    # Read effective sshd config (what's actually loaded, not just the file)
    if ! command -v sshd &>/dev/null; then
        warn "sshd non trouvé, check SSH ignoré"
        return
    fi

    local effective
    effective=$(sshd -T 2>/dev/null)

    # PasswordAuthentication must be no
    if echo "$effective" | grep -qi "^passwordauthentication yes"; then
        local override_file=""
        for f in /etc/ssh/sshd_config.d/*.conf; do
            grep -qi "passwordauthentication yes" "$f" 2>/dev/null && override_file=" (réécrit par $f)"
        done
        finding critical "PasswordAuthentication activé sur SSH${override_file}" \
            "L'authentification par mot de passe SSH est active. Vecteur d'entrée principal du brute force.\nVérifier: sshd -T | grep passwordauthentication\nFix: echo 'PasswordAuthentication no' > /etc/ssh/sshd_config.d/99-hardening.conf && systemctl reload sshd"
    fi

    # PermitRootLogin should not be 'yes'
    if echo "$effective" | grep -qi "^permitrootlogin yes$"; then
        finding warning "PermitRootLogin yes — connexion root par mot de passe autorisée" \
            "Recommandé: PermitRootLogin prohibit-password (clé SSH seulement)"
    fi

    # PermitEmptyPasswords must be no
    if echo "$effective" | grep -qi "^permitemptypasswords yes"; then
        finding critical "PermitEmptyPasswords activé" \
            "Les mots de passe vides sont autorisés en SSH. Critique."
    fi

    # cloud-init override check (the silent killer)
    local ci_file="/etc/ssh/sshd_config.d/50-cloud-init.conf"
    if [[ -f "$ci_file" ]]; then
        if grep -qi "passwordauthentication yes" "$ci_file"; then
            finding critical "cloud-init réécrit PasswordAuthentication yes" \
                "Le fichier $ci_file annule la config principale sshd_config.\nFix: echo 'PasswordAuthentication no' > $ci_file"
        fi
    fi

    # Check for unauthorized keys in root
    if [[ -f /root/.ssh/authorized_keys ]]; then
        local count
        count=$(grep -c 'ssh-' /root/.ssh/authorized_keys 2>/dev/null || echo 0)
        if [[ $count -gt 0 ]]; then
            local keys
            keys=$(grep 'ssh-' /root/.ssh/authorized_keys 2>/dev/null | awk '{print $NF}')
            # Only warn if any key comment looks suspicious
            echo "$keys" | grep -qiE '1337|h4x|r00t|admin_back|backdoor|test_key' && \
                finding critical "Clé SSH root au nom suspect" \
                    "Vérifier /root/.ssh/authorized_keys:\n$keys"
        fi
    fi
}
