#!/bin/bash
# Suspicious files in temporary directories

check_tmp_files() {
    local DIRS=("/var/tmp" "/tmp" "/dev/shm")
    local MAX_AGE_DAYS=1  # ELF binaries in /tmp older than 1 day are suspicious

    for dir in "${DIRS[@]}"; do
        [[ -d "$dir" ]] || continue

        # ELF binaries (executables) in temp dirs — always suspicious
        while IFS= read -r -d '' f; do
            if file "$f" 2>/dev/null | grep -q "ELF"; then
                local owner; owner=$(stat -c '%U' "$f" 2>/dev/null)
                local size;  size=$(stat -c '%s' "$f" 2>/dev/null)
                finding critical "Binaire ELF dans répertoire temporaire" \
                    "Fichier: $f\nPropriétaire: $owner | Taille: ${size} bytes\nLes mineurs et malwares se déploient typiquement dans /var/tmp ou /dev/shm."
            fi
        done < <(find "$dir" -type f -print0 2>/dev/null)

        # Hidden directories in /var/tmp or /tmp
        while IFS= read -r -d '' d; do
            finding warning "Répertoire caché dans $dir" \
                "Chemin: $d — les malwares utilisent des noms cachés dans /var/tmp pour persister entre les reboots."
        done < <(find "$dir" -maxdepth 2 -type d -name '.*' -print0 2>/dev/null)

        # Shell scripts in temp dirs
        while IFS= read -r -d '' f; do
            local first_line; first_line=$(head -1 "$f" 2>/dev/null)
            if echo "$first_line" | grep -q "^#!.*sh\|^#!.*bash"; then
                local content; content=$(cat "$f" 2>/dev/null)
                if echo "$content" | grep -qE "curl.*bash|wget.*bash|curl.*sh|base64"; then
                    finding critical "Script shell malveillant dans $dir" \
                        "Fichier: $f\nContenu suspect (curl|pipe|base64 détecté)"
                fi
            fi
        done < <(find "$dir" -type f -name '.*' -print0 2>/dev/null)
    done
}
