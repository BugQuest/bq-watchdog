#!/bin/bash
# Suspicious running processes

check_processes() {
    # Processes running from temp directories
    while IFS= read -r pid; do
        local exe; exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
        [[ -z "$exe" ]] && continue
        if echo "$exe" | grep -qE '^/tmp/|^/var/tmp/|^/dev/shm/'; then
            local user; user=$(stat -c '%U' "/proc/$pid" 2>/dev/null)
            local cpu;  cpu=$(ps -p "$pid" -o %cpu= 2>/dev/null | tr -d ' ')
            finding critical "Processus en cours depuis répertoire temporaire" \
                "PID: $pid | User: $user | CPU: ${cpu}%\nBinaire: $exe"
        fi
    done < <(ls /proc | grep -E '^[0-9]+$')

    # High CPU processes with no known path (deleted binaries running in memory)
    while IFS= read -r line; do
        local pid; pid=$(echo "$line" | awk '{print $2}')
        local cpu; cpu=$(echo "$line" | awk '{print $3}' | cut -d. -f1)
        [[ "$cpu" -lt 50 ]] && continue  # only flag >50% CPU

        local exe; exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
        if echo "$exe" | grep -q "(deleted)"; then
            finding warning "Processus haute CPU avec binaire supprimé (running in memory)" \
                "PID: $pid | CPU: ${cpu}%\nBinaire (supprimé): $exe\nTechnique courante pour dissimuler les mineurs."
        fi
    done < <(ps aux --no-headers 2>/dev/null)

    # Processes with suspicious command names (obfuscated hex names typical of color1337)
    while IFS= read -r line; do
        local cmd; cmd=$(echo "$line" | awk '{print $11}' | xargs basename 2>/dev/null)
        if echo "$cmd" | grep -qE '^[0-9a-f]{8}$'; then
            local pid; pid=$(echo "$line" | awk '{print $2}')
            local exe; exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
            finding critical "Processus au nom hexadécimal obfusqué (pattern color1337)" \
                "Commande: $cmd | PID: $pid\nBinaire: $exe\nLes mineurs Diicot utilisent des noms à 8 caractères hex (ex: fd93fba7, c90a5f7e)."
        fi
    done < <(ps aux --no-headers 2>/dev/null)

    # Known miner process names
    # Note: kswapd0 is a legitimate kernel thread when shown with brackets [kswapd0].
    # Only flag if it runs as a userspace process (no brackets, non-zero exe path).
    local MINER_NAMES=("xmrig" "xmr-stak" "minerd" "cpuminer" "cryptonight" "kworkerds")
    for name in "${MINER_NAMES[@]}"; do
        if pgrep -x "$name" &>/dev/null; then
            finding critical "Processus mineur connu détecté: $name" \
                "$(pgrep -a "$name" 2>/dev/null)"
        fi
    done

    # kswapd0 specifically: kernel thread if exe is empty, miner if it has a real path
    while IFS= read -r pid; do
        local exe; exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
        if [[ -n "$exe" && "$exe" != *"(deleted)"* ]]; then
            finding critical "kswapd0 userspace détecté — probable mineur XMRig" \
                "PID: $pid | Binaire: $exe\n[kswapd0] avec crochets = kernel légitime. Sans crochets et avec binaire = mineur."
        fi
    done < <(pgrep -x "kswapd0" 2>/dev/null || true)
}
