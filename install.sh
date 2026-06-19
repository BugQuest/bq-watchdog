#!/bin/bash
# bq-watchdog installer
# Usage: curl -fsSL https://github.com/BugQuest/bq-watchdog/releases/latest/download/install.sh | bash

set -euo pipefail

REPO="BugQuest/bq-watchdog"
INSTALL_DIR="/opt/bq-watchdog"
CRON_INTERVAL="${CRON_INTERVAL:-30}"  # minutes

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $*"; }
info() { echo -e "${CYAN}→${NC} $*"; }
warn() { echo -e "${YELLOW}⚠${NC} $*"; }
die()  { echo -e "${RED}✗ $*${NC}" >&2; exit 1; }

echo ""
echo -e "${CYAN}╔════════════════════════════════════╗${NC}"
echo -e "${CYAN}║         bq-watchdog installer       ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════╝${NC}"
echo ""

# Root check
[[ $EUID -eq 0 ]] || die "Lance en root: sudo bash install.sh"

# Dependencies
for dep in curl jq; do
    command -v "$dep" &>/dev/null || { info "Installation de $dep..."; apt-get install -y -q "$dep"; }
done

# Get latest version
info "Récupération de la dernière version..."
LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | jq -r .tag_name 2>/dev/null || echo "")
if [[ -z "$LATEST" ]]; then
    die "Impossible de récupérer la dernière version depuis GitHub."
fi
ok "Version: $LATEST"

# Download
TARBALL_URL="https://github.com/${REPO}/releases/download/${LATEST}/bq-watchdog-${LATEST}.tar.gz"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

info "Téléchargement..."
curl -fsSL "$TARBALL_URL" -o "$TMP_DIR/bq-watchdog.tar.gz" || \
    die "Échec du téléchargement: $TARBALL_URL"

# Install
info "Installation dans $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
tar -xzf "$TMP_DIR/bq-watchdog.tar.gz" -C "$INSTALL_DIR" --strip-components=1
chmod +x "$INSTALL_DIR/watchdog.sh"

# Configuration
echo ""
echo -e "${CYAN}Configuration${NC}"
echo "────────────────────────────────────"

CONFIG_FILE="$INSTALL_DIR/config"
DISCORD_WEBHOOK=""
HEARTBEAT="0"

# Discord webhook
read -r -p "Webhook Discord (laisser vide pour désactiver): " DISCORD_WEBHOOK
if [[ -n "$DISCORD_WEBHOOK" ]]; then
    ok "Webhook configuré"
    read -r -p "Envoyer un message 'clean' si aucun finding ? [o/N]: " hb_answer
    [[ "$hb_answer" =~ ^[oOyY] ]] && HEARTBEAT="1"
else
    warn "Pas de webhook — les résultats seront seulement dans les logs."
fi

# Cron interval
read -r -p "Intervalle de vérification en minutes [défaut: 30]: " cron_input
CRON_INTERVAL="${cron_input:-30}"

# Write config
cat > "$CONFIG_FILE" <<EOF
DISCORD_WEBHOOK="${DISCORD_WEBHOOK}"
HEARTBEAT="${HEARTBEAT}"
LOG_FILE="/var/log/bq-watchdog.log"
CHECKS_DIR="${INSTALL_DIR}/checks"
LIB_DIR="${INSTALL_DIR}/lib"
EOF
chmod 600 "$CONFIG_FILE"
ok "Config écrite dans $CONFIG_FILE"

# Cron
CRON_LINE="*/${CRON_INTERVAL} * * * * root ${INSTALL_DIR}/watchdog.sh"
echo "$CRON_LINE" > /etc/cron.d/bq-watchdog
chmod 644 /etc/cron.d/bq-watchdog
ok "Cron installé: toutes les ${CRON_INTERVAL} minutes"

# Log file
touch /var/log/bq-watchdog.log
chmod 640 /var/log/bq-watchdog.log

# First run
echo ""
info "Premier audit en cours..."
echo "────────────────────────────────────"
bash "$INSTALL_DIR/watchdog.sh" && {
    echo ""
    ok "Serveur propre !"
} || {
    echo ""
    warn "Des findings ont été détectés — voir les résultats ci-dessus."
    [[ -n "$DISCORD_WEBHOOK" ]] && info "Alerte envoyée sur Discord."
}

echo ""
echo -e "${GREEN}Installation terminée.${NC}"
echo "  Logs      : /var/log/bq-watchdog.log"
echo "  Config    : $CONFIG_FILE"
echo "  Prochain  : dans $CRON_INTERVAL minutes (cron)"
echo "  Manuel    : sudo $INSTALL_DIR/watchdog.sh"
echo ""
