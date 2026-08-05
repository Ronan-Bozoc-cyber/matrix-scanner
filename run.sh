#!/usr/bin/env bash
# =====================================================================================
# run.sh — Lance Matrix Scanner Pro (Interface ASCII Cyberpunk)
# =====================================================================================
# Active l'environnement virtuel, choisit un port libre (5000 ou >= 10001), et propose
# le choix du navigateur (Navigateur par défaut ou lancement d'OnionHop 3.7.8 + Ouverture
# du logiciel dans le navigateur par défaut).
# =====================================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Couleurs ANSI Cyberpunk / Matrix
GREEN="\e[1;32m"
CYAN="\e[1;36m"
WHITE="\e[1;37m"
YELLOW="\e[1;33m"
RED="\e[1;31m"
DIM="\e[2m"
RESET="\e[0m"

# Fonction d'affichage du Banner ASCII Art
show_ascii_banner() {
    clear 2>/dev/null || true
    echo -e "${GREEN}"
    echo " ╔═════════════════════════════════════════════════════════════════════════════╗"
    echo " ║                                                                             ║"
    echo " ║  ███╗   ███╗    ███████╗  ██████╗  █████╗  ███╗   ██╗                       ║"
    echo " ║  ████╗ ████║    ██╔════╝ ██╔════╝ ██╔══██╗ ████╗  ██║                       ║"
    echo " ║  ██╔████╔██║ ▄▄ ███████╗ ██║      ███████║ ██╔██╗ ██║ ▄▄  ████████╗         ║"
    echo " ║  ██║╚██╔╝██║    ╚════██║ ██║      ██╔══██║ ██║╚██╗██║     ╚═══════╝         ║"
    echo " ║  ██║ ╚═╝ ██║ ▀▀ ███████║ ╚██████╗ ██║  ██║ ██║ ╚████║ ▀▀  ████████╗         ║"
    echo " ║  ╚═╝     ╚═╝    ╚══════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═╝  ╚═══╝  ╚═══════╝         ║"
    echo " ║                                                                             ║"
    echo -e " ║              ${CYAN}[ Professional Reconnaissance & CVE Dashboard ]${GREEN}               ║"
    echo -e " ║                          ${WHITE}Concepteur : Ronan BOZOC${GREEN}                           ║"
    echo " ╚═════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

show_ascii_banner

if [ "$EUID" -eq 0 ]; then
    echo -e "${RED}[x] ERREUR : Ne lancez pas ce script avec sudo/root. Utilisez : ./run.sh${RESET}"
    exit 1
fi

if [ ! -d "venv" ]; then
    echo -e "${RED}[x] ERREUR : Environnement virtuel introuvable. Lancez d'abord : ./install.sh${RESET}"
    exit 1
fi

# shellcheck disable=SC1091
source venv/bin/activate

echo -e "${CYAN}[⚙] Analyse des ports réseau en cours...${RESET}"
DETECTED_PORT=$(python3 -c "import app; print(app.find_available_port(5000, 10001))" 2>/dev/null | tail -n 1)
export PORT="${DETECTED_PORT:-5000}"
URL="http://127.0.0.1:${PORT}"
ONION_BIN=""

get_or_install_onionhop() {
    for candidate in "onionhop" "onionhop-3.7.8" "onion-hop" "OnionHop" "$HOME/.local/bin/OnionHop-x86_64.AppImage" "$HOME/.local/bin/onionhop" "/usr/local/bin/OnionHop-x86_64.AppImage"; do
        if command -v "$candidate" &>/dev/null; then
            echo "$(command -v "$candidate")"
            return 0
        elif [ -x "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done

    echo ""
    echo -e "${YELLOW} ┌─────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${YELLOW} │  [!] OnionHop 3.7.8 n'est pas détecté sur votre système Linux.         │${RESET}"
    echo -e "${YELLOW} └─────────────────────────────────────────────────────────────────────────┘${RESET}"
    read -t 20 -r -p " [?] Télécharger et installer OnionHop depuis GitHub (center2055/v3.7.8) ? [O/n] : " DO_INSTALL || DO_INSTALL="O"
    DO_INSTALL="${DO_INSTALL:-O}"

    if [[ "$DO_INSTALL" =~ ^[OoYy]$ ]]; then
        echo -e "${CYAN}[⬇] Téléchargement d'OnionHop 3.7.8 AppImage depuis GitHub...${RESET}"
        mkdir -p "$HOME/.local/bin"
        TARGET_APPIMAGE="$HOME/.local/bin/OnionHop-x86_64.AppImage"
        GITHUB_RELEASE_URL="https://github.com/center2055/OnionHop/releases/download/v3.7.8/OnionHop-x86_64.AppImage"

        if curl -L --progress-bar -o "$TARGET_APPIMAGE" "$GITHUB_RELEASE_URL"; then
            chmod +x "$TARGET_APPIMAGE"
            ln -sf "$TARGET_APPIMAGE" "$HOME/.local/bin/onionhop" 2>/dev/null || true
            echo -e "${GREEN}[✔] OnionHop 3.7.8 installé dans : $TARGET_APPIMAGE${RESET}"
            echo "$TARGET_APPIMAGE"
            return 0
        else
            echo -e "${RED}[x] Échec du téléchargement d'OnionHop depuis GitHub.${RESET}"
            return 1
        fi
    else
        echo -e "${DIM}[i] Installation d'OnionHop ignorée.${RESET}"
        return 1
    fi
}

CHOICE="1"
if [ -t 0 ]; then
    echo -e "${GREEN}"
    echo " ┌─────────────────────────────────────────────────────────────────────────────┐"
    echo " │                       CHOIX DU MODE DE NAVIGATION                           │"
    echo " ├─────────────────────────────────────────────────────────────────────────────┤"
    echo -e " │  ${WHITE}[1]${GREEN} Navigateur Système par défaut (Firefox / Chrome / Brave)               │"
    echo -e " │  ${WHITE}[2]${GREEN} Lancer OnionHop 3.7.8 (Tor) + Ouvrir dans le Navigateur Système        │"
    echo " └─────────────────────────────────────────────────────────────────────────────┘"
    echo -e "${RESET}"
    read -t 15 -r -p " [▶] Entrez votre choix (1 ou 2) [Défaut 15s : 1] : " USER_CHOICE || USER_CHOICE="1"
    CHOICE="${USER_CHOICE:-1}"
fi

if [ "$CHOICE" = "2" ]; then
    ONION_BIN=$(get_or_install_onionhop || true)
fi

(
    sleep 2
    if [ "$CHOICE" = "2" ] && [ -n "$ONION_BIN" ]; then
        echo -e "${CYAN}[🚀] Lancement de l'application OnionHop 3.7.8 ($ONION_BIN)...${RESET}"
        "$ONION_BIN" &>/dev/null &
    fi

    echo -e "${GREEN}[🌐] Ouverture de M_SCAN _ dans le navigateur par défaut ($URL)...${RESET}"
    if command -v xdg-open &>/dev/null; then
        xdg-open "$URL" &>/dev/null &
    fi
) &

echo ""
echo -e "${GREEN} ┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
echo -e "${GREEN} │ ${WHITE}[★] DÉMARRAGE DE M_SCAN _ SUR ${CYAN}$URL${GREEN}${RESET}"
echo -e "${GREEN} └─────────────────────────────────────────────────────────────────────────────┘${RESET}"
echo ""

python3 app.py
