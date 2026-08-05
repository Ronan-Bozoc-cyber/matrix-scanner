#!/usr/bin/env bash
# =====================================================================================
# run.sh — Lance Matrix Scanner
# =====================================================================================
# Active l'environnement virtuel, choisit un port libre (5000 ou >= 10001), et propose
# le choix du navigateur (Navigateur par défaut ou OnionHop 3.7.8 avec option d'installation
# depuis GitHub sous Linux).
# =====================================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ "$EUID" -eq 0 ]; then
    echo "[x] Ne lancez pas ce script avec sudo/root. Utilisez simplement : ./run.sh"
    exit 1
fi

if [ ! -d "venv" ]; then
    echo "[x] Environnement virtuel introuvable. Lancez d'abord : ./install.sh"
    exit 1
fi

# shellcheck disable=SC1091
source venv/bin/activate

# Détermination dynamique du port (5000 si libre, sinon port libre >= 10001)
DETECTED_PORT=$(python3 -c "import app; print(app.find_available_port(5000, 10001))" 2>/dev/null | tail -n 1)
export PORT="${DETECTED_PORT:-5000}"
URL="http://127.0.0.1:${PORT}"
ONION_BIN=""

# Fonction de détection ou d'installation d'OnionHop 3.7.8 depuis GitHub
get_or_install_onionhop() {
    # 1. Vérifier si un binaire OnionHop existe déjà
    for candidate in "onionhop" "onionhop-3.7.8" "onion-hop" "OnionHop" "$HOME/.local/bin/OnionHop-x86_64.AppImage" "$HOME/.local/bin/onionhop" "/usr/local/bin/OnionHop-x86_64.AppImage"; do
        if command -v "$candidate" &>/dev/null; then
            echo "$(command -v "$candidate")"
            return 0
        elif [ -x "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done

    # 2. Si introuvable, proposer le téléchargement/installation depuis GitHub
    echo ""
    echo "[!] OnionHop 3.7.8 n'est pas installé sur votre système Linux."
    read -t 20 -r -p "Voulez-vous le télécharger et l'installer depuis GitHub (center2055/OnionHop v3.7.8) ? [O/n] : " DO_INSTALL || DO_INSTALL="O"
    DO_INSTALL="${DO_INSTALL:-O}"

    if [[ "$DO_INSTALL" =~ ^[OoYy]$ ]]; then
        echo "[+] Téléchargement d'OnionHop 3.7.8 AppImage depuis GitHub (center2055/OnionHop)..."
        mkdir -p "$HOME/.local/bin"
        TARGET_APPIMAGE="$HOME/.local/bin/OnionHop-x86_64.AppImage"
        GITHUB_RELEASE_URL="https://github.com/center2055/OnionHop/releases/download/v3.7.8/OnionHop-x86_64.AppImage"

        if curl -L --progress-bar -o "$TARGET_APPIMAGE" "$GITHUB_RELEASE_URL"; then
            chmod +x "$TARGET_APPIMAGE"
            ln -sf "$TARGET_APPIMAGE" "$HOME/.local/bin/onionhop" 2>/dev/null || true
            echo "[+] OnionHop 3.7.8 a été installé avec succès dans : $TARGET_APPIMAGE"
            echo "$TARGET_APPIMAGE"
            return 0
        else
            echo "[x] Échec du téléchargement d'OnionHop depuis GitHub."
            return 1
        fi
    else
        echo "[i] Installation d'OnionHop ignorée."
        return 1
    fi
}

CHOICE="1"
if [ -t 0 ]; then
    echo ""
    echo "================================================================="
    echo "       MATRIX SCANNER PRO — CHOIX DU NAVIGATEUR         "
    echo "================================================================="
    echo "  1) Ouvrir dans le navigateur par défaut (ex: Firefox/Chrome)"
    echo "  2) Ouvrir dans OnionHop 3.7.8 (Réseau anonyme Tor)"
    echo "================================================================="
    read -t 15 -r -p "Votre choix (1 ou 2) [Défaut dans 15s : 1] : " USER_CHOICE || USER_CHOICE="1"
    CHOICE="${USER_CHOICE:-1}"
fi

if [ "$CHOICE" = "2" ]; then
    ONION_BIN=$(get_or_install_onionhop || true)
fi

(
    sleep 2
    if [ "$CHOICE" = "2" ] && [ -n "$ONION_BIN" ]; then
        echo "[+] Lancement de Matrix Scanner dans OnionHop 3.7.8 ($ONION_BIN)..."
        "$ONION_BIN" "$URL" &>/dev/null &
    else
        if [ "$CHOICE" = "2" ]; then
            echo "[!] OnionHop non disponible. Ouverture dans le navigateur par défaut..."
        else
            echo "[+] Ouverture dans le navigateur par défaut..."
        fi
        if command -v xdg-open &>/dev/null; then
            xdg-open "$URL" &>/dev/null &
        fi
    fi
) &

echo ""
echo "[+] Démarrage du serveur Matrix Scanner sur $URL"
python3 app.py
