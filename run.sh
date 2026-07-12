#!/usr/bin/env bash
# =====================================================================================
# run.sh — Lance Matrix Scanner
# =====================================================================================
# Active l'environnement virtuel créé par install.sh et démarre le serveur Flask.
# Ne lance JAMAIS ce script avec sudo : les capacités réseau nécessaires ont déjà
# été attribuées à l'interpréteur Python du venv par install.sh (voir setcap).
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

echo "[+] Démarrage de Matrix Scanner sur http://127.0.0.1:5000"
python3 app.py
