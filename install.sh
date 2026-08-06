#!/usr/bin/env bash
# =====================================================================================
# install.sh — Installation automatisée de Matrix Scanner
# =====================================================================================
# Ce script automatise l'intégralité de la procédure décrite dans README.md :
#   1. Vérification de l'OS (Debian/Ubuntu/Kali) et de Python 3
#   2. Création d'un environnement virtuel Python (venv)
#   3. Installation des dépendances Python (Flask)
#   4. Installation des outils système manquants (nmap, exploitdb) via apt
#   5. Attribution des capacités réseau (cap_net_raw, cap_net_admin) à l'interpréteur
#      Python du venv, pour permettre les scans -sS / -O SANS lancer le serveur en root
#
# Usage :
#   chmod +x install.sh
#   ./install.sh
#
# ⚠️  Ce script demande le mot de passe root via `sudo` UNIQUEMENT pour les étapes qui
#     le nécessitent réellement (apt install, setcap). Le serveur Flask lui-même ne
#     doit jamais être lancé en root : voir run.sh.
# =====================================================================================

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# -------------------------------------------------------------------------------
# 1. Vérification de la distribution
# -------------------------------------------------------------------------------
if ! command -v apt-get &>/dev/null; then
    err "Ce script suppose une distribution basée sur apt (Debian/Ubuntu/Kali)."
    err "Sur une autre distribution, installez manuellement : python3, python3-venv, nmap, exploitdb."
    exit 1
fi

if [ -f /etc/os-release ]; then
    . /etc/os-release
    log "Distribution détectée : ${PRETTY_NAME:-inconnue}"
fi

# -------------------------------------------------------------------------------
# 2. Vérification de Python 3
# -------------------------------------------------------------------------------
if ! command -v python3 &>/dev/null; then
    err "python3 est introuvable. Installez-le avec : sudo apt-get install -y python3"
    exit 1
fi
PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
log "Python détecté : $PY_VERSION"

# python3-venv seul ne suffit pas toujours à fournir un 'ensurepip' fonctionnel
# sur Debian/Kali récents (Python 3.12+) : python3-full apporte le nécessaire.
# On installe aussi python3-pip pour avoir un pip système de secours.
if ! python3 -c "import venv, ensurepip" &>/dev/null; then
    warn "Modules 'venv'/'ensurepip' incomplets, installation via apt (mot de passe requis)..."
    sudo apt-get update -qq
    sudo apt-get install -y python3-venv python3-full python3-pip
fi

# -------------------------------------------------------------------------------
# 3. Création de l'environnement virtuel (avec vérification/réparation de pip)
# -------------------------------------------------------------------------------
if [ -d "venv" ]; then
    log "Environnement virtuel déjà présent (venv/), réutilisation."
else
    log "Création de l'environnement virtuel..."
    python3 -m venv venv
fi

VENV_PY="venv/bin/python3"

# Vérifie que pip est réellement utilisable À L'INTÉRIEUR du venv. Si le venv a été
# créé sans ensurepip fonctionnel (cause de l'erreur "externally-managed-environment",
# le pip du venv est absent et le script retombe alors sur le pip système protégé),
# on tente une réparation avant, en dernier recours, de recréer le venv entièrement.
if ! "$VENV_PY" -m pip --version &>/dev/null; then
    warn "pip est absent ou cassé dans le venv, tentative de réparation (ensurepip)..."
    if ! "$VENV_PY" -m ensurepip --upgrade &>/dev/null; then
        warn "Échec de la réparation, recréation complète du venv..."
        rm -rf venv
        python3 -m venv venv
        VENV_PY="venv/bin/python3"
        if ! "$VENV_PY" -m ensurepip --upgrade &>/dev/null; then
            err "Impossible d'obtenir un pip fonctionnel dans le venv."
            err "Vérifiez l'installation de python3-full puis relancez ./install.sh"
            exit 1
        fi
    fi
    log "pip réparé avec succès dans le venv."
fi

# shellcheck disable=SC1091
source venv/bin/activate

log "Installation des dépendances Python (Flask)..."
python3 -m pip install --upgrade pip -q
python3 -m pip install -r requirements.txt -q
log "Dépendances Python installées."

# -------------------------------------------------------------------------------
# 4. Installation des outils système si absents
# -------------------------------------------------------------------------------
MISSING_PACKAGES=()

declare -A TOOL_PKGS=(
    ["nmap"]="nmap"
    ["searchsploit"]="exploitdb"
    ["nuclei"]="nuclei"
    ["whatweb"]="whatweb"
    ["wafw00f"]="wafw00f"
    ["wpscan"]="wpscan"
    ["gowitness"]="gowitness"
    ["netdiscover"]="netdiscover"
    ["nbtscan"]="nbtscan"
    ["nikto"]="nikto"
    ["enum4linux"]="enum4linux"
    ["smbmap"]="smbmap"
    ["whois"]="whois"
    ["sublist3r"]="sublist3r"
    ["subfinder"]="subfinder"
    ["joomscan"]="joomscan"
    ["droopescan"]="droopescan"
    ["moodlescan"]="moodlescan"
    ["sqlmap"]="sqlmap"
    ["nosqlmap"]="nosqlmap"
    ["gobuster"]="gobuster"
)

for cmd in "${!TOOL_PKGS[@]}"; do
    if ! command -v "$cmd" &>/dev/null; then
        MISSING_PACKAGES+=("${TOOL_PKGS[$cmd]}")
    fi
done

if [ ${#MISSING_PACKAGES[@]} -gt 0 ]; then
    warn "Paquets système manquants : ${MISSING_PACKAGES[*]}"
    warn "Installation via apt-get (authentification root requise)..."
    sudo apt-get update -qq
    sudo apt-get install -y "${MISSING_PACKAGES[@]}" || warn "Certains paquets facultatifs n'ont pas pu être installés via apt."
    log "Vérification/Installation des paquets terminée."
else
    log "Tous les outils système requis sont déjà installés."
fi

# S'assurer que policykit-1 est présent (nécessaire pour le bouton "Installer les
# dépendances" côté interface web, qui utilise pkexec pour les installations futures)
if ! command -v pkexec &>/dev/null; then
    warn "pkexec introuvable, installation de policykit-1..."
    sudo apt-get install -y policykit-1
fi

# -------------------------------------------------------------------------------
# 5. Attribution des capacités réseau au Python du venv (scans sans root)
# -------------------------------------------------------------------------------
# -sS (SYN scan) et -O (détection d'OS) nécessitent normalement les privilèges root
# pour construire des paquets réseau bruts. Plutôt que de lancer TOUT le serveur
# Flask en root (mauvaise pratique de sécurité), on attribue les capacités Linux
# minimales nécessaires uniquement à l'interpréteur Python du venv.
PYTHON_BIN="$(readlink -f venv/bin/python3)"

if command -v setcap &>/dev/null; then
    log "Attribution des capacités réseau (cap_net_raw, cap_net_admin) à $PYTHON_BIN..."
    if sudo setcap cap_net_raw,cap_net_admin+eip "$PYTHON_BIN"; then
        log "Capacités attribuées avec succès. Les scans -sS et -O fonctionneront sans sudo."
    else
        warn "Échec de l'attribution des capacités. Les scans -sS/-O nécessiteront -sT en alternative."
    fi
else
    warn "'setcap' introuvable (paquet libcap2-bin). Installation..."
    sudo apt-get install -y libcap2-bin
    sudo setcap cap_net_raw,cap_net_admin+eip "$PYTHON_BIN" || warn "Échec de l'attribution des capacités."
fi

# -------------------------------------------------------------------------------
# Fin
# -------------------------------------------------------------------------------
echo ""
log "Installation terminée !"
log "Lancez l'application avec : ./run.sh"
echo ""
warn "Rappel : n'utilisez cet outil que sur des machines que vous êtes autorisé à scanner."
