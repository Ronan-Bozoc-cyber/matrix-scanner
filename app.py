#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=====================================================================================
 MATRIX SCANNER - Tableau de bord pédagogique de reconnaissance réseau et de CVE
=====================================================================================

  ⚠️  AVERTISSEMENT LÉGAL ET ÉTHIQUE  ⚠️
  -----------------------------------------------------------------------------------
  Cet outil exécute des scans réseau réels (nmap) sur le système hôte.
  Le scan d'un système informatique sans autorisation explicite et écrite de son
  propriétaire est ILLÉGAL dans la quasi-totalité des juridictions (en France :
  article 323-1 et suivants du Code pénal - accès ou maintien frauduleux dans un
  système de traitement automatisé de données).

  Cette application est fournie à des fins strictement PÉDAGOGIQUES, pour être
  utilisée UNIQUEMENT sur :
    - des machines virtuelles personnelles (ex: Metasploitable, VulnHub, TryHackMe),
    - des réseaux de laboratoire isolés,
    - des cibles pour lesquelles vous disposez d'une autorisation écrite (pentest).

  Ne scannez JAMAIS une cible dont vous n'êtes pas propriétaire ou pour laquelle
  vous n'avez pas reçu d'autorisation explicite.
=====================================================================================

Architecture :
    - Backend Flask exposant une API REST (/api/...)
    - Communication avec l'OS via le module `subprocess` (jamais de shell=True avec
      une entrée utilisateur non validée -> protection contre l'injection de commande)
    - Parsing des résultats nmap au format XML (sortie native de nmap, -oX -)
    - Élévation de privilèges pour l'installation de paquets via `pkexec`, qui
      affiche une pop-up graphique Polkit native (aucun mot de passe ne transite
      par le code Python : c'est Polkit qui gère l'authentification système).
"""

import base64
import io
import importlib.util
import ipaddress
import json
import psutil
import re
import shutil
import subprocess
import threading
import time
import uuid
import tempfile
import os
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urlparse

import sqlite3
from flask import Flask, jsonify, render_template, request, send_file

DB_PATH = os.path.join(os.path.dirname(__file__), "scanner_history.db")

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tool TEXT,
                target TEXT,
                mode TEXT DEFAULT 'distant',
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                result_json TEXT
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS custom_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                author TEXT DEFAULT 'Auditeur Cybersécurité',
                description TEXT DEFAULT '',
                content_html TEXT DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS report_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER,
                item_title TEXT,
                item_html TEXT,
                added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(report_id) REFERENCES custom_reports(id) ON DELETE CASCADE
            )
        ''')
        conn.commit()

def save_history(tool, target, result, mode="distant"):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("INSERT INTO history (tool, target, mode, result_json) VALUES (?, ?, ?, ?)",
                         (tool, target, mode, json.dumps(result)))
            conn.commit()
    except Exception as e:
        print(f"Erreur sauvegarde SQLite : {e}")

init_db()

app = Flask(__name__)

# ---------------------------------------------------------------------------------
# État global très simple (application mono-utilisateur, usage local uniquement)
# ---------------------------------------------------------------------------------
INSTALL_STATUS = {
    "running": False,
    "success": None,
    "log": "",
    "finished_at": None,
}

SCAN_JOBS = {}  # job_id -> dict(status, result, error)
NUCLEI_JOBS = {}  # job_id -> dict(status, result, error)
WHATWEB_JOBS = {}  # job_id -> dict(status, result, error)
ACTIVE_PROCESSES = {}  # job_id -> subprocess.Popen

# Paquets système nécessaires et leur binaire/commande de vérification associée
REQUIRED_TOOLS = {
    "nmap": {
        "check_cmd": ["nmap", "--version"],
        "apt_package": "nmap",
        "description": "Scanner de ports et de services réseau",
    },
    "searchsploit": {
        "check_cmd": ["searchsploit", "-h"],
        "apt_package": "exploitdb",
        "description": "Recherche d'exploits/CVE connus (base Exploit-DB locale)",
    },
    "nuclei": {
        "check_cmd": ["nuclei", "-version"],
        "apt_package": "nuclei",
        "description": "Scanner de vulnérabilités basé sur des templates (web/réseau)",
    },
    "whatweb": {
        "check_cmd": ["whatweb", "--version"],
        "apt_package": "whatweb",
        "description": "Scanner d'empreintes technologiques Web",
    },
    "wafw00f": {
        "check_cmd": ["wafw00f", "--version"],
        "apt_package": "wafw00f",
        "description": "Détection de pare-feux applicatifs web (WAF)",
    },
    "wpscan": {
        "check_cmd": ["wpscan", "--version"],
        "apt_package": "wpscan",
        "description": "Scanner spécialisé de vulnérabilités WordPress",
    },
    "gowitness": {
        "check_cmd": ["gowitness", "version"],
        "apt_package": "gowitness",
        "description": "Outil de capture d'écran web en masse",
    },
    "netdiscover": {
        "check_cmd": ["netdiscover", "-h"],
        "apt_package": "netdiscover",
        "description": "Exploration ARP active/passive pour réseau local",
    },
    "nbtscan": {
        "check_cmd": ["nbtscan", "-h"],
        "apt_package": "nbtscan",
        "description": "Résolution de nom d'hôte et groupes de travail NetBIOS",
    },
    "nikto": {
        "check_cmd": ["nikto", "-Version"],
        "apt_package": "nikto",
        "description": "Scanner de vulnérabilités et fichiers dangereux pour serveurs Web",
    },
    "enum4linux": {
        "check_cmd": ["enum4linux", "-h"],
        "apt_package": "enum4linux",
        "description": "Énumération complète des informations Windows et partages Samba/SMB",
    },
    "smbmap": {
        "check_cmd": ["smbmap", "-h"],
        "apt_package": "smbmap",
        "description": "Énumération des droits d'accès et partages réseau SMB",
    },
    "psutil": {
        "py_module": "psutil",
        "pip_package": "psutil",
        "description": "Statistiques système et monitoring CPU/RAM",
    },
    "python-docx": {
        "py_module": "docx",
        "pip_package": "python-docx",
        "description": "Génération et exportation de rapports Word (.docx)",
    },
    "whois": {
        "check_cmd": ["whois", "--version"],
        "apt_package": "whois",
        "description": "Consultation des informations du registre de nom de domaine (WHOIS)",
    },
    "sublist3r": {
        "check_cmd": ["sublist3r", "-h"],
        "apt_package": "sublist3r",
        "description": "Énumération OSINT passive de sous-domaines web",
    },
    "reportlab": {
        "py_module": "reportlab",
        "pip_package": "reportlab",
        "description": "Génération et exportation de rapports PDF",
    },
}


# =====================================================================================
# SECTION 1 : VÉRIFICATION DES PRÉREQUIS
# =====================================================================================

def _tool_is_installed(cmd):
    """Vérifie qu'un binaire est présent et exécutable, sans planter si absent."""
    binary = cmd[0]
    if shutil.which(binary) is None:
        return False
    try:
        subprocess.run(
            cmd, capture_output=True, timeout=10, check=False
        )
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False

def _py_module_is_installed(mod_name):
    """Vérifie si un module Python est installé et importable."""
    try:
        return importlib.util.find_spec(mod_name) is not None
    except Exception:
        return False


@app.route("/api/check-deps", methods=["GET"])
def check_deps():
    """
    Renvoie l'état d'installation de chaque outil requis.
    Le frontend utilise cette route au chargement de la page pour afficher
    (ou non) le bandeau d'alerte "dépendances manquantes".
    """
    status = {}
    missing_packages = []
    for name, meta in REQUIRED_TOOLS.items():
        if "py_module" in meta:
            installed = _py_module_is_installed(meta["py_module"])
            pkg_name = meta.get("pip_package", name)
        else:
            installed = _tool_is_installed(meta["check_cmd"])
            pkg_name = meta.get("apt_package", name)

        if not installed:
            missing_packages.append(pkg_name)

        status[name] = {
            "installed": installed,
            "description": meta["description"],
            "is_python": "py_module" in meta,
        }
    return jsonify({
        "all_installed": len(missing_packages) == 0,
        "tools": status,
        "missing_apt_packages": missing_packages,
    })


LAST_NET_IO = {"bytes_recv": 0, "bytes_sent": 0, "time": 0}

@app.route("/api/system-stats")
def api_system_stats():
    global LAST_NET_IO
    now = time.time()
    cpu_percent = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()

    net_io = psutil.net_io_counters()
    rx_speed = 0.0
    tx_speed = 0.0

    if LAST_NET_IO["time"] > 0 and now > LAST_NET_IO["time"]:
        dt = now - LAST_NET_IO["time"]
        rx_speed = (net_io.bytes_recv - LAST_NET_IO["bytes_recv"]) / dt
        tx_speed = (net_io.bytes_sent - LAST_NET_IO["bytes_sent"]) / dt

    LAST_NET_IO["bytes_recv"] = net_io.bytes_recv
    LAST_NET_IO["bytes_sent"] = net_io.bytes_sent
    LAST_NET_IO["time"] = now

    return jsonify({
        "cpu_percent": round(cpu_percent, 1),
        "ram_percent": round(mem.percent, 1),
        "ram_used_gb": round(mem.used / (1024 ** 3), 2),
        "ram_total_gb": round(mem.total / (1024 ** 3), 2),
        "rx_bytes_sec": round(rx_speed, 1),
        "tx_bytes_sec": round(tx_speed, 1),
    })


def _run_install_thread(packages):
    """
    Exécute `pkexec apt-get install -y <paquets>` dans un thread séparé.

    Pourquoi pkexec et pas sudo ?
    -----------------------------
    - `sudo` en ligne de commande exigerait de faire transiter le mot de passe
      root via le processus Python (mauvaise pratique, terminal bloquant).
    - `pkexec` délègue l'authentification à Polkit, qui affiche une fenêtre
      graphique native du système (GNOME/KDE) demandant le mot de passe.
      Le mot de passe ne transite JAMAIS par notre application : Polkit
      s'exécute en dehors du processus Flask.
    - Le thread Python ne fait qu'attendre la fin du processus pkexec, sans
      bloquer le reste du serveur Flask (les autres requêtes HTTP continuent
      d'être traitées).
    """
    INSTALL_STATUS["running"] = True
    INSTALL_STATUS["success"] = None
    INSTALL_STATUS["log"] = "Lancement de pkexec, veuillez valider la fenêtre système...\n"
    INSTALL_STATUS["finished_at"] = None

    cmd = ["pkexec", "apt-get", "install", "-y"] + packages
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minutes max
        )
        INSTALL_STATUS["log"] += result.stdout + "\n" + result.stderr

        # Codes de sortie usuels pour pkexec :
        #   0   -> succès
        #   126 -> authentification annulée par l'utilisateur (pop-up fermée)
        #   127 -> pkexec/commande introuvable
        if result.returncode == 0:
            INSTALL_STATUS["success"] = True
        elif result.returncode == 126:
            INSTALL_STATUS["success"] = False
            INSTALL_STATUS["log"] += "\n[Annulé par l'utilisateur : authentification refusée ou fermée]"
        else:
            INSTALL_STATUS["success"] = False
            INSTALL_STATUS["log"] += f"\n[Échec, code de retour {result.returncode}]"

    except FileNotFoundError:
        INSTALL_STATUS["success"] = False
        INSTALL_STATUS["log"] += (
            "\n[Erreur : la commande 'pkexec' est introuvable sur ce système. "
            "Installez le paquet 'policykit-1' ou lancez l'installation manuellement : "
            f"sudo apt-get install -y {' '.join(packages)}]"
        )
    except subprocess.TimeoutExpired:
        INSTALL_STATUS["success"] = False
        INSTALL_STATUS["log"] += "\n[Délai d'attente dépassé]"
    finally:
        INSTALL_STATUS["running"] = False
        INSTALL_STATUS["finished_at"] = datetime.now().isoformat()


@app.route("/api/install-deps", methods=["POST"])
def install_deps():
    """
    Déclenche l'installation des paquets manquants via pkexec.
    Non-bloquant : renvoie immédiatement, le frontend doit poller
    /api/install-status pour suivre la progression.
    """
    if INSTALL_STATUS["running"]:
        return jsonify({"error": "Une installation est déjà en cours."}), 409

    data = request.get_json(silent=True) or {}
    packages = data.get("packages")

    # Si aucun paquet n'est explicitement fourni, on recalcule la liste
    # des paquets manquants côté serveur (source de vérité)
    if not packages:
        packages = []
        for name, meta in REQUIRED_TOOLS.items():
            if not _tool_is_installed(meta["check_cmd"]):
                packages.append(meta["apt_package"])

    # Liste blanche stricte : on n'autorise QUE les paquets connus de
    # REQUIRED_TOOLS, jamais une chaîne arbitraire envoyée par le client.
    allowed_packages = {meta["apt_package"] for meta in REQUIRED_TOOLS.values()}
    packages = [p for p in packages if p in allowed_packages]

    if not packages:
        return jsonify({"error": "Aucun paquet valide à installer."}), 400

    thread = threading.Thread(target=_run_install_thread, args=(packages,), daemon=True)
    thread.start()

    return jsonify({"started": True, "packages": packages})


@app.route("/api/install-status", methods=["GET"])
def install_status():
    """Route de polling utilisée par le frontend pendant l'installation."""
    return jsonify(INSTALL_STATUS)


# =====================================================================================
# SECTION 2 : VALIDATION DES ENTRÉES UTILISATEUR (sécurité)
# =====================================================================================

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def validate_target(target):
    """
    Valide et parse la cible (IP, CIDR, hostname, ou plages d'IP multiples).
    Supporte les virgules et les plages du type 192.168.1.11-192.168.1.21.
    """
    target = target.strip()
    if not target:
        return False, "La cible ne peut pas être vide."

    # Séparation par virgules et espaces pour gérer les cibles multiples
    raw_targets = [t.strip() for t in target.replace(',', ' ').split() if t.strip()]
    if not raw_targets:
        return False, "Cible invalide."

    valid_targets = []
    
    for t in raw_targets:
        # Si la cible est une URL (http/https), extraire l'hôte
        if t.startswith("http://") or t.startswith("https://"):
            parsed = urlparse(t)
            t = parsed.netloc.split(":")[0] if parsed.netloc else parsed.path.split("/")[0].split(":")[0]

        # Vérification des plages d'IP (ex: 192.168.1.11-192.168.1.21 ou 192.168.1.11-21)
        if '-' in t:
            parts = t.split('-')
            if len(parts) == 2:
                start_ip, end_ip = parts[0].strip(), parts[1].strip()
                # Conversion du format IP-IP complet vers IP-fin attendu par Nmap
                if '.' in end_ip:
                    start_octets = start_ip.split('.')
                    end_octets = end_ip.split('.')
                    if len(start_octets) == 4 and len(end_octets) == 4:
                        if start_octets[:3] == end_octets[:3]:
                            t = f"{start_ip}-{end_octets[3]}"
                        else:
                            return False, f"Plage invalide (les IP doivent être dans le même /24) : {t}"
                
                # Vérification de sécurité de la chaîne finale pour Nmap
                if re.match(r'^[\w\.\-]+$', t):
                    valid_targets.append(t)
                    continue

        # IP simple ou réseau CIDR
        try:
            ipaddress.ip_network(t, strict=False)
            valid_targets.append(t)
            continue
        except ValueError:
            pass

        # Nom d'hôte (ex: localhost, machine.local)
        if HOSTNAME_RE.match(t):
            valid_targets.append(t)
            continue

        return False, f"Cible ou format invalide : {t}"

    return True, valid_targets


ALLOWED_TIMING = {"0", "1", "2", "3", "4", "5"}
ALLOWED_SCAN_TYPES = {"sS", "sT", "sU", "sA", "sn"}
ALLOWED_PORT_MODES = {"fast", "top1000", "top_1000", "all", "custom"}
CUSTOM_PORTS_RE = re.compile(r"^[0-9,\-]{1,200}$")


# =====================================================================================
# SECTION 3 : CONSTRUCTION DE LA COMMANDE NMAP À PARTIR DES OPTIONS GRAPHIQUES
# =====================================================================================

def build_nmap_command(options):
    """
    Traduit les options choisies graphiquement par l'élève en flags nmap.
    Chaque flag est documenté ici et dans l'interface (voir index.html)
    pour que l'élève comprenne ce qu'il déclenche réellement.
    """
    cmd = ["nmap"]
    explanation = []  # trace pédagogique des flags utilisés, renvoyée au frontend

    scan_type = options.get("scan_type", "sS")
    if scan_type not in ALLOWED_SCAN_TYPES:
        scan_type = "sS"
    cmd.append(f"-{scan_type}")
    explanation.append({
        "flag": f"-{scan_type}",
        "meaning": {
            "sS": "Scan SYN furtif (half-open) : rapide, ne complète pas la connexion TCP.",
            "sT": "Scan Connect() complet : plus lent mais ne nécessite pas les privilèges root.",
            "sU": "Scan UDP : plus lent, détecte les services UDP (DNS, SNMP...).",
            "sA": "Scan ACK : sert à cartographier les règles de pare-feu (stateful vs stateless).",
            "sn": "Ping scan uniquement : détecte les hôtes en vie sans scanner les ports.",
        }[scan_type],
    })

    # Détection de version des services (-sV)
    if options.get("service_version"):
        cmd.append("-sV")
        explanation.append({
            "flag": "-sV",
            "meaning": "Sonde chaque port ouvert pour identifier le service et sa version exacte (ex: Apache 2.4.29).",
        })

    # Détection d'OS (-O) - nécessite les privilèges root, on prévient l'élève
    if options.get("os_detection"):
        cmd.append("-O")
        explanation.append({
            "flag": "-O",
            "meaning": "Tente de deviner le système d'exploitation de la cible via l'empreinte de sa pile TCP/IP.",
        })

    # Scripts NSE par défaut (--script=default) : detection de vulnérabilités basiques
    if options.get("default_scripts"):
        cmd.append("--script=default")
        explanation.append({
            "flag": "--script=default",
            "meaning": "Exécute les scripts NSE 'sûrs' par défaut (bannières, infos basiques, quelques vulnérabilités connues).",
        })

    if options.get("vuln_scripts"):
        cmd.append("--script=vuln")
        explanation.append({
            "flag": "--script=vuln",
            "meaning": "Exécute les scripts NSE dédiés à la détection de vulnérabilités connues (plus long, plus intrusif).",
        })

    if options.get("vulners_script"):
        cmd.append("--script=vulners")
        explanation.append({
            "flag": "--script=vulners",
            "meaning": "Interroge l'API Vulners avec les versions détectées pour lister les CVE et scores CVSS associés.",
        })

    if options.get("aggressive_scan"):
        cmd.append("-A")
        explanation.append({
            "flag": "-A",
            "meaning": "Scan agressif : active la détection d'OS, la détection de version, le scan de scripts (-sC) et traceroute. Nécessite les privilèges root.",
        })

    # Ports à scanner
    port_mode = options.get("port_mode", "top1000")
    if port_mode not in ALLOWED_PORT_MODES:
        port_mode = "top1000"

    if port_mode == "fast":
        cmd.append("-F")
        explanation.append({"flag": "-F", "meaning": "Scan rapide : seulement les 100 ports les plus courants."})
    elif port_mode in ["top1000", "top_1000"]:
        # comportement par défaut de nmap (top 1000 ports), pas de flag nécessaire
        explanation.append({"flag": "(défaut)", "meaning": "Scan des 1000 ports les plus courants (comportement par défaut de nmap)."})
    elif port_mode == "all":
        cmd.append("-p-")
        explanation.append({"flag": "-p-", "meaning": "Scan de l'intégralité des 65535 ports TCP (le plus long, le plus exhaustif)."})
    elif port_mode == "custom":
        custom_ports = str(options.get("custom_ports", ""))
        if CUSTOM_PORTS_RE.match(custom_ports):
            cmd.extend(["-p", custom_ports])
            explanation.append({"flag": f"-p {custom_ports}", "meaning": "Scan restreint à la liste/plage de ports spécifiée."})

    # Timing template (intensité / vitesse du scan, slider -T0 à -T5)
    timing = str(options.get("timing", "3"))
    if timing not in ALLOWED_TIMING:
        timing = "3"
    cmd.append(f"-T{timing}")
    timing_meanings = {
        "0": "Paranoïaque : extrêmement lent, pour passer sous le radar des IDS.",
        "1": "Furtif : très lent, discret.",
        "2": "Poli : réduit la charge réseau, plus lent que la normale.",
        "3": "Normal : vitesse par défaut de nmap.",
        "4": "Agressif : rapide, suppose un réseau fiable et rapide.",
        "5": "Insane : le plus rapide possible, peut manquer des résultats sur réseau lent.",
    }
    explanation.append({"flag": f"-T{timing}", "meaning": timing_meanings[timing]})

    if options.get("skip_host_discovery") or options.get("scan_type") == "sS" or options.get("is_local"):
        cmd.append("-Pn")
        explanation.append({
            "flag": "-Pn",
            "meaning": "Désactive le ping préalable : Nmap scanne directement les ports sans vérifier d'abord si l’hôte répond aux ICMP/Echo.",
        })

    # Mode verbeux + rapport de statistiques périodique.
    # nmap écrit alors des lignes de progression ("Stats: xx:xx elapsed;
    # xx% done; ETC: ...") sur stderr, PENDANT que stdout reste réservé au
    # flux XML propre (-oX -). C'est ce qui permet d'afficher un suivi en
    # temps réel côté frontend sans corrompre le parsing XML final.
    cmd.append("-v")
    cmd.extend(["--stats-every", "2s"])
    explanation.append({
        "flag": "-v --stats-every 2s",
        "meaning": "Active l'affichage de la progression du scan toutes les 2 secondes (visible dans le terminal de suivi).",
    })

    # Sortie XML sur stdout pour parsing structuré
    cmd.extend(["-oX", "-"])

    return cmd, explanation


def resolve_host_identity(ip, mac=None, vendor=None):
    """
    Enrichit les informations d'un équipement local en interrogeant NetBIOS (nbtscan),
    le DNS inversé et en analysant le préfixe MAC / Constructeur.
    """
    identity = {
        "hostname": "",
        "netbios_name": "",
        "workgroup": "",
        "vendor": vendor or "Inconnu",
        "category": "Équipement Réseau",
        "icon": "fa-server"
    }

    if not ip or ip == "inconnu":
        return identity

    # 1. Résolution DNS inversée silencieuse avec timeout très court (0.5s)
    try:
        orig_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(0.5)
        host_tuple = socket.gethostbyaddr(ip)
        socket.setdefaulttimeout(orig_timeout)
        if host_tuple and host_tuple[0]:
            identity["hostname"] = host_tuple[0]
    except Exception:
        pass

    # 2. Résolution NetBIOS via nbtscan (timeout 0.8s)
    if shutil.which("nbtscan"):
        try:
            res = subprocess.run(
                ["nbtscan", "-m", ip],
                capture_output=True,
                text=True,
                timeout=0.8
            )
            if res.stdout:
                lines = res.stdout.strip().split("\n")
                for line in lines:
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            identity["netbios_name"] = parts[1]
                        if len(parts) >= 4:
                            identity["workgroup"] = parts[3]
                        break
        except Exception:
            pass

    # 3. Dictionnaires de marques / catégories basés sur le nom, le vendeur MAC ou le NetBIOS
    search_str = f"{identity['vendor']} {identity['hostname']} {identity['netbios_name']}".lower()

    if any(k in search_str for k in ["freebox", "free sas", "freebox2", "livebox", "sagemcom", "technicolor", "netgear", "tp-link", "cisco", "asus", "huawei", "zte"]):
        identity["category"] = "Routeur / Répéteur / Box"
        identity["icon"] = "fa-wifi"
    elif any(k in search_str for k in ["apple", "iphone", "ipad", "macbook", "imac", "apple-tv"]):
        identity["category"] = "Équipement Apple"
        identity["icon"] = "fa-apple"
    elif any(k in search_str for k in ["samsung", "lg", "philips", "sony", "tcl", "chromecast", "firetv", "tv"]):
        identity["category"] = "Smart TV / Médias"
        identity["icon"] = "fa-tv"
    elif any(k in search_str for k in ["hp", "hewlett", "epson", "canon", "brother", "xerox", "printer"]):
        identity["category"] = "Imprimante Réseau"
        identity["icon"] = "fa-print"
    elif any(k in search_str for k in ["synology", "qnap", "nas", "truenas"]):
        identity["category"] = "Serveur NAS / Stockage"
        identity["icon"] = "fa-database"
    elif any(k in search_str for k in ["espressif", "tuya", "sonoff", "shelly", "raspberry", "arduino", "esp8266", "esp32"]):
        identity["category"] = "Objet Connecté / IoT"
        identity["icon"] = "fa-microchip"
    elif any(k in search_str for k in ["windows", "desktop", "workstation", "pc", "dell", "lenovo", "acer", "msi"]):
        identity["category"] = "Station PC / Windows"
        identity["icon"] = "fa-desktop"

    return identity


# =====================================================================================
# SECTION 4 : EXÉCUTION DU SCAN ET PARSING XML
# =====================================================================================

def parse_nmap_xml(xml_output):
    """Parse la sortie XML native de nmap en structure JSON exploitable par le frontend."""
    root = ET.fromstring(xml_output)
    hosts_result = []

    for host in root.findall("host"):
        status_el = host.find("status")
        host_state = status_el.get("state") if status_el is not None else "up"

        ip_addr = "inconnu"
        mac_addr = None
        vendor = None
        for addr_el in host.findall("address"):
            addr_type = addr_el.get("addrtype")
            if addr_type in ["ipv4", "ipv6"]:
                ip_addr = addr_el.get("addr")
            elif addr_type == "mac":
                mac_addr = addr_el.get("addr")
                vendor = addr_el.get("vendor")

        hostname_el = host.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else None

        # OS detection
        os_matches = []
        os_el = host.find("os")
        if os_el is not None:
            for match in os_el.findall("osmatch"):
                os_matches.append({
                    "name": match.get("name"),
                    "accuracy": match.get("accuracy"),
                })

        ports_result = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                state_el = port.find("state")
                service_el = port.find("service")

                scripts = []
                for script in port.findall("script"):
                    scripts.append({
                        "id": script.get("id"),
                        "output": script.get("output", "")[:2000],  # borne la taille
                    })

                ports_result.append({
                    "port": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "state": state_el.get("state") if state_el is not None else "unknown",
                    "service": service_el.get("name") if service_el is not None else "",
                    "product": service_el.get("product") if service_el is not None else "",
                    "version": service_el.get("version") if service_el is not None else "",
                    "scripts": scripts,
                })

        identity = resolve_host_identity(ip_addr, mac_addr, vendor)

        hosts_result.append({
            "ip": ip_addr,
            "mac": mac_addr,
            "vendor": identity["vendor"],
            "hostname": hostname or identity["hostname"] or identity["netbios_name"],
            "netbios_name": identity["netbios_name"],
            "workgroup": identity["workgroup"],
            "category": identity["category"],
            "icon": identity["icon"],
            "status": host_state,
            "os_matches": os_matches,
            "ports": ports_result,
        })

    return hosts_result


MAX_LOG_LINES = 5000  # borne de sécurité pour éviter une consommation mémoire illimitée


def _run_scan_thread(job_id, cmd, target, mode="distant"):
    """
    Lance nmap avec subprocess.Popen (au lieu de subprocess.run) afin de pouvoir
    lire sa sortie AU FUR ET À MESURE, plutôt que d'attendre la fin complète du
    processus. Deux threads lecteurs dédiés évitent les blocages classiques liés
    aux tubes (pipes) : un pipe non lu qui se remplit peut bloquer le processus
    enfant indéfiniment (deadlock) si stdout et stderr ne sont pas consommés en
    parallèle.

        - stdout -> accumulé silencieusement, c'est le flux XML final (-oX -),
                    parsé uniquement une fois le scan terminé.
        - stderr -> chaque ligne (messages -v / --stats-every) est ajoutée en
                    direct à job["log"], relu par le frontend via polling sur
                    /api/scan-status/<job_id> pour afficher le "terminal live".
    """
    SCAN_JOBS[job_id]["status"] = "running"
    SCAN_JOBS[job_id]["log"] = []

    # stdbuf force un buffering ligne par ligne côté nmap (au lieu du buffering
    # par bloc utilisé automatiquement quand la sortie n'est pas un vrai
    # terminal), pour que les lignes de progression arrivent sans latence.
    run_cmd = cmd
    input_data = None
    if CONFIGURED_SUDO_PASSWORD:
        run_cmd = ["sudo", "-S"] + cmd
        input_data = f"{CONFIGURED_SUDO_PASSWORD}\n"
    elif shutil.which("stdbuf"):
        run_cmd = ["stdbuf", "-oL", "-eL"] + cmd

    def append_log(line):
        log = SCAN_JOBS[job_id]["log"]
        log.append(line)
        if len(log) > MAX_LOG_LINES:
            del log[0:len(log) - MAX_LOG_LINES]

    try:
        process = subprocess.Popen(
            run_cmd,
            stdin=subprocess.PIPE if input_data else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        if input_data:
            try:
                process.stdin.write(input_data)
                process.stdin.flush()
            except Exception:
                pass
        ACTIVE_PROCESSES[job_id] = process
    except FileNotFoundError:
        SCAN_JOBS[job_id]["status"] = "error"
        SCAN_JOBS[job_id]["error"] = "La commande nmap est introuvable."
        return
    except PermissionError:
        SCAN_JOBS[job_id]["status"] = "error"
        SCAN_JOBS[job_id]["error"] = (
            "Permission refusée : certains types de scans (-sS, -O) nécessitent "
            "les privilèges root. Lancez le serveur Flask avec les capacités "
            "réseau adéquates (voir README, section setcap)."
        )
        return

    stdout_chunks = []

    def read_stdout():
        for chunk in process.stdout:
            stdout_chunks.append(chunk)

    def read_stderr():
        for line in process.stderr:
            clean_line = line.rstrip("\n")
            if clean_line:
                append_log(clean_line)

    t_out = threading.Thread(target=read_stdout, daemon=True)
    t_err = threading.Thread(target=read_stderr, daemon=True)
    t_out.start()
    t_err.start()

    try:
        process.wait(timeout=900)  # 15 minutes max, un scan -p- peut être long
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        SCAN_JOBS[job_id]["status"] = "error"
        SCAN_JOBS[job_id]["error"] = "Délai d'attente dépassé (15 minutes). Réduisez la portée du scan."
        append_log("[✘ Scan interrompu : délai dépassé]")
        return

    t_out.join(timeout=5)
    t_err.join(timeout=5)

    full_stdout = "".join(stdout_chunks)

    if process.returncode != 0 and not full_stdout.strip():
        SCAN_JOBS[job_id]["status"] = "error"
        SCAN_JOBS[job_id]["error"] = (
            "\n".join(SCAN_JOBS[job_id]["log"][-15:]) or "nmap a échoué sans sortie."
        )
        return

    try:
        parsed = parse_nmap_xml(full_stdout)
    except ET.ParseError:
        SCAN_JOBS[job_id]["status"] = "error"
        SCAN_JOBS[job_id]["error"] = "Impossible d'analyser la sortie XML de nmap."
        return
    except Exception as exc:  # sécurité : ne jamais laisser planter le thread silencieusement
        SCAN_JOBS[job_id]["status"] = "error"
        SCAN_JOBS[job_id]["error"] = f"Erreur inattendue lors du parsing : {exc}"
        return

    SCAN_JOBS[job_id]["status"] = "done"
    save_history("nmap", target, parsed, mode=mode)
    SCAN_JOBS[job_id]["result"] = parsed
    append_log("[✔ Scan terminé]")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    """
    Lance un scan nmap asynchrone à partir des options graphiques envoyées
    par le frontend. Renvoie un job_id à poller via /api/scan-status/<id>.
    """
    data = request.get_json(silent=True) or {}
    target = data.get("target", "")
    mode = data.get("mode", "distant")

    is_valid, msg = validate_target(target)
    if not is_valid:
        return jsonify({"error": msg}), 400

    # Vérification que nmap est bien installé avant de lancer quoi que ce soit
    if not _tool_is_installed(REQUIRED_TOOLS["nmap"]["check_cmd"]):
        return jsonify({"error": "nmap n'est pas installé. Utilisez le bouton d'installation des dépendances."}), 412

    cmd, explanation = build_nmap_command(data.get("options", {}))
    cmd.extend(msg)  # liste de cibles validées ajoutées à la fin de la commande

    job_id = str(uuid.uuid4())
    SCAN_JOBS[job_id] = {
        "status": "queued",
        "result": None,
        "error": None,
        "log": [],
        "command": " ".join(cmd),
        "explanation": explanation,
        "started_at": datetime.now().isoformat(),
    }

    target_str = ", ".join(msg)
    thread = threading.Thread(target=_run_scan_thread, args=(job_id, cmd, target_str, mode), daemon=True)
    thread.start()

    return jsonify({
        "job_id": job_id,
        "command_preview": " ".join(cmd),
        "explanation": explanation,
    })


@app.route("/api/scan-status/<job_id>", methods=["GET"])
def scan_status(job_id):
    job = SCAN_JOBS.get(job_id)
    if job is None:
        return jsonify({"error": "job_id inconnu"}), 404
    return jsonify(job)


@app.route("/api/scan/stop", methods=["POST"])
def stop_all_scans():
    """
    Arrête immédiatement tous les scans Nmap, Netdiscover, Nuclei, WhatWeb en cours.
    """
    stopped_count = 0
    for job_id, proc in list(ACTIVE_PROCESSES.items()):
        if proc:
            try:
                proc.terminate()
                stopped_count += 1
            except Exception:
                pass
    ACTIVE_PROCESSES.clear()

    all_job_dicts = [SCAN_JOBS, NETDISCOVER_JOBS, NUCLEI_JOBS, WHATWEB_JOBS, WPSCAN_JOBS]
    for jobs in all_job_dicts:
        for job_id, job in list(jobs.items()):
            if job.get("status") in ["running", "queued"]:
                job["status"] = "error"
                job["error"] = "Scan interrompu par l'utilisateur."

    return jsonify({"success": True, "stopped_count": stopped_count})


# =====================================================================================
# SECTION 5 : RECHERCHE DE CVE / EXPLOITS VIA SEARCHSPLOIT
# =====================================================================================

SEARCHSPLOIT_CACHE = {}

@app.route("/api/cve-search", methods=["POST"])
def cve_search():
    """
    Recherche des exploits/CVE connus pour un couple (produit, version)
    détecté par nmap -sV, via la base Exploit-DB locale (searchsploit).
    Les résultats sont mis en cache mémoire pour accélérer les requêtes réseau.
    """
    data = request.get_json(silent=True) or {}
    product = str(data.get("product", "")).strip()
    version = str(data.get("version", "")).strip()

    if not product:
        return jsonify({"error": "Produit manquant."}), 400

    query = f"{product} {version}".strip()

    if query in SEARCHSPLOIT_CACHE:
        return jsonify({"query": query, "results": SEARCHSPLOIT_CACHE[query]})

    if not _tool_is_installed(REQUIRED_TOOLS["searchsploit"]["check_cmd"]):
        return jsonify({"error": "searchsploit n'est pas installé.", "results": []}), 412

    try:
        result = subprocess.run(
            ["searchsploit", "--json", query],
            capture_output=True,
            text=True,
            timeout=30,
        )
        results = []
        if result.stdout:
            try:
                payload = json.loads(result.stdout)
                for entry in payload.get("RESULTS_EXPLOIT", []):
                    results.append({
                        "title": entry.get("Title"),
                        "edb_id": entry.get("EDB-ID"),
                        "date": entry.get("Date"),
                        "type": entry.get("Type"),
                        "platform": entry.get("Platform"),
                    })
            except json.JSONDecodeError:
                pass

        # Si aucun résultat avec produit + version, réessayer avec produit uniquement
        if not results and version:
            res_prod = subprocess.run(
                ["searchsploit", "--json", product],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if res_prod.stdout:
                try:
                    payload = json.loads(res_prod.stdout)
                    for entry in payload.get("RESULTS_EXPLOIT", []):
                        results.append({
                            "title": entry.get("Title"),
                            "edb_id": entry.get("EDB-ID"),
                            "date": entry.get("Date"),
                            "type": entry.get("Type"),
                            "platform": entry.get("Platform"),
                        })
                except json.JSONDecodeError:
                    pass

        SEARCHSPLOIT_CACHE[query] = results
        return jsonify({"query": query, "results": results})

    except subprocess.TimeoutExpired:
        return jsonify({"error": "searchsploit a mis trop de temps à répondre."}), 504
    except FileNotFoundError:
        return jsonify({"error": "searchsploit introuvable."}), 412


# =====================================================================================
# SECTION 6 : NUCLEI SCANNER
# =====================================================================================

def _run_nuclei_thread(job_id, target_url, tags="", options=None):
    if options is None:
        options = {}
        
    NUCLEI_JOBS[job_id]["status"] = "running"
    NUCLEI_JOBS[job_id]["log"] = []
    
    cmd = ["nuclei", "-u", target_url, "-jsonl", "-nc"]
    if tags:
        cmd.extend(["-tags", tags])
        
    rate_limit = options.get("rate_limit")
    if rate_limit:
        cmd.extend(["-rl", str(rate_limit)])
    
    def append_log(line):
        log = NUCLEI_JOBS[job_id]["log"]
        log.append(line)
        if len(log) > MAX_LOG_LINES:
            del log[0:len(log) - MAX_LOG_LINES]

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        NUCLEI_JOBS[job_id]["status"] = "error"
        NUCLEI_JOBS[job_id]["error"] = "La commande nuclei est introuvable."
        return

    stdout_chunks = []

    def read_stdout():
        for chunk in process.stdout:
            stdout_chunks.append(chunk)

    def read_stderr():
        for line in process.stderr:
            clean_line = line.rstrip("\n")
            if clean_line:
                append_log(clean_line)

    t_out = threading.Thread(target=read_stdout, daemon=True)
    t_err = threading.Thread(target=read_stderr, daemon=True)
    t_out.start()
    t_err.start()

    try:
        process.wait(timeout=1800)  # 30 minutes max
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        NUCLEI_JOBS[job_id]["status"] = "error"
        NUCLEI_JOBS[job_id]["error"] = "Délai d'attente dépassé (30 minutes)."
        append_log("[✘ Scan interrompu : délai dépassé]")
        return

    t_out.join(timeout=5)
    t_err.join(timeout=5)

    full_stdout = "".join(stdout_chunks)
    
    results = []
    for line in full_stdout.strip().split("\n"):
        if not line.strip():
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            pass

    NUCLEI_JOBS[job_id]["status"] = "done"
    NUCLEI_JOBS[job_id]["result"] = results
    save_history("nuclei", target_url, results)
    append_log("[✔ Scan terminé]")


@app.route("/api/nuclei-scan", methods=["POST"])
def start_nuclei_scan():
    data = request.get_json(silent=True) or {}
    target_url = data.get("target_url", "").strip()
    tags = data.get("tags", "").strip()

    options = data.get("options", {})

    if not target_url:
        return jsonify({"error": "URL cible manquante."}), 400

    if not _tool_is_installed(REQUIRED_TOOLS["nuclei"]["check_cmd"]):
        return jsonify({"error": "nuclei n'est pas installé."}), 412

    job_id = str(uuid.uuid4())
    NUCLEI_JOBS[job_id] = {
        "status": "queued",
        "result": None,
        "error": None,
        "log": [],
        "target_url": target_url,
        "tags": tags,
        "started_at": datetime.now().isoformat(),
    }

    thread = threading.Thread(target=_run_nuclei_thread, args=(job_id, target_url, tags, options), daemon=True)
    thread.start()

    return jsonify({
        "job_id": job_id
    })

@app.route("/api/nuclei-status/<job_id>", methods=["GET"])
def nuclei_status(job_id):
    job = NUCLEI_JOBS.get(job_id)
    if job is None:
        return jsonify({"error": "job_id inconnu"}), 404
    return jsonify(job)


# =====================================================================================
# SECTION 7 : WHATWEB SCANNER
# =====================================================================================

def _run_whatweb_thread(job_id, target_url, options):
    WHATWEB_JOBS[job_id]["status"] = "running"
    
    # WhatWeb écrit son JSON dans un fichier. On utilise tempfile pour le chemin.
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_file:
        tmp_path = tmp_file.name

    # Construction de la commande à partir des options reçues
    cmd = ["whatweb"]
    cmd += ["-a", str(options.get("aggression", 1))]
    cmd += ["--follow-redirect", options.get("follow_redirect", "always")]
    cmd += ["--open-timeout", str(options.get("open_timeout", 15))]
    cmd += ["--read-timeout", str(options.get("read_timeout", 30))]

    user_agent = options.get("user_agent", "")
    if user_agent:
        cmd += ["-U", user_agent]

    if options.get("verbose"):
        cmd += ["-v"]

    if options.get("no_errors"):
        cmd += ["--no-errors"]

    if options.get("no_cookies"):
        cmd += ["--no-cookies"]

    wait_time = options.get("wait")
    if wait_time and int(wait_time) > 0:
        cmd += ["--wait", str(wait_time)]

    # Sortie JSON dans fichier temporaire + suppression de la couleur ANSI
    cmd += ["--log-json", tmp_path, "--colour=never", target_url]

    # Sauvegarde de la commande finale pour l'affichage dans le frontend
    WHATWEB_JOBS[job_id]["command"] = " ".join(cmd)

    try:
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(180, options.get("open_timeout", 15) + options.get("read_timeout", 30) + 30),
        )
        
        # WhatWeb peut retourner 0 même s'il ne trouve pas l'hôte (et génère un JSON "[]")
        if process.returncode != 0 and process.returncode != 1:
            WHATWEB_JOBS[job_id]["status"] = "error"
            WHATWEB_JOBS[job_id]["error"] = f"WhatWeb a échoué (code {process.returncode}): {process.stderr.strip() or process.stdout.strip()}"
            return

        # Parsing du fichier JSON généré
        results = []
        try:
            with open(tmp_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if content:
                    results = json.loads(content)
        except json.JSONDecodeError as e:
            WHATWEB_JOBS[job_id]["status"] = "error"
            WHATWEB_JOBS[job_id]["error"] = f"Impossible de lire la sortie JSON de WhatWeb : {e}"
            return
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

        # Si le JSON est vide, on vérifie s'il y a eu une erreur de connexion affichée par WhatWeb
        if not results:
            full_output = process.stdout + "\n" + process.stderr
            if "ERROR Opening" in full_output or "ERROR:" in full_output:
                error_lines = [line.strip() for line in full_output.splitlines() if "ERROR" in line]
                err_msg = error_lines[0] if error_lines else "Erreur de connexion (cible injoignable ou bloquée)."
                WHATWEB_JOBS[job_id]["status"] = "error"
                WHATWEB_JOBS[job_id]["error"] = err_msg
                return

        WHATWEB_JOBS[job_id]["status"] = "done"
        WHATWEB_JOBS[job_id]["result"] = results
        save_history("whatweb", target_url, results)

    except subprocess.TimeoutExpired:
        WHATWEB_JOBS[job_id]["status"] = "error"
        WHATWEB_JOBS[job_id]["error"] = "Délai d'attente dépassé pour WhatWeb."
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
    except FileNotFoundError:
        WHATWEB_JOBS[job_id]["status"] = "error"
        WHATWEB_JOBS[job_id]["error"] = "La commande whatweb est introuvable."
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
    except Exception as exc:
        WHATWEB_JOBS[job_id]["status"] = "error"
        WHATWEB_JOBS[job_id]["error"] = f"Erreur inattendue : {exc}"
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

@app.route("/api/whatweb-scan", methods=["POST"])
def start_whatweb_scan():
    data = request.get_json(silent=True) or {}
    target_url = data.get("target_url", "").strip()
    options = data.get("options", {})

    if not target_url:
        return jsonify({"error": "URL cible manquante."}), 400

    # Validation de l'agressivité
    aggression = int(options.get("aggression", 1))
    if aggression not in [1, 3, 4]:
        return jsonify({"error": "Niveau d'agressivité invalide (valeurs acceptées : 1, 3, 4)."}), 400

    if not _tool_is_installed(REQUIRED_TOOLS["whatweb"]["check_cmd"]):
        return jsonify({"error": "whatweb n'est pas installé."}), 412

    job_id = str(uuid.uuid4())
    WHATWEB_JOBS[job_id] = {
        "status": "queued",
        "result": None,
        "error": None,
        "command": None,
        "target_url": target_url,
        "started_at": datetime.now().isoformat(),
    }

    thread = threading.Thread(target=_run_whatweb_thread, args=(job_id, target_url, options), daemon=True)
    thread.start()

    return jsonify({"job_id": job_id})

@app.route("/api/whatweb-status/<job_id>", methods=["GET"])
def whatweb_status(job_id):
    job = WHATWEB_JOBS.get(job_id)
    if job is None:
        return jsonify({"error": "job_id inconnu"}), 404
    return jsonify(job)

# =====================================================================================
# SECTION 8 : SCREENSHOT (GOWITNESS)
# =====================================================================================

SCREENSHOT_DIR = os.path.join(app.static_folder, 'screenshots')
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

@app.route("/api/screenshot", methods=["POST"])
def take_screenshot():
    data = request.get_json(silent=True) or {}
    target_url = data.get("target_url", "").strip()

    if not target_url:
        return jsonify({"error": "URL cible manquante."}), 400

    if not _tool_is_installed(REQUIRED_TOOLS["gowitness"]["check_cmd"]):
        return jsonify({"error": "gowitness n'est pas installé."}), 412

    # Assurez-vous que l'URL a un schéma (http:// ou https://) pour gowitness
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "http://" + target_url

    # Generer un nom de fichier unique basé sur le hash de l'url
    import hashlib
    filename = hashlib.md5(target_url.encode()).hexdigest() + ".jpeg"
    filepath = os.path.join(SCREENSHOT_DIR, filename)

    cmd = ["gowitness", "scan", "single", "-u", target_url, "--screenshot-path", SCREENSHOT_DIR, "--screenshot-format", "jpeg"]

    try:
        # Lancement synchrone (prend quelques secondes)
        subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        # Gowitness enregistre le fichier sous forme de <protocole>-<domaine>.jpeg
        # Par defaut, on recupere l'image la plus recente dans le dossier si le nom est dur a deviner
        import glob
        list_of_files = glob.glob(os.path.join(SCREENSHOT_DIR, '*.jpeg'))
        if not list_of_files:
             return jsonify({"error": "La capture d'écran a échoué (fichier non généré)."}), 500
             
        latest_file = max(list_of_files, key=os.path.getctime)
        relative_path = os.path.relpath(latest_file, app.static_folder)
        # Fix backslashes on windows just in case
        relative_path = relative_path.replace('\\', '/')

        return jsonify({"screenshot_url": f"/static/{relative_path}"})

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Délai dépassé pour la capture d'écran."}), 504
    except Exception as exc:
        return jsonify({"error": f"Erreur de capture : {str(exc)}"}), 500

# =====================================================================================
# SECTION 9 : WPSCAN
# =====================================================================================

WPSCAN_JOBS = {}

def _run_wpscan_thread(job_id, target_url):
    WPSCAN_JOBS[job_id]["status"] = "running"
    WPSCAN_JOBS[job_id]["log"] = []
    
    # URL needs scheme
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "http://" + target_url

    cmd = ["wpscan", "--url", target_url, "--random-user-agent", "--format", "json", "--no-update"]

    try:
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        # Wpscan exits with >0 if vulnerabilities are found or if an error occurs.
        # So we just try to parse stdout as JSON regardless of return code.
        results = {}
        try:
            # Look for JSON output. WPScan might output some text before JSON if there are warnings
            out = process.stdout.strip()
            # Find first '{'
            start_idx = out.find('{')
            if start_idx != -1:
                 results = json.loads(out[start_idx:])
        except json.JSONDecodeError as e:
            WPSCAN_JOBS[job_id]["status"] = "error"
            WPSCAN_JOBS[job_id]["error"] = f"Impossible de lire le JSON WPScan: {e}\nOut: {process.stdout[:100]}"
            return
            
        if not results:
             WPSCAN_JOBS[job_id]["status"] = "error"
             WPSCAN_JOBS[job_id]["error"] = "Aucun résultat exploitable retourné par WPScan."
             return

        WPSCAN_JOBS[job_id]["status"] = "done"
        WPSCAN_JOBS[job_id]["result"] = results
        save_history("wpscan", target_url, results)

    except subprocess.TimeoutExpired:
        WPSCAN_JOBS[job_id]["status"] = "error"
        WPSCAN_JOBS[job_id]["error"] = "Délai d'attente dépassé pour WPScan (5 min)."
    except Exception as exc:
        WPSCAN_JOBS[job_id]["status"] = "error"
        WPSCAN_JOBS[job_id]["error"] = f"Erreur inattendue : {exc}"


@app.route("/api/wpscan", methods=["POST"])
def start_wpscan():
    data = request.get_json(silent=True) or {}
    target_url = data.get("target_url", "").strip()

    if not target_url:
        return jsonify({"error": "URL cible manquante."}), 400

    if not _tool_is_installed(REQUIRED_TOOLS["wpscan"]["check_cmd"]):
        return jsonify({"error": "wpscan n'est pas installé."}), 412

    job_id = str(uuid.uuid4())
    WPSCAN_JOBS[job_id] = {
        "status": "queued",
        "result": None,
        "error": None,
        "log": [],
        "target_url": target_url,
        "started_at": datetime.now().isoformat(),
    }

    thread = threading.Thread(target=_run_wpscan_thread, args=(job_id, target_url), daemon=True)
    thread.start()

    return jsonify({"job_id": job_id})

@app.route("/api/wpscan-status/<job_id>", methods=["GET"])
def wpscan_status(job_id):
    job = WPSCAN_JOBS.get(job_id)
    if job is None:
        return jsonify({"error": "job_id inconnu"}), 404
    return jsonify(job)

# =====================================================================================
# SECTION 7.5 : WAFW00F (WAF DETECTION)
# =====================================================================================

@app.route("/api/waf-scan", methods=["POST"])
def waf_scan():
    """
    Exécute wafw00f pour détecter la présence d'un pare-feu applicatif.
    C'est un scan très rapide, donc on le fait de manière synchrone.
    """
    data = request.get_json(silent=True) or {}
    target_url = data.get("target_url", "").strip()

    if not target_url:
        return jsonify({"error": "URL cible manquante."}), 400

    if not _tool_is_installed(REQUIRED_TOOLS["wafw00f"]["check_cmd"]):
        return jsonify({"error": "wafw00f n'est pas installé."}), 412

    urls = []
    if not target_url.startswith("http"):
        urls = ["https://" + target_url]
    else:
        urls = [target_url]

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_file:
        tmp_path = tmp_file.name

    cmd = ["wafw00f"] + urls + ["-f", "json", "-o", tmp_path]

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=20)

        results = []
        if os.path.exists(tmp_path):
            with open(tmp_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if content:
                    results = json.loads(content)
            os.remove(tmp_path)

        # Structure du retour
        if not results:
            return jsonify({"detected": False, "firewall": None})

        # Wafw00f renvoie parfois une liste de dictionnaires si on a testé plusieurs URLs
        for waf_data in results:
            if waf_data.get("detected"):
                return jsonify({
                    "detected": True,
                    "firewall": waf_data.get("firewall"),
                    "manufacturer": waf_data.get("manufacturer")
                })
                
        return jsonify({"detected": False, "firewall": None})

    except subprocess.TimeoutExpired:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        return jsonify({"error": "Délai d'attente dépassé pour wafw00f."}), 504
    except Exception as exc:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        return jsonify({"error": f"Erreur lors de la détection WAF : {exc}"}), 500


# =====================================================================================
# SECTION 7.6 : WHOIS & DOMAIN RECON
# =====================================================================================

def extract_root_domain(target_url):
    cleaned = target_url.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0].strip()
    parts = cleaned.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return cleaned


@app.route("/api/whois-scan", methods=["POST"])
def whois_scan():
    data = request.get_json(silent=True) or {}
    target_url = data.get("target_url", "").strip()

    if not target_url:
        return jsonify({"error": "Cible manquante."}), 400

    domain = extract_root_domain(target_url)

    cmd = ["whois", domain]
    try:
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        raw_text = process.stdout or process.stderr

        registrar = None
        created_date = None
        updated_date = None
        expiry_date = None
        dnssec = None
        statuses = []
        name_servers = []

        for line in raw_text.splitlines():
            line_str = line.strip()
            line_lower = line_str.lower()
            if not registrar and ("registrar:" in line_lower or "sponsoring registrar:" in line_lower):
                registrar = line_str.split(":", 1)[-1].strip()
            elif not created_date and ("creation date:" in line_lower or "created:" in line_lower or "created on:" in line_lower):
                created_date = line_str.split(":", 1)[-1].strip()
            elif not updated_date and ("updated date:" in line_lower or "last-update:" in line_lower or "changed:" in line_lower):
                updated_date = line_str.split(":", 1)[-1].strip()
            elif not expiry_date and ("registry expiry date:" in line_lower or "expiry date:" in line_lower or "expiration date:" in line_lower or "expires:" in line_lower):
                expiry_date = line_str.split(":", 1)[-1].strip()
            elif not dnssec and "dnssec:" in line_lower:
                dnssec = line_str.split(":", 1)[-1].strip()
            elif "domain status:" in line_lower or "status:" in line_lower:
                st = line_str.split(":", 1)[-1].strip().split()[0]
                if st and st not in statuses and len(statuses) < 4:
                    statuses.append(st)
            elif "name server:" in line_lower or "nserver:" in line_lower:
                ns = line_str.split(":", 1)[-1].strip().lower()
                if ns and ns not in name_servers:
                    name_servers.append(ns)

        return jsonify({
            "domain": domain,
            "registrar": registrar or "Non divulgué / Privé",
            "created_date": created_date or "Non renseignée",
            "updated_date": updated_date or "Non renseignée",
            "expiry_date": expiry_date or "Non renseignée",
            "dnssec": dnssec or "Inconnu / Non configuré",
            "statuses": statuses,
            "name_servers": name_servers[:6],
            "raw_text": raw_text[:4000]
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Délai d'attente dépassé pour la requête WHOIS."}), 504
    except Exception as exc:
        return jsonify({"error": f"Erreur WHOIS : {exc}"}), 500


# =====================================================================================
# SECTION 7.7 : SUBLIST3R & DNSRECON (SUBDOMAIN ENUMERATION)
# =====================================================================================

@app.route("/api/subdomains-scan", methods=["POST"])
def subdomains_scan():
    data = request.get_json(silent=True) or {}
    target_url = data.get("target_url", "").strip()

    if not target_url:
        return jsonify({"error": "Cible manquante."}), 400

    root_domain = extract_root_domain(target_url)

    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp_file:
        tmp_path = tmp_file.name

    subdomains = set()

    # Tentative 1 : Sublist3r OSINT (recherche passive multi-moteurs)
    cmd = ["sublist3r", "-d", root_domain, "-o", tmp_path, "-t", "5"]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        if os.path.exists(tmp_path):
            with open(tmp_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    sd = line.strip().lower()
                    if sd:
                        subdomains.add(sd)
            os.remove(tmp_path)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    # Tentative 2 (Fallback ou complément) : DNSRecon si Sublist3r a trouvé peu de résultats
    if len(subdomains) < 2:
        try:
            dr_cmd = ["dnsrecon", "-d", root_domain, "-t", "std"]
            res = subprocess.run(dr_cmd, capture_output=True, text=True, timeout=25)
            output = res.stdout or ""
            for line in output.splitlines():
                matches = re.findall(rf'([a-zA-Z0-9_.-]+\.{re.escape(root_domain)})', line, re.IGNORECASE)
                for m in matches:
                    subdomains.add(m.lower())
        except Exception:
            pass

    sorted_subdomains = sorted(list(subdomains))

    return jsonify({
        "domain": root_domain,
        "subdomains": sorted_subdomains,
        "count": len(sorted_subdomains)
    })



# =====================================================================================
# SECTION 7.8 : NETDISCOVER (ARP DISCOVERY)
# =====================================================================================

NETDISCOVER_JOBS = {}

CONFIGURED_SUDO_PASSWORD = ""

@app.route("/api/settings/sudo", methods=["POST"])
def set_sudo_password():
    global CONFIGURED_SUDO_PASSWORD
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    if not password:
        CONFIGURED_SUDO_PASSWORD = ""
        return jsonify({"success": True, "message": "Mot de passe effacé."})

    try:
        res = subprocess.run(
            ["sudo", "-k", "-S", "id"],
            input=f"{password}\n",
            capture_output=True,
            text=True,
            timeout=5
        )
        if res.returncode == 0:
            CONFIGURED_SUDO_PASSWORD = password
            return jsonify({"success": True, "message": "Accès sudo vérifié et activé pour Netdiscover !" })
        else:
            return jsonify({"success": False, "error": "Mot de passe sudo/root invalide."}), 401
    except Exception as exc:
        return jsonify({"success": False, "error": f"Erreur de vérification sudo : {exc}"}), 500


@app.route("/api/settings/sudo/clear", methods=["POST"])
def clear_sudo_password():
    global CONFIGURED_SUDO_PASSWORD
    CONFIGURED_SUDO_PASSWORD = ""
    return jsonify({"success": True, "message": "Mot de passe effacé."})


def _run_netdiscover_thread(job_id, target):
    NETDISCOVER_JOBS[job_id]["status"] = "running"
    NETDISCOVER_JOBS[job_id]["log"] = []

    # Clean target for Netdiscover
    is_valid, msg = validate_target(target)
    if is_valid and msg:
        target = msg[0]


    if CONFIGURED_SUDO_PASSWORD:
        cmd = ["sudo", "-S", "netdiscover", "-r", target, "-P", "-N", "-f"]
        input_data = f"{CONFIGURED_SUDO_PASSWORD}\n"
    else:
        cmd = ["netdiscover", "-r", target, "-P", "-N", "-f"]
        input_data = None

    try:
        process = subprocess.run(cmd, input=input_data, capture_output=True, text=True, timeout=40)
        output = (process.stdout or "") + (process.stderr or "")

        if "permission" in output.lower() or "cap_net_raw" in output.lower() or "socket failed" in output.lower():
            # Fallback vers ARP scan via nmap -sn -PR
            fallback_cmd = ["nmap", "-sn", "-PR", target, "-oX", "-"]
            fb_process = subprocess.run(fallback_cmd, capture_output=True, text=True, timeout=30)
            if fb_process.returncode == 0 and fb_process.stdout:
                parsed_hosts = parse_nmap_xml(fb_process.stdout)
                devices = []
                for h in parsed_hosts:
                    devices.append({
                        "ip": h.get("ip"),
                        "mac": h.get("mac") or "Inconnu",
                        "count": 1,
                        "len": 60,
                        "vendor": h.get("vendor") or "Inconnu"
                    })
                NETDISCOVER_JOBS[job_id]["status"] = "done"
                NETDISCOVER_JOBS[job_id]["result"] = devices
                save_history("netdiscover", target, devices)
                return

            NETDISCOVER_JOBS[job_id]["status"] = "error"
            NETDISCOVER_JOBS[job_id]["error"] = (
                "Permission refusée par le système Linux (capture de paquets ARP bruts). "
                "Pour autoriser Netdiscover dans l'application Flask, exécutez la commande suivante dans votre terminal : "
                "sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/netdiscover"
            )
            return

        devices = []
        # Netdiscover format: IP MAC Count Len Vendor
        pattern = re.compile(r"^\s*([\d\.]+)\s+([0-9a-fA-F:]{17})\s+(\d+)\s+(\d+)\s+(.*)$")
        for line in output.splitlines():
            line_str = line.strip()
            match = pattern.match(line_str)
            if match:
                ip_val = match.group(1)
                mac_val = match.group(2)
                v_val = match.group(5).strip() or "Inconnu"
                identity = resolve_host_identity(ip_val, mac_val, v_val)

                devices.append({
                    "ip": ip_val,
                    "mac": mac_val,
                    "count": int(match.group(3)),
                    "len": int(match.group(4)),
                    "vendor": identity["vendor"],
                    "hostname": identity["hostname"] or identity["netbios_name"],
                    "netbios_name": identity["netbios_name"],
                    "workgroup": identity["workgroup"],
                    "category": identity["category"],
                    "icon": identity["icon"]
                })

        NETDISCOVER_JOBS[job_id]["status"] = "done"
        NETDISCOVER_JOBS[job_id]["result"] = devices
        save_history("netdiscover", target, devices)

    except subprocess.TimeoutExpired:
        NETDISCOVER_JOBS[job_id]["status"] = "error"
        NETDISCOVER_JOBS[job_id]["error"] = "Délai d'attente dépassé pour Netdiscover (40s)."
    except Exception as exc:
        NETDISCOVER_JOBS[job_id]["status"] = "error"
        NETDISCOVER_JOBS[job_id]["error"] = f"Erreur lors de l'exécution de Netdiscover : {exc}"


@app.route("/api/netdiscover-scan", methods=["POST"])
def start_netdiscover_scan():
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()

    if not target:
        return jsonify({"error": "Cible manquante."}), 400

    if not _tool_is_installed(REQUIRED_TOOLS["netdiscover"]["check_cmd"]):
        return jsonify({"error": "netdiscover n'est pas installé."}), 412

    job_id = str(uuid.uuid4())
    NETDISCOVER_JOBS[job_id] = {
        "status": "queued",
        "result": None,
        "error": None,
        "target": target,
        "started_at": datetime.now().isoformat(),
    }

    thread = threading.Thread(target=_run_netdiscover_thread, args=(job_id, target), daemon=True)
    thread.start()

    return jsonify({"job_id": job_id})


@app.route("/api/netdiscover-status/<job_id>", methods=["GET"])
def netdiscover_status(job_id):
    job = NETDISCOVER_JOBS.get(job_id)
    if job is None:
        return jsonify({"error": "job_id inconnu"}), 404
    return jsonify(job)


# =====================================================================================
# SECTION 8 : ROUTES FRONTEND
# =====================================================================================

@app.route("/")
def index():
    return render_template("home.html", active_page="home")

@app.route("/web")
def web():
    return render_template("web.html", active_page="web")

@app.route("/local")
def local():
    return render_template("local.html", active_page="local")

@app.route("/history")
@app.route("/history_page")
def history_page():
    return render_template("history.html", active_page="history")

@app.route("/settings")
def settings():
    return render_template("settings.html", active_page="settings")

@app.route("/api/history", methods=["GET"])
def get_history():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT id, tool, target, mode, timestamp FROM history ORDER BY timestamp DESC").fetchall()
            return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/history/<int:history_id>", methods=["GET"])
def get_history_detail(history_id):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM history WHERE id = ?", (history_id,)).fetchone()
            if row:
                data = dict(row)
                data["result_json"] = json.loads(data["result_json"])
                return jsonify(data)
            return jsonify({"error": "Non trouvé"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/history/<int:history_id>", methods=["DELETE"])
def delete_history(history_id):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM history WHERE id = ?", (history_id,))
            conn.commit()
            return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/history/delete-batch", methods=["POST"])
def delete_history_batch():
    try:
        data = request.get_json() or {}
        ids = data.get("ids", [])
        if not ids:
            return jsonify({"error": "Aucun rapport sélectionné"}), 400
        
        with sqlite3.connect(DB_PATH) as conn:
            placeholders = ",".join(["?"] * len(ids))
            conn.execute(f"DELETE FROM history WHERE id IN ({placeholders})", ids)
            conn.commit()
            return jsonify({"success": True, "deleted_count": len(ids)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =====================================================================================
# SECTION 9 : GESTION DES RAPPORTS PERSONNALISÉS (API & EXPORTATION)
# =====================================================================================

@app.route("/reports")
def reports_page():
    return render_template("reports.html", active_page="reports")

@app.route("/api/reports", methods=["GET"])
def get_reports():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT id, title, author, description, created_at, updated_at FROM custom_reports ORDER BY updated_at DESC").fetchall()
            return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/reports", methods=["POST"])
def create_report():
    try:
        data = request.get_json() or {}
        title = data.get("title", "Nouveau Rapport").strip() or "Nouveau Rapport"
        author = data.get("author", "Auditeur Cybersécurité").strip()
        description = data.get("description", "").strip()
        initial_html = f"<h1>{title}</h1><p><strong>Auditeur :</strong> {author}</p><p><strong>Date :</strong> {datetime.now().strftime('%d/%m/%Y %H:%M')}</p><hr><p>{description}</p>"
        
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO custom_reports (title, author, description, content_html, updated_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
                (title, author, description, initial_html)
            )
            report_id = cursor.lastrowid
            conn.commit()
            return jsonify({"id": report_id, "title": title, "success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/reports/<int:report_id>", methods=["GET"])
def get_report_detail(report_id):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM custom_reports WHERE id = ?", (report_id,)).fetchone()
            if not row:
                return jsonify({"error": "Rapport non trouvé"}), 404
            items = conn.execute("SELECT * FROM report_items WHERE report_id = ? ORDER BY added_at ASC", (report_id,)).fetchall()
            data = dict(row)
            data["items"] = [dict(i) for i in items]
            return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/reports/<int:report_id>", methods=["PUT"])
def update_report(report_id):
    try:
        data = request.get_json() or {}
        title = data.get("title")
        author = data.get("author")
        description = data.get("description")
        content_html = data.get("content_html")

        fields = []
        params = []
        if title is not None:
            fields.append("title = ?")
            params.append(title)
        if author is not None:
            fields.append("author = ?")
            params.append(author)
        if description is not None:
            fields.append("description = ?")
            params.append(description)
        if content_html is not None:
            fields.append("content_html = ?")
            params.append(content_html)

        if not fields:
            return jsonify({"error": "Aucune modification fournie"}), 400

        fields.append("updated_at = CURRENT_TIMESTAMP")
        params.append(report_id)

        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(f"UPDATE custom_reports SET {', '.join(fields)} WHERE id = ?", params)
            conn.commit()
            return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/reports/<int:report_id>", methods=["DELETE"])
def delete_report(report_id):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM custom_reports WHERE id = ?", (report_id,))
            conn.execute("DELETE FROM report_items WHERE report_id = ?", (report_id,))
            conn.commit()
            return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/reports/<int:report_id>/append", methods=["POST"])
def append_to_report(report_id):
    try:
        data = request.get_json() or {}
        item_title = data.get("title", "Élément d'analyse")
        item_html = data.get("html", "")

        if not item_html:
            return jsonify({"error": "Contenu HTML vide"}), 400

        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT content_html FROM custom_reports WHERE id = ?", (report_id,)).fetchone()
            if not row:
                return jsonify({"error": "Rapport non trouvé"}), 404

            current_html = row["content_html"] or ""
            new_block = f'<div class="report-section-block" style="margin-top:20px; padding:15px; border-left:4px solid #00ff41; background:rgba(0,255,65,0.05);"><h3>{item_title}</h3>{item_html}</div>'
            updated_html = current_html + new_block

            conn.execute(
                "UPDATE custom_reports SET content_html = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (updated_html, report_id)
            )
            conn.execute(
                "INSERT INTO report_items (report_id, item_title, item_html) VALUES (?, ?, ?)",
                (report_id, item_title, item_html)
            )
            conn.commit()
            return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/reports/<int:report_id>/export/docx", methods=["GET"])
def export_report_docx(report_id):
    try:
        import docx
        from docx.shared import Inches, Pt, RGBColor
        from bs4 import BeautifulSoup
    except ImportError:
        return jsonify({"error": "Module python-docx non disponible"}), 500

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        report = conn.execute("SELECT * FROM custom_reports WHERE id = ?", (report_id,)).fetchone()
        if not report:
            return jsonify({"error": "Rapport introuvable"}), 404

    doc = docx.Document()
    title_p = doc.add_heading(report["title"], level=0)
    meta_p = doc.add_paragraph(f"Auditeur : {report['author']} | Date : {report['updated_at']}")
    meta_p.runs[0].font.italic = True
    meta_p.runs[0].font.color.rgb = RGBColor(100, 100, 100)

    html_content = report["content_html"] or ""
    temp_files = []
    
    try:
        soup = BeautifulSoup(html_content, "html.parser")
        for elem in soup.find_all(['h1', 'h2', 'h3', 'h4', 'p', 'table', 'img']):
            if elem.name in ['h1', 'h2', 'h3', 'h4']:
                level = int(elem.name[1])
                doc.add_heading(elem.get_text().strip(), level=level)
            elif elem.name == 'p':
                text = elem.get_text().strip()
                if text:
                    doc.add_paragraph(text)
            elif elem.name == 'table':
                rows = elem.find_all('tr')
                if rows:
                    col_count = max(len(r.find_all(['td', 'th'])) for r in rows)
                    if col_count > 0:
                        doc_table = doc.add_table(rows=len(rows), cols=col_count)
                        doc_table.style = 'Table Grid'
                        for r_idx, r in enumerate(rows):
                            cols = r.find_all(['td', 'th'])
                            for c_idx, c in enumerate(cols):
                                if c_idx < col_count:
                                    doc_table.cell(r_idx, c_idx).text = c.get_text().strip()
            elif elem.name == 'img' and elem.get('src', '').startswith('data:image'):
                src = elem['src']
                try:
                    header, encoded = src.split(',', 1)
                    img_bytes = base64.b64decode(encoded)
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmp_img:
                        tmp_img.write(img_bytes)
                        tmp_path = tmp_img.name
                        temp_files.append(tmp_path)
                    doc.add_picture(tmp_path, width=Inches(6.0))
                except Exception as img_err:
                    print(f"Erreur insertion image Word : {img_err}")
    except Exception as parse_err:
        for line in html_content.replace("<br>", "\n").replace("</p>", "\n").split("\n"):
            clean_text = re.sub('<[^<]+?>', '', line).strip()
            if clean_text:
                doc.add_paragraph(clean_text)

    mem_file = io.BytesIO()
    doc.save(mem_file)

    for tmp in temp_files:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass

    mem_file.seek(0)
    filename = f"Rapport_{report_id}_{re.sub(r'[^a-zA-Z0-9]', '_', report['title'])}.docx"
    return send_file(
        mem_file,
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        as_attachment=True,
        download_name=filename
    )

@app.route("/api/reports/<int:report_id>/export/pdf", methods=["GET"])
def export_report_pdf(report_id):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from bs4 import BeautifulSoup
    except ImportError:
        return jsonify({"error": "Module reportlab non disponible"}), 500

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        report = conn.execute("SELECT * FROM custom_reports WHERE id = ?", (report_id,)).fetchone()
        if not report:
            return jsonify({"error": "Rapport introuvable"}), 404

    pdf_buffer = io.BytesIO()
    doc = SimpleDocTemplate(pdf_buffer, pagesize=A4, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=18, textColor=colors.HexColor('#00aa2b'), spaceAfter=10)
    meta_style = ParagraphStyle('MetaStyle', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor('#555555'), spaceAfter=15)
    body_style = ParagraphStyle('BodyStyle', parent=styles['Normal'], fontSize=10, leading=14, spaceAfter=8)

    story = []
    story.append(Paragraph(report['title'], title_style))
    story.append(Paragraph(f"Auditeur : {report['author']} | Date : {report['updated_at']}", meta_style))
    story.append(Spacer(1, 10))

    html_content = report["content_html"] or ""
    temp_files = []

    try:
        soup = BeautifulSoup(html_content, "html.parser")
        for elem in soup.find_all(['h1', 'h2', 'h3', 'h4', 'p', 'table', 'img']):
            if elem.name in ['h1', 'h2', 'h3', 'h4']:
                level_style = ParagraphStyle('Heading', parent=styles['Heading2'], fontSize=13, textColor=colors.HexColor('#1a5e20'), spaceBefore=8, spaceAfter=4)
                story.append(Paragraph(elem.get_text().strip(), level_style))
            elif elem.name == 'p':
                text = elem.get_text().strip()
                if text:
                    story.append(Paragraph(text, body_style))
            elif elem.name == 'table':
                rows = elem.find_all('tr')
                table_data = []
                for r in rows:
                    cols = r.find_all(['td', 'th'])
                    row_data = [Paragraph(c.get_text().strip(), body_style) for c in cols]
                    if row_data:
                        table_data.append(row_data)
                if table_data:
                    t = Table(table_data)
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e8f5e9')),
                        ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor('#1b5e20')),
                        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
                        ('PADDING', (0,0), (-1,-1), 4),
                    ]))
                    story.append(t)
                    story.append(Spacer(1, 10))
            elif elem.name == 'img' and elem.get('src', '').startswith('data:image'):
                src = elem['src']
                try:
                    header, encoded = src.split(',', 1)
                    img_bytes = base64.b64decode(encoded)
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmp_img:
                        tmp_img.write(img_bytes)
                        tmp_path = tmp_img.name
                        temp_files.append(tmp_path)
                    rl_img = RLImage(tmp_path, width=450, height=250)
                    story.append(rl_img)
                    story.append(Spacer(1, 10))
                except Exception as img_err:
                    print(f"Erreur insertion image PDF : {img_err}")
    except Exception:
        clean_text = re.sub('<[^<]+?>', '', html_content)
        story.append(Paragraph(clean_text, body_style))

    doc.build(story)

    for tmp in temp_files:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass

    pdf_buffer.seek(0)
    filename = f"Rapport_{report_id}_{re.sub(r'[^a-zA-Z0-9]', '_', report['title'])}.pdf"
    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename
    )


if __name__ == "__main__":
    # debug=True est pratique en pédagogie (affichage des erreurs)
    # use_reloader=False empêche les redémarrages intempestifs du serveur lors des écritures SQLite en base de données
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)
