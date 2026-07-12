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

import ipaddress
import json
import re
import shutil
import subprocess
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime

from flask import Flask, jsonify, render_template, request

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
            cmd, capture_output=True, timeout=5, check=False
        )
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
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
        installed = _tool_is_installed(meta["check_cmd"])
        status[name] = {
            "installed": installed,
            "description": meta["description"],
        }
        if not installed:
            missing_packages.append(meta["apt_package"])

    return jsonify({
        "all_installed": len(missing_packages) == 0,
        "tools": status,
        "missing_apt_packages": missing_packages,
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
    Valide strictement la cible fournie par l'élève : IP unique, plage CIDR,
    ou nom d'hôte simple. Rejette tout caractère de shell / métacaractère
    permettant une injection de commande (';', '|', '&', '`', '$', etc.)
    puisque nous passons systématiquement des listes d'arguments à
    subprocess (jamais shell=True), mais on valide quand même en amont
    pour donner un message d'erreur pédagogique clair à l'élève.
    """
    target = target.strip()
    if not target:
        return False, "La cible ne peut pas être vide."

    # IP simple ou réseau CIDR
    try:
        ipaddress.ip_network(target, strict=False)
        return True, target
    except ValueError:
        pass

    # Nom d'hôte (ex: localhost, machine.local)
    if HOSTNAME_RE.match(target):
        return True, target

    return False, (
        "Cible invalide. Formats acceptés : adresse IP (192.168.1.10), "
        "plage CIDR (192.168.1.0/24) ou nom d'hôte (metasploitable.local)."
    )


ALLOWED_TIMING = {"0", "1", "2", "3", "4", "5"}
ALLOWED_SCAN_TYPES = {"sS", "sT", "sU", "sA", "sn"}
ALLOWED_PORT_MODES = {"fast", "top1000", "all", "custom"}
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

    # Ports à scanner
    port_mode = options.get("port_mode", "fast")
    if port_mode not in ALLOWED_PORT_MODES:
        port_mode = "fast"

    if port_mode == "fast":
        cmd.append("-F")
        explanation.append({"flag": "-F", "meaning": "Scan rapide : seulement les 100 ports les plus courants."})
    elif port_mode == "top1000":
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


# =====================================================================================
# SECTION 4 : EXÉCUTION DU SCAN ET PARSING XML
# =====================================================================================

def parse_nmap_xml(xml_output):
    """Parse la sortie XML native de nmap en structure JSON exploitable par le frontend."""
    root = ET.fromstring(xml_output)
    hosts_result = []

    for host in root.findall("host"):
        status_el = host.find("status")
        if status_el is not None and status_el.get("state") != "up":
            continue

        address_el = host.find("address")
        ip_addr = address_el.get("addr") if address_el is not None else "inconnu"

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

        hosts_result.append({
            "ip": ip_addr,
            "hostname": hostname,
            "os_matches": os_matches,
            "ports": ports_result,
        })

    return hosts_result


MAX_LOG_LINES = 2000  # borne de sécurité pour éviter une consommation mémoire illimitée


def _run_scan_thread(job_id, cmd):
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
    if shutil.which("stdbuf"):
        run_cmd = ["stdbuf", "-oL", "-eL"] + cmd

    def append_log(line):
        log = SCAN_JOBS[job_id]["log"]
        log.append(line)
        if len(log) > MAX_LOG_LINES:
            del log[0:len(log) - MAX_LOG_LINES]

    try:
        process = subprocess.Popen(
            run_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
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

    is_valid, msg = validate_target(target)
    if not is_valid:
        return jsonify({"error": msg}), 400

    # Vérification que nmap est bien installé avant de lancer quoi que ce soit
    if not _tool_is_installed(REQUIRED_TOOLS["nmap"]["check_cmd"]):
        return jsonify({"error": "nmap n'est pas installé. Utilisez le bouton d'installation des dépendances."}), 412

    cmd, explanation = build_nmap_command(data.get("options", {}))
    cmd.append(msg)  # cible validée, ajoutée en dernier argument (liste, pas de shell)

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

    thread = threading.Thread(target=_run_scan_thread, args=(job_id, cmd), daemon=True)
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


# =====================================================================================
# SECTION 5 : RECHERCHE DE CVE / EXPLOITS VIA SEARCHSPLOIT
# =====================================================================================

@app.route("/api/cve-search", methods=["POST"])
def cve_search():
    """
    Recherche des exploits/CVE connus pour un couple (produit, version)
    détecté par nmap -sV, via la base Exploit-DB locale (searchsploit).

    On utilise searchsploit en mode --json pour obtenir une sortie structurée,
    et on lance la commande avec une liste d'arguments (pas de shell=True)
    pour éviter toute injection, même si les chaînes proviennent de nmap
    (donc a priori fiables, mais on ne fait jamais confiance par défaut).
    """
    data = request.get_json(silent=True) or {}
    product = str(data.get("product", "")).strip()
    version = str(data.get("version", "")).strip()

    if not product:
        return jsonify({"error": "Produit manquant."}), 400

    if not _tool_is_installed(REQUIRED_TOOLS["searchsploit"]["check_cmd"]):
        return jsonify({"error": "searchsploit n'est pas installé.", "results": []}), 412

    query = f"{product} {version}".strip()

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

        return jsonify({"query": query, "results": results})

    except subprocess.TimeoutExpired:
        return jsonify({"error": "searchsploit a mis trop de temps à répondre."}), 504
    except FileNotFoundError:
        return jsonify({"error": "searchsploit introuvable."}), 412


# =====================================================================================
# SECTION 6 : ROUTES FRONTEND
# =====================================================================================

@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    # debug=True est pratique en pédagogie (rechargement automatique du code)
    # mais NE DOIT JAMAIS être utilisé tel quel en production / réseau exposé.
    # host="127.0.0.1" restreint l'accès à la machine locale de l'élève.
    app.run(host="127.0.0.1", port=5000, debug=True)
