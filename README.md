# 🟢 Matrix scanner : plateforme pédagogique d'audit réseau, de sécurité web et de CVE

**Matrix Scanner** est un tableau de bord web interactif, visuel et pédagogique conçu pour les élèves ingénieurs, les professionnels et les passionnés de cybersécurité.

Il permet d'apprendre et d'expérimenter concrètement la reconnaissance réseau avec `nmap`, l'analyse d'applications web (en-têtes de sécurité, WAF, empreintes), l'exploration de réseaux locaux (LAN, SMB, NetBIOS) et la recherche de vulnérabilités réelles (CVE) via la base locale Exploit-DB (`searchsploit`).

---

## ⚠️ Avertissement légal et éthique

**L'utilisation de cet outil doit se faire exclusivement sur des systèmes dont vous êtes propriétaire ou pour lesquels vous possédez une autorisation écrite explicite.**

* **Cadre légal** : en France, l'accès ou le maintien frauduleux dans un système de traitement automatisé de données est puni par l'article 323-1 et suivants du Code pénal.
* **Usage recommandé** : environnements de TP isolés, machines virtuelles de laboratoire (*Metasploitable, VulnHub, TryHackMe*), ou missions de test d'intrusion dûment autorisées.

---

## 🎓 Objectifs pédagogiques

Matrix Scanner n'est pas une boîte noire : il est spécialement conçu pour transmettre les concepts fondamentaux de la sécurité offensive et défensive :

1. **Faire le lien UI vers CLI** : chaque option sélectionnée dans l'interface reconstruit et affiche en temps réel la commande exacte qui est exécutée (`Command Preview`).
2. **Comprendre la mécanique des paquets réseau** : différencier un scan TCP SYN (`-sS`) discret d'un scan TCP Connect (`-sT`) ou d'un scan furtif FIN/NULL/Xmas, et comprendre l'exigence de privilèges (*raw sockets*).
3. **Évaluer la sécurité d'une application web à distance** : détecter la présence d'un pare-feu applicatif (WAF) et vérifier l'absence d'en-têtes HTTP de protection (*HSTS, CSP, X-Frame-Options, etc.*).
4. **Explorer un réseau local (LAN)** : réaliser la découverte d'hôtes par ARP, l'énumération NetBIOS et l'audit des partages SMB.
5. **Pratiquer la gestion des vulnérabilités** : associer chaque service et version logicielle détectés (`-sV`) à des failles réelles répertoriées dans la base de données Exploit-DB.

---

## 🛠️ Outils de sécurité issus de Kali Linux et vérification automatique

Matrix Scanner s'appuie sur une suite de 12 outils de référence issus de la distribution Kali Linux :

1. **`nmap`** : scanner de ports, résolution de services et détection d'empreinte système.
2. **`searchsploit` (exploitdb)** : recherche d'exploits et de vulnérabilités réelles (CVE) dans la base locale Exploit-DB.
3. **`whatweb`** : analyseur d'empreintes technologiques web (CMS, serveurs web, frameworks).
4. **`wafw00f`** : outil de détection des pare-feux applicatifs web (WAF).
5. **`nikto`** : scanner de vulnérabilités web et recherche de fichiers dangereux.
6. **`nuclei`** : scanner de vulnérabilités basé sur des modèles de détection réseau et web.
7. **`wpscan`** : scanner spécialisé dans la détection des failles sur le CMS WordPress.
8. **`gowitness`** : outil automatisé de capture d'écran d'applications web.
9. **`netdiscover`** : outil de découverte d'hôtes et d'exploration ARP active ou passive sur le réseau local.
10. **`nbtscan`** : résolution de noms d'hôtes et énumération des groupes de travail NetBIOS.
11. **`enum4linux`** : énumération complète des informations Windows, utilisateurs et partages Samba/SMB.
12. **`smbmap`** : analyse fine des autorisations et des droits d'accès aux partages réseau SMB.

### 🔍 Vérification automatique et installation en un clic
Au chargement de l'application, le backend exécute automatiquement une vérification de la présence de chacun de ces 12 outils sur le système hôte.

Si un ou plusieurs outils sont absents :
* L'interface affiche automatiquement un bandeau d'alerte listant les paquets manquants.
* Un bouton d'installation **"Installer les outils manquants"** est proposé à l'utilisateur.
* En cliquant sur ce bouton, l'application fait appel à `pkexec` (Polkit) qui affiche la boîte de dialogue d'authentification graphique native du système.
* L'utilisateur saisit son mot de passe administrateur et le système installe automatiquement les outils requis via `apt-get`, sans que le serveur Flask n'ait besoin d'être lancé en root.

---

## ⚡ Fonctionnalités et workflows détaillés

Le logiciel distingue clairement deux workflows d'analyse selon la nature de la cible :

### 🌐 1. Workflow du scan web et à distance (`/web`)

Ce workflow est dédié à l'audit de cibles distantes (noms de domaine, URL web, adresses IP publiques ou distantes) :

```
[1. Saisie IP/Domaine] -> [2. Test Ping ICMP] -> [3. Scan Nmap -sV -O] -> [4. Audit Web & WAF]
   -> [5. Capture d'écran Web] -> [6. Corrélation CVE Searchsploit] -> [7. Score de Risque Distant] -> [8. Archivage SQLite]
```

* **Étape 1 : normalisation de la cible** : extrait et valide l'IP ou le domaine pour éliminer tout risque d'injection de commande.
* **Étape 2 : test de réactivité distante** : envoi de requêtes ICMP/Ping pour vérifier si la cible répond.
* **Étape 3 : scan Nmap des services distants** : identification des ports ouverts, résolution des versions de services (`-sV`) et empreinte du système d'exploitation (`-O`).
* **Étape 4 : audit web approfondi et WAF** : si des services web (80, 443, 8080...) sont ouverts, détection du pare-feu applicatif via `wafw00f`, analyse des technologies web via `whatweb` et `nikto`, puis audit des en-têtes de sécurité HTTP (*HSTS, CSP, X-Frame-Options, X-Content-Type-Options*).
* **Étape 5 : capture d'écran headless** : génération automatique d'un visuel de l'application web distante.
* **Étape 6 : corrélation CVE** : recherche automatique des failles connues dans la base locale Exploit-DB via `searchsploit --json` et vérification de modèles `nuclei`.
* **Étape 7 : score de risque web distant (0 à 100)** : calcul d'un score de sévérité basé sur la vulnérabilité des en-têtes HTTP, l'exposition des ports et les CVE identifiées.
* **Étape 8 : archivage et rendu** : sauvegarde du rapport complet dans la base SQLite locale et génération de graphiques interactifs (Chart.js).

---

### 🏠 2. Workflow du scan réseau local (`/local`)

Ce workflow est spécialement conçu pour la reconnaissance et l'exploration de machines sur le réseau local (LAN, adresses IP privées, sous-réseaux) :

```
[1. Détection Sous-réseau LAN] -> [2. Balayage ARP Netdiscover] -> [3. Résolution NetBIOS Nbtscan]
   -> [4. Scan Nmap Ports Locaux] -> [5. Énumération SMB Enum4linux/Smbmap] -> [6. Corrélation CVE LAN] -> [7. Archivage SQLite]
```

* **Étape 1 : identification de la plage LAN** : détection de l'interface réseau locale et de la plage IP du sous-réseau (ex: `192.168.1.0/24`).
* **Étape 2 : découverte d'hôtes par ARP** : utilisation de `netdiscover` pour repérer toutes les machines actives sur le segment local, même si le pare-feu de la cible bloque le ping ICMP.
* **Étape 3 : résolution NetBIOS et noms d'hôtes** : exécution de `nbtscan` pour identifier les noms de machines Windows/Samba et les groupes de travail locaux.
* **Étape 4 : cartographie des services locaux** : scan Nmap des ports réseau de la machine locale sélectionnée (`-sS`/`-sT`).
* **Étape 5 : énumération approfondie des partages SMB/Samba** : si les ports 139 ou 445 sont ouverts, lancement de `enum4linux` et `smbmap` pour lister les partages réseau accessibles, les utilisateurs et la politique de sécurité.
* **Étape 6 : évaluation du niveau d'exposition du LAN** : corrélation avec la base Exploit-DB et enregistrement du rapport dans la base de données SQLite locale.

---

### ⚙️ 3. Workflow du scan manuel avancé

Permet aux élèves de configurer et d'expérimenter finement les options avancées de `nmap` :

#### Types de scans pris en charge :
* **TCP SYN Scan (`-sS`)** : furtif ("half-open"), envoie un SYN et attend SYN-ACK sans finaliser la connexion. Nécessite les capacités réseau `cap_net_raw`.
* **TCP Connect Scan (`-sT`)** : établit une connexion TCP complète via l'API `connect()` du système. Utilisable sans privilèges root.
* **UDP Scan (`-sU`)** : balaye les services UDP (DNS, DHCP, SNMP...). Plus lent et sujet aux pertes de paquets.
* **Scans furtifs (`-sF`, `-sN`, `-sX`)** : scans FIN, NULL et Xmas tirant parti des spécifications RFC TCP pour contourner certains filtres stateless.
* **TCP ACK Scan (`-sA`)** : permet de déterminer si les ports sont filtrés par un pare-feu à état (*stateful*).

#### Options d'évasion et timing :
* **Contrôle de vitesse (`-T0` à `-T5`)** : de Paranoid (esquive IDS) à Insane (scans ultra-rapides sur réseaux locaux fiables).
* **Fragmentation de paquets (`-f`)** : scinde les en-têtes TCP en petits paquets pour échapper à la détection de certains IDS.
* **Leurres IP (`-D RND:5`)** : masque l'IP réelle du scanner au milieu d'IP fictives générées aléatoirement.
* **Traceroute (`--traceroute`)** : cartographie les sauts réseau (routeurs/pare-feux) jusqu'à la cible.

---

### 📊 4. Historique et base de données SQLite (`scanner_history.db`)

Tous les scans réalisés (web, local ou manuel) sont enregistrés localement dans une base SQLite.
* Conserve le contexte de chaque scan (cible, mode local ou distant, type de scan, horodatage, résultats JSON complets).
* Permet la consultation ultérieure, le rechargement interactif des rapports et la suppression d'entrées d'historique.

---

## 🔒 Privilèges Linux et sécurité (`setcap`)

Pourquoi les scans `-sS` et `-O` nécessitent-ils des privilèges spéciaux ?
Les paquets réseau sur mesure (Raw Sockets) requièrent traditionnellement d'exécuter la commande en `root`.

Pour éviter la mauvaise pratique de sécurité qui consisterait à exécuter l'ensemble du serveur Flask avec `sudo`, le script d'installation utilise la fonctionnalité **Linux Capabilities** :
```bash
sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f venv/bin/python3)
```
Cela attribue uniquement à l'interpréteur Python du venv les privilèges stricts d'émission de paquets bruts, garantissant une étanchéité et une sécurité maximales.

---

## 🚀 Guide d'installation et lancement pas à pas

### Méthode 1 : installation automatisée (recommandée)

```bash
# 1. Cloner le projet et se placer dans le dossier
cd matrix-scanner

# 2. Rendre les scripts exécutables
chmod +x install.sh run.sh

# 3. Lancer le script d'installation (demande sudo uniquement pour apt et setcap)
./install.sh

# 4. Lancer le serveur (sans sudo)
./run.sh
```

### Méthode 2 : installation manuelle

```bash
# 1. Créer et activer l'environnement virtuel Python
python3 -m venv venv
source venv/bin/activate

# 2. Installer les dépendances Python
pip install -r requirements.txt

# 3. Installer les outils système (sur Debian/Ubuntu/Kali)
sudo apt-get update
sudo apt-get install -y nmap exploitdb whatweb wafw00f nikto nuclei wpscan gowitness netdiscover nbtscan enum4linux smbmap policykit-1 libcap2-bin

# 4. Attribuer les capacités réseau au Python du venv
sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f venv/bin/python3)

# 5. Lancer l'application
python3 app.py
```

### Accès à l'application
Une fois démarré, ouvrez votre navigateur web à l'adresse : `http://127.0.0.1:5000`

---

## 📁 Architecture du projet

```
matrix-scanner/
├── app.py                 # Backend Flask : routes API REST, orchestration subprocess, SQLite, CVE
├── install.sh             # Script d'installation automatisé (venv, apt-get, setcap)
├── run.sh                 # Script de lancement du serveur local
├── requirements.txt       # Dépendances Python (Flask)
├── scanner_history.db     # Base de données SQLite générée automatiquement
├── README.md              # Documentation pédagogique du projet
├── templates/             # Templates HTML Jinja2 modularisés
│   ├── base.html          # Layout principal (barre de nav, canvas Matrix, scripts)
│   ├── home.html          # Vue d'ensemble et accueil du tableau de bord
│   ├── web.html           # Interface dédiée aux audits Web & WAF à distance
│   ├── local.html         # Interface dédiée à la reconnaissance LAN / Réseau local
│   ├── history.html       # Interface de consultation de l'historique SQLite
│   ├── settings.html      # État des dépendances et outils système
│   └── partials/          # Composants réutilisables
│       ├── results.html   # Rendu dynamique des résultats de scan & graphiques Chart.js
│       ├── modal.html     # Modales interactives de détails CVE / Exploit-DB
│       ├── manual_settings.html # Formulaire des options avancées Nmap
│       └── banners.html   # Bandeaux d'alerte des dépendances
└── static/
    ├── style.css          # Thème sombre Matrix / Cyberpunk (Glassmorphism & animations)
    ├── script.js          # Logique frontend (requêtes API asynchrones, Chart.js, modales)
    └── matrix.js          # Animation Canvas effet pluie de code Matrix
```

---

## 🛠️ Guide de dépannage (FAQ)

| Symptôme | Cause probable | Solution |
|---|---|---|
| **Erreur "Permission refusée" lors du scan -sS / -O** | Capacités `setcap` non attribuées au venv | Exécuter `sudo setcap cap_net_raw,cap_net_admin+eip venv/bin/python3` ou utiliser le mode `-sT`. |
| **Le bouton "Installer les outils manquants" ne réagit pas** | `policykit-1` manquant sur le système | Installer Polkit via terminal : `sudo apt-get install policykit-1`. |
| **Erreur de création de venv sous Debian/Kali** | Module `ensurepip` absent | Exécuter `sudo apt-get install python3-full` puis relancer `./install.sh`. |
| **Le scan est très long ou ne répond pas** | Pare-feu bloquant ou hôte injoignable | Réduire le nombre de ports, vérifier la réactivité avec un ping, ou utiliser le timing `-T3`. |
