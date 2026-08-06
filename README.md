# 🟢 M-SCAN : plateforme d'audit réseau, de sécurité web, de CVE et de génération de rapports

> **Concepteur & Développeur** : **Ronan BOZOC**

**M-SCAN** est un tableau de bord web interactif, visuel et professionnel conçu par **Ronan BOZOC** pour les élèves ingénieurs, les professionnels de la cybersécurité et les experts en test d'intrusion.

Il permet de réaliser des audits de reconnaissance réseau avec `nmap`, d'analyser des applications web (en-têtes de sécurité, pare-feu applicatif WAF, empreintes technologiques), d'explorer des réseaux locaux (LAN, partages SMB, NetBIOS), de corréler des vulnérabilités réelles (CVE) via Exploit-DB, d'exporter des **rapports d'audit professionnels aux formats PDF et Word (.docx)**, ainsi que de **protéger son IP publique via le réseau Tor avec OnionHop 3.7.8**.

---

## 🚀 Nouvelles fonctionnalités clés

### 📄 1. Génération & Exportation de rapports d'audit (PDF & Word .docx)
* **Exportation PDF (`reportlab`)** : génère automatiquement un document d'audit PDF complet avec en-tête professionnel, résumé exécutif, matrice d'évaluation des risques, liste des ports/services découverts et détails des vulnérabilités CVE.
* **Exportation Word (.docx) (`python-docx`)** : produit un document `.docx` entièrement modifiable, prêt à être intégré dans un livrable de test d'intrusion ou un rapport de TP académique.
* **Accès instantané** : téléchargeable directement en 1-clic depuis la page des résultats de scan ou depuis l'historique des analyses.

### 🧅 2. Protection de l'IP publique & Intégration d'OnionHop (Réseau Tor)
* **Protection de l'IP d'origine** : lors du lancement avec `./run.sh`, l'utilisateur peut choisir de démarrer **OnionHop 3.7.8** pour faire transiter les requêtes et masquer son IP publique réelle derrière le réseau Tor.
* **Installation automatisée depuis GitHub** : si OnionHop n'est pas détecté sur le système Linux, `./run.sh` propose de le télécharger et d'installer l'AppImage v3.7.8 depuis le dépôt officiel GitHub (`center2055/OnionHop`).
* **Moniteur d'IP publique en temps réel** : la barre latérale du dashboard interroge dynamiquement l'IP publique active. Lorsque OnionHop est en cours d'exécution, l'adresse IP du nœud de sortie Tor est immédiatement détectée et affichée avec un **bouton de copie rapide en 1 clic**.

### 💻 3. Interface de lancement ASCII Art & Cyberpunk (`M-SCAN`)
* **Terminal Cyberpunk Vert Matrix** : le script `./run.sh` arbore un design ASCII Art en vert phosphore Matrix (`#00FF00`), proposant un menu interactif avec minuteur de démarrage automatique (15s par défaut).
* **Gestion dynamique des ports réseau** : le serveur vérifie la disponibilité des ports. Si le port par défaut `5000` est déjà utilisé sur la machine, l'application sélectionne automatiquement le premier port libre supérieur ou égal à `10001`.

### 📊 4. Télémétrie et moniteur système en direct
* **Barre latérale interactive** : affichage de l'horloge système en temps réel, de l'utilisation du processeur (% CPU), de la mémoire (% RAM) et du débit réseau avec graphique dynamique Canvas (Sparkline).

---

## ⚠️ Avertissement légal et éthique

**L'utilisation de cet outil doit se faire exclusivement sur des systèmes dont vous êtes propriétaire ou pour lesquels vous possédez une autorisation écrite explicite.**

* **Cadre légal** : en France, l'accès ou le maintien frauduleux dans un système de traitement automatisé de données est puni par l'article 323-1 et suivants du Code pénal.
* **Usage recommandé** : environnements de TP isolés, machines virtuelles de laboratoire (*Metasploitable, VulnHub, TryHackMe*), ou missions de test d'intrusion duly autorisées.

---

## 🎓 Objectifs pédagogiques

M-SCAN n'est pas une boîte noire : il est spécialement conçu pour transmettre les concepts fondamentaux de la sécurité offensive et défensive :

1. **Faire le lien UI vers CLI** : chaque option sélectionnée dans l'interface reconstruit et affiche en temps réel la commande exacte qui est exécutée (`Command Preview`).
2. **Comprendre la mécanique des paquets réseau** : différencier un scan TCP SYN (`-sS`) discret d'un scan TCP Connect (`-sT`) ou d'un scan furtif FIN/NULL/Xmas, et comprendre l'exigence de privilèges (*raw sockets*).
3. **Évaluer la sécurité d'une application web à distance** : détecter la présence d'un pare-feu applicatif (WAF) et vérifier l'absence d'en-têtes HTTP de protection (*HSTS, CSP, X-Frame-Options, etc.*).
4. **Explorer un réseau local (LAN)** : réaliser la découverte d'hôtes par ARP, l'énumération NetBIOS et l'audit des partages SMB.
5. **Pratiquer la gestion des vulnérabilités & rapports** : associer chaque service et version logicielle détectés (`-sV`) à des failles réelles répertoriées dans Exploit-DB et générer un rapport PDF / Word récapitulatif.

---

## 🛠️ Outils de sécurité et modules système (18 outils au total)

M-SCAN s'appuie sur une suite complète de **18 outils de référence** issus de Kali Linux et de modules Python spécialisés :

1. **`nmap`** : scanner de ports, résolution de services et détection d'empreinte système.
2. **`searchsploit` (exploitdb)** : recherche d'exploits et de vulnérabilités réelles (CVE) dans la base locale Exploit-DB.
3. **`nuclei`** : scanner de vulnérabilités basé sur des modèles de détection réseau et web.
4. **`whatweb`** : analyseur d'empreintes technologiques web (CMS, serveurs web, frameworks).
5. **`wafw00f`** : outil de détection des pare-feux applicatifs web (WAF).
6. **`wpscan`** : scanner spécialisé dans la détection des failles sur le CMS WordPress.
7. **`gowitness`** : outil automatisé de capture d'écran d'applications web.
8. **`netdiscover`** : outil de découverte d'hôtes et d'exploration ARP active ou passive sur le réseau local.
9. **`nbtscan`** : résolution de noms d'hôtes et énumération des groupes de travail NetBIOS.
10. **`nikto`** : scanner de vulnérabilités web et recherche de fichiers dangereux.
11. **`enum4linux`** : énumération complète des informations Windows, utilisateurs et partages Samba/SMB.
12. **`smbmap`** : analyse fine des autorisations et des droits d'accès aux partages réseau SMB.
13. **`whois`** : consultation des informations de registre des noms de domaine (WHOIS).
14. **`sublist3r`** : énumération passive OSINT de sous-domaines web.
15. **`subfinder`** : découverte rapide multi-sources de sous-domaines web.
16. **`reportlab`** : moteur de génération et d'exportation de rapports PDF professionnels.
17. **`python-docx`** : moteur de génération et d'exportation de rapports Word (.docx).
18. **`psutil`** : télémétrie système, statistiques de processeur (CPU) et mémoire (RAM) en temps réel.

### 🔍 Vérification automatique et installation en un clic
Au chargement de l'application, le backend exécute automatiquement une vérification de la présence de chacun de ces 18 outils et modules sur le système hôte.

Si un ou plusieurs outils sont absents :
* L'interface affiche automatiquement un bandeau d'alerte listant les paquets manquants.
* Un bouton d'installation **"Installer les outils manquants"** est proposé à l'utilisateur.
* En cliquant sur ce bouton, l'application fait appel à `pkexec` (Polkit) qui affiche la boîte de dialogue d'authentification graphique native du système Linux.
* L'utilisateur saisit son mot de passe administrateur et le système installe automatiquement les outils requis via `apt-get` / `pip`, sans que le serveur Flask n'ait besoin d'être lancé en root.

---

## ⚡ Fonctionnalités et workflows détaillés

Le logiciel distingue clairement deux workflows d'analyse selon la nature de la cible :

### 🌐 1. Workflow du scan web et à distance (`/web`)

Ce workflow est dédié à l'audit de cibles distantes (noms de domaine, URL web, adresses IP publiques ou distantes) :

```
[Étape 1 : WHOIS] 
   └─► [Étape 2 : Sous-domaines Subfinder / Sublist3r / DNS Probe] 
          └─► [Étape 3 : Détection WAF (Wafw00f)] 
                 └─► [Étape 4 : Capture d'écran Gowitness] 
                        └─► [Étape 5 : Empreinte CMS WhatWeb] 
                               └─► [Étape 6 : Scan Nmap, Nuclei & CVE Searchsploit]
```

| Étape | Action & Outils | Rôle & Pourquoi ces outils sont utilisés ? |
| :--- | :--- | :--- |
| **Étape 1** | **`WHOIS`** | **Information de domaine passive** : Extrait le registrar, les serveurs DNS d'autorité (NS), les dates d'enregistrement et la configuration DNSSEC sans toucher directement à l'application web. |
| **Étape 2** | 🔍 **`Subfinder` + `Sublist3r` + `DNS Probe` (`dnsprobe`)** | **Énumération hybride des sous-domaines (OSINT & DNS)** :<br>• `Subfinder` : Interroge les certificats TLS (*CT Logs*), SecurityTrails et Chaos.<br>• `Sublist3r` : Recherche passive sur les moteurs de recherche.<br>• **`DNS Probe` (`dnsprobe` / sondage DNS direct)** : Réalise des résolutions DNS multithreadées sur les préfixes fréquents (`api.`, `dev.`, `admin.`, `vpn.`, `cloud.`) avec **filtre anti-Wildcard DNS** pour éliminer les faux positifs (`*.domaine.com`). |
| **Étape 3** | 🔴 **`Wafw00f`** | **Détection du Pare-Feu Applicatif (WAF)** : Identifie si un WAF (*Cloudflare, ModSecurity, AWS WAF, Imperva*) filtre le trafic.<br>👉 **Placé avant les scans actifs** pour savoir si les requêtes futures risquent d'être bloquées ou altérées. |
| **Étape 4** | 📷 **`Gowitness`** | **Capture d'écran Web Headless** : Rendu visuel automatique de la page d'accueil de la cible. |
| **Étape 5** | 🧩 **`WhatWeb`** | **Empreinte technologique & CMS** : Détection de la pile logicielle (WordPress, Joomla, Nginx, Apache, PHP, en-têtes HTTP de sécurité). |
| **Étape 6** | ⚡ **`Nmap` + `Nuclei` + `Searchsploit`** | **Cartographie réseau & Audit CVE** : Balayage des ports/services (`nmap`), exécution de templates de vulnérabilités (`nuclei`) et corrélation des versions logicielles avec la base d'exploits Exploit-DB (`searchsploit`). |
| **Livrables** | 📄 **`ReportLab` (PDF) + `Python-Docx` (Word)** | **Rapports d'audit & SQLite** : Calcul du score de risque global (0 à 100) et génération immédiate des rapports téléchargeables. |

---

### 🏠 2. Workflow du scan réseau local (`/local`)

Ce workflow est spécialement conçu pour la reconnaissance et l'exploration de machines sur le réseau local (LAN, adresses IP privées, sous-réseaux) :

```
[Étape 1 : Plage LAN] 
   └─► [Étape 2 : Balayage ARP Netdiscover] 
          └─► [Étape 3 : Résolution NetBIOS & mDNS Nbtscan] 
                 └─► [Étape 4 : Cartographie Ports & OS Nmap] 
                        └─► [Étape 5 : Énumération SMB Enum4linux / SMBMap] 
                               └─► [Étape 6 : Corrélation CVE & Rapports]
```

| Étape | Action & Outils | Rôle & Pourquoi ces outils sont utilisés ? |
| :--- | :--- | :--- |
| **Étape 1** | 📡 **Détection d'interface LAN** | **Identification de la plage IP** : Détecte l'interface réseau active et calcule la plage du sous-réseau local (ex. `192.168.1.0/24`). |
| **Étape 2** | 🔍 **`Netdiscover`** | **Découverte d'hôtes par paquets ARP** : Repère toutes les adresses IP et MAC actives du segment LAN.<br>👉 **Pourquoi l'ARP ?** L'ARP fonctionne au niveau de la couche 2 (Liaison). Il permet de détecter les hôtes actifs même si leur pare-feu (ex. Windows Defender) bloque les pings ICMP. |
| **Étape 3** | 📇 **`nbtscan` + `mDNS`** | **Identification NetBIOS & Noms d'hôtes** : Interroge le service NetBIOS (UDP 137) et mDNS pour identifier le nom de machine, le domaine/groupe de travail (*WORKGROUP*) et le constructeur de la carte réseau (OUI MAC). |
| **Étape 4** | ⚡ **`Nmap` (`-sS` / `-sT` / `-sV` / `-O`)** | **Cartographie des ports & services locaux** : Balaye les ports ouverts sur la machine sélectionnée, identifie les bannières de service (ex. *Samba 4.15*, *IIS*, *RDP*, *SSH*) et déduit le système d'exploitation. |
| **Étape 5** | 📁 **`enum4linux` + `smbmap`** | **Énumération approfondie des partages SMB/Samba** *(si ports 139/445 ouverts)* :<br>• `enum4linux` : Extrait les utilisateurs, groupes, politiques de mots de passe et partages NTLM.<br>• `smbmap` : Vérifie visuellement les autorisations d'accès (*READ*, *WRITE*, *NO ACCESS*) sur chaque dossier partagé. |
| **Étape 6** | 🛡️ **`Searchsploit` + `ReportLab` + `Python-Docx`** | **Corrélation CVE & Génération des livrables** : Croise les versions logicielles avec Exploit-DB, calcule le score de risque LAN et génère les rapports d'audit **PDF** et **Word (.docx)**. |

---

### ⚙️ 3. Workflow du scan manuel avancé

Permet aux utilisateurs de configurer et d'expérimenter finement les options avancées de `nmap` :

#### Types de scans pris en charge :
* **TCP SYN Scan (`-sS`)** : furtif ("half-open"), envoie un SYN et attend SYN-ACK sans finaliser la connexion. Nécessite les capacités réseau `cap_net_raw`.
* **TCP Connect Scan (`-sT`)** : établit une connexion TCP complète via l'API `connect()` du système. Utilisable sans privilèges root.
* **UDP Scan (`-sU`)** : balaye les services UDP (DNS, DHCP, SNMP...).
* **Scans furtifs (`-sF`, `-sN`, `-sX`)** : scans FIN, NULL et Xmas tirant parti des spécifications RFC TCP.
* **TCP ACK Scan (`-sA`)** : détermine si les ports sont filtrés par un pare-feu à état (*stateful*).

#### Options d'évasion et timing :
* **Contrôle de vitesse (`-T0` à `-T5`)** : de Paranoid (esquive IDS) à Insane (scans ultra-rapides).
* **Fragmentation de paquets (`-f`)** : scinde les en-têtes TCP en petits paquets pour échapper aux IDS.
* **Leurres IP (`-D RND:5`)** : masque l'IP réelle du scanner au milieu d'IP fictives générées aléatoirement.
* **Traceroute (`--traceroute`)** : cartographie les sauts réseau jusqu'à la cible.

---

### 📊 4. Historique, rapports & base SQLite (`scanner_history.db`)

Tous les scans réalisés (web, local ou manuel) sont enregistrés localement dans une base SQLite.
* Conserve le contexte de chaque scan (cible, type de scan, horodatage, résultats JSON complets).
* Permet la consultation ultérieure, le rechargement interactif des résultats, la suppression d'entrées et le **téléchargement immédiat de rapports PDF ou Word**.

---

## 🔒 Privilèges Linux et sécurité (`setcap`)

Pourquoi les scans `-sS` et `-O` nécessitent-ils des privilèges spéciaux ?
Les paquets réseau sur mesure (Raw Sockets) requièrent traditionnellement d'exécuter la commande en `root`.

Pour éviter la mauvaise pratique de sécurité qui consisterait à exécuter le serveur Flask avec `sudo`, le script d'installation utilise la fonctionnalité **Linux Capabilities** :
```bash
sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f venv/bin/python3)
```
Cela attribue uniquement à l'interpréteur Python du venv les privilèges stricts d'émission de paquets bruts, garantissant une sécurité maximale.

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

# 4. Lancer le serveur avec l'interface ASCII Matrix Green
./run.sh
```

### Méthode 2 : installation manuelle

```bash
# 1. Créer et activer l'environnement virtuel Python
python3 -m venv venv
source venv/bin/activate

# 2. Installer les dépendances Python (Flask, ReportLab, Python-Docx, PySocks)
pip install -r requirements.txt

# 3. Installer les outils système (sur Debian/Ubuntu/Kali)
sudo apt-get update
sudo apt-get install -y nmap exploitdb whatweb wafw00f nikto nuclei wpscan gowitness netdiscover nbtscan enum4linux smbmap policykit-1 libcap2-bin curl

# 4. Attribuer les capacités réseau au Python du venv
sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f venv/bin/python3)

# 5. Lancer l'application
python3 app.py
```

---

## 📁 Architecture du projet

```
matrix-scanner/
├── app.py                 # Backend Flask : routes API REST, export PDF/DOCX, proxy OnionHop, SQLite, CVE
├── install.sh             # Script d'installation automatisé (venv, apt-get, setcap)
├── run.sh                 # Script de lancement interactive (ASCII Art M-SCAN, OnionHop Tor, ports dynamiques)
├── requirements.txt       # Dépendances Python (Flask, reportlab, python-docx, requests, PySocks)
├── scanner_history.db     # Base de données SQLite générée automatiquement
├── README.md              # Documentation officielle du projet
├── templates/             # Templates HTML Jinja2 modularisés
│   ├── base.html          # Layout principal (barre latérale, moniteur IP, horloge, canvas Matrix)
│   ├── home.html          # Vue d'ensemble et accueil du tableau de bord
│   ├── web.html           # Interface dédiée aux audits Web & WAF à distance
│   ├── local.html         # Interface dédiée à la reconnaissance LAN / Réseau local
│   ├── history.html       # Interface de consultation et d'exportation PDF/DOCX
│   ├── settings.html      # État des dépendances et outils système
│   └── partials/          # Composants réutilisables
│       ├── results.html   # Rendu dynamique des résultats, boutons d'export PDF/Word & Chart.js
│       ├── modal.html     # Modales interactives de détails CVE / Exploit-DB
│       ├── manual_settings.html # Formulaire des options avancées Nmap
│       └── banners.html   # Bandeaux d'alerte des dépendances
└── static/
    ├── style.css          # Thème sombre Matrix / Cyberpunk (Glassmorphism & animations)
    ├── script.js          # Logique frontend (moniteur IP temps réel, requêtes API, Chart.js, modales)
    └── matrix.js          # Animation Canvas effet pluie de code Matrix
```

---

## 🛠️ Guide de dépannage (FAQ)

| Symptôme | Cause probable | Solution |
|---|---|---|
| **Erreur "Permission refusée" lors du scan -sS / -O** | Capacités `setcap` non attribuées au venv | Exécuter `sudo setcap cap_net_raw,cap_net_admin+eip venv/bin/python3` ou utiliser le mode `-sT`. |
| **Le bouton "Installer les outils manquants" ne réagit pas** | `policykit-1` manquant sur le système | Installer Polkit via terminal : `sudo apt-get install policykit-1`. |
| **Erreur de téléchargement d'OnionHop** | Absence d'accès réseau ou curl non disponible | Vérifier la connexion Internet et installer `curl` (`sudo apt-get install curl`). |
| **Le port 5000 est déjà occupé** | Un autre service web tourne sur 5000 | `./run.sh` sélectionne automatiquement un port libre `>= 10001`. |
