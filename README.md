# 🟢 Matrix Scanner — Plateforme Pédagogique d'Audit Réseau, de Sécurité Web & de CVE

**Matrix Scanner** est un tableau de bord web interactif, visuel et pédagogique conçu pour les élèves ingénieurs, les professionnels et les passionnés de cybersécurité. 

Il permet d'apprendre et d'expérimenter concrètement la reconnaissance réseau avec `nmap`, l'analyse d'applications web (en-têtes de sécurité, WAF, empreintes) et la recherche de vulnérabilités réelles (CVE) via la base locale Exploit-DB (`searchsploit`).

---

## ⚠️ AVERTISSEMENT LÉGAL ET ÉTHIQUE

**L'utilisation de cet outil doit se faire exclusivement sur des systèmes dont vous êtes propriétaire ou pour lesquels vous possédez une autorisation écrite explicite.**

- **Cadre légal** : En France, l'accès ou le maintien frauduleux dans un système de traitement automatisé de données est puni par l'article 323-1 et suivants du Code pénal.
- **Usage recommandé** : Environnements de TP isolés, machines virtuelles de laboratoire (*Metasploitable, VulnHub, TryHackMe*), ou missions de test d'intrusion dûment autorisées.

---

## 🎓 Objectifs Pédagogiques

Matrix Scanner n'est pas une "boîte noire" : il est spécialement conçu pour transmettre les concepts fondamentaux de la sécurité offensive et défensive :

1. **Faire le lien UI ➔ CLI** : Chaque option sélectionnée dans l'interface reconstruit et affiche en temps réel la commande `nmap` exacte qui est exécutée (`Command Preview`).
2. **Comprendre la mécanique des paquets réseau** : Différencier un scan TCP SYN (`-sS`) discret d'un scan TCP Connect (`-sT`) ou d'un scan furtif FIN/NULL/Xmas, et comprendre l'exigence de privilèges (*raw sockets*).
3. **Évaluer la sécurité d'une application Web** : Détecter la présence d'un pare-feu applicatif (WAF) et vérifier l'absence d'en-têtes HTTP de protection (*HSTS, CSP, X-Frame-Options, etc.*).
4. **Pratiquer la gestion des vulnérabilités** : Associer chaque service et version logicielle détectés (`-sV`) à des failles réelles répertoriées dans la base de données Exploit-DB.

---

## ⚡ Fonctionnalités & Workflows Détaillés

### 🤖 1. Workflow Autopilote & Scan Intelligent (`/web` & `/local`)

Le mode Autopilote enchaîne automatiquement 8 étapes d'analyse :

```
[1. Saisie IP/Domaine] ➔ [2. Test Ping ICMP] ➔ [3. Scan Nmap -sV -O] ➔ [4. Audit Web & WAF]
   ➔ [5. Capture d'écran Web] ➔ [6. Corrélation CVE Searchsploit] ➔ [7. Score de Risque] ➔ [8. Archivage SQLite]
```

- **Étape 1 : Normalisation de la cible** — Extrait et valide l'IP ou le domaine pour éliminer tout risque d'injection.
- **Étape 2 : Test de réactivité** — Envoi de requêtes ICMP/Ping pour valider la connectivité réseau de l'hôte.
- **Étape 3 : Scan Nmap approfondi** — Détection des ports ouverts, résolution de versions des services (`-sV`) et empreinte d'OS (`-O`).
- **Étape 4 : Audit Web & En-têtes HTTP** — Si des ports Web (80, 443, 8080...) sont ouverts, détection des technologies (`whatweb`), du WAF et audit des en-têtes de sécurité HTTP.
- **Étape 5 : Capture d'écran headless** — Prise de vue automatique des applications web découvertes pour un aperçu visuel rapide.
- **Étape 6 : Corrélation CVE locale** — Interrogation de la base locale Exploit-DB (`searchsploit --json`) sur la base des couples `(service, version)`.
- **Étape 7 : Calcul du Score de Risque (0 à 100)** — Algorithme pondérant l'exposition des ports sensibles, la gravité des CVE et le niveau de protection HTTP.
- **Étape 8 : Archivage & Rendu** — Sauvegarde dans la base SQLite locale et affichage des résultats sous forme de graphiques interactifs (Chart.js).

---

### ⚙️ 2. Workflow du Scan Manuel Avancé

Permet d'expérimenter finement les options avancées de `nmap` :

#### Types de Scans pris en charge :
- **TCP SYN Scan (`-sS`)** : Furtif ("half-open"), envoie un SYN et attend SYN-ACK sans finaliser la connexion. Nécessite les capacités réseau `cap_net_raw`.
- **TCP Connect Scan (`-sT`)** : Établit une connexion TCP complète via l'API `connect()` du système. Utilisable sans privilèges root.
- **UDP Scan (`-sU`)** : Balaye les services UDP (DNS, DHCP, SNMP...). Plus lent et sujet aux pertes de paquets.
- **Scans Furtifs (`-sF`, `-sN`, `-sX`)** : Scans FIN, NULL et Xmas tirant parti des spécifications RFC TCP pour contourner certains filtres stateless.
- **TCP ACK Scan (`-sA`)** : Permet de déterminer si les ports sont filtrés par un pare-feu à état (*stateful*).

#### Options d'Évasion & Timing :
- **Contrôle de vitesse (`-T0` à `-T5`)** : De Paranoid (esquive IDS) à Insane (scans ultra-rapides sur réseaux locaux fiables).
- **Fragmentation de paquets (`-f`)** : Scinde les en-têtes TCP en petits paquets pour échapper à la détection de certains IDS.
- **Leurres IP (`-D RND:5`)** : Masque l'IP réelle du scanner au milieu d'IP fictives générées aléatoirement.
- **Traceroute (`--traceroute`)** : Cartographie les sauts réseau (routeurs/pare-feux) jusqu'à la cible.

---

### 📊 3. Historique & Base de données SQLite (`scanner_history.db`)

Tous les scans réalisés sont enregistrés localement dans une base SQLite.
- Conserve le contexte de chaque scan (cible, type de scan, horodatage, résultats JSON complets).
- Permet la consultation ultérieure, le rechargement interactif des rapports et la suppression d'entrées d'historique.

---

### 🛠️ 4. Gestionnaire de Dépendances & Sécurité Polkit

Matrix Scanner requiert des outils système sous-jacents (`nmap`, `exploitdb`, `whatweb`, `policykit-1`).
- Au démarrage, l'application vérifie automatiquement la présence de chaque binaire.
- Si un outil manque, un bouton d'installation graphique s'affiche.
- L'installation s'appuie sur `pkexec` (Polkit) : l'utilisateur saisit son mot de passe dans la pop-up système native. **Aucun identifiant ne transite dans le code Python**.

---

## 🔒 Privilèges Linux & Sécurité (`setcap`)

Pourquoi les scans `-sS` et `-O` nécessitent-ils des privilèges spéciaux ?
Les paquets réseau sur-mesure (Raw Sockets) requièrent traditionnellement d'exécuter la commande en `root`. 

Pour éviter la mauvaise pratique de sécurité qui consisterait à exécuter l'ensemble du serveur Flask avec `sudo`, le script d'installation utilise la fonctionnalité **Linux Capabilities** :
```bash
sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f venv/bin/python3)
```
Cela attribue uniquement à l'interpréteur Python du venv les privilèges stricts d'émission de paquets bruts, garantissant une étanchéité et une sécurité maximales.

---

## 🚀 Guide d'Installation & Lancement Pas à Pas

### Méthode 1 : Installation automatisée (Recommandée)

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

### Méthode 2 : Installation manuelle

```bash
# 1. Créer et activer l'environnement virtuel Python
python3 -m venv venv
source venv/bin/activate

# 2. Installer les dépendances Python
pip install -r requirements.txt

# 3. Installer les outils système (sur Debian/Ubuntu/Kali)
sudo apt-get update
sudo apt-get install -y nmap exploitdb whatweb policykit-1 libcap2-bin

# 4. Attribuer les capacités réseau au Python du venv
sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f venv/bin/python3)

# 5. Lancer l'application
python3 app.py
```

### Accès à l'application
Une fois démarré, ouvrez votre navigateur web à l'adresse : **`http://127.0.0.1:5000`**

---

## 📁 Architecture du Projet

```
matrix-scanner/
├── app.py                 # Backend Flask : Routes API REST, orchestration subprocess, SQLite, CVE
├── install.sh             # Script d'installation automatisé (venv, apt-get, setcap)
├── run.sh                 # Script de lancement du serveur local
├── requirements.txt       # Dépendances Python (Flask)
├── scanner_history.db     # Base de données SQLite générée automatiquement
├── README.md              # Documentation pédagogique du projet
├── templates/             # Templates HTML Jinja2 modularisés
│   ├── base.html          # Layout principal (barre de nav, canvas Matrix, scripts)
│   ├── home.html          # Vue d'ensemble et accueil du tableau de bord
│   ├── web.html           # Interface dédiée aux audits Web & WAF
│   ├── local.html         # Interface dédiée à la reconnaissance LAN / Réseau
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

## 🛠️ Guide de Dépannage (FAQ)

| Symptôme | Cause probable | Solution |
|---|---|---|
| **Erreur "Permission refusée" lors du scan -sS / -O** | Capacités `setcap` non attribuées au venv | Exécuter `sudo setcap cap_net_raw,cap_net_admin+eip venv/bin/python3` ou utiliser le mode `-sT`. |
| **Le bouton "Installer les dépendances" ne réagit pas** | `policykit-1` manquant sur le système | Installer Polkit via terminal : `sudo apt-get install policykit-1`. |
| **Erreur de création de venv sous Debian/Kali** | Module `ensurepip` absent | Exécuter `sudo apt-get install python3-full` puis relancer `./install.sh`. |
| **Le scan est très long ou ne répond pas** | Pare-feu bloquant ou hôte injoignable | Réduire le nombre de ports, vérifier la réactivité avec un ping, ou utiliser le timing `-T3`. |
