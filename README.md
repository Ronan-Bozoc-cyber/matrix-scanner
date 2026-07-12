# 🟢 Matrix Scanner — Dashboard pédagogique de reconnaissance réseau et de CVE

Application web locale destinée aux élèves ingénieurs pour apprendre, de manière
visuelle et guidée, l'utilisation de `nmap` et la recherche de vulnérabilités connues
via `searchsploit` (base Exploit-DB).

## ⚠️ AVERTISSEMENT LÉGAL

**N'utilisez cet outil que sur des machines que vous possédez ou pour lesquelles vous
disposez d'une autorisation écrite explicite** (VM de lab type Metasploitable, réseau
de TP isolé, environnement CTF...). Scanner un système tiers sans autorisation est
une infraction pénale dans la plupart des pays (en France : art. 323-1 du Code pénal).

## Prérequis système

- Linux (Debian, Ubuntu ou Kali)
- Python 3.9+
- `policykit-1` (fournit `pkexec`, généralement préinstallé sur les environnements de bureau)
- Un accès `apt` (pour l'installation automatique de `nmap` et `exploitdb` si absents)

L'application détecte elle-même si `nmap` et `searchsploit` sont installés et propose
un bouton d'installation graphique (authentification via la pop-up système Polkit).

## Installation automatisée (recommandée)

Un script `install.sh` automatise l'intégralité de la procédure : création du venv,
installation de Flask, installation des paquets système manquants (`nmap`,
`exploitdb`, `policykit-1`) via `apt`, et attribution des capacités réseau nécessaires
aux scans `-sS`/`-O` sans avoir à lancer le serveur en root.

```bash
cd matrix-scanner
chmod +x install.sh run.sh
./install.sh      # demande le mot de passe root UNIQUEMENT pour apt et setcap
./run.sh           # lance le serveur (jamais avec sudo)
```

Le script est idempotent : vous pouvez le relancer sans risque, il détecte ce qui
est déjà installé et ne réinstalle que ce qui manque.

## Installation manuelle (alternative)

```bash
# 1. Se placer dans le dossier du projet
cd matrix-scanner

# 2. Créer un environnement virtuel (recommandé)
python3 -m venv venv
source venv/bin/activate

# 3. Installer les dépendances Python
pip install -r requirements.txt
```

## Lancement du serveur de développement

```bash
./run.sh
# ou manuellement :
source venv/bin/activate && python3 app.py
```

Le serveur démarre sur **http://127.0.0.1:5000** (accessible uniquement depuis la
machine locale). Ouvrez cette adresse dans votre navigateur.

## Pourquoi certains scans nécessitent-ils les droits root ?

Les scans **SYN (-sS)** et la **détection d'OS (-O)** de nmap nécessitent la capacité
de construire des paquets réseau bruts (raw sockets), ce qui requiert des privilèges
élevés. Deux options pour les élèves :

1. **`install.sh` attribue automatiquement** les capacités réseau ciblées à
   l'interpréteur Python du venv (plus sûr que de lancer tout le serveur en root) :
   ```bash
   sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f venv/bin/python3)
   ```
   Cette étape est déjà incluse dans `install.sh` — aucune action manuelle requise.
2. **Utiliser le scan Connect (-sT)**, qui fonctionne sans privilèges particuliers
   (option disponible directement dans l'interface), si `setcap` n'est pas disponible
   sur votre système.

## Structure du projet

```
matrix-scanner/
├── app.py                 # Backend Flask : dépendances, scan, parsing XML, CVE
├── install.sh              # Installation automatisée (venv, apt, setcap)
├── run.sh                   # Lancement du serveur (jamais en root)
├── requirements.txt
├── README.md
├── templates/
│   └── index.html         # Interface (formulaires + zone de résultats)
└── static/
    ├── style.css           # Thème "Matrix"
    └── script.js            # Logique frontend (canvas, appels API, Chart.js)
```

## Fonctionnement pédagogique

- Chaque option graphique (type de scan, ports, intensité, cases à cocher) est
  accompagnée d'un encart expliquant le flag `nmap` réellement utilisé sous le capot.
- La commande exacte exécutée est affichée à l'écran avant/pendant le scan
  (`command-preview`), pour que l'élève fasse le lien entre l'interface graphique et
  la ligne de commande.
- Les résultats sont parsés depuis le XML natif de nmap (`-oX -`) et présentés sous
  forme de tableaux + graphique Chart.js (nombre de ports ouverts par service).
- Pour chaque service détecté avec sa version (`-sV`), un lien "🔍 Chercher CVE"
  interroge la base Exploit-DB locale via `searchsploit --json`.

## Dépannage

| Symptôme | Cause probable | Solution |
|---|---|---|
| Le bouton d'installation ne fait rien | `policykit-1` non installé | `sudo apt-get install policykit-1` puis relancer |
| "Permission refusée" pendant le scan | -sS/-O sans privilèges | Voir section "droits root" ci-dessus, ou utiliser -sT |
| Pop-up d'authentification fermée | Annulation volontaire | Relancer le bouton d'installation |
| Le scan ne se termine jamais | Cible injoignable / pare-feu | Vérifier la connectivité (`ping`), réduire la portée du scan |
