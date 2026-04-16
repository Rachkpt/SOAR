# 🛡️ SOC Automation Pipeline

> **Full-auto Security Operations Center pipeline** — Splunk → TheHive → Cortex → MISP → VirusTotal → Firewall → Telegram

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://python.org)
[![TheHive](https://img.shields.io/badge/TheHive-5.x-yellow)](https://thehive-project.org)
[![Cortex](https://img.shields.io/badge/Cortex-3.x-orange)](https://github.com/TheHive-Project/Cortex)
[![MISP](https://img.shields.io/badge/MISP-2.4%2B-red)](https://www.misp-project.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## 📋 Table des Matières

- [Vue d'ensemble](#-vue-densemble)
- [Architecture](#-architecture)
- [Prérequis](#-prérequis)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Démarrage](#-démarrage)
- [Flux automatique](#-flux-automatique)
- [Endpoints Service A](#-endpoints-service-a)
- [Commandes CLI](#-commandes-cli)
- [Notifications Telegram](#-notifications-telegram)
- [Structure des fichiers](#-structure-des-fichiers)
- [Dépannage](#-dépannage)
- [Contribuer](#-contribuer)

---

## 🔭 Vue d'ensemble

Ce projet est un pipeline SOC complet qui automatise la réponse aux incidents de sécurité. Dès qu'une alerte arrive depuis **Splunk**, le pipeline :

1. Crée une **alerte dans TheHive**
2. Promeut l'alerte en **cas d'investigation**
3. Ajoute les **observables** (IPs, hashes, domaines) au cas
4. Lance les **analyseurs Cortex** automatiquement via TheHive
5. Vérifie les IoCs sur **VirusTotal** et **MISP**
6. **Bloque les IPs** malveillantes sur le firewall (Windows/Linux)
7. Envoie des **notifications Telegram** à chaque étape

Tout est 100% automatique, sans intervention humaine.

---

## 🏗️ Architecture

```
┌─────────────┐     webhook      ┌──────────────┐
│   Splunk    │ ────────────────▶│  Service A   │
│  (SIEM)     │   POST /alert    │  Flask :5000 │
└─────────────┘                  └──────┬───────┘
                                        │ Crée alerte
                                        ▼
                                 ┌──────────────┐
                                 │   TheHive    │◀────────────────┐
                                 │  :9000       │                 │
                                 └──────┬───────┘                 │
                                        │ poll toutes les 20s     │
                                        ▼                         │
                                 ┌──────────────┐    résultats    │
                                 │  Service B   │─────────────────┘
                                 │  (Responder) │
                                 └──────┬───────┘
                        ┌───────────────┼───────────────┐
                        ▼               ▼               ▼
                 ┌────────────┐  ┌────────────┐  ┌────────────┐
                 │   Cortex   │  │    MISP    │  │ VirusTotal │
                 │   :9001    │  │   :443     │  │   (API)    │
                 └────────────┘  └────────────┘  └────────────┘
                        │
                        ▼
                 ┌────────────┐        ┌────────────┐
                 │  Firewall  │        │  Telegram  │
                 │ (netsh/    │        │    Bot     │
                 │  iptables) │        └────────────┘
                 └────────────┘
```

<img width="7019" height="4963" alt="topo" src="https://github.com/user-attachments/assets/2a2217a4-1cdf-4592-83ac-157d1a0552c7" />



### Composants

| Composant | Rôle | Port |
|-----------|------|------|
| **Service A** | Webhook Flask — reçoit alertes Splunk, les envoie à TheHive | 5000 |
| **Service B** | Responder — poll TheHive, orchestre Cortex/MISP/VT/Firewall | — |
| **TheHive** | Gestion des alertes et cas d'investigation | 9000 |
| **Cortex** | Moteur d'analyse automatique (AbuseIPDB, VT, etc.) | 9001 |
| **MISP** | Threat Intelligence Platform — lookup et partage d'IoCs | 443 |
| **VirusTotal** | Réputation IPs, hashes, domaines via API | — |

---

## ✅ Prérequis

### Système

| Système | Supporté |
|---------|----------|
| Ubuntu 20.04 / 22.04 / 24.04 | ✅ Recommandé |
| Debian 11 / 12 | ✅ |
| Windows 10 / 11 (PowerShell Admin) | ✅ |
| CentOS / RHEL 8+ | ✅ |
| macOS 12+ | ✅ (sans blocage firewall) |

### Versions logicielles

```
Python     >= 3.8
TheHive    >= 5.0  (testé sur 5.2.x)
Cortex     >= 3.0
MISP       >= 2.4
Splunk     >= 8.0  (ou tout système capable d'envoyer des webhooks HTTP)
```

### Clés API nécessaires

- **TheHive** : clé API utilisateur (profil → API Key)
- **Cortex** : clé API utilisateur
- **MISP** : clé API utilisateur (Administration → Auth Keys)
- **VirusTotal** : clé API gratuite sur [virustotal.com](https://www.virustotal.com/gui/join-us)
- **Telegram** : token bot ([BotFather](https://t.me/BotFather)) + Chat ID

---

## 📦 Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/TON-USERNAME/soc-automation-pipeline.git
cd soc-automation-pipeline
```

### 2. Créer un environnement virtuel (recommandé)

```bash
# Linux / macOS
python3 -m venv venv
source venv/bin/activate

# Windows PowerShell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Installer les dépendances

```bash
pip install -r requirements.txt
```

Ou via le lanceur intégré :

```bash
python start.py install
```

### 4. Vérifier l'installation

```bash
python start.py status
```

---

## ⚙️ Configuration

### Copier le fichier de configuration

```bash
cp env.example .env
```

### Éditer `.env`

```ini
# ─── TheHive ──────────────────────────────────────────────────────
THEHIVE_URL=http://VOTRE_IP:9000
THEHIVE_APIKEY=votre_cle_api_thehive

# ─── Cortex ───────────────────────────────────────────────────────
CORTEX_URL=http://VOTRE_IP:9001
CORTEX_APIKEY=votre_cle_api_cortex

# ─── MISP ─────────────────────────────────────────────────────────
MISP_URL=https://VOTRE_IP_MISP
MISP_APIKEY=votre_cle_api_misp
MISP_ENABLED=true

# ─── VirusTotal ───────────────────────────────────────────────────
VT_ENABLED=true
VT_APIKEY=votre_cle_api_virustotal
VT_TIMEOUT=15
VT_MIN_DETECTIONS=2

# ─── Service A — Webhook ──────────────────────────────────────────
LISTEN_HOST=0.0.0.0
LISTEN_PORT=5000
RATE_LIMIT_SEC=10

# ─── Service B — Responder ────────────────────────────────────────
POLL_INTERVAL=20
STATE_FILE=responder_state.json
BLACKLIST_FILE=ip_blacklist.txt

# ─── Réponse active ───────────────────────────────────────────────
# Mettre true pour bloquer vraiment les IPs (nécessite admin/root)
ACTIVE_RESPONSE=false
BLOCK_DURATION_MIN=10
BLOCK_ALL_IPS=true
BLOCK_ON_BRUTEFORCE=true

# Timeout attente résultats Cortex (secondes)
CORTEX_JOB_TIMEOUT=180

# ─── Telegram ─────────────────────────────────────────────────────
TELEGRAM_ENABLED=true
TELEGRAM_TOKEN=votre_token_bot
TELEGRAM_CHAT_ID=votre_chat_id

# ─── Gmail (optionnel) ────────────────────────────────────────────
GMAIL_ENABLED=false
GMAIL_USER=
GMAIL_PASS=
GMAIL_TO=

# ─── Logs ─────────────────────────────────────────────────────────
LOG_FILE=service_a.log
LOG_FILE_B=service_b.log
LOG_LEVEL=INFO
NOTIFY_MIN_SEV=1
```

> ⚠️ **Important** : Ne jamais mettre de commentaires inline sur les valeurs !
> ```ini
> BLOCK_DURATION_MIN=10       ← INCORRECT (cause une erreur)
> BLOCK_DURATION_MIN=10       # Correct (commentaire sur ligne séparée)
> ```

### Obtenir le Chat ID Telegram

```bash
# Après avoir créé ton bot avec BotFather et envoyé un message :
curl "https://api.telegram.org/botVOTRE_TOKEN/getUpdates"
# Le chat_id est dans: result[0].message.chat.id
```

### Configurer le webhook Splunk

Dans Splunk, créer une **Alert Action** de type webhook :

```
URL       : http://VOTRE_IP_PIPELINE:5000/alert
Method    : POST
Content   : application/json
Payload   :
{
  "result": {
    "src_ip":   "$result.src_ip$",
    "user":     "$result.user$",
    "host":     "$result.host$",
    "count":    "$result.count$",
    "severity": "high",
    "source":   "$result.source$"
  },
  "search_name": "$name$",
  "owner":       "$owner$"
}
```

---

## 🚀 Démarrage

### Lancer les deux services ensemble

```bash
# Linux / macOS
python start.py both

# Windows (PowerShell en Administrateur pour le vrai blocage)
python start.py both
```

### Lancer séparément

```bash
# Service A uniquement (webhook Splunk)
python start.py a

# Service B uniquement (responder)
python start.py b
```

### Activer le vrai blocage firewall

```bash
# Dans .env :
ACTIVE_RESPONSE=true

# Linux — nécessite root :
sudo python3 start.py both

# Windows — nécessite Administrateur :
# Clic droit sur PowerShell → "Exécuter en tant qu'administrateur"
python start.py both
```

---

## 🔄 Flux Automatique

Une fois lancé, voici ce qui se passe pour chaque alerte Splunk :

```
1. Splunk envoie un webhook POST /alert
        ↓
2. Service A crée une Alerte dans TheHive
   → Notification Telegram : "Alerte créée"
        ↓
3. Service B détecte l'alerte (poll toutes les 20s)
        ↓
4. Promotion Alerte → Cas TheHive
   → Notification Telegram : "Cas #N créé"
        ↓
5. Pour chaque Observable (IP / Hash / Domaine) :
   ├── a. Ajout de l'Observable au Cas TheHive
   ├── b. VirusTotal : analyse + commentaire dans le cas
   │      → Notification Telegram avec verdict
   ├── c. MISP : lookup IoC + commentaire si hit
   │      → Notification Telegram si trouvé
   ├── d. Blocage IP firewall si brute force / malveillant
   │      → Notification Telegram : "IP bloquée Xmin"
   └── e. Cortex : lancement analyseurs via TheHive
          → Résultats en commentaires dans le cas
          → Notification Telegram par analyseur
        ↓
6. Rapport récapitulatif ajouté dans le cas TheHive
        ↓
7. Déblocage automatique après X minutes (timer)
   → Notification Telegram : "IP débloquée"
```

---

## 🌐 Endpoints Service A

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `POST` | `/alert` | Webhook principal — reçoit les alertes Splunk |
| `GET` | `/health` | Vérification de l'état du service |
| `GET` | `/test` | Envoie une alerte de test vers TheHive |
| `GET` | `/telegram-test` | Teste la notification Telegram |
| `GET` | `/vt-test` | Teste la connexion VirusTotal |
| `GET` | `/debug` | Affiche les derniers payloads reçus |
| `GET` | `/stats` | Statistiques du service |

### Test du webhook

```bash
curl -X POST http://localhost:5000/alert \
  -H "Content-Type: application/json" \
  -d '{
    "result": {
      "src_ip": "1.2.3.4",
      "user": "root",
      "host": "server-01",
      "count": "5",
      "severity": "high",
      "source": "/var/log/auth.log"
    },
    "search_name": "Brute Force SSH"
  }'
```

---

## 🖥️ Commandes CLI

```bash
# Voir les IPs actuellement bloquées
python start.py list

# Débloquer une IP manuellement
python start.py unblock 1.2.3.4

# État complet du système
python start.py status

# Tester l'intégration complète
python start.py test

# Tester Telegram
python start.py telegram
```

---

## 📱 Notifications Telegram

Le bot envoie des notifications pour chaque événement :

| Événement | Exemple |
|-----------|---------|
| 🚀 Démarrage | `SOC Pipeline v10.0.0 démarré` |
| 📁 Cas créé | `Cas #42 créé — [SPLUNK] alert` |
| 🦠 VirusTotal | `🔴 MALVEILLANT 15/72 rep=-85` |
| 🌐 MISP Hit | `IoC trouvé dans MISP` |
| 🚫 IP bloquée | `10.x.x.x bloquée 10min — brute force` |
| 🔬 Cortex | `AbuseIPDB: malicious — score 95` |
| ✅ IP débloquée | `10.x.x.x débloquée — timer expiré` |

### Configurer le bot Telegram

1. Ouvrir [@BotFather](https://t.me/BotFather) sur Telegram
2. `/newbot` → donner un nom → récupérer le **token**
3. Envoyer un message à ton bot
4. Récupérer le **Chat ID** :
   ```bash
   curl "https://api.telegram.org/bot<TOKEN>/getUpdates"
   ```
5. Mettre `TELEGRAM_ENABLED=true` dans `.env`

---

## 📁 Structure des Fichiers

```
soc-automation-pipeline/
│
├── start.py                      # Lanceur universel (Windows/Linux/macOS)
├── service_splunk_to_thehive.py  # Service A — Webhook Flask
├── service_thehive_responder.py  # Service B — Responder Full Auto
│
├── .env                          # Configuration (à créer depuis env.example)
├── env.example                   # Template de configuration
├── requirements.txt              # Dépendances Python
│
├── responder_state.json          # État des alertes traitées (auto-généré)
├── ip_blacklist.json             # Blacklist IPs avec timers (auto-généré)
├── ip_blacklist.txt              # Blacklist lisible (auto-généré)
│
├── service_a.log                 # Logs Service A (auto-généré)
├── service_b.log                 # Logs Service B (auto-généré)
│
├── test_service_a.py             # Tests d'intégration
└── README.md                     # Ce fichier
```

---

## 🔧 Installation de TheHive + Cortex + MISP

### TheHive & Cortex (Ubuntu 22.04)

```bash
# Dépendances Java
sudo apt install -y openjdk-11-jre-headless

# Clé GPG TheHive Project
wget -O- https://archives.strangebee.com/keys/strangebee.gpg | \
  sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg

# Dépôt TheHive
echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.x main' | \
  sudo tee /etc/apt/sources.list.d/strangebee.list

sudo apt update
sudo apt install -y thehive cortex

# Démarrer les services
sudo systemctl enable thehive cortex
sudo systemctl start thehive cortex

# Vérifier
sudo systemctl status thehive
sudo systemctl status cortex
```

### MISP (Ubuntu 22.04)

```bash
# Installation automatique via script officiel
wget -O /tmp/INSTALL.sh https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh
bash /tmp/INSTALL.sh

# Ou via Docker
git clone https://github.com/MISP/misp-docker
cd misp-docker
cp template.env .env
docker compose up -d
```

### Configurer Cortex avec TheHive

1. Ouvrir Cortex : `http://VOTRE_IP:9001`
2. Créer un compte admin
3. **Organizations** → créer une org
4. **Users** → créer un utilisateur API → copier la clé
5. **Analyzers** → activer AbuseIPDB, VirusTotal, MaxMind, etc.
6. Dans TheHive → **Organisation** → **Connectors** → ajouter Cortex

### Configurer les analyseurs Cortex

```bash
# Sur le serveur Cortex, s'assurer que python3 est disponible
which python3
python3 --version

# Si absent
sudo apt install python3 python3-pip -y

# Pour AbuseIPDB, configurer la clé API dans Cortex :
# Analyzers → AbuseIPDB → Configure → api_key: VOTRE_CLE_ABUSEIPDB
```

> 📝 Clé AbuseIPDB gratuite sur [abuseipdb.com](https://www.abuseipdb.com/register)

---

## 🐛 Dépannage

### Service B ne crée pas de cas

```bash
# Vérifier que Service B tourne
Get-Process python  # Windows
ps aux | grep python  # Linux

# Voir les logs Service B
Get-Content service_b.log -Tail 50  # Windows
tail -50 service_b.log              # Linux
```

### Cortex — `python3: No such file or directory`

```bash
# Sur le serveur Cortex (Ubuntu/Debian)
sudo apt install python3 python3-pip -y
sudo ln -sf /usr/bin/python3 /usr/local/bin/python3
sudo systemctl restart cortex
```

### Blocage IP ne fonctionne pas (Windows)

```
→ Relancer PowerShell en tant qu'Administrateur
→ Vérifier : ACTIVE_RESPONSE=true dans .env
→ Tester manuellement :
   netsh advfirewall firewall add rule name="TEST" dir=in action=block remoteip=1.2.3.4
```

### Blocage IP ne fonctionne pas (Linux)

```bash
# Vérifier root
sudo python3 start.py both

# Vérifier iptables
sudo apt install iptables -y
sudo iptables -L INPUT | head -20
```

### MISP timeout

```bash
# Vérifier la connexion
curl -k https://VOTRE_IP_MISP/users/login

# Vérifier le service
sudo systemctl status misp-workers
sudo systemctl status apache2
```

### `.env` — erreur `invalid literal for int`

```ini
# ❌ INCORRECT — commentaire inline
BLOCK_DURATION_MIN=10       ← durée en minutes

# ✅ CORRECT — commentaire sur ligne séparée
# durée en minutes
BLOCK_DURATION_MIN=10
```

### Voir les alertes en temps réel

```bash
# Suivre les deux logs en même temps
# Linux
tail -f service_a.log service_b.log

# Windows PowerShell
Get-Content service_a.log, service_b.log -Wait -Tail 20
```

---

## 📊 Variables d'environnement — Référence complète

| Variable | Défaut | Description |
|----------|--------|-------------|
| `THEHIVE_URL` | — | URL de TheHive (ex: `http://192.168.1.10:9000`) |
| `THEHIVE_APIKEY` | — | Clé API TheHive |
| `CORTEX_URL` | — | URL de Cortex (ex: `http://192.168.1.10:9001`) |
| `CORTEX_APIKEY` | — | Clé API Cortex |
| `MISP_URL` | — | URL de MISP (ex: `https://192.168.1.11`) |
| `MISP_APIKEY` | — | Clé API MISP |
| `MISP_ENABLED` | `true` | Activer/désactiver MISP |
| `VT_ENABLED` | `true` | Activer VirusTotal |
| `VT_APIKEY` | — | Clé API VirusTotal |
| `VT_TIMEOUT` | `15` | Timeout requêtes VT (secondes) |
| `VT_MIN_DETECTIONS` | `2` | Seuil détections pour verdict malveillant |
| `LISTEN_HOST` | `0.0.0.0` | Interface d'écoute Service A |
| `LISTEN_PORT` | `5000` | Port webhook Service A |
| `RATE_LIMIT_SEC` | `10` | Délai anti-doublon entre alertes identiques |
| `POLL_INTERVAL` | `20` | Fréquence poll TheHive (secondes) |
| `ACTIVE_RESPONSE` | `false` | `true` = blocage firewall réel |
| `BLOCK_DURATION_MIN` | `10` | Durée de blocage IP (minutes) |
| `BLOCK_ON_BRUTEFORCE` | `true` | Bloquer IPs brute force automatiquement |
| `CORTEX_JOB_TIMEOUT` | `180` | Attente max résultats Cortex (secondes) |
| `TELEGRAM_ENABLED` | `false` | Activer notifications Telegram |
| `TELEGRAM_TOKEN` | — | Token du bot Telegram |
| `TELEGRAM_CHAT_ID` | — | Chat ID Telegram |
| `GMAIL_ENABLED` | `false` | Activer notifications Gmail |
| `LOG_FILE` | `service_a.log` | Fichier log Service A |
| `LOG_FILE_B` | `service_b.log` | Fichier log Service B |
| `LOG_LEVEL` | `INFO` | Niveau de log (`DEBUG`, `INFO`, `WARNING`) |

---

## 🔐 Sécurité

- Ne jamais commiter le fichier `.env` dans Git
- Le fichier `.gitignore` exclut automatiquement `.env`, `*.log`, `*.json`
- Utiliser des clés API avec les permissions minimales nécessaires
- Pour la production, mettre le webhook Service A derrière un reverse proxy (nginx) avec HTTPS
- MISP : utiliser `verify=True` en production avec un certificat valide

### Exemple `.gitignore`

```gitignore
.env
*.log
ip_blacklist.*
responder_state.json
__pycache__/
venv/
*.pyc
```

---

## 🤝 Contribuer

Les contributions sont les bienvenues !

1. Fork le projet
2. Créer une branche : `git checkout -b feature/ma-fonctionnalite`
3. Commiter : `git commit -m 'feat: ajouter ma fonctionnalité'`
4. Pousser : `git push origin feature/ma-fonctionnalite`
5. Ouvrir une Pull Request

### Idées de contributions

- [ ] Support Elasticsearch/OpenSearch
- [ ] Interface web de monitoring
- [ ] Support webhooks PagerDuty / Slack
- [ ] Tests unitaires complets
- [ ] Docker Compose pour déploiement tout-en-un
- [ ] Support TheHive v4 (rétrocompatibilité)

---

## 📄 Licence

MIT License — voir [LICENSE](LICENSE)

---

## 🙏 Technologies utilisées

| Technologie | Usage |
|-------------|-------|
| Tuto Installation TheHive Crortex MISP  | ---> https://youtu.be/Vr4flc55S5c?si=6NNDCI1J6VGavFz8
| intégrer Cortex et MISP à TheHive dans votre SOC |--->  https://youtu.be/ovUuNQsW_FQ?si=MKPUYpWmnugg-gpT
| [TheHive](https://thehive-project.org) | Gestion des cas de sécurité |
| [Cortex](https://github.com/TheHive-Project/Cortex) | Analyse automatique des observables |
| [MISP](https://www.misp-project.org) | Threat Intelligence |
| [VirusTotal](https://www.virustotal.com) | Réputation fichiers/IPs/domaines |
| [Flask](https://flask.palletsprojects.com) | Webhook HTTP Service A |
| [thehive4py](https://github.com/TheHive-Project/TheHive4py) | Client Python TheHive |
| [Splunk](https://www.splunk.com) | Source d'alertes SIEM |

---

<div align="center">

**SOC Automation Pipeline** — Projet académique / Lab SOC personnel

*Construit pour automatiser la réponse aux incidents de sécurité*

</div>
