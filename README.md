# 🛡️ SOC Automation Pipeline

<div align="center">

**Pipeline de réponse aux incidents 100% automatique**
Splunk → TheHive → Cortex → MISP → VirusTotal → Firewall → Telegram

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![TheHive](https://img.shields.io/badge/TheHive-5.2.x-F5A800?style=for-the-badge)](https://thehive-project.org)
[![Cortex](https://img.shields.io/badge/Cortex-3.x-FF6B35?style=for-the-badge)](https://github.com/TheHive-Project/Cortex)
[![MISP](https://img.shields.io/badge/MISP-2.4%2B-CC0000?style=for-the-badge)](https://www.misp-project.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docs.docker.com/compose)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)](LICENSE)

</div>

---

## 📖 Table des Matières

- [Vue d'ensemble](#-vue-densemble)
- [Architecture](#-architecture)
- [Prérequis](#-prérequis)
- [Installation de l'infrastructure](#-installation-de-linfrastructure-docker)
- [Configuration TheHive + Cortex + MISP](#-configuration-thehive--cortex--misp)
- [Configuration Suricata IDS](#-configuration-suricata-ids)
- [Installation du Pipeline SOC](#-installation-du-pipeline-soc)
- [Fichier de configuration .env](#-fichier-de-configuration-env)
- [Configuration Splunk](#-configuration-splunk)
- [Démarrage](#-démarrage)
- [Flux automatique complet](#-flux-automatique-complet)
- [Endpoints Service A](#-endpoints-service-a)
- [Commandes CLI](#-commandes-cli)
- [Notifications Telegram](#-notifications-telegram)
- [Structure du projet](#-structure-du-projet)
- [Dépannage](#-dépannage)

---

## 🔭 Vue d'ensemble

Ce projet est un **pipeline SOC (Security Operations Center) complet** qui automatise entièrement la détection et la réponse aux incidents de sécurité.

### Ce que fait le pipeline

Dès qu'une alerte arrive depuis **Splunk** (ou tout SIEM compatible webhook) :

| Étape | Action | Outil |
|-------|--------|-------|
| 1 | Réception de l'alerte via webhook | Service A (Flask) |
| 2 | Enrichissement des IoCs | VirusTotal API |
| 3 | Création alerte dans TheHive | TheHive 5 |
| 4 | Promotion alerte → Cas d'investigation | Service B |
| 5 | Ajout des observables au cas | TheHive API |
| 6 | Analyse automatique des IoCs | Cortex (via TheHive) |
| 7 | Lookup et partage des IoCs | MISP |
| 8 | Blocage firewall des IPs malveillantes | netsh / iptables |
| 9 | Notification à chaque étape | Telegram + Gmail |

**Tout est 100% automatique**, sans intervention humaine nécessaire.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        RÉSEAU SOC                               │
│                                                                 │
│  ┌──────────┐   webhook    ┌─────────────────────────────────┐  │
│  │  Splunk  │ ────────────▶│         Service A               │  │
│  │  (SIEM)  │  POST /alert │     Flask Webhook :5000         │  │
│  └──────────┘              └──────────────┬──────────────────┘  │
│                                           │ Crée alerte         │
│  ┌──────────┐                             ▼                     │
│  │ Suricata │ ──── logs ──▶  ┌────────────────────────┐        │
│  │  (IDS)   │               │       TheHive :9000      │◀──┐   │
│  └──────────┘               │   Alertes & Cas         │   │   │
│                             └────────────┬───────────┘   │   │
│                                          │ poll /20s      │   │
│                                          ▼                │   │
│                             ┌────────────────────────┐    │   │
│                             │       Service B         │────┘   │
│                             │  Responder Full Auto    │        │
│                             └───┬────┬────┬───────────┘        │
│                                 │    │    │                     │
│                    ┌────────────┘    │    └──────────────┐      │
│                    ▼                ▼                    ▼      │
│           ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│           │    Cortex    │  │     MISP     │  │ VirusTotal   │ │
│           │   :9001      │  │    :443      │  │   (API v3)   │ │
│           │ AbuseIPDB    │  │  IoC DB      │  │ IPs/Hashes   │ │
│           │ MaxMind      │  │  Threat Intel│  │ Domaines     │ │
│           └──────────────┘  └──────────────┘  └──────────────┘ │
│                    │                                            │
│                    ▼                                            │
│           ┌──────────────┐        ┌──────────────┐             │
│           │   Firewall   │        │   Telegram   │             │
│           │ netsh/iptables│        │     Bot      │             │
│           │ Blocage auto │        │ Notifications│             │
│           └──────────────┘        └──────────────┘             │
└─────────────────────────────────────────────────────────────────┘
```

### Stack technique

| Composant | Rôle | Port | Technologie |
|-----------|------|------|-------------|
| **Service A** | Webhook Flask — reçoit alertes Splunk | 5000 | Python / Flask |
| **Service B** | Responder — orchestre tout le pipeline | — | Python |
| **TheHive** | Gestion des alertes et cas | 9000 | Java / Cassandra |
| **Cortex** | Moteur d'analyse automatique | 9001 | Java / Docker |
| **MISP** | Threat Intelligence Platform | 80/443 | PHP / MySQL |
| **Elasticsearch** | Backend index TheHive | 9200 | Java |
| **Cassandra** | Base de données TheHive | 9042 | Java |
| **MinIO** | Stockage fichiers TheHive | 9002 | Go |
| **Suricata** | IDS réseau | — | C |

---

## ✅ Prérequis

### Système d'exploitation recommandé

> **Ubuntu 22.04 LTS** est recommandé pour le serveur hébergeant Docker.
> Le pipeline Python fonctionne sur Windows, Linux et macOS.

| OS | Statut |
|----|--------|
| Ubuntu 20.04 / 22.04 / 24.04 | ✅ Recommandé |
| Debian 11 / 12 | ✅ Supporté |
| Windows 10 / 11 (PowerShell Admin) | ✅ Supporté |
| CentOS / RHEL 8+ | ✅ Supporté |
| macOS 12+ | ⚠️ Sans blocage firewall |

### Ressources minimales (serveur Docker)

| Ressource | Minimum | Recommandé |
|-----------|---------|------------|
| CPU | 4 cœurs | 8 cœurs |
| RAM | 8 Go | 16 Go |
| Disque | 50 Go | 100 Go SSD |

### Logiciels requis

```
Docker          >= 20.10
Docker Compose  >= 2.0
Python          >= 3.8
pip             >= 21.0
```

### Clés API nécessaires

| Service | Où obtenir | Gratuit |
|---------|-----------|---------|
| **TheHive** | Profil utilisateur → API Key | ✅ |
| **Cortex** | Users → API Key | ✅ |
| **MISP** | Administration → Auth Keys | ✅ |
| **VirusTotal** | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) | ✅ (500 req/jour) |
| **Telegram Bot** | [@BotFather](https://t.me/BotFather) sur Telegram | ✅ |
| **AbuseIPDB** | [abuseipdb.com/register](https://www.abuseipdb.com/register) | ✅ |

---

## 🐳 Installation de l'Infrastructure (Docker)

### 1. Installer Docker et Docker Compose

```bash
# Ubuntu / Debian
sudo apt update && sudo apt upgrade -y
sudo apt install -y ca-certificates curl gnupg lsb-release

# Clé GPG Docker
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Dépôt Docker
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Ajouter votre utilisateur au groupe docker
sudo usermod -aG docker $USER
newgrp docker

# Vérifier
docker --version
docker compose version
```

### 2. Cloner le dépôt

```bash
git clone https://github.com/TON-USERNAME/soc-automation-pipeline.git
cd soc-automation-pipeline
```

### 3. Préparer la structure des dossiers

```bash
mkdir -p cortex/logs
mkdir -p server-configs logs files ssl

# Créer le fichier de configuration Cortex minimal
cat > cortex/application.conf << 'EOF'
play.http.secret.key = "CortexTestPassword"

search {
  index = cortex
  uri = "http://elasticsearch:9200"
}

analyzer {
  urls = [
    "https://download.thehive-project.org/analyzers.json"
  ]
}

responder {
  urls = [
    "https://download.thehive-project.org/responders.json"
  ]
}
EOF
```

### 4. Ajuster les paramètres kernel pour Elasticsearch

```bash
# Requis pour Elasticsearch
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
```

### 5. Lancer l'infrastructure

```bash
docker compose up -d

# Vérifier que tous les conteneurs tournent
docker compose ps
```

Attendre environ **3-5 minutes** que tous les services démarrent.

```bash
# Surveiller les logs
docker compose logs -f thehive
docker compose logs -f cortex
```

### 6. Vérifier les services

| Service | URL | Identifiants par défaut |
|---------|-----|------------------------|
| TheHive | http://VOTRE_IP:9000 | Créer un compte admin au premier accès |
| Cortex | http://VOTRE_IP:9001 | Créer un compte admin au premier accès |
| MISP | http://VOTRE_IP ou https://VOTRE_IP | admin@admin.test / admin |
| MinIO | http://VOTRE_IP:9002 | minioadmin / minioadmin |
| Elasticsearch | http://VOTRE_IP:9200 | Aucun (pas d'auth) |

---

## ⚙️ Configuration TheHive + Cortex + MISP

### TheHive — Premier démarrage

1. Ouvrir `http://VOTRE_IP:9000`
2. Cliquer **"Create a new database"** → attendre l'initialisation
3. Créer un compte administrateur
4. Aller dans **Organisation** → créer votre organisation
5. Créer un utilisateur avec rôle **analyst**
6. Aller dans **Profil** → **API Key** → **Créer** → copier la clé

### Cortex — Configuration

1. Ouvrir `http://VOTRE_IP:9001`
2. Cliquer **"Update Database"** → initialisation
3. Créer un compte admin
4. **Organizations** → **Add Organization** → donner un nom
5. **Users** → **Add User** → rôle `read,analyze` → **Create API Key** → copier
6. **Organizations** → votre org → **Analyzers** → activer :
   - `AbuseIPDB_2_0` → configurer votre clé API AbuseIPDB
   - `VirusTotal_GetReport_3_0` → configurer votre clé VT
   - `MaxMind_GeoIP_4_0`
   - `Shodan_Host_2_0` (optionnel)

```bash
# S'assurer que python3 est disponible pour les analyseurs Cortex
# Sur le serveur hébergeant Docker :
which python3
python3 --version

# Si absent :
sudo apt install python3 python3-pip -y
```

### Intégration TheHive ↔ Cortex (via GUI)

1. Dans TheHive → **Organisation** → **Connectors**
2. **Cortex** → **Add Cortex server**
3. Remplir :
   - **Name** : `cortex.local`
   - **URL** : `http://cortex.local:9001`
   - **API Key** : votre clé Cortex
4. Cliquer **Test** → doit afficher ✅

### MISP — Configuration initiale

1. Ouvrir `https://VOTRE_IP` (ignorer l'avertissement SSL)
2. Se connecter : `admin@admin.test` / `admin`
3. **Changer le mot de passe** immédiatement
4. **Administration** → **Server Settings** → changer `MISP.baseurl` avec votre IP
5. **Administration** → **Auth Keys** → **Add authentication key** → copier

### Intégration TheHive ↔ MISP

Dans TheHive → **Organisation** → **Connectors** → **MISP** → **Add MISP server** :

```
Name    : misp.local
URL     : https://misp.local
API Key : VOTRE_CLE_MISP
```

Ou via le fichier de configuration (si non Docker) :

```hocon
play.modules.enabled += org.thp.thehive.connector.misp.MispModule

misp {
  interval: 1 hour
  servers: [
    {
      name = "MISP"
      url  = "https://misp.local"
      auth {
        type = key
        key  = "VOTRE_CLE_API_MISP"
      }
      tags             = ["misp", "threat-intel"]
      caseTemplate     = "misp"
    }
  ]
}
```

---

## 🔍 Configuration Suricata IDS

Suricata est l'IDS réseau qui détecte les scans NMAP, les connexions Metasploit, et autres menaces réseau. Ses alertes sont envoyées à Splunk qui les transmet au pipeline.

### Installation Suricata

```bash
# Ubuntu / Debian
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt update
sudo apt install suricata -y

# Vérifier la version
suricata --version
```

### Configuration de base

```bash
# Éditer la configuration principale
sudo nano /etc/suricata/suricata.yaml
```

Modifier la section `af-packet` avec votre interface réseau :

```yaml
af-packet:
  - interface: eth0   # Remplacer par votre interface (ip a pour voir)
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
```

### Règles de détection personnalisées

Créer un fichier de règles pour détecter les scans NMAP et Metasploit :

```bash
sudo nano /etc/suricata/rules/soc-custom.rules
```

Ajouter les règles suivantes :

```
# ══════════════════════════════════════════════════════════════════
# SOC Pipeline — Règles de détection personnalisées
# Détection des scans NMAP (T1 à T5) et activité Metasploit
# ══════════════════════════════════════════════════════════════════

# SYN SCAN -sS (vitesses T1-T5)
alert tcp any any -> any [21,22,23,25,53,80,88,110,135,137,138,139,143,161,389,443,445,465,514,587,636,853,993,995,1194,1433,1720,3306,3389,8080,8443,11211,27017,51820] (msg:"POSSBL PORT SCAN (NMAP -sS)"; flow:to_server,stateless; flags:S; window:1024; tcp.mss:1460; threshold:type threshold, track by_src, count 20, seconds 70; classtype:attempted-recon; sid:3400001; priority:2; rev:1;)

alert tcp any any -> any ![21,22,23,25,53,80,88,110,135,137,138,139,143,161,389,443,445,465,514,587,636,853,993,995,1194,1433,1720,3306,3389,8080,8443,11211,27017,51820] (msg:"POSSBL PORT SCAN (NMAP -sS)"; flow:to_server,stateless; flags:S; window:1024; tcp.mss:1460; threshold:type threshold, track by_src, count 7, seconds 135; classtype:attempted-recon; sid:3400002; priority:2; rev:2;)

# SYN-ACK 3-WAY SCAN -sT (vitesses T2-T5)
alert tcp any ![22,25,53,80,88,143,443,445,465,587,853,993,1194,8080,51820] -> any ![22,25,53,80,88,143,443,445,465,587,853,993,1194,8080,51820] (msg:"POSSBL PORT SCAN (NMAP -sT)"; flow:to_server; window:32120; flags:S; threshold:type threshold, track by_src, count 20, seconds 70; classtype:attempted-recon; sid:3400003; rev:3;)

# ACK SCAN -sA (vitesses T2-T5)
alert tcp any ![22,25,53,80,88,143,443,445,465,587,853,993,1194,8080,51820] -> any ![22,25,53,80,88,143,443,445,465,587,853,993,1194,8080,51820] (msg:"POSSBL PORT SCAN (NMAP -sA)"; flags:A; flow:stateless; window:1024; threshold:type threshold, track by_dst, count 20, seconds 70; classtype:attempted-recon; sid:3400004; priority:2; rev:5;)

# CHRISTMAS TREE SCAN -sX (vitesses T1-T5)
alert tcp any any -> any any (msg:"POSSBL PORT SCAN (NMAP -sX)"; flags:FPU; flow:to_server,stateless; threshold:type threshold, track by_src, count 3, seconds 120; classtype:attempted-recon; sid:3400005; rev:2;)

# FRAGMENTED SCAN -f (vitesses T1-T5)
alert ip any any -> any any (msg:"POSSBL SCAN FRAG (NMAP -f)"; fragbits:M+D; threshold:type limit, track by_src, count 3, seconds 1210; classtype:attempted-recon; sid:3400006; priority:2; rev:6;)

# UDP SCAN -sU (vitesses T1-T5)
alert udp any any -> any [53,67,68,69,123,161,162,389,520,1026,1027,1028,1029,1194,1434,1900,11211,12345,27017,51820] (msg:"POSSBL PORT SCAN (NMAP -sU)"; flow:to_server,stateless; classtype:attempted-recon; sid:3400007; priority:2; rev:6; threshold:type threshold, track by_src, count 20, seconds 70; dsize:0;)

alert udp any any -> any ![53,67,68,69,123,161,162,389,520,1026,1027,1028,1029,1194,1434,1900,11211,12345,27017,51820] (msg:"POSSBL PORT SCAN (NMAP -sU)"; flow:to_server,stateless; classtype:attempted-recon; sid:3400008; priority:2; rev:6; threshold:type threshold, track by_src, count 7, seconds 135; dsize:0;)

# METASPLOIT — Port 4444 (shell reverse TCP par défaut)
alert tcp any ![21,22,23,25,53,80,88,110,135,137,138,139,143,161,389,443,445,465,514,587,636,853,993,995,1194,1433,1720,3306,3389,8080,8443,11211,27017,51820] -> any 4444 (msg:"POSSBL SHELL METASPLOIT TCP:4444"; classtype:trojan-activity; sid:3400020; priority:1; rev:2;)

alert udp any ![53,67,68,69,123,161,162,389,520,1026,1027,1028,1029,1194,1434,1900,11211,12345,27017,51820] -> any 4444 (msg:"POSSBL SHELL METASPLOIT UDP:4444"; classtype:trojan-activity; sid:3400021; priority:1; rev:2;)
```

### Activer les règles personnalisées

```bash
# Éditer suricata.yaml pour inclure nos règles
sudo nano /etc/suricata/suricata.yaml
```

Trouver la section `rule-files` et ajouter :

```yaml
rule-files:
  - suricata.rules
  - soc-custom.rules    # Ajouter cette ligne
```

### Démarrer Suricata

```bash
# Tester la configuration
sudo suricata -T -c /etc/suricata/suricata.yaml

# Démarrer le service
sudo systemctl enable suricata
sudo systemctl start suricata
sudo systemctl status suricata

# Voir les alertes en temps réel
sudo tail -f /var/log/suricata/fast.log
```

---

## 📦 Installation du Pipeline SOC

### 1. Préparer l'environnement Python

```bash
# Aller dans le dossier du projet
cd soc-automation-pipeline

# Créer un environnement virtuel
python3 -m venv venv

# Activer l'environnement
source venv/bin/activate          # Linux / macOS
# OU
.\venv\Scripts\Activate.ps1       # Windows PowerShell

# Installer les dépendances
pip install -r requirements.txt
```

### 2. Vérifier l'installation

```bash
python start.py install
python start.py status
```

---

## 🔧 Fichier de Configuration .env

### Créer le fichier

```bash
cp env.example .env
nano .env
```

### Référence complète de toutes les variables

```ini
# ══════════════════════════════════════════════════════════════════
#  SOC Automation Pipeline — Configuration
# ══════════════════════════════════════════════════════════════════
#
#  ⚠️  RÈGLE IMPORTANTE : jamais de commentaire après une valeur !
#  ❌  BLOCK_DURATION_MIN=10   ← commentaire    (provoque une erreur)
#  ✅  BLOCK_DURATION_MIN=10
#      # commentaire sur une ligne séparée
#
# ══════════════════════════════════════════════════════════════════

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
RETRY_ATTEMPTS=3
RETRY_DELAY_SEC=5

# ─── Service B — Responder ────────────────────────────────────────
POLL_INTERVAL=20
MIN_SEVERITY=1
RESPONSE_MIN_SEV=2
STATE_FILE=responder_state.json
BLACKLIST_FILE=ip_blacklist.txt
CORTEX_JOB_TIMEOUT=180

# ─── Réponse Active — Blocage Firewall ────────────────────────────
# false = simulation (aucun blocage réel)
# true  = blocage firewall réel (nécessite admin/root)
ACTIVE_RESPONSE=false
BLOCK_DURATION_MIN=10
BLOCK_ALL_IPS=true
BLOCK_ON_BRUTEFORCE=true

# ─── Telegram ─────────────────────────────────────────────────────
TELEGRAM_ENABLED=true
TELEGRAM_TOKEN=votre_token_bot_telegram
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

### Tableau de référence des variables

| Variable | Valeur par défaut | Description |
|----------|-------------------|-------------|
| `THEHIVE_URL` | — | URL TheHive (ex: `http://192.168.1.10:9000`) |
| `THEHIVE_APIKEY` | — | Clé API TheHive |
| `CORTEX_URL` | — | URL Cortex (ex: `http://192.168.1.10:9001`) |
| `CORTEX_APIKEY` | — | Clé API Cortex |
| `MISP_URL` | — | URL MISP (ex: `https://192.168.1.11`) |
| `MISP_APIKEY` | — | Clé API MISP |
| `MISP_ENABLED` | `true` | Activer MISP |
| `VT_ENABLED` | `true` | Activer VirusTotal |
| `VT_APIKEY` | — | Clé API VirusTotal |
| `VT_TIMEOUT` | `15` | Timeout requêtes VT (secondes) |
| `VT_MIN_DETECTIONS` | `2` | Seuil détections pour verdict malveillant |
| `LISTEN_PORT` | `5000` | Port webhook Service A |
| `RATE_LIMIT_SEC` | `10` | Anti-doublon entre alertes identiques |
| `POLL_INTERVAL` | `20` | Fréquence poll TheHive (secondes) |
| `ACTIVE_RESPONSE` | `false` | `true` = blocage firewall réel |
| `BLOCK_DURATION_MIN` | `10` | Durée de blocage (minutes) |
| `BLOCK_ON_BRUTEFORCE` | `true` | Bloquer automatiquement si brute force |
| `CORTEX_JOB_TIMEOUT` | `180` | Attente max résultats Cortex (secondes) |
| `TELEGRAM_ENABLED` | `false` | Activer notifications Telegram |
| `TELEGRAM_TOKEN` | — | Token bot Telegram |
| `TELEGRAM_CHAT_ID` | — | Chat ID Telegram |
| `LOG_LEVEL` | `INFO` | Niveau log (`DEBUG`, `INFO`, `WARNING`) |

---

## 📡 Configuration Splunk

### Créer un webhook dans Splunk

1. **Settings** → **Searches, Reports and Alerts**
2. Créer ou éditer une alerte
3. **Alert Actions** → **Add Actions** → **Webhook**
4. Configurer :

```
URL     : http://VOTRE_IP_PIPELINE:5000/alert
Method  : POST
```

### Format du payload Splunk (4 formats supportés)

**Format 1 — Standard avec `result` :**
```json
{
  "search_name": "Brute Force SSH Détecté",
  "severity": "high",
  "result": {
    "src_ip":       "1.2.3.4",
    "dest_ip":      "192.168.1.10",
    "user":         "root",
    "host":         "serveur-prod",
    "count":        "15",
    "source":       "/var/log/auth.log",
    "_time":        "2024-01-15T10:30:00"
  }
}
```

**Format 2 — Avec hash de fichier :**
```json
{
  "search_name": "Fichier Malveillant Détecté",
  "severity": "critical",
  "result": {
    "host":      "poste-01",
    "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
    "process":   "malware.exe",
    "user":      "john.doe"
  }
}
```

**Format 3 — Avec domaine :**
```json
{
  "search_name": "DNS Suspect",
  "severity": "medium",
  "result": {
    "src_ip":  "192.168.1.50",
    "domain":  "malware-c2.xyz",
    "host":    "workstation-05"
  }
}
```

### Alertes Suricata → Splunk

Configurer Splunk pour ingérer les logs Suricata :

```bash
# Dans Splunk Universal Forwarder sur le serveur Suricata
# Éditer inputs.conf
[monitor:///var/log/suricata/eve.json]
disabled = false
index = suricata
sourcetype = suricata
```

---

## 🚀 Démarrage

### Lancer les deux services

```bash
# Les deux services ensemble
python start.py both

# Ou séparément
python start.py a    # Service A (webhook)
python start.py b    # Service B (responder)
```

### Activer le vrai blocage firewall

```bash
# Dans .env : ACTIVE_RESPONSE=true

# Linux — nécessite root :
sudo python3 start.py both

# Windows — relancer PowerShell en Administrateur :
# Clic droit sur PowerShell → "Exécuter en tant qu'administrateur"
python start.py both
```

### Sortie attendue au démarrage

```
══  Service A + B — Lancement simultané  ═══════════════
  Lancement de Service A (webhook :5000)...
  Lancement de Service B (responder Cortex+MISP)...
  ✓ Service A PID 12345
  ✓ Service B PID 12346
  Les deux services tournent. Ctrl+C pour arrêter.

[TELEGRAM] ✅ Bot @votre_bot

==============================================================
  SOC Pipeline — Service A  v7.0.0
==============================================================
  TheHive     : ✅ OK — http://192.168.1.10:9000
  VirusTotal  : ✅ OK
  Telegram    : ✅ OK
  Gmail       : ⚪ Désactivé
  Webhook     : http://0.0.0.0:5000/alert
==============================================================

╔══════════════════════════════════════════════════════════╗
║  SOC Pipeline — Service B  v10.0.0  FULL AUTO           ║
╠══════════════════════════════════════════════════════════╣
║  TheHive  : http://192.168.1.10:9000                    ║
║  VT       : ✅ Actif                                    ║
║  Cortex   : ✅ 8 analyseurs                             ║
║  MISP     : ✅ Actif                                    ║
║  Blocage  : ⚠️  SIMULATION                              ║
╚══════════════════════════════════════════════════════════╝
```

---

## 🔄 Flux Automatique Complet

Voici exactement ce qui se passe pour chaque alerte reçue :

```
1️⃣  Splunk/Suricata détecte une menace
     → Webhook POST /alert envoyé au Service A
          │
          ▼
2️⃣  Service A reçoit et parse l'alerte
     → Extraction des IoCs (IP, hash, domaine, URL)
     → Enrichissement VirusTotal (IPs publiques + hashes)
     → Création Alerte TheHive avec observables
     → 📱 Telegram : "🔴 ALERTE SOC — HIGH"
          │
          ▼
3️⃣  Service B détecte l'alerte (poll toutes les 20s)
     → Vérification : alerte déjà traitée ?
          │
          ▼
4️⃣  Promotion Alerte → Cas TheHive
     → 3 méthodes de fallback garanties
     → 📱 Telegram : "📁 Cas #42 créé"
          │
          ▼
5️⃣  Pour chaque Observable (IP / Hash / Domaine) :
     │
     ├── a) Ajout Observable au Cas TheHive
     │       → Visible dans l'onglet Observables
     │
     ├── b) VirusTotal
     │       → IPs publiques : check réputation
     │       → Hashes : détection malware
     │       → Commentaire ajouté dans le cas
     │       → 📱 Telegram : "🔴 MALVEILLANT 45/72"
     │
     ├── c) MISP Lookup
     │       → Vérification dans la base IoC
     │       → Si trouvé : tag + commentaire dans le cas
     │       → 📱 Telegram : "🌐 MISP HIT"
     │
     ├── d) Blocage IP Firewall
     │       → Si brute force OU VT malveillant OU MISP hit
     │       → Windows : netsh advfirewall
     │       → Linux : iptables -I INPUT DROP
     │       → Timer de déblocage automatique
     │       → Commentaire dans le cas TheHive
     │       → 📱 Telegram : "🚫 IP BLOQUÉE 10min"
     │
     └── e) Cortex (via API TheHive)
             → Lancement analyseurs prioritaires
             → AbuseIPDB, MaxMind, VT, Shodan...
             → Résultats dans l'onglet Analyzers du cas
             → Commentaire avec verdicts
             → 📱 Telegram par analyseur
          │
          ▼
6️⃣  Rapport récapitulatif dans le cas TheHive
     → Tableau IPs / VT / MISP / Blocage
     → Liste des actions Cortex
     → Commandes de déblocage
          │
          ▼
7️⃣  ⏱️  Après X minutes : déblocage automatique
     → Suppression règle firewall
     → 📱 Telegram : "✅ IP débloquée"
```

---

## 🌐 Endpoints Service A

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `POST` | `/alert` | **Webhook principal** — reçoit les alertes Splunk |
| `GET` | `/health` | Vérification état complet du service |
| `GET` | `/test` | Envoie une alerte de test avec IP Tor (VT la détecte) |
| `GET` | `/telegram-test` | Teste le bot Telegram avec diagnostic |
| `GET` | `/vt-test` | Teste la connexion VirusTotal |
| `GET` | `/debug` | Affiche les 10 derniers payloads reçus |
| `GET` | `/stats` | Statistiques (reçus, créés, doublons, erreurs) |

### Tests rapides

```bash
# Health check
curl http://localhost:5000/health

# Alerte de test (envoie une vraie alerte à TheHive)
curl http://localhost:5000/test

# Test Telegram
curl http://localhost:5000/telegram-test

# Test VirusTotal
curl http://localhost:5000/vt-test

# Webhook manuel
curl -X POST http://localhost:5000/alert \
  -H "Content-Type: application/json" \
  -d '{
    "search_name": "Test Brute Force SSH",
    "severity": "high",
    "result": {
      "src_ip":  "185.220.101.50",
      "user":    "root",
      "host":    "serveur-01",
      "count":   "50",
      "source":  "/var/log/auth.log"
    }
  }'
```

---

## 🖥️ Commandes CLI

```bash
# État complet du système
python start.py status

# Voir toutes les IPs actuellement bloquées
python start.py list

# Débloquer une IP manuellement
python start.py unblock 1.2.3.4

# Lancer uniquement Service A
python start.py a

# Lancer uniquement Service B
python start.py b

# Lancer les deux services
python start.py both

# Installer les dépendances
python start.py install

# Tester toute l'intégration
python start.py test

# Tester Telegram
python start.py telegram
```

---

## 📱 Notifications Telegram

### Configurer le bot

1. Ouvrir Telegram → chercher **@BotFather**
2. Envoyer `/newbot`
3. Donner un nom → récupérer le **token**
4. **Envoyer un message** à votre bot (pour activer le chat)
5. Récupérer votre **Chat ID** :

```bash
curl "https://api.telegram.org/botVOTRE_TOKEN/getUpdates"
# Chercher : result[0].message.chat.id
```

6. Mettre à jour `.env` :
```ini
TELEGRAM_ENABLED=true
TELEGRAM_TOKEN=1234567890:AAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TELEGRAM_CHAT_ID=123456789
```

### Types de notifications

| Emoji | Événement | Déclencheur |
|-------|-----------|-------------|
| 🚀 | Service démarré | Au lancement |
| 🔴 | Alerte High/Critical | Réception webhook Splunk |
| 📁 | Cas créé dans TheHive | Promotion alerte |
| 🦠 | Résultat VirusTotal | Analyse IoC |
| 🌐 | MISP Hit | IoC trouvé dans MISP |
| 🚫 | IP Bloquée | Blocage firewall actif |
| ⚠️ | IP en simulation | ACTIVE_RESPONSE=false |
| 🔬 | Résultat Cortex | Analyseur terminé |
| ✅ | IP Débloquée | Timer expiré ou manuel |

---

## 📁 Structure du Projet

```
soc-automation-pipeline/
│
├── 📄 docker-compose.yml             # Infrastructure complète (TheHive, Cortex, MISP...)
│
├── 🐍 start.py                       # Lanceur universel (Windows/Linux/macOS)
├── 🐍 service_splunk_to_thehive.py   # Service A — Webhook Flask v7.0.0
├── 🐍 service_thehive_responder.py   # Service B — Responder Full Auto v10.0.0
├── 🐍 test_service_a.py              # Tests d'intégration
│
├── 📄 .env                           # Configuration (à créer depuis env.example)
├── 📄 env.example                    # Template de configuration
├── 📄 requirements.txt               # Dépendances Python
├── 📄 .gitignore                     # Fichiers exclus de Git
│
├── 📁 cortex/
│   ├── application.conf              # Configuration Cortex
│   └── logs/                         # Logs Cortex
│
├── 📁 server-configs/                # Configuration MISP
├── 📁 logs/                          # Logs MISP
├── 📁 files/                         # Fichiers MISP
├── 📁 ssl/                           # Certificats SSL
│
├── 📄 responder_state.json           # État des alertes traitées (auto-généré)
├── 📄 ip_blacklist.json              # Blacklist avec timers (auto-généré)
├── 📄 ip_blacklist.txt               # Blacklist lisible (auto-généré)
│
├── 📄 service_a.log                  # Logs Service A (auto-généré)
└── 📄 service_b.log                  # Logs Service B (auto-généré)
```

---

## 🐛 Dépannage

### Service B ne crée pas de cas

```bash
# Vérifier les logs Service B
tail -50 service_b.log        # Linux
Get-Content service_b.log -Tail 50  # Windows PowerShell

# Tester manuellement l'API TheHive
curl -X POST http://VOTRE_IP:9000/api/v1/query?name=list-alerts \
  -H "Authorization: Bearer VOTRE_CLE" \
  -H "Content-Type: application/json" \
  -d '{"query":[{"_name":"listAlert"},{"_name":"page","from":0,"to":5}]}'
```

### Cortex — `python3: No such file or directory`

```bash
# Sur le serveur hébergeant Cortex
sudo apt install python3 python3-pip -y
sudo ln -sf /usr/bin/python3 /usr/local/bin/python3

# Redémarrer Cortex
docker compose restart cortex.local
```

### Blocage IP ne fonctionne pas (Windows)

```
Cause : PowerShell n'est pas lancé en Administrateur
Fix   : Clic droit → "Exécuter en tant qu'administrateur"
Vérif : ACTIVE_RESPONSE=true dans .env
Test  : netsh advfirewall firewall show rule name=all | findstr SOC
```

### Blocage IP ne fonctionne pas (Linux)

```bash
# Nécessite root
sudo python3 start.py both

# Vérifier les règles iptables
sudo iptables -L INPUT -n --line-numbers | head -20

# Installer iptables si absent
sudo apt install iptables -y
```

### MISP — Timeout de connexion

```bash
# Vérifier que le conteneur MISP tourne
docker compose ps misp.local

# Voir les logs MISP
docker compose logs misp.local --tail 50

# Tester la connexion manuellement
curl -k -H "Authorization: VOTRE_CLE" \
  https://VOTRE_IP_MISP/users/login
```

### Erreur `.env` — `invalid literal for int`

```ini
# ❌ INCORRECT — provoque une erreur Python
BLOCK_DURATION_MIN=10    ← durée en minutes

# ✅ CORRECT — commentaire sur sa propre ligne
# Durée de blocage en minutes
BLOCK_DURATION_MIN=10
```

### TheHive v5 — alertes ignorées

Ce bug est corrigé dans v8.1.0+. TheHive v5 utilise `_id` (underscore) et non `id`.
Vérifier que vous utilisez bien `service_thehive_responder.py` v8.1.0 ou supérieur.

### Suivre les logs en temps réel

```bash
# Linux — les deux logs simultanément
tail -f service_a.log service_b.log

# Windows PowerShell
Get-Content service_a.log -Wait -Tail 20
Get-Content service_b.log -Wait -Tail 20
```

---

## 🔐 Sécurité

> ⚠️ **Ne jamais commiter le fichier `.env` dans Git**

Le fichier `.gitignore` protège automatiquement :
- `.env` (credentials)
- `*.log` (logs)
- `ip_blacklist.*` (données blacklist)
- `responder_state.json`

### Bonnes pratiques

- Utiliser des clés API avec **permissions minimales** nécessaires
- En production, mettre le webhook derrière **nginx avec HTTPS**
- Pour MISP, utiliser `verify=True` avec un certificat SSL valide
- Changer les mots de passe par défaut de MISP, MinIO immédiatement

---

## 📚 Ressources utiles

| Ressource | Lien |
|-----------|------|
| TheHive Documentation | [docs.strangebee.com](https://docs.strangebee.com) |
| Cortex Documentation | [github.com/TheHive-Project/Cortex](https://github.com/TheHive-Project/Cortex) |
| MISP Documentation | [www.misp-project.org/documentation](https://www.misp-project.org/documentation/) |
| VirusTotal API v3 | [developers.virustotal.com](https://developers.virustotal.com/reference/overview) |
| Suricata Rules | [suricata.readthedocs.io](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/) |
| TheHive + Cortex + MISP Setup (vidéo) | [Tutoriel YouTube — Installation complète](https://youtu.be/ovUuNQsW_FQ) |
| Intégration TheHive + Cortex (vidéo) | [Tutoriel YouTube — Intégration](https://youtu.be/ovUuNQsW_FQ) |
| AbuseIPDB | [abuseipdb.com](https://www.abuseipdb.com) |
| BotFather Telegram | [t.me/BotFather](https://t.me/BotFather) |

---

## 🤝 Contribuer

Les contributions sont les bienvenues !

```bash
# Fork → Clone → Branch
git checkout -b feature/ma-fonctionnalite

# Développer → Commit
git commit -m "feat: description de la fonctionnalité"

# Push → Pull Request
git push origin feature/ma-fonctionnalite
```

### Idées de contributions

- [ ] Support Elasticsearch/OpenSearch comme source d'alertes
- [ ] Interface web de monitoring des cas et blocages
- [ ] Support webhooks PagerDuty / Slack / Teams
- [ ] Tests unitaires et d'intégration complets
- [ ] Docker Compose tout-en-un (pipeline + infrastructure)
- [ ] Dashboard Grafana pour les métriques SOC

---

## 📄 Licence

Distribué sous licence **MIT**. Voir [LICENSE](LICENSE) pour plus d'informations.

---

<div align="center">

**SOC Automation Pipeline** — Projet de Lab SOC Personnel

*Automatiser la détection et la réponse aux incidents de sécurité*

⭐ N'oublie pas de mettre une étoile si ce projet t'a aidé !

</div>
