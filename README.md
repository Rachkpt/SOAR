# 🛡️ SOC Automation Pipeline (SOAR)

<div align="center">

**Pipeline de détection et de réponse aux incidents, 100 % automatique**

Suricata / Splunk → TheHive → Cortex → MISP → VirusTotal → Firewall → Telegram

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![TheHive](https://img.shields.io/badge/TheHive-5.2.x-F5A800?style=for-the-badge)](https://docs.strangebee.com/thehive/)
[![Cortex](https://img.shields.io/badge/Cortex-3.x-FF6B35?style=for-the-badge)](https://github.com/TheHive-Project/Cortex)
[![MISP](https://img.shields.io/badge/MISP-2.4%2B-CC0000?style=for-the-badge)](https://www.misp-project.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docs.docker.com/compose)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)](LICENSE)

</div>

---

## 📖 Sommaire

- [Vue d'ensemble](#-vue-densemble)
- [Architecture](#️-architecture)
- [Structure du projet](#-structure-du-projet)
- [Démarrage rapide](#-démarrage-rapide-5-commandes)
- [Prérequis](#-prérequis)
- [1. Infrastructure Docker](#1️⃣-infrastructure-docker)
- [2. Configuration TheHive + Cortex + MISP](#2️⃣-configuration-thehive--cortex--misp)
- [3. Suricata IDS](#3️⃣-suricata-ids)
- [4. Splunk](#4️⃣-splunk)
- [5. Installation du pipeline Python](#5️⃣-installation-du-pipeline-python)
- [6. Fichier .env](#6️⃣-fichier-env)
- [Démarrage](#-démarrage)
- [Flux automatique détaillé](#-flux-automatique-détaillé)
- [Réponse active : quoi est bloqué et quand](#-réponse-active--quoi-est-bloqué-et-quand)
- [Endpoints du Service A](#-endpoints-du-service-a)
- [Commandes CLI](#️-commandes-cli)
- [Notifications Telegram](#-notifications-telegram)
- [Tests](#-tests)
- [Dépannage](#-dépannage)
- [Sécurité](#-sécurité)
- [Références et documentation détaillée](#-références-et-documentation-détaillée)
- [Journal des versions](#-journal-des-versions)

---

## 🔭 Vue d'ensemble

Ce projet est un **SOAR** (Security Orchestration, Automation and Response) complet
pour lab SOC. Dès qu'une alerte arrive depuis **Splunk** ou **Suricata**, la chaîne
suivante se déroule sans aucune intervention humaine :

| Étape | Action | Composant |
|-------|--------|-----------|
| 1 | Réception de l'alerte par webhook HTTP | Service A (Flask) |
| 2 | Extraction des IoCs (IP, hash, domaine, URL) | Service A |
| 3 | Enrichissement VirusTotal | API VirusTotal v3 |
| 4 | Création de l'**alerte** dans TheHive | API REST TheHive v1 |
| 5 | Promotion de l'alerte en **cas** d'investigation | Service B |
| 6 | Ajout des observables au cas | API REST TheHive v1 |
| 7 | **Lancement automatique des analyseurs Cortex** | Cortex via TheHive |
| 8 | Lookup et publication d'IoC dans MISP | API MISP |
| 9 | **Blocage firewall** de l'IP attaquante | netsh / iptables |
| 10 | Rapport markdown dans le cas + notification | TheHive + Telegram |
| 11 | Déblocage automatique après expiration du timer | Service B |

### Ce qui a changé dans cette version

Le pipeline a été entièrement réorganisé et corrigé :

- **Plus de `thehive4py`.** La bibliothèque est abandonnée et dépend de `libmagic`,
  dont l'import **fait planter l'interpréteur Python sous Windows**. Le projet parle
  maintenant directement à l'**API REST v1 de TheHive 5**.
- **Cortex se lance vraiment tout seul.** Les analyseurs sont découverts via
  `/api/connector/cortex/analyzer` de TheHive (la source de vérité), avec repli sur
  l'API Cortex directe, deux routes de lancement et un rafraîchissement automatique
  si Cortex démarre après le Service B.
- **Le blocage couvre bien plus que le brute force** : scan de ports NMAP, shells
  Metasploit, mouvement latéral, vol d'identifiants, rançongiciel, exfiltration,
  verdicts VirusTotal et hits MISP (voir [le tableau des déclencheurs](#-réponse-active--quoi-est-bloqué-et-quand)).
- **135 tests unitaires** hors ligne, exécutables par `python start.py unit`.

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                            RÉSEAU SOC                                │
│                                                                      │
│  ┌──────────┐                                                        │
│  │ Suricata │ ── eve.json ──┐                                        │
│  │  (IDS)   │               │                                        │
│  └──────────┘               ▼                                        │
│                        ┌──────────┐   webhook    ┌────────────────┐  │
│                        │  Splunk  │ ────────────▶│   Service A    │  │
│                        │  (SIEM)  │  POST /alert │  Flask :5000   │  │
│                        └──────────┘              └───────┬────────┘  │
│                                                          │ alerte    │
│                                                          ▼           │
│                                            ┌─────────────────────┐   │
│                                            │    TheHive :9000    │◀─┐│
│                                            │   Alertes  &  Cas   │  ││
│                                            └──────────┬──────────┘  ││
│                                                       │ poll 20 s   ││
│                                                       ▼             ││
│                                            ┌─────────────────────┐  ││
│                                            │     Service B       │──┘│
│                                            │  Responder auto     │   │
│                                            └──┬─────┬─────┬──────┘   │
│                        ┌──────────────────────┘     │     └───────┐  │
│                        ▼                            ▼             ▼  │
│               ┌─────────────┐            ┌─────────────┐  ┌──────────┴──┐
│               │   Cortex    │            │    MISP     │  │ VirusTotal  │
│               │   :9001     │            │   :80/443   │  │   API v3    │
│               │ AbuseIPDB   │            │  IoC / TI   │  │ IP · hash   │
│               │ MaxMind     │            │             │  │ domaine·URL │
│               │ Shodan…     │            └─────────────┘  └─────────────┘
│               └─────────────┘                                        │
│                        │                                             │
│          ┌─────────────┴─────────────┐                               │
│          ▼                           ▼                               │
│  ┌───────────────┐          ┌────────────────┐                       │
│  │   Firewall    │          │    Telegram    │                       │
│  │ netsh/iptables│          │      Bot       │                       │
│  │ blocage + TTL │          │ notifications  │                       │
│  └───────────────┘          └────────────────┘                       │
└──────────────────────────────────────────────────────────────────────┘
```

### Stack technique

| Composant | Rôle | Port | Techno |
|-----------|------|------|--------|
| **Service A** | Webhook Flask — reçoit les alertes Splunk | 5000 | Python / Flask |
| **Service B** | Responder — orchestre tout le pipeline | — | Python |
| **TheHive** | Gestion des alertes et des cas | 9000 | Scala / Cassandra |
| **Cortex** | Moteur d'analyse automatique | 9001 | Scala / Docker |
| **MISP** | Threat Intelligence Platform | 80 / 443 | PHP / MySQL |
| **Elasticsearch** | Index de TheHive et Cortex | 9200 | Java |
| **Cassandra** | Base de données de TheHive | 9042 | Java |
| **MinIO** | Stockage des pièces jointes | 9002 | Go |
| **Suricata** | IDS réseau | — | C |

---

## 📁 Structure du projet

```
SOAR/
│
├── start.py                              # Lanceur universel (stdlib seulement)
├── requirements.txt                      # Dépendances Python
├── .env.example                          # Modèle de configuration
├── .gitignore
├── LICENSE
├── README.md
│
├── src/
│   ├── soc_common.py                     # Socle partagé : .env, logs, client
│   │                                     # TheHive REST v1, Observable, Telegram
│   ├── service_a_splunk_to_thehive.py    # Service A — webhook          v8.0.0
│   └── service_b_thehive_responder.py    # Service B — responder auto   v11.0.0
│
├── docker/
│   ├── docker-compose.yml                # TheHive + Cortex + MISP + dépendances
│   ├── cortex/application.conf           # Configuration Cortex
│   └── thehive/application.conf          # Connecteur MISP (optionnel)
│
├── suricata/
│   └── soc-custom.rules                  # Règles NMAP / Metasploit
│
├── tests/
│   ├── harness.py                        # Mini-harnais (aucune dépendance)
│   ├── run_tests.py                      # Lance toutes les suites
│   ├── test_soc_common.py                # 33 tests
│   ├── test_service_a.py                 # 54 tests
│   └── test_service_b.py                 # 48 tests
│
├── data/                                 # Généré : état, blacklist  (git-ignoré)
└── logs/                                 # Généré : journaux         (git-ignoré)
```

---

## ⚡ Démarrage rapide (5 commandes)

```bash
git clone https://github.com/Rachkpt/SOAR.git
cd SOAR

python start.py install          # installe flask, requests, urllib3
python start.py init             # crée .env depuis .env.example
# éditer .env : THEHIVE_URL + THEHIVE_APIKEY au minimum
python start.py status           # vérifie que tout est en place
python start.py both             # lance les Services A et B
```

Sans argument, `python start.py` ouvre un **menu interactif** qui couvre tout.

---

## ✅ Prérequis

### Système

> **Ubuntu 22.04 LTS** est recommandé pour le serveur Docker.
> Le pipeline Python tourne sur Windows, Linux et macOS.

| OS | Statut |
|----|--------|
| Ubuntu 20.04 / 22.04 / 24.04 | ✅ Recommandé |
| Debian 11 / 12 | ✅ Supporté |
| Windows 10 / 11 (PowerShell Admin) | ✅ Supporté |
| CentOS / RHEL 8+ | ✅ Supporté |
| macOS 12+ | ⚠️ Sans blocage firewall |

### Ressources du serveur Docker

| Ressource | Minimum | Recommandé |
|-----------|---------|------------|
| CPU | 4 cœurs | 8 cœurs |
| RAM | 8 Go | 16 Go |
| Disque | 50 Go | 100 Go SSD |

### Logiciels

```
Docker          >= 20.10
Docker Compose  >= 2.0
Python          >= 3.8   (testé jusqu'à 3.13)
pip             >= 21.0
```

### Clés API

| Service | Où l'obtenir | Gratuit |
|---------|--------------|---------|
| **TheHive** | avatar → Settings → API Keys → Create | ✅ |
| **Cortex** | Organizations → Users → Create API Key | ✅ |
| **MISP** | Administration → List Auth Keys → Add | ✅ |
| **VirusTotal** | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) | ✅ 500 req/jour |
| **AbuseIPDB** | [abuseipdb.com/register](https://www.abuseipdb.com/register) | ✅ 1 000 req/jour |
| **Telegram Bot** | [@BotFather](https://t.me/BotFather) | ✅ |
| **Shodan** (option) | [account.shodan.io/register](https://account.shodan.io/register) | ⚠️ limité |

---

## 1️⃣ Infrastructure Docker

### Installer Docker et Docker Compose

📚 Documentation officielle : **[docs.docker.com/engine/install/ubuntu](https://docs.docker.com/engine/install/ubuntu/)**

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y ca-certificates curl gnupg lsb-release

sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

sudo usermod -aG docker $USER && newgrp docker
docker --version && docker compose version
```

### Préparer et lancer la stack

```bash
cd SOAR/docker

# Dossiers montés par docker-compose
mkdir -p cortex/logs server-configs logs files ssl

# Requis par Elasticsearch, sinon le conteneur boucle au démarrage
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf

# Optionnel : URL réelle de MISP
echo "MISP_BASEURL=https://$(hostname -I | awk '{print $1}')" > .env

docker compose up -d
docker compose ps
```

Compter **3 à 5 minutes** pour que tout démarre.

```bash
docker compose logs -f thehive
docker compose logs -f cortex.local
```

### Vérifier les services

| Service | URL | Identifiants |
|---------|-----|--------------|
| TheHive | `http://VOTRE_IP:9000` | compte admin créé au 1er accès |
| Cortex | `http://VOTRE_IP:9001` | compte admin créé au 1er accès |
| MISP | `https://VOTRE_IP` | `admin@admin.test` / `admin` |
| MinIO | `http://VOTRE_IP:9002` | `minioadmin` / `minioadmin` |
| Elasticsearch | `http://VOTRE_IP:9200` | aucune authentification |

---

## 2️⃣ Configuration TheHive + Cortex + MISP

### TheHive — premier démarrage

📚 [Guide officiel TheHive 5](https://docs.strangebee.com/thehive/installation/) ·
[Documentation API](https://docs.strangebee.com/thehive/api-docs/)

1. Ouvrir `http://VOTRE_IP:9000` → **Create a new database**
2. Créer le compte administrateur
3. **Organisations** → créer votre organisation
4. **Users** → créer un utilisateur avec le profil `analyst`
5. Sur cet utilisateur : **API Keys** → **Create** → copier la clé
   → c'est la valeur de `THEHIVE_APIKEY` dans `.env`

> La clé doit appartenir à un utilisateur de l'organisation, pas au super-admin :
> le super-admin n'a pas accès aux cas.

### Cortex — configuration

📚 [Documentation Cortex](https://github.com/TheHive-Project/CortexDocs) ·
[Catalogue des analyseurs](https://github.com/TheHive-Project/Cortex-Analyzers)

1. Ouvrir `http://VOTRE_IP:9001` → **Update Database**
2. Créer le compte admin
3. **Organizations** → **Add Organization**
4. **Users** → **Add User** → rôles `read, analyze, orgadmin` → **Create API Key**
5. **Organizations** → votre org → **Analyzers** → activer et configurer :

| Analyseur | Type d'observable | Clé API requise |
|-----------|-------------------|-----------------|
| `AbuseIPDB_1_0` | ip | AbuseIPDB |
| `VirusTotal_GetReport_3_1` | ip, hash, domain, url | VirusTotal |
| `MaxMind_GeoIP_4_0` | ip | aucune |
| `Shodan_Host_1_0` | ip | Shodan |
| `OTXQuery_2_0` | ip, hash, domain, url | AlienVault OTX |
| `URLhaus_2_0` | url, domain, hash | aucune |

```bash
# Les analyseurs sont des conteneurs Docker : vérifier que Cortex peut les lancer
docker compose logs cortex.local | grep -i analyzer
docker images | grep cortexneurons
```

### Connecter TheHive ↔ Cortex

📚 [Guide d'intégration](https://docs.strangebee.com/thehive/administration/connectors/cortex/)

1. TheHive → **Organisation** → **Connectors** → **Cortex** → **Add Cortex server**
2. Renseigner :
   - **Name** : `cortex.local`
   - **URL** : `http://cortex.local:9001`
   - **API Key** : la clé Cortex
3. **Test** → doit afficher ✅

Vérification côté pipeline :

```bash
python start.py cortex
# Cortex : 8 analyseur(s) détecté(s) via TheHive
```

Si le compte est à `0`, le Service B ne pourra rien lancer : reprendre cette étape.

### MISP — configuration

📚 [Documentation MISP](https://www.misp-project.org/documentation/) ·
[Guide de l'API REST](https://www.misp-project.org/openapi/)

1. Ouvrir `https://VOTRE_IP` (accepter l'avertissement TLS)
2. Se connecter avec `admin@admin.test` / `admin` → **changer le mot de passe**
3. **Administration** → **Server Settings** → `MISP.baseurl` = votre URL
4. **Administration** → **List Auth Keys** → **Add authentication key** → copier
5. Dans `.env` : `MISP_ENABLED=true`, `MISP_URL`, `MISP_APIKEY`

Connecter TheHive à MISP : **Organisation** → **Connectors** → **MISP** →
**Add MISP server** (`https://misp.local` + clé API).
La variante par fichier est fournie dans [`docker/thehive/application.conf`](docker/thehive/application.conf).

---

## 3️⃣ Suricata IDS

📚 [Documentation Suricata](https://docs.suricata.io/) ·
[Écriture de règles](https://docs.suricata.io/en/latest/rules/intro.html) ·
[Suricata + Splunk](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html)

```bash
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt update && sudo apt install suricata -y
suricata --version
```

### Interface d'écoute

```bash
ip a                                    # repérer l'interface
sudo nano /etc/suricata/suricata.yaml
```

```yaml
af-packet:
  - interface: eth0        # remplacer par votre interface
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
```

### Règles personnalisées

Le fichier [`suricata/soc-custom.rules`](suricata/soc-custom.rules) détecte les
scans NMAP `-sS`, `-sT`, `-sA`, `-sX`, `-sU`, `-f` (vitesses T1 à T5) et les
shells Metasploit sur le port 4444.

```bash
sudo cp suricata/soc-custom.rules /etc/suricata/rules/
sudo nano /etc/suricata/suricata.yaml
```

```yaml
rule-files:
  - suricata.rules
  - soc-custom.rules       # ajouter cette ligne
```

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml    # test de configuration
sudo systemctl enable --now suricata
sudo tail -f /var/log/suricata/fast.log            # alertes en direct
```

### Vérifier la détection

```bash
# Depuis une autre machine du lab, contre le capteur Suricata
nmap -sS -T4 IP_DU_CAPTEUR
# → « POSSBL PORT SCAN (NMAP -sS) » doit apparaître dans fast.log
```

Ces alertes remontent à Splunk, puis au pipeline, qui **bloque l'IP scanneuse**
lorsque `ACTIVE_RESPONSE=true` et `BLOCK_ON_PORTSCAN=true`.

---

## 4️⃣ Splunk

📚 [Installer Splunk Enterprise](https://docs.splunk.com/Documentation/Splunk/latest/Installation/InstallonLinux) ·
[Alert actions – Webhook](https://docs.splunk.com/Documentation/Splunk/latest/Alert/Webhooks) ·
[Universal Forwarder](https://docs.splunk.com/Documentation/Forwarder/latest/Forwarder/Abouttheuniversalforwarder)

### Ingérer les logs Suricata

`inputs.conf` du Universal Forwarder installé sur le capteur :

```ini
[monitor:///var/log/suricata/eve.json]
disabled   = false
index      = suricata
sourcetype = suricata
```

### Créer le webhook

1. **Settings** → **Searches, Reports and Alerts** → créer/éditer une alerte
2. **Alert Actions** → **Add Actions** → **Webhook**
3. **URL** : `http://IP_DU_PIPELINE:5000/alert`

> Splunk n'envoie que du POST JSON : rien d'autre à configurer.

### Formats de payload acceptés

Le parseur accepte **4 formats**, plus un repli.

**Format 1 — standard avec `result`**
```json
{
  "search_name": "Brute Force SSH détecté",
  "severity": "high",
  "result": {
    "src_ip":  "1.2.3.4",
    "dest_ip": "192.168.1.10",
    "user":    "root",
    "host":    "serveur-prod",
    "count":   "15",
    "source":  "/var/log/auth.log",
    "_time":   "2026-01-15T10:30:00"
  }
}
```

**Format 2 — hash de fichier malveillant**
```json
{
  "search_name": "Fichier malveillant détecté",
  "severity": "critical",
  "result": {
    "host":      "poste-01",
    "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
    "process":   "malware.exe",
    "user":      "john.doe"
  }
}
```

**Format 3 — domaine C2**
```json
{
  "search_name": "DNS suspect",
  "severity": "medium",
  "result": { "src_ip": "192.168.1.50", "domain": "malware-c2.xyz", "host": "poste-05" }
}
```

**Format 4** — `result` contenant une chaîne JSON, et **repli** — payload plat
(`{"search_name": "...", "src_ip": "...", "host": "..."}`).

Champs reconnus : `src_ip`, `src`, `dest_ip`, `dest`, `user`, `host`, `source`,
`index`, `process_name`, `Image`, `file_hash`, `hash`, `md5`, `sha1`, `sha256`,
`domain`, `dest_domain`, `query`, `url`, `uri`, `CommandLine`, `EventCode`, `_time`.

---

## 5️⃣ Installation du pipeline Python

```bash
cd SOAR

# Environnement virtuel (recommandé)
python3 -m venv venv
source venv/bin/activate            # Linux / macOS
.\venv\Scripts\Activate.ps1         # Windows PowerShell

python start.py install
python start.py unit                # 135 tests unitaires, hors ligne
python start.py status
```

Trois dépendances seulement : `flask`, `requests`, `urllib3`.
**`thehive4py` n'est plus utilisé** — voir les commentaires de
[`requirements.txt`](requirements.txt).

---

## 6️⃣ Fichier .env

```bash
python start.py init      # copie .env.example → .env
nano .env
```

Le modèle complet et commenté est dans [`.env.example`](.env.example).
Variables essentielles :

| Variable | Défaut | Description |
|----------|--------|-------------|
| `THEHIVE_URL` | — | URL de TheHive, ex. `http://192.168.1.10:9000` |
| `THEHIVE_APIKEY` | — | Clé API d'un utilisateur `analyst` |
| `CORTEX_ENABLED` | `true` | Lancer les analyseurs Cortex automatiquement |
| `CORTEX_URL` / `CORTEX_APIKEY` | — | Secours si TheHive ne liste pas les analyseurs |
| `CORTEX_JOB_TIMEOUT` | `180` | Attente max d'un analyseur (s) |
| `CORTEX_MAX_ANALYZERS` | `5` | Analyseurs lancés par observable |
| `MISP_ENABLED` / `MISP_URL` / `MISP_APIKEY` | `false` | Threat Intelligence |
| `MISP_VERIFY_SSL` | `false` | Certificat auto-signé en lab |
| `VT_ENABLED` / `VT_APIKEY` | `true` | Enrichissement VirusTotal |
| `VT_MIN_DETECTIONS` | `2` | Seuil de verdict « malveillant » |
| `LISTEN_PORT` | `5000` | Port du webhook |
| `RATE_LIMIT_SEC` | `10` | Anti-flood sur alertes identiques |
| `POLL_INTERVAL` | `20` | Fréquence d'interrogation de TheHive (s) |
| `MIN_SEVERITY` | `1` | Sévérité minimale traitée |
| `RESPONSE_MIN_SEV` | `2` | Sévérité minimale pour bloquer |
| `ACTIVE_RESPONSE` | `false` | `true` = blocage firewall réel |
| `BLOCK_DURATION_MIN` | `10` | Durée d'un blocage (min) |
| `BLOCK_ON_BRUTEFORCE` | `true` | Bloquer les attaques par force brute |
| `BLOCK_ON_PORTSCAN` | `true` | Bloquer les scans de ports |
| `BLOCK_ON_THREAT` | `true` | Bloquer les autres catégories de menace |
| `BLOCK_ALL_IPS` | `false` | Bloquer aussi les IP internes |
| `TELEGRAM_*` | `false` | Notifications |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

> 💡 Les commentaires en fin de ligne (`BLOCK_DURATION_MIN=10  # minutes`) sont
> désormais tolérés : l'erreur historique `invalid literal for int()` ne peut
> plus se produire.

---

## 🚀 Démarrage

```bash
python start.py both        # Services A + B, redémarrage auto si crash
python start.py a           # Service A seul (webhook)
python start.py b           # Service B seul (responder)
```

### Activer le blocage réel

```bash
# dans .env : ACTIVE_RESPONSE=true

# Linux — root requis pour iptables
sudo python3 start.py both

# Windows — PowerShell en tant qu'administrateur
python start.py both
```

Si `ACTIVE_RESPONSE=true` sans les privilèges, le Service B le signale au
démarrage et `python start.py status` affiche `Privilèges : utilisateur standard`.

### Sortie attendue

```
══  Services A + B — lancement simultané  ══════════
  Lancement de Service A (webhook)...
  Lancement de Service B (responder)...
  ✓ Service A — PID 12345
  ✓ Service B — PID 12346

==============================================================
  SOC Pipeline — Service A  v8.0.0
==============================================================
  TheHive      : ✅ OK — http://192.168.1.10:9000
  VirusTotal   : ✅ OK
  Telegram     : ✅ OK
  Gmail        : ⚪ Désactivé
  Webhook      : http://0.0.0.0:5000/alert
==============================================================

==================================================================
  SOC Pipeline — Service B  v11.0.0  FULL AUTO
==================================================================
  TheHive     : http://192.168.1.10:9000
  VirusTotal  : ✅ actif
  Cortex      : ✅ 8 analyseur(s) via TheHive
  MISP        : ✅ actif
  Blocage     : 🔴 RÉEL (Administrateur)
  Cadence     : 10 min de blocage — poll 20s
==================================================================
```

---

## 🔄 Flux automatique détaillé

```
1️⃣  Suricata ou Splunk détecte une menace
      → POST /alert vers le Service A
           │
2️⃣  Service A
      → parse le payload (4 formats)
      → extrait les IoCs : IP, hash, domaine, URL, utilisateur, cmdline
      → interroge VirusTotal (IP publiques, hashes, domaines, URL)
      → si VT est formel, la sévérité est remontée à High
      → crée l'ALERTE TheHive avec ses observables
      → 📱 Telegram : « 🔴 ALERTE SOC — HIGH »
           │
3️⃣  Service B — poll toutes les 20 s
      → ignore les alertes déjà traitées (data/responder_state.json)
      → filtre sur MIN_SEVERITY
           │
4️⃣  Promotion ALERTE → CAS
      → POST /api/v1/alert/{id}/case, avec repli création + merge
      → 📱 Telegram : « 📁 Cas #42 créé »
           │
5️⃣  Pour CHAQUE observable (IP / hash / domaine) :
      │
      ├── a) Ajout de l'observable au cas TheHive
      │
      ├── b) 🔬 CORTEX — lancé en premier, en tâche de fond
      │        → analyseurs triés par priorité selon le type
      │          ip     : AbuseIPDB → VirusTotal → MaxMind → Shodan → OTX
      │          hash   : VirusTotal → Cuckoo → OTX
      │          domain : VirusTotal → DomainTools → OTX
      │        → un job Cortex par analyseur, résultats attendus en parallèle
      │        → verdicts écrits en commentaire dans le cas
      │        → tag « cortex-malicious » si un analyseur est formel
      │        → 📱 Telegram par analyseur
      │
      ├── c) 🦠 VIRUSTOTAL
      │        → IP publiques, hashes de fichiers, domaines
      │        → commentaire markdown + tag « vt-malicious »
      │
      ├── d) 🌐 MISP
      │        → lookup de l'IoC dans la base
      │        → si absent mais malveillant : publication automatique
      │
      └── e) 🚫 BLOCAGE FIREWALL
               → voir le tableau des déclencheurs ci-dessous
               → Windows : netsh advfirewall (règles IN + OUT)
               → Linux   : iptables -I INPUT/OUTPUT ... -j DROP
               → timer de déblocage automatique programmé
           │
6️⃣  Rapport markdown complet dans le cas
      → tableau IP / VT / MISP / blocage, hashes, domaines
      → journal de toutes les actions
      → sévérité du cas remontée et tag « confirmed-malicious »
           │
7️⃣  ⏱ Après BLOCK_DURATION_MIN
      → règle firewall supprimée automatiquement
      → 📱 Telegram : « ✅ IP débloquée »
```

---

## 🚫 Réponse active : quoi est bloqué et quand

Le Service B classe chaque alerte en **catégories de menace**, à partir des tags
posés par le Service A et d'une recherche par mots-clés dans le titre et la
description.

| Catégorie | Déclencheurs typiques | Bloque si |
|-----------|----------------------|-----------|
| `brute_force` | tag `brute_force`, « failed password », « invalid user », EventCode 4625 | `BLOCK_ON_BRUTEFORCE=true` |
| `port_scan` | « POSSBL PORT SCAN (NMAP -sS) », nmap, masscan, zmap, attempted-recon | `BLOCK_ON_PORTSCAN=true` |
| `exploitation` | Metasploit, meterpreter, reverse shell, port 4444, `CVE-…` | `BLOCK_ON_THREAT=true` |
| `lateral_movement` | psexec, wmic, winrm, pass-the-hash, SMB, RDP | `BLOCK_ON_THREAT=true` |
| `credential_dumping` | mimikatz, lsass, secretsdump, ntds.dit | `BLOCK_ON_THREAT=true` |
| `ransomware` | ransom, `vssadmin delete`, `wbadmin delete` | `BLOCK_ON_THREAT=true` |
| `malware` | tag `vt-malicious`, C2, botnet, trojan | `BLOCK_ON_THREAT=true` |
| `exfiltration` | exfil, DLP, large upload | `BLOCK_ON_THREAT=true` |
| `privilege_escalation` | EventCode 4672, escalade de privilèges | `BLOCK_ON_THREAT=true` |
| **VirusTotal** | ≥ `VT_MIN_DETECTIONS` moteurs positifs, ou réputation ≤ -10 | toujours |
| **MISP** | l'IoC existe déjà dans MISP | toujours |

### Garde-fous

Une IP n'est bloquée que si **toutes** ces conditions sont réunies :

1. `ACTIVE_RESPONSE=true` — sinon simulation journalisée ;
2. le processus a les droits **Administrateur** (Windows) ou **root** (Linux) ;
3. la sévérité du cas est ≥ `RESPONSE_MIN_SEV` (défaut 2 = Medium) ;
4. l'IP est publique, ou `BLOCK_ALL_IPS=true` pour inclure les IP internes ;
5. l'IP n'est pas déjà bloquée.

> ⚠️ `BLOCK_ALL_IPS=true` peut couper un poste interne du réseau. À réserver
> aux labs.

### Ce qui n'est PAS fait automatiquement

Le pipeline **ne supprime aucun fichier** sur les machines surveillées : il n'y
a pas d'agent EDR déployé. Un hash malveillant est enrichi, tagué
`vt-malicious`, commenté dans le cas, publié dans MISP et notifié — la mise en
quarantaine reste une action de l'analyste (ou d'un responder Cortex à ajouter).

### Vérifier les règles posées

```bash
# Linux
sudo iptables -L INPUT -n --line-numbers | grep DROP

# Windows
netsh advfirewall firewall show rule name=all | findstr SOC_BLOCK
```

```bash
python start.py list                # IPs bloquées + temps restant
python start.py unblock 1.2.3.4     # déblocage manuel immédiat
```

---

## 🌐 Endpoints du Service A

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `POST` | `/alert` | **Webhook principal** — alertes Splunk |
| `GET` | `/health` | État du service + connexion TheHive |
| `GET` | `/test` | Envoie une vraie alerte de test (IP Tor connue de VT) |
| `GET` | `/telegram-test` | Teste le bot Telegram |
| `GET` | `/vt-test` | Teste la clé VirusTotal |
| `GET` | `/debug` | 10 derniers payloads reçus |
| `GET` | `/stats` | Compteurs : reçus, créés, doublons, erreurs |

```bash
curl http://localhost:5000/health
curl http://localhost:5000/test
curl http://localhost:5000/vt-test

curl -X POST http://localhost:5000/alert \
  -H "Content-Type: application/json" \
  -d '{
    "search_name": "Test Brute Force SSH",
    "severity": "high",
    "result": {
      "src_ip": "185.220.101.50",
      "user":   "root",
      "host":   "serveur-01",
      "count":  "50",
      "source": "/var/log/auth.log"
    }
  }'
```

Codes de réponse de `/alert` : `201 created`, `200 duplicate`,
`200 rate_limited`, `400` payload invalide, `502` TheHive injoignable.

---

## 🖥️ Commandes CLI

```bash
python start.py                  # menu interactif
python start.py install          # installer les dépendances
python start.py init             # créer .env depuis .env.example
python start.py a                # Service A seul
python start.py b                # Service B seul
python start.py both             # A + B avec redémarrage automatique
python start.py status           # état complet de l'intégration
python start.py test             # tests end-to-end (services lancés)
python start.py unit             # 135 tests unitaires (hors ligne)
python start.py telegram         # message de test Telegram
python start.py telegram-config  # configuration Telegram guidée
python start.py list             # IPs actuellement bloquées
python start.py unblock 1.2.3.4  # débloquer une IP
python start.py cortex           # analyseurs Cortex détectés
python start.py logs             # fin des journaux
```

---

## 📱 Notifications Telegram

📚 [Documentation de l'API Bot](https://core.telegram.org/bots/api) ·
[Créer un bot](https://core.telegram.org/bots/features#botfather)

```bash
python start.py telegram-config    # assistant : token, chat ID, message de test
```

Manuellement :

1. Telegram → **@BotFather** → `/newbot` → récupérer le **token**
2. Envoyer `/start` à votre bot
3. Ouvrir `https://api.telegram.org/botVOTRE_TOKEN/getUpdates` → relever
   `result[0].message.chat.id`
4. Dans `.env` :
   ```ini
   TELEGRAM_ENABLED=true
   TELEGRAM_TOKEN=1234567890:AAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   TELEGRAM_CHAT_ID=123456789
   ```

| Emoji | Événement |
|-------|-----------|
| 🚀 | Service démarré |
| 🔴 🟠 🟡 🟢 | Alerte reçue (selon la sévérité) |
| 📁 | Cas créé dans TheHive |
| 🦠 | Résultat VirusTotal |
| 🔬 | Résultat d'un analyseur Cortex |
| 🌐 | IoC trouvé dans MISP |
| 🚫 | IP bloquée |
| ⚠️ | Blocage simulé (`ACTIVE_RESPONSE=false`) |
| ❌ | Blocage impossible ou cas non créé |
| ✅ | IP débloquée |

---

## 🧪 Tests

```bash
python start.py unit             # les 3 suites
python tests/test_soc_common.py  # 33 tests — env, client TheHive, Telegram
python tests/test_service_a.py   # 54 tests — parsing, VT, endpoints Flask
python tests/test_service_b.py   # 48 tests — menaces, blocage, Cortex, état
```

Les tests sont **entièrement hors ligne** : aucune requête réseau, aucune règle
firewall posée, aucun `.env` lu (`SOC_SKIP_DOTENV=1`), fichiers temporaires
confinés dans `tests/.tmp/`.

```
  RÉSULTAT GLOBAL : toutes les suites sont vertes
```

Tests end-to-end, avec les services lancés :

```bash
python start.py both      # dans un terminal
python start.py test      # dans un autre
```

---

## 🐛 Dépannage

### `ModuleNotFoundError: No module named 'flask'`

```bash
python start.py install
```

### Le Service A plante à l'import sous Windows

Symptôme historique : l'interpréteur se ferme sans message, ou `magic` échoue.
Cause : `thehive4py` importe `libmagic`, absent de Windows.
**Cette version n'utilise plus thehive4py** — si l'erreur persiste, c'est qu'un
ancien `service_splunk_to_thehive.py` traîne encore : supprimez-le.

### Aucun analyseur Cortex ne se lance

```bash
python start.py cortex
```

- `0 analyseur` → le connecteur Cortex n'est pas configuré dans TheHive
  (**Organisation → Connectors → Cortex → Test**) ;
- analyseurs listés mais jobs en échec → vérifier les clés API des analyseurs
  dans Cortex, et que le socket Docker est bien monté :
  ```bash
  docker compose logs cortex.local --tail 100
  docker ps | grep cortexneurons
  ```
- Cortex démarré après le Service B : le registre se rafraîchit tout seul au
  bout de 5 minutes, ou immédiatement avec `python start.py cortex`.

### Cortex — `python3: No such file or directory`

```bash
sudo apt install python3 python3-pip -y
sudo ln -sf /usr/bin/python3 /usr/local/bin/python3
docker compose restart cortex.local
```

### Le Service B ne crée pas de cas

```bash
tail -50 logs/service_b.log                        # Linux
Get-Content logs/service_b.log -Tail 50            # Windows

# Tester l'API TheHive à la main
curl -X POST "http://VOTRE_IP:9000/api/v1/query?name=list-alerts" \
  -H "Authorization: Bearer VOTRE_CLE" \
  -H "Content-Type: application/json" \
  -d '{"query":[{"_name":"listAlert"},{"_name":"page","from":0,"to":5}]}'
```

Une erreur `401` signifie une clé invalide ; une clé de super-admin ne voit
aucun cas — utiliser un utilisateur `analyst` de l'organisation.

### Le blocage d'IP ne fonctionne pas

```bash
python start.py status      # doit afficher « Privilèges : ✓ admin/root »
```

| Cause | Correctif |
|-------|-----------|
| `ACTIVE_RESPONSE=false` | passer à `true` dans `.env` |
| Pas administrateur (Windows) | PowerShell → « Exécuter en tant qu'administrateur » |
| Pas root (Linux) | `sudo python3 start.py both` |
| `iptables` absent | `sudo apt install iptables -y` |
| Sévérité trop basse | abaisser `RESPONSE_MIN_SEV` |
| IP interne ignorée | `BLOCK_ALL_IPS=true` (labs uniquement) |

### MISP — timeout de connexion

```bash
docker compose ps misp.local
docker compose logs misp.local --tail 50
curl -k -H "Authorization: VOTRE_CLE" https://VOTRE_IP_MISP/servers/getVersion
```

Certificat auto-signé → `MISP_VERIFY_SSL=false` dans `.env`.

### `invalid literal for int()` au démarrage

Corrigé : les commentaires en fin de ligne du `.env` sont maintenant tolérés.
Si l'erreur revient, la valeur ne contient aucun chiffre du tout.

### Suivre les journaux

```bash
python start.py logs
tail -f logs/service_a.log logs/service_b.log            # Linux
Get-Content logs/service_a.log -Wait -Tail 20            # Windows
```

---

## 🔐 Sécurité

> ⚠️ **Ne jamais committer le fichier `.env`** — il contient toutes vos clés API.

`.gitignore` protège déjà `.env`, `data/`, `logs/`, `*.log`, les blacklists et
l'état du responder.

Bonnes pratiques :

- clés API avec le **minimum de permissions** nécessaires ;
- en production, webhook derrière **nginx + HTTPS** et filtrage par IP source ;
- `MISP_VERIFY_SSL=true` et `THEHIVE_VERIFY_SSL=true` avec de vrais certificats ;
- changer immédiatement les mots de passe par défaut de MISP, MinIO et le
  `--secret` de TheHive dans `docker-compose.yml` ;
- commencer avec `ACTIVE_RESPONSE=false` pour observer ce qui *serait* bloqué
  avant d'activer le blocage réel ;
- si une clé a fuité (dépôt public, capture d'écran…), la **révoquer et la
  régénérer** immédiatement.

---

## 📚 Références et documentation détaillée

### TheHive / Cortex / MISP

| Ressource | Lien |
|-----------|------|
| Documentation TheHive 5 | [docs.strangebee.com/thehive](https://docs.strangebee.com/thehive/) |
| Installation TheHive (Docker, DEB, RPM) | [docs.strangebee.com/thehive/installation](https://docs.strangebee.com/thehive/installation/) |
| API REST TheHive v1 | [docs.strangebee.com/thehive/api-docs](https://docs.strangebee.com/thehive/api-docs/) |
| Connecteurs TheHive (Cortex, MISP) | [docs.strangebee.com/thehive/administration/connectors](https://docs.strangebee.com/thehive/administration/connectors/) |
| Documentation Cortex | [github.com/TheHive-Project/CortexDocs](https://github.com/TheHive-Project/CortexDocs) |
| Catalogue des analyseurs Cortex | [github.com/TheHive-Project/Cortex-Analyzers](https://github.com/TheHive-Project/Cortex-Analyzers) |
| Écrire son propre analyseur | [github.com/TheHive-Project/CortexDocs/blob/master/api/how-to-create-an-analyzer.md](https://github.com/TheHive-Project/CortexDocs/blob/master/api/how-to-create-an-analyzer.md) |
| Documentation MISP | [misp-project.org/documentation](https://www.misp-project.org/documentation/) |
| API REST MISP (OpenAPI) | [misp-project.org/openapi](https://www.misp-project.org/openapi/) |
| Livre MISP (installation, tuning) | [misp.github.io/MISP/](https://misp.github.io/MISP/) |
| MISP Docker (image utilisée ici) | [github.com/coolacid/docker-misp](https://github.com/coolacid/docker-misp) |

### Détection : Suricata et Splunk

| Ressource | Lien |
|-----------|------|
| Documentation Suricata | [docs.suricata.io](https://docs.suricata.io/) |
| Format des règles Suricata | [docs.suricata.io/en/latest/rules/intro.html](https://docs.suricata.io/en/latest/rules/intro.html) |
| Sortie EVE JSON (pour Splunk) | [docs.suricata.io/en/latest/output/eve/eve-json-output.html](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html) |
| Réglage des performances Suricata | [docs.suricata.io/en/latest/performance/index.html](https://docs.suricata.io/en/latest/performance/index.html) |
| Règles Emerging Threats (gratuites) | [rules.emergingthreats.net](https://rules.emergingthreats.net/open/suricata/) |
| Installer Splunk Enterprise | [docs.splunk.com/…/InstallonLinux](https://docs.splunk.com/Documentation/Splunk/latest/Installation/InstallonLinux) |
| Alertes et webhooks Splunk | [docs.splunk.com/…/Webhooks](https://docs.splunk.com/Documentation/Splunk/latest/Alert/Webhooks) |
| Universal Forwarder | [docs.splunk.com/…/Abouttheuniversalforwarder](https://docs.splunk.com/Documentation/Forwarder/latest/Forwarder/Abouttheuniversalforwarder) |
| Langage de recherche SPL | [docs.splunk.com/Documentation/SplunkCloud/latest/SearchReference](https://docs.splunk.com/Documentation/SplunkCloud/latest/SearchReference/WhatsInThisManual) |

### Threat Intelligence et enrichissement

| Ressource | Lien |
|-----------|------|
| API VirusTotal v3 | [docs.virustotal.com/reference/overview](https://docs.virustotal.com/reference/overview) |
| Quotas VirusTotal (offre gratuite) | [docs.virustotal.com/reference/public-vs-premium-api](https://docs.virustotal.com/reference/public-vs-premium-api) |
| API AbuseIPDB | [docs.abuseipdb.com](https://docs.abuseipdb.com/) |
| AlienVault OTX | [otx.alienvault.com/api](https://otx.alienvault.com/api) |
| Shodan | [developer.shodan.io](https://developer.shodan.io/) |
| URLhaus (abuse.ch) | [urlhaus.abuse.ch/api](https://urlhaus.abuse.ch/api/) |
| MaxMind GeoIP | [dev.maxmind.com/geoip](https://dev.maxmind.com/geoip/) |

### Infrastructure et outils

| Ressource | Lien |
|-----------|------|
| Installer Docker Engine | [docs.docker.com/engine/install](https://docs.docker.com/engine/install/) |
| Docker Compose | [docs.docker.com/compose](https://docs.docker.com/compose/) |
| `vm.max_map_count` (Elasticsearch) | [elastic.co/guide/…/vm-max-map-count.html](https://www.elastic.co/guide/en/elasticsearch/reference/current/vm-max-map-count.html) |
| iptables — manuel | [netfilter.org/documentation](https://www.netfilter.org/documentation/) |
| `netsh advfirewall` — référence | [learn.microsoft.com/…/netsh-advfirewall-firewall-control-firewall-behavior](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/netsh-advfirewall-firewall-control-firewall-behavior) |
| API Bot Telegram | [core.telegram.org/bots/api](https://core.telegram.org/bots/api) |
| Mots de passe d'application Gmail | [support.google.com/accounts/answer/185833](https://support.google.com/accounts/answer/185833) |
| Documentation Flask | [flask.palletsprojects.com](https://flask.palletsprojects.com/) |
| Documentation Requests | [requests.readthedocs.io](https://requests.readthedocs.io/) |

### Méthodologie SOC

| Ressource | Lien |
|-----------|------|
| MITRE ATT&CK | [attack.mitre.org](https://attack.mitre.org/) |
| Guide NIST de gestion des incidents (SP 800-61) | [csrc.nist.gov/pubs/sp/800/61/r2/final](https://csrc.nist.gov/pubs/sp/800/61/r2/final) |
| Sigma — règles de détection portables | [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) |
| Atomic Red Team — tests de détection | [github.com/redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) |
| The DFIR Report — cas réels | [thedfirreport.com](https://thedfirreport.com/) |

### Tutoriels vidéo

| Ressource | Lien |
|-----------|------|
| TheHive + Cortex + MISP — installation complète | [youtu.be/ovUuNQsW_FQ](https://youtu.be/ovUuNQsW_FQ) |
| Chaîne officielle StrangeBee | [youtube.com/@strangebee](https://www.youtube.com/@strangebee) |

---

## 📌 Journal des versions

| Version | Composant | Changements |
|---------|-----------|-------------|
| **v8.0.0** | Service A | Client TheHive REST v1 natif ; fin de `thehive4py` ; console UTF-8 Windows ; `.env` tolérant aux commentaires ; `datetime.utcnow()` remplacé ; anti-doublon sans fuite mémoire ; verrous sur les compteurs |
| **v11.0.0** | Service B | Découverte Cortex via TheHive + rafraîchissement auto ; blocage étendu (scan de ports, exploitation, latéral, credential dumping, rançongiciel…) ; plus de règle firewall posée en simulation ; `MIN_SEVERITY` / `RESPONSE_MIN_SEV` / `BLOCK_ALL_IPS` réellement appliqués ; MISP en TLS configurable ; état écrit de façon atomique |
| — | start.py | Chemins `src/` corrigés ; menu itératif (plus de récursion) ; commandes `init`, `unit`, `list`, `unblock`, `cortex`, `logs` ; contrôle des privilèges ; stdlib uniquement |
| — | Projet | Arborescence `docker/ src/ suricata/ tests/ data/ logs/` ; 135 tests unitaires ; LICENSE MIT ; clé API en dur retirée de la configuration TheHive |

---

<div align="center">

**SOC Automation Pipeline** — lab SOC personnel

*Automatiser la détection et la réponse aux incidents de sécurité*

⭐ Une étoile si le projet vous a aidé

</div>
