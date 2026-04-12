# 🛡️ SOC Automation Pipeline

**Splunk → TheHive → Cortex + MISP + VirusTotal → Active Response + Telegram**

Pipeline SOC complet et autonome : détection dans Splunk, création automatique de cas dans TheHive, enrichissement multi-sources (VirusTotal, Cortex, MISP) et réponse active aux incidents.

---

## 📋 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SOC Automation Pipeline                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  SPLUNK          SERVICE A              THEHIVE             │
│  (SIEM)    →    Webhook Flask    →    Alerte créée          │
│  Alerte         :5000/alert          + Artifacts IOC        │
│                      ↓                     ↓               │
│              VirusTotal v3          SERVICE B               │
│              (enrichissement)       Poll 30s                │
│                      ↓                  ↓                  │
│              THEHIVE Alert         Cortex + MISP + VT       │
│              Sévérité              Analyse IOC               │
│              escaladée si VT       Tags + Commentaire        │
│                      ↓                  ↓                  │
│              TELEGRAM              TELEGRAM                  │
│              Notification          Rapport analyse           │
│              immédiate             + Actions prises          │
│                                         ↓                  │
│                                    iptables block           │
│                                    (si activé)              │
└─────────────────────────────────────────────────────────────┘
```

---

## 🗂️ Structure du projet

```
soc-pipeline/
├── src/
│   ├── service_splunk_to_thehive.py   # Service A — Webhook Splunk→TheHive + VT
│   └── service_thehive_responder.py   # Service B — Responder Cortex+MISP+VT
├── .env.example                        # Template de configuration
├── .env                                # Votre config (ne pas committer !)
├── requirements.txt                    # Dépendances Python
├── start.py                            # Lanceur universel (menu interactif)
└── README.md                           # Ce fichier
```

---

## ⚡ Démarrage rapide (5 minutes)

### 1. Cloner et installer

```bash
git clone https://github.com/VOTRE_USER/soc-pipeline.git
cd soc-pipeline

# Installer les dépendances
pip install -r requirements.txt
# ou sur Ubuntu/Debian :
pip3 install -r requirements.txt --break-system-packages
```

### 2. Configurer

```bash
cp .env.example .env
nano .env
```

Remplir au minimum :
- `THEHIVE_APIKEY` — clé API TheHive
- `VT_APIKEY` — clé VirusTotal (gratuite sur virustotal.com)
- `TELEGRAM_TOKEN` + `TELEGRAM_CHAT_ID` (optionnel mais recommandé)

### 3. Lancer

```bash
# Menu interactif (recommandé)
python start.py

# Ou directement :
python start.py a      # Service A uniquement (webhook)
python start.py both   # Service A + B ensemble
```

### 4. Configurer Splunk

Dans Splunk (`http://10.2.3.114:8000`) :
```
Settings → Searches, Reports, Alerts → votre alerte
→ Add Actions → Webhook
→ URL : http://VOTRE-IP:5000/alert
```

### 5. Tester

```bash
# Test santé
curl http://localhost:5000/health

# Test alerte → TheHive (avec VT si configuré)
curl http://localhost:5000/test

# Test Telegram
curl http://localhost:5000/telegram-test

# Test VirusTotal
curl http://localhost:5000/vt-test
```

---

## 🔧 Configuration détaillée

### Variables d'environnement (`.env`)

| Variable | Description | Défaut |
|----------|-------------|--------|
| `THEHIVE_URL` | URL TheHive | `http://10.2.3.122:9000` |
| `THEHIVE_APIKEY` | Clé API TheHive | — |
| `CORTEX_URL` | URL Cortex | `http://10.2.3.122:9001` |
| `CORTEX_APIKEY` | Clé API Cortex | — |
| `MISP_URL` | URL MISP | `https://10.2.3.121` |
| `MISP_APIKEY` | Clé API MISP | — |
| `MISP_ENABLED` | Activer MISP | `true` |
| `VT_ENABLED` | Activer VirusTotal | `true` |
| `VT_APIKEY` | **Clé VirusTotal v3** (gratuite) | — |
| `VT_MIN_DETECTIONS` | Seuil malveillant VT | `2` |
| `LISTEN_PORT` | Port du webhook | `5000` |
| `RATE_LIMIT_SEC` | Anti-flood (sec) | `10` |
| `POLL_INTERVAL` | Fréquence poll TheHive | `30` |
| `MIN_SEVERITY` | Sévérité min à traiter | `3` (High) |
| `ACTIVE_RESPONSE` | Blocage iptables | `false` |
| `TELEGRAM_ENABLED` | Notifications Telegram | `false` |
| `TELEGRAM_TOKEN` | Token BotFather | — |
| `TELEGRAM_CHAT_ID` | Chat ID Telegram | — |
| `NOTIFY_MIN_SEV` | Seuil notif Telegram | `3` (High) |
| `GMAIL_ENABLED` | Notifications Gmail | `false` |

---

## 🦠 VirusTotal — Configuration

VirusTotal v3 est intégré dans **les deux services** :

**Service A** : enrichit les IOC de chaque alerte Splunk avant création dans TheHive
- Analyse : IP publiques, hashs, domaines, URLs
- Escalade automatique de sévérité si VT détecte une menace
- Résultats dans la description de l'alerte TheHive

**Service B** : analyse les observables de chaque cas TheHive
- Verdict par observable dans le commentaire du cas
- Tags automatiques : `vt-malicious`, `vt-suspicious`

**Obtenir une clé gratuite** :
1. Aller sur [virustotal.com](https://www.virustotal.com/gui/join-us)
2. Créer un compte
3. Menu profil → API Key → copier la clé
4. Limite gratuite : **500 requêtes/jour**, 4 req/min

```bash
# Tester votre clé
curl -H "x-apikey: VOTRE_CLE" https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8
```

---

## 📡 Service A — Webhook Splunk → TheHive

### Endpoints disponibles

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/alert` | POST | Webhook principal Splunk |
| `/health` | GET | État complet du service |
| `/test` | GET | Alerte de test (avec VT) |
| `/telegram-test` | GET | Tester Telegram |
| `/vt-test` | GET | Tester VirusTotal |
| `/debug` | GET | 50 derniers payloads reçus |
| `/stats` | GET | Statistiques |

### Formats Splunk supportés

Le service détecte automatiquement 4 formats :

```json
// Format 1 : result dict (standard Splunk)
{"search_name":"SSH BF","severity":"high","result":{"src_ip":"1.2.3.4"}}

// Format 2 : results list
{"search_name":"..","results":[{"src_ip":"1.2.3.4"}]}

// Format 3 : payload plat
{"search_name":"..","severity":"high","src_ip":"1.2.3.4","host":"srv01"}

// Format 4 : result comme JSON string
{"search_name":"..","result":"{\"src_ip\":\"1.2.3.4\"}"}
```

### IOC extraits automatiquement

| Champ Splunk | Type TheHive | VT analysé |
|-------------|-------------|-----------|
| `src_ip`, `dest_ip` | `ip` | ✅ (IPs publiques) |
| `file_hash`, `md5`, `sha256` | `hash` | ✅ |
| `domain`, `dest_domain` | `domain` | ✅ |
| `url`, `uri` | `url` | ✅ |
| `user`, `username` | `other` | — |
| `CommandLine` | `other` | — |

### Sévérité Splunk → TheHive

| Splunk | TheHive | Telegram |
|--------|---------|---------|
| `info` / `low` | Low (1) | Non |
| `medium` | Medium (2) | Non |
| `high` | High (3) | ✅ |
| `critical` | Critical (4) | ✅ |

> **Auto-escalade** : si VirusTotal détecte une menace, la sévérité monte automatiquement à High (3) minimum.

---

## 🤖 Service B — TheHive Responder

Le Service B poll TheHive toutes les 30s et traite les cas High/Critical non encore traités.

### Pipeline de traitement

```
Cas TheHive détecté
        ↓
Récupération des observables
        ↓
[VirusTotal] Analyse IP/hash/domain/URL
        ↓
[Cortex] Analyzers sur chaque observable
   AbuseIPDB + VirusTotal + Shodan (IP)
   VirusTotal + Maltiverse (hash)
   PassiveTotal + VirusTotal (domain)
        ↓
[MISP] Lookup IOC + Push si nouveau malveillant
        ↓
Tags automatiques : malicious / suspicious / clean / vt-malicious / misp-hit
        ↓
Commentaire de synthèse dans TheHive
        ↓
[Telegram] Rapport d'analyse
        ↓
[iptables] Blocage IP (si ACTIVE_RESPONSE=true + Critical)
```

### Réponse active iptables

> ⚠️ **Désactivée par défaut** (`ACTIVE_RESPONSE=false`).
> Activer uniquement sur Linux avec droits root.

**Protection absolue** : les plages IP internes ne sont **JAMAIS** bloquées :
- `10.0.0.0/8`
- `192.168.0.0/16`
- `172.16.0.0/12`
- `127.0.0.0/8`

**Condition de blocage** :
- Cas de sévérité Critical (4) **ET/OU** Cortex/VT détecte malveillant **ET/OU** MISP hit
- L'IP doit être externe et valide

```bash
# Voir les IPs bloquées
cat ip_blacklist.txt

# Débloquer une IP manuellement
iptables -D INPUT  -s 185.220.101.50 -j DROP
iptables -D OUTPUT -d 185.220.101.50 -j DROP
```

---

## 📱 Telegram — Configuration

### Créer le bot

```
1. Ouvrir Telegram → chercher @BotFather
2. Envoyer : /newbot
3. Nom : SOC_Rachad
4. Username : SOC_Rachad_Bot  (doit finir par "bot")
5. Copier le TOKEN affiché
```

### Récupérer le Chat ID

```bash
# 1. Envoyer /start au bot dans Telegram
# 2. Récupérer le chat_id :
curl https://api.telegram.org/botVOTRE_TOKEN/getUpdates
# Chercher "id" dans la réponse
```

### Configuration rapide via menu

```bash
python start.py telegram-config
```

### Test

```bash
# Via menu
python start.py telegram

# Via endpoint
curl http://localhost:5000/telegram-test
```

---

## 🚀 Déploiement production (systemd)

### Copier les fichiers

```bash
sudo mkdir -p /opt/soc
sudo cp src/service_splunk_to_thehive.py /opt/soc/
sudo cp src/service_thehive_responder.py /opt/soc/
sudo cp requirements.txt .env /opt/soc/
sudo chmod 600 /opt/soc/.env

# Environnement Python
cd /opt/soc
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```

### Service A — `/etc/systemd/system/soc-service-a.service`

```ini
[Unit]
Description=SOC Pipeline Service A — Splunk to TheHive
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/soc
EnvironmentFile=/opt/soc/.env
ExecStart=/opt/soc/venv/bin/python3 service_splunk_to_thehive.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### Service B — `/etc/systemd/system/soc-service-b.service`

```ini
[Unit]
Description=SOC Pipeline Service B — TheHive Responder
After=network.target soc-service-a.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/soc
EnvironmentFile=/opt/soc/.env
ExecStart=/opt/soc/venv/bin/python3 service_thehive_responder.py
Restart=always
RestartSec=15
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### Activer

```bash
sudo systemctl daemon-reload
sudo systemctl enable  soc-service-a soc-service-b
sudo systemctl start   soc-service-a soc-service-b
sudo systemctl status  soc-service-a soc-service-b

# Logs en temps réel
journalctl -u soc-service-a -f
journalctl -u soc-service-b -f
```

---

## 🐳 Docker

```bash
# Lancer avec Docker Compose
docker compose up -d
docker compose logs -f
```

`docker-compose.yml` :
```yaml
services:
  soc-service-a:
    build:
      context: .
      dockerfile: Dockerfile.a
    env_file: .env
    ports:
      - "5000:5000"
    restart: unless-stopped

  soc-service-b:
    build:
      context: .
      dockerfile: Dockerfile.b
    env_file: .env
    network_mode: host
    privileged: true
    restart: unless-stopped
```

`Dockerfile.a` :
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/service_splunk_to_thehive.py .
EXPOSE 5000
CMD ["python3", "service_splunk_to_thehive.py"]
```

`Dockerfile.b` :
```dockerfile
FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y iptables && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/service_thehive_responder.py .
CMD ["python3", "service_thehive_responder.py"]
```

---

## ⚡ Alertes Splunk recommandées

### Brute Force SSH Linux (121 events détectés)

```spl
index=linux_logs source="/var/log/auth.log" "Failed password"
| rex "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "for (?:invalid user )?(?P<user>\S+) from"
| stats count by src_ip, user, host
| where count > 5
| eval severity="high", source="/var/log/auth.log"
```

### Brute Force Windows (EventCode 4625)

```spl
index=windows_logs EventCode=4625
| stats count by src_ip, user, host
| where count > 5
| eval severity="high"
```

### Processus suspects (mimikatz, psexec...)

```spl
index=windows_logs EventCode=4688
| eval suspect=if(match(process_name,"(?i)mimikatz|psexec|pwdump|lsass|procdump"),1,0)
| where suspect=1
| eval severity="critical"
```

> Pour chaque alerte : **Save As → Alert → Planifié toutes les 5 min → Add Actions → Webhook → `http://VOTRE-IP:5000/alert`**

---

## 🔍 Diagnostic

```bash
# Menu complet
python start.py status

# Tests rapides
python start.py test      # test end-to-end complet
python start.py telegram  # test Telegram
python start.py a         # voir logs Service A au démarrage

# Via endpoints
curl http://localhost:5000/health        | python3 -m json.tool
curl http://localhost:5000/vt-test       | python3 -m json.tool
curl http://localhost:5000/telegram-test | python3 -m json.tool
curl http://localhost:5000/debug         | python3 -m json.tool
curl http://localhost:5000/stats         | python3 -m json.tool

# Logs
tail -f service_a.log
tail -f service_b.log | python3 -m json.tool

# State Service B
cat responder_state.json | python3 -m json.tool
```

---

## 🏗️ Infrastructure testée

| Composant | IP | Version |
|-----------|-----|---------|
| Splunk Enterprise | 10.2.3.114:8000 | 9.x |
| TheHive | 10.2.3.122:9000 | 5.x |
| Cortex | 10.2.3.122:9001 | 3.x |
| MISP | 10.2.3.121 | 2.4+ |
| VirusTotal API | cloud | v3 |

---

## 🧪 Tests

```bash
# Tests unitaires (24 tests)
python3 tests/test_service_a.py
python3 tests/test_service_b.py

# Test intégration complète (Service A doit tourner)
python start.py test
```

---

## 📄 Licence

MIT — Rachad Lab SOC Pipeline

---

## 📞 Support

1. Vérifier `python start.py status`
2. Consulter les logs : `tail -f service_a.log`
3. Endpoint debug : `curl http://localhost:5000/debug`
4. Ouvrir une issue GitHub

---

*SOC Automation Pipeline v7.0.0 — Rachad Lab*
