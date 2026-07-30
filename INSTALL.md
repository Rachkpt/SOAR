# 📦 Guide d'installation — SOC Automation Pipeline

Toutes les commandes du projet sont ici. Pour comprendre ce que fait le pipeline
avant de l'installer, lisez d'abord le **[README](README.md)**.

---

## 🎬 Vidéos de référence

Ces deux tutoriels couvrent l'installation et l'intégration de la stack. Ils
sont la meilleure entrée en matière si vous partez de zéro.

| Sujet | Lien |
|-------|------|
| **Installer TheHive, MISP et Cortex** | **[youtu.be/Vr4flc55S5c](https://youtu.be/Vr4flc55S5c)** |
| **Intégrer les trois ensemble** | **[youtu.be/ovUuNQsW_FQ](https://youtu.be/ovUuNQsW_FQ)** |

Le `docker-compose.yml` de ce dépôt reprend cette architecture, avec quelques
correctifs (voir [§1](#1️⃣-infrastructure-docker)).

---

## 📖 Sommaire

- [Prérequis](#-prérequis)
- [1. Infrastructure Docker](#1️⃣-infrastructure-docker)
- [2. TheHive](#2️⃣-thehive)
- [3. Cortex](#3️⃣-cortex)
- [4. MISP](#4️⃣-misp)
- [5. Suricata](#5️⃣-suricata)
- [6. Splunk](#6️⃣-splunk)
- [7. Le pipeline Python](#7️⃣-le-pipeline-python)
- [8. Le fichier .env](#8️⃣-le-fichier-env)
- [Activer la réponse active](#-activer-la-réponse-active)
- [Toutes les commandes](#-toutes-les-commandes)
- [Endpoints du Service A](#-endpoints-du-service-a)
- [Tests](#-tests)
- [Dépannage](#-dépannage)
- [Sécurité](#-sécurité)
- [Documentation de référence](#-documentation-de-référence)

---

## ✅ Prérequis

### Systèmes supportés

| OS | Statut |
|----|--------|
| Ubuntu 20.04 / 22.04 / 24.04 | ✅ Recommandé pour le serveur Docker |
| Debian 11 / 12 | ✅ Supporté |
| Windows 10 / 11 (PowerShell Admin) | ✅ Supporté |
| CentOS / RHEL 8+ | ✅ Supporté |
| macOS 12+ | ⚠️ Sans blocage pare-feu |

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
```

### Clés API à préparer

| Service | Où l'obtenir | Gratuit |
|---------|--------------|---------|
| TheHive | avatar → Settings → API Keys → Create | ✅ |
| Cortex | Organizations → Users → Create API Key | ✅ |
| MISP | Administration → List Auth Keys → Add | ✅ |
| VirusTotal | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) | ✅ 500 req/jour |
| AbuseIPDB | [abuseipdb.com/register](https://www.abuseipdb.com/register) | ✅ 1 000 req/jour |
| Telegram | [@BotFather](https://t.me/BotFather) | ✅ |
| Shodan (option) | [account.shodan.io/register](https://account.shodan.io/register) | ⚠️ limité |

---

## 1️⃣ Infrastructure Docker

📺 **[Vidéo : installation de TheHive, MISP et Cortex](https://youtu.be/Vr4flc55S5c)**

### Installer Docker

📚 [docs.docker.com/engine/install/ubuntu](https://docs.docker.com/engine/install/ubuntu/)

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

### Lancer la stack

```bash
git clone https://github.com/Rachkpt/SOAR.git
cd SOAR/docker

# Dossiers montés par docker-compose
mkdir -p cortex/logs server-configs logs files ssl

# Requis par Elasticsearch, sinon le conteneur redémarre en boucle
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

### Vérifier

| Service | URL | Identifiants |
|---------|-----|--------------|
| TheHive | `http://VOTRE_IP:9000` | compte admin créé au 1er accès |
| Cortex | `http://VOTRE_IP:9001` | compte admin créé au 1er accès |
| MISP | `https://VOTRE_IP` | `admin@admin.test` / `admin` |
| MinIO | `http://VOTRE_IP:9002` | `minioadmin` / `minioadmin` |
| Elasticsearch | `http://VOTRE_IP:9200` | aucune authentification |

> **Différences avec le compose de la vidéo :** la clé `version:` a été retirée
> (obsolète en Compose v2), `redis` a été ajouté aux dépendances de MISP,
> `MISP_BASEURL` est paramétrable, le volume TheHive ne masque plus son fichier
> de configuration, et `cortex/application.conf` est fourni prêt à l'emploi.

---

## 2️⃣ TheHive

📚 [docs.strangebee.com/thehive](https://docs.strangebee.com/thehive/)

1. Ouvrir `http://VOTRE_IP:9000` → **Create a new database**
2. Créer le compte administrateur
3. **Organisations** → créer votre organisation
4. **Users** → créer un utilisateur avec le profil `analyst`
5. Sur cet utilisateur : **API Keys** → **Create** → copier la clé

> ⚠️ La clé doit appartenir à un utilisateur **de l'organisation**, pas au
> super-admin : celui-ci n'a pas accès aux cas, et le Service B ne verrait rien.

Vérification :

```bash
curl -X POST "http://VOTRE_IP:9000/api/v1/query?name=list-alerts" \
  -H "Authorization: Bearer VOTRE_CLE" \
  -H "Content-Type: application/json" \
  -d '{"query":[{"_name":"listAlert"},{"_name":"page","from":0,"to":5}]}'
```

---

## 3️⃣ Cortex

📚 [github.com/TheHive-Project/CortexDocs](https://github.com/TheHive-Project/CortexDocs)

1. Ouvrir `http://VOTRE_IP:9001` → **Update Database**
2. Créer le compte admin
3. **Organizations** → **Add Organization**
4. **Users** → **Add User** → rôles `read, analyze, orgadmin` → **Create API Key**
5. **Organizations** → votre org → **Analyzers** → activer et configurer :

| Analyseur | Types d'observables | Clé API requise |
|-----------|---------------------|-----------------|
| `AbuseIPDB_1_0` | ip | AbuseIPDB |
| `VirusTotal_GetReport_3_1` | ip, hash, domain, url | VirusTotal |
| `MaxMind_GeoIP_4_0` | ip | aucune |
| `Shodan_Host_1_0` | ip | Shodan |
| `OTXQuery_2_0` | ip, hash, domain, url | AlienVault OTX |
| `URLhaus_2_0` | url, domain, hash | aucune |

```bash
# Les analyseurs sont des conteneurs Docker : vérifier que Cortex les récupère
docker compose logs cortex.local | grep -i analyzer
docker images | grep cortexneurons
```

### Connecter TheHive ↔ Cortex

📺 **[Vidéo : intégration des trois outils](https://youtu.be/ovUuNQsW_FQ)**
📚 [docs.strangebee.com/thehive/administration/connectors/cortex](https://docs.strangebee.com/thehive/administration/connectors/cortex/)

1. TheHive → **Organisation** → **Connectors** → **Cortex** → **Add Cortex server**
2. **Name** : `cortex.local` — **URL** : `http://cortex.local:9001` — **API Key** : la clé Cortex
3. **Test** → doit afficher ✅

Vérification côté pipeline :

```bash
python start.py cortex
# Cortex : 8 analyseur(s) détecté(s) via TheHive
```

> Si le compte affiche `0`, le Service B ne pourra lancer aucune analyse.
> Reprenez cette étape avant d'aller plus loin.

---

## 4️⃣ MISP

📚 [misp-project.org/documentation](https://www.misp-project.org/documentation/)

1. Ouvrir `https://VOTRE_IP` (accepter l'avertissement TLS)
2. Se connecter avec `admin@admin.test` / `admin` → **changer le mot de passe**
3. **Administration** → **Server Settings** → `MISP.baseurl` = votre URL
4. **Administration** → **List Auth Keys** → **Add authentication key** → copier

Dans `.env` : `MISP_ENABLED=true`, `MISP_URL`, `MISP_APIKEY`.

### Connecter TheHive ↔ MISP

TheHive → **Organisation** → **Connectors** → **MISP** → **Add MISP server**
(`https://misp.local` + clé API).

La variante par fichier de configuration est fournie dans
[`docker/thehive/application.conf`](docker/thehive/application.conf).

Vérification :

```bash
curl -k -H "Authorization: VOTRE_CLE" https://VOTRE_IP/servers/getVersion
```

---

## 5️⃣ Suricata

📚 [docs.suricata.io](https://docs.suricata.io/)

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

### Règles de détection

[`suricata/soc-custom.rules`](suricata/soc-custom.rules) détecte les scans NMAP
`-sS`, `-sT`, `-sA`, `-sX`, `-sU`, `-f` (vitesses T1 à T5) et les shells
Metasploit sur le port 4444.

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
# Depuis une AUTRE machine du lab, contre le capteur Suricata
nmap -sS -T4 IP_DU_CAPTEUR
# → « POSSBL PORT SCAN (NMAP -sS) » doit apparaître dans fast.log
```

C'est cette alerte qui, remontée à Splunk puis au pipeline, déclenche le blocage
de l'IP scanneuse.

---

## 6️⃣ Splunk

📚 [docs.splunk.com — webhooks](https://docs.splunk.com/Documentation/Splunk/latest/Alert/Webhooks)

### Ingérer les logs Suricata

`inputs.conf` du Universal Forwarder installé sur le capteur :

```ini
[monitor:///var/log/suricata/eve.json]
disabled   = false
index      = suricata
sourcetype = suricata
```

### Créer le webhook

1. **Settings** → **Searches, Reports and Alerts** → créer ou éditer une alerte
2. **Alert Actions** → **Add Actions** → **Webhook**
3. **URL** : `http://IP_DU_PIPELINE:5000/alert`

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

**Format 4** — `result` contenant une chaîne JSON.
**Repli** — payload plat : `{"search_name": "...", "src_ip": "...", "host": "..."}`.

Champs reconnus : `src_ip`, `src`, `dest_ip`, `dest`, `user`, `host`, `source`,
`index`, `process_name`, `Image`, `file_hash`, `hash`, `md5`, `sha1`, `sha256`,
`domain`, `dest_domain`, `query`, `url`, `uri`, `CommandLine`, `EventCode`, `_time`.

---

## 7️⃣ Le pipeline Python

```bash
cd SOAR

# Environnement virtuel (recommandé)
python3 -m venv venv
source venv/bin/activate            # Linux / macOS
.\venv\Scripts\Activate.ps1         # Windows PowerShell

python start.py install             # flask, requests, urllib3
python start.py unit                # 168 tests unitaires, hors ligne
python start.py status              # état complet
```

---

## 8️⃣ Le fichier .env

```bash
python start.py init      # copie .env.example → .env
nano .env
```

Le modèle complet et commenté est dans [`.env.example`](.env.example).

### Variables essentielles

| Variable | Défaut | Description |
|----------|--------|-------------|
| `THEHIVE_URL` | — | URL de TheHive, ex. `http://192.168.1.10:9000` |
| `THEHIVE_APIKEY` | — | Clé API d'un utilisateur `analyst` |
| `THEHIVE_VERIFY_SSL` | `true` | `false` si certificat auto-signé |

### Cortex

| Variable | Défaut | Description |
|----------|--------|-------------|
| `CORTEX_ENABLED` | `true` | Lancer les analyseurs automatiquement |
| `CORTEX_URL` | — | Secours si TheHive ne liste pas les analyseurs |
| `CORTEX_APIKEY` | — | Idem |
| `CORTEX_JOB_TIMEOUT` | `180` | Attente maximale d'un analyseur (s) |
| `CORTEX_MAX_ANALYZERS` | `5` | Analyseurs lancés par observable |

### Enrichissement

| Variable | Défaut | Description |
|----------|--------|-------------|
| `VT_ENABLED` / `VT_APIKEY` | `true` | Enrichissement VirusTotal |
| `VT_TIMEOUT` | `15` | Timeout des requêtes (s) |
| `VT_MIN_DETECTIONS` | `2` | Seuil de verdict « malveillant » |
| `MISP_ENABLED` | `false` | Lookup et publication d'IoC |
| `MISP_URL` / `MISP_APIKEY` | — | Accès MISP |
| `MISP_VERIFY_SSL` | `false` | `false` en lab (certificat auto-signé) |

### Service A

| Variable | Défaut | Description |
|----------|--------|-------------|
| `LISTEN_HOST` / `LISTEN_PORT` | `0.0.0.0` / `5000` | Écoute du webhook |
| `RATE_LIMIT_SEC` | `10` | Anti-flood sur alertes identiques |
| `RETRY_ATTEMPTS` / `RETRY_DELAY_SEC` | `3` / `5` | Reprise sur échec réseau |
| `NOTIFY_MIN_SEV` | `1` | Sévérité minimale notifiée |

### Service B

| Variable | Défaut | Description |
|----------|--------|-------------|
| `POLL_INTERVAL` | `20` | Fréquence d'interrogation de TheHive (s) |
| `MIN_SEVERITY` | `1` | Sévérité minimale traitée |
| `RESPONSE_MIN_SEV` | `2` | Sévérité minimale pour déclencher une réponse |
| `STATE_FILE` | `responder_state.json` | Alertes déjà traitées (dossier `data/`) |
| `BLACKLIST_FILE` | `ip_blacklist.txt` | Liste lisible des IP bloquées |

### Réponse active — IP

| Variable | Défaut | Description |
|----------|--------|-------------|
| `ACTIVE_RESPONSE` | `false` | `true` = blocage pare-feu réel |
| `BLOCK_DURATION_MIN` | `10` | Durée d'un blocage (min) |
| `BLOCK_ON_BRUTEFORCE` | `true` | Bloquer les attaques par force brute |
| `BLOCK_ON_PORTSCAN` | `true` | Bloquer les scans de ports |
| `BLOCK_ON_THREAT` | `true` | Bloquer les autres catégories de menace |
| `BLOCK_ALL_IPS` | `false` | Inclure les IP internes (labs uniquement) |

### Réponse active — fichiers

| Variable | Défaut | Description |
|----------|--------|-------------|
| `FILE_RESPONSE_ENABLED` | `false` | Activer la réponse sur fichiers |
| `FILE_RESPONSE_MODE` | `quarantine` | `report`, `quarantine` ou `delete` |
| `FILE_SCAN_PATHS` | *(vide)* | Dossiers à analyser, séparés par des virgules |
| `QUARANTINE_DIR` | `quarantine` | Coffre (dossier `data/`) |
| `FILE_MAX_SIZE_MB` | `200` | Taille maximale d'un fichier lu |
| `FILE_MAX_FILES` | `200000` | Nombre maximal de fichiers par analyse |

### Notifications et journaux

| Variable | Défaut | Description |
|----------|--------|-------------|
| `TELEGRAM_ENABLED` / `TELEGRAM_TOKEN` / `TELEGRAM_CHAT_ID` | `false` | Notifications |
| `GMAIL_ENABLED` / `GMAIL_USER` / `GMAIL_PASS` / `GMAIL_TO` | `false` | Courriel |
| `LOG_FILE` / `LOG_FILE_B` | `service_a.log` / `service_b.log` | Dossier `logs/` |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

> 💡 Les commentaires en fin de ligne (`BLOCK_DURATION_MIN=10  # minutes`) sont
> tolérés : l'erreur `invalid literal for int()` ne peut plus se produire.

---

## 🔥 Activer la réponse active

Par défaut le pipeline **ne bloque rien et ne touche à aucun fichier**. Il
détecte, journalise et notifie ce qu'il *aurait* fait. C'est volontaire :
observez d'abord une journée, activez ensuite.

### Étape 1 — blocage des IP

```ini
# .env
ACTIVE_RESPONSE=true
BLOCK_DURATION_MIN=10
```

Le blocage exige des privilèges système :

```bash
# Linux — root requis pour iptables
sudo python3 start.py both

# Windows — PowerShell en tant qu'administrateur
python start.py both

# Ou, depuis une session non privilégiée :
python start.py elevate
```

**Prouver que le blocage fonctionne réellement**, sans attendre une attaque :

```bash
python start.py test-block 203.0.113.10
```

La commande pose la règle, interroge le pare-feu pour vérifier qu'elle existe
vraiment, puis la retire :

```
=== Test du blocage firewall ===
Cible            : 203.0.113.10
Plateforme       : Windows / netsh
ACTIVE_RESPONSE  : ✅ true
Privilèges       : ✅ admin/root

1/3 — pose de la règle...      ✅ règle posée
2/3 — vérification...          ✅ règle présente dans le firewall
3/3 — retrait de la règle...   ✅ règle retirée

✅ Le blocage firewall fonctionne.
```

Si une étape échoue, la cause exacte est affichée.

### Étape 2 — fichiers malveillants

```ini
# .env
FILE_RESPONSE_ENABLED=true
FILE_RESPONSE_MODE=quarantine

# Dossiers à surveiller — VIDE par défaut, donc inactif
FILE_SCAN_PATHS=/srv/partage,/home/utilisateur/Downloads
# Windows : FILE_SCAN_PATHS=C:\Users\Public\Downloads,D:\partage
```

```bash
python start.py files            # état + contenu de la quarantaine
```

**Tester sur un fichier réel :**

```bash
# 1. Créer un fichier témoin et relever son hash
echo "contenu de test" > /srv/partage/temoin.bin
sha256sum /srv/partage/temoin.bin

# 2. Lancer la recherche : le fichier part en quarantaine
python start.py scan <le_hash_sha256>

# 3. Vérifier
ls /srv/partage/            # temoin.bin a disparu
python start.py files       # il apparaît dans la quarantaine

# 4. Le remettre en place
python start.py restore <id_affiché>
```

**Garde-fous, dans l'ordre où ils s'appliquent :**

1. Rien ne se passe tant que `FILE_RESPONSE_ENABLED=false`
2. Aucun dossier n'est analysé tant que `FILE_SCAN_PATHS` est vide
3. Les répertoires système sont refusés, même listés explicitement :
   `C:\Windows`, `C:\Program Files`, `/etc`, `/usr`, `/bin`, `/boot`, `/dev`…
4. Une racine de disque (`C:\`, `/`) est refusée
5. Les liens symboliques ne sont ni suivis ni touchés
6. Seuls les hashes **confirmés malveillants** par VirusTotal ou MISP agissent
7. Les fichiers au-delà de `FILE_MAX_SIZE_MB` ne sont pas lus

> **Choisissez `quarantine` plutôt que `delete`.** Un faux positif se restaure
> en une commande ; une suppression est définitive.

### Ce qui n'est pas automatisé

Le pipeline agit sur la machine où tourne le Service B et sur les dossiers que
vous lui désignez — typiquement un partage réseau. Il n'y a **pas d'agent
déployé sur les postes** : pour nettoyer un poste distant, il faut monter son
partage dans `FILE_SCAN_PATHS`, ou ajouter un responder Cortex qui pilote votre
EDR.

---

## 🖥️ Toutes les commandes

### Installation

```bash
python start.py install          # installer les dépendances Python
python start.py init             # créer .env depuis .env.example
```

### Services

```bash
python start.py                  # menu interactif
python start.py a                # Service A seul (webhook)
python start.py b                # Service B seul (responder)
python start.py both             # A + B, redémarrage automatique si crash
python start.py elevate          # relancer en administrateur / root
```

### Réponse active — IP

```bash
python start.py test-block 203.0.113.10   # prouver que le blocage fonctionne
python start.py list                      # IP bloquées + temps restant
python start.py unblock 1.2.3.4           # débloquer immédiatement
```

### Réponse active — fichiers

```bash
python start.py files                     # état + quarantaine
python start.py scan <hash>               # chercher et neutraliser
python start.py restore <id>              # restaurer un fichier
python start.py purge <id>                # suppression définitive du coffre
```

### Diagnostic

```bash
python start.py status           # état complet de l'intégration
python start.py cortex           # analyseurs Cortex détectés
python start.py unit             # 168 tests unitaires (hors ligne)
python start.py e2e              # intégration bout en bout (TheHive simulé)
python start.py test             # tests end-to-end (services réels lancés)
python start.py telegram         # message de test Telegram
python start.py telegram-config  # configuration Telegram guidée
python start.py logs             # fin des journaux
```

### Vérifier les règles posées par le pipeline

```bash
# Linux
sudo iptables -L INPUT -n --line-numbers | grep DROP

# Windows
netsh advfirewall firewall show rule name=all | findstr SOC_BLOCK
```

---

## 🌐 Endpoints du Service A

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `POST` | `/alert` | **Webhook principal** — alertes Splunk |
| `GET` | `/health` | État du service + connexion TheHive |
| `GET` | `/test` | Envoie une vraie alerte de test |
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

## 📱 Telegram

📚 [core.telegram.org/bots/api](https://core.telegram.org/bots/api)

```bash
python start.py telegram-config    # assistant guidé
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
| 🔒 | Fichier mis en quarantaine |
| 🗑 | Fichier supprimé |
| ⚠️ | Action simulée (réponse active désactivée) |
| ❌ | Échec (blocage impossible, cas non créé…) |
| ✅ | IP débloquée |

---

## 🧪 Tests

### Tests unitaires — 168 tests, hors ligne

```bash
python start.py unit                  # les 4 suites
python tests/test_soc_common.py       # 33 — env, client TheHive, Telegram
python tests/test_file_responder.py   # 33 — quarantaine, garde-fous système
python tests/test_service_a.py        # 54 — parsing, VT, endpoints Flask
python tests/test_service_b.py        # 48 — menaces, blocage, Cortex, état
```

Aucune requête réseau, aucune règle pare-feu posée, aucun `.env` lu
(`SOC_SKIP_DOTENV=1`), fichiers confinés dans `tests/.tmp/`.

### Test d'intégration bout en bout — 44 vérifications

```bash
python start.py e2e
```

Cette commande démarre un **faux serveur TheHive 5**, lance le **vrai Service A**,
lui envoie une alerte Splunk, puis fait tourner un cycle du **vrai Service B**.
Elle vérifie ensuite que toute la chaîne a réellement eu lieu :

```
[OK]  POST /alert -> 201 created
[OK]  alerte creee dans TheHive
[OK]  tags brute_force + port_scan + linux
[OK]  cas crees dans TheHive
[OK]  observables ajoutes aux cas
[OK]  jobs Cortex lances automatiquement
[OK]  AbuseIPDB lance sur l'IP
[OK]  verdict Cortex malicious remonte
[OK]  commentaire de rapport ecrit
[OK]  fichier malveillant retire du partage
[OK]  fichier sain intact
[OK]  contenu du fichier preserve
[OK]  cas tague file-neutralized
...
  44/44 verifications OK
```

Aucun serveur réel requis, aucune connexion Internet, aucune règle pare-feu.
C'est le moyen le plus rapide de vérifier que le pipeline fonctionne avant de
le brancher sur votre infrastructure.

### Tests end-to-end contre votre infrastructure réelle

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

Symptôme : l'interpréteur se ferme sans message, ou `magic` échoue.
Cause : `thehive4py` importe `libmagic`, absent de Windows.
**Cette version n'utilise plus thehive4py.** Si l'erreur persiste, un ancien
`service_splunk_to_thehive.py` traîne encore — supprimez-le.

### Aucun analyseur Cortex ne se lance

```bash
python start.py cortex
```

- `0 analyseur` → le connecteur Cortex n'est pas configuré dans TheHive
  (**Organisation → Connectors → Cortex → Test**)
- analyseurs listés mais jobs en échec → vérifier les clés API des analyseurs
  dans Cortex et le montage du socket Docker :
  ```bash
  docker compose logs cortex.local --tail 100
  docker ps | grep cortexneurons
  ```
- Cortex démarré après le Service B → le registre se rafraîchit seul au bout de
  5 minutes, ou immédiatement avec `python start.py cortex`

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
```

Une erreur `401` signifie une clé invalide. Une clé de **super-admin ne voit
aucun cas** : utiliser un utilisateur `analyst` de l'organisation.

### Les IP ne sont pas bloquées

```bash
python start.py status         # doit afficher « Privilèges : ✓ admin/root »
python start.py test-block 203.0.113.10
```

| Cause | Correctif |
|-------|-----------|
| `ACTIVE_RESPONSE=false` | passer à `true` dans `.env` |
| Pas administrateur (Windows) | `python start.py elevate` |
| Pas root (Linux) | `sudo python3 start.py both` |
| `iptables` absent | `sudo apt install iptables -y` |
| Sévérité trop basse | abaisser `RESPONSE_MIN_SEV` |
| IP interne ignorée | `BLOCK_ALL_IPS=true` (labs uniquement) |

### Les fichiers malveillants ne sont pas neutralisés

```bash
python start.py files
```

| Message | Correctif |
|---------|-----------|
| `Activée : ❌ non` | `FILE_RESPONSE_ENABLED=true` dans `.env` |
| `Opérationnelle : ❌ non` | renseigner `FILE_SCAN_PATHS` |
| `[REFUSÉ] … répertoire système protégé` | choisir un dossier de données, pas un dossier système |
| Rien n'est trouvé | le hash doit être **confirmé malveillant** par VirusTotal ou MISP, et le fichier doit se trouver sous un dossier surveillé |

### MISP — timeout de connexion

```bash
docker compose ps misp.local
docker compose logs misp.local --tail 50
curl -k -H "Authorization: VOTRE_CLE" https://VOTRE_IP/servers/getVersion
```

Certificat auto-signé → `MISP_VERIFY_SSL=false` dans `.env`.

### `invalid literal for int()` au démarrage

Corrigé : les commentaires en fin de ligne du `.env` sont tolérés. Si l'erreur
revient, c'est que la valeur ne contient aucun chiffre.

### Suivre les journaux

```bash
python start.py logs
tail -f logs/service_a.log logs/service_b.log            # Linux
Get-Content logs/service_a.log -Wait -Tail 20            # Windows
```

---

## 🔐 Sécurité

> ⚠️ **Ne jamais committer le fichier `.env`** — il contient toutes vos clés API.

`.gitignore` protège déjà `.env`, `data/`, `logs/`, `*.log`, les blacklists,
l'état du responder et la quarantaine.

- Clés API avec le **minimum de permissions** nécessaires
- En production : webhook derrière **nginx + HTTPS**, filtrage par IP source
- `MISP_VERIFY_SSL=true` et `THEHIVE_VERIFY_SSL=true` avec de vrais certificats
- Changer les mots de passe par défaut de MISP, MinIO, et le `--secret` de
  TheHive dans `docker-compose.yml`
- Commencer avec `ACTIVE_RESPONSE=false` pour observer ce qui *serait* bloqué
- Préférer `FILE_RESPONSE_MODE=quarantine` à `delete`
- Si une clé a fuité (dépôt public, capture d'écran…), la **révoquer et la
  régénérer** immédiatement

---

## 📚 Documentation de référence

### TheHive / Cortex / MISP

| Ressource | Lien |
|-----------|------|
| Documentation TheHive 5 | [docs.strangebee.com/thehive](https://docs.strangebee.com/thehive/) |
| Installation TheHive | [docs.strangebee.com/thehive/installation](https://docs.strangebee.com/thehive/installation/) |
| API REST TheHive v1 | [docs.strangebee.com/thehive/api-docs](https://docs.strangebee.com/thehive/api-docs/) |
| Connecteurs TheHive | [docs.strangebee.com/thehive/administration/connectors](https://docs.strangebee.com/thehive/administration/connectors/) |
| Documentation Cortex | [github.com/TheHive-Project/CortexDocs](https://github.com/TheHive-Project/CortexDocs) |
| Catalogue des analyseurs | [github.com/TheHive-Project/Cortex-Analyzers](https://github.com/TheHive-Project/Cortex-Analyzers) |
| Écrire son propre analyseur | [CortexDocs — how-to-create-an-analyzer](https://github.com/TheHive-Project/CortexDocs/blob/master/api/how-to-create-an-analyzer.md) |
| Documentation MISP | [misp-project.org/documentation](https://www.misp-project.org/documentation/) |
| API REST MISP (OpenAPI) | [misp-project.org/openapi](https://www.misp-project.org/openapi/) |
| Livre MISP | [misp.github.io/MISP](https://misp.github.io/MISP/) |
| Image Docker MISP utilisée | [github.com/coolacid/docker-misp](https://github.com/coolacid/docker-misp) |

### Détection — Suricata et Splunk

| Ressource | Lien |
|-----------|------|
| Documentation Suricata | [docs.suricata.io](https://docs.suricata.io/) |
| Format des règles | [docs.suricata.io — rules/intro](https://docs.suricata.io/en/latest/rules/intro.html) |
| Sortie EVE JSON | [docs.suricata.io — eve-json-output](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html) |
| Performances Suricata | [docs.suricata.io — performance](https://docs.suricata.io/en/latest/performance/index.html) |
| Règles Emerging Threats | [rules.emergingthreats.net](https://rules.emergingthreats.net/open/suricata/) |
| Installer Splunk Enterprise | [docs.splunk.com — InstallonLinux](https://docs.splunk.com/Documentation/Splunk/latest/Installation/InstallonLinux) |
| Alertes et webhooks Splunk | [docs.splunk.com — Webhooks](https://docs.splunk.com/Documentation/Splunk/latest/Alert/Webhooks) |
| Universal Forwarder | [docs.splunk.com — Forwarder](https://docs.splunk.com/Documentation/Forwarder/latest/Forwarder/Abouttheuniversalforwarder) |
| Langage SPL | [docs.splunk.com — SearchReference](https://docs.splunk.com/Documentation/SplunkCloud/latest/SearchReference/WhatsInThisManual) |

### Threat Intelligence

| Ressource | Lien |
|-----------|------|
| API VirusTotal v3 | [docs.virustotal.com/reference/overview](https://docs.virustotal.com/reference/overview) |
| Quotas VirusTotal | [docs.virustotal.com — public vs premium](https://docs.virustotal.com/reference/public-vs-premium-api) |
| API AbuseIPDB | [docs.abuseipdb.com](https://docs.abuseipdb.com/) |
| AlienVault OTX | [otx.alienvault.com/api](https://otx.alienvault.com/api) |
| Shodan | [developer.shodan.io](https://developer.shodan.io/) |
| URLhaus (abuse.ch) | [urlhaus.abuse.ch/api](https://urlhaus.abuse.ch/api/) |
| MaxMind GeoIP | [dev.maxmind.com/geoip](https://dev.maxmind.com/geoip/) |

### Infrastructure

| Ressource | Lien |
|-----------|------|
| Installer Docker Engine | [docs.docker.com/engine/install](https://docs.docker.com/engine/install/) |
| Docker Compose | [docs.docker.com/compose](https://docs.docker.com/compose/) |
| `vm.max_map_count` | [elastic.co — vm-max-map-count](https://www.elastic.co/guide/en/elasticsearch/reference/current/vm-max-map-count.html) |
| iptables | [netfilter.org/documentation](https://www.netfilter.org/documentation/) |
| `netsh advfirewall` | [learn.microsoft.com — netsh-advfirewall](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/netsh-advfirewall-firewall-control-firewall-behavior) |
| API Bot Telegram | [core.telegram.org/bots/api](https://core.telegram.org/bots/api) |
| Mots de passe d'application Gmail | [support.google.com/accounts/answer/185833](https://support.google.com/accounts/answer/185833) |
| Flask | [flask.palletsprojects.com](https://flask.palletsprojects.com/) |
| Requests | [requests.readthedocs.io](https://requests.readthedocs.io/) |

### Méthodologie SOC

| Ressource | Lien |
|-----------|------|
| MITRE ATT&CK | [attack.mitre.org](https://attack.mitre.org/) |
| NIST SP 800-61 — gestion des incidents | [csrc.nist.gov/pubs/sp/800/61/r2/final](https://csrc.nist.gov/pubs/sp/800/61/r2/final) |
| Sigma — règles de détection portables | [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) |
| Atomic Red Team | [github.com/redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) |
| The DFIR Report — cas réels | [thedfirreport.com](https://thedfirreport.com/) |

### Vidéos

| Sujet | Lien |
|-------|------|
| Installation de TheHive, MISP et Cortex | [youtu.be/Vr4flc55S5c](https://youtu.be/Vr4flc55S5c) |
| Intégration des trois outils | [youtu.be/ovUuNQsW_FQ](https://youtu.be/ovUuNQsW_FQ) |
| Chaîne officielle StrangeBee | [youtube.com/@strangebee](https://www.youtube.com/@strangebee) |

---

## 📌 Journal des versions

| Version | Composant | Changements |
|---------|-----------|-------------|
| **v8.0.0** | Service A | Client TheHive REST v1 natif ; fin de `thehive4py` ; console UTF-8 Windows ; `.env` tolérant aux commentaires ; `datetime.utcnow()` remplacé ; anti-doublon sans fuite mémoire |
| **v11.0.0** | Service B | Découverte Cortex via TheHive + rafraîchissement automatique ; blocage étendu (scan de ports, exploitation, mouvement latéral, vol d'identifiants, rançongiciel…) ; **réponse sur fichiers malveillants** ; plus de règle pare-feu posée en simulation ; `MIN_SEVERITY` / `RESPONSE_MIN_SEV` / `BLOCK_ALL_IPS` réellement appliqués ; état écrit de façon atomique |
| — | file_responder | Recherche par hash MD5/SHA1/SHA256, quarantaine réversible, suppression, restauration, garde-fous sur les répertoires système |
| — | start.py | Chemins `src/` corrigés ; menu itératif ; commandes `init`, `unit`, `list`, `unblock`, `test-block`, `files`, `scan`, `restore`, `purge`, `cortex`, `elevate`, `logs` |
| — | Projet | Arborescence réorganisée ; 168 tests unitaires ; LICENSE MIT ; clé API en dur retirée de la configuration TheHive |
