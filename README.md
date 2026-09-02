# 🛡️ SOC Automation Pipeline (SOAR)

<div align="center">

**Détection et réponse aux incidents, entièrement automatisées**

Suricata / Splunk → TheHive → Cortex → MISP → VirusTotal → Réponse active → Telegram

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![TheHive](https://img.shields.io/badge/TheHive-5.2.x-F5A800?style=for-the-badge)](https://docs.strangebee.com/thehive/)
[![Cortex](https://img.shields.io/badge/Cortex-3.x-FF6B35?style=for-the-badge)](https://github.com/TheHive-Project/Cortex)
[![Suricata](https://img.shields.io/badge/Suricata-7.x-EF4444?style=for-the-badge)](https://suricata.io)
[![Splunk](https://img.shields.io/badge/Splunk-9.x-65A637?style=for-the-badge&logo=splunk&logoColor=white)](https://splunk.com)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docs.docker.com/compose)
[![Tests](https://img.shields.io/badge/Tests-168%20unitaires-22C55E?style=for-the-badge)](tests/)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)](LICENSE)

</div>

---

## À quoi sert ce projet

Dans un SOC, la partie pénible n'est pas de détecter une attaque : c'est tout ce
qui vient après. Ouvrir un ticket, chercher qui est l'IP, lancer les analyses,
vérifier si l'IoC est déjà connu, bloquer la source, prévenir l'équipe. À chaque
alerte. Toute la nuit.

Ce projet fait ce travail à votre place, du bout en bout. Une alerte arrive
depuis **Splunk** ou **Suricata**. Trente secondes plus tard, un cas
d'investigation existe dans **TheHive**, ses observables ont été analysés par
**Cortex**, comparés à **VirusTotal** et à **MISP**, l'IP attaquante est bloquée
au pare-feu, le fichier malveillant est en quarantaine, et un rapport complet
attend l'analyste — qui a reçu une notification **Telegram**.

| # | Étape | Réalisé par |
|---|-------|-------------|
| 1 | Réception de l'alerte par webhook HTTP | Service A |
| 2 | Extraction des IoCs : IP, hash, domaine, URL, utilisateur, ligne de commande | Service A |
| 3 | Enrichissement VirusTotal, remontée de sévérité si l'IoC est connu | Service A |
| 4 | Création de l'**alerte** dans TheHive avec ses observables | Service A |
| 5 | Promotion de l'alerte en **cas** d'investigation | Service B |
| 6 | **Lancement automatique des analyseurs Cortex** sur chaque observable | Service B |
| 7 | Recherche dans MISP, publication de l'IoC s'il est inédit | Service B |
| 8 | **Blocage pare-feu de l'IP attaquante**, avec déblocage programmé | Service B |
| 9 | **Quarantaine ou suppression du fichier malveillant** | Service B |
| 10 | Rapport markdown dans le cas + notification Telegram à chaque étape | Service B |

---

## 🗺️ Topologie du lab

```
┌───────────────────────────────────────────────────────────────────────────┐
│                             RÉSEAU SOC (lab)                               │
│                                                                           │
│   Attaquant ──nmap / ssh / metasploit──▶  Cible = CAPTEUR Suricata         │
│                                            │  eve.json                     │
│                                            ▼                               │
│                                   ┌──────────────────┐                     │
│                                   │  Splunk UF       │ monitor eve.json    │
│                                   └────────┬─────────┘                     │
│                                            ▼ :9997                         │
│                                   ┌──────────────────┐  recherche +        │
│                                   │  Splunk Indexer  │  action webhook     │
│                                   └────────┬─────────┘                     │
│                                            ▼  POST /alert                  │
│                                   ┌──────────────────┐                     │
│                                   │  Service A :5000  │  webhook Flask      │
│                                   └────────┬─────────┘                     │
│                                            ▼  alerte                       │
│                                   ┌──────────────────┐◀──┐                 │
│                                   │  TheHive :9000   │   │ poll 20 s       │
│                                   │  Alertes & Cas   │   │                 │
│                                   └────────┬─────────┘   │                 │
│                                            ▼             │                 │
│                                   ┌──────────────────┐───┘                 │
│                                   │  Service B (auto) │                    │
│                                   └──┬────┬────┬──────┘                    │
│                          ┌───────────┘    │    └───────────┐               │
│                          ▼                ▼                ▼               │
│                 ┌────────────┐   ┌────────────┐   ┌────────────┐           │
│                 │  Cortex    │   │   MISP     │   │ VirusTotal │           │
│                 │  :9001     │   │  :80/443   │   │  API v3    │           │
│                 └────────────┘   └────────────┘   └────────────┘           │
│                          │                                                 │
│              ┌───────────┼───────────┬───────────┐                         │
│              ▼           ▼           ▼           ▼                         │
│        ┌──────────┐ ┌──────────┐ ┌────────┐ ┌──────────┐                   │
│        │ Pare-feu │ │Quarantn. │ │Rapport │ │ Telegram │                  │
│        │netsh/ipt.│ │ fichiers │ │TheHive │ │  / Gmail │                  │
│        └──────────┘ └──────────┘ └────────┘ └──────────┘                   │
└───────────────────────────────────────────────────────────────────────────┘
```

| Composant | Rôle | Port |
|-----------|------|------|
| **Service A** | Webhook Flask — reçoit et enrichit les alertes | 5000 |
| **Service B** | Responder — orchestre analyse et réponse active | — |
| **TheHive** | Gestion des alertes et des cas | 9000 |
| **Cortex** | Moteur d'analyse automatique | 9001 |
| **MISP** | Plateforme de Threat Intelligence | 80 / 443 |
| **Suricata** | IDS réseau — écrit `eve.json` | — |
| **Splunk** | SIEM — ingère `eve.json`, déclenche le webhook | 8000 / 9997 |

> ⚠️ Sur un bridge Proxmox **sans port-mirroring**, une machine ne voit que son
> propre trafic. Le **capteur Suricata doit donc être la machine cible** de
> l'attaque (ou un port SPAN dédié).

---

# 📦 Installation — de A à Z

Chaque étape est indépendante et se termine par une **vérification**. Ne passez à
la suivante qu'une fois la vérification verte.

- [Étape 0 — Prérequis](#étape-0--prérequis)
- [Étape 1 — Infrastructure Docker (TheHive + Cortex + MISP)](#étape-1--infrastructure-docker)
- [Étape 2 — TheHive : organisation, utilisateur analyste, clé API](#étape-2--thehive)
- [Étape 3 — Cortex : connecteur, analyseurs, permissions](#étape-3--cortex)
- [Étape 4 — Suricata : le capteur](#étape-4--suricata)
- [Étape 5 — Splunk : ingestion + recherche + webhook](#étape-5--splunk)
- [Étape 6 — Le pipeline Python (Service A + Service B)](#étape-6--le-pipeline-python)
- [Étape 7 — Activer la réponse active](#étape-7--activer-la-réponse-active-optionnel)
- [Étape 8 — Vérification bout en bout](#étape-8--vérification-bout-en-bout)

---

## Étape 0 — Prérequis

| | |
|---|---|
| **Serveur Docker** | 4 cœurs, 8 Go RAM, 50 Go disque minimum (TheHive + Cortex + MISP) |
| **Machine capteur** | Ubuntu/Debian, sur le chemin du trafic à surveiller |
| **Machine pipeline** | Python 3.8+ (testé jusqu'à 3.13), `flask` `requests` `urllib3` |
| **Splunk** | 9.x, licence **Trial ou Enterprise** (la licence *Free* désactive les alertes) |
| **Clés API** | TheHive, Cortex, VirusTotal (gratuite) ; MISP / Telegram / Gmail optionnels |

```bash
git clone https://github.com/Rachkpt/SOAR.git
cd SOAR
python start.py install      # installe flask / requests / urllib3
```

> Si un conteneur LXC Proxmox héberge Docker : cocher **nesting=1** et **keyctl=1**
> (Options → Features), sinon Docker ne démarre pas.

---

## Étape 1 — Infrastructure Docker

Stack `docker-compose.yml` : TheHive 5.2 + Cassandra + Elasticsearch + MinIO +
Cortex + MISP.

```bash
cd SOAR/docker
mkdir -p cortex/logs server-configs logs files ssl

# Dossier de travail des jobs Cortex — DOIT être accessible en écriture au
# conteneur Cortex (il tourne en utilisateur non-root). Sinon : tous les jobs
# échouent avec « java.nio.file.AccessDeniedException ... prepareJobFolder ».
sudo mkdir -p /tmp/cortex-jobs && sudo chmod 777 /tmp/cortex-jobs
# /tmp est vidé au reboot → on fige les droits :
echo 'd /tmp/cortex-jobs 0777 root root -' | sudo tee /etc/tmpfiles.d/cortex-jobs.conf

# Téléchargement robuste (réseau instable) puis démarrage
chmod +x pull-images.sh && ./pull-images.sh
docker compose up -d
docker compose ps          # 9 services doivent être "running"
```

**Vérification**

```bash
curl -s http://127.0.0.1:9000/api/v1/status ; echo     # TheHive : HTTP 200
curl -s http://127.0.0.1:9001/api/status    ; echo     # Cortex  : HTTP 200
```
TheHive met 1 à 3 min à devenir disponible après Cassandra / Elasticsearch.

---

## Étape 2 — TheHive

1. Ouvrez `http://<IP-serveur>:9000`, connectez-vous en `admin@thehive.local`.
2. **Créez une organisation** (ex. `soc`) : *Admin → Organizations → Add*.
3. Dans cette organisation, **créez un utilisateur `analyst`** avec le profil
   `analyst` (ou `org-admin`) : *Users → Add*.
4. Sur cet utilisateur : **Create API key**, copiez-la.

> 🔴 **Piège classique.** La clé de l'utilisateur `admin@thehive.local`
> n'appartient à **aucune organisation** : Service B ne verra **aucune** alerte
> ni cas. Utilisez **toujours** la clé d'un utilisateur d'organisation.

**Vérification** (avec la clé copiée) :

```bash
curl -s -H "Authorization: Bearer <CLE_THEHIVE>" \
  http://<IP>:9000/api/v1/user/current | python3 -m json.tool
```
`organisation` doit être votre org (**pas** `admin`) et `permissions` doit
contenir `manageAlert/create`, `manageCase/create`, `manageAnalyse`.

---

## Étape 3 — Cortex

### 3.1 Connecter Cortex à TheHive

1. `http://<IP>:9001` → créez une organisation, un utilisateur, une **API key**
   (*Organization → Users → Create API Key*).
2. *Organization → Analyzers* → **activez** les analyseurs voulus (au minimum
   **AbuseIPDB**, **MaxMind_GeoIP**, **VirusTotal_GetReport**) et renseignez
   leurs clés API.
3. Sur **chaque analyseur activé** → *Edit* :
   - **Max TLP** = `AMBER (2)` ou `RED (3)`
   - **Max PAP** = `AMBER (2)` ou `RED (3)`
   > Les observables créés par Service B sont **TLP:AMBER**. Si `Max TLP` reste
   > à `GREEN`, tous les jobs échouent avec *« TLP is above the maximum allowed »*.
4. Dans **TheHive** : *Organisation → Connectors → Cortex → Add* (URL
   `http://cortex.local:9001`, la clé API Cortex) puis **Test** → doit être vert.

### 3.2 Pré-télécharger les images d'analyseurs

Cortex lance chaque analyseur dans un conteneur Docker (« neuron »). Si l'image
n'est pas là et que l'auto-pull échoue, **tous les jobs finissent en Failure**
avec un `errorMessage` vide.

```bash
# Sur l'HÔTE DOCKER
CORTEX_APIKEY=<CLE_CORTEX> bash SOAR/scripts/pull-cortex-analyzers.sh
```
Le script demande à Cortex la liste **exacte** des images (bon registre
`ghcr.io/thehive-project/…`, bon tag) et les tire une par une.

**Vérification**

```bash
docker images | grep ghcr.io/thehive-project
```
puis Cortex → **New Analysis** → `AbuseIPDB` sur `8.8.8.8` (TLP AMBER) → **Success**
avec un rapport (score, pays, ISP).

---

## Étape 4 — Suricata

À installer **sur la machine capteur** (= la cible des attaques dans un lab sans
port-mirroring).

```bash
# clonez le dépôt sur le capteur, puis :
sudo bash SOAR/scripts/install-suricata-soc.sh
# surcharge possible :
sudo IFACE=eth1 HOMENET='[10.0.0.0/8,192.168.0.0/16]' bash SOAR/scripts/install-suricata-soc.sh
```

Le script :
- installe Suricata (PPA OISF sur Ubuntu, paquet distrib sur Debian) ;
- déploie **`suricata/soc-custom.rules`** (scans NMAP `-sS -sT -sA -sX -sU -f`,
  SSH brute force, shells Metasploit port 4444) + le jeu **ET Open** ;
- règle `HOME_NET` et l'interface, active `community-id` ;
- **coupe le bruit** des règles décodeur/stream (trames L2 du bridge Proxmox,
  `SURICATA Ethertype unknown`) ;
- valide (`suricata -T`) et active le service.

> Les règles de scan sont en `source = any` **volontairement** : dans un lab
> l'attaquant est interne, `$EXTERNAL_NET` ne matcherait rien.

**Vérification** — depuis une **autre** machine :

```bash
nmap -sS -p1-1000 <ip-du-capteur>
# sur le capteur :
grep 'POSSBL' /var/log/suricata/fast.log
tail -f /var/log/suricata/eve.json | grep '"event_type":"alert"'
```

---

## Étape 5 — Splunk

### 5.1 Ingérer `eve.json`

Sur la machine **capteur** (avec un Universal Forwarder déjà relié à
l'indexeur) :

```bash
UF=/opt/splunkforwarder/bin/splunk
mkdir -p /opt/splunkforwarder/etc/apps/suricata_inputs/local
cat > /opt/splunkforwarder/etc/apps/suricata_inputs/local/inputs.conf <<'EOF'
[monitor:///var/log/suricata/eve.json]
sourcetype = suricata:json
index = main
disabled = false
EOF
$UF restart
```
`eve.json` doit être lisible par l'utilisateur du forwarder
(`chmod 644 /var/log/suricata/eve.json` ou `usermod -aG adm splunkfwd`).

### 5.2 Parsing JSON — sur l'indexeur / search head

Le sourcetype `suricata:json` n'est pas connu de Splunk : sans config, aucun
champ (`event_type`, `src_ip`, `alert.signature`…) n'est extrait.

```bash
cat >> $SPLUNK_HOME/etc/system/local/props.conf <<'EOF'

[suricata:json]
KV_MODE = json
TIME_PREFIX = "timestamp":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N%z
MAX_TIMESTAMP_LOOKAHEAD = 40
SHOULD_LINEMERGE = false
TRUNCATE = 100000
EOF
$SPLUNK_HOME/bin/splunk restart
```

**Vérification** : `index=main sourcetype=suricata:json event_type=alert` (Last
15 min, après un scan) renvoie des lignes avec `src_ip`, `alert.signature`…

### 5.3 Créer la recherche et l'action webhook

> Créez l'alerte **depuis l'UI** (*Enregistrer sous → Alerte*). Une saved search
> posée à la main dans `etc/system/local/savedsearches.conf` n'a **pas de
> contexte propriétaire/app** → le scheduler ne l'exécute jamais.

**a. La recherche** (Search & Reporting) :

```spl
index=main sourcetype=suricata:json event_type=alert
| rename "alert.signature" AS signature, "alert.severity" AS sig_sev
| search (signature="POSSBL*" OR signature="SOC *" OR sig_sev<=2)
| stats min(_time) AS _time count AS hits values(signature) AS sigs
        by src_ip dest_ip
| where hits >= 3
| eval search_name="Suricata IDS: ".mvjoin(sigs," | "),
       severity="high", host=dest_ip, user="N/A", source="suricata"
```

> Pour le SSH sur `auth.log` (déjà remonté par le forwarder), ajoutez une
> seconde alerte identique sur
> `sourcetype=linux_secure ("Failed password" OR "Invalid user")`.

**b. Enregistrer sous → Alerte** :

| Réglage | Valeur |
|---|---|
| Titre | `SOAR-Suricata-TheHive` |
| Autorisation | **Partagé dans l'application** |
| Type d'alerte | **Planifié → Exécuter sur Cron** `*/1 * * * *` |
| Intervalle de temps | `-5m@m` → `now` |
| Déclencher quand | **Nombre de résultats** *est supérieur à* `0` |
| Déclencher | **Pour chaque résultat** |
| Throttle | ✅ `120` s, champ `src_ip` |
| **+ Actions → Webhook** | URL `http://<IP-Service-A>:5000/alert` |

> 🔴 **`http://`, pas `https://`** — Service A est un serveur Flask en HTTP clair.
> Une URL `https://` fait échouer le handshake TLS, aucun webhook n'est livré.

**Vérification** :

```bash
# depuis l'indexeur, il exécute l'action webhook :
curl -s http://<IP-Service-A>:5000/health ; echo

# la recherche est-elle bien planifiée ?
$SPLUNK_HOME/bin/splunk search \
  'index=_internal sourcetype=scheduler savedsearch_name="SOAR-Suricata-TheHive" earliest=-15m | table _time status result_count' \
  -auth admin:<mdp>
```
`status=success` et, quand une attaque est en cours, `result_count>0`.

---

## Étape 6 — Le pipeline Python

Sur la **machine pipeline** (peut être n'importe où, du moment qu'elle joint
TheHive et reçoit le webhook de Splunk).

```bash
cd SOAR
python start.py install
python start.py init            # copie .env.example → .env
nano .env
```

Renseignez au minimum :

```ini
THEHIVE_URL=http://<IP-TheHive>:9000
THEHIVE_APIKEY=<clé de l'utilisateur analyste, PAS admin>
CORTEX_URL=http://<IP-Cortex>:9001
CORTEX_APIKEY=<clé Cortex>
VT_APIKEY=<clé VirusTotal gratuite>

LISTEN_HOST=0.0.0.0            # ⚠️ 0.0.0.0, pas une IP fixe : sinon /test et
LISTEN_PORT=5000              #    les appels locaux échouent, et le service
                             #    plante si l'IP n'est pas locale
POLL_INTERVAL=20
ACTIVE_RESPONSE=false         # simulation par défaut — voir Étape 7
TELEGRAM_ENABLED=true         # optionnel
TELEGRAM_TOKEN=...
TELEGRAM_CHAT_ID=...
```

### Lancer en service (systemd, redémarrage auto)

```bash
PY=$(command -v python3); APP=$(pwd)

sudo tee /etc/systemd/system/soar-a.service >/dev/null <<EOF
[Unit]
Description=SOAR Service A - webhook Splunk -> TheHive
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
WorkingDirectory=$APP
ExecStart=$PY $APP/src/service_a_splunk_to_thehive.py
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/soar-b.service >/dev/null <<EOF
[Unit]
Description=SOAR Service B - responder TheHive (Cortex / MISP / firewall)
After=network-online.target soar-a.service
Wants=network-online.target
[Service]
Type=simple
User=root
WorkingDirectory=$APP
ExecStart=$PY $APP/src/service_b_thehive_responder.py run
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now soar-a.service soar-b.service
```

> `User=root` est nécessaire pour la réponse active (`iptables` / `netsh`).
> `soar-b` redémarre seul si TheHive est momentanément injoignable — plus de
> boucle infinie perdue.

Pour un lancement manuel rapide : `python start.py both`.

**Vérification**

```bash
ss -ltnp | grep 5000                       # Service A écoute sur 0.0.0.0:5000
curl -s http://127.0.0.1:5000/health | python3 -m json.tool
curl -s -XPOST http://127.0.0.1:5000/alert -H 'Content-Type: application/json' \
  -d '{"search_name":"TEST","severity":"high","result":{"host":"h1","src_ip":"45.155.205.233","dest_ip":"10.0.0.5","user":"root","_time":"2026-01-01T00:00:00Z"}}' \
  | python3 -m json.tool
```
→ `"status": "created"` + un cas apparaît dans TheHive quelques secondes plus tard
(`journalctl -u soar-b -f`).

---

## Étape 7 — Activer la réponse active (optionnel)

Par défaut **tout est en simulation** : le pipeline détecte, journalise et notifie
ce qu'il *aurait* fait, sans rien bloquer ni déplacer.

```ini
# .env
ACTIVE_RESPONSE=true          # blocage iptables / netsh réel
BLOCK_DURATION_MIN=10         # déblocage auto après ce délai
BLOCK_ALL_IPS=false           # true = bloque aussi les IP internes (lab only)

FILE_RESPONSE_ENABLED=true    # neutralisation des fichiers malveillants
FILE_RESPONSE_MODE=quarantine # quarantine (réversible) | delete | report
FILE_SCAN_PATHS=/srv/partage,/home/user/Downloads
```

```bash
sudo systemctl restart soar-b            # Linux : root requis pour iptables
python start.py test-block 203.0.113.10  # prouve le blocage de bout en bout
python start.py list                     # IP bloquées
python start.py unblock <ip>             # déblocage manuel
```

Les répertoires système (`C:\Windows`, `/etc`, `/usr`, `/bin`…) sont refusés
par construction, même listés dans `FILE_SCAN_PATHS`.

---

## Étape 8 — Vérification bout en bout

```bash
# 1. attaque depuis une machine tierce
nmap -sS -p1-1000 <ip-capteur>
hydra -l root -P wordlist.txt ssh://<ip-capteur>     # ou une boucle ssh

# 2. sur la machine pipeline
watch -n2 'curl -s http://127.0.0.1:5000/stats | jq .stats'
journalctl -u soar-a -u soar-b -f
```

Chaîne attendue, en moins d'une minute :

```
Suricata fast.log : POSSBL PORT SCAN (NMAP -sS)
Splunk scheduler  : SOAR-Suricata-TheHive  status=success result_count=1
Service A         : Alerte TheHive créée : id=... obs=N vt=1
Service B         : ALERTE ... → Cas #N créé
Service B         : Cortex : lancement de K analyseur(s) sur [ip] <src>
TheHive cas #N    : commentaires VirusTotal + Cortex, tags vt-malicious / cortex-*
Telegram          : « Cas #N créé », verdicts, décision de blocage
```

Le harnais d'intégration rejoue toute cette chaîne hors ligne :

```bash
python start.py e2e
```

---

# 🧰 Commandes

Tout passe par `python start.py` (menu interactif si lancé sans argument).

| Commande | Effet |
|---|---|
| `install` | installe les dépendances Python |
| `init` | crée `.env` depuis `.env.example` |
| `a` / `b` / `both` | démarre Service A / B / les deux |
| `status` | état complet du pipeline |
| `unit` | 168 tests unitaires hors ligne |
| `e2e` | 44 vérifications d'intégration contre un faux TheHive |
| `cortex` | recharge le registre des analyseurs Cortex |
| `list` / `unblock <ip>` / `test-block <ip>` | gestion des blocages |
| `files` / `scan <hash>` / `restore <id>` / `purge <id>` | réponse fichiers |
| `telegram-config` | configuration guidée du bot Telegram |
| `logs` | suit `logs/service_a.log` et `logs/service_b.log` |

Endpoints du Service A : `POST /alert` · `GET /health` · `GET /test` ·
`GET /telegram-test` · `GET /vt-test` · `GET /debug` · `GET /stats`.

---

# 🐛 Dépannage

| Symptôme | Cause / correctif |
|---|---|
| Service A plante au démarrage (`Cannot assign requested address`) | `LISTEN_HOST` pointe une IP non locale → mettre `0.0.0.0` |
| `GET /test` ou `curl 127.0.0.1:5000` échoue | idem : `LISTEN_HOST=0.0.0.0` |
| Service B : `Connection refused` en boucle sur `:9000` | la stack Docker n'est pas démarrée / pas encore prête |
| Service B ne voit aucune alerte | clé API = **super-admin** → utiliser une clé d'utilisateur d'organisation |
| `received: 0` dans `/stats` malgré des alertes Splunk | l'action webhook n'est pas déclenchée → licence Splunk *Free* (alerting désactivé), ou recherche non planifiée, ou URL en `https://` |
| Recherche Splunk jamais exécutée (`sourcetype=scheduler` vide) | saved search dans `system/local` → la recréer **via l'UI** (contexte owner/app) |
| Cas créé mais **Cortex ne se lance pas** (`analyseurs en cours=0`) | observables recopiés par la promotion → corrigé dans `soc_common.py` (`find_case_observable`) ; sinon connecteur Cortex non testé dans TheHive |
| Jobs Cortex tous en **Failure**, `errorMessage` = chemin `/tmp/cortex-jobs/…` | `/tmp/cortex-jobs` non accessible en écriture au conteneur → `chmod 777` + règle `tmpfiles.d` |
| Jobs Cortex **Failure**, `input: null` | image du neuron absente → `scripts/pull-cortex-analyzers.sh` (bon registre = `ghcr.io/thehive-project/…`) |
| Jobs Cortex : *« TLP is above the maximum allowed »* | `Max TLP` de l'analyseur < AMBER → passer à `AMBER (2)` |
| Jobs Cortex en échec sur `10.x` / `239.x` / `0.0.0.0` | normal (IP non publique) — corrigé : Service B ne soumet plus le non-routable |
| Suricata inonde `fast.log` de `SURICATA Ethertype unknown` | bruit L2 du bridge — le script d'install le coupe déjà (`suppress` + `#*events.rules`) |
| Aucun `event_type: alert` dans Splunk | règles Suricata non chargées (`suricata-update`) ou attaque interne non couverte |
| Champs non extraits côté Splunk | `props.conf` `[suricata:json]` `KV_MODE=json` manquant / mauvais sourcetype |
| Telegram/Gmail muets | `NOTIFY_MIN_SEV` trop haut ; Gmail = **mot de passe d'application** ; port 465 sortant ouvert |
| `invalid literal for int()` | commentaire de fin de ligne sans chiffre dans `.env` |

Journaux :

```bash
journalctl -u soar-a -u soar-b -f
tail -f logs/service_a.log logs/service_b.log
docker compose logs -f thehive cortex.local
```

---

# 🗂️ Structure du dépôt

```
SOAR/
├── start.py                              Lanceur universel
├── README.md                            Ce guide
├── INSTALL.md                           Notes détaillées Docker / Suricata / Splunk
├── .env.example                         Configuration commentée, exhaustive
│
├── src/
│   ├── soc_common.py                    Socle : .env, logs, client TheHive REST v1
│   ├── service_a_splunk_to_thehive.py   Service A — webhook            v8.0.0
│   ├── service_b_thehive_responder.py   Service B — responder auto     v11.0.0
│   └── file_responder.py               Recherche par hash, quarantaine
│
├── scripts/
│   ├── install-suricata-soc.sh         Installe le capteur Suricata + règles custom
│   └── pull-cortex-analyzers.sh        Pré-télécharge les images d'analyseurs Cortex
│
├── docker/                              Stack TheHive + Cortex + MISP
├── suricata/soc-custom.rules            Détection NMAP, SSH brute force, Metasploit
├── tests/                               168 tests unitaires + 44 e2e, hors ligne
└── data/  logs/                         Généré à l'exécution
```

---

# ✅ Qualité

- **168 tests unitaires** hors ligne : aucune requête réseau, aucune règle
  pare-feu posée, aucun fichier touché hors du bac à sable. → `python start.py unit`
- **44 vérifications d'intégration** bout en bout contre un faux serveur TheHive 5 :
  webhook → alerte → cas → observables → jobs Cortex → verdicts → rapport →
  décision de blocage → quarantaine. → `python start.py e2e`
- **Pas de dépendance native.** Le projet parle directement à l'API REST v1 de
  TheHive 5 (pas de `thehive4py`, abandonné et cassé sous Windows).

---

# 👤 Auteur

**Rachad Aledji** — alias **12ak_H4ck**
[![LinkedIn](https://img.shields.io/badge/LinkedIn-ar--rachad--aledji-0A66C2?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/ar-rachad-aledji/)
[![GitHub](https://img.shields.io/badge/GitHub-Rachkpt-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/Rachkpt)

Contributions : voir les *issues* / *pull requests* du dépôt.

# 📄 Licence

MIT — voir [LICENSE](LICENSE).
