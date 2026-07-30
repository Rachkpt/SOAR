# 🛡️ SOC Automation Pipeline (SOAR)

<div align="center">

**Détection et réponse aux incidents, entièrement automatisées**

Suricata / Splunk → TheHive → Cortex → MISP → VirusTotal → Réponse active → Telegram

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![TheHive](https://img.shields.io/badge/TheHive-5.2.x-F5A800?style=for-the-badge)](https://docs.strangebee.com/thehive/)
[![Cortex](https://img.shields.io/badge/Cortex-3.x-FF6B35?style=for-the-badge)](https://github.com/TheHive-Project/Cortex)
[![MISP](https://img.shields.io/badge/MISP-2.4%2B-CC0000?style=for-the-badge)](https://www.misp-project.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docs.docker.com/compose)
[![Tests](https://img.shields.io/badge/Tests-168%20unitaires-22C55E?style=for-the-badge)](tests/)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)](LICENSE)

**[📦 Guide d'installation complet → INSTALL.md](INSTALL.md)**

</div>

---

## À quoi sert ce projet

Dans un SOC, la partie pénible n'est pas de détecter une attaque : c'est tout ce
qui vient après. Ouvrir un ticket, chercher qui est l'IP, lancer les analyses,
vérifier si l'IoC est déjà connu, bloquer la source, prévenir l'équipe. À chaque
alerte. Toute la nuit.

Ce projet fait ce travail à votre place, du bout en bout.

Une alerte arrive depuis **Splunk** ou **Suricata**. Trente secondes plus tard, un
cas d'investigation existe dans **TheHive**, ses observables ont été analysés par
**Cortex**, comparés à **VirusTotal** et à **MISP**, l'IP attaquante est bloquée
au niveau du pare-feu, le fichier malveillant est en quarantaine, et un rapport
complet attend l'analyste — qui a reçu une notification **Telegram**.

Aucune intervention humaine dans la boucle.

---

## Ce que fait le pipeline, concrètement

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

## La réponse active

C'est ce qui distingue ce projet d'un simple connecteur : il **agit**.

### Blocage des adresses IP

Le pipeline classe chaque alerte par catégorie de menace, puis bloque la source
au niveau du pare-feu du système — `netsh advfirewall` sous Windows, `iptables`
sous Linux — dans les deux sens, entrant et sortant.

| Catégorie détectée | Exemples de déclencheurs |
|--------------------|--------------------------|
| **Scan de ports** | règles Suricata NMAP `-sS -sT -sA -sX -sU -f`, masscan, zmap |
| **Force brute** | échecs d'authentification répétés, EventCode 4625, SSH |
| **Exploitation** | Metasploit, meterpreter, reverse shell, port 4444 |
| **Mouvement latéral** | psexec, wmic, winrm, pass-the-hash, SMB, RDP |
| **Vol d'identifiants** | mimikatz, accès à lsass, secretsdump, ntds.dit |
| **Rançongiciel** | `vssadmin delete`, `wbadmin delete`, suppression de clichés |
| **Exfiltration** | volumétrie sortante anormale, alertes DLP |
| **Verdict externe** | VirusTotal au-dessus du seuil, ou IoC déjà présent dans MISP |

Le blocage expire tout seul après le délai configuré, et l'IP est débloquée sans
intervention. À tout moment : `python start.py list` pour voir les IP bloquées,
`python start.py unblock <ip>` pour en libérer une.

### Neutralisation des fichiers malveillants

Quand VirusTotal ou MISP confirme qu'un hash est malveillant, le pipeline
**retrouve le fichier sur les dossiers surveillés** et le neutralise :

- **`quarantine`** — le fichier est déplacé dans un coffre, hors d'atteinte, et
  reste restaurable en une commande. C'est le mode recommandé.
- **`delete`** — suppression définitive.
- **`report`** — signalement seul, aucune action.

Les répertoires système (`C:\Windows`, `/etc`, `/usr`, `/bin`…) sont refusés par
construction, même s'ils sont explicitement listés dans la configuration. Aucun
dossier n'est analysé tant que vous n'en avez désigné un.

> ⚠️ **Le mode simulation est le comportement par défaut.** `ACTIVE_RESPONSE=false`
> et `FILE_RESPONSE_ENABLED=false` : le pipeline détecte, journalise et notifie
> tout ce qu'il *aurait* fait, sans rien bloquer ni déplacer. Observez d'abord,
> activez ensuite. Le détail est dans [INSTALL.md](INSTALL.md#-activer-la-réponse-active).

---

## Architecture

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
│               ┌─────────────┐            ┌─────────────┐  ┌─────────────┐
│               │   Cortex    │            │    MISP     │  │ VirusTotal  │
│               │   :9001     │            │   :80/443   │  │   API v3    │
│               │ AbuseIPDB   │            │  IoC / TI   │  │ IP · hash   │
│               │ MaxMind     │            │             │  │ domaine·URL │
│               │ Shodan…     │            └─────────────┘  └─────────────┘
│               └─────────────┘                                        │
│                        │                                             │
│        ┌───────────────┼───────────────┬───────────────┐             │
│        ▼               ▼               ▼               ▼             │
│ ┌────────────┐ ┌──────────────┐ ┌────────────┐ ┌────────────┐        │
│ │  Pare-feu  │ │ Quarantaine  │ │  Rapport   │ │  Telegram  │        │
│ │netsh/iptbls│ │  fichiers    │ │  TheHive   │ │notifications│       │
│ └────────────┘ └──────────────┘ └────────────┘ └────────────┘        │
└──────────────────────────────────────────────────────────────────────┘
```

| Composant | Rôle | Port |
|-----------|------|------|
| **Service A** | Webhook Flask — reçoit et enrichit les alertes | 5000 |
| **Service B** | Responder — orchestre analyse et réponse active | — |
| **TheHive** | Gestion des alertes et des cas | 9000 |
| **Cortex** | Moteur d'analyse automatique | 9001 |
| **MISP** | Plateforme de Threat Intelligence | 80 / 443 |
| **Suricata** | IDS réseau | — |
| **Splunk** | SIEM, source des alertes | 8000 |

---

## Structure du dépôt

```
SOAR/
├── start.py                              Lanceur universel — tout passe par là
├── INSTALL.md                            Guide d'installation et toutes les commandes
├── .env.example                          Configuration commentée, exhaustive
│
├── src/
│   ├── soc_common.py                     Socle : .env, journaux, client TheHive REST v1
│   ├── service_a_splunk_to_thehive.py    Service A — webhook            v8.0.0
│   ├── service_b_thehive_responder.py    Service B — responder auto     v11.0.0
│   └── file_responder.py                 Recherche par hash, quarantaine, suppression
│
├── docker/                               Stack complète TheHive + Cortex + MISP
├── suricata/soc-custom.rules             Détection NMAP et Metasploit
├── tests/                                168 tests unitaires, hors ligne
└── data/  logs/                          Généré à l'exécution
```

---

## Démarrage

```bash
git clone https://github.com/Rachkpt/SOAR.git
cd SOAR
python start.py install
python start.py init
python start.py both
```

`python start.py` sans argument ouvre un menu interactif qui couvre l'ensemble
des fonctions.

L'infrastructure Docker, la configuration de TheHive, Cortex, MISP, Suricata et
Splunk, l'activation de la réponse active et le dépannage sont détaillés dans
**[INSTALL.md](INSTALL.md)**.

---

## Prérequis

| | |
|---|---|
| **Python** | 3.8 minimum, testé jusqu'à 3.13 |
| **Dépendances** | `flask`, `requests`, `urllib3` — c'est tout |
| **Serveur Docker** | 4 cœurs, 8 Go de RAM, 50 Go de disque au minimum |
| **Systèmes** | Ubuntu, Debian, CentOS, Windows 10/11, macOS |
| **Clés API** | TheHive, Cortex, VirusTotal (gratuite), MISP et Telegram optionnels |

---

## Qualité

- **168 tests unitaires**, entièrement hors ligne : aucune requête réseau, aucune
  règle pare-feu posée, aucun fichier touché hors du bac à sable de test.
  → `python start.py unit`
- **44 vérifications d'intégration bout en bout** contre un serveur TheHive
  simulé : webhook → alerte → cas → observables → jobs Cortex → verdicts →
  rapport → décision de blocage → quarantaine du fichier malveillant.
  → `python start.py e2e`
- **Pas de dépendance native.** Le projet parle directement à l'API REST v1 de
  TheHive 5. `thehive4py` n'est pas utilisé : la bibliothèque est abandonnée et
  importe `libmagic`, ce qui fait planter l'interpréteur Python sous Windows.

---

## Licence

MIT — voir [LICENSE](LICENSE).

---

<div align="center">

**SOC Automation Pipeline** — lab SOC personnel

⭐ Une étoile si le projet vous a aidé

</div>
