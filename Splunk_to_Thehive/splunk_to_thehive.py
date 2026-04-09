#!/usr/bin/env python3
"""
splunk_to_thehive.py  —  SOC Rachad (version corrigée)
=======================================================
Passerelle Splunk -> TheHive

CORRECTIONS v2 :
- Gère TOUS les formats de payload Splunk (result, results, racine, vide)
- Endpoint /debug pour voir exactement ce que Splunk envoie
- Endpoint /test pour tester sans Splunk
- Alerte acceptée même sans src_ip (payload minimal)
- Meilleure gestion des doublons
- Logs plus détaillés pour diagnostiquer

Usage :
source splunk_thehive_env/bin/activate
export THEHIVE_APIKEY="J9LiEsGJDFFfDmBuAKyj+MUmWyytwNTx"
python3 splunk_to_thehive.py

Splunk webhook URL : http://10.2.3.114:5000/alert
"""

import os
import json
import hashlib
import logging
from datetime import datetime

from flask import Flask, request, jsonify
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact

# =============================================================
# LOGGING
# =============================================================
logging.basicConfig(
level=logging.INFO,
format="%(asctime)s [%(levelname)s] %(message)s",
datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# =============================================================
# CONFIGURATION
# =============================================================
THEHIVE_URL    = os.getenv("THEHIVE_URL",    "http://10.2.3.122:9000")
THEHIVE_APIKEY = os.getenv("THEHIVE_APIKEY", "J9LiEsGJDFFfDmBuAKyj+MUmWyytwNTx")
LISTEN_HOST    = os.getenv("LISTEN_HOST",    "0.0.0.0")
LISTEN_PORT    = int(os.getenv("LISTEN_PORT", "5000"))

# =============================================================
# MAPPINGS
# =============================================================
SEVERITY_MAP = {
"critical": 4, "high": 3, "medium": 2,
"low": 1, "info": 1, "unknown": 2,
}

AUTO_TAGS = {
"brute":       "brute_force",
"ssh":         "ssh",
"failed pass": "failed_auth",
"failed":      "failed_auth",
"lateral":     "lateral_movement",
"mimikatz":    "credential_dumping",
"psexec":      "lateral_movement",
"ransom":      "ransomware",
"scan":        "port_scan",
"download":    "malicious_download",
"privilege":   "privilege_escalation",
"sudo":        "privilege_escalation",
"admin":       "admin_activity",
"vssadmin":    "ransomware",
"powershell":  "powershell",
"4625":        "failed_auth",
"4688":        "process_creation",
"4648":        "explicit_logon",
"4672":        "privilege_escalation",
}

# =============================================================
# INIT
# =============================================================
app = Flask(__name__)
api = TheHiveApi(THEHIVE_URL, THEHIVE_APIKEY)

# Stocke les derniers payloads reçus pour debug
_debug_payloads = []


# =============================================================
# UTILITAIRES
# =============================================================

def map_severity(s: str) -> int:
return SEVERITY_MAP.get(str(s).lower(), 2)


def generate_source_ref(search_name: str, result: dict) -> str:
raw = "{}-{}-{}".format(
search_name,
result.get("src_ip", result.get("host", "")),
result.get("_time", datetime.utcnow().isoformat()),
)
return "splunk-" + hashlib.md5(raw.encode()).hexdigest()[:12]


def detect_auto_tags(search_name: str, result: dict) -> list:
tags = ["splunk", "auto-created"]
combined = (search_name + " " + json.dumps(result)).lower()
for pattern, tag in AUTO_TAGS.items():
if pattern in combined and tag not in tags:
tags.append(tag)
source = result.get("source", "").lower()
index  = result.get("index",  "").lower()
if "windows" in index or "winevent" in source:
tags.append("windows")
elif "linux" in index or "auth.log" in source or "syslog" in source:
tags.append("linux")
return tags


def extract_artifacts(result: dict) -> list:
artifacts = []

# IP source
src_ip = str(result.get("src_ip", result.get("src", ""))).strip()
if src_ip and src_ip not in ("-", "N/A", "", "none", "null"):
artifacts.append(AlertArtifact(
dataType="ip", data=src_ip,
message="IP source (Splunk)", tags=["splunk", "src_ip"], ioc=True,
))

# IP destination
dest_ip = str(result.get("dest_ip", result.get("dest", ""))).strip()
if dest_ip and dest_ip not in ("-", "N/A", "", "none", "null"):
artifacts.append(AlertArtifact(
dataType="ip", data=dest_ip,
message="IP destination (Splunk)", tags=["splunk", "dest_ip"],
))

# Utilisateur
user = str(result.get("user", result.get("User", result.get("username", "")))).strip()
if user and user not in ("-", "N/A", "", "none", "null"):
artifacts.append(AlertArtifact(
dataType="other", data=user,
message="Utilisateur impliqué", tags=["splunk", "user"],
))

# Hash
file_hash = str(result.get("file_hash", result.get("hash", result.get("md5", "")))).strip()
if file_hash and len(file_hash) in (32, 40, 64):
artifacts.append(AlertArtifact(
dataType="hash", data=file_hash,
message="Hash fichier suspect", tags=["splunk", "malware"], ioc=True,
))

# Domaine
domain = str(result.get("domain", result.get("dest_domain", result.get("query", "")))).strip()
if domain and domain not in ("-", "N/A", "", "none", "null") and "." in domain:
artifacts.append(AlertArtifact(
dataType="domain", data=domain,
message="Domaine suspect", tags=["splunk", "network"], ioc=True,
))

# URL
url = str(result.get("url", result.get("uri", ""))).strip()
if url and url.startswith(("http://", "https://")):
artifacts.append(AlertArtifact(
dataType="url", data=url,
message="URL suspecte", tags=["splunk", "network"], ioc=True,
))

# Hostname comme artifact si pas d'IP
if not artifacts:
host = str(result.get("host", "")).strip()
if host and host not in ("-", "N/A", ""):
artifacts.append(AlertArtifact(
dataType="other", data=host,
message="Hôte source", tags=["splunk", "host"],
))

return artifacts


def build_description(search_name: str, result: dict, raw_payload: dict) -> str:
lines = [
"## Alerte Splunk : {}".format(search_name),
"",
"### Informations générales",
"- **Hôte**        : `{}`".format(result.get("host",   "N/A")),
"- **Source**      : `{}`".format(result.get("source", "N/A")),
"- **Index**       : `{}`".format(result.get("index",  "N/A")),
"- **Horodatage**  : `{}`".format(result.get("_time",  "N/A")),
"",
"### Indicateurs détectés",
"- **IP source**   : `{}`".format(result.get("src_ip",       result.get("src", "N/A"))),
"- **IP dest**     : `{}`".format(result.get("dest_ip",      result.get("dest", "N/A"))),
"- **Utilisateur** : `{}`".format(result.get("user",         result.get("username", "N/A"))),
"- **Processus**   : `{}`".format(result.get("process_name", result.get("Image", "N/A"))),
"- **Domaine**     : `{}`".format(result.get("domain",       "N/A")),
"- **Hash**        : `{}`".format(result.get("file_hash",    result.get("hash", "N/A"))),
"",
"### Données brutes Splunk",
"```json",
json.dumps(result, indent=2, ensure_ascii=False),
"```",
"",
"> *Alerte créée automatiquement par la passerelle Splunk → TheHive*",
]
return "\n".join(lines)


def parse_splunk_payload(data: dict) -> tuple:
"""
Parse TOUS les formats possibles de payload Splunk :

Format 1 (standard webhook) :
{"search_name": "...", "severity": "high", "result": {"src_ip": "...", ...}}

Format 2 (splunk alert avec résultats multiples) :
{"search_name": "...", "results": [{"src_ip": "..."}, ...]}

Format 3 (custom alert action) :
{"name": "...", "result": {...}}

Format 4 (payload plat - tout à la racine) :
{"search_name": "...", "src_ip": "...", "host": "..."}

Retourne : (search_name, severity, result_dict)
"""
search_name = (
data.get("search_name")
or data.get("name")
or data.get("alert_name")
or "Alerte Splunk"
)
severity = (
data.get("severity")
or data.get("alert.severity")
or data.get("urgency")
or "medium"
)

# Essai 1 : champ "result" (dict)
result = data.get("result")
if isinstance(result, dict) and result:
return search_name, severity, result

# Essai 2 : champ "results" (liste)
results_list = data.get("results")
if isinstance(results_list, list) and results_list:
return search_name, severity, results_list[0]

# Essai 3 : payload plat (les champs sont directement à la racine)
# Détecte si des champs "intéressants" sont à la racine
ioc_fields = {"src_ip","dest_ip","user","host","source","index",
"process_name","file_hash","domain","url","_time","hash","src","dest"}
flat_result = {k: v for k, v in data.items()
if k in ioc_fields or k.startswith("result.")}
if flat_result:
log.info("Format payload plat détecté — champs extraits : {}".format(list(flat_result.keys())))
return search_name, severity, flat_result

# Essai 4 : champ "result" mais string JSON
result_str = data.get("result")
if isinstance(result_str, str):
try:
result = json.loads(result_str)
if isinstance(result, dict):
return search_name, severity, result
except Exception:
pass

# Aucun résultat trouvé → on retourne quand même avec un dict minimal
# pour ne pas rejeter l'alerte complètement
minimal = {
"host":    data.get("host", data.get("server_host", "N/A")),
"source":  data.get("source", "Splunk Webhook"),
"_time":   data.get("_time", datetime.utcnow().isoformat()),
}
log.warning("Aucun champ 'result' trouvé — utilisation du payload minimal : {}".format(minimal))
return search_name, severity, minimal


# =============================================================
# ENDPOINTS
# =============================================================

@app.route("/alert", methods=["POST"])
def receive_alert():
"""
Endpoint principal : reçoit les alertes Splunk.
Configure dans Splunk : Alerts > Add Actions > Webhook > http://10.2.3.114:5000/alert
"""
global _debug_payloads

try:
raw_body = request.get_data(as_text=True)
data = request.get_json(force=True, silent=True)

log.info("=" * 60)
log.info("ALERTE REÇUE depuis {}".format(request.remote_addr))
log.info("Body brut (500 chars) : {}".format(raw_body[:500]))
log.info("=" * 60)

# Stocker pour /debug
_debug_payloads.append({
"timestamp": datetime.utcnow().isoformat(),
"ip": request.remote_addr,
"raw": raw_body[:2000],
"parsed": data,
})
if len(_debug_payloads) > 20:
_debug_payloads = _debug_payloads[-20:]

if not data:
log.warning("Payload vide ou non-JSON — body : {}".format(raw_body[:200]))
return jsonify({"status": "error", "reason": "payload non-JSON ou vide"}), 400

search_name, severity, result = parse_splunk_payload(data)

log.info("Alerte parsée : '{}' | sév={} | hôte={}".format(
search_name, severity, result.get("host", "N/A")
))
log.info("Champs result : {}".format(list(result.keys())))

# Construire l'alerte TheHive
source_ref  = generate_source_ref(search_name, result)
tags        = detect_auto_tags(search_name, result)
artifacts   = extract_artifacts(result)
description = build_description(search_name, result, data)

log.info("Artifacts extraits : {}".format(
[(a.dataType, a.data) for a in artifacts]
))

alert = Alert(
title       = "[SPLUNK] {}".format(search_name),
tlp         = 2,
severity    = map_severity(severity),
status      = "New",
type        = "external",
source      = "Splunk",
sourceRef   = source_ref,
description = description,
tags        = tags,
artifacts   = artifacts,
)

response = api.create_alert(alert)

if response.status_code == 201:
alert_id = response.json().get("id", "?")
log.info("✅ Alerte TheHive créée : id={} | ref={}".format(alert_id, source_ref))
return jsonify({
"status": "created",
"alert_id": alert_id,
"source_ref": source_ref,
"artifacts_count": len(artifacts),
}), 201

elif response.status_code in (400, 409) and (
"already exists" in response.text.lower()
or "duplicate" in response.text.lower()
):
log.info("Doublon détecté, ignoré : ref={}".format(source_ref))
return jsonify({"status": "duplicate", "source_ref": source_ref}), 200

else:
log.error("❌ Erreur TheHive HTTP {} : {}".format(
response.status_code, response.text[:300]
))
return jsonify({
"status": "error",
"http_code": response.status_code,
"detail": response.text,
}), 500

except Exception as e:
log.exception("Erreur inattendue : {}".format(e))
return jsonify({"status": "error", "detail": str(e)}), 500


@app.route("/debug", methods=["GET"])
def debug():
"""
Affiche les 20 derniers payloads reçus de Splunk.
Utilise : curl http://10.2.3.114:5000/debug | python3 -m json.tool
"""
return jsonify({
"total_received": len(_debug_payloads),
"last_payloads": _debug_payloads,
}), 200


@app.route("/test", methods=["GET", "POST"])
def test_alert():
"""
Crée une alerte de test dans TheHive sans passer par Splunk.
Utilise : curl http://10.2.3.114:5000/test
"""
fake_payload = {
"search_name": "TEST - Brute Force SSH depuis 10.2.3.50",
"severity": "high",
"result": {
"host":         "server-client",
"source":       "/var/log/auth.log",
"index":        "linux_logs",
"src_ip":       "10.2.3.50",
"dest_ip":      "10.2.3.114",
"user":         "root",
"process_name": "sshd",
"_time":        datetime.utcnow().isoformat(),
"count":        "121",
"message":      "Failed password for root from 10.2.3.50 port 37934 ssh2",
}
}
# Injecter dans le flux normal
import requests as req
try:
r = req.post(
"http://127.0.0.1:{}{}".format(LISTEN_PORT, "/alert"),
json=fake_payload,
timeout=10,
)
return jsonify({
"status": "test_sent",
"webhook_response": r.json(),
"http_code": r.status_code,
}), 200
except Exception as e:
return jsonify({"status": "error", "detail": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
"""Health check — vérifie connexion TheHive."""
try:
resp = api.find_alerts(query={}, range="0-1")
thehive_ok = resp.status_code == 200
except Exception:
thehive_ok = False

return jsonify({
"status":            "ok" if thehive_ok else "degraded",
"service":           "splunk-to-thehive",
"thehive_url":       THEHIVE_URL,
"thehive_reachable": thehive_ok,
"timestamp":         datetime.utcnow().isoformat() + "Z",
"endpoints": {
"alert":  "POST /alert  — webhook Splunk",
"debug":  "GET  /debug  — voir derniers payloads reçus",
"test":   "GET  /test   — envoyer alerte de test",
"health": "GET  /health — ce endpoint",
}
}), 200 if thehive_ok else 503


# =============================================================
# MAIN
# =============================================================
if __name__ == "__main__":
log.info("=" * 60)
log.info("  Passerelle Splunk -> TheHive  (v2 corrigée)")
log.info("=" * 60)
log.info("  TheHive  : {}".format(THEHIVE_URL))
log.info("  Écoute   : http://{}:{}".format(LISTEN_HOST, LISTEN_PORT))
log.info("  Webhook  : POST /alert")
log.info("  Debug    : GET  /debug")
log.info("  Test     : GET  /test")
log.info("  Health   : GET  /health")
log.info("=" * 60)
app.run(host=LISTEN_HOST, port=LISTEN_PORT, debug=False)
