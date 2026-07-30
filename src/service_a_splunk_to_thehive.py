#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  SOC Automation Pipeline — Service A                        ║
║  Splunk → TheHive  (webhook + enrichissement VirusTotal)    ║
║  Version : 8.0.0                                            ║
╚══════════════════════════════════════════════════════════════╝

Flux :
  Alerte Splunk → POST /alert → parsing → enrichissement VT
                → alerte TheHive → Telegram / Gmail

Endpoints :
  POST /alert          Webhook Splunk
  GET  /health         Health check complet
  GET  /test           Envoie une alerte de test
  GET  /telegram-test  Teste Telegram
  GET  /vt-test        Teste VirusTotal
  GET  /debug          Derniers payloads reçus
  GET  /stats          Statistiques du service

Nouveautés v8.0.0 :
  - Client TheHive REST v1 natif (fin de la dépendance thehive4py,
    abandonnée et cassée sous Windows à cause de libmagic)
  - Parsing .env tolérant aux commentaires en fin de ligne
  - Console UTF-8 sous Windows, plus de UnicodeEncodeError
  - datetime.utcnow() (déprécié) remplacé partout
"""

import base64
import hashlib
import ipaddress
import json
import re
import smtplib
import sys
import threading
import time
from collections import defaultdict
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from functools import wraps

import requests
from flask import Flask, jsonify, request

from soc_common import (
    DATA_DIR, LOGS_DIR, Observable, Telegram, TheHiveClient,
    enable_utf8_console, env_bool, env_int, env_str, load_dotenv,
    now_str, resolve_path, setup_logger, utcnow_iso,
)

VERSION = "8.0.0"

enable_utf8_console()
ENV_PATH = load_dotenv()


# ──────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────
class Config:
    def __init__(self):
        self.THEHIVE_URL        = env_str("THEHIVE_URL", "http://127.0.0.1:9000")
        self.THEHIVE_APIKEY     = env_str("THEHIVE_APIKEY")
        self.THEHIVE_VERIFY_SSL = env_bool("THEHIVE_VERIFY_SSL", True)

        self.LISTEN_HOST = env_str("LISTEN_HOST", "0.0.0.0")
        self.LISTEN_PORT = env_int("LISTEN_PORT", 5000)

        self.VT_ENABLED        = env_bool("VT_ENABLED", True)
        self.VT_APIKEY         = env_str("VT_APIKEY")
        self.VT_TIMEOUT        = env_int("VT_TIMEOUT", 15)
        self.VT_MIN_DETECTIONS = env_int("VT_MIN_DETECTIONS", 2)

        self.RATE_LIMIT_SEC  = env_int("RATE_LIMIT_SEC", 10)
        self.RETRY_ATTEMPTS  = env_int("RETRY_ATTEMPTS", 3)
        self.RETRY_DELAY_SEC = env_int("RETRY_DELAY_SEC", 5)
        self.NOTIFY_MIN_SEV  = env_int("NOTIFY_MIN_SEV", 3)

        self.TELEGRAM_ENABLED = env_bool("TELEGRAM_ENABLED", False)
        self.TELEGRAM_TOKEN   = env_str("TELEGRAM_TOKEN")
        self.TELEGRAM_CHAT_ID = env_str("TELEGRAM_CHAT_ID")

        self.GMAIL_ENABLED = env_bool("GMAIL_ENABLED", False)
        self.GMAIL_USER    = env_str("GMAIL_USER")
        self.GMAIL_PASS    = env_str("GMAIL_PASS")
        self.GMAIL_TO      = env_str("GMAIL_TO")

        self.LOG_FILE  = resolve_path(env_str("LOG_FILE", "service_a.log"), LOGS_DIR)
        self.LOG_LEVEL = env_str("LOG_LEVEL", "INFO")

    @property
    def vt_ready(self) -> bool:
        return bool(self.VT_ENABLED and self.VT_APIKEY)


cfg = Config()
log = setup_logger("SOC-A", cfg.LOG_FILE, cfg.LOG_LEVEL)


# ──────────────────────────────────────────────────────────────────
# CONSTANTES
# ──────────────────────────────────────────────────────────────────
SEVERITY_MAP = {
    "critical": 4, "high": 3, "medium": 2,
    "low": 1, "info": 1, "informational": 1,
    "warning": 2, "unknown": 2,
    "1": 1, "2": 2, "3": 3, "4": 4,
}
SEVERITY_LABEL = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
SEVERITY_EMOJI = {1: "🟢", 2: "🟡", 3: "🟠", 4: "🔴"}

AUTO_TAGS = {
    r"brute.?force|failed.pass|4625": "brute_force",
    r"ssh|sftp":                      "ssh",
    r"lateral|psexec|wmic|winrm":     "lateral_movement",
    r"mimikatz|pwdump|lsass":         "credential_dumping",
    r"ransom|vssadmin|wbadmin":       "ransomware",
    r"scan|nmap|masscan":             "port_scan",
    r"download|bitsadmin":            "malicious_download",
    r"privilege|escalat|4672|sudo":   "privilege_escalation",
    r"powershell|encoded":            "powershell",
    r"persist|4698|startup":          "persistence",
    r"exfil|dlp":                     "exfiltration",
    r"rdp|3389":                      "rdp",
    r"smb|445|pass.the":              "smb_attack",
}

HASH_LENGTHS = (32, 40, 64)


# ──────────────────────────────────────────────────────────────────
# ÉTAT GLOBAL
# ──────────────────────────────────────────────────────────────────
app      = Flask(__name__)
thehive  = TheHiveClient(cfg.THEHIVE_URL, cfg.THEHIVE_APIKEY,
                         retries=cfg.RETRY_ATTEMPTS, retry_delay=cfg.RETRY_DELAY_SEC,
                         verify=cfg.THEHIVE_VERIFY_SSL, logger=log)
telegram = Telegram(cfg.TELEGRAM_TOKEN, cfg.TELEGRAM_CHAT_ID,
                    cfg.TELEGRAM_ENABLED, logger=log)

_rate_cache     = {}
_rate_lock      = threading.Lock()
_stats          = defaultdict(int)
_stats_lock     = threading.Lock()
_debug_payloads = []
_debug_lock     = threading.Lock()


def bump(counter: str, value: int = 1) -> None:
    with _stats_lock:
        _stats[counter] += value


# ──────────────────────────────────────────────────────────────────
# ANTI-DOUBLON (rate limiter)
# ──────────────────────────────────────────────────────────────────
def is_rate_limited(key: str) -> bool:
    if cfg.RATE_LIMIT_SEC <= 0:
        return False
    with _rate_lock:
        now  = time.time()
        last = _rate_cache.get(key, 0.0)
        if now - last < cfg.RATE_LIMIT_SEC:
            bump("rate_limited")
            return True
        _rate_cache[key] = now
        # purge des entrées expirées : évite la fuite mémoire sur un service long
        if len(_rate_cache) > 5000:
            cutoff = now - cfg.RATE_LIMIT_SEC
            for expired in [k for k, v in _rate_cache.items() if v < cutoff]:
                _rate_cache.pop(expired, None)
        return False


# ──────────────────────────────────────────────────────────────────
# RETRY
# ──────────────────────────────────────────────────────────────────
def with_retry(max_attempts=None, delay=None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            attempts = max_attempts or cfg.RETRY_ATTEMPTS
            pause    = cfg.RETRY_DELAY_SEC if delay is None else delay
            last_exc = None
            for i in range(1, attempts + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as exc:          # noqa: BLE001 — relayée après les essais
                    last_exc = exc
                    log.warning("Retry %d/%d %s : %s", i, attempts, func.__name__, exc)
                    if i < attempts:
                        time.sleep(pause * i)
            raise last_exc
        return wrapper
    return decorator


# ──────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────
def _is_ip(value) -> bool:
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def _is_valid_public_ip(value) -> bool:
    try:
        addr = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback
                or addr.is_link_local or addr.is_multicast
                or addr.is_reserved or addr.is_unspecified)


def _clean(value) -> str:
    """Normalise un champ Splunk ; retourne "" si la valeur n'est pas exploitable."""
    if value is None:
        return ""
    text = str(value).strip()
    if text.lower() in ("", "-", "n/a", "na", "none", "null", "unknown"):
        return ""
    return text


# ══════════════════════════════════════════════════════════════════
# VIRUSTOTAL v3
# ══════════════════════════════════════════════════════════════════
class VirusTotalClient:
    BASE_URL = "https://www.virustotal.com/api/v3"

    @classmethod
    def _get(cls, endpoint: str) -> dict:
        if not cfg.vt_ready:
            return {}
        try:
            r = requests.get(
                "{}/{}".format(cls.BASE_URL, endpoint),
                headers={"x-apikey": cfg.VT_APIKEY, "Accept": "application/json"},
                timeout=cfg.VT_TIMEOUT,
            )
            if r.status_code == 200:
                return r.json()
            if r.status_code == 404:
                log.debug("VT : non trouvé %s", endpoint)
            elif r.status_code == 429:
                log.warning("VT : quota atteint (rate limit)")
            else:
                log.warning("VT HTTP %d sur %s", r.status_code, endpoint)
        except requests.exceptions.Timeout:
            log.warning("VT : timeout après %ds", cfg.VT_TIMEOUT)
        except requests.RequestException as exc:
            log.error("VT erreur : %s", exc)
        except ValueError as exc:
            log.error("VT réponse illisible : %s", exc)
        return {}

    @classmethod
    def _parse_stats(cls, data: dict) -> dict:
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats") or {}
        return {
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total":      sum(stats.values()) if stats else 0,
            "reputation": attrs.get("reputation", 0),
            "country":    attrs.get("country", ""),
            "as_owner":   attrs.get("as_owner", ""),
            "names":      (attrs.get("names") or [])[:3],
            "tags":       (attrs.get("tags") or [])[:5],
        }

    @classmethod
    def check_ip(cls, ip) -> dict:
        if not _clean(ip) or not cfg.vt_ready:
            return {}
        data = cls._get("ip_addresses/{}".format(ip))
        if not data:
            return {}
        result = cls._parse_stats(data)
        result.update({"type": "ip", "value": ip})
        log.info("VT IP %s : malicious=%d suspicious=%d reputation=%d",
                 ip, result["malicious"], result["suspicious"], result["reputation"])
        return result

    @classmethod
    def check_domain(cls, domain) -> dict:
        if not _clean(domain) or not cfg.vt_ready:
            return {}
        data = cls._get("domains/{}".format(domain))
        if not data:
            return {}
        result = cls._parse_stats(data)
        result.update({"type": "domain", "value": domain})
        return result

    @classmethod
    def check_hash(cls, file_hash) -> dict:
        if not _clean(file_hash) or not cfg.vt_ready:
            return {}
        data = cls._get("files/{}".format(file_hash))
        if not data:
            return {}
        attrs  = data.get("data", {}).get("attributes", {})
        result = cls._parse_stats(data)
        result.update({
            "type":      "hash",
            "value":     file_hash,
            "file_name": attrs.get("meaningful_name", ""),
            "file_type": attrs.get("type_description", ""),
            "file_size": attrs.get("size", 0),
        })
        log.info("VT hash %s : malicious=%d fichier=%s",
                 str(file_hash)[:16], result["malicious"], result["file_name"])
        return result

    @classmethod
    def check_url(cls, url) -> dict:
        if not _clean(url) or not cfg.vt_ready:
            return {}
        url_id = base64.urlsafe_b64encode(str(url).encode()).decode().rstrip("=")
        data   = cls._get("urls/{}".format(url_id))
        if not data:
            return {}
        result = cls._parse_stats(data)
        result.update({"type": "url", "value": url})
        return result

    @classmethod
    def is_malicious(cls, vt_result) -> bool:
        if not vt_result:
            return False
        return (vt_result.get("malicious", 0) >= cfg.VT_MIN_DETECTIONS
                or vt_result.get("suspicious", 0) >= cfg.VT_MIN_DETECTIONS * 2
                or vt_result.get("reputation", 0) <= -10)

    @classmethod
    def format_summary(cls, vt_result) -> str:
        if not vt_result:
            return "VT : non analysé"
        mal = vt_result.get("malicious", 0)
        sus = vt_result.get("suspicious", 0)
        tot = vt_result.get("total", 0)
        rep = vt_result.get("reputation", 0)
        if mal > 0:
            verdict = "🔴 MALVEILLANT"
        elif sus > 0:
            verdict = "🟡 SUSPECT"
        elif tot > 0:
            verdict = "🟢 PROPRE"
        else:
            verdict = "⚪ INCONNU"
        parts = ["{} ({}/{} détections".format(verdict, mal, tot)]
        if rep != 0:
            parts.append("rep={}".format(rep))
        if vt_result.get("country"):
            parts.append("pays={}".format(vt_result["country"]))
        if vt_result.get("file_name"):
            parts.append("fichier={}".format(vt_result["file_name"]))
        return ", ".join(parts) + ")"

    @classmethod
    def enrich_observables(cls, result: dict) -> dict:
        """Interroge VirusTotal pour les IoCs du payload. Retourne {ioc: résultat}."""
        vt_results = {}
        if not cfg.vt_ready:
            return vt_results

        for field_name in ("src_ip", "src", "dest_ip", "dest"):
            ip = _clean(result.get(field_name))
            if ip and _is_valid_public_ip(ip) and ip not in vt_results:
                vt = cls.check_ip(ip)
                if vt:
                    vt_results[ip] = vt
                time.sleep(0.3)

        for field_name in ("file_hash", "hash", "md5", "sha1", "sha256", "FileHash"):
            file_hash = _clean(result.get(field_name))
            if file_hash and len(file_hash) in HASH_LENGTHS and file_hash not in vt_results:
                vt = cls.check_hash(file_hash)
                if vt:
                    vt_results[file_hash] = vt
                time.sleep(0.3)
                break

        for field_name in ("domain", "dest_domain", "query", "QueryName"):
            domain = _clean(result.get(field_name))
            if domain and "." in domain and not _is_ip(domain) and domain not in vt_results:
                vt = cls.check_domain(domain)
                if vt:
                    vt_results[domain] = vt
                time.sleep(0.3)
                break

        url = _clean(result.get("url") or result.get("uri"))
        if url.startswith(("http://", "https://")) and url not in vt_results:
            vt = cls.check_url(url)
            if vt:
                vt_results[url] = vt
        return vt_results


# ══════════════════════════════════════════════════════════════════
# PARSING SPLUNK — 4 formats supportés
# ══════════════════════════════════════════════════════════════════
class SplunkParser:
    IOC_FIELDS = {
        "src_ip", "dest_ip", "src", "dest", "user", "User", "username",
        "host", "source", "index", "process_name", "Image", "file_hash",
        "hash", "md5", "sha1", "sha256", "domain", "dest_domain", "query",
        "url", "uri", "_time", "CommandLine", "ParentImage", "EventCode",
    }

    @classmethod
    def parse(cls, data: dict) -> tuple:
        """Retourne (nom_alerte, sévérité_brute, dict_résultat)."""
        data = data or {}
        name = (data.get("search_name") or data.get("name")
                or data.get("alert_name") or "Alerte Splunk")
        sev  = (data.get("severity") or data.get("alert.severity")
                or data.get("urgency") or "medium")

        # Format 1 — { "result": {...} }
        result = data.get("result")
        if isinstance(result, dict) and result:
            return name, sev, result

        # Format 2 — { "results": [ {...} ] }
        results = data.get("results")
        if isinstance(results, list) and results and isinstance(results[0], dict):
            return name, sev, results[0]

        # Format 3 — payload plat
        flat = {k: v for k, v in data.items() if k in cls.IOC_FIELDS}
        if flat:
            return name, sev, flat

        # Format 4 — { "result": "<JSON encodé en chaîne>" }
        if isinstance(result, str) and result.strip():
            try:
                parsed = json.loads(result)
                if isinstance(parsed, dict):
                    return name, sev, parsed
            except (ValueError, TypeError):
                pass

        # Repli — payload minimal
        return name, sev, {
            "host":   data.get("host", data.get("server_host", "N/A")),
            "source": data.get("source", "Splunk Webhook"),
            "_time":  data.get("_time", utcnow_iso()),
        }


# ══════════════════════════════════════════════════════════════════
# ENRICHISSEMENT
# ══════════════════════════════════════════════════════════════════
class AlertEnricher:

    @staticmethod
    def normalize_severity(value) -> int:
        return SEVERITY_MAP.get(str(value).strip().lower(), 2)

    @staticmethod
    def generate_source_ref(name: str, result: dict) -> str:
        raw = "{}-{}-{}".format(
            name,
            result.get("src_ip", result.get("src", result.get("host", ""))),
            result.get("_time", now_str()[:16]),
        )
        return "splunk-" + hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]

    @staticmethod
    def extract_tags(name: str, result: dict, vt_results: dict) -> list:
        tags     = ["splunk", "auto-ingested"]
        combined = "{} {}".format(name, json.dumps(result, default=str)).lower()

        for pattern, tag in AUTO_TAGS.items():
            if re.search(pattern, combined) and tag not in tags:
                tags.append(tag)

        source = str(result.get("source", "")).lower()
        index  = str(result.get("index", "")).lower()
        if "windows" in index or "winevent" in source:
            tags.append("windows")
        elif "linux" in index or "auth.log" in source or "syslog" in source:
            tags.append("linux")

        event_code = _clean(result.get("EventCode") or result.get("event_code"))
        if event_code:
            tags.append("ec-{}".format(event_code))

        for vt in (vt_results or {}).values():
            if VirusTotalClient.is_malicious(vt):
                tags.append("vt-malicious")
            elif vt.get("suspicious", 0) > 0:
                tags.append("vt-suspicious")

        return list(dict.fromkeys(tags))

    @staticmethod
    def extract_observables(result: dict, vt_results: dict) -> list:
        """Construit les Observables TheHive à partir du résultat Splunk."""
        vt_results  = vt_results or {}
        observables = []

        def add(dtype, value, message, ioc=False, tags=None):
            data = _clean(value)
            if not data:
                return
            vt       = vt_results.get(data, {})
            obs_tags = list(tags or []) + ["splunk"]
            if vt:
                message = "{} | {}".format(message, VirusTotalClient.format_summary(vt))
                if VirusTotalClient.is_malicious(vt):
                    ioc = True
                    obs_tags.append("vt-malicious")
            observables.append(Observable(dataType=dtype, data=data,
                                          message=message, tags=obs_tags, ioc=ioc))

        for f in ("src_ip", "src", "SourceIp"):
            if _clean(result.get(f)):
                add("ip", result[f], "IP source (Splunk)", ioc=True, tags=["src_ip"])
                break
        for f in ("dest_ip", "dest", "DestinationIp"):
            if _clean(result.get(f)):
                add("ip", result[f], "IP destination (Splunk)", tags=["dest_ip"])
                break
        for f in ("user", "User", "username", "AccountName"):
            if _clean(result.get(f)):
                add("other", result[f], "Utilisateur impliqué", tags=["user"])
                break
        for f in ("file_hash", "hash", "md5", "sha1", "sha256", "FileHash"):
            value = _clean(result.get(f))
            if value and len(value) in HASH_LENGTHS:
                add("hash", value, "Hash fichier suspect", ioc=True, tags=["hash"])
                break
        for f in ("domain", "dest_domain", "query", "QueryName"):
            value = _clean(result.get(f))
            if value and "." in value and not _is_ip(value):
                add("domain", value, "Domaine suspect", ioc=True, tags=["domain"])
                break
        for f in ("url", "uri"):
            value = _clean(result.get(f))
            if value.startswith(("http://", "https://")):
                add("url", value, "URL suspecte", ioc=True, tags=["url"])
                break

        cmdline = _clean(result.get("CommandLine") or result.get("command_line"))
        if len(cmdline) > 10:
            add("other", cmdline[:500], "Ligne de commande", tags=["cmdline"])

        if not observables:
            add("other", result.get("host"), "Hôte source", tags=["host"])
        return observables

    @staticmethod
    def build_description(name: str, result: dict, vt_results: dict) -> str:
        lines = [
            "## 🚨 Alerte Splunk : {}".format(name), "",
            "### 📋 Informations générales",
            "| Champ | Valeur |", "|-------|--------|",
            "| **Hôte** | `{}` |".format(result.get("host", "N/A")),
            "| **Source** | `{}` |".format(result.get("source", "N/A")),
            "| **Index** | `{}` |".format(result.get("index", "N/A")),
            "| **Horodatage** | `{}` |".format(result.get("_time", "N/A")),
            "", "### 🎯 Indicateurs détectés",
            "| Type | Valeur |", "|------|--------|",
            "| IP source | `{}` |".format(result.get("src_ip", result.get("src", "N/A"))),
            "| IP dest | `{}` |".format(result.get("dest_ip", result.get("dest", "N/A"))),
            "| Utilisateur | `{}` |".format(result.get("user", "N/A")),
            "| Processus | `{}` |".format(result.get("process_name", result.get("Image", "N/A"))),
            "| Domaine | `{}` |".format(result.get("domain", "N/A")),
            "| Hash | `{}` |".format(result.get("file_hash", result.get("hash", "N/A"))),
            "| EventCode | `{}` |".format(result.get("EventCode", "N/A")),
        ]

        if vt_results:
            lines += ["", "### 🦠 Analyse VirusTotal", "| IoC | Verdict |", "|-----|---------|"]
            for ioc, vt in vt_results.items():
                mal = vt.get("malicious", 0)
                sus = vt.get("suspicious", 0)
                tot = vt.get("total", 0)
                rep = vt.get("reputation", 0)
                if mal >= cfg.VT_MIN_DETECTIONS:
                    verdict = "🔴 **MALVEILLANT**"
                elif sus > 0:
                    verdict = "🟡 **Suspect**"
                elif tot > 0:
                    verdict = "🟢 Propre"
                else:
                    verdict = "⚪ Inconnu"
                lines.append("| `{}` | {} ({}/{} détect., rep={}) |".format(
                    str(ioc)[:50], verdict, mal, tot, rep))
                if vt.get("country"):
                    lines.append("| Pays | `{}` |".format(vt["country"]))
                if vt.get("as_owner"):
                    lines.append("| AS | `{}` |".format(vt["as_owner"]))
                if vt.get("file_name"):
                    lines.append("| Fichier | `{}` ({}) |".format(
                        vt["file_name"], vt.get("file_type", "")))
        elif cfg.VT_ENABLED and not cfg.VT_APIKEY:
            lines += ["", "### 🦠 Analyse VirusTotal",
                      "> ⚠️ Enrichissement ignoré : `VT_APIKEY` absente du fichier `.env`."]

        lines += [
            "", "### 📦 Données brutes Splunk", "```json",
            json.dumps(result, indent=2, ensure_ascii=False, default=str)[:3000],
            "```", "",
            "---",
            "> *Ingéré automatiquement par SOC Pipeline Service A v{}*".format(VERSION),
            "> *{} UTC*".format(utcnow_iso()[:19].replace("T", " ")),
        ]
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════
# NOTIFICATIONS
# ══════════════════════════════════════════════════════════════════
class Notifier:

    @staticmethod
    def send_gmail_async(subject: str, body_text: str, body_html=None) -> None:
        if not (cfg.GMAIL_ENABLED and cfg.GMAIL_USER and cfg.GMAIL_PASS and cfg.GMAIL_TO):
            return

        def _send():
            try:
                msg = MIMEMultipart("alternative")
                msg["Subject"] = subject
                msg["From"]    = cfg.GMAIL_USER
                msg["To"]      = cfg.GMAIL_TO
                msg.attach(MIMEText(body_text, "plain", "utf-8"))
                if body_html:
                    msg.attach(MIMEText(body_html, "html", "utf-8"))
                with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=20) as server:
                    server.login(cfg.GMAIL_USER, cfg.GMAIL_PASS)
                    server.sendmail(cfg.GMAIL_USER, cfg.GMAIL_TO, msg.as_string())
                log.info("SOC-A — Gmail OK : %s", subject)
            except (smtplib.SMTPException, OSError) as exc:
                log.error("Gmail : %s", exc)

        threading.Thread(target=_send, daemon=True).start()

    @classmethod
    def send_alert(cls, name: str, severity: int, result: dict,
                   alert_id: str = "", vt_results=None) -> None:
        if severity < cfg.NOTIFY_MIN_SEV:
            return
        vt_results = vt_results or {}

        vt_lines = []
        for ioc, vt in vt_results.items():
            if not vt:
                continue
            icon = ("🔴" if VirusTotalClient.is_malicious(vt)
                    else "🟡" if vt.get("suspicious", 0) > 0 else "🟢")
            vt_lines.append("{} <code>{}</code> {}/{}".format(
                icon, str(ioc)[:30], vt.get("malicious", 0), vt.get("total", 0)))

        body = [
            "{} <b>ALERTE SOC — {}</b>".format(
                SEVERITY_EMOJI.get(severity, "⚪"),
                SEVERITY_LABEL.get(severity, "?").upper()), "",
            "<b>Recherche :</b> {}".format(name),
            "<b>Hôte      :</b> <code>{}</code>".format(result.get("host", "N/A")),
            "<b>IP src    :</b> <code>{}</code>".format(
                result.get("src_ip", result.get("src", "N/A"))),
            "<b>IP dst    :</b> <code>{}</code>".format(
                result.get("dest_ip", result.get("dest", "N/A"))),
            "<b>User      :</b> <code>{}</code>".format(result.get("user", "N/A")),
            "<b>Heure     :</b> {}".format(result.get("_time", now_str())),
        ]
        if vt_lines:
            body += ["", "<b>🦠 VirusTotal :</b>"] + vt_lines
        body += ["", "<i>SOC Pipeline Service A v{}</i>".format(VERSION)]
        message = "\n".join(body)

        keyboard = None
        if alert_id:
            keyboard = {"inline_keyboard": [[{
                "text": "🔍 Voir dans TheHive",
                "url":  "{}/alerts/{}".format(cfg.THEHIVE_URL.rstrip("/"), alert_id),
            }]]}

        telegram.send_async(message, keyboard)
        cls.send_gmail_async(
            "[SOC {}] {}".format(SEVERITY_LABEL.get(severity, "?").upper(), name),
            re.sub(r"</?(b|i|code)>", "", message))


# ══════════════════════════════════════════════════════════════════
# CRÉATION DE L'ALERTE THEHIVE
# ══════════════════════════════════════════════════════════════════
DUPLICATE_HINTS = ("already exist", "already been", "duplicate", "conflict", "createerror")


@with_retry()
def create_thehive_alert(payload: dict) -> tuple:
    """Crée l'alerte dans TheHive. Retourne (statut, alert_id, détail).

    statut ∈ {"created", "duplicate", "error"} ; lève une exception si
    TheHive est injoignable (le décorateur retente alors automatiquement).
    """
    code, body = thehive.create_alert(payload)

    if code == 201:
        return "created", str((body or {}).get("_id") or (body or {}).get("id") or ""), ""
    if code == 409:
        return "duplicate", "", "conflit sourceRef"
    if code == 400:
        detail = json.dumps(body, ensure_ascii=False, default=str) if body else ""
        if any(hint in detail.lower() for hint in DUPLICATE_HINTS):
            return "duplicate", "", detail[:200]
        return "error", "", detail[:300] or "HTTP 400"
    if code in (401, 403):
        return "error", "", "HTTP {} — THEHIVE_APIKEY invalide ou droits insuffisants".format(code)
    if code == 0:
        raise ConnectionError("TheHive injoignable ({})".format(cfg.THEHIVE_URL))
    raise RuntimeError("TheHive HTTP {} : {}".format(code, str(body)[:200]))


# ══════════════════════════════════════════════════════════════════
# CONTRÔLE AU DÉMARRAGE
# ══════════════════════════════════════════════════════════════════
def startup_check() -> None:
    time.sleep(2)

    thehive_ok = thehive.ping()
    if not thehive_ok:
        log.critical("TheHive injoignable — vérifier THEHIVE_URL et THEHIVE_APIKEY")

    vt_ok = None
    if cfg.VT_ENABLED:
        vt_ok = False
        if cfg.VT_APIKEY:
            try:
                r = requests.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
                                 headers={"x-apikey": cfg.VT_APIKEY}, timeout=10)
                vt_ok = r.status_code == 200
            except requests.RequestException:
                vt_ok = False

    telegram_ok = None
    if cfg.TELEGRAM_ENABLED:
        if not cfg.TELEGRAM_TOKEN:
            log.warning("TELEGRAM_ENABLED=true mais TELEGRAM_TOKEN est vide")
            telegram_ok = False
        elif not cfg.TELEGRAM_CHAT_ID:
            log.warning("TELEGRAM_ENABLED=true mais TELEGRAM_CHAT_ID est vide")
            telegram_ok = False
        else:
            bot         = telegram.get_me()
            telegram_ok = bool(bot)
            if bot:
                log.info("Telegram : bot @%s", bot.get("username", "?"))
                telegram.send(
                    "🚀 <b>SOC Pipeline — Service A démarré</b>\n"
                    "⏰ {}\n\n{} TheHive : {}\n{} VirusTotal : {}\n"
                    "📡 Webhook : :{}/alert".format(
                        now_str(),
                        "✅" if thehive_ok else "❌", cfg.THEHIVE_URL,
                        "✅" if vt_ok else "⚠️",
                        "Actif" if vt_ok else "vérifier VT_APIKEY",
                        cfg.LISTEN_PORT))

    gmail_ok = None
    if cfg.GMAIL_ENABLED and cfg.GMAIL_USER and cfg.GMAIL_PASS:
        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=20) as server:
                server.login(cfg.GMAIL_USER, cfg.GMAIL_PASS)
            gmail_ok = True
        except (smtplib.SMTPException, OSError):
            gmail_ok = False

    def status(value):
        if value is True:
            return "✅ OK"
        if value is False:
            return "❌ ERREUR"
        return "⚪ Désactivé"

    print("")
    print("=" * 62)
    print("  SOC Pipeline — Service A  v{}".format(VERSION))
    print("=" * 62)
    print("  TheHive      : {} — {}".format(status(thehive_ok), cfg.THEHIVE_URL))
    print("  VirusTotal   : {}{}".format(
        status(vt_ok), "" if cfg.VT_APIKEY else " (VT_APIKEY non définie)"))
    print("  Telegram     : {}".format(status(telegram_ok)))
    print("  Gmail        : {}".format(status(gmail_ok)))
    print("  Webhook      : http://{}:{}/alert".format(cfg.LISTEN_HOST, cfg.LISTEN_PORT))
    print("  Anti-doublon : {}s".format(cfg.RATE_LIMIT_SEC))
    print("  Logs         : {}".format(cfg.LOG_FILE))
    print("-" * 62)
    print("  Endpoints :")
    print("    POST /alert         — webhook Splunk")
    print("    GET  /health        — health check")
    print("    GET  /test          — alerte de test")
    print("    GET  /telegram-test — tester Telegram")
    print("    GET  /vt-test       — tester VirusTotal")
    print("    GET  /debug         — derniers payloads")
    print("    GET  /stats         — statistiques")
    print("=" * 62)


# ══════════════════════════════════════════════════════════════════
# ENDPOINTS FLASK
# ══════════════════════════════════════════════════════════════════
@app.route("/alert", methods=["POST"])
def receive_alert():
    try:
        raw  = request.get_data(as_text=True) or ""
        data = request.get_json(force=True, silent=True)

        with _debug_lock:
            _debug_payloads.append({"ts": utcnow_iso(),
                                    "ip": request.remote_addr,
                                    "raw": raw[:800]})
            del _debug_payloads[:-50]

        bump("received")
        if not isinstance(data, dict) or not data:
            bump("errors")
            return jsonify({"status": "error", "reason": "payload non-JSON ou vide"}), 400

        name, severity_raw, result = SplunkParser.parse(data)
        severity   = AlertEnricher.normalize_severity(severity_raw)
        source_ref = AlertEnricher.generate_source_ref(name, result)

        log.info("SOC-A — Alerte : '%s' sev=%d host=%s ref=%s",
                 name, severity, result.get("host", "N/A"), source_ref)

        if is_rate_limited(source_ref):
            log.info("SOC-A — Doublon ignoré (anti-flood) : ref=%s", source_ref)
            return jsonify({"status": "rate_limited", "source_ref": source_ref}), 200

        vt_results = {}
        if cfg.vt_ready:
            try:
                vt_results = VirusTotalClient.enrich_observables(result)
                bump("vt_analyses", len(vt_results))
                vt_malicious = sum(1 for v in vt_results.values()
                                   if VirusTotalClient.is_malicious(v))
                if vt_malicious:
                    bump("vt_malicious", vt_malicious)
                    severity = max(severity, 3)
            except Exception as exc:          # noqa: BLE001 — VT ne doit jamais bloquer l'ingestion
                log.error("Enrichissement VT en échec : %s", exc)

        tags        = AlertEnricher.extract_tags(name, result, vt_results)
        observables = AlertEnricher.extract_observables(result, vt_results)
        description = AlertEnricher.build_description(name, result, vt_results)

        payload = {
            "type":        "external",
            "source":      "Splunk",
            "sourceRef":   source_ref,
            "title":       "[SPLUNK] {}".format(name),
            "description": description,
            "severity":    severity,
            "tlp":         2,
            "pap":         2,
            "tags":        tags,
            "observables": [o.to_dict() for o in observables],
        }

        try:
            outcome, alert_id, detail = create_thehive_alert(payload)
        except Exception as exc:              # noqa: BLE001 — on renvoie une réponse HTTP propre
            bump("errors")
            log.error("Création alerte TheHive impossible : %s", exc)
            return jsonify({"status": "error", "detail": str(exc)}), 502

        if outcome == "created":
            bump("created")
            log.info("SOC-A — Alerte TheHive créée : id=%s ref=%s sev=%d obs=%d vt=%d",
                     alert_id, source_ref, severity, len(observables), len(vt_results))
            Notifier.send_alert(name, severity, result, alert_id, vt_results)
            return jsonify({
                "status":          "created",
                "alert_id":        alert_id,
                "source_ref":      source_ref,
                "severity":        SEVERITY_LABEL.get(severity, "?"),
                "artifacts_count": len(observables),
                "tags":            tags,
                "virustotal": {
                    "analyzed":  len(vt_results),
                    "malicious": sum(1 for v in vt_results.values()
                                     if VirusTotalClient.is_malicious(v)),
                },
            }), 201

        if outcome == "duplicate":
            bump("duplicates")
            log.info("SOC-A — Doublon TheHive : ref=%s", source_ref)
            return jsonify({"status": "duplicate", "source_ref": source_ref}), 200

        bump("errors")
        log.error("TheHive a refusé l'alerte : %s", detail)
        return jsonify({"status": "error", "detail": detail}), 502

    except Exception as exc:                  # noqa: BLE001 — filet de sécurité Flask
        bump("errors")
        log.exception("Erreur /alert : %s", exc)
        return jsonify({"status": "error", "detail": str(exc)}), 500


@app.route("/health", methods=["GET"])
def health():
    thehive_ok = thehive.ping()
    return jsonify({
        "status":     "healthy" if thehive_ok else "degraded",
        "service":    "soc-service-a",
        "version":    VERSION,
        "thehive":    thehive_ok,
        "thehive_ok": thehive_ok,        # clé conservée pour start.py
        "vt":         cfg.vt_ready,
        "telegram":   telegram.enabled,
        "stats":      dict(_stats),
        "timestamp":  utcnow_iso(),
    }), 200 if thehive_ok else 503


@app.route("/vt-test", methods=["GET"])
def vt_test():
    if not cfg.VT_ENABLED:
        return jsonify({"status": "disabled", "fix": "VT_ENABLED=true dans .env"}), 200
    if not cfg.VT_APIKEY:
        return jsonify({"status": "no_key", "fix": "Ajouter VT_APIKEY dans .env"}), 400
    vt = VirusTotalClient.check_ip("8.8.8.8")
    if vt:
        return jsonify({"status": "ok", "message": "VirusTotal fonctionne", "result": vt}), 200
    return jsonify({"status": "error", "fix": "Vérifier VT_APIKEY / la connexion"}), 502


@app.route("/telegram-test", methods=["GET"])
def telegram_test():
    if not cfg.TELEGRAM_ENABLED:
        return jsonify({"status": "disabled", "fix": "TELEGRAM_ENABLED=true dans .env"}), 200
    if not cfg.TELEGRAM_TOKEN:
        return jsonify({"status": "no_token", "fix": "TELEGRAM_TOKEN vide dans .env"}), 400
    if not cfg.TELEGRAM_CHAT_ID:
        return jsonify({"status": "no_chat_id", "fix": "TELEGRAM_CHAT_ID vide dans .env"}), 400
    sent = telegram.send(
        "🧪 <b>TEST SOC Pipeline — Service A v{}</b>\n\n"
        "✅ Telegram <b>fonctionne</b>\n⏰ {}\n\n"
        "<b>TheHive :</b> {}\n<b>VT :</b> {}".format(
            VERSION, now_str(), cfg.THEHIVE_URL,
            "Actif ✅" if cfg.vt_ready else "Non configuré ⚠️"))
    return jsonify({"status": "success" if sent else "send_failed"}), 200 if sent else 502


@app.route("/test", methods=["GET", "POST"])
def test_alert():
    fake = {
        "search_name": "TEST — SOC Pipeline v{}".format(VERSION),
        "severity":    "high",
        "result": {
            "host":         "srv-linux-01",
            "source":       "/var/log/auth.log",
            "index":        "linux_logs",
            "src_ip":       "185.220.101.50",
            "dest_ip":      "192.168.1.10",
            "user":         "root",
            "process_name": "sshd",
            "_time":        utcnow_iso(),
            "count":        "121",
            "message":      "Failed password for root from 185.220.101.50 port 22 ssh2",
        },
    }
    try:
        r = requests.post("http://127.0.0.1:{}/alert".format(cfg.LISTEN_PORT),
                          json=fake, timeout=60)
        return jsonify({"status": "test_sent", "response": r.json()}), 200
    except (requests.RequestException, ValueError) as exc:
        return jsonify({"status": "error", "detail": str(exc)}), 502


@app.route("/debug", methods=["GET"])
def debug():
    with _debug_lock:
        last = list(_debug_payloads[-10:])
    return jsonify({"total_received": _stats.get("received", 0),
                    "last_payloads":  last,
                    "stats":          dict(_stats)}), 200


@app.route("/stats", methods=["GET"])
def stats():
    return jsonify({"stats": dict(_stats), "timestamp": utcnow_iso()}), 200


# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════
def main() -> int:
    if not cfg.THEHIVE_APIKEY:
        log.warning("THEHIVE_APIKEY est vide — TheHive refusera les alertes")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    threading.Thread(target=startup_check, daemon=True).start()
    try:
        app.run(host=cfg.LISTEN_HOST, port=cfg.LISTEN_PORT,
                debug=False, use_reloader=False, threaded=True)
    except OSError as exc:
        log.critical("Impossible d'écouter sur %s:%s — %s",
                     cfg.LISTEN_HOST, cfg.LISTEN_PORT, exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
