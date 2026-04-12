#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  SOC Automation Pipeline — Service A                        ║
║  Splunk → TheHive  (webhook + VirusTotal enrichment)        ║
║  Version : 7.0.0  |  Rachad Lab                            ║
╚══════════════════════════════════════════════════════════════╝

Flux :
  Splunk alerte → POST /alert → parse → enrich VT → TheHive alert → Telegram

Endpoints :
  POST /alert          Webhook Splunk
  GET  /health         Health check complet
  GET  /test           Alerte de test
  GET  /telegram-test  Tester Telegram
  GET  /vt-test        Tester VirusTotal
  GET  /debug          Derniers payloads reçus
  GET  /stats          Statistiques du service
"""

import os, json, hashlib, logging, smtplib, time, threading, re, sys, platform
from datetime import datetime
from collections import defaultdict
from logging.handlers import RotatingFileHandler
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
from pathlib import Path

# ══════════════════════════════════════════════════════════════════
# CHARGEMENT .env — AVANT TOUT (critique pour Telegram + config)
# Fonctionne : Windows, Ubuntu, Debian, CentOS, Arch, macOS, Docker
# ══════════════════════════════════════════════════════════════════
def _load_env_file() -> str:
    """
    Charge le .env depuis plusieurs emplacements possibles.
    ECRASE toujours les variables (permet rechargement après modif).
    Retourne le chemin chargé ou None.
    """
    candidates = [
        Path(__file__).parent / ".env",
        Path(__file__).parent.parent / ".env",
        Path.cwd() / ".env",
        Path.home() / ".env",
    ]
    for path in candidates:
        if path.exists():
            count = 0
            with open(path, encoding="utf-8") as f:
                for raw in f:
                    line = raw.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, val = line.partition("=")
                    key = key.strip()
                    val = val.strip().strip('"').strip("'")
                    os.environ[key] = val          # écrase toujours
                    count += 1
            print("[ENV] Chargé : {} ({} variables)".format(path, count))
            return str(path)
    print("[ENV] Aucun .env trouvé — variables système utilisées")
    return None

_ENV_PATH = _load_env_file()
# ══════════════════════════════════════════════════════════════════

import requests
from flask import Flask, request, jsonify
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact


# ──────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────
class Config:
    # TheHive
    THEHIVE_URL    = os.getenv("THEHIVE_URL",    "http://10.2.3.122:9000")
    THEHIVE_APIKEY = os.getenv("THEHIVE_APIKEY", "J9LiEsGJDFFfDmBuAKyj+MUmWyytwNTx")

    # Webhook
    LISTEN_HOST  = os.getenv("LISTEN_HOST", "0.0.0.0")
    LISTEN_PORT  = int(os.getenv("LISTEN_PORT", "5000"))

    # VirusTotal
    VT_ENABLED = os.getenv("VT_ENABLED", "true").lower() == "true"
    VT_APIKEY  = os.getenv("VT_APIKEY",  "")          # clé API VT v3
    VT_TIMEOUT = int(os.getenv("VT_TIMEOUT", "15"))
    VT_MIN_DETECTIONS = int(os.getenv("VT_MIN_DETECTIONS", "2"))  # seuil malveillant

    # Rate limiting
    RATE_LIMIT_SEC  = int(os.getenv("RATE_LIMIT_SEC",  "10"))
    RETRY_ATTEMPTS  = int(os.getenv("RETRY_ATTEMPTS",  "3"))
    RETRY_DELAY_SEC = int(os.getenv("RETRY_DELAY_SEC", "5"))

    # Notifications
    NOTIFY_MIN_SEV = int(os.getenv("NOTIFY_MIN_SEV", "3"))  # 3=High 4=Critical

    # Telegram
    TELEGRAM_ENABLED  = os.getenv("TELEGRAM_ENABLED",  "false").lower() == "true"
    TELEGRAM_TOKEN    = os.getenv("TELEGRAM_TOKEN",    "")
    TELEGRAM_CHAT_ID  = os.getenv("TELEGRAM_CHAT_ID",  "")

    # Gmail
    GMAIL_ENABLED = os.getenv("GMAIL_ENABLED", "false").lower() == "true"
    GMAIL_USER    = os.getenv("GMAIL_USER",    "")
    GMAIL_PASS    = os.getenv("GMAIL_PASS",    "")
    GMAIL_TO      = os.getenv("GMAIL_TO",      "")

    # Logs
    LOG_FILE  = os.getenv("LOG_FILE",  "service_a.log")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

cfg = Config()


# ──────────────────────────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────────────────────────
def _setup_logger() -> logging.Logger:
    logger = logging.getLogger("SOC-A")
    logger.setLevel(getattr(logging, cfg.LOG_LEVEL, logging.INFO))

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    try:
        fh = RotatingFileHandler(cfg.LOG_FILE, maxBytes=10_000_000, backupCount=5,
                                  encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except Exception:
        pass

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)

    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    return logger

log = _setup_logger()


# ──────────────────────────────────────────────────────────────────
# CONSTANTES
# ──────────────────────────────────────────────────────────────────
SEVERITY_MAP = {
    "critical": 4, "high": 3, "medium": 2,
    "low": 1, "info": 1, "informational": 1,
    "warning": 2, "unknown": 2,
}
SEVERITY_LABEL = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
SEVERITY_EMOJI = {1: "🟢", 2: "🟡", 3: "🟠", 4: "🔴"}
SEV_COLOR = {1: "#22c55e", 2: "#eab308", 3: "#f97316", 4: "#ef4444"}

AUTO_TAGS = {
    r"brute.?force|failed.pass|4625": "brute_force",
    r"ssh|sftp":                        "ssh",
    r"lateral|psexec|wmic|winrm":      "lateral_movement",
    r"mimikatz|pwdump|lsass":          "credential_dumping",
    r"ransom|vssadmin|wbadmin":        "ransomware",
    r"scan|nmap|masscan":              "port_scan",
    r"download|bitsadmin":             "malicious_download",
    r"privilege|escalat|4672|sudo":    "privilege_escalation",
    r"powershell|encoded":             "powershell",
    r"persist|4698|startup":           "persistence",
    r"exfil|dlp":                      "exfiltration",
    r"rdp|3389":                       "rdp",
    r"smb|445|pass.the":               "smb_attack",
}


# ──────────────────────────────────────────────────────────────────
# STATE
# ──────────────────────────────────────────────────────────────────
app             = Flask(__name__)
thehive         = TheHiveApi(cfg.THEHIVE_URL, cfg.THEHIVE_APIKEY)
_rate_cache     = defaultdict(float)
_rate_lock      = threading.Lock()
_debug_payloads = []
_stats          = defaultdict(int)


# ──────────────────────────────────────────────────────────────────
# RATE LIMITER
# ──────────────────────────────────────────────────────────────────
def is_rate_limited(key: str) -> bool:
    with _rate_lock:
        now  = time.time()
        last = _rate_cache.get(key, 0.0)
        if now - last < cfg.RATE_LIMIT_SEC:
            _stats["rate_limited"] += 1
            return True
        _rate_cache[key] = now
        return False


# ──────────────────────────────────────────────────────────────────
# RETRY
# ──────────────────────────────────────────────────────────────────
def with_retry(max_attempts: int = None, delay: int = None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            att = max_attempts or cfg.RETRY_ATTEMPTS
            dly = delay        or cfg.RETRY_DELAY_SEC
            last_exc = None
            for i in range(1, att + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exc = e
                    log.warning("Retry %d/%d %s: %s", i, att, func.__name__, e)
                    if i < att:
                        time.sleep(dly * i)
            raise last_exc
        return wrapper
    return decorator


# ══════════════════════════════════════════════════════════════════
# VIRUSTOTAL v3 — ENRICHISSEMENT IOC
# ══════════════════════════════════════════════════════════════════
class VirusTotalClient:
    """
    Client VirusTotal API v3.
    Analyse : IP, domain, hash (MD5/SHA1/SHA256), URL.
    Gratuit : 500 requêtes/jour, 4 req/min.
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    @classmethod
    def _headers(cls) -> dict:
        return {"x-apikey": cfg.VT_APIKEY, "Accept": "application/json"}

    @classmethod
    def _get(cls, endpoint: str) -> dict:
        """GET avec timeout et gestion d'erreurs."""
        if not cfg.VT_ENABLED or not cfg.VT_APIKEY:
            return {}
        try:
            r = requests.get(
                "{}/{}".format(cls.BASE_URL, endpoint),
                headers=cls._headers(),
                timeout=cfg.VT_TIMEOUT,
            )
            if r.status_code == 200:
                return r.json()
            elif r.status_code == 404:
                log.debug("VT: non trouvé %s", endpoint)
            elif r.status_code == 429:
                log.warning("VT: rate limit atteint (quota 4 req/min ou 500/jour)")
            else:
                log.warning("VT HTTP %d : %s", r.status_code, r.text[:100])
        except requests.exceptions.Timeout:
            log.warning("VT: timeout après %ds", cfg.VT_TIMEOUT)
        except Exception as e:
            log.error("VT erreur: %s", e)
        return {}

    @classmethod
    def _post(cls, endpoint: str, data: dict) -> dict:
        if not cfg.VT_ENABLED or not cfg.VT_APIKEY:
            return {}
        try:
            r = requests.post(
                "{}/{}".format(cls.BASE_URL, endpoint),
                headers=cls._headers(),
                data=data,
                timeout=cfg.VT_TIMEOUT,
            )
            if r.status_code in (200, 201):
                return r.json()
        except Exception as e:
            log.error("VT POST erreur: %s", e)
        return {}

    @classmethod
    def _parse_stats(cls, data: dict) -> dict:
        """Extrait malicious/suspicious/harmless depuis la réponse VT."""
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "malicious":  stats.get("malicious",  0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless",   0),
            "undetected": stats.get("undetected", 0),
            "total":      sum(stats.values()) if stats else 0,
            "reputation": attrs.get("reputation", 0),
            "country":    attrs.get("country", ""),
            "as_owner":   attrs.get("as_owner", ""),
            "names":      attrs.get("names", [])[:3],
            "tags":       attrs.get("tags", [])[:5],
        }

    @classmethod
    def check_ip(cls, ip: str) -> dict:
        """Analyse une IP sur VirusTotal."""
        if not ip or not cfg.VT_APIKEY:
            return {}
        data = cls._get("ip_addresses/{}".format(ip))
        if not data:
            return {}
        result = cls._parse_stats(data)
        result["type"] = "ip"
        result["value"] = ip
        log.info("VT IP %s: malicious=%d suspicious=%d reputation=%d",
                 ip, result["malicious"], result["suspicious"], result["reputation"])
        return result

    @classmethod
    def check_domain(cls, domain: str) -> dict:
        """Analyse un domaine sur VirusTotal."""
        if not domain or not cfg.VT_APIKEY:
            return {}
        data = cls._get("domains/{}".format(domain))
        if not data:
            return {}
        result = cls._parse_stats(data)
        result["type"] = "domain"
        result["value"] = domain
        log.info("VT domain %s: malicious=%d suspicious=%d",
                 domain, result["malicious"], result["suspicious"])
        return result

    @classmethod
    def check_hash(cls, file_hash: str) -> dict:
        """Analyse un hash (MD5/SHA1/SHA256) sur VirusTotal."""
        if not file_hash or not cfg.VT_APIKEY:
            return {}
        data = cls._get("files/{}".format(file_hash))
        if not data:
            return {}
        attrs  = data.get("data", {}).get("attributes", {})
        result = cls._parse_stats(data)
        result["type"]      = "hash"
        result["value"]     = file_hash
        result["file_name"] = attrs.get("meaningful_name", "")
        result["file_type"] = attrs.get("type_description", "")
        result["file_size"] = attrs.get("size", 0)
        result["magic"]     = attrs.get("magic", "")
        log.info("VT hash %s: malicious=%d file=%s",
                 file_hash[:16], result["malicious"], result["file_name"])
        return result

    @classmethod
    def check_url(cls, url: str) -> dict:
        """Analyse une URL sur VirusTotal."""
        if not url or not cfg.VT_APIKEY:
            return {}
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        data = cls._get("urls/{}".format(url_id))
        if not data:
            return {}
        result = cls._parse_stats(data)
        result["type"]  = "url"
        result["value"] = url
        log.info("VT url %s: malicious=%d", url[:50], result["malicious"])
        return result

    @classmethod
    def is_malicious(cls, vt_result: dict) -> bool:
        """Détermine si un résultat VT indique une menace."""
        if not vt_result:
            return False
        malicious  = vt_result.get("malicious",  0)
        suspicious = vt_result.get("suspicious", 0)
        reputation = vt_result.get("reputation", 0)
        return (
            malicious  >= cfg.VT_MIN_DETECTIONS
            or suspicious >= cfg.VT_MIN_DETECTIONS * 2
            or reputation <= -10
        )

    @classmethod
    def format_summary(cls, vt_result: dict) -> str:
        """Formate un résumé lisible du résultat VT."""
        if not vt_result:
            return "VT: non analysé"
        mal = vt_result.get("malicious",  0)
        sus = vt_result.get("suspicious", 0)
        tot = vt_result.get("total",      0)
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
        """
        Analyse tous les IOC d'un résultat Splunk sur VirusTotal.
        Retourne un dict {ioc_value: vt_result}.
        """
        vt_results = {}
        if not cfg.VT_ENABLED or not cfg.VT_APIKEY:
            return vt_results

        # IPs
        for field in ("src_ip", "src", "dest_ip", "dest"):
            ip = str(result.get(field, "")).strip()
            if ip and _is_valid_public_ip(ip) and ip not in vt_results:
                vt = cls.check_ip(ip)
                if vt:
                    vt_results[ip] = vt
                time.sleep(0.3)  # respecter le rate limit VT (4 req/min)

        # Hash
        for field in ("file_hash", "hash", "md5", "sha1", "sha256", "FileHash"):
            fhash = str(result.get(field, "")).strip()
            if fhash and len(fhash) in (32, 40, 64) and fhash not in vt_results:
                vt = cls.check_hash(fhash)
                if vt:
                    vt_results[fhash] = vt
                time.sleep(0.3)
                break

        # Domain
        for field in ("domain", "dest_domain", "query", "QueryName"):
            dom = str(result.get(field, "")).strip()
            if dom and "." in dom and not _is_ip(dom) and dom not in vt_results:
                vt = cls.check_domain(dom)
                if vt:
                    vt_results[dom] = vt
                time.sleep(0.3)
                break

        # URL
        url = str(result.get("url", result.get("uri", ""))).strip()
        if url and url.startswith(("http://", "https://")) and url not in vt_results:
            vt = cls.check_url(url)
            if vt:
                vt_results[url] = vt

        return vt_results


def _is_ip(s: str) -> bool:
    """Vérifie si une chaîne est une IP valide."""
    try:
        import ipaddress
        ipaddress.ip_address(s.strip())
        return True
    except ValueError:
        return False


def _is_valid_public_ip(ip: str) -> bool:
    """Vérifie si une IP est valide ET publique (pas interne)."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip.strip())
        return not (addr.is_private or addr.is_loopback
                    or addr.is_link_local or addr.is_multicast)
    except ValueError:
        return False


# ══════════════════════════════════════════════════════════════════
# PARSING SPLUNK
# ══════════════════════════════════════════════════════════════════
class SplunkParser:
    """Parse tous les formats de payload Splunk (4 formats supportés)."""

    IOC_FIELDS = {
        "src_ip","dest_ip","src","dest","user","User","username",
        "host","source","index","process_name","Image","file_hash",
        "hash","md5","sha1","sha256","domain","dest_domain","query",
        "url","uri","_time","CommandLine","ParentImage","EventCode",
    }

    @classmethod
    def parse(cls, data: dict) -> tuple:
        """Retourne (search_name, severity, result_dict)."""
        name = (data.get("search_name") or data.get("name")
                or data.get("alert_name") or "Alerte Splunk")
        sev  = (data.get("severity") or data.get("alert.severity")
                or data.get("urgency") or "medium")

        # Format 1: result dict
        r = data.get("result")
        if isinstance(r, dict) and r:
            return name, sev, r

        # Format 2: results list
        rl = data.get("results")
        if isinstance(rl, list) and rl:
            return name, sev, rl[0]

        # Format 3: payload plat (IOC à la racine)
        flat = {k: v for k, v in data.items() if k in cls.IOC_FIELDS}
        if flat:
            return name, sev, flat

        # Format 4: result comme JSON string
        if isinstance(r, str):
            try:
                parsed = json.loads(r)
                if isinstance(parsed, dict):
                    return name, sev, parsed
            except Exception:
                pass

        # Fallback minimal
        minimal = {
            "host":   data.get("host", data.get("server_host", "N/A")),
            "source": data.get("source", "Splunk Webhook"),
            "_time":  data.get("_time", datetime.utcnow().isoformat()),
        }
        log.warning("Aucun format reconnu, fallback: %s", list(minimal.keys()))
        return name, sev, minimal


# ══════════════════════════════════════════════════════════════════
# ENRICHISSEMENT ALERT
# ══════════════════════════════════════════════════════════════════
class AlertEnricher:

    @staticmethod
    def normalize_severity(s: str) -> int:
        return SEVERITY_MAP.get(str(s).strip().lower(), 2)

    @staticmethod
    def generate_source_ref(name: str, result: dict) -> str:
        raw = "{}-{}-{}".format(
            name,
            result.get("src_ip", result.get("src", result.get("host", ""))),
            result.get("_time", datetime.utcnow().strftime("%Y-%m-%d %H:%M")),
        )
        return "splunk-" + hashlib.sha256(raw.encode()).hexdigest()[:16]

    @staticmethod
    def extract_tags(name: str, result: dict, vt_results: dict) -> list:
        tags     = ["splunk", "auto-ingested"]
        combined = (name + " " + json.dumps(result, default=str)).lower()

        for pattern, tag in AUTO_TAGS.items():
            if re.search(pattern, combined) and tag not in tags:
                tags.append(tag)

        # OS
        src = result.get("source", "").lower()
        idx = result.get("index",  "").lower()
        if "windows" in idx or "winevent" in src:
            tags.append("windows")
        elif "linux" in idx or "auth.log" in src or "syslog" in src:
            tags.append("linux")

        # EventCode
        ec = str(result.get("EventCode", result.get("event_code", "")))
        if ec:
            tags.append("ec-{}".format(ec))

        # VirusTotal tags
        for ioc, vt in vt_results.items():
            if VirusTotalClient.is_malicious(vt):
                if "vt-malicious" not in tags:
                    tags.append("vt-malicious")
            elif vt.get("suspicious", 0) > 0:
                if "vt-suspicious" not in tags:
                    tags.append("vt-suspicious")

        return list(dict.fromkeys(tags))

    @staticmethod
    def extract_observables(result: dict, vt_results: dict) -> list:
        """Extrait les IOC et ajoute les résultats VirusTotal dans les messages."""
        artifacts = []

        def add(dtype, value, msg, ioc=False, tags=None):
            v = str(value).strip()
            if v and v.lower() not in ("-", "n/a", "", "none", "null", "unknown"):
                # Enrichir le message avec VT si disponible
                vt = vt_results.get(v, {})
                if vt:
                    msg = "{} | {}".format(msg, VirusTotalClient.format_summary(vt))
                    if VirusTotalClient.is_malicious(vt):
                        ioc = True
                artifacts.append(AlertArtifact(
                    dataType=dtype, data=v, message=msg,
                    tags=(tags or []) + ["splunk"] + (["vt-malicious"] if vt and VirusTotalClient.is_malicious(vt) else []),
                    ioc=ioc,
                ))

        # IP source
        for f in ("src_ip", "src", "SourceIp"):
            v = result.get(f, "")
            if v:
                add("ip", v, "IP source (Splunk)", ioc=True, tags=["src_ip"])
                break

        # IP dest
        for f in ("dest_ip", "dest", "DestinationIp"):
            v = result.get(f, "")
            if v:
                add("ip", v, "IP destination (Splunk)", tags=["dest_ip"])
                break

        # User
        for f in ("user", "User", "username", "AccountName"):
            v = result.get(f, "")
            if v:
                add("other", v, "Utilisateur impliqué", tags=["user"])
                break

        # Hash
        for f in ("file_hash", "hash", "md5", "sha1", "sha256", "FileHash"):
            v = result.get(f, "")
            if v and len(v) in (32, 40, 64):
                add("hash", v, "Hash fichier suspect", ioc=True, tags=["hash"])
                break

        # Domain
        for f in ("domain", "dest_domain", "query", "QueryName"):
            v = result.get(f, "")
            if v and "." in str(v) and not _is_ip(str(v)):
                add("domain", v, "Domaine suspect", ioc=True, tags=["domain"])
                break

        # URL
        for f in ("url", "uri"):
            v = result.get(f, "")
            if v and str(v).startswith(("http://", "https://")):
                add("url", v, "URL suspecte", ioc=True, tags=["url"])
                break

        # CommandLine
        cmd = result.get("CommandLine", result.get("command_line", ""))
        if cmd and len(str(cmd)) > 10:
            add("other", str(cmd)[:500], "Ligne de commande", tags=["cmdline"])

        # Fallback host
        if not artifacts:
            h = result.get("host", "")
            if h:
                add("other", h, "Hôte source", tags=["host"])

        return artifacts

    @staticmethod
    def build_description(name: str, result: dict, vt_results: dict) -> str:
        """Construit la description TheHive avec résultats VirusTotal."""
        lines = [
            "## 🚨 Alerte Splunk : {}".format(name),
            "",
            "### 📋 Informations générales",
            "| Champ | Valeur |",
            "|-------|--------|",
            "| **Hôte** | `{}` |".format(result.get("host", "N/A")),
            "| **Source** | `{}` |".format(result.get("source", "N/A")),
            "| **Index** | `{}` |".format(result.get("index", "N/A")),
            "| **Horodatage** | `{}` |".format(result.get("_time", "N/A")),
            "",
            "### 🎯 Indicateurs détectés",
            "| Type | Valeur |",
            "|------|--------|",
            "| IP source | `{}` |".format(result.get("src_ip", result.get("src", "N/A"))),
            "| IP dest | `{}` |".format(result.get("dest_ip", result.get("dest", "N/A"))),
            "| Utilisateur | `{}` |".format(result.get("user", "N/A")),
            "| Processus | `{}` |".format(result.get("process_name", result.get("Image", "N/A"))),
            "| Domaine | `{}` |".format(result.get("domain", "N/A")),
            "| Hash | `{}` |".format(result.get("file_hash", result.get("hash", "N/A"))),
            "| EventCode | `{}` |".format(result.get("EventCode", "N/A")),
        ]

        # Section VirusTotal
        if vt_results:
            lines += ["", "### 🦠 Analyse VirusTotal"]
            for ioc, vt in vt_results.items():
                mal = vt.get("malicious",  0)
                sus = vt.get("suspicious", 0)
                tot = vt.get("total",      0)
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
                    ioc[:50], verdict, mal, tot, rep
                ))
                # Infos supplémentaires
                if vt.get("country"):
                    lines.append("| Pays | `{}` |".format(vt["country"]))
                if vt.get("as_owner"):
                    lines.append("| AS | `{}` |".format(vt["as_owner"]))
                if vt.get("file_name"):
                    lines.append("| Fichier | `{}` ({}) |".format(
                        vt["file_name"], vt.get("file_type", "")
                    ))
                if vt.get("tags"):
                    lines.append("| Tags VT | `{}` |".format(", ".join(vt["tags"])))
        else:
            if cfg.VT_ENABLED and not cfg.VT_APIKEY:
                lines += ["", "> ⚠️ *VirusTotal : VT_APIKEY non configurée*"]
            elif not cfg.VT_ENABLED:
                lines += ["", "> ℹ️ *VirusTotal désactivé (VT_ENABLED=false)*"]

        lines += [
            "",
            "### 📦 Données brutes Splunk",
            "```json",
            json.dumps(result, indent=2, ensure_ascii=False, default=str)[:3000],
            "```",
            "",
            "---",
            "> *Ingéré automatiquement par SOC Pipeline Service A v7.0.0*",
            "> *{}*".format(datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")),
        ]
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════
# NOTIFICATIONS
# ══════════════════════════════════════════════════════════════════
class Notifier:

    @staticmethod
    def _send_telegram_raw(message: str, keyboard: dict = None):
        """Envoi Telegram direct (synchrone, pour startup/test)."""
        if not cfg.TELEGRAM_ENABLED or not cfg.TELEGRAM_TOKEN or not cfg.TELEGRAM_CHAT_ID:
            return False
        try:
            payload = {
                "chat_id":    cfg.TELEGRAM_CHAT_ID,
                "text":       message[:4096],
                "parse_mode": "HTML",
            }
            if keyboard:
                payload["reply_markup"] = json.dumps(keyboard)
            r = requests.post(
                "https://api.telegram.org/bot{}/sendMessage".format(cfg.TELEGRAM_TOKEN),
                json=payload, timeout=10,
            )
            if r.status_code == 200:
                log.info("Telegram OK")
                return True
            else:
                log.warning("Telegram erreur %d: %s", r.status_code, r.text[:200])
                return False
        except Exception as e:
            log.error("Telegram exception: %s", e)
            return False

    @classmethod
    def _send_telegram_async(cls, message: str, keyboard: dict = None):
        """Envoi Telegram en arrière-plan."""
        threading.Thread(
            target=cls._send_telegram_raw,
            args=(message, keyboard),
            daemon=True,
        ).start()

    @staticmethod
    def _send_gmail_async(subject: str, body_text: str, body_html: str = None):
        if not cfg.GMAIL_ENABLED or not all([cfg.GMAIL_USER, cfg.GMAIL_PASS, cfg.GMAIL_TO]):
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
                with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
                    s.login(cfg.GMAIL_USER, cfg.GMAIL_PASS)
                    s.sendmail(cfg.GMAIL_USER, cfg.GMAIL_TO, msg.as_string())
                log.info("Gmail OK: %s", subject)
            except Exception as e:
                log.error("Gmail: %s", e)

        threading.Thread(target=_send, daemon=True).start()

    @classmethod
    def send_alert(cls, name: str, sev: int, result: dict,
                   alert_id: str = None, vt_results: dict = None):
        """Notifie Telegram + Gmail quand une alerte est créée."""
        if sev < cfg.NOTIFY_MIN_SEV:
            return

        vt_results  = vt_results or {}
        sev_emoji   = SEVERITY_EMOJI.get(sev, "⚪")
        sev_label   = SEVERITY_LABEL.get(sev, "?")
        now         = result.get("_time", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))

        # Résumé VT
        vt_lines = []
        for ioc, vt in vt_results.items():
            if vt:
                mal = vt.get("malicious", 0)
                tot = vt.get("total",     0)
                ico = "🔴" if VirusTotalClient.is_malicious(vt) else ("🟡" if vt.get("suspicious",0) > 0 else "🟢")
                vt_lines.append("{} <code>{}</code> {}/{}".format(ico, ioc[:30], mal, tot))

        # Message Telegram
        tg = [
            "{} <b>ALERTE SOC — {}</b>".format(sev_emoji, sev_label.upper()),
            "",
            "<b>Recherche :</b> {}".format(name),
            "<b>Hôte      :</b> <code>{}</code>".format(result.get("host", "N/A")),
            "<b>IP src    :</b> <code>{}</code>".format(result.get("src_ip", result.get("src", "N/A"))),
            "<b>IP dst    :</b> <code>{}</code>".format(result.get("dest_ip", result.get("dest", "N/A"))),
            "<b>User      :</b> <code>{}</code>".format(result.get("user", "N/A")),
            "<b>Processus :</b> <code>{}</code>".format(result.get("process_name", "N/A")),
            "<b>Heure     :</b> {}".format(now),
        ]
        if vt_lines:
            tg += ["", "<b>🦠 VirusTotal :</b>"] + vt_lines
        tg += ["", "<i>SOC Pipeline Service A v7.0.0</i>"]

        # Boutons
        kbd = {"inline_keyboard": [[], []]}
        if alert_id:
            kbd["inline_keyboard"][0].append({
                "text": "🔍 Voir alerte TheHive",
                "url":  "{}/alerts/{}".format(cfg.THEHIVE_URL, alert_id),
            })
        if alert_id:
            kbd["inline_keyboard"][1] += [
                {"text": "⬆️ Escalader",        "url": "{}/alerts/{}".format(cfg.THEHIVE_URL, alert_id)},
                {"text": "✅ Marquer comme vu", "url": "{}/alerts/{}".format(cfg.THEHIVE_URL, alert_id)},
            ]
        kbd["inline_keyboard"] = [r for r in kbd["inline_keyboard"] if r]

        cls._send_telegram_async("\n".join(tg), kbd)

        # Email HTML
        col   = SEV_COLOR.get(sev, "#64748b")
        gmail_html = """<html><body style="font-family:Arial,sans-serif;background:#f1f5f9;padding:20px">
<div style="background:#fff;border-radius:8px;padding:24px;max-width:640px;margin:auto;border-left:5px solid {col}">
  <h2 style="color:{col};margin-top:0">{emoji} Alerte SOC — {sev}</h2>
  <table style="width:100%;border-collapse:collapse;font-size:14px">
    <tr><td style="padding:6px;color:#666;width:40%"><b>Recherche</b></td><td style="padding:6px">{name}</td></tr>
    <tr style="background:#f8fafc"><td style="padding:6px;color:#666"><b>Hôte</b></td><td style="padding:6px;font-family:monospace">{host}</td></tr>
    <tr><td style="padding:6px;color:#666"><b>IP source</b></td><td style="padding:6px;font-family:monospace">{src}</td></tr>
    <tr style="background:#f8fafc"><td style="padding:6px;color:#666"><b>Utilisateur</b></td><td style="padding:6px;font-family:monospace">{user}</td></tr>
    <tr><td style="padding:6px;color:#666"><b>Horodatage</b></td><td style="padding:6px">{ts}</td></tr>
  </table>
  {vt_section}
  <div style="margin-top:16px">
    <a href="{url}/alerts/{aid}" style="background:#2563eb;color:#fff;padding:10px 18px;border-radius:6px;text-decoration:none;font-size:13px">🔍 Voir dans TheHive</a>
  </div>
  <hr style="border:none;border-top:1px solid #e2e8f0;margin-top:20px">
  <p style="color:#94a3b8;font-size:11px">SOC Pipeline Service A v7.0.0 — Rachad Lab</p>
</div></body></html>""".format(
            col=col, emoji=sev_emoji, sev=sev_label.upper(),
            name=name, host=result.get("host","N/A"),
            src=result.get("src_ip", result.get("src","N/A")),
            user=result.get("user","N/A"), ts=now,
            url=cfg.THEHIVE_URL, aid=alert_id or "",
            vt_section="<h3>🦠 VirusTotal</h3><ul>{}</ul>".format(
                "".join("<li>{}</li>".format(l) for l in vt_lines)
            ) if vt_lines else "",
        )
        cls._send_gmail_async(
            "[SOC {}] {}".format(sev_label.upper(), name),
            "\n".join(tg).replace("<b>","").replace("</b>","")
                         .replace("<i>","").replace("</i>","")
                         .replace("<code>","").replace("</code>",""),
            gmail_html,
        )


# ══════════════════════════════════════════════════════════════════
# THEHIVE SERVICE (avec retry)
# ══════════════════════════════════════════════════════════════════
class TheHiveService:

    @staticmethod
    @with_retry()
    def create_alert(alert: Alert):
        return thehive.create_alert(alert)


# ══════════════════════════════════════════════════════════════════
# STARTUP CHECK
# ══════════════════════════════════════════════════════════════════
def startup_check():
    time.sleep(2)

    # TheHive
    thehive_ok = False
    try:
        r = thehive.find_alerts(query={}, range="0-1")
        thehive_ok = r.status_code == 200
    except Exception as e:
        log.error("TheHive inaccessible: %s", e)

    # VirusTotal
    vt_ok = False
    if cfg.VT_ENABLED and cfg.VT_APIKEY:
        try:
            r = requests.get(
                "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
                headers={"x-apikey": cfg.VT_APIKEY},
                timeout=10,
            )
            vt_ok = r.status_code == 200
        except Exception:
            vt_ok = False

    # Telegram
    telegram_ok = None
    if cfg.TELEGRAM_ENABLED:
        if not cfg.TELEGRAM_TOKEN:
            print("[TELEGRAM] ⚠️  TELEGRAM_TOKEN vide dans .env !")
            telegram_ok = False
        elif not cfg.TELEGRAM_CHAT_ID:
            print("[TELEGRAM] ⚠️  TELEGRAM_CHAT_ID vide dans .env !")
            telegram_ok = False
        else:
            try:
                r = requests.get(
                    "https://api.telegram.org/bot{}/getMe".format(cfg.TELEGRAM_TOKEN),
                    timeout=8,
                )
                if r.status_code == 200:
                    bot = r.json().get("result", {})
                    telegram_ok = True
                    print("[TELEGRAM] ✅ Bot @{}".format(bot.get("username","?")))
                    # Message de démarrage
                    Notifier._send_telegram_raw(
                        "🚀 <b>SOC Pipeline — Service A démarré</b>\n"
                        "⏰ {}\n\n"
                        "{} TheHive : {}\n"
                        "{} VirusTotal : {}\n"
                        "📡 Webhook : :5000/alert".format(
                            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "✅" if thehive_ok else "❌", cfg.THEHIVE_URL,
                            "✅" if vt_ok else ("⚠️ clé manquante" if not cfg.VT_APIKEY else "❌"),
                            "Actif" if vt_ok else "Vérifier VT_APIKEY",
                        )
                    )
                else:
                    telegram_ok = False
                    print("[TELEGRAM] ❌ Token invalide (HTTP {})".format(r.status_code))
            except Exception as e:
                telegram_ok = False
                print("[TELEGRAM] ❌ Erreur connexion : {}".format(e))

    # Gmail
    gmail_ok = None
    if cfg.GMAIL_ENABLED and cfg.GMAIL_USER and cfg.GMAIL_PASS:
        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
                s.login(cfg.GMAIL_USER, cfg.GMAIL_PASS)
            gmail_ok = True
        except Exception:
            gmail_ok = False

    def st(v):
        if v is True:  return "✅ OK"
        if v is False: return "❌ ERREUR"
        return "⚪ Désactivé"

    print("")
    print("=" * 62)
    print("  SOC Pipeline — Service A  v7.0.0")
    print("=" * 62)
    print("  TheHive     : {} — {}".format(st(thehive_ok), cfg.THEHIVE_URL))
    print("  VirusTotal  : {}{}".format(
        st(vt_ok) if cfg.VT_ENABLED else "⚪ Désactivé",
        "" if cfg.VT_APIKEY else " (VT_APIKEY non défini)",
    ))
    print("  Telegram    : {}".format(st(telegram_ok)))
    print("  Gmail       : {}".format(st(gmail_ok)))
    print("  Webhook     : http://{}:{}/alert".format(cfg.LISTEN_HOST, cfg.LISTEN_PORT))
    print("  Rate limit  : {}s".format(cfg.RATE_LIMIT_SEC))
    print("-" * 62)
    print("  Endpoints   :")
    print("    POST /alert         — webhook Splunk")
    print("    GET  /health        — health check")
    print("    GET  /test          — alerte de test")
    print("    GET  /telegram-test — tester Telegram")
    print("    GET  /vt-test       — tester VirusTotal")
    print("    GET  /debug         — derniers payloads")
    print("    GET  /stats         — statistiques")
    print("=" * 62)

    if not thehive_ok:
        log.critical("TheHive inaccessible — vérifier THEHIVE_URL et THEHIVE_APIKEY")


# ══════════════════════════════════════════════════════════════════
# ENDPOINTS FLASK
# ══════════════════════════════════════════════════════════════════

@app.route("/alert", methods=["POST"])
def receive_alert():
    """Endpoint principal : reçoit les alertes Splunk."""
    global _debug_payloads
    try:
        raw  = request.get_data(as_text=True)
        data = request.get_json(force=True, silent=True)

        # Stocker pour debug
        _debug_payloads.append({
            "ts": datetime.utcnow().isoformat() + "Z",
            "ip": request.remote_addr,
            "raw": raw[:800],
        })
        if len(_debug_payloads) > 50:
            _debug_payloads = _debug_payloads[-50:]

        _stats["received"] += 1

        if not data:
            _stats["errors"] += 1
            return jsonify({"status": "error", "reason": "payload non-JSON ou vide"}), 400

        # Parse
        name, sev_str, result = SplunkParser.parse(data)
        sev_int    = AlertEnricher.normalize_severity(sev_str)
        source_ref = AlertEnricher.generate_source_ref(name, result)

        log.info("Alerte: '%s' sev=%d host=%s ref=%s",
                 name, sev_int, result.get("host","N/A"), source_ref)

        # Rate limit
        if is_rate_limited(source_ref):
            return jsonify({"status": "rate_limited", "source_ref": source_ref}), 200

        # VirusTotal enrichissement (asynchrone pour ne pas bloquer)
        vt_results = {}
        if cfg.VT_ENABLED and cfg.VT_APIKEY:
            try:
                vt_results = VirusTotalClient.enrich_observables(result)
                _stats["vt_analyses"] += len(vt_results)
                vt_malicious = sum(1 for v in vt_results.values()
                                   if VirusTotalClient.is_malicious(v))
                if vt_malicious:
                    _stats["vt_malicious"] += vt_malicious
                    # Escalader la sévérité si VT confirme menace
                    if sev_int < 3:
                        sev_int = 3
                        log.info("Sévérité escaladée à High (VT malicious: %d)", vt_malicious)
            except Exception as e:
                log.error("VT enrichissement erreur: %s", e)

        # Enrichissement
        tags      = AlertEnricher.extract_tags(name, result, vt_results)
        artifacts = AlertEnricher.extract_observables(result, vt_results)
        desc      = AlertEnricher.build_description(name, result, vt_results)

        # Créer alerte TheHive
        alert = Alert(
            title       = "[SPLUNK] {}".format(name),
            tlp         = 2,
            severity    = sev_int,
            status      = "New",
            type        = "external",
            source      = "Splunk",
            sourceRef   = source_ref,
            description = desc,
            tags        = tags,
            artifacts   = artifacts,
        )

        response = TheHiveService.create_alert(alert)

        if response.status_code == 201:
            alert_id = response.json().get("id", "")
            _stats["created"] += 1
            log.info("Alerte TheHive créée: id=%s ref=%s sev=%d art=%d vt=%d",
                     alert_id, source_ref, sev_int, len(artifacts), len(vt_results))

            Notifier.send_alert(name, sev_int, result, alert_id, vt_results)

            return jsonify({
                "status":          "created",
                "alert_id":        alert_id,
                "source_ref":      source_ref,
                "severity":        SEVERITY_LABEL.get(sev_int, "?"),
                "artifacts_count": len(artifacts),
                "tags":            tags,
                "virustotal": {
                    "analyzed": len(vt_results),
                    "malicious": sum(1 for v in vt_results.values()
                                     if VirusTotalClient.is_malicious(v)),
                    "results": {k: {
                        "malicious": v.get("malicious",0),
                        "total":     v.get("total",0),
                        "verdict":   "malicious" if VirusTotalClient.is_malicious(v) else "clean",
                    } for k,v in vt_results.items()},
                },
            }), 201

        elif response.status_code in (400, 409):
            _stats["duplicates"] += 1
            log.info("Doublon ignoré: ref=%s", source_ref)
            return jsonify({"status": "duplicate", "source_ref": source_ref}), 200

        else:
            _stats["errors"] += 1
            log.error("TheHive HTTP %d: %s", response.status_code, response.text[:300])
            return jsonify({
                "status":    "error",
                "http_code": response.status_code,
                "detail":    response.text[:300],
            }), 500

    except Exception as e:
        _stats["errors"] += 1
        log.exception("Erreur /alert: %s", e)
        return jsonify({"status": "error", "detail": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    thehive_ok = False
    try:
        r = thehive.find_alerts(query={}, range="0-1")
        thehive_ok = r.status_code == 200
    except Exception:
        pass

    return jsonify({
        "status":              "healthy" if thehive_ok else "degraded",
        "service":             "soc-service-a",
        "version":             "7.0.0",
        "thehive_url":         cfg.THEHIVE_URL,
        "thehive_ok":          thehive_ok,
        "virustotal_enabled":  cfg.VT_ENABLED,
        "virustotal_key_set":  bool(cfg.VT_APIKEY),
        "telegram_enabled":    cfg.TELEGRAM_ENABLED,
        "telegram_ready":      cfg.TELEGRAM_ENABLED and bool(cfg.TELEGRAM_TOKEN) and bool(cfg.TELEGRAM_CHAT_ID),
        "gmail_enabled":       cfg.GMAIL_ENABLED,
        "rate_limit_sec":      cfg.RATE_LIMIT_SEC,
        "notify_min_severity": SEVERITY_LABEL.get(cfg.NOTIFY_MIN_SEV, "?"),
        "stats":               dict(_stats),
        "timestamp":           datetime.utcnow().isoformat() + "Z",
    }), 200 if thehive_ok else 503


@app.route("/vt-test", methods=["GET"])
def vt_test():
    """Teste VirusTotal avec une IP connue malveillante (1.1.1.1 = test bénin)."""
    if not cfg.VT_ENABLED:
        return jsonify({"status": "disabled", "fix": "VT_ENABLED=true dans .env"}), 200
    if not cfg.VT_APIKEY:
        return jsonify({
            "status": "no_key",
            "fix": "Ajouter VT_APIKEY=VOTRE_CLE dans .env. Clé gratuite sur virustotal.com",
        }), 400

    # Test avec 8.8.8.8 (Google DNS — propre)
    vt = VirusTotalClient.check_ip("8.8.8.8")
    if vt:
        return jsonify({
            "status":  "ok",
            "message": "VirusTotal fonctionne !",
            "test_ip": "8.8.8.8",
            "result":  vt,
            "verdict": VirusTotalClient.format_summary(vt),
        }), 200
    else:
        return jsonify({
            "status": "error",
            "fix":    "Vérifier VT_APIKEY et la connexion internet",
        }), 500


@app.route("/telegram-test", methods=["GET"])
def telegram_test():
    """Teste Telegram avec diagnostic complet."""
    diag = {
        "TELEGRAM_ENABLED":   cfg.TELEGRAM_ENABLED,
        "TELEGRAM_TOKEN_SET": bool(cfg.TELEGRAM_TOKEN),
        "TELEGRAM_CHAT_ID":   cfg.TELEGRAM_CHAT_ID or "VIDE",
    }

    if not cfg.TELEGRAM_ENABLED:
        return jsonify({"status": "disabled", "fix": "TELEGRAM_ENABLED=true dans .env", "config": diag}), 200
    if not cfg.TELEGRAM_TOKEN:
        return jsonify({"status": "no_token",  "fix": "TELEGRAM_TOKEN vide dans .env", "config": diag}), 400
    if not cfg.TELEGRAM_CHAT_ID:
        return jsonify({"status": "no_chat_id","fix": "TELEGRAM_CHAT_ID vide dans .env", "config": diag}), 400

    # Vérifier token
    try:
        r = requests.get(
            "https://api.telegram.org/bot{}/getMe".format(cfg.TELEGRAM_TOKEN), timeout=8
        )
        if r.status_code != 200:
            return jsonify({"status": "invalid_token", "telegram": r.json(), "config": diag}), 400
        bot = r.json().get("result", {})
    except Exception as e:
        return jsonify({"status": "connection_error", "detail": str(e)}), 500

    # Envoyer message test
    msg = (
        "🧪 <b>TEST SOC Pipeline — Service A v7.0.0</b>\n\n"
        "✅ Telegram <b>fonctionne !</b>\n"
        "⏰ {}\n\n"
        "<b>Config :</b>\n"
        "• TheHive : {}\n"
        "• VT : {}\n\n"
        "<i>Tu recevras les alertes Splunk High/Critical ici.</i>"
    ).format(
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        cfg.THEHIVE_URL,
        "Actif ✅" if (cfg.VT_ENABLED and cfg.VT_APIKEY) else "Non configuré ⚠️",
    )

    ok = Notifier._send_telegram_raw(msg)
    if ok:
        return jsonify({
            "status":  "success",
            "message": "Message envoyé ! Vérifie ton Telegram.",
            "bot":     bot.get("username"),
            "config":  diag,
        }), 200
    else:
        return jsonify({
            "status": "send_failed",
            "fix":    "Envoie /start au bot dans Telegram d'abord",
            "config": diag,
        }), 400


@app.route("/test", methods=["GET", "POST"])
def test_alert():
    """Envoie une alerte de test complète (inclut VT si configuré)."""
    fake = {
        "search_name": "TEST — SOC Pipeline v7.0.0",
        "severity":    "high",
        "result": {
            "host":         "srv-linux-01",
            "source":       "/var/log/auth.log",
            "index":        "linux_logs",
            "src_ip":       "185.220.101.50",   # IP Tor connue — VT la marquera
            "dest_ip":      "10.2.3.114",
            "user":         "root",
            "process_name": "sshd",
            "_time":        datetime.utcnow().isoformat(),
            "count":        "121",
            "message":      "Failed password for root from 185.220.101.50 port 22 ssh2",
        },
    }
    try:
        r = requests.post(
            "http://127.0.0.1:{}/alert".format(cfg.LISTEN_PORT),
            json=fake, timeout=30,  # 30s pour laisser VT analyser
        )
        return jsonify({"status": "test_sent", "response": r.json()}), 200
    except Exception as e:
        return jsonify({"status": "error", "detail": str(e)}), 500


@app.route("/debug", methods=["GET"])
def debug():
    return jsonify({
        "total_received": _stats.get("received", 0),
        "last_payloads":  _debug_payloads[-10:],
        "stats":          dict(_stats),
    }), 200


@app.route("/stats", methods=["GET"])
def stats():
    return jsonify({
        "stats":     dict(_stats),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }), 200


# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    threading.Thread(target=startup_check, daemon=True).start()
    app.run(
        host=cfg.LISTEN_HOST,
        port=cfg.LISTEN_PORT,
        debug=False,
        use_reloader=False,
    )
