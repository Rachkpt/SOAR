#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  SOC Automation Pipeline — Service A                        ║
║  Splunk → TheHive  (webhook + VirusTotal enrichment)        ║
║  Version : 7.0.0                                            ║
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
# CHARGEMENT .env
# ══════════════════════════════════════════════════════════════════
def _load_env_file() -> str:
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
                    os.environ[key.strip()] = val.strip().strip('"').strip("'")
                    count += 1
            print("[ENV] Chargé : {} ({} variables)".format(path, count))
            return str(path)
    print("[ENV] Aucun .env trouvé — variables système utilisées")
    return None

_ENV_PATH = _load_env_file()

import requests
from flask import Flask, request, jsonify
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact


# ──────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────
class Config:
    THEHIVE_URL    = os.getenv("THEHIVE_URL",    "http://_IP_:9000")
    THEHIVE_APIKEY = os.getenv("THEHIVE_APIKEY", "")
    LISTEN_HOST    = os.getenv("LISTEN_HOST",    "0.0.0.0")
    LISTEN_PORT    = int(os.getenv("LISTEN_PORT", "5000"))
    VT_ENABLED         = os.getenv("VT_ENABLED", "true").lower() == "true"
    VT_APIKEY          = os.getenv("VT_APIKEY",  "")
    VT_TIMEOUT         = int(os.getenv("VT_TIMEOUT", "15"))
    VT_MIN_DETECTIONS  = int(os.getenv("VT_MIN_DETECTIONS", "2"))
    RATE_LIMIT_SEC     = int(os.getenv("RATE_LIMIT_SEC",  "10"))
    RETRY_ATTEMPTS     = int(os.getenv("RETRY_ATTEMPTS",  "3"))
    RETRY_DELAY_SEC    = int(os.getenv("RETRY_DELAY_SEC", "5"))
    NOTIFY_MIN_SEV     = int(os.getenv("NOTIFY_MIN_SEV",  "3"))
    TELEGRAM_ENABLED   = os.getenv("TELEGRAM_ENABLED",  "false").lower() == "true"
    TELEGRAM_TOKEN     = os.getenv("TELEGRAM_TOKEN",    "")
    TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID",  "")
    GMAIL_ENABLED      = os.getenv("GMAIL_ENABLED", "false").lower() == "true"
    GMAIL_USER         = os.getenv("GMAIL_USER",    "")
    GMAIL_PASS         = os.getenv("GMAIL_PASS",    "")
    GMAIL_TO           = os.getenv("GMAIL_TO",      "")
    LOG_FILE           = os.getenv("LOG_FILE",  "service_a.log")
    LOG_LEVEL          = os.getenv("LOG_LEVEL", "INFO")

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
        fh = RotatingFileHandler(cfg.LOG_FILE, maxBytes=10_000_000,
                                  backupCount=5, encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except Exception:
        pass
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
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
SEV_COLOR      = {1: "#22c55e", 2: "#eab308", 3: "#f97316", 4: "#ef4444"}

AUTO_TAGS = {
    r"brute.?force|failed.pass|4625": "brute_force",
    r"ssh|sftp":                       "ssh",
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
            att      = max_attempts or cfg.RETRY_ATTEMPTS
            dly      = delay        or cfg.RETRY_DELAY_SEC
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
# VIRUSTOTAL v3
# ══════════════════════════════════════════════════════════════════
class VirusTotalClient:
    BASE_URL = "https://www.virustotal.com/api/v3"

    @classmethod
    def _headers(cls) -> dict:
        return {"x-apikey": cfg.VT_APIKEY, "Accept": "application/json"}

    @classmethod
    def _get(cls, endpoint: str) -> dict:
        if not cfg.VT_ENABLED or not cfg.VT_APIKEY:
            return {}
        try:
            r = requests.get(
                "{}/{}".format(cls.BASE_URL, endpoint),
                headers=cls._headers(),
                timeout=cfg.VT_TIMEOUT,
            )
            if r.status_code == 200:   return r.json()
            elif r.status_code == 404: log.debug("VT: non trouvé %s", endpoint)
            elif r.status_code == 429: log.warning("VT: rate limit")
            else:                      log.warning("VT HTTP %d", r.status_code)
        except requests.exceptions.Timeout:
            log.warning("VT: timeout après %ds", cfg.VT_TIMEOUT)
        except Exception as e:
            log.error("VT erreur: %s", e)
        return {}

    @classmethod
    def _parse_stats(cls, data: dict) -> dict:
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "malicious":  stats.get("malicious",  0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless",   0),
            "undetected": stats.get("undetected", 0),
            "total":      sum(stats.values()) if stats else 0,
            "reputation": attrs.get("reputation", 0),
            "country":    attrs.get("country",    ""),
            "as_owner":   attrs.get("as_owner",   ""),
            "names":      attrs.get("names",      [])[:3],
            "tags":       attrs.get("tags",       [])[:5],
        }

    @classmethod
    def check_ip(cls, ip: str) -> dict:
        if not ip or not cfg.VT_APIKEY: return {}
        data   = cls._get("ip_addresses/{}".format(ip))
        if not data: return {}
        result = cls._parse_stats(data)
        result["type"]  = "ip"
        result["value"] = ip
        log.info("VT IP %s: malicious=%d suspicious=%d reputation=%d",
                 ip, result["malicious"], result["suspicious"], result["reputation"])
        return result

    @classmethod
    def check_domain(cls, domain: str) -> dict:
        if not domain or not cfg.VT_APIKEY: return {}
        data   = cls._get("domains/{}".format(domain))
        if not data: return {}
        result = cls._parse_stats(data)
        result["type"]  = "domain"
        result["value"] = domain
        return result

    @classmethod
    def check_hash(cls, file_hash: str) -> dict:
        if not file_hash or not cfg.VT_APIKEY: return {}
        data   = cls._get("files/{}".format(file_hash))
        if not data: return {}
        attrs  = data.get("data", {}).get("attributes", {})
        result = cls._parse_stats(data)
        result["type"]      = "hash"
        result["value"]     = file_hash
        result["file_name"] = attrs.get("meaningful_name", "")
        result["file_type"] = attrs.get("type_description", "")
        result["file_size"] = attrs.get("size", 0)
        log.info("VT hash %s: malicious=%d file=%s",
                 file_hash[:16], result["malicious"], result["file_name"])
        return result

    @classmethod
    def check_url(cls, url: str) -> dict:
        if not url or not cfg.VT_APIKEY: return {}
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        data   = cls._get("urls/{}".format(url_id))
        if not data: return {}
        result = cls._parse_stats(data)
        result["type"]  = "url"
        result["value"] = url
        return result

    @classmethod
    def is_malicious(cls, vt_result: dict) -> bool:
        if not vt_result: return False
        return (
            vt_result.get("malicious",  0) >= cfg.VT_MIN_DETECTIONS
            or vt_result.get("suspicious", 0) >= cfg.VT_MIN_DETECTIONS * 2
            or vt_result.get("reputation", 0) <= -10
        )

    @classmethod
    def format_summary(cls, vt_result: dict) -> str:
        if not vt_result: return "VT: non analysé"
        mal = vt_result.get("malicious",  0)
        sus = vt_result.get("suspicious", 0)
        tot = vt_result.get("total",      0)
        rep = vt_result.get("reputation", 0)
        if mal > 0:   verdict = "🔴 MALVEILLANT"
        elif sus > 0: verdict = "🟡 SUSPECT"
        elif tot > 0: verdict = "🟢 PROPRE"
        else:         verdict = "⚪ INCONNU"
        parts = ["{} ({}/{} détections".format(verdict, mal, tot)]
        if rep != 0:                  parts.append("rep={}".format(rep))
        if vt_result.get("country"):  parts.append("pays={}".format(vt_result["country"]))
        if vt_result.get("file_name"):parts.append("fichier={}".format(vt_result["file_name"]))
        return ", ".join(parts) + ")"

    @classmethod
    def enrich_observables(cls, result: dict) -> dict:
        vt_results = {}
        if not cfg.VT_ENABLED or not cfg.VT_APIKEY:
            return vt_results
        for field in ("src_ip", "src", "dest_ip", "dest"):
            ip = str(result.get(field, "")).strip()
            if ip and _is_valid_public_ip(ip) and ip not in vt_results:
                vt = cls.check_ip(ip)
                if vt: vt_results[ip] = vt
                time.sleep(0.3)
        for field in ("file_hash", "hash", "md5", "sha1", "sha256", "FileHash"):
            fhash = str(result.get(field, "")).strip()
            if fhash and len(fhash) in (32, 40, 64) and fhash not in vt_results:
                vt = cls.check_hash(fhash)
                if vt: vt_results[fhash] = vt
                time.sleep(0.3)
                break
        for field in ("domain", "dest_domain", "query", "QueryName"):
            dom = str(result.get(field, "")).strip()
            if dom and "." in dom and not _is_ip(dom) and dom not in vt_results:
                vt = cls.check_domain(dom)
                if vt: vt_results[dom] = vt
                time.sleep(0.3)
                break
        url = str(result.get("url", result.get("uri", ""))).strip()
        if url and url.startswith(("http://", "https://")) and url not in vt_results:
            vt = cls.check_url(url)
            if vt: vt_results[url] = vt
        return vt_results


def _is_ip(s: str) -> bool:
    try:
        import ipaddress; ipaddress.ip_address(s.strip()); return True
    except ValueError: return False

def _is_valid_public_ip(ip: str) -> bool:
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip.strip())
        return not (addr.is_private or addr.is_loopback
                    or addr.is_link_local or addr.is_multicast)
    except ValueError: return False


# ══════════════════════════════════════════════════════════════════
# PARSING SPLUNK — 4 formats supportés
# ══════════════════════════════════════════════════════════════════
class SplunkParser:
    IOC_FIELDS = {
        "src_ip","dest_ip","src","dest","user","User","username",
        "host","source","index","process_name","Image","file_hash",
        "hash","md5","sha1","sha256","domain","dest_domain","query",
        "url","uri","_time","CommandLine","ParentImage","EventCode",
    }

    @classmethod
    def parse(cls, data: dict) -> tuple:
        name = (data.get("search_name") or data.get("name")
                or data.get("alert_name") or "Alerte Splunk")
        sev  = (data.get("severity") or data.get("alert.severity")
                or data.get("urgency") or "medium")
        r = data.get("result")
        if isinstance(r, dict) and r:
            return name, sev, r
        rl = data.get("results")
        if isinstance(rl, list) and rl:
            return name, sev, rl[0]
        flat = {k: v for k, v in data.items() if k in cls.IOC_FIELDS}
        if flat:
            return name, sev, flat
        if isinstance(r, str):
            try:
                parsed = json.loads(r)
                if isinstance(parsed, dict): return name, sev, parsed
            except Exception: pass
        minimal = {
            "host":   data.get("host",   data.get("server_host", "N/A")),
            "source": data.get("source", "Splunk Webhook"),
            "_time":  data.get("_time",  datetime.utcnow().isoformat()),
        }
        return name, sev, minimal


# ══════════════════════════════════════════════════════════════════
# ENRICHISSEMENT
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
        src = result.get("source", "").lower()
        idx = result.get("index",  "").lower()
        if "windows" in idx or "winevent" in src:
            tags.append("windows")
        elif "linux" in idx or "auth.log" in src or "syslog" in src:
            tags.append("linux")
        ec = str(result.get("EventCode", result.get("event_code", "")))
        if ec: tags.append("ec-{}".format(ec))
        for ioc, vt in vt_results.items():
            if VirusTotalClient.is_malicious(vt):
                if "vt-malicious" not in tags: tags.append("vt-malicious")
            elif vt.get("suspicious", 0) > 0:
                if "vt-suspicious" not in tags: tags.append("vt-suspicious")
        return list(dict.fromkeys(tags))

    @staticmethod
    def extract_observables(result: dict, vt_results: dict) -> list:
        artifacts = []

        def add(dtype, value, msg, ioc=False, tags=None):
            v  = str(value).strip()
            if v and v.lower() not in ("-", "n/a", "", "none", "null", "unknown"):
                vt = vt_results.get(v, {})
                if vt:
                    msg  = "{} | {}".format(msg, VirusTotalClient.format_summary(vt))
                    if VirusTotalClient.is_malicious(vt): ioc = True
                artifacts.append(AlertArtifact(
                    dataType=dtype, data=v, message=msg,
                    tags=(tags or []) + ["splunk"] +
                         (["vt-malicious"] if vt and VirusTotalClient.is_malicious(vt) else []),
                    ioc=ioc,
                ))

        for f in ("src_ip", "src", "SourceIp"):
            v = result.get(f, "")
            if v: add("ip", v, "IP source (Splunk)", ioc=True, tags=["src_ip"]); break
        for f in ("dest_ip", "dest", "DestinationIp"):
            v = result.get(f, "")
            if v: add("ip", v, "IP destination (Splunk)", tags=["dest_ip"]); break
        for f in ("user", "User", "username", "AccountName"):
            v = result.get(f, "")
            if v: add("other", v, "Utilisateur impliqué", tags=["user"]); break
        for f in ("file_hash", "hash", "md5", "sha1", "sha256", "FileHash"):
            v = result.get(f, "")
            if v and len(v) in (32, 40, 64):
                add("hash", v, "Hash fichier suspect", ioc=True, tags=["hash"]); break
        for f in ("domain", "dest_domain", "query", "QueryName"):
            v = result.get(f, "")
            if v and "." in str(v) and not _is_ip(str(v)):
                add("domain", v, "Domaine suspect", ioc=True, tags=["domain"]); break
        for f in ("url", "uri"):
            v = result.get(f, "")
            if v and str(v).startswith(("http://", "https://")):
                add("url", v, "URL suspecte", ioc=True, tags=["url"]); break
        cmd = result.get("CommandLine", result.get("command_line", ""))
        if cmd and len(str(cmd)) > 10:
            add("other", str(cmd)[:500], "Ligne de commande", tags=["cmdline"])
        if not artifacts:
            h = result.get("host", "")
            if h: add("other", h, "Hôte source", tags=["host"])
        return artifacts

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
            lines += ["", "### 🦠 Analyse VirusTotal"]
            for ioc, vt in vt_results.items():
                mal = vt.get("malicious",  0)
                sus = vt.get("suspicious", 0)
                tot = vt.get("total",      0)
                rep = vt.get("reputation", 0)
                if mal >= cfg.VT_MIN_DETECTIONS: verdict = "🔴 **MALVEILLANT**"
                elif sus > 0:                    verdict = "🟡 **Suspect**"
                elif tot > 0:                    verdict = "🟢 Propre"
                else:                            verdict = "⚪ Inconnu"
                lines.append("| `{}` | {} ({}/{} détect., rep={}) |".format(
                    ioc[:50], verdict, mal, tot, rep))
                if vt.get("country"):   lines.append("| Pays | `{}` |".format(vt["country"]))
                if vt.get("as_owner"): lines.append("| AS | `{}` |".format(vt["as_owner"]))
                if vt.get("file_name"):lines.append("| Fichier | `{}` ({}) |".format(
                    vt["file_name"], vt.get("file_type", "")))
        lines += [
            "", "### 📦 Données brutes Splunk", "```json",
            json.dumps(result, indent=2, ensure_ascii=False, default=str)[:3000],
            "```", "",
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
        if not cfg.TELEGRAM_ENABLED or not cfg.TELEGRAM_TOKEN or not cfg.TELEGRAM_CHAT_ID:
            return False
        try:
            payload = {"chat_id": cfg.TELEGRAM_CHAT_ID, "text": message[:4096], "parse_mode": "HTML"}
            if keyboard: payload["reply_markup"] = json.dumps(keyboard)
            r = requests.post(
                "https://api.telegram.org/bot{}/sendMessage".format(cfg.TELEGRAM_TOKEN),
                json=payload, timeout=10)
            if r.status_code == 200:
                log.info("SOC-A — Telegram OK"); return True
            log.warning("Telegram erreur %d: %s", r.status_code, r.text[:200]); return False
        except Exception as e:
            log.error("Telegram exception: %s", e); return False

    @classmethod
    def _send_telegram_async(cls, message: str, keyboard: dict = None):
        threading.Thread(target=cls._send_telegram_raw, args=(message, keyboard), daemon=True).start()

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
                if body_html: msg.attach(MIMEText(body_html, "html", "utf-8"))
                with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
                    s.login(cfg.GMAIL_USER, cfg.GMAIL_PASS)
                    s.sendmail(cfg.GMAIL_USER, cfg.GMAIL_TO, msg.as_string())
                log.info("SOC-A — Gmail OK: %s", subject)
            except Exception as e:
                log.error("Gmail: %s", e)
        threading.Thread(target=_send, daemon=True).start()

    @classmethod
    def send_alert(cls, name: str, sev: int, result: dict,
                   alert_id: str = None, vt_results: dict = None):
        if sev < cfg.NOTIFY_MIN_SEV: return
        vt_results  = vt_results or {}
        sev_emoji   = SEVERITY_EMOJI.get(sev, "⚪")
        sev_label   = SEVERITY_LABEL.get(sev, "?")
        now         = result.get("_time", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
        vt_lines    = []
        for ioc, vt in vt_results.items():
            if vt:
                mal = vt.get("malicious", 0); tot = vt.get("total", 0)
                ico = "🔴" if VirusTotalClient.is_malicious(vt) else ("🟡" if vt.get("suspicious",0)>0 else "🟢")
                vt_lines.append("{} <code>{}</code> {}/{}".format(ico, ioc[:30], mal, tot))
        tg = [
            "{} <b>ALERTE SOC — {}</b>".format(sev_emoji, sev_label.upper()), "",
            "<b>Recherche :</b> {}".format(name),
            "<b>Hôte      :</b> <code>{}</code>".format(result.get("host", "N/A")),
            "<b>IP src    :</b> <code>{}</code>".format(result.get("src_ip", result.get("src", "N/A"))),
            "<b>IP dst    :</b> <code>{}</code>".format(result.get("dest_ip", result.get("dest", "N/A"))),
            "<b>User      :</b> <code>{}</code>".format(result.get("user", "N/A")),
            "<b>Heure     :</b> {}".format(now),
        ]
        if vt_lines: tg += ["", "<b>🦠 VirusTotal :</b>"] + vt_lines
        tg += ["", "<i>SOC Pipeline Service A v7.0.0</i>"]
        kbd = {"inline_keyboard": []}
        if alert_id:
            kbd["inline_keyboard"].append([{
                "text": "🔍 Voir dans TheHive",
                "url":  "{}/alerts/{}".format(cfg.THEHIVE_URL, alert_id),
            }])
        cls._send_telegram_async("\n".join(tg), kbd if kbd["inline_keyboard"] else None)
        cls._send_gmail_async(
            "[SOC {}] {}".format(sev_label.upper(), name),
            "\n".join(tg).replace("<b>","").replace("</b>","")
                         .replace("<i>","").replace("</i>","")
                         .replace("<code>","").replace("</code>",""),
        )


# ══════════════════════════════════════════════════════════════════
# THEHIVE SERVICE
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
    thehive_ok = False
    try:
        r = thehive.find_alerts(query={}, range="0-1")
        thehive_ok = r.status_code == 200
    except Exception as e:
        log.error("TheHive inaccessible: %s", e)

    vt_ok = False
    if cfg.VT_ENABLED and cfg.VT_APIKEY:
        try:
            r = requests.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
                             headers={"x-apikey": cfg.VT_APIKEY}, timeout=10)
            vt_ok = r.status_code == 200
        except Exception: pass

    telegram_ok = None
    if cfg.TELEGRAM_ENABLED:
        if not cfg.TELEGRAM_TOKEN:
            print("[TELEGRAM] ⚠️  TELEGRAM_TOKEN vide dans .env !"); telegram_ok = False
        elif not cfg.TELEGRAM_CHAT_ID:
            print("[TELEGRAM] ⚠️  TELEGRAM_CHAT_ID vide dans .env !"); telegram_ok = False
        else:
            try:
                r = requests.get("https://api.telegram.org/bot{}/getMe".format(cfg.TELEGRAM_TOKEN), timeout=8)
                if r.status_code == 200:
                    bot = r.json().get("result", {})
                    telegram_ok = True
                    print("[TELEGRAM] ✅ Bot @{}".format(bot.get("username","?")))
                    Notifier._send_telegram_raw(
                        "🚀 <b>SOC Pipeline — Service A démarré</b>\n"
                        "⏰ {}\n\n"
                        "{} TheHive : {}\n"
                        "{} VirusTotal : {}\n"
                        "📡 Webhook : :5000/alert".format(
                            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "✅" if thehive_ok else "❌", cfg.THEHIVE_URL,
                            "✅" if vt_ok else "⚠️",
                            "Actif" if vt_ok else "Vérifier VT_APIKEY"))
                else:
                    telegram_ok = False
            except Exception as e:
                telegram_ok = False
                print("[TELEGRAM] ❌ Erreur : {}".format(e))

    gmail_ok = None
    if cfg.GMAIL_ENABLED and cfg.GMAIL_USER and cfg.GMAIL_PASS:
        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
                s.login(cfg.GMAIL_USER, cfg.GMAIL_PASS)
            gmail_ok = True
        except Exception: gmail_ok = False

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
        "" if cfg.VT_APIKEY else " (VT_APIKEY non défini)"))
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
    global _debug_payloads
    try:
        raw  = request.get_data(as_text=True)
        data = request.get_json(force=True, silent=True)
        _debug_payloads.append({"ts": datetime.utcnow().isoformat()+"Z",
                                 "ip": request.remote_addr, "raw": raw[:800]})
        if len(_debug_payloads) > 50: _debug_payloads = _debug_payloads[-50:]
        _stats["received"] += 1
        if not data:
            _stats["errors"] += 1
            return jsonify({"status": "error", "reason": "payload non-JSON ou vide"}), 400

        name, sev_str, result = SplunkParser.parse(data)
        sev_int    = AlertEnricher.normalize_severity(sev_str)
        source_ref = AlertEnricher.generate_source_ref(name, result)

        log.info("SOC-A — Alerte: '%s' sev=%d host=%s ref=%s",
                 name, sev_int, result.get("host","N/A"), source_ref)

        if is_rate_limited(source_ref):
            log.info("SOC-A — Doublon ignoré: ref=%s", source_ref)
            return jsonify({"status": "rate_limited", "source_ref": source_ref}), 200

        vt_results = {}
        if cfg.VT_ENABLED and cfg.VT_APIKEY:
            try:
                vt_results     = VirusTotalClient.enrich_observables(result)
                _stats["vt_analyses"] += len(vt_results)
                vt_malicious   = sum(1 for v in vt_results.values()
                                     if VirusTotalClient.is_malicious(v))
                if vt_malicious:
                    _stats["vt_malicious"] += vt_malicious
                    if sev_int < 3: sev_int = 3
            except Exception as e:
                log.error("VT enrichissement erreur: %s", e)

        tags      = AlertEnricher.extract_tags(name, result, vt_results)
        artifacts = AlertEnricher.extract_observables(result, vt_results)
        desc      = AlertEnricher.build_description(name, result, vt_results)

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
            log.info("SOC-A — Alerte TheHive créée: id=%s ref=%s sev=%d art=%d vt=%d",
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
                    "analyzed":  len(vt_results),
                    "malicious": sum(1 for v in vt_results.values()
                                     if VirusTotalClient.is_malicious(v)),
                },
            }), 201
        elif response.status_code in (400, 409):
            _stats["duplicates"] += 1
            log.info("SOC-A — Doublon ignoré: ref=%s", source_ref)
            return jsonify({"status": "duplicate", "source_ref": source_ref}), 200
        else:
            _stats["errors"] += 1
            log.error("TheHive HTTP %d: %s", response.status_code, response.text[:300])
            return jsonify({"status": "error", "http_code": response.status_code}), 500

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
    except Exception: pass
    return jsonify({
        "status":    "healthy" if thehive_ok else "degraded",
        "service":   "soc-service-a",
        "version":   "7.0.0",
        "thehive":   thehive_ok,
        "vt":        cfg.VT_ENABLED and bool(cfg.VT_APIKEY),
        "telegram":  cfg.TELEGRAM_ENABLED,
        "stats":     dict(_stats),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }), 200 if thehive_ok else 503


@app.route("/vt-test", methods=["GET"])
def vt_test():
    if not cfg.VT_ENABLED:
        return jsonify({"status": "disabled", "fix": "VT_ENABLED=true dans .env"}), 200
    if not cfg.VT_APIKEY:
        return jsonify({"status": "no_key", "fix": "Ajouter VT_APIKEY dans .env"}), 400
    vt = VirusTotalClient.check_ip("8.8.8.8")
    if vt:
        return jsonify({"status": "ok", "message": "VirusTotal fonctionne !", "result": vt}), 200
    return jsonify({"status": "error", "fix": "Vérifier VT_APIKEY"}), 500


@app.route("/telegram-test", methods=["GET"])
def telegram_test():
    if not cfg.TELEGRAM_ENABLED:
        return jsonify({"status": "disabled", "fix": "TELEGRAM_ENABLED=true dans .env"}), 200
    if not cfg.TELEGRAM_TOKEN:
        return jsonify({"status": "no_token", "fix": "TELEGRAM_TOKEN vide dans .env"}), 400
    if not cfg.TELEGRAM_CHAT_ID:
        return jsonify({"status": "no_chat_id", "fix": "TELEGRAM_CHAT_ID vide dans .env"}), 400
    msg = ("🧪 <b>TEST SOC Pipeline — Service A v7.0.0</b>\n\n"
           "✅ Telegram <b>fonctionne !</b>\n⏰ {}\n\n"
           "<b>TheHive :</b> {}\n<b>VT :</b> {}").format(
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        cfg.THEHIVE_URL,
        "Actif ✅" if (cfg.VT_ENABLED and cfg.VT_APIKEY) else "Non configuré ⚠️")
    ok = Notifier._send_telegram_raw(msg)
    return jsonify({"status": "success" if ok else "send_failed"}), 200 if ok else 400


@app.route("/test", methods=["GET", "POST"])
def test_alert():
    fake = {
        "search_name": "TEST — SOC Pipeline v7.0.0",
        "severity":    "high",
        "result": {
            "host":         "srv-linux-01",
            "source":       "/var/log/auth.log",
            "index":        "linux_logs",
            "src_ip":       "185.220.101.50",
            "dest_ip":      "192.168.1.10",
            "user":         "root",
            "process_name": "sshd",
            "_time":        datetime.utcnow().isoformat(),
            "count":        "121",
            "message":      "Failed password for root from 185.220.101.50 port 22 ssh2",
        },
    }
    try:
        r = requests.post("http://127.0.0.1:{}/alert".format(cfg.LISTEN_PORT),
                          json=fake, timeout=30)
        return jsonify({"status": "test_sent", "response": r.json()}), 200
    except Exception as e:
        return jsonify({"status": "error", "detail": str(e)}), 500


@app.route("/debug", methods=["GET"])
def debug():
    return jsonify({"total_received": _stats.get("received", 0),
                    "last_payloads":  _debug_payloads[-10:],
                    "stats":          dict(_stats)}), 200


@app.route("/stats", methods=["GET"])
def stats():
    return jsonify({"stats": dict(_stats),
                    "timestamp": datetime.utcnow().isoformat() + "Z"}), 200


# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    threading.Thread(target=startup_check, daemon=True).start()
    app.run(host=cfg.LISTEN_HOST, port=cfg.LISTEN_PORT, debug=False, use_reloader=False)
