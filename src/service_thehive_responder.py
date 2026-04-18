#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  SOC Automation Pipeline — Service B                        ║
║  TheHive Responder — Full Auto v10.0.0                      ║
╚══════════════════════════════════════════════════════════════╝

Flux 100% automatique :
  1. Poll TheHive → alertes New/Updated
  2. Promotion alerte → Cas TheHive
  3. Ajout Observables au cas (IP, hash, domain)
  4. VirusTotal → commentaire + tag dans le cas
  5. MISP lookup → commentaire si hit / push si malveillant
  6. Blocage IP firewall (Windows netsh / Linux iptables)
  7. Cortex → lancement analyseurs via TheHive → résultats en commentaires
  8. Rapport récapitulatif dans le cas
  9. Telegram à chaque étape

Corrections v10 vs v8 :
  - TheHive v5 : _id (underscore) et non id
  - add_tag() via API v1 directe
  - update_status() via API v1 directe
  - Cortex lancé VIA TheHive (observable → analyseur)
  - Résultats Cortex en thread background (non bloquant)
"""

import os, json, logging, time, subprocess, re, sys, warnings, threading, smtplib, ipaddress
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

warnings.filterwarnings("ignore", category=DeprecationWarning)


# ──────────────────────────────────────────────────────────────────
# CHARGEMENT .env
# ──────────────────────────────────────────────────────────────────
def _load_env():
    for p in [Path(__file__).parent/".env", Path.cwd()/".env", Path.home()/".env"]:
        if p.exists():
            count = 0
            with open(p, encoding="utf-8") as f:
                for raw in f:
                    line = raw.strip()
                    if not line or line.startswith("#") or "=" not in line: continue
                    k, _, v = line.partition("=")
                    os.environ[k.strip()] = v.strip().strip('"').strip("'")
                    count += 1
            print("[ENV] {} ({} vars)".format(p, count))
            return str(p)
    return None

_load_env()

import requests
from thehive4py.api import TheHiveApi
from thehive4py.models import CaseTaskLog


# ──────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────
class Config:
    THEHIVE_URL          = os.getenv("THEHIVE_URL",          "http://_IP_:9000")
    THEHIVE_APIKEY       = os.getenv("THEHIVE_APIKEY",       "")
    CORTEX_URL           = os.getenv("CORTEX_URL",           "http://_IP_:9001")
    CORTEX_APIKEY        = os.getenv("CORTEX_APIKEY",        "")
    MISP_URL             = os.getenv("MISP_URL",             "https://_IP_")
    MISP_APIKEY          = os.getenv("MISP_APIKEY",          "")
    MISP_ENABLED         = os.getenv("MISP_ENABLED",         "true").lower() == "true"
    VT_ENABLED           = os.getenv("VT_ENABLED",           "true").lower() == "true"
    VT_APIKEY            = os.getenv("VT_APIKEY",            "")
    VT_TIMEOUT           = int(os.getenv("VT_TIMEOUT",       "15").split()[0])
    VT_MIN_DETECTIONS    = int(os.getenv("VT_MIN_DETECTIONS","2").split()[0])
    POLL_INTERVAL_SEC    = int(os.getenv("POLL_INTERVAL",    "20").split()[0])
    STATE_FILE           = os.getenv("STATE_FILE",           "responder_state.json")
    BLACKLIST_FILE       = os.getenv("BLACKLIST_FILE",       "ip_blacklist.txt")
    LOG_FILE             = os.getenv("LOG_FILE_B",           "service_b.log")
    LOG_LEVEL            = os.getenv("LOG_LEVEL",            "INFO")
    ACTIVE_RESPONSE      = os.getenv("ACTIVE_RESPONSE",      "false").lower() == "true"
    BLOCK_DURATION_MIN   = int(os.getenv("BLOCK_DURATION_MIN","10").split()[0])
    BLOCK_ON_BRUTEFORCE  = os.getenv("BLOCK_ON_BRUTEFORCE",  "true").lower() == "true"
    BRUTE_FORCE_TAGS     = ["brute_force","ssh","failed_auth","brute-force","bruteforce"]
    BRUTE_FORCE_KW       = ["brute","ssh","failed","auth","force","login","invalid","unauthorized"]
    TELEGRAM_ENABLED     = os.getenv("TELEGRAM_ENABLED",     "false").lower() == "true"
    TELEGRAM_TOKEN       = os.getenv("TELEGRAM_TOKEN",       "")
    TELEGRAM_CHAT_ID     = os.getenv("TELEGRAM_CHAT_ID",     "")
    GMAIL_ENABLED        = os.getenv("GMAIL_ENABLED",        "false").lower() == "true"
    GMAIL_USER           = os.getenv("GMAIL_USER",           "")
    GMAIL_PASS           = os.getenv("GMAIL_PASS",           "")
    GMAIL_TO             = os.getenv("GMAIL_TO",             "")
    CORTEX_JOB_TIMEOUT   = int(os.getenv("CORTEX_JOB_TIMEOUT","180").split()[0])

cfg = Config()


# ──────────────────────────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────────────────────────
def _setup_log():
    logger = logging.getLogger("SOC-B")
    logger.setLevel(getattr(logging, cfg.LOG_LEVEL, logging.INFO))
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
    try:
        fh = RotatingFileHandler(cfg.LOG_FILE, maxBytes=10_000_000, backupCount=5, encoding="utf-8")
        fh.setFormatter(fmt); logger.addHandler(fh)
    except Exception: pass
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt); logger.addHandler(ch)
    return logger

log = _setup_log()


def _get_id(obj: dict) -> str:
    """TheHive v5 = '_id', v4 = 'id'. Compatible les deux."""
    return (obj.get("_id") or obj.get("id") or "").strip() if obj else ""


# ──────────────────────────────────────────────────────────────────
# TELEGRAM
# ──────────────────────────────────────────────────────────────────
class TG:
    @staticmethod
    def send(msg: str):
        if not cfg.TELEGRAM_ENABLED or not cfg.TELEGRAM_TOKEN or not cfg.TELEGRAM_CHAT_ID: return
        def _s():
            try:
                requests.post(
                    "https://api.telegram.org/bot{}/sendMessage".format(cfg.TELEGRAM_TOKEN),
                    json={"chat_id": cfg.TELEGRAM_CHAT_ID, "text": msg[:4096], "parse_mode": "HTML"},
                    timeout=10)
            except Exception as e: log.error("Telegram: %s", e)
        threading.Thread(target=_s, daemon=True).start()


# ──────────────────────────────────────────────────────────────────
# THEHIVE — toutes les opérations
# ──────────────────────────────────────────────────────────────────
class TH:
    thehive = TheHiveApi(cfg.THEHIVE_URL, cfg.THEHIVE_APIKEY)

    @staticmethod
    def _hdr():
        return {"Authorization": "Bearer {}".format(cfg.THEHIVE_APIKEY),
                "Content-Type": "application/json", "Accept": "application/json"}

    @classmethod
    def _post(cls, path, data, retries=3):
        for i in range(1, retries+1):
            try:
                r = requests.post("{}{}".format(cfg.THEHIVE_URL, path),
                                  headers=cls._hdr(), json=data, timeout=20)
                if r.status_code in (200, 201): return r.json()
                log.warning("POST %s HTTP %d [%d/%d]", path, r.status_code, i, retries)
            except Exception as e: log.warning("POST %s [%d/%d]: %s", path, i, retries, e)
            if i < retries: time.sleep(2*i)
        return None

    @classmethod
    def _get(cls, path):
        try:
            r = requests.get("{}{}".format(cfg.THEHIVE_URL, path),
                             headers=cls._hdr(), timeout=15)
            if r.status_code == 200: return r.json()
        except Exception as e: log.error("GET %s: %s", path, e)
        return None

    @classmethod
    def _patch(cls, path, data):
        try:
            requests.patch("{}{}".format(cfg.THEHIVE_URL, path),
                           headers=cls._hdr(), json=data, timeout=10)
        except Exception as e: log.error("PATCH %s: %s", path, e)

    @classmethod
    def fetch_new_alerts(cls):
        r = cls._post("/api/v1/query?name=list-alerts", {"query": [
            {"_name": "listAlert"},
            {"_name": "filter", "_in": {"_field": "status", "_values": ["New", "Updated"]}},
            {"_name": "sort", "_fields": [{"_createdAt": "desc"}]},
            {"_name": "page", "from": 0, "to": 200}]})
        if r and isinstance(r, list): return r
        try:
            r2 = cls.thehive.find_alerts(
                query={"_in": {"status": ["New", "Updated"]}},
                sort=["-createdAt"], range="0-200")
            if r2.status_code == 200: return r2.json()
        except Exception as e: log.error("fetch_alerts: %s", e)
        return []

    @classmethod
    def promote(cls, alert_id, title, alert_data):
        # v5 natif
        c = cls._post("/api/v1/alert/{}/case".format(alert_id), {})
        if c and _get_id(c):
            log.info("Promotion v5 OK: %s → cas #%s", alert_id, c.get("number","?"))
            return c
        # v4
        try:
            r = cls.thehive.promote_alert_to_case(alert_id)
            if r and r.status_code in (200, 201): return r.json()
        except Exception as e: log.warning("Promote v4: %s", e)
        # Manuel
        c = cls._post("/api/v1/case", {
            "title":       title,
            "description": alert_data.get("description", "Alert: " + alert_id),
            "severity":    alert_data.get("severity", 2),
            "tags":        list(set(alert_data.get("tags", []) + ["auto-promoted", "from-splunk"])),
            "tlp": 2, "pap": 2, "status": "Open"})
        if c and _get_id(c):
            try:
                requests.post("{}/api/v1/alert/{}/merge/{}".format(
                    cfg.THEHIVE_URL, alert_id, _get_id(c)),
                    headers=cls._hdr(), timeout=10)
            except Exception: pass
            return c
        return None

    @classmethod
    def get_alert_observables(cls, alert_id, alert_data):
        r = cls._get("/api/v1/alert/{}/observable".format(alert_id))
        if r and isinstance(r, list): return r
        return alert_data.get("artifacts", alert_data.get("observables", []))

    @classmethod
    def add_observable_to_case(cls, case_id: str, datatype: str, data: str,
                                message: str = "", tags: list = None) -> str:
        """Ajoute un observable au cas TheHive. Retourne l'ID créé."""
        payload = {
            "dataType": datatype, "data": data,
            "message":  message or "Auto-ajouté par SOC Pipeline v10",
            "tlp": 2, "pap": 2, "ioc": True,
            "tags": tags or ["auto-added"]
        }
        r = cls._post("/api/v1/case/{}/observable".format(case_id), payload)
        if r:
            if isinstance(r, list) and r:   obs_id = _get_id(r[0])
            elif isinstance(r, dict):        obs_id = _get_id(r)
            else:                            obs_id = ""
            if obs_id:
                log.info("Observable ajouté: [%s] %s → cas %s", datatype, data[:40], case_id)
                return obs_id
        return ""

    @classmethod
    def run_cortex_on_observable(cls, case_id: str, observable_id: str,
                                  analyzer_id: str, analyzer_name: str) -> str:
        """Lance un analyseur Cortex sur un observable via TheHive."""
        r = cls._post(
            "/api/v1/case/{}/observable/{}/analyzer/{}".format(
                case_id, observable_id, analyzer_id), {})
        if r:
            job_id = r.get("cortexJobId", r.get("id", ""))
            if job_id:
                log.info("Cortex job lancé via TheHive: %s (job=%s)", analyzer_name, job_id)
                return job_id
        # Fallback
        r2 = cls._post("/api/connector/cortex/job", {
            "analyzerId": analyzer_id,
            "artifactId": observable_id,
            "cortexId":   "local",
        })
        if r2:
            job_id = r2.get("cortexJobId", r2.get("id", ""))
            if job_id: return job_id
        log.warning("Impossible de lancer %s sur obs %s", analyzer_name, observable_id[:8])
        return ""

    @classmethod
    def get_cortex_job_result(cls, job_id: str, timeout_sec: int = 180) -> dict:
        """Attend le résultat d'un job Cortex via TheHive."""
        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            try:
                r = requests.get(
                    "{}/api/connector/cortex/job/{}".format(cfg.THEHIVE_URL, job_id),
                    headers=cls._hdr(), timeout=10)
                if r.status_code == 200:
                    job    = r.json()
                    status = job.get("status", "")
                    if status == "Success":
                        taxos    = job.get("report",{}).get("summary",{}).get("taxonomies",[])
                        verdicts = ["{}/{}:{}".format(t.get("namespace",""),
                                    t.get("predicate",""), t.get("value","")) for t in taxos]
                        level    = max((t.get("level","info") for t in taxos),
                                       key=lambda x: ["info","safe","suspicious","malicious"
                                                      ].index(x) if x in
                                       ["info","safe","suspicious","malicious"] else 0,
                                       default="info")
                        return {"status": "success", "verdicts": verdicts, "level": level}
                    elif status in ("Failure", "Deleted"):
                        return {"status": "failure",
                                "error": job.get("report",{}).get("errorMessage", status)}
            except Exception as e: log.error("Cortex job wait %s: %s", job_id, e); break
            time.sleep(5)
        return {"status": "timeout"}

    @classmethod
    def add_comment(cls, case_id, msg):
        r = cls._post("/api/v1/case/{}/comment".format(case_id), {"message": msg})
        if not r:
            try: cls.thehive.create_case_task_log(case_id, CaseTaskLog(message=msg))
            except Exception as e: log.error("comment: %s", e)

    @classmethod
    def add_tag(cls, case_id, tag):
        try:
            r = requests.get("{}/api/v1/case/{}".format(cfg.THEHIVE_URL, case_id),
                             headers=cls._hdr(), timeout=10)
            if r.status_code == 200:
                existing = r.json().get("tags", [])
                if tag not in existing:
                    requests.patch("{}/api/v1/case/{}".format(cfg.THEHIVE_URL, case_id),
                                   headers=cls._hdr(),
                                   json={"tags": existing + [tag]}, timeout=10)
        except Exception as e: log.error("add_tag: %s", e)

    @classmethod
    def update_status(cls, case_id, status):
        try:
            requests.patch("{}/api/v1/case/{}".format(cfg.THEHIVE_URL, case_id),
                           headers=cls._hdr(), json={"status": status}, timeout=10)
        except Exception as e: log.error("update_status: %s", e)

    @classmethod
    def mark_alert_inprogress(cls, alert_id):
        cls._patch("/api/v1/alert/{}".format(alert_id), {"status": "InProgress"})


# ──────────────────────────────────────────────────────────────────
# CORTEX — Chargement des analyseurs disponibles
# ──────────────────────────────────────────────────────────────────
class Cortex:
    PRIORITY = {
        "ip":     ["AbuseIPDB","VirusTotal_GetReport","MaxMind_GeoIP","Shodan_Host","OTXQuery"],
        "hash":   ["VirusTotal_GetReport","Cuckoo","OTXQuery"],
        "domain": ["VirusTotal_GetReport","DomainTools","OTXQuery"],
        "url":    ["VirusTotal_GetReport","URLScan_io"],
    }

    def __init__(self):
        self.analyzers = {}    # {name: id}
        self.by_type   = {}    # {datatype: [(name, id)]}
        self._load()

    def _hdr(self):
        return {"Authorization": "Bearer {}".format(cfg.CORTEX_APIKEY),
                "Content-Type": "application/json", "Accept": "application/json"}

    def _load(self):
        if not cfg.CORTEX_APIKEY:
            log.warning("Cortex: CORTEX_APIKEY manquante"); return
        try:
            r = requests.get("{}/api/analyzer".format(cfg.CORTEX_URL),
                             headers=self._hdr(), timeout=10)
            if r.status_code != 200:
                log.warning("Cortex: HTTP %d", r.status_code); return
            for a in r.json():
                name = a.get("name",""); aid = a.get("id","")
                self.analyzers[name] = aid
                for dt in a.get("dataTypeList",[]):
                    self.by_type.setdefault(dt, []).append((name, aid))
            log.info("Cortex: %d analyseurs — types: %s",
                     len(self.analyzers), list(self.by_type.keys()))
        except Exception as e: log.warning("Cortex load: %s", e)

    def get_analyzers_for(self, datatype: str) -> list:
        available      = self.by_type.get(datatype, [])
        if not available: return []
        priority_names = self.PRIORITY.get(datatype, [])
        def rank(item):
            for base in priority_names:
                if item[0].startswith(base): return priority_names.index(base)
            return 999
        return sorted(available, key=rank)[:5]

cortex = Cortex()


# ──────────────────────────────────────────────────────────────────
# VIRUSTOTAL
# ──────────────────────────────────────────────────────────────────
class VT:
    BASE = "https://www.virustotal.com/api/v3"

    @classmethod
    def _get(cls, ep):
        if not cfg.VT_ENABLED or not cfg.VT_APIKEY: return {}
        try:
            r = requests.get("{}/{}".format(cls.BASE, ep),
                             headers={"x-apikey": cfg.VT_APIKEY}, timeout=cfg.VT_TIMEOUT)
            if r.status_code == 200: return r.json()
            if r.status_code == 404: return {}
            if r.status_code == 429: log.warning("VT rate limit, attente 60s"); time.sleep(60)
        except Exception as e: log.error("VT: %s", e)
        return {}

    @classmethod
    def _parse(cls, d):
        a = d.get("data",{}).get("attributes",{})
        s = a.get("last_analysis_stats",{})
        return {"malicious": s.get("malicious",0), "suspicious": s.get("suspicious",0),
                "harmless":  s.get("harmless",0),  "undetected": s.get("undetected",0),
                "total":     sum(s.values()) if s else 0,
                "reputation":a.get("reputation",0), "country": a.get("country",""),
                "as_owner":  a.get("as_owner","")}

    @classmethod
    def check_ip(cls, ip):
        d = cls._get("ip_addresses/{}".format(ip))
        if not d: return {}
        r = cls._parse(d); r.update({"type":"ip","value":ip})
        log.info("VT IP %s: mal=%d susp=%d total=%d rep=%d",
                 ip,r["malicious"],r["suspicious"],r["total"],r["reputation"])
        return r

    @classmethod
    def check_hash(cls, h):
        d = cls._get("files/{}".format(h))
        if not d: return {}
        r = cls._parse(d)
        r.update({"type":"hash","value":h,
                  "file_name":d.get("data",{}).get("attributes",{}).get("meaningful_name","")})
        log.info("VT hash %s: mal=%d total=%d", h[:16], r["malicious"], r["total"])
        return r

    @classmethod
    def check_domain(cls, dom):
        d = cls._get("domains/{}".format(dom))
        if not d: return {}
        r = cls._parse(d); r.update({"type":"domain","value":dom}); return r

    @classmethod
    def is_malicious(cls, r):
        if not r: return False
        return (r.get("malicious",0) >= cfg.VT_MIN_DETECTIONS or
                r.get("suspicious",0) >= cfg.VT_MIN_DETECTIONS * 2 or
                r.get("reputation",0) <= -10)

    @classmethod
    def verdict(cls, r):
        if not r: return "⚪ Non indexé (IP privée)"
        m,s,t,rep = r.get("malicious",0),r.get("suspicious",0),r.get("total",0),r.get("reputation",0)
        if cls.is_malicious(r): return "🔴 MALVEILLANT ({}/{} rep={})".format(m,t,rep)
        if s>0:                 return "🟡 Suspect ({}/{} rep={})".format(s,t,rep)
        if t>0:                 return "🟢 Propre (0/{} rep={})".format(t,rep)
        return "⚪ Non indexé"

    @classmethod
    def summary_md(cls, r, target):
        if not r: return "⚪ {} — non indexé sur VirusTotal (IP privée)".format(target)
        return ("**VirusTotal** — `{}`\n- Verdict: {}\n- Détections: **{}/{}**\n"
                "- Réputation: {}\n- Pays: {} | AS: {}").format(
            target, cls.verdict(r),
            r.get("malicious",0), r.get("total",0),
            r.get("reputation",0), r.get("country","N/A"), r.get("as_owner","N/A"))


# ──────────────────────────────────────────────────────────────────
# MISP
# ──────────────────────────────────────────────────────────────────
class MISP:
    @staticmethod
    def _hdr():
        return {"Authorization": cfg.MISP_APIKEY,
                "Content-Type": "application/json", "Accept": "application/json"}

    @classmethod
    def _req(cls, path, data=None):
        try:
            fn = requests.post if data else requests.get
            kw = {"headers": cls._hdr(), "timeout": 8, "verify": False}
            if data: kw["json"] = data
            r = fn("{}{}".format(cfg.MISP_URL, path), **kw)
            return r.json() if r.status_code in (200,201) else None
        except Exception as e: log.error("MISP: %s", e); return None

    @classmethod
    def lookup(cls, val, itype):
        if not cfg.MISP_ENABLED or not cfg.MISP_APIKEY: return False
        try:
            r = cls._req("/attributes/restSearch", {"value": val, "type": itype, "limit": 1})
            if r and r.get("response",{}).get("Attribute",[]):
                log.info("MISP hit: %s", val); return True
        except Exception as e: log.error("MISP lookup: %s", e)
        return False

    @classmethod
    def push(cls, val, itype, info=""):
        if not cfg.MISP_ENABLED or not cfg.MISP_APIKEY: return False
        t = {"ip":"ip-dst","domain":"domain","hash":"md5","url":"url","other":"text"}
        try:
            r = cls._req("/events", {"Event": {
                "info":            "SOC Auto {}".format(info or val),
                "distribution":    0, "threat_level_id": 1, "analysis": 1,
                "Attribute": [{"type": t.get(itype,"text"), "category": "Network activity",
                               "value": val, "to_ids": True}]}})
            if r: log.info("MISP push OK: %s", val); return True
        except Exception as e: log.error("MISP push: %s", e)
        return False


# ──────────────────────────────────────────────────────────────────
# FIREWALL
# ──────────────────────────────────────────────────────────────────
class Firewall:
    @staticmethod
    def block(ip: str) -> bool:
        if sys.platform == "win32":
            ok = True
            for direction, suffix in [("in","IN"),("out","OUT")]:
                name = "SOC_BLOCK_{}_{}".format(ip.replace(".","_"), suffix)
                subprocess.run(
                    ["netsh","advfirewall","firewall","delete","rule","name={}".format(name)],
                    capture_output=True, timeout=10)
                r = subprocess.run([
                    "netsh","advfirewall","firewall","add","rule",
                    "name={}".format(name), "dir={}".format(direction),
                    "action=block", "remoteip={}".format(ip), "enable=yes", "profile=any"
                ], capture_output=True, timeout=10, text=True)
                if r.returncode != 0:
                    log.error("netsh %s: %s", suffix, r.stdout.strip()[:100]); ok = False
                else:
                    log.info("✅ Firewall %s bloquée (%s)", ip, suffix)
            return ok
        else:
            ok = True
            for cmd in [["iptables","-I","INPUT","1","-s",ip,"-j","DROP"],
                        ["iptables","-I","OUTPUT","1","-d",ip,"-j","DROP"]]:
                try:
                    r = subprocess.run(cmd, capture_output=True, timeout=10)
                    if r.returncode != 0:
                        log.error("iptables: %s", r.stderr.decode()[:80]); ok = False
                except FileNotFoundError:
                    log.error("iptables absent — apt install iptables"); return False
                except Exception as e: log.error("iptables: %s", e); ok = False
            return ok

    @staticmethod
    def unblock(ip: str):
        if sys.platform == "win32":
            for suffix in ["IN","OUT"]:
                try:
                    subprocess.run(["netsh","advfirewall","firewall","delete","rule",
                        "name=SOC_BLOCK_{}_{}".format(ip.replace(".","_"), suffix)],
                        capture_output=True, timeout=10)
                except Exception: pass
        else:
            for cmd in [["iptables","-D","INPUT","-s",ip,"-j","DROP"],
                        ["iptables","-D","OUTPUT","-d",ip,"-j","DROP"]]:
                try: subprocess.run(cmd, capture_output=True, timeout=10)
                except Exception: pass


# ──────────────────────────────────────────────────────────────────
# BLACKLIST MANAGER
# ──────────────────────────────────────────────────────────────────
class BlacklistManager:
    JSON_FILE = "ip_blacklist.json"

    def __init__(self):
        self._blocked = {}
        self._lock    = threading.Lock()
        self._check_admin()
        self._restore()

    def _check_admin(self):
        if sys.platform == "win32":
            try:
                import ctypes
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    log.warning("⚠️  Pas Administrateur Windows — relancer en Admin pour le vrai blocage")
                else:
                    log.info("✅ Windows Administrateur — blocage firewall actif")
            except Exception: pass
        elif os.geteuid() != 0:
            log.warning("⚠️  Pas root Linux — relancer avec sudo pour iptables")
        else:
            log.info("✅ Linux root — iptables actif")

    def _restore(self):
        p = Path(self.JSON_FILE)
        if not p.exists(): return
        try:
            with open(p) as f: data = json.load(f)
            now = datetime.now()
            for ip, info in data.items():
                ba        = datetime.fromisoformat(info["blocked_at"])
                remaining = cfg.BLOCK_DURATION_MIN - (now - ba).total_seconds() / 60
                if remaining > 0:
                    Firewall.block(ip)
                    t = threading.Timer(remaining * 60, self._expire, args=[ip])
                    t.daemon = True; t.start()
                    self._blocked[ip] = {"blocked_at":ba,"reason":info.get("reason","?"),"timer":t}
                    log.info("IP %s restaurée (%.1f min)", ip, remaining)
                else:
                    Firewall.unblock(ip)
        except Exception as e: log.error("Restore blacklist: %s", e)

    def _save(self):
        try:
            data = {ip:{"blocked_at":v["blocked_at"].isoformat(),"reason":v["reason"]}
                    for ip,v in self._blocked.items()}
            with open(self.JSON_FILE,"w") as f: json.dump(data, f, indent=2)
            with open(cfg.BLACKLIST_FILE,"w") as f:
                f.write("# IPs bloquées — SOC Pipeline v10.0.0\n\n")
                for ip, info in self._blocked.items():
                    exp = info["blocked_at"] + timedelta(minutes=cfg.BLOCK_DURATION_MIN)
                    f.write("{} | {} | {} | expire {}\n".format(
                        ip, info["blocked_at"].strftime("%Y-%m-%d %H:%M:%S"),
                        info["reason"], exp.strftime("%H:%M:%S")))
        except Exception as e: log.error("Save blacklist: %s", e)

    def _expire(self, ip):
        with self._lock:
            if ip not in self._blocked: return
            info = self._blocked.pop(ip)
            Firewall.unblock(ip); self._save()
        log.info("✅ %s débloquée auto (%d min)", ip, cfg.BLOCK_DURATION_MIN)
        TG.send("✅ <b>IP Débloquée — Timer</b>\nIP: <code>{}</code>\nDurée: {} min\nRaison: {}".format(
            ip, cfg.BLOCK_DURATION_MIN, info.get("reason","?")))

    def block(self, ip, reason="brute force") -> dict:
        with self._lock:
            if ip in self._blocked:
                exp = self._blocked[ip]["blocked_at"] + timedelta(minutes=cfg.BLOCK_DURATION_MIN)
                return {"success":False,"already_blocked":True,"expires_at":exp.strftime("%H:%M:%S")}
            if not cfg.ACTIVE_RESPONSE:
                log.warning("⚠️  SIMULATION: %s SERAIT bloquée (%s)", ip, reason)
                return {"success":False,"dry_run":True}
            ok  = Firewall.block(ip)
            now = datetime.now()
            exp = now + timedelta(minutes=cfg.BLOCK_DURATION_MIN)
            if ok:
                t = threading.Timer(cfg.BLOCK_DURATION_MIN * 60, self._expire, args=[ip])
                t.daemon = True; t.start()
                self._blocked[ip] = {"blocked_at":now,"reason":reason,"timer":t}
                self._save()
                log.warning("🚫 BLOQUÉ: %s | %s | expire %s", ip, reason, exp.strftime("%H:%M:%S"))
                return {"success":True,"expires_at":exp.strftime("%H:%M:%S"),
                        "blocked_at":now.strftime("%H:%M:%S")}
            log.error("❌ Firewall ÉCHEC pour %s — vérifier droits admin", ip)
            return {"success":False,"error":"firewall échoué"}

    def unblock(self, ip) -> bool:
        with self._lock:
            if ip not in self._blocked: return False
            info = self._blocked.pop(ip)
            if info.get("timer"): info["timer"].cancel()
            Firewall.unblock(ip); self._save()
            log.info("✅ %s débloquée manuellement", ip)
            return True

    def is_blocked(self, ip) -> bool:
        with self._lock: return ip in self._blocked

    def list_blocked(self) -> list:
        with self._lock:
            now = datetime.now()
            return [{"ip":ip,"reason":info["reason"],
                     "remaining_min":round(max(0,cfg.BLOCK_DURATION_MIN-
                                              (now-info["blocked_at"]).total_seconds()/60),1),
                     "expires_at":(info["blocked_at"]+timedelta(minutes=cfg.BLOCK_DURATION_MIN)
                                   ).strftime("%H:%M:%S")}
                    for ip,info in self._blocked.items()]

blacklist = BlacklistManager()


# ──────────────────────────────────────────────────────────────────
# UTILITAIRES
# ──────────────────────────────────────────────────────────────────
def is_internal(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback
    except ValueError: return False

def extract_ips(alert_data, observables):
    ips = []
    for obs in observables:
        if obs.get("dataType") == "ip":
            ip = obs.get("data","").strip()
            if ip and ip not in ips: ips.append(ip)
    for art in alert_data.get("artifacts",[]):
        if art.get("dataType") == "ip":
            ip = art.get("data","").strip()
            if ip and ip not in ips: ips.append(ip)
    if not ips:
        for ip in re.findall(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', alert_data.get("description","")):
            try:
                if all(0<=int(p)<=255 for p in ip.split(".")) and ip not in ips:
                    ips.append(ip)
            except Exception: pass
    return ips

def extract_hashes(alert_data, observables):
    hashes = []
    for obs in observables:
        if obs.get("dataType") in ("hash","md5","sha256","sha1"):
            h = obs.get("data","").strip()
            if h and h not in hashes: hashes.append(h)
    for h in re.findall(r'\b[0-9a-fA-F]{32,64}\b', alert_data.get("description","")):
        if h not in hashes: hashes.append(h)
    return hashes

def extract_domains(alert_data, observables):
    domains = []
    for obs in observables:
        if obs.get("dataType") == "domain":
            d = obs.get("data","").strip()
            if d and d not in domains: domains.append(d)
    return domains


# ──────────────────────────────────────────────────────────────────
# STATE
# ──────────────────────────────────────────────────────────────────
class StateManager:
    def __init__(self):
        self.path  = Path(cfg.STATE_FILE)
        self._s    = self._load()
        self._lock = threading.Lock()

    def _load(self):
        if self.path.exists():
            try:
                with open(self.path) as f: return json.load(f)
            except Exception: pass
        return {"processed_alerts":[],"processed_cases":[]}

    def _save(self):
        try:
            with open(self.path,"w") as f: json.dump(self._s, f, indent=2)
        except Exception as e: log.error("State save: %s", e)

    def is_done(self, eid, etype="alert"):
        with self._lock: return eid in self._s.get("processed_{}s".format(etype),[])

    def mark_done(self, eid, etype="alert"):
        with self._lock:
            k = "processed_{}s".format(etype)
            if k not in self._s: self._s[k] = []
            if eid not in self._s[k]:
                self._s[k].append(eid)
                self._s[k] = self._s[k][-20000:]
                self._save()

state = StateManager()


# ══════════════════════════════════════════════════════════════════
# PROCESSEUR PRINCIPAL — FLUX COMPLET 100% AUTO
# ══════════════════════════════════════════════════════════════════
class AlertProcessor:

    def process(self, alert_data: dict):
        alert_id = _get_id(alert_data)   # FIX v10: TheHive v5 utilise "_id"
        title    = alert_data.get("title", "Alerte Splunk")
        severity = alert_data.get("severity", 2)
        tags     = alert_data.get("tags", [])
        tlp      = alert_data.get("tlp", 2)

        log.info("═" * 60)
        log.info("ALERTE %s [sev=%d]: %s", alert_id, severity, title[:60])

        raw_obs = TH.get_alert_observables(alert_id, alert_data)
        ips     = extract_ips(alert_data, raw_obs)
        hashes  = extract_hashes(alert_data, raw_obs)
        domains = extract_domains(alert_data, raw_obs)
        log.info("Observables: IPs=%s | Hashes=%s | Domains=%s", ips, hashes, domains)

        is_bf = (any(t in tags for t in cfg.BRUTE_FORCE_TAGS) or
                 any(k in title.lower() for k in cfg.BRUTE_FORCE_KW))

        # ── Promotion alerte → Cas TheHive ────────────────────────
        case     = TH.promote(alert_id, title, alert_data)
        case_id  = _get_id(case) if case else ""
        case_num = case.get("number", case.get("caseId","?")) if case else "ERREUR"

        if not case or not case_id:
            log.error("❌ ÉCHEC promotion alerte %s", alert_id)
            TG.send("❌ <b>CAS NON CRÉÉ</b>\n{}\n{}".format(title[:60], alert_id))
            return

        log.info("✅ Cas #%s créé (id=%s)", case_num, case_id)
        TH.mark_alert_inprogress(alert_id)
        TH.add_tag(case_id, "auto-processed")
        if is_bf: TH.add_tag(case_id, "brute_force")

        TG.send("📁 <b>Cas #{}</b> créé\n{}\nIP: <code>{}</code>\n"
                "<a href='{}/cases/{}/details'>→ TheHive</a>".format(
                    case_num, title[:80], ips[0] if ips else "N/A",
                    cfg.THEHIVE_URL, case_id))

        vt_results  = {}; misp_hits = []; blocked_ips = []; actions = []
        all_obs     = ([("ip",ip)     for ip  in ips]    +
                       [("hash",h)    for h   in hashes] +
                       [("domain",dom)for dom in domains])

        for datatype, value in all_obs:
            log.info("── Observable [%s] %s", datatype, value)

            # a) Ajouter observable au cas TheHive
            tags_obs = ["auto-added", datatype]
            if datatype=="ip" and is_internal(value): tags_obs.append("internal-ip")
            if is_bf and datatype=="ip":              tags_obs.append("brute-force-source")
            obs_id = TH.add_observable_to_case(
                case_id, datatype, value,
                message="Détecté dans alerte Splunk — {}".format(alert_id),
                tags=tags_obs)

            # b) VirusTotal
            vt = {}
            if cfg.VT_ENABLED and cfg.VT_APIKEY:
                if datatype=="ip" and not is_internal(value):
                    vt = VT.check_ip(value); time.sleep(0.5)
                elif datatype=="ip" and is_internal(value):
                    actions.append("VT ignoré pour {} (IP privée)".format(value))
                elif datatype=="hash":
                    vt = VT.check_hash(value); time.sleep(0.5)
                elif datatype=="domain":
                    vt = VT.check_domain(value); time.sleep(0.5)
                if vt:
                    vt_results[value] = vt
                    actions.append("VT {} → {}".format(value, VT.verdict(vt)))
                    TH.add_comment(case_id,
                        "### 🦠 VirusTotal — `{}`\n\n{}\n\n"
                        "*Analysé par SOC Pipeline v10*".format(value, VT.summary_md(vt, value)))
                    m = vt.get("malicious",0); t2 = vt.get("total",0)
                    emoji = "🔴" if VT.is_malicious(vt) else ("🟡" if vt.get("suspicious",0)>0 else "🟢")
                    TG.send("{} <b>VirusTotal</b>\nCible: <code>{}</code>\n"
                            "Détections: {}/{}\nRéputation: {}\nCas: #{}".format(
                                emoji, value, m, t2, vt.get("reputation",0), case_num))
                    if VT.is_malicious(vt): TH.add_tag(case_id, "vt-malicious")

            # c) MISP lookup
            misp_type = {"ip":"ip","hash":"md5","domain":"domain"}.get(datatype,"other")
            if MISP.lookup(value, misp_type):
                misp_hits.append(value)
                actions.append("🌐 MISP HIT: {}".format(value))
                TH.add_tag(case_id, "misp-hit")
                TH.add_comment(case_id,
                    "### 🌐 MISP — IoC Trouvé\n\n"
                    "**`{}`** présent dans MISP (type: `{}`)\n\n"
                    "*SOC Pipeline v10*".format(value, misp_type))
                TG.send("🌐 <b>MISP HIT</b>\nValeur: <code>{}</code>\nType: {}\nCas: #{}".format(
                    value, misp_type, case_num))

            # Push MISP si VT malveillant
            if vt and VT.is_malicious(vt) and value not in misp_hits:
                MISP.push(value, misp_type, info="Cas #{} — {}".format(case_num, title[:40]))

            # d) Blocage IP
            if datatype == "ip":
                vt_bad   = value in vt_results and VT.is_malicious(vt_results[value])
                misp_bad = value in misp_hits
                should_block = (is_bf and cfg.BLOCK_ON_BRUTEFORCE) or vt_bad or misp_bad
                if should_block and not blacklist.is_blocked(value):
                    reasons = []
                    if is_bf:    reasons.append("brute force")
                    if vt_bad:   reasons.append("VT {}/{}".format(
                        vt_results[value].get("malicious",0),vt_results[value].get("total",0)))
                    if misp_bad: reasons.append("MISP hit")
                    r_str = " | ".join(reasons) or "menace"
                    res   = blacklist.block(value, r_str)
                    if res.get("success"):
                        blocked_ips.append(value)
                        exp = res["expires_at"]
                        actions.append("🚫 BLOQUÉ {}min: {} → expire {}".format(
                            cfg.BLOCK_DURATION_MIN, value, exp))
                        TH.add_tag(case_id, "ip-blocked")
                        TH.add_comment(case_id,
                            "### 🚫 IP Bloquée — `{}`\n\n"
                            "**Raison**: {}\n**Durée**: {} min\n**Expire**: {}\n\n"
                            "```\npython start.py unblock {}\n```\n\n"
                            "*SOC Pipeline v10*".format(
                                value, r_str, cfg.BLOCK_DURATION_MIN, exp, value))
                        TG.send("🚫 <b>IP BLOQUÉE — {}min</b>\nIP: <code>{}</code>\n"
                                "Raison: {}\nExpire: {}\nCas: #{}".format(
                                    cfg.BLOCK_DURATION_MIN, value, r_str, exp, case_num))
                    elif res.get("dry_run"):
                        actions.append("⚠️ SIMULATION: {} ({})".format(value, r_str))
                        TG.send("⚠️ <b>SIMULATION</b> — {} serait bloquée\nRaison: {}\nCas: #{}".format(
                            value, r_str, case_num))
                    elif res.get("already_blocked"):
                        actions.append("⏳ Déjà bloquée: {}".format(value))

            # e) Cortex via TheHive
            if obs_id and cortex.analyzers:
                analyzers_for = cortex.get_analyzers_for(datatype)
                if analyzers_for:
                    log.info("Cortex: %d analyseurs sur [%s] %s", len(analyzers_for), datatype, value)
                    TH.add_tag(case_id, "cortex-running")
                    actions.append("🔬 Cortex: {} analyseurs sur {}".format(len(analyzers_for), value))

                    def _run_cortex(case_id, obs_id, value, analyzers_for, case_num):
                        lines = ["### 🔬 Cortex — `{}`\n".format(value)]
                        for name, aid in analyzers_for:
                            job_id = TH.run_cortex_on_observable(case_id, obs_id, aid, name)
                            if not job_id:
                                lines.append("- **{}**: ❌ impossible de lancer".format(name))
                                continue
                            result = TH.get_cortex_job_result(job_id, cfg.CORTEX_JOB_TIMEOUT)
                            status = result.get("status","?")
                            if status == "success":
                                verdicts = result.get("verdicts",[])
                                level    = result.get("level","info")
                                v_str    = " | ".join(verdicts) if verdicts else "OK"
                                emoji    = {"malicious":"🔴","suspicious":"🟡",
                                            "safe":"🟢","info":"🔵"}.get(level,"⚪")
                                lines.append("- **{}**: {} {}".format(name, emoji, v_str))
                                TG.send("{} <b>Cortex — {}</b>\nCible: <code>{}</code>\n"
                                        "Verdict: {}\nCas: #{}".format(
                                            emoji, name, value, v_str, case_num))
                                if level == "malicious": TH.add_tag(case_id, "cortex-malicious")
                            elif status == "failure":
                                lines.append("- **{}**: ❌ {}".format(name, result.get("error","?")[:60]))
                            else:
                                lines.append("- **{}**: ⏱ Timeout".format(name))
                            time.sleep(0.5)
                        lines.append("\n*SOC Pipeline v10 — analyse via TheHive*")
                        TH.add_comment(case_id, "\n".join(lines))

                    t = threading.Thread(
                        target=_run_cortex,
                        args=(case_id, obs_id, value, analyzers_for, case_num),
                        daemon=True)
                    t.start()

        # ── Rapport récapitulatif ─────────────────────────────────
        self._write_summary(case_id, case_num, alert_id, title,
                            ips, hashes, domains, blocked_ips,
                            misp_hits, vt_results, actions, is_bf)

        if blocked_ips or misp_hits or any(VT.is_malicious(v) for v in vt_results.values()):
            TH.update_status(case_id, "InProgress")

        log.info("═══ DONE %s → cas #%s | bloquées=%s", alert_id, case_num, blocked_ips)

    def _write_summary(self, case_id, case_num, alert_id, title,
                       ips, hashes, domains, blocked, misp_hits, vt_results, actions, is_bf):
        lines = [
            "## 🤖 SOC Pipeline v10.0.0 — Rapport Complet", "",
            "| Champ | Valeur |", "|-------|--------|",
            "| **Date** | {} |".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            "| **Alerte** | `{}` |".format(alert_id),
            "| **Cas** | #{} |".format(case_num),
            "| **Brute Force** | {} |".format("🔴 OUI" if is_bf else "🟢 Non"),
            "| **Réponse Active** | {} |".format(
                "🔴 OUI (blocage réel)" if cfg.ACTIVE_RESPONSE else "⚠️ SIMULATION"), "",
        ]
        if ips:
            lines += ["### 🌐 IPs","| IP | Type | VT | MISP | Bloquée |","|---|---|---|---|---|"]
            for ip in ips:
                vt = vt_results.get(ip,{})
                lines.append("| `{}` | {} | {} | {} | {} |".format(
                    ip,
                    "🏠 Interne" if is_internal(ip) else "🌐 Externe",
                    VT.verdict(vt) if vt else "⚪ Privée" if is_internal(ip) else "⚪ N/A",
                    "🔴 HIT" if ip in misp_hits else "🟢 Clean",
                    "🚫 {}min".format(cfg.BLOCK_DURATION_MIN) if ip in blocked
                    else "⚠️ Simul." if not cfg.ACTIVE_RESPONSE and is_bf else "✅ Non"))
        if hashes:
            lines += ["","### 🔑 Hashes","| Hash | VT |","|---|---|"]
            for h in hashes:
                vt = vt_results.get(h,{})
                lines.append("| `{}...` | {} |".format(h[:20], VT.verdict(vt) if vt else "⚪ N/A"))
        if blocked:
            lines += ["","### 🚫 IPs Bloquées",""]
            for ip in blocked:
                info = blacklist._blocked.get(ip,{})
                exp  = (info.get("blocked_at",datetime.now())+timedelta(minutes=cfg.BLOCK_DURATION_MIN)
                        ).strftime("%H:%M:%S") if info else "?"
                lines.append("- `{}` expire {} — `python start.py unblock {}`".format(ip,exp,ip))
        if actions:
            lines += ["","### 📊 Actions",""]
            lines += ["- {}".format(a) for a in actions]
        lines += ["","---","> *SOC Pipeline v10.0.0 — 100% Automatique*"]
        TH.add_comment(case_id, "\n".join(lines))


# ══════════════════════════════════════════════════════════════════
# POLLER
# ══════════════════════════════════════════════════════════════════
class Poller:
    def __init__(self): self.proc = AlertProcessor()

    def run_once(self):
        alerts = TH.fetch_new_alerts()
        log.debug("Poll: %d alertes", len(alerts))
        n = 0
        for a in alerts:
            aid = _get_id(a)   # FIX v10 : "_id" TheHive v5
            if not aid or state.is_done(aid,"alert"): continue
            state.mark_done(aid,"alert"); n+=1
            try: self.proc.process(a)
            except Exception as e: log.exception("process %s: %s", aid, e)
        if n: log.info("Cycle: %d alertes traitées", n)

    def run(self):
        vt_s = "✅ Actif" if (cfg.VT_ENABLED and cfg.VT_APIKEY) else "❌ VT_APIKEY manquante"
        co_s = "✅ {} analyseurs".format(len(cortex.analyzers)) if cortex.analyzers else "⚠️  0 analyseurs"
        print("")
        print("╔══════════════════════════════════════════════════════════╗")
        print("║  SOC Pipeline — Service B  v10.0.0  FULL AUTO           ║")
        print("╠══════════════════════════════════════════════════════════╣")
        print("║  TheHive  : {}".format(cfg.THEHIVE_URL).ljust(57)+"║")
        print("║  VT       : {}".format(vt_s).ljust(57)+"║")
        print("║  Cortex   : {}".format(co_s).ljust(57)+"║")
        print("║  MISP     : {}".format("✅ Actif" if cfg.MISP_ENABLED else "⚪ off").ljust(57)+"║")
        print("║  Blocage  : {}".format("🔴 ACTIF" if cfg.ACTIVE_RESPONSE else "⚠️  SIMULATION").ljust(57)+"║")
        print("║  Durée    : {} min — Poll: {}s".format(
            cfg.BLOCK_DURATION_MIN, cfg.POLL_INTERVAL_SEC).ljust(57)+"║")
        print("╠══════════════════════════════════════════════════════════╣")
        print("║  FLUX: Alerte→Cas→Obs→Cortex→VT→MISP→Blocage→Telegram  ║")
        print("╚══════════════════════════════════════════════════════════╝")
        if not cfg.ACTIVE_RESPONSE:
            print("\n  ⚠️  SIMULATION — ACTIVE_RESPONSE=true dans .env pour vrai blocage")
            print("  ⚠️  Windows: relancer PowerShell en Administrateur")
            print("  ⚠️  Linux:   sudo python3 start.py both\n")
        TG.send("🚀 <b>SOC Pipeline v10.0.0 — FULL AUTO</b>\n\n"
                "🦠 VT: {}\n🔬 Cortex: {}\n🌐 MISP: {}\n"
                "🚫 Blocage: {}\n⏱ {}min / poll {}s".format(
                    vt_s, co_s, "✅" if cfg.MISP_ENABLED else "off",
                    "🔴 ACTIF" if cfg.ACTIVE_RESPONSE else "⚠️ SIMULATION",
                    cfg.BLOCK_DURATION_MIN, cfg.POLL_INTERVAL_SEC))
        while True:
            try: self.run_once()
            except KeyboardInterrupt: break
            except Exception as e: log.exception("Poll: %s", e)
            time.sleep(cfg.POLL_INTERVAL_SEC)


# ══════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════
def cli_unblock(ip):
    if blacklist.unblock(ip):
        print("✅ {} débloquée".format(ip))
        TG.send("✅ <b>Débloquée manuellement</b>: <code>{}</code>".format(ip))
    else:
        print("⚠️  {} non trouvée dans la blacklist".format(ip))

def cli_list():
    bl = blacklist.list_blocked()
    if not bl: print("Aucune IP bloquée."); return
    print("\nIPs bloquées ({}) :".format(len(bl)))
    for b in bl:
        print("  {} | expire {} | reste {}min | {}".format(
            b["ip"], b["expires_at"], b["remaining_min"], b["reason"]))

def cli_status():
    print("\n=== SOC Pipeline v10.0.0 ===")
    print("ACTIVE_RESPONSE:", "✅ OUI" if cfg.ACTIVE_RESPONSE else "❌ NON (simulation)")
    print("VT             :", "✅" if (cfg.VT_ENABLED and cfg.VT_APIKEY) else "❌")
    print("Cortex         :", len(cortex.analyzers), "analyseurs")
    if cortex.analyzers:
        for dt, anals in cortex.by_type.items():
            print("  [{}]: {}".format(dt, ", ".join(n for n,_ in anals[:3])))
    print("MISP           :", "✅" if cfg.MISP_ENABLED else "❌")
    print("Telegram       :", "✅" if cfg.TELEGRAM_ENABLED else "❌")
    cli_list()


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        cmd = sys.argv[1].lower()
        if cmd == "unblock" and len(sys.argv) >= 3: cli_unblock(sys.argv[2]); sys.exit(0)
        if cmd in ("list","ls"):  cli_list();   sys.exit(0)
        if cmd == "status":       cli_status(); sys.exit(0)
    if cfg.ACTIVE_RESPONSE:
        log.warning("🔴 RÉPONSE ACTIVE — IPs brute force seront bloquées")
    else:
        log.warning("⚠️  SIMULATION — ACTIVE_RESPONSE=false")
    Poller().run()
