#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  SOC Automation Pipeline — Service B                        ║
║  TheHive → Cortex + MISP + VirusTotal + Active Response     ║
║  Version : 7.0.0  |  Rachad Lab                            ║
╚══════════════════════════════════════════════════════════════╝

Flux :
  Poll TheHive (30s) → Cas High/Critical → Cortex + MISP + VT
  → Tags + Commentaire + Telegram → Blocage IP (si activé)
"""

import os, json, hashlib, logging, time, subprocess, re, ipaddress, sys, warnings
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

warnings.filterwarnings("ignore", category=DeprecationWarning)

# ══════════════════════════════════════════════════════════════════
# CHARGEMENT .env — DOIT ÊTRE FAIT EN PREMIER
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
                    key = key.strip()
                    val = val.strip().strip('"').strip("'")
                    os.environ[key] = val
                    count += 1
            print("[ENV] Chargé : {} ({} variables)".format(path, count))
            return str(path)
    print("[ENV] Aucun .env trouvé — variables système utilisées")
    return None

_ENV_PATH = _load_env_file()
# ══════════════════════════════════════════════════════════════════

import requests
from thehive4py.api import TheHiveApi
from thehive4py.models import CaseTaskLog


# ──────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────
class Config:
    THEHIVE_URL    = os.getenv("THEHIVE_URL",    "http://10.2.3.122:9000")
    THEHIVE_APIKEY = os.getenv("THEHIVE_APIKEY", "J9LiEsGJDFFfDmBuAKyj+MUmWyytwNTx")

    CORTEX_URL    = os.getenv("CORTEX_URL",    "http://10.2.3.122:9001")
    CORTEX_APIKEY = os.getenv("CORTEX_APIKEY", "bWlV+gaFN5SWvymWfk1u1Rp8tMWYnJG+")

    MISP_URL    = os.getenv("MISP_URL",    "https://10.2.3.121")
    MISP_APIKEY = os.getenv("MISP_APIKEY", "fT4SirMbSXZeBZMIFSwQIXyaIW1smGmX6uuAOv1s")
    MISP_ENABLED = os.getenv("MISP_ENABLED", "true").lower() == "true"

    VT_ENABLED = os.getenv("VT_ENABLED", "true").lower() == "true"
    VT_APIKEY  = os.getenv("VT_APIKEY",  "")
    VT_TIMEOUT = int(os.getenv("VT_TIMEOUT", "15"))
    VT_MIN_DETECTIONS = int(os.getenv("VT_MIN_DETECTIONS", "2"))

    POLL_INTERVAL_SEC = int(os.getenv("POLL_INTERVAL",   "30"))
    MIN_SEVERITY      = int(os.getenv("MIN_SEVERITY",    "3"))
    RESPONSE_MIN_SEV  = int(os.getenv("RESPONSE_MIN_SEV","4"))

    STATE_FILE     = os.getenv("STATE_FILE",    "responder_state.json")
    LOG_FILE       = os.getenv("LOG_FILE_B",    "service_b.log")
    LOG_LEVEL      = os.getenv("LOG_LEVEL",     "INFO")

    ACTIVE_RESPONSE = os.getenv("ACTIVE_RESPONSE", "false").lower() == "true"
    BLACKLIST_FILE  = os.getenv("BLACKLIST_FILE",  "ip_blacklist.txt")

    TELEGRAM_ENABLED = os.getenv("TELEGRAM_ENABLED", "false").lower() == "true"
    TELEGRAM_TOKEN   = os.getenv("TELEGRAM_TOKEN",   "")
    TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

    SAFE_NETWORKS = [
        "127.0.0.0/8", "10.0.0.0/8",
        "172.16.0.0/12", "192.168.0.0/16", "::1/128",
    ]

cfg = Config()


# ──────────────────────────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────────────────────────
def _setup_logger() -> logging.Logger:
    logger = logging.getLogger("SOC-B")
    logger.setLevel(getattr(logging, cfg.LOG_LEVEL, logging.INFO))

    class JsonFmt(logging.Formatter):
        def format(self, r):
            obj = {"ts": datetime.utcnow().isoformat()+"Z",
                   "level": r.levelname, "service": "SOC-B", "msg": r.getMessage()}
            if r.exc_info:
                obj["exc"] = self.formatException(r.exc_info)
            return json.dumps(obj, ensure_ascii=False)

    try:
        fh = RotatingFileHandler(cfg.LOG_FILE, maxBytes=10_000_000,
                                  backupCount=5, encoding="utf-8")
        fh.setFormatter(JsonFmt())
        logger.addHandler(fh)
    except Exception:
        pass

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)
    return logger

log = _setup_logger()


# ──────────────────────────────────────────────────────────────────
# STATE MANAGER
# ──────────────────────────────────────────────────────────────────
class StateManager:
    def __init__(self, path: str):
        self.path   = Path(path)
        self._state = self._load()

    def _load(self) -> dict:
        if self.path.exists():
            try:
                with open(self.path) as f:
                    return json.load(f)
            except Exception:
                pass
        return {"processed_cases": [], "processed_alerts": [], "blocked_ips": []}

    def _save(self):
        try:
            with open(self.path, "w") as f:
                json.dump(self._state, f, indent=2)
        except Exception as e:
            log.error("Erreur save state: %s", e)

    def is_processed(self, eid: str, etype: str = "case") -> bool:
        return eid in self._state.get("processed_{}s".format(etype), [])

    def mark_processed(self, eid: str, etype: str = "case"):
        key = "processed_{}s".format(etype)
        if key not in self._state:
            self._state[key] = []
        if eid not in self._state[key]:
            self._state[key].append(eid)
            self._state[key] = self._state[key][-10000:]
            self._save()

    def is_ip_blocked(self, ip: str) -> bool:
        return ip in self._state.get("blocked_ips", [])

    def mark_ip_blocked(self, ip: str):
        if "blocked_ips" not in self._state:
            self._state["blocked_ips"] = []
        if ip not in self._state["blocked_ips"]:
            self._state["blocked_ips"].append(ip)
            self._save()


state   = StateManager(cfg.STATE_FILE)
thehive = TheHiveApi(cfg.THEHIVE_URL, cfg.THEHIVE_APIKEY)

def _headers(apikey: str) -> dict:
    return {"Authorization": "Bearer {}".format(apikey),
            "Content-Type": "application/json", "Accept": "application/json"}


# ──────────────────────────────────────────────────────────────────
# SAFETY
# ──────────────────────────────────────────────────────────────────
class SafetyChecker:
    SAFE_NETS = [ipaddress.ip_network(n, strict=False) for n in cfg.SAFE_NETWORKS]

    @classmethod
    def is_safe_ip(cls, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip.strip())
            return any(addr in net for net in cls.SAFE_NETS)
        except ValueError:
            return True

    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        try:
            ipaddress.ip_address(ip.strip())
            return True
        except ValueError:
            return False


# ══════════════════════════════════════════════════════════════════
# VIRUSTOTAL v3
# ══════════════════════════════════════════════════════════════════
class VTClient:
    BASE = "https://www.virustotal.com/api/v3"

    @classmethod
    def _get(cls, endpoint: str) -> dict:
        if not cfg.VT_ENABLED or not cfg.VT_APIKEY:
            return {}
        try:
            r = requests.get(
                "{}/{}".format(cls.BASE, endpoint),
                headers={"x-apikey": cfg.VT_APIKEY},
                timeout=cfg.VT_TIMEOUT,
            )
            if r.status_code == 200:
                return r.json()
            elif r.status_code == 429:
                log.warning("VT: rate limit — attente 60s")
                time.sleep(60)
            elif r.status_code == 404:
                pass  # IOC inconnu de VT
            else:
                log.warning("VT HTTP %d pour %s", r.status_code, endpoint[:50])
        except requests.Timeout:
            log.warning("VT timeout")
        except Exception as e:
            log.error("VT erreur: %s", e)
        return {}

    @classmethod
    def _stats(cls, data: dict) -> dict:
        attrs = data.get("data", {}).get("attributes", {})
        s = attrs.get("last_analysis_stats", {})
        return {
            "malicious":  s.get("malicious",  0),
            "suspicious": s.get("suspicious", 0),
            "harmless":   s.get("harmless",   0),
            "undetected": s.get("undetected", 0),
            "total":      sum(s.values()) if s else 0,
            "reputation": attrs.get("reputation", 0),
            "country":    attrs.get("country", ""),
            "as_owner":   attrs.get("as_owner", ""),
            "tags":       attrs.get("tags", [])[:5],
            "names":      attrs.get("names", [])[:3],
        }

    @classmethod
    def check_ip(cls, ip: str) -> dict:
        d = cls._get("ip_addresses/{}".format(ip))
        if not d:
            return {}
        r = cls._stats(d)
        r.update({"type": "ip", "value": ip})
        log.info("VT IP %s: mal=%d sus=%d rep=%d", ip, r["malicious"], r["suspicious"], r["reputation"])
        return r

    @classmethod
    def check_domain(cls, domain: str) -> dict:
        d = cls._get("domains/{}".format(domain))
        if not d:
            return {}
        r = cls._stats(d)
        r.update({"type": "domain", "value": domain})
        log.info("VT domain %s: mal=%d", domain, r["malicious"])
        return r

    @classmethod
    def check_hash(cls, fhash: str) -> dict:
        d = cls._get("files/{}".format(fhash))
        if not d:
            return {}
        attrs = d.get("data", {}).get("attributes", {})
        r = cls._stats(d)
        r.update({
            "type":      "hash",
            "value":     fhash,
            "file_name": attrs.get("meaningful_name", ""),
            "file_type": attrs.get("type_description", ""),
            "file_size": attrs.get("size", 0),
        })
        log.info("VT hash %s: mal=%d file=%s", fhash[:16], r["malicious"], r["file_name"])
        return r

    @classmethod
    def check_url(cls, url: str) -> dict:
        import base64
        uid = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        d = cls._get("urls/{}".format(uid))
        if not d:
            return {}
        r = cls._stats(d)
        r.update({"type": "url", "value": url})
        return r

    @classmethod
    def is_malicious(cls, r: dict) -> bool:
        if not r:
            return False
        return (r.get("malicious",0) >= cfg.VT_MIN_DETECTIONS
                or r.get("suspicious",0) >= cfg.VT_MIN_DETECTIONS * 2
                or r.get("reputation",0) <= -10)

    @classmethod
    def verdict(cls, r: dict) -> str:
        if not r:
            return "⚪ Inconnu"
        m, s, t = r.get("malicious",0), r.get("suspicious",0), r.get("total",0)
        if cls.is_malicious(r):
            return "🔴 MALVEILLANT ({}/{})".format(m, t)
        elif s > 0:
            return "🟡 Suspect ({} suspect/{})".format(s, t)
        elif t > 0:
            return "🟢 Propre (0/{})".format(t)
        return "⚪ Inconnu (non indexé)"


# ══════════════════════════════════════════════════════════════════
# CORTEX
# ══════════════════════════════════════════════════════════════════
class CortexAnalyzer:
    ANALYZER_MAP = {
        "ip":     ["AbuseIPDB_1_0", "VirusTotal_GetReport_3_1", "Shodan_Host_2_0"],
        "hash":   ["VirusTotal_GetReport_3_1", "Maltiverse_1_0"],
        "domain": ["PassiveTotal_DomainDetails_2_0", "VirusTotal_GetReport_3_1"],
        "url":    ["VirusTotal_GetReport_3_1", "URLhaus_2_0"],
        "other":  [],
    }

    @classmethod
    def get_available(cls) -> list:
        if not cfg.CORTEX_APIKEY:
            return []
        try:
            r = requests.get(
                "{}/api/analyzer".format(cfg.CORTEX_URL),
                headers=_headers(cfg.CORTEX_APIKEY),
                timeout=10,
            )
            if r.status_code == 200:
                return [a["name"] for a in r.json()]
        except Exception as e:
            log.warning("Cortex get analyzers: %s", e)
        return []

    @classmethod
    def run(cls, analyzer_id: str, data_type: str, data: str) -> Optional[dict]:
        if not cfg.CORTEX_APIKEY:
            return None
        try:
            r = requests.post(
                "{}/api/analyzer/{}/run".format(cfg.CORTEX_URL, analyzer_id),
                headers=_headers(cfg.CORTEX_APIKEY),
                json={"analyzerId": analyzer_id, "dataType": data_type, "data": data},
                timeout=15,
            )
            if r.status_code not in (200, 201):
                return None
            job_id = r.json().get("id")
            if not job_id:
                return None

            # Attendre résultat (max 120s)
            for _ in range(24):
                time.sleep(5)
                jr = requests.get(
                    "{}/api/job/{}".format(cfg.CORTEX_URL, job_id),
                    headers=_headers(cfg.CORTEX_APIKEY),
                    timeout=10,
                )
                if jr.status_code == 200:
                    job = jr.json()
                    status = job.get("status","")
                    if status == "Success":
                        return job.get("report", {})
                    elif status in ("Failure", "Deleted"):
                        return None
        except Exception as e:
            log.error("Cortex %s: %s", analyzer_id, e)
        return None

    @classmethod
    def is_malicious(cls, results: dict) -> bool:
        for _, report in results.items():
            s = report.get("summary", {})
            if s.get("malicious", 0) > 2:
                return True
            if s.get("abuseScore", 0) > 50:
                return True
            if s.get("threatScore", 0) > 70:
                return True
            for t in report.get("taxonomies", []):
                if t.get("level") in ("malicious", "suspicious") and \
                   t.get("value") not in ("0", "clean"):
                    return True
        return False


# ══════════════════════════════════════════════════════════════════
# MISP
# ══════════════════════════════════════════════════════════════════
class MISPClient:

    @staticmethod
    def _req(method: str, path: str, data: dict = None) -> Optional[dict]:
        try:
            hdrs = {**_headers(cfg.MISP_APIKEY), "Accept": "application/json"}
            fn   = requests.get if method == "GET" else requests.post
            kw   = {"headers": hdrs, "timeout": 10, "verify": False}
            if data:
                kw["json"] = data
            r = fn("{}{}".format(cfg.MISP_URL, path), **kw)
            return r.json() if r.status_code in (200, 201) else None
        except Exception as e:
            log.error("MISP %s %s: %s", method, path, e)
            return None

    @classmethod
    def lookup(cls, value: str, ioc_type: str) -> bool:
        if not cfg.MISP_ENABLED or not cfg.MISP_APIKEY:
            return False
        try:
            res = cls._req("POST", "/attributes/restSearch",
                           {"value": value, "type": ioc_type, "limit": 1})
            if res:
                attrs = res.get("response", {}).get("Attribute", [])
                if attrs:
                    log.info("MISP hit: %s (%s)", value, ioc_type)
                    return True
        except Exception as e:
            log.error("MISP lookup: %s", e)
        return False

    @classmethod
    def push(cls, value: str, ioc_type: str, comment: str = "", case_id: str = "") -> bool:
        if not cfg.MISP_ENABLED or not cfg.MISP_APIKEY:
            return False
        type_map = {"ip":"ip-dst","domain":"domain","hash":"md5","url":"url","other":"text"}
        try:
            res = cls._req("POST", "/events", {"Event": {
                "info":            "SOC Auto — Case {} — {}".format(case_id, value),
                "distribution":    0,
                "threat_level_id": 1,
                "analysis":        1,
                "Attribute": [{"type": type_map.get(ioc_type,"text"),
                               "category": "Network activity",
                               "value": value,
                               "comment": comment or "Auto-pushed by SOC Pipeline v7",
                               "to_ids": True}],
            }})
            if res:
                log.info("MISP push OK: %s", value)
                return True
        except Exception as e:
            log.error("MISP push: %s", e)
        return False


# ══════════════════════════════════════════════════════════════════
# ACTIVE RESPONSE
# ══════════════════════════════════════════════════════════════════
class ActiveResponder:

    @staticmethod
    def block_ip(ip: str) -> bool:
        if not cfg.ACTIVE_RESPONSE:
            log.info("Active response désactivé — IP %s non bloquée", ip)
            return False
        if SafetyChecker.is_safe_ip(ip):
            log.warning("IP %s interne — BLOCAGE REFUSÉ (protection réseau)", ip)
            return False
        if state.is_ip_blocked(ip):
            log.info("IP %s déjà bloquée", ip)
            return True

        try:
            for cmd in [
                ["iptables", "-A", "INPUT",  "-s", ip, "-j", "DROP"],
                ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
            ]:
                r = subprocess.run(cmd, capture_output=True, timeout=10)
                if r.returncode != 0:
                    log.error("iptables erreur pour %s: %s", ip, r.stderr.decode()[:100])
                    return False

            state.mark_ip_blocked(ip)
            try:
                with open(cfg.BLACKLIST_FILE, "a") as f:
                    f.write("{} {}\n".format(ip, datetime.utcnow().isoformat()))
            except Exception:
                pass

            log.info("IP bloquée via iptables: %s", ip)
            return True

        except FileNotFoundError:
            log.error("iptables non disponible — install : apt install iptables")
            return False
        except Exception as e:
            log.error("Blocage IP %s: %s", ip, e)
            return False

    @staticmethod
    def unblock_ip(ip: str) -> bool:
        try:
            for cmd in [
                ["iptables", "-D", "INPUT",  "-s", ip, "-j", "DROP"],
                ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
            ]:
                subprocess.run(cmd, capture_output=True, timeout=10)
            log.info("IP débloquée: %s", ip)
            return True
        except Exception as e:
            log.error("Déblocage %s: %s", ip, e)
            return False


# ══════════════════════════════════════════════════════════════════
# THEHIVE CASE MANAGER
# ══════════════════════════════════════════════════════════════════
class CaseManager:

    @staticmethod
    def add_tag(case_id: str, tag: str):
        try:
            r = thehive.get_case(case_id)
            if r.status_code == 200:
                existing = r.json().get("tags", [])
                if tag not in existing:
                    thehive.update_case(case_id, {"tags": existing + [tag]})
        except Exception as e:
            log.error("add_tag %s %s: %s", case_id, tag, e)

    @staticmethod
    def add_comment(case_id: str, message: str):
        try:
            # TheHive v5 API
            r = requests.post(
                "{}/api/v1/case/{}/comment".format(cfg.THEHIVE_URL, case_id),
                headers=_headers(cfg.THEHIVE_APIKEY),
                json={"message": message},
                timeout=10,
            )
            if r.status_code not in (200, 201):
                # Fallback v4
                thehive.create_case_task_log(case_id, CaseTaskLog(message=message))
        except Exception as e:
            log.error("add_comment %s: %s", case_id, e)

    @staticmethod
    def update_status(case_id: str, status: str):
        try:
            thehive.update_case(case_id, {"status": status})
        except Exception as e:
            log.error("update_status %s: %s", case_id, e)

    @staticmethod
    def get_observables(case_id: str) -> list:
        try:
            # TheHive v5
            r = requests.post(
                "{}/api/v1/case/{}/observable".format(cfg.THEHIVE_URL, case_id),
                headers=_headers(cfg.THEHIVE_APIKEY),
                json={"query": [{"_name": "listObservable"}]},
                timeout=10,
            )
            if r.status_code == 200:
                return r.json()
            # Fallback v4
            r2 = thehive.get_case_observables(case_id)
            if r2.status_code == 200:
                return r2.json()
        except Exception as e:
            log.error("get_observables %s: %s", case_id, e)
        return []


# ══════════════════════════════════════════════════════════════════
# TELEGRAM
# ══════════════════════════════════════════════════════════════════
def notify_telegram(message: str):
    if not cfg.TELEGRAM_ENABLED or not cfg.TELEGRAM_TOKEN or not cfg.TELEGRAM_CHAT_ID:
        return
    try:
        requests.post(
            "https://api.telegram.org/bot{}/sendMessage".format(cfg.TELEGRAM_TOKEN),
            json={"chat_id": cfg.TELEGRAM_CHAT_ID,
                  "text": message[:4096], "parse_mode": "HTML"},
            timeout=10,
        )
    except Exception as e:
        log.error("Telegram: %s", e)


# ══════════════════════════════════════════════════════════════════
# PROCESSEUR DE CAS — pipeline complet
# ══════════════════════════════════════════════════════════════════
class CaseProcessor:

    def __init__(self):
        self.available_analyzers = CortexAnalyzer.get_available()
        log.info("Cortex : %d analyseurs disponibles", len(self.available_analyzers))

    def process_case(self, case: dict):
        case_id  = case.get("id", "")
        case_num = case.get("caseId", "?")
        severity = case.get("severity", 1)
        title    = case.get("title", "")

        log.info("Traitement cas #%s id=%s sev=%d: '%s'",
                 case_num, case_id, severity, title[:60])

        state.mark_processed(case_id)
        CaseManager.add_tag(case_id, "auto-processed")

        observables     = CaseManager.get_observables(case_id)
        analysis_summary = []
        malicious_ips    = []
        misp_hits        = []
        cortex_malicious = False
        vt_malicious     = False
        actions_taken    = []
        vt_summary       = []

        # ── Analyse par observable ───────────────────────────────
        for obs in observables:
            dtype = obs.get("dataType", "other")
            data  = obs.get("data",     "")
            if not data:
                continue

            log.info("Observable: type=%s data=%s", dtype, str(data)[:50])

            # 1. VirusTotal (plus rapide que Cortex)
            if cfg.VT_ENABLED and cfg.VT_APIKEY:
                vt = {}
                try:
                    if dtype == "ip" and SafetyChecker.is_valid_ip(str(data)):
                        if not SafetyChecker.is_safe_ip(str(data)):
                            vt = VTClient.check_ip(str(data))
                    elif dtype == "hash":
                        vt = VTClient.check_hash(str(data))
                    elif dtype == "domain":
                        vt = VTClient.check_domain(str(data))
                    elif dtype == "url":
                        vt = VTClient.check_url(str(data))

                    if vt:
                        verdict = VTClient.verdict(vt)
                        vt_summary.append("{} `{}` → {}".format(dtype, str(data)[:30], verdict))
                        if VTClient.is_malicious(vt):
                            vt_malicious = True
                            analysis_summary.append("🔴 VT MALVEILLANT: {} {}".format(dtype, data))
                            if dtype == "ip":
                                malicious_ips.append(str(data))
                        else:
                            analysis_summary.append("🟢 VT Propre: {} {}".format(dtype, data))
                        time.sleep(0.3)  # rate limit VT
                except Exception as e:
                    log.error("VT pour %s: %s", data, e)

            # 2. Cortex
            if self.available_analyzers:
                analyzers = CortexAnalyzer.ANALYZER_MAP.get(dtype, [])
                for aid in analyzers:
                    if aid not in self.available_analyzers:
                        continue
                    result = CortexAnalyzer.run(aid, dtype, str(data))
                    if result:
                        if CortexAnalyzer.is_malicious({aid: result}):
                            cortex_malicious = True
                            analysis_summary.append("🔴 Cortex MALVEILLANT: {} {}".format(dtype, data))
                            if dtype == "ip":
                                malicious_ips.append(str(data))
                        else:
                            analysis_summary.append("🟢 Cortex Propre: {} {}".format(dtype, data))

            # 3. MISP lookup
            if cfg.MISP_ENABLED:
                misp_hit = MISPClient.lookup(str(data), dtype)
                if misp_hit:
                    misp_hits.append(str(data))
                    analysis_summary.append("⚠️ MISP HIT: {} {}".format(dtype, data))
                    CaseManager.add_tag(case_id, "misp-hit")
                elif (vt_malicious or cortex_malicious) and cfg.MISP_APIKEY:
                    pushed = MISPClient.push(str(data), dtype, case_id=case_id)
                    if pushed:
                        actions_taken.append("IOC poussé MISP: {}".format(data))

        # ── Tags résultats ────────────────────────────────────────
        is_threat = cortex_malicious or vt_malicious or misp_hits
        if is_threat:
            CaseManager.add_tag(case_id, "malicious")
            CaseManager.add_tag(case_id, "confirmed-threat")
            if vt_malicious:
                CaseManager.add_tag(case_id, "vt-malicious")
        elif analysis_summary:
            CaseManager.add_tag(case_id, "suspicious")
        else:
            CaseManager.add_tag(case_id, "clean")

        # ── Réponse active ────────────────────────────────────────
        if cfg.ACTIVE_RESPONSE and (severity >= cfg.RESPONSE_MIN_SEV or is_threat):
            seen = set()
            for ip in malicious_ips:
                if ip in seen:
                    continue
                seen.add(ip)
                if not SafetyChecker.is_safe_ip(ip):
                    blocked = ActiveResponder.block_ip(ip)
                    if blocked:
                        actions_taken.append("IP bloquée iptables: {}".format(ip))
                        analysis_summary.append("🚫 IP BLOQUÉE: {}".format(ip))
                        log.info("IP %s bloquée (cas #%s)", ip, case_num)
                        notify_telegram(
                            "🚫 <b>IP BLOQUÉE AUTOMATIQUEMENT</b>\n"
                            "IP: <code>{}</code>\n"
                            "Cas TheHive: <a href='{}/cases/{}/details'>#{}</a>".format(
                                ip, cfg.THEHIVE_URL, case_id, case_num
                            )
                        )

        # ── Commentaire de synthèse dans TheHive ─────────────────
        lines = [
            "## 🤖 Rapport d'analyse automatique — SOC Pipeline v7.0.0",
            "",
            "**Date** : {}".format(datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")),
            "**Observables analysés** : {}".format(len(observables)),
            "",
        ]

        if vt_summary:
            lines += ["### 🦠 VirusTotal", ""]
            lines += ["- {}".format(s) for s in vt_summary]
            lines.append("")

        if analysis_summary:
            lines += ["### 📊 Résultats d'analyse", ""]
            lines += ["- {}".format(s) for s in analysis_summary]
            lines.append("")

        if actions_taken:
            lines += ["### ⚡ Actions effectuées", ""]
            lines += ["- {}".format(a) for a in actions_taken]
            lines.append("")

        lines += [
            "### 📋 Statut",
            "- VirusTotal malveillant : **{}**".format("Oui 🔴" if vt_malicious else "Non 🟢"),
            "- Cortex malveillant     : **{}**".format("Oui 🔴" if cortex_malicious else "Non 🟢"),
            "- MISP hits              : **{}**".format(len(misp_hits)),
            "- IPs bloquées           : **{}**".format(
                len([a for a in actions_taken if "iptables" in a])
            ),
            "",
            "> *Généré par SOC Pipeline Service B v7.0.0 — Rachad Lab*",
        ]

        CaseManager.add_comment(case_id, "\n".join(lines))

        if is_threat:
            CaseManager.update_status(case_id, "InProgress")

        # ── Notification Telegram ─────────────────────────────────
        sev_label = {1:"Low",2:"Medium",3:"High",4:"Critical"}.get(severity,"?")
        tg_lines  = [
            "🔍 <b>Analyse terminée — Cas #{}</b>".format(case_num),
            "<b>Titre :</b> {}".format(title[:80]),
            "<b>Sévérité :</b> {}".format(sev_label),
            "<b>Observables :</b> {}".format(len(observables)),
            "<b>VT malveillant :</b> {}".format("OUI 🔴" if vt_malicious else "non 🟢"),
            "<b>Cortex malveillant :</b> {}".format("OUI 🔴" if cortex_malicious else "non 🟢"),
            "<b>MISP hits :</b> {}".format(len(misp_hits)),
        ]
        if actions_taken:
            tg_lines.append("<b>Actions :</b> {}".format(", ".join(actions_taken)))
        tg_lines.append(
            "\n<a href='{}/cases/{}/details'>→ Voir dans TheHive</a>".format(
                cfg.THEHIVE_URL, case_id
            )
        )
        notify_telegram("\n".join(tg_lines))

        log.info("Cas %s traité: vt=%s cortex=%s misp=%d actions=%d",
                 case_id, vt_malicious, cortex_malicious, len(misp_hits), len(actions_taken))


# ══════════════════════════════════════════════════════════════════
# POLLER THEHIVE
# ══════════════════════════════════════════════════════════════════
class TheHivePoller:

    def __init__(self):
        self.processor = CaseProcessor()

    def fetch_cases(self) -> list:
        try:
            # TheHive v5 API
            query = {"query": [
                {"_name": "listCase"},
                {"_name": "filter", "_gte": {"_field": "severity", "_value": cfg.MIN_SEVERITY}},
                {"_name": "sort",   "_fields": [{"_createdAt": "desc"}]},
                {"_name": "page",   "from": 0, "to": 50},
            ]}
            r = requests.post(
                "{}/api/v1/query?name=list-cases".format(cfg.THEHIVE_URL),
                headers=_headers(cfg.THEHIVE_APIKEY),
                json=query, timeout=15,
            )
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass

        # Fallback TheHive v4
        try:
            r2 = thehive.find_cases(
                query={"_gte": {"severity": cfg.MIN_SEVERITY}},
                sort=["-createdAt"], range="0-50",
            )
            if r2.status_code == 200:
                return r2.json()
        except Exception as e:
            log.error("fetch_cases: %s", e)
        return []

    def poll_once(self):
        cases = self.fetch_cases()
        log.debug("Poll: %d cas trouvés", len(cases))
        new_count = 0
        for case in cases:
            case_id  = case.get("id","")
            if not case_id or state.is_processed(case_id):
                continue
            if case.get("severity", 1) < cfg.MIN_SEVERITY:
                continue
            if case.get("status","") in ("Resolved","Deleted","Duplicated"):
                state.mark_processed(case_id)
                continue
            new_count += 1
            try:
                self.processor.process_case(case)
            except Exception as e:
                log.error("process_case %s: %s", case_id, e)
                state.mark_processed(case_id)
        if new_count:
            log.info("Cycle: %d nouveaux cas traités", new_count)

    def run(self):
        log.info("Service B démarré — poll toutes les %ds", cfg.POLL_INTERVAL_SEC)
        print("=" * 62)
        print("  SOC Pipeline — Service B  v7.0.0")
        print("=" * 62)
        print("  TheHive   : {}".format(cfg.THEHIVE_URL))
        print("  Cortex    : {}".format(cfg.CORTEX_URL))
        print("  MISP      : {} ({})".format(cfg.MISP_URL, "activé" if cfg.MISP_ENABLED else "désactivé"))
        print("  VT        : {} ({})".format(
            "activé" if (cfg.VT_ENABLED and cfg.VT_APIKEY) else "désactivé",
            "clé OK" if cfg.VT_APIKEY else "VT_APIKEY manquante",
        ))
        print("  Réponse   : {}".format("ACTIVE ⚠️" if cfg.ACTIVE_RESPONSE else "passive"))
        print("  Poll      : toutes les {}s".format(cfg.POLL_INTERVAL_SEC))
        print("  Sév. min  : {}".format({1:"Low",2:"Medium",3:"High",4:"Critical"}.get(cfg.MIN_SEVERITY,"?")))
        print("=" * 62)

        notify_telegram(
            "🚀 <b>SOC Pipeline — Service B démarré</b>\n"
            "⏰ {}\n\n"
            "🔬 Cortex : {} analyseurs\n"
            "🦠 VT : {}\n"
            "🌐 MISP : {}\n"
            "⚡ Réponse active : {}".format(
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                len(self.processor.available_analyzers),
                "Actif ✅" if (cfg.VT_ENABLED and cfg.VT_APIKEY) else "Non configuré ⚠️",
                "Actif ✅" if cfg.MISP_ENABLED else "Désactivé",
                "ACTIVE ⚠️" if cfg.ACTIVE_RESPONSE else "Désactivée (safe)",
            )
        )

        while True:
            try:
                self.poll_once()
            except KeyboardInterrupt:
                log.info("Arrêt")
                break
            except Exception as e:
                log.error("Cycle poll: %s", e)
            time.sleep(cfg.POLL_INTERVAL_SEC)


# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if cfg.ACTIVE_RESPONSE:
        log.warning("RÉPONSE ACTIVE ACTIVÉE — blocage iptables actif")
        print("[⚠️] Réponse active activée — les IPs malveillantes seront bloquées")

    TheHivePoller().run()
