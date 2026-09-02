#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  SOC Automation Pipeline — Service B                        ║
║  TheHive Responder — Full Auto v11.0.0                      ║
║  By 12ak_H4ck                                               ║
╚══════════════════════════════════════════════════════════════╝

Flux 100 % automatique, pour chaque alerte TheHive :
  1. Poll TheHive          → alertes New / Updated
  2. Promotion alerte      → Cas TheHive
  3. Ajout des observables au cas (IP, hash, domaine)
  4. Cortex                → lancement AUTOMATIQUE des analyseurs
                             sur chaque observable du cas
  5. VirusTotal            → commentaire + tag dans le cas
  6. MISP                  → lookup, puis push si l'IoC est malveillant
  7. Blocage firewall      → netsh (Windows) / iptables (Linux)
                             avec déblocage automatique programmé
  8. Rapport récapitulatif → commentaire markdown dans le cas
  9. Telegram              → notification à chaque étape

Nouveautés v11.0.0 :
  - Client TheHive REST v1 natif (plus de thehive4py, cassé sous Windows)
  - Cortex : découverte des analyseurs VIA TheHive (/api/connector/cortex),
    rafraîchissement automatique, deux routes de lancement en secours
  - Blocage : plus de règles firewall posées en mode SIMULATION au
    redémarrage ; vérification des droits admin/root avant d'agir
  - Variables .env MIN_SEVERITY / RESPONSE_MIN_SEV / BLOCK_ALL_IPS
    réellement appliquées (elles étaient documentées mais ignorées)
  - Parsing .env tolérant aux commentaires en fin de ligne
"""

import ipaddress
import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta

import requests
import urllib3

from file_responder import FileResponder
from soc_common import (
    DATA_DIR, LOGS_DIR, Observable, Telegram, TheHiveClient,
    enable_utf8_console, env_bool, env_int, env_str, load_dotenv,
    now_str, resolve_path, setup_logger, thehive_id,
)

VERSION = "11.0.0"

enable_utf8_console()
load_dotenv()


# ──────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────
class Config:
    def __init__(self):
        self.THEHIVE_URL        = env_str("THEHIVE_URL", "http://127.0.0.1:9000")
        self.THEHIVE_APIKEY     = env_str("THEHIVE_APIKEY")
        self.THEHIVE_VERIFY_SSL = env_bool("THEHIVE_VERIFY_SSL", True)

        self.CORTEX_URL         = env_str("CORTEX_URL", "http://127.0.0.1:9001")
        self.CORTEX_APIKEY      = env_str("CORTEX_APIKEY")
        self.CORTEX_ENABLED     = env_bool("CORTEX_ENABLED", True)
        self.CORTEX_JOB_TIMEOUT = env_int("CORTEX_JOB_TIMEOUT", 180)
        self.CORTEX_MAX_ANALYZERS = env_int("CORTEX_MAX_ANALYZERS", 5)

        self.MISP_URL        = env_str("MISP_URL", "https://127.0.0.1")
        self.MISP_APIKEY     = env_str("MISP_APIKEY")
        self.MISP_ENABLED    = env_bool("MISP_ENABLED", False)
        self.MISP_VERIFY_SSL = env_bool("MISP_VERIFY_SSL", False)

        self.VT_ENABLED        = env_bool("VT_ENABLED", True)
        self.VT_APIKEY         = env_str("VT_APIKEY")
        self.VT_TIMEOUT        = env_int("VT_TIMEOUT", 15)
        self.VT_MIN_DETECTIONS = env_int("VT_MIN_DETECTIONS", 2)

        self.POLL_INTERVAL_SEC = env_int("POLL_INTERVAL", 20)
        self.MIN_SEVERITY      = env_int("MIN_SEVERITY", 1)
        self.RESPONSE_MIN_SEV  = env_int("RESPONSE_MIN_SEV", 2)

        self.STATE_FILE     = resolve_path(env_str("STATE_FILE", "responder_state.json"), DATA_DIR)
        self.BLACKLIST_FILE = resolve_path(env_str("BLACKLIST_FILE", "ip_blacklist.txt"), DATA_DIR)
        self.BLACKLIST_JSON = resolve_path("ip_blacklist.json", DATA_DIR)

        self.LOG_FILE  = resolve_path(env_str("LOG_FILE_B", "service_b.log"), LOGS_DIR)
        self.LOG_LEVEL = env_str("LOG_LEVEL", "INFO")

        self.ACTIVE_RESPONSE     = env_bool("ACTIVE_RESPONSE", False)
        self.BLOCK_DURATION_MIN  = env_int("BLOCK_DURATION_MIN", 10)
        self.BLOCK_ON_BRUTEFORCE = env_bool("BLOCK_ON_BRUTEFORCE", True)
        self.BLOCK_ON_PORTSCAN   = env_bool("BLOCK_ON_PORTSCAN", True)
        self.BLOCK_ON_THREAT     = env_bool("BLOCK_ON_THREAT", True)
        self.BLOCK_ALL_IPS       = env_bool("BLOCK_ALL_IPS", False)

        # Réponse sur les fichiers malveillants (recherche par hash)
        self.FILE_RESPONSE_ENABLED = env_bool("FILE_RESPONSE_ENABLED", False)
        self.FILE_RESPONSE_MODE    = env_str("FILE_RESPONSE_MODE", "quarantine")
        self.FILE_SCAN_PATHS       = [p for p in re.split(
            r"[;,]", env_str("FILE_SCAN_PATHS", "")) if p.strip()]
        self.QUARANTINE_DIR        = env_str("QUARANTINE_DIR", str(DATA_DIR / "quarantine"))
        self.FILE_MAX_SIZE_MB      = env_int("FILE_MAX_SIZE_MB", 200)
        self.FILE_MAX_FILES        = env_int("FILE_MAX_FILES", 200000)

        self.TELEGRAM_ENABLED = env_bool("TELEGRAM_ENABLED", False)
        self.TELEGRAM_TOKEN   = env_str("TELEGRAM_TOKEN")
        self.TELEGRAM_CHAT_ID = env_str("TELEGRAM_CHAT_ID")

    @property
    def vt_ready(self) -> bool:
        return bool(self.VT_ENABLED and self.VT_APIKEY)

    @property
    def misp_ready(self) -> bool:
        return bool(self.MISP_ENABLED and self.MISP_APIKEY)


cfg = Config()
log = setup_logger("SOC-B", cfg.LOG_FILE, cfg.LOG_LEVEL)

if not cfg.MISP_VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

telegram = Telegram(cfg.TELEGRAM_TOKEN, cfg.TELEGRAM_CHAT_ID,
                    cfg.TELEGRAM_ENABLED, logger=log)
thehive  = TheHiveClient(cfg.THEHIVE_URL, cfg.THEHIVE_APIKEY,
                         verify=cfg.THEHIVE_VERIFY_SSL, logger=log)


def notify(message: str) -> None:
    telegram.send_async(message)


# ══════════════════════════════════════════════════════════════════
# CORTEX — registre des analyseurs
# ══════════════════════════════════════════════════════════════════
class CortexRegistry:
    """Découvre les analyseurs Cortex et les classe par type de donnée.

    Deux sources, dans l'ordre :
      1. TheHive  → GET /api/connector/cortex/analyzer  (source de vérité :
         ce sont les analyseurs que TheHive sait réellement lancer)
      2. Cortex   → GET {CORTEX_URL}/api/analyzer       (secours)

    Le registre se rafraîchit tout seul s'il est vide : un Cortex démarré
    après le Service B est donc pris en compte sans redémarrage.
    """

    PRIORITY = {
        "ip":     ["AbuseIPDB", "VirusTotal_GetReport", "MaxMind_GeoIP", "Shodan_Host", "OTXQuery"],
        "hash":   ["VirusTotal_GetReport", "Cuckoo", "OTXQuery"],
        "domain": ["VirusTotal_GetReport", "DomainTools", "OTXQuery", "Urlscan_io_Search"],
        "url":    ["VirusTotal_GetReport", "URLScan_io", "Urlscan_io_Search"],
        "other":  ["OTXQuery"],
    }
    REFRESH_SEC = 300

    def __init__(self):
        # Pas de chargement ici : l'import du module ne doit provoquer aucun
        # appel réseau, sinon les commandes CLI (list, unblock) attendraient
        # inutilement les timeouts DNS de TheHive et Cortex.
        self.by_type    = {}      # {datatype: [(name, analyzer_id, cortex_id)]}
        self.analyzers  = {}      # {name: analyzer_id}
        self.source     = "aucune"
        self._last_load = 0.0
        self._lock      = threading.Lock()

    # ── chargement ───────────────────────────────────────────────
    def load(self) -> int:
        with self._lock:
            self._last_load = time.time()
            entries = self._from_thehive()
            source  = "TheHive"
            if not entries:
                entries = self._from_cortex()
                source  = "Cortex (direct)"
            if not entries:
                self.source = "aucune"
                return 0

            by_type, analyzers = {}, {}
            for name, analyzer_id, cortex_id, datatypes in entries:
                analyzers[name] = analyzer_id
                for datatype in datatypes:
                    by_type.setdefault(datatype, []).append((name, analyzer_id, cortex_id))
            self.by_type   = by_type
            self.analyzers = analyzers
            self.source    = source
            log.info("Cortex : %d analyseurs via %s — types : %s",
                     len(analyzers), source, sorted(by_type))
            return len(analyzers)

    def _from_thehive(self) -> list:
        if not cfg.CORTEX_ENABLED:
            return []
        entries = []
        for item in thehive.cortex_analyzers():
            if not isinstance(item, dict):
                continue
            analyzer_id = str(item.get("id") or item.get("analyzerId") or "")
            name        = str(item.get("name") or analyzer_id)
            if not analyzer_id:
                continue
            cortex_ids = item.get("cortexIds") or []
            cortex_id  = str(cortex_ids[0]) if cortex_ids else ""
            datatypes  = item.get("dataTypeList") or item.get("dataTypes") or []
            entries.append((name, analyzer_id, cortex_id, [str(d) for d in datatypes]))
        return entries

    def _from_cortex(self) -> list:
        if not (cfg.CORTEX_ENABLED and cfg.CORTEX_APIKEY):
            if cfg.CORTEX_ENABLED and not cfg.CORTEX_APIKEY:
                log.warning("Cortex : CORTEX_APIKEY absente et TheHive ne liste aucun analyseur")
            return []
        try:
            r = requests.get(
                "{}/api/analyzer".format(cfg.CORTEX_URL.rstrip("/")),
                headers={"Authorization": "Bearer {}".format(cfg.CORTEX_APIKEY),
                         "Accept": "application/json"},
                timeout=15)
            if r.status_code != 200:
                log.warning("Cortex : HTTP %d sur /api/analyzer", r.status_code)
                return []
            payload = r.json()
        except (requests.RequestException, ValueError) as exc:
            log.warning("Cortex injoignable (%s) : %s", cfg.CORTEX_URL, exc)
            return []

        entries = []
        for item in payload if isinstance(payload, list) else []:
            analyzer_id = str(item.get("id") or "")
            name        = str(item.get("name") or analyzer_id)
            if not analyzer_id:
                continue
            datatypes = [str(d) for d in (item.get("dataTypeList") or [])]
            entries.append((name, analyzer_id, "", datatypes))
        return entries

    # ── consultation ─────────────────────────────────────────────
    def refresh_if_needed(self) -> None:
        if self.analyzers:
            return
        if time.time() - self._last_load >= self.REFRESH_SEC:
            log.info("Cortex : nouvelle tentative de découverte des analyseurs")
            self.load()

    def get_for(self, datatype: str) -> list:
        """Analyseurs applicables au type, triés par priorité."""
        available = list(self.by_type.get(datatype, []))
        if not available:
            # dernier recours : demander directement à TheHive pour ce type
            for item in thehive.cortex_analyzers_for(datatype):
                if not isinstance(item, dict):
                    continue
                analyzer_id = str(item.get("id") or "")
                if not analyzer_id:
                    continue
                cortex_ids = item.get("cortexIds") or []
                available.append((str(item.get("name") or analyzer_id),
                                  analyzer_id,
                                  str(cortex_ids[0]) if cortex_ids else ""))
        if not available:
            return []

        priority = self.PRIORITY.get(datatype, [])

        def rank(entry):
            for index, base in enumerate(priority):
                if entry[0].startswith(base):
                    return index
            return len(priority) + 1

        return sorted(available, key=rank)[:max(1, cfg.CORTEX_MAX_ANALYZERS)]


# ══════════════════════════════════════════════════════════════════
# CORTEX — exécution des jobs
# ══════════════════════════════════════════════════════════════════
LEVEL_ORDER = {"info": 0, "safe": 1, "suspicious": 2, "malicious": 3}
LEVEL_EMOJI = {"info": "🔵", "safe": "🟢", "suspicious": "🟡", "malicious": "🔴"}


def _parse_job_report(job: dict) -> dict:
    report = job.get("report")
    if isinstance(report, str):
        try:
            report = json.loads(report)
        except ValueError:
            report = {}
    if not isinstance(report, dict):
        report = {}
    taxonomies = (report.get("summary") or {}).get("taxonomies") or []
    verdicts   = ["{}/{}={}".format(t.get("namespace", "?"),
                                    t.get("predicate", "?"),
                                    t.get("value", "?"))
                  for t in taxonomies if isinstance(t, dict)]
    level = "info"
    for taxonomy in taxonomies:
        candidate = str(taxonomy.get("level", "info")).lower()
        if LEVEL_ORDER.get(candidate, 0) > LEVEL_ORDER.get(level, 0):
            level = candidate
    return {"verdicts": verdicts, "level": level,
            "error": report.get("errorMessage", "")}


def wait_cortex_job(job_id: str, timeout_sec: int) -> dict:
    """Attend la fin d'un job Cortex. Retourne un dict de statut."""
    deadline = time.time() + max(10, timeout_sec)
    delay    = 3
    while time.time() < deadline:
        job = thehive.get_cortex_job(job_id)
        if job is None:
            time.sleep(delay)
            continue
        status = str(job.get("status", ""))
        if status in ("Success", "Successful"):
            parsed = _parse_job_report(job)
            return {"status": "success", **parsed}
        if status in ("Failure", "Failed", "Deleted"):
            parsed = _parse_job_report(job)
            return {"status": "failure", "error": parsed.get("error") or status}
        time.sleep(delay)
        delay = min(delay + 2, 10)
    return {"status": "timeout"}


def launch_cortex_job(case_id: str, observable_id: str,
                      analyzer_id: str, cortex_id: str) -> str:
    """Lance un analyseur via les deux routes possibles de TheHive."""
    job_id = thehive.run_cortex_job(analyzer_id, observable_id, cortex_id)
    if job_id:
        return job_id
    return thehive.run_analyzer_on_observable(case_id, observable_id, analyzer_id)


# ══════════════════════════════════════════════════════════════════
# VIRUSTOTAL
# ══════════════════════════════════════════════════════════════════
class VT:
    BASE = "https://www.virustotal.com/api/v3"

    @classmethod
    def _get(cls, endpoint: str) -> dict:
        if not cfg.vt_ready:
            return {}
        try:
            r = requests.get("{}/{}".format(cls.BASE, endpoint),
                             headers={"x-apikey": cfg.VT_APIKEY},
                             timeout=cfg.VT_TIMEOUT)
            if r.status_code == 200:
                return r.json()
            if r.status_code == 429:
                log.warning("VT : quota atteint, pause de 60s")
                time.sleep(60)
            elif r.status_code != 404:
                log.warning("VT HTTP %d sur %s", r.status_code, endpoint)
        except (requests.RequestException, ValueError) as exc:
            log.error("VT : %s", exc)
        return {}

    @classmethod
    def _parse(cls, data: dict) -> dict:
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
        }

    @classmethod
    def check(cls, datatype: str, value: str) -> dict:
        endpoint = {"ip": "ip_addresses/{}", "hash": "files/{}",
                    "domain": "domains/{}"}.get(datatype)
        if not endpoint:
            return {}
        data = cls._get(endpoint.format(value))
        if not data:
            return {}
        result = cls._parse(data)
        result.update({"type": datatype, "value": value})
        if datatype == "hash":
            result["file_name"] = data.get("data", {}).get(
                "attributes", {}).get("meaningful_name", "")
        log.info("VT %s %s : mal=%d susp=%d total=%d rep=%d",
                 datatype, str(value)[:32], result["malicious"],
                 result["suspicious"], result["total"], result["reputation"])
        return result

    @classmethod
    def is_malicious(cls, result) -> bool:
        if not result:
            return False
        return (result.get("malicious", 0) >= cfg.VT_MIN_DETECTIONS
                or result.get("suspicious", 0) >= cfg.VT_MIN_DETECTIONS * 2
                or result.get("reputation", 0) <= -10)

    @classmethod
    def verdict(cls, result) -> str:
        if not result:
            return "⚪ Non indexé"
        mal = result.get("malicious", 0)
        sus = result.get("suspicious", 0)
        tot = result.get("total", 0)
        rep = result.get("reputation", 0)
        if cls.is_malicious(result):
            return "🔴 MALVEILLANT ({}/{} rep={})".format(mal, tot, rep)
        if sus > 0:
            return "🟡 Suspect ({}/{} rep={})".format(sus, tot, rep)
        if tot > 0:
            return "🟢 Propre (0/{} rep={})".format(tot, rep)
        return "⚪ Non indexé"

    @classmethod
    def summary_md(cls, result, target: str) -> str:
        if not result:
            return "⚪ `{}` — non indexé sur VirusTotal".format(target)
        return ("**VirusTotal** — `{}`\n"
                "- Verdict : {}\n"
                "- Détections : **{}/{}**\n"
                "- Réputation : {}\n"
                "- Pays : {} | AS : {}").format(
            target, cls.verdict(result),
            result.get("malicious", 0), result.get("total", 0),
            result.get("reputation", 0),
            result.get("country") or "N/A", result.get("as_owner") or "N/A")


# ══════════════════════════════════════════════════════════════════
# MISP
# ══════════════════════════════════════════════════════════════════
class MISP:
    TYPE_MAP = {"ip": "ip-dst", "domain": "domain", "hash": "md5",
                "url": "url", "other": "text"}

    @classmethod
    def _request(cls, path: str, payload=None):
        if not cfg.misp_ready:
            return None
        url = "{}{}".format(cfg.MISP_URL.rstrip("/"), path)
        try:
            fn = requests.post if payload is not None else requests.get
            kwargs = {
                "headers": {"Authorization": cfg.MISP_APIKEY,
                            "Content-Type": "application/json",
                            "Accept": "application/json"},
                "timeout": 12,
                "verify":  cfg.MISP_VERIFY_SSL,
            }
            if payload is not None:
                kwargs["json"] = payload
            r = fn(url, **kwargs)
            if r.status_code in (200, 201):
                return r.json()
            log.warning("MISP HTTP %d sur %s", r.status_code, path)
        except (requests.RequestException, ValueError) as exc:
            log.error("MISP : %s", exc)
        return None

    @classmethod
    def lookup(cls, value: str, datatype: str) -> bool:
        if not cfg.misp_ready:
            return False
        data = cls._request("/attributes/restSearch",
                            {"value": value, "limit": 1})
        if not isinstance(data, dict):
            return False
        attributes = (data.get("response") or {}).get("Attribute") or []
        if attributes:
            log.info("MISP hit : %s", value)
            return True
        return False

    @classmethod
    def push(cls, value: str, datatype: str, info: str = "") -> bool:
        if not cfg.misp_ready:
            return False
        data = cls._request("/events", {"Event": {
            "info":            "SOC Auto — {}".format(info or value),
            "distribution":    0,
            "threat_level_id": 1,
            "analysis":        1,
            "Attribute": [{
                "type":     cls.TYPE_MAP.get(datatype, "text"),
                "category": "Network activity",
                "value":    value,
                "to_ids":   True,
            }],
        }})
        if data:
            log.info("MISP push OK : %s", value)
            return True
        return False


# ══════════════════════════════════════════════════════════════════
# FIREWALL
# ══════════════════════════════════════════════════════════════════
IS_WINDOWS = os.name == "nt"


def has_admin_rights() -> bool:
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:                     # noqa: BLE001 — API Windows capricieuse
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


class Firewall:
    """Blocage IP : netsh advfirewall (Windows) ou iptables (Linux)."""

    @staticmethod
    def _rule_name(ip: str, direction: str) -> str:
        return "SOC_BLOCK_{}_{}".format(ip.replace(".", "_").replace(":", "_"), direction)

    @staticmethod
    def _run(cmd: list, timeout: int = 15):
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError:
            log.error("Commande introuvable : %s", cmd[0])
        except subprocess.TimeoutExpired:
            log.error("Timeout sur : %s", " ".join(cmd))
        except OSError as exc:
            log.error("Erreur d'exécution %s : %s", cmd[0], exc)
        return None

    @classmethod
    def block(cls, ip: str) -> bool:
        if IS_WINDOWS:
            return cls._block_windows(ip)
        return cls._block_linux(ip)

    @classmethod
    def unblock(cls, ip: str) -> bool:
        if IS_WINDOWS:
            return cls._unblock_windows(ip)
        return cls._unblock_linux(ip)

    # ── Windows ──────────────────────────────────────────────────
    @classmethod
    def _block_windows(cls, ip: str) -> bool:
        ok = True
        for direction in ("in", "out"):
            name = cls._rule_name(ip, direction.upper())
            cls._run(["netsh", "advfirewall", "firewall", "delete", "rule",
                      "name={}".format(name)])
            result = cls._run(["netsh", "advfirewall", "firewall", "add", "rule",
                               "name={}".format(name), "dir={}".format(direction),
                               "action=block", "remoteip={}".format(ip),
                               "enable=yes", "profile=any"])
            if result is None or result.returncode != 0:
                detail = (result.stdout or result.stderr or "").strip()[:150] if result else "-"
                log.error("netsh %s a échoué pour %s : %s", direction, ip, detail)
                ok = False
            else:
                log.info("Firewall : %s bloquée (%s)", ip, direction.upper())
        return ok

    @classmethod
    def _unblock_windows(cls, ip: str) -> bool:
        ok = True
        for direction in ("IN", "OUT"):
            result = cls._run(["netsh", "advfirewall", "firewall", "delete", "rule",
                               "name={}".format(cls._rule_name(ip, direction))])
            if result is None:
                ok = False
        return ok

    # ── Linux ────────────────────────────────────────────────────
    @classmethod
    def _block_linux(cls, ip: str) -> bool:
        binary = "ip6tables" if ":" in ip else "iptables"
        ok = True
        for chain, flag in (("INPUT", "-s"), ("OUTPUT", "-d")):
            # -C teste si la règle existe déjà : on évite les doublons
            check = cls._run([binary, "-C", chain, flag, ip, "-j", "DROP"])
            if check is not None and check.returncode == 0:
                continue
            result = cls._run([binary, "-I", chain, "1", flag, ip, "-j", "DROP"])
            if result is None or result.returncode != 0:
                detail = (result.stderr or "").strip()[:150] if result else "commande absente"
                log.error("%s %s a échoué pour %s : %s", binary, chain, ip, detail)
                ok = False
            else:
                log.info("Firewall : %s bloquée (%s)", ip, chain)
        return ok

    @classmethod
    def _unblock_linux(cls, ip: str) -> bool:
        binary = "ip6tables" if ":" in ip else "iptables"
        ok = True
        for chain, flag in (("INPUT", "-s"), ("OUTPUT", "-d")):
            # boucle : la règle peut avoir été insérée plusieurs fois
            for _ in range(5):
                result = cls._run([binary, "-D", chain, flag, ip, "-j", "DROP"])
                if result is None or result.returncode != 0:
                    break
            else:
                ok = False
        return ok


# ══════════════════════════════════════════════════════════════════
# BLACKLIST — blocages avec déblocage automatique
# ══════════════════════════════════════════════════════════════════
class BlacklistManager:

    def __init__(self):
        self._blocked = {}                     # {ip: {blocked_at, reason, timer}}
        self._lock    = threading.RLock()
        self.admin    = has_admin_rights()
        self._log_privileges()
        self._restore()

    def _log_privileges(self) -> None:
        if not cfg.ACTIVE_RESPONSE:
            log.warning("Mode SIMULATION — ACTIVE_RESPONSE=false, aucune IP ne sera bloquée")
            return
        if self.admin:
            log.info("Privilèges OK — blocage firewall réel actif (%s)",
                     "netsh" if IS_WINDOWS else "iptables")
        elif IS_WINDOWS:
            log.error("ACTIVE_RESPONSE=true mais PowerShell n'est pas Administrateur "
                      "— le blocage échouera")
        else:
            log.error("ACTIVE_RESPONSE=true mais le service ne tourne pas en root "
                      "— relancer avec sudo")

    # ── persistance ──────────────────────────────────────────────
    def _restore(self) -> None:
        path = cfg.BLACKLIST_JSON
        if not path.exists():
            return
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            log.error("Blacklist illisible (%s) : %s", path, exc)
            return

        now = datetime.now()
        for ip, info in (data or {}).items():
            try:
                blocked_at = datetime.fromisoformat(info["blocked_at"])
            except (KeyError, TypeError, ValueError):
                continue
            remaining = cfg.BLOCK_DURATION_MIN - (now - blocked_at).total_seconds() / 60
            if remaining <= 0:
                if cfg.ACTIVE_RESPONSE:
                    Firewall.unblock(ip)
                continue
            # En simulation on ne repose AUCUNE règle firewall : on garde
            # simplement la trace pour que le rapport reste cohérent.
            if cfg.ACTIVE_RESPONSE and self.admin:
                Firewall.block(ip)
            timer = threading.Timer(remaining * 60, self._expire, args=[ip])
            timer.daemon = True
            timer.start()
            self._blocked[ip] = {"blocked_at": blocked_at,
                                 "reason": info.get("reason", "?"),
                                 "timer": timer}
            log.info("IP %s restaurée depuis la blacklist (%.1f min restantes)", ip, remaining)
        self._save()

    def _save(self) -> None:
        try:
            with open(cfg.BLACKLIST_JSON, "w", encoding="utf-8") as fh:
                json.dump({ip: {"blocked_at": info["blocked_at"].isoformat(),
                                "reason": info["reason"]}
                           for ip, info in self._blocked.items()}, fh, indent=2)
            with open(cfg.BLACKLIST_FILE, "w", encoding="utf-8") as fh:
                fh.write("# IPs bloquées — SOC Pipeline v{}\n".format(VERSION))
                fh.write("# ip | bloquée le | raison | expire\n\n")
                for ip, info in self._blocked.items():
                    expires = info["blocked_at"] + timedelta(minutes=cfg.BLOCK_DURATION_MIN)
                    fh.write("{} | {} | {} | expire {}\n".format(
                        ip, info["blocked_at"].strftime("%Y-%m-%d %H:%M:%S"),
                        info["reason"], expires.strftime("%H:%M:%S")))
        except OSError as exc:
            log.error("Écriture blacklist impossible : %s", exc)

    # ── actions ──────────────────────────────────────────────────
    def _expire(self, ip: str) -> None:
        with self._lock:
            info = self._blocked.pop(ip, None)
            if info is None:
                return
            if cfg.ACTIVE_RESPONSE:
                Firewall.unblock(ip)
            self._save()
        log.info("%s débloquée automatiquement après %d min", ip, cfg.BLOCK_DURATION_MIN)
        notify("✅ <b>IP débloquée — timer</b>\nIP : <code>{}</code>\nDurée : {} min\n"
               "Raison initiale : {}".format(ip, cfg.BLOCK_DURATION_MIN,
                                             info.get("reason", "?")))

    def block(self, ip: str, reason: str = "menace") -> dict:
        with self._lock:
            if ip in self._blocked:
                expires = self._blocked[ip]["blocked_at"] + timedelta(
                    minutes=cfg.BLOCK_DURATION_MIN)
                return {"success": False, "already_blocked": True,
                        "expires_at": expires.strftime("%H:%M:%S")}

            if not cfg.ACTIVE_RESPONSE:
                log.warning("SIMULATION : %s SERAIT bloquée (%s)", ip, reason)
                return {"success": False, "dry_run": True}

            if not self.admin:
                log.error("Blocage impossible pour %s : privilèges insuffisants", ip)
                return {"success": False,
                        "error": "admin/root requis" if not IS_WINDOWS
                                 else "PowerShell Administrateur requis"}

            if not Firewall.block(ip):
                log.error("Le firewall a refusé la règle pour %s", ip)
                return {"success": False, "error": "règle firewall refusée"}

            now     = datetime.now()
            expires = now + timedelta(minutes=cfg.BLOCK_DURATION_MIN)
            timer   = threading.Timer(cfg.BLOCK_DURATION_MIN * 60, self._expire, args=[ip])
            timer.daemon = True
            timer.start()
            self._blocked[ip] = {"blocked_at": now, "reason": reason, "timer": timer}
            self._save()
            log.warning("BLOQUÉ : %s | %s | expire %s",
                        ip, reason, expires.strftime("%H:%M:%S"))
            return {"success": True,
                    "blocked_at": now.strftime("%H:%M:%S"),
                    "expires_at": expires.strftime("%H:%M:%S")}

    def unblock(self, ip: str) -> bool:
        with self._lock:
            info = self._blocked.pop(ip, None)
            if info is None:
                # on tente quand même de retirer une règle orpheline
                if cfg.ACTIVE_RESPONSE and self.admin:
                    Firewall.unblock(ip)
                return False
            timer = info.get("timer")
            if timer:
                timer.cancel()
            if cfg.ACTIVE_RESPONSE:
                Firewall.unblock(ip)
            self._save()
        log.info("%s débloquée manuellement", ip)
        return True

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._blocked

    def info(self, ip: str) -> dict:
        with self._lock:
            return dict(self._blocked.get(ip, {}))

    def list_blocked(self) -> list:
        with self._lock:
            now = datetime.now()
            return [{
                "ip":            ip,
                "reason":        info["reason"],
                "blocked_at":    info["blocked_at"].strftime("%Y-%m-%d %H:%M:%S"),
                "remaining_min": round(max(0.0, cfg.BLOCK_DURATION_MIN
                                           - (now - info["blocked_at"]).total_seconds() / 60), 1),
                "expires_at":    (info["blocked_at"] + timedelta(
                    minutes=cfg.BLOCK_DURATION_MIN)).strftime("%H:%M:%S"),
            } for ip, info in self._blocked.items()]


# ══════════════════════════════════════════════════════════════════
# ÉTAT (alertes déjà traitées)
# ══════════════════════════════════════════════════════════════════
class StateManager:
    MAX_ENTRIES = 20000

    def __init__(self):
        self.path  = cfg.STATE_FILE
        self._lock = threading.Lock()
        self._data = self._load()

    def _load(self) -> dict:
        if self.path.exists():
            try:
                with open(self.path, encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, dict):
                    return data
            except (OSError, ValueError) as exc:
                log.warning("État illisible (%s) : %s — repart de zéro", self.path, exc)
        return {"processed_alerts": [], "processed_cases": []}

    def _save(self) -> None:
        try:
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=2)
            tmp.replace(self.path)
        except OSError as exc:
            log.error("Sauvegarde de l'état impossible : %s", exc)

    def is_done(self, entity_id: str, kind: str = "alert") -> bool:
        with self._lock:
            return entity_id in self._data.get("processed_{}s".format(kind), [])

    def mark_done(self, entity_id: str, kind: str = "alert") -> None:
        key = "processed_{}s".format(kind)
        with self._lock:
            bucket = self._data.setdefault(key, [])
            if entity_id in bucket:
                return
            bucket.append(entity_id)
            del bucket[:-self.MAX_ENTRIES]
            self._save()

    def unmark(self, entity_id: str, kind: str = "alert") -> None:
        key = "processed_{}s".format(kind)
        with self._lock:
            bucket = self._data.get(key, [])
            if entity_id in bucket:
                bucket.remove(entity_id)
                self._save()


# ══════════════════════════════════════════════════════════════════
# UTILITAIRES
# ══════════════════════════════════════════════════════════════════
HASH_RE = re.compile(r"\b([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b")
IP_RE   = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# ── Catégories de menaces déclenchant une réponse active ──────────
# clé = catégorie, valeur = (tags TheHive, mots-clés du titre/description)
THREAT_CATEGORIES = {
    "brute_force": (
        ["brute_force", "brute-force", "bruteforce", "failed_auth", "ssh"],
        ["brute", "failed password", "failed login", "invalid user",
         "authentication failure", "unauthorized", "4625"],
    ),
    "port_scan": (
        ["port_scan", "portscan", "recon", "scan"],
        ["port scan", "portscan", "nmap", "masscan", "zmap", "-ss", "-st",
         "-sa", "-sx", "-su", "attempted-recon", "scan frag", "sweep"],
    ),
    "exploitation": (
        ["exploit", "trojan-activity", "shellcode", "metasploit"],
        ["metasploit", "meterpreter", "reverse shell", "shell m-sploit",
         "exploit", "payload", "4444", "cve-"],
    ),
    "lateral_movement": (
        ["lateral_movement", "smb_attack", "rdp"],
        ["lateral", "psexec", "wmic", "winrm", "pass the hash", "pass-the-hash"],
    ),
    "credential_dumping": (
        ["credential_dumping"],
        ["mimikatz", "lsass", "pwdump", "secretsdump", "ntds.dit"],
    ),
    "ransomware": (
        ["ransomware"],
        ["ransom", "vssadmin delete", "wbadmin delete", "shadowcopy"],
    ),
    "malware": (
        ["malicious_download", "vt-malicious", "misp-hit", "malware"],
        ["malware", "malicious", "c2", "command and control", "botnet", "trojan"],
    ),
    "exfiltration": (
        ["exfiltration", "dlp"],
        ["exfil", "data leak", "large upload"],
    ),
    "privilege_escalation": (
        ["privilege_escalation"],
        ["privilege escalation", "escalat", "4672"],
    ),
}


def detect_threats(title: str, tags, description: str = "") -> list:
    """Catégories de menace détectées dans une alerte TheHive.

    On combine les tags posés par le Service A (issus des règles Splunk /
    Suricata) et une recherche par mots-clés dans le titre et la description.
    """
    normalized_tags = {str(tag).strip().lower() for tag in (tags or [])}
    haystack        = "{} {}".format(title or "", description or "").lower()
    found           = []
    for category, (category_tags, keywords) in THREAT_CATEGORIES.items():
        if normalized_tags.intersection(category_tags) or any(
                keyword in haystack for keyword in keywords):
            found.append(category)
    return found


def is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def is_public_ip(value: str) -> bool:
    """IP routable sur Internet — analysable par Cortex / VirusTotal / AbuseIPDB."""
    try:
        addr = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


def _is_junk_ip(value: str) -> bool:
    """Adresse jamais exploitable : multicast, broadcast, réservée, 0.0.0.0…"""
    try:
        addr = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return True
    return (addr.is_multicast or addr.is_reserved
            or addr.is_unspecified or addr.is_link_local)


def _observable_values(observables, datatypes) -> list:
    values = []
    for obs in observables or []:
        if not isinstance(obs, dict):
            continue
        if str(obs.get("dataType", "")).lower() in datatypes:
            value = str(obs.get("data", "")).strip()
            if value and value not in values:
                values.append(value)
    return values


def extract_ips(alert_data: dict, observables: list) -> list:
    ips = _observable_values(observables, {"ip"})
    for artifact in alert_data.get("artifacts") or []:
        if isinstance(artifact, dict) and str(artifact.get("dataType", "")).lower() == "ip":
            value = str(artifact.get("data", "")).strip()
            if value and value not in ips:
                ips.append(value)
    if not ips:
        for candidate in IP_RE.findall(str(alert_data.get("description", ""))):
            if is_valid_ip(candidate) and candidate not in ips:
                ips.append(candidate)
    # On garde les IP privées (utile pour BLOCK_ALL_IPS en lab) mais on écarte
    # multicast / broadcast / réservées qui ne font que des jobs Cortex en échec.
    return [ip for ip in ips if is_valid_ip(ip) and not _is_junk_ip(ip)]


def extract_hashes(alert_data: dict, observables: list) -> list:
    hashes = _observable_values(observables, {"hash", "md5", "sha1", "sha256"})
    for candidate in HASH_RE.findall(str(alert_data.get("description", ""))):
        if candidate not in hashes:
            hashes.append(candidate)
    return hashes


def extract_domains(alert_data: dict, observables: list) -> list:
    return _observable_values(observables, {"domain", "fqdn"})


# ══════════════════════════════════════════════════════════════════
# INSTANCES GLOBALES
# ══════════════════════════════════════════════════════════════════
cortex_registry = CortexRegistry()
blacklist       = BlacklistManager()
state           = StateManager()
file_responder  = FileResponder(
    enabled=cfg.FILE_RESPONSE_ENABLED,
    mode=cfg.FILE_RESPONSE_MODE,
    scan_paths=cfg.FILE_SCAN_PATHS,
    quarantine_dir=cfg.QUARANTINE_DIR,
    max_size_mb=cfg.FILE_MAX_SIZE_MB,
    max_files=cfg.FILE_MAX_FILES,
    logger=log,
    notifier=notify,
)

for _path, _why in file_responder.rejected_paths:
    log.error("FILE_SCAN_PATHS : « %s » refusé — %s", _path, _why)
if cfg.FILE_RESPONSE_ENABLED and not file_responder.ready:
    log.error("FILE_RESPONSE_ENABLED=true mais aucun dossier valide à analyser "
              "— renseigner FILE_SCAN_PATHS dans .env")


# ══════════════════════════════════════════════════════════════════
# PROCESSEUR D'ALERTE — le cœur du pipeline
# ══════════════════════════════════════════════════════════════════
class AlertProcessor:

    def process(self, alert_data: dict) -> None:
        alert_id = thehive_id(alert_data)
        title    = str(alert_data.get("title") or "Alerte Splunk")
        severity = int(alert_data.get("severity") or 2)
        tags     = [str(t) for t in (alert_data.get("tags") or [])]

        log.info("═" * 60)
        log.info("ALERTE %s [sev=%d] : %s", alert_id, severity, title[:70])

        observables_raw = thehive.alert_observables(alert_id)
        if not observables_raw:
            observables_raw = alert_data.get("artifacts") or alert_data.get("observables") or []
        ips     = extract_ips(alert_data, observables_raw)
        hashes  = extract_hashes(alert_data, observables_raw)
        domains = extract_domains(alert_data, observables_raw)
        log.info("Observables — IPs=%s | hashes=%s | domaines=%s", ips, hashes, domains)

        threats        = detect_threats(title, tags, str(alert_data.get("description", "")))
        is_brute_force = "brute_force" in threats
        if threats:
            log.info("Menaces détectées : %s", ", ".join(threats))

        # ── 1. Promotion alerte → cas ────────────────────────────
        case = self._promote(alert_id, title, alert_data)
        if not case:
            log.error("Échec de la promotion de l'alerte %s en cas", alert_id)
            notify("❌ <b>Cas non créé</b>\n{}\nAlerte : <code>{}</code>".format(
                title[:70], alert_id))
            state.unmark(alert_id, "alert")     # on retentera au prochain cycle
            return

        case_id  = thehive_id(case)
        case_num = case.get("number", case.get("caseId", "?"))
        log.info("Cas #%s créé (id=%s)", case_num, case_id)

        thehive.set_alert_status(alert_id, "InProgress")
        thehive.add_tag(case_id, "auto-processed")
        for category in threats:
            thehive.add_tag(case_id, category)

        notify("📁 <b>Cas #{}</b> créé\n{}\nIP : <code>{}</code>\n"
               "<a href=\"{}/cases/{}/details\">→ ouvrir dans TheHive</a>".format(
                   case_num, title[:80], ips[0] if ips else "N/A",
                   cfg.THEHIVE_URL.rstrip("/"), case_id))

        # ── 2. Traitement de chaque observable ───────────────────
        cortex_registry.refresh_if_needed()
        vt_results, misp_hits, blocked_ips, actions = {}, [], [], []
        cortex_threads, malicious_hashes = [], []

        targets = ([("ip", ip) for ip in ips]
                   + [("hash", h) for h in hashes]
                   + [("domain", d) for d in domains])

        for datatype, value in targets:
            log.info("── Observable [%s] %s", datatype, value)

            obs_id = self._add_observable(case_id, datatype, value,
                                          alert_id, is_brute_force)

            # 2a. Cortex — lancé en premier pour que les analyseurs
            #     travaillent pendant les appels VT / MISP
            thread = self._start_cortex(case_id, case_num, obs_id, datatype, value, actions)
            if thread:
                cortex_threads.append(thread)

            # 2b. VirusTotal
            vt = self._run_virustotal(case_id, case_num, datatype, value, actions)
            if vt:
                vt_results[value] = vt

            # 2c. MISP
            misp_type = {"ip": "ip", "hash": "hash", "domain": "domain"}.get(datatype, "other")
            if MISP.lookup(value, misp_type):
                misp_hits.append(value)
                actions.append("🌐 MISP HIT : {}".format(value))
                thehive.add_tag(case_id, "misp-hit")
                thehive.add_comment(case_id,
                                    "### 🌐 MISP — IoC connu\n\n"
                                    "**`{}`** est déjà présent dans MISP (type `{}`).\n\n"
                                    "*SOC Pipeline v{}*".format(value, misp_type, VERSION))
                notify("🌐 <b>MISP HIT</b>\nValeur : <code>{}</code>\nType : {}\n"
                       "Cas : #{}".format(value, misp_type, case_num))
            elif vt and VT.is_malicious(vt):
                if MISP.push(value, misp_type,
                             info="Cas #{} — {}".format(case_num, title[:40])):
                    actions.append("🌐 MISP : IoC publié ({})".format(value))

            # 2d. Blocage firewall
            if datatype == "ip":
                self._maybe_block(case_id, case_num, value, severity, threats,
                                  vt_results, misp_hits, blocked_ips, actions)

            # 2e. Hash confirmé malveillant → réponse sur le fichier
            if datatype == "hash" and (VT.is_malicious(vt) or value in misp_hits):
                malicious_hashes.append(value)

        # ── 2f. Recherche et neutralisation des fichiers ─────────
        if malicious_hashes:
            thehive.add_tag(case_id, "malicious-file")
            self._start_file_response(case_id, case_num, malicious_hashes, actions)

        # ── 3. Rapport ───────────────────────────────────────────
        self._write_summary(case_id, case_num, alert_id, title, ips, hashes, domains,
                            blocked_ips, misp_hits, vt_results, actions, threats)

        confirmed = bool(blocked_ips or misp_hits
                         or any(VT.is_malicious(v) for v in vt_results.values()))
        if confirmed:
            # Menace confirmée : on remonte la sévérité du cas et on le passe en cours
            thehive.update_case(case_id, {"status": "InProgress",
                                          "severity": max(severity, 3)})
            thehive.add_tag(case_id, "confirmed-malicious")

        log.info("═══ TERMINÉ %s → cas #%s | bloquées=%s | analyseurs Cortex en cours=%d",
                 alert_id, case_num, blocked_ips or "aucune", len(cortex_threads))

    # ── promotion ────────────────────────────────────────────────
    @staticmethod
    def _promote(alert_id: str, title: str, alert_data: dict):
        case = thehive.promote_alert(alert_id)
        if case:
            return case
        log.warning("Promotion native indisponible — création manuelle du cas")
        case = thehive.create_case({
            "title":       title,
            "description": alert_data.get("description") or "Depuis l'alerte {}".format(alert_id),
            "severity":    alert_data.get("severity", 2),
            "tags":        sorted(set(list(alert_data.get("tags") or [])
                                      + ["auto-promoted", "from-splunk"])),
            "tlp": 2, "pap": 2,
        })
        if case:
            thehive.merge_alert_into_case(alert_id, thehive_id(case))
        return case

    # ── observable ───────────────────────────────────────────────
    @staticmethod
    def _add_observable(case_id, datatype, value, alert_id, is_brute_force) -> str:
        tags = ["auto-added", datatype]
        if datatype == "ip" and is_internal(value):
            tags.append("internal-ip")
        if datatype == "ip" and is_brute_force:
            tags.append("brute-force-source")
        obs_id = thehive.add_observable(case_id, Observable(
            dataType=datatype, data=value,
            message="Détecté dans l'alerte Splunk {}".format(alert_id),
            tags=tags, ioc=True))
        if not obs_id:
            # Déjà recopié depuis l'alerte lors de la promotion : on récupère
            # son id existant pour pouvoir quand même lancer Cortex dessus.
            obs_id = thehive.find_case_observable(case_id, datatype, value)
        if obs_id:
            log.info("Observable au cas : [%s] %s (id=%s)", datatype, value, obs_id)
        else:
            log.warning("Observable introuvable sur le cas : [%s] %s", datatype, value)
        return obs_id

    # ── cortex ───────────────────────────────────────────────────
    @staticmethod
    def _start_cortex(case_id, case_num, obs_id, datatype, value, actions):
        if not (cfg.CORTEX_ENABLED and obs_id):
            return None
        if datatype == "ip" and not is_public_ip(value):
            log.info("Cortex ignoré pour %s (IP non publique)", value)
            actions.append("Cortex ignoré pour {} (IP non publique)".format(value))
            return None
        analyzers = cortex_registry.get_for(datatype)
        if not analyzers:
            log.warning("Cortex : aucun analyseur disponible pour le type '%s'", datatype)
            return None

        log.info("Cortex : lancement de %d analyseur(s) sur [%s] %s",
                 len(analyzers), datatype, value)
        thehive.add_tag(case_id, "cortex-running")
        actions.append("🔬 Cortex : {} analyseur(s) sur {}".format(len(analyzers), value))

        def _worker():
            lines   = ["### 🔬 Cortex — `{}`\n".format(value)]
            worst   = "info"
            started = 0
            for name, analyzer_id, cortex_id in analyzers:
                job_id = launch_cortex_job(case_id, obs_id, analyzer_id, cortex_id)
                if not job_id:
                    lines.append("- **{}** : ❌ lancement impossible".format(name))
                    continue
                started += 1
                result = wait_cortex_job(job_id, cfg.CORTEX_JOB_TIMEOUT)
                status = result.get("status")
                if status == "success":
                    level    = result.get("level", "info")
                    verdicts = result.get("verdicts") or ["OK"]
                    emoji    = LEVEL_EMOJI.get(level, "⚪")
                    lines.append("- **{}** : {} {}".format(name, emoji, " | ".join(verdicts)))
                    if LEVEL_ORDER.get(level, 0) > LEVEL_ORDER.get(worst, 0):
                        worst = level
                    notify("{} <b>Cortex — {}</b>\nCible : <code>{}</code>\n"
                           "Verdict : {}\nCas : #{}".format(
                               emoji, name, value, " | ".join(verdicts), case_num))
                elif status == "failure":
                    lines.append("- **{}** : ❌ {}".format(
                        name, str(result.get("error", "erreur"))[:80]))
                else:
                    lines.append("- **{}** : ⏱ timeout ({}s)".format(
                        name, cfg.CORTEX_JOB_TIMEOUT))
                time.sleep(0.5)

            if worst == "malicious":
                thehive.add_tag(case_id, "cortex-malicious")
            elif worst == "suspicious":
                thehive.add_tag(case_id, "cortex-suspicious")
            lines.append("\n*{} analyseur(s) lancé(s) — SOC Pipeline v{}*".format(started, VERSION))
            thehive.add_comment(case_id, "\n".join(lines))

        thread = threading.Thread(target=_worker, daemon=True,
                                  name="cortex-{}".format(str(value)[:20]))
        thread.start()
        return thread

    # ── virustotal ───────────────────────────────────────────────
    @staticmethod
    def _run_virustotal(case_id, case_num, datatype, value, actions):
        if not cfg.vt_ready:
            return {}
        if datatype == "ip" and is_internal(value):
            actions.append("VT ignoré pour {} (IP privée)".format(value))
            return {}

        vt = VT.check(datatype, value)
        time.sleep(0.5)                      # quota gratuit : 4 requêtes/minute
        if not vt:
            return {}

        actions.append("VT {} → {}".format(value, VT.verdict(vt)))
        thehive.add_comment(case_id,
                            "### 🦠 VirusTotal — `{}`\n\n{}\n\n*SOC Pipeline v{}*".format(
                                value, VT.summary_md(vt, value), VERSION))
        emoji = ("🔴" if VT.is_malicious(vt)
                 else "🟡" if vt.get("suspicious", 0) > 0 else "🟢")
        notify("{} <b>VirusTotal</b>\nCible : <code>{}</code>\nDétections : {}/{}\n"
               "Réputation : {}\nCas : #{}".format(
                   emoji, value, vt.get("malicious", 0), vt.get("total", 0),
                   vt.get("reputation", 0), case_num))
        if VT.is_malicious(vt):
            thehive.add_tag(case_id, "vt-malicious")
        return vt

    # ── blocage ──────────────────────────────────────────────────
    @staticmethod
    def _block_reasons(ip, threats, vt_results, misp_hits) -> list:
        """Raisons justifiant le blocage de cette IP (liste vide = on ne bloque pas)."""
        reasons = []
        if "brute_force" in threats and cfg.BLOCK_ON_BRUTEFORCE:
            reasons.append("brute force")
        if "port_scan" in threats and cfg.BLOCK_ON_PORTSCAN:
            reasons.append("scan de ports")
        if cfg.BLOCK_ON_THREAT:
            for category in threats:
                if category not in ("brute_force", "port_scan"):
                    reasons.append(category.replace("_", " "))
        if VT.is_malicious(vt_results.get(ip, {})):
            vt = vt_results[ip]
            reasons.append("VirusTotal {}/{}".format(
                vt.get("malicious", 0), vt.get("total", 0)))
        if ip in misp_hits:
            reasons.append("MISP hit")
        return reasons

    @classmethod
    def _maybe_block(cls, case_id, case_num, ip, severity, threats,
                     vt_results, misp_hits, blocked_ips, actions):
        if blacklist.is_blocked(ip):
            actions.append("⏳ Déjà bloquée : {}".format(ip))
            return
        if is_internal(ip) and not cfg.BLOCK_ALL_IPS:
            actions.append("🏠 {} interne — blocage ignoré (BLOCK_ALL_IPS=false)".format(ip))
            return

        reasons = cls._block_reasons(ip, threats, vt_results, misp_hits)
        if not reasons:
            return
        if severity < cfg.RESPONSE_MIN_SEV:
            actions.append("↩️ {} : sévérité {} < RESPONSE_MIN_SEV={} — pas de blocage".format(
                ip, severity, cfg.RESPONSE_MIN_SEV))
            return
        reason = " | ".join(dict.fromkeys(reasons))

        result = blacklist.block(ip, reason)
        if result.get("success"):
            blocked_ips.append(ip)
            expires = result["expires_at"]
            actions.append("🚫 BLOQUÉE {}min : {} → expire {}".format(
                cfg.BLOCK_DURATION_MIN, ip, expires))
            thehive.add_tag(case_id, "ip-blocked")
            thehive.add_comment(case_id,
                                "### 🚫 IP bloquée — `{}`\n\n"
                                "- **Raison** : {}\n- **Durée** : {} min\n"
                                "- **Expire à** : {}\n\n"
                                "Déblocage manuel :\n```\npython start.py unblock {}\n```\n\n"
                                "*SOC Pipeline v{}*".format(
                                    ip, reason, cfg.BLOCK_DURATION_MIN,
                                    expires, ip, VERSION))
            notify("🚫 <b>IP BLOQUÉE — {} min</b>\nIP : <code>{}</code>\nRaison : {}\n"
                   "Expire : {}\nCas : #{}".format(
                       cfg.BLOCK_DURATION_MIN, ip, reason, expires, case_num))
        elif result.get("dry_run"):
            actions.append("⚠️ SIMULATION : {} ({})".format(ip, reason))
            notify("⚠️ <b>SIMULATION</b> — <code>{}</code> serait bloquée\n"
                   "Raison : {}\nCas : #{}\n"
                   "<i>ACTIVE_RESPONSE=true dans .env pour un blocage réel</i>".format(
                       ip, reason, case_num))
        elif result.get("already_blocked"):
            actions.append("⏳ Déjà bloquée : {}".format(ip))
        else:
            error = result.get("error", "inconnue")
            actions.append("❌ Blocage échoué pour {} : {}".format(ip, error))
            notify("❌ <b>Blocage impossible</b>\nIP : <code>{}</code>\n{}".format(ip, error))

    # ── réponse sur fichiers ─────────────────────────────────────
    @staticmethod
    def _start_file_response(case_id, case_num, hashes, actions):
        """Cherche les fichiers correspondant aux hashes malveillants confirmés.

        L'analyse disque peut durer : elle tourne en tâche de fond et publie
        son résultat dans un commentaire dédié du cas.
        """
        if not file_responder.enabled:
            actions.append("📁 {} hash(es) malveillant(s) — réponse fichier désactivée "
                           "(FILE_RESPONSE_ENABLED=false)".format(len(hashes)))
            return None
        if not file_responder.ready:
            actions.append("📁 Réponse fichier active mais aucun dossier valide "
                           "dans FILE_SCAN_PATHS")
            return None

        actions.append("📁 Recherche de {} hash(es) sur {} dossier(s) — mode {}".format(
            len(hashes), len(file_responder.scan_paths), file_responder.mode))

        def _worker():
            reason = "hash confirmé malveillant — cas #{}".format(case_num)
            try:
                results = file_responder.respond(hashes, reason=reason)
            except Exception as exc:      # noqa: BLE001 — ne doit jamais tuer le service
                log.exception("Réponse fichier en échec : %s", exc)
                thehive.add_comment(case_id,
                                    "### 📁 Réponse sur fichiers\n\n"
                                    "❌ Analyse interrompue : `{}`".format(exc))
                return

            if not results:
                thehive.add_comment(
                    case_id,
                    "### 📁 Réponse sur fichiers\n\n"
                    "Aucun fichier correspondant aux hashes suivants n'a été trouvé "
                    "dans les dossiers surveillés :\n\n{}\n\n"
                    "Dossiers analysés : {}\n\n*SOC Pipeline v{}*".format(
                        "\n".join("- `{}`".format(h) for h in hashes),
                        ", ".join("`{}`".format(p) for p in file_responder.scan_paths),
                        VERSION))
                return

            neutralized = [r for r in results if r.get("success")
                           and r.get("action") in ("quarantine", "delete")]
            if neutralized:
                thehive.add_tag(case_id, "file-neutralized")
            thehive.add_comment(case_id, "{}\n\n*SOC Pipeline v{}*".format(
                file_responder.summary_md(results), VERSION))
            log.warning("Réponse fichier terminée : %d action(s), %d neutralisation(s)",
                        len(results), len(neutralized))

        thread = threading.Thread(target=_worker, daemon=True,
                                  name="file-response-{}".format(case_num))
        thread.start()
        return thread

    # ── rapport ──────────────────────────────────────────────────
    @staticmethod
    def _write_summary(case_id, case_num, alert_id, title, ips, hashes, domains,
                       blocked, misp_hits, vt_results, actions, threats):
        is_brute_force = "brute_force" in threats
        lines = [
            "## 🤖 SOC Pipeline v{} — Rapport automatique".format(VERSION), "",
            "| Champ | Valeur |", "|-------|--------|",
            "| **Date** | {} |".format(now_str()),
            "| **Alerte** | `{}` |".format(alert_id),
            "| **Cas** | #{} |".format(case_num),
            "| **Menaces détectées** | {} |".format(
                ", ".join("🔴 " + t.replace("_", " ") for t in threats)
                if threats else "🟢 aucune catégorie connue"),
            "| **Réponse active** | {} |".format(
                "🔴 Oui (blocage réel)" if cfg.ACTIVE_RESPONSE else "⚠️ Simulation"),
            "| **Cortex** | {} analyseur(s) chargé(s) via {} |".format(
                len(cortex_registry.analyzers), cortex_registry.source),
            "",
        ]

        if ips:
            lines += ["### 🌐 Adresses IP",
                      "| IP | Portée | VirusTotal | MISP | Blocage |",
                      "|----|--------|-----------|------|---------|"]
            for ip in ips:
                vt = vt_results.get(ip, {})
                if ip in blocked:
                    block_state = "🚫 {} min".format(cfg.BLOCK_DURATION_MIN)
                elif not cfg.ACTIVE_RESPONSE and is_brute_force:
                    block_state = "⚠️ Simulation"
                else:
                    block_state = "✅ Non"
                lines.append("| `{}` | {} | {} | {} | {} |".format(
                    ip,
                    "🏠 Interne" if is_internal(ip) else "🌐 Externe",
                    VT.verdict(vt) if vt else "⚪ N/A",
                    "🔴 HIT" if ip in misp_hits else "🟢 Aucun",
                    block_state))

        if hashes:
            lines += ["", "### 🔑 Hashes", "| Hash | VirusTotal |", "|------|-----------|"]
            for value in hashes:
                vt = vt_results.get(value, {})
                lines.append("| `{}…` | {} |".format(
                    value[:24], VT.verdict(vt) if vt else "⚪ N/A"))

        if domains:
            lines += ["", "### 🌍 Domaines", "| Domaine | VirusTotal |", "|---------|-----------|"]
            for value in domains:
                vt = vt_results.get(value, {})
                lines.append("| `{}` | {} |".format(value, VT.verdict(vt) if vt else "⚪ N/A"))

        if blocked:
            lines += ["", "### 🚫 IPs bloquées", ""]
            for ip in blocked:
                info    = blacklist.info(ip)
                blocked_at = info.get("blocked_at")
                expires = ((blocked_at + timedelta(minutes=cfg.BLOCK_DURATION_MIN))
                           .strftime("%H:%M:%S") if blocked_at else "?")
                lines.append("- `{}` — expire à {} — déblocage : "
                             "`python start.py unblock {}`".format(ip, expires, ip))

        if actions:
            lines += ["", "### 📊 Journal des actions", ""]
            lines += ["- {}".format(action) for action in actions]

        lines += ["", "> ℹ️ Les résultats Cortex arrivent dans des commentaires séparés "
                      "au fur et à mesure que les analyseurs se terminent.",
                  "", "---", "> *SOC Pipeline v{} — 100 % automatique*".format(VERSION)]
        thehive.add_comment(case_id, "\n".join(lines))


# ══════════════════════════════════════════════════════════════════
# POLLER
# ══════════════════════════════════════════════════════════════════
class Poller:
    def __init__(self):
        self.processor = AlertProcessor()

    def run_once(self) -> int:
        alerts    = thehive.list_alerts(("New", "Updated"))
        processed = 0
        for alert in alerts:
            alert_id = thehive_id(alert)
            if not alert_id or state.is_done(alert_id, "alert"):
                continue
            if int(alert.get("severity") or 2) < cfg.MIN_SEVERITY:
                log.info("Alerte %s ignorée (sévérité < MIN_SEVERITY=%d)",
                         alert_id, cfg.MIN_SEVERITY)
                state.mark_done(alert_id, "alert")
                continue
            state.mark_done(alert_id, "alert")
            processed += 1
            try:
                self.processor.process(alert)
            except Exception as exc:          # noqa: BLE001 — une alerte ne doit pas tuer le poller
                log.exception("Traitement de %s en échec : %s", alert_id, exc)
        if processed:
            log.info("Cycle terminé : %d alerte(s) traitée(s)", processed)
        return processed

    def run(self) -> int:
        cortex_registry.load()          # découverte des analyseurs au démarrage
        print_banner()
        if not thehive.ping():
            log.error("TheHive injoignable (%s) — vérifier THEHIVE_URL / THEHIVE_APIKEY. "
                      "Le service continue et réessaiera à chaque cycle.", cfg.THEHIVE_URL)
        notify("🚀 <b>SOC Pipeline v{} — Service B démarré</b>\n\n"
               "🦠 VirusTotal : {}\n🔬 Cortex : {} analyseur(s)\n🌐 MISP : {}\n"
               "🚫 Blocage : {}\n⏱ {} min / poll {}s".format(
                   VERSION,
                   "actif" if cfg.vt_ready else "inactif",
                   len(cortex_registry.analyzers),
                   "actif" if cfg.misp_ready else "inactif",
                   "RÉEL" if cfg.ACTIVE_RESPONSE else "SIMULATION",
                   cfg.BLOCK_DURATION_MIN, cfg.POLL_INTERVAL_SEC))
        try:
            while True:
                try:
                    self.run_once()
                except Exception as exc:      # noqa: BLE001 — boucle de service
                    log.exception("Erreur pendant le cycle : %s", exc)
                time.sleep(max(5, cfg.POLL_INTERVAL_SEC))
        except KeyboardInterrupt:
            log.info("Arrêt demandé (Ctrl+C)")
            return 0


# ══════════════════════════════════════════════════════════════════
# AFFICHAGE
# ══════════════════════════════════════════════════════════════════
def print_banner() -> None:
    rows = [
        ("TheHive", cfg.THEHIVE_URL),
        ("VirusTotal", "✅ actif" if cfg.vt_ready else "❌ VT_APIKEY manquante"),
        ("Cortex", "✅ {} analyseur(s) via {}".format(
            len(cortex_registry.analyzers), cortex_registry.source)
            if cortex_registry.analyzers else "⚠️ 0 analyseur détecté"),
        ("MISP", "✅ actif" if cfg.misp_ready else "⚪ désactivé"),
        ("Blocage", "🔴 RÉEL ({})".format("Administrateur" if blacklist.admin else "SANS DROITS !")
            if cfg.ACTIVE_RESPONSE else "⚠️ SIMULATION"),
        ("Fichiers", "🔴 {} sur {} dossier(s)".format(
            file_responder.mode, len(file_responder.scan_paths))
            if file_responder.ready else "⚪ désactivée"),
        ("Cadence", "{} min de blocage — poll {}s".format(
            cfg.BLOCK_DURATION_MIN, cfg.POLL_INTERVAL_SEC)),
        ("Logs", str(cfg.LOG_FILE)),
    ]
    print("")
    print("=" * 66)
    print("  SOC Pipeline — Service B  v{}  FULL AUTO".format(VERSION))
    print("=" * 66)
    for label, value in rows:
        print("  {:<12}: {}".format(label, value))
    print("-" * 66)
    print("  Flux : Alerte → Cas → Observables → Cortex → VT → MISP → Blocage → Telegram")
    print("=" * 66)
    if not cfg.ACTIVE_RESPONSE:
        print("\n  ⚠️  SIMULATION — mettre ACTIVE_RESPONSE=true dans .env pour bloquer réellement")
        print("      Windows : relancer PowerShell en Administrateur")
        print("      Linux   : sudo python3 start.py both\n")
    elif not blacklist.admin:
        print("\n  ❌ ACTIVE_RESPONSE=true mais les privilèges manquent — le blocage échouera.")
        print("      Windows : PowerShell « Exécuter en tant qu'administrateur »")
        print("      Linux   : sudo python3 start.py both\n")


# ══════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════
def cli_unblock(ip: str) -> int:
    if not is_valid_ip(ip):
        print("Adresse IP invalide : {}".format(ip))
        return 2
    if blacklist.unblock(ip):
        print("✅ {} débloquée".format(ip))
        telegram.send("✅ <b>Déblocage manuel</b> : <code>{}</code>".format(ip))
        return 0
    print("⚠️  {} n'était pas dans la blacklist (règles firewall nettoyées si présentes)"
          .format(ip))
    return 1


def cli_list() -> int:
    blocked = blacklist.list_blocked()
    if not blocked:
        print("Aucune IP bloquée.")
        return 0
    print("\nIPs bloquées ({}) :".format(len(blocked)))
    for entry in blocked:
        print("  {:<16} expire {} | reste {:>5} min | {}".format(
            entry["ip"], entry["expires_at"], entry["remaining_min"], entry["reason"]))
    return 0


def cli_status() -> int:
    cortex_registry.load()
    print("\n=== SOC Pipeline — Service B v{} ===".format(VERSION))
    print("TheHive         :", "✅ joignable" if thehive.ping() else "❌ injoignable",
          "—", cfg.THEHIVE_URL)
    print("Réponse active  :", "✅ oui" if cfg.ACTIVE_RESPONSE else "❌ non (simulation)")
    print("Privilèges      :", "✅ admin/root" if blacklist.admin else "❌ insuffisants")
    print("VirusTotal      :", "✅" if cfg.vt_ready else "❌")
    print("MISP            :", "✅" if cfg.misp_ready else "❌")
    print("Telegram        :", "✅" if telegram.enabled else "❌")
    print("Cortex          :", len(cortex_registry.analyzers),
          "analyseur(s) via", cortex_registry.source)
    for datatype in sorted(cortex_registry.by_type):
        names = [name for name, _, _ in cortex_registry.by_type[datatype][:4]]
        print("   [{}] {}".format(datatype, ", ".join(names)))
    print("Réponse fichier :", "✅ {}".format(file_responder.mode)
          if file_responder.ready else "❌ inactive")
    cli_list()
    file_responder.print_status()
    return 0


def cli_reload_cortex() -> int:
    count = cortex_registry.load()
    print("Cortex : {} analyseur(s) détecté(s) via {}".format(count, cortex_registry.source))
    return 0 if count else 1


def cli_test_block(ip: str) -> int:
    """Prouve que le blocage firewall fonctionne réellement, de bout en bout."""
    if not is_valid_ip(ip):
        print("Adresse IP invalide : {}".format(ip))
        return 2
    if is_internal(ip):
        print("⚠️  {} est une IP interne : à ne tester que si vous savez ce que "
              "vous faites.".format(ip))

    print("\n=== Test du blocage firewall ===")
    print("Cible            :", ip)
    print("Plateforme       :", "Windows / netsh" if IS_WINDOWS else "Linux / iptables")
    print("ACTIVE_RESPONSE  :", "✅ true" if cfg.ACTIVE_RESPONSE else "❌ false")
    print("Privilèges       :", "✅ admin/root" if blacklist.admin else "❌ insuffisants")

    if not cfg.ACTIVE_RESPONSE:
        print("\n❌ Impossible : mettre ACTIVE_RESPONSE=true dans .env, puis relancer.")
        return 1
    if not blacklist.admin:
        print("\n❌ Impossible : privilèges insuffisants.")
        print("   Windows : PowerShell → « Exécuter en tant qu'administrateur »")
        print("   Linux   : sudo python3 start.py test-block {}".format(ip))
        return 1

    print("\n1/3 — pose de la règle...")
    if not Firewall.block(ip):
        print("❌ Le firewall a refusé la règle. Voir les journaux ci-dessus.")
        return 1
    print("    ✅ règle posée")

    print("2/3 — vérification auprès du système...")
    if IS_WINDOWS:
        check = Firewall._run(["netsh", "advfirewall", "firewall", "show", "rule",
                               "name={}".format(Firewall._rule_name(ip, "IN"))])
        found = bool(check and check.returncode == 0 and "SOC_BLOCK" in (check.stdout or ""))
    else:
        binary = "ip6tables" if ":" in ip else "iptables"
        check  = Firewall._run([binary, "-C", "INPUT", "-s", ip, "-j", "DROP"])
        found  = bool(check and check.returncode == 0)
    print("    {} règle {}".format("✅" if found else "❌",
                                    "présente dans le firewall" if found else "INTROUVABLE"))

    print("3/3 — retrait de la règle...")
    Firewall.unblock(ip)
    print("    ✅ règle retirée\n")

    if found:
        print("✅ Le blocage firewall fonctionne. Les IP malveillantes seront "
              "réellement bloquées {} min.".format(cfg.BLOCK_DURATION_MIN))
        return 0
    print("❌ La règle n'a pas été retrouvée : le blocage ne serait pas effectif.")
    return 1


def cli_files() -> int:
    file_responder.print_status()
    file_responder.print_quarantine()
    return 0


def cli_scan(value: str) -> int:
    """Recherche un hash dans les dossiers surveillés et applique le mode configuré."""
    from file_responder import normalize_hash
    if not normalize_hash(value):
        print("Hash invalide : attendu 32 (MD5), 40 (SHA1) ou 64 (SHA256) "
              "caractères hexadécimaux.")
        return 2
    if not file_responder.enabled:
        print("Réponse fichier désactivée — mettre FILE_RESPONSE_ENABLED=true dans .env")
        return 1
    if not file_responder.ready:
        print("Aucun dossier valide à analyser — renseigner FILE_SCAN_PATHS dans .env")
        file_responder.print_status()
        return 1

    print("Recherche de {} (mode {}) dans :".format(value, file_responder.mode))
    for path in file_responder.scan_paths:
        print("   ", path)
    results = file_responder.respond([value], reason="recherche manuelle")
    if not results:
        print("\nAucun fichier correspondant.")
        return 0
    print("")
    for result in results:
        print("  {} {} → {}".format(
            "✅" if result.get("success") else "❌",
            result.get("action"), result.get("path")))
    return 0


def cli_restore(entry_id: str) -> int:
    result = file_responder.restore(entry_id)
    if result.get("success"):
        print("✅ Fichier restauré : {}".format(result["path"]))
        return 0
    print("❌ Restauration impossible : {}".format(result.get("error")))
    return 1


def cli_purge(entry_id: str) -> int:
    result = file_responder.purge(entry_id)
    if result.get("success"):
        print("✅ Élément supprimé définitivement de la quarantaine : {}".format(entry_id))
        return 0
    print("❌ Suppression impossible : {}".format(result.get("error")))
    return 1


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv:
        command = argv[0].lower()
        if command == "unblock" and len(argv) >= 2:
            return cli_unblock(argv[1])
        if command in ("list", "ls"):
            return cli_list()
        if command == "status":
            return cli_status()
        if command in ("cortex", "analyzers"):
            return cli_reload_cortex()
        if command in ("test-block", "testblock") and len(argv) >= 2:
            return cli_test_block(argv[1])
        if command in ("files", "quarantine"):
            return cli_files()
        if command == "scan" and len(argv) >= 2:
            return cli_scan(argv[1])
        if command == "restore" and len(argv) >= 2:
            return cli_restore(argv[1])
        if command == "purge" and len(argv) >= 2:
            return cli_purge(argv[1])
        if command not in ("run", "start"):
            print("Usage : service_b_thehive_responder.py [run | status | list |\n"
                  "        unblock <ip> | test-block <ip> | cortex |\n"
                  "        files | scan <hash> | restore <id> | purge <id>]")
            return 2
    return Poller().run()


if __name__ == "__main__":
    sys.exit(main())
